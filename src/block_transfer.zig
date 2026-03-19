/// Server-side Block1 (upload reassembly) and Block2 (large response
/// fragmentation) per RFC 7959.
///
/// A single pre-allocated pool tracks active transfers of both kinds.
/// Block1: server collects fragments transparently, handler sees the
/// complete payload. Block2: handler returns a full (large) payload,
/// server serves blocks on demand as the client requests them.
const std = @import("std");
const posix = std.posix;
const coapz = @import("coapz");

const BlockTransfer = @This();

pub const Config = struct {
    max_transfers: u16 = 32,
    max_payload: u32 = 64 * 1024,
    buffer_size: u16 = 1280,
};

pub const TransferKind = enum(u8) { block1_receiving, block2_serving };
pub const State = enum(u8) { free, active };

pub const Slot = struct {
    state: State,
    kind: TransferKind,
    token: [8]u8,
    token_len: u8,
    request_tag: [8]u8,
    request_tag_len: u8,
    peer_address: std.net.Address,
    payload_length: u32,
    next_num: u32,
    szx: u3,
    created_at_ns: i64,
    next_free: u16,
};

pub const AppendResult = enum { more, complete, error_too_large, error_wrong_num };

pub const Block2Result = struct {
    data: []const u8,
    more: bool,
};

// ── Pool state ──

slots: []Slot,
payload_buffer: []u8,
config: Config,
count_active: u16,
free_head: u16,

const empty_sentinel: u16 = 0xFFFF;

pub fn init(allocator: std.mem.Allocator, config: Config) !BlockTransfer {
    if (config.max_transfers == 0) return error.InvalidConfig;

    const slots = try allocator.alloc(Slot, config.max_transfers);
    errdefer allocator.free(slots);

    const payload_buffer = try allocator.alloc(u8, @as(usize, config.max_transfers) * config.max_payload);
    errdefer allocator.free(payload_buffer);

    for (slots, 0..) |*slot, i| {
        slot.* = .{
            .state = .free,
            .kind = .block1_receiving,
            .token = .{0} ** 8,
            .token_len = 0,
            .request_tag = .{0} ** 8,
            .request_tag_len = 0,
            .peer_address = std.mem.zeroes(std.net.Address),
            .payload_length = 0,
            .next_num = 0,
            .szx = 0,
            .created_at_ns = 0,
            .next_free = if (i + 1 < config.max_transfers)
                @intCast(i + 1)
            else
                empty_sentinel,
        };
    }

    return .{
        .slots = slots,
        .payload_buffer = payload_buffer,
        .config = config,
        .count_active = 0,
        .free_head = 0,
    };
}

pub fn deinit(self: *BlockTransfer, allocator: std.mem.Allocator) void {
    allocator.free(self.slots);
    allocator.free(self.payload_buffer);
}

/// Allocate a transfer slot. Returns slot index or null if full.
pub fn allocate(
    self: *BlockTransfer,
    token: []const u8,
    peer_address: std.net.Address,
    kind: TransferKind,
    szx: u3,
    now_ns: i64,
    request_tag: []const u8,
) ?u16 {
    if (self.free_head == empty_sentinel) return null;

    const idx = self.free_head;
    const slot = &self.slots[idx];
    self.free_head = slot.next_free;
    self.count_active += 1;

    slot.* = .{
        .state = .active,
        .kind = kind,
        .token = blk: {
            var t: [8]u8 = .{0} ** 8;
            const len = @min(token.len, 8);
            @memcpy(t[0..len], token[0..len]);
            break :blk t;
        },
        .token_len = @intCast(@min(token.len, 8)),
        .request_tag = blk: {
            var rt: [8]u8 = .{0} ** 8;
            const len = @min(request_tag.len, 8);
            @memcpy(rt[0..len], request_tag[0..len]);
            break :blk rt;
        },
        .request_tag_len = @intCast(@min(request_tag.len, 8)),
        .peer_address = peer_address,
        .payload_length = 0,
        .next_num = 0,
        .szx = szx,
        .created_at_ns = now_ns,
        .next_free = empty_sentinel,
    };

    return idx;
}

/// Release a slot back to the free list.
pub fn release(self: *BlockTransfer, idx: u16) void {
    self.slots[idx].state = .free;
    self.slots[idx].next_free = self.free_head;
    self.free_head = idx;
    self.count_active -|= 1;
}

/// Find an active transfer by token, peer address, and request tag.
pub fn findByToken(self: *const BlockTransfer, token: []const u8, peer: std.net.Address, request_tag: []const u8) ?u16 {
    for (self.slots, 0..) |*slot, i| {
        if (slot.state != .active) continue;
        if (slot.token_len != token.len) continue;
        if (!std.mem.eql(u8, slot.token[0..slot.token_len], token)) continue;
        if (slot.request_tag_len != request_tag.len) continue;
        if (!std.mem.eql(u8, slot.request_tag[0..slot.request_tag_len], request_tag)) continue;
        if (!addrEqual(slot.peer_address, peer)) continue;
        return @intCast(i);
    }
    return null;
}

/// Evict transfers older than `timeout_ns`.
pub fn evictExpired(self: *BlockTransfer, now_ns: i64, timeout_ns: i64) u16 {
    var evicted: u16 = 0;
    for (self.slots, 0..) |*slot, i| {
        if (slot.state != .active) continue;
        if (now_ns - slot.created_at_ns > timeout_ns) {
            self.release(@intCast(i));
            evicted += 1;
        }
    }
    return evicted;
}

// ── Block1 reassembly ──

/// Append a Block1 fragment. Returns whether more blocks are expected,
/// the transfer is complete, or an error occurred.
pub fn appendBlock1(self: *BlockTransfer, idx: u16, num: u32, more: bool, data: []const u8) AppendResult {
    const slot = &self.slots[idx];
    if (num != slot.next_num) return .error_wrong_num;
    const new_len = slot.payload_length + @as(u32, @intCast(data.len));
    if (new_len > self.config.max_payload) return .error_too_large;
    const buf = self.payloadBuf(idx);
    @memcpy(buf[slot.payload_length..][0..data.len], data);
    slot.payload_length = new_len;
    slot.next_num = num + 1;
    return if (more) .more else .complete;
}

/// Get the reassembled payload for a completed Block1 transfer.
pub fn payloadSlice(self: *const BlockTransfer, idx: u16) []const u8 {
    return self.payloadBuf(idx)[0..self.slots[idx].payload_length];
}

// ── Block2 fragmentation ──

/// Store a full response payload for Block2 serving.
pub fn storeBlock2Payload(self: *BlockTransfer, idx: u16, payload: []const u8) void {
    const buf = self.payloadBuf(idx);
    const len = @min(payload.len, self.config.max_payload);
    @memcpy(buf[0..len], payload[0..len]);
    self.slots[idx].payload_length = @intCast(len);
}

/// Serve a single Block2 chunk. Client may request a different SZX
/// (smaller block size) than the one used to store.
pub fn serveBlock2(self: *const BlockTransfer, idx: u16, num: u32, szx: u3) Block2Result {
    const slot = &self.slots[idx];
    const block_size: u32 = @as(u32, 1) << (@as(u5, szx) + 4);
    const offset = @as(u32, num) * block_size;
    if (offset >= slot.payload_length) return .{ .data = &.{}, .more = false };
    const remaining = slot.payload_length - offset;
    const chunk = @min(remaining, block_size);
    const buf = self.payloadBuf(idx);
    return .{
        .data = buf[offset..][0..chunk],
        .more = (offset + chunk) < slot.payload_length,
    };
}

// ── Internal ──

fn payloadBuf(self: *const BlockTransfer, idx: u16) []u8 {
    const offset = @as(usize, idx) * self.config.max_payload;
    return self.payload_buffer[offset..][0..self.config.max_payload];
}

fn addrEqual(a: std.net.Address, b: std.net.Address) bool {
    if (a.any.family != b.any.family) return false;
    return switch (a.any.family) {
        posix.AF.INET => std.mem.eql(u8, std.mem.asBytes(&a.in), std.mem.asBytes(&b.in)),
        posix.AF.INET6 => std.mem.eql(u8, std.mem.asBytes(&a.in6), std.mem.asBytes(&b.in6)),
        else => false,
    };
}

// ── Tests ──

const testing = std.testing;

test "init and deinit" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 4, .max_payload = 1024 });
    defer pool.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 0), pool.count_active);
}

test "allocate and release" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 2, .max_payload = 1024 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const idx = pool.allocate(&.{0xAA}, addr, .block1_receiving, 6, 0, &.{}) orelse
        return error.PoolExhausted;
    try testing.expectEqual(@as(u16, 1), pool.count_active);
    try testing.expectEqual(State.active, pool.slots[idx].state);

    pool.release(idx);
    try testing.expectEqual(@as(u16, 0), pool.count_active);
}

test "pool exhaustion" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 2, .max_payload = 256 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    try testing.expect(pool.allocate(&.{0x01}, addr, .block1_receiving, 6, 0, &.{}) != null);
    try testing.expect(pool.allocate(&.{0x02}, addr, .block1_receiving, 6, 0, &.{}) != null);
    try testing.expect(pool.allocate(&.{0x03}, addr, .block1_receiving, 6, 0, &.{}) == null);
}

test "findByToken" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 4, .max_payload = 256 });
    defer pool.deinit(testing.allocator);

    const addr1 = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const addr2 = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 5683);
    const idx = pool.allocate(&.{ 0xAA, 0xBB }, addr1, .block1_receiving, 6, 0, &.{}) orelse
        return error.PoolExhausted;

    try testing.expectEqual(idx, pool.findByToken(&.{ 0xAA, 0xBB }, addr1, &.{}).?);
    try testing.expect(pool.findByToken(&.{ 0xAA, 0xBB }, addr2, &.{}) == null); // wrong addr
    try testing.expect(pool.findByToken(&.{0xCC}, addr1, &.{}) == null); // wrong token
}

test "block1: reassemble three fragments" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 4, .max_payload = 4096 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const idx = pool.allocate(&.{0xAA}, addr, .block1_receiving, 6, 0, &.{}) orelse
        return error.PoolExhausted;

    const block = [_]u8{0x42} ** 1024;
    try testing.expect(pool.appendBlock1(idx, 0, true, &block) == .more);
    try testing.expect(pool.appendBlock1(idx, 1, true, &block) == .more);
    try testing.expect(pool.appendBlock1(idx, 2, false, &block) == .complete);

    const payload = pool.payloadSlice(idx);
    try testing.expectEqual(@as(usize, 3072), payload.len);
    try testing.expectEqual(@as(u8, 0x42), payload[0]);
    try testing.expectEqual(@as(u8, 0x42), payload[3071]);
}

test "block1: error on wrong block number" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 4, .max_payload = 4096 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const idx = pool.allocate(&.{0xAA}, addr, .block1_receiving, 6, 0, &.{}) orelse
        return error.PoolExhausted;

    try testing.expect(pool.appendBlock1(idx, 0, true, "data") == .more);
    try testing.expect(pool.appendBlock1(idx, 5, true, "data") == .error_wrong_num); // expected 1
}

test "block1: error on payload too large" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 4, .max_payload = 100 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const idx = pool.allocate(&.{0xAA}, addr, .block1_receiving, 6, 0, &.{}) orelse
        return error.PoolExhausted;

    const big = [_]u8{0x42} ** 101;
    try testing.expect(pool.appendBlock1(idx, 0, false, &big) == .error_too_large);
}

test "block2: store payload and serve blocks" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 4, .max_payload = 4096 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const payload = [_]u8{0x42} ** 2500;
    const idx = pool.allocate(&.{0xAA}, addr, .block2_serving, 6, 0, &.{}) orelse
        return error.PoolExhausted;

    pool.storeBlock2Payload(idx, &payload);

    // Block 0: 1024 bytes, more=true
    const b0 = pool.serveBlock2(idx, 0, 6);
    try testing.expectEqual(@as(usize, 1024), b0.data.len);
    try testing.expect(b0.more);

    // Block 1: 1024 bytes, more=true
    const b1 = pool.serveBlock2(idx, 1, 6);
    try testing.expectEqual(@as(usize, 1024), b1.data.len);
    try testing.expect(b1.more);

    // Block 2: 452 bytes, more=false
    const b2 = pool.serveBlock2(idx, 2, 6);
    try testing.expectEqual(@as(usize, 452), b2.data.len);
    try testing.expect(!b2.more);
}

test "block2: smaller SZX negotiation" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 4, .max_payload = 4096 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const payload = [_]u8{0x42} ** 600;
    const idx = pool.allocate(&.{0xAA}, addr, .block2_serving, 6, 0, &.{}) orelse
        return error.PoolExhausted;

    pool.storeBlock2Payload(idx, &payload);

    // Client requests SZX=4 (256 bytes) instead of 6 (1024).
    const b0 = pool.serveBlock2(idx, 0, 4);
    try testing.expectEqual(@as(usize, 256), b0.data.len);
    try testing.expect(b0.more);

    const b1 = pool.serveBlock2(idx, 1, 4);
    try testing.expectEqual(@as(usize, 256), b1.data.len);
    try testing.expect(b1.more);

    const b2 = pool.serveBlock2(idx, 2, 4);
    try testing.expectEqual(@as(usize, 88), b2.data.len);
    try testing.expect(!b2.more);
}

test "block2: out of range block number" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 4, .max_payload = 4096 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const idx = pool.allocate(&.{0xAA}, addr, .block2_serving, 6, 0, &.{}) orelse
        return error.PoolExhausted;

    pool.storeBlock2Payload(idx, "hello");

    const b = pool.serveBlock2(idx, 99, 6);
    try testing.expectEqual(@as(usize, 0), b.data.len);
    try testing.expect(!b.more);
}

test "evictExpired" {
    var pool = try BlockTransfer.init(testing.allocator, .{ .max_transfers = 4, .max_payload = 256 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    _ = pool.allocate(&.{0x01}, addr, .block1_receiving, 6, 1000, &.{});
    _ = pool.allocate(&.{0x02}, addr, .block1_receiving, 6, 5000, &.{});

    const evicted = pool.evictExpired(6000, 4000);
    try testing.expectEqual(@as(u16, 1), evicted);
    try testing.expectEqual(@as(u16, 1), pool.count_active);
}
