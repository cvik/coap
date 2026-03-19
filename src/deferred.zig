/// Pre-allocated pool for deferred (separate) CoAP responses.
///
/// When a handler calls `Request.defer()`, the server sends an empty ACK
/// immediately and allocates a slot here. The handler later calls
/// `DeferredResponse.respond()` from any thread, which encodes the response
/// and enqueues the slot index in a lock-free MPSC ring. The server tick
/// loop drains the ring, sends the response as a new CON, and handles
/// retransmission until the client ACKs.
const std = @import("std");
const posix = std.posix;
const coapz = @import("coapz");
const handler = @import("handler.zig");
const constants = @import("constants.zig");

const Deferred = @This();

pub const Config = struct {
    max_deferred: u16 = 16,
    buffer_size: u16 = 1280,
};

pub const State = enum(u8) {
    free,
    /// Empty ACK sent, waiting for handler to call respond().
    pending,
    /// Response encoded, queued for tick loop to send.
    ready,
    /// CON response sent, waiting for client ACK.
    sent,
};

pub const Slot = struct {
    state: std.atomic.Value(State),
    token: [8]u8,
    token_len: u8,
    peer_address: std.net.Address,
    /// Message ID for the separate CON response (not the original request).
    msg_id: u16,
    response_length: u16,
    retransmit_count: u8,
    retransmit_deadline_ns: i64,
    created_at_ns: i64,
    next_free: u16,
};

pub const DeferredResponse = struct {
    pool: *Deferred,
    slot_idx: u16,

    /// Deliver the response. Safe to call from any thread.
    /// Encodes the response as a CON packet into stable pool storage and
    /// enqueues for sending on the next server tick.
    pub fn respond(self: DeferredResponse, response: handler.Response) void {
        const slot = &self.pool.slots[self.slot_idx];
        const buf = self.pool.responseBuf(self.slot_idx);
        const pkt = coapz.Packet{
            .kind = .confirmable,
            .code = response.code,
            .msg_id = slot.msg_id,
            .token = slot.token[0..slot.token_len],
            .options = response.options,
            .payload = response.payload,
            .data_buf = &.{},
        };
        if (pkt.writeBuf(buf)) |written| {
            slot.response_length = @intCast(written.len);
            self.pool.enqueue(self.slot_idx);
        } else |_| {
            self.pool.release(self.slot_idx);
        }
    }

    /// Cancel without sending a response. Releases the slot.
    pub fn cancel(self: DeferredResponse) void {
        self.pool.release(self.slot_idx);
    }
};

pub const QueueEntry = struct {
    idx: u16,
    seq: std.atomic.Value(u32),
};

// ── Pool state ──

slots: []Slot,
response_buffer: []u8,
config: Config,
count_active: u16,
free_head: u16,

// MPSC ring buffer (#46).
queue: []QueueEntry,
queue_head: std.atomic.Value(u32), // producer claims slot (atomic)
queue_tail: u32, // consumer reads (single-threaded tick)
queue_mask: u32,

const empty_sentinel: u16 = 0xFFFF;

pub fn init(allocator: std.mem.Allocator, config: Config) !Deferred {
    if (config.max_deferred == 0) return error.InvalidConfig;

    const slots = try allocator.alloc(Slot, config.max_deferred);
    errdefer allocator.free(slots);

    const response_buffer = try allocator.alloc(u8, @as(usize, config.max_deferred) * config.buffer_size);
    errdefer allocator.free(response_buffer);

    // Queue capacity: next power of two >= max_deferred.
    const queue_size = blk: {
        var size: u16 = 1;
        while (size < config.max_deferred) size <<= 1;
        break :blk size;
    };
    const queue = try allocator.alloc(QueueEntry, queue_size);
    errdefer allocator.free(queue);
    for (queue, 0..) |*entry, i| {
        entry.* = .{ .idx = 0, .seq = std.atomic.Value(u32).init(@intCast(i)) };
    }

    for (slots, 0..) |*slot, i| {
        slot.* = .{
            .state = std.atomic.Value(State).init(.free),
            .token = .{0} ** 8,
            .token_len = 0,
            .peer_address = std.mem.zeroes(std.net.Address),
            .msg_id = 0,
            .response_length = 0,
            .retransmit_count = 0,
            .retransmit_deadline_ns = 0,
            .created_at_ns = 0,
            .next_free = if (i + 1 < config.max_deferred)
                @intCast(i + 1)
            else
                empty_sentinel,
        };
    }

    return .{
        .slots = slots,
        .response_buffer = response_buffer,
        .config = config,
        .count_active = 0,
        .free_head = 0,
        .queue = queue,
        .queue_head = std.atomic.Value(u32).init(0),
        .queue_tail = 0,
        .queue_mask = @as(u32, queue_size) - 1,
    };
}

pub fn deinit(self: *Deferred, allocator: std.mem.Allocator) void {
    allocator.free(self.slots);
    allocator.free(self.response_buffer);
    allocator.free(self.queue);
}

/// Allocate a slot for a deferred response. Returns slot index or null if full.
pub fn allocate(
    self: *Deferred,
    token: []const u8,
    peer_address: std.net.Address,
    msg_id: u16,
    now_ns: i64,
) ?u16 {
    if (self.free_head == empty_sentinel) return null;

    const idx = self.free_head;
    const slot = &self.slots[idx];
    self.free_head = slot.next_free;
    self.count_active += 1;

    slot.* = .{
        .state = std.atomic.Value(State).init(.pending),
        .token = blk: {
            var t: [8]u8 = .{0} ** 8;
            const len = @min(token.len, 8);
            @memcpy(t[0..len], token[0..len]);
            break :blk t;
        },
        .token_len = @intCast(@min(token.len, 8)),
        .peer_address = peer_address,
        .msg_id = msg_id,
        .response_length = 0,
        .retransmit_count = 0,
        .retransmit_deadline_ns = 0,
        .created_at_ns = now_ns,
        .next_free = empty_sentinel,
    };

    return idx;
}

/// Release a slot back to the free list.
pub fn release(self: *Deferred, idx: u16) void {
    self.slots[idx].state.store(.free, .release);
    self.slots[idx].next_free = self.free_head;
    self.free_head = idx;
    self.count_active -|= 1;
}

/// Get the response buffer for a slot.
pub fn responseBuf(self: *Deferred, idx: u16) []u8 {
    const offset = @as(usize, idx) * self.config.buffer_size;
    return self.response_buffer[offset..][0..self.config.buffer_size];
}

/// Enqueue a slot index for the tick loop to process.
/// Called from handler threads — must be thread-safe.
/// Uses Vyukov-style sequenced MPSC: claim slot via fetchAdd, write data,
/// then publish by storing the expected sequence number (#46).
fn enqueue(self: *Deferred, idx: u16) void {
    const pos = self.queue_head.fetchAdd(1, .acq_rel);
    const entry = &self.queue[pos & self.queue_mask];
    // Spin until the slot is available (consumer has advanced past it).
    while (entry.seq.load(.acquire) != pos) {
        std.atomic.spinLoopHint();
    }
    entry.idx = idx;
    self.slots[idx].state.store(.ready, .release);
    entry.seq.store(pos +% 1, .release); // publish
}

/// Drain all queued slot indices. Called from the server tick loop only.
/// Returns a slice into `out_buf` with the drained indices.
pub fn drainQueue(self: *Deferred, out_buf: []u16) []const u16 {
    var count: u16 = 0;
    while (count < out_buf.len) {
        const entry = &self.queue[self.queue_tail & self.queue_mask];
        const expected_seq = self.queue_tail +% 1;
        if (entry.seq.load(.acquire) != expected_seq) break; // not published yet
        out_buf[count] = entry.idx;
        // Advance the slot sequence so producers can reuse it.
        entry.seq.store(self.queue_tail +% @as(u32, @intCast(self.queue.len)), .release);
        self.queue_tail +%= 1;
        count += 1;
    }
    return out_buf[0..count];
}

/// Find a pending/sent slot by message ID and peer address (for ACK matching).
/// Linear scan — fine for small pool (default 16).
pub fn findByMsgId(self: *Deferred, msg_id: u16, peer_address: std.net.Address) ?u16 {
    for (self.slots, 0..) |*slot, i| {
        const state = slot.state.load(.acquire);
        if ((state == .sent or state == .ready) and
            slot.msg_id == msg_id and
            addrEqual(slot.peer_address, peer_address))
        {
            return @intCast(i);
        }
    }
    return null;
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
    var pool = try Deferred.init(testing.allocator, .{});
    defer pool.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 0), pool.count_active);
}

test "allocate and release" {
    var pool = try Deferred.init(testing.allocator, .{});
    defer pool.deinit(testing.allocator);

    const idx = pool.allocate(
        &.{ 0xAA, 0xBB },
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683),
        0x1234,
        1_000_000_000,
    ) orelse return error.PoolExhausted;

    try testing.expectEqual(@as(u16, 1), pool.count_active);
    try testing.expectEqual(State.pending, pool.slots[idx].state.load(.acquire));
    try testing.expectEqual(@as(u8, 2), pool.slots[idx].token_len);
    try testing.expectEqual(@as(u8, 0xAA), pool.slots[idx].token[0]);

    pool.release(idx);
    try testing.expectEqual(@as(u16, 0), pool.count_active);
}

test "pool exhaustion" {
    var pool = try Deferred.init(testing.allocator, .{ .max_deferred = 2 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const a = pool.allocate(&.{0x01}, addr, 1, 0);
    const b = pool.allocate(&.{0x02}, addr, 2, 0);
    const c = pool.allocate(&.{0x03}, addr, 3, 0);

    try testing.expect(a != null);
    try testing.expect(b != null);
    try testing.expect(c == null); // full
}

test "enqueue and drain" {
    var pool = try Deferred.init(testing.allocator, .{});
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const idx = pool.allocate(&.{0xAA}, addr, 0x1234, 0) orelse
        return error.PoolExhausted;

    pool.enqueue(idx);
    try testing.expectEqual(State.ready, pool.slots[idx].state.load(.acquire));

    var buf: [16]u16 = undefined;
    const drained = pool.drainQueue(&buf);
    try testing.expectEqual(@as(usize, 1), drained.len);
    try testing.expectEqual(idx, drained[0]);

    // Second drain is empty.
    const drained2 = pool.drainQueue(&buf);
    try testing.expectEqual(@as(usize, 0), drained2.len);
}

test "DeferredResponse.respond encodes and enqueues" {
    var pool = try Deferred.init(testing.allocator, .{});
    defer pool.deinit(testing.allocator);

    const idx = pool.allocate(
        &.{ 0xAA, 0xBB },
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683),
        0x1234,
        0,
    ) orelse return error.PoolExhausted;

    const handle = DeferredResponse{ .pool = &pool, .slot_idx = idx };
    handle.respond(.{ .code = .content, .payload = "hello" });

    try testing.expectEqual(State.ready, pool.slots[idx].state.load(.acquire));
    try testing.expect(pool.slots[idx].response_length > 0);

    // Verify it's in the queue.
    var buf: [16]u16 = undefined;
    const drained = pool.drainQueue(&buf);
    try testing.expectEqual(@as(usize, 1), drained.len);
}

test "DeferredResponse.cancel releases slot" {
    var pool = try Deferred.init(testing.allocator, .{});
    defer pool.deinit(testing.allocator);

    const idx = pool.allocate(
        &.{0xAA},
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683),
        0x1234,
        0,
    ) orelse return error.PoolExhausted;

    const handle = DeferredResponse{ .pool = &pool, .slot_idx = idx };
    handle.cancel();

    try testing.expectEqual(@as(u16, 0), pool.count_active);
}

test "findByMsgId" {
    var pool = try Deferred.init(testing.allocator, .{});
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const idx = pool.allocate(&.{0xAA}, addr, 0x5678, 0) orelse
        return error.PoolExhausted;

    // Not found while pending (findByMsgId only matches .sent/.ready).
    pool.slots[idx].state.store(.sent, .release);
    try testing.expectEqual(idx, pool.findByMsgId(0x5678, addr).?);

    // Wrong msg_id.
    try testing.expect(pool.findByMsgId(0x9999, addr) == null);
}

test "concurrent enqueue from multiple threads" {
    var pool = try Deferred.init(testing.allocator, .{ .max_deferred = 8 });
    defer pool.deinit(testing.allocator);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    var indices: [4]u16 = undefined;
    for (&indices, 0..) |*idx, i| {
        idx.* = pool.allocate(&.{0xAA}, addr, @intCast(i), 0) orelse
            return error.PoolExhausted;
    }

    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*t, i| {
        const Worker = struct {
            fn run(p: *Deferred, slot_idx: u16) void {
                p.slots[slot_idx].response_length = 4;
                p.enqueue(slot_idx);
            }
        };
        t.* = try std.Thread.spawn(.{}, Worker.run, .{ &pool, indices[i] });
    }
    for (&threads) |t| t.join();

    var buf: [16]u16 = undefined;
    const drained = pool.drainQueue(&buf);
    try testing.expectEqual(@as(usize, 4), drained.len);
}
