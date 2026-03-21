/// Server-side RFC 7641 Observe registry.
///
/// Tracks observed resources and their subscribers. Application code calls
/// `server.notify(resource_id, response)` from any thread to push
/// notifications. The tick loop drains the MPSC queue and sends NON
/// notifications to all registered observers.
const std = @import("std");
const posix = std.posix;
const coapz = @import("coapz");
const handler = @import("handler.zig");

const ObserverRegistry = @This();

pub const Config = struct {
    /// Maximum number of observed resources.
    max_resources: u16 = 64,
    /// Maximum total observer entries across all resources.
    max_observers: u16 = 256,
    /// Wire buffer size for encoding notifications.
    buffer_size: u16 = 1280,
    /// Notification queue depth (power of 2).
    queue_depth: u16 = 64,
};

pub const Observer = struct {
    active: bool = false,
    peer_address: std.net.Address,
    token: [8]u8,
    token_len: u8,
    /// Notifications sent to this observer (for CON interval).
    notify_count: u16 = 0,
    /// Non-zero when a CON notification is outstanding.
    pending_con_msg_id: u16 = 0,
    retransmit_count: u4 = 0,
    retransmit_deadline_ns: i64 = 0,
};

pub const Resource = struct {
    active: bool = false,
    /// Atomic: read from notify() (any thread), written from handler threads.
    observer_count: std.atomic.Value(u16) = std.atomic.Value(u16).init(0),
    seq: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

pub const NotifyEntry = struct {
    resource_id: u16,
    response_len: u16,
    queue_slot: u16,
};

const QueueSlot = struct {
    entry: NotifyEntry,
    seq: std.atomic.Value(u32),
};

// ── Registry state ──

resources: []Resource,
observers: []Observer,
resource_count: u16,
config: Config,
observers_per_resource: u16,

// MPSC notification queue with per-slot sequencing (#46).
notify_queue: []QueueSlot,
notify_buffer: []u8,
notify_head: std.atomic.Value(u32),
notify_tail: u32,
notify_mask: u32,

pub fn init(allocator: std.mem.Allocator, config: Config) !ObserverRegistry {
    if (config.max_resources == 0 or config.max_observers == 0) return error.InvalidConfig;

    const resources = try allocator.alloc(Resource, config.max_resources);
    errdefer allocator.free(resources);
    @memset(resources, .{});

    const observers = try allocator.alloc(Observer, config.max_observers);
    errdefer allocator.free(observers);
    for (observers) |*obs| {
        obs.* = .{
            .peer_address = std.mem.zeroes(std.net.Address),
            .token = .{0} ** 8,
            .token_len = 0,
        };
    }

    // Queue depth: next power of two >= config.queue_depth.
    const queue_size = blk: {
        var size: u16 = 1;
        while (size < config.queue_depth) size <<= 1;
        break :blk size;
    };
    const notify_queue = try allocator.alloc(QueueSlot, queue_size);
    errdefer allocator.free(notify_queue);
    for (notify_queue, 0..) |*slot, i| {
        slot.* = .{
            .entry = .{ .resource_id = 0, .response_len = 0, .queue_slot = 0 },
            .seq = std.atomic.Value(u32).init(@intCast(i)),
        };
    }

    const notify_buffer = try allocator.alloc(u8, @as(usize, queue_size) * config.buffer_size);
    errdefer allocator.free(notify_buffer);

    return .{
        .resources = resources,
        .observers = observers,
        .resource_count = 0,
        .config = config,
        .observers_per_resource = config.max_observers / config.max_resources,
        .notify_queue = notify_queue,
        .notify_buffer = notify_buffer,
        .notify_head = std.atomic.Value(u32).init(0),
        .notify_tail = 0,
        .notify_mask = @as(u32, queue_size) - 1,
    };
}

pub fn deinit(self: *ObserverRegistry, allocator: std.mem.Allocator) void {
    allocator.free(self.resources);
    allocator.free(self.observers);
    allocator.free(self.notify_queue);
    allocator.free(self.notify_buffer);
}

/// Allocate a resource slot. Returns resource ID or null if full.
pub fn allocateResource(self: *ObserverRegistry) ?u16 {
    for (self.resources, 0..) |*res, i| {
        if (!res.active) {
            res.active = true;
            res.observer_count.store(0, .monotonic);
            res.seq = std.atomic.Value(u32).init(0);
            self.resource_count += 1;
            return @intCast(i);
        }
    }
    return null;
}

/// Register a client as an observer of a resource. Idempotent — if the
/// same peer+token is already registered, returns true without duplicating.
pub fn addObserver(self: *ObserverRegistry, resource_id: u16, peer: std.net.Address, token: []const u8) bool {
    if (resource_id >= self.resources.len or !self.resources[resource_id].active) return false;

    const base = @as(usize, resource_id) * self.observers_per_resource;
    const slice = self.observers[base..][0..self.observers_per_resource];

    // Check for existing (idempotent).
    for (slice) |*obs| {
        if (obs.active and obs.token_len == token.len and
            std.mem.eql(u8, obs.token[0..obs.token_len], token) and
            addrEqual(obs.peer_address, peer))
        {
            return true;
        }
    }

    // Find free slot.
    for (slice) |*obs| {
        if (!obs.active) {
            obs.active = true;
            obs.peer_address = peer;
            obs.token_len = @intCast(@min(token.len, 8));
            obs.token = .{0} ** 8;
            @memcpy(obs.token[0..obs.token_len], token[0..obs.token_len]);
            obs.notify_count = 0;
            obs.pending_con_msg_id = 0;
            obs.retransmit_count = 0;
            obs.retransmit_deadline_ns = 0;
            _ = self.resources[resource_id].observer_count.fetchAdd(1, .monotonic);
            return true;
        }
    }
    return false; // partition full
}

/// Remove a specific observer by peer address and token.
pub fn removeObserver(self: *ObserverRegistry, resource_id: u16, peer: std.net.Address, token: []const u8) void {
    if (resource_id >= self.resources.len or !self.resources[resource_id].active) return;

    const base = @as(usize, resource_id) * self.observers_per_resource;
    const slice = self.observers[base..][0..self.observers_per_resource];

    for (slice) |*obs| {
        if (obs.active and obs.token_len == token.len and
            std.mem.eql(u8, obs.token[0..obs.token_len], token) and
            addrEqual(obs.peer_address, peer))
        {
            obs.active = false;
            _ = self.resources[resource_id].observer_count.fetchSub(1, .monotonic);
            return;
        }
    }
}

/// Remove all observers from a given peer address (e.g. on RST).
pub fn removeByPeer(self: *ObserverRegistry, peer: std.net.Address) void {
    for (self.resources, 0..) |*res, ri| {
        if (!res.active) continue;
        const base = ri * self.observers_per_resource;
        const slice = self.observers[base..][0..self.observers_per_resource];
        for (slice) |*obs| {
            if (obs.active and addrEqual(obs.peer_address, peer)) {
                obs.active = false;
                _ = res.observer_count.fetchSub(1, .monotonic);
            }
        }
    }
}

/// Get the observer list for a resource (for tick loop to iterate).
pub fn getObservers(self: *const ObserverRegistry, resource_id: u16) []const Observer {
    const base = @as(usize, resource_id) * self.observers_per_resource;
    return self.observers[base..][0..self.observers_per_resource];
}

/// Mutable version for tick-loop use (CON notification state updates).
pub fn getObserversMut(self: *ObserverRegistry, resource_id: u16) []Observer {
    const base = @as(usize, resource_id) * self.observers_per_resource;
    return self.observers[base..][0..self.observers_per_resource];
}

/// Push a notification to the queue. Thread-safe.
/// Encodes the response as a NON CoAP packet with Observe option for each
/// observer. The tick loop sends them.
/// Push a notification to the queue. Thread-safe.
/// Uses Vyukov-style sequenced MPSC (#46). Also fixes #47 by tracking
/// the queue slot index in the entry.
pub fn notify(self: *ObserverRegistry, resource_id: u16, response: handler.Response) void {
    if (resource_id >= self.resources.len or !self.resources[resource_id].active) return;
    // observer_count check is racy but harmless — worst case we encode
    // a notification that gets sent to zero observers.
    if (self.resources[resource_id].observer_count.load(.monotonic) == 0) return;

    // Claim a queue slot atomically.
    const pos = self.notify_head.fetchAdd(1, .acq_rel);
    const slot_idx: u16 = @intCast(pos & self.notify_mask);
    const qs = &self.notify_queue[slot_idx];

    // Spin until the slot is available (consumer has advanced past it).
    while (qs.seq.load(.acquire) != pos) {
        std.atomic.spinLoopHint();
    }

    // Increment sequence number (atomic — notify may be called from any thread).
    const seq = self.resources[resource_id].seq.fetchAdd(1, .monotonic) +% 1;

    const buf = self.notifyBuf(slot_idx);

    // Store notification metadata for per-observer encoding in drain phase.
    // Layout: [code:1][obs_seq:4 LE][opts_count:1][opts...][payload...]
    // Each option: [kind:2 LE][len:2 LE][value:len]
    const resp_opts: u8 = @intCast(@min(response.options.len, 15));
    buf[0] = @intFromEnum(response.code);
    std.mem.writeInt(u32, buf[1..5], seq, .little);
    buf[5] = resp_opts;
    var buf_pos: usize = 6;
    for (response.options[0..resp_opts]) |opt| {
        if (buf_pos + 4 + opt.value.len > buf.len) {
            qs.entry = .{ .resource_id = resource_id, .response_len = 0, .queue_slot = slot_idx };
            qs.seq.store(pos +% 1, .release);
            return;
        }
        std.mem.writeInt(u16, buf[buf_pos..][0..2], @intFromEnum(opt.kind), .little);
        std.mem.writeInt(u16, buf[buf_pos + 2 ..][0..2], @intCast(opt.value.len), .little);
        buf_pos += 4;
        @memcpy(buf[buf_pos..][0..opt.value.len], opt.value);
        buf_pos += opt.value.len;
    }
    // Payload.
    const payload_len = @min(response.payload.len, buf.len - buf_pos);
    @memcpy(buf[buf_pos..][0..payload_len], response.payload[0..payload_len]);
    buf_pos += payload_len;

    qs.entry = .{
        .resource_id = resource_id,
        .response_len = @intCast(buf_pos),
        .queue_slot = slot_idx,
    };
    qs.seq.store(pos +% 1, .release); // publish
}

/// Drain the notification queue. Called from tick loop only.
pub fn drainNotifyQueue(self: *ObserverRegistry, out: []NotifyEntry) []const NotifyEntry {
    var count: u16 = 0;
    while (count < out.len) {
        const qs = &self.notify_queue[self.notify_tail & self.notify_mask];
        const expected_seq = self.notify_tail +% 1;
        if (qs.seq.load(.acquire) != expected_seq) break;
        out[count] = qs.entry;
        qs.seq.store(self.notify_tail +% @as(u32, @intCast(self.notify_queue.len)), .release);
        self.notify_tail +%= 1;
        count += 1;
    }
    return out[0..count];
}

/// Get the encoded notification data for a queue slot.
pub fn notifyData(self: *const ObserverRegistry, slot_idx: u16) []const u8 {
    const buf = self.notifyBuf(slot_idx & self.notify_mask);
    // Find the actual length from the queue entry — caller passes it.
    return buf;
}

pub fn notifyBuf(self: *const ObserverRegistry, slot: u16) []u8 {
    const offset = @as(usize, slot) * self.config.buffer_size;
    return self.notify_buffer[offset..][0..self.config.buffer_size];
}

/// Clear pending CON state when an ACK is received for a CON notification.
pub fn ackConNotification(self: *ObserverRegistry, msg_id: u16, peer: std.net.Address) void {
    for (self.observers) |*obs| {
        if (!obs.active) continue;
        if (obs.pending_con_msg_id != msg_id) continue;
        if (!addrEqual(obs.peer_address, peer)) continue;
        obs.pending_con_msg_id = 0;
        obs.retransmit_count = 0;
        return;
    }
}

pub const NotifyMeta = struct {
    code: coapz.Code,
    obs_seq: u32,
    /// Slot 0 is reserved for the Observe option (set by caller).
    options: []coapz.Option,
    payload: []const u8,
};

/// Decode notification metadata from a notify buffer slot.
/// `arena` is used to allocate the options array.
pub fn decodeNotifyMeta(data: []const u8, arena: std.mem.Allocator) ?NotifyMeta {
    if (data.len < 6) return null;
    const code: coapz.Code = @enumFromInt(data[0]);
    const obs_seq = std.mem.readInt(u32, data[1..5], .little);
    const opts_count = data[5];
    var buf_pos: usize = 6;
    // +1 for the observe option prepended by the caller.
    const options = arena.alloc(coapz.Option, @as(usize, opts_count) + 1) catch return null;
    for (0..opts_count) |i| {
        if (buf_pos + 4 > data.len) return null;
        const kind: coapz.OptionKind = @enumFromInt(std.mem.readInt(u16, data[buf_pos..][0..2], .little));
        const vlen = std.mem.readInt(u16, data[buf_pos + 2 ..][0..2], .little);
        buf_pos += 4;
        if (buf_pos + vlen > data.len) return null;
        options[i + 1] = .{ .kind = kind, .value = data[buf_pos..][0..vlen] };
        buf_pos += vlen;
    }
    return .{
        .code = code,
        .obs_seq = obs_seq,
        .options = options,
        .payload = if (buf_pos < data.len) data[buf_pos..] else &.{},
    };
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
    var reg = try ObserverRegistry.init(testing.allocator, .{
        .max_resources = 4,
        .max_observers = 16,
    });
    defer reg.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 0), reg.resource_count);
}

test "allocate resource" {
    var reg = try ObserverRegistry.init(testing.allocator, .{
        .max_resources = 2,
        .max_observers = 8,
    });
    defer reg.deinit(testing.allocator);

    const r0 = reg.allocateResource() orelse return error.Full;
    const r1 = reg.allocateResource() orelse return error.Full;
    try testing.expectEqual(@as(u16, 2), reg.resource_count);
    try testing.expect(r0 != r1);

    // Full.
    try testing.expect(reg.allocateResource() == null);
}

test "add and remove observer" {
    var reg = try ObserverRegistry.init(testing.allocator, .{
        .max_resources = 4,
        .max_observers = 16,
    });
    defer reg.deinit(testing.allocator);

    const rid = reg.allocateResource() orelse return error.Full;
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);

    try testing.expect(reg.addObserver(rid, addr, &.{ 0xAA, 0xBB }));
    try testing.expectEqual(@as(u16, 1), reg.resources[rid].observer_count.load(.acquire));

    reg.removeObserver(rid, addr, &.{ 0xAA, 0xBB });
    try testing.expectEqual(@as(u16, 0), reg.resources[rid].observer_count.load(.acquire));
}

test "duplicate observer is idempotent" {
    var reg = try ObserverRegistry.init(testing.allocator, .{
        .max_resources = 4,
        .max_observers = 16,
    });
    defer reg.deinit(testing.allocator);

    const rid = reg.allocateResource() orelse return error.Full;
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);

    try testing.expect(reg.addObserver(rid, addr, &.{0xAA}));
    try testing.expect(reg.addObserver(rid, addr, &.{0xAA})); // duplicate
    try testing.expectEqual(@as(u16, 1), reg.resources[rid].observer_count.load(.acquire));
}

test "removeByPeer removes all observers for that peer" {
    var reg = try ObserverRegistry.init(testing.allocator, .{
        .max_resources = 4,
        .max_observers = 16,
    });
    defer reg.deinit(testing.allocator);

    const r0 = reg.allocateResource() orelse return error.Full;
    const r1 = reg.allocateResource() orelse return error.Full;
    const addr1 = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    const addr2 = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 5683);

    _ = reg.addObserver(r0, addr1, &.{0x01});
    _ = reg.addObserver(r1, addr1, &.{0x02});
    _ = reg.addObserver(r0, addr2, &.{0x03});

    reg.removeByPeer(addr1);
    // r0: addr1/0x01 removed, addr2/0x03 kept → count=1
    try testing.expectEqual(@as(u16, 1), reg.resources[r0].observer_count.load(.acquire));
    // r1: addr1/0x02 removed → count=0
    try testing.expectEqual(@as(u16, 0), reg.resources[r1].observer_count.load(.acquire));
}

test "notify enqueues and drain processes" {
    var reg = try ObserverRegistry.init(testing.allocator, .{
        .max_resources = 4,
        .max_observers = 16,
    });
    defer reg.deinit(testing.allocator);

    const rid = reg.allocateResource() orelse return error.Full;
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    _ = reg.addObserver(rid, addr, &.{0xAA});

    reg.notify(rid, .{ .code = .content, .payload = "22.5" });

    var entries: [16]NotifyEntry = undefined;
    const drained = reg.drainNotifyQueue(&entries);
    try testing.expectEqual(@as(usize, 1), drained.len);
    try testing.expectEqual(rid, drained[0].resource_id);
    try testing.expect(drained[0].response_len > 0);
}

test "notify increments sequence number" {
    var reg = try ObserverRegistry.init(testing.allocator, .{
        .max_resources = 4,
        .max_observers = 16,
    });
    defer reg.deinit(testing.allocator);

    const rid = reg.allocateResource() orelse return error.Full;
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683);
    _ = reg.addObserver(rid, addr, &.{0xAA});

    reg.notify(rid, .{ .code = .content, .payload = "v1" });
    reg.notify(rid, .{ .code = .content, .payload = "v2" });

    try testing.expectEqual(@as(u32, 2), reg.resources[rid].seq.load(.acquire));
}

test "notify skipped when no observers" {
    var reg = try ObserverRegistry.init(testing.allocator, .{
        .max_resources = 4,
        .max_observers = 16,
    });
    defer reg.deinit(testing.allocator);

    const rid = reg.allocateResource() orelse return error.Full;
    // No observers added.
    reg.notify(rid, .{ .code = .content, .payload = "nobody listening" });

    var entries: [16]NotifyEntry = undefined;
    const drained = reg.drainNotifyQueue(&entries);
    try testing.expectEqual(@as(usize, 0), drained.len);
}
