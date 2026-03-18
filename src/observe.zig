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
};

pub const Resource = struct {
    active: bool = false,
    observer_count: u16 = 0,
    seq: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

pub const NotifyEntry = struct {
    resource_id: u16,
    response_len: u16,
};

// ── Registry state ──

resources: []Resource,
observers: []Observer,
resource_count: u16,
config: Config,
observers_per_resource: u16,

// MPSC notification queue.
notify_queue: []NotifyEntry,
notify_buffer: []u8,
notify_head: std.atomic.Value(u16),
notify_tail: u16,
notify_mask: u16,

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
    const notify_queue = try allocator.alloc(NotifyEntry, queue_size);
    errdefer allocator.free(notify_queue);
    @memset(notify_queue, .{ .resource_id = 0, .response_len = 0 });

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
        .notify_head = std.atomic.Value(u16).init(0),
        .notify_tail = 0,
        .notify_mask = queue_size - 1,
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
            res.observer_count = 0;
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
            self.resources[resource_id].observer_count += 1;
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
            self.resources[resource_id].observer_count -|= 1;
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
                res.observer_count -|= 1;
            }
        }
    }
}

/// Get the observer list for a resource (for tick loop to iterate).
pub fn getObservers(self: *const ObserverRegistry, resource_id: u16) []const Observer {
    const base = @as(usize, resource_id) * self.observers_per_resource;
    return self.observers[base..][0..self.observers_per_resource];
}

/// Push a notification to the queue. Thread-safe.
/// Encodes the response as a NON CoAP packet with Observe option for each
/// observer. The tick loop sends them.
pub fn notify(self: *ObserverRegistry, resource_id: u16, response: handler.Response) void {
    if (resource_id >= self.resources.len or !self.resources[resource_id].active) return;
    if (self.resources[resource_id].observer_count == 0) return;

    // Increment sequence number (atomic — notify may be called from any thread).
    const seq = self.resources[resource_id].seq.fetchAdd(1, .monotonic) +% 1;

    // Encode a template notification (NON, with Observe option).
    // Token is placeholder — tick loop patches it per observer.
    const head = self.notify_head.load(.acquire);
    const slot = head & self.notify_mask;
    const buf = self.notifyBuf(slot);

    var obs_buf: [4]u8 = undefined;
    const obs_opt = coapz.Option.uint(.observe, seq, &obs_buf);

    // Merge observe option with response options.
    // For simplicity, encode with just the observe option + response options.
    // We build the options array on the stack.
    var opts_buf: [16]coapz.Option = undefined;
    opts_buf[0] = obs_opt;
    const resp_opts = @min(response.options.len, opts_buf.len - 1);
    for (response.options[0..resp_opts], 1..) |opt, i| {
        opts_buf[i] = opt;
    }

    const pkt = coapz.Packet{
        .kind = .non_confirmable,
        .code = response.code,
        .msg_id = 0, // tick loop assigns per-send
        .token = &.{0}, // tick loop patches per observer
        .options = opts_buf[0 .. 1 + resp_opts],
        .payload = response.payload,
        .data_buf = &.{},
    };

    if (pkt.writeBuf(buf)) |written| {
        const entry = NotifyEntry{
            .resource_id = resource_id,
            .response_len = @intCast(written.len),
        };
        self.notify_queue[slot] = entry;
        _ = self.notify_head.fetchAdd(1, .release);
    } else |_| {}
}

/// Drain the notification queue. Called from tick loop only.
pub fn drainNotifyQueue(self: *ObserverRegistry, out: []NotifyEntry) []const NotifyEntry {
    const head = self.notify_head.load(.acquire);
    var count: u16 = 0;
    while (self.notify_tail != head and count < out.len) {
        const slot = self.notify_tail & self.notify_mask;
        out[count] = self.notify_queue[slot];
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
    try testing.expectEqual(@as(u16, 1), reg.resources[rid].observer_count);

    reg.removeObserver(rid, addr, &.{ 0xAA, 0xBB });
    try testing.expectEqual(@as(u16, 0), reg.resources[rid].observer_count);
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
    try testing.expectEqual(@as(u16, 1), reg.resources[rid].observer_count);
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
    try testing.expectEqual(@as(u16, 1), reg.resources[r0].observer_count);
    // r1: addr1/0x02 removed → count=0
    try testing.expectEqual(@as(u16, 0), reg.resources[r1].observer_count);
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
