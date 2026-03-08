/// Per-IP token bucket rate limiter with pre-allocated open-addressing hash table.
///
/// Pattern follows exchange.zig: linear probing, backward-shift deletion,
/// intrusive free list. Clock-hand eviction when the table is full.
const std = @import("std");

const RateLimiter = @This();

pub const Config = struct {
    /// Maximum number of tracked IPs. 0 = rate limiting disabled.
    ip_count: u16 = 1024,
    /// Token refill rate per second.
    tokens_per_sec: u16 = 100,
    /// Maximum burst size (token bucket capacity).
    burst: u16 = 200,
};

const State = enum(u8) { free, active };

const Slot = struct {
    ip_addr: u32,
    tokens: u16,
    last_refill_ns: i128,
    state: State,
    next_free: u16,
};

const empty_sentinel: u16 = 0xFFFF;
const ns_per_sec: i128 = std.time.ns_per_s;

slots: []Slot,
table: []u16,
table_mask: u16,
free_head: u16,
clock_hand: u16,
config: Config,

pub fn init(allocator: std.mem.Allocator, config: Config) !RateLimiter {
    if (config.ip_count == 0) return error.InvalidConfig;
    if (config.burst == 0 or config.tokens_per_sec == 0) return error.InvalidConfig;

    const slots = try allocator.alloc(Slot, config.ip_count);
    errdefer allocator.free(slots);

    // Table size: next power of two >= 2 * ip_count.
    const table_size = blk: {
        var size: u32 = 1;
        while (size < @as(u32, config.ip_count) * 2) {
            size <<= 1;
        }
        break :blk @as(u16, @intCast(size));
    };

    const table = try allocator.alloc(u16, table_size);
    errdefer allocator.free(table);

    for (slots, 0..) |*slot, i| {
        slot.* = .{
            .ip_addr = 0,
            .tokens = 0,
            .last_refill_ns = 0,
            .state = .free,
            .next_free = if (i + 1 < config.ip_count)
                @intCast(i + 1)
            else
                empty_sentinel,
        };
    }

    @memset(table, empty_sentinel);

    return .{
        .slots = slots,
        .table = table,
        .table_mask = table_size - 1,
        .free_head = 0,
        .clock_hand = 0,
        .config = config,
    };
}

pub fn deinit(self: *RateLimiter, allocator: std.mem.Allocator) void {
    allocator.free(self.slots);
    allocator.free(self.table);
}

/// Check if a packet from `ip_addr` is allowed. Deducts one token.
/// Returns true if allowed, false if rate-limited.
pub fn allow(self: *RateLimiter, ip_addr: u32, now_ns: i128) bool {
    const key = hash_ip(ip_addr);

    // Look up existing entry.
    if (self.find_slot(key, ip_addr)) |slot_idx| {
        const slot = &self.slots[slot_idx];
        self.refill(slot, now_ns);
        if (slot.tokens == 0) return false;
        slot.tokens -= 1;
        return true;
    }

    // New IP — allocate a slot.
    const slot_idx = self.allocate_slot(key, ip_addr, now_ns) orelse {
        // Table completely full with no eviction candidate.
        // Fail open: allow the packet rather than DoS everyone.
        return true;
    };
    const slot = &self.slots[slot_idx];
    // New entry starts with burst - 1 tokens (one deducted for this packet).
    slot.tokens = self.config.burst - 1;
    return true;
}

pub fn reset(self: *RateLimiter) void {
    for (self.slots) |*slot| {
        slot.state = .free;
        slot.ip_addr = 0;
        slot.tokens = 0;
        slot.last_refill_ns = 0;
    }
    // Rebuild free list.
    for (self.slots, 0..) |*slot, i| {
        slot.next_free = if (i + 1 < self.config.ip_count)
            @intCast(i + 1)
        else
            empty_sentinel;
    }
    @memset(self.table, empty_sentinel);
    self.free_head = 0;
    self.clock_hand = 0;
}

// ── Internal ──

fn hash_ip(ip: u32) u64 {
    // FNV-1a on 4 bytes.
    var h: u64 = 0xcbf29ce484222325;
    const bytes: [4]u8 = @bitCast(ip);
    for (bytes) |b| {
        h ^= b;
        h *%= 0x100000001b3;
    }
    return h;
}

fn find_slot(self: *const RateLimiter, key: u64, ip_addr: u32) ?u16 {
    var idx: u16 = @intCast(@as(u32, @truncate(key)) & self.table_mask);
    var probes: u16 = 0;
    while (probes <= self.table_mask) : (probes += 1) {
        const slot_idx = self.table[idx];
        if (slot_idx == empty_sentinel) return null;
        if (self.slots[slot_idx].ip_addr == ip_addr and self.slots[slot_idx].state == .active) {
            return slot_idx;
        }
        idx = (idx + 1) & self.table_mask;
    }
    return null;
}

fn refill(self: *const RateLimiter, slot: *Slot, now_ns: i128) void {
    const elapsed = now_ns - slot.last_refill_ns;
    if (elapsed <= 0) return;
    const new_tokens: i128 = @divFloor(elapsed * self.config.tokens_per_sec, ns_per_sec);
    if (new_tokens > 0) {
        const capped: u16 = @intCast(@min(
            @as(u64, self.config.burst) - slot.tokens,
            @as(u64, @intCast(@min(new_tokens, std.math.maxInt(u16)))),
        ));
        slot.tokens += capped;
        slot.last_refill_ns = now_ns;
    }
}

fn allocate_slot(self: *RateLimiter, key: u64, ip_addr: u32, now_ns: i128) ?u16 {
    var slot_idx: u16 = undefined;

    if (self.free_head != empty_sentinel) {
        // Free list has a slot.
        slot_idx = self.free_head;
        self.free_head = self.slots[slot_idx].next_free;
    } else {
        // Must evict. Clock-hand sweep: prefer quiet IPs (tokens >= burst/2).
        slot_idx = self.evict() orelse return null;
    }

    const slot = &self.slots[slot_idx];
    slot.* = .{
        .ip_addr = ip_addr,
        .tokens = 0,
        .last_refill_ns = now_ns,
        .state = .active,
        .next_free = empty_sentinel,
    };

    // Insert into hash table.
    var idx: u16 = @intCast(@as(u32, @truncate(key)) & self.table_mask);
    while (self.table[idx] != empty_sentinel) {
        idx = (idx + 1) & self.table_mask;
    }
    self.table[idx] = slot_idx;

    return slot_idx;
}

fn evict(self: *RateLimiter) ?u16 {
    const half_burst = self.config.burst / 2;
    const count = self.config.ip_count;

    // First pass: evict quiet IP (tokens >= burst/2).
    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const idx = (self.clock_hand +% i) % count;
        const slot = &self.slots[idx];
        if (slot.state == .active and slot.tokens >= half_burst) {
            self.clock_hand = (idx +% 1) % count;
            self.remove_slot(idx);
            return idx;
        }
    }

    // Second pass: evict oldest (smallest last_refill_ns).
    var oldest_idx: ?u16 = null;
    var oldest_ns: i128 = std.math.maxInt(i128);
    for (self.slots, 0..) |*slot, si| {
        if (slot.state == .active and slot.last_refill_ns < oldest_ns) {
            oldest_ns = slot.last_refill_ns;
            oldest_idx = @intCast(si);
        }
    }

    if (oldest_idx) |oi| {
        self.remove_slot(oi);
        return oi;
    }

    return null;
}

fn remove_slot(self: *RateLimiter, slot_idx: u16) void {
    const slot = &self.slots[slot_idx];
    const key = hash_ip(slot.ip_addr);
    slot.state = .free;

    // Remove from hash table with backward-shift deletion.
    var idx: u16 = @intCast(@as(u32, @truncate(key)) & self.table_mask);
    while (self.table[idx] != empty_sentinel) {
        if (self.table[idx] == slot_idx) {
            self.table[idx] = empty_sentinel;
            self.rehash_after_remove(idx);
            return;
        }
        idx = (idx + 1) & self.table_mask;
    }
}

fn rehash_after_remove(self: *RateLimiter, removed_idx: u16) void {
    var gap = removed_idx;
    var idx = (removed_idx + 1) & self.table_mask;
    while (self.table[idx] != empty_sentinel) {
        const si = self.table[idx];
        const desired: u16 = @intCast(
            @as(u32, @truncate(hash_ip(self.slots[si].ip_addr))) & self.table_mask,
        );
        if (wrapping_distance(desired, idx, self.table_mask) >=
            wrapping_distance(desired, gap, self.table_mask))
        {
            self.table[gap] = si;
            self.table[idx] = empty_sentinel;
            gap = idx;
        }
        idx = (idx + 1) & self.table_mask;
    }
}

fn wrapping_distance(from: u16, to: u16, mask: u16) u16 {
    return (to -% from) & mask;
}

// ─── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "init and deinit" {
    var rl = try RateLimiter.init(testing.allocator, .{
        .ip_count = 8,
        .tokens_per_sec = 10,
        .burst = 20,
    });
    defer rl.deinit(testing.allocator);
}

test "allow basic" {
    var rl = try RateLimiter.init(testing.allocator, .{
        .ip_count = 8,
        .tokens_per_sec = 10,
        .burst = 5,
    });
    defer rl.deinit(testing.allocator);

    const ip: u32 = 0x7F000001; // 127.0.0.1
    const now: i128 = 1_000_000_000; // 1 second

    // First 5 requests should succeed (burst=5).
    for (0..5) |_| {
        try testing.expect(rl.allow(ip, now));
    }
    // 6th should fail.
    try testing.expect(!rl.allow(ip, now));
}

test "token refill over time" {
    var rl = try RateLimiter.init(testing.allocator, .{
        .ip_count = 8,
        .tokens_per_sec = 10,
        .burst = 5,
    });
    defer rl.deinit(testing.allocator);

    const ip: u32 = 0x7F000001;
    var now: i128 = 1_000_000_000;

    // Exhaust tokens.
    for (0..5) |_| {
        try testing.expect(rl.allow(ip, now));
    }
    try testing.expect(!rl.allow(ip, now));

    // Advance 1 second: should refill 10 tokens (capped at burst=5).
    now += ns_per_sec;
    for (0..5) |_| {
        try testing.expect(rl.allow(ip, now));
    }
    try testing.expect(!rl.allow(ip, now));
}

test "multiple IPs independent" {
    var rl = try RateLimiter.init(testing.allocator, .{
        .ip_count = 8,
        .tokens_per_sec = 10,
        .burst = 2,
    });
    defer rl.deinit(testing.allocator);

    const ip1: u32 = 0x01020304;
    const ip2: u32 = 0x05060708;
    const now: i128 = 1_000_000_000;

    // Each IP gets its own bucket.
    try testing.expect(rl.allow(ip1, now));
    try testing.expect(rl.allow(ip1, now));
    try testing.expect(!rl.allow(ip1, now));

    try testing.expect(rl.allow(ip2, now));
    try testing.expect(rl.allow(ip2, now));
    try testing.expect(!rl.allow(ip2, now));
}

test "eviction on table full" {
    var rl = try RateLimiter.init(testing.allocator, .{
        .ip_count = 2,
        .tokens_per_sec = 100,
        .burst = 200,
    });
    defer rl.deinit(testing.allocator);

    const now: i128 = 1_000_000_000;

    // Fill the table with 2 IPs.
    try testing.expect(rl.allow(0x01020301, now));
    try testing.expect(rl.allow(0x01020302, now));

    // Third IP should trigger eviction and still succeed.
    try testing.expect(rl.allow(0x01020303, now));
}

test "reset clears all state" {
    var rl = try RateLimiter.init(testing.allocator, .{
        .ip_count = 8,
        .tokens_per_sec = 10,
        .burst = 2,
    });
    defer rl.deinit(testing.allocator);

    const ip: u32 = 0x7F000001;
    const now: i128 = 1_000_000_000;

    try testing.expect(rl.allow(ip, now));
    try testing.expect(rl.allow(ip, now));
    try testing.expect(!rl.allow(ip, now));

    rl.reset();

    // After reset, tokens should be available again.
    try testing.expect(rl.allow(ip, now));
    try testing.expect(rl.allow(ip, now));
    try testing.expect(!rl.allow(ip, now));
}

test "disabled config returns error" {
    try testing.expectError(error.InvalidConfig, RateLimiter.init(
        testing.allocator,
        .{ .ip_count = 0, .tokens_per_sec = 10, .burst = 20 },
    ));
}
