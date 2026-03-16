/// Per-IP token bucket rate limiter with pre-allocated open-addressing hash table.
///
/// Pattern follows exchange.zig: linear probing, backward-shift deletion,
/// intrusive free list. Clock-hand eviction when the table is full.
const std = @import("std");
const posix = std.posix;

const RateLimiter = @This();

pub const Config = struct {
    /// Maximum number of tracked IPs. 0 = rate limiting disabled.
    ip_count: u16 = 1024,
    /// Token refill rate per second.
    tokens_per_sec: u16 = 100,
    /// Maximum burst size (token bucket capacity).
    burst: u16 = 200,
};

/// Family-aware address key for IPv4/IPv6-agnostic rate limiting.
/// Port is excluded — multiple connections from the same IP share a bucket.
pub const AddrKey = struct {
    family: u16,
    addr: [16]u8,

    pub const zero: AddrKey = .{ .family = 0, .addr = .{0} ** 16 };

    pub fn fromAddress(address: std.net.Address) AddrKey {
        return switch (address.any.family) {
            posix.AF.INET => .{
                .family = posix.AF.INET,
                .addr = blk: {
                    var a: [16]u8 = .{0} ** 16;
                    const src: [4]u8 = @bitCast(address.in.sa.addr);
                    @memcpy(a[0..4], &src);
                    break :blk a;
                },
            },
            posix.AF.INET6 => .{
                .family = posix.AF.INET6,
                .addr = address.in6.sa.addr,
            },
            else => zero,
        };
    }

    pub fn eql(a: AddrKey, b: AddrKey) bool {
        return a.family == b.family and std.mem.eql(u8, &a.addr, &b.addr);
    }

    pub fn hash(self: AddrKey) u64 {
        var h: u64 = 0xcbf29ce484222325;
        const fam_bytes: [2]u8 = @bitCast(self.family);
        for (fam_bytes) |b| {
            h ^= b;
            h *%= 0x100000001b3;
        }
        for (self.addr) |b| {
            h ^= b;
            h *%= 0x100000001b3;
        }
        return h;
    }
};

const State = enum(u8) { free, active };

const Slot = struct {
    addr_key: AddrKey,
    tokens: u16,
    last_refill_ns: i64,
    state: State,
    next_free: u16,
};

const empty_sentinel: u16 = 0xFFFF;
const ns_per_sec: i64 = std.time.ns_per_s;

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
            .addr_key = AddrKey.zero,
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

/// Check if a packet from `addr_key` is allowed. Deducts one token.
/// Returns true if allowed, false if rate-limited.
pub fn allow(self: *RateLimiter, addr_key: AddrKey, now_ns: i64) bool {
    const key = addr_key.hash();

    // Look up existing entry.
    if (self.find_slot(key, addr_key)) |slot_idx| {
        const slot = &self.slots[slot_idx];
        self.refill(slot, now_ns);
        if (slot.tokens == 0) return false;
        slot.tokens -= 1;
        return true;
    }

    // New IP — allocate a slot.
    const slot_idx = self.allocate_slot(key, addr_key, now_ns) orelse {
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
        slot.addr_key = AddrKey.zero;
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

fn find_slot(self: *const RateLimiter, key: u64, addr_key: AddrKey) ?u16 {
    var idx: u16 = @intCast(@as(u32, @truncate(key)) & self.table_mask);
    var probes: u16 = 0;
    while (probes <= self.table_mask) : (probes += 1) {
        const slot_idx = self.table[idx];
        if (slot_idx == empty_sentinel) return null;
        if (self.slots[slot_idx].addr_key.eql(addr_key) and self.slots[slot_idx].state == .active) {
            return slot_idx;
        }
        idx = (idx + 1) & self.table_mask;
    }
    return null;
}

fn refill(self: *const RateLimiter, slot: *Slot, now_ns: i64) void {
    const elapsed = now_ns - slot.last_refill_ns;
    if (elapsed <= 0) return;
    const new_tokens: i64 = @divFloor(elapsed * self.config.tokens_per_sec, ns_per_sec);
    if (new_tokens > 0) {
        const capped: u16 = @intCast(@min(
            @as(u64, self.config.burst) - slot.tokens,
            @as(u64, @intCast(@min(new_tokens, std.math.maxInt(u16)))),
        ));
        slot.tokens += capped;
        slot.last_refill_ns = now_ns;
    }
}

fn allocate_slot(self: *RateLimiter, key: u64, addr_key: AddrKey, now_ns: i64) ?u16 {
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
        .addr_key = addr_key,
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
    var oldest_ns: i64 = std.math.maxInt(i64);
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
    const key = slot.addr_key.hash();
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
            @as(u32, @truncate(self.slots[si].addr_key.hash())) & self.table_mask,
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

fn ipv4Key(comptime ip: u32) AddrKey {
    return .{
        .family = posix.AF.INET,
        .addr = blk: {
            var a: [16]u8 = .{0} ** 16;
            a[0..4].* = @bitCast(ip);
            break :blk a;
        },
    };
}

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

    const ip = ipv4Key(0x7F000001);
    const now: i64 = 1_000_000_000;

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

    const ip = ipv4Key(0x7F000001);
    var now: i64 = 1_000_000_000;

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

    const ip1 = ipv4Key(0x01020304);
    const ip2 = ipv4Key(0x05060708);
    const now: i64 = 1_000_000_000;

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

    const now: i64 = 1_000_000_000;

    // Fill the table with 2 IPs.
    try testing.expect(rl.allow(ipv4Key(0x01020301), now));
    try testing.expect(rl.allow(ipv4Key(0x01020302), now));

    // Third IP should trigger eviction and still succeed.
    try testing.expect(rl.allow(ipv4Key(0x01020303), now));
}

test "reset clears all state" {
    var rl = try RateLimiter.init(testing.allocator, .{
        .ip_count = 8,
        .tokens_per_sec = 10,
        .burst = 2,
    });
    defer rl.deinit(testing.allocator);

    const ip = ipv4Key(0x7F000001);
    const now: i64 = 1_000_000_000;

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

test "IPv6 addresses independent from IPv4" {
    var rl = try RateLimiter.init(testing.allocator, .{
        .ip_count = 8,
        .tokens_per_sec = 10,
        .burst = 2,
    });
    defer rl.deinit(testing.allocator);

    const v4 = AddrKey.fromAddress(try std.net.Address.parseIp("127.0.0.1", 5683));
    const v6 = AddrKey.fromAddress(try std.net.Address.parseIp("::1", 5683));
    const now: i64 = 1_000_000_000;

    try testing.expect(rl.allow(v4, now));
    try testing.expect(rl.allow(v4, now));
    try testing.expect(!rl.allow(v4, now)); // exhausted

    // IPv6 has its own bucket
    try testing.expect(rl.allow(v6, now));
    try testing.expect(rl.allow(v6, now));
    try testing.expect(!rl.allow(v6, now));
}
