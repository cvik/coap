/// CoAP message exchange tracking for CON/ACK reliability.
///
/// Provides duplicate detection and response caching per RFC 7252 §4.
/// All memory is pre-allocated at init. Uses an open-addressing hash
/// table keyed on (peer_address, message_id) for O(1) lookups and an
/// intrusive free list for O(1) slot allocation.
const std = @import("std");
const posix = std.posix;
const constants = @import("constants.zig");

const Exchange = @This();

pub const Config = struct {
    /// Maximum number of concurrent exchanges.
    exchange_count: u16 = 256,
    /// Maximum encoded response size to cache for retransmission.
    response_size_max: u16 = 1280,
};

pub const State = enum(u8) {
    free,
    completed,
};

pub const Slot = struct {
    state: State,
    peer_key: u64,
    /// Address-only hash (no message ID) for peer-based eviction.
    addr_key: u32,
    message_id: u16,
    response_length: u16,
    /// Monotonic timestamp (ns) when exchange was completed.
    completed_at_ns: i64,
    /// Index of next free slot (when state == .free).
    next_free: u16,
};

slots: []Slot,
/// Backing buffer for cached responses, indexed as
/// slots[i] -> response_buffer[i * response_size_max ..].
response_buffer: []u8,
/// Hash table mapping peer_key XOR message_id -> slot index.
/// Uses open addressing with linear probing.
/// 0xFFFF = empty sentinel.
table: []u16,
table_mask: u16,
/// Head of intrusive free list through slots.
free_head: u16,
/// Count of active (non-free) exchanges.
count_active: u16,
config: Config,

const empty_sentinel: u16 = 0xFFFF;

pub fn init(allocator: std.mem.Allocator, config: Config) !Exchange {
    if (config.exchange_count == 0 or config.response_size_max == 0) return error.InvalidConfig;

    const slots = try allocator.alloc(Slot, config.exchange_count);
    errdefer allocator.free(slots);

    const response_buffer = try allocator.alloc(
        u8,
        @as(usize, config.exchange_count) * config.response_size_max,
    );
    errdefer allocator.free(response_buffer);

    // Table size: next power of two >= 2 * exchange_count.
    const table_size = blk: {
        var size: u32 = 1;
        while (size < @as(u32, config.exchange_count) * 2) {
            size <<= 1;
        }
        break :blk @as(u16, @intCast(size));
    };

    const table = try allocator.alloc(u16, table_size);
    errdefer allocator.free(table);

    // Initialize free list and table.
    for (slots, 0..) |*slot, i| {
        slot.* = .{
            .state = .free,
            .peer_key = 0,
            .addr_key = 0,
            .message_id = 0,
            .response_length = 0,
            .completed_at_ns = 0,
            .next_free = if (i + 1 < config.exchange_count)
                @intCast(i + 1)
            else
                empty_sentinel,
        };
    }

    @memset(table, empty_sentinel);

    return .{
        .slots = slots,
        .response_buffer = response_buffer,
        .table = table,
        .table_mask = table_size - 1,
        .free_head = 0,
        .count_active = 0,
        .config = config,
    };
}

pub fn deinit(exchange: *Exchange, allocator: std.mem.Allocator) void {
    allocator.free(exchange.slots);
    allocator.free(exchange.response_buffer);
    allocator.free(exchange.table);
}

/// Hash peer address only (no message ID) for peer-based eviction.
pub fn addr_hash(address: std.net.Address) u32 {
    var hash: u32 = 0x811c9dc5; // FNV-1a 32-bit offset basis
    for (addrBytes(address)) |b| {
        hash ^= b;
        hash *%= 0x01000193; // FNV-1a 32-bit prime
    }
    return hash;
}

/// Compute a hash key from peer address and message ID.
pub fn peer_key(address: std.net.Address, message_id: u16) u64 {
    var hash: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for (addrBytes(address)) |b| {
        hash ^= b;
        hash *%= 0x100000001b3; // FNV-1a prime
    }
    hash ^= @as(u64, message_id);
    hash *%= 0x100000001b3;
    return hash;
}

/// Extract the relevant address bytes for hashing (family-aware).
fn addrBytes(address: std.net.Address) []const u8 {
    return switch (address.any.family) {
        posix.AF.INET => std.mem.asBytes(&address.in),
        posix.AF.INET6 => std.mem.asBytes(&address.in6),
        else => std.mem.asBytes(&address.in),
    };
}

/// Look up an exchange by peer address and message ID.
/// Returns the slot index if found, null otherwise.
pub fn find(exchange: *const Exchange, key: u64) ?u16 {
    var idx: u16 = @intCast(@as(u32, @truncate(key)) & exchange.table_mask);
    var probes: u16 = 0;

    while (probes <= exchange.table_mask) : (probes += 1) {
        const slot_idx = exchange.table[idx];
        if (slot_idx == empty_sentinel) {
            return null;
        }
        const slot = &exchange.slots[slot_idx];
        if (slot.peer_key == key) {
            return slot_idx;
        }
        idx = (idx + 1) & exchange.table_mask;
    }
    return null;
}

/// Record a completed exchange with its cached response.
/// Returns null if the pool is exhausted.
pub fn insert(
    exchange: *Exchange,
    key: u64,
    addr_key: u32,
    message_id: u16,
    response_data: []const u8,
    now_ns: i64,
) ?u16 {
    if (exchange.free_head == empty_sentinel) {
        return null;
    }
    if (response_data.len > exchange.config.response_size_max) {
        return null;
    }

    if (exchange.find(key) != null) return null;

    // Allocate from free list.
    const slot_idx = exchange.free_head;
    const slot = &exchange.slots[slot_idx];
    exchange.free_head = slot.next_free;
    exchange.count_active += 1;
    // Invariant: free_head == empty_sentinel guards over-allocation above.
    std.debug.assert(exchange.count_active <= exchange.config.exchange_count);

    // Populate slot.
    slot.* = .{
        .state = .completed,
        .peer_key = key,
        .addr_key = addr_key,
        .message_id = message_id,
        .response_length = @intCast(response_data.len),
        .completed_at_ns = now_ns,
        .next_free = empty_sentinel,
    };

    // Cache the response.
    const offset = @as(usize, slot_idx) * exchange.config.response_size_max;
    @memcpy(
        exchange.response_buffer[offset..][0..response_data.len],
        response_data,
    );

    // Insert into hash table.
    var idx: u16 = @intCast(
        @as(u32, @truncate(key)) & exchange.table_mask,
    );
    while (exchange.table[idx] != empty_sentinel) {
        idx = (idx + 1) & exchange.table_mask;
    }
    exchange.table[idx] = slot_idx;

    return slot_idx;
}

/// Get the cached response for a slot.
pub fn cached_response(exchange: *const Exchange, slot_idx: u16) []const u8 {
    const slot = &exchange.slots[slot_idx];
    std.debug.assert(slot.state == .completed);
    const offset = @as(usize, slot_idx) * exchange.config.response_size_max;
    return exchange.response_buffer[offset..][0..slot.response_length];
}

/// Evict all completed exchanges for a given peer address.
/// Called when a new (non-duplicate) request arrives from a peer,
/// proving the peer received all prior responses.
pub fn evict_peer(exchange: *Exchange, ak: u32) u16 {
    var evicted: u16 = 0;
    for (exchange.slots, 0..) |*slot, i| {
        if (slot.state != .completed) continue;
        if (slot.addr_key != ak) continue;
        exchange.remove(@intCast(i));
        evicted += 1;
    }
    return evicted;
}

/// Evict exchanges that have expired past the exchange lifetime.
/// Returns the number of evicted exchanges.
pub fn evict_expired(exchange: *Exchange, now_ns: i64, lifetime_ms: u32) u16 {
    const lifetime_ns: i64 = @as(i64, lifetime_ms) *
        std.time.ns_per_ms;
    var evicted: u16 = 0;

    for (exchange.slots, 0..) |*slot, i| {
        if (slot.state != .completed) {
            continue;
        }
        if (now_ns - slot.completed_at_ns < lifetime_ns) {
            continue;
        }
        exchange.remove(@intCast(i));
        evicted += 1;
    }
    return evicted;
}

/// Remove a specific exchange and return its slot to the free list.
pub fn remove(exchange: *Exchange, slot_idx: u16) void {
    const slot = &exchange.slots[slot_idx];
    std.debug.assert(slot.state == .completed);

    // Remove from hash table.
    exchange.remove_from_table(slot.peer_key);

    // Return to free list.
    slot.state = .free;
    slot.next_free = exchange.free_head;
    exchange.free_head = slot_idx;
    exchange.count_active -= 1;
}

fn remove_from_table(exchange: *Exchange, key: u64) void {
    var idx: u16 = @intCast(
        @as(u32, @truncate(key)) & exchange.table_mask,
    );
    var probes: u16 = 0;

    while (probes <= exchange.table_mask) : (probes += 1) {
        const slot_idx = exchange.table[idx];
        if (slot_idx == empty_sentinel) {
            return;
        }
        if (exchange.slots[slot_idx].peer_key == key) {
            // Found. Remove and rehash subsequent entries.
            exchange.table[idx] = empty_sentinel;
            exchange.rehash_after_remove(idx);
            return;
        }
        idx = (idx + 1) & exchange.table_mask;
    }
}

/// After removing a table entry, shift back subsequent entries that
/// were displaced by linear probing (backward-shift deletion).
fn rehash_after_remove(exchange: *Exchange, removed_idx: u16) void {
    var gap = removed_idx;
    var idx = (removed_idx + 1) & exchange.table_mask;
    while (exchange.table[idx] != empty_sentinel) {
        const slot_idx = exchange.table[idx];
        const desired: u16 = @intCast(
            @as(u32, @truncate(exchange.slots[slot_idx].peer_key)) &
                exchange.table_mask,
        );
        // If moving this entry to the gap would place it on or closer
        // to its desired position, shift it back.
        if (wrapping_distance(desired, idx, exchange.table_mask) >=
            wrapping_distance(desired, gap, exchange.table_mask))
        {
            exchange.table[gap] = slot_idx;
            exchange.table[idx] = empty_sentinel;
            gap = idx;
        }
        idx = (idx + 1) & exchange.table_mask;
    }
}

fn wrapping_distance(from: u16, to: u16, mask: u16) u16 {
    return (to -% from) & mask;
}

// ─── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "init and deinit" {
    var pool = try Exchange.init(testing.allocator, .{
        .exchange_count = 8,
        .response_size_max = 64,
    });
    defer pool.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 0), pool.count_active);
    try testing.expectEqual(@as(u16, 0), pool.free_head);
}

test "insert and find" {
    var pool = try Exchange.init(testing.allocator, .{
        .exchange_count = 8,
        .response_size_max = 64,
    });
    defer pool.deinit(testing.allocator);

    const addr = try std.net.Address.parseIp("127.0.0.1", 5683);
    const key = Exchange.peer_key(addr, 0x1234);

    try testing.expect(pool.find(key) == null);

    const slot = pool.insert(key, 0, 0x1234, "response", 0);
    try testing.expect(slot != null);
    try testing.expectEqual(@as(u16, 1), pool.count_active);

    const found = pool.find(key);
    try testing.expect(found != null);
    try testing.expectEqualSlices(
        u8,
        "response",
        pool.cached_response(found.?),
    );
}

test "duplicate detection" {
    var pool = try Exchange.init(testing.allocator, .{
        .exchange_count = 8,
        .response_size_max = 64,
    });
    defer pool.deinit(testing.allocator);

    const addr = try std.net.Address.parseIp("127.0.0.1", 5683);
    const key = Exchange.peer_key(addr, 0xAAAA);

    _ = pool.insert(key, 0, 0xAAAA, "first", 0);
    try testing.expectEqual(@as(u16, 1), pool.count_active);

    // Same key should be found (duplicate).
    const found = pool.find(key);
    try testing.expect(found != null);
    try testing.expectEqualSlices(
        u8,
        "first",
        pool.cached_response(found.?),
    );
}

test "pool exhaustion" {
    var pool = try Exchange.init(testing.allocator, .{
        .exchange_count = 2,
        .response_size_max = 64,
    });
    defer pool.deinit(testing.allocator);

    const addr = try std.net.Address.parseIp("127.0.0.1", 5683);
    const k1 = Exchange.peer_key(addr, 1);
    const k2 = Exchange.peer_key(addr, 2);
    const k3 = Exchange.peer_key(addr, 3);

    try testing.expect(pool.insert(k1, 0, 1, "a", 0) != null);
    try testing.expect(pool.insert(k2, 0, 2, "b", 0) != null);
    try testing.expect(pool.insert(k3, 0, 3, "c", 0) == null);
    try testing.expectEqual(@as(u16, 2), pool.count_active);
}

test "evict expired" {
    var pool = try Exchange.init(testing.allocator, .{
        .exchange_count = 4,
        .response_size_max = 64,
    });
    defer pool.deinit(testing.allocator);

    const addr = try std.net.Address.parseIp("127.0.0.1", 5683);
    const k1 = Exchange.peer_key(addr, 1);
    const k2 = Exchange.peer_key(addr, 2);

    // Insert at time 0.
    _ = pool.insert(k1, 0, 1, "old", 0);
    // Insert at a recent time.
    const recent: i64 = @as(i64, constants.exchange_lifetime_ms) *
        std.time.ns_per_ms;
    _ = pool.insert(k2, 0, 2, "new", recent);

    try testing.expectEqual(@as(u16, 2), pool.count_active);

    // Evict at time = lifetime + 1ms. Only the old one should expire.
    const now = recent + std.time.ns_per_ms;
    const evicted = pool.evict_expired(now, constants.exchange_lifetime_ms);
    try testing.expectEqual(@as(u16, 1), evicted);
    try testing.expectEqual(@as(u16, 1), pool.count_active);

    // Old key gone, new key still present.
    try testing.expect(pool.find(k1) == null);
    try testing.expect(pool.find(k2) != null);
}

test "remove is public" {
    var pool = try Exchange.init(testing.allocator, .{
        .exchange_count = 8,
        .response_size_max = 64,
    });
    defer pool.deinit(testing.allocator);

    const addr = try std.net.Address.parseIp("127.0.0.1", 5683);
    const key = Exchange.peer_key(addr, 0x0001);

    const slot = pool.insert(key, 0, 0x0001, "data", 0);
    try testing.expect(slot != null);
    try testing.expectEqual(@as(u16, 1), pool.count_active);

    pool.remove(slot.?);
    try testing.expectEqual(@as(u16, 0), pool.count_active);
    try testing.expect(pool.find(key) == null);
}

test "rehash after remove does not orphan entries" {
    var pool = try Exchange.init(testing.allocator, .{
        .exchange_count = 4,
        .response_size_max = 16,
    });
    defer pool.deinit(testing.allocator);

    // Craft keys that map to specific desired indices.
    // Lower 32 bits & 7 = desired index (table_mask=7 for exchange_count=4).
    const key_a: u64 = 0x0001_0000_0000_0003; // desired=3
    const key_b: u64 = 0x0002_0000_0000_0003; // desired=3
    const key_c: u64 = 0x0003_0000_0000_0003; // desired=3
    const key_d: u64 = 0x0004_0000_0000_0005; // desired=5

    _ = pool.insert(key_a, 0, 1, "a", 0);
    _ = pool.insert(key_b, 0, 2, "b", 0);
    _ = pool.insert(key_c, 0, 3, "c", 0);
    _ = pool.insert(key_d, 0, 4, "d", 0);

    const slot_a = pool.find(key_a).?;
    pool.remove(slot_a);

    try testing.expect(pool.find(key_b) != null);
    try testing.expect(pool.find(key_c) != null);
    try testing.expect(pool.find(key_d) != null);
}

test "rehash after remove with simple chain" {
    var pool = try Exchange.init(testing.allocator, .{
        .exchange_count = 4,
        .response_size_max = 16,
    });
    defer pool.deinit(testing.allocator);

    const key_x: u64 = 0x0001_0000_0000_0002; // desired=2
    const key_y: u64 = 0x0002_0000_0000_0002; // desired=2

    _ = pool.insert(key_x, 0, 1, "x", 0);
    _ = pool.insert(key_y, 0, 2, "y", 0);

    const slot_x = pool.find(key_x).?;
    pool.remove(slot_x);

    try testing.expect(pool.find(key_y) != null);
    try testing.expectEqualSlices(
        u8,
        "y",
        pool.cached_response(pool.find(key_y).?),
    );
}

test "rehash after remove wraps around table" {
    var pool = try Exchange.init(testing.allocator, .{
        .exchange_count = 4,
        .response_size_max = 16,
    });
    defer pool.deinit(testing.allocator);

    const key_e: u64 = 0x0001_0000_0000_0006; // desired=6
    const key_f: u64 = 0x0002_0000_0000_0006; // desired=6
    const key_g: u64 = 0x0003_0000_0000_0006; // desired=6

    _ = pool.insert(key_e, 0, 1, "e", 0);
    _ = pool.insert(key_f, 0, 2, "f", 0);
    _ = pool.insert(key_g, 0, 3, "g", 0);

    const slot_e = pool.find(key_e).?;
    pool.remove(slot_e);

    try testing.expect(pool.find(key_f) != null);
    try testing.expect(pool.find(key_g) != null);
}

test "evict_peer removes all exchanges for a peer" {
    var pool = try Exchange.init(testing.allocator, .{
        .exchange_count = 8,
        .response_size_max = 64,
    });
    defer pool.deinit(testing.allocator);

    const addr_a = try std.net.Address.parseIp("10.0.0.1", 5683);
    const addr_b = try std.net.Address.parseIp("10.0.0.2", 5683);
    const ak_a = Exchange.addr_hash(addr_a);
    const ak_b = Exchange.addr_hash(addr_b);

    // Two exchanges from peer A, one from peer B.
    _ = pool.insert(Exchange.peer_key(addr_a, 1), ak_a, 1, "a1", 0);
    _ = pool.insert(Exchange.peer_key(addr_a, 2), ak_a, 2, "a2", 0);
    _ = pool.insert(Exchange.peer_key(addr_b, 3), ak_b, 3, "b1", 0);
    try testing.expectEqual(@as(u16, 3), pool.count_active);

    // Evict peer A — should remove 2, leave peer B.
    const evicted = pool.evict_peer(ak_a);
    try testing.expectEqual(@as(u16, 2), evicted);
    try testing.expectEqual(@as(u16, 1), pool.count_active);
    try testing.expect(pool.find(Exchange.peer_key(addr_b, 3)) != null);
}

test "addr_hash differentiates IPv4 and IPv6" {
    const v4 = try std.net.Address.parseIp("127.0.0.1", 5683);
    const v6 = try std.net.Address.parseIp("::1", 5683);
    try testing.expect(Exchange.addr_hash(v4) != Exchange.addr_hash(v6));
}

test "peer_key differentiates IPv4 and IPv6" {
    const v4 = try std.net.Address.parseIp("127.0.0.1", 5683);
    const v6 = try std.net.Address.parseIp("::1", 5683);
    try testing.expect(Exchange.peer_key(v4, 0x1234) != Exchange.peer_key(v6, 0x1234));
}

test "addr_hash different IPv6 addresses produce different hashes" {
    const a = try std.net.Address.parseIp("::1", 5683);
    const b = try std.net.Address.parseIp("fe80::1", 5683);
    try testing.expect(Exchange.addr_hash(a) != Exchange.addr_hash(b));
}
