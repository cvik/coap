/// DTLS 1.2 session table.
///
/// Pre-allocated open-addressed hash table with intrusive LRU doubly-linked
/// list and free list. Provides O(1) lookup, allocation, and eviction.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const State = enum(u8) {
    free,
    handshaking,
    established,
};

pub const ServerHandshakeState = enum(u8) {
    idle,
    expect_client_hello,
    cookie_sent,
    expect_client_key_exchange,
    expect_change_cipher_spec,
    expect_finished,
    complete,
};

pub const Config = struct {
    capacity: u32 = 65536,
    timeout_s: u16 = 300,
};

pub const Session = struct {
    state: State,
    peer_hash: u64,
    addr: std.net.Address,

    // Crypto state
    client_write_key: [16]u8,
    server_write_key: [16]u8,
    client_write_iv: [4]u8,
    server_write_iv: [4]u8,
    read_epoch: u16,
    write_epoch: u16,
    read_sequence: u48,
    write_sequence: u48,
    replay_window: u64,

    // Handshake state
    handshake_state: ServerHandshakeState,
    handshake_hash: Sha256,
    client_random: [32]u8,
    server_random: [32]u8,
    message_seq: u16,
    retransmit_deadline_ns: i64,
    retransmit_count: u8,
    retransmit_timeout_ms: u32,

    // Resumption-ready (unused in v1)
    master_secret: [48]u8,
    session_id: [32]u8,
    session_id_len: u8,

    // Eviction
    last_activity_ns: i64,
    lru_prev: u32,
    lru_next: u32,
    next_free: u32,

    pub fn zeroKeys(self: *Session) void {
        std.crypto.secureZero(u8, &self.client_write_key);
        std.crypto.secureZero(u8, &self.server_write_key);
        std.crypto.secureZero(u8, &self.client_write_iv);
        std.crypto.secureZero(u8, &self.server_write_iv);
        std.crypto.secureZero(u8, &self.master_secret);
        std.crypto.secureZero(u8, &self.client_random);
        std.crypto.secureZero(u8, &self.server_random);
    }
};

const empty_sentinel: u32 = 0xFFFFFFFF;

pub const SessionTable = struct {
    slots: []Session,
    /// Hash table mapping hash bucket -> slot index.
    /// Uses open addressing with linear probing.
    /// empty_sentinel = empty bucket.
    table: []u32,
    table_mask: u32,
    /// Head of intrusive free list through slots[i].next_free.
    free_head: u32,
    /// Most recently used (LRU head).
    lru_head: u32,
    /// Least recently used (eviction candidate).
    lru_tail: u32,
    count_active: u32,
    config: Config,

    pub fn init(allocator: std.mem.Allocator, config: Config) !SessionTable {
        if (config.capacity == 0) return error.InvalidConfig;

        const slots = try allocator.alloc(Session, config.capacity);
        errdefer allocator.free(slots);

        // Table size: next power of two >= 2 * capacity.
        const table_size: u32 = blk: {
            var size: u32 = 1;
            while (size < @as(u32, config.capacity) * 2) {
                size <<= 1;
            }
            break :blk size;
        };

        const table = try allocator.alloc(u32, table_size);
        errdefer allocator.free(table);

        // Init free list chain.
        for (slots, 0..) |*slot, i| {
            slot.state = .free;
            slot.next_free = if (i + 1 < config.capacity)
                @intCast(i + 1)
            else
                empty_sentinel;
        }

        @memset(table, empty_sentinel);

        return .{
            .slots = slots,
            .table = table,
            .table_mask = table_size - 1,
            .free_head = 0,
            .lru_head = empty_sentinel,
            .lru_tail = empty_sentinel,
            .count_active = 0,
            .config = config,
        };
    }

    pub fn deinit(self: *SessionTable, allocator: std.mem.Allocator) void {
        allocator.free(self.slots);
        allocator.free(self.table);
    }

    /// Look up a session by peer address.
    pub fn lookup(self: *SessionTable, addr: std.net.Address) ?*Session {
        const hash = addrHash(addr);
        var idx: u32 = @intCast(hash & self.table_mask);
        var probes: u32 = 0;

        while (probes <= self.table_mask) : (probes += 1) {
            const slot_idx = self.table[idx];
            if (slot_idx == empty_sentinel) return null;
            const session = &self.slots[slot_idx];
            if (session.peer_hash == hash and addrEqual(session.addr, addr)) {
                return session;
            }
            idx = (idx + 1) & self.table_mask;
        }
        return null;
    }

    /// Allocate a new session for the given address.
    /// Evicts LRU if no free slots remain. Returns null if capacity == 0.
    pub fn allocate(self: *SessionTable, addr: std.net.Address, now_ns: i64) ?*Session {
        if (self.config.capacity == 0) return null;

        // Get a free slot — either from free list or by evicting LRU.
        const slot_idx: u32 = if (self.free_head != empty_sentinel) blk: {
            const idx = self.free_head;
            self.free_head = self.slots[idx].next_free;
            break :blk idx;
        } else blk: {
            self.evictLru();
            // After eviction, free_head should have the newly freed slot.
            const idx = self.free_head;
            self.free_head = self.slots[idx].next_free;
            break :blk idx;
        };

        const session = &self.slots[slot_idx];

        // Initialize session fields.
        session.state = .handshaking;
        session.peer_hash = addrHash(addr);
        session.addr = addr;
        session.client_write_key = [_]u8{0} ** 16;
        session.server_write_key = [_]u8{0} ** 16;
        session.client_write_iv = [_]u8{0} ** 4;
        session.server_write_iv = [_]u8{0} ** 4;
        session.read_epoch = 0;
        session.write_epoch = 0;
        session.read_sequence = 0;
        session.write_sequence = 0;
        session.replay_window = 0;
        session.handshake_state = .idle;
        session.handshake_hash = Sha256.init(.{});
        session.client_random = [_]u8{0} ** 32;
        session.server_random = [_]u8{0} ** 32;
        session.message_seq = 0;
        session.retransmit_deadline_ns = 0;
        session.retransmit_count = 0;
        session.retransmit_timeout_ms = 0;
        session.master_secret = [_]u8{0} ** 48;
        session.session_id = [_]u8{0} ** 32;
        session.session_id_len = 0;
        session.last_activity_ns = now_ns;
        session.lru_prev = empty_sentinel;
        session.lru_next = empty_sentinel;
        session.next_free = empty_sentinel;

        self.insertIntoTable(slot_idx);
        self.lruPushFront(session);
        self.count_active += 1;

        return session;
    }

    /// Move a session to the LRU head and update last_activity_ns.
    pub fn promote(self: *SessionTable, session: *Session, now_ns: i64) void {
        session.last_activity_ns = now_ns;
        self.lruRemove(session);
        self.lruPushFront(session);
    }

    /// Release a session back to the free list, zeroing key material.
    pub fn release(self: *SessionTable, session: *Session) void {
        session.zeroKeys();
        const slot_idx = self.slotIndex(session);
        self.removeFromTable(slot_idx);
        self.lruRemove(session);
        session.state = .free;
        session.next_free = self.free_head;
        self.free_head = slot_idx;
        self.count_active -= 1;
    }

    // ── Internal helpers ─────────────────────────────────────────────

    fn slotIndex(self: *SessionTable, session: *Session) u32 {
        return @intCast(@divExact(
            @intFromPtr(session) - @intFromPtr(self.slots.ptr),
            @sizeOf(Session),
        ));
    }

    fn insertIntoTable(self: *SessionTable, slot_idx: u32) void {
        const hash = self.slots[slot_idx].peer_hash;
        var idx: u32 = @intCast(hash & self.table_mask);
        while (self.table[idx] != empty_sentinel) {
            idx = (idx + 1) & self.table_mask;
        }
        self.table[idx] = slot_idx;
    }

    fn removeFromTable(self: *SessionTable, slot_idx: u32) void {
        const hash = self.slots[slot_idx].peer_hash;
        var idx: u32 = @intCast(hash & self.table_mask);
        var probes: u32 = 0;

        while (probes <= self.table_mask) : (probes += 1) {
            const ti = self.table[idx];
            if (ti == empty_sentinel) return;
            if (ti == slot_idx) {
                // Found. Remove and rehash subsequent entries.
                self.table[idx] = empty_sentinel;
                self.rehashAfterRemove(idx);
                return;
            }
            idx = (idx + 1) & self.table_mask;
        }
    }

    fn rehashAfterRemove(self: *SessionTable, removed_idx: u32) void {
        var gap = removed_idx;
        var idx = (removed_idx + 1) & self.table_mask;
        while (self.table[idx] != empty_sentinel) {
            const si = self.table[idx];
            const desired: u32 = @intCast(self.slots[si].peer_hash & self.table_mask);
            if (wrappingDistance(desired, idx, self.table_mask) >=
                wrappingDistance(desired, gap, self.table_mask))
            {
                self.table[gap] = si;
                self.table[idx] = empty_sentinel;
                gap = idx;
            }
            idx = (idx + 1) & self.table_mask;
        }
    }

    fn lruRemove(self: *SessionTable, session: *Session) void {
        const slot_idx = self.slotIndex(session);
        const prev = session.lru_prev;
        const next = session.lru_next;

        if (prev != empty_sentinel) {
            self.slots[prev].lru_next = next;
        } else {
            // This was the head.
            self.lru_head = next;
        }

        if (next != empty_sentinel) {
            self.slots[next].lru_prev = prev;
        } else {
            // This was the tail.
            self.lru_tail = prev;
        }

        _ = slot_idx;
        session.lru_prev = empty_sentinel;
        session.lru_next = empty_sentinel;
    }

    fn lruPushFront(self: *SessionTable, session: *Session) void {
        const slot_idx = self.slotIndex(session);
        session.lru_prev = empty_sentinel;
        session.lru_next = self.lru_head;

        if (self.lru_head != empty_sentinel) {
            self.slots[self.lru_head].lru_prev = slot_idx;
        } else {
            // List was empty — this is also the tail.
            self.lru_tail = slot_idx;
        }

        self.lru_head = slot_idx;
    }

    fn evictLru(self: *SessionTable) void {
        std.debug.assert(self.lru_tail != empty_sentinel);
        const slot_idx = self.lru_tail;
        const session = &self.slots[slot_idx];

        session.zeroKeys();
        self.removeFromTable(slot_idx);
        self.lruRemove(session);

        session.state = .free;
        session.next_free = self.free_head;
        self.free_head = slot_idx;
        self.count_active -= 1;
    }
};

fn addrHash(addr: std.net.Address) u64 {
    const addr_bytes: [16]u8 = @bitCast(addr.any);
    var hash: u64 = 0xcbf29ce484222325; // FNV-1a 64-bit offset basis
    for (addr_bytes) |b| {
        hash ^= b;
        hash *%= 0x100000001b3; // FNV-1a 64-bit prime
    }
    return hash;
}

fn addrEqual(a: std.net.Address, b: std.net.Address) bool {
    const ab: [16]u8 = @bitCast(a.any);
    const bb: [16]u8 = @bitCast(b.any);
    return std.mem.eql(u8, &ab, &bb);
}

fn wrappingDistance(from: u32, to: u32, mask: u32) u32 {
    return (to -% from) & mask;
}

// ── Tests ────────────────────────────────────────────────────────────

const testing = std.testing;

test "init and deinit" {
    var tbl = try SessionTable.init(testing.allocator, .{ .capacity = 8 });
    defer tbl.deinit(testing.allocator);

    try testing.expectEqual(@as(u32, 0), tbl.count_active);
}

test "allocate and lookup" {
    var tbl = try SessionTable.init(testing.allocator, .{ .capacity = 8 });
    defer tbl.deinit(testing.allocator);

    const addr = try std.net.Address.parseIp("127.0.0.1", 5684);
    const session = tbl.allocate(addr, 0).?;

    try testing.expectEqual(State.handshaking, session.state);
    try testing.expectEqual(@as(u32, 1), tbl.count_active);

    const found = tbl.lookup(addr);
    try testing.expect(found != null);
    try testing.expectEqual(session, found.?);
}

test "lookup returns null for unknown" {
    var tbl = try SessionTable.init(testing.allocator, .{ .capacity = 8 });
    defer tbl.deinit(testing.allocator);

    const addr = try std.net.Address.parseIp("10.0.0.1", 5684);
    try testing.expect(tbl.lookup(addr) == null);
}

test "release zeros key material" {
    var tbl = try SessionTable.init(testing.allocator, .{ .capacity = 8 });
    defer tbl.deinit(testing.allocator);

    const addr = try std.net.Address.parseIp("127.0.0.1", 5684);
    const session = tbl.allocate(addr, 0).?;

    @memset(&session.client_write_key, 0xFF);
    @memset(&session.server_write_key, 0xFF);
    @memset(&session.master_secret, 0xFF);

    tbl.release(session);

    try testing.expectEqual(@as(u32, 0), tbl.count_active);
    // Keys should be zeroed by zeroKeys().
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &session.client_write_key);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &session.server_write_key);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 48), &session.master_secret);

    // Lookup should find nothing.
    try testing.expect(tbl.lookup(addr) == null);
}

test "LRU eviction when table full" {
    var tbl = try SessionTable.init(testing.allocator, .{ .capacity = 4 });
    defer tbl.deinit(testing.allocator);

    var addrs: [4]std.net.Address = undefined;
    for (0..4) |i| {
        addrs[i] = try std.net.Address.parseIp("10.0.0.1", @intCast(6000 + i));
        _ = tbl.allocate(addrs[i], @intCast(i));
    }
    try testing.expectEqual(@as(u32, 4), tbl.count_active);

    // The LRU tail is the oldest session (index 0, time 0).
    const oldest_addr = addrs[0];

    // Allocate 5th — should evict oldest (LRU tail).
    const new_addr = try std.net.Address.parseIp("10.0.0.2", 7000);
    _ = tbl.allocate(new_addr, 100).?;

    try testing.expectEqual(@as(u32, 4), tbl.count_active);
    try testing.expect(tbl.lookup(oldest_addr) == null);
    try testing.expect(tbl.lookup(new_addr) != null);
}

test "promote moves to LRU head" {
    var tbl = try SessionTable.init(testing.allocator, .{ .capacity = 4 });
    defer tbl.deinit(testing.allocator);

    var addrs: [4]std.net.Address = undefined;
    var sessions: [4]*Session = undefined;
    for (0..4) |i| {
        addrs[i] = try std.net.Address.parseIp("10.0.0.1", @intCast(6000 + i));
        sessions[i] = tbl.allocate(addrs[i], @intCast(i)).?;
    }
    // LRU order (tail → head): 0, 1, 2, 3

    // Promote session 0 (the LRU tail) to head.
    tbl.promote(sessions[0], 100);
    // LRU order (tail → head): 1, 2, 3, 0

    // Next eviction candidate is sessions[1] (addr index 1).
    const addr_new = try std.net.Address.parseIp("10.0.0.2", 7000);
    _ = tbl.allocate(addr_new, 200).?;

    // sessions[0] was promoted — should survive.
    try testing.expect(tbl.lookup(addrs[0]) != null);
    // sessions[1] should have been evicted.
    try testing.expect(tbl.lookup(addrs[1]) == null);
    // New address should be present.
    try testing.expect(tbl.lookup(addr_new) != null);
}
