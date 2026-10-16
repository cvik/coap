//! Private, versioned benchmark control protocol. No cross-machine clock comparison.
const std = @import("std");
pub const version: u8 = 1;
pub const nonce_len = 16;
pub const start_len = 21;
pub const stats_len = 48;
pub const max_requests: u32 = 16_000_000;
pub const Mode = enum(u8) { con = 0, non = 1 };
pub const Start = struct {
    nonce: [nonce_len]u8,
    expected: u32,
    mode: Mode,
    pub fn encode(self: Start) [start_len]u8 {
        var bytes: [start_len]u8 = undefined;
        @memcpy(bytes[0..16], &self.nonce);
        std.mem.writeInt(u32, bytes[16..20], self.expected, .big);
        bytes[20] = @backingInt(self.mode);
        return bytes;
    }
    pub fn decode(bytes: []const u8) !Start {
        if (bytes.len != start_len) return error.InvalidStart;
        const count = std.mem.readInt(u32, bytes[16..20], .big);
        if (count == 0 or count > max_requests or bytes[20] > 1) return error.InvalidStart;
        return .{ .nonce = bytes[0..16].*, .expected = count, .mode = @fromBackingInt(@intCast(bytes[20])) };
    }
};
pub const Stats = struct {
    received: u64 = 0,
    duplicates: u64 = 0,
    elapsed_ns: u64 = 0,
    idle_ns: u64 = 0,
    expected: u32 = 0,
    capacity: u32 = 0,
    active: bool = false,
    tracking_failed: bool = false,
    pub fn encode(self: Stats) [stats_len]u8 {
        var bytes: [stats_len]u8 = @splat(0);
        @memcpy(bytes[0..4], "CBEN");
        bytes[4] = version;
        bytes[5] = @as(u8, @intFromBool(self.active)) | (@as(u8, @intFromBool(self.tracking_failed)) << 1);
        std.mem.writeInt(u64, bytes[8..16], self.received, .big);
        std.mem.writeInt(u64, bytes[16..24], self.duplicates, .big);
        std.mem.writeInt(u64, bytes[24..32], self.elapsed_ns, .big);
        std.mem.writeInt(u64, bytes[32..40], self.idle_ns, .big);
        std.mem.writeInt(u32, bytes[40..44], self.expected, .big);
        std.mem.writeInt(u32, bytes[44..48], self.capacity, .big);
        return bytes;
    }
    pub fn decode(bytes: []const u8) !Stats {
        if (bytes.len != stats_len or !std.mem.eql(u8, bytes[0..4], "CBEN")) return error.NotBenchmarkServer;
        if (bytes[4] != version) return error.UnsupportedBenchmarkVersion;
        if (bytes[5] & ~@as(u8, 3) != 0 or bytes[6] != 0 or bytes[7] != 0) return error.InvalidStats;
        return .{ .received = std.mem.readInt(u64, bytes[8..16], .big), .duplicates = std.mem.readInt(u64, bytes[16..24], .big), .elapsed_ns = std.mem.readInt(u64, bytes[24..32], .big), .idle_ns = std.mem.readInt(u64, bytes[32..40], .big), .expected = std.mem.readInt(u32, bytes[40..44], .big), .capacity = std.mem.readInt(u32, bytes[44..48], .big), .active = bytes[5] & 1 != 0, .tracking_failed = bytes[5] & 2 != 0 };
    }
};
pub fn token(prefix: [4]u8, id: u32) [8]u8 {
    var bytes: [8]u8 = undefined;
    @memcpy(bytes[0..4], &prefix);
    std.mem.writeInt(u32, bytes[4..8], id, .big);
    return bytes;
}
test "protocol rejects malformed bounds, flags and reserved bytes" {
    const start: Start = .{ .nonce = @splat(0), .expected = 0, .mode = .non };
    var bytes = start.encode();
    try std.testing.expectError(error.InvalidStart, Start.decode(&bytes));
    std.mem.writeInt(u32, bytes[16..20], max_requests + 1, .big);
    try std.testing.expectError(error.InvalidStart, Start.decode(&bytes));
    std.mem.writeInt(u32, bytes[16..20], 1, .big);
    bytes[20] = 2;
    try std.testing.expectError(error.InvalidStart, Start.decode(&bytes));
    var stats = (Stats{}).encode();
    try std.testing.expectError(error.NotBenchmarkServer, Stats.decode(stats[0..47]));
    stats[5] = 4;
    try std.testing.expectError(error.InvalidStats, Stats.decode(&stats));
    stats[5] = 0;
    stats[6] = 1;
    try std.testing.expectError(error.InvalidStats, Stats.decode(&stats));
}

test "protocol bounded encoding and validation" {
    const start: Start = .{ .nonce = @splat(7), .expected = 100000, .mode = .non };
    const bytes = start.encode();
    try std.testing.expectEqualDeep(start, try Start.decode(&bytes));
    try std.testing.expectError(error.InvalidStart, Start.decode(bytes[0..20]));
    const stats: Stats = .{ .received = 99999, .expected = 100000, .capacity = max_requests, .elapsed_ns = 42, .active = true };
    var encoded = stats.encode();
    try std.testing.expectEqualDeep(stats, try Stats.decode(&encoded));
    encoded[4] = 2;
    try std.testing.expectError(error.UnsupportedBenchmarkVersion, Stats.decode(&encoded));
    const t = token(.{ 1, 2, 3, 4 }, 65536);
    try std.testing.expectEqual(@as(u32, 65536), std.mem.readInt(u32, t[4..8], .big));
}
