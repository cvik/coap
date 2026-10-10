/// Stateless DTLS cookie generation and verification (RFC 6347 §4.2.1).
///
/// Cookie = HMAC-SHA256(server_secret, client_addr_bytes || client_random)
const std = @import("std");
const platform = @import("../platform.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Generate a stateless DTLS cookie.
pub fn generate(server_secret: [32]u8, client_addr: std.Io.net.IpAddress, client_random: [32]u8) [32]u8 {
    var mac: [32]u8 = undefined;
    var h = HmacSha256.init(&server_secret);
    // Canonical socket bytes avoid hashing padding in native address types.
    const sa = platform.SocketAddress.init(client_addr);
    h.update(sa.bytes());
    h.update(&client_random);
    h.final(&mac);
    return mac;
}

/// Verify a DTLS cookie against a single server secret.
pub fn verify(server_secret: [32]u8, client_addr: std.Io.net.IpAddress, client_random: [32]u8, cookie: []const u8) bool {
    if (cookie.len != 32) return false;
    const expected = generate(server_secret, client_addr, client_random);
    return std.crypto.timing_safe.eql([32]u8, expected, cookie[0..32].*);
}

/// Verify with rotation: try current secret, then previous.
pub fn verifyWithRotation(current_secret: [32]u8, previous_secret: [32]u8, client_addr: std.Io.net.IpAddress, client_random: [32]u8, cookie: []const u8) bool {
    return verify(current_secret, client_addr, client_random, cookie) or
        verify(previous_secret, client_addr, client_random, cookie);
}

test "generate and verify round-trip" {
    const secret: [32]u8 = @splat(0x42);
    const addr = platform.ip4([4]u8{ 127, 0, 0, 1 }, 5684);
    const random: [32]u8 = @splat(0xab);

    const cookie = generate(secret, addr, random);
    try std.testing.expect(verify(secret, addr, random, &cookie));
}

test "verify fails with wrong address" {
    const secret: [32]u8 = @splat(0x01);
    const addr1 = platform.ip4([4]u8{ 127, 0, 0, 1 }, 5684);
    const addr2 = platform.ip4([4]u8{ 192, 168, 1, 1 }, 5684);
    const random: [32]u8 = @splat(0x22);

    const cookie = generate(secret, addr1, random);
    try std.testing.expect(!verify(secret, addr2, random, &cookie));
}

test "verify fails with wrong secret" {
    const secret1: [32]u8 = @splat(0x01);
    const secret2: [32]u8 = @splat(0x02);
    const addr = platform.ip4([4]u8{ 10, 0, 0, 1 }, 5684);
    const random: [32]u8 = @splat(0x33);

    const cookie = generate(secret1, addr, random);
    try std.testing.expect(!verify(secret2, addr, random, &cookie));
}

test "verify fails with wrong length (truncated cookie)" {
    const secret: [32]u8 = @splat(0x55);
    const addr = platform.ip4([4]u8{ 127, 0, 0, 1 }, 5684);
    const random: [32]u8 = @splat(0x66);

    const cookie = generate(secret, addr, random);
    try std.testing.expect(!verify(secret, addr, random, cookie[0..16]));
    try std.testing.expect(!verify(secret, addr, random, cookie[0..0]));
    try std.testing.expect(!verify(secret, addr, random, cookie[0..31]));
}

test "verify fails with wrong client_random" {
    const secret: [32]u8 = @splat(0x77);
    const addr = platform.ip4([4]u8{ 127, 0, 0, 1 }, 5684);
    const random1: [32]u8 = @splat(0x88);
    const random2: [32]u8 = @splat(0x99);

    const cookie = generate(secret, addr, random1);
    try std.testing.expect(!verify(secret, addr, random2, &cookie));
}

test "verifyWithRotation accepts cookie from previous secret" {
    const current: [32]u8 = @splat(0xaa);
    const previous: [32]u8 = @splat(0xbb);
    const addr = platform.ip4([4]u8{ 127, 0, 0, 1 }, 5684);
    const random: [32]u8 = @splat(0xcc);

    const cookie = generate(previous, addr, random);
    try std.testing.expect(verifyWithRotation(current, previous, addr, random, &cookie));
    // also ensure current-secret cookies pass
    const cookie2 = generate(current, addr, random);
    try std.testing.expect(verifyWithRotation(current, previous, addr, random, &cookie2));
}

test "verifyWithRotation rejects cookie from neither secret" {
    const current: [32]u8 = @splat(0xdd);
    const previous: [32]u8 = @splat(0xee);
    const other: [32]u8 = @splat(0xff);
    const addr = platform.ip4([4]u8{ 127, 0, 0, 1 }, 5684);
    const random: [32]u8 = @splat(0x11);

    const cookie = generate(other, addr, random);
    try std.testing.expect(!verifyWithRotation(current, previous, addr, random, &cookie));
}
