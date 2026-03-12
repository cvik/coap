/// Stateless DTLS cookie generation and verification (RFC 6347 §4.2.1).
///
/// Cookie = HMAC-SHA256(server_secret, client_addr_bytes || client_random)
const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Generate a stateless DTLS cookie.
pub fn generate(server_secret: [32]u8, client_addr: std.net.Address, client_random: [32]u8) [32]u8 {
    const addr_bytes: [16]u8 = @bitCast(client_addr.any);
    var mac: [32]u8 = undefined;
    var h = HmacSha256.init(&server_secret);
    h.update(&addr_bytes);
    h.update(&client_random);
    h.final(&mac);
    return mac;
}

/// Verify a DTLS cookie against a single server secret.
pub fn verify(server_secret: [32]u8, client_addr: std.net.Address, client_random: [32]u8, cookie: []const u8) bool {
    if (cookie.len != 32) return false;
    const expected = generate(server_secret, client_addr, client_random);
    return std.crypto.timing_safe.eql([32]u8, expected, cookie[0..32].*);
}

/// Verify with rotation: try current secret, then previous.
pub fn verifyWithRotation(current_secret: [32]u8, previous_secret: [32]u8, client_addr: std.net.Address, client_random: [32]u8, cookie: []const u8) bool {
    return verify(current_secret, client_addr, client_random, cookie) or
        verify(previous_secret, client_addr, client_random, cookie);
}

test "generate and verify round-trip" {
    const secret = [_]u8{0x42} ** 32;
    const addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 5684);
    const random = [_]u8{0xab} ** 32;

    const cookie = generate(secret, addr, random);
    try std.testing.expect(verify(secret, addr, random, &cookie));
}

test "verify fails with wrong address" {
    const secret = [_]u8{0x01} ** 32;
    const addr1 = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 5684);
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 5684);
    const random = [_]u8{0x22} ** 32;

    const cookie = generate(secret, addr1, random);
    try std.testing.expect(!verify(secret, addr2, random, &cookie));
}

test "verify fails with wrong secret" {
    const secret1 = [_]u8{0x01} ** 32;
    const secret2 = [_]u8{0x02} ** 32;
    const addr = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 5684);
    const random = [_]u8{0x33} ** 32;

    const cookie = generate(secret1, addr, random);
    try std.testing.expect(!verify(secret2, addr, random, &cookie));
}

test "verify fails with wrong length (truncated cookie)" {
    const secret = [_]u8{0x55} ** 32;
    const addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 5684);
    const random = [_]u8{0x66} ** 32;

    const cookie = generate(secret, addr, random);
    try std.testing.expect(!verify(secret, addr, random, cookie[0..16]));
    try std.testing.expect(!verify(secret, addr, random, cookie[0..0]));
    try std.testing.expect(!verify(secret, addr, random, cookie[0..31]));
}

test "verify fails with wrong client_random" {
    const secret = [_]u8{0x77} ** 32;
    const addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 5684);
    const random1 = [_]u8{0x88} ** 32;
    const random2 = [_]u8{0x99} ** 32;

    const cookie = generate(secret, addr, random1);
    try std.testing.expect(!verify(secret, addr, random2, &cookie));
}

test "verifyWithRotation accepts cookie from previous secret" {
    const current = [_]u8{0xaa} ** 32;
    const previous = [_]u8{0xbb} ** 32;
    const addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 5684);
    const random = [_]u8{0xcc} ** 32;

    const cookie = generate(previous, addr, random);
    try std.testing.expect(verifyWithRotation(current, previous, addr, random, &cookie));
    // also ensure current-secret cookies pass
    const cookie2 = generate(current, addr, random);
    try std.testing.expect(verifyWithRotation(current, previous, addr, random, &cookie2));
}

test "verifyWithRotation rejects cookie from neither secret" {
    const current = [_]u8{0xdd} ** 32;
    const previous = [_]u8{0xee} ** 32;
    const other = [_]u8{0xff} ** 32;
    const addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 5684);
    const random = [_]u8{0x11} ** 32;

    const cookie = generate(other, addr, random);
    try std.testing.expect(!verifyWithRotation(current, previous, addr, random, &cookie));
}
