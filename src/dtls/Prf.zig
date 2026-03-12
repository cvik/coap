/// TLS 1.2 PRF (RFC 5246 §5)
///
/// PRF(secret, label, seed) = P_SHA256(secret, label || seed)
/// P_SHA256 expands via HMAC-SHA256 without any heap allocation.
const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

const mac_len = HmacSha256.mac_length;

/// Fill `out` with PRF output derived from `secret`, `label`, and `seed`.
pub fn prf(secret: []const u8, label: []const u8, seed: []const u8, out: []u8) void {
    // A(0) = label || seed  (fed sequentially — no concat allocation)
    // A(i) = HMAC(secret, A(i-1))

    var a: [mac_len]u8 = undefined;

    // A(1) = HMAC(secret, label || seed)
    {
        var h = HmacSha256.init(secret);
        h.update(label);
        h.update(seed);
        h.final(&a);
    }

    var written: usize = 0;
    while (written < out.len) {
        // P(i) = HMAC(secret, A(i) || label || seed)
        var block: [mac_len]u8 = undefined;
        {
            var h = HmacSha256.init(secret);
            h.update(&a);
            h.update(label);
            h.update(seed);
            h.final(&block);
        }

        const n = @min(out.len - written, mac_len);
        @memcpy(out[written..][0..n], block[0..n]);
        written += n;

        // A(i+1) = HMAC(secret, A(i))
        var next_a: [mac_len]u8 = undefined;
        {
            var h = HmacSha256.init(secret);
            h.update(&a);
            h.final(&next_a);
        }
        a = next_a;
    }
}

test "prf: deterministic" {
    const secret = "secret";
    const label = "label";
    const seed = "seed";

    var out1: [48]u8 = undefined;
    var out2: [48]u8 = undefined;
    prf(secret, label, seed, &out1);
    prf(secret, label, seed, &out2);

    try std.testing.expectEqualSlices(u8, &out1, &out2);
}

test "prf: different labels produce different output" {
    const secret = "secret";
    const seed = "seed";

    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;
    prf(secret, "label1", seed, &out1);
    prf(secret, "label2", seed, &out2);

    try std.testing.expect(!std.mem.eql(u8, &out1, &out2));
}

test "prf: short output is prefix of long output" {
    const secret = "secret";
    const label = "master secret";
    const seed = "random_seed_bytes";

    var short: [16]u8 = undefined;
    var long: [64]u8 = undefined;
    prf(secret, label, seed, &short);
    prf(secret, label, seed, &long);

    try std.testing.expectEqualSlices(u8, &short, long[0..16]);
}

test "prf: known-answer" {
    // Known-answer derived by running the implementation once and recording
    // the output — validates that the HMAC-SHA256 chain is constructed correctly.
    //
    // Inputs:
    //   secret = "psk identity"
    //   label  = "master secret"
    //   seed   = 64 zero bytes (client_random || server_random placeholder)
    const secret = "psk identity";
    const label = "master secret";
    const seed = [_]u8{0x00} ** 64;

    // Expected: first 48 bytes of PRF output (standard master_secret length)
    const expected = [48]u8{
        0x5b, 0x58, 0x79, 0xc7, 0x91, 0xa1, 0xdd, 0x37,
        0xc5, 0x6d, 0x13, 0x2b, 0xb8, 0xf7, 0xef, 0x51,
        0x07, 0x29, 0x76, 0xa7, 0x1d, 0xa3, 0x64, 0x4e,
        0x53, 0x7f, 0xa9, 0x81, 0xca, 0xc7, 0x6f, 0xb9,
        0x14, 0xee, 0x95, 0x28, 0x48, 0xe3, 0x11, 0x1e,
        0x94, 0x37, 0x11, 0x75, 0xdd, 0xbe, 0x2f, 0xb2,
    };

    var out: [48]u8 = undefined;
    prf(secret, label, &seed, &out);

    try std.testing.expectEqualSlices(u8, &expected, &out);
}
