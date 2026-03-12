/// AES-128-CCM-8 AEAD implementation for DTLS 1.2.
///
/// CCM = CTR encryption + CBC-MAC authentication (RFC 3610).
/// Parameters:
///   Key:   16 bytes (AES-128)
///   Nonce: 12 bytes → L = 15 - 12 = 3 (3-byte counter field)
///   Tag:   8 bytes (CCM-8)
const std = @import("std");
const Aes128 = std.crypto.core.aes.Aes128;
const AesEncryptCtx = std.crypto.core.aes.AesEncryptCtx;

const tag_len = 8;
const key_len = 16;
const nonce_len = 12;
const block_len = 16;

// CCM parameters for nonce_len = 12:
//   L  = 15 - nonce_len = 3  (length field bytes)
//   L' = L - 1 = 2           (encoded as bits 2:0)
//   M' = (tag_len - 2) / 2 = 3 (encoded as bits 5:3)
const l_param = 3; // length field bytes
const l_prime = l_param - 1; // = 2
const m_prime = (tag_len - 2) / 2; // = 3

// B0 flags: bit6 = Adata, bits5:3 = M', bits2:0 = L'
const b0_flags_no_ad: u8 = (0 << 6) | (m_prime << 3) | l_prime;
const b0_flags_ad: u8 = (1 << 6) | (m_prime << 3) | l_prime;

// Counter block flags: reserved bits 0, bits2:0 = L'
const ctr_flags: u8 = l_prime;

/// Encrypt plaintext with AES-128-CCM-8.
/// out.len must equal plaintext.len + tag_len (8).
pub fn encrypt(plaintext: []const u8, ad: []const u8, nonce: [nonce_len]u8, key: [key_len]u8, out: []u8) void {
    std.debug.assert(out.len == plaintext.len + tag_len);

    const aes = Aes128.initEnc(key);

    // Step 1: CBC-MAC over B0 + AD + plaintext
    const mac_tag: [block_len]u8 = computeCbcMac(aes, plaintext, ad, nonce);

    // Step 2: Encrypt plaintext with AES-CTR (counter starts at 1)
    ctrEncrypt(aes, nonce, plaintext, out[0..plaintext.len]);

    // Step 3: Encrypt the tag with AES-CTR counter 0
    var ctr0_block: [block_len]u8 = makeCtrBlock(nonce, 0);
    var ctr0_enc: [block_len]u8 = undefined;
    aes.encrypt(&ctr0_enc, &ctr0_block);
    for (0..tag_len) |i| {
        out[plaintext.len + i] = mac_tag[i] ^ ctr0_enc[i];
    }
}

/// Decrypt and authenticate ciphertext_and_tag with AES-128-CCM-8.
/// ciphertext_and_tag.len must be >= tag_len (8).
/// out.len must equal ciphertext_and_tag.len - tag_len.
/// Returns error.AuthenticationFailed if authentication fails.
pub fn decrypt(ciphertext_and_tag: []const u8, ad: []const u8, nonce: [nonce_len]u8, key: [key_len]u8, out: []u8) error{AuthenticationFailed}!void {
    std.debug.assert(ciphertext_and_tag.len >= tag_len);
    std.debug.assert(out.len == ciphertext_and_tag.len - tag_len);

    const ciphertext = ciphertext_and_tag[0..out.len];
    const received_tag = ciphertext_and_tag[out.len..][0..tag_len];

    const aes = Aes128.initEnc(key);

    // Step 1: Decrypt ciphertext with AES-CTR (counter starts at 1) into out
    ctrEncrypt(aes, nonce, ciphertext, out);

    // Step 2: Compute CBC-MAC over the decrypted plaintext
    const mac_tag: [block_len]u8 = computeCbcMac(aes, out, ad, nonce);

    // Step 3: Decrypt the expected tag using AES-CTR counter 0
    var ctr0_block: [block_len]u8 = makeCtrBlock(nonce, 0);
    var ctr0_enc: [block_len]u8 = undefined;
    aes.encrypt(&ctr0_enc, &ctr0_block);
    var expected_tag: [tag_len]u8 = undefined;
    for (0..tag_len) |i| {
        expected_tag[i] = mac_tag[i] ^ ctr0_enc[i];
    }

    // Step 4: Constant-time tag comparison
    if (!std.crypto.timing_safe.eql([tag_len]u8, expected_tag, received_tag[0..tag_len].*)) {
        std.crypto.secureZero(u8, out);
        return error.AuthenticationFailed;
    }
}

/// Build the CCM counter block for a given counter value.
/// Format: flags || nonce || counter (3 bytes, big-endian)
fn makeCtrBlock(nonce: [nonce_len]u8, counter: u24) [block_len]u8 {
    var block: [block_len]u8 = undefined;
    block[0] = ctr_flags;
    @memcpy(block[1..1 + nonce_len], &nonce);
    // 3-byte big-endian counter at bytes 13..15
    block[13] = @intCast((counter >> 16) & 0xFF);
    block[14] = @intCast((counter >> 8) & 0xFF);
    block[15] = @intCast(counter & 0xFF);
    return block;
}

/// AES-CTR encryption/decryption (symmetric operation).
/// Counter starts at 1. Writes to dst which must be same length as src.
fn ctrEncrypt(aes: AesEncryptCtx(Aes128), nonce: [nonce_len]u8, src: []const u8, dst: []u8) void {
    std.debug.assert(dst.len == src.len);
    var counter: u24 = 1;
    var offset: usize = 0;
    while (offset < src.len) : (offset += block_len) {
        const ctr_block = makeCtrBlock(nonce, counter);
        var keystream: [block_len]u8 = undefined;
        aes.encrypt(&keystream, &ctr_block);
        const chunk_len = @min(block_len, src.len - offset);
        for (0..chunk_len) |i| {
            dst[offset + i] = src[offset + i] ^ keystream[i];
        }
        counter += 1;
    }
}

/// Compute CBC-MAC per RFC 3610.
/// Returns the full 16-byte CBC-MAC value.
fn computeCbcMac(aes: AesEncryptCtx(Aes128), plaintext: []const u8, ad: []const u8, nonce: [nonce_len]u8) [block_len]u8 {
    var x: [block_len]u8 = undefined;

    // Build and process B0
    var b0: [block_len]u8 = undefined;
    b0[0] = if (ad.len > 0) b0_flags_ad else b0_flags_no_ad;
    @memcpy(b0[1..1 + nonce_len], &nonce);
    // 3-byte big-endian message length at bytes 13..15
    const msg_len = plaintext.len;
    b0[13] = @intCast((msg_len >> 16) & 0xFF);
    b0[14] = @intCast((msg_len >> 8) & 0xFF);
    b0[15] = @intCast(msg_len & 0xFF);

    aes.encrypt(&x, &b0);

    // Process additional data (if any)
    if (ad.len > 0) {
        // For ad.len < 65280 (0xFF00): 2-byte big-endian length prefix
        // Standard DTLS records are well under this limit.
        std.debug.assert(ad.len < 0xFF00);

        // Treat the AD encoding as a stream: 2-byte length prefix then AD bytes,
        // processed in 16-byte blocks (zero-padded at the end).
        // Use a temp buffer to build each block, XOR into x, then AES-encrypt.
        var tmp: [block_len]u8 = undefined;

        // Build the first AD block: [len_hi, len_lo, ad[0..14 or less]]
        var ad_block: [block_len]u8 = [_]u8{0} ** block_len;
        ad_block[0] = @intCast((ad.len >> 8) & 0xFF);
        ad_block[1] = @intCast(ad.len & 0xFF);
        const first_chunk = @min(block_len - 2, ad.len);
        for (0..first_chunk) |i| ad_block[2 + i] = ad[i];

        for (0..block_len) |i| x[i] ^= ad_block[i];
        aes.encrypt(&tmp, &x);
        x = tmp;

        // Process remaining AD bytes in 16-byte blocks
        var ad_offset: usize = first_chunk;
        while (ad_offset < ad.len) {
            const chunk_len = @min(block_len, ad.len - ad_offset);
            for (0..chunk_len) |i| x[i] ^= ad[ad_offset + i];
            aes.encrypt(&tmp, &x);
            x = tmp;
            ad_offset += chunk_len;
        }
    }

    // Process plaintext in 16-byte blocks
    var pt_offset: usize = 0;
    while (pt_offset < plaintext.len) : (pt_offset += block_len) {
        const chunk_len = @min(block_len, plaintext.len - pt_offset);
        var tmp: [block_len]u8 = undefined;
        for (0..chunk_len) |i| x[i] ^= plaintext[pt_offset + i];
        // Remaining bytes: no XOR needed (XOR with 0 = identity), already in x
        aes.encrypt(&tmp, &x);
        x = tmp;
    }

    return x;
}

// ----- Tests -----

const testing = std.testing;

test "round-trip: basic encrypt/decrypt" {
    const key = [_]u8{0x01} ** key_len;
    const nonce = [_]u8{0x02} ** nonce_len;
    const plaintext = "Hello, DTLS!";
    const ad = "additional data";

    var ciphertext: [plaintext.len + tag_len]u8 = undefined;
    encrypt(plaintext, ad, nonce, key, &ciphertext);

    var recovered: [plaintext.len]u8 = undefined;
    try decrypt(&ciphertext, ad, nonce, key, &recovered);
    try testing.expectEqualSlices(u8, plaintext, &recovered);
}

test "authentication failure on tampered ciphertext" {
    const key = [_]u8{0xAB} ** key_len;
    const nonce = [_]u8{0xCD} ** nonce_len;
    const plaintext = "secret message";
    const ad = "header";

    var ciphertext: [plaintext.len + tag_len]u8 = undefined;
    encrypt(plaintext, ad, nonce, key, &ciphertext);

    // Tamper with first byte of ciphertext
    ciphertext[0] ^= 0xFF;

    var recovered: [plaintext.len]u8 = undefined;
    const result = decrypt(&ciphertext, ad, nonce, key, &recovered);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "authentication failure on tampered tag" {
    const key = [_]u8{0x11} ** key_len;
    const nonce = [_]u8{0x22} ** nonce_len;
    const plaintext = "data";
    const ad = "ad";

    var ciphertext: [plaintext.len + tag_len]u8 = undefined;
    encrypt(plaintext, ad, nonce, key, &ciphertext);

    // Tamper with tag
    ciphertext[plaintext.len] ^= 0x01;

    var recovered: [plaintext.len]u8 = undefined;
    const result = decrypt(&ciphertext, ad, nonce, key, &recovered);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "empty plaintext (tag only)" {
    const key = [_]u8{0x42} ** key_len;
    const nonce = [_]u8{0x99} ** nonce_len;
    const plaintext = "";
    const ad = "some header";

    var ciphertext: [plaintext.len + tag_len]u8 = undefined;
    encrypt(plaintext, ad, nonce, key, &ciphertext);
    // Output should be exactly tag_len bytes
    try testing.expectEqual(@as(usize, tag_len), ciphertext.len);

    var recovered: [plaintext.len]u8 = undefined;
    try decrypt(&ciphertext, ad, nonce, key, &recovered);
}

test "empty plaintext empty ad" {
    const key = [_]u8{0x55} ** key_len;
    const nonce = [_]u8{0x66} ** nonce_len;

    var ciphertext: [tag_len]u8 = undefined;
    encrypt("", "", nonce, key, &ciphertext);

    var recovered: [0]u8 = undefined;
    try decrypt(&ciphertext, "", nonce, key, &recovered);
}

test "1-byte plaintext" {
    const key = [_]u8{0xAA} ** key_len;
    const nonce = [_]u8{0xBB} ** nonce_len;
    const plaintext = [_]u8{0xFF};
    const ad = "hdr";

    var ciphertext: [plaintext.len + tag_len]u8 = undefined;
    encrypt(&plaintext, ad, nonce, key, &ciphertext);

    var recovered: [plaintext.len]u8 = undefined;
    try decrypt(&ciphertext, ad, nonce, key, &recovered);
    try testing.expectEqualSlices(u8, &plaintext, &recovered);
}

test "16-byte plaintext (exact block)" {
    const key = [_]u8{0x12} ** key_len;
    const nonce = [_]u8{0x34} ** nonce_len;
    const plaintext = [_]u8{0x56} ** block_len;
    const ad = "block-aligned";

    var ciphertext: [plaintext.len + tag_len]u8 = undefined;
    encrypt(&plaintext, ad, nonce, key, &ciphertext);

    var recovered: [plaintext.len]u8 = undefined;
    try decrypt(&ciphertext, ad, nonce, key, &recovered);
    try testing.expectEqualSlices(u8, &plaintext, &recovered);
}

test "17-byte plaintext (crosses block boundary)" {
    const key = [_]u8{0x78} ** key_len;
    const nonce = [_]u8{0x9A} ** nonce_len;
    const plaintext = [_]u8{0xBC} ** 17;
    const ad = "cross-block";

    var ciphertext: [plaintext.len + tag_len]u8 = undefined;
    encrypt(&plaintext, ad, nonce, key, &ciphertext);

    var recovered: [plaintext.len]u8 = undefined;
    try decrypt(&ciphertext, ad, nonce, key, &recovered);
    try testing.expectEqualSlices(u8, &plaintext, &recovered);
}

test "32-byte plaintext (two full blocks)" {
    const key = [_]u8{0xDE} ** key_len;
    const nonce = [_]u8{0xAD} ** nonce_len;
    const plaintext = [_]u8{0xBE} ** 32;
    const ad = "two blocks";

    var ciphertext: [plaintext.len + tag_len]u8 = undefined;
    encrypt(&plaintext, ad, nonce, key, &ciphertext);

    var recovered: [plaintext.len]u8 = undefined;
    try decrypt(&ciphertext, ad, nonce, key, &recovered);
    try testing.expectEqualSlices(u8, &plaintext, &recovered);
}

test "wrong AD causes authentication failure" {
    const key = [_]u8{0x33} ** key_len;
    const nonce = [_]u8{0x44} ** nonce_len;
    const plaintext = "payload";
    const ad = "correct-ad";

    var ciphertext: [plaintext.len + tag_len]u8 = undefined;
    encrypt(plaintext, ad, nonce, key, &ciphertext);

    var recovered: [plaintext.len]u8 = undefined;
    const result = decrypt(&ciphertext, "wrong-ad", nonce, key, &recovered);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "output zeroed on auth failure" {
    const key = [_]u8{0x77} ** key_len;
    const nonce = [_]u8{0x88} ** nonce_len;
    const plaintext = "sensitive";
    const ad = "hdr";

    var ciphertext: [plaintext.len + tag_len]u8 = undefined;
    encrypt(plaintext, ad, nonce, key, &ciphertext);

    // Tamper
    ciphertext[0] ^= 0x01;

    var recovered: [plaintext.len]u8 = [_]u8{0xFF} ** plaintext.len;
    _ = decrypt(&ciphertext, ad, nonce, key, &recovered) catch {};
    // After auth failure, output should be zeroed
    try testing.expectEqualSlices(u8, &([_]u8{0} ** plaintext.len), &recovered);
}

test "different nonces produce different ciphertexts" {
    const key = [_]u8{0xEE} ** key_len;
    const nonce1 = [_]u8{0x01} ** nonce_len;
    const nonce2 = [_]u8{0x02} ** nonce_len;
    const plaintext = "same plaintext";
    const ad = "same ad";

    var ct1: [plaintext.len + tag_len]u8 = undefined;
    var ct2: [plaintext.len + tag_len]u8 = undefined;
    encrypt(plaintext, ad, nonce1, key, &ct1);
    encrypt(plaintext, ad, nonce2, key, &ct2);

    // Ciphertexts must differ
    try testing.expect(!std.mem.eql(u8, &ct1, &ct2));

    // Both must decrypt correctly
    var r1: [plaintext.len]u8 = undefined;
    var r2: [plaintext.len]u8 = undefined;
    try decrypt(&ct1, ad, nonce1, key, &r1);
    try decrypt(&ct2, ad, nonce2, key, &r2);
    try testing.expectEqualSlices(u8, plaintext, &r1);
    try testing.expectEqualSlices(u8, plaintext, &r2);
}
