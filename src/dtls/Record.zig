/// DTLS 1.2 record layer: encoding, decoding, encryption, and anti-replay.
const std = @import("std");
const Ccm = @import("Ccm.zig");
const types = @import("types.zig");

pub const Record = struct {
    content_type: types.ContentType,
    epoch: u16,
    sequence_number: u48,
    payload: []const u8,
};

const Header = struct {
    content_type: types.ContentType,
    epoch: u16,
    sequence_number: u48,
    length: u16,
};

/// Parse a 13-byte DTLS record header. Returns null on version mismatch or truncated buffer.
/// Layout: ContentType(1) | Version(2) | Epoch(2) | SequenceNumber(6) | Length(2)
fn parseHeader(buf: []const u8) ?Header {
    if (buf.len < types.record_header_len) return null;
    // Version check: must be DTLS 1.2 (0xFE 0xFD).
    if (buf[1] != 0xFE or buf[2] != 0xFD) return null;
    return .{
        .content_type = @as(types.ContentType, @enumFromInt(buf[0])),
        .epoch = std.mem.readInt(u16, buf[3..5], .big),
        .sequence_number = std.mem.readInt(u48, buf[5..11], .big),
        .length = std.mem.readInt(u16, buf[11..13], .big),
    };
}

/// Write a 13-byte DTLS record header into out[0..13].
fn writeHeader(
    out: []u8,
    content_type: types.ContentType,
    epoch: u16,
    sequence_number: u48,
    length: u16,
) void {
    std.debug.assert(out.len >= types.record_header_len);
    out[0] = @intFromEnum(content_type);
    // Version: DTLS 1.2 = 0xFE 0xFD
    out[1] = 0xFE;
    out[2] = 0xFD;
    std.mem.writeInt(u16, out[3..5], epoch, .big);
    std.mem.writeInt(u48, out[5..11], sequence_number, .big);
    std.mem.writeInt(u16, out[11..13], length, .big);
}

/// Build the 13-byte additional data for AEAD (RFC 5246 §6.2.3.3).
/// Layout: seq_num(8) || type(1) || version(2) || length(2)
/// where seq_num = epoch(2) || sequence_number(6) for DTLS.
fn buildAd(epoch: u16, seq: u48, content_type: types.ContentType, plaintext_len: u16) [types.record_header_len]u8 {
    var ad: [types.record_header_len]u8 = undefined;
    std.mem.writeInt(u16, ad[0..2], epoch, .big);
    std.mem.writeInt(u48, ad[2..8], seq, .big);
    ad[8] = @intFromEnum(content_type);
    ad[9] = 0xFE; // DTLS 1.2
    ad[10] = 0xFD;
    std.mem.writeInt(u16, ad[11..13], plaintext_len, .big);
    return ad;
}

/// Build the 8-byte explicit nonce: epoch(2) || seq(6), both big-endian.
fn buildExplicitNonce(epoch: u16, seq: u48) [types.explicit_nonce_len]u8 {
    var en: [types.explicit_nonce_len]u8 = undefined;
    std.mem.writeInt(u16, en[0..2], epoch, .big);
    std.mem.writeInt(u48, en[2..types.explicit_nonce_len], seq, .big);
    return en;
}

/// Build the 12-byte nonce for CCM: implicit_iv(4) || explicit_nonce(8).
fn buildNonce(implicit_iv: [4]u8, explicit_nonce: [types.explicit_nonce_len]u8) [12]u8 {
    var nonce: [12]u8 = undefined;
    @memcpy(nonce[0..4], &implicit_iv);
    @memcpy(nonce[4..12], &explicit_nonce);
    return nonce;
}

/// Anti-replay check and window update.
/// Returns true if the packet should be accepted (not a replay / not too old).
fn replayCheck(seq: u48, window: *u64, max_seq: *u48) bool {
    if (seq > max_seq.*) {
        const diff = seq - max_seq.*;
        if (diff >= 64) {
            // Gap too large — reset window entirely.
            window.* = 1;
        } else {
            const shift: u6 = @intCast(diff);
            window.* = (window.* << shift) | 1;
        }
        max_seq.* = seq;
        return true;
    }

    const diff = max_seq.* - seq;
    if (diff >= 64) return false; // Too old.

    const bit: u64 = @as(u64, 1) << @intCast(diff);
    if (window.* & bit != 0) return false; // Duplicate.

    window.* |= bit;
    return true;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encode a plaintext DTLS record (epoch 0).
/// Writes header(13) + payload into out. Advances sequence_number.
/// Returns the encoded slice.
pub fn encodePlaintext(
    content_type: types.ContentType,
    payload: []const u8,
    sequence_number: *u48,
    out: []u8,
) []const u8 {
    std.debug.assert(payload.len <= std.math.maxInt(u16));
    const total = types.record_header_len + payload.len;
    std.debug.assert(out.len >= total);

    writeHeader(out, content_type, 0, sequence_number.*, @intCast(payload.len));
    @memcpy(out[types.record_header_len..][0..payload.len], payload);
    sequence_number.* += 1;

    return out[0..total];
}

/// Encode an encrypted DTLS record (epoch >= 1).
/// Wire format: header(13) || explicit_nonce(8) || ciphertext || tag(8)
/// Returns the encoded slice.
pub fn encodeEncrypted(
    content_type: types.ContentType,
    plaintext: []const u8,
    write_key: [16]u8,
    write_iv: [4]u8,
    epoch: u16,
    sequence_number: *u48,
    out: []u8,
) []const u8 {
    std.debug.assert(plaintext.len + types.encryption_overhead <= std.math.maxInt(u16));
    const ciphertext_and_tag_len = plaintext.len + types.ccm8_tag_len;
    const record_len = types.explicit_nonce_len + ciphertext_and_tag_len;
    const total = types.record_header_len + record_len;
    std.debug.assert(out.len >= total);

    const seq = sequence_number.*;

    // Build explicit nonce.
    const explicit_nonce = buildExplicitNonce(epoch, seq);

    // Write header. Length field = explicit_nonce + ciphertext + tag.
    writeHeader(out, content_type, epoch, seq, @intCast(record_len));

    // Write explicit nonce.
    @memcpy(out[types.record_header_len..][0..types.explicit_nonce_len], &explicit_nonce);

    // Build AD with plaintext length (RFC 5246 §6.2.3.3 ordering).
    const ad = buildAd(epoch, seq, content_type, @intCast(plaintext.len));

    // Encrypt into out after the explicit nonce.
    const ct_slice = out[types.record_header_len + types.explicit_nonce_len ..][0..ciphertext_and_tag_len];
    const nonce = buildNonce(write_iv, explicit_nonce);
    Ccm.encrypt(plaintext, &ad, nonce, write_key, ct_slice);

    sequence_number.* += 1;

    return out[0..total];
}

/// Decode a plaintext DTLS record (epoch 0).
pub fn decodePlaintext(buf: []const u8) ?Record {
    const hdr = parseHeader(buf) orelse return null;
    if (hdr.epoch != 0) return null;

    const end = types.record_header_len + hdr.length;
    if (buf.len < end) return null;

    return .{
        .content_type = hdr.content_type,
        .epoch = hdr.epoch,
        .sequence_number = hdr.sequence_number,
        .payload = buf[types.record_header_len..end],
    };
}

/// Decode and decrypt a DTLS record (epoch >= 1).
/// Performs anti-replay check. Returns null on replay, auth failure, or malformed record.
pub fn decodeEncrypted(
    buf: []const u8,
    read_key: [16]u8,
    read_iv: [4]u8,
    replay_window: *u64,
    max_seq: *u48,
    plaintext_buf: []u8,
) ?Record {
    const hdr = parseHeader(buf) orelse return null;
    if (hdr.epoch == 0) return null;

    // record_len = explicit_nonce(8) + ciphertext + tag(8); minimum 16.
    if (hdr.length < types.encryption_overhead) return null;

    const end = types.record_header_len + hdr.length;
    if (buf.len < end) return null;

    const record_body = buf[types.record_header_len..end];
    const explicit_nonce: [types.explicit_nonce_len]u8 = record_body[0..types.explicit_nonce_len].*;
    const ct_and_tag = record_body[types.explicit_nonce_len..];
    const plaintext_len = ct_and_tag.len - types.ccm8_tag_len;

    if (plaintext_buf.len < plaintext_len) return null;

    // Save replay state for rollback on auth failure.
    const saved_window = replay_window.*;
    const saved_max_seq = max_seq.*;

    // Anti-replay check.
    if (!replayCheck(hdr.sequence_number, replay_window, max_seq)) return null;

    // Build AD with plaintext length (RFC 5246 §6.2.3.3 ordering).
    const ad = buildAd(hdr.epoch, hdr.sequence_number, hdr.content_type, @intCast(plaintext_len));

    const nonce = buildNonce(read_iv, explicit_nonce);
    const out_slice = plaintext_buf[0..plaintext_len];
    Ccm.decrypt(ct_and_tag, &ad, nonce, read_key, out_slice) catch {
        // Auth failed — restore replay window state.
        replay_window.* = saved_window;
        max_seq.* = saved_max_seq;
        return null;
    };

    return .{
        .content_type = hdr.content_type,
        .epoch = hdr.epoch,
        .sequence_number = hdr.sequence_number,
        .payload = out_slice,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "encode/decode plaintext record (epoch 0) round-trip" {
    const payload = "hello dtls";
    var seq: u48 = 0;
    var buf: [types.record_header_len + payload.len]u8 = undefined;

    const encoded = encodePlaintext(.application_data, payload, &seq, &buf);

    // Sequence number was advanced.
    try testing.expectEqual(@as(u48, 1), seq);

    const rec = decodePlaintext(encoded) orelse return error.TestUnexpectedNull;
    try testing.expectEqual(types.ContentType.application_data, rec.content_type);
    try testing.expectEqual(@as(u16, 0), rec.epoch);
    try testing.expectEqual(@as(u48, 0), rec.sequence_number);
    try testing.expectEqualSlices(u8, payload, rec.payload);
}

test "encode/decode encrypted record (epoch 1) round-trip" {
    const payload = "secret data";
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 4;
    var seq: u48 = 5;

    var buf: [types.record_overhead + payload.len]u8 = undefined;
    const encoded = encodeEncrypted(.application_data, payload, key, iv, 1, &seq, &buf);

    try testing.expectEqual(@as(u48, 6), seq);

    var pt_buf: [payload.len]u8 = undefined;
    var window: u64 = 0;
    var max_seq: u48 = 0;

    const rec = decodeEncrypted(encoded, key, iv, &window, &max_seq, &pt_buf) orelse
        return error.TestUnexpectedNull;

    try testing.expectEqual(types.ContentType.application_data, rec.content_type);
    try testing.expectEqual(@as(u16, 1), rec.epoch);
    try testing.expectEqual(@as(u48, 5), rec.sequence_number);
    try testing.expectEqualSlices(u8, payload, rec.payload);
}

test "anti-replay window rejects duplicate" {
    const payload = "data";
    const key = [_]u8{0xAA} ** 16;
    const iv = [_]u8{0xBB} ** 4;
    var seq: u48 = 10;

    var buf: [types.record_overhead + payload.len]u8 = undefined;
    const encoded = encodeEncrypted(.handshake, payload, key, iv, 1, &seq, &buf);

    var pt_buf: [payload.len]u8 = undefined;
    var window: u64 = 0;
    var max_seq: u48 = 0;

    // First decode: should succeed.
    const rec1 = decodeEncrypted(encoded, key, iv, &window, &max_seq, &pt_buf);
    try testing.expect(rec1 != null);

    // Second decode: same record — replay, must fail.
    const rec2 = decodeEncrypted(encoded, key, iv, &window, &max_seq, &pt_buf);
    try testing.expect(rec2 == null);
}

test "anti-replay window accepts out-of-order within window" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 4;
    const payload = "pkt";

    // Encode records with seq 0, 1, 2.
    var seq0: u48 = 0;
    var seq1: u48 = 1;
    var seq2: u48 = 2;

    var buf0: [types.record_overhead + payload.len]u8 = undefined;
    var buf1: [types.record_overhead + payload.len]u8 = undefined;
    var buf2: [types.record_overhead + payload.len]u8 = undefined;

    const enc0 = encodeEncrypted(.application_data, payload, key, iv, 1, &seq0, &buf0);
    const enc1 = encodeEncrypted(.application_data, payload, key, iv, 1, &seq1, &buf1);
    const enc2 = encodeEncrypted(.application_data, payload, key, iv, 1, &seq2, &buf2);

    var pt_buf: [payload.len]u8 = undefined;
    var window: u64 = 0;
    var max_seq: u48 = 0;

    // Receive in order: 2, 0, 1 — all should succeed.
    const r2 = decodeEncrypted(enc2, key, iv, &window, &max_seq, &pt_buf);
    try testing.expect(r2 != null);
    try testing.expectEqual(@as(u48, 2), r2.?.sequence_number);

    const r0 = decodeEncrypted(enc0, key, iv, &window, &max_seq, &pt_buf);
    try testing.expect(r0 != null);
    try testing.expectEqual(@as(u48, 0), r0.?.sequence_number);

    const r1 = decodeEncrypted(enc1, key, iv, &window, &max_seq, &pt_buf);
    try testing.expect(r1 != null);
    try testing.expectEqual(@as(u48, 1), r1.?.sequence_number);
}
