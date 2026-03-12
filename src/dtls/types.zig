const std = @import("std");

pub const ProtocolVersion = struct {
    major: u8 = 0xFE,
    minor: u8 = 0xFD, // DTLS 1.2
};

pub const dtls_1_2: ProtocolVersion = .{ .major = 0xFE, .minor = 0xFD };

pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    _,
};

pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
    _,
};

pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    handshake_failure = 40,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    internal_error = 80,
    _,
};

pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3,
    server_key_exchange = 12,
    server_hello_done = 14,
    client_key_exchange = 16,
    finished = 20,
    _,
};

pub const CipherSuite = enum(u16) {
    tls_psk_with_aes_128_ccm_8 = 0xC0A8,
    _,
};

pub const Psk = struct {
    /// PSK identity. Must outlive the Server/Client.
    identity: []const u8,
    /// Pre-shared key bytes. Must outlive the Server/Client.
    key: []const u8,
};

/// Maximum cookie length (HMAC-SHA256 output).
pub const max_cookie_len: usize = 32;

/// DTLS record header size.
pub const record_header_len: usize = 13;

/// Explicit nonce length for AES-CCM in DTLS (epoch + sequence number).
pub const explicit_nonce_len: usize = 8;

/// AES-128-CCM-8 tag length.
pub const ccm8_tag_len: usize = 8;

/// Total encryption overhead per record.
pub const encryption_overhead: usize = explicit_nonce_len + ccm8_tag_len;

/// Total record overhead (header + encryption).
pub const record_overhead: usize = record_header_len + encryption_overhead;

/// Check if a byte is a DTLS content type (used for wire discrimination).
pub fn isDtlsContentType(byte: u8) bool {
    return byte >= 20 and byte <= 25;
}

/// Encode a DTLS alert record (2 bytes: level + description).
pub fn encodeAlert(level: AlertLevel, desc: AlertDescription, out: *[2]u8) void {
    out[0] = @intFromEnum(level);
    out[1] = @intFromEnum(desc);
}

test "isDtlsContentType" {
    // valid content types
    try std.testing.expect(isDtlsContentType(20)); // change_cipher_spec
    try std.testing.expect(isDtlsContentType(21)); // alert
    try std.testing.expect(isDtlsContentType(22)); // handshake
    try std.testing.expect(isDtlsContentType(23)); // application_data
    try std.testing.expect(isDtlsContentType(24));
    try std.testing.expect(isDtlsContentType(25));

    // invalid
    try std.testing.expect(!isDtlsContentType(0));
    try std.testing.expect(!isDtlsContentType(19));
    try std.testing.expect(!isDtlsContentType(26));
    try std.testing.expect(!isDtlsContentType(255));
}

test "encodeAlert" {
    var buf: [2]u8 = undefined;

    encodeAlert(.warning, .close_notify, &buf);
    try std.testing.expectEqual(@as(u8, 1), buf[0]);
    try std.testing.expectEqual(@as(u8, 0), buf[1]);

    encodeAlert(.fatal, .handshake_failure, &buf);
    try std.testing.expectEqual(@as(u8, 2), buf[0]);
    try std.testing.expectEqual(@as(u8, 40), buf[1]);

    encodeAlert(.fatal, .internal_error, &buf);
    try std.testing.expectEqual(@as(u8, 2), buf[0]);
    try std.testing.expectEqual(@as(u8, 80), buf[1]);
}

test "constants" {
    try std.testing.expectEqual(@as(usize, 32), max_cookie_len);
    try std.testing.expectEqual(@as(usize, 13), record_header_len);
    try std.testing.expectEqual(@as(usize, 8), explicit_nonce_len);
    try std.testing.expectEqual(@as(usize, 8), ccm8_tag_len);
    try std.testing.expectEqual(@as(usize, 16), encryption_overhead);
    try std.testing.expectEqual(@as(usize, 29), record_overhead);
}

test "dtls_1_2 version" {
    try std.testing.expectEqual(@as(u8, 0xFE), dtls_1_2.major);
    try std.testing.expectEqual(@as(u8, 0xFD), dtls_1_2.minor);
}
