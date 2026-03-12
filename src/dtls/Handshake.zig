/// DTLS 1.2 PSK handshake state machine.
///
/// Implements key derivation (RFC 4279), handshake message framing (RFC 6347),
/// and both server-side and client-side state machines for PSK-only cipher suites.
const std = @import("std");
const types = @import("types.zig");
const Prf = @import("Prf.zig");
const Record = @import("Record.zig");
const Cookie = @import("Cookie.zig");
const Session = @import("Session.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

pub const KeyBlock = struct {
    client_write_key: [16]u8,
    server_write_key: [16]u8,
    client_write_iv: [4]u8,
    server_write_iv: [4]u8,
};

/// Build PSK pre-master secret: <2-byte len><zeroes><2-byte len><PSK bytes>
/// RFC 4279 section 2.
pub fn buildPreMasterSecret(psk: []const u8, buf: []u8) []const u8 {
    std.debug.assert(psk.len <= types.max_psk_key_len);
    const psk_len: u16 = @intCast(psk.len);
    const total = 2 + psk.len + 2 + psk.len;
    std.debug.assert(buf.len >= total);
    std.mem.writeInt(u16, buf[0..2], psk_len, .big);
    @memset(buf[2..][0..psk.len], 0);
    std.mem.writeInt(u16, buf[2 + psk.len ..][0..2], psk_len, .big);
    @memcpy(buf[4 + psk.len ..][0..psk.len], psk);
    return buf[0..total];
}

/// Master secret = PRF(pre_master, "master secret", client_random || server_random)[0..48]
pub fn deriveMasterSecret(pre_master: []const u8, client_random: [32]u8, server_random: [32]u8) [48]u8 {
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &client_random);
    @memcpy(seed[32..64], &server_random);
    var master: [48]u8 = undefined;
    Prf.prf(pre_master, "master secret", &seed, &master);
    return master;
}

/// Key block = PRF(master, "key expansion", server_random || client_random)
/// client_write_key(16) + server_write_key(16) + client_write_iv(4) + server_write_iv(4) = 40 bytes
pub fn deriveKeys(master_secret: [48]u8, server_random: [32]u8, client_random: [32]u8) KeyBlock {
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &server_random);
    @memcpy(seed[32..64], &client_random);
    var material: [40]u8 = undefined;
    Prf.prf(&master_secret, "key expansion", &seed, &material);
    const kb: KeyBlock = .{
        .client_write_key = material[0..16].*,
        .server_write_key = material[16..32].*,
        .client_write_iv = material[32..36].*,
        .server_write_iv = material[36..40].*,
    };
    std.crypto.secureZero(u8, &material);
    return kb;
}

// ---------------------------------------------------------------------------
// Handshake message encode/decode
// ---------------------------------------------------------------------------

pub const handshake_header_len = 12;

pub const HandshakeMessage = struct {
    msg_type: types.HandshakeType,
    message_seq: u16,
    body: []const u8,
};

pub fn encodeHandshakeMessage(msg_type: types.HandshakeType, message_seq: u16, body: []const u8, out: []u8) []const u8 {
    const total = handshake_header_len + body.len;
    std.debug.assert(out.len >= total);
    const body_len: u24 = @intCast(body.len);
    out[0] = @intFromEnum(msg_type);
    out[1] = @intCast((body_len >> 16) & 0xFF);
    out[2] = @intCast((body_len >> 8) & 0xFF);
    out[3] = @intCast(body_len & 0xFF);
    std.mem.writeInt(u16, out[4..6], message_seq, .big);
    out[6] = 0;
    out[7] = 0;
    out[8] = 0;
    out[9] = out[1];
    out[10] = out[2];
    out[11] = out[3];
    @memcpy(out[handshake_header_len..][0..body.len], body);
    return out[0..total];
}

pub fn decodeHandshakeMessage(buf: []const u8) ?HandshakeMessage {
    if (buf.len < handshake_header_len) return null;
    const body_len: u24 = (@as(u24, buf[1]) << 16) | (@as(u24, buf[2]) << 8) | buf[3];
    const frag_offset: u24 = (@as(u24, buf[6]) << 16) | (@as(u24, buf[7]) << 8) | buf[8];
    const frag_len: u24 = (@as(u24, buf[9]) << 16) | (@as(u24, buf[10]) << 8) | buf[11];
    if (frag_offset != 0 or frag_len != body_len) return null;
    if (buf.len < handshake_header_len + body_len) return null;
    return .{
        .msg_type = @enumFromInt(buf[0]),
        .message_seq = std.mem.readInt(u16, buf[4..6], .big),
        .body = buf[handshake_header_len..][0..body_len],
    };
}

// ---------------------------------------------------------------------------
// Handshake action
// ---------------------------------------------------------------------------

pub const HandshakeAction = union(enum) {
    /// Send records to the peer (one or more messages encoded in send_buf).
    send: []const u8,
    /// Handshake complete — session established.
    established,
    /// Handshake failed.
    failed: types.AlertDescription,
    /// No action needed.
    none,
};

// ---------------------------------------------------------------------------
// Server-side state machine
// ---------------------------------------------------------------------------

pub fn serverProcessMessage(
    session: *Session.Session,
    content_type: types.ContentType,
    payload: []const u8,
    psk: types.Psk,
    cookie_secret: [32]u8,
    cookie_secret_prev: [32]u8,
    send_buf: []u8,
) HandshakeAction {
    if (psk.identity.len > types.max_psk_identity_len or psk.key.len > types.max_psk_key_len)
        return .{ .failed = .internal_error };
    switch (content_type) {
        .handshake => return serverProcessHandshake(session, payload, psk, cookie_secret, cookie_secret_prev, send_buf),
        .change_cipher_spec => return serverProcessCcs(session, payload),
        else => return .{ .failed = .unexpected_message },
    }
}

fn serverProcessHandshake(
    session: *Session.Session,
    payload: []const u8,
    psk: types.Psk,
    cookie_secret: [32]u8,
    cookie_secret_prev: [32]u8,
    send_buf: []u8,
) HandshakeAction {
    const msg = decodeHandshakeMessage(payload) orelse
        return .{ .failed = .decode_error };

    switch (session.handshake_state) {
        .idle, .expect_client_hello, .cookie_sent => {
            if (msg.msg_type != .client_hello)
                return .{ .failed = .unexpected_message };
            return serverHandleClientHello(session, msg.body, payload, psk, cookie_secret, cookie_secret_prev, send_buf);
        },
        .expect_client_key_exchange => {
            if (msg.msg_type != .client_key_exchange)
                return .{ .failed = .unexpected_message };
            return serverHandleClientKeyExchange(session, msg.body, payload, psk);
        },
        .expect_finished => {
            if (msg.msg_type != .finished)
                return .{ .failed = .unexpected_message };
            return serverHandleFinished(session, msg.body, payload, send_buf);
        },
        else => return .{ .failed = .unexpected_message },
    }
}

/// Stateless check: is the payload a ClientHello with a valid cookie?
/// Returns true only if the payload parses as a ClientHello containing a
/// cookie that passes rotation-aware verification against the peer address.
/// Used to gate session allocation — no session is created until the cookie
/// exchange succeeds.
pub fn isClientHelloWithValidCookie(
    payload: []const u8,
    cookie_secret: [32]u8,
    cookie_secret_prev: [32]u8,
    peer_addr: std.net.Address,
) bool {
    const msg = decodeHandshakeMessage(payload) orelse return false;
    if (msg.msg_type != .client_hello) return false;
    const body = msg.body;

    // Parse enough of the ClientHello to extract cookie.
    var off: usize = 0;
    if (body.len < 2 + 32 + 1) return false;
    off += 2; // client_version
    const client_random: [32]u8 = body[off..][0..32].*;
    off += 32;

    // session_id
    if (off >= body.len) return false;
    const sid_len = body[off];
    off += 1;
    if (off + sid_len > body.len) return false;
    off += sid_len;

    // cookie
    if (off >= body.len) return false;
    const cookie_len = body[off];
    off += 1;
    if (off + cookie_len > body.len) return false;
    if (cookie_len == 0) return false;
    const cookie = body[off..][0..cookie_len];

    return Cookie.verifyWithRotation(cookie_secret, cookie_secret_prev, peer_addr, client_random, cookie);
}

/// Build a HelloVerifyRequest statelessly (no session required).
/// Returns the encoded DTLS record slice within `send_buf`, or null if
/// the payload does not parse as a valid ClientHello.
pub fn buildStatelessHvr(
    payload: []const u8,
    cookie_secret: [32]u8,
    peer_addr: std.net.Address,
    send_buf: []u8,
) ?[]const u8 {
    const msg = decodeHandshakeMessage(payload) orelse return null;
    if (msg.msg_type != .client_hello) return null;
    const body = msg.body;

    if (body.len < 2 + 32 + 1) return null;
    const client_random: [32]u8 = body[2..34].*;

    const cookie = Cookie.generate(cookie_secret, peer_addr, client_random);

    // HelloVerifyRequest body: server_version(2) + cookie_len(1) + cookie(32)
    var hvr_body: [35]u8 = undefined;
    hvr_body[0] = 0xFE; // DTLS 1.2
    hvr_body[1] = 0xFD;
    hvr_body[2] = 32;
    @memcpy(hvr_body[3..35], &cookie);

    var hs_buf: [64]u8 = undefined;
    const hs_msg = encodeHandshakeMessage(.hello_verify_request, 0, &hvr_body, &hs_buf);

    var record_buf: [128]u8 = undefined;
    var seq: u48 = 0;
    const rec = Record.encodePlaintext(.handshake, hs_msg, &seq, &record_buf);
    if (rec.len > send_buf.len) return null;
    @memcpy(send_buf[0..rec.len], rec);
    return send_buf[0..rec.len];
}

fn serverProcessCcs(
    session: *Session.Session,
    payload: []const u8,
) HandshakeAction {
    if (session.handshake_state != .expect_change_cipher_spec)
        return .{ .failed = .unexpected_message };
    if (payload.len != 1 or payload[0] != 0x01)
        return .{ .failed = .decode_error };

    // Activate read keys (client -> server direction).
    session.read_epoch = 1;
    session.read_sequence = 0;
    session.handshake_state = .expect_finished;
    return .none;
}

fn serverHandleClientHello(
    session: *Session.Session,
    body: []const u8,
    full_hs_msg: []const u8,
    psk: types.Psk,
    cookie_secret: [32]u8,
    cookie_secret_prev: [32]u8,
    send_buf: []u8,
) HandshakeAction {
    // Parse ClientHello body:
    // client_version(2) + client_random(32) + session_id_len(1) + session_id(var) +
    // cookie_len(1) + cookie(var) + cipher_suites_len(2) + cipher_suites(var) +
    // compression_len(1) + compression(var)
    var off: usize = 0;

    if (body.len < 2 + 32 + 1) return .{ .failed = .decode_error };

    // Skip client_version
    off += 2;

    // client_random
    const client_random: [32]u8 = body[off..][0..32].*;
    off += 32;

    // session_id
    if (off >= body.len) return .{ .failed = .decode_error };
    const sid_len = body[off];
    off += 1;
    if (off + sid_len > body.len) return .{ .failed = .decode_error };
    off += sid_len;

    // cookie
    if (off >= body.len) return .{ .failed = .decode_error };
    const cookie_len = body[off];
    off += 1;
    if (off + cookie_len > body.len) return .{ .failed = .decode_error };
    const cookie = body[off..][0..cookie_len];
    off += cookie_len;

    // If no cookie, send HelloVerifyRequest.
    if (cookie_len == 0) {
        return serverSendHelloVerifyRequest(session, client_random, cookie_secret, send_buf);
    }

    // Verify cookie against current and previous secrets (rotation-safe).
    if (!Cookie.verifyWithRotation(cookie_secret, cookie_secret_prev, session.addr, client_random, cookie)) {
        return serverSendHelloVerifyRequest(session, client_random, cookie_secret, send_buf);
    }

    // Cookie valid — reset hash for the real handshake, starting with this ClientHello.
    session.handshake_hash = Sha256.init(.{});
    session.handshake_hash.update(full_hs_msg);
    session.client_random = client_random;
    session.message_seq = 0;

    // Generate server_random.
    std.crypto.random.bytes(&session.server_random);

    // Build response flight: ServerHello + ServerKeyExchange + ServerHelloDone
    var offset: usize = 0;
    var hs_buf: [256]u8 = undefined;
    var record_buf: [300]u8 = undefined;

    // --- ServerHello ---
    {
        // body: server_version(2) + server_random(32) + session_id_len(1,0) + cipher_suite(2) + compression(1,0)
        var sh_body: [38]u8 = undefined;
        sh_body[0] = 0xFE; // DTLS 1.2
        sh_body[1] = 0xFD;
        @memcpy(sh_body[2..34], &session.server_random);
        sh_body[34] = 0; // session_id_len = 0
        std.mem.writeInt(u16, sh_body[35..37], @intFromEnum(types.CipherSuite.tls_psk_with_aes_128_ccm_8), .big);
        sh_body[37] = 0; // compression = null

        // Server's own message_seq counter starts at 0, independent of client's.
        const hs_msg = encodeHandshakeMessage(.server_hello, session.message_seq, &sh_body, &hs_buf);
        session.handshake_hash.update(hs_msg);
        const rec = Record.encodePlaintext(.handshake, hs_msg, &session.write_sequence, &record_buf);
        @memcpy(send_buf[offset..][0..rec.len], rec);
        offset += rec.len;
    }

    // --- ServerKeyExchange (PSK) ---
    if (psk.identity.len > 0) {
        // body: psk_identity_hint_len(2) + psk_identity_hint(var)
        var ske_body: [256]u8 = undefined;
        std.mem.writeInt(u16, ske_body[0..2], @intCast(psk.identity.len), .big);
        @memcpy(ske_body[2..][0..psk.identity.len], psk.identity);
        const ske_body_slice = ske_body[0 .. 2 + psk.identity.len];

        session.message_seq += 1;
        const hs_msg = encodeHandshakeMessage(.server_key_exchange, session.message_seq, ske_body_slice, &hs_buf);
        session.handshake_hash.update(hs_msg);
        const rec = Record.encodePlaintext(.handshake, hs_msg, &session.write_sequence, &record_buf);
        @memcpy(send_buf[offset..][0..rec.len], rec);
        offset += rec.len;
    }

    // --- ServerHelloDone ---
    {
        session.message_seq += 1;
        const hs_msg = encodeHandshakeMessage(.server_hello_done, session.message_seq, &.{}, &hs_buf);
        session.handshake_hash.update(hs_msg);
        const rec = Record.encodePlaintext(.handshake, hs_msg, &session.write_sequence, &record_buf);
        @memcpy(send_buf[offset..][0..rec.len], rec);
        offset += rec.len;
    }

    session.handshake_state = .expect_client_key_exchange;
    return .{ .send = send_buf[0..offset] };
}

fn serverSendHelloVerifyRequest(
    session: *Session.Session,
    client_random: [32]u8,
    cookie_secret: [32]u8,
    send_buf: []u8,
) HandshakeAction {
    const cookie = Cookie.generate(cookie_secret, session.addr, client_random);

    // HelloVerifyRequest body: server_version(2) + cookie_len(1) + cookie(32) = 35
    var hvr_body: [35]u8 = undefined;
    hvr_body[0] = 0xFE; // DTLS 1.2
    hvr_body[1] = 0xFD;
    hvr_body[2] = 32; // cookie length
    @memcpy(hvr_body[3..35], &cookie);

    var hs_buf: [64]u8 = undefined;
    const hs_msg = encodeHandshakeMessage(.hello_verify_request, 0, &hvr_body, &hs_buf);
    // HVR is not included in handshake hash per RFC 6347.

    var record_buf: [128]u8 = undefined;
    const rec = Record.encodePlaintext(.handshake, hs_msg, &session.write_sequence, &record_buf);
    @memcpy(send_buf[0..rec.len], rec);

    session.handshake_state = .cookie_sent;
    return .{ .send = send_buf[0..rec.len] };
}

fn serverHandleClientKeyExchange(
    session: *Session.Session,
    body: []const u8,
    full_hs_msg: []const u8,
    psk: types.Psk,
) HandshakeAction {
    // Parse ClientKeyExchange: psk_identity_len(2) + psk_identity(var)
    if (body.len < 2) return .{ .failed = .decode_error };
    const id_len = std.mem.readInt(u16, body[0..2], .big);
    if (body.len < 2 + id_len) return .{ .failed = .decode_error };
    const identity = body[2..][0..id_len];

    // Verify identity matches.
    if (!std.mem.eql(u8, identity, psk.identity))
        return .{ .failed = .handshake_failure };

    // Hash the ClientKeyExchange message.
    session.handshake_hash.update(full_hs_msg);

    // Derive keys.
    var pms_buf: [256]u8 = undefined;
    const pre_master = buildPreMasterSecret(psk.key, &pms_buf);
    session.master_secret = deriveMasterSecret(pre_master, session.client_random, session.server_random);
    std.crypto.secureZero(u8, &pms_buf);
    const keys = deriveKeys(session.master_secret, session.server_random, session.client_random);
    session.client_write_key = keys.client_write_key;
    session.server_write_key = keys.server_write_key;
    session.client_write_iv = keys.client_write_iv;
    session.server_write_iv = keys.server_write_iv;

    session.handshake_state = .expect_change_cipher_spec;
    return .none;
}

fn serverHandleFinished(
    session: *Session.Session,
    body: []const u8,
    full_hs_msg: []const u8,
    send_buf: []u8,
) HandshakeAction {
    if (body.len != 12) return .{ .failed = .decode_error };

    // Compute expected client verify_data: PRF(master, "client finished", SHA256(all_hs_msgs_before_finished))
    var expected_verify: [12]u8 = undefined;
    {
        var hash_copy = session.handshake_hash;
        const hs_hash = hash_copy.finalResult();
        Prf.prf(&session.master_secret, "client finished", &hs_hash, &expected_verify);
    }

    if (!std.crypto.timing_safe.eql([12]u8, expected_verify, body[0..12].*))
        return .{ .failed = .decrypt_error };

    // Hash the client Finished message (needed for server finished computation).
    session.handshake_hash.update(full_hs_msg);

    // Build server flight: CCS + Finished
    var offset: usize = 0;
    var record_buf: [128]u8 = undefined;

    // --- CCS ---
    {
        const ccs_payload = [_]u8{0x01};
        const rec = Record.encodePlaintext(.change_cipher_spec, &ccs_payload, &session.write_sequence, &record_buf);
        @memcpy(send_buf[offset..][0..rec.len], rec);
        offset += rec.len;
    }

    // Activate write keys (server -> client direction).
    session.write_epoch = 1;
    session.write_sequence = 0;

    // --- Server Finished ---
    {
        var server_verify: [12]u8 = undefined;
        var hash_copy = session.handshake_hash;
        const hs_hash = hash_copy.finalResult();
        Prf.prf(&session.master_secret, "server finished", &hs_hash, &server_verify);

        var hs_buf: [64]u8 = undefined;
        session.message_seq += 1;
        const hs_msg = encodeHandshakeMessage(.finished, session.message_seq, &server_verify, &hs_buf);
        // Hash server Finished for completeness.
        session.handshake_hash.update(hs_msg);

        const rec = Record.encodeEncrypted(
            .handshake,
            hs_msg,
            session.server_write_key,
            session.server_write_iv,
            session.write_epoch,
            &session.write_sequence,
            &record_buf,
        );
        @memcpy(send_buf[offset..][0..rec.len], rec);
        offset += rec.len;
    }

    session.state = .established;
    session.handshake_state = .complete;
    return .{ .send = send_buf[0..offset] };
}

// ---------------------------------------------------------------------------
// Client-side state machine
// ---------------------------------------------------------------------------

pub const ClientHandshakeState = enum(u8) {
    idle,
    expect_hello_verify_or_server_hello,
    expect_server_key_exchange,
    expect_server_hello_done,
    expect_change_cipher_spec,
    expect_finished,
    complete,
};

/// Build the initial ClientHello message (no cookie). Returns the record bytes
/// to send and sets up session state.
pub fn clientBuildInitialHello(
    session: *Session.Session,
    client_hs_state: *ClientHandshakeState,
    psk: types.Psk,
    send_buf: []u8,
) HandshakeAction {
    if (psk.identity.len > types.max_psk_identity_len or psk.key.len > types.max_psk_key_len)
        return .{ .failed = .internal_error };

    // Generate client_random.
    std.crypto.random.bytes(&session.client_random);

    // Reset handshake hash.
    session.handshake_hash = Sha256.init(.{});

    // Build ClientHello body (no cookie).
    var ch_body: [256]u8 = undefined;
    const ch_len = buildClientHelloBody(session.client_random, &.{}, &ch_body);

    var hs_buf: [300]u8 = undefined;
    session.message_seq = 0;
    const hs_msg = encodeHandshakeMessage(.client_hello, session.message_seq, ch_body[0..ch_len], &hs_buf);
    session.handshake_hash.update(hs_msg);

    var record_buf: [350]u8 = undefined;
    const rec = Record.encodePlaintext(.handshake, hs_msg, &session.write_sequence, &record_buf);
    @memcpy(send_buf[0..rec.len], rec);

    client_hs_state.* = .expect_hello_verify_or_server_hello;
    return .{ .send = send_buf[0..rec.len] };
}

/// Process an incoming message on the client side.
pub fn clientProcessMessage(
    session: *Session.Session,
    client_hs_state: *ClientHandshakeState,
    content_type: types.ContentType,
    payload: []const u8,
    psk: types.Psk,
    send_buf: []u8,
) HandshakeAction {
    switch (content_type) {
        .handshake => return clientProcessHandshake(session, client_hs_state, payload, psk, send_buf),
        .change_cipher_spec => return clientProcessCcs(session, client_hs_state, payload),
        else => return .{ .failed = .unexpected_message },
    }
}

fn clientProcessHandshake(
    session: *Session.Session,
    client_hs_state: *ClientHandshakeState,
    payload: []const u8,
    psk: types.Psk,
    send_buf: []u8,
) HandshakeAction {
    const msg = decodeHandshakeMessage(payload) orelse
        return .{ .failed = .decode_error };

    switch (client_hs_state.*) {
        .expect_hello_verify_or_server_hello => {
            if (msg.msg_type == .hello_verify_request)
                return clientHandleHelloVerifyRequest(session, client_hs_state, msg.body, send_buf);
            if (msg.msg_type == .server_hello)
                return clientHandleServerHello(session, client_hs_state, msg.body, payload);
            return .{ .failed = .unexpected_message };
        },
        .expect_server_key_exchange => {
            if (msg.msg_type == .server_key_exchange) {
                return clientHandleServerKeyExchange(session, client_hs_state, payload);
            }
            // ServerKeyExchange is optional for PSK — might get ServerHelloDone instead.
            if (msg.msg_type == .server_hello_done) {
                return clientHandleServerHelloDone(session, client_hs_state, payload, psk, send_buf);
            }
            return .{ .failed = .unexpected_message };
        },
        .expect_server_hello_done => {
            if (msg.msg_type != .server_hello_done)
                return .{ .failed = .unexpected_message };
            return clientHandleServerHelloDone(session, client_hs_state, payload, psk, send_buf);
        },
        .expect_finished => {
            if (msg.msg_type != .finished)
                return .{ .failed = .unexpected_message };
            return clientHandleFinished(session, client_hs_state, msg.body, payload);
        },
        else => return .{ .failed = .unexpected_message },
    }
}

fn clientProcessCcs(
    session: *Session.Session,
    client_hs_state: *ClientHandshakeState,
    payload: []const u8,
) HandshakeAction {
    if (client_hs_state.* != .expect_change_cipher_spec)
        return .{ .failed = .unexpected_message };
    if (payload.len != 1 or payload[0] != 0x01)
        return .{ .failed = .decode_error };

    session.read_epoch = 1;
    session.read_sequence = 0;
    client_hs_state.* = .expect_finished;
    return .none;
}

fn clientHandleHelloVerifyRequest(
    session: *Session.Session,
    client_hs_state: *ClientHandshakeState,
    body: []const u8,
    send_buf: []u8,
) HandshakeAction {
    // HVR body: server_version(2) + cookie_len(1) + cookie(var)
    if (body.len < 3) return .{ .failed = .decode_error };
    const cookie_len = body[2];
    if (body.len < 3 + @as(usize, cookie_len)) return .{ .failed = .decode_error };
    const cookie = body[3..][0..cookie_len];

    // Reset hash — HVR and initial ClientHello are not included.
    session.handshake_hash = Sha256.init(.{});

    // Reset write sequence for retransmitted ClientHello.
    session.write_sequence = 0;

    // Build new ClientHello with cookie.
    var ch_body: [256]u8 = undefined;
    const ch_len = buildClientHelloBody(session.client_random, cookie, &ch_body);

    var hs_buf: [300]u8 = undefined;
    session.message_seq = 0;
    const hs_msg = encodeHandshakeMessage(.client_hello, session.message_seq, ch_body[0..ch_len], &hs_buf);
    session.handshake_hash.update(hs_msg);

    var record_buf: [350]u8 = undefined;
    const rec = Record.encodePlaintext(.handshake, hs_msg, &session.write_sequence, &record_buf);
    @memcpy(send_buf[0..rec.len], rec);

    client_hs_state.* = .expect_hello_verify_or_server_hello;
    return .{ .send = send_buf[0..rec.len] };
}

fn clientHandleServerHello(
    session: *Session.Session,
    client_hs_state: *ClientHandshakeState,
    body: []const u8,
    full_hs_msg: []const u8,
) HandshakeAction {
    // ServerHello body: version(2) + server_random(32) + session_id_len(1) + session_id(var)
    //                   + cipher_suite(2) + compression(1)
    if (body.len < 2 + 32 + 1) return .{ .failed = .decode_error };

    var off: usize = 2; // skip version
    session.server_random = body[off..][0..32].*;
    off += 32;

    const sid_len = body[off];
    off += 1;
    if (off + sid_len > body.len) return .{ .failed = .decode_error };
    off += sid_len;

    if (off + 3 > body.len) return .{ .failed = .decode_error };
    // Could verify cipher suite and compression here.
    // off += 2 + 1;

    session.handshake_hash.update(full_hs_msg);
    client_hs_state.* = .expect_server_key_exchange;
    return .none;
}

fn clientHandleServerKeyExchange(
    session: *Session.Session,
    client_hs_state: *ClientHandshakeState,
    full_hs_msg: []const u8,
) HandshakeAction {
    session.handshake_hash.update(full_hs_msg);
    client_hs_state.* = .expect_server_hello_done;
    return .none;
}

fn clientHandleServerHelloDone(
    session: *Session.Session,
    client_hs_state: *ClientHandshakeState,
    full_hs_msg: []const u8,
    psk: types.Psk,
    send_buf: []u8,
) HandshakeAction {
    session.handshake_hash.update(full_hs_msg);

    // Build client flight: ClientKeyExchange + CCS + Finished
    var offset: usize = 0;
    var hs_buf: [256]u8 = undefined;
    var record_buf: [300]u8 = undefined;

    // --- ClientKeyExchange ---
    {
        var cke_body: [256]u8 = undefined;
        std.mem.writeInt(u16, cke_body[0..2], @intCast(psk.identity.len), .big);
        @memcpy(cke_body[2..][0..psk.identity.len], psk.identity);
        const cke_body_slice = cke_body[0 .. 2 + psk.identity.len];

        session.message_seq += 1;
        const hs_msg = encodeHandshakeMessage(.client_key_exchange, session.message_seq, cke_body_slice, &hs_buf);
        session.handshake_hash.update(hs_msg);
        const rec = Record.encodePlaintext(.handshake, hs_msg, &session.write_sequence, &record_buf);
        @memcpy(send_buf[offset..][0..rec.len], rec);
        offset += rec.len;
    }

    // Derive keys.
    var pms_buf: [256]u8 = undefined;
    const pre_master = buildPreMasterSecret(psk.key, &pms_buf);
    session.master_secret = deriveMasterSecret(pre_master, session.client_random, session.server_random);
    std.crypto.secureZero(u8, &pms_buf);
    const keys = deriveKeys(session.master_secret, session.server_random, session.client_random);
    session.client_write_key = keys.client_write_key;
    session.server_write_key = keys.server_write_key;
    session.client_write_iv = keys.client_write_iv;
    session.server_write_iv = keys.server_write_iv;

    // --- CCS ---
    {
        const ccs_payload = [_]u8{0x01};
        const rec = Record.encodePlaintext(.change_cipher_spec, &ccs_payload, &session.write_sequence, &record_buf);
        @memcpy(send_buf[offset..][0..rec.len], rec);
        offset += rec.len;
    }

    // Activate write keys (client -> server direction).
    session.write_epoch = 1;
    session.write_sequence = 0;

    // --- Client Finished ---
    {
        var client_verify: [12]u8 = undefined;
        var hash_copy = session.handshake_hash;
        const hs_hash = hash_copy.finalResult();
        Prf.prf(&session.master_secret, "client finished", &hs_hash, &client_verify);

        session.message_seq += 1;
        const hs_msg = encodeHandshakeMessage(.finished, session.message_seq, &client_verify, &hs_buf);
        session.handshake_hash.update(hs_msg);

        const rec = Record.encodeEncrypted(
            .handshake,
            hs_msg,
            session.client_write_key,
            session.client_write_iv,
            session.write_epoch,
            &session.write_sequence,
            &record_buf,
        );
        @memcpy(send_buf[offset..][0..rec.len], rec);
        offset += rec.len;
    }

    client_hs_state.* = .expect_change_cipher_spec;
    return .{ .send = send_buf[0..offset] };
}

fn clientHandleFinished(
    session: *Session.Session,
    client_hs_state: *ClientHandshakeState,
    body: []const u8,
    full_hs_msg: []const u8,
) HandshakeAction {
    if (body.len != 12) return .{ .failed = .decode_error };

    // Verify server Finished.
    var expected_verify: [12]u8 = undefined;
    {
        var hash_copy = session.handshake_hash;
        const hs_hash = hash_copy.finalResult();
        Prf.prf(&session.master_secret, "server finished", &hs_hash, &expected_verify);
    }

    if (!std.crypto.timing_safe.eql([12]u8, expected_verify, body[0..12].*))
        return .{ .failed = .decrypt_error };

    session.handshake_hash.update(full_hs_msg);
    session.state = .established;
    client_hs_state.* = .complete;
    return .established;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn buildClientHelloBody(client_random: [32]u8, cookie: []const u8, out: []u8) usize {
    var off: usize = 0;

    // client_version: DTLS 1.2
    out[0] = 0xFE;
    out[1] = 0xFD;
    off = 2;

    // client_random
    @memcpy(out[off..][0..32], &client_random);
    off += 32;

    // session_id_len = 0
    out[off] = 0;
    off += 1;

    // cookie
    out[off] = @intCast(cookie.len);
    off += 1;
    if (cookie.len > 0) {
        @memcpy(out[off..][0..cookie.len], cookie);
        off += cookie.len;
    }

    // cipher_suites: length(2) + TLS_PSK_WITH_AES_128_CCM_8(2)
    std.mem.writeInt(u16, out[off..][0..2], 2, .big);
    off += 2;
    std.mem.writeInt(u16, out[off..][0..2], @intFromEnum(types.CipherSuite.tls_psk_with_aes_128_ccm_8), .big);
    off += 2;

    // compression_methods: length(1) + null(1)
    out[off] = 1;
    off += 1;
    out[off] = 0;
    off += 1;

    return off;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "buildPreMasterSecret: known PSK" {
    const psk = "secretkey";
    var buf: [256]u8 = undefined;
    const pms = buildPreMasterSecret(psk, &buf);

    // total = 2 + 9 + 2 + 9 = 22
    try testing.expectEqual(@as(usize, 22), pms.len);
    // First 2 bytes: PSK length (9) in big-endian.
    try testing.expectEqual(@as(u16, 9), std.mem.readInt(u16, pms[0..2], .big));
    // Next 9 bytes: zeroes.
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 9), pms[2..11]);
    // Next 2 bytes: PSK length again.
    try testing.expectEqual(@as(u16, 9), std.mem.readInt(u16, pms[11..13], .big));
    // Final 9 bytes: PSK value.
    try testing.expectEqualSlices(u8, psk, pms[13..22]);
}

test "deriveKeys: deterministic and distinct" {
    const psk = "test-psk";
    var pms_buf: [256]u8 = undefined;
    const pms = buildPreMasterSecret(psk, &pms_buf);

    const client_random = [_]u8{0x11} ** 32;
    const server_random = [_]u8{0x22} ** 32;

    const master = deriveMasterSecret(pms, client_random, server_random);
    const keys1 = deriveKeys(master, server_random, client_random);
    const keys2 = deriveKeys(master, server_random, client_random);

    // Deterministic.
    try testing.expectEqualSlices(u8, &keys1.client_write_key, &keys2.client_write_key);
    try testing.expectEqualSlices(u8, &keys1.server_write_key, &keys2.server_write_key);
    try testing.expectEqualSlices(u8, &keys1.client_write_iv, &keys2.client_write_iv);
    try testing.expectEqualSlices(u8, &keys1.server_write_iv, &keys2.server_write_iv);

    // Client and server keys differ.
    try testing.expect(!std.mem.eql(u8, &keys1.client_write_key, &keys1.server_write_key));
    try testing.expect(!std.mem.eql(u8, &keys1.client_write_iv, &keys1.server_write_iv));
}

test "handshake message encode/decode round-trip" {
    const body = "hello body data";
    var buf: [256]u8 = undefined;
    const encoded = encodeHandshakeMessage(.client_hello, 42, body, &buf);

    try testing.expectEqual(@as(usize, handshake_header_len + body.len), encoded.len);

    const decoded = decodeHandshakeMessage(encoded) orelse
        return error.TestUnexpectedNull;
    try testing.expectEqual(types.HandshakeType.client_hello, decoded.msg_type);
    try testing.expectEqual(@as(u16, 42), decoded.message_seq);
    try testing.expectEqualSlices(u8, body, decoded.body);
}

test "decodeHandshakeMessage: too short" {
    const short = [_]u8{0} ** 11;
    try testing.expect(decodeHandshakeMessage(&short) == null);
}

test "full server handshake" {
    const psk_identity = "test-identity";
    const psk_key = "test-key-value";
    const psk = types.Psk{ .identity = psk_identity, .key = psk_key };
    const cookie_secret = [_]u8{0x42} ** 32;
    const addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 5684);

    // Create a server session.
    var server_session: Session.Session = undefined;
    initTestSession(&server_session, addr);

    var send_buf: [2048]u8 = undefined;
    var client_random: [32]u8 = undefined;
    std.crypto.random.bytes(&client_random);

    // Step 1: ClientHello without cookie → expect HelloVerifyRequest
    {
        var ch_body_buf: [256]u8 = undefined;
        const ch_len = buildClientHelloBody(client_random, &.{}, &ch_body_buf);
        var hs_buf: [300]u8 = undefined;
        const hs_msg = encodeHandshakeMessage(.client_hello, 0, ch_body_buf[0..ch_len], &hs_buf);

        const action = serverProcessMessage(&server_session, .handshake, hs_msg, psk, cookie_secret, cookie_secret, &send_buf);
        switch (action) {
            .send => |data| {
                try testing.expect(data.len > 0);
                // Should contain a HelloVerifyRequest record.
                const rec = Record.decodePlaintext(data) orelse return error.TestUnexpectedNull;
                try testing.expectEqual(types.ContentType.handshake, rec.content_type);
                const hvr = decodeHandshakeMessage(rec.payload) orelse return error.TestUnexpectedNull;
                try testing.expectEqual(types.HandshakeType.hello_verify_request, hvr.msg_type);
            },
            else => return error.TestUnexpectedResult,
        }
        try testing.expectEqual(Session.ServerHandshakeState.cookie_sent, server_session.handshake_state);
    }

    // Step 2: ClientHello with valid cookie → expect ServerHello flight
    var server_flight_data: [2048]u8 = undefined;
    var server_flight_len: usize = 0;
    {
        const cookie = Cookie.generate(cookie_secret, addr, client_random);
        var ch_body_buf: [256]u8 = undefined;
        const ch_len = buildClientHelloBody(client_random, &cookie, &ch_body_buf);
        var hs_buf: [300]u8 = undefined;
        const hs_msg = encodeHandshakeMessage(.client_hello, 0, ch_body_buf[0..ch_len], &hs_buf);

        const action = serverProcessMessage(&server_session, .handshake, hs_msg, psk, cookie_secret, cookie_secret, &send_buf);
        switch (action) {
            .send => |data| {
                try testing.expect(data.len > 0);
                @memcpy(server_flight_data[0..data.len], data);
                server_flight_len = data.len;
            },
            else => return error.TestUnexpectedResult,
        }
        try testing.expectEqual(Session.ServerHandshakeState.expect_client_key_exchange, server_session.handshake_state);
    }

    // Step 3: ClientKeyExchange
    {
        var cke_body: [256]u8 = undefined;
        std.mem.writeInt(u16, cke_body[0..2], @intCast(psk_identity.len), .big);
        @memcpy(cke_body[2..][0..psk_identity.len], psk_identity);
        var hs_buf: [300]u8 = undefined;
        const hs_msg = encodeHandshakeMessage(.client_key_exchange, 1, cke_body[0 .. 2 + psk_identity.len], &hs_buf);

        const action = serverProcessMessage(&server_session, .handshake, hs_msg, psk, cookie_secret, cookie_secret, &send_buf);
        try testing.expectEqual(HandshakeAction.none, action);
        try testing.expectEqual(Session.ServerHandshakeState.expect_change_cipher_spec, server_session.handshake_state);
    }

    // Step 4: ChangeCipherSpec
    {
        const action = serverProcessMessage(&server_session, .change_cipher_spec, &[_]u8{0x01}, psk, cookie_secret, cookie_secret, &send_buf);
        try testing.expectEqual(HandshakeAction.none, action);
        try testing.expectEqual(Session.ServerHandshakeState.expect_finished, server_session.handshake_state);
        try testing.expectEqual(@as(u16, 1), server_session.read_epoch);
    }

    // Step 5: Client Finished
    {
        // Compute client verify_data.
        var client_verify: [12]u8 = undefined;
        {
            var hash_copy = server_session.handshake_hash;
            const hs_hash = hash_copy.finalResult();
            Prf.prf(&server_session.master_secret, "client finished", &hs_hash, &client_verify);
        }

        var hs_buf: [64]u8 = undefined;
        const hs_msg = encodeHandshakeMessage(.finished, 2, &client_verify, &hs_buf);

        const action = serverProcessMessage(&server_session, .handshake, hs_msg, psk, cookie_secret, cookie_secret, &send_buf);
        switch (action) {
            .send => |data| {
                try testing.expect(data.len > 0);
                // Should contain CCS + Finished.
            },
            else => return error.TestUnexpectedResult,
        }
        try testing.expectEqual(Session.State.established, server_session.state);
        try testing.expectEqual(Session.ServerHandshakeState.complete, server_session.handshake_state);
        try testing.expectEqual(@as(u16, 1), server_session.write_epoch);
    }
}

test "full client-server handshake integration" {
    const psk_identity = "my-device";
    const psk_key = "my-secret-key";
    const psk = types.Psk{ .identity = psk_identity, .key = psk_key };
    const cookie_secret = [_]u8{0xAA} ** 32;
    const addr = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 5684);

    var server_session: Session.Session = undefined;
    initTestSession(&server_session, addr);

    var client_session: Session.Session = undefined;
    initTestSession(&client_session, addr);

    var client_hs_state: ClientHandshakeState = .idle;
    var send_buf: [2048]u8 = undefined;
    var send_buf2: [2048]u8 = undefined;

    // Client → Initial ClientHello
    const action1 = clientBuildInitialHello(&client_session, &client_hs_state, psk, &send_buf);
    var client_data: []const u8 = undefined;
    switch (action1) {
        .send => |data| client_data = data,
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(ClientHandshakeState.expect_hello_verify_or_server_hello, client_hs_state);

    // Server processes ClientHello → HelloVerifyRequest
    {
        const rec = Record.decodePlaintext(client_data) orelse return error.TestUnexpectedNull;
        const action = serverProcessMessage(&server_session, rec.content_type, rec.payload, psk, cookie_secret, cookie_secret, &send_buf2);
        switch (action) {
            .send => |data| {
                // Client processes HVR
                const hvr_rec = Record.decodePlaintext(data) orelse return error.TestUnexpectedNull;
                const hvr_action = clientProcessMessage(
                    &client_session,
                    &client_hs_state,
                    hvr_rec.content_type,
                    hvr_rec.payload,
                    psk,
                    &send_buf,
                );
                switch (hvr_action) {
                    .send => |ch2_data| client_data = ch2_data,
                    else => return error.TestUnexpectedResult,
                }
            },
            else => return error.TestUnexpectedResult,
        }
    }

    // Server processes ClientHello with cookie → ServerHello flight
    var server_flight: []const u8 = undefined;
    {
        const rec = Record.decodePlaintext(client_data) orelse return error.TestUnexpectedNull;
        const action = serverProcessMessage(&server_session, rec.content_type, rec.payload, psk, cookie_secret, cookie_secret, &send_buf2);
        switch (action) {
            .send => |data| server_flight = data,
            else => return error.TestUnexpectedResult,
        }
    }

    // Client processes server flight (multiple records)
    {
        var off: usize = 0;
        while (off < server_flight.len) {
            // Parse record header to get length.
            if (off + types.record_header_len > server_flight.len) break;
            const rec_len = std.mem.readInt(u16, server_flight[off + 11 ..][0..2], .big);
            const total_rec = types.record_header_len + rec_len;
            if (off + total_rec > server_flight.len) break;

            const rec = Record.decodePlaintext(server_flight[off..][0..total_rec]) orelse {
                off += total_rec;
                continue;
            };

            const action = clientProcessMessage(
                &client_session,
                &client_hs_state,
                rec.content_type,
                rec.payload,
                psk,
                &send_buf,
            );
            switch (action) {
                .send => |data| {
                    // Client sends CKE + CCS + Finished flight.
                    // Feed it to the server.
                    var srv_off: usize = 0;
                    while (srv_off < data.len) {
                        if (srv_off + types.record_header_len > data.len) break;
                        const srv_rec_len = std.mem.readInt(u16, data[srv_off + 11 ..][0..2], .big);
                        const srv_total = types.record_header_len + srv_rec_len;
                        if (srv_off + srv_total > data.len) break;

                        const srv_rec_data = data[srv_off..][0..srv_total];
                        const epoch = std.mem.readInt(u16, srv_rec_data[3..5], .big);

                        if (epoch == 0) {
                            const srv_rec = Record.decodePlaintext(srv_rec_data) orelse {
                                srv_off += srv_total;
                                continue;
                            };
                            _ = serverProcessMessage(&server_session, srv_rec.content_type, srv_rec.payload, psk, cookie_secret, cookie_secret, &send_buf2);
                        } else {
                            // Encrypted record (Finished).
                            var pt_buf: [256]u8 = undefined;
                            const srv_rec = Record.decodeEncrypted(
                                srv_rec_data,
                                server_session.client_write_key,
                                server_session.client_write_iv,
                                &server_session.replay_window,
                                &server_session.read_sequence,
                                &pt_buf,
                            ) orelse {
                                srv_off += srv_total;
                                continue;
                            };
                            const srv_action = serverProcessMessage(&server_session, srv_rec.content_type, srv_rec.payload, psk, cookie_secret, cookie_secret, &send_buf2);
                            switch (srv_action) {
                                .send => |srv_resp| {
                                    // Server sends CCS + Finished back. Feed to client.
                                    var cli_off: usize = 0;
                                    while (cli_off < srv_resp.len) {
                                        if (cli_off + types.record_header_len > srv_resp.len) break;
                                        const cli_rec_len = std.mem.readInt(u16, srv_resp[cli_off + 11 ..][0..2], .big);
                                        const cli_total = types.record_header_len + cli_rec_len;
                                        if (cli_off + cli_total > srv_resp.len) break;

                                        const cli_rec_data = srv_resp[cli_off..][0..cli_total];
                                        const cli_epoch = std.mem.readInt(u16, cli_rec_data[3..5], .big);

                                        if (cli_epoch == 0) {
                                            const cli_rec = Record.decodePlaintext(cli_rec_data) orelse {
                                                cli_off += cli_total;
                                                continue;
                                            };
                                            _ = clientProcessMessage(&client_session, &client_hs_state, cli_rec.content_type, cli_rec.payload, psk, &send_buf);
                                        } else {
                                            var cli_pt_buf: [256]u8 = undefined;
                                            const cli_rec = Record.decodeEncrypted(
                                                cli_rec_data,
                                                client_session.server_write_key,
                                                client_session.server_write_iv,
                                                &client_session.replay_window,
                                                &client_session.read_sequence,
                                                &cli_pt_buf,
                                            ) orelse {
                                                cli_off += cli_total;
                                                continue;
                                            };
                                            _ = clientProcessMessage(&client_session, &client_hs_state, cli_rec.content_type, cli_rec.payload, psk, &send_buf);
                                        }
                                        cli_off += cli_total;
                                    }
                                },
                                else => {},
                            }
                        }
                        srv_off += srv_total;
                    }
                },
                .none => {},
                .established => {},
                else => return error.TestUnexpectedResult,
            }
            off += total_rec;
        }
    }

    // Both sides should be established with matching keys.
    try testing.expectEqual(Session.State.established, server_session.state);
    try testing.expectEqual(Session.State.established, client_session.state);
    try testing.expectEqual(ClientHandshakeState.complete, client_hs_state);
    try testing.expectEqualSlices(u8, &server_session.master_secret, &client_session.master_secret);
    try testing.expectEqualSlices(u8, &server_session.client_write_key, &client_session.client_write_key);
    try testing.expectEqualSlices(u8, &server_session.server_write_key, &client_session.server_write_key);
}

fn initTestSession(session: *Session.Session, addr: std.net.Address) void {
    session.* = .{
        .state = .handshaking,
        .peer_hash = 0,
        .addr = addr,
        .client_write_key = .{0} ** 16,
        .server_write_key = .{0} ** 16,
        .client_write_iv = .{0} ** 4,
        .server_write_iv = .{0} ** 4,
        .read_epoch = 0,
        .write_epoch = 0,
        .read_sequence = 0,
        .write_sequence = 0,
        .replay_window = 0,
        .handshake_state = .idle,
        .handshake_hash = Sha256.init(.{}),
        .client_random = .{0} ** 32,
        .server_random = .{0} ** 32,
        .message_seq = 0,
        .retransmit_deadline_ns = 0,
        .retransmit_count = 0,
        .retransmit_timeout_ms = 0,
        .master_secret = .{0} ** 48,
        .session_id = .{0} ** 32,
        .session_id_len = 0,
        .last_activity_ns = 0,
        .lru_prev = 0xFFFFFFFF,
        .lru_next = 0xFFFFFFFF,
        .next_free = 0xFFFFFFFF,
    };
}
