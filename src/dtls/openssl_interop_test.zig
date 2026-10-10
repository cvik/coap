/// OpenSSL interop tests for DTLS 1.2 PSK.
///
/// Validates that our DTLS client handshake state machine can complete
/// a handshake with OpenSSL's s_server. Skipped when openssl is not
/// available or does not support PSK-AES128-CCM8.
const std = @import("std");
const platform = @import("../platform.zig");
const testing = std.testing;
const posix = platform;

const dtls = @import("dtls.zig");
const Record = @import("Record.zig");
const Handshake = @import("Handshake.zig");
const Session = @import("Session.zig");

const test_psk = dtls.types.Psk{
    .identity = "test-device",
    .key = "0123456789abcdef", // 16 bytes
};

/// PSK key as hex string for openssl -psk flag.
const test_psk_hex = "30313233343536373839616263646566";

/// Check if openssl is available and supports the required cipher.
fn opensslAvailable() bool {
    var child = std.process.spawn(testing.io, .{
        .argv = &.{ "openssl", "ciphers", "PSK-AES128-CCM8@SECLEVEL=0" },
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return false;
    const result = child.wait(testing.io) catch return false;
    return result == .exited and result.exited == 0;
}

/// Generate a self-signed cert for openssl s_server (required even for PSK).
fn generateTestCert(cert_path: []const u8, key_path: []const u8) bool {
    var child = std.process.spawn(testing.io, .{
        .argv = &.{
            "openssl", "req",    "-x509", "-newkey",  "rsa:2048",
            "-keyout", key_path, "-out",  cert_path,  "-days",
            "1",       "-nodes", "-subj", "/CN=test", "-batch",
        },
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return false;
    const result = child.wait(testing.io) catch return false;
    return result == .exited and result.exited == 0;
}

/// Start OpenSSL DTLS server. Returns the child process.
/// Caller must hold stdin_pipe open to keep the server alive.
/// Note: do NOT use -listen — it creates a new connected socket after
/// cookie verification, so responses go to a different source port.
fn startOpensslServer(port: u16, psk_hex: []const u8, cert_path: []const u8, key_path: []const u8) !std.process.Child {
    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch unreachable;

    return std.process.spawn(testing.io, .{ .argv = &.{
        "openssl",
        "s_server",
        "-dtls1_2",
        "-4",
        "-cert",
        cert_path,
        "-key",
        key_path,
        "-psk",
        psk_hex,
        "-psk_identity",
        test_psk.identity,
        "-cipher",
        "PSK-AES128-CCM8@SECLEVEL=0",
        "-port",
        port_str,
        "-quiet",
    }, .stdin = .pipe, .stdout = .ignore, .stderr = .ignore });
}

/// Blocking recv with deadline (ms-granularity poll via sleep).
fn recvWithDeadline(fd: posix.fd_t, buf: []u8, deadline_ns: i128) ?usize {
    while (true) {
        const n = posix.recv(fd, buf, 0) catch |err| switch (err) {
            error.WouldBlock => {
                if (platform.nanoTimestamp() >= deadline_ns) return null;
                platform.sleep(500 * std.time.ns_per_us);
                continue;
            },
            else => return null,
        };
        return n;
    }
}

test "OpenSSL interop: handshake state machine with OpenSSL s_server" {
    if (!opensslAvailable()) {
        std.log.warn("openssl not available or missing PSK-AES128-CCM8, skipping", .{});
        return;
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &dir_buf);
    const cert_path = try std.fmt.allocPrint(testing.allocator, "{s}/cert.pem", .{dir_buf[0..dir_len]});
    defer testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrint(testing.allocator, "{s}/key.pem", .{dir_buf[0..dir_len]});
    defer testing.allocator.free(key_path);
    if (!generateTestCert(cert_path, key_path)) {
        std.log.warn("failed to generate test cert, skipping", .{});
        return;
    }

    const port: u16 = 19790;

    var ossl = startOpensslServer(port, test_psk_hex, cert_path, key_path) catch {
        std.log.warn("failed to start openssl s_server, skipping", .{});
        return;
    };
    defer {
        if (ossl.stdin) |stdin| stdin.close(testing.io);
        ossl.stdin = null;
        ossl.kill(testing.io);
    }

    // Wait for server to start listening.
    platform.sleep(500 * std.time.ns_per_ms);

    // Create raw UDP socket, bypassing Client abstraction.
    const dest = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(fd);
    try posix.connect(fd, dest);

    var session: Session.Session = std.mem.zeroInit(Session.Session, .{ .addr = platform.ip4(.{ 0, 0, 0, 0 }, 0) });
    var hs_state: Handshake.ClientHandshakeState = .idle;
    var send_buf: [512]u8 = undefined;
    var recv_buf: [1500]u8 = undefined;
    var pt_buf: [512]u8 = undefined;

    // Build and send initial ClientHello.
    const action = Handshake.clientBuildInitialHello(&session, &hs_state, test_psk, &send_buf, &.{});
    const initial_flight = switch (action) {
        .send => |data| data,
        else => return error.TestUnexpectedResult,
    };
    _ = posix.send(fd, initial_flight, 0) catch return error.TestUnexpectedResult;

    const deadline_ns: i128 = platform.nanoTimestamp() + 10 * std.time.ns_per_s;

    // Handshake loop.
    while (hs_state != .complete) {
        if (platform.nanoTimestamp() >= deadline_ns) {
            std.debug.print("interop: timeout in state {}\n", .{hs_state});
            return error.TestUnexpectedResult;
        }

        const n = recvWithDeadline(fd, &recv_buf, deadline_ns) orelse {
            return error.TestUnexpectedResult;
        };
        const data = recv_buf[0..n];

        // Iterate records in datagram.
        var off: usize = 0;
        while (off < data.len) {
            const remaining = data[off..];
            if (remaining.len < dtls.types.record_header_len) break;

            const rec_len = std.mem.readInt(u16, remaining[11..13], .big);
            const total_rec = dtls.types.record_header_len + rec_len;
            if (remaining.len < total_rec) break;

            const rec_data = remaining[0..total_rec];
            const epoch = std.mem.readInt(u16, rec_data[3..5], .big);

            const record = if (epoch == 0)
                Record.decodePlaintext(rec_data)
            else
                Record.decodeEncrypted(
                    rec_data,
                    session.server_write_key,
                    session.server_write_iv,
                    &session.replay_window,
                    &session.read_sequence,
                    &pt_buf,
                );

            off += total_rec;
            const rec = record orelse continue;

            const hs_action = Handshake.clientProcessMessage(
                &session,
                &hs_state,
                rec.content_type,
                rec.payload,
                test_psk,
                &send_buf,
            );
            switch (hs_action) {
                .send => |sdata| {
                    _ = posix.send(fd, sdata, 0) catch {};
                },
                .established => {},
                .failed => {
                    std.debug.print("interop: handshake failed in state {}\n", .{hs_state});
                    return error.TestUnexpectedResult;
                },
                .none => {},
            }
        }
    }

    // Handshake succeeded.
    try testing.expectEqual(.established, session.state);
}
