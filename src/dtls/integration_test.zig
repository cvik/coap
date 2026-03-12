const std = @import("std");
const testing = std.testing;
const posix = std.posix;
const linux = std.os.linux;

const dtls = @import("dtls.zig");
const Server = @import("../Server.zig");
const Client = @import("../Client.zig");
const handler = @import("../handler.zig");
const coapz = @import("coapz");

fn echoHandler(request: handler.Request) ?handler.Response {
    return .{ .payload = request.packet.payload };
}

const ServerRunner = struct {
    server: *Server,
    should_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(self: *@This()) void {
        while (!self.should_stop.load(.monotonic)) {
            self.server.tick() catch {};
            var cqes: [256]linux.io_uring_cqe = std.mem.zeroes([256]linux.io_uring_cqe);
            _ = self.server.io.wait_cqes(cqes[0..], 0) catch {};
        }
    }

    fn stop(self: *@This(), thread: std.Thread) void {
        self.should_stop.store(true, .monotonic);
        // Send a dummy packet to wake the server from blocking wait_cqes.
        const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
        defer posix.close(fd);
        const dest = std.net.Address.parseIp(
            "127.0.0.1",
            self.server.config.port,
        ) catch return;
        _ = posix.sendto(fd, &[_]u8{0}, 0, &dest.any, dest.getOsSockLen()) catch {};
        thread.join();
    }
};

const test_psk = dtls.types.Psk{
    .identity = "test-device",
    .key = "0123456789abcdef", // 16 bytes
};

test "DTLS: full handshake and CoAP echo over localhost" {
    const port: u16 = 19750;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .psk = test_psk,
    }, echoHandler);
    defer server.deinit();
    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .psk = test_psk,
    });
    defer client.deinit();

    try client.handshake();

    // Verify handshake succeeded.
    try testing.expect(client.dtls_session != null);
    try testing.expectEqual(.established, client.dtls_session.?.state);

    // CON GET — echo handler returns empty payload for GET.
    const result = try client.get(testing.allocator, "/test");
    defer result.deinit(testing.allocator);
    try testing.expectEqual(.content, result.code);
}

test "DTLS: CON POST echo with payload" {
    const port: u16 = 19751;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .psk = test_psk,
    }, echoHandler);
    defer server.deinit();
    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .psk = test_psk,
    });
    defer client.deinit();

    try client.handshake();
    try testing.expectEqual(.established, client.dtls_session.?.state);

    // POST with payload — echo handler returns the payload back.
    const result = try client.post(testing.allocator, "/echo", "hello-dtls");
    defer result.deinit(testing.allocator);
    try testing.expectEqual(.content, result.code);
    try testing.expectEqualSlices(u8, "hello-dtls", result.payload);
}

test "DTLS: multiple requests on one session" {
    const port: u16 = 19752;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .psk = test_psk,
    }, echoHandler);
    defer server.deinit();
    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .psk = test_psk,
    });
    defer client.deinit();

    try client.handshake();

    // Send multiple requests sequentially on the same session.
    for (0..5) |i| {
        var payload_buf: [32]u8 = undefined;
        const payload = std.fmt.bufPrint(&payload_buf, "msg-{d}", .{i}) catch unreachable;

        const result = try client.post(testing.allocator, "/echo", payload);
        defer result.deinit(testing.allocator);
        try testing.expectEqual(.content, result.code);
        try testing.expectEqualSlices(u8, payload, result.payload);
    }
}

test "plain UDP works without PSK" {
    const port: u16 = 19753;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
    }, echoHandler);
    defer server.deinit();
    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
    });
    defer client.deinit();

    // Should work without handshake — no DTLS.
    const result = try client.get(testing.allocator, "/hello");
    defer result.deinit(testing.allocator);
    try testing.expectEqual(.content, result.code);
}

test "DTLS: handshake fails with wrong PSK key" {
    const port: u16 = 19754;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .psk = test_psk,
    }, echoHandler);
    defer server.deinit();
    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .psk = .{
            .identity = "test-device",
            .key = "wrong-key-value!", // 16 bytes but wrong
        },
        .handshake_timeout_ms = 3_000,
    });
    defer client.deinit();

    const result = client.handshake();
    try testing.expectError(error.HandshakeFailed, result);
}

test "DTLS: NON cast over encrypted channel" {
    const port: u16 = 19755;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .psk = test_psk,
    }, echoHandler);
    defer server.deinit();
    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .psk = test_psk,
    });
    defer client.deinit();

    try client.handshake();

    // NON fire-and-forget should not error.
    try client.cast(.post, &.{}, "fire-and-forget");
}
