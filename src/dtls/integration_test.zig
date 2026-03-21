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

var block1_received_len: usize = 0;
var block1_first_byte: u8 = 0;
var block1_last_byte: u8 = 0;

fn block1BodyHandler(request: handler.Request) ?handler.Response {
    const body = request.payload();
    block1_received_len = body.len;
    if (body.len > 0) {
        block1_first_byte = body[0];
        block1_last_byte = body[body.len - 1];
    }
    return handler.Response{
        .code = .changed,
        .payload = "ok",
        .options = &.{},
    };
}

test "Block1: handler receives full reassembled body" {
    const port: u16 = 19770;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .max_block_transfers = 8,
        .max_block_payload = 8192,
    }, block1BodyHandler);
    defer server.deinit();
    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .max_in_flight = 4,
    });
    defer client.deinit();

    // 2048-byte payload — requires multiple blocks at default szx=6 (1024 bytes).
    const payload = [_]u8{0x42} ** 2048;
    var path_buf: [1]coapz.Option = .{coapz.Option{ .kind = .uri_path, .value = "data" }};
    block1_received_len = 0;
    const result = try client.upload(testing.allocator, .put, &path_buf, &payload);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(.changed, result.code);
    // Handler should have received the FULL reassembled body (2048 bytes).
    // Bug #81: handler only sees the last fragment (1024 bytes).
    try testing.expectEqual(@as(usize, 2048), block1_received_len);
    try testing.expectEqual(@as(u8, 0x42), block1_first_byte);
    try testing.expectEqual(@as(u8, 0x42), block1_last_byte);
}

var observe_resource_id: ?u16 = null;

fn observeRegHandler(request: handler.Request) ?handler.Response {
    if (request.method() == .get) {
        if (observe_resource_id) |rid| {
            _ = request.observeResource(rid);
        }
        var obs_buf: [4]u8 = undefined;
        const obs_opt = coapz.Option.uint(.observe, 1, &obs_buf);
        const opts = request.arena.dupe(coapz.Option, &.{obs_opt}) catch
            return handler.Response.withCode(.internal_server_error);
        return handler.Response{
            .code = .content,
            .payload = "initial",
            .options = opts,
        };
    }
    return handler.Response.withCode(.method_not_allowed);
}

test "Observe: notification carries correct client token" {
    const port: u16 = 19771;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .max_observers = 16,
        .max_observe_resources = 4,
    }, observeRegHandler);
    defer server.deinit();

    const rid = server.allocateResource() orelse return error.NoResource;
    observe_resource_id = rid;

    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .max_in_flight = 4,
    });
    defer client.deinit();

    // Register observe.
    var path_buf: [1]coapz.Option = .{coapz.Option{ .kind = .uri_path, .value = "temp" }};
    var stream = try client.observe(&path_buf);

    // Push a notification from the server.
    server.notify(rid, handler.Response{
        .code = .content,
        .payload = "22.5",
        .options = &.{},
    });

    // stream.next() blocks — use a thread with cancel timeout.
    const NextCtx = struct {
        stream: *Client.ObserveStream,
        result: ?Client.ObserveStream.Notification = null,
        fn run(self: *@This()) void {
            self.result = self.stream.next(testing.allocator) catch null;
        }
    };
    var next_ctx = NextCtx{ .stream = &stream };
    const next_thread = try std.Thread.spawn(.{}, NextCtx.run, .{&next_ctx});

    std.Thread.sleep(300 * std.time.ns_per_ms);
    stream.cancel() catch {};
    next_thread.join();

    const notif = next_ctx.result orelse return error.NoNotification;
    defer notif.deinit(testing.allocator);

    // Verify token matches client's observe subscription token.
    // Bug #82: token was &.{0} instead of the real client token,
    // which meant routeObserve never matched and next() blocked forever.
    const sub = &client.observes[0];
    const expected_token = sub.token[0..sub.token_len];
    try testing.expectEqualSlices(u8, expected_token, notif.packet.token);
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
