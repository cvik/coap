/// CoAP server built on io_uring.
///
/// All memory is pre-allocated at init. Handlers receive a per-request
/// arena allocator that resets after each batch of completions.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const coapz = @import("coapz");
const Io = @import("Io.zig");
const handler = @import("handler.zig");
const constants = @import("constants.zig");
const log = std.log.scoped(.coapd);

const Cqe = linux.io_uring_cqe;

const Server = @This();

pub const Config = struct {
    port: u16 = constants.port_default,
    buffer_count: u16 = constants.buffer_count_default,
    buffer_size: u32 = constants.buffer_size_default,
};

allocator: std.mem.Allocator,
io: Io,
handler_fn: handler.HandlerFn,
arena: std.heap.ArenaAllocator,
config: Config,

// Pre-allocated per-CQE response state.
addrs_response: []linux.sockaddr,
msgs_response: []linux.msghdr_const,
iovs_response: []posix.iovec,
buffer_response: []u8,

// Recv state.
addr_recv: linux.sockaddr,
msg_recv: linux.msghdr,

pub fn init(
    allocator: std.mem.Allocator,
    config: Config,
    handler_fn: handler.HandlerFn,
) !Server {
    std.debug.assert(config.buffer_count > 0);
    std.debug.assert(config.buffer_size >= 64);
    std.debug.assert(config.port > 0);

    var io = try Io.init(
        allocator,
        config.buffer_count,
        config.buffer_size,
    );
    errdefer io.deinit(allocator);

    const batch: usize = @min(
        constants.completion_batch_max,
        config.buffer_count,
    );

    const addrs_response = try allocator.alloc(
        linux.sockaddr,
        batch,
    );
    errdefer allocator.free(addrs_response);

    const msgs_response = try allocator.alloc(
        linux.msghdr_const,
        batch,
    );
    errdefer allocator.free(msgs_response);

    const iovs_response = try allocator.alloc(posix.iovec, batch);
    errdefer allocator.free(iovs_response);

    const buffer_response = try allocator.alloc(
        u8,
        batch * config.buffer_size,
    );
    errdefer allocator.free(buffer_response);

    return .{
        .allocator = allocator,
        .io = io,
        .handler_fn = handler_fn,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .config = config,
        .addrs_response = addrs_response,
        .msgs_response = msgs_response,
        .iovs_response = iovs_response,
        .buffer_response = buffer_response,
        .addr_recv = std.mem.zeroes(linux.sockaddr),
        .msg_recv = std.mem.zeroes(linux.msghdr),
    };
}

pub fn deinit(server: *Server) void {
    server.arena.deinit();
    server.io.deinit(server.allocator);
    server.allocator.free(server.addrs_response);
    server.allocator.free(server.msgs_response);
    server.allocator.free(server.iovs_response);
    server.allocator.free(server.buffer_response);
}

pub fn run(server: *Server) !void {
    try server.io.setup(server.config.port);

    server.msg_recv.name = &server.addr_recv;
    server.msg_recv.namelen = @sizeOf(linux.sockaddr);
    server.msg_recv.controllen = 0;

    try server.io.recv_multishot(&server.msg_recv);
    _ = try server.io.submit();

    log.info("coapd listening on port {d}", .{server.config.port});

    while (true) {
        try server.tick();
    }
}

fn tick(server: *Server) !void {
    const batch_max = constants.completion_batch_max;
    var cqes: [batch_max]Cqe = std.mem.zeroes([batch_max]Cqe);

    const count = try server.io.wait_cqes(cqes[0..], 1);
    var recv_failed = false;

    for (cqes[0..count], 0..) |cqe, index| {
        if (Io.is_recv(&cqe) and !Io.is_success(&cqe)) {
            // Multishot recv is cancelled on error. Must re-arm.
            recv_failed = true;
            continue;
        }
        if (!Io.is_success(&cqe)) {
            continue;
        }
        if (!Io.is_recv(&cqe)) {
            continue;
        }

        server.handle_recv(&cqe, index) catch |err| {
            log.err("handle_recv: {}", .{err});
        };
    }

    if (recv_failed) {
        log.warn("multishot recv failed, re-arming", .{});
        try server.io.recv_multishot(&server.msg_recv);
    }

    _ = try server.io.submit();
    _ = server.arena.reset(.retain_capacity);
}

fn handle_recv(
    server: *Server,
    cqe: *const Cqe,
    index: usize,
) !void {
    const arena = server.arena.allocator();

    const recv = try server.io.decode_recv(cqe);

    // Release the kernel buffer. Log on failure rather than
    // silently losing buffers from the pool.
    defer server.io.release_buffer(recv.buffer_id) catch |err| {
        log.err("release_buffer {d}: {}", .{ recv.buffer_id, err });
    };

    const packet = coapz.Packet.read(arena, recv.payload) catch |err| {
        log.debug("malformed CoAP packet: {}", .{err});
        return;
    };

    const request = handler.Request{
        .packet = packet,
        .peer_address = recv.peer_address,
        .arena = arena,
    };

    const response = server.handler_fn(request) orelse {
        // No response. For CON, an empty ACK would go here (Phase 2).
        return;
    };

    // Build the response packet.
    const response_kind: coapz.MessageKind = switch (packet.kind) {
        .confirmable => .acknowledgement,
        else => .non_confirmable,
    };

    const response_packet = coapz.Packet{
        .kind = response_kind,
        .code = response.code,
        .msg_id = packet.msg_id,
        .token = packet.token,
        .options = response.options,
        .payload = response.payload,
        .data_buf = &.{},
    };

    const data_wire = try response_packet.write(arena);

    if (data_wire.len > server.config.buffer_size) {
        log.err("response too large: {d} > {d}", .{
            data_wire.len,
            server.config.buffer_size,
        });
        return;
    }

    // Copy into pre-allocated response buffer so arena can reset.
    const offset_buf = index * server.config.buffer_size;
    const slot = server.buffer_response[offset_buf..][0..data_wire.len];
    @memcpy(slot, data_wire);

    // Copy the peer address directly — it is already a valid sockaddr.
    server.addrs_response[index] = recv.peer_address.any;

    server.iovs_response[index] = .{
        .base = @ptrCast(slot.ptr),
        .len = slot.len,
    };

    server.msgs_response[index] = .{
        .name = @ptrCast(&server.addrs_response[index]),
        .namelen = @sizeOf(linux.sockaddr),
        .iov = @ptrCast(&server.iovs_response[index]),
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    try server.io.send_msg(&server.msgs_response[index]);
}

const testing = std.testing;

fn echo_handler(request: handler.Request) ?handler.Response {
    return .{ .payload = request.packet.payload };
}

fn null_handler(_: handler.Request) ?handler.Response {
    return null;
}

/// Helper: setup server io and multishot recv (for tests).
fn setup_for_test(server: *Server) !void {
    try server.io.setup(server.config.port);
    server.msg_recv.name = &server.addr_recv;
    server.msg_recv.namelen = @sizeOf(linux.sockaddr);
    server.msg_recv.controllen = 0;
    try server.io.recv_multishot(&server.msg_recv);
    _ = try server.io.submit();
}

/// Helper: create a UDP client socket with a receive timeout.
fn test_client(port: u16) !posix.socket_t {
    const fd = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        0,
    );

    // Set 1 second receive timeout.
    const timeout = posix.timeval{ .sec = 1, .usec = 0 };
    try posix.setsockopt(
        fd,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        std.mem.asBytes(&timeout),
    );

    // Connect so recv works without recvfrom.
    const dest = try std.net.Address.parseIp("127.0.0.1", port);
    try posix.connect(fd, &dest.any, dest.getOsSockLen());

    return fd;
}

test "init and deinit" {
    var server = try Server.init(testing.allocator, .{
        .port = 19680,
        .buffer_count = 4,
        .buffer_size = 256,
    }, echo_handler);
    server.deinit();
}

test "init and deinit with null handler" {
    var server = try Server.init(testing.allocator, .{
        .port = 19681,
        .buffer_count = 4,
        .buffer_size = 256,
    }, null_handler);
    server.deinit();
}

test "round-trip: NON echo via UDP" {
    const port: u16 = 19683;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, echo_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x1234,
        .token = &.{ 0xAA, 0xBB },
        .options = &.{},
        .payload = "hello",
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    _ = try posix.send(client_fd, wire, 0);

    // First tick: recv the request, queue the sendmsg, submit.
    try server.tick();
    // Second tick: the sendmsg CQE completes, no new recv yet.
    // Use non-blocking wait to avoid hanging if no CQEs ready.
    {
        var cqes: [constants.completion_batch_max]Cqe =
            std.mem.zeroes([constants.completion_batch_max]Cqe);
        _ = try server.io.wait_cqes(cqes[0..], 0);
    }

    var buf: [1280]u8 = undefined;
    const n = try posix.recv(client_fd, &buf, 0);
    try testing.expect(n > 0);

    const response = try coapz.Packet.read(
        testing.allocator,
        buf[0..n],
    );
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.non_confirmable, response.kind);
    try testing.expectEqual(.content, response.code);
    try testing.expectEqual(@as(u16, 0x1234), response.msg_id);
    try testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, response.token);
    try testing.expectEqualSlices(u8, "hello", response.payload);
}

test "round-trip: CON echoes as ACK" {
    const port: u16 = 19684;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, echo_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .post,
        .msg_id = 0xABCD,
        .token = &.{0x01},
        .options = &.{},
        .payload = "data",
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    _ = try posix.send(client_fd, wire, 0);
    try server.tick();
    {
        var cqes: [constants.completion_batch_max]Cqe =
            std.mem.zeroes([constants.completion_batch_max]Cqe);
        _ = try server.io.wait_cqes(cqes[0..], 0);
    }

    var buf: [1280]u8 = undefined;
    const n = try posix.recv(client_fd, &buf, 0);
    try testing.expect(n > 0);

    const response = try coapz.Packet.read(
        testing.allocator,
        buf[0..n],
    );
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.acknowledgement, response.kind);
    try testing.expectEqual(.content, response.code);
    try testing.expectEqual(@as(u16, 0xABCD), response.msg_id);
    try testing.expectEqualSlices(u8, &.{0x01}, response.token);
    try testing.expectEqualSlices(u8, "data", response.payload);
}

test "null handler sends no response" {
    const port: u16 = 19685;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, null_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x5678,
        .token = &.{},
        .options = &.{},
        .payload = &.{},
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    _ = try posix.send(client_fd, wire, 0);
    try server.tick();

    // No response expected. Non-blocking check.
    var buf: [1280]u8 = undefined;
    const result = posix.recv(
        client_fd,
        &buf,
        posix.SOCK.NONBLOCK,
    );
    try testing.expectError(error.WouldBlock, result);
}
