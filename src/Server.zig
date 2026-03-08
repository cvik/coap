/// CoAP server built on io_uring.
///
/// All memory is pre-allocated at init. Handlers receive a per-request
/// arena allocator that resets after each batch of completions.
/// CON messages are deduplicated and their responses are cached for
/// retransmission per RFC 7252 §4.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const coapz = @import("coapz");
const Io = @import("Io.zig");
const Exchange = @import("exchange.zig");
const handler = @import("handler.zig");
const constants = @import("constants.zig");
const log = std.log.scoped(.coapd);

const Cqe = linux.io_uring_cqe;

const Server = @This();

pub const Config = struct {
    port: u16 = constants.port_default,
    buffer_count: u16 = constants.buffer_count_default,
    buffer_size: u32 = constants.buffer_size_default,
    /// Maximum concurrent CON exchanges for duplicate detection.
    exchange_count: u16 = 256,
    /// Link-format payload for GET /.well-known/core (RFC 6690).
    /// If null, requests pass through to the handler.
    well_known_core: ?[]const u8 = null,
    /// Number of server threads. Each gets its own socket/ring/exchange pool.
    /// Kernel distributes packets via SO_REUSEPORT.
    thread_count: u16 = 1,
};

allocator: std.mem.Allocator,
io: Io,
handler_fn: handler.HandlerFn,
arena: std.heap.ArenaAllocator,
config: Config,
exchanges: Exchange,

// Pre-allocated per-CQE response state.
addrs_response: []linux.sockaddr,
msgs_response: []linux.msghdr_const,
iovs_response: []posix.iovec,
buffer_response: []u8,

// Recv state.
addr_recv: linux.sockaddr,
msg_recv: linux.msghdr,

// Eviction timer.
last_eviction_ns: i128,

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

    var exchanges = try Exchange.init(allocator, .{
        .exchange_count = config.exchange_count,
        .response_size_max = @intCast(config.buffer_size),
    });
    errdefer exchanges.deinit(allocator);

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
        .exchanges = exchanges,
        .addrs_response = addrs_response,
        .msgs_response = msgs_response,
        .iovs_response = iovs_response,
        .buffer_response = buffer_response,
        .addr_recv = std.mem.zeroes(linux.sockaddr),
        .msg_recv = std.mem.zeroes(linux.msghdr),
        .last_eviction_ns = 0,
    };
}

pub fn deinit(server: *Server) void {
    server.arena.deinit();
    server.exchanges.deinit(server.allocator);
    server.io.deinit(server.allocator);
    server.allocator.free(server.addrs_response);
    server.allocator.free(server.msgs_response);
    server.allocator.free(server.iovs_response);
    server.allocator.free(server.buffer_response);
}

/// Bind the socket, register buffers, and arm the multishot recv.
/// After this returns the server is ready to accept packets.
pub fn listen(server: *Server) !void {
    try server.io.setup(server.config.port);

    server.msg_recv.name = &server.addr_recv;
    server.msg_recv.namelen = @sizeOf(linux.sockaddr);
    server.msg_recv.controllen = 0;

    try server.io.recv_multishot(&server.msg_recv);
    _ = try server.io.submit();
}

pub fn run(server: *Server) !void {
    try server.listen();

    const extra = server.config.thread_count -| 1;
    const threads = try server.allocator.alloc(std.Thread, extra);
    defer server.allocator.free(threads);

    for (threads) |*t| {
        t.* = try std.Thread.spawn(.{}, run_worker, .{
            server.allocator,
            server.config,
            server.handler_fn,
        });
    }

    log.info("coapd listening on port {d} ({d} thread{s})", .{
        server.config.port,
        server.config.thread_count,
        if (server.config.thread_count > 1) "s" else "",
    });

    while (true) {
        try server.tick();
    }
}

fn run_worker(
    allocator: std.mem.Allocator,
    config: Config,
    handler_fn: handler.HandlerFn,
) void {
    var worker = Server.init(allocator, config, handler_fn) catch return;
    defer worker.deinit();
    worker.listen() catch return;
    while (true) worker.tick() catch return;
}

pub fn tick(server: *Server) !void {
    const batch_max = constants.completion_batch_max;
    var cqes: [batch_max]Cqe = std.mem.zeroes([batch_max]Cqe);

    const count = try server.io.wait_cqes(cqes[0..], 1);
    var recv_failed = false;

    for (cqes[0..count], 0..) |cqe, index| {
        if (Io.is_recv(&cqe) and !Io.is_success(&cqe)) {
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

    // Periodic exchange eviction (~every 10 seconds).
    const now = std.time.nanoTimestamp();
    const eviction_interval_ns: i128 = 10 * std.time.ns_per_s;
    if (now - server.last_eviction_ns > eviction_interval_ns) {
        const evicted = server.exchanges.evict_expired(now);
        if (evicted > 0) {
            log.debug("evicted {d} expired exchanges", .{evicted});
        }
        server.last_eviction_ns = now;
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

    defer server.io.release_buffer(recv.buffer_id) catch |err| {
        log.err("release_buffer {d}: {}", .{ recv.buffer_id, err });
    };

    const packet = coapz.Packet.read(arena, recv.payload) catch |err| {
        log.debug("malformed CoAP packet: {}", .{err});
        return;
    };

    // RST cancels the matching exchange.
    if (packet.kind == .reset) {
        const key = Exchange.peer_key(recv.peer_address, packet.msg_id);
        if (server.exchanges.find(key)) |slot_idx| {
            server.exchanges.remove(slot_idx);
        }
        return;
    }

    const is_con = packet.kind == .confirmable;

    // CON duplicate detection.
    if (is_con) {
        const key = Exchange.peer_key(recv.peer_address, packet.msg_id);
        if (server.exchanges.find(key)) |slot_idx| {
            // Duplicate CON — retransmit cached response.
            const cached = server.exchanges.cached_response(slot_idx);
            try server.send_data(cached, recv.peer_address, index);
            return;
        }
    }

    const request = handler.Request{
        .packet = packet,
        .peer_address = recv.peer_address,
        .arena = arena,
    };

    const maybe_response = blk: {
        if (server.config.well_known_core) |wkc| {
            if (is_well_known_core(packet)) {
                var cf_buf: [2]u8 = undefined;
                const cf_opt = coapz.Option.content_format(
                    .link_format,
                    &cf_buf,
                );
                const opts = try arena.dupe(coapz.Option, &.{cf_opt});
                break :blk @as(?handler.Response, .{
                    .code = .content,
                    .options = opts,
                    .payload = wkc,
                });
            }
        }
        break :blk server.handler_fn(request);
    };

    if (maybe_response) |response| {
        const response_kind: coapz.MessageKind = if (is_con)
            .acknowledgement
        else
            .non_confirmable;

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
        try server.send_data(data_wire, recv.peer_address, index);

        // Cache the response for CON dedup.
        if (is_con) {
            const key = Exchange.peer_key(
                recv.peer_address,
                packet.msg_id,
            );
            const now = std.time.nanoTimestamp();
            if (server.exchanges.insert(
                key,
                packet.msg_id,
                data_wire,
                now,
            ) == null) {
                log.warn("exchange pool full, cannot cache", .{});
            }
        }
    } else if (is_con) {
        // No handler response, but CON requires an empty ACK.
        const ack = coapz.Packet{
            .kind = .acknowledgement,
            .code = .empty,
            .msg_id = packet.msg_id,
            .token = &.{},
            .options = &.{},
            .payload = &.{},
            .data_buf = &.{},
        };
        const data_wire = try ack.write(arena);
        try server.send_data(data_wire, recv.peer_address, index);

        // Cache the empty ACK too.
        const key = Exchange.peer_key(
            recv.peer_address,
            packet.msg_id,
        );
        const now = std.time.nanoTimestamp();
        _ = server.exchanges.insert(
            key,
            packet.msg_id,
            data_wire,
            now,
        );
    }
}

/// Encode and queue a UDP response to the peer.
fn send_data(
    server: *Server,
    data: []const u8,
    peer_address: std.net.Address,
    index: usize,
) !void {
    if (data.len > server.config.buffer_size) {
        log.err("response too large: {d} > {d}", .{
            data.len,
            server.config.buffer_size,
        });
        return;
    }

    const offset_buf = index * server.config.buffer_size;
    const slot = server.buffer_response[offset_buf..][0..data.len];
    @memcpy(slot, data);

    server.addrs_response[index] = peer_address.any;

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

/// Check if the packet is a GET /.well-known/core request.
fn is_well_known_core(packet: coapz.Packet) bool {
    if (packet.code != .get) return false;

    var it = packet.find_options(.uri_path);
    const seg1 = it.next() orelse return false;
    if (!std.mem.eql(u8, seg1.value, ".well-known")) return false;
    const seg2 = it.next() orelse return false;
    if (!std.mem.eql(u8, seg2.value, "core")) return false;
    // Must be exactly two segments.
    return it.next() == null;
}

// ─── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

fn echo_handler(request: handler.Request) ?handler.Response {
    return .{ .payload = request.packet.payload };
}

fn null_handler(_: handler.Request) ?handler.Response {
    return null;
}

var handler_call_count: u32 = 0;

fn counting_handler(request: handler.Request) ?handler.Response {
    handler_call_count += 1;
    return .{ .payload = request.packet.payload };
}

/// Helper: setup server io and multishot recv (for tests).
fn setup_for_test(server: *Server) !void {
    try server.listen();
}

/// Helper: create a UDP client socket with a receive timeout.
fn test_client(port: u16) !posix.socket_t {
    const fd = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        0,
    );

    const timeout = posix.timeval{ .sec = 1, .usec = 0 };
    try posix.setsockopt(
        fd,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        std.mem.asBytes(&timeout),
    );

    const dest = try std.net.Address.parseIp("127.0.0.1", port);
    try posix.connect(fd, &dest.any, dest.getOsSockLen());

    return fd;
}

/// Helper: send, tick, and receive a response.
fn send_tick_recv(
    server: *Server,
    client_fd: posix.socket_t,
    wire: []const u8,
) ![]const u8 {
    _ = try posix.send(client_fd, wire, 0);
    try server.tick();

    var cqes: [constants.completion_batch_max]Cqe =
        std.mem.zeroes([constants.completion_batch_max]Cqe);
    _ = try server.io.wait_cqes(cqes[0..], 0);

    var buf: [1280]u8 = undefined;
    const n = try posix.recv(client_fd, &buf, 0);
    // Copy to arena so caller can use it without lifetime issues.
    const result = try testing.allocator.alloc(u8, n);
    @memcpy(result, buf[0..n]);
    return result;
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

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);

    const response = try coapz.Packet.read(testing.allocator, raw);
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

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);

    const response = try coapz.Packet.read(testing.allocator, raw);
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.acknowledgement, response.kind);
    try testing.expectEqual(.content, response.code);
    try testing.expectEqual(@as(u16, 0xABCD), response.msg_id);
    try testing.expectEqualSlices(u8, &.{0x01}, response.token);
    try testing.expectEqualSlices(u8, "data", response.payload);
}

test "CON null handler sends empty ACK" {
    const port: u16 = 19685;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, null_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0x9999,
        .token = &.{0x42},
        .options = &.{},
        .payload = &.{},
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);

    const response = try coapz.Packet.read(testing.allocator, raw);
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.acknowledgement, response.kind);
    try testing.expectEqual(.empty, response.code);
    try testing.expectEqual(@as(u16, 0x9999), response.msg_id);
}

test "NON null handler sends no response" {
    const port: u16 = 19686;

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

    var buf: [1280]u8 = undefined;
    const result = posix.recv(
        client_fd,
        &buf,
        posix.SOCK.NONBLOCK,
    );
    try testing.expectError(error.WouldBlock, result);
}

test "CON duplicate detection" {
    const port: u16 = 19687;

    handler_call_count = 0;
    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
        .exchange_count = 16,
    }, counting_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0xDEAD,
        .token = &.{0x01},
        .options = &.{},
        .payload = "test",
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    // First request — handler should be called.
    const raw1 = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw1);
    try testing.expectEqual(@as(u32, 1), handler_call_count);

    // Second request (same msg_id) — handler should NOT be called.
    // The cached response should be retransmitted.
    const raw2 = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw2);
    try testing.expectEqual(@as(u32, 1), handler_call_count);

    // Both responses should be identical.
    try testing.expectEqualSlices(u8, raw1, raw2);

    const response = try coapz.Packet.read(testing.allocator, raw2);
    defer response.deinit(testing.allocator);
    try testing.expectEqual(.acknowledgement, response.kind);
    try testing.expectEqualSlices(u8, "test", response.payload);
}

test "RST cancels CON exchange" {
    const port: u16 = 19688;

    handler_call_count = 0;
    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
        .exchange_count = 16,
    }, counting_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    // Send CON, get ACK — handler called once.
    const con_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0xBEEF,
        .token = &.{0x01},
        .options = &.{},
        .payload = "rst-test",
        .data_buf = &.{},
    };
    const con_wire = try con_packet.write(testing.allocator);
    defer testing.allocator.free(con_wire);

    const raw1 = try send_tick_recv(&server, client_fd, con_wire);
    defer testing.allocator.free(raw1);
    try testing.expectEqual(@as(u32, 1), handler_call_count);

    // Send RST with same msg_id to cancel the exchange.
    const rst_packet = coapz.Packet{
        .kind = .reset,
        .code = .empty,
        .msg_id = 0xBEEF,
        .token = &.{},
        .options = &.{},
        .payload = &.{},
        .data_buf = &.{},
    };
    const rst_wire = try rst_packet.write(testing.allocator);
    defer testing.allocator.free(rst_wire);

    _ = try posix.send(client_fd, rst_wire, 0);
    try server.tick();

    // Drain any send CQEs.
    var cqes: [constants.completion_batch_max]Cqe =
        std.mem.zeroes([constants.completion_batch_max]Cqe);
    _ = try server.io.wait_cqes(cqes[0..], 0);

    // Send same CON again — exchange was cleared, handler called again.
    const raw2 = try send_tick_recv(&server, client_fd, con_wire);
    defer testing.allocator.free(raw2);
    try testing.expectEqual(@as(u32, 2), handler_call_count);
}

test "GET /.well-known/core returns link format" {
    const port: u16 = 19689;
    const wkc_payload = "</sensors>;rt=\"temperature\"";

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
        .well_known_core = wkc_payload,
    }, null_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x7777,
        .token = &.{0x42},
        .options = &.{
            .{ .kind = .uri_path, .value = ".well-known" },
            .{ .kind = .uri_path, .value = "core" },
        },
        .payload = &.{},
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);

    const response = try coapz.Packet.read(testing.allocator, raw);
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.content, response.code);
    try testing.expectEqualSlices(u8, wkc_payload, response.payload);

    // Verify content-format option is present (value 40 = link_format).
    var cf_it = response.find_options(.content_format);
    const cf_opt = cf_it.next();
    try testing.expect(cf_opt != null);
}

test "well_known_core null passes to handler" {
    const port: u16 = 19690;

    handler_call_count = 0;
    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, counting_handler);
    defer server.deinit();
    try setup_for_test(&server);

    // Send a /.well-known/core request — should pass to handler.
    const request_packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x8888,
        .token = &.{0x01},
        .options = &.{
            .{ .kind = .uri_path, .value = ".well-known" },
            .{ .kind = .uri_path, .value = "core" },
        },
        .payload = &.{},
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);
    try testing.expectEqual(@as(u32, 1), handler_call_count);
}
