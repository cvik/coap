const std = @import("std");
const coapz = @import("coapz");
const log = std.log.scoped(.coapd);

/// Incoming CoAP request passed to the handler function.
pub const Request = struct {
    /// Parsed CoAP packet. Valid only for the handler invocation.
    packet: coapz.Packet,
    /// Source address of the peer.
    peer_address: std.net.Address,
    /// Arena allocator that resets after the handler returns.
    arena: std.mem.Allocator,

    /// Request method (GET, POST, PUT, DELETE, …).
    pub inline fn method(self: Request) coapz.Code {
        return self.packet.code;
    }

    /// Request payload bytes.
    pub inline fn payload(self: Request) []const u8 {
        return self.packet.payload;
    }

    /// Iterator over URI-Path option segments.
    pub inline fn pathSegments(self: Request) coapz.OptionIterator {
        return self.packet.find_options(.uri_path);
    }

    /// Iterator over URI-Query option values.
    pub inline fn querySegments(self: Request) coapz.OptionIterator {
        return self.packet.find_options(.uri_query);
    }

    /// Iterator over options of a given kind.
    pub inline fn findOptions(self: Request, kind: coapz.OptionKind) coapz.OptionIterator {
        return self.packet.find_options(kind);
    }

    /// First option of a given kind, or null.
    pub inline fn findOption(self: Request, kind: coapz.OptionKind) ?coapz.Option {
        return self.packet.find_option(kind);
    }
};

/// CoAP response returned by a handler.
pub const Response = struct {
    code: coapz.Code = .content,
    options: []const coapz.Option = &.{},
    payload: []const u8 = &.{},
};

/// Type-erased handler function stored by the server.
pub const HandlerFn = *const fn (?*anyopaque, Request) ?Response;

/// Simple handler function type (no context).
pub const SimpleHandlerFn = *const fn (Request) ?Response;

/// Trampoline for simple handlers: recovers the original function pointer
/// from the type-erased context and calls it.
pub fn wrapSimple(ctx: ?*anyopaque, request: Request) ?Response {
    const func: SimpleHandlerFn = @ptrCast(ctx.?);
    return func(request);
}

/// Wrap a handler that returns `!?Response` into a `SimpleHandlerFn`.
/// Errors are logged and converted to 5.00 Internal Server Error.
pub fn safeWrap(comptime func: fn (Request) anyerror!?Response) SimpleHandlerFn {
    return struct {
        fn call(request: Request) ?Response {
            return func(request) catch |err| {
                log.warn("handler error: {}", .{err});
                return .{ .code = .internal_server_error };
            };
        }
    }.call;
}

/// Wrap a typed-context handler that returns `!?Response`.
/// Errors are logged and converted to 5.00 Internal Server Error.
pub fn safeWrapContext(comptime Context: type, comptime func: fn (Context, Request) anyerror!?Response) fn (Context, Request) ?Response {
    return struct {
        fn call(ctx: Context, request: Request) ?Response {
            return func(ctx, request) catch |err| {
                log.warn("handler error: {}", .{err});
                return .{ .code = .internal_server_error };
            };
        }
    }.call;
}

// ─── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

fn failing_handler(_: Request) anyerror!?Response {
    return error.SomethingBroke;
}

fn ok_handler(_: Request) anyerror!?Response {
    return .{ .code = .content, .payload = "ok" };
}

fn null_fallible_handler(_: Request) anyerror!?Response {
    return null;
}

test "safeWrap converts error to 5.00" {
    const wrapped = safeWrap(failing_handler);
    const dummy_packet = std.mem.zeroes(coapz.Packet);
    const request = Request{
        .packet = dummy_packet,
        .peer_address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683),
        .arena = testing.allocator,
    };
    const resp = wrapped(request);
    try testing.expect(resp != null);
    try testing.expectEqual(coapz.Code.internal_server_error, resp.?.code);
}

test "safeWrap passes through success" {
    const wrapped = safeWrap(ok_handler);
    const dummy_packet = std.mem.zeroes(coapz.Packet);
    const request = Request{
        .packet = dummy_packet,
        .peer_address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683),
        .arena = testing.allocator,
    };
    const resp = wrapped(request);
    try testing.expect(resp != null);
    try testing.expectEqual(coapz.Code.content, resp.?.code);
    try testing.expectEqualSlices(u8, "ok", resp.?.payload);
}

test "safeWrap passes through null" {
    const wrapped = safeWrap(null_fallible_handler);
    const dummy_packet = std.mem.zeroes(coapz.Packet);
    const request = Request{
        .packet = dummy_packet,
        .peer_address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683),
        .arena = testing.allocator,
    };
    const resp = wrapped(request);
    try testing.expect(resp == null);
}

fn testRequest(code: coapz.Code, options: []const coapz.Option, body: []const u8) !Request {
    const pkt = coapz.Packet{
        .kind = .confirmable,
        .code = code,
        .msg_id = 1,
        .token = &.{},
        .options = options,
        .payload = body,
        .data_buf = &.{},
    };
    var buf: [256]u8 = undefined;
    const wire = try pkt.writeBuf(&buf);
    const parsed = try coapz.Packet.read(testing.allocator, wire);
    return .{
        .packet = parsed,
        .peer_address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683),
        .arena = testing.allocator,
    };
}

test "Request.method returns packet code" {
    const req = try testRequest(.get, &.{}, &.{});
    defer req.packet.deinit(testing.allocator);
    try testing.expectEqual(coapz.Code.get, req.method());
}

test "Request.payload returns packet payload" {
    const req = try testRequest(.post, &.{}, "body");
    defer req.packet.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, "body", req.payload());
}

test "Request.pathSegments iterates uri_path options" {
    const req = try testRequest(.get, &.{
        .{ .kind = .uri_path, .value = "hello" },
        .{ .kind = .uri_path, .value = "world" },
    }, &.{});
    defer req.packet.deinit(testing.allocator);
    var it = req.pathSegments();
    try testing.expectEqualSlices(u8, "hello", it.next().?.value);
    try testing.expectEqualSlices(u8, "world", it.next().?.value);
    try testing.expect(it.next() == null);
}
