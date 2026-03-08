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
