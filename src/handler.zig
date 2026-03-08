const std = @import("std");
const coapz = @import("coapz");

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
