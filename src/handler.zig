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

/// Handler function type.
/// Return null to send no response (valid for NON requests).
/// For CON requests, returning null still sends an empty ACK.
pub const HandlerFn = *const fn (Request) ?Response;
