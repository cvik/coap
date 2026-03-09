/// coapd — High-performance CoAP server and client on io_uring.
///
/// ## Quick start (server)
///
/// ```zig
/// var server = try coapd.Server.init(allocator, .{}, handler);
/// defer server.deinit();
/// try server.run();
/// ```
///
/// ## Quick start (client)
///
/// ```zig
/// var client = try coapd.Client.init(allocator, .{ .host = "127.0.0.1" });
/// defer client.deinit();
/// const result = try client.get(allocator, "/temperature");
/// defer result.deinit(allocator);
/// ```

/// CoAP server. See `Server.Config` for configuration options.
pub const Server = @import("Server.zig");

/// CoAP client for a single peer. One client per server endpoint.
pub const Client = @import("Client.zig");

/// Server configuration. Alias for `Server.Config`.
pub const Config = Server.Config;

/// Incoming request passed to the handler function.
pub const Request = @import("handler.zig").Request;

/// Response returned by a handler.
pub const Response = @import("handler.zig").Response;

/// Type-erased handler function pointer (internal).
pub const HandlerFn = @import("handler.zig").HandlerFn;

/// Simple handler function type: `fn(Request) ?Response`.
pub const SimpleHandlerFn = @import("handler.zig").SimpleHandlerFn;

/// Wrap a fallible handler (`!?Response`) into a `SimpleHandlerFn`.
/// Errors are logged and converted to 5.00 Internal Server Error.
pub const safeWrap = @import("handler.zig").safeWrap;

/// Wrap a fallible context handler into one that catches errors.
/// See `safeWrap` for the non-context variant.
pub const safeWrapContext = @import("handler.zig").safeWrapContext;

/// Full coapz library re-export for advanced use (packet construction, etc.).
pub const coap = @import("coapz");

/// CoAP method and response codes (e.g. `.get`, `.post`, `.content`, `.not_found`).
pub const Code = coap.Code;

/// A single CoAP option (kind + value pair).
pub const Option = coap.Option;

/// CoAP option identifiers (e.g. `.uri_path`, `.content_format`, `.observe`).
pub const OptionKind = coap.OptionKind;

/// IANA CoAP Content-Format values (e.g. `.json`, `.cbor`, `.text_plain`).
pub const ContentFormat = coap.ContentFormat;

const handler = @import("handler.zig");
const constants = @import("constants.zig");
const Io = @import("Io.zig");
const Exchange = @import("exchange.zig");
const RateLimiter = @import("rate_limiter.zig");

test {
    _ = handler;
    _ = constants;
    _ = Io;
    _ = Server;
    _ = Client;
    _ = Exchange;
    _ = RateLimiter;
}
