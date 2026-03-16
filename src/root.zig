//! # coap
//!
//! High-performance CoAP server and client library for Zig, built on
//! Linux io_uring.
//!
//! ## Features
//!
//! **Server:** zero-allocation hot path, CON/ACK reliability with duplicate
//! detection, multi-threaded via SO_REUSEPORT, per-IP rate limiting with
//! three-level load shedding, .well-known/core discovery (RFC 6690),
//! DTLS 1.2 PSK security (RFC 6347).
//!
//! **Client:** CON request/response with retransmission (RFC 7252 §4.2),
//! pipelined async requests (submit/poll) for high-throughput workloads,
//! NON fire-and-forget, transparent Block2 reassembly, Block1 segmented
//! upload (RFC 7959), observe subscriptions (RFC 7641), DTLS 1.2 PSK
//! handshake and encrypted transport.
//!
//! ## Quick start — server
//!
//! ```zig
//! const coap = @import("coap");
//!
//! fn echo(req: coap.Request) ?coap.Response {
//!     return coap.Response.ok(req.payload());
//! }
//!
//! pub fn main() !void {
//!     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//!     var server = try coap.Server.init(gpa.allocator(), .{}, echo);
//!     defer server.deinit();
//!     try server.run();
//! }
//! ```
//!
//! ## Quick start — client
//!
//! ```zig
//! const coap = @import("coap");
//!
//! pub fn main() !void {
//!     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//!     const allocator = gpa.allocator();
//!
//!     var client = try coap.Client.init(allocator, .{
//!         .host = "127.0.0.1",
//!     });
//!     defer client.deinit();
//!
//!     const result = try client.get(allocator, "/temperature");
//!     defer result.deinit(allocator);
//!     std.debug.print("{s}\n", .{result.payload});
//! }
//! ```
//!
//! ## Memory model
//!
//! Both server and client pre-allocate all internal buffers at init.
//! The server handler receives a per-request arena that resets after
//! each tick — no per-request heap allocations occur in the hot path.
//!
//! Client methods like `get()` and `call()` take a separate allocator
//! for the response; the caller owns the `Result` and frees it via
//! `result.deinit(allocator)`.

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

/// DTLS 1.2 module (CoAPs, RFC 7252 §9).
pub const dtls = @import("dtls/dtls.zig");

/// PSK credential for use with DTLS.
pub const Psk = dtls.Psk;

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
const Deferred = @import("deferred.zig");

/// Handle for a deferred (separate) response. See `Request.defer()`.
pub const DeferredResponse = Deferred.DeferredResponse;

test {
    _ = handler;
    _ = constants;
    _ = Io;
    _ = Server;
    _ = Client;
    _ = Exchange;
    _ = RateLimiter;
    _ = Deferred;
    _ = dtls;
}
