const std = @import("std");
const coapz = @import("coapz");
const Deferred = @import("deferred.zig");
const ObserverRegistry = @import("observe.zig");
const log = std.log.scoped(.coap);

/// Incoming CoAP request passed to the handler function.
///
/// All data (packet, options, payload) is backed by the per-request arena
/// and is only valid for the duration of the handler invocation. Do not
/// store references to request data beyond the handler return.
///
/// ## Example
///
/// ```zig
/// fn handler(req: coap.Request) ?coap.Response {
///     if (req.method() != .get) return coap.Response.methodNotAllowed();
///
///     var it = req.pathSegments();
///     const resource = it.next() orelse return coap.Response.notFound();
///
///     if (std.mem.eql(u8, resource.value, "temperature")) {
///         return coap.Response.ok("22.5");
///     }
///     return coap.Response.notFound();
/// }
/// ```
pub const Request = struct {
    /// Parsed CoAP packet. Use the convenience accessors below for common
    /// fields; access `packet` directly for advanced use (token, message
    /// kind, raw option iteration).
    packet: coapz.Packet,
    /// Source address of the peer.
    peer_address: std.net.Address,
    /// Per-request arena allocator. Resets after the handler returns.
    /// Use for temporary allocations needed during response construction
    /// (e.g. duping option slices via `Response.content()`).
    arena: std.mem.Allocator,
    /// True when the request arrived over a DTLS-secured transport (CoAPs).
    is_secure: bool = false,
    /// Deferred response context. Non-null when the server has a deferred
    /// pool configured (`Config.max_deferred > 0`) and the request is CON.
    defer_ctx: ?DeferContext = null,
    /// Observe context. Non-null when the server has an observer registry.
    observe_ctx: ?ObserveContext = null,
    /// Route parameters captured by the router (e.g. `:id` segments).
    route_params: [max_route_params]RouteParam = [_]RouteParam{.{}} ** max_route_params,
    route_param_count: u8 = 0,
    payload_override: ?[]const u8 = null,

    pub const max_route_params = 4;
    pub const RouteParam = struct {
        name: []const u8 = "",
        value: []const u8 = "",
    };

    /// Context for `defer()`. Provided by the server; not user-constructible.
    pub const DeferContext = struct {
        pool: *Deferred,
        next_msg_id: u16,
    };

    /// Context for observe registration. Provided by the server.
    pub const ObserveContext = struct {
        registry: *ObserverRegistry,
        peer_address: std.net.Address,
        token: []const u8,
    };

    /// Request a deferred (separate) response. The server immediately sends
    /// an empty ACK and the returned handle allows delivering the actual
    /// response later — from any thread.
    ///
    /// Returns `null` if the deferred pool is full or the request is NON.
    ///
    /// ```zig
    /// fn handler(req: coap.Request) ?coap.Response {
    ///     const deferred = req.deferResponse() orelse return coap.Response.ok("sync fallback");
    ///     my_worker.submit(deferred, req.payload());
    ///     return null; // server sends empty ACK
    /// }
    /// // Later, from worker thread:
    /// deferred.respond(coap.Response.ok(result));
    /// ```
    pub fn deferResponse(self: Request) ?Deferred.DeferredResponse {
        const ctx = self.defer_ctx orelse return null;
        const idx = ctx.pool.allocate(
            self.packet.token,
            self.peer_address,
            ctx.next_msg_id,
            @truncate(std.time.nanoTimestamp()),
        ) orelse return null;
        return .{ .pool = ctx.pool, .slot_idx = idx };
    }

    /// Register this client as an observer of the given resource.
    /// The `resource_id` is obtained from `server.allocateResource()`.
    /// Returns true if registered, false if the registry is full.
    pub fn observeResource(self: Request, resource_id: u16) bool {
        const ctx = self.observe_ctx orelse return false;
        return ctx.registry.addObserver(resource_id, ctx.peer_address, ctx.token);
    }

    /// Remove this client from the observer list of the given resource.
    pub fn removeObserver(self: Request, resource_id: u16) void {
        const ctx = self.observe_ctx orelse return;
        ctx.registry.removeObserver(resource_id, ctx.peer_address, ctx.token);
    }

    /// Look up a named route parameter captured by the router.
    /// Returns `null` if the parameter was not captured.
    ///
    /// ```zig
    /// // Route: .{ .get, "/sensor/:id", handler }
    /// fn handler(req: coap.Request) ?coap.Response {
    ///     const id = req.param("id") orelse return coap.Response.badRequest();
    ///     // id is a []const u8 pointing into the request's URI-Path option data
    /// }
    /// ```
    pub fn param(self: Request, name: []const u8) ?[]const u8 {
        for (self.route_params[0..self.route_param_count]) |p| {
            if (std.mem.eql(u8, p.name, name)) return p.value;
        }
        return null;
    }

    /// Return the Echo option value from this request, if present (RFC 9175 §2).
    /// The handler can compare this with a previously sent Echo to verify freshness.
    pub fn echoOption(self: Request) ?[]const u8 {
        const echo_kind: coapz.OptionKind = @enumFromInt(252);
        if (self.packet.find_option(echo_kind)) |opt| return opt.value;
        return null;
    }

    /// If-Match ETag values from the request (RFC 7252 §5.10.1).
    /// Returns an iterator over all If-Match options.
    pub inline fn ifMatch(self: Request) coapz.OptionIterator {
        return self.packet.find_options(.if_match);
    }

    /// True if the request contains an If-None-Match option (RFC 7252 §5.10.2).
    pub inline fn ifNoneMatch(self: Request) bool {
        return self.packet.find_option(.if_none_match) != null;
    }

    /// ETag values from the request.
    pub inline fn etags(self: Request) coapz.OptionIterator {
        return self.packet.find_options(.etag);
    }

    /// Request method (`.get`, `.post`, `.put`, `.delete`, …).
    pub inline fn method(self: Request) coapz.Code {
        return self.packet.code;
    }

    /// Request payload bytes. Empty slice if no payload.
    pub inline fn payload(self: Request) []const u8 {
        return self.payload_override orelse self.packet.payload;
    }

    /// Iterator over URI-Path segments. Each call to `next()` returns
    /// one path component (e.g. `/a/b` yields `"a"` then `"b"`).
    pub inline fn pathSegments(self: Request) coapz.OptionIterator {
        return self.packet.find_options(.uri_path);
    }

    /// Iterator over URI-Query values. Each query parameter is a
    /// separate option (e.g. `?a=1&b=2` yields `"a=1"` then `"b=2"`).
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
///
/// Return a `Response` to send a reply, or `null` for no response (NON
/// requests) or an empty ACK (CON requests).
///
/// **Lifetime:** `payload` and `options` must remain valid until the
/// handler returns. Point them at request data, string literals, or
/// arena-allocated slices — the server copies the encoded response
/// before the arena resets.
///
/// ## Examples
///
/// ```zig
/// // Simple payload response.
/// return Response.ok("hello");
///
/// // JSON with Content-Format header.
/// return Response.content(request.arena, .json, "{\"temp\": 22.5}");
///
/// // Struct literal for full control.
/// return .{ .code = .content, .options = opts, .payload = data };
/// ```
pub const Response = struct {
    /// Response code. Defaults to 2.05 Content.
    code: coapz.Code = .content,
    /// CoAP options to include in the response (e.g. Content-Format).
    options: []const coapz.Option = &.{},
    /// Response body. Empty by default.
    payload: []const u8 = &.{},

    /// 2.05 Content with payload.
    pub inline fn ok(body: []const u8) Response {
        return .{ .payload = body };
    }

    /// 2.05 Content with a Content-Format option and payload.
    /// Allocates the options slice from `arena`. On allocation failure,
    /// returns 5.00 Internal Server Error.
    pub fn content(arena: std.mem.Allocator, fmt: coapz.ContentFormat, body: []const u8) Response {
        var cf_buf: [2]u8 = undefined;
        const cf_opt = coapz.Option.content_format(fmt, &cf_buf);
        const opts = arena.dupe(coapz.Option, &.{cf_opt}) catch
            return .{ .code = .internal_server_error };
        return .{ .options = opts, .payload = body };
    }

    /// 2.01 Created.
    pub inline fn created() Response {
        return .{ .code = .created };
    }

    /// 2.03 Valid.
    pub inline fn valid() Response {
        return .{ .code = .valid };
    }

    /// 2.02 Deleted.
    pub inline fn deleted() Response {
        return .{ .code = .deleted };
    }

    /// 2.04 Changed.
    pub inline fn changed() Response {
        return .{ .code = .changed };
    }

    /// 4.04 Not Found.
    pub inline fn notFound() Response {
        return .{ .code = .not_found };
    }

    /// 4.00 Bad Request.
    pub inline fn badRequest() Response {
        return .{ .code = .bad_request };
    }

    /// 4.05 Method Not Allowed.
    pub inline fn methodNotAllowed() Response {
        return .{ .code = .method_not_allowed };
    }

    /// 4.01 Unauthorized.
    pub inline fn unauthorized() Response {
        return .{ .code = .unauthorized };
    }

    /// 4.03 Forbidden.
    pub inline fn forbidden() Response {
        return .{ .code = .forbidden };
    }

    /// 4.02 Bad Option.
    pub inline fn badOption() Response {
        return .{ .code = .bad_option };
    }

    /// 4.12 Precondition Failed.
    pub inline fn preconditionFailed() Response {
        return .{ .code = .precondition_failed };
    }

    /// Response with an arbitrary code and no payload.
    pub inline fn withCode(code: coapz.Code) Response {
        return .{ .code = code };
    }

    /// Add an Echo option (RFC 9175 §2) to this response for freshness
    /// verification. The client must reflect the Echo value in subsequent
    /// requests. Generates a random 8-byte Echo value.
    pub fn withEcho(self: Response, arena: std.mem.Allocator) Response {
        const echo_kind: coapz.OptionKind = @enumFromInt(252);
        var echo_val: [8]u8 = undefined;
        std.crypto.random.bytes(&echo_val);
        const echo_opt = coapz.Option{ .kind = echo_kind, .value = arena.dupe(u8, &echo_val) catch return self };
        const existing = self.options;
        const opts = arena.alloc(coapz.Option, existing.len + 1) catch return self;
        @memcpy(opts[0..existing.len], existing);
        opts[existing.len] = echo_opt;
        return .{ .code = self.code, .options = opts, .payload = self.payload };
    }
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

/// Wrap a fallible handler (`!?Response`) into a `SimpleHandlerFn`.
/// Errors are logged via `std.log` and converted to 5.00 Internal Server Error.
///
/// ```zig
/// fn handler(req: Request) !?Response {
///     const data = try expensive_lookup(req.arena);
///     return Response.ok(data);
/// }
///
/// var server = try Server.init(allocator, .{}, safeWrap(handler));
/// ```
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

/// Wrap a fallible context handler (`!?Response`) so errors are caught.
/// Errors are logged via `std.log` and converted to 5.00 Internal Server Error.
///
/// ```zig
/// fn handler(ctx: *State, req: Request) !?Response {
///     const data = try ctx.lookup(req.arena);
///     return Response.ok(data);
/// }
///
/// var server = try Server.initContext(
///     allocator, .{}, safeWrapContext(*State, handler), &state,
/// );
/// ```
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

test "Response.ok sets content code and payload" {
    const r = Response.ok("hello");
    try testing.expectEqual(coapz.Code.content, r.code);
    try testing.expectEqualSlices(u8, "hello", r.payload);
}

test "Response.notFound sets 4.04" {
    try testing.expectEqual(coapz.Code.not_found, Response.notFound().code);
}

test "Response.badRequest sets 4.00" {
    try testing.expectEqual(coapz.Code.bad_request, Response.badRequest().code);
}

test "Response.content sets content-format option" {
    const r = Response.content(testing.allocator, .json, "{}");
    defer testing.allocator.free(r.options);
    try testing.expectEqual(coapz.Code.content, r.code);
    try testing.expectEqualSlices(u8, "{}", r.payload);
    try testing.expectEqual(@as(usize, 1), r.options.len);
    try testing.expectEqual(coapz.OptionKind.content_format, r.options[0].kind);
}

test "Response.withCode sets arbitrary code" {
    try testing.expectEqual(coapz.Code.gateway_timeout, Response.withCode(.gateway_timeout).code);
}
