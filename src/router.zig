/// Comptime CoAP request router.
///
/// Generates a handler function from a declarative route table. Routes are
/// matched by method + path segments with no heap allocation — the route
/// table is baked into the binary as a series of comptime-unrolled checks.
///
/// ```zig
/// const router = coap.Router(.{
///     .{ .get,  "/temperature", getTemperature },
///     .{ .put,  "/temperature", setTemperature },
///     .{ .post, "/led",         toggleLed },
/// });
///
/// var server = try coap.Server.init(allocator, .{}, router.handler());
/// ```
const std = @import("std");
const coapz = @import("coapz");
const handler_mod = @import("handler.zig");
const Request = handler_mod.Request;
const Response = handler_mod.Response;

/// Create a router from a comptime route table.
/// Each route is a tuple: `{ method, path, handler_fn }`.
///
/// - `method`: a `coapz.Code` (e.g. `.get`, `.post`, `.put`, `.delete`)
/// - `path`: a string like `"/sensors/temperature"` (leading `/` optional)
/// - `handler_fn`: a `fn(Request) ?Response`
pub fn Router(comptime routes: anytype) type {
    return struct {
        /// Returns a `SimpleHandlerFn` that dispatches to the matching route.
        /// Unmatched requests return 4.04 Not Found.
        pub fn handler() handler_mod.SimpleHandlerFn {
            return dispatch;
        }

        /// Returns a `SimpleHandlerFn` with a custom fallback for unmatched requests.
        pub fn handlerWithFallback(comptime fallback: handler_mod.SimpleHandlerFn) handler_mod.SimpleHandlerFn {
            return struct {
                fn f(req: Request) ?Response {
                    return dispatch_inner(req) orelse fallback(req);
                }
            }.f;
        }

        fn dispatch(req: Request) ?Response {
            return dispatch_inner(req) orelse Response.withCode(.not_found);
        }

        fn dispatch_inner(req: Request) ?Response {
            inline for (routes) |route| {
                const method = route[0];
                const path = route[1];
                const route_handler = route[2];

                if (req.method() == method) {
                    if (matchAndCapture(req, path)) |params| {
                        var r = req;
                        r.route_params = params.params;
                        r.route_param_count = params.count;
                        return @as(handler_mod.SimpleHandlerFn, route_handler)(r);
                    }
                }
            }
            return null;
        }

        const CaptureResult = struct {
            params: [Request.max_route_params]Request.RouteParam,
            count: u8,
        };

        fn matchAndCapture(req: Request, comptime path: []const u8) ?CaptureResult {
            const segments = comptime splitPath(path);
            var it = req.pathSegments();
            var result = CaptureResult{
                .params = [_]Request.RouteParam{.{}} ** Request.max_route_params,
                .count = 0,
            };
            inline for (segments) |expected| {
                const actual = it.next() orelse return null;
                if (comptime isParam(expected)) {
                    // Capture: ":name" → strip the ":" prefix for the param name.
                    if (result.count < Request.max_route_params) {
                        result.params[result.count] = .{
                            .name = expected[1..],
                            .value = actual.value,
                        };
                        result.count += 1;
                    }
                } else {
                    if (!std.mem.eql(u8, actual.value, expected)) return null;
                }
            }
            // Ensure no trailing segments.
            if (it.next() != null) return null;
            return result;
        }

        fn isParam(comptime seg: []const u8) bool {
            return seg.len > 1 and seg[0] == ':';
        }

        fn splitPath(comptime path: []const u8) []const []const u8 {
            const trimmed = if (path.len > 0 and path[0] == '/') path[1..] else path;
            if (trimmed.len == 0) return &.{};

            comptime var count: usize = 0;
            comptime var it = std.mem.splitScalar(u8, trimmed, '/');
            comptime while (it.next()) |seg| {
                if (seg.len > 0) count += 1;
            };

            comptime var result: [count][]const u8 = undefined;
            comptime var idx: usize = 0;
            comptime var it2 = std.mem.splitScalar(u8, trimmed, '/');
            comptime while (it2.next()) |seg| {
                if (seg.len > 0) {
                    result[idx] = seg;
                    idx += 1;
                }
            };
            return &result;
        }
    };
}

// ── Tests ──

const testing = std.testing;

fn echoHandler(req: Request) ?Response {
    return Response.ok(req.payload());
}

fn putHandler(_: Request) ?Response {
    return Response.changed();
}

fn deleteHandler(_: Request) ?Response {
    return Response.deleted();
}

fn fallbackHandler(_: Request) ?Response {
    return Response.withCode(.bad_request);
}

fn buildRequest(comptime method: coapz.Code, comptime path: []const u8) Request {
    const segments = comptime blk: {
        const trimmed = if (path.len > 0 and path[0] == '/') path[1..] else path;
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, trimmed, '/');
        while (it.next()) |seg| {
            if (seg.len > 0) count += 1;
        }

        var result: [count]coapz.Option = undefined;
        var idx: usize = 0;
        var it2 = std.mem.splitScalar(u8, trimmed, '/');
        while (it2.next()) |seg| {
            if (seg.len > 0) {
                result[idx] = .{ .kind = .uri_path, .value = seg };
                idx += 1;
            }
        }
        break :blk result;
    };

    return .{
        .packet = .{
            .kind = .confirmable,
            .code = method,
            .msg_id = 0,
            .token = &.{},
            .options = &segments,
            .payload = "test",
            .data_buf = &.{},
        },
        .peer_address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 5683),
        .arena = testing.allocator,
    };
}

test "router: exact method + path match" {
    const R = Router(.{
        .{ .get, "/temperature", echoHandler },
        .{ .put, "/temperature", putHandler },
    });
    const h = R.handler();

    const resp_get = h(buildRequest(.get, "/temperature")).?;
    try testing.expectEqual(coapz.Code.content, resp_get.code);
    try testing.expectEqualSlices(u8, "test", resp_get.payload);

    const resp_put = h(buildRequest(.put, "/temperature")).?;
    try testing.expectEqual(coapz.Code.changed, resp_put.code);
}

test "router: no match returns 4.04" {
    const R = Router(.{
        .{ .get, "/temperature", echoHandler },
    });
    const h = R.handler();

    const resp = h(buildRequest(.get, "/unknown")).?;
    try testing.expectEqual(coapz.Code.not_found, resp.code);
}

test "router: wrong method returns 4.04" {
    const R = Router(.{
        .{ .get, "/temperature", echoHandler },
    });
    const h = R.handler();

    const resp = h(buildRequest(.delete, "/temperature")).?;
    try testing.expectEqual(coapz.Code.not_found, resp.code);
}

test "router: multi-segment path" {
    const R = Router(.{
        .{ .get, "/sensors/temperature", echoHandler },
    });
    const h = R.handler();

    const resp = h(buildRequest(.get, "/sensors/temperature")).?;
    try testing.expectEqual(coapz.Code.content, resp.code);

    // Partial path doesn't match.
    const resp2 = h(buildRequest(.get, "/sensors")).?;
    try testing.expectEqual(coapz.Code.not_found, resp2.code);

    // Longer path doesn't match.
    const resp3 = h(buildRequest(.get, "/sensors/temperature/extra")).?;
    try testing.expectEqual(coapz.Code.not_found, resp3.code);
}

test "router: root path" {
    const R = Router(.{
        .{ .get, "/", echoHandler },
    });
    const h = R.handler();

    const resp = h(buildRequest(.get, "/")).?;
    try testing.expectEqual(coapz.Code.content, resp.code);
}

test "router: handlerWithFallback" {
    const R = Router(.{
        .{ .get, "/temperature", echoHandler },
    });
    const h = R.handlerWithFallback(fallbackHandler);

    const resp = h(buildRequest(.post, "/unknown")).?;
    try testing.expectEqual(coapz.Code.bad_request, resp.code);
}

test "router: multiple routes first match wins" {
    const R = Router(.{
        .{ .get, "/a", echoHandler },
        .{ .get, "/a", deleteHandler },
    });
    const h = R.handler();

    const resp = h(buildRequest(.get, "/a")).?;
    try testing.expectEqual(coapz.Code.content, resp.code); // echoHandler, not deleteHandler
}

fn paramHandler(req: Request) ?Response {
    const id = req.param("id") orelse return Response.badRequest();
    return Response.ok(id);
}

test "router: param capture" {
    const R = Router(.{
        .{ .get, "/sensor/:id", paramHandler },
    });
    const h = R.handler();

    const resp = h(buildRequest(.get, "/sensor/42")).?;
    try testing.expectEqual(coapz.Code.content, resp.code);
    try testing.expectEqualSlices(u8, "42", resp.payload);
}

test "router: param with exact segments" {
    const R = Router(.{
        .{ .get, "/sensor/:id/readings", paramHandler },
    });
    const h = R.handler();

    // Matches — id captured, but paramHandler only returns id.
    const resp = h(buildRequest(.get, "/sensor/abc/readings")).?;
    try testing.expectEqual(coapz.Code.content, resp.code);
    try testing.expectEqualSlices(u8, "abc", resp.payload);

    // Doesn't match — wrong trailing segment.
    const resp2 = h(buildRequest(.get, "/sensor/abc/other")).?;
    try testing.expectEqual(coapz.Code.not_found, resp2.code);
}

fn multiParamHandler(req: Request) ?Response {
    const zone = req.param("zone") orelse return Response.badRequest();
    const id = req.param("id") orelse return Response.badRequest();
    // Return zone:id concatenated via a simple check.
    _ = zone;
    return Response.ok(id);
}

test "router: multiple params" {
    const R = Router(.{
        .{ .get, "/zone/:zone/sensor/:id", multiParamHandler },
    });
    const h = R.handler();

    const resp = h(buildRequest(.get, "/zone/north/sensor/7")).?;
    try testing.expectEqual(coapz.Code.content, resp.code);
    try testing.expectEqualSlices(u8, "7", resp.payload); // returns id param
}

test "router: param doesn't match empty segment" {
    const R = Router(.{
        .{ .get, "/sensor/:id", paramHandler },
    });
    const h = R.handler();

    // Too short — no id segment.
    const resp = h(buildRequest(.get, "/sensor")).?;
    try testing.expectEqual(coapz.Code.not_found, resp.code);
}

test "router: exact route takes priority over param route" {
    const R = Router(.{
        .{ .get, "/sensor/special", echoHandler },
        .{ .get, "/sensor/:id", paramHandler },
    });
    const h = R.handler();

    // Exact match first.
    const resp = h(buildRequest(.get, "/sensor/special")).?;
    try testing.expectEqual(coapz.Code.content, resp.code);
    try testing.expectEqualSlices(u8, "test", resp.payload); // echoHandler returns payload

    // Param match second.
    const resp2 = h(buildRequest(.get, "/sensor/42")).?;
    try testing.expectEqual(coapz.Code.content, resp2.code);
    try testing.expectEqualSlices(u8, "42", resp2.payload); // paramHandler returns id
}
