/// URI path and query string helpers for building CoAP options.
///
/// Splits path/query strings into CoAP options on caller-provided
/// stack buffers. No heap allocation.
///
/// ```zig
/// var buf: [uri.max_options]coapz.Option = undefined;
/// const opts = uri.fromUri("/sensors/temp?unit=celsius", &buf);
/// const result = try client.call(allocator, .get, opts, &.{});
/// ```
const std = @import("std");
const coapz = @import("coapz");

/// Maximum combined path + query segments supported.
pub const max_options = 24;

/// Split a URI path string into URI-Path options.
/// Strips leading `/`, splits on `/`, skips empty segments.
///
/// ```zig
/// var buf: [uri.max_options]coapz.Option = undefined;
/// const opts = uri.fromPath("sensors/temperature", &buf);
/// ```
pub fn fromPath(path: []const u8, buf: []coapz.Option) []const coapz.Option {
    const trimmed = if (path.len > 0 and path[0] == '/') path[1..] else path;
    if (trimmed.len == 0) return buf[0..0];

    var count: usize = 0;
    var it = std.mem.splitScalar(u8, trimmed, '/');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        if (count >= buf.len) break;
        buf[count] = .{ .kind = .uri_path, .value = seg };
        count += 1;
    }
    return buf[0..count];
}

/// Split a query string into URI-Query options.
/// Splits on `&`, skips empty segments. Do not include the leading `?`.
///
/// ```zig
/// var buf: [uri.max_options]coapz.Option = undefined;
/// const opts = uri.fromQuery("unit=celsius&format=json", &buf);
/// ```
pub fn fromQuery(query: []const u8, buf: []coapz.Option) []const coapz.Option {
    if (query.len == 0) return buf[0..0];

    var count: usize = 0;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        if (count >= buf.len) break;
        buf[count] = .{ .kind = .uri_query, .value = seg };
        count += 1;
    }
    return buf[0..count];
}

/// Parse a combined URI string with path and optional query into CoAP options.
/// Splits path on `/` into URI-Path options and query on `&` into URI-Query options.
/// Options are sorted (path before query) as required by CoAP wire format.
///
/// ```zig
/// var buf: [uri.max_options]coapz.Option = undefined;
/// const opts = uri.fromUri("/sensors/temp?unit=celsius&fmt=json", &buf);
/// ```
pub fn fromUri(uri_str: []const u8, buf: []coapz.Option) []const coapz.Option {
    // Split on '?' to separate path and query.
    const qmark = std.mem.indexOfScalar(u8, uri_str, '?');
    const path_part = if (qmark) |q| uri_str[0..q] else uri_str;
    const query_part = if (qmark) |q| uri_str[q + 1 ..] else "";

    const path_opts = fromPath(path_part, buf);
    const remaining = buf[path_opts.len..];
    const query_opts = fromQuery(query_part, remaining);

    return buf[0 .. path_opts.len + query_opts.len];
}

// ── Tests ──

const testing = std.testing;

test "fromPath: simple" {
    var buf: [max_options]coapz.Option = undefined;
    const opts = fromPath("sensors/temperature", &buf);
    try testing.expectEqual(@as(usize, 2), opts.len);
    try testing.expectEqualSlices(u8, "sensors", opts[0].value);
    try testing.expectEqualSlices(u8, "temperature", opts[1].value);
    try testing.expectEqual(coapz.OptionKind.uri_path, opts[0].kind);
}

test "fromPath: leading slash" {
    var buf: [max_options]coapz.Option = undefined;
    const opts = fromPath("/a/b/c", &buf);
    try testing.expectEqual(@as(usize, 3), opts.len);
    try testing.expectEqualSlices(u8, "a", opts[0].value);
}

test "fromPath: empty" {
    var buf: [max_options]coapz.Option = undefined;
    try testing.expectEqual(@as(usize, 0), fromPath("", &buf).len);
    try testing.expectEqual(@as(usize, 0), fromPath("/", &buf).len);
}

test "fromPath: skips empty segments" {
    var buf: [max_options]coapz.Option = undefined;
    const opts = fromPath("a//b", &buf);
    try testing.expectEqual(@as(usize, 2), opts.len);
}

test "fromQuery: simple" {
    var buf: [max_options]coapz.Option = undefined;
    const opts = fromQuery("unit=celsius&fmt=json", &buf);
    try testing.expectEqual(@as(usize, 2), opts.len);
    try testing.expectEqualSlices(u8, "unit=celsius", opts[0].value);
    try testing.expectEqualSlices(u8, "fmt=json", opts[1].value);
    try testing.expectEqual(coapz.OptionKind.uri_query, opts[0].kind);
}

test "fromQuery: empty" {
    var buf: [max_options]coapz.Option = undefined;
    try testing.expectEqual(@as(usize, 0), fromQuery("", &buf).len);
}

test "fromUri: path only" {
    var buf: [max_options]coapz.Option = undefined;
    const opts = fromUri("/sensors/temp", &buf);
    try testing.expectEqual(@as(usize, 2), opts.len);
    try testing.expectEqual(coapz.OptionKind.uri_path, opts[0].kind);
}

test "fromUri: path + query" {
    var buf: [max_options]coapz.Option = undefined;
    const opts = fromUri("/sensors/temp?unit=c&fmt=json", &buf);
    try testing.expectEqual(@as(usize, 4), opts.len);
    try testing.expectEqual(coapz.OptionKind.uri_path, opts[0].kind);
    try testing.expectEqual(coapz.OptionKind.uri_path, opts[1].kind);
    try testing.expectEqual(coapz.OptionKind.uri_query, opts[2].kind);
    try testing.expectEqual(coapz.OptionKind.uri_query, opts[3].kind);
    try testing.expectEqualSlices(u8, "sensors", opts[0].value);
    try testing.expectEqualSlices(u8, "unit=c", opts[2].value);
}

test "fromUri: query only" {
    var buf: [max_options]coapz.Option = undefined;
    const opts = fromUri("?key=val", &buf);
    try testing.expectEqual(@as(usize, 1), opts.len);
    try testing.expectEqual(coapz.OptionKind.uri_query, opts[0].kind);
}
