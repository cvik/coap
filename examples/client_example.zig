const std = @import("std");
const coapd = @import("coapd");
const coapz = @import("coapz");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = try coapd.Client.init(allocator, .{
        .host = "127.0.0.1",
        .port = 5683,
    });
    defer client.deinit();

    // Fire-and-forget NON request.
    try client.cast(.get, &.{}, "ping");
    std.debug.print("cast: sent NON GET\n", .{});

    // Blocking CON request/response.
    const result = try client.call(allocator, .get, &.{
        .{ .kind = .uri_path, .value = "hello" },
    }, "world");
    defer result.deinit(allocator);

    std.debug.print("call: code={}, payload={s}\n", .{
        result.code,
        result.payload,
    });
}
