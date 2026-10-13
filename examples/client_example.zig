const std = @import("std");
const coap = @import("coap");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = try coap.Client.init(allocator, .{
        .host = "127.0.0.1",
        .port = 5683,
    });
    defer client.deinit();

    // Fire-and-forget NON request.
    try client.cast(.get, &.{}, "ping");
    std.debug.print("cast: sent NON GET\n", .{});

    // One reusable response buffer; increase payload capacity for Block2.
    var storage: coap.Client.ResponseStorage(4096) = .{};
    const result = try client.get(storage.buffers(), "/hello");
    // Borrowed result: consume before reusing storage, never deinit it.

    std.debug.print("call: code={}, payload={s}\n", .{
        result.code,
        result.payload,
    });
}
