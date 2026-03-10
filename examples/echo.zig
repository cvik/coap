const std = @import("std");
const coap = @import("coap");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try coap.Server.init(allocator, .{}, echo);
    defer server.deinit();

    try server.run();
}

fn echo(request: coap.Request) ?coap.Response {
    return coap.Response.ok(request.payload());
}
