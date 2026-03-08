const std = @import("std");
const coapd = @import("coapd");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try coapd.Server.init(allocator, .{}, echo);
    defer server.deinit();

    try server.run();
}

fn echo(request: coapd.Request) ?coapd.Response {
    return .{ .payload = request.packet.payload };
}
