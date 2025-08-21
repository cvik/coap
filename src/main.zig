const UdpServer = @import("root.zig").Server;
const std = @import("std");
const testing = std.testing;

pub fn main() !void {
    var alloc = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = alloc.allocator();

    var server = UdpServer.init(gpa, 9898) catch |err| {
        std.debug.print("ERROR: {any}", .{err});
        return;
    };
    defer server.deinit() catch unreachable;

    server.run(handler) catch |err| {
        std.log.err("ERROR: {any}", .{err});
        return;
    };
}

fn handler(data: []const u8) []const u8 {
    std.log.debug("Got data: {s}\n", .{data});
    return data;
}
