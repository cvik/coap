//! Linux syscall boundary for the io_uring backend. Public addresses use std.Io types.
const std = @import("std");
const linux = std.os.linux;
pub const AF = linux.AF;
pub const SOCK = linux.SOCK;
pub const SO = linux.SO;
pub const SOL = linux.SOL;
pub const POLL = linux.POLL;
pub const SIG = linux.SIG;
pub const fd_t = linux.fd_t;
pub const socket_t = fd_t;
pub const pid_t = linux.pid_t;
pub const timeval = linux.timeval;
pub const iovec = std.posix.iovec;
pub const pollfd = linux.pollfd;
pub const poll = std.posix.poll;
pub const mmap = std.posix.mmap;
pub const munmap = std.posix.munmap;
pub const kill = std.posix.kill;

pub const SocketAddress = extern union {
    any: linux.sockaddr,
    ip4: linux.sockaddr.in,
    ip6: linux.sockaddr.in6,

    pub fn init(a: std.Io.net.IpAddress) SocketAddress {
        return switch (a) {
            .ip4 => |v| .{ .ip4 = .{ .port = std.mem.nativeToBig(u16, v.port), .addr = @bitCast(v.bytes) } },
            .ip6 => |v| .{ .ip6 = .{ .port = std.mem.nativeToBig(u16, v.port), .addr = v.bytes, .flowinfo = std.mem.nativeToBig(u32, v.flow), .scope_id = v.interface.index } },
        };
    }

    pub fn len(a: *const SocketAddress) linux.socklen_t {
        return if (a.any.family == AF.INET) @sizeOf(linux.sockaddr.in) else @sizeOf(linux.sockaddr.in6);
    }

    pub fn bytes(a: *const SocketAddress) []const u8 {
        return std.mem.asBytes(a)[0..a.len()];
    }

    pub fn address(a: *const SocketAddress) !std.Io.net.IpAddress {
        return switch (a.any.family) {
            AF.INET => .{ .ip4 = .{ .port = std.mem.bigToNative(u16, a.ip4.port), .bytes = @bitCast(a.ip4.addr) } },
            AF.INET6 => .{ .ip6 = .{ .port = std.mem.bigToNative(u16, a.ip6.port), .bytes = a.ip6.addr, .flow = std.mem.bigToNative(u32, a.ip6.flowinfo), .interface = .{ .index = a.ip6.scope_id } } },
            else => error.UnsupportedAddressFamily,
        };
    }
};

/// Preserve numeric IPv6 scope IDs in string-based client/server configs.
/// Native parse requires an I/O context to resolve scopes, even numeric ones.
pub fn parseIp(text: []const u8, port: u16) !std.Io.net.IpAddress {
    if (std.mem.indexOfScalar(u8, text, '%')) |separator| {
        var address = try std.Io.net.IpAddress.parseIp6(text[0..separator], port);
        const scope = std.fmt.parseInt(u32, text[separator + 1 ..], 10) catch return error.InvalidScopeId;
        address.ip6.interface = .{ .index = scope };
        return address;
    }
    return std.Io.net.IpAddress.parse(text, port);
}

pub fn ip4(bytes: [4]u8, port: u16) std.Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}
pub fn family(a: std.Io.net.IpAddress) u32 {
    return switch (a) {
        .ip4 => AF.INET,
        .ip6 => AF.INET6,
    };
}
/// Match the complete endpoint, including IPv6 scope and flow information.
/// std.Io.net.IpAddress.eql currently compares only address bytes and port.
pub fn addressEqual(a: std.Io.net.IpAddress, b: std.Io.net.IpAddress) bool {
    if (!a.eql(&b)) return false;
    return switch (a) {
        .ip4 => true,
        .ip6 => |v| v.flow == b.ip6.flow and v.interface.index == b.ip6.interface.index,
    };
}

pub fn addressLen(a: std.Io.net.IpAddress) linux.socklen_t {
    return switch (a) {
        .ip4 => @sizeOf(linux.sockaddr.in),
        .ip6 => @sizeOf(linux.sockaddr.in6),
    };
}

const SocketError = error{ WouldBlock, ConnectionRefused, ConnectionResetByPeer, NetworkUnreachable, MessageTooBig, AddressInUse, AccessDenied, SystemResources, Unexpected };
fn result(rc: usize) SocketError!usize {
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .AGAIN => error.WouldBlock,
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .NETUNREACH, .HOSTUNREACH => error.NetworkUnreachable,
        .MSGSIZE => error.MessageTooBig,
        .ADDRINUSE => error.AddressInUse,
        .ACCES, .PERM => error.AccessDenied,
        .NOMEM, .NOBUFS, .MFILE, .NFILE => error.SystemResources,
        else => error.Unexpected,
    };
}
pub fn socket(domain: u32, kind: u32, protocol: u32) SocketError!fd_t {
    return @intCast(try result(linux.socket(domain, kind, protocol)));
}
pub fn close(fd: fd_t) void {
    _ = linux.close(fd);
}
pub fn connect(fd: fd_t, a: std.Io.net.IpAddress) SocketError!void {
    const sa = SocketAddress.init(a);
    while (true) {
        const rc = linux.connect(fd, &sa.any, sa.len());
        if (linux.errno(rc) == .INTR) continue;
        _ = try result(rc);
        return;
    }
}
pub fn bind(fd: fd_t, a: std.Io.net.IpAddress) SocketError!void {
    const sa = SocketAddress.init(a);
    _ = try result(linux.bind(fd, &sa.any, sa.len()));
}
pub fn setsockopt(fd: fd_t, level: i32, option: u32, value: []const u8) SocketError!void {
    _ = try result(linux.setsockopt(fd, level, option, value.ptr, @intCast(value.len)));
}
pub fn send(fd: fd_t, data: []const u8, flags: u32) SocketError!usize {
    return sendto(fd, data, flags, null);
}
pub fn sendto(fd: fd_t, data: []const u8, flags: u32, a: ?std.Io.net.IpAddress) SocketError!usize {
    const sa = if (a) |v| SocketAddress.init(v) else undefined;
    while (true) {
        const rc = linux.sendto(fd, data.ptr, data.len, flags, if (a != null) &sa.any else null, if (a != null) sa.len() else 0);
        if (linux.errno(rc) == .INTR) continue;
        return result(rc);
    }
}
pub fn recv(fd: fd_t, data: []u8, flags: u32) SocketError!usize {
    while (true) {
        const rc = linux.recvfrom(fd, data.ptr, data.len, flags, null, null);
        if (linux.errno(rc) == .INTR) continue;
        return result(rc);
    }
}

/// CLOCK_MONOTONIC keeps retransmission deadlines immune to wall-clock changes.
pub fn nanoTimestamp() i128 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) @panic("clock_gettime failed");
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}
pub fn sleep(ns: u64) void {
    var ts: linux.timespec = .{ .sec = @intCast(ns / std.time.ns_per_s), .nsec = @intCast(ns % std.time.ns_per_s) };
    while (true) {
        const rc = linux.nanosleep(&ts, &ts);
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => @panic("nanosleep failed"),
        }
    }
}
pub fn randomBytes(buffer: []u8) void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const rc = linux.getrandom(buffer[offset..].ptr, buffer.len - offset, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) @panic("getrandom returned zero");
                offset += rc;
            },
            .INTR => continue,
            else => @panic("getrandom failed"),
        }
    }
}
pub fn randomInt(comptime T: type) T {
    var value: T = undefined;
    randomBytes(std.mem.asBytes(&value));
    return value;
}

// The benchmark intentionally forks so shared counters measure server throughput.
pub fn fork() SocketError!pid_t {
    return @intCast(try result(linux.fork()));
}
pub fn open(path: [:0]const u8, flags: linux.O, mode: linux.mode_t) SocketError!fd_t {
    return @intCast(try result(linux.open(path.ptr, flags, mode)));
}
pub fn dup2(old: fd_t, new: fd_t) SocketError!void {
    _ = try result(linux.dup2(old, new));
}
pub fn waitpid(pid: pid_t, flags: u32) void {
    var status: u32 = undefined;
    while (linux.errno(linux.waitpid(pid, &status, flags)) == .INTR) {}
}

test "UDP syscall boundary reports WouldBlock and transfers datagrams" {
    const receiver = try socket(AF.INET, SOCK.DGRAM | SOCK.NONBLOCK, 0);
    defer close(receiver);
    try bind(receiver, ip4(.{ 127, 0, 0, 1 }, 0));
    var sa: SocketAddress = undefined;
    var len: linux.socklen_t = @sizeOf(SocketAddress);
    _ = try result(linux.getsockname(receiver, &sa.any, &len));
    const destination = try sa.address();
    var buffer: [32]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, recv(receiver, &buffer, 0));
    const sender = try socket(AF.INET, SOCK.DGRAM, 0);
    defer close(sender);
    try connect(sender, destination);
    try std.testing.expectEqual(@as(usize, 4), try send(sender, "ping", 0));
    var fds = [_]pollfd{.{ .fd = receiver, .events = POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try poll(&fds, 1000));
    const received = try recv(receiver, &buffer, 0);
    try std.testing.expectEqualStrings("ping", buffer[0..received]);
}

test "native addresses round-trip through Linux socket representation" {
    for ([_][]const u8{ "127.0.0.1", "::1", "fe80::1" }) |text| {
        const a = try std.Io.net.IpAddress.parse(text, 5683);
        const sa = SocketAddress.init(a);
        const b = try sa.address();
        try std.testing.expect(a.eql(&b));
    }
    var scoped = try parseIp("fe80::1%3", 5684);
    try std.testing.expectEqual(@as(u32, 3), scoped.ip6.interface.index);
    try std.testing.expectError(error.InvalidScopeId, parseIp("fe80::1%", 5684));
    try std.testing.expectError(error.InvalidScopeId, parseIp("fe80::1%4294967296", 5684));
    scoped.ip6.flow = 42;
    const sa = SocketAddress.init(scoped);
    const roundtrip = try sa.address();
    try std.testing.expect(addressEqual(scoped, roundtrip));
    var other_scope = scoped;
    other_scope.ip6.interface.index = 4;
    try std.testing.expect(!addressEqual(scoped, other_scope));
    var other_flow = scoped;
    other_flow.ip6.flow = 43;
    try std.testing.expect(!addressEqual(scoped, other_flow));
}
