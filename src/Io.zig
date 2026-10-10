/// io_uring abstraction for UDP send/receive.
///
/// Manages the ring, provided buffer pool, multishot recvmsg, and
/// sendmsg operations. All buffers are allocated upfront at init.
const std = @import("std");
const platform = @import("platform.zig");
const linux = std.os.linux;
const posix = platform;
const Cqe = linux.io_uring_cqe;
const constants = @import("constants.zig");

const log = std.log.scoped(.io);

const Io = @This();

/// Missing from zig std linux definitions.
const MSG_TRUNC: u32 = 0x20;

const UserData = enum(u64) {
    nop = 0,
    provide_buffers,
    send_msg,
    recv_msg,
    tick_timeout,
};

ring: linux.IoUring,
buffers: []u8,
iovecs: []posix.iovec,
buffer_count: u16,
buffer_size: u32,
fd_socket: ?posix.socket_t,
buffer_ring: *align(std.heap.page_size_min) linux.io_uring_buf_ring,
buffer_ring_entries: u16,

pub fn init(
    allocator: std.mem.Allocator,
    buffer_count: u16,
    buffer_size: u32,
) !Io {
    if (buffer_count == 0 or buffer_size == 0) return error.InvalidConfig;

    // Retain the existing SQ/CQ sizing for sends, receive bursts and timers.
    // Buffer returns now publish descriptors directly, without an SQE/CQE.
    const ring_entries: u16 = buffer_count *| 4;
    var ring = try linux.IoUring.init(ring_entries, linux.IORING_SETUP_COOP_TASKRUN);
    errdefer ring.deinit();

    const total = @as(usize, buffer_count) * buffer_size;
    const buffers = try allocator.alloc(u8, total);
    errdefer allocator.free(buffers);

    const iovecs = try allocator.alloc(posix.iovec, buffer_count);
    errdefer allocator.free(iovecs);

    const entries = std.math.ceilPowerOfTwo(u16, buffer_count) catch return error.InvalidConfig;
    const br = try linux.IoUring.setup_buf_ring(ring.fd, entries, constants.buffer_group_id, .{ .inc = false });
    linux.IoUring.buf_ring_init(br);
    const mask = linux.IoUring.buf_ring_mask(entries);
    for (0..buffer_count) |i| {
        const offset = i * buffer_size;
        linux.IoUring.buf_ring_add(br, buffers[offset..][0..buffer_size], @intCast(i), mask, @intCast(i));
    }
    linux.IoUring.buf_ring_advance(br, buffer_count);

    return .{
        .ring = ring,
        .buffer_ring = br,
        .buffer_ring_entries = entries,
        .buffers = buffers,
        .iovecs = iovecs,
        .buffer_count = buffer_count,
        .buffer_size = buffer_size,
        .fd_socket = null,
    };
}

pub fn deinit(io: *Io, allocator: std.mem.Allocator) void {
    // Closing the ring first cancels its receive and releases kernel access.
    // Do not unregister via a potentially reused fd after closing it.
    io.ring.deinit();
    const ring_bytes: [*]align(std.heap.page_size_min) u8 = @ptrCast(io.buffer_ring);
    std.posix.munmap(ring_bytes[0 .. @as(usize, io.buffer_ring_entries) * @sizeOf(linux.io_uring_buf)]);
    allocator.free(io.buffers);
    allocator.free(io.iovecs);
    if (io.fd_socket) |fd| {
        posix.close(fd);
    }
}

/// Bind and register a UDP socket. Buffers were published during init.
pub fn setup(io: *Io, port: u16, bind_address: []const u8) !void {
    const address = try platform.parseIp(bind_address, port);
    const family = platform.family(address);

    const fd = try posix.socket(family, posix.SOCK.DGRAM, 0);
    io.fd_socket = fd;

    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));

    // Enable dual-stack for IPv6 sockets (accept both v4 and v6 clients).
    if (family == posix.AF.INET6) {
        posix.setsockopt(fd, linux.IPPROTO.IPV6, linux.IPV6.V6ONLY, &std.mem.toBytes(@as(c_int, 0))) catch |err| {
            log.debug("IPV6_V6ONLY: {}", .{err});
        };
    }

    // Increase socket buffers for throughput.
    const buf_size = std.mem.toBytes(@as(c_int, 4 * 1024 * 1024));
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &buf_size) catch |err| {
        log.debug("SO_SNDBUF: {}", .{err});
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &buf_size) catch |err| {
        log.debug("SO_RCVBUF: {}", .{err});
    };

    try posix.bind(fd, address);

    for (io.iovecs, 0..) |*iov, i| {
        iov.* = .{
            .base = @ptrCast(io.buffers.ptr + (i * io.buffer_size)),
            .len = io.buffer_size,
        };
    }

    try io.ring.register_files(&.{fd});
    // The initial buffers were published in the shared ring during init.
}

/// Queue a multishot recvmsg operation.
pub fn recv_multishot(
    io: *Io,
    msg_header: *linux.msghdr,
) !void {
    _ = io.fd_socket orelse return error.SocketNotReady;
    const sqe = try io.ring.get_sqe();
    sqe.prep_recvmsg_multishot(0, msg_header, MSG_TRUNC);
    sqe.flags |= linux.IOSQE_BUFFER_SELECT | linux.IOSQE_FIXED_FILE;
    sqe.user_data = @backingInt(UserData.recv_msg);
    sqe.buf_index = constants.buffer_group_id;
}

/// Queue a sendmsg operation.
pub fn send_msg(
    io: *Io,
    msg_header: *linux.msghdr_const,
) !void {
    _ = io.fd_socket orelse return error.SocketNotReady;
    const sqe = try io.ring.get_sqe();
    sqe.prep_sendmsg(0, msg_header, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    sqe.user_data = @backingInt(UserData.send_msg);
}

/// Wait for at least `wait_count` completions. Does not submit.
pub fn wait_cqes(
    io: *Io,
    cqes: []Cqe,
    wait_count: u32,
) !u32 {
    return io.ring.copy_cqes(cqes, wait_count);
}

/// Submit queued SQEs.
pub fn submit(io: *Io) !u32 {
    return io.ring.submit();
}

/// Return a provided buffer once all references into it have been consumed/copied.
/// A single producer publishes one whole datagram buffer; incremental mode is off.
pub fn release_buffer(io: *Io, buffer_id: u16) !void {
    if (buffer_id >= io.buffer_count) return error.InvalidBufferId;
    const offset = @as(usize, buffer_id) * io.buffer_size;
    linux.IoUring.buf_ring_add(
        io.buffer_ring,
        io.buffers[offset..][0..io.buffer_size],
        buffer_id,
        linux.IoUring.buf_ring_mask(io.buffer_ring_entries),
        0,
    );
    linux.IoUring.buf_ring_advance(io.buffer_ring, 1);
}

/// Extract the peer address and payload from a recv CQE.
pub const RecvResult = struct {
    peer_address: std.Io.net.IpAddress,
    payload: []const u8,
    buffer_id: u16,
};

pub fn decode_recv(io: *const Io, cqe: *const Cqe) !RecvResult {
    const buffer_id: u16 = try cqe.buffer_id();
    const offset = @as(usize, buffer_id) * io.buffer_size;
    const buffer_end = offset + io.buffer_size;

    const recvmsg_out: *linux.io_uring_recvmsg_out =
        @ptrCast(@alignCast(io.buffers.ptr + offset));

    const name_offset = offset + @sizeOf(linux.io_uring_recvmsg_out);
    const payload_offset = name_offset + recvmsg_out.namelen;
    const payload_length = recvmsg_out.payloadlen;

    if (payload_offset + payload_length > buffer_end) {
        return error.PayloadOutOfBounds;
    }

    // sockaddr's family is native-endian, unlike its network-endian port.
    const peer_family = std.mem.bytesToValue(u16, io.buffers[name_offset..][0..2]);

    var peer: platform.SocketAddress = undefined;
    const address_len: usize = switch (peer_family) {
        posix.AF.INET => @sizeOf(linux.sockaddr.in),
        posix.AF.INET6 => @sizeOf(linux.sockaddr.in6),
        else => return error.UnsupportedAddressFamily,
    };
    if (recvmsg_out.namelen < address_len or name_offset + address_len > buffer_end)
        return error.PayloadOutOfBounds;
    @memcpy(std.mem.asBytes(&peer)[0..address_len], io.buffers[name_offset..][0..address_len]);
    const net_address = try peer.address();

    return .{
        .peer_address = net_address,
        .payload = io.buffers[payload_offset..][0..payload_length],
        .buffer_id = buffer_id,
    };
}

/// Queue a timeout that fires after `ms` milliseconds.
/// Ensures `wait_cqes` unblocks periodically so the server can
/// check shutdown flags even when no packets arrive.
pub fn queue_timeout(io: *Io, ts: *const linux.kernel_timespec) !void {
    _ = try io.ring.timeout(@backingInt(UserData.tick_timeout), ts, 0, 0);
}

/// Check whether a CQE is a recv_msg completion.
pub fn is_recv(cqe: *const Cqe) bool {
    return cqe.user_data == @backingInt(UserData.recv_msg);
}

/// Check whether a CQE is a tick timeout completion.
pub fn is_timeout(cqe: *const Cqe) bool {
    return cqe.user_data == @backingInt(UserData.tick_timeout);
}

/// Check whether a CQE completed successfully.
pub fn is_success(cqe: *const Cqe) bool {
    return cqe.err() == .SUCCESS;
}

// ─── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

fn checkInitAllocation(allocator: std.mem.Allocator) !void {
    var io = try Io.init(allocator, 4, 256);
    defer io.deinit(allocator);
}

test "provided ring init cleans up after allocation failures" {
    try testing.checkAllAllocationFailures(testing.allocator, checkInitAllocation, .{});
}

test "decode_recv preserves IPv4 and scoped IPv6 socket addresses" {
    const addresses = [_]std.Io.net.IpAddress{
        platform.ip4(.{ 1, 2, 3, 4 }, 0x1234),
        try platform.parseIp("fe80::1%3", 5684),
    };
    for (addresses) |address| {
        var buffer: [64]u8 align(@alignOf(linux.io_uring_recvmsg_out)) = @splat(0);
        const sa = platform.SocketAddress.init(address);
        const header: *linux.io_uring_recvmsg_out = @ptrCast(&buffer);
        header.* = .{ .namelen = sa.len(), .controllen = 0, .payloadlen = 4, .flags = 0 };
        const name_offset = @sizeOf(linux.io_uring_recvmsg_out);
        @memcpy(buffer[name_offset..][0..sa.len()], sa.bytes());
        @memcpy(buffer[name_offset + sa.len() ..][0..4], "ping");
        const io: Io = .{
            .ring = undefined,
            .buffers = &buffer,
            .iovecs = &.{},
            .buffer_count = 1,
            .buffer_size = buffer.len,
            .fd_socket = null,
            .buffer_ring = undefined,
            .buffer_ring_entries = 0,
        };
        const cqe: Cqe = .{ .user_data = 0, .res = 0, .flags = linux.IORING_CQE_F_BUFFER };
        const result = try io.decode_recv(&cqe);
        try testing.expect(platform.addressEqual(address, result.peer_address));
        try testing.expectEqualStrings("ping", result.payload);
        try testing.expectEqual(@as(u16, 0), result.buffer_id);
    }
}

test "SO_REUSEPORT allows two instances on same port" {
    const port: u16 = 19691;
    const allocator = testing.allocator;

    var io1 = try Io.init(allocator, 4, 256);
    defer io1.deinit(allocator);
    try io1.setup(port, "0.0.0.0");

    var io2 = try Io.init(allocator, 4, 256);
    defer io2.deinit(allocator);
    try io2.setup(port, "0.0.0.0");
}
