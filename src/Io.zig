/// io_uring abstraction for UDP send/receive.
///
/// Manages the ring, provided buffer pool, multishot recvmsg, and
/// sendmsg operations. All buffers are allocated upfront at init.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
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
};

ring: linux.IoUring,
buffers: []u8,
iovecs: []posix.iovec,
buffer_count: u16,
buffer_size: u32,
fd_socket: ?posix.socket_t,

pub fn init(
    allocator: std.mem.Allocator,
    buffer_count: u16,
    buffer_size: u32,
) !Io {
    if (buffer_count == 0 or buffer_size == 0) return error.InvalidConfig;

    // Ring must accommodate send + release_buffer per recv, plus overhead.
    // Each received packet may generate up to 3 SQEs: release_buffer,
    // send_msg response, and periodic provide_buffers. The 4x multiplier
    // covers this worst case with headroom for the multishot recv SQE.
    const ring_entries: u16 = buffer_count *| 4;
    var ring = try linux.IoUring.init(ring_entries, 0);
    errdefer ring.deinit();

    const total = @as(usize, buffer_count) * buffer_size;
    const buffers = try allocator.alloc(u8, total);
    errdefer allocator.free(buffers);

    const iovecs = try allocator.alloc(posix.iovec, buffer_count);
    errdefer allocator.free(iovecs);

    return .{
        .ring = ring,
        .buffers = buffers,
        .iovecs = iovecs,
        .buffer_count = buffer_count,
        .buffer_size = buffer_size,
        .fd_socket = null,
    };
}

pub fn deinit(io: *Io, allocator: std.mem.Allocator) void {
    io.ring.deinit();
    allocator.free(io.buffers);
    allocator.free(io.iovecs);
    if (io.fd_socket) |fd| {
        posix.close(fd);
    }
}

/// Bind a UDP socket and register buffers with the kernel.
pub fn setup(io: *Io, port: u16, bind_address: []const u8) !void {
    const address = try std.net.Address.parseIp(bind_address, port);

    // Only IPv4 is supported; IPv6 requires larger sockaddr buffers
    // throughout the recv/send paths.
    if (address.any.family != posix.AF.INET) return error.UnsupportedAddressFamily;

    const fd = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        0,
    );
    io.fd_socket = fd;

    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));

    // Increase socket buffers for throughput.
    const buf_size = std.mem.toBytes(@as(c_int, 4 * 1024 * 1024));
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &buf_size) catch |err| {
        log.debug("SO_SNDBUF: {}", .{err});
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &buf_size) catch |err| {
        log.debug("SO_RCVBUF: {}", .{err});
    };

    try posix.bind(fd, &address.any, address.getOsSockLen());

    for (io.iovecs, 0..) |*iov, i| {
        iov.* = .{
            .base = @ptrCast(io.buffers.ptr + (i * io.buffer_size)),
            .len = io.buffer_size,
        };
    }
    try io.ring.register_buffers(io.iovecs);

    // Provide initial buffer pool to the kernel.
    _ = try io.ring.provide_buffers(
        @intFromEnum(UserData.provide_buffers),
        @ptrCast(io.buffers.ptr),
        io.buffer_size,
        io.buffer_count,
        constants.buffer_group_id,
        0,
    );
    _ = try io.ring.submit();
    const cqe = try io.ring.copy_cqe();
    if (cqe.err() != .SUCCESS) {
        return error.BufferSetupFailed;
    }
}

/// Queue a multishot recvmsg operation.
pub fn recv_multishot(
    io: *Io,
    msg_header: *linux.msghdr,
) !void {
    const fd = io.fd_socket orelse return error.SocketNotReady;
    const sqe = try io.ring.get_sqe();
    sqe.prep_recvmsg_multishot(fd, msg_header, MSG_TRUNC);
    sqe.flags |= linux.IOSQE_BUFFER_SELECT;
    sqe.user_data = @intFromEnum(UserData.recv_msg);
    sqe.buf_index = constants.buffer_group_id;
}

/// Queue a sendmsg operation.
pub fn send_msg(
    io: *Io,
    msg_header: *linux.msghdr_const,
) !void {
    const fd = io.fd_socket orelse return error.SocketNotReady;
    const sqe = try io.ring.get_sqe();
    sqe.prep_sendmsg(fd, msg_header, 0);
    sqe.user_data = @intFromEnum(UserData.send_msg);
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

/// Return a provided buffer to the kernel pool.
pub fn release_buffer(io: *Io, buffer_id: u16) !void {
    std.debug.assert(buffer_id < io.buffer_count);
    const offset = @as(usize, buffer_id) * io.buffer_size;
    _ = try io.ring.provide_buffers(
        @intFromEnum(UserData.provide_buffers),
        @ptrCast(io.buffers.ptr + offset),
        io.buffer_size,
        1,
        constants.buffer_group_id,
        buffer_id,
    );
}

/// Extract the peer address and payload from a recv CQE.
pub const RecvResult = struct {
    peer_address: std.net.Address,
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

    const peer_addr: *linux.sockaddr.in =
        @ptrCast(@alignCast(io.buffers.ptr + name_offset));

    // Port from sockaddr is in network byte order; initIp4 expects host order.
    const net_address = std.net.Address.initIp4(
        @bitCast(peer_addr.addr),
        std.mem.bigToNative(u16, peer_addr.port),
    );

    return .{
        .peer_address = net_address,
        .payload = io.buffers[payload_offset..][0..payload_length],
        .buffer_id = buffer_id,
    };
}

/// Check whether a CQE is a recv_msg completion.
pub fn is_recv(cqe: *const Cqe) bool {
    return cqe.user_data == @intFromEnum(UserData.recv_msg);
}

/// Check whether a CQE completed successfully.
pub fn is_success(cqe: *const Cqe) bool {
    return cqe.err() == .SUCCESS;
}

// ─── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

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
