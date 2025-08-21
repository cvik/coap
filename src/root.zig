//! UdpServer library
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const log = std.log.scoped(.udp);
const testing = std.testing;
const print = std.debug.print;
const Sqe = linux.io_uring_sqe;
const Cqe = linux.io_uring_cqe;
const pretty = @import("pretty");

// TODO: Make these options with defaults when initializing the UdpServer.
const BUFFER_COUNT = 128;
const BUFFER_SIZE = 4096;
const BUFFER_GROUP_ID = 42;
const CQES_MAX = 1024;

const MSG_TRUNC = 32; // Missing in Zig iouring

const EntryType = enum(u64) {
    nop = 0,
    provide_buffers,
    send_msg,
    recv_msg,
};

pub const Server = struct {
    const Self = @This();
    alloc: ?std.mem.Allocator,

    ring: linux.IoUring,
    buffers: []u8,
    iovecs: []posix.iovec,

    port: u16,
    sock_fd: posix.socket_t,

    pub fn init(alloc: std.mem.Allocator, port: u16) !Self {
        const ring = try linux.IoUring.init(BUFFER_COUNT, 0);

        const buffers = try alloc.alloc(u8, BUFFER_COUNT * BUFFER_SIZE);
        errdefer alloc.free(buffers);

        const iovecs = try alloc.alloc(posix.iovec, BUFFER_COUNT);
        errdefer alloc.free(iovecs);

        return Self{
            .alloc = alloc,
            .ring = ring,
            .buffers = buffers,
            .port = port,
            .sock_fd = undefined,
            .iovecs = iovecs,
        };
    }

    pub fn deinit(self: *Self) !void {
        try self.ring.unregister_buffers();
        self.ring.deinit();

        var alloc = self.alloc orelse return error.NoAllocator;
        alloc.free(self.buffers);
        alloc.free(self.iovecs);
    }

    // TODO: handler should get a std.net.Address as well
    pub fn run(self: *Self, handler: fn ([]const u8) []const u8) !void {
        // setup address and socket
        self.sock_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        const laddr = try std.net.Address.parseIp("0.0.0.0", self.port);
        try std.posix.bind(self.sock_fd, &laddr.any, laddr.getOsSockLen());

        for (self.iovecs, 0..) |*iov, i| {
            const ptr = self.buffers.ptr + (i * BUFFER_SIZE);
            iov.* = .{
                .base = @ptrCast(ptr),
                .len = BUFFER_SIZE,
            };
        }
        try self.ring.register_buffers(self.iovecs);

        {
            _ = try self.ring.provide_buffers(
                @intFromEnum(EntryType.provide_buffers),
                @ptrCast(self.buffers.ptr),
                BUFFER_SIZE,
                BUFFER_COUNT,
                BUFFER_GROUP_ID,
                0,
            );
            _ = try self.ring.submit();
            const cqe_pb = try self.ring.copy_cqe();
            if (cqe_pb.err() != .SUCCESS) {
                return error.SetupBuffersFailed;
            }
        }

        var ss_addr: linux.sockaddr = std.mem.zeroes(linux.sockaddr);
        var msg_in: linux.msghdr = std.mem.zeroes(linux.msghdr);
        msg_in.name = &ss_addr;
        msg_in.namelen = @sizeOf(linux.sockaddr);
        msg_in.controllen = 0;

        const sqe = try self.ring.get_sqe();
        sqe.prep_recvmsg_multishot(self.sock_fd, &msg_in, 0);
        sqe.flags |= MSG_TRUNC | linux.IOSQE_BUFFER_SELECT;
        sqe.user_data = @intFromEnum(EntryType.recv_msg);
        sqe.buf_index = BUFFER_GROUP_ID;

        _ = try self.ring.submit();

        std.log.info("Running receive loop...", .{});
        while (true) {
            var cqes: [CQES_MAX]Cqe = std.mem.zeroes([CQES_MAX]Cqe);
            const n = try self.ring.copy_cqes(cqes[0..], 1); // BLOCKS
            print("-- Popped {d} completed entries\n", .{n});

            var addr_out: [CQES_MAX]linux.sockaddr = undefined;
            var msg_out: [CQES_MAX]linux.msghdr_const = undefined;

            for (cqes[0..n], 0..) |cqe, i| {
                print("|{d}| cqe: {any}, result: {any}\n", .{ i, cqe, cqe.err() });
                if (cqe.err() != .SUCCESS) {
                    continue;
                }

                const user_data: EntryType = @enumFromInt(cqe.user_data);
                switch (user_data) {
                    .provide_buffers => {},
                    .send_msg => {
                        // TODO: Count messages and bytes
                    },
                    .recv_msg => {
                        // TODO: This contains duplicate data
                        const msg = try self.deriveRecvMessage(&cqe);
                        const resp_payload = handler(msg.data);
                        var resp = Response{
                            .msg = @constCast(&msg),
                            .addr_out = &addr_out[i],
                            .msg_out = &msg_out[i],
                            .iov = @constCast(&posix.iovec{
                                .base = @constCast(resp_payload.ptr),
                                .len = resp_payload.len,
                            }),
                        };

                        resp.init();

                        const sqe_s = try self.ring.get_sqe();
                        sqe_s.prep_sendmsg(self.sock_fd, resp.msg_out, linux.IORING_SEND_ZC_REPORT_USAGE);
                        sqe_s.user_data = @intFromEnum(EntryType.send_msg);

                        try self.enqueueReleaseBuffer(try cqe.buffer_id());
                    },
                    .nop => {},
                }
            }
            const m = try self.ring.submit();
            print("--Submitted {d} events\n\n", .{m});
        }
    }

    fn enqueueReleaseBuffer(self: *Self, buf_id: u16) !void {
        _ = try self.ring.provide_buffers(
            @intFromEnum(EntryType.provide_buffers),
            @ptrCast(self.buffers.ptr),
            BUFFER_SIZE,
            1,
            BUFFER_GROUP_ID,
            buf_id,
        );
    }

    fn deriveRecvMessage(self: *const Self, cqe: *const linux.io_uring_cqe) !Message {
        const buf_id: u16 = try cqe.buffer_id();
        const off = @as(usize, buf_id) * BUFFER_SIZE;

        const recvmsg_out: *linux.io_uring_recvmsg_out =
            @ptrCast(@alignCast(self.buffers.ptr + off));
        print("recvmsg_out: {any}\n", .{recvmsg_out});
        const peer_addr: *linux.sockaddr.in =
            @ptrCast(@alignCast(self.buffers.ptr + off + recvmsg_out.namelen));

        var payload: []u8 = undefined;
        payload.ptr = @ptrCast(self.buffers.ptr + off +
            @sizeOf(linux.io_uring_recvmsg_out) + @sizeOf(linux.sockaddr.in));
        payload.len = recvmsg_out.payloadlen;

        const net_addr = std.net.Address.initIp4(@bitCast(peer_addr.addr), peer_addr.port);
        print("net_addr: {any}\n", .{net_addr});

        return Message{
            .addr = peer_addr.*,
            .data = payload,
        };
    }

    const Message = struct {
        addr: linux.sockaddr.in,
        data: []u8,
    };

    const Response = struct {
        msg: *Message,
        msg_out: *linux.msghdr_const,
        addr_out: *linux.sockaddr,
        iov: *posix.iovec,

        fn init(self: *Response) void {
            const port = self.msg.addr.port;
            const port_hi: u8 = @intCast(port >> 8);
            const port_lo: u8 = @intCast(port & 0xFF);

            const addr: [4]u8 = @bitCast(self.msg.addr.addr);

            self.addr_out.family = self.msg.addr.family;
            self.addr_out.data = [14]u8{
                port_lo, port_hi,
                addr[0], addr[1],
                addr[2], addr[3],
                0,       0,
                0,       0,
                0,       0,
                0,       0,
            };

            self.msg_out.* = linux.msghdr_const{
                .name = @constCast(@ptrCast(self.addr_out)),
                .namelen = @sizeOf(linux.sockaddr),
                .iov = @ptrCast(self.iov),
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            };
        }
    };

    const Context = struct {
        entryType: EntryType,
        id: u64,
    };
};
