/// CoAP client on a connected UDP socket.
///
/// One client per peer — connects to a single server via `connect()`'d UDP.
/// Supports NON fire-and-forget (cast), CON request/response with
/// retransmission (call), raw send/recv, RFC 7641 observe, RFC 7959 Block1
/// upload, and transparent Block2 reassembly inside call().
///
/// Single-threaded, tick-driven. Not thread-safe.
const std = @import("std");
const posix = std.posix;
const coapz = @import("coapz");
const constants = @import("constants.zig");
const log = std.log.scoped(.coapd_client);

const Client = @This();

pub const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = constants.port_default,
    max_in_flight: u16 = 32,
    buffer_size: u32 = constants.buffer_size_default,
    token_len: u3 = 2,
    /// Block size exponent: block_size = 2^(szx+4). Default 6 = 1024 bytes.
    default_szx: u3 = 6,
};

pub const Result = struct {
    code: coapz.Code,
    options: []const coapz.Option,
    payload: []const u8,
    packet: coapz.Packet,
    /// When true, payload is a standalone allocation (Block2 reassembly)
    /// that must be freed separately from the packet.
    owns_payload: bool = false,

    pub fn deinit(self: Result, allocator: std.mem.Allocator) void {
        if (self.owns_payload) {
            allocator.free(@constCast(self.payload));
        }
        self.packet.deinit(allocator);
    }
};

// ─── In-flight slot ──────────────────────────────────────────────

const InFlightState = enum(u8) { free, pending };

const InFlightSlot = struct {
    state: InFlightState,
    token: [8]u8,
    token_len: u3,
    msg_id: u16,
    retransmit_count: u4,
    next_retransmit_ns: i128,
    timeout_ns: u64,
    /// Offset into send_buf for retransmission data.
    send_offset: u32,
    send_len: u16,
    next_free: u16,
};

// ─── Observe ─────────────────────────────────────────────────────

const max_observes: u8 = 8;
const max_pending_notifications: u8 = 8;

const PendingNotification = struct {
    data: []u8,
    len: u16,
    msg_id: u16,
    is_con: bool,
};

const ObserveSub = struct {
    token: [8]u8,
    token_len: u3,
    active: bool,
    last_seq: u24,
    pending_count: u8,
    pending: [max_pending_notifications]PendingNotification,
};

pub const ObserveStream = struct {
    client: *Client,
    sub_idx: u8,

    pub const Notification = struct {
        code: coapz.Code,
        options: []const coapz.Option,
        payload: []const u8,
        packet: coapz.Packet,

        pub fn deinit(self: Notification, allocator: std.mem.Allocator) void {
            self.packet.deinit(allocator);
        }
    };

    /// Wait for the next observe notification. Returns null if cancelled.
    pub fn next(self: *ObserveStream, allocator: std.mem.Allocator) !?Notification {
        const sub = &self.client.observes[self.sub_idx];
        if (!sub.active) return null;

        while (true) {
            if (sub.pending_count > 0) {
                const pending = &sub.pending[0];
                const packet = coapz.Packet.read(allocator, pending.data[0..pending.len]) catch {
                    self.client.allocator.free(pending.data);
                    shiftPending(sub);
                    continue;
                };

                if (pending.is_con) {
                    self.client.sendAck(pending.msg_id, packet.token) catch {};
                }

                self.client.allocator.free(pending.data);
                shiftPending(sub);

                return .{
                    .code = packet.code,
                    .options = packet.options,
                    .payload = packet.payload,
                    .packet = packet,
                };
            }

            const got_data = try self.client.tickOnce();
            if (!got_data and !sub.active) return null;
        }
    }

    /// Cancel the observe subscription by sending deregister.
    pub fn cancel(self: *ObserveStream) !void {
        const sub = &self.client.observes[self.sub_idx];
        if (!sub.active) return;
        sub.active = false;

        var obs_buf: [4]u8 = undefined;
        const obs_opt = coapz.Option.uint(.observe, 1, &obs_buf);
        var token_buf: [8]u8 = undefined;
        @memcpy(token_buf[0..sub.token_len], sub.token[0..sub.token_len]);

        const dereg = coapz.Packet{
            .kind = .confirmable,
            .code = .get,
            .msg_id = self.client.nextMsgId(),
            .token = token_buf[0..sub.token_len],
            .options = &.{obs_opt},
            .payload = &.{},
            .data_buf = &.{},
        };

        var buf: [constants.buffer_size_default]u8 = undefined;
        const wire = dereg.writeBuf(&buf) catch return;
        self.client.sendDirect(wire) catch {};

        for (sub.pending[0..sub.pending_count]) |*p| {
            self.client.allocator.free(p.data);
        }
        sub.pending_count = 0;
    }

    fn shiftPending(sub: *ObserveSub) void {
        if (sub.pending_count <= 1) {
            sub.pending_count = 0;
            return;
        }
        for (0..sub.pending_count - 1) |i| {
            sub.pending[i] = sub.pending[i + 1];
        }
        sub.pending_count -= 1;
    }
};

// ─── Client struct ───────────────────────────────────────────────

allocator: std.mem.Allocator,
config: Config,
fd: posix.socket_t,

send_buf: []u8,
recv_buf: []u8,

slots: []InFlightSlot,
slot_table: []u16,
table_mask: u16,
free_head: u16,
count_active: u16,

observes: [max_observes]ObserveSub,

next_msg_id_val: u16,
next_token_val: u64,
rng: std.Random.DefaultPrng,

const empty_sentinel: u16 = 0xFFFF;

pub fn init(allocator: std.mem.Allocator, config: Config) !Client {
    if (config.max_in_flight == 0) return error.InvalidConfig;
    if (config.buffer_size < 64) return error.InvalidConfig;

    const dest = try std.net.Address.parseIp(config.host, config.port);
    if (dest.any.family != posix.AF.INET) return error.UnsupportedAddressFamily;

    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    errdefer posix.close(fd);
    try posix.connect(fd, &dest.any, dest.getOsSockLen());

    const buf_size = std.mem.toBytes(@as(c_int, 2 * 1024 * 1024));
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &buf_size) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &buf_size) catch {};

    const send_buf = try allocator.alloc(
        u8,
        @as(usize, config.max_in_flight) * config.buffer_size,
    );
    errdefer allocator.free(send_buf);

    const recv_buf = try allocator.alloc(u8, config.buffer_size);
    errdefer allocator.free(recv_buf);

    const slots = try allocator.alloc(InFlightSlot, config.max_in_flight);
    errdefer allocator.free(slots);

    for (slots, 0..) |*slot, i| {
        slot.* = .{
            .state = .free,
            .token = undefined,
            .token_len = 0,
            .msg_id = 0,
            .retransmit_count = 0,
            .next_retransmit_ns = 0,
            .timeout_ns = 0,
            .send_offset = 0,
            .send_len = 0,
            .next_free = if (i + 1 < config.max_in_flight)
                @intCast(i + 1)
            else
                empty_sentinel,
        };
    }

    const table_size = blk: {
        var size: u32 = 1;
        while (size < @as(u32, config.max_in_flight) * 2) {
            size <<= 1;
        }
        break :blk @as(u16, @intCast(size));
    };
    const slot_table = try allocator.alloc(u16, table_size);
    errdefer allocator.free(slot_table);
    @memset(slot_table, empty_sentinel);

    var seed: u64 = undefined;
    std.crypto.random.bytes(std.mem.asBytes(&seed));
    var rng = std.Random.DefaultPrng.init(seed);

    const initial_msg_id: u16 = rng.random().int(u16);

    var observes: [max_observes]ObserveSub = undefined;
    for (&observes) |*obs| {
        obs.* = .{
            .token = undefined,
            .token_len = 0,
            .active = false,
            .last_seq = 0,
            .pending_count = 0,
            .pending = undefined,
        };
    }

    return .{
        .allocator = allocator,
        .config = config,
        .fd = fd,
        .send_buf = send_buf,
        .recv_buf = recv_buf,
        .slots = slots,
        .slot_table = slot_table,
        .table_mask = table_size - 1,
        .free_head = 0,
        .count_active = 0,
        .observes = observes,
        .next_msg_id_val = initial_msg_id,
        .next_token_val = 0,
        .rng = rng,
    };
}

pub fn deinit(client: *Client) void {
    for (&client.observes) |*obs| {
        if (obs.active) {
            for (obs.pending[0..obs.pending_count]) |*p| {
                client.allocator.free(p.data);
            }
        }
    }
    posix.close(client.fd);
    client.allocator.free(client.send_buf);
    client.allocator.free(client.recv_buf);
    client.allocator.free(client.slots);
    client.allocator.free(client.slot_table);
}

// ─── cast (NON fire-and-forget) ──────────────────────────────────

pub fn cast(
    client: *Client,
    code: coapz.Code,
    options: []const coapz.Option,
    payload: []const u8,
) !void {
    var token_buf: [8]u8 = undefined;
    const token = client.makeToken(&token_buf);

    const packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = code,
        .msg_id = client.nextMsgId(),
        .token = token,
        .options = options,
        .payload = payload,
        .data_buf = &.{},
    };

    var buf: [constants.buffer_size_default]u8 = undefined;
    const wire = try packet.writeBuf(&buf);
    try client.sendDirect(wire);
}

// ─── call (CON with retransmission + Block2 reassembly) ──────────

pub fn call(
    client: *Client,
    allocator: std.mem.Allocator,
    code: coapz.Code,
    options: []const coapz.Option,
    payload: []const u8,
) !Result {
    var token_buf: [8]u8 = undefined;
    const token = client.makeToken(&token_buf);
    const msg_id = client.nextMsgId();

    const slot_idx = try client.allocSlot();

    const slot = &client.slots[slot_idx];

    const packet = coapz.Packet{
        .kind = .confirmable,
        .code = code,
        .msg_id = msg_id,
        .token = token,
        .options = options,
        .payload = payload,
        .data_buf = &.{},
    };

    const offset: u32 = @as(u32, slot_idx) * client.config.buffer_size;
    const slot_buf = client.send_buf[offset..][0..client.config.buffer_size];
    const wire = packet.writeBuf(slot_buf) catch |err| {
        client.freeSlot(slot_idx);
        return err;
    };

    @memcpy(slot.token[0..token.len], token);
    slot.token_len = @intCast(token.len);
    slot.msg_id = msg_id;
    slot.retransmit_count = 0;
    slot.send_offset = offset;
    slot.send_len = @intCast(wire.len);
    slot.state = .pending;

    const initial_timeout = client.randomizedTimeout(constants.ack_timeout_ms);
    slot.timeout_ns = initial_timeout;
    slot.next_retransmit_ns = std.time.nanoTimestamp() + @as(i128, initial_timeout);

    client.insertTable(slot_idx, client.tokenKey(token));
    // After insertTable, errors must use freeSlotAndTable.
    errdefer client.freeSlotAndTable(slot_idx);

    try client.sendDirect(wire);

    return client.waitForResponse(allocator, slot_idx, code, options);
}

// ─── sendRaw / recvRaw ───────────────────────────────────────────

pub fn sendRaw(client: *Client, packet: coapz.Packet) !void {
    var buf: [constants.buffer_size_default]u8 = undefined;
    const wire = try packet.writeBuf(&buf);
    try client.sendDirect(wire);
}

pub fn recvRaw(
    client: *Client,
    allocator: std.mem.Allocator,
    timeout_ms: u32,
) !?coapz.Packet {
    const deadline = std.time.nanoTimestamp() +
        @as(i128, timeout_ms) * std.time.ns_per_ms;

    while (true) {
        const now = std.time.nanoTimestamp();
        if (now >= deadline) return null;

        const data = client.tryRecv() orelse {
            std.Thread.sleep(1 * std.time.ns_per_ms);
            continue;
        };
        const packet = coapz.Packet.read(allocator, data) catch continue;
        return packet;
    }
}

// ─── observe (RFC 7641) ──────────────────────────────────────────

pub fn observe(
    client: *Client,
    options: []const coapz.Option,
) !ObserveStream {
    const sub_idx = for (0..max_observes) |i| {
        if (!client.observes[i].active) break @as(u8, @intCast(i));
    } else return error.TooManyObserves;

    var token_buf: [8]u8 = undefined;
    const token = client.makeToken(&token_buf);
    const msg_id = client.nextMsgId();

    // Observe=0 must come before uri_path options (lower option number).
    var obs_val_buf: [4]u8 = undefined;
    const obs_opt = coapz.Option.uint(.observe, 0, &obs_val_buf);

    var combined_options: [32]coapz.Option = undefined;
    combined_options[0] = obs_opt;
    const opt_count = @min(options.len, 31);
    for (0..opt_count) |i| {
        combined_options[i + 1] = options[i];
    }

    const packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = msg_id,
        .token = token,
        .options = combined_options[0 .. opt_count + 1],
        .payload = &.{},
        .data_buf = &.{},
    };

    const sub = &client.observes[sub_idx];
    @memcpy(sub.token[0..token.len], token);
    sub.token_len = @intCast(token.len);
    sub.active = true;
    sub.last_seq = 0;
    sub.pending_count = 0;

    const slot_idx = try client.allocSlot();

    const slot = &client.slots[slot_idx];
    const offset: u32 = @as(u32, slot_idx) * client.config.buffer_size;
    const slot_buf = client.send_buf[offset..][0..client.config.buffer_size];
    const wire = packet.writeBuf(slot_buf) catch |err| {
        client.freeSlot(slot_idx);
        sub.active = false;
        return err;
    };

    @memcpy(slot.token[0..token.len], token);
    slot.token_len = @intCast(token.len);
    slot.msg_id = msg_id;
    slot.retransmit_count = 0;
    slot.send_offset = offset;
    slot.send_len = @intCast(wire.len);
    slot.state = .pending;

    const initial_timeout = client.randomizedTimeout(constants.ack_timeout_ms);
    slot.timeout_ns = initial_timeout;
    slot.next_retransmit_ns = std.time.nanoTimestamp() + @as(i128, initial_timeout);

    client.insertTable(slot_idx, client.tokenKey(token));
    errdefer {
        client.freeSlotAndTable(slot_idx);
        sub.active = false;
    }

    try client.sendDirect(wire);

    // Wait for the initial ACK (confirms subscription).
    try client.waitForAck(slot_idx);

    return .{
        .client = client,
        .sub_idx = sub_idx,
    };
}

// ─── upload (RFC 7959 Block1) ────────────────────────────────────

pub fn upload(
    client: *Client,
    allocator: std.mem.Allocator,
    code: coapz.Code,
    options: []const coapz.Option,
    payload: []const u8,
) !Result {
    var szx = client.config.default_szx;
    var block_size: usize = @as(usize, 1) << (@as(u4, szx) + 4);

    var block_num: u32 = 0;
    while (true) {
        const start = block_num * block_size;
        const end = @min(start + block_size, payload.len);
        const is_last = (end >= payload.len);
        const block_payload = if (start < payload.len) payload[start..end] else &[_]u8{};

        var block_buf: [3]u8 = undefined;
        const block_val = coapz.BlockValue{
            .num = block_num,
            .more = !is_last,
            .szx = szx,
        };
        const block_opt = block_val.option(.block1, &block_buf);

        var combined: [32]coapz.Option = undefined;
        const opt_count = @min(options.len, 31);
        for (0..opt_count) |i| {
            combined[i] = options[i];
        }
        combined[opt_count] = block_opt;

        const result = try client.call(
            allocator,
            code,
            combined[0 .. opt_count + 1],
            block_payload,
        );

        if (is_last) {
            return result;
        }

        const resp_code = result.code;

        // Honor server's szx preference.
        var resp_blk_it = result.packet.find_options(.block1);
        if (resp_blk_it.next()) |resp_blk_opt| {
            if (resp_blk_opt.as_block()) |resp_blk| {
                if (resp_blk.szx < szx) {
                    szx = resp_blk.szx;
                    block_size = @as(usize, 1) << (@as(u4, szx) + 4);
                    block_num = @intCast(end / block_size);
                    result.deinit(allocator);
                    continue;
                }
            }
        }

        result.deinit(allocator);

        if (resp_code != .@"continue") {
            return error.UploadRejected;
        }

        block_num += 1;
    }
}

// ─── Internal: I/O helpers ───────────────────────────────────────

fn sendDirect(client: *Client, data: []const u8) !void {
    _ = posix.send(client.fd, data, 0) catch |err| {
        log.err("send failed: {}", .{err});
        return error.SendFailed;
    };
}

fn sendAck(client: *Client, msg_id: u16, token: []const u8) !void {
    const ack = coapz.Packet{
        .kind = .acknowledgement,
        .code = .empty,
        .msg_id = msg_id,
        .token = token,
        .options = &.{},
        .payload = &.{},
        .data_buf = &.{},
    };
    var buf: [64]u8 = undefined;
    const wire = ack.writeBuf(&buf) catch return;
    client.sendDirect(wire) catch {};
}

/// Non-blocking recv. Returns data slice or null if nothing available.
fn tryRecv(client: *Client) ?[]const u8 {
    const n = posix.recv(client.fd, client.recv_buf, 0) catch return null;
    if (n == 0) return null;
    return client.recv_buf[0..n];
}

/// Poll for recv with deadline. Returns data or null on timeout.
fn recvUntil(client: *Client, deadline_ns: i128) ?[]const u8 {
    while (true) {
        if (client.tryRecv()) |data| return data;
        const now = std.time.nanoTimestamp();
        if (now >= deadline_ns) return null;
        // Brief sleep to avoid busy-loop; 500µs is short enough for
        // CoAP retransmission granularity (seconds).
        std.Thread.sleep(500 * std.time.ns_per_us);
    }
}

/// Process one recv cycle. Returns true if data was received and dispatched.
fn tickOnce(client: *Client) !bool {
    const deadline = std.time.nanoTimestamp() + 50 * std.time.ns_per_ms;
    const data = client.recvUntil(deadline) orelse return false;
    client.dispatchRecv(data);
    return true;
}

/// Dispatch a received packet to observe subscriptions.
fn dispatchRecv(client: *Client, data: []const u8) void {
    if (data.len < 4) return;
    const tkl: u8 = data[0] & 0x0F;
    if (data.len < 4 + tkl) return;
    const token = data[4..][0..tkl];
    _ = client.routeObserve(token, data);
}

/// Try to route data to an observe subscription. Returns true if consumed.
fn routeObserve(client: *Client, token: []const u8, data: []const u8) bool {
    for (&client.observes) |*obs| {
        if (!obs.active) continue;
        if (obs.token_len != token.len) continue;
        if (!std.mem.eql(u8, obs.token[0..obs.token_len], token)) continue;

        if (obs.pending_count < max_pending_notifications) {
            const copy = client.allocator.alloc(u8, data.len) catch return true;
            @memcpy(copy, data);
            const msg_kind: u2 = @intCast((data[0] >> 4) & 0x03);
            obs.pending[obs.pending_count] = .{
                .data = copy,
                .len = @intCast(data.len),
                .msg_id = @as(u16, data[2]) << 8 | data[3],
                .is_con = msg_kind == 0,
            };
            obs.pending_count += 1;
        }
        return true;
    }
    return false;
}

/// Wait for a response to a specific in-flight slot.
/// Handles retransmission, Block2 reassembly (iterative), and observe routing.
fn waitForResponse(
    client: *Client,
    allocator: std.mem.Allocator,
    cur_slot_idx: u16,
    original_code: coapz.Code,
    original_options: []const coapz.Option,
) !Result {
    var slot_idx = cur_slot_idx;
    var assembled_payload: std.ArrayListUnmanaged(u8) = .empty;
    defer assembled_payload.deinit(allocator);
    var doing_block2 = false;

    while (true) {
        const slot = &client.slots[slot_idx];
        const now = std.time.nanoTimestamp();

        // Check retransmission timeout.
        if (slot.state == .pending and now >= slot.next_retransmit_ns) {
            if (slot.retransmit_count >= constants.max_retransmit) {
                client.freeSlotAndTable(slot_idx);
                return error.Timeout;
            }
            const wire = client.send_buf[slot.send_offset..][0..slot.send_len];
            client.sendDirect(wire) catch {};
            slot.retransmit_count += 1;
            slot.timeout_ns *= 2;
            slot.next_retransmit_ns = now + @as(i128, slot.timeout_ns);
        }

        // Wait until next retransmit deadline or a short poll interval.
        const poll_deadline = @min(
            slot.next_retransmit_ns,
            now + 50 * std.time.ns_per_ms,
        );
        const data = client.recvUntil(poll_deadline) orelse continue;

        if (data.len < 4) continue;

        const tkl: u8 = data[0] & 0x0F;
        if (data.len < 4 + tkl) continue;
        const recv_token = data[4..][0..tkl];

        // Route observe notifications.
        if (client.routeObserve(recv_token, data)) continue;

        // Check if token matches our slot.
        if (slot.token_len != tkl) continue;
        if (!std.mem.eql(u8, slot.token[0..slot.token_len], recv_token)) continue;

        const response = coapz.Packet.read(allocator, data) catch continue;

        if (response.kind == .reset) {
            response.deinit(allocator);
            client.freeSlotAndTable(slot_idx);
            return error.Reset;
        }

        // Check for Block2 with more=true.
        var blk2_it = response.find_options(.block2);
        if (blk2_it.next()) |blk2_opt| {
            if (blk2_opt.as_block()) |blk2| {
                if (blk2.more) {
                    try assembled_payload.appendSlice(allocator, response.payload);
                    doing_block2 = true;
                    response.deinit(allocator);
                    client.freeSlotAndTable(slot_idx);

                    slot_idx = try client.sendBlock2Request(
                        blk2.num + 1,
                        blk2.szx,
                        original_code,
                        original_options,
                    );
                    continue;
                }
            }
        }

        // Final response.
        client.freeSlotAndTable(slot_idx);

        if (doing_block2) {
            try assembled_payload.appendSlice(allocator, response.payload);
            response.deinit(allocator);

            const full_payload = try allocator.alloc(u8, assembled_payload.items.len);
            @memcpy(full_payload, assembled_payload.items);

            const final = coapz.Packet.read(allocator, data) catch
                return error.InvalidPacket;

            return .{
                .code = final.code,
                .options = final.options,
                .payload = full_payload,
                .packet = final,
                .owns_payload = true,
            };
        }

        return .{
            .code = response.code,
            .options = response.options,
            .payload = response.payload,
            .packet = response,
        };
    }
}

/// Send a Block2 continuation GET and set up a new in-flight slot.
fn sendBlock2Request(
    client: *Client,
    block_num: u32,
    szx: u3,
    code: coapz.Code,
    options: []const coapz.Option,
) !u16 {
    var token_buf: [8]u8 = undefined;
    const token = client.makeToken(&token_buf);
    const msg_id = client.nextMsgId();

    var block_buf: [3]u8 = undefined;
    const blk = coapz.BlockValue{
        .num = block_num,
        .more = false,
        .szx = szx,
    };
    const block_opt = blk.option(.block2, &block_buf);

    var combined: [32]coapz.Option = undefined;
    const opt_count = @min(options.len, 31);
    for (0..opt_count) |i| {
        combined[i] = options[i];
    }
    combined[opt_count] = block_opt;

    const packet = coapz.Packet{
        .kind = .confirmable,
        .code = code,
        .msg_id = msg_id,
        .token = token,
        .options = combined[0 .. opt_count + 1],
        .payload = &.{},
        .data_buf = &.{},
    };

    const new_slot_idx = try client.allocSlot();
    const new_slot = &client.slots[new_slot_idx];
    const offset: u32 = @as(u32, new_slot_idx) * client.config.buffer_size;
    const slot_buf = client.send_buf[offset..][0..client.config.buffer_size];
    const wire = packet.writeBuf(slot_buf) catch |err| {
        client.freeSlot(new_slot_idx);
        return err;
    };

    @memcpy(new_slot.token[0..token.len], token);
    new_slot.token_len = @intCast(token.len);
    new_slot.msg_id = msg_id;
    new_slot.retransmit_count = 0;
    new_slot.send_offset = offset;
    new_slot.send_len = @intCast(wire.len);
    new_slot.state = .pending;

    const initial_timeout = client.randomizedTimeout(constants.ack_timeout_ms);
    new_slot.timeout_ns = initial_timeout;
    new_slot.next_retransmit_ns = std.time.nanoTimestamp() + @as(i128, initial_timeout);

    client.insertTable(new_slot_idx, client.tokenKey(token));
    errdefer client.freeSlotAndTable(new_slot_idx);

    try client.sendDirect(wire);

    return new_slot_idx;
}

/// Wait for ACK to a specific in-flight slot (for observe registration).
fn waitForAck(client: *Client, slot_idx: u16) !void {
    const slot = &client.slots[slot_idx];

    while (true) {
        const now = std.time.nanoTimestamp();

        if (now >= slot.next_retransmit_ns) {
            if (slot.retransmit_count >= constants.max_retransmit) {
                client.freeSlotAndTable(slot_idx);
                return error.Timeout;
            }
            const wire = client.send_buf[slot.send_offset..][0..slot.send_len];
            client.sendDirect(wire) catch {};
            slot.retransmit_count += 1;
            slot.timeout_ns *= 2;
            slot.next_retransmit_ns = now + @as(i128, slot.timeout_ns);
        }

        const poll_deadline = @min(
            slot.next_retransmit_ns,
            now + 50 * std.time.ns_per_ms,
        );
        const data = client.recvUntil(poll_deadline) orelse continue;

        if (data.len < 4) continue;
        const tkl: u8 = data[0] & 0x0F;
        if (data.len < 4 + tkl) continue;
        const recv_token = data[4..][0..tkl];

        if (slot.token_len != tkl) continue;
        if (!std.mem.eql(u8, slot.token[0..slot.token_len], recv_token)) continue;

        // Buffer as first observe notification.
        for (&client.observes) |*obs| {
            if (!obs.active) continue;
            if (obs.token_len != slot.token_len) continue;
            if (!std.mem.eql(u8, obs.token[0..obs.token_len], slot.token[0..slot.token_len])) continue;

            if (obs.pending_count < max_pending_notifications) {
                const copy = try client.allocator.alloc(u8, data.len);
                @memcpy(copy, data);
                obs.pending[obs.pending_count] = .{
                    .data = copy,
                    .len = @intCast(data.len),
                    .msg_id = @as(u16, data[2]) << 8 | data[3],
                    .is_con = false,
                };
                obs.pending_count += 1;
            }
            break;
        }

        client.freeSlotAndTable(slot_idx);
        return;
    }
}

// ─── Internal: slot management ───────────────────────────────────

fn allocSlot(client: *Client) !u16 {
    if (client.free_head == empty_sentinel) return error.TooManyInFlight;
    const idx = client.free_head;
    client.free_head = client.slots[idx].next_free;
    client.count_active += 1;
    return idx;
}

fn freeSlot(client: *Client, idx: u16) void {
    client.slots[idx].state = .free;
    client.slots[idx].next_free = client.free_head;
    client.free_head = idx;
    client.count_active -= 1;
}

fn freeSlotAndTable(client: *Client, idx: u16) void {
    const slot = &client.slots[idx];
    const key = client.tokenKey(slot.token[0..slot.token_len]);
    client.removeTable(key);
    client.freeSlot(idx);
}

// ─── Internal: hash table ────────────────────────────────────────

fn tokenKey(_: *const Client, token: []const u8) u64 {
    var hash: u64 = 0xcbf29ce484222325; // FNV-1a
    for (token) |b| {
        hash ^= b;
        hash *%= 0x100000001b3;
    }
    return hash;
}

fn insertTable(client: *Client, slot_idx: u16, key: u64) void {
    var idx: u16 = @intCast(@as(u32, @truncate(key)) & client.table_mask);
    while (client.slot_table[idx] != empty_sentinel) {
        idx = (idx + 1) & client.table_mask;
    }
    client.slot_table[idx] = slot_idx;
}

fn findSlot(client: *const Client, key: u64) ?u16 {
    var idx: u16 = @intCast(@as(u32, @truncate(key)) & client.table_mask);
    var probes: u16 = 0;
    while (probes <= client.table_mask) : (probes += 1) {
        const slot_idx = client.slot_table[idx];
        if (slot_idx == empty_sentinel) return null;
        const slot = &client.slots[slot_idx];
        if (client.tokenKey(slot.token[0..slot.token_len]) == key) {
            return slot_idx;
        }
        idx = (idx + 1) & client.table_mask;
    }
    return null;
}

fn removeTable(client: *Client, key: u64) void {
    var idx: u16 = @intCast(@as(u32, @truncate(key)) & client.table_mask);
    var probes: u16 = 0;
    while (probes <= client.table_mask) : (probes += 1) {
        const slot_idx = client.slot_table[idx];
        if (slot_idx == empty_sentinel) return;
        const slot = &client.slots[slot_idx];
        if (client.tokenKey(slot.token[0..slot.token_len]) == key) {
            client.slot_table[idx] = empty_sentinel;
            client.rehashAfterRemove(idx);
            return;
        }
        idx = (idx + 1) & client.table_mask;
    }
}

fn rehashAfterRemove(client: *Client, removed_idx: u16) void {
    var gap = removed_idx;
    var idx = (removed_idx + 1) & client.table_mask;
    while (client.slot_table[idx] != empty_sentinel) {
        const slot_idx = client.slot_table[idx];
        const slot = &client.slots[slot_idx];
        const key = client.tokenKey(slot.token[0..slot.token_len]);
        const desired: u16 = @intCast(@as(u32, @truncate(key)) & client.table_mask);

        if (wrappingDistance(desired, idx, client.table_mask) >=
            wrappingDistance(desired, gap, client.table_mask))
        {
            client.slot_table[gap] = slot_idx;
            client.slot_table[idx] = empty_sentinel;
            gap = idx;
        }
        idx = (idx + 1) & client.table_mask;
    }
}

fn wrappingDistance(from: u16, to: u16, mask: u16) u16 {
    return (to -% from) & mask;
}

// ─── Internal: ID generation ─────────────────────────────────────

fn nextMsgId(client: *Client) u16 {
    const id = client.next_msg_id_val;
    client.next_msg_id_val = id +% 1;
    return id;
}

fn makeToken(client: *Client, buf: *[8]u8) []const u8 {
    const val = client.next_token_val;
    client.next_token_val += 1;
    const len = client.config.token_len;
    var i: u3 = 0;
    while (i < len) : (i += 1) {
        buf[i] = @intCast((val >> (@as(u6, i) * 8)) & 0xFF);
    }
    return buf[0..len];
}

fn randomizedTimeout(client: *Client, base_ms: u32) u64 {
    // RFC 7252 §4.2: timeout = base × random(1.0, ACK_RANDOM_FACTOR)
    // ACK_RANDOM_FACTOR = 1.5, so range is [base, 1.5 * base].
    const base_ns: u64 = @as(u64, base_ms) * std.time.ns_per_ms;
    const jitter_range = base_ns / 2;
    const jitter = client.rng.random().uintLessThan(u64, jitter_range + 1);
    return base_ns + jitter;
}

// ─── Tests ───────────────────────────────────────────────────────

const testing = std.testing;
const linux = std.os.linux;
const coapd_server = @import("Server.zig");
const coapd_handler = @import("handler.zig");

const ServerRunner = struct {
    server: *coapd_server,
    should_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(self: *@This()) void {
        while (!self.should_stop.load(.monotonic)) {
            self.server.tick() catch {};
            var cqes: [256]linux.io_uring_cqe = std.mem.zeroes([256]linux.io_uring_cqe);
            _ = self.server.io.wait_cqes(cqes[0..], 0) catch {};
        }
    }

    fn stop(self: *@This(), thread: std.Thread) void {
        self.should_stop.store(true, .monotonic);
        // Send a dummy packet to wake the server from blocking wait_cqes.
        const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
        defer posix.close(fd);
        const dest = std.net.Address.parseIp(
            "127.0.0.1",
            self.server.config.port,
        ) catch return;
        _ = posix.sendto(fd, &[_]u8{0}, 0, &dest.any, dest.getOsSockLen()) catch {};
        thread.join();
    }
};

fn startTestServer(port: u16, handler_fn: anytype) !coapd_server {
    var server = try coapd_server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
    }, handler_fn);
    try server.listen();
    return server;
}

fn echoHandler(request: coapd_handler.Request) ?coapd_handler.Response {
    return .{ .payload = request.packet.payload };
}

fn nullHandler(_: coapd_handler.Request) ?coapd_handler.Response {
    return null;
}

test "init and deinit" {
    var client = try Client.init(testing.allocator, .{
        .port = 15683,
        .max_in_flight = 4,
    });
    client.deinit();
}

test "init rejects invalid config" {
    try testing.expectError(
        error.InvalidConfig,
        Client.init(testing.allocator, .{ .max_in_flight = 0 }),
    );
}

test "cast NON to server" {
    const port: u16 = 29701;
    var server = try startTestServer(port, echoHandler);
    defer server.deinit();

    var client = try Client.init(testing.allocator, .{
        .port = port,
        .max_in_flight = 4,
    });
    defer client.deinit();

    try client.cast(.get, &.{}, "hello");
}

test "sendRaw and recvRaw round-trip" {
    const port: u16 = 29702;
    var server = try startTestServer(port, echoHandler);
    defer server.deinit();

    var client = try Client.init(testing.allocator, .{
        .port = port,
        .max_in_flight = 4,
    });
    defer client.deinit();

    const request = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x1234,
        .token = &.{ 0xAA, 0xBB },
        .options = &.{},
        .payload = "raw-test",
        .data_buf = &.{},
    };

    try client.sendRaw(request);

    // Server needs to process.
    try server.tick();
    var cqes: [256]linux.io_uring_cqe = std.mem.zeroes([256]linux.io_uring_cqe);
    _ = try server.io.wait_cqes(cqes[0..], 0);

    const response = try client.recvRaw(testing.allocator, 2000) orelse
        return error.NoResponse;
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.non_confirmable, response.kind);
    try testing.expectEqual(.content, response.code);
    try testing.expectEqualSlices(u8, "raw-test", response.payload);
}

test "call CON round-trip" {
    const port: u16 = 29703;
    var server = try startTestServer(port, echoHandler);
    defer server.deinit();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .port = port,
        .max_in_flight = 4,
    });
    defer client.deinit();

    const result = try client.call(
        testing.allocator,
        .get,
        &.{},
        "hello-con",
    );
    defer result.deinit(testing.allocator);

    try testing.expectEqual(.content, result.code);
    try testing.expectEqualSlices(u8, "hello-con", result.payload);
}

test "recvRaw returns null on timeout" {
    const port: u16 = 29798;
    var server = try startTestServer(port, nullHandler);
    defer server.deinit();

    var client = try Client.init(testing.allocator, .{
        .port = port,
        .max_in_flight = 4,
    });
    defer client.deinit();

    const result = try client.recvRaw(testing.allocator, 50);
    try testing.expect(result == null);
}
