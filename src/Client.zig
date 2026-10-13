/// CoAP client on a connected UDP socket.
///
/// One client per peer — connects to a single server via `connect()`'d UDP.
/// Supports NON fire-and-forget (`cast`), CON request/response with
/// retransmission (`call`, `get`, `post`, `put`, `delete`), pipelined
/// async requests (`submit`, `poll`), raw send/recv, RFC 7641 observe,
/// RFC 7959 Block1 upload, and transparent Block2 reassembly.
///
/// Single-threaded, tick-driven. Not thread-safe.
///
/// **Memory:** `init()` pre-allocates send/recv buffers and in-flight slot
/// tables. These are owned by the client and freed in `deinit()`.
/// CON response APIs decode into caller-owned ResponseBuffers, with bounded
/// Block2 reassembly and no heap allocation. Results borrow this storage.
/// Raw receives and Observe notifications retain explicit allocator APIs.
///
/// ## Example
///
/// ```zig
/// var client = try Client.init(allocator, .{ .host = "10.0.0.1" });
/// defer client.deinit();
///
/// var storage: Client.ResponseStorage(4096) = .{};
/// const result = try client.get(storage.buffers(), "/sensor/temperature");
/// std.debug.print("{s}\n", .{result.payload});
/// ```
const std = @import("std");
const platform = @import("platform.zig");
const posix = platform;
const coapz = @import("coapz");
const constants = @import("constants.zig");
const dtls = @import("dtls/dtls.zig");
const log = std.log.scoped(.coap_client);

const Client = @This();

fn nanoTimestamp() i64 {
    return @intCast(platform.nanoTimestamp());
}

/// Client configuration. All fields have sensible defaults.
pub const Config = struct {
    /// Server address (IPv4 or IPv6). Default: `"127.0.0.1"`.
    host: []const u8 = "127.0.0.1",
    /// Server UDP port. Default: 5683 (CoAP standard).
    port: u16 = constants.port_default,
    /// Maximum concurrent CON requests in flight. Default: 32.
    max_in_flight: u16 = 32,
    /// Maximum CoAP datagram size in bytes. Default: 1280.
    buffer_size: u32 = constants.buffer_size_default,
    /// Token length in bytes (1–8). Default: 2.
    token_len: u3 = 2,
    /// Block size exponent for Block1/Block2: `block_size = 2^(szx+4)`.
    /// Default: 6 (1024 bytes).
    default_szx: u3 = 6,
    /// PSK credentials for DTLS. null = plain UDP.
    psk: ?dtls.types.Psk = null,
    /// DTLS handshake timeout in milliseconds.
    handshake_timeout_ms: u32 = 10_000,
};

/// Response from a CON request (`call`, `get`, `post`, `put`, `delete`, `upload`).
///
/// **Lifetime:** Borrows the storage supplied with the request. All bytes and
/// option descriptors remain valid until that storage is reused, even after
/// another receive or client.deinit(). Never deinit this result or its packet.
pub const Result = struct {
    /// Response code (e.g. `.content`, `.not_found`).
    code: coapz.Code,
    /// Response options; descriptors and values borrow caller storage.
    options: []const coapz.Option,
    /// Body borrows packet storage, or payload storage for Block2 reassembly.
    payload: []const u8,
    /// Borrowed packet view, including the complete reassembled payload.
    packet: coapz.Packet,
};

/// Caller-owned storage, borrowed exclusively by one request until completion.
/// Result bytes/options remain valid until the caller reuses this storage.
/// packet holds one wire datagram; payload bounds multi-block reassembly.
/// All three regions and every pending request's storage must be disjoint.
/// Use distinct storage while retaining multiple completed results.
pub const ResponseBuffers = struct {
    packet: []u8,
    options: []coapz.Option,
    payload: []u8 = &.{},
};

/// Convenience storage; construct once, then reuse after consuming each result.
pub fn ResponseStorage(comptime payload_capacity: usize) type {
    return struct {
        packet: [constants.buffer_size_default]u8 = undefined,
        options: [32]coapz.Option = undefined,
        payload: [payload_capacity]u8 = undefined,
        pub fn buffers(self: *@This()) ResponseBuffers {
            return .{ .packet = &self.packet, .options = &self.options, .payload = &self.payload };
        }
    };
}

const packet_view = @import("packet_view.zig");

fn byteRangesOverlap(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;
    return @intFromPtr(a.ptr) < @intFromPtr(b.ptr) + b.len and
        @intFromPtr(b.ptr) < @intFromPtr(a.ptr) + a.len;
}

fn buffersDisjoint(buffers: ResponseBuffers) bool {
    const options = std.mem.sliceAsBytes(buffers.options);
    return !byteRangesOverlap(buffers.packet, buffers.payload) and
        !byteRangesOverlap(buffers.packet, options) and !byteRangesOverlap(buffers.payload, options);
}

fn buffersOverlap(a: ResponseBuffers, b: ResponseBuffers) bool {
    const left = [_][]const u8{ a.packet, std.mem.sliceAsBytes(a.options), a.payload };
    const right = [_][]const u8{ b.packet, std.mem.sliceAsBytes(b.options), b.payload };
    for (left) |x| for (right) |y| {
        if (byteRangesOverlap(x, y)) return true;
    };
    return false;
}

/// Opaque handle identifying a submitted async request.
/// Valid until the corresponding Completion is returned by poll().
pub const RequestHandle = u16;

/// Completion returned by poll() when a submitted request finishes.
pub const Completion = struct {
    /// Handle matching the one returned by submit().
    handle: RequestHandle,
    /// Borrowed response or correlated request failure. No deinit is required.
    result: anyerror!Result,
};

// ─── In-flight slot ──────────────────────────────────────────────

const InFlightState = enum(u8) { free, pending };

const InFlightSlot = struct {
    state: InFlightState,
    token: [8]u8,
    token_len: u3,
    msg_id: u16,
    retransmit_count: u4,
    next_retransmit_ns: i64,
    timeout_ns: u64,
    /// Offset into send_buf for retransmission data.
    send_offset: u32,
    send_len: u16,
    next_free: u16,
    // Async Block2 reassembly state.
    response_buffers: ResponseBuffers = .{ .packet = &.{}, .options = &.{} },
    block2_length: usize = 0,
    block2_offset: usize = 0,
    acknowledged: bool = false,
    doing_block2: bool,
    block2_etag: [8]u8,
    block2_etag_len: u4,
    original_code: coapz.Code,
    original_options_buf: [16]coapz.Option,
    original_options_len: u5,
    /// Handle returned to caller by submit(); stable across Block2 continuations.
    original_handle: u16,
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

/// Handle for an active RFC 7641 observe subscription.
///
/// Returned by `Client.observe()`. Call `next()` or `nextBuf()` in a loop
/// to receive notifications, and `cancel()` to unsubscribe.
///
/// **Lifetime:** The stream borrows the `Client` and must not outlive it.
/// CON notifications are automatically ACKed.
///
/// ```zig
/// var stream = try client.observe(&.{
///     .{ .kind = .uri_path, .value = "temperature" },
/// });
/// while (try stream.next(allocator)) |notif| {
///     defer notif.deinit(allocator);
///     std.debug.print("{s}\n", .{notif.payload});
/// }
/// try stream.cancel();
/// ```
pub const ObserveStream = struct {
    client: *Client,
    sub_idx: u8,

    /// A single observe notification. Caller must call `deinit()` with
    /// the same allocator passed to `next()`.
    pub const Notification = struct {
        code: coapz.Code,
        options: []const coapz.Option,
        payload: []const u8,
        packet: coapz.Packet,

        pub fn deinit(self: Notification, allocator: std.mem.Allocator) void {
            self.packet.deinit(allocator);
        }
    };

    /// A notification parsed into a caller-provided buffer. No heap
    /// allocation; data is valid only until the next `nextBuf()` call.
    pub const BufNotification = struct {
        code: coapz.Code,
        options: []const coapz.Option,
        payload: []const u8,
    };

    /// Block until the next observe notification arrives.
    /// Returns `null` if the subscription was cancelled.
    ///
    /// **Blocking:** Blocks indefinitely until a notification arrives or
    /// cancelled via `cancel()`. Use a dedicated thread if needed.
    ///
    /// **Lifetime:** The returned `Notification` owns its packet data.
    /// Caller must call `notification.deinit(allocator)` when done.
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

    pub const Error = error{BufferTooSmall};

    /// Like `next()`, but parses the notification into a caller-provided
    /// buffer instead of heap-allocating. Returns `null` if cancelled,
    /// `error.BufferTooSmall` if the packet doesn't fit in `buf`.
    ///
    /// **Blocking:** This call blocks indefinitely until a notification
    /// arrives or the subscription is cancelled via `cancel()`. For
    /// non-blocking use, call from a dedicated thread and use `cancel()`
    /// from another thread to unblock.
    ///
    /// **Lifetime:** The returned `BufNotification` fields point into `buf`
    /// and are valid until the next `nextBuf()` call or until `buf` is reused.
    pub fn nextBuf(self: *ObserveStream, buf: []u8) !?BufNotification {
        const sub = &self.client.observes[self.sub_idx];
        if (!sub.active) return null;

        while (true) {
            if (sub.pending_count > 0) {
                const pending = &sub.pending[0];
                var fba = std.heap.FixedBufferAllocator.init(buf);
                const packet = coapz.Packet.read(fba.allocator(), pending.data[0..pending.len]) catch |err| {
                    if (err == error.OutOfMemory) {
                        return error.BufferTooSmall;
                    }
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
                };
            }

            const got_data = try self.client.tickOnce();
            if (!got_data and !sub.active) return null;
        }
    }

    /// Cancel the observe subscription by sending a deregister GET
    /// (Observe=1). Drains any buffered pending notifications.
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
        self.client.sendCoap(wire) catch {};

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

/// True after receiving the first valid response from the peer.
/// When false, only `nstart` (default 1) CON requests are allowed
/// in-flight per RFC 7252 §4.7.
peer_confirmed: bool,

observes: [max_observes]ObserveSub,

next_msg_id_val: u16,
next_token_val: u64,
rng: std.Random.DefaultPrng,

dtls_session: ?dtls.Session.Session,
dtls_client_hs_state: dtls.Handshake.ClientHandshakeState,
/// Cached session data for DTLS resumption.
dtls_cached_session_id: [32]u8,
dtls_cached_session_id_len: u8,
dtls_cached_master_secret: [48]u8,

const empty_sentinel: u16 = 0xFFFF;

/// Create a client and connect to the server at `config.host:config.port`.
///
/// Pre-allocates `max_in_flight * buffer_size` bytes for the send buffer,
/// `buffer_size` for the recv buffer, plus slot tracking tables. All owned
/// by the client and freed in `deinit()`.
///
/// Returns `error.InvalidConfig` if `max_in_flight` is 0 or `buffer_size` < 64.
/// Supports both IPv4 and IPv6 addresses.
pub fn init(allocator: std.mem.Allocator, config: Config) !Client {
    if (config.max_in_flight == 0) return error.InvalidConfig;
    if (config.buffer_size < 64) return error.InvalidConfig;
    // DTLS encryption uses comptime-sized stack buffers bounded by buffer_size_default.
    if (config.psk != null and config.buffer_size > constants.buffer_size_default)
        return error.InvalidConfig;

    var effective_config = config;
    if (config.psk != null and config.port == constants.port_default) {
        effective_config.port = constants.coaps_port_default;
    }

    const dest = try platform.parseIp(effective_config.host, effective_config.port);

    const fd = try posix.socket(platform.family(dest), posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    errdefer posix.close(fd);
    try posix.connect(fd, dest);

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
            .block2_length = 0,
            .doing_block2 = false,
            .block2_etag = undefined,
            .block2_etag_len = 0,
            .original_code = .empty,
            .original_options_buf = undefined,
            .original_options_len = 0,
            .original_handle = 0,
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
    platform.randomBytes(std.mem.asBytes(&seed));
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
        .config = effective_config,
        .fd = fd,
        .send_buf = send_buf,
        .recv_buf = recv_buf,
        .slots = slots,
        .slot_table = slot_table,
        .table_mask = table_size - 1,
        .free_head = 0,
        .count_active = 0,
        .peer_confirmed = false,
        .observes = observes,
        .next_msg_id_val = initial_msg_id,
        .next_token_val = platform.randomInt(u64),
        .rng = rng,
        .dtls_session = if (effective_config.psk != null) std.mem.zeroInit(dtls.Session.Session, .{ .addr = platform.ip4(.{ 0, 0, 0, 0 }, 0) }) else null,
        .dtls_client_hs_state = .idle,
        .dtls_cached_session_id = .{0} ** 32,
        .dtls_cached_session_id_len = 0,
        .dtls_cached_master_secret = .{0} ** 48,
    };
}

/// Release all client-owned memory and close the socket.
/// Outstanding results remain valid in caller storage; pending borrows end.
pub fn deinit(client: *Client) void {
    if (client.dtls_session) |*sess| sess.zeroKeys();
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

// ─── DTLS handshake ──────────────────────────────────────────────

/// Perform the DTLS 1.2 PSK handshake. Must be called after init() and
/// before any CoAP send/recv when PSK is configured.
/// Retransmits lost flights per RFC 6347 §4.2.4.
pub fn handshake(client: *Client) !void {
    const psk = client.config.psk orelse return error.NoPskConfigured;
    var sess = &(client.dtls_session orelse return error.NoPskConfigured);

    // Initialize session state.
    sess.state = .handshaking;
    sess.write_sequence = 0;
    sess.read_sequence = 0;
    sess.write_epoch = 0;
    sess.read_epoch = 0;
    sess.replay_window = 0;

    // Set cached session_id for resumption attempt.
    sess.session_id = client.dtls_cached_session_id;
    sess.session_id_len = client.dtls_cached_session_id_len;

    var send_buf: [512]u8 = undefined;

    // Build and send initial ClientHello (includes session_id if cached).
    const cached_sid = client.dtls_cached_session_id[0..client.dtls_cached_session_id_len];
    const action = dtls.Handshake.clientBuildInitialHello(
        sess,
        &client.dtls_client_hs_state,
        psk,
        &send_buf,
        cached_sid,
    );
    var last_flight: []const u8 = switch (action) {
        .send => |data| data,
        .failed => return error.HandshakeFailed,
        else => unreachable,
    };
    try client.sendDirect(last_flight);

    const now_ns = nanoTimestamp();
    const deadline_ns: i64 = now_ns +
        @as(i64, client.config.handshake_timeout_ms) * std.time.ns_per_ms;

    // Retransmit timer (RFC 6347 §4.2.4): exponential backoff.
    var retransmit_timeout_ms: u32 = constants.dtls_retransmit_initial_ms;
    var retransmit_deadline_ns: i64 = now_ns +
        @as(i64, retransmit_timeout_ms) * std.time.ns_per_ms;

    // Loop: receive server messages, process, send responses.
    // A single UDP datagram may contain multiple DTLS records (a flight),
    // so we iterate through all records in each received datagram.
    var pt_buf: [512]u8 = undefined;
    while (client.dtls_client_hs_state != .complete) {
        const now = nanoTimestamp();
        if (now >= deadline_ns) return error.Timeout;

        // Retransmit last flight if timer expired.
        if (now >= retransmit_deadline_ns) {
            if (retransmit_timeout_ms >= constants.dtls_retransmit_max_ms)
                return error.Timeout;
            client.sendDirect(last_flight) catch {};
            retransmit_timeout_ms = @min(retransmit_timeout_ms * 2, constants.dtls_retransmit_max_ms);
            retransmit_deadline_ns = now + @as(i64, retransmit_timeout_ms) * std.time.ns_per_ms;
            continue;
        }

        // Poll until retransmit deadline or overall deadline.
        const poll_deadline_ns = @min(retransmit_deadline_ns, deadline_ns);
        const hs_remaining_ns = poll_deadline_ns - now;
        const hs_timeout_ms: i32 = @intCast(@max(1, @divTrunc(@min(hs_remaining_ns, 100 * std.time.ns_per_ms), std.time.ns_per_ms)));
        const data = client.pollRecv(hs_timeout_ms) orelse continue;

        // Must be a DTLS record.
        if (data.len < 1 or !dtls.types.isDtlsContentType(data[0])) continue;

        // Iterate all records in the datagram.
        var off: usize = 0;
        while (off < data.len) {
            const remaining = data[off..];
            if (remaining.len < dtls.types.record_header_len) break;

            const rec_len = std.mem.readInt(u16, remaining[11..13], .big);
            const total_rec = dtls.types.record_header_len + rec_len;
            if (remaining.len < total_rec) break;

            const rec_data = remaining[0..total_rec];
            const epoch = std.mem.readInt(u16, rec_data[3..5], .big);

            const record = if (epoch == 0)
                dtls.Record.decodePlaintext(rec_data)
            else
                dtls.Record.decodeEncrypted(
                    rec_data,
                    sess.server_write_key,
                    sess.server_write_iv,
                    &sess.replay_window,
                    &sess.read_sequence,
                    &pt_buf,
                );

            off += total_rec;

            const rec = record orelse continue;

            const hs_action = dtls.Handshake.clientProcessMessage(
                sess,
                &client.dtls_client_hs_state,
                rec.content_type,
                rec.payload,
                psk,
                &send_buf,
            );
            switch (hs_action) {
                .send => |sdata| {
                    last_flight = sdata;
                    try client.sendDirect(sdata);
                    // Reset retransmit timer on new flight.
                    retransmit_timeout_ms = constants.dtls_retransmit_initial_ms;
                    retransmit_deadline_ns = nanoTimestamp() +
                        @as(i64, retransmit_timeout_ms) * std.time.ns_per_ms;
                },
                .established => {
                    // Cache session for resumption.
                    client.dtls_cached_session_id = sess.session_id;
                    client.dtls_cached_session_id_len = sess.session_id_len;
                    client.dtls_cached_master_secret = sess.master_secret;
                    return;
                },
                .failed => return error.HandshakeFailed,
                .none => {},
            }
        }
    }
}

// ─── cast (NON fire-and-forget) ──────────────────────────────────

/// Send a NON (non-confirmable) request. Fire-and-forget — no response
/// is expected and the call does not block. No memory is allocated.
///
/// ```zig
/// try client.cast(.post, &.{
///     .{ .kind = .uri_path, .value = "log" },
/// }, "event happened");
/// ```
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
    try client.sendCoap(wire);
}

// ─── call (CON with retransmission + Block2 reassembly) ──────────

/// Send a CON (confirmable) request and block until a response arrives.
///
/// Automatically retransmits per RFC 7252 §4.2 (up to 4 retries, ~93s).
/// Transparently reassembles Block2 multi-block responses.
///
/// The returned Result borrows buffers; consume it before reusing storage.
/// Returns RequestsInFlight rather than discarding unrelated completions.
///
/// For simple path-based requests, prefer `get()`, `post()`, `put()`,
/// `delete()` which build URI-Path options automatically.
///
/// Returns `error.Timeout` after max retransmissions.
/// Returns `error.Reset` if the server sends RST.
/// Returns `error.TooManyInFlight` if `max_in_flight` slots are exhausted.
pub fn call(
    client: *Client,
    buffers: ResponseBuffers,
    code: coapz.Code,
    options: []const coapz.Option,
    payload: []const u8,
) !Result {
    if (client.count_active != 0) return error.RequestsInFlight;
    const handle = try client.submit(buffers, code, options, payload);

    while (true) {
        const completion = try client.poll(50) orelse continue;
        std.debug.assert(completion.handle == handle);
        return completion.result;
    }
}

// ─── Async API (submit / poll) ───────────────────────────────────

/// Submit a CON request without blocking. Returns a handle that
/// identifies this request in subsequent poll() completions.
///
/// The request is serialized, encrypted (if DTLS), and sent immediately.
/// Use poll() to drive the event loop and receive completions. Response buffers
/// are exclusively borrowed until completion, cancel(), or client.deinit().
/// Option values must remain valid until completion for Block2 continuations.
/// At most 16 request options are supported; excess is rejected, not truncated.
///
/// Returns error.TooManyInFlight if max_in_flight slots are exhausted.
/// Returns error.NstartExceeded if peer is unconfirmed and NSTART
/// outstanding CONs are already in flight (RFC 7252 §4.7).
pub fn submit(
    client: *Client,
    buffers: ResponseBuffers,
    code: coapz.Code,
    options: []const coapz.Option,
    payload: []const u8,
) !RequestHandle {
    if (options.len > 16) return error.TooManyRequestOptions;
    if (std.debug.runtime_safety) {
        std.debug.assert(buffersDisjoint(buffers));
        for (client.slots) |slot| {
            if (slot.state == .pending) std.debug.assert(!buffersOverlap(buffers, slot.response_buffers));
        }
    }
    var block2_offset: usize = 0;
    for (options) |option| {
        if (option.kind == .block2) {
            const block = option.as_block() orelse return error.InvalidBlock2;
            if (block.szx == 7) return error.InvalidBlock2;
            block2_offset = @as(usize, block.num) * (@as(usize, 1) << (@as(u4, block.szx) + 4));
        }
    }
    // NSTART enforcement (RFC 7252 §4.7): limit outstanding CONs
    // to nstart until the first successful response from this peer.
    if (!client.peer_confirmed and client.count_active >= constants.nstart) {
        return error.NstartExceeded;
    }

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

    // Store original request info for Block2 continuation.
    slot.original_code = code;
    const opt_count: u5 = @intCast(@min(options.len, slot.original_options_buf.len));
    for (0..opt_count) |i| {
        slot.original_options_buf[i] = options[i];
    }
    slot.original_options_len = opt_count;
    slot.doing_block2 = false;
    slot.response_buffers = buffers;
    slot.acknowledged = false;
    slot.block2_length = 0;
    slot.block2_offset = block2_offset;
    slot.original_handle = slot_idx;

    const initial_timeout = client.randomizedTimeout(constants.ack_timeout_ms);
    slot.timeout_ns = initial_timeout;
    slot.next_retransmit_ns = nanoTimestamp() + @as(i64, @intCast(initial_timeout));

    client.insertTable(slot_idx, client.tokenKey(token));

    client.sendCoap(wire) catch |err| {
        client.freeSlotAndTable(slot_idx);
        return err;
    };

    return slot_idx;
}

/// Drive the event loop: receive, decrypt, match tokens, handle
/// retransmissions, and process Block2 continuations.
///
/// Returns a Completion if any submitted request finished, null if
/// nothing completed within timeout_ms (0 = non-blocking).
///
/// completion.result is an error union, correlated by handle. Results borrow
/// the buffers attached to submit(); no deinit is required.
///
/// Multiple calls to poll() are needed to drain all pending completions
/// when multiple requests are in flight.
/// Process responses into the storage attached to submit(). No heap allocation.
pub fn poll(client: *Client, timeout_ms: i32) !?Completion {
    if (client.count_active == 0) return null;
    const now = nanoTimestamp();
    var earliest: i64 = now + 50 * std.time.ns_per_ms;
    for (client.slots, 0..) |*slot, i| {
        if (slot.state != .pending) continue;
        if (now >= slot.next_retransmit_ns) {
            if (slot.acknowledged or slot.retransmit_count >= constants.max_retransmit)
                return client.finish(@intCast(i), error.Timeout);
            client.sendCoap(client.send_buf[slot.send_offset..][0..slot.send_len]) catch |err|
                return client.finish(@intCast(i), err);
            slot.retransmit_count += 1;
            slot.timeout_ns *= 2;
            slot.next_retransmit_ns = now + @as(i64, @intCast(slot.timeout_ns));
        }
        earliest = @min(earliest, slot.next_retransmit_ns);
    }
    const wait_ms: i32 = if (timeout_ms == 0) 0 else @intCast(@max(1, @min(timeout_ms, @divTrunc(earliest - now, std.time.ns_per_ms))));
    const raw = client.pollRecv(wait_ms) orelse return null;
    var plaintext: [constants.buffer_size_default]u8 = undefined;
    const data = client.decryptRecv(raw, &plaintext) orelse return null;
    if (data.len < 4 or data[0] >> 6 != 1) return null;
    const tkl: usize = data[0] & 15;
    if (tkl > 8 or data.len < 4 + tkl) return null;
    const kind = coapz.Packet.peekKind(data);
    const mid = coapz.Packet.peekMsgId(data).?;
    if (kind == .reset or (kind == .acknowledgement and data[1] == 0)) {
        if (data.len != 4 or data[1] != 0) return null;
        for (client.slots, 0..) |*slot, i| {
            if (slot.state != .pending or slot.msg_id != mid) continue;
            if (kind == .reset) return client.finish(@intCast(i), error.Reset);
            if (slot.acknowledged) return null;
            slot.acknowledged = true;
            slot.next_retransmit_ns = now + @as(i64, constants.max_transmit_wait_ms) * std.time.ns_per_ms;
            return null;
        }
        return null;
    }
    const token = data[4..][0..tkl];
    if (client.routeObserve(token, data)) return null;
    const idx = client.findSlot(client.tokenKey(token)) orelse return null;
    const slot = &client.slots[idx];
    if (!std.mem.eql(u8, slot.token[0..slot.token_len], token)) return null;
    if (kind == .acknowledgement and mid != slot.msg_id) return null;
    if (data[1] >> 5 < 2) return null;
    return client.processResponse(idx, data);
}

/// Abandon a currently pending handle and release its storage borrow.
/// Does not retract a transmitted request or cancel remote application work.
/// Handles are reusable; never cancel a handle after consuming its completion.
pub fn cancel(client: *Client, handle: RequestHandle) void {
    if (handle >= client.slots.len or client.slots[handle].state != .pending) return;
    client.freeSlotAndTable(handle);
}

fn finish(client: *Client, idx: u16, result: anyerror!Result) Completion {
    const handle = client.slots[idx].original_handle;
    client.freeSlotAndTable(idx);
    return .{ .handle = handle, .result = result };
}

fn processResponse(client: *Client, idx: u16, data: []const u8) !?Completion {
    const slot = &client.slots[idx];
    const buffers = slot.response_buffers;
    if (data.len > buffers.packet.len) return client.finish(idx, error.ResponseBufferTooSmall);
    @memcpy(buffers.packet[0..data.len], data);
    var packet = packet_view.read(buffers.packet[0..data.len], buffers.options) catch |err| {
        if (err == error.ResponseOptionsTooSmall) return client.finish(idx, err);
        return null; // Malformed datagrams do not complete a pending request.
    };
    client.peer_confirmed = true;
    if (packet.kind == .confirmable) client.sendAck(packet.msg_id, &.{}) catch |err| return client.finish(idx, err);
    if (@intFromEnum(packet.code) >> 5 != 2)
        return client.finish(idx, .{ .code = packet.code, .options = packet.options, .payload = packet.payload, .packet = packet });
    if (packet.find_option(.block2)) |option| {
        const block = option.as_block() orelse return client.finish(idx, error.InvalidBlock2);
        if (block.szx == 7) return client.finish(idx, error.InvalidBlock2);
        const block_size: usize = @as(usize, 1) << (@as(u4, block.szx) + 4);
        const offset = @as(u64, block.num) * block_size;
        // A retransmitted separate CON block must be ACKed but not appended.
        if (slot.doing_block2 and offset < slot.block2_offset + slot.block2_length) return null;
        if (offset != slot.block2_offset + slot.block2_length or packet.payload.len > block_size)
            return client.finish(idx, error.InvalidBlock2);
        if (!checkBlock2Etag(slot, packet)) return client.finish(idx, error.EtagMismatch);
        if (block.more or slot.doing_block2) {
            if (packet.payload.len > buffers.payload.len - slot.block2_length)
                return client.finish(idx, error.ResponsePayloadTooSmall);
            @memcpy(buffers.payload[slot.block2_length..][0..packet.payload.len], packet.payload);
            slot.block2_length += packet.payload.len;
            slot.doing_block2 = true;
            if (block.more) {
                if (packet.payload.len != block_size) return client.finish(idx, error.InvalidBlock2);
                client.continueBlock2(idx, block.num + 1, block.szx) catch |err| return client.finish(idx, err);
                return null;
            }
            packet.payload = buffers.payload[0..slot.block2_length];
        }
    } else if (slot.doing_block2) return client.finish(idx, error.InvalidBlock2);
    return client.finish(idx, .{ .code = packet.code, .options = packet.options, .payload = packet.payload, .packet = packet });
}

fn continueBlock2(client: *Client, idx: u16, num: u32, szx: u3) !void {
    if (num > 0xfffff) return error.InvalidBlock2;
    const slot = &client.slots[idx];
    var options: [17]coapz.Option = undefined;
    var count: usize = 0;
    for (slot.original_options_buf[0..slot.original_options_len]) |option| {
        if (option.kind == .block2 or option.kind == .block1) continue;
        options[count] = option;
        count += 1;
    }
    var encoded_block: [3]u8 = undefined;
    options[count] = (coapz.BlockValue{ .num = num, .more = false, .szx = szx }).option(.block2, &encoded_block);
    count += 1;
    const Order = struct {
        fn less(_: void, a: coapz.Option, b: coapz.Option) bool {
            return @intFromEnum(a.kind) < @intFromEnum(b.kind);
        }
    };
    std.mem.sort(coapz.Option, options[0..count], {}, Order.less);
    const packet: coapz.Packet = .{ .kind = .confirmable, .code = slot.original_code, .msg_id = client.nextMsgId(), .token = slot.token[0..slot.token_len], .options = options[0..count], .payload = &.{}, .data_buf = &.{} };
    const wire = try packet.writeBuf(client.send_buf[slot.send_offset..][0..client.config.buffer_size]);
    slot.msg_id = packet.msg_id;
    slot.send_len = @intCast(wire.len);
    slot.retransmit_count = 0;
    slot.acknowledged = false;
    slot.timeout_ns = client.randomizedTimeout(constants.ack_timeout_ms);
    slot.next_retransmit_ns = nanoTimestamp() + @as(i64, @intCast(slot.timeout_ns));
    try client.sendCoap(wire);
}

// ─── Path convenience methods ────────────────────────────────────

const uri = @import("uri.zig");

/// CON GET by URI path. Splits `path` into URI-Path options and
/// calls `call()`. The result borrows the supplied response buffers.
pub fn get(client: *Client, buffers: ResponseBuffers, path: []const u8) !Result {
    var buf: [uri.max_options]coapz.Option = undefined;
    return client.call(buffers, .get, uri.fromUri(path, &buf), &.{});
}

/// CON POST by URI path and payload. Result borrows buffers.
pub fn post(client: *Client, buffers: ResponseBuffers, path: []const u8, payload: []const u8) !Result {
    var buf: [uri.max_options]coapz.Option = undefined;
    return client.call(buffers, .post, uri.fromUri(path, &buf), payload);
}

/// CON PUT by URI path and payload. Result borrows buffers.
pub fn put(client: *Client, buffers: ResponseBuffers, path: []const u8, payload: []const u8) !Result {
    var buf: [uri.max_options]coapz.Option = undefined;
    return client.call(buffers, .put, uri.fromUri(path, &buf), payload);
}

/// CON DELETE by URI path. Result borrows buffers.
pub fn delete(client: *Client, buffers: ResponseBuffers, path: []const u8) !Result {
    var buf: [uri.max_options]coapz.Option = undefined;
    return client.call(buffers, .delete, uri.fromUri(path, &buf), &.{});
}

// ─── sendRaw / recvRaw ───────────────────────────────────────────

/// Send a pre-built CoAP packet without protocol automation.
/// No retransmission, no token generation — the caller controls everything.
pub fn sendRaw(client: *Client, packet: coapz.Packet) !void {
    var buf: [constants.buffer_size_default]u8 = undefined;
    const wire = try packet.writeBuf(&buf);
    try client.sendCoap(wire);
}

/// Receive a single raw CoAP packet, blocking up to `timeout_ms`.
/// Returns `null` on timeout. Caller owns the packet and must call
/// `packet.deinit(allocator)`.
pub fn recvRaw(
    client: *Client,
    allocator: std.mem.Allocator,
    timeout_ms: u32,
) !?coapz.Packet {
    const deadline = nanoTimestamp() +
        @as(i64, timeout_ms) * std.time.ns_per_ms;

    while (true) {
        const now = nanoTimestamp();
        if (now >= deadline) return null;

        const remaining_ms: i32 = @intCast(@max(1, @divTrunc(deadline - now, std.time.ns_per_ms)));
        const raw_data = client.pollRecv(remaining_ms) orelse continue;
        var pt_buf: [constants.buffer_size_default]u8 = undefined;
        const data = client.decryptRecv(raw_data, &pt_buf) orelse continue;
        const packet = coapz.Packet.read(allocator, data) catch continue;
        return packet;
    }
}

// ─── observe (RFC 7641) ──────────────────────────────────────────

/// Subscribe to a resource for observe notifications (RFC 7641).
///
/// Sends a CON GET with Observe=0 and blocks until the initial ACK
/// confirms the subscription. Returns an `ObserveStream` for receiving
/// subsequent notifications.
///
/// The Observe option is prepended automatically; pass only URI-Path
/// and other options. Maximum 8 concurrent observe subscriptions.
///
/// Returns `error.TooManyObserves` if 8 subscriptions are already active.
pub fn observe(
    client: *Client,
    options: []const coapz.Option,
) !ObserveStream {
    // NSTART enforcement (RFC 7252 §4.7).
    if (!client.peer_confirmed and client.count_active >= constants.nstart) {
        return error.NstartExceeded;
    }

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
    slot.next_retransmit_ns = nanoTimestamp() + @as(i64, @intCast(initial_timeout));

    client.insertTable(slot_idx, client.tokenKey(token));
    errdefer {
        client.freeSlotAndTable(slot_idx);
        sub.active = false;
    }

    try client.sendCoap(wire);

    // Wait for the initial ACK (confirms subscription).
    try client.waitForAck(slot_idx);

    return .{
        .client = client,
        .sub_idx = sub_idx,
    };
}

// ─── upload (RFC 7959 Block1) ────────────────────────────────────

/// Upload a large payload using RFC 7959 Block1 segmented transfer.
///
/// Splits `payload` into blocks of `config.default_szx` size and sends
/// each as a separate CON request. Honors the server's preferred block
/// size if it responds with a smaller SZX value.
///
/// Returns the final borrowed response. Intermediate replies reuse the same
/// buffers; final Block2 reassembly is bounded too. Consume before reuse.
///
/// ```zig
/// var storage: Client.ResponseStorage(4096) = .{};
/// const result = try client.upload(storage.buffers(), .put, &.{
///     .{ .kind = .uri_path, .value = "firmware" },
/// }, large_payload);
/// ```
pub fn upload(
    client: *Client,
    buffers: ResponseBuffers,
    code: coapz.Code,
    options: []const coapz.Option,
    payload: []const u8,
) !Result {
    if (options.len > 15) return error.TooManyRequestOptions;
    if (payload.len > std.math.maxInt(u32)) return error.UploadTooLarge;
    var szx = client.config.default_szx;
    var block_size: usize = @as(usize, 1) << (@as(u4, szx) + 4);

    var block_num: u32 = 0;
    while (true) {
        if (block_num > 0xfffff) return error.UploadTooLarge;
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
        const opt_count = options.len;
        for (0..opt_count) |i| {
            combined[i] = options[i];
        }
        combined[opt_count] = block_opt;
        std.mem.sort(coapz.Option, combined[0 .. opt_count + 1], {}, struct {
            fn less(_: void, a: coapz.Option, b: coapz.Option) bool {
                return @intFromEnum(a.kind) < @intFromEnum(b.kind);
            }
        }.less);

        const result = try client.call(
            buffers,
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
                if (resp_code != .@"continue") return error.UploadRejected;
                if (resp_blk.szx < szx) {
                    szx = resp_blk.szx;
                    block_size = @as(usize, 1) << (@as(u4, szx) + 4);
                    block_num = @intCast(end / block_size);
                    continue;
                }
            }
        }

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

/// Send CoAP data, encrypting as a DTLS application_data record if DTLS is active.
fn sendCoap(client: *Client, wire: []const u8) !void {
    if (client.dtls_session) |*sess| {
        if (sess.state != .established) return error.DtlsNotEstablished;
        var enc_buf: [constants.buffer_size_default + dtls.types.record_overhead]u8 = undefined;
        if (wire.len > constants.buffer_size_default) return error.BufferTooSmall;
        const encrypted = dtls.Record.encodeEncrypted(
            .application_data,
            wire,
            sess.client_write_key,
            sess.client_write_iv,
            sess.write_epoch,
            &sess.write_sequence,
            &enc_buf,
        );
        return client.sendDirect(encrypted);
    }
    return client.sendDirect(wire);
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
    try client.sendCoap(wire);
}

/// Non-blocking recv. Returns data slice or null if nothing available.
fn tryRecv(client: *Client) ?[]const u8 {
    const n = posix.recv(client.fd, client.recv_buf, 0) catch return null;
    if (n == 0) return null;
    return client.recv_buf[0..n];
}

/// Poll for recv with timeout in milliseconds. Returns data or null on timeout.
/// Uses poll() syscall instead of sleep-loop for minimal latency.
fn pollRecv(client: *Client, timeout_ms: i32) ?[]const u8 {
    // Try non-blocking recv first (avoids syscall if data already queued).
    if (client.tryRecv()) |data| return data;
    if (timeout_ms == 0) return null;

    var pfd = [1]posix.pollfd{.{
        .fd = client.fd,
        .events = posix.POLL.IN,
        .revents = 0,
    }};
    _ = posix.poll(&pfd, timeout_ms) catch return null;

    if (pfd[0].revents & posix.POLL.IN != 0) {
        return client.tryRecv();
    }
    return null;
}

/// Decrypt a DTLS record if DTLS is active, returning the plaintext CoAP data.
/// Returns the raw data unchanged if no DTLS.
/// Returns null if decryption fails or not application_data.
fn decryptRecv(client: *Client, data: []const u8, pt_buf: []u8) ?[]const u8 {
    const sess = &(client.dtls_session orelse return data);
    if (sess.state != .established) return null;

    if (data.len < 1 or !dtls.types.isDtlsContentType(data[0])) return null;

    const record = dtls.Record.decodeEncrypted(
        data,
        sess.server_write_key,
        sess.server_write_iv,
        &sess.replay_window,
        &sess.read_sequence,
        pt_buf,
    ) orelse return null;

    if (record.content_type != .application_data) return null;
    return record.payload;
}

/// Process one recv cycle. Returns true if data was received and dispatched.
fn tickOnce(client: *Client) !bool {
    const raw_data = client.pollRecv(50) orelse return false;
    var pt_buf: [constants.buffer_size_default]u8 = undefined;
    const data = client.decryptRecv(raw_data, &pt_buf) orelse return false;
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
/// Extract the Observe option sequence number from raw CoAP wire data.
/// Returns null if no Observe option is present.
fn parseObserveSeq(data: []const u8) ?u24 {
    const opt = coapz.Packet.peekOption(data, .observe) orelse return null;
    return @intCast(opt.as_uint() orelse return null);
}

fn routeObserve(client: *Client, token: []const u8, data: []const u8) bool {
    for (&client.observes) |*obs| {
        if (!obs.active) continue;
        if (obs.token_len != token.len) continue;
        if (!std.mem.eql(u8, obs.token[0..obs.token_len], token)) continue;

        client.peer_confirmed = true;

        // RFC 7641 §3.4: check observe sequence freshness.
        // Extract observe option value from the wire data.
        if (parseObserveSeq(data)) |seq| {
            if (obs.last_seq != 0 or seq != 0) {
                // Fresh if seq > last (with 24-bit wrap-around tolerance).
                const diff = seq -% obs.last_seq;
                if (diff == 0 or diff > 0x800000) {
                    // Stale or duplicate — drop silently.
                    return true;
                }
            }
            obs.last_seq = seq;
        }

        if (obs.pending_count < max_pending_notifications) {
            const copy = client.allocator.alloc(u8, data.len) catch return true;
            @memcpy(copy, data);
            obs.pending[obs.pending_count] = .{
                .data = copy,
                .len = @intCast(data.len),
                .msg_id = coapz.Packet.peekMsgId(data) orelse 0,
                .is_con = coapz.Packet.peekKind(data) == .confirmable,
            };
            obs.pending_count += 1;
        }
        return true;
    }
    return false;
}

/// Wait for ACK to a specific in-flight slot (for observe registration).
fn waitForAck(client: *Client, slot_idx: u16) !void {
    const slot = &client.slots[slot_idx];

    while (true) {
        const now = nanoTimestamp();

        if (now >= slot.next_retransmit_ns) {
            if (slot.retransmit_count >= constants.max_retransmit) {
                client.freeSlotAndTable(slot_idx);
                return error.Timeout;
            }
            const wire = client.send_buf[slot.send_offset..][0..slot.send_len];
            client.sendCoap(wire) catch {};
            slot.retransmit_count += 1;
            slot.timeout_ns *= 2;
            slot.next_retransmit_ns = now + @as(i64, @intCast(slot.timeout_ns));
        }

        const retransmit_remaining_ns = slot.next_retransmit_ns - now;
        const ack_timeout_ms: i32 = @intCast(@max(1, @divTrunc(@min(retransmit_remaining_ns, 50 * std.time.ns_per_ms), std.time.ns_per_ms)));
        const raw_data = client.pollRecv(ack_timeout_ms) orelse continue;
        var pt_buf_ack: [constants.buffer_size_default]u8 = undefined;
        const data = client.decryptRecv(raw_data, &pt_buf_ack) orelse continue;

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
                    .msg_id = coapz.Packet.peekMsgId(data) orelse 0,
                    .is_con = coapz.Packet.peekKind(data) == .confirmable,
                };
                obs.pending_count += 1;
            }
            break;
        }

        client.peer_confirmed = true;
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
    client.slots[idx].block2_length = 0;
    client.slots[idx].doing_block2 = false;
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

/// Check Block2 ETag consistency (RFC 7959 §2.4). On first block, captures
/// the ETag into the slot. On subsequent blocks, compares and returns false
/// on mismatch. Returns true if no ETag present or ETag matches.
fn checkBlock2Etag(slot: *InFlightSlot, response: coapz.Packet) bool {
    const etag_opt = response.find_option(.etag) orelse {
        // No ETag — nothing to check. Clear any stored ETag.
        if (!slot.doing_block2) slot.block2_etag_len = 0;
        return true;
    };
    if (etag_opt.value.len > 8) return false;
    const len: u4 = @intCast(etag_opt.value.len);

    if (!slot.doing_block2) {
        // First block — capture ETag.
        @memcpy(slot.block2_etag[0..len], etag_opt.value);
        slot.block2_etag_len = len;
        return true;
    }

    // Subsequent block — compare.
    if (slot.block2_etag_len != len) return false;
    return std.mem.eql(u8, slot.block2_etag[0..len], etag_opt.value);
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
const coap_server = @import("Server.zig");
const coap_handler = @import("handler.zig");

const ServerRunner = struct {
    server: *coap_server,
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
        const dest = std.Io.net.IpAddress.parse(
            "127.0.0.1",
            self.server.config.port,
        ) catch return;
        _ = posix.sendto(fd, &[_]u8{0}, 0, dest) catch {};
        thread.join();
    }
};

fn startTestServer(port: u16, handler_fn: anytype) !coap_server {
    var server = try coap_server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
    }, handler_fn);
    try server.listen();
    return server;
}

fn echoHandler(request: coap_handler.Request) ?coap_handler.Response {
    return .{ .payload = request.packet.payload };
}

fn nullHandler(_: coap_handler.Request) ?coap_handler.Response {
    return null;
}

fn metadataEchoHandler(request: coap_handler.Request) ?coap_handler.Response {
    return .{ .payload = request.packet.payload, .options = &.{
        .{ .kind = .etag, .value = "tag-data" },
        .{ .kind = .content_format, .value = &.{0} },
    } };
}

fn awaitTestCompletion(client: *Client) !Completion {
    for (0..100) |_| if (try client.poll(50)) |completion| return completion;
    return error.NoCompletion;
}

test "CON responses use caller storage, retain metadata, and perform no allocation" {
    const port: u16 = 29730;
    var server = try startTestServer(port, metadataEchoHandler);
    defer server.deinit();
    var runner = ServerRunner{ .server = &server };
    const thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(thread);
    var client = try Client.init(testing.allocator, .{ .port = port, .max_in_flight = 4 });
    defer client.deinit();
    const allocator = client.allocator;
    defer client.allocator = allocator;
    client.allocator = testing.failing_allocator;
    var storage: [4]ResponseStorage(0) = .{ .{}, .{}, .{}, .{} };
    const first = try client.call(storage[0].buffers(), .get, &.{}, "retained");
    const one = try client.submit(storage[1].buffers(), .get, &.{}, "one");
    const two = try client.submit(storage[2].buffers(), .get, &.{}, "two");
    // Synchronous calls must not silently discard someone else's completion.
    try testing.expectError(error.RequestsInFlight, client.call(storage[3].buffers(), .get, &.{}, "bad"));
    var results: [2]Result = undefined;
    for (0..2) |_| {
        const completion = try awaitTestCompletion(&client);
        const i: usize = if (completion.handle == one) 0 else 1;
        try testing.expect(completion.handle == one or completion.handle == two);
        results[i] = try completion.result;
    }
    _ = try client.call(storage[3].buffers(), .get, &.{}, "overwrite-receive-buffer");
    try testing.expectEqualSlices(u8, "retained", first.payload);
    try testing.expectEqualSlices(u8, "one", results[0].payload);
    try testing.expectEqualSlices(u8, "two", results[1].payload);
    for ([_]Result{ first, results[0], results[1] }) |result| {
        try testing.expectEqualSlices(u8, "tag-data", result.packet.find_option(.etag).?.value);
        try testing.expectEqualSlices(u8, result.payload, result.packet.payload);
        try testing.expectEqual(@as(usize, 2), result.packet.token.len);
    }
}

test "CON packet and option capacity failures are correlated and permit retry" {
    const port: u16 = 29731;
    var server = try startTestServer(port, metadataEchoHandler);
    defer server.deinit();
    var runner = ServerRunner{ .server = &server };
    const thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(thread);
    var client = try Client.init(testing.allocator, .{ .port = port });
    defer client.deinit();
    const allocator = client.allocator;
    defer client.allocator = allocator;
    client.allocator = testing.failing_allocator;
    const handle = try client.submit(.{ .packet = &.{}, .options = &.{} }, .get, &.{}, "payload");
    const completion = try awaitTestCompletion(&client);
    try testing.expectEqual(handle, completion.handle);
    try testing.expectError(error.ResponseBufferTooSmall, completion.result);
    try testing.expectEqual(@as(u16, 0), client.count_active);
    var storage: ResponseStorage(0) = .{};
    const retry = try client.call(storage.buffers(), .get, &.{}, "retry");
    try testing.expectEqualSlices(u8, "retry", retry.payload);
    const h2 = try client.submit(.{ .packet = &storage.packet, .options = &.{} }, .get, &.{}, "options");
    const c2 = try awaitTestCompletion(&client);
    try testing.expectEqual(h2, c2.handle);
    try testing.expectError(error.ResponseOptionsTooSmall, c2.result);
    try testing.expectEqual(@as(u16, 0), client.count_active);
    _ = try client.call(storage.buffers(), .get, &.{}, "retry-again");
}

const bounded_test_body = blk: {
    @setEvalBranchQuota(4000);
    var bytes: [3000]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @intCast(i % 251);
    break :blk bytes;
};

fn boundedBodyHandler(_: coap_handler.Request) ?coap_handler.Response {
    return .{ .payload = &bounded_test_body };
}

test "plain and DTLS Block1/Block2 responses are bounded and allocation-free" {
    const credentials: dtls.types.Psk = .{ .identity = "bounded", .key = "0123456789abcdef" };
    for ([_]bool{ false, true }, 0..) |encrypted, i| {
        const port: u16 = @intCast(29732 + i);
        var server = try coap_server.init(testing.allocator, .{
            .port = port,
            .buffer_count = 16,
            .buffer_size = 1280,
            .exchange_count = 16,
            .rate_limit_ip_count = 0,
            .max_block_transfers = 8,
            .max_block_payload = 8192,
            .psk = if (encrypted) credentials else null,
        }, boundedBodyHandler);
        defer server.deinit();
        try server.listen();
        var runner = ServerRunner{ .server = &server };
        const thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
        defer runner.stop(thread);
        var client = try Client.init(testing.allocator, .{ .port = port, .psk = if (encrypted) credentials else null });
        defer client.deinit();
        if (encrypted) try client.handshake();
        const allocator = client.allocator;
        defer client.allocator = allocator;
        client.allocator = testing.failing_allocator;
        var small: ResponseStorage(3000) = .{};
        for ([_]usize{ 0, 1800, 2999 }) |capacity| {
            var buffers = small.buffers();
            buffers.payload = buffers.payload[0..capacity];
            const handle = try client.submit(buffers, .get, &.{}, &.{});
            const failed = try awaitTestCompletion(&client);
            try testing.expectEqual(handle, failed.handle);
            try testing.expectError(error.ResponsePayloadTooSmall, failed.result);
            try testing.expectEqual(@as(u16, 0), client.count_active);
        }
        var full: ResponseStorage(3000) = .{};
        const result = try client.get(full.buffers(), "/large");
        try testing.expectEqualSlices(u8, &bounded_test_body, result.payload);
        try testing.expectEqual(@as(u32, 3000), result.packet.find_option(.size2).?.as_uint().?);
        var upload_storage: ResponseStorage(3000) = .{};
        const uploaded = try client.upload(upload_storage.buffers(), .put, &.{
            .{ .kind = .uri_path, .value = "large" },
            .{ .kind = .size1, .value = &.{ 8, 0 } },
        }, &([_]u8{7} ** 2048));
        try testing.expectEqualSlices(u8, &bounded_test_body, uploaded.payload);
        // The second reassembly must not overwrite the first result or metadata.
        try testing.expectEqualSlices(u8, &bounded_test_body, result.packet.payload);
        try testing.expectEqual(@as(u32, 3000), result.packet.find_option(.size2).?.as_uint().?);
    }
}

test "cancel, timeout, and serialization failure release caller buffer borrows" {
    const port: u16 = 29734;
    var server = try startTestServer(port, nullHandler);
    defer server.deinit();
    var client = try Client.init(testing.allocator, .{ .port = port, .max_in_flight = 1 });
    defer client.deinit();
    const allocator = client.allocator;
    defer client.allocator = allocator;
    client.allocator = testing.failing_allocator;
    var storage: ResponseStorage(0) = .{};
    const h = try client.submit(storage.buffers(), .get, &.{}, "cancel");
    client.cancel(h);
    try testing.expectEqual(@as(u16, 0), client.count_active);
    const again = try client.submit(storage.buffers(), .get, &.{}, "timeout");
    client.slots[again].retransmit_count = constants.max_retransmit;
    client.slots[again].next_retransmit_ns = nanoTimestamp() - 1;
    const completion = (try client.poll(0)).?;
    try testing.expectEqual(again, completion.handle);
    try testing.expectError(error.Timeout, completion.result);
    try testing.expectEqual(@as(u16, 0), client.count_active);
    try testing.expectError(error.BufferTooSmall, client.submit(storage.buffers(), .get, &.{}, &([_]u8{0} ** 2000)));
    try testing.expectEqual(@as(u16, 0), client.count_active);
    const valid = try client.submit(storage.buffers(), .get, &.{}, "reused");
    client.cancel(valid);
    var block_buf: [3]u8 = undefined;
    const invalid = (coapz.BlockValue{ .num = 0, .more = false, .szx = 7 }).option(.block2, &block_buf);
    try testing.expectError(error.InvalidBlock2, client.submit(storage.buffers(), .get, &.{invalid}, &.{}));
    try testing.expectEqual(@as(u16, 0), client.count_active);
}

fn injectTestBlock(client: *Client, handle: RequestHandle, num: u32, szx: u3, more: bool, bytes: []const u8, tag: []const u8, kind: coapz.MessageKind) !?Completion {
    const slot = &client.slots[handle];
    var block_buf: [3]u8 = undefined;
    const block = (coapz.BlockValue{ .num = num, .szx = szx, .more = more }).option(.block2, &block_buf);
    const packet: coapz.Packet = .{ .kind = kind, .code = .content, .msg_id = slot.msg_id, .token = slot.token[0..slot.token_len], .payload = bytes, .data_buf = &.{}, .options = &.{ .{ .kind = .etag, .value = tag }, block } };
    var wire: [1280]u8 = undefined;
    return client.processResponse(handle, try packet.writeBuf(&wire));
}

test "Block2 handles reduced SZX, duplicate separate blocks, and retained option values" {
    const port: u16 = 29735;
    var server = try startTestServer(port, nullHandler);
    defer server.deinit();
    var client = try Client.init(testing.allocator, .{ .port = port });
    defer client.deinit();
    const allocator = client.allocator;
    defer client.allocator = allocator;
    client.allocator = testing.failing_allocator;
    var storage: ResponseStorage(55) = .{};
    const h = try client.submit(storage.buffers(), .get, &.{
        .{ .kind = .uri_path, .value = "a" },
        .{ .kind = .uri_path, .value = "b" },
        .{ .kind = .size1, .value = &.{55} },
    }, &.{});
    const token = client.slots[h].token;
    try testing.expect((try injectTestBlock(&client, h, 0, 1, true, &([_]u8{1} ** 32), "tag", .acknowledgement)) == null);
    try testing.expectEqualSlices(u8, token[0..client.config.token_len], client.slots[h].token[0..client.config.token_len]);
    var decoded_options: [17]coapz.Option = undefined;
    const pending = &client.slots[h];
    const continuation = try packet_view.read(client.send_buf[pending.send_offset..][0..pending.send_len], &decoded_options);
    try testing.expectEqualSlices(u8, "a", continuation.options[0].value);
    try testing.expectEqualSlices(u8, "b", continuation.options[1].value);
    try testing.expectEqual(.block2, continuation.options[2].kind);
    try testing.expectEqual(.size1, continuation.options[3].kind);
    // Retransmitted separate block: ACK it without duplicate assembly.
    try testing.expect((try injectTestBlock(&client, h, 0, 1, true, &([_]u8{1} ** 32), "tag", .confirmable)) == null);
    try testing.expectEqual(@as(usize, 32), client.slots[h].block2_length);
    try testing.expect((try injectTestBlock(&client, h, 2, 0, true, &([_]u8{2} ** 16), "tag", .acknowledgement)) == null);
    const completion = (try injectTestBlock(&client, h, 3, 0, false, "1234567", "tag", .acknowledgement)).?;
    try testing.expectEqual(h, completion.handle);
    const result = try completion.result;
    try testing.expectEqualSlices(u8, &([_]u8{1} ** 32 ++ [_]u8{2} ** 16 ++ "1234567".*), result.payload);
    const next = try client.submit(.{ .packet = &.{}, .options = &.{} }, .get, &.{}, &.{});
    client.cancel(next);
    try testing.expectEqualSlices(u8, "tag", result.packet.find_option(.etag).?.value);
    try testing.expectEqualSlices(u8, result.payload, result.packet.payload);
}

test "Block2 ETag mismatch and invalid offsets complete with correlated errors" {
    const port: u16 = 29736;
    var server = try startTestServer(port, nullHandler);
    defer server.deinit();
    var client = try Client.init(testing.allocator, .{ .port = port });
    defer client.deinit();
    var storage: ResponseStorage(64) = .{};
    const h = try client.submit(storage.buffers(), .get, &.{}, &.{});
    try testing.expect((try injectTestBlock(&client, h, 0, 0, true, &([_]u8{1} ** 16), "a", .acknowledgement)) == null);
    const mismatch = (try injectTestBlock(&client, h, 1, 0, false, "end", "b", .acknowledgement)).?;
    try testing.expectEqual(h, mismatch.handle);
    try testing.expectError(error.EtagMismatch, mismatch.result);
    try testing.expectEqual(@as(u16, 0), client.count_active);
    const h2 = try client.submit(storage.buffers(), .get, &.{}, &.{});
    const invalid = (try injectTestBlock(&client, h2, 1, 0, true, &([_]u8{1} ** 16), "a", .acknowledgement)).?;
    try testing.expectEqual(h2, invalid.handle);
    try testing.expectError(error.InvalidBlock2, invalid.result);
    try testing.expectEqual(@as(u16, 0), client.count_active);
    var block_buf: [3]u8 = undefined;
    const last = (coapz.BlockValue{ .num = 0xfffff, .szx = 0, .more = false }).option(.block2, &block_buf);
    const h3 = try client.submit(storage.buffers(), .get, &.{last}, &.{});
    const exhausted = (try injectTestBlock(&client, h3, 0xfffff, 0, true, &([_]u8{1} ** 16), "a", .acknowledgement)).?;
    try testing.expectEqual(h3, exhausted.handle);
    try testing.expectError(error.InvalidBlock2, exhausted.result);
    try testing.expectEqual(@as(u16, 0), client.count_active);
}

fn sendTestReply(server: *coap_server, client: *Client, kind: coapz.MessageKind, code: coapz.Code, mid: u16, token: []const u8, payload: []const u8) !void {
    var address: posix.SocketAddress = undefined;
    var len: linux.socklen_t = @sizeOf(posix.SocketAddress);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getsockname(client.fd, &address.any, &len)));
    var wire: [1280]u8 = undefined;
    const packet: coapz.Packet = .{ .kind = kind, .code = code, .msg_id = mid, .token = token, .options = &.{}, .payload = payload, .data_buf = &.{} };
    _ = try posix.sendto(server.io.fd_socket.?, try packet.writeBuf(&wire), 0, try address.address());
}

test "poll matches empty ACK/RST by MID and bounds ACKed request lifetime" {
    const port: u16 = 29737;
    var server = try startTestServer(port, nullHandler);
    defer server.deinit();
    var client = try Client.init(testing.allocator, .{ .port = port });
    defer client.deinit();
    const allocator = client.allocator;
    defer client.allocator = allocator;
    client.allocator = testing.failing_allocator;
    var storage: ResponseStorage(0) = .{};
    const h = try client.submit(storage.buffers(), .get, &.{}, "ack");
    const mid = client.slots[h].msg_id;
    try sendTestReply(&server, &client, .acknowledgement, .empty, mid +% 1, &.{}, &.{});
    try testing.expect((try client.poll(100)) == null);
    try testing.expect(!client.slots[h].acknowledged);
    try sendTestReply(&server, &client, .acknowledgement, .empty, mid, &.{}, &.{});
    try testing.expect((try client.poll(100)) == null);
    try testing.expect(client.slots[h].acknowledged);
    const deadline = client.slots[h].next_retransmit_ns;
    try sendTestReply(&server, &client, .acknowledgement, .empty, mid, &.{}, &.{});
    try testing.expect((try client.poll(100)) == null);
    try testing.expectEqual(deadline, client.slots[h].next_retransmit_ns);
    client.slots[h].next_retransmit_ns = nanoTimestamp() - 1;
    const timeout = (try client.poll(0)).?;
    try testing.expectEqual(h, timeout.handle);
    try testing.expectError(error.Timeout, timeout.result);
    const h2 = try client.submit(storage.buffers(), .get, &.{}, "reset");
    const mid2 = client.slots[h2].msg_id;
    try sendTestReply(&server, &client, .reset, .empty, mid2 +% 1, &.{}, &.{});
    try testing.expect((try client.poll(100)) == null);
    try sendTestReply(&server, &client, .reset, .empty, mid2, &.{}, &.{});
    const reset = (try client.poll(100)).?;
    try testing.expectEqual(h2, reset.handle);
    try testing.expectError(error.Reset, reset.result);
    const h3 = try client.submit(storage.buffers(), .get, &.{}, "separate");
    const slot = &client.slots[h3];
    try sendTestReply(&server, &client, .acknowledgement, .empty, slot.msg_id, &.{}, &.{});
    try testing.expect((try client.poll(100)) == null);
    try sendTestReply(&server, &client, .confirmable, .content, slot.msg_id +% 1, slot.token[0..slot.token_len], "separate");
    const completion = (try client.poll(100)).?;
    try testing.expectEqual(h3, completion.handle);
    try testing.expectEqualSlices(u8, "separate", (try completion.result).payload);
    try testing.expectEqual(@as(u16, 0), client.count_active);
}

test "caller-owned response remains valid after client destruction" {
    const port: u16 = 29738;
    var server = try startTestServer(port, nullHandler);
    defer server.deinit();
    var client = try Client.init(testing.allocator, .{ .port = port });
    var alive = true;
    defer if (alive) client.deinit();
    var storage: ResponseStorage(0) = .{};
    const h = try client.submit(storage.buffers(), .get, &.{}, &.{});
    const completion = (try injectTestBlock(&client, h, 0, 0, false, "owned-by-caller", "tag", .acknowledgement)).?;
    const result = try completion.result;
    client.deinit();
    alive = false;
    try testing.expectEqualSlices(u8, "owned-by-caller", result.payload);
    try testing.expectEqualSlices(u8, "tag", result.packet.find_option(.etag).?.value);
    try testing.expectEqual(@as(usize, 2), result.packet.token.len);
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

    var storage: ResponseStorage(0) = .{};
    const result = try client.call(storage.buffers(), .get, &.{}, "hello-con");

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

test "uri.fromPath splits path" {
    var buf: [uri.max_options]coapz.Option = undefined;
    const opts = uri.fromPath("/hello/world", &buf);
    try testing.expectEqual(@as(usize, 2), opts.len);
    try testing.expectEqualSlices(u8, "hello", opts[0].value);
    try testing.expectEqualSlices(u8, "world", opts[1].value);
}

test "uri.fromUri with query" {
    var buf: [uri.max_options]coapz.Option = undefined;
    const opts = uri.fromUri("/a/b?x=1", &buf);
    try testing.expectEqual(@as(usize, 3), opts.len);
    try testing.expectEqual(coapz.OptionKind.uri_path, opts[0].kind);
    try testing.expectEqual(coapz.OptionKind.uri_query, opts[2].kind);
}

test "get convenience calls call with path options" {
    const port: u16 = 29704;
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

    var storage: ResponseStorage(0) = .{};
    const result = try client.get(storage.buffers(), "/hello");
    try testing.expectEqual(coapz.Code.content, result.code);
}

test "submit returns handle without blocking" {
    const port: u16 = 29710;
    var server = try startTestServer(port, echoHandler);
    defer server.deinit();

    var client = try Client.init(testing.allocator, .{
        .port = port,
        .max_in_flight = 4,
    });
    defer client.deinit();

    var storage: ResponseStorage(0) = .{};
    const start = nanoTimestamp();
    const handle = try client.submit(storage.buffers(), .get, &.{}, "hello");
    const elapsed_us = @divTrunc(nanoTimestamp() - start, std.time.ns_per_us);

    try testing.expect(elapsed_us < 5000);
    try testing.expect(handle < 4);
}

test "submit and poll round-trip" {
    const port: u16 = 29711;
    var server = try startTestServer(port, echoHandler);
    defer server.deinit();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .port = port,
        .max_in_flight = 8,
    });
    defer client.deinit();

    var storage: ResponseStorage(0) = .{};
    const h = try client.submit(storage.buffers(), .get, &.{}, "async-hello");

    var completion: ?Completion = null;
    for (0..100) |_| {
        completion = try client.poll(50);
        if (completion != null) break;
    }

    const c = completion orelse return error.NoCompletion;
    const result = try c.result;
    try testing.expectEqual(h, c.handle);
    try testing.expectEqual(.content, result.code);
    try testing.expectEqualSlices(u8, "async-hello", result.payload);
}

test "multiple concurrent submits" {
    const port: u16 = 29712;
    var server = try startTestServer(port, echoHandler);
    defer server.deinit();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .port = port,
        .max_in_flight = 8,
    });
    defer client.deinit();

    var storage: [4]ResponseStorage(0) = .{ .{}, .{}, .{}, .{} };
    // Confirm peer first (NSTART enforcement).
    _ = try client.call(storage[0].buffers(), .get, &.{}, "warmup");
    _ = try client.submit(storage[0].buffers(), .get, &.{}, "req-0");
    _ = try client.submit(storage[1].buffers(), .get, &.{}, "req-1");
    _ = try client.submit(storage[2].buffers(), .get, &.{}, "req-2");
    _ = try client.submit(storage[3].buffers(), .get, &.{}, "req-3");

    var completed: u8 = 0;
    for (0..200) |_| {
        const c = try client.poll(50) orelse continue;
        const result = try c.result;
        try testing.expectEqual(.content, result.code);
        completed += 1;
        if (completed == 4) break;
    }
    try testing.expectEqual(@as(u8, 4), completed);
}

test "NSTART: second submit rejected before first response" {
    const port: u16 = 29720;
    var server = try startTestServer(port, echoHandler);
    defer server.deinit();

    var client = try Client.init(testing.allocator, .{
        .port = port,
        .max_in_flight = 8,
    });
    defer client.deinit();

    var storage: [2]ResponseStorage(0) = .{ .{}, .{} };
    // First submit should succeed (count_active=0 < nstart=1).
    _ = try client.submit(storage[0].buffers(), .get, &.{}, "first");

    // Second submit should fail — peer not confirmed, count_active=1 >= nstart.
    try testing.expectError(
        error.NstartExceeded,
        client.submit(storage[1].buffers(), .get, &.{}, "second"),
    );
}

test "NSTART: submit allowed after peer confirmed via poll" {
    const port: u16 = 29721;
    var server = try startTestServer(port, echoHandler);
    defer server.deinit();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .port = port,
        .max_in_flight = 8,
    });
    defer client.deinit();

    var storage: [2]ResponseStorage(0) = .{ .{}, .{} };
    // First submit — should work.
    _ = try client.submit(storage[0].buffers(), .get, &.{}, "first");

    // Poll until first response arrives — confirms peer.
    var confirmed = false;
    for (0..100) |_| {
        const c = try client.poll(50) orelse continue;
        _ = try c.result;
        confirmed = true;
        break;
    }
    try testing.expect(confirmed);
    try testing.expect(client.peer_confirmed);

    // Now submit should succeed — peer is confirmed.
    _ = try client.submit(storage[0].buffers(), .get, &.{}, "second");
    _ = try client.submit(storage[1].buffers(), .get, &.{}, "third");
}

test "NSTART: call confirms peer, subsequent submits work" {
    const port: u16 = 29722;
    var server = try startTestServer(port, echoHandler);
    defer server.deinit();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .port = port,
        .max_in_flight = 8,
    });
    defer client.deinit();

    try testing.expect(!client.peer_confirmed);

    // call() does submit+poll internally — should confirm peer.
    var storage: [4]ResponseStorage(0) = .{ .{}, .{}, .{}, .{} };
    _ = try client.call(storage[0].buffers(), .get, &.{}, "hello");

    try testing.expect(client.peer_confirmed);

    // Multiple concurrent submits now work.
    _ = try client.submit(storage[1].buffers(), .get, &.{}, "a");
    _ = try client.submit(storage[2].buffers(), .get, &.{}, "b");
    _ = try client.submit(storage[3].buffers(), .get, &.{}, "c");
}

test "checkBlock2Etag captures and compares" {
    var slot: InFlightSlot = .{
        .state = .free,
        .token = undefined,
        .token_len = 0,
        .msg_id = 0,
        .retransmit_count = 0,
        .next_retransmit_ns = 0,
        .timeout_ns = 0,
        .send_offset = 0,
        .send_len = 0,
        .next_free = 0xFFFF,
        .block2_length = 0,
        .doing_block2 = false,
        .block2_etag = undefined,
        .block2_etag_len = 0,
        .original_code = .empty,
        .original_options_buf = undefined,
        .original_options_len = 0,
        .original_handle = 0,
    };

    // Build a fake packet with ETag option.
    const etag_a = [_]u8{ 0xAA, 0xBB };
    const etag_b = [_]u8{ 0xCC, 0xDD };
    var opt_a = [1]coapz.Option{.{ .kind = .etag, .value = &etag_a }};
    var opt_b = [1]coapz.Option{.{ .kind = .etag, .value = &etag_b }};
    const pkt_a = coapz.Packet{
        .kind = .acknowledgement,
        .code = .content,
        .msg_id = 0,
        .token = &.{},
        .options = &opt_a,
        .payload = &.{},
        .data_buf = &.{},
    };
    const pkt_b = coapz.Packet{
        .kind = .acknowledgement,
        .code = .content,
        .msg_id = 0,
        .token = &.{},
        .options = &opt_b,
        .payload = &.{},
        .data_buf = &.{},
    };

    // First block — captures ETag.
    try testing.expect(checkBlock2Etag(&slot, pkt_a));
    try testing.expectEqual(@as(u4, 2), slot.block2_etag_len);
    try testing.expectEqualSlices(u8, &etag_a, slot.block2_etag[0..2]);

    // Subsequent block — same ETag passes.
    slot.doing_block2 = true;
    try testing.expect(checkBlock2Etag(&slot, pkt_a));

    // Different ETag fails.
    try testing.expect(!checkBlock2Etag(&slot, pkt_b));
}
