/// CoAP server built on io_uring.
///
/// All memory is pre-allocated at init. Handlers receive a per-request
/// arena allocator that resets after each batch of completions.
/// CON messages are deduplicated and their responses are cached for
/// retransmission per RFC 7252 §4.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const coapz = @import("coapz");
const Io = @import("Io.zig");
const Exchange = @import("exchange.zig");
const RateLimiter = @import("rate_limiter.zig");
const handler = @import("handler.zig");
const constants = @import("constants.zig");
const log = std.log.scoped(.coapd);

const Cqe = linux.io_uring_cqe;

const Server = @This();

pub const LoadLevel = enum { normal, throttled, shedding };

pub const Config = struct {
    port: u16 = constants.port_default,
    buffer_count: u16 = constants.buffer_count_default,
    buffer_size: u32 = constants.buffer_size_default,
    /// Maximum concurrent CON exchanges for duplicate detection.
    exchange_count: u16 = 256,
    /// Link-format payload for GET /.well-known/core (RFC 6690).
    /// If null, requests pass through to the handler.
    well_known_core: ?[]const u8 = null,
    /// Number of server threads. Each gets its own socket/ring/exchange pool.
    /// Kernel distributes packets via SO_REUSEPORT.
    thread_count: u16 = 1,
    /// IPv4 address to bind. Use "127.0.0.1" for loopback only.
    bind_address: []const u8 = "0.0.0.0",
    /// Maximum arena size in bytes. Arena is trimmed after each tick.
    max_arena_size: usize = 256 * 1024,
    /// Per-IP rate limit: max tracked IPs. 0 = disabled.
    rate_limit_ip_count: u16 = 1024,
    /// Per-IP rate limit: tokens refilled per second.
    rate_limit_tokens_per_sec: u16 = 100,
    /// Per-IP rate limit: maximum burst (bucket capacity).
    rate_limit_burst: u16 = 200,
    /// Load shedding: enter throttled when any pool reaches this %.
    load_shed_throttle_pct: u8 = 75,
    /// Load shedding: enter shedding when any pool reaches this %.
    load_shed_critical_pct: u8 = 90,
    /// Load shedding: recover to normal when both pools drop below this %.
    load_shed_recover_pct: u8 = 50,
};

allocator: std.mem.Allocator,
io: Io,
handler_fn: handler.HandlerFn,
handler_context: ?*anyopaque,
arena: std.heap.ArenaAllocator,
config: Config,
exchanges: Exchange,
running: std.atomic.Value(bool),

// Pre-allocated per-CQE response state.
addrs_response: []linux.sockaddr,
msgs_response: []linux.msghdr_const,
iovs_response: []posix.iovec,
buffer_response: []u8,

/// Pre-allocated emergency ACK buffers for OOM conditions.
/// Each slot holds a 4-byte empty ACK (one per batch slot).
emergency_ack: []u8,

// Recv state.
addr_recv: linux.sockaddr,
msg_recv: linux.msghdr,

// Eviction timer.
last_eviction_ns: i128,
tick_count: u64,

// Server-side message ID counter for NON responses.
next_msg_id: u16,

// Arena management.
force_free_all: bool,

// Load shedding and rate limiting.
load_level: LoadLevel,
buffers_outstanding: u16,
rate_limiter: ?RateLimiter,
tick_now_ns: i128,

/// Pre-allocated RST buffers for rate-limited/shed CON packets.
rate_limit_rst: []u8,

/// Initialize with a simple handler (no context). Backward compatible.
pub fn init(
    allocator: std.mem.Allocator,
    config: Config,
    handler_fn: handler.SimpleHandlerFn,
) !Server {
    return init_raw(allocator, config, handler.wrapSimple, @ptrCast(@constCast(handler_fn)));
}

/// Initialize with a typed context handler.
///
/// The handler receives a typed pointer and a request:
///   fn handle(ctx: *MyState, request: Request) ?Response
pub fn initContext(
    allocator: std.mem.Allocator,
    config: Config,
    comptime handler_fn: anytype,
    context: anytype,
) !Server {
    const Context = @TypeOf(context);
    const gen = struct {
        fn call(ctx: ?*anyopaque, request: handler.Request) ?handler.Response {
            const typed: Context = @ptrCast(@alignCast(ctx.?));
            return handler_fn(typed, request);
        }
    };
    return init_raw(allocator, config, gen.call, @ptrCast(@constCast(context)));
}

fn init_raw(
    allocator: std.mem.Allocator,
    config: Config,
    handler_fn: handler.HandlerFn,
    handler_context: ?*anyopaque,
) !Server {
    if (config.buffer_count == 0 or
        config.buffer_size < 64 or
        config.port == 0) return error.InvalidConfig;

    var io = try Io.init(
        allocator,
        config.buffer_count,
        config.buffer_size,
    );
    errdefer io.deinit(allocator);

    var exchanges = try Exchange.init(allocator, .{
        .exchange_count = config.exchange_count,
        .response_size_max = @intCast(config.buffer_size),
    });
    errdefer exchanges.deinit(allocator);

    const batch: usize = @min(
        constants.completion_batch_max,
        config.buffer_count,
    );

    const addrs_response = try allocator.alloc(
        linux.sockaddr,
        batch,
    );
    errdefer allocator.free(addrs_response);

    const msgs_response = try allocator.alloc(
        linux.msghdr_const,
        batch,
    );
    errdefer allocator.free(msgs_response);

    const iovs_response = try allocator.alloc(posix.iovec, batch);
    errdefer allocator.free(iovs_response);

    const buffer_response = try allocator.alloc(
        u8,
        batch * config.buffer_size,
    );
    errdefer allocator.free(buffer_response);

    const emergency_ack = try allocator.alloc(u8, batch * 4);
    errdefer allocator.free(emergency_ack);

    const rate_limit_rst = try allocator.alloc(u8, batch * 4);
    errdefer allocator.free(rate_limit_rst);

    var rate_limiter: ?RateLimiter = null;
    if (config.rate_limit_ip_count > 0) {
        rate_limiter = try RateLimiter.init(allocator, .{
            .ip_count = config.rate_limit_ip_count,
            .tokens_per_sec = config.rate_limit_tokens_per_sec,
            .burst = config.rate_limit_burst,
        });
    }
    errdefer if (rate_limiter) |*rl| rl.deinit(allocator);

    return .{
        .allocator = allocator,
        .io = io,
        .handler_fn = handler_fn,
        .handler_context = handler_context,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .config = config,
        .exchanges = exchanges,
        .running = std.atomic.Value(bool).init(true),
        .addrs_response = addrs_response,
        .msgs_response = msgs_response,
        .iovs_response = iovs_response,
        .buffer_response = buffer_response,
        .emergency_ack = emergency_ack,
        .addr_recv = std.mem.zeroes(linux.sockaddr),
        .msg_recv = std.mem.zeroes(linux.msghdr),
        .last_eviction_ns = 0,
        .tick_count = 0,
        .next_msg_id = std.crypto.random.int(u16),
        .force_free_all = false,
        .load_level = .normal,
        .buffers_outstanding = 0,
        .rate_limiter = rate_limiter,
        .tick_now_ns = 0,
        .rate_limit_rst = rate_limit_rst,
    };
}

pub fn deinit(server: *Server) void {
    server.arena.deinit();
    server.exchanges.deinit(server.allocator);
    server.io.deinit(server.allocator);
    server.allocator.free(server.addrs_response);
    server.allocator.free(server.msgs_response);
    server.allocator.free(server.iovs_response);
    server.allocator.free(server.buffer_response);
    server.allocator.free(server.emergency_ack);
    server.allocator.free(server.rate_limit_rst);
    if (server.rate_limiter) |*rl| rl.deinit(server.allocator);
}

/// Bind the socket, register buffers, and arm the multishot recv.
/// After this returns the server is ready to accept packets.
pub fn listen(server: *Server) !void {
    try server.io.setup(server.config.port, server.config.bind_address);

    server.msg_recv.name = &server.addr_recv;
    server.msg_recv.namelen = @sizeOf(linux.sockaddr);
    server.msg_recv.controllen = 0;

    try server.io.recv_multishot(&server.msg_recv);
    _ = try server.io.submit();
}

/// Signal the server and all worker threads to stop after the current tick.
pub fn stop(server: *Server) void {
    server.running.store(false, .release);
}

pub fn run(server: *Server) !void {
    try server.listen();

    const extra = server.config.thread_count -| 1;
    const threads = try server.allocator.alloc(std.Thread, extra);
    defer server.allocator.free(threads);

    for (threads) |*t| {
        t.* = try std.Thread.spawn(.{}, run_worker, .{
            server.allocator,
            server.config,
            server.handler_fn,
            server.handler_context,
            &server.running,
        });
    }

    log.info("coapd listening on port {d} ({d} thread{s})", .{
        server.config.port,
        server.config.thread_count,
        if (server.config.thread_count > 1) "s" else "",
    });

    server.tick_loop() catch |err| {
        log.err("main thread exiting: {}", .{err});
        return err;
    };

    for (threads) |t| t.join();
}

fn run_worker(
    allocator: std.mem.Allocator,
    config: Config,
    handler_fn: handler.HandlerFn,
    handler_context: ?*anyopaque,
    running: *std.atomic.Value(bool),
) void {
    var worker = init_raw(allocator, config, handler_fn, handler_context) catch |err| {
        log.err("worker init failed: {}", .{err});
        return;
    };
    defer worker.deinit();
    worker.listen() catch |err| {
        log.err("worker listen failed: {}", .{err});
        return;
    };
    var consecutive_failures: u32 = 0;
    while (running.load(.acquire)) {
        worker.tick() catch |err| {
            if (is_transient(err)) {
                consecutive_failures += 1;
                log.warn("worker tick transient error ({d}/3): {}", .{
                    consecutive_failures,
                    err,
                });
                if (consecutive_failures >= 3) {
                    log.err("worker exiting: {}", .{err});
                    return;
                }
                continue;
            }
            log.err("worker exiting: {}", .{err});
            return;
        };
        consecutive_failures = 0;
    }
}

fn is_transient(err: anyerror) bool {
    return switch (err) {
        error.SignalInterrupt,
        error.SystemResources,
        error.CompletionQueueOvercommitted,
        error.SubmissionQueueFull,
        => true,
        else => false,
    };
}

fn tick_loop(server: *Server) !void {
    var consecutive_failures: u32 = 0;
    while (server.running.load(.acquire)) {
        server.tick() catch |err| {
            if (is_transient(err)) {
                consecutive_failures += 1;
                log.warn("tick transient error ({d}/3): {}", .{
                    consecutive_failures,
                    err,
                });
                if (consecutive_failures >= 3) return err;
                continue;
            }
            return err;
        };
        consecutive_failures = 0;
    }
}

pub fn tick(server: *Server) !void {
    const batch_max = constants.completion_batch_max;
    var cqes: [batch_max]Cqe = std.mem.zeroes([batch_max]Cqe);

    server.tick_now_ns = std.time.nanoTimestamp();

    const count = try server.io.wait_cqes(cqes[0..], 1);
    var recv_failed = false;
    var recv_fail_count: u32 = 0;
    var processed: u32 = 0;

    for (cqes[0..count], 0..) |cqe, index| {
        if (Io.is_recv(&cqe) and !Io.is_success(&cqe)) {
            recv_failed = true;
            recv_fail_count += 1;
            continue;
        }
        if (!Io.is_success(&cqe)) {
            continue;
        }
        if (!Io.is_recv(&cqe)) {
            continue;
        }

        server.handle_recv(&cqe, index) catch |err| {
            switch (err) {
                error.PayloadOutOfBounds => log.debug("handle_recv: {}", .{err}),
                else => log.err("handle_recv: {}", .{err}),
            }
        };

        // Flush SQEs periodically to return buffers to the kernel
        // before the provided buffer pool is exhausted.
        processed += 1;
        if (processed % 64 == 0) {
            _ = server.io.submit() catch {};
        }
    }

    if (recv_failed) {
        log.warn("multishot recv failed ({d} in batch), re-arming", .{recv_fail_count});
        try server.io.recv_multishot(&server.msg_recv);
    }

    // Periodic exchange eviction (~every 10 seconds).
    const eviction_interval_ns: i128 = 10 * std.time.ns_per_s;
    if (server.tick_now_ns - server.last_eviction_ns > eviction_interval_ns) {
        const evicted = server.exchanges.evict_expired(server.tick_now_ns);
        if (evicted > 0) {
            log.debug("evicted {d} expired exchanges", .{evicted});
        }
        server.last_eviction_ns = server.tick_now_ns;
    }

    // Compute load level based on buffer/exchange pool utilization.
    server.update_load_level();

    _ = try server.io.submit();

    server.tick_count += 1;

    // Adaptive arena reset: free_all after busy ticks or periodically,
    // otherwise retain with size limit to cap memory growth.
    const busy_threshold: u32 = @min(constants.completion_batch_max, server.config.buffer_count) / 2;
    if (server.force_free_all or server.tick_count % 100 == 0) {
        _ = server.arena.reset(.free_all);
        server.force_free_all = false;
    } else {
        _ = server.arena.reset(.{ .retain_with_limit = server.config.max_arena_size });
    }
    if (processed > busy_threshold) {
        server.force_free_all = true;
    }
}

fn handle_recv(
    server: *Server,
    cqe: *const Cqe,
    index: usize,
) !void {
    const arena = server.arena.allocator();

    const recv = try server.io.decode_recv(cqe);
    server.buffers_outstanding +|= 1;

    // Save raw header bytes before buffer release for emergency ACK.
    var raw_header: [4]u8 = .{ 0, 0, 0, 0 };
    if (recv.payload.len >= 4) {
        @memcpy(&raw_header, recv.payload[0..4]);
    }

    // Load shedding: drop new packets when critically loaded.
    if (server.load_level == .shedding) {
        // Always serve cached CON retransmits.
        if (recv.payload.len >= 4) {
            const msg_id = std.mem.readInt(u16, raw_header[2..4], .big);
            const key = Exchange.peer_key(recv.peer_address, msg_id);
            if (server.exchanges.find(key)) |slot_idx| {
                const cached = server.exchanges.cached_response(slot_idx);
                release_buffer_robust(&server.io, recv.buffer_id);
                server.buffers_outstanding -|= 1;
                server.send_data(cached, recv.peer_address, index) catch {};
                return;
            }
        }
        // CON: send RST. NON: drop silently.
        const is_con_raw = recv.payload.len >= 1 and ((recv.payload[0] >> 4) & 0x03) == 0;
        release_buffer_robust(&server.io, recv.buffer_id);
        server.buffers_outstanding -|= 1;
        if (is_con_raw) server.send_rst(&raw_header, recv.peer_address, index);
        return;
    }

    // Rate limiting in throttled mode.
    if (server.load_level == .throttled) {
        if (server.rate_limiter) |*rl| {
            const ip = recv.peer_address.in.sa.addr;
            if (!rl.allow(ip, server.tick_now_ns)) {
                const is_con_raw = recv.payload.len >= 1 and ((recv.payload[0] >> 4) & 0x03) == 0;
                release_buffer_robust(&server.io, recv.buffer_id);
                server.buffers_outstanding -|= 1;
                if (is_con_raw) server.send_rst(&raw_header, recv.peer_address, index);
                return;
            }
        }
    }

    const packet = coapz.Packet.read(arena, recv.payload) catch |err| {
        release_buffer_robust(&server.io, recv.buffer_id);
        server.buffers_outstanding -|= 1;
        switch (err) {
            error.OutOfMemory => {
                log.warn("OOM parsing packet, sending emergency ACK", .{});
                server.send_emergency_ack(&raw_header, recv.peer_address, index);
            },
            else => log.debug("malformed CoAP packet: {}", .{err}),
        }
        return;
    };

    // Release the recv buffer immediately — Packet.read copied all
    // data into the arena, so the provided buffer can be returned to
    // the kernel pool without waiting for response construction.
    release_buffer_robust(&server.io, recv.buffer_id);
    server.buffers_outstanding -|= 1;

    // RST cancels the matching exchange.
    if (packet.kind == .reset) {
        const key = Exchange.peer_key(recv.peer_address, packet.msg_id);
        if (server.exchanges.find(key)) |slot_idx| {
            server.exchanges.remove(slot_idx);
        }
        return;
    }

    const is_con = packet.kind == .confirmable;

    // CON duplicate detection.
    if (is_con) {
        const key = Exchange.peer_key(recv.peer_address, packet.msg_id);
        if (server.exchanges.find(key)) |slot_idx| {
            // Duplicate CON — retransmit cached response.
            const cached = server.exchanges.cached_response(slot_idx);
            try server.send_data(cached, recv.peer_address, index);
            return;
        }
    }

    const request = handler.Request{
        .packet = packet,
        .peer_address = recv.peer_address,
        .arena = arena,
    };

    const maybe_response = blk: {
        if (server.config.well_known_core) |wkc| {
            if (is_well_known_core(packet)) {
                var cf_buf: [2]u8 = undefined;
                const cf_opt = coapz.Option.content_format(
                    .link_format,
                    &cf_buf,
                );
                const opts = arena.dupe(coapz.Option, &.{cf_opt}) catch |err| {
                    switch (err) {
                        error.OutOfMemory => {
                            log.warn("OOM building well-known response, sending emergency ACK", .{});
                            if (is_con) server.send_emergency_ack(&raw_header, recv.peer_address, index);
                            return;
                        },
                    }
                };
                break :blk @as(?handler.Response, .{
                    .code = .content,
                    .options = opts,
                    .payload = wkc,
                });
            }
        }
        break :blk server.handler_fn(server.handler_context, request);
    };

    if (maybe_response) |response| {
        const response_kind: coapz.MessageKind = if (is_con)
            .acknowledgement
        else
            .non_confirmable;

        const response_packet = coapz.Packet{
            .kind = response_kind,
            .code = response.code,
            .msg_id = if (is_con) packet.msg_id else server.nextMsgId(),
            .token = packet.token,
            .options = response.options,
            .payload = response.payload,
            .data_buf = &.{},
        };

        const data_wire = response_packet.write(arena) catch |err| {
            switch (err) {
                error.OutOfMemory => {
                    log.warn("OOM encoding response, sending emergency ACK", .{});
                    if (is_con) server.send_emergency_ack(&raw_header, recv.peer_address, index);
                },
                else => log.err("response write failed: {}", .{err}),
            }
            return;
        };
        try server.send_data(data_wire, recv.peer_address, index);

        // Cache the response for CON dedup.
        if (is_con) {
            const key = Exchange.peer_key(
                recv.peer_address,
                packet.msg_id,
            );
            if (server.exchanges.insert(
                key,
                packet.msg_id,
                data_wire,
                server.tick_now_ns,
            ) == null) {
                // Try evicting expired entries before giving up.
                const evicted = server.exchanges.evict_expired(server.tick_now_ns);
                if (evicted > 0) {
                    server.last_eviction_ns = server.tick_now_ns;
                    _ = server.exchanges.insert(key, packet.msg_id, data_wire, server.tick_now_ns);
                } else {
                    log.warn("exchange pool full ({d} active), cannot cache", .{server.exchanges.count_active});
                }
            }
        }
    } else if (is_con) {
        // No handler response, but CON requires an empty ACK.
        const ack = coapz.Packet{
            .kind = .acknowledgement,
            .code = .empty,
            .msg_id = packet.msg_id,
            .token = &.{},
            .options = &.{},
            .payload = &.{},
            .data_buf = &.{},
        };
        const data_wire = ack.write(arena) catch |err| {
            switch (err) {
                error.OutOfMemory => {
                    log.warn("OOM encoding empty ACK, sending emergency ACK", .{});
                    server.send_emergency_ack(&raw_header, recv.peer_address, index);
                },
                else => log.err("ack write failed: {}", .{err}),
            }
            return;
        };
        try server.send_data(data_wire, recv.peer_address, index);

        // Cache the empty ACK too.
        const key = Exchange.peer_key(
            recv.peer_address,
            packet.msg_id,
        );
        if (server.exchanges.insert(
            key,
            packet.msg_id,
            data_wire,
            server.tick_now_ns,
        ) == null) {
            const evicted = server.exchanges.evict_expired(server.tick_now_ns);
            if (evicted > 0) {
                server.last_eviction_ns = server.tick_now_ns;
                _ = server.exchanges.insert(key, packet.msg_id, data_wire, server.tick_now_ns);
            } else {
                log.warn("exchange pool full ({d} active), cannot cache", .{server.exchanges.count_active});
            }
        }
    }
}

/// Send a pre-allocated empty ACK when OOM prevents normal response.
/// Extracts msg_id from raw CoAP header bytes (first 4 bytes of payload).
fn send_emergency_ack(
    server: *Server,
    raw_payload: []const u8,
    peer_address: std.net.Address,
    index: usize,
) void {
    if (raw_payload.len < 4) return;

    // CoAP header: ver|type|tkl(1B) code(1B) msg_id(2B)
    // Check if CON (type bits = 0b00 in bits 5:4)
    const type_bits = (raw_payload[0] >> 4) & 0x03;
    if (type_bits != 0) return; // not CON

    const slot = index * 4;
    if (slot + 4 > server.emergency_ack.len) return;

    // Build empty ACK: version=1, type=ACK(2), tkl=0, code=0.00, same msg_id
    server.emergency_ack[slot + 0] = 0x60; // ver=1, type=ACK(10), tkl=0
    server.emergency_ack[slot + 1] = 0x00; // code = 0.00 (empty)
    server.emergency_ack[slot + 2] = raw_payload[2]; // msg_id high
    server.emergency_ack[slot + 3] = raw_payload[3]; // msg_id low

    const ack_data = server.emergency_ack[slot..][0..4];
    server.send_data(ack_data, peer_address, index) catch {};
}

/// Send a pre-allocated RST for rate-limited/shed CON packets.
fn send_rst(
    server: *Server,
    raw_header: []const u8,
    peer_address: std.net.Address,
    index: usize,
) void {
    if (raw_header.len < 4) return;

    const slot = index * 4;
    if (slot + 4 > server.rate_limit_rst.len) return;

    // Build RST: version=1, type=RST(3), tkl=0, code=0.00, same msg_id
    server.rate_limit_rst[slot + 0] = 0x70; // ver=1, type=RST(11), tkl=0
    server.rate_limit_rst[slot + 1] = 0x00;
    server.rate_limit_rst[slot + 2] = raw_header[2];
    server.rate_limit_rst[slot + 3] = raw_header[3];

    const rst_data = server.rate_limit_rst[slot..][0..4];
    server.send_data(rst_data, peer_address, index) catch {};
}

/// Recompute load level based on pool utilization.
fn update_load_level(server: *Server) void {
    const buf_pct: u16 = if (server.config.buffer_count > 0)
        (server.buffers_outstanding *| 100) / server.config.buffer_count
    else
        0;
    const exch_pct: u16 = if (server.config.exchange_count > 0)
        (@as(u16, server.exchanges.count_active) *| 100) / server.config.exchange_count
    else
        0;

    const max_pct: u16 = @max(buf_pct, exch_pct);

    switch (server.load_level) {
        .normal => {
            if (max_pct >= server.config.load_shed_critical_pct) {
                server.load_level = .shedding;
                log.warn("load shedding: critical ({d}%)", .{max_pct});
            } else if (max_pct >= server.config.load_shed_throttle_pct) {
                server.load_level = .throttled;
                log.info("load shedding: throttled ({d}%)", .{max_pct});
            }
        },
        .throttled => {
            if (max_pct >= server.config.load_shed_critical_pct) {
                server.load_level = .shedding;
                log.warn("load shedding: critical ({d}%)", .{max_pct});
            } else if (max_pct < server.config.load_shed_recover_pct) {
                server.load_level = .normal;
                log.info("load shedding: recovered", .{});
            }
        },
        .shedding => {
            if (max_pct < server.config.load_shed_recover_pct) {
                server.load_level = .normal;
                log.info("load shedding: recovered", .{});
            } else if (max_pct < server.config.load_shed_throttle_pct) {
                server.load_level = .throttled;
                log.info("load shedding: eased to throttled ({d}%)", .{max_pct});
            }
        },
    }
}

/// Encode and queue a UDP response to the peer.
fn send_data(
    server: *Server,
    data: []const u8,
    peer_address: std.net.Address,
    index: usize,
) !void {
    const batch: usize = @min(constants.completion_batch_max, server.config.buffer_count);
    std.debug.assert(index < batch);

    if (data.len > server.config.buffer_size) {
        log.err("response too large: {d} > {d}", .{
            data.len,
            server.config.buffer_size,
        });
        return;
    }

    const offset_buf = index * server.config.buffer_size;
    const slot = server.buffer_response[offset_buf..][0..data.len];
    @memcpy(slot, data);

    server.addrs_response[index] = peer_address.any;

    server.iovs_response[index] = .{
        .base = @ptrCast(slot.ptr),
        .len = slot.len,
    };

    server.msgs_response[index] = .{
        .name = @ptrCast(&server.addrs_response[index]),
        .namelen = @sizeOf(linux.sockaddr),
        .iov = @ptrCast(&server.iovs_response[index]),
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    try server.io.send_msg(&server.msgs_response[index]);
}

/// Release a buffer back to the kernel, flushing the SQ on failure and retrying once.
fn release_buffer_robust(io: *Io, buffer_id: u16) void {
    io.release_buffer(buffer_id) catch {
        _ = io.submit() catch {};
        io.release_buffer(buffer_id) catch |err| {
            log.err("buffer {d} lost: {}", .{ buffer_id, err });
        };
    };
}

fn nextMsgId(server: *Server) u16 {
    const id = server.next_msg_id;
    server.next_msg_id = id +% 1;
    return id;
}

/// Check if the packet is a GET /.well-known/core request.
fn is_well_known_core(packet: coapz.Packet) bool {
    if (packet.code != .get) return false;

    var it = packet.find_options(.uri_path);
    const seg1 = it.next() orelse return false;
    if (!std.mem.eql(u8, seg1.value, ".well-known")) return false;
    const seg2 = it.next() orelse return false;
    if (!std.mem.eql(u8, seg2.value, "core")) return false;
    // Must be exactly two segments.
    return it.next() == null;
}

// ─── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

fn echo_handler(request: handler.Request) ?handler.Response {
    return .{ .payload = request.packet.payload };
}

fn null_handler(_: handler.Request) ?handler.Response {
    return null;
}

var handler_call_count = std.atomic.Value(u32).init(0);

fn counting_handler(request: handler.Request) ?handler.Response {
    _ = handler_call_count.fetchAdd(1, .monotonic);
    return .{ .payload = request.packet.payload };
}

/// Helper: setup server io and multishot recv (for tests).
fn setup_for_test(server: *Server) !void {
    try server.listen();
}

/// Helper: create a UDP client socket with a receive timeout.
fn test_client(port: u16) !posix.socket_t {
    const fd = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        0,
    );

    const timeout = posix.timeval{ .sec = 1, .usec = 0 };
    try posix.setsockopt(
        fd,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        std.mem.asBytes(&timeout),
    );

    const dest = try std.net.Address.parseIp("127.0.0.1", port);
    try posix.connect(fd, &dest.any, dest.getOsSockLen());

    return fd;
}

/// Helper: send, tick, and receive a response.
fn send_tick_recv(
    server: *Server,
    client_fd: posix.socket_t,
    wire: []const u8,
) ![]const u8 {
    _ = try posix.send(client_fd, wire, 0);
    try server.tick();

    var cqes: [constants.completion_batch_max]Cqe =
        std.mem.zeroes([constants.completion_batch_max]Cqe);
    _ = try server.io.wait_cqes(cqes[0..], 0);

    var buf: [1280]u8 = undefined;
    const n = try posix.recv(client_fd, &buf, 0);
    // Copy to arena so caller can use it without lifetime issues.
    const result = try testing.allocator.alloc(u8, n);
    @memcpy(result, buf[0..n]);
    return result;
}

test "init and deinit" {
    var server = try Server.init(testing.allocator, .{
        .port = 19680,
        .buffer_count = 4,
        .buffer_size = 256,
    }, echo_handler);
    server.deinit();
}

test "init and deinit with null handler" {
    var server = try Server.init(testing.allocator, .{
        .port = 19681,
        .buffer_count = 4,
        .buffer_size = 256,
    }, null_handler);
    server.deinit();
}

test "round-trip: NON echo via UDP" {
    const port: u16 = 19683;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, echo_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x1234,
        .token = &.{ 0xAA, 0xBB },
        .options = &.{},
        .payload = "hello",
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);

    const response = try coapz.Packet.read(testing.allocator, raw);
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.non_confirmable, response.kind);
    try testing.expectEqual(.content, response.code);
    try testing.expect(response.msg_id != 0x1234);
    try testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, response.token);
    try testing.expectEqualSlices(u8, "hello", response.payload);
}

test "round-trip: CON echoes as ACK" {
    const port: u16 = 19684;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, echo_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .post,
        .msg_id = 0xABCD,
        .token = &.{0x01},
        .options = &.{},
        .payload = "data",
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);

    const response = try coapz.Packet.read(testing.allocator, raw);
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.acknowledgement, response.kind);
    try testing.expectEqual(.content, response.code);
    try testing.expectEqual(@as(u16, 0xABCD), response.msg_id);
    try testing.expectEqualSlices(u8, &.{0x01}, response.token);
    try testing.expectEqualSlices(u8, "data", response.payload);
}

test "CON null handler sends empty ACK" {
    const port: u16 = 19685;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, null_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0x9999,
        .token = &.{0x42},
        .options = &.{},
        .payload = &.{},
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);

    const response = try coapz.Packet.read(testing.allocator, raw);
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.acknowledgement, response.kind);
    try testing.expectEqual(.empty, response.code);
    try testing.expectEqual(@as(u16, 0x9999), response.msg_id);
}

test "NON null handler sends no response" {
    const port: u16 = 19686;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, null_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x5678,
        .token = &.{},
        .options = &.{},
        .payload = &.{},
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    _ = try posix.send(client_fd, wire, 0);
    try server.tick();

    var buf: [1280]u8 = undefined;
    const result = posix.recv(
        client_fd,
        &buf,
        posix.SOCK.NONBLOCK,
    );
    try testing.expectError(error.WouldBlock, result);
}

test "CON duplicate detection" {
    const port: u16 = 19687;

    handler_call_count.store(0, .monotonic);
    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
        .exchange_count = 16,
    }, counting_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0xDEAD,
        .token = &.{0x01},
        .options = &.{},
        .payload = "test",
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    // First request — handler should be called.
    const raw1 = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw1);
    try testing.expectEqual(@as(u32, 1), handler_call_count.load(.monotonic));

    // Second request (same msg_id) — handler should NOT be called.
    // The cached response should be retransmitted.
    const raw2 = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw2);
    try testing.expectEqual(@as(u32, 1), handler_call_count.load(.monotonic));

    // Both responses should be identical.
    try testing.expectEqualSlices(u8, raw1, raw2);

    const response = try coapz.Packet.read(testing.allocator, raw2);
    defer response.deinit(testing.allocator);
    try testing.expectEqual(.acknowledgement, response.kind);
    try testing.expectEqualSlices(u8, "test", response.payload);
}

test "RST cancels CON exchange" {
    const port: u16 = 19688;

    handler_call_count.store(0, .monotonic);
    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
        .exchange_count = 16,
    }, counting_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    // Send CON, get ACK — handler called once.
    const con_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0xBEEF,
        .token = &.{0x01},
        .options = &.{},
        .payload = "rst-test",
        .data_buf = &.{},
    };
    const con_wire = try con_packet.write(testing.allocator);
    defer testing.allocator.free(con_wire);

    const raw1 = try send_tick_recv(&server, client_fd, con_wire);
    defer testing.allocator.free(raw1);
    try testing.expectEqual(@as(u32, 1), handler_call_count.load(.monotonic));

    // Send RST with same msg_id to cancel the exchange.
    const rst_packet = coapz.Packet{
        .kind = .reset,
        .code = .empty,
        .msg_id = 0xBEEF,
        .token = &.{},
        .options = &.{},
        .payload = &.{},
        .data_buf = &.{},
    };
    const rst_wire = try rst_packet.write(testing.allocator);
    defer testing.allocator.free(rst_wire);

    _ = try posix.send(client_fd, rst_wire, 0);
    try server.tick();

    // Drain any send CQEs.
    var cqes: [constants.completion_batch_max]Cqe =
        std.mem.zeroes([constants.completion_batch_max]Cqe);
    _ = try server.io.wait_cqes(cqes[0..], 0);

    // Send same CON again — exchange was cleared, handler called again.
    const raw2 = try send_tick_recv(&server, client_fd, con_wire);
    defer testing.allocator.free(raw2);
    try testing.expectEqual(@as(u32, 2), handler_call_count.load(.monotonic));
}

test "GET /.well-known/core returns link format" {
    const port: u16 = 19689;
    const wkc_payload = "</sensors>;rt=\"temperature\"";

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
        .well_known_core = wkc_payload,
    }, null_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x7777,
        .token = &.{0x42},
        .options = &.{
            .{ .kind = .uri_path, .value = ".well-known" },
            .{ .kind = .uri_path, .value = "core" },
        },
        .payload = &.{},
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);

    const response = try coapz.Packet.read(testing.allocator, raw);
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.content, response.code);
    try testing.expectEqualSlices(u8, wkc_payload, response.payload);

    // Verify content-format option is present (value 40 = link_format).
    var cf_it = response.find_options(.content_format);
    const cf_opt = cf_it.next();
    try testing.expect(cf_opt != null);
}

test "well_known_core null passes to handler" {
    const port: u16 = 19690;

    handler_call_count.store(0, .monotonic);
    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, counting_handler);
    defer server.deinit();
    try setup_for_test(&server);

    // Send a /.well-known/core request — should pass to handler.
    const request_packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x8888,
        .token = &.{0x01},
        .options = &.{
            .{ .kind = .uri_path, .value = ".well-known" },
            .{ .kind = .uri_path, .value = "core" },
        },
        .payload = &.{},
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(port);
    defer posix.close(client_fd);

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);
    try testing.expectEqual(@as(u32, 1), handler_call_count.load(.monotonic));
}

const TestCtx = struct { call_count: u32 = 0 };

fn ctx_handler(ctx: *TestCtx, request: handler.Request) ?handler.Response {
    ctx.call_count += 1;
    return .{ .payload = request.packet.payload };
}

test "initContext with typed handler" {
    var ctx = TestCtx{};
    var server = try Server.initContext(testing.allocator, .{
        .port = 19692,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, ctx_handler, &ctx);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x4444,
        .token = &.{0x01},
        .options = &.{},
        .payload = "ctx-test",
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = try test_client(19692);
    defer posix.close(client_fd);

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);

    try testing.expectEqual(@as(u32, 1), ctx.call_count);
}

test "init rejects invalid config" {
    try testing.expectError(error.InvalidConfig, Server.init(
        testing.allocator,
        .{ .port = 19700, .buffer_count = 0, .buffer_size = 256 },
        echo_handler,
    ));
    try testing.expectError(error.InvalidConfig, Server.init(
        testing.allocator,
        .{ .port = 19700, .buffer_count = 4, .buffer_size = 32 },
        echo_handler,
    ));
    try testing.expectError(error.InvalidConfig, Server.init(
        testing.allocator,
        .{ .port = 0, .buffer_count = 4, .buffer_size = 256 },
        echo_handler,
    ));
}
