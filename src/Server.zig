/// CoAP server built on io_uring.
///
/// All memory is pre-allocated at `init`. Handlers receive a per-request
/// arena allocator that resets after each batch of completions.
/// CON messages are deduplicated and their responses are cached for
/// retransmission per RFC 7252 §4.
///
/// **Memory:** `init` pre-allocates all buffers (response slots, emergency
/// ACKs, rate-limiter state, exchange pool). No allocations occur during
/// request handling — the per-request arena is reset (not freed) after
/// each tick. Call `deinit()` to release everything.
///
/// ## Example
///
/// ```zig
/// fn handler(req: coap.Request) ?coap.Response {
///     return coap.Response.ok(req.payload());
/// }
///
/// var server = try coap.Server.init(allocator, .{}, handler);
/// defer server.deinit();
/// try server.run();
/// ```
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const coapz = @import("coapz");
const Io = @import("Io.zig");
const Exchange = @import("exchange.zig");
const RateLimiter = @import("rate_limiter.zig");
const Deferred = @import("deferred.zig");
const handler = @import("handler.zig");
const constants = @import("constants.zig");
const dtls = @import("dtls/dtls.zig");
const log = std.log.scoped(.coap);

const Cqe = linux.io_uring_cqe;

const Server = @This();

/// Current server load level, determined by buffer and exchange pool utilization.
pub const LoadLevel = enum {
    /// All requests processed normally.
    normal,
    /// Per-IP rate limiting active. CON packets over limit get RST, NON dropped.
    throttled,
    /// New packets dropped. Only cached CON retransmissions are served.
    shedding,
};

pub const Config = struct {
    port: u16 = constants.port_default,
    buffer_count: u16 = constants.buffer_count_default,
    buffer_size: u32 = constants.buffer_size_default,
    /// Maximum concurrent CON exchanges for duplicate detection.
    exchange_count: u16 = 256,
    /// Maximum concurrent deferred (separate) responses. 0 = disabled.
    max_deferred: u16 = 16,
    /// Link-format payload for GET /.well-known/core (RFC 6690).
    /// If null, requests pass through to the handler.
    well_known_core: ?[]const u8 = null,
    /// Number of server threads. Each gets its own socket/ring/exchange pool.
    /// Kernel distributes packets via SO_REUSEPORT.
    /// When > 1, the handler context pointer is shared — see `initContext`.
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
    /// Log warning when handler takes longer than this (ns). 0 = disabled.
    /// When enabled, adds a nanoTimestamp() call per handler invocation.
    handler_warn_ns: u64 = 0,
    /// Maximum worker restart attempts before giving up.
    max_worker_restarts: u16 = 5,
    /// Exchange lifetime in milliseconds. Cached CON responses are
    /// evicted after this duration. RFC 7252 default is ~247s; shorter
    /// values reclaim slots faster on reliable networks.
    /// 0 = use RFC 7252 derived value (exchange_lifetime_ms).
    exchange_lifetime_ms: u32 = 0,
    /// CPU core IDs for thread pinning. Thread i pins to
    /// cpu_affinity[i % len]. null = no pinning (default).
    cpu_affinity: ?[]const u16 = null,
    /// Additional option numbers the application recognizes as critical.
    /// Options listed here (plus all standard coapz options) will NOT
    /// trigger 4.02 Bad Option rejection.
    recognized_options: []const u16 = &.{},
    /// PSK credentials for DTLS. null = plain UDP only.
    psk: ?dtls.types.Psk = null,
    /// Maximum concurrent DTLS sessions.
    dtls_session_count: u32 = constants.dtls_session_count_default,
    /// Idle DTLS session timeout in seconds.
    dtls_session_timeout_s: u16 = constants.dtls_session_timeout_s,
};

allocator: std.mem.Allocator,
io: Io,
handler_fn: handler.HandlerFn,
handler_context: ?*anyopaque,
arena: std.heap.ArenaAllocator,
config: Config,
exchanges: Exchange,
deferred: ?Deferred,
exchange_lifetime_ms: u32,
running: std.atomic.Value(bool),

// Pre-allocated per-CQE response state.
addrs_response: []std.net.Address,
msgs_response: []linux.msghdr_const,
iovs_response: []posix.iovec,
buffer_response: []u8,

/// Pre-allocated emergency ACK buffers for OOM conditions.
/// Each slot holds a 4-byte empty ACK (one per batch slot).
emergency_ack: []u8,

// Recv state.
addr_recv: linux.sockaddr.in6,
msg_recv: linux.msghdr,

// Eviction timer.
last_eviction_ns: i64,
tick_count: u64,

// Server-side message ID counter for NON responses.
next_msg_id: u16,

// Arena management.
force_free_all: bool,

// Load shedding and rate limiting.
load_level: LoadLevel,
buffers_outstanding: u16,
buffers_peak: u16,
rate_limiter: ?RateLimiter,
tick_now_ns: i64,

/// Pre-allocated RST buffers for rate-limited/shed CON packets.
rate_limit_rst: []u8,

// DTLS state.
dtls_sessions: ?*dtls.Session.SessionTable,
dtls_cookie_secret: [32]u8,
dtls_cookie_secret_prev: [32]u8,
dtls_cookie_rotation_ns: i64,

/// Initialize with a simple handler (no context).
///
/// Pre-allocates all buffers. Returns `error.InvalidConfig` if
/// `buffer_count` is 0, `buffer_size` < 64, or `port` is 0.
pub fn init(
    allocator: std.mem.Allocator,
    config: Config,
    handler_fn: handler.SimpleHandlerFn,
) !Server {
    return init_raw(allocator, config, handler.wrapSimple, @ptrCast(@constCast(handler_fn)));
}

/// Initialize with a typed context handler. The context pointer is
/// type-erased internally and passed to the handler on every invocation.
///
/// **Thread safety:** When `Config.thread_count > 1`, the context pointer
/// is shared across worker threads. Mutations must use `@atomicRmw`,
/// mutexes, or thread-local state to avoid data races.
///
/// ```zig
/// fn handle(ctx: *State, req: Request) ?Response {
///     _ = @atomicRmw(u64, &ctx.counter, .Add, 1, .monotonic);
///     return Response.ok(req.payload());
/// }
/// var server = try Server.initContext(allocator, .{}, handle, &state);
/// ```
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

/// Clamp buffer_count so that all io_uring instances fit within
/// RLIMIT_MEMLOCK. Only the ring structures are locked (provided buffers
/// are not pinned). Each ring locks approximately:
///   SQ: ring_entries × 64 bytes (io_uring_sqe)
///   CQ: ring_entries × 2 × 16 bytes (io_uring_cqe)
///   ring_entries = next_pow2(buffer_count × 4)
/// When RLIMIT_MEMLOCK is unlimited (or getrlimit fails), the requested
/// count is returned unchanged. Minimum returned value is 4.
fn clampBufferCount(requested: u16, thread_count: u16) u16 {
    const rl = std.posix.getrlimit(.MEMLOCK) catch return requested;
    if (rl.cur == linux.RLIM.INFINITY) return requested; // unlimited

    const budget = rl.cur;
    const tc: u64 = @max(1, thread_count);
    const per_thread = budget / tc;

    var candidate: u16 = requested;
    while (candidate > 4) {
        const ring_entries = std.math.ceilPowerOfTwo(u32, @as(u32, candidate) *| 4) catch break;
        // SQE: 64 bytes each, CQE: 16 bytes each (2× ring_entries).
        const locked: u64 = @as(u64, ring_entries) * 96;
        if (locked <= per_thread) break;
        candidate /= 2;
    }
    if (candidate < requested) {
        log.info("buffer_count clamped {d} → {d} (RLIMIT_MEMLOCK {d}, {d} threads)", .{
            requested, candidate, budget, tc,
        });
    }
    return @max(candidate, 4);
}

fn init_raw(
    allocator: std.mem.Allocator,
    config_in: Config,
    handler_fn: handler.HandlerFn,
    handler_context: ?*anyopaque,
) !Server {
    var config = config_in;

    // When PSK is configured and the port is still the plain CoAP default,
    // switch to the CoAPs (DTLS) default port per RFC 7252 §6.2.
    if (config.psk != null and config.port == constants.port_default) {
        config.port = constants.coaps_port_default;
    }

    if (config.buffer_count == 0 or
        config.buffer_size < 64 or
        config.port == 0) return error.InvalidConfig;

    if (config.cpu_affinity) |cores| {
        if (cores.len == 0) return error.InvalidConfig;
    }

    config.buffer_count = clampBufferCount(config.buffer_count, config.thread_count);

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

    var deferred: ?Deferred = null;
    if (config.max_deferred > 0) {
        deferred = try Deferred.init(allocator, .{
            .max_deferred = config.max_deferred,
            .buffer_size = @intCast(config.buffer_size),
        });
    }
    errdefer if (deferred) |*d| d.deinit(allocator);

    const batch: usize = @min(
        constants.completion_batch_max,
        config.buffer_count,
    );

    const addrs_response = try allocator.alloc(
        std.net.Address,
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

    var dtls_sessions: ?*dtls.Session.SessionTable = null;
    var dtls_cookie_secret: [32]u8 = .{0} ** 32;
    var dtls_cookie_secret_prev: [32]u8 = .{0} ** 32;
    if (config.psk != null) {
        const tbl_ptr = try allocator.create(dtls.Session.SessionTable);
        errdefer allocator.destroy(tbl_ptr);
        tbl_ptr.* = try dtls.Session.SessionTable.init(allocator, .{
            .capacity = config.dtls_session_count,
            .timeout_s = config.dtls_session_timeout_s,
        });
        errdefer tbl_ptr.deinit(allocator);
        dtls_sessions = tbl_ptr;
        std.crypto.random.bytes(&dtls_cookie_secret);
        std.crypto.random.bytes(&dtls_cookie_secret_prev);
    }

    return .{
        .allocator = allocator,
        .io = io,
        .handler_fn = handler_fn,
        .handler_context = handler_context,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .config = config,
        .exchanges = exchanges,
        .deferred = deferred,
        .exchange_lifetime_ms = if (config.exchange_lifetime_ms > 0)
            config.exchange_lifetime_ms
        else
            constants.exchange_lifetime_ms,
        .running = std.atomic.Value(bool).init(true),
        .addrs_response = addrs_response,
        .msgs_response = msgs_response,
        .iovs_response = iovs_response,
        .buffer_response = buffer_response,
        .emergency_ack = emergency_ack,
        .addr_recv = std.mem.zeroes(linux.sockaddr.in6),
        .msg_recv = std.mem.zeroes(linux.msghdr),
        .last_eviction_ns = 0,
        .tick_count = 0,
        .next_msg_id = std.crypto.random.int(u16),
        .force_free_all = false,
        .load_level = .normal,
        .buffers_outstanding = 0,
        .buffers_peak = 0,
        .rate_limiter = rate_limiter,
        .tick_now_ns = 0,
        .rate_limit_rst = rate_limit_rst,
        .dtls_sessions = dtls_sessions,
        .dtls_cookie_secret = dtls_cookie_secret,
        .dtls_cookie_secret_prev = dtls_cookie_secret_prev,
        .dtls_cookie_rotation_ns = 0,
    };
}

/// Release all server-owned memory (arena, exchange pool, io_uring,
/// response buffers, rate limiter) and close the socket.
pub fn deinit(server: *Server) void {
    server.arena.deinit();
    server.exchanges.deinit(server.allocator);
    if (server.deferred) |*d| d.deinit(server.allocator);
    server.io.deinit(server.allocator);
    server.allocator.free(server.addrs_response);
    server.allocator.free(server.msgs_response);
    server.allocator.free(server.iovs_response);
    server.allocator.free(server.buffer_response);
    server.allocator.free(server.emergency_ack);
    server.allocator.free(server.rate_limit_rst);
    if (server.rate_limiter) |*rl| rl.deinit(server.allocator);
    if (server.dtls_sessions) |tbl| {
        // Zero key material from all active sessions before freeing.
        for (tbl.slots) |*slot| {
            if (slot.state != .free) slot.zeroKeys();
        }
        tbl.deinit(server.allocator);
        server.allocator.destroy(tbl);
    }
    std.crypto.secureZero(u8, &server.dtls_cookie_secret);
    std.crypto.secureZero(u8, &server.dtls_cookie_secret_prev);
}

/// Bind the socket, register buffers, and arm the multishot recv.
/// After this returns the server is ready to accept packets.
pub fn listen(server: *Server) !void {
    try server.io.setup(server.config.port, server.config.bind_address);

    server.msg_recv.name = @ptrCast(&server.addr_recv);
    // Set name buffer size based on actual socket family.
    const bind_addr = try std.net.Address.parseIp(server.config.bind_address, server.config.port);
    server.msg_recv.namelen = bind_addr.getOsSockLen();
    server.msg_recv.controllen = 0;

    try server.io.recv_multishot(&server.msg_recv);
    _ = try server.io.submit();
}

/// Signal the server and all worker threads to stop after the current tick.
/// Thread-safe — safe to call from a signal handler or another thread.
pub fn stop(server: *Server) void {
    server.running.store(false, .release);
}

const WorkerState = struct {
    thread: ?std.Thread,
    exited: std.atomic.Value(bool),
    restart_count: u16,
    index: u16,
};

/// Blocking main loop: binds the socket, spawns worker threads (if
/// `thread_count > 1`), and processes packets until `stop()` is called.
/// Worker threads that crash are automatically restarted up to
/// `max_worker_restarts` times.
pub fn run(server: *Server) !void {
    try server.listen();

    if (server.config.cpu_affinity) |cores| {
        setCpuAffinity(cores[0]);
    }

    const extra = server.config.thread_count -| 1;
    const workers = try server.allocator.alloc(WorkerState, extra);
    defer server.allocator.free(workers);

    for (workers, 0..) |*w, i| {
        w.* = .{
            .thread = null,
            .exited = std.atomic.Value(bool).init(false),
            .restart_count = 0,
            .index = @intCast(i),
        };
        w.thread = std.Thread.spawn(.{}, run_worker, .{
            server.allocator,
            server.config,
            server.handler_fn,
            server.handler_context,
            &server.running,
            w,
        }) catch |err| {
            log.err("worker {d} spawn failed: {}", .{ i, err });
            continue;
        };
    }

    log.info("coap listening on port {d} ({d} thread{s})", .{
        server.config.port,
        server.config.thread_count,
        if (server.config.thread_count > 1) "s" else "",
    });

    // Main tick loop with worker monitoring.
    var consecutive_failures: u32 = 0;
    while (server.running.load(.acquire)) {
        server.tick() catch |err| {
            if (is_transient(err)) {
                consecutive_failures += 1;
                log.warn("tick transient error ({d}/3): {}", .{
                    consecutive_failures,
                    err,
                });
                if (consecutive_failures >= 3) {
                    log.err("main thread exiting: {}", .{err});
                    break;
                }
                continue;
            }
            log.err("main thread exiting: {}", .{err});
            break;
        };
        consecutive_failures = 0;

        // Monitor workers every 100 ticks.
        if (server.tick_count % 100 == 0) {
            server.monitor_workers(workers);
        }
    }

    server.drain();
    for (workers) |*w| {
        if (w.thread) |t| {
            t.join();
            w.thread = null;
        }
    }
}

fn monitor_workers(
    server: *Server,
    workers: []WorkerState,
) void {
    for (workers) |*w| {
        if (!w.exited.load(.acquire)) continue;
        // Worker has exited — join it.
        if (w.thread) |t| {
            t.join();
            w.thread = null;
        }
        if (w.restart_count >= server.config.max_worker_restarts) {
            log.err("worker {d} exceeded max restarts ({d}), not restarting", .{
                w.index,
                server.config.max_worker_restarts,
            });
            continue;
        }
        // Respawn.
        w.restart_count += 1;
        w.exited.store(false, .release);
        w.thread = std.Thread.spawn(.{}, run_worker, .{
            server.allocator,
            server.config,
            server.handler_fn,
            server.handler_context,
            &server.running,
            w,
        }) catch |err| {
            log.err("worker {d} respawn failed: {}", .{ w.index, err });
            w.exited.store(true, .release);
            continue;
        };
        log.info("worker {d} respawned (restart {d}/{d})", .{
            w.index,
            w.restart_count,
            server.config.max_worker_restarts,
        });
    }
}

fn setCpuAffinity(core: u16) void {
    var set = std.mem.zeroes(linux.cpu_set_t);
    const usize_bits = @bitSizeOf(usize);
    const word = core / usize_bits;
    if (word >= set.len) {
        log.warn("cpu affinity: core {d} exceeds max {d}", .{ core, set.len * usize_bits - 1 });
        return;
    }
    set[word] = @as(usize, 1) << @intCast(core % usize_bits);
    linux.sched_setaffinity(0, &set) catch |err| {
        log.warn("sched_setaffinity core {d}: {}", .{ core, err });
    };
}

fn run_worker(
    allocator: std.mem.Allocator,
    config: Config,
    handler_fn: handler.HandlerFn,
    handler_context: ?*anyopaque,
    running: *std.atomic.Value(bool),
    state: *WorkerState,
) void {
    defer state.exited.store(true, .release);

    // Backoff on restart.
    if (state.restart_count > 0) {
        const backoff_ms: u64 = @min(
            @as(u64, 100) << @intCast(@min(state.restart_count, 6)),
            5000,
        );
        log.info("worker {d} restarting (attempt {d}, backoff {d}ms)", .{
            state.index,
            state.restart_count,
            backoff_ms,
        });
        std.Thread.sleep(backoff_ms * std.time.ns_per_ms);
    }

    if (config.cpu_affinity) |cores| {
        setCpuAffinity(cores[(state.index + 1) % cores.len]);
    }

    var worker = init_raw(allocator, config, handler_fn, handler_context) catch |err| {
        log.err("worker {d} init failed: {}", .{ state.index, err });
        return;
    };
    defer {
        worker.drain();
        worker.deinit();
    }
    worker.listen() catch |err| {
        log.err("worker {d} listen failed: {}", .{ state.index, err });
        return;
    };
    var consecutive_failures: u32 = 0;
    while (running.load(.acquire)) {
        worker.tick() catch |err| {
            if (is_transient(err)) {
                consecutive_failures += 1;
                log.warn("worker {d} tick transient error ({d}/3): {}", .{
                    state.index,
                    consecutive_failures,
                    err,
                });
                if (consecutive_failures >= 3) {
                    log.err("worker {d} exiting: {}", .{ state.index, err });
                    return;
                }
                continue;
            }
            log.err("worker {d} exiting: {}", .{ state.index, err });
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

/// Drain pending io_uring completions before shutdown.
fn drain(server: *Server) void {
    _ = server.io.submit() catch {};
    var cqes: [constants.completion_batch_max]Cqe = std.mem.zeroes([constants.completion_batch_max]Cqe);
    _ = server.io.wait_cqes(cqes[0..], 0) catch {};
}

/// Process one batch of io_uring completions (up to 256 packets).
///
/// For each received packet: parses, calls the handler, sends the
/// response, and manages CON deduplication. Also performs periodic
/// exchange eviction, load level updates, and arena resets.
///
/// Use `listen()` + `tick()` in a loop when you need control over the
/// event loop (e.g. for graceful shutdown or integration with other I/O).
pub fn tick(server: *Server) !void {
    const batch_max = constants.completion_batch_max;
    var cqes: [batch_max]Cqe = std.mem.zeroes([batch_max]Cqe);

    server.tick_now_ns = @intCast(std.time.nanoTimestamp());

    // Submit a timeout so wait_cqes unblocks periodically, allowing
    // the run loop to check the shutdown flag even when idle.
    const tick_ts = linux.kernel_timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
    server.io.queue_timeout(&tick_ts) catch {};
    _ = server.io.submit() catch {};

    const count = try server.io.wait_cqes(cqes[0..], 1);
    var recv_failed = false;
    var recv_fail_count: u32 = 0;
    var processed: u32 = 0;

    for (cqes[0..count], 0..) |cqe, index| {
        if (Io.is_timeout(&cqe)) continue;
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
    const eviction_interval_ns: i64 = 10 * std.time.ns_per_s;
    if (server.tick_now_ns - server.last_eviction_ns > eviction_interval_ns) {
        const evicted = server.exchanges.evict_expired(server.tick_now_ns, server.exchange_lifetime_ms);
        if (evicted > 0) {
            log.debug("evicted {d} expired exchanges", .{evicted});
        }
        server.last_eviction_ns = server.tick_now_ns;
    }

    // DTLS cookie secret rotation and session timeout eviction.
    if (server.dtls_sessions) |tbl| {
        const rotation_ns: i64 = @as(i64, constants.dtls_cookie_secret_rotation_s) * std.time.ns_per_s;
        if (server.tick_now_ns - server.dtls_cookie_rotation_ns > rotation_ns) {
            server.dtls_cookie_secret_prev = server.dtls_cookie_secret;
            std.crypto.random.bytes(&server.dtls_cookie_secret);
            server.dtls_cookie_rotation_ns = server.tick_now_ns;
        }

        // Evict timed-out sessions from LRU tail.
        const timeout_ns: i64 = @as(i64, server.config.dtls_session_timeout_s) * std.time.ns_per_s;
        var evicted_sessions: u32 = 0;
        while (tbl.lru_tail != 0xFFFFFFFF) {
            const tail = &tbl.slots[tbl.lru_tail];
            if (server.tick_now_ns - tail.last_activity_ns < timeout_ns) break;
            tbl.release(tail);
            evicted_sessions += 1;
        }
        if (evicted_sessions > 0) {
            log.debug("evicted {d} timed-out DTLS sessions", .{evicted_sessions});
        }

        // TODO: scan handshaking sessions for expired retransmit deadlines and
        // re-send the server's last flight. Currently the server relies on the
        // client to retransmit, which is sufficient for most cases but not
        // fully spec-compliant (RFC 6347 §4.2.4).
    }

    // Drain deferred response queue and retransmit pending CONs.
    server.drainDeferred();

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
    server.buffers_peak = @max(server.buffers_peak, server.buffers_outstanding);

    // Save raw header bytes before buffer release for emergency ACK.
    var raw_header: [4]u8 = .{ 0, 0, 0, 0 };
    if (recv.payload.len >= 4) {
        @memcpy(&raw_header, recv.payload[0..4]);
    }

    // Wire discrimination: DTLS content types (20-25) vs CoAP v1 (top 2 bits = 01).
    if (recv.payload.len >= 1) {
        if (server.config.psk != null) {
            if (dtls.types.isDtlsContentType(recv.payload[0])) {
                // DTLS record — handle in dedicated path.
                server.process_dtls_record(recv, index);
                return;
            }
            // PSK configured but not a DTLS record — drop plain CoAP.
            release_buffer_robust(&server.io, recv.buffer_id);
            server.buffers_outstanding -|= 1;
            return;
        }
        // No PSK — drop non-CoAP-v1 packets.
        if ((recv.payload[0] >> 6) != 1) {
            release_buffer_robust(&server.io, recv.buffer_id);
            server.buffers_outstanding -|= 1;
            return;
        }
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
            const addr_key = RateLimiter.AddrKey.fromAddress(recv.peer_address);
            if (!rl.allow(addr_key, server.tick_now_ns)) {
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
        // Also cancel any deferred response the client RST'd.
        if (server.deferred) |*pool| {
            if (pool.findByMsgId(packet.msg_id, recv.peer_address)) |idx| {
                pool.release(idx);
            }
        }
        return;
    }

    // ACK for a deferred (separate) CON response — release the slot.
    if (packet.kind == .acknowledgement) {
        if (server.deferred) |*pool| {
            if (pool.findByMsgId(packet.msg_id, recv.peer_address)) |idx| {
                pool.release(idx);
            }
        }
        return;
    }

    const is_con = packet.kind == .confirmable;

    const addr_key = Exchange.addr_hash(recv.peer_address);

    // CON duplicate detection.
    if (is_con) {
        const key = Exchange.peer_key(recv.peer_address, packet.msg_id);
        if (server.exchanges.find(key)) |slot_idx| {
            // Duplicate CON — retransmit cached response.
            const cached = server.exchanges.cached_response(slot_idx);
            try server.send_data(cached, recv.peer_address, index);
            return;
        }
        // New request from this peer — they received all prior responses,
        // so evict stale exchanges for this address.
        _ = server.exchanges.evict_peer(addr_key);
    }

    // Critical option rejection (RFC 7252 §5.4.1).
    if (server.hasUnrecognizedCriticalOption(packet.options)) {
        const bad_opt_response = coapz.Packet{
            .kind = if (is_con) .acknowledgement else .non_confirmable,
            .code = .bad_option,
            .msg_id = if (is_con) packet.msg_id else server.nextMsgId(),
            .token = packet.token,
            .options = &.{},
            .payload = &.{},
            .data_buf = &.{},
        };

        const data_wire = server.send_packet(bad_opt_response, recv.peer_address, index) catch |err| {
            switch (err) {
                error.OutOfMemory, error.BufferTooSmall => {
                    if (is_con) server.send_emergency_ack(&raw_header, recv.peer_address, index);
                },
                else => log.err("bad option response send failed: {}", .{err}),
            }
            return;
        };

        if (is_con) {
            const key = Exchange.peer_key(recv.peer_address, packet.msg_id);
            if (server.exchanges.insert(key, addr_key, packet.msg_id, data_wire, server.tick_now_ns) == null) {
                const evicted = server.exchanges.evict_expired(server.tick_now_ns, server.exchange_lifetime_ms);
                if (evicted > 0) {
                    server.last_eviction_ns = server.tick_now_ns;
                    _ = server.exchanges.insert(key, addr_key, packet.msg_id, data_wire, server.tick_now_ns);
                }
            }
        }
        return;
    }

    // For CON requests, provide deferred response context so the handler
    // can call request.deferResponse() for separate (delayed) responses.
    var defer_ctx: ?handler.Request.DeferContext = null;
    if (is_con) {
        if (server.deferred) |*d| {
            defer_ctx = .{
                .pool = d,
                .next_msg_id = server.nextMsgId(),
            };
        }
    }

    const request = handler.Request{
        .packet = packet,
        .peer_address = recv.peer_address,
        .arena = arena,
        .defer_ctx = defer_ctx,
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
        const before = if (server.config.handler_warn_ns > 0) std.time.nanoTimestamp() else 0;
        const result = server.handler_fn(server.handler_context, request);
        if (server.config.handler_warn_ns > 0) {
            const after = std.time.nanoTimestamp();
            const elapsed: u64 = @intCast(@max(0, after - before));
            if (elapsed > server.config.handler_warn_ns) {
                log.warn("slow handler: {d}ms", .{elapsed / std.time.ns_per_ms});
            }
        }
        break :blk result;
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

        const data_wire = server.send_packet(response_packet, recv.peer_address, index) catch |err| {
            switch (err) {
                error.OutOfMemory, error.BufferTooSmall => {
                    log.warn("encoding response failed, sending emergency ACK", .{});
                    if (is_con) server.send_emergency_ack(&raw_header, recv.peer_address, index);
                },
                else => log.err("response send failed: {}", .{err}),
            }
            return;
        };

        // Cache the response for CON dedup.
        if (is_con) {
            const key = Exchange.peer_key(
                recv.peer_address,
                packet.msg_id,
            );
            if (server.exchanges.insert(
                key,
                addr_key,
                packet.msg_id,
                data_wire,
                server.tick_now_ns,
            ) == null) {
                // Try evicting expired entries before giving up.
                const evicted = server.exchanges.evict_expired(server.tick_now_ns, server.exchange_lifetime_ms);
                if (evicted > 0) {
                    server.last_eviction_ns = server.tick_now_ns;
                    _ = server.exchanges.insert(key, addr_key, packet.msg_id, data_wire, server.tick_now_ns);
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
        const data_wire = server.send_packet(ack, recv.peer_address, index) catch |err| {
            switch (err) {
                error.OutOfMemory, error.BufferTooSmall => {
                    log.warn("encoding empty ACK failed, sending emergency ACK", .{});
                    server.send_emergency_ack(&raw_header, recv.peer_address, index);
                },
                else => log.err("ack send failed: {}", .{err}),
            }
            return;
        };

        // Cache the empty ACK too.
        const key = Exchange.peer_key(
            recv.peer_address,
            packet.msg_id,
        );
        if (server.exchanges.insert(
            key,
            addr_key,
            packet.msg_id,
            data_wire,
            server.tick_now_ns,
        ) == null) {
            const evicted = server.exchanges.evict_expired(server.tick_now_ns, server.exchange_lifetime_ms);
            if (evicted > 0) {
                server.last_eviction_ns = server.tick_now_ns;
                _ = server.exchanges.insert(key, addr_key, packet.msg_id, data_wire, server.tick_now_ns);
            } else {
                log.warn("exchange pool full ({d} active), cannot cache", .{server.exchanges.count_active});
            }
        }
    }
}

/// Process a DTLS datagram: may contain multiple records (a flight).
/// Handles handshake, decrypt application data, dispatch to handler.
fn process_dtls_record(
    server: *Server,
    recv: Io.RecvResult,
    index: usize,
) void {
    const psk = server.config.psk.?;
    const tbl = server.dtls_sessions.?;
    const peer = recv.peer_address;

    // Determine epoch from first record header (bytes 3-4 big-endian).
    const record_epoch = if (recv.payload.len >= 5)
        std.mem.readInt(u16, recv.payload[3..5], .big)
    else
        0;

    // Look up existing session.
    var session = tbl.lookup(peer);

    // For epoch 0 records from unknown peers, perform stateless cookie
    // verification before allocating a session. This prevents resource
    // exhaustion from spoofed source addresses (RFC 6347 §4.2.1).
    if (session == null and record_epoch == 0) {
        const record = dtls.Record.decodePlaintext(recv.payload) orelse {
            release_buffer_robust(&server.io, recv.buffer_id);
            server.buffers_outstanding -|= 1;
            log.debug("DTLS: malformed plaintext record", .{});
            return;
        };

        // Only handshake records with a valid cookie can create sessions.
        // All other epoch-0 records from unknown peers are dropped.
        if (record.content_type != .handshake) {
            release_buffer_robust(&server.io, recv.buffer_id);
            server.buffers_outstanding -|= 1;
            log.debug("DTLS: non-handshake epoch-0 from unknown peer, dropping", .{});
            return;
        }

        if (!dtls.Handshake.isClientHelloWithValidCookie(
            record.payload,
            server.dtls_cookie_secret,
            server.dtls_cookie_secret_prev,
            peer,
        )) {
            // No cookie or invalid cookie — send stateless HVR without
            // allocating a session (anti-amplification).
            const buf = server.response_buf(index);
            if (dtls.Handshake.buildStatelessHvr(
                record.payload,
                server.dtls_cookie_secret,
                peer,
                buf,
            )) |hvr| {
                release_buffer_robust(&server.io, recv.buffer_id);
                server.buffers_outstanding -|= 1;
                server.send_data(hvr, peer, index) catch |err| {
                    log.warn("DTLS stateless HVR send failed: {}", .{err});
                };
            } else {
                release_buffer_robust(&server.io, recv.buffer_id);
                server.buffers_outstanding -|= 1;
                log.debug("DTLS: invalid ClientHello, dropping", .{});
            }
            return;
        }

        // Valid cookie — allocate session now.
        session = tbl.allocate(peer, server.tick_now_ns) orelse {
            log.warn("DTLS session table full, dropping packet", .{});
            release_buffer_robust(&server.io, recv.buffer_id);
            server.buffers_outstanding -|= 1;
            return;
        };
    }

    // For non-epoch-0 packets from unknown peers, drop.
    const sess = session orelse {
        release_buffer_robust(&server.io, recv.buffer_id);
        server.buffers_outstanding -|= 1;
        log.debug("DTLS: no session for encrypted record, dropping", .{});
        return;
    };

    // Copy datagram to stack before releasing the recv buffer, so we can
    // iterate through multiple records without the buffer being reused.
    var dgram_buf: [constants.buffer_size_default]u8 = undefined;
    const dgram_len = @min(recv.payload.len, dgram_buf.len);
    @memcpy(dgram_buf[0..dgram_len], recv.payload[0..dgram_len]);
    const dgram = dgram_buf[0..dgram_len];

    release_buffer_robust(&server.io, recv.buffer_id);
    server.buffers_outstanding -|= 1;

    // Iterate all records in the datagram.
    var off: usize = 0;
    while (off < dgram.len) {
        const remaining = dgram[off..];
        if (remaining.len < dtls.types.record_header_len) break;

        const rec_len = std.mem.readInt(u16, remaining[11..13], .big);
        const total_rec = dtls.types.record_header_len + rec_len;
        if (remaining.len < total_rec) break;

        const rec_data = remaining[0..total_rec];
        const rec_epoch = std.mem.readInt(u16, rec_data[3..5], .big);

        off += total_rec;

        if (rec_epoch == 0) {
            const record = dtls.Record.decodePlaintext(rec_data) orelse continue;

            const buf = server.response_buf(index);
            const action = dtls.Handshake.serverProcessMessage(
                sess,
                record.content_type,
                record.payload,
                psk,
                server.dtls_cookie_secret,
                server.dtls_cookie_secret_prev,
                buf,
            );

            switch (action) {
                .send => |data| {
                    tbl.promote(sess, server.tick_now_ns);
                    server.send_data(data, peer, index) catch |err| {
                        log.warn("DTLS handshake send failed: {}", .{err});
                    };
                },
                .established => {
                    tbl.promote(sess, server.tick_now_ns);
                    log.debug("DTLS session established: {any}", .{peer});
                },
                .failed => |desc| {
                    log.debug("DTLS handshake failed: {any}", .{desc});
                    server.send_dtls_alert(sess, .fatal, desc, index, peer);
                    tbl.release(sess);
                    return;
                },
                .none => {},
            }
        } else {
            // Encrypted record — during handshake this is the Finished message;
            // for established sessions this is application_data.
            if (sess.state == .established) {
                var plaintext_buf: [constants.buffer_size_default]u8 = undefined;
                const record = dtls.Record.decodeEncrypted(
                    rec_data,
                    sess.client_write_key,
                    sess.client_write_iv,
                    &sess.replay_window,
                    &sess.read_sequence,
                    &plaintext_buf,
                ) orelse {
                    log.debug("DTLS: decrypt/auth failed", .{});
                    continue;
                };

                tbl.promote(sess, server.tick_now_ns);

                switch (record.content_type) {
                    .application_data => {
                        server.process_dtls_coap(record.payload, sess, peer, index);
                    },
                    .alert => {
                        if (record.payload.len >= 2 and record.payload[0] == @intFromEnum(dtls.types.AlertLevel.fatal)) {
                            log.debug("DTLS: received fatal alert {d}", .{record.payload[1]});
                            tbl.release(sess);
                            return;
                        } else if (record.payload.len >= 2 and record.payload[1] == @intFromEnum(dtls.types.AlertDescription.close_notify)) {
                            log.debug("DTLS: close_notify from peer", .{});
                            tbl.release(sess);
                            return;
                        }
                    },
                    else => {
                        log.debug("DTLS: unexpected content type in encrypted record: {d}", .{@intFromEnum(record.content_type)});
                    },
                }
            } else {
                // Handshaking — encrypted Finished record.
                var plaintext_buf: [constants.buffer_size_default]u8 = undefined;
                const record = dtls.Record.decodeEncrypted(
                    rec_data,
                    sess.client_write_key,
                    sess.client_write_iv,
                    &sess.replay_window,
                    &sess.read_sequence,
                    &plaintext_buf,
                ) orelse {
                    log.debug("DTLS: decrypt/auth failed (handshake)", .{});
                    continue;
                };

                const buf = server.response_buf(index);
                const action = dtls.Handshake.serverProcessMessage(
                    sess,
                    record.content_type,
                    record.payload,
                    psk,
                    server.dtls_cookie_secret,
                    server.dtls_cookie_secret_prev,
                    buf,
                );

                switch (action) {
                    .send => |data| {
                        tbl.promote(sess, server.tick_now_ns);
                        server.send_data(data, peer, index) catch |err| {
                            log.warn("DTLS handshake send failed: {}", .{err});
                        };
                    },
                    .established => {
                        tbl.promote(sess, server.tick_now_ns);
                        log.debug("DTLS session established: {any}", .{peer});
                    },
                    .failed => |desc| {
                        log.debug("DTLS handshake failed: {any}", .{desc});
                        server.send_dtls_alert(sess, .fatal, desc, index, peer);
                        tbl.release(sess);
                        return;
                    },
                    .none => {},
                }
            }
        }
    }
}

/// Parse decrypted application data as CoAP, invoke handler, encrypt and send response.
fn process_dtls_coap(
    server: *Server,
    coap_payload: []const u8,
    session: *dtls.Session.Session,
    peer: std.net.Address,
    index: usize,
) void {
    const arena = server.arena.allocator();

    const packet = coapz.Packet.read(arena, coap_payload) catch |err| {
        log.debug("DTLS: malformed CoAP in application_data: {}", .{err});
        return;
    };

    if (packet.kind == .reset) return;

    const is_con = packet.kind == .confirmable;
    const addr_key = Exchange.addr_hash(peer);

    // CON duplicate detection.
    if (is_con) {
        const key = Exchange.peer_key(peer, packet.msg_id);
        if (server.exchanges.find(key)) |slot_idx| {
            // Duplicate CON — retransmit cached response (already encrypted).
            const cached = server.exchanges.cached_response(slot_idx);
            server.send_data(cached, peer, index) catch {};
            return;
        }
        _ = server.exchanges.evict_peer(addr_key);
    }

    // Critical option rejection (RFC 7252 §5.4.1).
    if (server.hasUnrecognizedCriticalOption(packet.options)) {
        const bad_opt_response = coapz.Packet{
            .kind = if (is_con) .acknowledgement else .non_confirmable,
            .code = .bad_option,
            .msg_id = if (is_con) packet.msg_id else server.nextMsgId(),
            .token = packet.token,
            .options = &.{},
            .payload = &.{},
            .data_buf = &.{},
        };

        const wire = server.send_dtls_packet(session, bad_opt_response, peer, index) catch |err| {
            log.warn("DTLS bad option response failed: {}", .{err});
            return;
        };

        if (is_con) {
            const key = Exchange.peer_key(peer, packet.msg_id);
            if (server.exchanges.insert(key, addr_key, packet.msg_id, wire, server.tick_now_ns) == null) {
                const evicted = server.exchanges.evict_expired(server.tick_now_ns, server.exchange_lifetime_ms);
                if (evicted > 0) {
                    server.last_eviction_ns = server.tick_now_ns;
                    _ = server.exchanges.insert(key, addr_key, packet.msg_id, wire, server.tick_now_ns);
                }
            }
        }
        return;
    }

    var dtls_defer_ctx: ?handler.Request.DeferContext = null;
    if (is_con) {
        if (server.deferred) |*d| {
            dtls_defer_ctx = .{
                .pool = d,
                .next_msg_id = server.nextMsgId(),
            };
        }
    }

    const request = handler.Request{
        .packet = packet,
        .peer_address = peer,
        .arena = arena,
        .is_secure = true,
        .defer_ctx = dtls_defer_ctx,
    };

    const maybe_response = blk: {
        if (server.config.well_known_core) |wkc| {
            if (is_well_known_core(packet)) {
                var cf_buf: [2]u8 = undefined;
                const cf_opt = coapz.Option.content_format(.link_format, &cf_buf);
                const opts = arena.dupe(coapz.Option, &.{cf_opt}) catch return;
                break :blk @as(?handler.Response, .{
                    .code = .content,
                    .options = opts,
                    .payload = wkc,
                });
            }
        }
        const before = if (server.config.handler_warn_ns > 0) std.time.nanoTimestamp() else 0;
        const result = server.handler_fn(server.handler_context, request);
        if (server.config.handler_warn_ns > 0) {
            const after = std.time.nanoTimestamp();
            const elapsed: u64 = @intCast(@max(0, after - before));
            if (elapsed > server.config.handler_warn_ns) {
                log.warn("slow handler: {d}ms", .{elapsed / std.time.ns_per_ms});
            }
        }
        break :blk result;
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

        const wire = server.send_dtls_packet(session, response_packet, peer, index) catch |err| {
            log.warn("DTLS response send failed: {}", .{err});
            return;
        };

        if (is_con) {
            const key = Exchange.peer_key(peer, packet.msg_id);
            if (server.exchanges.insert(key, addr_key, packet.msg_id, wire, server.tick_now_ns) == null) {
                const evicted = server.exchanges.evict_expired(server.tick_now_ns, server.exchange_lifetime_ms);
                if (evicted > 0) {
                    server.last_eviction_ns = server.tick_now_ns;
                    _ = server.exchanges.insert(key, addr_key, packet.msg_id, wire, server.tick_now_ns);
                } else {
                    log.warn("exchange pool full ({d} active), cannot cache DTLS response", .{server.exchanges.count_active});
                }
            }
        }
    } else if (is_con) {
        // Empty ACK for CON with no handler response.
        const ack = coapz.Packet{
            .kind = .acknowledgement,
            .code = .empty,
            .msg_id = packet.msg_id,
            .token = &.{},
            .options = &.{},
            .payload = &.{},
            .data_buf = &.{},
        };
        const wire = server.send_dtls_packet(session, ack, peer, index) catch |err| {
            log.warn("DTLS empty ACK send failed: {}", .{err});
            return;
        };

        const key = Exchange.peer_key(peer, packet.msg_id);
        if (server.exchanges.insert(key, addr_key, packet.msg_id, wire, server.tick_now_ns) == null) {
            const evicted = server.exchanges.evict_expired(server.tick_now_ns, server.exchange_lifetime_ms);
            if (evicted > 0) {
                server.last_eviction_ns = server.tick_now_ns;
                _ = server.exchanges.insert(key, addr_key, packet.msg_id, wire, server.tick_now_ns);
            } else {
                log.warn("exchange pool full ({d} active), cannot cache DTLS response", .{server.exchanges.count_active});
            }
        }
    }
}

/// Encode a CoAP packet, encrypt it as a DTLS application_data record, and send.
/// Returns the encrypted wire data (in the response buffer) for exchange caching.
///
/// Layout: CoAP plaintext is written at buf[29..] (after record_overhead).
/// encodeEncrypted writes header at buf[0..13], explicit nonce at buf[13..21],
/// and ciphertext at buf[21..]. The ciphertext region overlaps the plaintext
/// start (buf[29]) only after the first 8 bytes of ciphertext. This is safe
/// because CCM computes the MAC over plaintext first, then ctrEncrypt processes
/// 16-byte blocks — each block's read completes before overlapping writes occur.
fn send_dtls_packet(
    server: *Server,
    session: *dtls.Session.Session,
    pkt: coapz.Packet,
    peer: std.net.Address,
    index: usize,
) ![]const u8 {
    const buf = server.response_buf(index);

    // Encode CoAP into the tail of the buffer (after DTLS overhead).
    const overhead = dtls.types.record_overhead;
    if (buf.len <= overhead) return error.BufferTooSmall;
    const coap_buf = buf[overhead..];
    const coap_wire = pkt.writeBuf(coap_buf) catch |err| return err;

    // Encrypt into the buffer from the start.
    const encrypted = dtls.Record.encodeEncrypted(
        .application_data,
        coap_wire,
        session.server_write_key,
        session.server_write_iv,
        session.write_epoch,
        &session.write_sequence,
        buf,
    );

    try server.send_raw(encrypted, peer, index);
    return encrypted;
}

/// Send a DTLS alert record to a peer. For plaintext (epoch 0) alerts.
fn send_dtls_alert(
    server: *Server,
    session: *dtls.Session.Session,
    level: dtls.types.AlertLevel,
    desc: dtls.types.AlertDescription,
    index: usize,
    peer: std.net.Address,
) void {
    var alert_payload: [2]u8 = undefined;
    dtls.types.encodeAlert(level, desc, &alert_payload);

    const buf = server.response_buf(index);
    const record = dtls.Record.encodePlaintext(
        .alert,
        &alert_payload,
        &session.write_sequence,
        buf,
    );

    server.send_data(record, peer, index) catch {};
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

/// Drain deferred response queue and retransmit pending separate CONs.
fn drainDeferred(server: *Server) void {
    const pool = &(server.deferred orelse return);
    if (pool.count_active == 0) return;

    const batch: usize = @min(constants.completion_batch_max, server.config.buffer_count);

    // 1. Drain response queue — send new CON responses.
    var drain_buf: [64]u16 = undefined;
    const drained = pool.drainQueue(&drain_buf);
    for (drained) |slot_idx| {
        const slot = &pool.slots[slot_idx];
        const data = pool.responseBuf(slot_idx)[0..slot.response_length];
        server.send_data(data, slot.peer_address, @as(usize, slot_idx) % batch) catch {
            pool.release(slot_idx);
            continue;
        };
        slot.state.store(.sent, .release);
        const timeout_ms: i64 = @intCast(constants.ack_timeout_ms);
        slot.retransmit_deadline_ns = server.tick_now_ns + timeout_ms * std.time.ns_per_ms;
        slot.retransmit_count = 0;
    }

    // 2. Scan for retransmit deadlines on already-sent responses.
    for (pool.slots, 0..) |*slot, i| {
        if (slot.state.load(.acquire) != .sent) continue;
        if (server.tick_now_ns < slot.retransmit_deadline_ns) continue;

        slot.retransmit_count += 1;
        if (slot.retransmit_count > constants.max_retransmit) {
            pool.release(@intCast(i));
            continue;
        }

        const data = pool.responseBuf(@intCast(i))[0..slot.response_length];
        server.send_data(data, slot.peer_address, i % batch) catch continue;

        const backoff: u5 = @intCast(@min(slot.retransmit_count, 16));
        const timeout_ms: i64 = @as(i64, constants.ack_timeout_ms) << backoff;
        slot.retransmit_deadline_ns = server.tick_now_ns + timeout_ms * std.time.ns_per_ms;
    }
}

/// Recompute load level based on pool utilization.
fn update_load_level(server: *Server) void {
    const buf_pct: u16 = if (server.config.buffer_count > 0)
        (server.buffers_peak *| 100) / server.config.buffer_count
    else
        0;
    server.buffers_peak = 0;
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

/// Get the response buffer slot for a given CQE index.
fn response_buf(server: *Server, index: usize) []u8 {
    const offset_buf = index * server.config.buffer_size;
    return server.buffer_response[offset_buf..][0..server.config.buffer_size];
}

/// Encode a packet directly into the response buffer and queue it for sending.
fn send_packet(
    server: *Server,
    pkt: coapz.Packet,
    peer_address: std.net.Address,
    index: usize,
) ![]const u8 {
    const buf = server.response_buf(index);
    const data = pkt.writeBuf(buf) catch |err| return err;
    try server.send_raw(data, peer_address, index);
    return data;
}

/// Queue pre-encoded data from the response buffer (or other source) for sending.
fn send_data(
    server: *Server,
    data: []const u8,
    peer_address: std.net.Address,
    index: usize,
) !void {
    const batch: usize = @min(constants.completion_batch_max, server.config.buffer_count);
    if (index >= batch) return error.InvalidIndex;

    if (data.len > server.config.buffer_size) {
        log.err("response too large: {d} > {d}", .{
            data.len,
            server.config.buffer_size,
        });
        return;
    }

    // If data is not already in the response buffer, copy it in.
    const offset_buf = index * server.config.buffer_size;
    const slot_start = @intFromPtr(server.buffer_response.ptr) + offset_buf;
    const data_start = @intFromPtr(data.ptr);
    if (data_start < slot_start or data_start >= slot_start + server.config.buffer_size) {
        const slot = server.buffer_response[offset_buf..][0..data.len];
        @memcpy(slot, data);
        return server.send_raw(slot, peer_address, index);
    }

    return server.send_raw(data, peer_address, index);
}

/// Queue a sendmsg for data already positioned correctly.
fn send_raw(
    server: *Server,
    data: []const u8,
    peer_address: std.net.Address,
    index: usize,
) !void {
    server.addrs_response[index] = peer_address;

    server.iovs_response[index] = .{
        .base = @ptrCast(@constCast(data.ptr)),
        .len = data.len,
    };

    server.msgs_response[index] = .{
        .name = @ptrCast(&server.addrs_response[index]),
        .namelen = peer_address.getOsSockLen(),
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

/// Returns true if the option kind matches a named coapz standard option.
fn isRecognizedOption(kind: coapz.OptionKind) bool {
    return switch (kind) {
        .unknown => false,
        .if_match, .uri_host, .etag, .if_none_match, .observe,
        .uri_port, .location_path, .oscore, .uri_path,
        .content_format, .max_age, .uri_query, .accept,
        .location_query, .block2, .block1, .size2,
        .proxy_uri, .proxy_scheme, .size1, .no_response,
        => true,
        _ => false,
    };
}

/// Check if any option in the packet is an unrecognized critical option.
fn hasUnrecognizedCriticalOption(
    server: *const Server,
    options: []const coapz.Option,
) bool {
    for (options) |opt| {
        const num = @intFromEnum(opt.kind);
        if (num & 1 == 0) continue; // elective
        if (isRecognizedOption(opt.kind)) continue;
        if (std.mem.indexOfScalar(u16, server.config.recognized_options, num) != null) continue;
        return true;
    }
    return false;
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

test "cpu_affinity rejects empty list" {
    const empty: []const u16 = &.{};
    try testing.expectError(error.InvalidConfig, Server.init(
        testing.allocator,
        .{ .port = 19701, .buffer_count = 4, .buffer_size = 256, .cpu_affinity = empty },
        echo_handler,
    ));
}

test "CON with unknown critical option returns 4.02 Bad Option" {
    const port: u16 = 19710;
    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, echo_handler);
    defer server.deinit();
    try setup_for_test(&server);

    // Option number 99 is odd (critical) and not in coapz.OptionKind.
    const request_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0xCC01,
        .token = &.{0x01},
        .options = &.{
            .{ .kind = @enumFromInt(99), .value = "x" },
        },
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

    try testing.expectEqual(.acknowledgement, response.kind);
    try testing.expectEqual(.bad_option, response.code);
    try testing.expectEqual(@as(u16, 0xCC01), response.msg_id);
    try testing.expectEqualSlices(u8, &.{0x01}, response.token);
}

test "NON with unknown critical option returns 4.02 Bad Option" {
    const port: u16 = 19711;
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
        .msg_id = 0xCC02,
        .token = &.{0x02},
        .options = &.{
            .{ .kind = @enumFromInt(99), .value = "x" },
        },
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
    try testing.expectEqual(.bad_option, response.code);
    try testing.expectEqualSlices(u8, &.{0x02}, response.token);
}

test "known critical options pass through to handler" {
    const port: u16 = 19712;
    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, echo_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0xCC03,
        .token = &.{0x03},
        .options = &.{
            .{ .kind = .uri_path, .value = "test" },
        },
        .payload = "body",
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
    try testing.expectEqualSlices(u8, "body", response.payload);
}

test "unknown elective option passes through to handler" {
    const port: u16 = 19713;
    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
    }, echo_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0xCC04,
        .token = &.{0x04},
        .options = &.{
            .{ .kind = @enumFromInt(100), .value = "ignored" },
        },
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

    try testing.expectEqual(.content, response.code);
    try testing.expectEqualSlices(u8, "data", response.payload);
}

test "recognized_options allows custom critical options" {
    const port: u16 = 19714;
    const recognized: []const u16 = &.{99};
    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 8,
        .buffer_size = 1280,
        .recognized_options = recognized,
    }, echo_handler);
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0xCC05,
        .token = &.{0x05},
        .options = &.{
            .{ .kind = @enumFromInt(99), .value = "custom" },
        },
        .payload = "ok",
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
    try testing.expectEqualSlices(u8, "ok", response.payload);
}

fn test_client_ip(host: []const u8, port: u16) !posix.socket_t {
    const dest = try std.net.Address.parseIp(host, port);
    const fd = try posix.socket(dest.any.family, posix.SOCK.DGRAM, 0);
    const timeout = posix.timeval{ .sec = 1, .usec = 0 };
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    try posix.connect(fd, &dest.any, dest.getOsSockLen());
    return fd;
}

test "round-trip: NON echo via IPv6 loopback" {
    const port: u16 = 19715;

    var server = Server.init(testing.allocator, .{
        .port = port,
        .bind_address = "::1",
        .buffer_count = 8,
        .buffer_size = 1280,
        .rate_limit_ip_count = 0,
    }, echo_handler) catch return;
    defer server.deinit();
    try setup_for_test(&server);

    const request_packet = coapz.Packet{
        .kind = .non_confirmable,
        .code = .get,
        .msg_id = 0x1234,
        .token = &.{ 0xAA, 0xBB },
        .options = &.{},
        .payload = "ipv6",
        .data_buf = &.{},
    };
    const wire = try request_packet.write(testing.allocator);
    defer testing.allocator.free(wire);

    const client_fd = test_client_ip("::1", port) catch return;
    defer posix.close(client_fd);

    const raw = try send_tick_recv(&server, client_fd, wire);
    defer testing.allocator.free(raw);

    const response = try coapz.Packet.read(testing.allocator, raw);
    defer response.deinit(testing.allocator);

    try testing.expectEqual(.content, response.code);
    try testing.expectEqualSlices(u8, "ipv6", response.payload);
}
