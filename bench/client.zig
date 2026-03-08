/// coapd benchmark client.
///
/// Sends CoAP requests using a pipelined sliding window and measures
/// throughput and latency. Forks an embedded echo server by default.
/// When --threads N is used, spawns N client threads (each with its own
/// socket/source port) so SO_REUSEPORT distributes across server threads.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const coapz = @import("coapz");
const coapd = @import("coapd");

const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 5683,
    request_count: u32 = 100_000,
    payload_size: u16 = 0,
    warmup_count: u32 = 1_000,
    use_confirmable: bool = false,
    window_size: u16 = 256,
    embedded_server: bool = true,
    thread_count: u16 = 1,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = parse_args();

    // Fork an echo server process for CPU isolation.
    var server_pid: ?posix.pid_t = null;
    defer if (server_pid) |pid| {
        posix.kill(pid, posix.SIG.TERM) catch {};
        _ = posix.waitpid(pid, 0);
    };

    if (config.embedded_server) {
        server_pid = try fork_server(config.port, config.thread_count);
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    // Build the request template.
    const payload = try allocator.alloc(u8, config.payload_size);
    defer allocator.free(payload);
    @memset(payload, 'x');

    const kind: coapz.MessageKind = if (config.use_confirmable)
        .confirmable
    else
        .non_confirmable;

    const template = coapz.Packet{
        .kind = kind,
        .code = .get,
        .msg_id = 0,
        .token = &.{ 0x00, 0x00 },
        .options = &.{},
        .payload = payload,
        .data_buf = &.{},
    };
    const template_wire = try template.write(allocator);
    defer allocator.free(template_wire);

    // Connectivity probe (single socket).
    if (!config.embedded_server) {
        const probe_fd = try make_client_socket(config.host, config.port);
        defer posix.close(probe_fd);
        const probe = [_]u8{ 0x40, 0x00, 0x00, 0x00 };
        _ = posix.send(probe_fd, &probe, 0) catch {};
        var tmp: [64]u8 = undefined;
        _ = posix.recv(probe_fd, &tmp, 0) catch |err| {
            if (err == error.ConnectionRefused) {
                std.debug.print(
                    "error: no server on {s}:{d}\n",
                    .{ config.host, config.port },
                );
                std.process.exit(1);
            }
        };
    }

    // Warmup (single socket).
    if (config.warmup_count > 0) {
        std.debug.print(
            "warming up ({d} requests)...\n",
            .{config.warmup_count},
        );
        const warmup_fd = try make_client_socket(config.host, config.port);
        defer posix.close(warmup_fd);
        _ = try run_bench(
            allocator,
            warmup_fd,
            template_wire,
            config.warmup_count,
            config.window_size,
            false,
        );
    }

    // Benchmark.
    const n_clients = config.thread_count;
    std.debug.print(
        "benchmarking {d} requests (payload={d}B, {s}, window={d}, {d} client{s})...\n",
        .{
            config.request_count,
            config.payload_size,
            if (config.use_confirmable) "CON" else "NON",
            config.window_size,
            n_clients,
            if (n_clients > 1) "s" else "",
        },
    );

    const extra: u16 = n_clients -| 1;
    const threads = try allocator.alloc(std.Thread, extra);
    defer allocator.free(threads);

    const per_thread = config.request_count / n_clients;
    const remainder = config.request_count % n_clients;

    const worker_results = try allocator.alloc(WorkerResult, n_clients);
    defer {
        for (worker_results) |*wr| {
            if (wr.result) |*r| {
                if (r.latencies.len > 0)
                    allocator.free(r.latencies);
            }
        }
        allocator.free(worker_results);
    }

    const start = std.time.nanoTimestamp();

    // Spawn extra client threads.
    for (0..extra) |i| {
        worker_results[i] = .{};
        threads[i] = try std.Thread.spawn(.{}, client_worker, .{
            allocator,
            config,
            template_wire,
            per_thread,
            &worker_results[i],
        });
    }

    // Main thread runs its share (gets the remainder too).
    const main_count = per_thread + remainder;
    const main_fd = try make_client_socket(config.host, config.port);
    defer posix.close(main_fd);

    const main_result = try run_bench(
        allocator,
        main_fd,
        template_wire,
        main_count,
        config.window_size,
        true,
    );
    worker_results[extra] = .{ .result = main_result };

    // Join all threads.
    for (threads) |t| {
        t.join();
    }

    const elapsed_ns = std.time.nanoTimestamp() - start;

    // Aggregate results.
    var agg = BenchResult{
        .sent = 0,
        .received = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .errors = 0,
        .latency_min_ns = std.math.maxInt(i128),
        .latency_max_ns = 0,
        .latency_sum_ns = 0,
        .latencies = main_result.latencies,
        .latency_count = main_result.latency_count,
    };

    // Merge latencies into a single sorted array for percentiles.
    // Count total latencies first.
    var total_latencies: u64 = 0;
    for (worker_results) |wr| {
        if (wr.result) |r| {
            total_latencies += r.latency_count;
        }
    }

    const merged_latencies = if (total_latencies > 0)
        try allocator.alloc(i64, total_latencies)
    else
        @as([]i64, &.{});
    defer if (total_latencies > 0) allocator.free(merged_latencies);

    var merge_off: u64 = 0;
    for (worker_results) |wr| {
        if (wr.result) |r| {
            agg.sent += r.sent;
            agg.received += r.received;
            agg.bytes_sent += r.bytes_sent;
            agg.bytes_received += r.bytes_received;
            agg.errors += r.errors;
            agg.latency_sum_ns += r.latency_sum_ns;
            if (r.received > 0 and r.latency_min_ns < agg.latency_min_ns)
                agg.latency_min_ns = r.latency_min_ns;
            if (r.latency_max_ns > agg.latency_max_ns)
                agg.latency_max_ns = r.latency_max_ns;
            if (r.latency_count > 0) {
                @memcpy(
                    merged_latencies[merge_off..][0..r.latency_count],
                    r.latencies[0..r.latency_count],
                );
                merge_off += r.latency_count;
            }
        }
    }

    agg.latencies = merged_latencies;
    agg.latency_count = @intCast(total_latencies);

    report(config, &agg, elapsed_ns);
}

const WorkerResult = struct {
    result: ?BenchResult = null,
};

fn client_worker(
    allocator: std.mem.Allocator,
    config: Config,
    template_wire: []const u8,
    count: u32,
    out: *WorkerResult,
) void {
    const fd = make_client_socket(config.host, config.port) catch return;
    defer posix.close(fd);

    out.result = run_bench(
        allocator,
        fd,
        template_wire,
        count,
        config.window_size,
        true,
    ) catch return;
}

fn make_client_socket(host: []const u8, port: u16) !posix.socket_t {
    const dest = try std.net.Address.parseIp(host, port);
    const fd = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        0,
    );
    errdefer posix.close(fd);
    try posix.connect(fd, &dest.any, dest.getOsSockLen());

    // Tune socket buffers.
    const buf_size = std.mem.toBytes(@as(c_int, 4 * 1024 * 1024));
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &buf_size) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &buf_size) catch {};

    // Receive timeout for draining at end of benchmark.
    const timeout = posix.timeval{ .sec = 0, .usec = 100_000 };
    try posix.setsockopt(
        fd,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        std.mem.asBytes(&timeout),
    );

    return fd;
}

fn echo_handler(request: coapd.Request) ?coapd.Response {
    return .{ .payload = request.packet.payload };
}

fn fork_server(port: u16, thread_count: u16) !posix.pid_t {
    const pid = try posix.fork();
    if (pid == 0) {
        // Child process: run the echo server.
        var server = coapd.Server.init(
            std.heap.page_allocator,
            .{
                .port = port,
                .buffer_count = 256,
                .buffer_size = 1280,
                .thread_count = thread_count,
            },
            echo_handler,
        ) catch std.process.exit(1);
        server.run() catch std.process.exit(1);
        unreachable;
    }
    return pid;
}

const BenchResult = struct {
    sent: u64,
    received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    errors: u64,
    latency_min_ns: i128,
    latency_max_ns: i128,
    latency_sum_ns: i128,
    latencies: []i64,
    latency_count: u32,
};

fn run_bench(
    allocator: std.mem.Allocator,
    fd: posix.socket_t,
    template: []const u8,
    count: u32,
    window: u16,
    collect_latencies: bool,
) !BenchResult {
    std.debug.assert(window > 0);
    std.debug.assert(template.len >= 6);

    const latencies: []i64 = if (collect_latencies)
        try allocator.alloc(i64, count)
    else
        &.{};

    var result = BenchResult{
        .sent = 0,
        .received = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .errors = 0,
        .latency_min_ns = std.math.maxInt(i128),
        .latency_max_ns = 0,
        .latency_sum_ns = 0,
        .latencies = latencies,
        .latency_count = 0,
    };

    const timestamps = try allocator.alloc(i128, window);
    defer allocator.free(timestamps);
    @memset(timestamps, 0);

    var send_buf: [1280]u8 = undefined;
    std.debug.assert(template.len <= send_buf.len);
    @memcpy(send_buf[0..template.len], template);

    var recv_buf: [1280]u8 = undefined;
    var msg_id: u16 = 0;
    var in_flight: u32 = 0;
    var total_sent: u32 = 0;
    var consecutive_timeouts: u32 = 0;

    while (result.received + result.errors < count) {
        // Fill the send window.
        while (in_flight < window and total_sent < count) {
            const id_hi: u8 = @intCast(msg_id >> 8);
            const id_lo: u8 = @intCast(msg_id & 0xFF);
            send_buf[2] = id_hi;
            send_buf[3] = id_lo;
            send_buf[4] = id_hi;
            send_buf[5] = id_lo;

            timestamps[msg_id % window] = std.time.nanoTimestamp();

            _ = posix.send(fd, send_buf[0..template.len], 0) catch {
                result.errors += 1;
                total_sent += 1;
                msg_id +%= 1;
                continue;
            };

            result.sent += 1;
            result.bytes_sent += template.len;
            total_sent += 1;
            in_flight += 1;
            msg_id +%= 1;
        }

        if (in_flight == 0) {
            break;
        }

        // Receive one response (blocks up to SO_RCVTIMEO).
        const n = posix.recv(fd, &recv_buf, 0) catch |err| {
            if (err == error.WouldBlock) {
                consecutive_timeouts += 1;
                if (total_sent >= count and consecutive_timeouts >= 3) {
                    result.errors += @intCast(in_flight);
                    break;
                }
                continue;
            }
            result.errors += 1;
            if (in_flight > 0) {
                in_flight -= 1;
            }
            continue;
        };

        consecutive_timeouts = 0;
        in_flight -= 1;
        result.received += 1;
        result.bytes_received += n;

        // Track latency via token matching.
        if (n >= 6 and (recv_buf[0] & 0x0F) >= 2) {
            const token: u16 = @as(u16, recv_buf[4]) << 8 | recv_buf[5];
            const slot = token % window;
            const ts = timestamps[slot];
            if (ts > 0) {
                const latency = std.time.nanoTimestamp() - ts;
                result.latency_sum_ns += latency;
                if (latency < result.latency_min_ns) {
                    result.latency_min_ns = latency;
                }
                if (latency > result.latency_max_ns) {
                    result.latency_max_ns = latency;
                }
                if (collect_latencies and
                    result.latency_count < count)
                {
                    result.latencies[result.latency_count] =
                        @intCast(latency);
                    result.latency_count += 1;
                }
            }
        }
    }

    return result;
}

fn percentile_us(sorted: []i64, p: f64) f64 {
    if (sorted.len == 0) return 0;
    const idx: usize = @min(
        @as(usize, @intFromFloat(
            @as(f64, @floatFromInt(sorted.len)) * p,
        )),
        sorted.len - 1,
    );
    return @as(f64, @floatFromInt(sorted[idx])) / 1000.0;
}

fn report(config: Config, result: *BenchResult, elapsed_ns: i128) void {
    const elapsed_ms: f64 = @as(f64, @floatFromInt(elapsed_ns)) / 1e6;
    const elapsed_s: f64 = elapsed_ms / 1000.0;
    const rps: f64 = if (elapsed_s > 0)
        @as(f64, @floatFromInt(result.sent)) / elapsed_s
    else
        0;

    const avg_latency_us: f64 = if (result.received > 0)
        @as(f64, @floatFromInt(result.latency_sum_ns)) /
            @as(f64, @floatFromInt(result.received)) / 1000.0
    else
        0;
    const min_us: f64 = if (result.received > 0)
        @as(f64, @floatFromInt(result.latency_min_ns)) / 1000.0
    else
        0;
    const max_us: f64 = if (result.received > 0)
        @as(f64, @floatFromInt(result.latency_max_ns)) / 1000.0
    else
        0;

    // Sort latencies for percentile computation.
    const sorted = result.latencies[0..result.latency_count];
    std.mem.sortUnstable(i64, sorted, {}, std.sort.asc(i64));

    const p50 = percentile_us(sorted, 0.50);
    const p99 = percentile_us(sorted, 0.99);
    const p999 = percentile_us(sorted, 0.999);

    std.debug.print(
        \\
        \\── coapd benchmark results ──
        \\  target:     {s}:{d}
        \\  requests:   {d} sent, {d} received ({d:.1}% loss)
        \\  throughput: {d:.0} req/s
        \\  elapsed:    {d:.1} ms
        \\  latency:    avg={d:.1}µs min={d:.1}µs max={d:.1}µs
        \\  percentiles: p50={d:.1}µs p99={d:.1}µs p99.9={d:.1}µs
        \\  bytes:      {d} sent, {d} received
        \\  window:     {d}
        \\  threads:    {d} server, {d} client
        \\
    , .{
        config.host,
        config.port,
        result.sent,
        result.received,
        if (result.sent > 0)
            (1.0 - @as(f64, @floatFromInt(result.received)) /
                @as(f64, @floatFromInt(result.sent))) * 100.0
        else
            0.0,
        rps,
        elapsed_ms,
        avg_latency_us,
        min_us,
        max_us,
        p50,
        p99,
        p999,
        result.bytes_sent,
        result.bytes_received,
        config.window_size,
        config.thread_count,
        config.thread_count,
    });
}

fn parse_args() Config {
    var config = Config{};
    var args = std.process.args();
    _ = args.next();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--host")) {
            config.host = args.next() orelse "127.0.0.1";
        } else if (std.mem.eql(u8, arg, "--port")) {
            const val = args.next() orelse "5683";
            config.port = std.fmt.parseInt(u16, val, 10) catch 5683;
        } else if (std.mem.eql(u8, arg, "--count")) {
            const val = args.next() orelse "100000";
            config.request_count = std.fmt.parseInt(
                u32,
                val,
                10,
            ) catch 100_000;
        } else if (std.mem.eql(u8, arg, "--payload")) {
            const val = args.next() orelse "0";
            config.payload_size = std.fmt.parseInt(
                u16,
                val,
                10,
            ) catch 0;
        } else if (std.mem.eql(u8, arg, "--con")) {
            config.use_confirmable = true;
        } else if (std.mem.eql(u8, arg, "--warmup")) {
            const val = args.next() orelse "1000";
            config.warmup_count = std.fmt.parseInt(
                u32,
                val,
                10,
            ) catch 1_000;
        } else if (std.mem.eql(u8, arg, "--window")) {
            const val = args.next() orelse "256";
            config.window_size = std.fmt.parseInt(
                u16,
                val,
                10,
            ) catch 256;
        } else if (std.mem.eql(u8, arg, "--no-server")) {
            config.embedded_server = false;
        } else if (std.mem.eql(u8, arg, "--threads")) {
            const val = args.next() orelse "1";
            config.thread_count = std.fmt.parseInt(
                u16,
                val,
                10,
            ) catch 1;
        }
    }

    return config;
}
