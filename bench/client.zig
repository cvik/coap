/// CoAP benchmark suite.
///
/// Runs a matrix of scenarios (plain/DTLS × CON/NON × 1/N threads × payload
/// sizes) and prints a compact summary table. Forks embedded echo servers
/// as needed, grouped by (thread_count, use_dtls) to minimize restarts.
const std = @import("std");
const posix = std.posix;
const coapz = @import("coapz");
const coap = @import("coap");

const bench_psk: coap.Psk = .{
    .identity = "bench",
    .key = "0123456789abcdef",
};

// ── Types ──────────────────────────────────────────────────────────────

const SuiteConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 5683,
    warmup_count: u32 = 1_000,
    window_size: u16 = 256,
    embedded_server: bool = true,
    thread_count: u16 = 0, // 0 = nproc
    count_override: ?u32 = null,
    filter_plain: bool = true,
    filter_dtls: bool = true,
    filter_con: bool = true,
    filter_non: bool = true,
    filter_single: bool = true,
    filter_multi: bool = true,
};

const Scenario = struct {
    label: []const u8,
    use_dtls: bool,
    use_confirmable: bool,
    multi_thread: bool,
    payload_size: u16,
    request_count: u32,
};

const ScenarioResult = struct {
    rps: f64,
    p50_us: f64,
    p99_us: f64,
    p999_us: f64,
    errors: u64,
};

const ServerGroup = struct {
    use_dtls: bool,
    thread_count: u16,
};

const scenario_templates = [_]Scenario{
    .{ .label = "Plain NON  1T     0B", .use_dtls = false, .use_confirmable = false, .multi_thread = false, .payload_size = 0, .request_count = 100_000 },
    .{ .label = "Plain NON  1T   100B", .use_dtls = false, .use_confirmable = false, .multi_thread = false, .payload_size = 100, .request_count = 100_000 },
    .{ .label = "Plain NON  1T  1000B", .use_dtls = false, .use_confirmable = false, .multi_thread = false, .payload_size = 1000, .request_count = 100_000 },
    .{ .label = "Plain CON  1T     0B", .use_dtls = false, .use_confirmable = true, .multi_thread = false, .payload_size = 0, .request_count = 100_000 },
    .{ .label = "Plain CON  1T   100B", .use_dtls = false, .use_confirmable = true, .multi_thread = false, .payload_size = 100, .request_count = 100_000 },
    .{ .label = "Plain CON  1T  1000B", .use_dtls = false, .use_confirmable = true, .multi_thread = false, .payload_size = 1000, .request_count = 100_000 },
    .{ .label = "Plain NON ##T     0B", .use_dtls = false, .use_confirmable = false, .multi_thread = true, .payload_size = 0, .request_count = 100_000 },
    .{ .label = "Plain NON ##T   100B", .use_dtls = false, .use_confirmable = false, .multi_thread = true, .payload_size = 100, .request_count = 100_000 },
    .{ .label = "Plain NON ##T  1000B", .use_dtls = false, .use_confirmable = false, .multi_thread = true, .payload_size = 1000, .request_count = 100_000 },
    .{ .label = "Plain CON ##T     0B", .use_dtls = false, .use_confirmable = true, .multi_thread = true, .payload_size = 0, .request_count = 100_000 },
    .{ .label = "Plain CON ##T   100B", .use_dtls = false, .use_confirmable = true, .multi_thread = true, .payload_size = 100, .request_count = 100_000 },
    .{ .label = "Plain CON ##T  1000B", .use_dtls = false, .use_confirmable = true, .multi_thread = true, .payload_size = 1000, .request_count = 100_000 },
    .{ .label = "DTLS  CON  1T     0B", .use_dtls = true, .use_confirmable = true, .multi_thread = false, .payload_size = 0, .request_count = 25_000 },
    .{ .label = "DTLS  CON  1T   100B", .use_dtls = true, .use_confirmable = true, .multi_thread = false, .payload_size = 100, .request_count = 25_000 },
    .{ .label = "DTLS  CON  1T  1000B", .use_dtls = true, .use_confirmable = true, .multi_thread = false, .payload_size = 1000, .request_count = 25_000 },
    .{ .label = "DTLS  CON ##T     0B", .use_dtls = true, .use_confirmable = true, .multi_thread = true, .payload_size = 0, .request_count = 25_000 },
    .{ .label = "DTLS  CON ##T   100B", .use_dtls = true, .use_confirmable = true, .multi_thread = true, .payload_size = 100, .request_count = 25_000 },
    .{ .label = "DTLS  CON ##T  1000B", .use_dtls = true, .use_confirmable = true, .multi_thread = true, .payload_size = 1000, .request_count = 25_000 },
};

// ── Main ───────────────────────────────────────────────────────────────

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = parse_args();
    const cpu_count: u16 = if (config.thread_count > 0)
        config.thread_count
    else
        @intCast(@min(std.Thread.getCpuCount() catch 1, std.math.maxInt(u16)));

    var scenarios: [scenario_templates.len]?Scenario = .{null} ** scenario_templates.len;
    var total: u16 = 0;
    for (scenario_templates, 0..) |tmpl, i| {
        if (tmpl.use_dtls and !config.filter_dtls) continue;
        if (!tmpl.use_dtls and !config.filter_plain) continue;
        if (tmpl.use_confirmable and !config.filter_con) continue;
        if (!tmpl.use_confirmable and !config.filter_non) continue;
        if (tmpl.multi_thread and !config.filter_multi) continue;
        if (!tmpl.multi_thread and !config.filter_single) continue;
        var s = tmpl;
        if (config.count_override) |c| s.request_count = c;
        scenarios[i] = s;
        total += 1;
    }

    if (total == 0) {
        std.debug.print("warning: no scenarios match the given filters\n", .{});
        return;
    }

    std.debug.print("── benchmark suite ({d} scenarios, {d} CPUs) ──\n\n", .{ total, cpu_count });

    var results: [scenario_templates.len]?ScenarioResult = .{null} ** scenario_templates.len;
    var current_group: ?ServerGroup = null;
    var server_pid: ?posix.pid_t = null;
    var scenario_num: u16 = 0;

    defer kill_server(&server_pid);

    for (scenarios, 0..) |maybe_scenario, i| {
        const s = maybe_scenario orelse continue;
        scenario_num += 1;
        const tc = if (s.multi_thread) cpu_count else 1;
        const group = ServerGroup{ .use_dtls = s.use_dtls, .thread_count = tc };
        const port = if (s.use_dtls and config.port == 5683) @as(u16, 5684) else config.port;

        if (config.embedded_server) {
            const need_restart = if (current_group) |cur|
                cur.use_dtls != group.use_dtls or cur.thread_count != group.thread_count
            else
                true;

            if (need_restart) {
                kill_server(&server_pid);
                const psk: ?coap.Psk = if (s.use_dtls) bench_psk else null;
                server_pid = try fork_server(port, tc, psk);
                std.Thread.sleep(150 * std.time.ns_per_ms);
                current_group = group;
            }
        }

        const label = format_label(s.label, tc);
        std.debug.print("[{d:>2}/{d}] {s} ... ", .{ scenario_num, total, &label });

        const result = if (s.use_dtls)
            try run_scenario_dtls(allocator, config, s, tc, port)
        else
            try run_scenario_plain(allocator, config, s, tc, port);

        results[i] = result;
        std.debug.print("{d:>10} req/s\n", .{@as(u64, @intFromFloat(result.rps))});
    }

    std.debug.print("\n", .{});
    print_summary(cpu_count, &results, &scenarios);
}

// ── Plain UDP scenario ─────────────────────────────────────────────────

fn run_scenario_plain(
    allocator: std.mem.Allocator,
    config: SuiteConfig,
    s: Scenario,
    tc: u16,
    port: u16,
) !ScenarioResult {
    const count = s.request_count;

    const payload = try allocator.alloc(u8, s.payload_size);
    defer allocator.free(payload);
    @memset(payload, 'x');

    const kind: coapz.MessageKind = if (s.use_confirmable) .confirmable else .non_confirmable;
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

    // Warmup.
    if (config.warmup_count > 0) {
        const fd = try make_client_socket(config.host, port);
        defer posix.close(fd);
        _ = try run_bench(allocator, fd, template_wire, config.warmup_count, config.window_size, false);
    }

    const extra: u16 = tc -| 1;
    const threads = try allocator.alloc(std.Thread, extra);
    defer allocator.free(threads);

    const per_thread = count / tc;
    const remainder = count % tc;

    const worker_results = try allocator.alloc(PlainWorkerResult, tc);
    defer {
        for (worker_results) |*wr| {
            if (wr.result) |*r| {
                if (r.latencies.len > 0) allocator.free(r.latencies);
            }
        }
        allocator.free(worker_results);
    }

    const start = std.time.nanoTimestamp();

    for (0..extra) |j| {
        worker_results[j] = .{};
        threads[j] = try std.Thread.spawn(.{}, plain_worker, .{
            allocator, config.host, port, template_wire, per_thread, config.window_size, &worker_results[j],
        });
    }

    const main_fd = try make_client_socket(config.host, port);
    defer posix.close(main_fd);
    const main_result = try run_bench(allocator, main_fd, template_wire, per_thread + remainder, config.window_size, true);
    worker_results[extra] = .{ .result = main_result };

    for (threads) |t| t.join();

    const elapsed_ns = std.time.nanoTimestamp() - start;
    return aggregate_plain(allocator, worker_results, elapsed_ns);
}

const PlainWorkerResult = struct {
    result: ?BenchResult = null,
};

fn plain_worker(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    template_wire: []const u8,
    count: u32,
    window_size: u16,
    out: *PlainWorkerResult,
) void {
    const fd = make_client_socket(host, port) catch return;
    defer posix.close(fd);
    out.result = run_bench(allocator, fd, template_wire, count, window_size, true) catch return;
}

fn aggregate_plain(allocator: std.mem.Allocator, worker_results: []PlainWorkerResult, elapsed_ns: i128) !ScenarioResult {
    var total_sent: u64 = 0;
    var total_errors: u64 = 0;
    var total_lat_count: u64 = 0;

    for (worker_results) |wr| {
        if (wr.result) |r| {
            total_sent += r.sent;
            total_errors += r.errors;
            total_lat_count += r.latency_count;
        }
    }

    const merged = if (total_lat_count > 0)
        try allocator.alloc(i64, total_lat_count)
    else
        @as([]i64, &.{});
    defer if (total_lat_count > 0) allocator.free(merged);

    var off: u64 = 0;
    for (worker_results) |wr| {
        if (wr.result) |r| {
            if (r.latency_count > 0) {
                @memcpy(merged[off..][0..r.latency_count], r.latencies[0..r.latency_count]);
                off += r.latency_count;
            }
        }
    }

    std.mem.sortUnstable(i64, merged, {}, std.sort.asc(i64));

    const elapsed_s: f64 = @as(f64, @floatFromInt(elapsed_ns)) / 1e9;
    return .{
        .rps = if (elapsed_s > 0) @as(f64, @floatFromInt(total_sent)) / elapsed_s else 0,
        .p50_us = percentile_us(merged, 0.50),
        .p99_us = percentile_us(merged, 0.99),
        .p999_us = percentile_us(merged, 0.999),
        .errors = total_errors,
    };
}

// ── DTLS scenario ──────────────────────────────────────────────────────

fn run_scenario_dtls(
    allocator: std.mem.Allocator,
    config: SuiteConfig,
    s: Scenario,
    tc: u16,
    port: u16,
) !ScenarioResult {
    const count = s.request_count;
    const extra: u16 = tc -| 1;
    const threads = try allocator.alloc(std.Thread, extra);
    defer allocator.free(threads);

    const per_thread = count / tc;
    const remainder = count % tc;

    const worker_results = try allocator.alloc(DtlsWorkerResult, tc);
    defer {
        for (worker_results) |*wr| {
            if (wr.latencies) |l| allocator.free(l);
        }
        allocator.free(worker_results);
    }

    for (0..extra) |j| {
        worker_results[j] = .{};
        threads[j] = try std.Thread.spawn(.{}, dtls_worker, .{
            allocator, config.host, port, config.window_size, s.payload_size,
            per_thread, config.warmup_count, &worker_results[j],
        });
    }

    worker_results[extra] = .{};
    dtls_worker(
        allocator, config.host, port, config.window_size, s.payload_size,
        per_thread + remainder, config.warmup_count, &worker_results[extra],
    );

    for (threads) |t| t.join();

    return aggregate_dtls(allocator, worker_results);
}

const DtlsWorkerResult = struct {
    sent: u64 = 0,
    errors: u64 = 0,
    latencies: ?[]i64 = null,
    latency_count: u32 = 0,
    bench_elapsed_ns: i128 = 0,
};

fn dtls_worker(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    window: u16,
    payload_size: u16,
    count: u32,
    warmup_count: u32,
    out: *DtlsWorkerResult,
) void {
    var client = coap.Client.init(allocator, .{
        .host = host,
        .port = port,
        .psk = bench_psk,
        .max_in_flight = window,
    }) catch return;
    defer client.deinit();

    client.handshake() catch return;

    const payload = allocator.alloc(u8, payload_size) catch return;
    defer allocator.free(payload);
    @memset(payload, 'x');

    // Warmup (not timed).
    for (0..warmup_count) |_| {
        const r = client.call(allocator, .get, &.{}, payload) catch continue;
        r.deinit(allocator);
    }

    const timestamps = allocator.alloc(i128, window) catch return;
    defer allocator.free(timestamps);
    @memset(timestamps, 0);

    const latencies = allocator.alloc(i64, count) catch return;

    var sent: u64 = 0;
    var received: u64 = 0;
    var errors: u64 = 0;
    var latency_count: u32 = 0;
    var total_sent: u32 = 0;
    var in_flight: u16 = 0;

    // Timed benchmark phase only.
    const bench_start = std.time.nanoTimestamp();

    while (received + errors < count) {
        while (in_flight < window and total_sent < count) {
            const handle = client.submit(.get, &.{}, payload) catch {
                errors += 1;
                total_sent += 1;
                continue;
            };
            timestamps[handle] = std.time.nanoTimestamp();
            total_sent += 1;
            in_flight += 1;
            sent += 1;
        }

        if (in_flight == 0) break;

        const c = client.poll(allocator, 50) catch {
            errors += 1;
            if (in_flight > 0) in_flight -= 1;
            continue;
        };
        const completion = c orelse continue;

        in_flight -|= 1;

        if (completion.result._timeout or completion.result._reset) {
            errors += 1;
            continue;
        }
        defer completion.result.deinit(allocator);

        received += 1;

        const ts = timestamps[completion.handle];
        if (ts > 0) {
            const latency = std.time.nanoTimestamp() - ts;
            if (latency_count < count) {
                latencies[latency_count] = @intCast(@min(latency, std.math.maxInt(i64)));
                latency_count += 1;
            }
            timestamps[completion.handle] = 0;
        }
    }

    out.bench_elapsed_ns = std.time.nanoTimestamp() - bench_start;
    out.sent = sent;
    out.errors = errors;
    out.latencies = latencies;
    out.latency_count = latency_count;
}

fn aggregate_dtls(allocator: std.mem.Allocator, worker_results: []DtlsWorkerResult) !ScenarioResult {
    var total_sent: u64 = 0;
    var total_errors: u64 = 0;
    var total_lat_count: u64 = 0;
    var max_elapsed_ns: i128 = 0;

    for (worker_results) |wr| {
        total_sent += wr.sent;
        if (wr.bench_elapsed_ns > max_elapsed_ns) max_elapsed_ns = wr.bench_elapsed_ns;
        total_errors += wr.errors;
        total_lat_count += wr.latency_count;
    }

    const merged = if (total_lat_count > 0)
        try allocator.alloc(i64, total_lat_count)
    else
        @as([]i64, &.{});
    defer if (total_lat_count > 0) allocator.free(merged);

    var off: u64 = 0;
    for (worker_results) |wr| {
        if (wr.latencies) |l| {
            if (wr.latency_count > 0) {
                @memcpy(merged[off..][0..wr.latency_count], l[0..wr.latency_count]);
                off += wr.latency_count;
            }
        }
    }

    std.mem.sortUnstable(i64, merged, {}, std.sort.asc(i64));

    const elapsed_s: f64 = @as(f64, @floatFromInt(max_elapsed_ns)) / 1e9;
    return .{
        .rps = if (elapsed_s > 0) @as(f64, @floatFromInt(total_sent)) / elapsed_s else 0,
        .p50_us = percentile_us(merged, 0.50),
        .p99_us = percentile_us(merged, 0.99),
        .p999_us = percentile_us(merged, 0.999),
        .errors = total_errors,
    };
}

// ── Low-level UDP bench (unchanged) ────────────────────────────────────

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

        if (in_flight == 0) break;

        const n = posix.recv(fd, &recv_buf, 0) catch |err| {
            if (err == error.WouldBlock) {
                consecutive_timeouts += 1;
                if (consecutive_timeouts >= 3 and in_flight > 0) {
                    result.errors += @intCast(in_flight);
                    in_flight = 0;
                    if (total_sent >= count) break;
                }
                continue;
            }
            result.errors += 1;
            if (in_flight > 0) in_flight -= 1;
            continue;
        };

        consecutive_timeouts = 0;
        in_flight -|= 1;
        result.received += 1;
        result.bytes_received += n;

        if (n >= 6 and (recv_buf[0] & 0x0F) >= 2) {
            const token: u16 = @as(u16, recv_buf[4]) << 8 | recv_buf[5];
            const slot = token % window;
            const ts = timestamps[slot];
            if (ts > 0) {
                const latency = std.time.nanoTimestamp() - ts;
                result.latency_sum_ns += latency;
                if (latency < result.latency_min_ns) result.latency_min_ns = latency;
                if (latency > result.latency_max_ns) result.latency_max_ns = latency;
                if (collect_latencies and result.latency_count < count) {
                    result.latencies[result.latency_count] = @intCast(latency);
                    result.latency_count += 1;
                }
            }
        }
    }

    return result;
}

// ── Helpers ────────────────────────────────────────────────────────────

fn make_client_socket(host: []const u8, port: u16) !posix.socket_t {
    const dest = try std.net.Address.parseIp(host, port);
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    errdefer posix.close(fd);
    try posix.connect(fd, &dest.any, dest.getOsSockLen());

    const buf_size = std.mem.toBytes(@as(c_int, 4 * 1024 * 1024));
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &buf_size) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &buf_size) catch {};

    const timeout = posix.timeval{ .sec = 0, .usec = 100_000 };
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

    return fd;
}

fn echo_handler(request: coap.Request) ?coap.Response {
    return coap.Response.ok(request.payload());
}

fn fork_server(port: u16, thread_count: u16, psk: ?coap.Psk) !posix.pid_t {
    const pid = try posix.fork();
    if (pid == 0) {
        var server = coap.Server.init(
            std.heap.page_allocator,
            .{
                .port = port,
                .buffer_count = 512,
                .buffer_size = 1280,
                .thread_count = thread_count,
                .rate_limit_ip_count = 0,
                .psk = psk,
            },
            echo_handler,
        ) catch std.process.exit(1);
        server.run() catch std.process.exit(1);
        unreachable;
    }
    return pid;
}

fn kill_server(pid: *?posix.pid_t) void {
    if (pid.*) |p| {
        posix.kill(p, posix.SIG.TERM) catch {};
        _ = posix.waitpid(p, 0);
        pid.* = null;
    }
}

fn percentile_us(sorted: []i64, p: f64) f64 {
    if (sorted.len == 0) return 0;
    const idx: usize = @min(
        @as(usize, @intFromFloat(@as(f64, @floatFromInt(sorted.len)) * p)),
        sorted.len - 1,
    );
    return @as(f64, @floatFromInt(sorted[idx])) / 1000.0;
}

fn format_label(template: []const u8, thread_count: u16) [24]u8 {
    var buf: [24]u8 = .{' '} ** 24;
    var out_i: usize = 0;
    var in_i: usize = 0;
    while (in_i < template.len and out_i < buf.len) {
        if (in_i + 1 < template.len and template[in_i] == '#' and template[in_i + 1] == '#') {
            // Replace ## with thread count (up to 5 digits).
            const tc_str = std.fmt.bufPrint(buf[out_i..], "{d}", .{thread_count}) catch break;
            out_i += tc_str.len;
            in_i += 2;
        } else {
            buf[out_i] = template[in_i];
            out_i += 1;
            in_i += 1;
        }
    }
    return buf;
}

// ── Output ─────────────────────────────────────────────────────────────

fn print_summary(
    cpu_count: u16,
    results: *const [scenario_templates.len]?ScenarioResult,
    scenarios: *const [scenario_templates.len]?Scenario,
) void {
    std.debug.print(
        "── benchmark suite results ({d} CPUs) ──\n\n" ++
            "  {s:<24}  {s:>12}  {s:>9}  {s:>9}  {s:>9}  {s:>6}\n" ++
            "  ------------------------  ------------  ---------  ---------  ---------  ------\n",
        .{
            cpu_count,
            "Scenario", "req/s", "p50 us", "p99 us", "p99.9 us", "errs",
        },
    );

    for (scenarios, 0..) |maybe_s, i| {
        const s = maybe_s orelse continue;
        const r = results[i] orelse continue;
        const label = format_label(s.label, if (s.multi_thread) cpu_count else 1);
        std.debug.print("  {s}  {d:>12}  {d:>9.1}  {d:>9.1}  {d:>9.1}  {d:>6}\n", .{
            &label,
            @as(u64, @intFromFloat(r.rps)),
            r.p50_us,
            r.p99_us,
            r.p999_us,
            r.errors,
        });
    }

    std.debug.print("\n", .{});
}

// ── CLI ────────────────────────────────────────────────────────────────

fn parse_args() SuiteConfig {
    var config = SuiteConfig{};
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
            config.count_override = std.fmt.parseInt(u32, val, 10) catch null;
        } else if (std.mem.eql(u8, arg, "--warmup")) {
            const val = args.next() orelse "1000";
            config.warmup_count = std.fmt.parseInt(u32, val, 10) catch 1_000;
        } else if (std.mem.eql(u8, arg, "--window")) {
            const val = args.next() orelse "256";
            config.window_size = std.fmt.parseInt(u16, val, 10) catch 256;
        } else if (std.mem.eql(u8, arg, "--threads")) {
            const val = args.next() orelse "0";
            config.thread_count = std.fmt.parseInt(u16, val, 10) catch 0;
        } else if (std.mem.eql(u8, arg, "--no-server")) {
            config.embedded_server = false;
        } else if (std.mem.eql(u8, arg, "--plain-only")) {
            config.filter_dtls = false;
        } else if (std.mem.eql(u8, arg, "--dtls-only")) {
            config.filter_plain = false;
        } else if (std.mem.eql(u8, arg, "--con-only")) {
            config.filter_non = false;
        } else if (std.mem.eql(u8, arg, "--non-only")) {
            config.filter_con = false;
        } else if (std.mem.eql(u8, arg, "--single-only")) {
            config.filter_multi = false;
        } else if (std.mem.eql(u8, arg, "--multi-only")) {
            config.filter_single = false;
        } else if (std.mem.eql(u8, arg, "--payload") or
            std.mem.eql(u8, arg, "--con") or
            std.mem.eql(u8, arg, "--dtls"))
        {
            std.debug.print("error: {s} removed in suite mode, use filter flags\n", .{arg});
            std.process.exit(1);
        }
    }

    return config;
}
