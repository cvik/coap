# Benchmark Suite Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace single-scenario benchmark with a matrix runner that benchmarks 18 scenarios (plain/DTLS × CON/NON × 1/N threads × 0/100/1000B payload) and prints a compact summary table.

**Architecture:** Rewrite `bench/client.zig` main() to build a comptime scenario template array, patch nproc at runtime, group by server config, iterate groups forking/killing servers, run each scenario collecting results, print summary table. All existing run_bench/run_dtls_bench functions are reused. New run_dtls_bench_threaded added for multi-thread DTLS.

**Tech Stack:** Zig, posix (fork, poll, sockets), coap/coapz libraries.

**Spec:** `docs/superpowers/specs/2026-03-13-bench-suite-design.md`

---

## File Map

- Modify: `bench/client.zig` — full rewrite of main(), parse_args(), report(); add scenario types, matrix, grouping, summary table, multi-thread DTLS
- No new files needed

---

### Task 1: Define Scenario and ScenarioResult types, comptime matrix

**Files:**
- Modify: `bench/client.zig` (top of file, replace `Config`)

- [ ] **Step 1: Replace Config with SuiteConfig and Scenario types**

Replace the existing `Config` struct with:

```zig
const SuiteConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 5683,
    warmup_count: u32 = 1_000,
    window_size: u16 = 256,
    embedded_server: bool = true,
    thread_count: u16 = 0, // 0 = nproc
    count_override: ?u32 = null,
    // Filters (true = include)
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
    multi_thread: bool, // true = use thread_count, false = 1
    payload_size: u16,
    request_count: u32,
};

const ScenarioResult = struct {
    label: []const u8,
    rps: f64,
    p50_us: f64,
    p99_us: f64,
    p999_us: f64,
    errors: u64,
};
```

- [ ] **Step 2: Define comptime scenario template array**

```zig
const scenario_templates = [_]Scenario{
    // Plain NON, 1T
    .{ .label = "Plain NON  1T     0B", .use_dtls = false, .use_confirmable = false, .multi_thread = false, .payload_size = 0, .request_count = 100_000 },
    .{ .label = "Plain NON  1T   100B", .use_dtls = false, .use_confirmable = false, .multi_thread = false, .payload_size = 100, .request_count = 100_000 },
    .{ .label = "Plain NON  1T  1000B", .use_dtls = false, .use_confirmable = false, .multi_thread = false, .payload_size = 1000, .request_count = 100_000 },
    // Plain CON, 1T
    .{ .label = "Plain CON  1T     0B", .use_dtls = false, .use_confirmable = true, .multi_thread = false, .payload_size = 0, .request_count = 100_000 },
    .{ .label = "Plain CON  1T   100B", .use_dtls = false, .use_confirmable = true, .multi_thread = false, .payload_size = 100, .request_count = 100_000 },
    .{ .label = "Plain CON  1T  1000B", .use_dtls = false, .use_confirmable = true, .multi_thread = false, .payload_size = 1000, .request_count = 100_000 },
    // Plain NON, MT
    .{ .label = "Plain NON {T}     0B", .use_dtls = false, .use_confirmable = false, .multi_thread = true, .payload_size = 0, .request_count = 100_000 },
    .{ .label = "Plain NON {T}   100B", .use_dtls = false, .use_confirmable = false, .multi_thread = true, .payload_size = 100, .request_count = 100_000 },
    .{ .label = "Plain NON {T}  1000B", .use_dtls = false, .use_confirmable = false, .multi_thread = true, .payload_size = 1000, .request_count = 100_000 },
    // Plain CON, MT
    .{ .label = "Plain CON {T}     0B", .use_dtls = false, .use_confirmable = true, .multi_thread = true, .payload_size = 0, .request_count = 100_000 },
    .{ .label = "Plain CON {T}   100B", .use_dtls = false, .use_confirmable = true, .multi_thread = true, .payload_size = 100, .request_count = 100_000 },
    .{ .label = "Plain CON {T}  1000B", .use_dtls = false, .use_confirmable = true, .multi_thread = true, .payload_size = 1000, .request_count = 100_000 },
    // DTLS CON, 1T
    .{ .label = "DTLS  CON  1T     0B", .use_dtls = true, .use_confirmable = true, .multi_thread = false, .payload_size = 0, .request_count = 25_000 },
    .{ .label = "DTLS  CON  1T   100B", .use_dtls = true, .use_confirmable = true, .multi_thread = false, .payload_size = 100, .request_count = 25_000 },
    .{ .label = "DTLS  CON  1T  1000B", .use_dtls = true, .use_confirmable = true, .multi_thread = false, .payload_size = 1000, .request_count = 25_000 },
    // DTLS CON, MT
    .{ .label = "DTLS  CON {T}     0B", .use_dtls = true, .use_confirmable = true, .multi_thread = true, .payload_size = 0, .request_count = 25_000 },
    .{ .label = "DTLS  CON {T}   100B", .use_dtls = true, .use_confirmable = true, .multi_thread = true, .payload_size = 100, .request_count = 25_000 },
    .{ .label = "DTLS  CON {T}  1000B", .use_dtls = true, .use_confirmable = true, .multi_thread = true, .payload_size = 1000, .request_count = 25_000 },
};
```

Note: `{T}` in labels gets patched at runtime to the actual thread count (e.g. "32T") when building the filtered scenario list. Labels are fixed-width for table alignment.

- [ ] **Step 3: Compile and verify no errors**

Run: `zig build bench -Doptimize=ReleaseFast --help` (just compile, not run)
Expected: compiles without errors

- [ ] **Step 4: Commit**

```
git commit -m "bench: add Scenario/SuiteConfig types and comptime matrix"
```

---

### Task 2: Rewrite parse_args for suite CLI flags

**Files:**
- Modify: `bench/client.zig` (replace `parse_args`)

- [ ] **Step 1: Rewrite parse_args to return SuiteConfig**

```zig
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
            std.debug.print("error: --{s} removed in suite mode. Use filter flags instead.\n", .{arg[2..]});
            std.process.exit(1);
        }
    }

    return config;
}
```

- [ ] **Step 2: Compile and verify**

Run: `zig build bench -Doptimize=ReleaseFast` (compile only check — main() will break, that's fine for now since we're replacing it in the next task)

- [ ] **Step 3: Commit**

```
git commit -m "bench: rewrite parse_args for suite CLI flags"
```

---

### Task 3: Build filtered scenario list and grouping logic

**Files:**
- Modify: `bench/client.zig` (add `build_scenarios` function, add `ServerGroup`)

- [ ] **Step 1: Add build_scenarios function**

This takes the comptime templates, applies filters, patches thread counts and request counts, and returns a runtime list. Also formats labels with actual thread count.

```zig
const ServerGroup = struct {
    use_dtls: bool,
    thread_count: u16,
};

fn build_scenarios(config: SuiteConfig, cpu_count: u16) [scenario_templates.len]?Scenario {
    var scenarios: [scenario_templates.len]?Scenario = .{null} ** scenario_templates.len;

    for (scenario_templates, 0..) |tmpl, i| {
        // Apply filters.
        if (tmpl.use_dtls and !config.filter_dtls) continue;
        if (!tmpl.use_dtls and !config.filter_plain) continue;
        if (tmpl.use_confirmable and !config.filter_con) continue;
        if (!tmpl.use_confirmable and !config.filter_non) continue;
        if (tmpl.multi_thread and !config.filter_multi) continue;
        if (!tmpl.multi_thread and !config.filter_single) continue;

        var s = tmpl;
        if (config.count_override) |c| s.request_count = c;
        scenarios[i] = s;
    }

    return scenarios;
}

fn scenario_thread_count(s: Scenario, cpu_count: u16) u16 {
    return if (s.multi_thread) cpu_count else 1;
}

fn scenario_port(s: Scenario, base_port: u16) u16 {
    return if (s.use_dtls and base_port == 5683) 5684 else base_port;
}

fn server_group(s: Scenario, cpu_count: u16) ServerGroup {
    return .{
        .use_dtls = s.use_dtls,
        .thread_count = scenario_thread_count(s, cpu_count),
    };
}

fn count_scenarios(scenarios: [scenario_templates.len]?Scenario) u16 {
    var n: u16 = 0;
    for (scenarios) |s| if (s != null) { n += 1; }
    return n;
}
```

- [ ] **Step 2: Compile and verify**

- [ ] **Step 3: Commit**

```
git commit -m "bench: add scenario filtering and grouping"
```

---

### Task 4: Rewrite main() as scenario loop with server lifecycle

**Files:**
- Modify: `bench/client.zig` (replace `main`)

- [ ] **Step 1: Write new main()**

The new main builds the scenario list, iterates by server group, forks/kills servers between groups, runs each scenario, collects `ScenarioResult`s, prints progress, and prints summary table at the end.

```zig
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = parse_args();
    const cpu_count: u16 = if (config.thread_count > 0)
        config.thread_count
    else
        @intCast(@min(std.Thread.getCpuCount(), std.math.maxInt(u16)));

    const scenarios = build_scenarios(config, cpu_count);
    const total = count_scenarios(scenarios);

    if (total == 0) {
        std.debug.print("warning: no scenarios match the given filters\n", .{});
        return;
    }

    std.debug.print("── benchmark suite ({d} scenarios, {d} CPUs) ──\n\n", .{ total, cpu_count });

    var results: [scenario_templates.len]?ScenarioResult = .{null} ** scenario_templates.len;
    var current_server: ?ServerGroup = null;
    var server_pid: ?posix.pid_t = null;
    var scenario_num: u16 = 0;

    defer if (server_pid) |pid| {
        posix.kill(pid, posix.SIG.TERM) catch {};
        _ = posix.waitpid(pid, 0);
    };

    for (scenarios, 0..) |maybe_scenario, i| {
        const s = maybe_scenario orelse continue;
        scenario_num += 1;
        const tc = scenario_thread_count(s, cpu_count);
        const group = server_group(s, cpu_count);

        // Restart server if group changed.
        if (config.embedded_server) {
            const need_restart = if (current_server) |cur|
                cur.use_dtls != group.use_dtls or cur.thread_count != group.thread_count
            else
                true;

            if (need_restart) {
                if (server_pid) |pid| {
                    posix.kill(pid, posix.SIG.TERM) catch {};
                    _ = posix.waitpid(pid, 0);
                    server_pid = null;
                }
                const psk: ?coap.Psk = if (s.use_dtls) bench_psk else null;
                const port = scenario_port(s, config.port);
                server_pid = try fork_server(port, tc, psk);
                std.Thread.sleep(150 * std.time.ns_per_ms);
                current_server = group;
            }
        }

        // Print progress.
        const label = format_label(s.label, tc);
        std.debug.print("[{d:>2}/{d}] {s} ...", .{ scenario_num, total, &label });

        // Run scenario.
        const result = if (s.use_dtls)
            try run_scenario_dtls(allocator, config, s, cpu_count)
        else
            try run_scenario_plain(allocator, config, s, cpu_count);

        results[i] = result;

        std.debug.print(" {d:>10,.0} req/s\n", .{@as(u64, @intFromFloat(result.rps))});
    }

    // Print summary table.
    std.debug.print("\n", .{});
    print_summary(cpu_count, &results, &scenarios);
}
```

- [ ] **Step 2: Add format_label helper**

Replaces `{T}` placeholder in labels with actual thread count:

```zig
fn format_label(template: []const u8, thread_count: u16) [21]u8 {
    var buf: [21]u8 = .{' '} ** 21;
    var out_i: usize = 0;
    var in_i: usize = 0;
    while (in_i < template.len and out_i < buf.len) {
        if (in_i + 2 < template.len and
            template[in_i] == '{' and template[in_i + 1] == 'T' and template[in_i + 2] == '}')
        {
            // Write thread count right-aligned in 2 chars.
            const tc_str = std.fmt.bufPrint(buf[out_i..][0..2], "{d:>2}", .{thread_count}) catch "??";
            _ = tc_str;
            out_i += 2;
            in_i += 3;
        } else {
            buf[out_i] = template[in_i];
            out_i += 1;
            in_i += 1;
        }
    }
    return buf;
}
```

- [ ] **Step 3: Compile (won't link yet — run_scenario_plain/dtls and print_summary not written yet)**

- [ ] **Step 4: Commit**

```
git commit -m "bench: rewrite main() as scenario group loop"
```

---

### Task 5: Implement run_scenario_plain

**Files:**
- Modify: `bench/client.zig`

- [ ] **Step 1: Write run_scenario_plain**

Wraps the existing run_bench and multi-thread logic into a function that takes a Scenario and returns ScenarioResult:

```zig
fn run_scenario_plain(
    allocator: std.mem.Allocator,
    config: SuiteConfig,
    s: Scenario,
    cpu_count: u16,
) !ScenarioResult {
    const tc = scenario_thread_count(s, cpu_count);
    const port = scenario_port(s, config.port);
    const count = s.request_count;

    // Build request template.
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
        const warmup_fd = try make_client_socket(config.host, port);
        defer posix.close(warmup_fd);
        _ = try run_bench(allocator, warmup_fd, template_wire, config.warmup_count, config.window_size, false);
    }

    // Run with tc threads.
    const n_clients = tc;
    const extra: u16 = n_clients -| 1;
    const threads = try allocator.alloc(std.Thread, extra);
    defer allocator.free(threads);

    const per_thread = count / n_clients;
    const remainder = count % n_clients;

    const worker_results = try allocator.alloc(WorkerResult, n_clients);
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
        threads[j] = try std.Thread.spawn(.{}, client_worker, .{
            allocator, config.host, port, template_wire, per_thread, config.window_size, &worker_results[j],
        });
    }

    const main_count = per_thread + remainder;
    const main_fd = try make_client_socket(config.host, port);
    defer posix.close(main_fd);
    const main_result = try run_bench(allocator, main_fd, template_wire, main_count, config.window_size, true);
    worker_results[extra] = .{ .result = main_result };

    for (threads) |t| t.join();

    const elapsed_ns = std.time.nanoTimestamp() - start;

    // Aggregate and compute percentiles.
    return aggregate_results(allocator, worker_results, elapsed_ns);
}
```

- [ ] **Step 2: Write aggregate_results helper**

```zig
fn aggregate_results(
    allocator: std.mem.Allocator,
    worker_results: []WorkerResult,
    elapsed_ns: i128,
) !ScenarioResult {
    var total_sent: u64 = 0;
    var total_errors: u64 = 0;
    var total_latencies: u64 = 0;

    for (worker_results) |wr| {
        if (wr.result) |r| {
            total_sent += r.sent;
            total_errors += r.errors;
            total_latencies += r.latency_count;
        }
    }

    // Merge latencies for percentile computation.
    const merged = if (total_latencies > 0)
        try allocator.alloc(i64, total_latencies)
    else
        @as([]i64, &.{});
    defer if (total_latencies > 0) allocator.free(merged);

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
    const rps: f64 = if (elapsed_s > 0) @as(f64, @floatFromInt(total_sent)) / elapsed_s else 0;

    return .{
        .label = "",
        .rps = rps,
        .p50_us = percentile_us(merged, 0.50),
        .p99_us = percentile_us(merged, 0.99),
        .p999_us = percentile_us(merged, 0.999),
        .errors = total_errors,
    };
}
```

- [ ] **Step 3: Update client_worker signature**

The current client_worker takes a full Config. Change it to take individual params so it works with both the old Config and the new scenario runner:

```zig
fn client_worker(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    template_wire: []const u8,
    count: u32,
    window_size: u16,
    out: *WorkerResult,
) void {
    const fd = make_client_socket(host, port) catch return;
    defer posix.close(fd);
    out.result = run_bench(allocator, fd, template_wire, count, window_size, true) catch return;
}
```

- [ ] **Step 4: Compile and verify**

- [ ] **Step 5: Commit**

```
git commit -m "bench: add run_scenario_plain with multi-thread support"
```

---

### Task 6: Implement run_scenario_dtls (single and multi-thread)

**Files:**
- Modify: `bench/client.zig`

- [ ] **Step 1: Write run_scenario_dtls**

For single-thread, reuses existing run_dtls_bench logic. For multi-thread, spawns N threads each with their own coap.Client.

```zig
fn run_scenario_dtls(
    allocator: std.mem.Allocator,
    config: SuiteConfig,
    s: Scenario,
    cpu_count: u16,
) !ScenarioResult {
    const tc = scenario_thread_count(s, cpu_count);
    const port = scenario_port(s, config.port);
    const count = s.request_count;
    const window = config.window_size;

    if (tc == 1) {
        return run_dtls_single(allocator, config, s, port, window);
    }

    // Multi-thread DTLS: spawn tc threads, each with own Client.
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

    const start = std.time.nanoTimestamp();

    for (0..extra) |j| {
        worker_results[j] = .{};
        threads[j] = try std.Thread.spawn(.{}, dtls_worker, .{
            allocator, config.host, port, window, s.payload_size,
            per_thread, config.warmup_count, &worker_results[j],
        });
    }

    // Main thread.
    worker_results[extra] = .{};
    dtls_worker(
        allocator, config.host, port, window, s.payload_size,
        per_thread + remainder, config.warmup_count, &worker_results[extra],
    );

    for (threads) |t| t.join();

    const elapsed_ns = std.time.nanoTimestamp() - start;

    // Aggregate.
    var total_sent: u64 = 0;
    var total_errors: u64 = 0;
    var total_lat_count: u64 = 0;

    for (worker_results) |wr| {
        total_sent += wr.sent;
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
            @memcpy(merged[off..][0..wr.latency_count], l[0..wr.latency_count]);
            off += wr.latency_count;
        }
    }

    std.mem.sortUnstable(i64, merged, {}, std.sort.asc(i64));

    const elapsed_s: f64 = @as(f64, @floatFromInt(elapsed_ns)) / 1e9;
    const rps: f64 = if (elapsed_s > 0) @as(f64, @floatFromInt(total_sent)) / elapsed_s else 0;

    return .{
        .label = "",
        .rps = rps,
        .p50_us = percentile_us(merged, 0.50),
        .p99_us = percentile_us(merged, 0.99),
        .p999_us = percentile_us(merged, 0.999),
        .errors = total_errors,
    };
}
```

- [ ] **Step 2: Write DtlsWorkerResult and dtls_worker**

```zig
const DtlsWorkerResult = struct {
    sent: u64 = 0,
    errors: u64 = 0,
    latencies: ?[]i64 = null,
    latency_count: u32 = 0,
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

    // Warmup.
    for (0..warmup_count) |_| {
        const r = client.call(allocator, .get, &.{}, payload) catch continue;
        r.deinit(allocator);
    }

    // Sliding window benchmark.
    const timestamps = allocator.alloc(i128, window) catch return;
    defer allocator.free(timestamps);
    @memset(timestamps, 0);

    const latencies = allocator.alloc(i64, count) catch return;
    // ownership transferred to out on success, freed by caller

    var sent: u64 = 0;
    var received: u64 = 0;
    var errors: u64 = 0;
    var latency_count: u32 = 0;
    var total_sent: u32 = 0;
    var in_flight: u16 = 0;

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

    out.sent = sent;
    out.errors = errors;
    out.latencies = latencies;
    out.latency_count = latency_count;
}
```

- [ ] **Step 3: Write run_dtls_single helper**

Thin wrapper around the single-client DTLS bench (same logic as existing run_dtls_bench but returns ScenarioResult):

```zig
fn run_dtls_single(
    allocator: std.mem.Allocator,
    config: SuiteConfig,
    s: Scenario,
    port: u16,
    window: u16,
) !ScenarioResult {
    var out = DtlsWorkerResult{};
    dtls_worker(allocator, config.host, port, window, s.payload_size, s.request_count, config.warmup_count, &out);
    defer if (out.latencies) |l| allocator.free(l);

    const latencies = if (out.latencies) |l| l[0..out.latency_count] else @as([]i64, &.{});
    std.mem.sortUnstable(i64, latencies, {}, std.sort.asc(i64));

    // Compute elapsed from latencies (not wall clock for single thread).
    // Actually we need wall clock. Let's time it.
    // Hmm — dtls_worker doesn't return elapsed. We need to wrap it.
    // Solution: time the dtls_worker call in run_scenario_dtls for tc==1 too.
    // The run_scenario_dtls already does this for multi-thread. Let's just
    // use the same path for single-thread too (tc=1 means 0 extra threads).
    _ = config;
    _ = s;
    _ = port;
    _ = window;
    unreachable; // This function is removed — single-thread uses the same multi-thread path with tc=1.
}
```

Actually, on reflection, the multi-thread path with tc=1 works perfectly for single-thread (0 extra threads, main thread does all work). So **remove run_dtls_single entirely** and let run_scenario_dtls handle tc=1 naturally.

Updated run_scenario_dtls removes the `if (tc == 1)` branch.

- [ ] **Step 4: Compile and verify**

- [ ] **Step 5: Commit**

```
git commit -m "bench: add run_scenario_dtls with multi-thread support"
```

---

### Task 7: Implement print_summary table

**Files:**
- Modify: `bench/client.zig`

- [ ] **Step 1: Write print_summary**

```zig
fn print_summary(
    cpu_count: u16,
    results: *const [scenario_templates.len]?ScenarioResult,
    scenarios: *const [scenario_templates.len]?Scenario,
) void {
    std.debug.print(
        \\── benchmark suite results ({d} CPUs) ──
        \\
        \\  {s:<21}  {s:>12}  {s:>9}  {s:>9}  {s:>9}  {s:>6}
        \\  {s:─<21}  {s:─>12}  {s:─>9}  {s:─>9}  {s:─>9}  {s:─>6}
        \\
    , .{
        cpu_count,
        "Scenario", "req/s", "p50 µs", "p99 µs", "p99.9 µs", "errs",
        "", "", "", "", "", "",
    });

    for (scenarios.*, 0..) |maybe_s, i| {
        const s = maybe_s orelse continue;
        const r = results.*[i] orelse continue;
        const label = format_label(s.label, if (s.multi_thread) cpu_count else 1);
        std.debug.print("  {s}  {d:>12,.0}  {d:>9.1}  {d:>9.1}  {d:>9.1}  {d:>6}\n", .{
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
```

- [ ] **Step 2: Remove old report function**

Delete the existing `report()` function since it's replaced by print_summary.

- [ ] **Step 3: Remove old run_dtls_bench function**

Delete the existing `run_dtls_bench()` function since it's replaced by run_scenario_dtls/dtls_worker.

- [ ] **Step 4: Compile and verify**

Run: `zig build bench -Doptimize=ReleaseFast`
Expected: compiles cleanly

- [ ] **Step 5: Commit**

```
git commit -m "bench: add summary table, remove old report/run_dtls_bench"
```

---

### Task 8: End-to-end test run and fixes

**Files:**
- Modify: `bench/client.zig` (any bug fixes)

- [ ] **Step 1: Run full suite**

Run: `zig build bench -Doptimize=ReleaseFast`
Expected: 18 scenarios run with progress lines and summary table. May take 2-4 minutes.

- [ ] **Step 2: Run with filters**

Run: `zig build bench -Doptimize=ReleaseFast -- --plain-only --single-only`
Expected: 6 scenarios (plain NON/CON × 3 payloads, single-thread only)

Run: `zig build bench -Doptimize=ReleaseFast -- --dtls-only`
Expected: 6 DTLS scenarios

Run: `zig build bench -Doptimize=ReleaseFast -- --dtls-only --non-only`
Expected: "warning: no scenarios match the given filters"

- [ ] **Step 3: Fix any issues found**

- [ ] **Step 4: Run zig build test to ensure library tests still pass**

Run: `zig build test`
Expected: all tests pass

- [ ] **Step 5: Commit any fixes**

```
git commit -m "bench: fix suite issues found in testing"
```

---

### Task 9: Final cleanup and verification

- [ ] **Step 1: Run full benchmark suite one more time**

Run: `zig build bench -Doptimize=ReleaseFast`
Verify output looks clean and numbers are reasonable.

- [ ] **Step 2: Run zig build test**

- [ ] **Step 3: Commit final state**
