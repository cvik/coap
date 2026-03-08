/// coapd benchmark client.
///
/// Sends CoAP requests at maximum rate using io_uring and measures
/// throughput and latency. Pre-encodes all requests at init.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const coapz = @import("coapz");
const log = std.log.scoped(.bench);

const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 5683,
    request_count: u32 = 100_000,
    payload_size: u16 = 0,
    warmup_count: u32 = 1_000,
    use_confirmable: bool = false,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = parse_args();

    const dest = try std.net.Address.parseIp(config.host, config.port);
    const fd = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        0,
    );
    defer posix.close(fd);
    try posix.connect(fd, &dest.any, dest.getOsSockLen());

    // Build the request template.
    const payload = try allocator.alloc(u8, config.payload_size);
    defer allocator.free(payload);
    @memset(payload, 'x');

    const kind: coapz.MessageKind = if (config.use_confirmable)
        .confirmable
    else
        .non_confirmable;

    // Pre-encode a template packet. msg_id will be patched per-send.
    const template = coapz.Packet{
        .kind = kind,
        .code = .get,
        .msg_id = 0,
        .token = &.{ 0xBE, 0xEF },
        .options = &.{},
        .payload = payload,
        .data_buf = &.{},
    };
    const template_wire = try template.write(allocator);
    defer allocator.free(template_wire);

    // Warmup.
    if (config.warmup_count > 0) {
        std.debug.print(
            "warming up ({d} requests)...\n",
            .{config.warmup_count},
        );
        _ = try run_bench(fd, template_wire, config.warmup_count);
    }

    // Benchmark.
    std.debug.print(
        "benchmarking {d} requests (payload={d}B, {s})...\n",
        .{
            config.request_count,
            config.payload_size,
            if (config.use_confirmable) "CON" else "NON",
        },
    );

    const start = std.time.nanoTimestamp();
    const result = try run_bench(fd, template_wire, config.request_count);
    const elapsed_ns = std.time.nanoTimestamp() - start;

    report(config, result, elapsed_ns);
}

const BenchResult = struct {
    sent: u64,
    received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    latency_min_ns: i128,
    latency_max_ns: i128,
    latency_sum_ns: i128,
};

fn run_bench(
    fd: posix.socket_t,
    template: []const u8,
    count: u32,
) !BenchResult {
    var result = BenchResult{
        .sent = 0,
        .received = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .latency_min_ns = std.math.maxInt(i128),
        .latency_max_ns = 0,
        .latency_sum_ns = 0,
    };

    // Use a copy we can patch msg_id in.
    var buf: [1280]u8 = undefined;
    std.debug.assert(template.len <= buf.len);
    @memcpy(buf[0..template.len], template);

    var recv_buf: [1280]u8 = undefined;
    var send_timestamps: [256]i128 = undefined;

    // Simple send-one-recv-one pattern for accurate latency.
    var msg_id: u16 = 0;
    var remaining = count;

    while (remaining > 0) {
        // Patch msg_id (bytes 2-3 in CoAP header, big-endian).
        buf[2] = @intCast(msg_id >> 8);
        buf[3] = @intCast(msg_id & 0xFF);

        const slot = msg_id & 0xFF;
        send_timestamps[slot] = std.time.nanoTimestamp();

        _ = try posix.send(fd, buf[0..template.len], 0);
        result.sent += 1;
        result.bytes_sent += template.len;

        const n = posix.recv(fd, &recv_buf, 0) catch {
            remaining -= 1;
            msg_id +%= 1;
            continue;
        };

        const latency = std.time.nanoTimestamp() - send_timestamps[slot];
        result.received += 1;
        result.bytes_received += n;
        result.latency_sum_ns += latency;
        if (latency < result.latency_min_ns) {
            result.latency_min_ns = latency;
        }
        if (latency > result.latency_max_ns) {
            result.latency_max_ns = latency;
        }

        remaining -= 1;
        msg_id +%= 1;
    }

    return result;
}

fn report(config: Config, result: BenchResult, elapsed_ns: i128) void {
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

    std.debug.print(
        \\
        \\── coapd benchmark results ──
        \\  target:     {s}:{d}
        \\  requests:   {d} sent, {d} received ({d:.1}% loss)
        \\  throughput: {d:.0} req/s
        \\  elapsed:    {d:.1} ms
        \\  latency:    avg={d:.1}µs min={d:.1}µs max={d:.1}µs
        \\  bytes:      {d} sent, {d} received
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
        result.bytes_sent,
        result.bytes_received,
    });
}

fn parse_args() Config {
    var config = Config{};
    var args = std.process.args();
    _ = args.next(); // skip program name

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
        }
    }

    return config;
}
