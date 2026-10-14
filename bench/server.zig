//! Dedicated trusted-network benchmark server, not a production application.
const std = @import("std");
const coap = @import("coap");
const measurement = @import("measurement.zig");
const Credentials = @import("credentials.zig").Credentials;
const protocol = @import("protocol.zig");

pub const Config = struct {
    bind: []const u8 = "127.0.0.1",
    port: u16 = 5683,
    threads: u16 = 8,
    buffer_count: u16 = 512,
    buffer_size: u32 = 1280,
    exchange_count: u16 = 256,
    dtls_sessions: u32 = 4096,
    capacity: u32 = protocol.max_requests,
    timeout_ms: u32 = 30000,
    rate_ips: u16 = 0,
    rate: u16 = 100,
    burst: u16 = 200,
    allocator: enum { smp, debug } = .smp,
    psk_file: ?[]const u8 = null,
    cpus: [256]u16 = undefined,
    cpu_count: usize = 0,
    help: bool = false,
    verbose: bool = false,
};
const usage =
    "Usage: bench-server [options]\n" ++
    "  --bind IP                 Bind address (default: 127.0.0.1; explicit for remote)\n" ++
    "  --port N                  Port (default: 5683; DTLS defaults/auto-switches to 5684)\n" ++
    "  --threads N               Server workers, 1..256 (default: 8)\n" ++
    "  --allocator smp|debug     Startup/server allocator (default: smp)\n" ++
    "  --buffer-count N          Per worker, power of 2, 4..8192 (default: 512; memlock may clamp)\n" ++
    "  --buffer-size N           Datagram buffer bytes (default: 1280)\n" ++
    "  --exchange-count N        CON slots/worker, 1..16384 (default: 256)\n" ++
    "  --dtls-sessions N         DTLS capacity per worker (default: 4096)\n" ++
    "  --cpu-affinity A,B,...    Optional numeric CPU IDs, assigned cyclically\n" ++
    "  --max-requests N          Unique NON IDs per run, 1..16000000 (default: 16000000)\n" ++
    "  --session-timeout-ms N    Inactive run lease, minimum 1000 (default: 30000)\n" ++
    "  --rate-limit-ips N        Tracked IPs, 0..16384; 0 disables (default: 0)\n" ++
    "  --rate-limit N            Per-IP tokens/sec if enabled (default: 100)\n" ++
    "  --rate-burst N            Per-IP burst if enabled (default: 200)\n" ++
    "  --psk-file PATH           Enable DTLS; JSON {identity,key_hex}, 16..64 key bytes\n" ++
    "  --verbose                 Include routine transport logs (can perturb benchmarks)\n" ++
    "  -h, --help                Show help\n" ++
    "One measurement run at a time. Plain control is NOT authenticated: use WireGuard/trusted networks.\n";

pub fn parse(args: []const []const u8) !Config {
    var result: Config = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (std.mem.eql(u8, flag, "--help") or std.mem.eql(u8, flag, "-h")) {
            result.help = true;
            continue;
        }
        if (std.mem.eql(u8, flag, "--verbose")) {
            result.verbose = true;
            continue;
        }
        index += 1;
        if (index == args.len) return error.MissingArgument;
        const value = args[index];
        if (std.mem.eql(u8, flag, "--bind")) {
            result.bind = value;
        } else if (std.mem.eql(u8, flag, "--port")) {
            result.port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, flag, "--threads")) {
            result.threads = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, flag, "--buffer-count")) {
            result.buffer_count = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, flag, "--buffer-size")) {
            result.buffer_size = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, flag, "--exchange-count")) {
            result.exchange_count = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, flag, "--dtls-sessions")) {
            result.dtls_sessions = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, flag, "--max-requests")) {
            result.capacity = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, flag, "--session-timeout-ms")) {
            result.timeout_ms = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, flag, "--rate-limit-ips")) {
            result.rate_ips = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, flag, "--rate-limit")) {
            result.rate = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, flag, "--rate-burst")) {
            result.burst = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, flag, "--psk-file")) {
            result.psk_file = value;
        } else if (std.mem.eql(u8, flag, "--allocator")) {
            result.allocator = std.meta.stringToEnum(@TypeOf(result.allocator), value) orelse return error.InvalidAllocator;
        } else if (std.mem.eql(u8, flag, "--cpu-affinity")) {
            if (result.cpu_count != 0) return error.DuplicateAffinity;
            var parts = std.mem.splitScalar(u8, value, ',');
            while (parts.next()) |part| {
                if (part.len == 0 or result.cpu_count == result.cpus.len) return error.InvalidAffinity;
                result.cpus[result.cpu_count] = try std.fmt.parseInt(u16, part, 10);
                result.cpu_count += 1;
            }
        } else return error.UnknownArgument;
    }
    if (result.threads == 0 or result.threads > 256 or result.port == 0 or result.buffer_count < 4 or result.buffer_count > 8192 or !std.math.isPowerOfTwo(result.buffer_count) or result.buffer_size < 64 or result.buffer_size > 65535 or result.exchange_count == 0 or result.exchange_count > 16384 or result.rate_ips > 16384 or result.dtls_sessions == 0 or result.dtls_sessions > 65536 or result.capacity == 0 or result.capacity > protocol.max_requests or result.timeout_ms < 1000 or (result.rate_ips != 0 and (result.rate == 0 or result.burst == 0))) return error.InvalidConfig;
    _ = try coap.platform.parseIp(result.bind, result.port);
    return result;
}
var verbose_logging = false;
pub const std_options: std.Options = .{ .logFn = benchmarkLog };
fn benchmarkLog(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    const routine_warning = std.mem.startsWith(u8, format, "multishot recv failed");
    if (level == .err or (level == .warn and !routine_warning) or verbose_logging)
        std.log.defaultLog(level, scope, format, args);
}
var active_server: std.atomic.Value(?*coap.Server) = .init(null);
fn terminate(_: std.posix.SIG) callconv(.c) void {
    if (active_server.load(.acquire)) |server| server.stop();
}

pub fn main(init: std.process.Init.Minimal) !void {
    var arguments: [64][]const u8 = undefined;
    var iterator = init.args.iterate();
    _ = iterator.next();
    var count: usize = 0;
    while (iterator.next()) |arg| {
        if (count == arguments.len) return error.TooManyArguments;
        arguments[count] = arg;
        count += 1;
    }
    const config = parse(arguments[0..count]) catch |err| {
        std.debug.print("bench-server: {s}\n{s}", .{ @errorName(err), usage });
        return err;
    };
    if (config.help) {
        std.debug.print("{s}", .{usage});
        return;
    }
    verbose_logging = config.verbose;
    var debug: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug.deinit();
    const allocator = switch (config.allocator) {
        .smp => std.heap.smp_allocator,
        .debug => debug.allocator(),
    };
    var credentials: ?Credentials = if (config.psk_file) |path| try Credentials.load(path) else null;
    defer if (credentials) |*c| c.clear();
    var io = std.Io.Threaded.init(allocator, .{});
    defer io.deinit();
    var context = try measurement.Context.init(allocator, config.capacity, (@as(usize, config.threads) + 1) * 6, config.timeout_ms, io.io());
    defer context.deinit();
    var server = try coap.Server.initContext(allocator, .{
        .bind_address = config.bind,
        .port = config.port,
        .thread_count = config.threads,
        .buffer_count = config.buffer_count,
        .buffer_size = config.buffer_size,
        .exchange_count = config.exchange_count,
        .dtls_session_count = config.dtls_sessions,
        .rate_limit_ip_count = config.rate_ips,
        .rate_limit_tokens_per_sec = config.rate,
        .rate_limit_burst = config.burst,
        .cpu_affinity = if (config.cpu_count > 0) config.cpus[0..config.cpu_count] else null,
        .psk = if (credentials) |*c| c.psk() else null,
    }, measurement.Context.handle, &context);
    defer server.deinit();
    active_server.store(&server, .release);
    defer active_server.store(null, .release);
    const action: std.posix.Sigaction = .{ .handler = .{ .handler = terminate }, .mask = @splat(0), .flags = 0 };
    var old_int: std.posix.Sigaction = undefined;
    var old_term: std.posix.Sigaction = undefined;
    std.posix.sigaction(.INT, &action, &old_int);
    defer std.posix.sigaction(.INT, &old_int, null);
    std.posix.sigaction(.TERM, &action, &old_term);
    defer std.posix.sigaction(.TERM, &old_term, null);
    std.debug.print("bench-server: bind={s}:{d} workers={d} allocator={s} NON capacity={d} lease={d}ms rate-limit-ips={d} DTLS={}\n", .{ config.bind, server.config.port, config.threads, @tagName(config.allocator), config.capacity, config.timeout_ms, config.rate_ips, credentials != null });
    std.debug.print("  effective buffers={d}x{d} exchanges={d} DTLS-sessions/worker={d} affinity={s}\n", .{
        server.config.buffer_count,       server.config.buffer_size,                                                server.config.exchange_count,
        server.config.dtls_session_count, if (config.cpu_count == 0) "OS scheduled" else "requested (best-effort)",
    });
    if (credentials == null) std.debug.print("Plain benchmark controls are unauthenticated; use a trusted network/WireGuard.\n", .{});
    try server.run();
}
test "server CLI bounds match ring and u16 hash-table capacities" {
    try std.testing.expectError(error.InvalidConfig, parse(&.{ "--buffer-count", "3" }));
    try std.testing.expectError(error.InvalidConfig, parse(&.{ "--buffer-count", "600" }));
    try std.testing.expectError(error.InvalidConfig, parse(&.{ "--buffer-count", "16384" }));
    try std.testing.expectError(error.InvalidConfig, parse(&.{ "--exchange-count", "16385" }));
    try std.testing.expectError(error.InvalidConfig, parse(&.{ "--rate-limit-ips", "16385" }));
    _ = try parse(&.{ "--buffer-count", "8192", "--exchange-count", "16384", "--rate-limit-ips", "16384" });
}

test "server CLI validates bounds and explicit settings" {
    const c = try parse(&.{ "--threads", "8", "--bind", "::1", "--cpu-affinity", "0,1,2", "--max-requests", "1000" });
    try std.testing.expectEqual(@as(u16, 8), c.threads);
    try std.testing.expectEqual(@as(usize, 3), c.cpu_count);
    try std.testing.expectError(error.InvalidConfig, parse(&.{ "--threads", "0" }));
    try std.testing.expectError(error.InvalidAffinity, parse(&.{ "--cpu-affinity", "0," }));
    try std.testing.expectError(error.MissingArgument, parse(&.{"--port"}));
}
