# coapd

High-performance CoAP server library for Zig, built on Linux io_uring.

- Zero allocations in the hot path (arena resets per batch)
- CON/ACK reliability with duplicate detection and RST handling
- Multi-threaded via SO_REUSEPORT (no shared state between threads)
- .well-known/core resource discovery (RFC 6690)
- Simple handler interface: `fn(Request) ?Response`
- ~800K req/s single-threaded on loopback (scales with threads/core)

## Quick Start

```zig
const std = @import("std");
const coapd = @import("coapd");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var server = try coapd.Server.init(gpa.allocator(), .{}, echo);
    defer server.deinit();

    try server.run();
}

fn echo(request: coapd.Request) ?coapd.Response {
    return .{ .payload = request.packet.payload };
}
```

Add to your `build.zig.zon`:

```zig
.coapd = .{
    .url = "git+https://github.com/cvik/coapd#v0.2.0",
    .hash = "...",  // zig build will tell you the expected hash
},
```

Then in `build.zig`:

```zig
const coapd_dep = b.dependency("coapd", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("coapd", coapd_dep.module("coapd"));
```

## Handler Interface

The handler is a function pointer with the signature:

```zig
fn(coapd.Request) ?coapd.Response
```

### Request

The request provides:

- `packet` — parsed CoAP packet (`coapd.coap.Packet`), valid only during the
  handler call. Access method via `packet.code` (`.get`, `.post`, `.put`,
  `.delete`), URI via `packet.find_options(.uri_path)`, payload via
  `packet.payload`, and token via `packet.token`.
- `peer_address` — source address of the client (`std.net.Address`).
- `arena` — per-request arena allocator. Resets after the handler returns.
  Use it for any allocations needed during response construction.

### Response

Return a `coapd.Response` to send a reply, or `null` for no response.

```zig
const Response = struct {
    code: coapd.coap.Code = .content,      // response code
    options: []const coapd.coap.Option = &.{},  // CoAP options
    payload: []const u8 = &.{},            // response body
};
```

Common response codes: `.content` (2.05), `.created` (2.01), `.changed` (2.04),
`.deleted` (2.02), `.bad_request` (4.00), `.not_found` (4.04),
`.method_not_allowed` (4.05), `.internal_server_error` (5.00).

### Message Types

The server handles CoAP message types automatically:

- **CON** (confirmable) — response is sent as ACK with the matching message ID.
  If the handler returns `null`, an empty ACK is sent. Duplicate CON messages
  are detected and the cached response is retransmitted without calling the
  handler again.
- **NON** (non-confirmable) — response is sent as NON. If the handler returns
  `null`, no response is sent.
- **RST** (reset) — cancels the matching exchange (removes cached response).

### Panic Behavior

Handler functions must not panic. A panic in any handler will terminate the
server thread (or the entire process if it is the main thread). If your
handler calls code that may fail, use `catch` to convert errors into an
appropriate CoAP error response instead of allowing unwinding.

### Routing

There is no built-in router. Inspect the request packet directly:

```zig
fn handler(request: coapd.Request) ?coapd.Response {
    const pkt = request.packet;

    // Match on method + URI path.
    var it = pkt.find_options(.uri_path);
    const seg1 = it.next() orelse return .{ .code = .not_found };

    if (pkt.code == .get and std.mem.eql(u8, seg1.value, "temperature")) {
        return .{ .payload = "22.5" };
    }

    return .{ .code = .not_found };
}
```

### Response Options

Use the arena allocator to build response options:

```zig
fn handler(request: coapd.Request) ?coapd.Response {
    const coap = coapd.coap;

    // Set Content-Format to application/json (50).
    var cf_buf: [2]u8 = undefined;
    const cf = coap.Option.content_format(.json, &cf_buf);
    const opts = request.arena.dupe(coap.Option, &.{cf}) catch
        return .{ .code = .internal_server_error };

    return .{
        .code = .content,
        .options = opts,
        .payload = "{\"temp\": 22.5}",
    };
}
```

## Configuration

All fields have sensible defaults. Pass `.{}` for a standard server on port 5683.

```zig
var server = try coapd.Server.init(allocator, .{
    .port = 5683,            // UDP listen port
    .buffer_count = 512,     // io_uring provided buffers
    .buffer_size = 1280,     // max UDP datagram size (bytes)
    .exchange_count = 256,   // max concurrent CON exchanges
    .well_known_core = null, // RFC 6690 discovery payload
    .thread_count = 1,       // server threads (SO_REUSEPORT)
    .bind_address = "0.0.0.0", // IPv4 bind address
}, handler);
```

### `port`

UDP port to bind. Default: `5683` (CoAP standard port per RFC 7252).

### `bind_address`

IPv4 address to bind. Use `"127.0.0.1"` for loopback only, `"0.0.0.0"` for
all interfaces. IPv6 is not yet supported. Default: `"0.0.0.0"`.

### `buffer_count`

Number of provided buffers in the io_uring buffer pool. The kernel consumes
one buffer per incoming packet. Buffers are returned after each packet is
processed, but during bursts the pool must absorb all arrivals between
processing cycles. Set this to at least 2x your expected concurrent clients'
send window. Default: `512`.

Hard ceiling: 1024 (kernel `UIO_MAXIOV` limit for `register_buffers`).

### `buffer_size`

Maximum size of a single CoAP UDP datagram in bytes. Must be at least 64.
Default: `1280` (IPv6 minimum MTU, recommended by RFC 7252).

This also sets the maximum cached response size for CON deduplication.

### `exchange_count`

Maximum number of concurrent CON message exchanges tracked for duplicate
detection and response caching. Each exchange holds the peer address,
message ID, and a copy of the encoded response (up to `buffer_size` bytes).
Exchanges expire automatically per RFC 7252 section 4.8.2 (every ~247
seconds). Default: `256`.

Memory per exchange: `~8 + buffer_size` bytes. With defaults: `256 * 1288 ≈ 322 KB`.

If the pool is exhausted, new CON responses are sent but not cached — the
server logs a warning and duplicate detection is unavailable for those
exchanges.

### `well_known_core`

Static link-format string returned for `GET /.well-known/core` requests
(RFC 6690 resource discovery). When set, matching requests are intercepted
before reaching the handler. The response includes `Content-Format: 40`
(application/link-format).

```zig
var server = try coapd.Server.init(allocator, .{
    .well_known_core = "</temperature>;rt=\"temperature\";if=\"sensor\"," ++
                       "</led>;rt=\"light\";if=\"actuator\"",
}, handler);
```

When `null` (default), `/.well-known/core` requests pass through to the
handler like any other request.

### `thread_count`

Number of server threads. Each thread gets its own io_uring instance, UDP
socket, and exchange pool — there is no shared state between threads. The
kernel distributes incoming packets across sockets via `SO_REUSEPORT`
(4-tuple hash).

```zig
var server = try coapd.Server.init(allocator, .{
    .thread_count = 4,
}, handler);
```

Note: scaling depends on traffic coming from multiple source addresses/ports.
A single client socket always hashes to the same server thread. On loopback,
the kernel serializes UDP processing so multi-threading adds overhead without
throughput gain — benefits require a real NIC with RSS or CPU-intensive
handlers.

## Server Lifecycle

```zig
// 1. Init — pre-allocates all memory.
var server = try coapd.Server.init(allocator, config, handler);
defer server.deinit();

// 2a. Run (blocking) — binds, spawns threads, loops until stop().
try server.run();

// 2b. Or manual control:
try server.listen();       // bind socket, arm io_uring
while (running) {
    try server.tick();     // process one batch of completions
}

// 3. Graceful shutdown — call from another thread or signal handler.
server.stop();             // signals run() and all workers to exit
```

The `tick()` method processes up to 256 completion events, calls the handler
for each request, and submits responses. The arena allocator resets after
each tick. Use `listen()` + `tick()` when you need control over the event
loop (e.g., graceful shutdown, integration with other I/O).

## Logging

coapd uses `std.log` with the `.coapd` scope. Control verbosity via:

```zig
pub const std_options: std.Options = .{
    .log_level = .warn,  // suppress info/debug from coapd
};
```

Log messages:
- **info**: server started (port, thread count)
- **warn**: multishot recv re-armed, exchange pool full
- **debug**: malformed packets, exchange eviction counts
- **err**: buffer release failures

## Benchmarks

Single-threaded echo server, loopback, minimal CoAP NON GET (6 bytes):

```
zig build bench -Doptimize=ReleaseFast -- --count 1000000
```

| Metric | Value |
|--------|-------|
| Throughput | ~800K req/s |
| Avg latency | ~320µs |
| p50 latency | ~285µs |
| p99 latency | ~660µs |
| p99.9 latency | ~1000µs |
| Packet loss | 0% |

These numbers reflect single-threaded performance on loopback, where the
kernel's UDP stack is the bottleneck. With `--threads N` on a multi-core
machine with a real NIC (RSS distributing across queues), throughput scales
with core count.

Benchmark options: `--count`, `--window`, `--payload`, `--con`,
`--threads`, `--warmup`, `--no-server`, `--host`, `--port`.

## Requirements

- Linux (io_uring support, kernel 5.13+ for multishot recvmsg)
- Zig 0.15.1+

## Roadmap

- [x] CON/ACK reliability (duplicate detection, piggybacked ACK, response caching)
- [x] RST message handling
- [x] Pipelined benchmark client with embedded server
- [x] Multi-threading with SO_REUSEPORT
- [x] .well-known/core resource discovery (RFC 6690)
- [ ] Routing

## License

MIT
