# coap

High-performance CoAP server and client library for Zig, built on Linux io_uring.

### Highlights

- **Simple handler interface** — `fn(Request) ?Response`, with context handlers and error wrappers
- **Zero allocations in the hot path** — pre-allocated pools, arena resets per batch
- **Multi-threaded** — SO_REUSEPORT, no shared state between threads
- **DTLS 1.2 PSK** — pure Zig AES-128-CCM-8, stateless cookies, anti-replay
- **IPv4 and IPv6** with dual-stack support

### RFC compliance

Full compliance with the core CoAP protocol stack:

| RFC | Feature | Coverage |
|-----|---------|----------|
| [7252](https://datatracker.ietf.org/doc/html/rfc7252) | CoAP core, separate responses, critical options | Full |
| [7641](https://datatracker.ietf.org/doc/html/rfc7641) | Observe (client subscribe + server push) | Full |
| [7959](https://datatracker.ietf.org/doc/html/rfc7959) | Block-wise transfers (client + server) | Full |
| [6347](https://datatracker.ietf.org/doc/html/rfc6347) | DTLS 1.2 (PSK, flight retransmit) | Full |
| [9175](https://datatracker.ietf.org/doc/html/rfc9175) | Echo option, Request-Tag | Full |
| [6690](https://datatracker.ietf.org/doc/html/rfc6690) | .well-known/core discovery | Full |
| [4279](https://datatracker.ietf.org/doc/html/rfc4279) | PSK key exchange | Full |

See the [protocol compliance roadmap](docs/ROADMAP.md) for planned features.

## Quick Start

### Server

```zig
const std = @import("std");
const coap = @import("coap");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var server = try coap.Server.init(gpa.allocator(), .{}, echo);
    defer server.deinit();

    try server.run();
}

fn echo(request: coap.Request) ?coap.Response {
    return coap.Response.ok(request.payload());
}
```

### Client

```zig
const std = @import("std");
const coap = @import("coap");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = try coap.Client.init(allocator, .{
        .host = "127.0.0.1",
        .port = 5683,
    });
    defer client.deinit();

    // Fire-and-forget NON request.
    try client.cast(.get, &.{}, "ping");

    // Blocking CON request/response with retransmission.
    const result = try client.get(allocator, "/temperature");
    defer result.deinit(allocator);

    std.debug.print("response: {s}\n", .{result.payload});
}
```

### Server with DTLS

Pass PSK credentials to enable DTLS automatically. The server binds on port
5684 (CoAPS) and requires a valid DTLS handshake before accepting requests.

```zig
var server = try coap.Server.init(allocator, .{
    .psk = .{ .identity = "device1", .key = "supersecretkey1!" },
}, handler);
defer server.deinit();
try server.run();
```

### Client with DTLS

```zig
var client = try coap.Client.init(allocator, .{
    .host = "10.0.0.1",
    .psk = .{ .identity = "device1", .key = "supersecretkey1!" },
});
defer client.deinit();

try client.handshake();

const result = try client.get(allocator, "/temperature");
defer result.deinit(allocator);
```

All send/recv methods automatically encrypt/decrypt after `handshake()`.
Handlers can check `request.is_secure` to distinguish DTLS from plain requests.

## Installation

Add to your `build.zig.zon`:

```zig
.coap = .{
    .url = "git+https://github.com/cvik/coap#v0.6.2",
    .hash = "...",  // zig build will tell you the expected hash
},
```

Then in `build.zig`:

```zig
const coap_dep = b.dependency("coap", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("coap", coap_dep.module("coap"));
```

## Handler Interface

The handler is a function pointer with the signature:

```zig
fn(coap.Request) ?coap.Response
```

### Request

The request provides convenience accessors and the underlying packet:

- `method()` — request method (`.get`, `.post`, `.put`, `.delete`, …).
- `payload()` — request payload bytes.
- `pathSegments()` — iterator over URI-Path option segments.
- `querySegments()` — iterator over URI-Query option values.
- `findOptions(kind)` / `findOption(kind)` — option lookup by kind.
- `packet` — the full parsed CoAP packet (`coap.coap.Packet`) for advanced use.
- `peer_address` — source address of the client (`std.net.Address`).
- `arena` — per-request arena allocator. Resets after the handler returns.
  Use it for any allocations needed during response construction.

### Response

Return a `coap.Response` to send a reply, or `null` for no response.

Convenience constructors for common responses:

```zig
Response.ok("hello")                         // 2.05 Content with payload
Response.content(arena, .json, "{}")         // 2.05 with Content-Format option
Response.created()                           // 2.01 Created
Response.deleted()                           // 2.02 Deleted
Response.changed()                           // 2.04 Changed
Response.notFound()                          // 4.04 Not Found
Response.badRequest()                        // 4.00 Bad Request
Response.methodNotAllowed()                  // 4.05 Method Not Allowed
Response.unauthorized()                      // 4.01 Unauthorized
Response.forbidden()                         // 4.03 Forbidden
Response.badOption()                         // 4.02 Bad Option
Response.withCode(.gateway_timeout)          // arbitrary code
```

Or construct directly:

```zig
return .{ .code = .content, .options = opts, .payload = data };
```

### Context Handlers

Use `Server.initContext` to pass state to the handler without globals:

```zig
const State = struct { counter: u64 = 0 };

var state = State{};
var server = try coap.Server.initContext(allocator, .{}, handle, &state);

fn handle(ctx: *State, request: coap.Request) ?coap.Response {
    _ = @atomicRmw(u64, &ctx.counter, .Add, 1, .monotonic);
    return coap.Response.ok(request.payload());
}
```

The context pointer is type-erased internally and passed to the handler on
every invocation. When `thread_count > 1`, the context is shared across worker
threads — use atomic operations, mutexes, or thread-local state.

### Error Handling Wrappers

`safeWrap` converts a handler that returns `!?Response` into a
`SimpleHandlerFn`. Errors are logged and converted to 5.00 Internal Server
Error:

```zig
fn handler(request: coap.Request) !?coap.Response {
    const data = try fetchData(request.arena);
    return .{ .payload = data };
}

var server = try coap.Server.init(allocator, .{}, coap.safeWrap(handler));
```

`safeWrapContext` does the same for context handlers:

```zig
fn handler(ctx: *State, request: coap.Request) !?coap.Response {
    const data = try ctx.lookup(request.arena);
    return .{ .payload = data };
}

var server = try coap.Server.initContext(
    allocator, .{}, coap.safeWrapContext(*State, handler), &state,
);
```

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

Handler functions must not panic. A panic in any handler terminates the
entire process (Zig panics are not recoverable). Worker threads are
automatically restarted up to `max_worker_restarts` times (default: 5),
but this only covers normal thread exits (e.g. init failures, transient
I/O errors), not panics. Use `catch` to convert errors into CoAP error
responses, or use `safeWrap` for automatic error conversion.

### Routing

There is no built-in router. Use the request accessors to route:

```zig
fn handler(request: coap.Request) ?coap.Response {
    var it = request.pathSegments();
    const seg1 = it.next() orelse return coap.Response.notFound();

    if (request.method() == .get and std.mem.eql(u8, seg1.value, "temperature")) {
        return coap.Response.ok("22.5");
    }

    return coap.Response.notFound();
}
```

### Response Options

Use `Response.content()` to set Content-Format automatically:

```zig
fn handler(request: coap.Request) ?coap.Response {
    return coap.Response.content(request.arena, .json, "{\"temp\": 22.5}");
}
```

For custom options, use the arena allocator directly:

```zig
fn handler(request: coap.Request) ?coap.Response {
    var cf_buf: [2]u8 = undefined;
    const cf = coap.Option.content_format(.json, &cf_buf);
    const opts = request.arena.dupe(coap.Option, &.{cf}) catch
        return coap.Response.withCode(.internal_server_error);

    return .{ .code = .content, .options = opts, .payload = "{\"temp\": 22.5}" };
}
```

## Client API

A `Client` connects to a single server via a connected UDP socket. Create
multiple instances for multiple servers.

### init / deinit

```zig
var client = try coap.Client.init(allocator, .{
    .host = "127.0.0.1",
    .port = 5683,
    .max_in_flight = 32,       // max concurrent CON requests
    .token_len = 2,            // token length in bytes (1-8)
    .default_szx = 6,          // block size exponent (6 = 1024 bytes)
});
defer client.deinit();
```

### get / post / put / delete — path convenience

CON request/response by path string with automatic retransmission:

```zig
const result = try client.get(allocator, "/sensor/temperature");
defer result.deinit(allocator);
// result.code, result.payload, result.options

const r2 = try client.post(allocator, "/log", "event happened");
defer r2.deinit(allocator);
```

Returns `error.Timeout` after max retransmissions, `error.Reset` if the
server sends RST. Transparently reassembles Block2 multi-block responses.

### cast — NON fire-and-forget

Sends a NON request with no response expected:

```zig
try client.cast(.post, &.{
    .{ .kind = .uri_path, .value = "log" },
}, "event happened");
```

### call — CON request/response

Lower-level CON method accepting raw options. Use `get`/`post`/`put`/`delete`
for simpler path-based requests.

```zig
const result = try client.call(allocator, .get, &.{
    .{ .kind = .uri_path, .value = "sensor" },
}, &.{});
defer result.deinit(allocator);
```

### submit / poll — pipelined async

For high-throughput workloads, use `submit` to send CON requests without
blocking, then `poll` to drive the event loop and collect completions:

```zig
var client = try coap.Client.init(allocator, .{
    .host = "10.0.0.1",
    .max_in_flight = 64,
});
defer client.deinit();

// Submit multiple requests — returns immediately.
const h1 = try client.submit(.get, &.{
    .{ .kind = .uri_path, .value = "temperature" },
}, &.{});
const h2 = try client.submit(.get, &.{
    .{ .kind = .uri_path, .value = "humidity" },
}, &.{});

// Poll for completions (handles retransmission, Block2 reassembly).
while (try client.poll(allocator, 100)) |completion| {
    defer completion.result.deinit(allocator);
    if (completion.handle == h1) {
        std.debug.print("temp: {s}\n", .{completion.result.payload});
    } else if (completion.handle == h2) {
        std.debug.print("humidity: {s}\n", .{completion.result.payload});
    }
}
```

`poll` returns `null` when the timeout expires with no completion. Check
`completion.result._timeout` or `._reset` for error conditions. Option
`value` memory passed to `submit` must remain valid until the corresponding
completion.

The blocking `call`/`get`/`post`/`put`/`delete` methods are implemented as
`submit` + `poll` internally — both APIs share the same slot infrastructure
and can be mixed freely.

### sendRaw / recvRaw — low-level

Send and receive raw CoAP packets without protocol automation:

```zig
try client.sendRaw(packet);
const response = try client.recvRaw(allocator, 2000) orelse return; // 2s timeout
defer response.deinit(allocator);
```

### observe — RFC 7641

Subscribe to resource notifications:

```zig
var stream = try client.observe(&.{
    .{ .kind = .uri_path, .value = "temperature" },
});

while (try stream.next(allocator)) |notification| {
    defer notification.deinit(allocator);
    std.debug.print("update: {s}\n", .{notification.payload});
}

try stream.cancel();
```

CON notifications are automatically ACKed.

For zero-allocation notification processing, use `nextBuf` with a caller-provided buffer:

```zig
var buf: [1500]u8 = undefined;
while (try stream.nextBuf(&buf)) |notification| {
    // notification.payload and options live in buf — no deinit needed
    std.debug.print("update: {s}\n", .{notification.payload});
}
```

### upload — RFC 7959 Block1

Upload large payloads using Block1 segmentation:

```zig
const result = try client.upload(allocator, .put, &.{
    .{ .kind = .uri_path, .value = "firmware" },
}, large_payload);
defer result.deinit(allocator);
```

The server's preferred block size is honored if it responds with a
smaller SZX value.

## Server Configuration

All fields have sensible defaults. Pass `.{}` for a standard server on port 5683.

```zig
var server = try coap.Server.init(allocator, .{
    .port = 5683,                     // UDP listen port
    .bind_address = "0.0.0.0",        // IPv4/IPv6 bind address
    .buffer_count = 512,              // io_uring provided buffers
    .buffer_size = 1280,              // max UDP datagram size (bytes)
    .exchange_count = 256,            // max concurrent CON exchanges
    .max_deferred = 16,               // max concurrent separate responses
    .max_block_transfers = 32,        // max concurrent Block1/Block2 transfers
    .max_block_payload = 64 * 1024,   // max block transfer payload (bytes)
    .max_observers = 256,             // max total observer entries
    .max_observe_resources = 64,      // max observed resources
    .well_known_core = null,          // RFC 6690 discovery payload
    .recognized_options = &.{},       // extra critical options to allow
    .thread_count = 1,                // server threads (SO_REUSEPORT)
    .max_arena_size = 256 * 1024,     // arena trim threshold (bytes)
    .rate_limit_ip_count = 1024,      // max tracked IPs (0 = disabled)
    .rate_limit_tokens_per_sec = 100, // tokens refilled per second
    .rate_limit_burst = 200,          // max bucket capacity
    .load_shed_throttle_pct = 75,     // % utilization to start throttling
    .load_shed_critical_pct = 90,     // % utilization to start shedding
    .load_shed_recover_pct = 50,      // % utilization to recover
    .handler_warn_ns = 0,             // slow handler warning threshold (ns)
    .max_worker_restarts = 5,         // max worker restart attempts
    .cpu_affinity = &.{ 0, 1, 2, 3 }, // pin threads to CPU cores
}, handler);
```

### `port`

UDP port to bind. Default: `5683` (CoAP standard port per RFC 7252).

### `bind_address`

Address to bind. Use `"0.0.0.0"` for all IPv4 interfaces, `"::"` for
dual-stack IPv6 (accepts both v4 and v6 clients via `IPV6_V6ONLY=0`),
`"127.0.0.1"` or `"::1"` for loopback only. Default: `"0.0.0.0"`.

### `buffer_count`

Number of provided buffers in the io_uring buffer pool. The kernel consumes
one buffer per incoming packet. Buffers are returned after each packet is
processed, but during bursts the pool must absorb all arrivals between
processing cycles. Set this to at least 2x your expected concurrent clients'
send window. Default: `512`.

Higher values require more kernel memory per io_uring instance.

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

### `max_deferred`

Maximum concurrent separate (delayed) responses. When a handler calls
`request.deferResponse()`, the server sends an empty ACK and tracks the
pending response in this pool. Set to `0` to disable. Default: `16`.

### `max_block_transfers`

Maximum concurrent Block1 upload reassembly and Block2 large response
fragmentation transfers (shared pool). Set to `0` to disable block transfer
support. Default: `32`.

### `max_block_payload`

Maximum payload size for block transfers in bytes. Block1 uploads exceeding
this are rejected with 4.13. Block2 responses are capped at this size.
Default: `65536` (64 KB).

### `max_observers` / `max_observe_resources`

Maximum total observer entries and maximum observed resources for server-side
Observe (RFC 7641). The observer list is partitioned evenly across resources.
Set `max_observers` to `0` to disable. Defaults: `256` / `64`.

### `well_known_core`

Static link-format string returned for `GET /.well-known/core` requests
(RFC 6690 resource discovery). When set, matching requests are intercepted
before reaching the handler. The response includes `Content-Format: 40`
(application/link-format).

```zig
var server = try coap.Server.init(allocator, .{
    .well_known_core = "</temperature>;rt=\"temperature\";if=\"sensor\"," ++
                       "</led>;rt=\"light\";if=\"actuator\"",
}, handler);
```

When `null` (default), `/.well-known/core` requests pass through to the
handler like any other request.

### `recognized_options`

Additional critical option numbers the application understands. The server
automatically rejects unrecognized critical options (odd-numbered) with 4.02
Bad Option per RFC 7252 §5.4.1. All standard CoAP options are recognized by
default. Use this field to whitelist application-specific critical options:

```zig
var server = try coap.Server.init(allocator, .{
    .recognized_options = &.{ 2049, 2051 },  // application-specific critical options
}, handler);
```

Default: `&.{}` (only standard options recognized).

### `thread_count`

Number of server threads. Each thread gets its own io_uring instance, UDP
socket, and exchange pool — there is no shared state between threads. The
kernel distributes incoming packets across sockets via `SO_REUSEPORT`
(4-tuple hash).

```zig
var server = try coap.Server.init(allocator, .{
    .thread_count = 4,
}, handler);
```

Note: scaling depends on traffic coming from multiple source addresses/ports.
A single client socket always hashes to the same server thread. On loopback,
the kernel serializes UDP processing so multi-threading adds overhead without
throughput gain — benefits require a real NIC with RSS or CPU-intensive
handlers.

### `max_arena_size`

Maximum arena size in bytes before trimming. The per-tick arena is trimmed
back to this size after each batch of completions to prevent unbounded growth
from handler allocations. Default: `256 * 1024` (256 KB).

### `handler_warn_ns`

Log a warning when a handler invocation takes longer than this threshold in
nanoseconds. When enabled, adds a `nanoTimestamp()` call per handler
invocation. Set to `0` to disable (default). Useful for detecting slow
handlers in production.

### `max_worker_restarts`

Maximum number of times a crashed worker thread is automatically restarted.
After this limit, the worker is not respawned and a log error is emitted.
Default: `5`.

### `cpu_affinity`

Pin server threads to specific CPU cores. Thread *i* is pinned to
`cpu_affinity[i % len]` — the main thread uses index 0, workers use
indices 1..N-1. This keeps each thread's io_uring buffers hot in L1/L2
cache and reduces latency jitter from OS thread migration.

```zig
var server = try coap.Server.init(allocator, .{
    .thread_count = 4,
    .cpu_affinity = &.{ 0, 2, 4, 6 },  // pin to even cores
}, handler);
```

When `null` (default), no affinity is set — the OS schedules threads
freely. If pinning fails (e.g., core ID out of range or insufficient
permissions), a warning is logged and the thread continues unpinned.

### `psk`

PSK credentials for DTLS 1.2 (RFC 6347). When set, the server requires a
DTLS handshake before accepting CoAP requests. Uses
`TLS_PSK_WITH_AES_128_CCM_8` (the mandatory cipher suite for CoAP, per
RFC 7252 §9). The port auto-switches to 5684 (CoAPS) if the default 5683
was configured.

```zig
var server = try coap.Server.init(allocator, .{
    .psk = .{ .identity = "device1", .key = "supersecretkey1!" },
}, handler);
```

When `null` (default), no DTLS — plain CoAP over UDP.

### `dtls_session_count`

Maximum concurrent DTLS sessions. Each session holds handshake state and
encryption keys. Sessions are evicted LRU when the table is full.
Default: `65536`.

### `dtls_session_timeout_s`

Idle DTLS session timeout in seconds. Sessions with no activity for this
duration are evicted. Default: `300` (5 minutes).

## Rate Limiting

coap includes per-IP token bucket rate limiting, activated when the server
enters the `throttled` load level (see [Load Shedding](#load-shedding)).

Configuration:

- `rate_limit_ip_count` — max tracked IPs. Set to `0` to disable rate
  limiting entirely. Default: `1024`.
- `rate_limit_tokens_per_sec` — token refill rate per IP. Default: `100`.
- `rate_limit_burst` — maximum bucket capacity per IP. Default: `200`.

When a client exceeds its rate limit:

- **CON** messages receive a RST (from a pre-allocated buffer).
- **NON** messages are silently dropped.

## Load Shedding

The server monitors buffer pool and exchange pool utilization and
transitions between three load levels:

| Level | Trigger | Behavior |
|-------|---------|----------|
| **normal** | utilization < `throttle_pct` | All requests processed normally |
| **throttled** | any pool >= `throttle_pct` | Per-IP rate limiting applied |
| **shedding** | any pool >= `critical_pct` | New packets dropped; CONs get RST |

Recovery occurs when both pools drop below `load_shed_recover_pct`. The
hysteresis gap between trigger and recovery thresholds prevents oscillation.

During shedding, cached CON retransmissions are still served — only new
requests are dropped.

## Server Lifecycle

```zig
// 1. Init — pre-allocates all memory.
var server = try coap.Server.init(allocator, config, handler);
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

coap uses `std.log` with the `.coap` scope. Control verbosity via:

```zig
pub const std_options: std.Options = .{
    .log_level = .warn,  // suppress info/debug from coap
};
```

Log messages:
- **info**: server started (port, thread count), worker start/stop
- **warn**: multishot recv re-armed, exchange pool full, slow handler
  (when `handler_warn_ns` enabled), rate-limited clients
- **debug**: malformed packets, exchange eviction counts, load level changes
- **err**: buffer release failures, worker crash/restart exhaustion

## Benchmarks

Echo server on loopback (32 CPUs). The bench suite groups scenarios by
transport (Plain/DTLS) × type (NON/CON) × threads × payload size.
NON throughput is measured server-side via shared-memory atomic counters.
CON throughput is measured client-side (echo round-trip).

**Plain UDP:**

| Scenario | req/s | p50 µs | p99 µs | p99.9 µs |
|----------|------:|-------:|-------:|---------:|
| NON 1T 0B | 840K | — | — | — |
| NON 32T 0B | 3.3M | — | — | — |
| CON 1T 0B | 840K | 310 | 340 | 530 |
| CON 32T 0B | 5.0M | 210 | 1,480 | 2,580 |

**DTLS (TLS_PSK_WITH_AES_128_CCM_8):**

| Scenario | req/s | p50 µs | p99 µs | p99.9 µs |
|----------|------:|-------:|-------:|---------:|
| NON 1T 0B | 700K | — | — | — |
| NON 32T 0B | 3.5M | — | — | — |
| CON 1T 0B | 185K | 1,340 | 1,580 | 1,870 |
| CON 32T 0B | 1.1M | 1,500 | 3,690 | 6,410 |

Loopback numbers are bottlenecked by the kernel's UDP stack. With a real
NIC and RSS distributing across queues, throughput scales further with
core count.

Run benchmarks: `zig build bench -Doptimize=ReleaseFast`

Filter flags: `--plain-only`, `--dtls-only`, `--con-only`, `--non-only`,
`--single-only`, `--multi-only`. Use `--help` for all options.

## Requirements

- Linux (io_uring support, kernel 5.13+ for multishot recvmsg)
- Zig 0.15.1+

## Roadmap

- [x] CON/ACK reliability (duplicate detection, piggybacked ACK, response caching)
- [x] RST message handling
- [x] Pipelined benchmark client with embedded server
- [x] Multi-threading with SO_REUSEPORT
- [x] .well-known/core resource discovery (RFC 6690)
- [x] Per-IP rate limiting and load shedding
- [x] Client library (cast, call, observe, block transfer)
- [x] DTLS 1.2 PSK security (RFC 6347)
- [x] Pipelined async client API (submit/poll)
- [x] Auto-clamp buffer_count to fit RLIMIT_MEMLOCK
- [x] Parallel AES-CTR via AES-NI xorWide
- [x] Critical option rejection (RFC 7252 §5.4.1)
- [x] NSTART congestion control (RFC 7252 §4.7)
- [x] IPv6 with dual-stack support
- [x] Separate (delayed) responses (RFC 7252 §5.2.2)
- [x] Server-side Observe with thread-safe notify (RFC 7641)
- [x] Server-side Block1/Block2 transfers (RFC 7959)
- [x] Client observe sequence freshness check (RFC 7641 §3.4)

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full protocol compliance roadmap.

## License

MIT
