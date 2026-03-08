# coapd

High-performance CoAP server library for Zig, built on Linux io_uring.

## Usage

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

## Features

- io_uring multishot recvmsg with provided buffers
- Zero runtime allocations in the hot path (arena resets per batch)
- Simple handler interface: `fn(Request) ?Response`
- CoAP packet encode/decode via [coapz](https://github.com/cvik/coapz)
- CON/ACK reliability with duplicate detection and RST handling
- Multi-threaded server via SO_REUSEPORT
- .well-known/core resource discovery (RFC 6690)

## Roadmap

- [x] CON/ACK reliability (duplicate detection, piggybacked ACK, response caching)
- [x] RST message handling
- [x] Pipelined benchmark client with embedded server
- [x] Multi-threading with SO_REUSEPORT
- [x] .well-known/core resource discovery (RFC 6690)
- [ ] Routing

## Benchmarks

Echo server, loopback, minimal CoAP NON GET (6 bytes):

```
zig build bench -Doptimize=ReleaseFast -- --count 1000000
```

| Metric | Value |
|--------|-------|
| Throughput | ~852K req/s |
| Avg latency | ~300µs |
| p50 latency | ~285µs |
| p99 latency | ~715µs |
| p99.9 latency | ~897µs |
| Packet loss | 0% |

Multi-threading (`--threads N`) spawns N server threads (SO_REUSEPORT) and N
client threads. Scaling is limited on loopback since the kernel serializes
UDP processing through the loopback device. Gains are expected with real NICs
(RSS queue distribution) or CPU-intensive handlers.

Benchmark options: `--count`, `--window`, `--payload`, `--con`, `--threads`, `--no-server`.
