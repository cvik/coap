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
zig build bench -Doptimize=ReleaseFast -- --count 1000000 --threads 4
```

| Metric | 1 thread | 4 threads |
|--------|----------|-----------|
| Throughput | ~794K req/s | ~871K req/s |
| Avg latency | ~322µs | ~294µs |
| p50 latency | ~282µs | ~279µs |
| p99 latency | ~715µs | ~623µs |
| p99.9 latency | ~1076µs | ~829µs |
| Packet loss | 0% | 0% |

Benchmark options: `--count`, `--window`, `--payload`, `--con`, `--threads`, `--no-server`.
