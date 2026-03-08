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

## Roadmap

- [ ] CON/ACK reliability (retransmission, duplicate detection)
- [ ] io_uring benchmark client
- [ ] Routing
- [ ] Multi-threading with SO_REUSEPORT
- [ ] .well-known/core resource discovery

## Benchmarks

TBD
