# Changelog

## [0.2.0] - 2026-03-08
- RST message handling
- .well-known/core resource discovery (RFC 6690)
- Multi-threaded server via SO_REUSEPORT
- Percentile latency in benchmark

## [0.1.0] - 2026-03-08
- CoAP server on io_uring with multishot recvmsg
- CON/ACK reliability with duplicate detection
- Handler interface: fn(Request) ?Response
- Pipelined benchmark client with embedded server
