# Changelog

## [0.2.3] - 2026-03-09
- Request convenience accessors: method(), payload(), pathSegments(), querySegments(), findOptions()
- Response convenience constructors: ok(), content(), notFound(), badRequest(), etc
- Client path convenience methods: get(), post(), put(), delete()
- Re-export Code, Option, OptionKind, ContentFormat at root
- Hide Result.owns_payload implementation detail

## [0.2.2] - 2026-03-09
- CoAP client library: cast, call, sendRaw/recvRaw, observe, upload
- Block2 transparent reassembly, Block1 segmented upload
- RFC 7641 observe with ObserveStream
- Zero-alloc ObserveStream.nextBuf with caller-provided buffer

## [0.2.1] - 2026-03-08
- Fix bench hang, remove unnecessary register_buffers

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
