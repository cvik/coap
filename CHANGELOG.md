# Changelog

## [0.4.1] - 2026-03-13
- Server auto-clamps `buffer_count` to fit RLIMIT_MEMLOCK at init
- Bench: comma-separated large numbers in output, `--settings` and `--help` flags
- Bench: use all CPUs for multi-thread scenarios (was capped at 16)
- Bench: auto-scale server buffers and window per thread count

## [0.4.0] - 2026-03-13
- Pipelined async client API: `submit()` / `poll()` for high-throughput workloads
- `RequestHandle` and `Completion` types for non-blocking request/response
- Replace sleep-polling with `posix.poll()` syscall (eliminates 500µs latency floor)
- `call()` refactored as `submit` + `poll` wrapper (no API change)
- Transparent Block2 reassembly in async mode with stable handle tracking
- DTLS benchmark: pipelined sliding window (~1.8K → ~139K req/s)

## [0.3.0] - 2026-03-12
- DTLS 1.2 PSK security (RFC 6347) for server and client
- TLS_PSK_WITH_AES_128_CCM_8 cipher suite (RFC 7252 §9 mandatory)
- Pure Zig AES-128-CCM-8 AEAD and TLS 1.2 PRF implementation
- Stateless cookie exchange for anti-amplification (RFC 6347 §4.2.1)
- Pre-allocated session table with O(1) LRU eviction
- Anti-replay sliding window (64-bit, RFC 6347 §4.1.2.6)
- Client DTLS handshake with RFC 6347 §4.2.4 retransmission
- Auto port switching to 5684 (CoAPS) when PSK configured
- Wire discrimination: DTLS vs plain CoAP on same server
- Request.is_secure flag for handler-level security detection
- Benchmark --dtls flag for DTLS throughput measurement

## [0.2.6] - 2026-03-12
- Server: peer-based exchange eviction on new CON request from same address
- Server: configurable `exchange_lifetime_ms` option (default: RFC 7252 derived)
- Exchange: `addr_hash()` and `evict_peer()` for address-only eviction

## [0.2.5] - 2026-03-11
- Client: fix double-free of in-flight slot on timeout/reset in call()
- Server: add 50ms tick timeout so run loop exits on SIGINT without traffic

## [0.2.4] - 2026-03-10
- Server: measure handler duration per-invocation instead of per-tick
- Server: validate CoAP version before processing (drop non-v1 packets)
- Server: convert hot-path debug.assert to error returns (exchange.insert, send_data, Io.release_buffer)
- Server: downsize i128 timestamps to i64 (less cache pressure)
- Server: document thread-safety for context handlers
- Client: fix Block2 reassembly for blockwise observe notifications
- Client: send observe CON re-registrations on notification timeout
- Client: validate Block1 response option presence before upload continue
- Client: use random token for observe re-registration
- Client: use stack buffers for cast/sendRaw
- Comprehensive doc comments and autodoc

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
