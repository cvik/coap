# Changelog

## [0.7.0] - 2026-03-20
- Comptime request router: `coap.Router(.{ .{ .get, "/path", handler }, ... })`
- Route parameters: `/sensor/:id` with `req.param("id")` accessor
- URI helpers: `uri.fromPath()`, `uri.fromQuery()`, `uri.fromUri()`
- Client convenience methods now accept query strings (`/path?key=val`)
- DTLS server-side flight retransmission with cached flights (RFC 6347 §4.2.4)
- Bench: CPU affinity for server threads in multi-thread scenarios
- **Tier 6 ergonomics complete** (6.1-6.2)

## [0.6.2] - 2026-03-19
- Fix: Block2 use-after-free — Size2 on last block read after slot release (#45)
- Fix: MPSC ring race condition — sequenced Vyukov-style ring in deferred and observe (#46, #47, #57)
- Fix: wrong buffer index in drainNotifications (#47)
- Fix: `debug.assert` replaced with `@panic` for precondition checks in release builds (#48)
- Fix: CTR counter wrapping consistency in AES-CCM scalar path (#49)
- Fix: `observer_count` made atomic for thread safety (#50)
- Fix: retransmit backoff bound uses `max_retransmit` (#51)

## [0.6.1] - 2026-03-19
- Request-Tag (RFC 9175 §3) for Block1 upload disambiguation
- Echo option (RFC 9175 §2) request/response helpers for freshness verification
- Conditional request accessors: `ifMatch()`, `ifNoneMatch()`, `etags()`, `preconditionFailed()`
- Size1 rejection (4.13 Request Entity Too Large) and Size2 in Block2 responses
- **Tier 3 protocol extensions now fully complete** (3.1-3.4)

## [0.6.0] - 2026-03-18
- Server-side Observe: `server.notify(rid, response)` thread-safe push API (RFC 7641)
- `Request.observeResource(rid)` / `removeObserver(rid)` handler methods
- Server-side Block2: transparent large response fragmentation (RFC 7959)
- Server-side Block1: transparent upload reassembly (RFC 7959)
- Client observe sequence freshness check (RFC 7641 §3.4)
- Shared `BlockTransfer` pool (`Config.max_block_transfers`, `max_block_payload`)
- Updated to coapz v0.3.0 (zero-alloc peek helpers, emptyAck/emptyRst)
- **Tier 2 server-side protocol features now fully complete** (2.1-2.4)

## [0.5.1] - 2026-03-17
- Separate (delayed) responses: `Request.deferResponse()` API (RFC 7252 §5.2.2)
- Pre-allocated deferred pool with lock-free MPSC queue (`Config.max_deferred`)
- CON retransmission with exponential backoff for separate responses
- ACK/RST handling for deferred response lifecycle
- Tier 1 RFC 7252 core compliance now fully complete (1.1-1.5)

## [0.5.0] - 2026-03-16
- IPv6 support: server, client, DTLS, bench `--ipv6` flag
- Dual-stack via `IPV6_V6ONLY=0` when binding `::`
- Critical option rejection with 4.02 Bad Option (RFC 7252 §5.4.1)
- NSTART congestion control for new peers (RFC 7252 §4.7)
- Bench: DTLS NON scenarios with server-side throughput measurement
- Bench: shared-memory `ServerCounters` for NON req/s accuracy

## [0.4.2] - 2026-03-14
- DTLS: parallelize AES-CTR in CCM using `xorWide` (AES-NI pipelining)
- Bench: tree-structured output grouped by transport → type → thread/payload
- Bench: colored output, single-line progress, suppress server logs

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
