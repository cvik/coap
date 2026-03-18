# Protocol Compliance Roadmap

Status as of v0.6.0 (2026-03-18). Items ordered by priority within each tier.

Legend: `[x]` done, `[-]` partial, `[ ]` not started

---

## Tier 1 — RFC 7252 Core Compliance

These are protocol violations or mandatory omissions in the base CoAP spec.

### 1.1 Critical option rejection (§5.4.1)
- **Status:** `[x]` done
- **Issue:** Server silently ignores unrecognized critical options. RFC requires
  returning 4.02 Bad Option for any critical option (odd number) not understood.
- **Impact:** Breaks extensibility — endpoints using OSCORE or other critical-option
  extensions will have their constraints silently ignored.
- **Effort:** Small. Per-packet check in server recv path. Must be branchless or
  very cheap to avoid hot-path regression.
- **Perf note:** Single bitmask check per option during packet iteration. Negligible.
- **Resolution:** Server checks all options after parse, before handler dispatch.
  Unrecognized critical options return 4.02 Bad Option (both plain and DTLS paths).
  Users can extend via `Config.recognized_options`.

### 1.2 Separate (delayed) responses (§5.2.2)
- **Status:** `[x]` done
- **Issue:** Server always piggybacks response in ACK. No way for a handler to
  say "I need more time" — the server blocks until the handler returns. Slow
  handlers cause client retransmissions and timeouts.
- **Resolution:** Handler calls `request.deferResponse()` to get a
  `DeferredResponse` handle. Server sends empty ACK immediately. Handler
  delivers the response later (from any thread) via `handle.respond()`.
  Response sent as separate CON with exponential-backoff retransmission.
  Pre-allocated pending pool (`Config.max_deferred`, default 16) with
  lock-free MPSC queue. Zero overhead for synchronous handlers.

### 1.3 NSTART / congestion control (§4.7)
- **Status:** `[x]` done
- **Issue:** Client allows `max_in_flight` (default 32) simultaneous CONs. RFC
  mandates NSTART=1 for unknown/new peers until first response received.
- **Impact:** Spec violation. Could cause congestion on constrained links.
- **Effort:** Small. Track "peer confirmed" state in client. Gate in-flight count
  until first successful exchange.
- **Perf note:** After first response, pipelining resumes at full speed. Only
  cold-start is affected.
- **Resolution:** Client tracks `peer_confirmed` flag. `submit()` returns
  `error.NstartExceeded` when unconfirmed and `count_active >= nstart`. Confirmed
  on first response via `poll()`, `waitForResponse()`, or `routeObserve()`.

### 1.4 IPv6 support (§1)
- **Status:** `[x]` done
- **Issue:** AF_INET hardcoded in Io.zig, Client.zig, Server.zig. `sockaddr.in`
  cast in `decode_recv()` would overflow for `sockaddr_in6`. RFC 7252 treats
  IPv6 as essential.
- **Resolution:** Family auto-detected from bind/host address. Dual-stack via
  `IPV6_V6ONLY=0` when binding `"::"`. Family-aware address hashing in exchange,
  rate_limiter, DTLS Cookie, and DTLS Session. Bench supports `--ipv6` flag.

### 1.5 Option order validation on decode (§5.4.6)
- **Status:** `[x]` done — structurally enforced by delta encoding
- **Issue:** Incoming packets with out-of-order options are accepted silently.
  RFC requires options in ascending order; malformed packets should be rejected.
- **Impact:** Low practical impact but technically non-compliant. Could mask
  option-reordering attacks.
- **Resolution:** CoAP wire format uses delta encoding (unsigned additions to a
  running sum in `Packet.read()`), which structurally guarantees ascending option
  order on decode. No additional check needed — the property holds by construction.
  Encode path already validates via `UnsortedOptions` error.

---

## Tier 2 — Server-Side Protocol Features

The client handles these; the server does not.

### 2.1 Server-side Observe (RFC 7641)
- **Status:** `[x]` done
- **Issue:** Server receives observe registrations but cannot maintain an observer
  list or push notifications. This is the biggest functional gap.
- **Resolution:** Pre-allocated `ObserverRegistry` with resource slots and
  per-resource observer lists. Handler registers clients via
  `request.observeResource(rid)`. Application pushes notifications via
  thread-safe `server.notify(rid, response)` using lock-free MPSC queue.
  Tick loop sends NON notifications with auto-incrementing Observe sequence.
  Observers evicted on RST. Config: `max_observers` (256), `max_observe_resources` (64).

### 2.2 Server-side Block2 — large responses (RFC 7959)
- **Status:** `[x]` done
- **Issue:** Server responses capped at buffer_size (1280 bytes). No
  fragmentation engine for larger payloads.
- **Resolution:** Handler returns full payload; server fragments transparently.
  Shared `BlockTransfer` pool (`Config.max_block_transfers`, default 32) caches
  full payload and serves blocks on demand. SZX negotiation supported.

### 2.3 Server-side Block1 — large uploads (RFC 7959)
- **Status:** `[x]` done
- **Issue:** Server cannot receive payloads larger than one packet. No block
  reassembly on inbound requests.
- **Resolution:** Server reassembles Block1 fragments transparently. Handler
  sees the complete payload only after all blocks arrive. 2.31 Continue sent
  for intermediate blocks. Max upload size configurable via
  `Config.max_block_payload` (default 64KB). Shared pool with Block2.

### 2.4 Observe sequence reordering (RFC 7641 §3.4)
- **Status:** `[x]` done
- **Issue:** Client has `last_seq` field but `routeObserve()` never compares
  incoming sequence numbers. Stale/reordered notifications delivered as fresh.
- **Resolution:** Client extracts Observe option from wire data, compares with
  `last_seq` using 24-bit wrap-around freshness check per §3.4. Stale/duplicate
  notifications dropped silently.

---

## Tier 3 — Protocol Extensions

Important extensions beyond base CoAP.

### 3.1 Request-Tag (RFC 9175 §3)
- **Status:** `[ ]` not implemented
- **Issue:** Block1 reassembly uses token alone to match fragments. When
  multiple clients upload concurrently to the same resource, fragments can
  be mixed. Request-Tag disambiguates.
- **Impact:** Correctness issue under concurrent Block1 uploads.
- **Effort:** Small-medium. Add Request-Tag option generation in client uploads,
  matching in server Block1 reassembly (once 2.3 is implemented).

### 3.2 Echo option (RFC 9175 §2)
- **Status:** `[ ]` not implemented
- **Issue:** No mechanism for server to verify request freshness or client
  reachability. Needed to defend against replay attacks and IP spoofing.
- **Impact:** Security gap for deployments exposed to untrusted networks.
- **Effort:** Small. Server generates Echo value, client reflects it. State is
  a single opaque token per peer.

### 3.3 Conditional requests (§5.10.1-2)
- **Status:** `[-]` options parseable, no server enforcement
- **Issue:** If-Match and If-None-Match are defined in coapz but server never
  validates preconditions. No automatic 4.12 Precondition Failed.
- **Impact:** Handlers must implement conditional logic manually.
- **Effort:** Small for server-side pre-check. Requires ETag tracking which is
  application-specific, so likely remains handler-assisted.

### 3.4 Size1/Size2 options
- **Status:** `[-]` defined, not enforced
- **Issue:** No automatic 4.13 Request Entity Too Large when payload exceeds
  Size1. No Size2 in responses for total payload indication.
- **Impact:** Constrained devices can't pre-negotiate acceptable sizes.
- **Effort:** Small. Check Size1 against buffer capacity before handler dispatch.

---

## Tier 4 — Transport & Security

### 4.1 DTLS session resumption
- **Status:** `[-]` fields allocated in Session struct, unused
- **Issue:** Every reconnect requires full handshake (3 flights, ~1-3s worst
  case). Session ID fields exist but server always sends session_id_len=0.
- **Impact:** High latency on reconnect. Matters for mobile/intermittent clients.
- **Effort:** Medium. Requires:
  - Server assigns session_id in ServerHello
  - Client caches session_id + master_secret
  - Abbreviated handshake path in state machine
  - Session cache with TTL eviction

### 4.2 Server-side DTLS flight retransmission
- **Status:** `[-]` TODO at Server.zig:677
- **Issue:** Server relies on client to drive retransmission during handshake.
  Violates RFC 6347 §4.2.4 which requires both sides to retransmit.
- **Impact:** Handshakes may fail when server→client packet is lost.
- **Effort:** Small-medium. Scan handshaking sessions in tick loop, retransmit
  expired flights.

### 4.3 Additional DTLS cipher suites
- **Status:** `[ ]` single suite only
- **Issue:** Only TLS_PSK_WITH_AES_128_CCM_8. No alternatives for devices that
  prefer GCM or need AES-256.
- **Impact:** Limits interop with peers that require different suites.
- **Effort:** Medium per suite. Requires AEAD abstraction, cipher dispatch in
  handshake, and suite negotiation logic.
- **Candidate:** TLS_PSK_WITH_AES_128_GCM_SHA256 as second suite.

### 4.4 CoAP over TCP (RFC 8323)
- **Status:** `[ ]` not implemented
- **Issue:** No TCP transport. Blocks enterprise/cloud gateway use cases where
  UDP is firewalled or NAT is hostile.
- **Impact:** Cannot serve web-facing or enterprise deployments behind
  restrictive firewalls.
- **Effort:** Large. Essentially a parallel transport layer:
  - TCP framing (length-prefixed messages, no msg_id/ACK/CON)
  - Signaling messages (CSM, Ping, Pong, Release, Abort)
  - TLS instead of DTLS
  - No dedup needed (TCP is reliable)
  - Shared handler interface
- **Perf note:** io_uring is well-suited for TCP too. Could share the Io
  abstraction.

### 4.5 DTLS Connection ID (RFC 9146)
- **Status:** `[ ]` not implemented
- **Issue:** NAT rebinding or IP migration breaks DTLS sessions. CID allows
  sessions to survive address changes.
- **Impact:** Relevant for mobile clients or long-lived sessions behind NAT.
- **Effort:** Medium. CID negotiation in handshake + CID field in record header.

### 4.6 DTLS certificate auth (X.509, raw public keys)
- **Status:** `[ ]` PSK only
- **Issue:** No certificate-based authentication. Limits deployments that use
  PKI infrastructure.
- **Impact:** Cannot integrate with enterprise PKI or mTLS workflows.
- **Effort:** Large (5+ days). Requires ASN.1/X.509 parsing, signature
  verification (RSA/ECDSA), certificate chain validation.
- **Note:** Consider whether this belongs in the library or should be delegated
  to a DTLS proxy. PSK covers most IoT use cases.

---

## Tier 5 — Nice to Have

### 5.1 Multicast (RFC 7252 §8, RFC 7390)
- Group join/leave, multicast request handling, NON-only responses.
- Enables "discover all sensors on subnet" use cases.

### 5.2 OSCORE (RFC 8613)
- Object-level security alternative to DTLS. End-to-end through proxies.
- Relevant for constrained devices that can't afford DTLS.

### 5.3 Proxy support (RFC 7252 §5.7)
- Forward-proxy and reverse-proxy with Proxy-Uri/Proxy-Scheme options.
- Likely a separate component built on top of the library.

### 5.4 DNS hostname resolution
- Client currently requires dotted-quad IP. Adding `getaddrinfo` would
  improve usability but adds a blocking syscall concern.

### 5.5 CoAP over WebSocket (RFC 8323)
- WebSocket framing for browser-based CoAP clients. Niche but growing.

---

## Performance Invariants

Any work on the above must preserve these properties:

1. **Zero allocations in the hot path** — arena resets, pre-allocated buffers
2. **Pre-allocated fixed-size data structures** — no runtime growth
3. **No per-packet syscalls beyond io_uring** — batch submission
4. **Common-case paths pay no tax for optional features** — separate responses,
   block transfers, observe registries must not add overhead when unused
5. **Benchmark regression gate** — run `zig build bench -Doptimize=ReleaseFast`
   before and after. No regressions in req/s or p99 latency for plain
   NON/CON echo workloads.

---

## Suggested Implementation Order

Tier 1 and Tier 2 complete. Remaining sequence:

1. ~~**1.1** Critical option rejection~~ ✓
2. ~~**1.5** Option order validation~~ ✓
3. ~~**1.3** NSTART enforcement~~ ✓
4. ~~**1.4** IPv6~~ ✓
5. ~~**1.2** Separate responses~~ ✓
6. ~~**2.4** Observe sequence check~~ ✓
7. ~~**2.2** Server Block2~~ ✓
8. ~~**2.3** Server Block1~~ ✓
9. ~~**2.1** Server Observe~~ ✓
10. **3.4** Size1/Size2 — small, server pre-check
11. **3.1** Request-Tag — completes Block1 correctness
12. **3.2** Echo option — completes security posture
13. **4.2** Server DTLS retransmit — completes DTLS compliance
14. **4.1** DTLS session resumption — performance for reconnects
15. **4.3** Additional cipher suites — interop
16. **4.4** CoAP over TCP — new transport
