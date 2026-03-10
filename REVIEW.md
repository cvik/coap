# coap Project Review

## Overall Assessment

This is a well-crafted, focused CoAP server library at ~2,200 lines of source code (excluding tests/bench). For a v0.2.0, it's surprisingly mature in its core hot path, but has gaps in protocol coverage and some areas worth hardening.

---

## 1. Standards Compliance (RFC 7252)

**Good:**
- Transmission parameters in `constants.zig` are correct per section 4.8
- Exchange lifetime derivation matches section 4.8.2
- CON/ACK reliability with piggybacked responses, empty ACK for null handlers
- RST handling correctly cancels exchanges
- `.well-known/core` (RFC 6690) with correct Content-Format option
- Default port 5683, buffer size 1280 (IPv6 minimum MTU)
- Server-side msg_id for NON responses (section 4.4)

**Gaps / Issues:**
- **No separate response (section 5.2.2):** Only piggybacked ACK is supported. If a handler takes time (e.g. sensor read), the spec requires sending an empty ACK immediately, then a CON response later. Currently the server blocks until the handler returns.
- **No CON retransmission on the server side:** The server never retransmits its own CON responses. The response caching is only for dedup of incoming duplicate CON, not outbound reliability.
- **No block-wise transfer (RFC 7959):** Payload > 1 MTU can't be served. Acceptable for v0.2 but limits real-world use.
- **No observe (RFC 7641):** Expected for a CoAP server.
- **No DTLS (RFC 6347):** No security layer.
- **IPv6 not supported** -- explicitly called out, but RFC 7252 mandates IPv6 support (section 1).
- **Token matching for dedup uses only msg_id + peer address** -- this is correct per spec, but `peer_key` hashes the full `sockaddr` (16 bytes), which includes padding. The hash is used only for the table, and the `peer_key` is stored as a u64 for comparison -- collisions on the 64-bit hash could theoretically cause false dedup matches (wrong exchange found for a different peer). Very unlikely with FNV-1a on 18 bytes, but worth noting.
- **`handler_warn_ns` timing is wrong** (`Server.zig:650-655`): The elapsed time is computed as `after - server.tick_now_ns`, but `tick_now_ns` is set once per tick, not per handler invocation. If you process 100 packets in one tick, only the first handler's timing is roughly correct -- later ones accumulate the time of all previous handlers.

## 2. Performance

**Strengths:**
- Zero allocation hot path -- arena resets per batch, excellent
- Direct encoding into response buffer (`writeBuf`) avoids alloc+copy
- io_uring multishot recvmsg -- kernel-side batching
- Pre-allocated response buffers, iovecs, msghdr arrays
- Periodic SQ flush every 64 processed CQEs to keep buffers flowing
- Adaptive arena reset (free_all after busy ticks, retain_with_limit otherwise)
- ~737K req/s on loopback is strong

**Opportunities:**
- **`evict_expired` is O(n) linear scan over all slots** (`exchange.zig:213`). At 256 slots this is fine, but at higher `exchange_count` this becomes a bottleneck called every 10 seconds. A min-heap or sorted list by timestamp would be O(k log n) where k = evicted.
- **Eviction inside `handle_recv`** (`Server.zig:700`): When the exchange pool is full and insert fails, the server does an emergency `evict_expired` scan -- this happens inline in the hot path per-packet. Under sustained CON traffic this can be called for every single packet.
- **`update_load_level` uses `buffers_peak` which resets every tick** (`Server.zig:809`). This means load level oscillates on a per-tick basis rather than being smoothed. A moving average or exponential decay would give more stable load signals.
- **No registered buffers for sends** -- only recvs use provided buffers. Sends go through the normal path. For extreme throughput, `IORING_OP_SEND_ZC` with registered buffers could help.
- **Single `nanoTimestamp()` per tick** -- good for reducing syscalls, but means handler timing (when enabled) is imprecise for multi-packet ticks.
- **`batch * config.buffer_size` for response buffers** (`Server.zig:176`): With defaults this is `256 * 1280 = 320KB`. Fine for defaults, but if someone sets `buffer_size = 65535` and `buffer_count = 1024`, this balloons to ~16MB for response buffers alone plus another 16MB for response_buffer in exchange.

## 3. TigerStyle Compliance

**Good practices aligned with TigerStyle:**
- Pre-allocation of all resources at init, no allocation in the hot path
- Fixed-size data structures (exchange pool, rate limiter, buffer pool)
- Saturating arithmetic (`+|=`, `-|=`, `*|`) used for buffer tracking
- Error returns instead of panics for config validation
- Bounded retry loops (3 consecutive failures, max_worker_restarts)
- `debug.assert` for internal invariants (not user-facing)

**Deviations:**
- **`debug.assert` in exchange.zig:160** (`find(key) == null` before insert) -- this runs on every insert in debug builds but is stripped in release. If a double-insert ever happens in production, it silently corrupts the table. Should be an explicit check that returns null or an error.
- **`debug.assert` in `send_data`** (`Server.zig:875`) -- asserts `index < batch`. Should be a bounds check that returns error since `index` comes from CQE iteration.
- **`debug.assert` in Io.zig:166** (`buffer_id < buffer_count`) -- should be an error return since buffer_id comes from CQE.
- **No allocation limits on arena** -- the arena can grow unbounded within a tick if the handler allocates heavily. `max_arena_size` only trims *after* the tick. A handler that allocates 1GB in a single call will succeed and then be trimmed. Consider `std.heap.ArenaAllocator` with a `FixedBufferAllocator` backing to hard-cap.
- **`unreachable` in bench** (`client.zig:298`) after `server.run()` -- correct since run() is infinite loop, but TigerStyle would prefer an explicit exit.

## 4. Ergonomics

**Strong points:**
- Simple handler interface: `fn(Request) ?Response` -- hard to get wrong
- Good defaults -- `.{}` config works out of the box
- `safeWrap` / `safeWrapContext` for error handling
- `initContext` for passing state without globals
- Well-documented README with examples for every feature

**Suggestions:**
- **No routing abstraction** -- the README shows manual URI matching. While simplicity is a feature, even a minimal `fn route([]const u8, handler) void` would improve adoption.
- **Response builder missing** -- building options requires manual buffer management (see Response Options example). A `ResponseBuilder` using the arena would help.
- **No way to access the server from inside a handler** -- you can't get metrics, call `stop()`, or access config from within a handler. The context mechanism helps but doesn't expose server state.
- **`initContext` erases the type** -- if you pass the wrong type, you get a crash at runtime rather than a compile error. The current implementation is correct but the `@ptrCast(@alignCast(ctx.?))` in the generated trampoline will invoke safety-checked UB in debug and silent UB in release if types mismatch.

## 5. Memory Usage

**Good:**
- All memory pre-allocated at init -- predictable footprint
- Arena resets per tick prevent leaks
- Emergency ACK buffers are pre-allocated for OOM handling

**Detailed memory breakdown (defaults):**

| Component | Size |
|-----------|------|
| io_uring buffers | 512 * 1280 = 640 KB |
| io_uring iovecs | 512 * 16 = 8 KB |
| Exchange slots | 256 * ~40 = 10 KB |
| Exchange response cache | 256 * 1280 = 320 KB |
| Exchange hash table | 512 * 2 = 1 KB |
| Response buffers | 256 * 1280 = 320 KB |
| Response addrs/msgs/iovs | 256 * ~100 = 25 KB |
| Emergency ACK | 256 * 4 = 1 KB |
| RST buffers | 256 * 4 = 1 KB |
| Rate limiter slots | 1024 * ~32 = 32 KB |
| Rate limiter table | 2048 * 2 = 4 KB |
| Arena (trimmed) | up to 256 KB |
| **Total** | **~1.6 MB per thread** |

This is very reasonable. The dominant cost is response caching in the exchange pool.

**Concerns:**
- **`Slot.completed_at_ns` is `i128` (16 bytes)** in both exchange.zig and rate_limiter.zig -- this is oversized. `i64` nanoseconds covers ~292 years. Using `i128` doubles the per-slot overhead and causes alignment padding.
- **Rate limiter `Slot.last_refill_ns` is also `i128`** -- same issue.
- Each exchange slot holds the full `response_size_max` (1280 bytes by default) even for a 4-byte empty ACK.

## 6. Correctness

**Verified correct:**
- CON dedup logic: find -> cached retransmit; miss -> handle -> insert
- RST cancellation removes from hash table with proper backward-shift
- Empty ACK sent when handler returns null for CON
- NON null handler -> no response (tested)
- Emergency ACK correctly extracts msg_id from raw header
- Rate limiter fail-open when table is full (good: avoids DoS of all IPs)
- Worker restart with exponential backoff
- `next_msg_id` initialized from `std.crypto.random.int(u16)` (RFC 7252 section 4.4)

**Potential bugs:**
- **`is_con_raw` check** (`Server.zig:557`): `((recv.payload[0] >> 4) & 0x03) == 0` -- the CoAP version bits are in bits 7:6, type bits are in bits 5:4. `>> 4` gives `ver:type` as bits 3:2:1:0. Then `& 0x03` masks to just the type bits. CON = 0b00, so `== 0` is correct. **However**, this also matches if the version is wrong (e.g. garbage byte) and type bits happen to be 0. Not a real bug but slightly fragile.
- **Handler timing** (`Server.zig:650-655`): As noted above, `elapsed` measures time since tick start, not since handler invocation. For ticks processing multiple packets, this over-reports for later handlers.
- **Race in context handlers with multi-threading** (`Server.zig:281`): All worker threads receive the same `handler_context` pointer. If the context is mutable (like the `counter` example in README), this is a data race. The README example `ctx.counter += 1` is UB under `thread_count > 1`. The README should warn about this, or the server should document that `initContext` state must be thread-safe.

## 7. Robustness

**Good defenses:**
- Malformed packets logged at debug level, not fatal
- Buffer release failure -> flush + retry once -> log error (buffer lost)
- Multishot recv failure -> re-arm
- Transient error retry with 3-strike limit
- Worker restart with backoff and max restarts
- Load shedding with hysteresis (throttle/shed/recover thresholds)
- Pre-allocated RST/ACK for shedding mode -- no allocation needed
- `release_buffer_robust` with retry

**Attack surface / edge cases:**
- **Amplification:** A spoofed-source CON GET with a small request can trigger a large response (e.g. `.well-known/core`). The server has rate limiting but no per-response amplification awareness. CoAP amplification is a known attack vector (RFC 7252 section 11.3).
- **Exchange pool poisoning:** An attacker can fill the exchange pool with CON messages from spoofed sources. Each exchange lives for `exchange_lifetime_ms` (~247 seconds). With only 256 slots, ~1 CON/second from spoofed IPs would fill the pool and disable dedup for legitimate clients. Rate limiting helps but only kicks in at the throttle threshold.
- **Token/msg_id collision:** 16-bit msg_id space means collisions within exchange_lifetime from the same source. The spec requires endpoints to spread msg_ids, but a malicious client could reuse them to evict cached responses.
- **`Packet.read` allocates into arena** -- a crafted packet with many options or large option values could cause large arena allocations. The arena is unbounded within a tick.
- **No packet size validation beyond `buffer_size`** -- truncated packets (MSG_TRUNC) are handled by io_uring buffer sizing, but there's no explicit check for minimum CoAP header size (4 bytes) before the raw_header extraction at `Server.zig:538`. The `recv.payload.len >= 4` check is there, so this is fine.
- **The `drain()` function is minimal** -- it submits and reads once. If there are queued sends, they may be lost during shutdown.

## 8. OOM Handling for Requests

This is handled well for a v0.2:

1. **`Packet.read` OOM** (`Server.zig:582-583`): Sends emergency ACK (for CON), logs warning, returns -- packet dropped gracefully.
2. **Response encoding OOM** (`Server.zig:678-680`): Same emergency ACK path.
3. **Well-known/core option dupe OOM** (`Server.zig:634-638`): Emergency ACK.
4. **Exchange pool exhausted** (`Server.zig:698-706`): Emergency eviction attempt, then degrades gracefully (response sent but not cached -- no dedup for that exchange).
5. **Emergency ACK buffers are pre-allocated** -- can't OOM when sending them.

**Gaps:**
- **Arena OOM during handler execution:** If the handler uses the arena and it can't allocate, the handler itself must deal with it. `safeWrap` converts errors to 5.00, which works. But a handler that tries to build response options and fails has no pre-allocated fallback -- the 5.00 response itself needs to be encoded, which could also OOM if the arena is truly exhausted. In practice the arena would need to be unable to get a new page from the OS for this to happen, so it's very unlikely.
- **io_uring SQE exhaustion:** `get_sqe()` can fail if the ring is full. Most calls handle this with `try`, which propagates up and drops the packet. The `release_buffer_robust` retry helps, but if the ring is persistently full, buffers leak permanently.

---

## Summary Scores

| Area | Score | Notes |
|------|-------|-------|
| Standards compliance | 7/10 | Core protocol correct; missing separate response, observe, block, IPv6 |
| Performance | 9/10 | Excellent hot path; minor opportunities in eviction and load smoothing |
| TigerStyle | 8/10 | Strong pre-allocation discipline; some debug.assert should be error returns |
| Ergonomics | 7/10 | Clean API; lacks routing, response builder |
| Memory | 8/10 | Predictable; i128 timestamps wasteful; exchange cache uses fixed max per slot |
| Correctness | 8/10 | Solid; handler timing inaccurate; context threading undocumented |
| Robustness | 8/10 | Good graceful degradation; exchange pool poisoning possible |
| OOM handling | 9/10 | Emergency ACK path is well thought out |

**Overall: solid v0.2 library.** The core hot path is production-quality. The main maturity gaps are in protocol feature completeness (separate response, observe, block) rather than code quality. The most actionable improvements would be:

1. Fix handler timing to measure per-invocation
2. Document thread-safety requirements for context handlers
3. Convert hot-path `debug.assert` to error returns
4. Downsize `i128` timestamps to `i64`
5. Add amplification awareness or at least document the risk
