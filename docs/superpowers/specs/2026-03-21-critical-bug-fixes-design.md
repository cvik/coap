# Critical Bug Fixes (#81-#84)

Fixes for 4 high-severity bugs found in external code review (CODE_REVIEW.md).
All fixes use TDD — failing integration test first, then implementation.

## #81 — Block1 body never reaches handler

**Problem:** `handleBlock1()` returns `?handler.Response`. On completion it returns `null`
to signal "fall through to handler", but the caller still has the original `packet` with
only the last fragment's payload. The reassembled body in the block transfer pool is never
passed to the handler.

**Fix:**

1. New return type replacing `?handler.Response`:
   ```
   const Block1Result = union(enum) {
       response: handler.Response,  // intermediate/error — send and return
       complete: u16,               // slot index — get payload, call handler, release
   };
   ```

2. Add `payload_override: ?[]const u8 = null` field to `handler.Request`.

3. Change `request.payload()` to return `payload_override orelse packet.payload`.

4. At call site (both UDP and DTLS paths): on `.complete`, set
   `request.payload_override = bt.payloadSlice(idx)`, call handler, then `bt.release(idx)`.

**Test:** Client uploads multi-block body. Server handler asserts received payload equals
full original body, not just the last fragment.

## #82 — Observe notifications use wrong token

**Problem:** `ObserverRegistry.notify()` encodes a single template packet with hardcoded
`token = &.{0}`. `drainNotifications()` sends this template unchanged to all observers.
RFC 7641 requires each notification carry the client's registration token.

**Fix:**

1. `notify()` stores response metadata (code, options, payload) in the notification buffer
   instead of a pre-encoded packet. Add a small header: `response_code: u8`,
   `options_len: u16`, then options bytes, then payload bytes.

2. `drainNotifications()` encodes per-observer: reads metadata from buffer, constructs
   `coapz.Packet` with `token = obs.token[0..obs.token_len]` and a fresh `msg_id`, then
   encodes and sends.

3. This naturally combines with #83 — per-observer encoding lets us choose plain vs DTLS
   send path per observer.

**Test:** Client registers observe on a resource. Server notifies. Client asserts the
notification token matches its registration token.

## #83 — DTLS follow-up sent as plaintext

**Problem:** `drainDeferred()` and `drainNotifications()` use `send_data()` (plain UDP)
for all peers, including those connected via DTLS. Secure requests produce plaintext
follow-up traffic.

**Fix:**

1. Add `send_dtls_raw(session, data, peer, index)` — like `send_dtls_packet()` but takes
   pre-encoded CoAP bytes instead of a `coapz.Packet`. Encrypts into DTLS application_data
   record and sends.

2. In `drainDeferred()`: before sending, check `server.dtls_sessions.lookup(peer)`. If
   session found, use `send_dtls_raw()`. Otherwise `send_data()`.

3. In `drainNotifications()`: same pattern per observer. Combined with #82's per-observer
   encoding, check session and use `send_dtls_packet()` (takes Packet) directly.

Cost: one hash lookup per send — negligible.

**Test:** DTLS client sends CON request, handler defers response. Verify the deferred
response goes through the DTLS encrypted send path (not plain UDP).

## #84 — DTLS path has no block handling

**Problem:** `process_dtls_coap` goes straight from parse to handler with no Block1/Block2/
Size1 handling. The plain UDP path has all three (lines 1021-1081 in Server.zig).

**Fix:** Extract 3 shared helpers from the plain UDP inline code:

1. **`handleBlock2Followup(bt, packet, peer) -> ?Block2Response`**
   Extracted from lines 1021-1051. Checks for Block2 option with num > 0, looks up cached
   transfer, serves the requested block. Returns response data or null.

2. **`checkSize1(packet, block_transfers, config) -> ?handler.Response`**
   Extracted from lines 1053-1066. Returns 413 if declared size exceeds max, else null.

3. **`blockifyResponse(bt, response, packet, config) -> ?BlockifiedResponse`**
   Extracted from lines 1119-1145. If response payload exceeds block size, allocates
   transfer slot, stores payload, returns first block with Block2+Size2 options.

Both `handle_recv` and `process_dtls_coap` call these helpers. Plain path uses `send_data`/
`send_packet` for responses; DTLS path uses `send_dtls_packet`.

**Test:** DTLS client uploads multi-block body — handler asserts full reassembled payload.
DTLS client requests large resource — verify response is delivered via Block2 transfer.

## Implementation order

1. #81 (Block1 delivery) — foundational, #84 depends on it
2. #82 (Observe tokens) — independent
3. #83 (DTLS plaintext) — independent, but #82 fix shapes drainNotifications
4. #84 (DTLS blocks) — depends on #81's shared helpers

Each step: write failing test, implement fix, verify test passes, run full suite + bench.
