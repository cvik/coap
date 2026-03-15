# Separate (Delayed) Responses Design (RFC 7252 §5.2.2, Roadmap 1.2)

## Goal

Allow handlers to defer responses for slow operations (I/O, inter-service calls). The server sends an empty ACK immediately, then delivers the actual response later as a new CON message with retransmission.

## RFC 7252 §5.2.2 Flow

```
Client                  Server
  |  CON [0xAB01]  GET  -->  |   (1) Client sends CON request
  |  <--  ACK [0xAB01]      |   (2) Server sends empty ACK immediately
  |       ... time ...       |   (3) Handler does slow work
  |  <--  CON [0xAB02] 2.05 |   (4) Server sends response as NEW CON
  |  ACK [0xAB02]  -->      |   (5) Client ACKs the separate response
```

Key: step 4 uses a **new msg_id** but the **same token** as the original request.

## Architecture

No handler signature change. The existing `null` return for CON (= empty ACK) is the
entry point. A new `Server.sendResponse()` method delivers the late response. An MPSC
queue makes it thread-safe. A pre-allocated retransmission pool drives CON reliability
for outgoing separate responses.

### Zero-cost for synchronous handlers

- The MPSC queue drain in `tick()` is a single atomic load (queue empty = no work).
- The retransmission scan is skipped when the pool is empty (one comparison).
- No new branches in the normal piggybacked response path.

## API

### Deferring a response

The handler calls `server.deferResponse(req)` to capture request context, then
returns `null` (triggering the automatic empty ACK). The returned `DeferredCtx`
is a small value type (no heap allocation) that holds everything needed to deliver
the response later.

```zig
fn handler(ctx: *AppState, req: coap.Request) ?coap.Response {
    if (is_fast(req)) return coap.Response.ok("quick");

    // Slow: capture context, enqueue background work.
    const deferred = ctx.server.deferResponse(req) orelse
        return coap.Response.withCode(.internal_server_error);
    ctx.enqueue_work(deferred);
    return null; // server sends empty ACK
}
```

`DeferredCtx` is a plain struct — safe to copy, send across threads, store in queues:

```zig
const DeferredCtx = struct {
    peer: std.net.Address,
    token: [8]u8,
    token_len: u3,
    is_dtls: bool,
    session_idx: u16, // DTLS session table index (only valid when is_dtls)
};
```

### Delivering the late response

```zig
// From any thread (background worker, I/O callback, etc.):
try server.sendResponse(deferred, .{
    .code = .content,
    .payload = result_data,
});
```

`sendResponse()` encodes the response as a CON packet, enqueues the wire bytes
into the MPSC queue, and returns. The tick loop sends it and handles retransmission.

Returns `error.SeparatePoolFull` if the retransmission pool is exhausted.

## Internal Components

### SeparateResponse pool (new: `src/separate.zig`)

```
Config = struct {
    /// Max concurrent separate responses pending ACK.
    count: u16 = 16,
    /// Max encoded response size.
    response_size: u16 = 1280,
};

Slot = struct {
    state: enum { free, pending },
    msg_id: u16,
    peer: std.net.Address,
    retransmit_count: u4,
    next_retransmit_ns: i128,
    timeout_ns: u64,
    wire_len: u16,
    is_dtls: bool,
    session_idx: u16,
    next_free: u16,
};
```

Pre-allocated pool with:
- `slots: []Slot` — retransmission state per pending response.
- `wire_buffer: []u8` — plaintext CoAP packets, `count * response_size` bytes.
- `table: []u16` — hash table keyed on msg_id for O(1) ACK matching.
- `free_head: u16` — intrusive free list.

Methods:
- `insert(msg_id, peer, wire_data, is_dtls, session_idx, now_ns) ?u16`
- `find(msg_id) ?u16` — look up by msg_id (for ACK matching).
- `remove(slot_idx)` — free slot, return to free list.
- `cached_wire(slot_idx) []const u8` — get plaintext CoAP data.

**Important:** The pool stores **plaintext CoAP** bytes, not encrypted wire bytes.
For DTLS, each retransmission must re-encrypt with a fresh DTLS record sequence
number (RFC 6347 requires unique sequence numbers; replaying the same encrypted
record would be rejected by the client's replay window). For plain UDP, the
plaintext IS the wire format, so retransmission sends the stored bytes directly.

### MPSC Queue (new: `src/mpsc.zig`)

Bounded lock-free ring buffer for cross-thread submission.

```
Entry = struct {
    peer: std.net.Address,
    wire_len: u16,
    is_dtls: bool,
    session_idx: u16,
    wire: [response_size]u8,  // plaintext CoAP packet
    ready: std.atomic.Value(bool), // publication flag
};

Queue = struct {
    buffer: []Entry,
    mask: u32,
    head: std.atomic.Value(u32), // producers reserve via CAS
    tail: u32,                    // consumer (tick loop only)

    fn push(entry) error{Full}!void  // any thread
    fn pop() ?*Entry                 // tick loop only
};
```

**Publication protocol (prevents reading partial writes):**
1. Producer reserves slot via atomic CAS on `head`.
2. Producer writes entry data into `buffer[slot]`.
3. Producer sets `buffer[slot].ready.store(true, .release)`.
4. Consumer checks `buffer[tail].ready.load(.acquire)` before reading.
5. Consumer clears `ready` after processing.

### Server.zig integration

**New config field:**
```zig
/// Max concurrent separate (deferred) responses. 0 = disabled.
separate_response_count: u16 = 16,
```

**New state:**
- `separate_pool: SeparateResponse` — retransmission tracking.
- `separate_queue: mpsc.Queue` — cross-thread submission queue.

**Message ID generation:**
The existing `next_msg_id: u16` is converted to `std.atomic.Value(u16)` and used
for both piggybacked responses (tick loop) and separate responses (`sendResponse()`
from any thread). Single counter eliminates msg_id collisions. The tick loop uses
`fetchAdd(1, .monotonic)` instead of the current `id +% 1`.

**`deferResponse(req: Request) ?DeferredCtx`:**
Captures token, peer address, and DTLS session index. Returns null if
`separate_response_count == 0` (feature disabled). No allocation — just copies
fields into a stack struct.

**`sendResponse(ctx: DeferredCtx, response: Response) !void` (thread-safe):**
1. Generate msg_id via `next_msg_id.fetchAdd(1, .monotonic)`.
2. Encode response as CON packet (with ctx.token, new msg_id) into stack buffer.
3. Push plaintext wire bytes + peer + DTLS info into MPSC queue.
4. Return error if queue is full.

**`tick()` additions (after existing CQE processing):**

1. **Drain MPSC queue:** Pop entries, allocate retransmission slots, send.
   - For plain UDP: send stored plaintext directly.
   - For DTLS: encrypt plaintext via `send_dtls_packet()` using session_idx.
2. **Retransmission scan:** For each pending separate slot:
   - If `now >= next_retransmit_ns` and `retransmit_count < constants.max_retransmit`:
     retransmit (re-encrypt for DTLS), double timeout, increment count.
   - If `retransmit_count >= constants.max_retransmit`: free the slot (timed out).
   - Initial timeout: `randomizedTimeout(constants.ack_timeout_ms)` (2-3s per RFC 7252 §4.2).
   - Timeout doubles on each retransmit (exponential backoff).

**`handle_recv()` addition (ACK/RST matching):**

Currently the server processes RST (cancels exchange) and ignores ACK. Add:

- **ACK:** If `packet.kind == .acknowledgement`, look up `packet.msg_id` in the
  separate pool. If found, remove the slot (response delivered successfully).
- **RST:** Also check the separate pool (in addition to the existing exchange pool
  check). If found, remove the slot (client rejected the separate response).

## Interactions with Existing Mechanisms

### Client retransmits original CON after empty ACK

The empty ACK for the original request is cached in the exchange pool (existing
behavior at `Server.zig:1011-1031`). If the client retransmits its CON (same
msg_id) before receiving the ACK, the server's duplicate detection retransmits
the cached empty ACK. This is correct per RFC 7252.

### Exchange pool eviction

The exchange pool entry (cached empty ACK) has a lifetime of `exchange_lifetime_ms`
(~247s). If the handler takes longer than this to call `sendResponse()`, the entry
is evicted and a client retransmission would trigger the handler again (duplicate
invocation). Applications should complete separate responses well within this window.
The retransmission window for the separate response itself is ~45s (`max_retransmit=4`
with exponential backoff), so the practical deadline is driven by application logic,
not the protocol.

### Separate response is NOT cached in the exchange pool

The exchange pool entry for the original msg_id holds the empty ACK. The separate
response has its own msg_id and its own retransmission tracking in the separate pool.
These are independent — no interaction.

### Future: server-side Observe (roadmap 2.1)

Observe notifications are also server-initiated CON messages with retransmission.
The separate pool's retransmission mechanism can be reused or shared. This design
keeps the pool generic (msg_id + wire data + retransmit state) to enable reuse.

## Thread Safety

- `deferResponse()` is called from the handler (tick loop thread) — no synchronization needed.
- `sendResponse()` is safe to call from any thread — only touches the MPSC queue
  (lock-free CAS) and the atomic msg_id counter.
- The separate pool and retransmission state are only accessed from the tick loop.
- For `thread_count > 1`: each server thread has its own pools. The `DeferredCtx`
  captures which server instance to use (the application routes to the right one).

## Performance

- **Synchronous handler path:** One atomic load to check queue (empty = skip). One
  comparison to check separate pool (empty = skip). Both cache-hot. Negligible.
- **Separate response path:** One atomic CAS (queue push) + one send + one slot
  allocation. Same order as a normal response.
- **Memory:** `16 * 1280 = 20 KB` wire buffer + `16 * ~96B` slots + queue. ~25 KB total.
- **DTLS retransmission:** Re-encryption cost per retransmit (~1us for AES-128-CCM-8).
  Acceptable — retransmits are rare.

## Edge Cases

- **Application never responds:** Server's retransmission pool entry stays until
  `max_retransmit` (4 retransmits with exponential backoff, ~45s total), then freed.
  Client times out independently.
- **Client sends RST for separate CON:** Server matches RST msg_id to separate pool,
  frees the slot. Checked in addition to exchange pool (both are scanned for RST).
- **Queue full:** `sendResponse()` returns `error.SeparatePoolFull`. Application retries or drops.
- **Duplicate ACK:** `find()` returns null (already removed). Harmless.
- **Stale/wrong token in sendResponse:** Server sends a CON the client doesn't recognize.
  Client RSTs it. Server frees the slot. Harmless.
- **Token reuse by client:** RFC 7252 §5.3.1 requires unique tokens per endpoint pair.
  If the client violates this, the separate response may match the wrong request. This
  is a client bug, not a server concern.
