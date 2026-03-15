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

No handler signature change. The existing `null` return for CON (= empty ACK) is the entry point. A new `Server.sendResponse()` method delivers the late response. An MPSC queue makes it thread-safe. A pre-allocated retransmission pool drives CON reliability for outgoing separate responses.

### Zero-cost for synchronous handlers

- The MPSC queue drain in `tick()` is a single atomic load (queue empty = no work).
- The retransmission scan is skipped when the pool is empty (one comparison).
- No new branches in the normal piggybacked response path.

## API

### Handler side (no change to signature)

```zig
fn handler(ctx: *AppState, req: coap.Request) ?coap.Response {
    if (is_fast(req)) return coap.Response.ok("quick");

    // Slow: copy token + peer, enqueue background work.
    var tok: [8]u8 = undefined;
    @memcpy(tok[0..req.packet.token.len], req.packet.token);
    ctx.enqueue_work(.{
        .token = tok,
        .token_len = @intCast(req.packet.token.len),
        .peer = req.peer_address,
    });
    return null; // server sends empty ACK
}
```

### Delivering the late response

```zig
// From any thread (background worker, I/O callback, etc.):
try server.sendResponse(.{
    .peer = item.peer,
    .token = item.token[0..item.token_len],
    .code = .content,
    .payload = result_data,
});
```

`sendResponse()` encodes the response as a CON packet with a server-generated
msg_id, enqueues the wire bytes into the MPSC queue, and returns. The tick
loop sends it and handles retransmission.

Returns `error.SeparatePoolFull` if the retransmission pool is exhausted.

## Internal Components

### SeparateResponse struct (new: `src/separate.zig`)

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
    retransmit_count: u4,
    next_retransmit_ns: i128,
    timeout_ns: u64,
    wire_len: u16,
    next_free: u16,
};
```

Pre-allocated pool with:
- `slots: []Slot` — retransmission state per pending response.
- `wire_buffer: []u8` — encoded CON packets, `count * response_size` bytes.
- `table: []u16` — hash table keyed on msg_id for O(1) ACK matching.
- `free_head: u16` — intrusive free list.

Methods:
- `insert(msg_id, wire_data, now_ns) ?u16` — allocate slot, copy wire, start timer.
- `find(msg_id) ?u16` — look up by msg_id (for ACK matching).
- `remove(slot_idx)` — free slot, return to free list.
- `cached_wire(slot_idx) []const u8` — get wire data for retransmission.

### MPSC Queue (new: `src/mpsc.zig`)

Bounded lock-free ring buffer for cross-thread submission.

```
Entry = struct {
    peer: std.net.Address,
    wire_len: u16,
    wire: [response_size]u8, // pre-encoded CON packet
};

Queue = struct {
    buffer: []Entry,
    mask: u32,
    head: std.atomic.Value(u32), // producers (atomic CAS)
    tail: u32,                    // consumer (tick loop only)

    fn push(entry: Entry) error{Full}!void   // any thread
    fn pop() ?*Entry                          // tick loop only
};
```

The caller (`sendResponse`) encodes the packet and pushes the wire bytes.
The tick loop pops entries, allocates retransmission slots, and sends.

### Server.zig integration

**New config field:**
```zig
/// Max concurrent separate (deferred) responses. 0 = disabled.
separate_response_count: u16 = 16,
```

**New state:**
- `separate_pool: SeparateResponse` — retransmission tracking.
- `separate_queue: mpsc.Queue` — cross-thread submission queue.
- `next_separate_msg_id: std.atomic.Value(u16)` — atomic msg_id generator for `sendResponse()`.

**`sendResponse()` method (thread-safe):**
1. Generate msg_id via atomic increment.
2. Encode response as CON packet into a stack buffer.
3. Push wire bytes + peer into MPSC queue.
4. Return error if queue is full.

**`tick()` additions (after existing CQE processing):**
1. **Drain MPSC queue:** Pop entries, allocate retransmission slots, send wire data.
2. **Retransmission scan:** For each pending separate slot, check timeout. Retransmit
   or mark as timed out (free the slot after `max_retransmit` attempts).

**`handle_recv()` addition (ACK handling):**
Currently the server ignores incoming ACK messages. Add: if `packet.kind == .acknowledgement`,
look up `packet.msg_id` in the separate pool. If found, remove the slot (response delivered).

## Thread Safety

- `sendResponse()` is safe to call from any thread — only touches the MPSC queue (lock-free) and an atomic msg_id counter.
- The MPSC queue uses atomic CAS on `head` for producers, plain load on `tail` for the consumer.
- The separate pool and retransmission state are only accessed from the tick loop (single consumer).
- For `thread_count > 1`: each server thread has its own io_uring and pools. The application must call `sendResponse()` on the correct server instance (the one that received the original request).

## Performance

- **Synchronous handler path:** One atomic load to check if queue has entries (empty = skip). One comparison to check if separate pool has pending slots (empty = skip). Both are cache-hot. Negligible overhead.
- **Separate response path:** One MPSC push (atomic CAS) + one send + one slot allocation. Same order as a normal response.
- **Memory:** `16 * 1280 = 20 KB` wire buffer + `16 * ~64B` slots + queue overhead. ~25 KB total at defaults.

## Edge Cases

- **Application never responds:** Client times out on its end. Server's retransmission pool entry stays until `max_retransmit` (4 retransmits × exponential backoff ≈ 45s), then is freed automatically.
- **Client sends RST for the separate CON:** Server should match RST msg_id to the separate pool and free the slot. (Reuse existing RST handling path.)
- **Queue full:** `sendResponse()` returns `error.SeparatePoolFull`. Application can retry or drop.
- **Duplicate ACK:** `find()` returns null (already removed). Harmless.
