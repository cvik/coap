# Separate (Delayed) Responses Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow handlers to defer responses for slow operations. Server sends empty ACK immediately, then delivers the response later as a CON with retransmission.

**Architecture:** Handler calls `deferResponse(req)` to capture context, returns `null` (existing empty ACK behavior). `sendResponse()` enqueues via lock-free MPSC queue. Tick loop drains queue, sends CON responses, drives retransmission. ACK/RST from client frees slots.

**Tech Stack:** Zig 0.15, Linux io_uring, lock-free MPSC ring buffer, pre-allocated retransmission pool.

**Spec:** `docs/superpowers/specs/2026-03-15-separate-responses-design.md`

**Depends on:** IPv6 plan should be completed first (address type changes).

---

## File Map

- **Create:** `src/mpsc.zig` — bounded lock-free MPSC ring buffer
- **Create:** `src/separate.zig` — separate response retransmission pool
- **Modify:** `src/Server.zig` — integration: deferResponse, sendResponse, tick additions, ACK/RST matching, atomic msg_id
- **Modify:** `src/handler.zig` — DeferredCtx type
- **Modify:** `src/root.zig` — re-export DeferredCtx, add separate/mpsc to test runner
- **Modify:** `README.md` — document separate responses
- **Modify:** `docs/ROADMAP.md` — mark 1.2 done

---

## Chunk 1: Data Structures

### Task 1: MPSC ring buffer (`src/mpsc.zig`)

**Files:**
- Create: `src/mpsc.zig`

A bounded, lock-free, multi-producer single-consumer ring buffer. Uses atomic CAS on head for producers and a publication flag per slot to prevent reading partial writes.

- [ ] **Step 1: Define the Queue struct and Entry**

```zig
const std = @import("std");

pub fn MpscQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        const Slot = struct {
            data: T,
            ready: std.atomic.Value(bool),
        };

        buffer: []Slot,
        mask: u32,
        head: std.atomic.Value(u32),  // producers reserve via CAS
        tail: u32,                     // consumer only

        pub fn init(allocator: std.mem.Allocator, capacity: u16) !Self {
            // Round up to power of two.
            var size: u32 = 1;
            while (size < capacity) size <<= 1;
            const buffer = try allocator.alloc(Slot, size);
            for (buffer) |*slot| {
                slot.ready = std.atomic.Value(bool).init(false);
            }
            return .{
                .buffer = buffer,
                .mask = size - 1,
                .head = std.atomic.Value(u32).init(0),
                .tail = 0,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.buffer);
        }

        /// Push an item (any thread). Returns error.Full if queue is at capacity.
        pub fn push(self: *Self, item: T) error{Full}!void {
            while (true) {
                const head = self.head.load(.acquire);
                const tail = @atomicLoad(u32, &self.tail, .acquire);
                if (head -% tail >= self.mask + 1) return error.Full;
                if (self.head.cmpxchgWeak(head, head +% 1, .acq_rel, .monotonic)) |_| {
                    continue; // CAS failed, retry
                }
                const slot = &self.buffer[head & self.mask];
                slot.data = item;
                slot.ready.store(true, .release);
                return;
            }
        }

        /// Pop an item (consumer thread only). Returns null if empty.
        pub fn pop(self: *Self) ?*T {
            const slot = &self.buffer[self.tail & self.mask];
            if (!slot.ready.load(.acquire)) return null;
            slot.ready.store(false, .release);
            const ptr = &slot.data;
            self.tail +%= 1;
            return ptr;
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.head.load(.acquire) == self.tail;
        }
    };
}
```

- [ ] **Step 2: Write tests**

```zig
test "single producer single consumer" {
    var q = try MpscQueue(u32).init(testing.allocator, 4);
    defer q.deinit(testing.allocator);

    try q.push(42);
    try q.push(99);
    try testing.expectEqual(@as(u32, 42), q.pop().?.*);
    try testing.expectEqual(@as(u32, 99), q.pop().?.*);
    try testing.expect(q.pop() == null);
}

test "full queue returns error" {
    var q = try MpscQueue(u32).init(testing.allocator, 2);
    defer q.deinit(testing.allocator);

    try q.push(1);
    try q.push(2);
    try testing.expectError(error.Full, q.push(3));
}

test "wrap around" {
    var q = try MpscQueue(u32).init(testing.allocator, 2);
    defer q.deinit(testing.allocator);

    try q.push(1);
    _ = q.pop();
    try q.push(2);
    try q.push(3);
    try testing.expectEqual(@as(u32, 2), q.pop().?.*);
    try testing.expectEqual(@as(u32, 3), q.pop().?.*);
}
```

- [ ] **Step 3: Run tests**

Run: `zig build test`

- [ ] **Step 4: Commit**

```bash
git add src/mpsc.zig
git commit -m "mpsc: lock-free bounded MPSC ring buffer"
```

---

### Task 2: Separate response pool (`src/separate.zig`)

**Files:**
- Create: `src/separate.zig`

Pre-allocated pool for tracking outgoing CON responses pending ACK. Pattern follows exchange.zig: open-addressing hash table, intrusive free list.

- [ ] **Step 1: Define the pool struct**

```zig
const std = @import("std");
const constants = @import("constants.zig");

const SeparatePool = @This();

pub const Config = struct {
    count: u16 = 16,
    response_size: u16 = 1280,
};

pub const State = enum(u8) { free, pending };

pub const Slot = struct {
    state: State,
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

slots: []Slot,
wire_buffer: []u8,
table: []u16,
table_mask: u16,
free_head: u16,
count_active: u16,
config: Config,

const empty_sentinel: u16 = 0xFFFF;
```

- [ ] **Step 2: Implement init, deinit, insert, find, remove, cached_wire**

Follow exchange.zig patterns exactly. The key difference: keyed on msg_id only (not peer+msg_id), since server-generated msg_ids are unique.

- [ ] **Step 3: Write tests**

```zig
test "init and deinit" { ... }
test "insert and find by msg_id" { ... }
test "remove frees slot" { ... }
test "pool exhaustion returns null" { ... }
```

- [ ] **Step 4: Run tests**

Run: `zig build test`

- [ ] **Step 5: Commit**

```bash
git add src/separate.zig
git commit -m "separate: pre-allocated retransmission pool for deferred responses"
```

---

## Chunk 2: Server Integration

### Task 3: DeferredCtx type and Server integration

**Files:**
- Modify: `src/handler.zig` — add DeferredCtx struct
- Modify: `src/Server.zig` — add state, deferResponse, sendResponse, tick additions
- Modify: `src/root.zig` — re-export

- [ ] **Step 1: Add DeferredCtx to handler.zig**

```zig
/// Context for a deferred (separate) response. Returned by
/// `Server.deferResponse()`. Pass to `Server.sendResponse()` to
/// deliver the late response from any thread.
pub const DeferredCtx = struct {
    peer: std.net.Address,
    token: [8]u8,
    token_len: u3,
    is_dtls: bool,
    session_idx: u16,
};
```

- [ ] **Step 2: Convert `next_msg_id` to atomic in Server.zig**

Change line 133: `next_msg_id: u16` → `next_msg_id: std.atomic.Value(u16)`

Update `init()` to use `std.atomic.Value(u16).init(...)`.

Update `nextMsgId()` to use `fetchAdd(1, .monotonic)`.

- [ ] **Step 3: Add separate pool and MPSC queue state to Server**

Add fields after existing state:

```zig
separate_pool: ?SeparatePool,
separate_queue: ?mpsc.MpscQueue(SeparateEntry),
```

Where `SeparateEntry` holds the pre-encoded wire data + metadata:

```zig
const SeparateEntry = struct {
    peer: std.net.Address,
    wire_len: u16,
    is_dtls: bool,
    session_idx: u16,
    wire: [1280]u8,
};
```

Initialize in `init()` when `config.separate_response_count > 0`.

- [ ] **Step 4: Implement `deferResponse()`**

```zig
pub fn deferResponse(server: *const Server, request: handler.Request) ?handler.DeferredCtx {
    if (server.config.separate_response_count == 0) return null;
    var ctx: handler.DeferredCtx = .{
        .peer = request.peer_address,
        .token = undefined,
        .token_len = @intCast(request.packet.token.len),
        .is_dtls = request.is_secure,
        .session_idx = 0, // TODO: pass session index through Request
    };
    @memcpy(ctx.token[0..request.packet.token.len], request.packet.token);
    return ctx;
}
```

- [ ] **Step 5: Implement `sendResponse()` (thread-safe)**

```zig
pub fn sendResponse(
    server: *Server,
    ctx: handler.DeferredCtx,
    response: handler.Response,
) !void {
    const queue = &(server.separate_queue orelse return error.SeparateResponsesDisabled);
    const msg_id = server.next_msg_id.fetchAdd(1, .monotonic);

    const pkt = coapz.Packet{
        .kind = .confirmable,
        .code = response.code,
        .msg_id = msg_id,
        .token = ctx.token[0..ctx.token_len],
        .options = response.options,
        .payload = response.payload,
        .data_buf = &.{},
    };

    var entry: SeparateEntry = .{
        .peer = ctx.peer,
        .wire_len = 0,
        .is_dtls = ctx.is_dtls,
        .session_idx = ctx.session_idx,
        .wire = undefined,
    };

    const wire = pkt.writeBuf(&entry.wire) catch return error.BufferTooSmall;
    entry.wire_len = @intCast(wire.len);

    queue.push(entry) catch return error.SeparatePoolFull;
}
```

- [ ] **Step 6: Add tick loop additions**

In `tick()`, after existing CQE processing and before load level update:

```zig
// Drain separate response queue.
if (server.separate_queue) |*queue| {
    while (queue.pop()) |entry| {
        server.sendSeparateResponse(entry);
    }
}

// Retransmit pending separate responses.
if (server.separate_pool) |*pool| {
    if (pool.count_active > 0) {
        server.retransmitSeparateResponses();
    }
}
```

Implement `sendSeparateResponse()`: allocate pool slot, send wire data (encrypt for DTLS), start retransmit timer.

Implement `retransmitSeparateResponses()`: scan pending slots, retransmit on timeout (re-encrypt for DTLS), free after max_retransmit.

- [ ] **Step 7: Add ACK/RST matching for separate responses**

In `handle_recv()`, after the existing RST handling (line ~832):

```zig
// ACK matches a pending separate response.
if (packet.kind == .acknowledgement) {
    if (server.separate_pool) |*pool| {
        if (pool.find(packet.msg_id)) |slot_idx| {
            pool.remove(slot_idx);
        }
    }
    return;
}
```

For RST (extend existing block): also check separate pool in addition to exchange pool.

Same changes needed in `process_dtls_coap()`.

- [ ] **Step 8: Run tests**

Run: `zig build test`

- [ ] **Step 9: Commit**

```bash
git add src/Server.zig src/handler.zig src/root.zig
git commit -m "server: separate response support with MPSC queue and retransmission"
```

---

### Task 4: Integration tests

**Files:**
- Modify: `src/Server.zig` tests

- [ ] **Step 1: Test — deferred CON gets empty ACK, then separate CON response**

```zig
test "separate response: deferred CON gets empty ACK then CON response" {
    // 1. Create server with a handler that defers
    // 2. Send CON request
    // 3. Verify empty ACK received (code=0.00)
    // 4. Call server.sendResponse() with the deferred context
    // 5. Tick the server
    // 6. Verify CON response received (new msg_id, same token, code=2.05)
    // 7. Send ACK for the CON response
    // 8. Tick — verify separate pool slot freed
}
```

- [ ] **Step 2: Test — separate response retransmission**

```zig
test "separate response: retransmits CON if no ACK" {
    // 1. Send deferred response
    // 2. Don't ACK
    // 3. Tick multiple times past retransmit timeout
    // 4. Verify retransmission received (same msg_id, same payload)
}
```

- [ ] **Step 3: Test — RST cancels separate response**

```zig
test "separate response: RST cancels retransmission" {
    // 1. Send deferred response
    // 2. Client sends RST with matching msg_id
    // 3. Verify pool slot freed, no more retransmissions
}
```

- [ ] **Step 4: Run all tests and benchmarks**

```bash
zig build test
zig build bench -Doptimize=ReleaseFast
```

- [ ] **Step 5: Commit**

```bash
git add src/Server.zig
git commit -m "separate: integration tests for deferred responses"
```

---

### Task 5: Documentation and roadmap

**Files:**
- Modify: `README.md`
- Modify: `docs/ROADMAP.md`

- [ ] **Step 1: Add separate responses section to README**

In the Server features list, add:
```
- Separate (delayed) responses for async handlers (RFC 7252 §5.2.2)
```

Add a "Separate Responses" section in the handler docs with usage example.

Document `separate_response_count` config field.

- [ ] **Step 2: Update roadmap**

Mark 1.2 as `[x]` done.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/ROADMAP.md
git commit -m "docs: separate responses in README and roadmap"
```
