# Critical Bug Fixes (#81-#84) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 4 high-severity bugs from external code review: Block1 body delivery, Observe token, DTLS plaintext leak, DTLS block handling.

**Architecture:** TDD — each bug gets a failing integration test first, then minimal fix. Shared helpers extracted from plain UDP path for DTLS reuse. Fixes applied in dependency order: #81 → #82 → #83 → #84.

**Tech Stack:** Zig 0.15.2, io_uring, DTLS-PSK

---

## File Map

| File | Changes |
|------|---------|
| `src/Server.zig` | `handleBlock1` return type, Block1 call sites (UDP+DTLS), `drainNotifications`, `drainDeferred`, extract shared helpers, add `send_dtls_raw`, add block handling to `process_dtls_coap` |
| `src/handler.zig` | Add `payload_override` field to `Request`, update `payload()` accessor |
| `src/observe.zig` | Change `notify()` to store metadata instead of pre-encoded packet, add `NotifyMeta` struct |
| `src/dtls/integration_test.zig` | New integration tests for all 4 bugs |

---

### Task 1: #81 — Failing test for Block1 body delivery

**Files:**
- Modify: `src/dtls/integration_test.zig`

This test uploads a multi-block payload and verifies the handler receives the full reassembled body (not just the last fragment). Uses plain UDP since this is the first bug to fix.

- [ ] **Step 1: Write the failing test**

Add to `src/dtls/integration_test.zig`:

```zig
// Handler that asserts the full reassembled payload and echoes it back.
fn block1BodyHandler(request: handler.Request) ?handler.Response {
    const body = request.payload();
    // If Block1 delivery works, body should be the full reassembled payload.
    // If broken, body is only the last fragment (64 bytes or less).
    return handler.Response{
        .code = .changed,
        .payload = body,
        .options = &.{},
    };
}

test "Block1: handler receives full reassembled body" {
    const port: u16 = 19770;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .max_block_transfers = 8,
        .max_block_payload = 8192,
    }, block1BodyHandler);
    defer server.deinit();
    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .max_in_flight = 4,
    });
    defer client.deinit();

    // 2048-byte payload — requires multiple blocks at default szx=6 (1024 bytes).
    const payload = [_]u8{0x42} ** 2048;
    var path_buf: [1]coapz.Option = .{coapz.Option.path("data")};
    const result = try client.upload(testing.allocator, .put, &path_buf, &payload);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(.changed, result.code);
    // Handler should have echoed back the FULL reassembled body.
    try testing.expectEqual(@as(usize, 2048), result.payload.len);
    try testing.expectEqualSlices(u8, &payload, result.payload);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `zig build test 2>&1 | head -40`

Expected: Test fails — `result.payload.len` is the size of the last fragment (1024), not 2048. Or the echoed payload doesn't match the full body.

- [ ] **Step 3: Commit**

```bash
git add src/dtls/integration_test.zig
git commit -m "test: failing test for #81 Block1 body delivery"
```

---

### Task 2: #81 — Fix Block1 body delivery

**Files:**
- Modify: `src/handler.zig:28-158` — add `payload_override` field, update `payload()` accessor
- Modify: `src/Server.zig:1782-1832` — change `handleBlock1` return type
- Modify: `src/Server.zig:1068-1081` — update call site in plain UDP path

- [ ] **Step 1: Add `payload_override` to `handler.Request`**

In `src/handler.zig`, add field to `Request` struct (after `route_param_count` on line 48):

```zig
/// Internal: set by Block1 reassembly to override packet.payload
/// with the full reassembled body. Not user-settable.
payload_override: ?[]const u8 = null,
```

Update the `payload()` accessor (line 156-158) from:

```zig
pub inline fn payload(self: Request) []const u8 {
    return self.packet.payload;
}
```

to:

```zig
pub inline fn payload(self: Request) []const u8 {
    return self.payload_override orelse self.packet.payload;
}
```

- [ ] **Step 2: Change `handleBlock1` return type**

In `src/Server.zig`, define `Block1Result` above `handleBlock1` (near line 1780):

```zig
const Block1Result = union(enum) {
    response: handler.Response, // intermediate/error — send and return
    complete: u16,              // slot index — get payload, call handler, release
};
```

Change the function signature (line 1782-1789) from:

```zig
fn handleBlock1(
    server: *Server,
    bt: *BlockTransfer,
    bv: coapz.BlockValue,
    packet: coapz.Packet,
    peer: std.net.Address,
    arena: std.mem.Allocator,
) ?handler.Response {
```

to:

```zig
fn handleBlock1(
    server: *Server,
    bt: *BlockTransfer,
    bv: coapz.BlockValue,
    packet: coapz.Packet,
    peer: std.net.Address,
    arena: std.mem.Allocator,
) ?Block1Result {
```

Change all return values:
- `return handler.Response.withCode(...)` → `return .{ .response = handler.Response.withCode(...) }`
- `return makeContinueResponse(bv, arena)` → map: `if (makeContinueResponse(bv, arena)) |r| return .{ .response = r } else return .{ .response = handler.Response.withCode(.internal_server_error) }`
- `return null` (complete, line 1803) → `return .{ .complete = idx }`
- `return null` (complete, line 1822) → `return .{ .complete = idx }`
- On error branches where `bt.release(idx)` is called before returning, keep the release and return `.response`.

- [ ] **Step 3: Update call site in plain UDP path**

In `src/Server.zig`, change lines 1068-1081 from:

```zig
if (server.block_transfers) |*bt| {
    if (packet.find_option(.block1)) |opt| {
        if (opt.as_block()) |bv| {
            const bt_resp = server.handleBlock1(bt, bv, packet, recv.peer_address, arena);
            if (bt_resp) |resp| {
                server.sendResponse(resp, packet, recv.peer_address, is_con, addr_key, &raw_header, index) catch return;
                return;
            }
            // bt_resp == null → Block1 complete. packet.payload now points to
            // reassembled data in the transfer pool. Fall through to handler.
        }
    }
}
```

to:

Change `const request = handler.Request{` (line 1013) to `var request = handler.Request{`.

Declare `block1_slot` before the Block1 block and release after the handler:

```zig
var block1_slot: ?u16 = null;
if (server.block_transfers) |*bt| {
    if (packet.find_option(.block1)) |opt| {
        if (opt.as_block()) |bv| {
            if (server.handleBlock1(bt, bv, packet, recv.peer_address, arena)) |b1| switch (b1) {
                .response => |resp| {
                    server.sendResponse(resp, packet, recv.peer_address, is_con, addr_key, &raw_header, index) catch return;
                    return;
                },
                .complete => |bt_idx| {
                    request.payload_override = bt.payloadSlice(bt_idx);
                    block1_slot = bt_idx;
                },
            };
        }
    }
}
// ... handler runs here (line 1108) ...
// After handler returns and response is sent:
if (block1_slot) |idx| {
    if (server.block_transfers) |*bt| bt.release(idx);
}
```

Note: do NOT use `defer bt.release(bt_idx)` inside the switch prong — that defer would fire when the switch exits, freeing the payload before the handler sees it.

- [ ] **Step 4: Run test to verify it passes**

Run: `zig build test 2>&1 | head -40`

Expected: The "Block1: handler receives full reassembled body" test passes.

- [ ] **Step 5: Run full test suite and bench**

Run: `zig build test && zig build bench -Doptimize=ReleaseFast`

Expected: All tests pass, no performance regressions.

- [ ] **Step 6: Commit**

```bash
git add src/handler.zig src/Server.zig
git commit -m "fix: Block1 body delivery to handler (#81)"
```

---

### Task 3: #82 — Failing test for Observe token

**Files:**
- Modify: `src/dtls/integration_test.zig`

- [ ] **Step 1: Write the failing test**

Add to `src/dtls/integration_test.zig`. This test needs a handler that registers an observer, then the server sends a notification, and the client verifies the notification arrived with the correct token.

```zig
var observe_resource_id: ?u16 = null;
var observe_server_ptr: ?*Server = null;

fn observeRegisterHandler(request: handler.Request) ?handler.Response {
    if (request.method() == .get) {
        if (observe_resource_id) |rid| {
            _ = request.observeResource(rid);
        }
        // Return initial value with Observe option.
        var obs_buf: [4]u8 = undefined;
        const obs_opt = coapz.Option.uint(.observe, 1, &obs_buf);
        const opts = request.arena.dupe(coapz.Option, &.{obs_opt}) catch
            return handler.Response.withCode(.internal_server_error);
        return handler.Response{
            .code = .content,
            .payload = "initial",
            .options = opts,
        };
    }
    return handler.Response.withCode(.method_not_allowed);
}

test "Observe: notification carries correct client token" {
    const port: u16 = 19771;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .max_observers = 16,
        .max_observe_resources = 4,
    }, observeRegisterHandler);
    defer server.deinit();

    observe_server_ptr = &server;
    const rid = server.allocateResource() orelse return error.NoResource;
    observe_resource_id = rid;

    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .max_in_flight = 4,
    });
    defer client.deinit();

    // Register observe.
    var path_buf: [1]coapz.Option = .{coapz.Option.path("temp")};
    var stream = try client.observe(&path_buf);

    // Push a notification from the server.
    server.notify(rid, handler.Response{
        .code = .content,
        .payload = "22.5",
        .options = &.{},
    });

    // stream.next() blocks forever since it loops on tickOnce().
    // Bug #82: server sends token=&.{0}, client's routeObserve won't match
    // the subscription's real token, so the notification is silently dropped.
    // Run next() in a thread and cancel after timeout to avoid hanging.
    const NextResult = struct {
        stream: *Client.ObserveStream,
        result: ?Client.ObserveStream.Notification = null,
        err: bool = false,
        fn run(self: *@This()) void {
            self.result = self.stream.next(testing.allocator) catch {
                self.err = true;
                return;
            };
        }
    };
    var next_ctx = NextResult{ .stream = &stream };
    const next_thread = try std.Thread.spawn(.{}, NextResult.run, .{&next_ctx});

    // Give it some time to receive, then cancel to unblock.
    std.time.sleep(200 * std.time.ns_per_ms);
    stream.cancel() catch {};
    next_thread.join();

    if (next_ctx.result) |notif| {
        defer notif.deinit(testing.allocator);
        // If we got a notification, verify token matches.
        const sub = &client.observes[stream.sub_idx];
        const expected_token = sub.token[0..sub.token_len];
        try testing.expectEqualSlices(u8, expected_token, notif.packet.token);
        try testing.expectEqualSlices(u8, "22.5", notif.payload);
    } else {
        // No notification received — expected failure mode for bug #82.
        return error.NoNotification;
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `zig build test 2>&1 | head -40`

Expected: Test fails with `error.NoNotification` — the client's `routeObserve` drops the notification because the token (`&.{0}`) doesn't match the subscription's real token.

- [ ] **Step 3: Commit**

```bash
git add src/dtls/integration_test.zig
git commit -m "test: failing test for #82 Observe wrong token"
```

---

### Task 4: #82 — Fix Observe token patching

**Files:**
- Modify: `src/observe.zig:214-265` — store metadata instead of pre-encoded packet
- Modify: `src/Server.zig:1934-1959` — encode per-observer with correct token

The approach: `notify()` stores the response metadata (code, observe seq, options, payload) in the notify buffer as a simple format. `drainNotifications()` reads it and encodes a fresh packet per observer with the correct token and msg_id.

- [ ] **Step 1: Add `NotifyMeta` encoding in `observe.zig`**

Add a struct for the metadata format stored in the notify buffer. Layout:
- `[0]`: response code (u8)
- `[1..3]`: options_len (u16 LE)
- `[3..3+options_len]`: wire-encoded options (we can reuse the option encoding)
- `[3+options_len..]`: payload bytes

Change `notify()` to store metadata instead of a pre-encoded packet:

In `src/observe.zig`, replace lines 245-263 (the packet encoding block) with:

Note: use `buf_pos` for the buffer write cursor to avoid shadowing the MPSC queue `pos` variable.

```zig
// Store notification metadata for per-observer encoding in drain phase.
// Layout: [code:1][obs_seq:4][opts_count:1][opts...][payload...]
// Each option: [kind:2 LE][len:2 LE][value:len]
buf[0] = @intFromEnum(response.code);
std.mem.writeInt(u32, buf[1..5], seq, .little);
buf[5] = @intCast(resp_opts);
var buf_pos: usize = 6;
for (response.options[0..resp_opts]) |opt| {
    std.mem.writeInt(u16, buf[buf_pos..][0..2], @intFromEnum(opt.kind), .little);
    std.mem.writeInt(u16, buf[buf_pos + 2 ..][0..2], @intCast(opt.value.len), .little);
    buf_pos += 4;
    if (buf_pos + opt.value.len > buf.len) {
        qs.entry = .{ .resource_id = resource_id, .response_len = 0, .queue_slot = slot_idx };
        qs.seq.store(pos +% 1, .release); // MPSC queue `pos`, not `buf_pos`
        return;
    }
    @memcpy(buf[buf_pos..][0..opt.value.len], opt.value);
    buf_pos += opt.value.len;
}
// Payload
const payload_len = @min(response.payload.len, buf.len - buf_pos);
@memcpy(buf[buf_pos..][0..payload_len], response.payload[0..payload_len]);
buf_pos += payload_len;

qs.entry = .{
    .resource_id = resource_id,
    .response_len = @intCast(buf_pos),
    .queue_slot = slot_idx,
};
```

Remove the `obs_buf`, `obs_opt`, `opts_buf`, and `pkt` variables that are no longer needed (lines 235-253).

- [ ] **Step 2: Add metadata decoding helper to `observe.zig`**

Add a public struct and decode function:

```zig
pub const NotifyMeta = struct {
    code: coapz.Code,
    obs_seq: u32,
    options: []const coapz.Option,
    payload: []const u8,
};

/// Decode notification metadata from a notify buffer slot.
/// `arena` is used to allocate the options array.
pub fn decodeNotifyMeta(data: []const u8, arena: std.mem.Allocator) ?NotifyMeta {
    if (data.len < 6) return null;
    const code: coapz.Code = @enumFromInt(data[0]);
    const obs_seq = std.mem.readInt(u32, data[1..5], .little);
    const opts_count = data[5];
    var pos: usize = 6;
    const options = arena.alloc(coapz.Option, opts_count + 1) catch return null;
    // Slot 0 reserved for observe option (added by caller).
    for (0..opts_count) |i| {
        if (pos + 4 > data.len) return null;
        const kind: coapz.OptionKind = @enumFromInt(std.mem.readInt(u16, data[pos..][0..2], .little));
        const vlen = std.mem.readInt(u16, data[pos + 2 ..][0..2], .little);
        pos += 4;
        if (pos + vlen > data.len) return null;
        options[i + 1] = .{ .kind = kind, .value = data[pos..][0..vlen] };
        pos += vlen;
    }
    return .{
        .code = code,
        .obs_seq = obs_seq,
        .options = options,
        .payload = data[pos..],
    };
}
```

- [ ] **Step 3: Update `drainNotifications` in Server.zig to encode per-observer**

Replace the inner loop in `drainNotifications()` (lines 1943-1958) with:

```zig
for (drained) |entry| {
    if (entry.response_len == 0) continue;
    const notify_buf = reg.notifyBuf(entry.queue_slot);
    const meta_data = notify_buf[0..entry.response_len];
    const obs_list = reg.getObservers(entry.resource_id);
    const arena = server.arena.allocator();

    const meta = ObserverRegistry.decodeNotifyMeta(meta_data, arena) orelse continue;

    // Observe option (slot 0 in options array).
    var obs_buf: [4]u8 = undefined;
    meta.options[0] = coapz.Option.uint(.observe, meta.obs_seq, &obs_buf);

    var sent: usize = 0;
    for (obs_list) |*obs| {
        if (!obs.active) continue;
        const pkt = coapz.Packet{
            .kind = .non_confirmable,
            .code = meta.code,
            .msg_id = server.nextMsgId(),
            .token = obs.token[0..obs.token_len],
            .options = meta.options,
            .payload = meta.payload,
            .data_buf = &.{},
        };
        const buf_idx = sent % batch;
        const buf = server.response_buf(buf_idx);
        const wire = pkt.writeBuf(buf) catch continue;
        server.send_raw(wire, obs.peer_address, buf_idx) catch continue;
        sent += 1;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `zig build test 2>&1 | head -40`

Expected: "Observe: notification carries correct client token" passes.

- [ ] **Step 5: Run full suite and bench**

Run: `zig build test && zig build bench -Doptimize=ReleaseFast`

- [ ] **Step 6: Commit**

```bash
git add src/observe.zig src/Server.zig
git commit -m "fix: Observe notifications use per-observer token (#82)"
```

---

### Task 5: #83 — Failing test for DTLS plaintext leak

**Files:**
- Modify: `src/dtls/integration_test.zig`

Testing that DTLS deferred responses stay encrypted is tricky at the integration level since we can't inspect wire bytes easily. The approach: a DTLS client sends a CON request, handler defers, responds later. If the deferred response is sent encrypted, the client receives it normally. If sent as plaintext, the DTLS client won't be able to parse it (it expects encrypted records).

- [ ] **Step 1: Write the failing test**

```zig
var dtls_deferred_handle: ?Deferred.DeferredResponse = null;
var dtls_deferred_ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn dtlsDeferHandler(request: handler.Request) ?handler.Response {
    dtls_deferred_handle = request.deferResponse();
    dtls_deferred_ready.store(true, .release);
    return null; // server sends empty ACK
}

test "DTLS: deferred response is encrypted" {
    const port: u16 = 19772;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .max_deferred = 8,
        .psk = test_psk,
    }, dtlsDeferHandler);
    defer server.deinit();
    try server.listen();

    dtls_deferred_ready.store(false, .release);
    dtls_deferred_handle = null;

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .psk = test_psk,
        .max_in_flight = 4,
    });
    defer client.deinit();

    try client.handshake();
    try testing.expectEqual(.established, client.dtls_session.?.state);

    // Submit CON POST — handler defers.
    const handle = try client.submit(.post, &.{coapz.Option.path("deferred")}, "request");

    // Wait for handler to capture the deferred handle.
    var attempts: u32 = 0;
    while (!dtls_deferred_ready.load(.acquire)) : (attempts += 1) {
        if (attempts > 200) return error.Timeout;
        _ = client.poll(testing.allocator, 10) catch {};
    }

    // Deliver deferred response.
    if (dtls_deferred_handle) |h| {
        h.respond(handler.Response{
            .code = .content,
            .payload = "deferred-result",
            .options = &.{},
        });
    } else return error.NoDeferredHandle;

    // Client should receive the encrypted deferred response.
    // If it was sent as plaintext (#83), client will timeout or get garbage.
    var result: ?Client.Result = null;
    for (0..100) |_| {
        if (client.poll(testing.allocator, 20) catch null) |completion| {
            if (completion.handle == handle) {
                result = completion.result;
                break;
            }
            completion.result.deinit(testing.allocator);
        }
    }
    const r = result orelse return error.Timeout;
    defer r.deinit(testing.allocator);

    try testing.expectEqual(.content, r.code);
    try testing.expectEqualSlices(u8, "deferred-result", r.payload);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `zig build test 2>&1 | head -40`

Expected: Client times out or gets no valid response (plaintext CoAP sent to DTLS client).

- [ ] **Step 3: Commit**

```bash
git add src/dtls/integration_test.zig
git commit -m "test: failing test for #83 DTLS plaintext leak"
```

---

### Task 6: #83 — Fix DTLS plaintext leak in drain functions

**Files:**
- Modify: `src/Server.zig:1692-1720` — add `send_dtls_raw` helper
- Modify: `src/Server.zig:1961-2000` — fix `drainDeferred` to use encrypted send for DTLS peers
- Modify: `src/Server.zig:1934-1959` — fix `drainNotifications` (from Task 4) to use encrypted send for DTLS peers

- [ ] **Step 1: Add `send_dtls_raw` helper**

Add after `send_dtls_packet` (around line 1720) in `src/Server.zig`:

```zig
/// Encrypt pre-encoded CoAP bytes as DTLS application_data and send.
/// Used by drain paths where the CoAP packet is already wire-encoded.
fn send_dtls_raw(
    server: *Server,
    session: *dtls.Session.Session,
    coap_wire: []const u8,
    peer: std.net.Address,
    index: usize,
) !void {
    const buf = server.response_buf(index);
    const overhead = dtls.types.record_overhead;
    if (buf.len <= overhead) return error.BufferTooSmall;

    // Copy CoAP wire data after overhead region.
    if (coap_wire.len > buf.len - overhead) return error.BufferTooSmall;
    const dest = buf[overhead..][0..coap_wire.len];
    @memcpy(dest, coap_wire);

    const encrypted = dtls.Record.encodeEncrypted(
        .application_data,
        dest,
        session.server_write_key,
        session.server_write_iv,
        session.write_epoch,
        &session.write_sequence,
        buf,
    );

    try server.send_raw(encrypted, peer, index);
}
```

- [ ] **Step 2: Fix `drainDeferred` to encrypt for DTLS peers**

In `src/Server.zig`, update `drainDeferred` (lines 1970-1976, initial send):

Replace:
```zig
server.send_data(data, slot.peer_address, @as(usize, slot_idx) % batch) catch {
```

With:
```zig
const send_idx = @as(usize, slot_idx) % batch;
const send_ok = if (server.dtls_sessions) |*tbl| blk: {
    if (tbl.lookup(slot.peer_address)) |session| {
        server.send_dtls_raw(session, data, slot.peer_address, send_idx) catch break :blk false;
        break :blk true;
    }
    break :blk server.send_data(data, slot.peer_address, send_idx) != error;
} else server.send_data(data, slot.peer_address, send_idx) != error;

// Note: simplified — use a helper to avoid this pattern duplication.
```

Actually, cleaner approach — add a `sendMaybeEncrypted` helper:

```zig
/// Send pre-encoded CoAP data, encrypting if the peer has a DTLS session.
fn sendMaybeEncrypted(server: *Server, data: []const u8, peer: std.net.Address, index: usize) !void {
    if (server.dtls_sessions) |*tbl| {
        if (tbl.lookup(peer)) |session| {
            return server.send_dtls_raw(session, data, peer, index);
        }
    }
    return server.send_data(data, peer, index);
}
```

Then replace all `server.send_data(data, slot.peer_address, ...)` calls in `drainDeferred` with `server.sendMaybeEncrypted(data, slot.peer_address, ...)`.

Lines to change:
- Line 1973: `server.send_data(data, slot.peer_address, ...)` → `server.sendMaybeEncrypted(data, slot.peer_address, ...)`
- Line 1995: `server.send_data(data, slot.peer_address, ...)` → `server.sendMaybeEncrypted(data, slot.peer_address, ...)`

- [ ] **Step 3: Fix `drainNotifications` for DTLS peers**

In the `drainNotifications` per-observer encoding loop (from Task 4), replace the raw send:

```zig
server.send_raw(wire, obs.peer_address, buf_idx) catch continue;
```

with:

```zig
if (server.dtls_sessions) |*tbl| {
    if (tbl.lookup(obs.peer_address)) |session| {
        // For DTLS, re-encode: encode into buf[overhead..], then encrypt.
        const overhead = dtls.types.record_overhead;
        const dtls_buf = server.response_buf(buf_idx);
        const coap_buf = dtls_buf[overhead..];
        const coap_wire = pkt.writeBuf(coap_buf) catch continue;
        const encrypted = dtls.Record.encodeEncrypted(
            .application_data,
            coap_wire,
            session.server_write_key,
            session.server_write_iv,
            session.write_epoch,
            &session.write_sequence,
            dtls_buf,
        );
        server.send_raw(encrypted, obs.peer_address, buf_idx) catch continue;
        sent += 1;
        continue;
    }
}
server.send_raw(wire, obs.peer_address, buf_idx) catch continue;
```

Actually this is getting complex. Simpler: since we're encoding per-observer anyway, use `send_dtls_packet` (takes Packet) for DTLS observers and `send_packet` for plain:

```zig
if (server.dtls_sessions) |*tbl| {
    if (tbl.lookup(obs.peer_address)) |session| {
        _ = server.send_dtls_packet(session, pkt, obs.peer_address, buf_idx) catch continue;
        sent += 1;
        continue;
    }
}
_ = server.send_packet(pkt, obs.peer_address, buf_idx) catch continue;
sent += 1;
```

This is cleaner and reuses existing functions.

- [ ] **Step 4: Run test to verify it passes**

Run: `zig build test 2>&1 | head -40`

Expected: "DTLS: deferred response is encrypted" passes.

- [ ] **Step 5: Run full suite and bench**

Run: `zig build test && zig build bench -Doptimize=ReleaseFast`

- [ ] **Step 6: Commit**

```bash
git add src/Server.zig
git commit -m "fix: DTLS follow-up sent encrypted (#83)"
```

---

### Task 7: #84 — Failing test for DTLS block handling

**Files:**
- Modify: `src/dtls/integration_test.zig`

- [ ] **Step 1: Write failing test for DTLS Block1**

```zig
test "DTLS: Block1 upload delivers reassembled body" {
    const port: u16 = 19773;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .max_block_transfers = 8,
        .max_block_payload = 8192,
        .psk = test_psk,
    }, block1BodyHandler);  // Reuse from Task 1
    defer server.deinit();
    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .psk = test_psk,
        .max_in_flight = 4,
    });
    defer client.deinit();

    try client.handshake();
    try testing.expectEqual(.established, client.dtls_session.?.state);

    const payload = [_]u8{0x42} ** 2048;
    var path_buf: [1]coapz.Option = .{coapz.Option.path("data")};
    const result = try client.upload(testing.allocator, .put, &path_buf, &payload);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(.changed, result.code);
    try testing.expectEqual(@as(usize, 2048), result.payload.len);
    try testing.expectEqualSlices(u8, &payload, result.payload);
}
```

- [ ] **Step 2: Write failing test for DTLS Block2**

```zig
const large_response_payload = [_]u8{0xAB} ** 2048;

fn largeResponseHandler(request: handler.Request) ?handler.Response {
    _ = request;
    return handler.Response{
        .code = .content,
        .payload = &large_response_payload,
        .options = &.{},
    };
}

test "DTLS: Block2 large response transfer" {
    const port: u16 = 19774;

    var server = try Server.init(testing.allocator, .{
        .port = port,
        .buffer_count = 16,
        .buffer_size = 1280,
        .exchange_count = 16,
        .rate_limit_ip_count = 0,
        .max_block_transfers = 8,
        .max_block_payload = 8192,
        .psk = test_psk,
    }, largeResponseHandler);
    defer server.deinit();
    try server.listen();

    var runner = ServerRunner{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{&runner});
    defer runner.stop(server_thread);

    var client = try Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .psk = test_psk,
        .max_in_flight = 4,
    });
    defer client.deinit();

    try client.handshake();

    const result = try client.get(testing.allocator, "/large");
    defer result.deinit(testing.allocator);

    try testing.expectEqual(.content, result.code);
    try testing.expectEqual(@as(usize, 2048), result.payload.len);
    try testing.expectEqualSlices(u8, &large_response_payload, result.payload);
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `zig build test 2>&1 | head -40`

Expected: Both fail — DTLS path has no block handling. Block1 handler sees only last fragment. Block2 response is sent as single oversized packet (or truncated).

- [ ] **Step 4: Commit**

```bash
git add src/dtls/integration_test.zig
git commit -m "test: failing tests for #84 DTLS block handling"
```

---

### Task 8: #84 — Extract shared block helpers from plain UDP path

**Files:**
- Modify: `src/Server.zig:1021-1145` — extract helpers, refactor plain UDP path to use them

Extract the inline block handling into reusable functions. `handleBlock1` already exists. We need to extract Block2 follow-up and response blockification.

- [ ] **Step 1: Extract `handleBlock2Followup`**

Add new function near `handleBlock1` (around line 1780):

```zig
const Block2FollowupResult = struct {
    response: handler.Response,
    release_idx: ?u16, // slot to release after send (if final block)
};

/// Handle a Block2 follow-up request (num > 0). Returns the block response
/// if this is a valid follow-up, or null if not a follow-up.
fn handleBlock2Followup(
    bt: *BlockTransfer,
    packet: coapz.Packet,
    peer: std.net.Address,
    arena: std.mem.Allocator,
) ?Block2FollowupResult {
    const opt = packet.find_option(.block2) orelse return null;
    const bv = opt.as_block() orelse return null;
    if (bv.num == 0) return null;
    const bt_idx = bt.findByToken(packet.token, peer, &.{}) orelse return null;

    const block = bt.serveBlock2(bt_idx, bv.num, bv.szx);
    const total_payload_len = bt.slots[bt_idx].payload_length;
    const release_idx: ?u16 = if (!block.more) bt_idx else null;
    if (!block.more) bt.release(bt_idx);

    var b2_buf: [3]u8 = undefined;
    const b2_opt = (coapz.BlockValue{
        .num = bv.num,
        .more = block.more,
        .szx = bv.szx,
    }).option(.block2, &b2_buf);
    var sz2_buf: [4]u8 = undefined;
    const sz2_opt = coapz.Option.uint(.size2, total_payload_len, &sz2_buf);
    const opts = arena.dupe(coapz.Option, &.{ b2_opt, sz2_opt }) catch return null;

    return .{
        .response = .{
            .code = .content,
            .options = opts,
            .payload = block.data,
        },
        .release_idx = release_idx,
    };
}
```

Wait — `release_idx` is wrong here, we already released in the function. Remove that field. The function already calls `bt.release` if `!block.more`. Simplify:

```zig
fn handleBlock2Followup(
    bt: *BlockTransfer,
    packet: coapz.Packet,
    peer: std.net.Address,
    arena: std.mem.Allocator,
) ?handler.Response {
    const opt = packet.find_option(.block2) orelse return null;
    const bv = opt.as_block() orelse return null;
    if (bv.num == 0) return null;
    const bt_idx = bt.findByToken(packet.token, peer, &.{}) orelse return null;

    const block = bt.serveBlock2(bt_idx, bv.num, bv.szx);
    const total_payload_len = bt.slots[bt_idx].payload_length;
    if (!block.more) bt.release(bt_idx);

    var b2_buf: [3]u8 = undefined;
    const b2_opt = (coapz.BlockValue{
        .num = bv.num,
        .more = block.more,
        .szx = bv.szx,
    }).option(.block2, &b2_buf);
    var sz2_buf: [4]u8 = undefined;
    const sz2_opt = coapz.Option.uint(.size2, total_payload_len, &sz2_buf);
    const opts = arena.dupe(coapz.Option, &.{ b2_opt, sz2_opt }) catch return null;

    return .{
        .code = .content,
        .options = opts,
        .payload = block.data,
    };
}
```

- [ ] **Step 2: Extract `checkSize1`**

```zig
/// Check Size1 option; returns 4.13 response if declared size exceeds limit.
fn checkSize1(
    packet: coapz.Packet,
    has_block_transfers: bool,
    config: Config,
) ?handler.Response {
    const size1_opt = packet.find_option(.size1) orelse return null;
    const declared_size = size1_opt.as_uint() orelse return null;
    const max = if (has_block_transfers)
        config.max_block_payload
    else
        config.buffer_size;
    if (declared_size > max) {
        return handler.Response.withCode(.request_entity_too_large);
    }
    return null;
}
```

- [ ] **Step 3: Extract `blockifyResponse`**

```zig
/// If response payload exceeds block size, initiate Block2 transfer.
/// Returns modified response with first block, or original response unchanged.
fn blockifyResponse(
    bt: *BlockTransfer,
    response: handler.Response,
    packet: coapz.Packet,
    peer: std.net.Address,
    arena: std.mem.Allocator,
    now_ns: i64,
) handler.Response {
    const default_szx: u3 = 6; // 1024 bytes
    const block_size: u32 = @as(u32, 1) << (@as(u5, default_szx) + 4);
    if (response.payload.len <= block_size) return response;

    const bt_idx = bt.allocate(packet.token, peer, .block2_serving, default_szx, now_ns, &.{}) orelse
        return response;
    bt.storeBlock2Payload(bt_idx, response.payload);
    const block = bt.serveBlock2(bt_idx, 0, default_szx);
    var b2_buf: [3]u8 = undefined;
    const b2_opt = (coapz.BlockValue{
        .num = 0,
        .more = block.more,
        .szx = default_szx,
    }).option(.block2, &b2_buf);
    var sz2_buf: [4]u8 = undefined;
    const sz2_opt = coapz.Option.uint(.size2, @intCast(response.payload.len), &sz2_buf);
    const opts = arena.dupe(coapz.Option, &.{ b2_opt, sz2_opt }) catch return response;
    return .{
        .code = response.code,
        .options = opts,
        .payload = block.data,
    };
}
```

- [ ] **Step 4: Refactor plain UDP path to use shared helpers**

Replace inline code at lines 1021-1051 with:
```zig
if (server.block_transfers) |*bt| {
    if (handleBlock2Followup(bt, packet, recv.peer_address, arena)) |resp| {
        server.sendResponse(resp, packet, recv.peer_address, is_con, addr_key, &raw_header, index) catch return;
        return;
    }
}
```

Replace inline code at lines 1053-1066 with:
```zig
if (checkSize1(packet, server.block_transfers != null, server.config)) |resp| {
    server.sendResponse(resp, packet, recv.peer_address, is_con, addr_key, &raw_header, index) catch return;
    return;
}
```

Replace inline code at lines 1119-1145 with:
```zig
const response = if (server.block_transfers) |*bt|
    blockifyResponse(bt, response_raw, packet, recv.peer_address, arena, server.tick_now_ns)
else
    response_raw;
```

- [ ] **Step 5: Run tests to verify no regressions**

Run: `zig build test && zig build bench -Doptimize=ReleaseFast`

Expected: All existing tests still pass. #84 DTLS tests still fail (not wired up yet).

- [ ] **Step 6: Commit**

```bash
git add src/Server.zig
git commit -m "refactor: extract shared block helpers from UDP path"
```

---

### Task 9: #84 — Add block handling to DTLS path

**Files:**
- Modify: `src/Server.zig:1586-1620` — add block handling to `process_dtls_coap`

Insert block handling between context setup (line 1585) and handler invocation (line 1596).

- [ ] **Step 1: Add block handling to `process_dtls_coap`**

After the request construction (around line 1594), before the handler invocation block, insert:

```zig
// Block2 follow-up (skip handler).
if (server.block_transfers) |*bt| {
    if (handleBlock2Followup(bt, packet, peer, arena)) |resp| {
        const response_packet = coapz.Packet{
            .kind = if (is_con) .acknowledgement else .non_confirmable,
            .code = resp.code,
            .msg_id = if (is_con) packet.msg_id else server.nextMsgId(),
            .token = packet.token,
            .options = resp.options,
            .payload = resp.payload,
            .data_buf = &.{},
        };
        const wire = server.send_dtls_packet(session, response_packet, peer, index) catch return;
        if (is_con) {
            const key = Exchange.peerKey(peer, packet.msg_id);
            if (server.exchanges.insert(key, addr_key, packet.msg_id, wire, server.tick_now_ns) == null) {
                const evicted = server.exchanges.evictExpired(server.tick_now_ns, server.exchange_lifetime_ms);
                if (evicted > 0) {
                    server.last_eviction_ns = server.tick_now_ns;
                    _ = server.exchanges.insert(key, addr_key, packet.msg_id, wire, server.tick_now_ns);
                }
            }
        }
        return;
    }
}

// Size1 check.
if (checkSize1(packet, server.block_transfers != null, server.config)) |resp| {
    const response_packet = coapz.Packet{
        .kind = if (is_con) .acknowledgement else .non_confirmable,
        .code = resp.code,
        .msg_id = if (is_con) packet.msg_id else server.nextMsgId(),
        .token = packet.token,
        .options = resp.options,
        .payload = resp.payload,
        .data_buf = &.{},
    };
    _ = server.send_dtls_packet(session, response_packet, peer, index) catch return;
    return;
}

// Block1 reassembly.
var block1_slot: ?u16 = null;
if (server.block_transfers) |*bt| {
    if (packet.find_option(.block1)) |opt| {
        if (opt.as_block()) |bv| {
            if (server.handleBlock1(bt, bv, packet, peer, arena)) |b1| switch (b1) {
                .response => |resp| {
                    const response_packet = coapz.Packet{
                        .kind = if (is_con) .acknowledgement else .non_confirmable,
                        .code = resp.code,
                        .msg_id = if (is_con) packet.msg_id else server.nextMsgId(),
                        .token = packet.token,
                        .options = resp.options,
                        .payload = resp.payload,
                        .data_buf = &.{},
                    };
                    _ = server.send_dtls_packet(session, response_packet, peer, index) catch return;
                    return;
                },
                .complete => |bt_idx| {
                    request.payload_override = bt.payloadSlice(bt_idx);
                    block1_slot = bt_idx;
                },
            };
        }
    }
}
defer if (block1_slot) |idx| {
    if (server.block_transfers) |*bt| bt.release(idx);
};
```

Note: `request` must be `var` in this path too — change `const request = handler.Request{` to `var request = handler.Request{`.

Also add response blockification after the handler response, before sending. In the response handling (around line 1621):

```zig
if (maybe_response) |response_raw| {
    const response = if (server.block_transfers) |*bt|
        blockifyResponse(bt, response_raw, packet, peer, arena, server.tick_now_ns)
    else
        response_raw;
    // ... rest of response sending with `response` instead of `response_raw`
```

Wait — looking at the existing DTLS response code (line 1621), it uses `response` directly. Need to rename or adjust. The existing code has `if (maybe_response) |response| {` — change to `|response_raw|` and add blockification.

- [ ] **Step 2: Extract DTLS response send + cache helper to reduce duplication**

There's a repeated pattern: construct response_packet, send_dtls_packet, cache in exchanges. Extract a helper:

```zig
fn sendDtlsResponse(
    server: *Server,
    session: *dtls.Session.Session,
    response: handler.Response,
    packet: coapz.Packet,
    peer: std.net.Address,
    is_con: bool,
    addr_key: u32,
    index: usize,
) void {
    const response_packet = coapz.Packet{
        .kind = if (is_con) .acknowledgement else .non_confirmable,
        .code = response.code,
        .msg_id = if (is_con) packet.msg_id else server.nextMsgId(),
        .token = packet.token,
        .options = response.options,
        .payload = response.payload,
        .data_buf = &.{},
    };
    const wire = server.send_dtls_packet(session, response_packet, peer, index) catch |err| {
        log.warn("DTLS response send failed: {}", .{err});
        return;
    };
    if (is_con) {
        const key = Exchange.peerKey(peer, packet.msg_id);
        if (server.exchanges.insert(key, addr_key, packet.msg_id, wire, server.tick_now_ns) == null) {
            const evicted = server.exchanges.evictExpired(server.tick_now_ns, server.exchange_lifetime_ms);
            if (evicted > 0) {
                server.last_eviction_ns = server.tick_now_ns;
                _ = server.exchanges.insert(key, addr_key, packet.msg_id, wire, server.tick_now_ns);
            }
        }
    }
}
```

Use this in `process_dtls_coap` for the existing response send, and for all block response sends.

- [ ] **Step 3: Run tests to verify they pass**

Run: `zig build test 2>&1 | head -40`

Expected: All 4 DTLS block tests pass. All existing tests pass.

- [ ] **Step 4: Run full suite and bench**

Run: `zig build test && zig build bench -Doptimize=ReleaseFast`

- [ ] **Step 5: Commit**

```bash
git add src/Server.zig
git commit -m "fix: DTLS block-wise transfer handling (#84)"
```

---

### Task 10: Final verification and cleanup

**Files:**
- Modify: `src/Server.zig` — remove stale comments
- Verify: all tests pass, no bench regressions

- [ ] **Step 1: Remove stale comments**

In `src/Server.zig`:
- Remove the comment at line 1077-1078: `// bt_resp == null → Block1 complete. packet.payload now points to reassembled data in the transfer pool. Fall through to handler.` (no longer accurate after refactor)
- Remove the TODO at line 1954: `// TODO: per-observer token patching for correctness.` (fixed)
- Clean up any other stale comments from refactored code.

- [ ] **Step 2: Run full test suite**

Run: `zig build test`

Expected: All tests pass.

- [ ] **Step 3: Run bench**

Run: `zig build bench -Doptimize=ReleaseFast`

Expected: No performance regressions.

- [ ] **Step 4: Commit**

```bash
git add src/Server.zig
git commit -m "cleanup: remove stale comments from block/observe fixes"
```
