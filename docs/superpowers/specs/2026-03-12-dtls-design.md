# DTLS 1.2 Support for CoAP Server and Client

## Overview

Add DTLS 1.2 (RFC 6347) security to the CoAP server and client. Pure Zig implementation
with no C dependencies. PSK-only cipher suite (`TLS_PSK_WITH_AES_128_CCM_8`) for the
initial milestone. Activated automatically when PSK credentials are provided in config.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Protocol version | DTLS 1.2 (RFC 6347) | CoAP ecosystem standard (RFC 7252 §9.1) |
| Implementation | Pure Zig | Matches project philosophy, zero C deps |
| Auth mode | PSK-only | Minimal scope; mandatory cipher for CoAP |
| Cipher suite | TLS_PSK_WITH_AES_128_CCM_8 | RFC 7252 mandatory-to-implement |
| I/O model | Inline in tick() + session table | No extra abstraction, fast path for established sessions |
| Session eviction | Idle-timeout + LRU fallback | Handles both quiet devices and table pressure |
| Session resumption | Not implemented, designed for | Fields reserved in session struct |
| Activation | Auto when PSK provided | Ergonomic, no separate types or toggles |

## Architecture

Layered modules under `src/dtls/`:

```
src/dtls/
  Ccm.zig         -- AES-128-CCM-8 AEAD
  Prf.zig         -- TLS 1.2 PRF (HMAC-SHA256)
  Record.zig      -- DTLS record layer encode/decode/encrypt/decrypt
  Handshake.zig   -- PSK handshake state machine
  Session.zig     -- per-peer session table with eviction
  Cookie.zig      -- stateless HelloVerifyRequest cookie generation
```

## Module Details

### Ccm.zig — AES-128-CCM-8

Implements AEAD cipher from RFC 6655. CCM is AES-CTR encryption + AES-CBC-MAC
authentication, built on `std.crypto.core.aes.Aes128`.

Parameters:
- Key: 16 bytes (AES-128)
- Nonce: 12 bytes = implicit_iv (4 bytes from key material) || explicit_nonce (8 bytes from record)
  - Per RFC 6655 §3: concatenation, not XOR
  - The 8-byte explicit nonce (epoch || sequence_number) is transmitted on the wire
- Tag: 8 bytes (CCM-8)

```zig
pub fn encrypt(
    plaintext: []const u8,
    ad: []const u8,
    nonce: [12]u8,
    key: [16]u8,
    out: []u8,               // ciphertext || 8-byte tag
) void

pub fn decrypt(
    ciphertext_and_tag: []const u8,
    ad: []const u8,
    nonce: [12]u8,
    key: [16]u8,
    out: []u8,
) error{AuthenticationFailed}!void
```

No allocations. Testable against RFC 3610 vectors.

### Prf.zig — TLS 1.2 PRF

HMAC-SHA-256 based PRF (RFC 5246 §5):

```
PRF(secret, label, seed) = P_SHA256(secret, label || seed)
P_SHA256(secret, seed) = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...
A(0) = seed, A(i) = HMAC(secret, A(i-1))
```

Used for:
- Pre-master secret → master secret derivation
- Master secret → key block expansion (client/server write keys + IVs)
- Finished message verify_data computation

Built on `std.crypto.auth.hmac.sha2.HmacSha256`. No allocations.

```zig
pub fn prf(
    secret: []const u8,
    label: []const u8,
    seed: []const u8,
    out: []u8,
) void
```

### Record.zig — DTLS Record Layer

Encodes/decodes DTLS records (RFC 6347 §4.1).

Record header (13 bytes):
```
ContentType:     u8    (handshake=22, app_data=23, change_cipher_spec=20, alert=21)
ProtocolVersion: u16   (0xFEFD = DTLS 1.2)
Epoch:           u16   (0 = plaintext, 1+ = encrypted)
SequenceNumber:  u48   (6 bytes, per-epoch, monotonic)
Length:          u16   (payload length, includes 8-byte tag if encrypted)
```

Encryption (epoch > 0, per RFC 6655 §3 GenericAEADCipher):
- Nonce = implicit_iv (4 bytes) || explicit_nonce (8 bytes)
  - explicit_nonce = epoch (2 bytes) || sequence_number (6 bytes), sent on the wire
- Additional data = 13-byte record header (length field = plaintext length)
- Wire format: record_header (13) || explicit_nonce (8) || ciphertext || tag (8)
- Total overhead: 29 bytes per record (13 header + 8 explicit nonce + 8 tag)
- Max plaintext per record: buffer_size - 29 (default 1280 - 29 = 1251 bytes)

Anti-replay:
- 64-bit sliding window for received sequence numbers (RFC 6347 §4.1.2.6)
- Duplicate or too-old sequence numbers silently dropped
- Window size is tunable if reordering issues arise in practice

```zig
pub const Record = struct {
    content_type: ContentType,
    epoch: u16,
    sequence_number: u48,
    payload: []const u8,
};

pub fn decode(buf: []const u8, session: *const Session) ?Record
pub fn encode(content_type: ContentType, plaintext: []const u8, session: *Session, out: []u8) []const u8
```

No allocations. 29 bytes overhead per record (13 header + 8 explicit nonce + 8 tag).
All DTLS records are bounded by `buffer_size` (default 1280), ensuring they fit within
the IPv6 minimum MTU without IP fragmentation.

### Handshake.zig — PSK Handshake State Machine

DTLS 1.2 PSK handshake (RFC 6347 + RFC 4279):

```
Client                                 Server
------                                 ------
ClientHello          -------->
                     <--------   HelloVerifyRequest (cookie)
ClientHello (cookie) -------->
                     <--------   ServerHello
                     <--------   ServerKeyExchange (psk_identity_hint)
                     <--------   ServerHelloDone
ClientKeyExchange    -------->   (psk_identity)
ChangeCipherSpec     -------->
Finished             -------->
                     <--------   ChangeCipherSpec
                     <--------   Finished
```

Server-side states:
```zig
pub const ServerHandshakeState = enum {
    idle,
    expect_client_hello,
    cookie_sent,
    expect_client_key_exchange,
    expect_change_cipher_spec,
    expect_finished,
    complete,
};
```

Client-side states:
```zig
pub const ClientHandshakeState = enum {
    idle,
    expect_hello_verify_or_server_hello,
    expect_server_key_exchange,
    expect_server_hello_done,
    expect_change_cipher_spec,
    expect_finished,
    complete,
};
```

Cookie mechanism (RFC 6347 §4.2.1):
- Cookie = HMAC-SHA256(server_secret, client_ip || client_random)
- Server secret rotates periodically (default 300s)
- Stateless — no session allocated until cookie verified
- Prevents spoofed-source-IP amplification attacks

Handshake message header (12 bytes, distinct from record header):
```
msg_type:        u8   (client_hello=1, server_hello=2, etc.)
length:          u24  (total message body length)
message_seq:     u16  (handshake-level sequence, NOT record sequence)
fragment_offset: u24
fragment_length: u24
```
- `message_seq` is a separate counter from the record layer sequence number
- Retransmitted handshake messages reuse the same `message_seq`
- Receiver deduplicates by `message_seq`, not record sequence number

Handshake retransmission (RFC 6347 §4.2.4):
- Initial timeout: 1s, doubles per retransmit, max 60s
- Max retransmits: 5 (then handshake fails)
- Timer checks in tick() — iterate handshaking sessions list
- Flights are identified by `message_seq`, retransmits resend the full flight

Key derivation (PSK, RFC 4279 §2):
- Pre-master secret: `<2-byte len><zeroes of PSK length><2-byte len><PSK bytes>`
- Master secret = PRF(pre_master, "master secret", client_random || server_random)[0..48]
- Key block = PRF(master, "key expansion", server_random || client_random)
  → client_write_key(16) + server_write_key(16) + client_write_iv(4) + server_write_iv(4)

Finished message:
- verify_data = PRF(master, label, SHA256(all_handshake_messages))[0..12]
- Requires incremental SHA-256 hash of all handshake message bodies

ChangeCipherSpec handling:
- CCS is a single-byte record (content type 20, payload `0x01`)
- CCS itself is sent/received under the current (old) epoch
- On sending CCS: increment write_epoch, reset write_sequence to 0, activate write keys
- On receiving CCS: increment read_epoch, reset read_sequence to 0, activate read keys
- CCS arriving out of order (before expected) triggers handshake failure

Alert protocol:
- Send `handshake_failure` (40) on: unknown PSK identity, unexpected message type
- Send `decrypt_error` (51) on: Finished verify_data mismatch
- Send `bad_record_mac` (20) on: record decryption/authentication failure
- Send `close_notify` (0) on: graceful session teardown
- Received alerts: log, tear down session, release slot

ServerKeyExchange:
- Sent with psk_identity_hint from config. If config identity is empty, ServerKeyExchange
  is omitted entirely and client state machine skips to expect ServerHelloDone.

Fragmentation:
- PSK handshake messages are small (<200 bytes), single-fragment sends
- Receive-side reassembly supported for interop with peers that fragment

Re-encoding state for retransmission:
- Server retransmit flight: server_random, selected cipher suite, psk_identity_hint
- Client retransmit flight: client_random, cookie, psk_identity
- These are stored in the session's handshake state during handshake, freed on completion

No allocations during handshake. Handshake hash state (~112 bytes) stored in session.
Retransmit re-encodes from state rather than buffering the flight.

### Session.zig — Per-Peer Session Table

Pre-allocated open-addressed hash table of session slots.

```zig
pub const Session = struct {
    state: State,                    // free, handshaking, established
    peer_addr: u64,                  // hash of peer address for table indexing
    addr: std.net.Address,           // full peer address for equality check after hash lookup

    // Crypto state (epoch 1+)
    client_write_key: [16]u8,
    server_write_key: [16]u8,
    client_write_iv: [4]u8,
    server_write_iv: [4]u8,
    read_epoch: u16,
    write_epoch: u16,
    read_sequence: u48,
    write_sequence: u48,
    replay_window: u64,              // anti-replay bitmask

    // Handshake state (active during handshaking, retained for retransmit re-encoding)
    handshake: HandshakeState,
    handshake_hash: Sha256,          // incremental hash (~112 bytes)
    client_random: [32]u8,           // needed for key derivation + retransmit
    server_random: [32]u8,           // needed for key derivation + retransmit
    cookie: [32]u8,                  // client: for retransmit; server: not stored
    message_seq: u16,                // handshake-level sequence counter
    retransmit_deadline_ns: i64,
    retransmit_count: u8,
    retransmit_timeout_ms: u32,

    // Resumption-ready (unused in v1)
    master_secret: [48]u8,
    session_id: [32]u8,
    session_id_len: u8,

    // Eviction (doubly-linked list ordered by last_activity_ns)
    last_activity_ns: i64,
    lru_prev: u32,
    lru_next: u32,
    next_free: u32,
};
```

Estimated size: ~400 bytes per slot. At default 65536 sessions: ~25MB per thread.
At 100K sessions: ~38MB per thread. Configurable via `dtls_session_count`.

Table operations:
- **Lookup:** hash peer address → probe table → compare full `addr` for equality → return `*Session` or null. O(1) average. Hash is for indexing only; full address comparison prevents collision-based session confusion (security critical).
- **Allocate:** pop from free list. If empty, evict from LRU tail (check idle timeout first). O(1).
- **Promote:** on activity, move session to LRU head. O(1).
- **Release:** zero all key material via `std.crypto.utils.secureZero`, push to free list. O(1).

Separate linked-list head for `handshaking` sessions for efficient retransmit timer scan.

### Cookie.zig — Stateless Cookie Generation

```zig
pub fn generate(server_secret: [32]u8, client_addr: std.net.Address, client_random: [32]u8) [32]u8
pub fn verify(server_secret: [32]u8, client_addr: std.net.Address, client_random: [32]u8, cookie: []const u8) bool
```

Server secret rotation: maintain current + previous secret to accept cookies generated
with the recently-rotated secret.

## Server Integration

Packet processing in `tick()`:

```
recv UDP datagram
  ├─ if no PSK configured → plain CoAP (unchanged)
  ├─ read first byte to discriminate:
  │    DTLS content types (20-25) → DTLS processing
  │    CoAP version bits 01 (0x40-0x7F) → drop (PSK configured = DTLS only, no plain CoAP)
  │    other → drop
  ├─ handshake (22):
  │    ├─ no cookie → HelloVerifyRequest (stateless, no session)
  │    ├─ valid cookie → allocate session, drive state machine
  │    └─ existing handshaking session → continue handshake
  ├─ application_data (23):
  │    ├─ lookup session → not found → drop
  │    ├─ decrypt → auth fail → drop
  │    ├─ anti-replay fail → drop
  │    └─ pass plaintext to CoAP handler
  └─ alert (21):
       └─ close session, release slot
```

Response path:
- Session exists → Record.encode(encrypt) → sendmsg
- Plain UDP → CoAP encode → sendmsg (unchanged)

Handler sees same `Request` as before, with added `is_secure: bool` field.

Port: defaults to 5684 (CoAPs) when PSK configured, 5683 otherwise. User can override.

Retransmit timer check at end of each `tick()` — iterate handshaking sessions list only.

## Client Integration

```
init():
  create socket (unchanged)
  if psk provided → store PSK, session state = idle
  else → plain UDP (unchanged)

handshake():
  drive DTLS handshake via internal tick loop with configurable timeout (default 10s)
  on success → session state = established
  on timeout/failure → return error

call()/cast():
  if session established → Record.encode before send
  else → plain CoAP send

recv:
  if session established → Record.decode before CoAP parse
  else → plain CoAP parse
```

The handshake is separated from `init()` so the caller controls when it happens.
`handshake()` runs an internal tick loop (reusing the existing `tickOnce()` pattern)
and returns once complete or on timeout. The socket remains non-blocking throughout.

Config addition:
```zig
psk: ?Psk = null,              // null = plain UDP
handshake_timeout_ms: u32 = 10_000,
```

## Config Summary

Server additions:
```zig
psk: ?Psk = null,
dtls_session_count: u32 = 65536,
dtls_session_timeout_s: u16 = 300,
```

Client addition:
```zig
psk: ?Psk = null,
```

Shared:
```zig
pub const Psk = struct {
    identity: []const u8,
    key: []const u8,
};
```
Both slices must remain valid for the lifetime of the Server/Client.
The implementation does not copy them.

## Testing

### Unit tests (per module, RFC test vectors)
- **Ccm.zig** — RFC 3610 test vectors, authentication failure on tampered data
- **Prf.zig** — RFC 5246 PRF test vectors
- **Record.zig** — encode/decode round-trip, anti-replay window accept/reject
- **Session.zig** — allocation, lookup, eviction (idle + LRU), free list, key zeroing
- **Handshake.zig** — state transitions with crafted messages, cookie verify, key derivation
- **Cookie.zig** — generation, verification, rotation acceptance

### Integration tests
- **Loopback handshake** — client + server full PSK handshake over localhost
- **Loopback CoAP over DTLS** — encrypted request/response round-trip
- **Handshake retransmission** — simulated packet loss, verify retransmit and completion
- **Session eviction** — fill table, verify eviction and new peer connectivity
- **Plain UDP regression** — existing tests pass with no PSK configured

### Interop tests
- **OpenSSL** as reference implementation:
  - Test our server: `openssl s_client -dtls1_2 -psk <hex> -psk_identity <id> -connect 127.0.0.1:5684`
  - Test our client: `openssl s_server -dtls1_2 -psk <hex> -psk_identity <id> -port 5684`
- Gated behind `-Dinterop-test` build flag (requires OpenSSL installed)
- Catches: nonce construction, byte ordering, message formatting, PRF computation divergence

### Benchmarks
- Handshake throughput (handshakes/sec)
- Application data throughput: DTLS vs plain UDP
- Session table lookup at various fill levels

## Wire Discrimination

DTLS records start with ContentType byte (20-25). CoAP messages start with version
bits `01` (values 0x40-0x7F). No overlap — single byte distinguishes them.

## Memory Budget

Per session: ~400 bytes. At default 65536 sessions: ~25MB per thread.
At 100K sessions: ~38MB per thread. Configurable via `dtls_session_count`.

## Security Considerations

- Key material zeroed on session release via `std.crypto.utils.secureZero`
- Cookie exchange prevents amplification attacks
- Anti-replay window prevents record replay
- No session allocated until cookie verified (prevents state exhaustion)
- Server secret rotation with overlap window for cookie continuity
- Session table lookup uses full address equality after hash indexing (prevents hash collision attacks)
- When PSK is configured, plain CoAP is rejected (DTLS-only mode)

## Future Work (Not in Scope)

- DTLS 1.3 (RFC 9147)
- Session resumption (session ID based)
- Raw Public Keys (RFC 7250)
- X.509 certificates
- Additional cipher suites
- Dual-port serving (CoAP + CoAPs simultaneously)
- Connection ID extension (RFC 9146)
