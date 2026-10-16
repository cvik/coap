# Two-machine benchmarks

Linux and Zig 0.17.0 are required. `bench-server` is a dedicated echo/measurement
server, not an example application server. Allow sufficient locked-memory budget
for its io_uring workers (`ulimit -l`; local verification/CI use 8192 KiB). An
insufficient budget can fail startup with `SystemResources`, even after buffer
count clamping; do not treat such a run as a zero-throughput sample.

It supports IPv4/IPv6, plain CoAP or
DTLS-PSK, and one active measurement session at a time. Configuration is CLI-only.

## Plain CoAP over WireGuard

On the server machine, bind explicitly to its WireGuard address:

```sh
zig build bench-server -Doptimize=fast
./zig-out/bin/bench-server --bind <server-wg-ip> --port 5683 \
  --threads 8 --allocator smp --exchange-count 4096
```

This target **builds/installs only** the server; it does not start it. The default
bind is `127.0.0.1`, default worker count is 8, and rate limiting is disabled by
default. Plain controls are unauthenticated: keep this server on WireGuard or
another trusted, access-controlled network. Do not expose it publicly.

On the client machine:

```sh
# Completed CON responses over the client's measurement interval.
zig build bench -Doptimize=fast -- \
  --no-server --host <server-wg-ip> --port 5683 \
  --threads 8 --multi-only --multi-window 256 \
  --plain-only --con-only --allocator smp --count 3000000

# Unique NON requests received at the remote handler, including explicit loss.
zig build bench -Doptimize=fast -- \
  --no-server --host <server-wg-ip> --port 5683 \
  --threads 8 --multi-only --plain-only --non-only \
  --allocator smp --count 3000000
```

These run the existing 0/100/1000-byte payload matrix. Use `--payload-only 1000`
for one payload. `--window` controls single-thread CON concurrency (default 256);
`--multi-window` controls **each** multi-thread client's CON concurrency (default
64). Both accept 1..16384 (bounded by the client's internal hash table). Eight clients with window 256 allow at most 2048
outstanding requests. Client `--threads` does not configure remote server workers.
NON remains an unpaced fixed-count burst; window settings do not pace it.

Each client obtains a fresh session before warmup and releases it afterward.
A concurrent benchmark is rejected rather than resetting someone else's counters.
Crashed clients leave an inactivity lease (default 30 seconds); valid measured
traffic and owner/nonce-checked control operations refresh activity. An abandoned idle
lease is reclaimed on the next control operation. Finish is idempotent until a new
run replaces it. Stop the server with SIGINT or SIGTERM.

## DTLS credentials

The standalone server requires a credentials file to enable DTLS. Generate one
on a trusted machine and copy it securely to both machines, readable only by the
benchmark user:

```sh
umask 077
python3 - <<'PY' > bench-psk.json
import json, secrets
print(json.dumps({"identity": "remote-benchmark", "key_hex": secrets.token_hex(32)}))
PY
```

The exact JSON fields are `identity` (1..128 UTF-8 bytes) and `key_hex` (16..64 key
bytes, hexadecimal encoded). Unknown/duplicate fields and malformed credentials
are rejected. The file is bounded to 2048 bytes. Secrets are not accepted as CLI
values or printed; owned parsing/key buffers are cleared after use.

```sh
# Server machine; one server instance is either plain or DTLS.
./zig-out/bin/bench-server --bind <server-wg-ip> --port 5684 \
  --threads 8 --allocator smp --exchange-count 4096 --psk-file bench-psk.json

# Client machine; replace --con-only with --non-only for receipt accounting.
zig build bench -Doptimize=fast -- \
  --no-server --host <server-wg-ip> --port 5684 \
  --threads 8 --multi-only --multi-window 256 --allocator smp \
  --dtls-only --con-only --psk-file bench-psk.json --count 3000000
```

The server/library switches port 5683 to 5684 when PSK is enabled; specify 5684 or
a different custom port explicitly. In the client, `--psk-file` changes DTLS
credentials but does **not** select the transport: use `--dtls-only`. Without a
file the client retains the public embedded-test PSK; it is not a deployment key.
Control and measured traffic use the same transport/PSK. The DTLS control client
also consumes a server session slot. For IPv6 use literal addresses (`::1` for
loopback); do not put brackets around the CLI address.

## Server controls

`./zig-out/bin/bench-server --help` lists defaults and bounds. Available settings:

- `--bind`, `--port`, `--threads` (1..256), `--allocator smp|debug`.
- `--buffer-count`, `--buffer-size`: application datagram buffers **per worker**,
  not UDP socket queue byte sizes. Buffer count must be a power of two, 4..8192.
  The library may clamp it to memlock availability; startup reports effective configuration.
- `--exchange-count`: per-worker CON response cache/exchange capacity, 1..16384.
- `--dtls-sessions`: per-worker DTLS session capacity (startup allocation).
- `--cpu-affinity A,B,...`: optional best-effort CPU placement, cyclic across
  workers. Defaults to OS scheduling; invalid/unavailable affinity is warned.
- `--max-requests`: receipt bitmap/run-count capacity, 1..16000000 (default
  16000000). Both CON and NON session counts must fit this bound.
- `--session-timeout-ms`: inactive lease, minimum 1000 ms (default 30000).
- `--rate-limit-ips`: tracked IP capacity, 0..16384; 0 disables (default 0).
  `--rate-limit` and `--rate-burst` select per-IP tokens/sec and burst when enabled.
- `--psk-file`: enable DTLS with file credentials.
- `--verbose`: include routine transport logs, which can perturb measurements.
  Fatal/configuration warnings remain visible without it; repetitive receive-error
  logging from unconsumed NON replies is suppressed by default.

Receipt storage is allocated once at startup: a bounded atomic bitset (2 MB at
16 million IDs), per-worker counters, and control reply buffers. No measurement
handler allocation or growable per-run container is used. A fixed worker-slot
budget includes library worker restarts; exhaustion is reported as tracking
failure, never disguised as network loss. These guarantees describe measurement
storage, not a new allocation guarantee for the underlying server or raw APIs.

## Reading NON results

Each remote NON case emits one `REMOTE_BENCHMARK {...}` JSON line (stderr, like
the existing benchmark output), containing transport, client threads, payload,
attempted requests, successful local sends, unique handler receipts, missing,
duplicates, local errors, and `server_elapsed_ns`.

- `missing = sent - received`; local errors are separate, not delivery failures.
- Warmup and control requests are excluded. IDs are globally unique within the
  run, not per socket. A run-prefix/ID token and coordinator IP exclude unrelated
  traffic; per-worker counters and a shared atomic bitset suppress duplicates.
- After sending, the client polls until all expected requests arrive or receipt
  activity is quiet for 250 ms, with a 5-second drain deadline. Finish freezes the
  final snapshot. Missing means **not received before this finite cutoff**, not
  an infinite-time loss proof or localization of the drop layer.
- NON table `req/s` is unique handler receipts divided by the **server-local
  first-to-last matching receipt interval**, including duplicate arrival timing.
  It is not sender send rate, a synchronized cross-machine wall interval, or a
  loss-free sustainable capacity. Zero-length receive intervals report zero rate.
- NON replies are echoed but not drained/validated by the data clients. These are
  request-delivery results, not reply-delivery results. UDP error counters can
  include those unconsumed replies.

Remote NON refuses unsupported servers, malformed accounting, capacity overflow,
tracking failure, overlapping sessions, or unsuccessful drain/control operations;
it never falls back to claiming local send rate as delivery. CON can fall back to
a generic echo server that reports unsupported control, with an explicit warning
that it has no benchmark lease. The plain CON generator validates correlated
content responses and ignores duplicate/unrelated replies; it is still the
existing raw UDP generator, not the public CON retransmission engine. DTLS CON
uses the public client. Plain timing includes worker startup/warmup; DTLS uses the
existing synchronized post-warmup gate. Use long counts and record these shapes.

There is no timed-run controller, pacing/search for an acceptable loss threshold,
remote host automation, or WireGuard setup. Record build mode, both allocators,
worker/window counts, RTT, MTU, tunnel bandwidth, CPU utilization and loss. A
1 Gbit/s tunnel may bottleneck before the server, especially with 1000-byte
payloads. Concurrent requests needed to fill it depend on RTT, not just cores.

## Verification

```sh
zig build test
zig build test -Doptimize=safe
zig build -Doptimize=fast
python3 bench/remote-smoke.py
```

The smoke script uses local separate server/client processes, ephemeral custom
PSKs, both IP families/transports, single/multi clients, lease/capacity/overlap
checks, and a generic echo peer with duplicate replies across the 16-bit MID wrap.
It is functional verification, **not** a two-machine or WireGuard performance
measurement. Pass an alternate binary directory as its first argument if needed.
