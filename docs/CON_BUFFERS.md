# Bounded caller-owned CON responses

CON responses do not require heap allocation. The previous Client parsed each
response with `coapz.Packet.read(allocator, ...)`, and Block2 grew an ArrayList.
Its blanket zero-allocation interpretation was therefore incorrect.

## Contract and implementation

- `submit`, `call`, `get`, `post`, `put`, `delete`, and `upload` take
  `Client.ResponseBuffers`; response allocator arguments are removed.
- Caller storage has a wire-datagram byte slice, option-descriptor slice, and
  a separate bounded byte slice for multi-block Block2 payloads. These can be
  disjoint regions of one startup allocation. `ResponseStorage(N)` supplies
  1280 wire bytes, 32 descriptors, and N reassembly bytes without allocation.
- Each pending request exclusively borrows independent storage. A completed
  result retains its bytes, token, option values/descriptors, and payload until
  the caller reuses that storage, including after other receives or client
  destruction. Results and their packet views must never be deinited.
- `Completion.result` is an error union, correlated by handle. Capacity failures
  are `ResponseBufferTooSmall`, `ResponseOptionsTooSmall`, and
  `ResponsePayloadTooSmall`; the affected request's state is released and the
  caller can retry. There is no allocator fallback, growth, or resizing.
- `cancel(handle)` releases a pending local borrow, not remote application work.
  Handles are reused, so only cancel a currently pending handle.
- Blocking calls reject other pending requests with `RequestsInFlight` rather
  than consuming and silently discarding their completions.
- Request option values must remain valid through completion. The existing
  bounded request-option store holds 16 descriptors; excess is now rejected
  instead of silently truncated. Upload reserves one descriptor for Block1.
- The internal decoder performs bounds-checked, allocation-free parsing into
  the caller's option array, with views of the caller's copied wire bytes.
- Block2 stays in one request slot with one token/handle, appends into bounded
  storage, checks offsets and ETags, tolerates duplicate separate blocks, and
  keeps final option values alive. Continuation options are stably sorted.
- Empty ACK/RST is matched by MID; ACK stops request retransmission but leaves a
  bounded deadline for a separate response. Separate CON responses are ACKed.

There are no allocating CON compatibility wrappers. Raw receive and Observe
notification APIs retain their explicit allocator behavior. An active Observe
stream may allocate notifications while CON polling routes them; this is not a
blanket zero-allocation guarantee for every Client API.

## Verification

Debug and ReleaseSafe each pass **194/194 tests**. Default Debug and ReleaseFast
builds include the library, examples, and benchmark. New regressions cover:

- Client allocator replaced by the always-failing allocator after initialization
  (and DTLS handshake), including plain/DTLS Block1 plus Block2 responses.
- Independent retained replies and metadata across slot reuse, further receives,
  another reassembly, and client destruction.
- Correlated packet/option/payload exhaustion, including first, intermediate,
  and final Block2 fragments, followed by successful retry.
- Cancellation, timeout, serialization failure, ACK/RST matching, separate
  response lifetime, token continuity, SZX reduction, duplicate blocks,
  option ordering, ETag mismatch, malformed options, and invalid offsets.

A separate strace probe (30,000 requests plus 1,000 warmup, 100-byte DTLS CON,
window 32, ReleaseFast/DebugAllocator) included client and embedded-server
startup/teardown. Mapping calls fell from **30,752 mmap / 60,712 munmap** to
**327 / 306**. These are whole-process totals, not claims of zero syscalls or
zero server allocation. Traced throughput is not used for performance results.

## Benchmarks

Machine: AMD Ryzen AI MAX+ 395, 16 cores / 32 logical CPUs, Linux 7.1.11,
Zig 0.16.0. Every comparison uses ReleaseFast and the same allocator on both
sides. `debug` means **DebugAllocator**, not a Debug build; `smp` uses the Zig
SMP allocator without libc linkage. The production allocator is not changed.

The control library is unmodified main at
`51d6d76dcfc1be0c345602f4eef95991065c8730`. Both sides use the candidate benchmark
with identical warmup, buffer-index bookkeeping, payload validation, and
measurement synchronization; the control patch only adapts response ownership
back to the old API. Allocation and handshake/warmup happen before a shared
start gate. DTLS CON throughput is validated successful replies divided by the
common interval from that gate to the last worker's finish, not a sum of
independently timed workers.

Main matrix: 300,000 total requests, 1,000 warmup per worker, window 32 with one
worker and 64 per worker with four; three repetitions, alternating backend
order. All 72 DTLS runs have zero errors. Arithmetic means:

| Allocator | Workers | Payload | Original req/s | Caller buffers req/s | Ratio |
|---|---:|---:|---:|---:|---:|
| DebugAllocator | 1 | 0 | 190,941 | 645,073 | 3.378x |
| DebugAllocator | 1 | 100 | 183,217 | 577,659 | 3.153x |
| DebugAllocator | 1 | 1000 | 152,162 | 338,886 | 2.227x |
| DebugAllocator | 4 | 0 | 158,173 | 1,130,526 | 7.147x |
| DebugAllocator | 4 | 100 | 151,922 | 946,852 | 6.232x |
| DebugAllocator | 4 | 1000 | 184,507 | 577,727 | 3.131x |
| SMP | 1 | 0 | 639,040 | 656,789 | 1.028x |
| SMP | 1 | 100 | 578,247 | 583,135 | 1.008x |
| SMP | 1 | 1000 | 332,409 | 336,018 | 1.011x |
| SMP | 4 | 0 | 1,266,015 | 1,480,875 | 1.170x |
| SMP | 4 | 100 | 1,215,340 | 1,431,524 | 1.178x |
| SMP | 4 | 1000 | 629,188 | 707,269 | 1.124x |

Four-worker placement/scheduling is not controlled and results vary widely.
A further **24 SMP runs**, with 3,000,000 total requests and two repetitions,
also have zero errors. Single-worker ratios are **1.007x / 0.996x / 1.002x**;
four-worker ratios are **1.944x / 0.722x / 1.402x** at 0/100/1000 bytes. Longer
runs do not remove the four-worker variability or negative cells. Do not claim
a universal SMP speedup or a reliable four-worker regression magnitude.

A **36-run plain CON control** uses the unchanged raw UDP generator, not the
public Client response path. All runs have zero errors; ratios are
1.034x/1.032x/1.015x with one worker and 1.470x/1.084x/0.606x with four. These
are control variability, not evidence of a Client API speedup. NON is excluded:
its server-counter/warmup/drain accounting differs, and zero client errors
alone do not demonstrate full delivery.

The robust outcome is bounded ownership and elimination of response heap
allocation. Default DebugAllocator performance improves substantially; when
allocation is already cheap, single-worker throughput is roughly unchanged.

Raw data, binary hashes, full commands, and outputs:

- `CON_BUFFERS_RESULTS.json`: final 72-run DTLS matrix.
- `CON_BUFFERS_SMP_LONG_RESULTS.json`: 24 longer SMP comparisons.
- `CON_BUFFERS_PLAIN_RESULTS.json`: 36 raw UDP controls.
- `CON_BUFFERS_INITIAL_RESULTS.json`: earlier exploratory 72-run matrix, before
  explicit safety-build-only overlap assertions and final protocol hardening;
  retained to expose variability, not used in the final table.
- `CON_BUFFERS_ALLOCATIONS.json`: mapping-count probe and provenance.

## Reproduction

Build the candidate with `zig build -Doptimize=ReleaseFast`; `zig build bench`
**runs** the suite, whereas the default build only builds its executable.
The benchmark header identifies its build mode and client allocator.

For the control, check out the fixed base commit in a separate worktree, copy
this revision's `bench/client.zig` to a control source file, and apply
`bench/con-buffers-control.patch` to that copy. Build it with `zig build-exe`,
using that base worktree's `src/root.zig` as module `coap` and the same fetched
coapz v0.3.0 source as module `coapz`. Set ReleaseFast on **every module**:

```sh
zig build-exe -OReleaseFast --dep coapz --dep coap -Mroot="$CONTROL_SOURCE" \
  -OReleaseFast -Mcoapz="$COAPZ_SOURCE" \
  -OReleaseFast --dep coapz -Mcoap="$CONTROL_WORKTREE/src/root.zig" \
  -femit-bin=/tmp/coap-con-control

python3 bench/con-buffers.py /tmp/coap-con-control zig-out/bin/bench \
  --output /tmp/con-results.json
python3 bench/con-buffers.py /tmp/coap-con-control zig-out/bin/bench \
  --allocators smp --count 3000000 --repetitions 2 --output /tmp/con-long.json
python3 bench/con-buffers.py /tmp/coap-con-control zig-out/bin/bench \
  --plain --allocators debug --output /tmp/con-plain.json
```

Only the control benchmark is adapted; do not change its library, dependency,
allocator defaults, crypto, or CQE-clearing behavior. Avoid simultaneous test,
build, or profiling load during timing runs.
