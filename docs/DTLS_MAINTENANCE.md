# DTLS handshake maintenance fix

Baseline: `39c42dc` (unmodified original implementation). Fixed version uses the
same benchmark, crypto, client pipeline, capacity and socket settings. This is
not the Zio experiment and changes no public API or configured limits.

## Cause and fix

`Server.tick()` called `checkDtlsRetransmits()` after every completion batch.
That loop visited all 65,536 allocated capacity slots even with one established
session and no pending handshake. A one-million-request profile attributed
70.2% of combined client/server sampled user CPU to that state check.

The fix checks at most once per 50ms using the existing idle tick wakeups and
walks the existing live-session LRU chain, not free capacity. Only handshaking
sessions with cached flights can retransmit. The successor is saved before
release so timeouts can unlink head/interior/tail nodes safely. The cadence
adds up to one check interval plus existing tick processing/wakeup latency;
handshake retry counts, cached bytes and exponential-backoff limits are unchanged.

No capacity reduction, new collection, allocation or thread was introduced.

## Tests

183/183 tests pass in Debug and ReleaseSafe. ReleaseFast library, examples and
benchmark build. New regressions cover expired head/tail removal, established
sessions with cached flights, slot reuse, empty live lists, cadence boundaries,
uncached handshakes, retransmission bytes and capped exponential backoff.

## Throughput

AMD Ryzen AI MAX+ 395, Linux 7.1.11-arch1-1, Zig 0.16.0, ReleaseFast.
Each DTLS scenario: 300,000 measured requests, 1,000 warmup, five repetitions,
alternating original/fixed execution order, one new embedded server per run.
Single-worker window 32; four-worker window 64 per worker. All runs report
nonzero throughput and zero errors. Arithmetic means, requests/second:

| Workers | Payload | Original | Fixed | Change |
|---:|---:|---:|---:|---:|
| 1 | 0 | 183,498 | 182,031 | -0.8% |
| 1 | 100 | 176,570 | 177,729 | +0.7% |
| 1 | 1000 | 144,206 | 147,581 | +2.3% |
| 4 | 0 | 139,873 | 158,603 | +13.4% |
| 4 | 100 | 140,281 | 150,623 | +7.4% |
| 4 | 1000 | 154,925 | 178,363 | +15.1% |

Across all payloads, means improve **0.6% single-worker** and **12.1%
four-worker**. There is no demonstrated 2x throughput gain from this fix alone.

An additional 36-run plain-CON control (100,000 requests, three repetitions)
changes aggregate mean throughput by +0.3% single-worker and -0.3% four-worker.
Individual short multi-worker measurements vary substantially; no statistical
significance is claimed for those small aggregate differences.

## Follow-up profile

Same 100-byte, window-32 workload, one million measured requests. Sampling uses
`perf record -m 1 -e cpu-clock -F 499 -g`; small perf buffers avoid exhausting
locked-memory resources needed by io_uring. Invalid zero-throughput profiling
attempts were discarded, never treated as successful runs.

After the fix, `Server.tick` accounts for 8.7% of sampled user CPU; the old
capacity-scan hotspot is absent. Combined sampled user CPU event count fell
from approximately 4.81 to 2.39 CPU-seconds. A separate `perf stat` pair reported
user CPU 4.48 -> 2.24 seconds, while wall time was 6.20 -> 5.98 seconds. These
single profiling pairs include setup/warmup and are diagnostic, not repeated
performance estimates. System CPU remained substantial.

The next large user-space hotspot is `memset` (34.8%), with CCM authentication
14.4%. Removing the full-capacity scan saves CPU but does not eliminate the
original client/I/O/remaining tick costs. The previous Zio whole-system speed
gap must not be attributed exclusively to this loop.

## Reproduction

Build the original and fixed checkouts with `zig build -Doptimize=ReleaseFast`.
From the fixed checkout:

```sh
python3 bench/dtls-maintenance.py ../zio-baseline/zig-out/bin/bench \
  zig-out/bin/bench --output docs/DTLS_MAINTENANCE_RESULTS.json
python3 bench/dtls-maintenance.py ../zio-baseline/zig-out/bin/bench \
  zig-out/bin/bench --plain --count 100000 --repetitions 3 \
  --output docs/DTLS_MAINTENANCE_PLAIN_RESULTS.json
```

Raw JSON includes executable SHA-256, every command/output and latency
percentiles. The harness rejects zero throughput, errors or wrong scenarios
and cleans isolated process groups on interruption/timeout.
