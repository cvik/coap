# Zig 0.17 migration: performance checks

These are historical measurements of the original migration (`00b0935`),
before rebasing onto the later I/O and benchmark changes in `871c8a2`.
They do not establish performance parity for the rebased branch.

## Rebase verification

On `871c8a2` plus this migration, 217 tests pass in debug, safe, fast and
safe/baseline-CPU configurations. Normal/optimized builds, documentation,
ARM64 cross-builds and remote benchmark smoke checks pass. Smoke checks cover
IPv4/IPv6, plain/DTLS, single/multi clients and the remote accounting protocol.
The full 24-scenario optimized suite reports zero request errors; an isolated
1000-byte single-thread DTLS NON check measures 417,149 req/s with zero errors.
These are verification runs, not a matched performance comparison with latest
main. Historical throughput/tail conclusions below must not be extrapolated to
the rebased branch.

## Historical method

Compare the merged Zig 0.16 tree (`39c42dc`, identical to PR #93's `11d3b52`)
with this Zig 0.17 migration. Both use optimized native-CPU builds:
`-Doptimize=ReleaseFast` on Zig 0.16.0 and `-Doptimize=fast` on Zig 0.17.0.
The machine is an AMD Ryzen AI MAX+ 395 running Linux 7.1.11. No governor or
system tuning was changed.

Each of the 24 scenarios uses five sequential, alternating baseline/migration
runs: 500,000 requests, 10,000 warmup requests, CPU affinity 0–7. Each process
runs only one scenario. Multi-threaded cases use four clients/server workers;
windows are 256 (single-threaded) and 64 per client (multi-threaded).

```sh
zig build -Doptimize=fast
taskset -c 0-7 ./zig-out/bin/bench --threads 4 --count 500000 \
  --warmup 10000 --dtls-only --non-only --single-only --payload-only 1000
```

Use the other transport/type/threading/payload filters to reproduce the matrix.
Run the two versions sequentially, never concurrently. Separate invocations
avoid outstanding NON traffic contaminating the next scenario's counters.

## Regression found and repaired

A syntax-only migration compiled and passed the crypto vectors, but caused a
repeatable large-payload regression: single-threaded 1000-byte DTLS NON fell
from 330,652 to 254,277 req/s (-23.1%), and CON fell 12.1%.

An encryption/decryption microbenchmark using runtime keys and non-inlined
entry points reproduced the problem without networking: 1000-byte encryption
rose from about 625 to 1064 ns/op. A constant-key benchmark largely hid it.
Disassembly showed repeated byte extractions/insertions in the loop-carried
CBC-MAC state. Zig 0.17's logical array/vector `@bitCast` lowering made the
previous fixed-width XOR unexpectedly expensive.

The full-block XOR now uses explicit `*align(1)` byte-vector views rather than
logical bit casts. Three post-fix runtime-key microbenchmark runs measured
about 618 versus 626 ns/op for encryption and 621 versus 625 ns/op for
decryption. These measurements isolate CCM and are not network latency claims.

Independent AESCCM vectors still cover full and partial block boundaries.
An additional test uses deliberately unaligned plaintext/ciphertext/output,
checks the independent 1000-byte ciphertext/tag digest, and verifies that
authentication failure zeros the output. Safe, fast and software-AES tests pass.

## Final end-to-end medians

Throughput is req/s; positive changes are improvements. p99 is microseconds.
All rows below were collected after the CCM repair.

| Transport/type | Threads | Bytes | Zig 0.16 | Zig 0.17 | Change | p99 0.16 → 0.17 |
|---|---:|---:|---:|---:|---:|---:|
| Plain NON | 1 | 0 | 938,079 | 918,021 | -2.1% | — |
| Plain NON | 1 | 100 | 901,224 | 905,209 | +0.4% | — |
| Plain NON | 1 | 1000 | 775,558 | 786,585 | +1.4% | — |
| Plain NON | 4 | 0 | 1,954,575 | 2,152,937 | +10.1% | — |
| Plain NON | 4 | 100 | 1,784,826 | 2,007,386 | +12.5% | — |
| Plain NON | 4 | 1000 | 1,132,483 | 1,567,608 | +38.4% | — |
| Plain CON | 1 | 0 | 783,799 | 794,518 | +1.4% | 620.0 → 576.1 |
| Plain CON | 1 | 100 | 792,186 | 791,230 | -0.1% | 516.1 → 641.0 |
| Plain CON | 1 | 1000 | 742,504 | 741,343 | -0.2% | 664.7 → 648.3 |
| Plain CON | 4 | 0 | 1,546,872 | 1,142,689 | -26.1% | 213.1 → 262.1 |
| Plain CON | 4 | 100 | 1,048,441 | 1,490,036 | +42.1% | 269.4 → 248.4 |
| Plain CON | 4 | 1000 | 1,002,461 | 1,436,344 | +43.3% | 287.1 → 229.7 |
| DTLS NON | 1 | 0 | 619,367 | 620,424 | +0.2% | — |
| DTLS NON | 1 | 100 | 546,332 | 548,172 | +0.3% | — |
| DTLS NON | 1 | 1000 | 330,496 | 327,682 | -0.9% | — |
| DTLS NON | 4 | 0 | 1,513,865 | 1,501,675 | -0.8% | — |
| DTLS NON | 4 | 100 | 1,458,563 | 1,285,490 | -11.9% | — |
| DTLS NON | 4 | 1000 | 609,841 | 748,835 | +22.8% | — |
| DTLS CON | 1 | 0 | 177,544 | 176,657 | -0.5% | 2260.4 → 2318.9 |
| DTLS CON | 1 | 100 | 168,250 | 166,458 | -1.1% | 2463.5 → 2372.3 |
| DTLS CON | 1 | 1000 | 142,200 | 141,128 | -0.8% | 2594.8 → 2620.1 |
| DTLS CON | 4 | 0 | 153,617 | 156,667 | +2.0% | 2698.4 → 2620.0 |
| DTLS CON | 4 | 100 | 157,151 | 158,945 | +1.1% | 2603.7 → 2541.8 |
| DTLS CON | 4 | 1000 | 179,698 | 180,645 | +0.5% | 2263.1 → 2287.8 |

## Interpretation and remaining limitations

The reproducible large-payload DTLS regression is repaired; single-threaded
throughput medians are within about 2.1% of the Zig 0.16 baseline. This does
not establish regression-free performance or resolve historical Zig 0.15
comparison concerns in [the earlier report](ZIG_016_PERFORMANCE.md).

Plain CON 1T/100B p99 is higher in the final sample (516.1 → 641.0 µs), while
an earlier five-run set measured it lower (627.1 → 598.7 µs). That discrepancy
warrants caution about tail-latency conclusions rather than a claim of parity.

Four-thread results remain highly sensitive to SO_REUSEPORT hashing of
ephemeral client source ports and scheduler placement. For example, Plain
CON 4T/0B migration throughput ranged from 1,004,074 to 1,514,403 req/s,
versus 1,008,000 to 2,782,266 for the baseline. The -26.1% median is a regression
candidate, not proof of an intrinsic slowdown; large positive medians are
similarly not reliable improvement claims. Controlled client-flow/worker
placement and additional profiling are needed to settle these cases.

All sampled runs reported zero request errors. NON is fire-and-forget, so
zero errors does not establish zero UDP loss. Loopback results do not predict
real-network performance. ARM64 and big-endian PowerPC tests were
cross-compiled, not executed; no cross-target runtime results are claimed.
