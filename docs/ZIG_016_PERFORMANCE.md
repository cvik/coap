# Zig 0.16 migration: performance checks

## Method

Baseline: revision `145100e` built with Zig 0.15.2. Migration: Zig 0.16.0.
Both use `ReleaseFast`, native CPU targeting, Linux 7.1.11, and the same
AMD Ryzen AI MAX+ 395 machine. No CPU governor or system tuning was changed.

Each comparison uses five sequential, alternating baseline/migration runs,
500,000 requests and 10,000 warmup requests per invocation. Each invocation
runs exactly one scenario; both processes inherit CPU affinity 0–7. The
multi-threaded cases use four clients and four server threads. Windows are
256 (single-threaded) and 64 per client (multi-threaded).

The baseline benchmark received only the payload-filter harness addition;
its library and crypto implementation were unchanged. Example command:

```sh
zig build -Doptimize=ReleaseFast
taskset -c 0-7 ./zig-out/bin/bench --threads 4 --count 500000 \
  --warmup 10000 --dtls-only --non-only --single-only --payload-only 1000
```

Change the transport, message type, threading and payload filters to repeat
the matrix below. Baseline and migration must run sequentially, not concurrently.

The original multi-scenario suite produced large spurious NON differences:
outstanding traffic from a prior scenario can contaminate counters reset
before the next handshake/warmup. The added `--payload-only` filter allows
one scenario per process without changing the measured library paths.

## Finding and repair

Unchanged CCM code compiled with Zig 0.16 made 1000-byte single-threaded DTLS
NON throughput **7.5% lower** (278,820 → 258,000 req/s). An isolated encryption
microbenchmark also found a reproducible slowdown with no networking involved:
about 852 → 1007 ns per 1000-byte encryption.

The plaintext CBC-MAC loop used a variable-sized byte XOR on every block.
Splitting full blocks from the partial tail and expressing the full-block XOR
as a fixed-width vector removed this slowdown. Three post-fix encryption
microbenchmark runs measured approximately 615 ns/op versus the old baseline's
852 ns/op (28% less time). The same fix measured about 90 versus 114 ns/op for
100-byte encryption. These are encryption-only measurements, not end-to-end
latency predictions.

The optimized code is checked against independent Python cryptography AESCCM
ciphertext/tag digests at lengths 0, 15, 16, 17, 31, 32, 33, 100, 1000 and 1024,
as well as the existing authentication-failure and OpenSSL interoperability tests.

## End-to-end medians

Plain rows were collected before the CCM-only optimization (their code paths
are unaffected); DTLS rows were collected afterwards. Throughput is req/s.
Positive throughput changes are improvements. p99 is in microseconds.

| Transport/type | Threads | Bytes | Baseline | Migration | Change | p99 baseline → migration |
|---|---:|---:|---:|---:|---:|---:|
| Plain NON | 1 | 0 | 914,578 | 911,607 | -0.3% | — |
| Plain NON | 1 | 100 | 865,007 | 861,352 | -0.4% | — |
| Plain NON | 1 | 1000 | 763,076 | 752,559 | -1.4% | — |
| Plain NON | 4 | 0 | 1,874,929 | 1,893,968 | +1.0% | — |
| Plain NON | 4 | 100 | 1,374,825 | 1,905,470 | +38.6% | — |
| Plain NON | 4 | 1000 | 1,439,007 | 1,367,405 | -5.0% | — |
| Plain CON | 1 | 0 | 762,894 | 770,913 | +1.1% | 649.8 → 592.2 |
| Plain CON | 1 | 100 | 755,935 | 772,439 | +2.2% | 638.0 → 590.1 |
| Plain CON | 1 | 1000 | 731,170 | 723,972 | -1.0% | 669.4 → 667.3 |
| Plain CON | 4 | 0 | 1,525,991 | 1,515,705 | -0.7% | 216.3 → 201.9 |
| Plain CON | 4 | 100 | 1,476,967 | 1,053,877 | -28.6% | 227.3 → 277.1 |
| Plain CON | 4 | 1000 | 1,438,915 | 1,377,972 | -4.2% | 221.2 → 272.2 |
| DTLS NON | 1 | 0 | 629,074 | 620,053 | -1.4% | — |
| DTLS NON | 1 | 100 | 538,213 | 546,878 | +1.6% | — |
| DTLS NON | 1 | 1000 | 286,838 | 329,586 | +14.9% | — |
| DTLS NON | 4 | 0 | 1,474,945 | 1,100,510 | -25.4% | — |
| DTLS NON | 4 | 100 | 974,870 | 1,291,080 | +32.4% | — |
| DTLS NON | 4 | 1000 | 679,838 | 774,786 | +14.0% | — |
| DTLS CON | 1 | 0 | 181,116 | 178,627 | -1.4% | 1795.9 → 2172.4 |
| DTLS CON | 1 | 100 | 173,409 | 170,722 | -1.5% | 1861.4 → 2230.0 |
| DTLS CON | 1 | 1000 | 136,089 | 141,732 | +4.1% | 2266.7 → 2504.6 |
| DTLS CON | 4 | 0 | 158,208 | 153,749 | -2.8% | 2531.0 → 2709.7 |
| DTLS CON | 4 | 100 | 165,328 | 154,986 | -6.3% | 2269.8 → 2645.8 |
| DTLS CON | 4 | 1000 | 183,118 | 182,130 | -0.5% | 1880.5 → 2220.0 |

## Remaining risks and limitations

This is **not a regression-free result**. Single-threaded DTLS CON p99 remains
about 10–21% higher. The four-thread CON cases above also contain throughput
regression candidates, including Plain 100B (-28.6%) and DTLS 100B (-6.3%).

Multi-threaded samples are noisy: SO_REUSEPORT hashes the clients' ephemeral
source ports, so four clients do not necessarily use all four server workers
evenly. For example, Plain CON 100B migration throughput ranged from 988,952
to 1,502,454 req/s; DTLS NON 0B ranged from 969,653 to 1,590,372. These ranges
make a claim of either broad improvement or broad regression unjustified.
A follow-up needs controlled worker placement/client flows and tail-latency
profiling before declaring performance parity.

All sampled runs reported zero benchmark request errors. NON is
fire-and-forget; zero errors does **not** establish zero UDP packet loss.
The NON metric uses server counters rather than reliable delivery accounting.
Measurements are loopback-specific and do not predict real-network throughput.
