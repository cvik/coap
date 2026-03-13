# Benchmark Suite Design

Single `zig build bench` invocation that runs a matrix of scenarios and prints a compact summary table.

## Scenario Matrix

18 scenarios: `{plain, dtls} × {NON, CON} × {1, nproc} × {0, 100, 1000}B`, minus DTLS+NON (no fire-and-forget bench path yet).

- Plain: 2 modes × 2 thread counts × 3 payloads = 12
- DTLS: 1 mode (CON) × 2 thread counts × 3 payloads = 6

Scenarios are comptime templates with runtime thread-count patching (nproc). No heap allocation for the scenario list.

```zig
const Scenario = struct {
    label: []const u8,
    use_dtls: bool,
    use_confirmable: bool,
    thread_count: u16,      // 1 or nproc (patched at runtime)
    payload_size: u16,      // 0, 100, 1000
    request_count: u32,     // 100K plain, 25K DTLS
};
```

## Server Grouping

Scenarios grouped by `(thread_count, use_dtls)` — 4 groups:

1. Plain, 1 thread — port 5683 (6 scenarios)
2. Plain, N threads — port 5683 (6 scenarios)
3. DTLS, 1 thread — port 5684 (3 scenarios)
4. DTLS, N threads — port 5684 (3 scenarios)

CON vs NON does not affect server configuration (exchange tracking is transparent), so it is not a grouping axis.

Per group: fork server → warmup → run all scenarios → kill server. 4 restarts total (~600ms overhead).

### Multi-thread DTLS

N threads each with own `coap.Client` (own handshake, own socket). Results aggregated same as plain multi-thread.

Session affinity relies on `connect()`'d UDP sockets — `SO_REUSEPORT` hashes on the 4-tuple, so each client's packets consistently reach the same server worker.

### Warmup

Warmup once per server group using the first scenario's parameters. For multi-thread DTLS groups, all N clients spawn, perform handshake + warmup in parallel, then scenarios run sequentially.

## Output

Progress line per scenario while running:

```
[ 1/18] Plain NON 1T 0B ... 842,103 req/s
[ 2/18] Plain NON 1T 100B ... 831,455 req/s
```

Compact summary table at the end:

```
── benchmark suite results (32 CPUs) ──

  Scenario                  req/s     p50 µs    p99 µs   p99.9 µs
  ─────────────────────────────────────────────────────────────────
  Plain NON  1T     0B    842,103       12.3      28.1       54.2
  Plain NON  1T   100B    831,455       12.8      29.4       58.1
  ...
  DTLS  CON 32T  1000B    ...
```

No per-scenario detail dump.

## CLI

`zig build bench` runs all 18 scenarios. Flags filter/override:

| Flag | Effect |
|------|--------|
| `--plain-only` | Skip DTLS scenarios |
| `--dtls-only` | Skip plain scenarios |
| `--con-only` | Skip NON scenarios |
| `--non-only` | Skip CON scenarios |
| `--single-only` | Skip multi-thread scenarios |
| `--multi-only` | Skip single-thread scenarios |
| `--count N` | Override request count for all scenarios |
| `--warmup N` | Override warmup count |
| `--window N` | Override window size |
| `--threads N` | Override multi-thread count (default: nproc) |
| `--host`, `--port` | External server target |
| `--no-server` | Don't fork embedded server |

Combinable: `--dtls-only --con-only` = 6 DTLS scenarios only.

Empty scenario set (e.g. `--dtls-only --non-only`): print warning and exit 0.

Removed flags: `--payload`, `--con`, `--dtls`. Print error and exit if user passes these to aid migration.

### External server (`--no-server`)

When `--no-server` is used, plain scenarios target `--port` (default 5683), DTLS scenarios target port 5684 (or `--port` if non-default). The external server must support all requested scenario types. Use filter flags to restrict to what the external server supports.

## Request Counts

- Plain scenarios: 100,000 requests
- DTLS scenarios: 25,000 requests
- `--count N` overrides both

## Implementation Notes

- Rewrite `main()` to build scenario list, group by server config, iterate
- Comptime scenario template array, runtime nproc patching
- Extract existing `run_bench` and `run_dtls_bench` as-is (they already take config params)
- Add `run_dtls_bench_threaded` for multi-thread DTLS (spawn N clients, aggregate)
- `ScenarioResult` captures label + req/s + p50/p99/p999 for table rendering
- Server fork/kill logic extracted into helper for reuse across groups
- `nproc` detected via `std.Thread.getCpuCount()`
