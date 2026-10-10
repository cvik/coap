#!/usr/bin/env python3
"""Compare response storage using matched common-wall benchmark generators.

The control uses the unmodified base library and con-buffers-control.patch on
this revision's benchmark source. Both binaries must be fast builds
(ReleaseFast on Zig 0.16).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import statistics
import subprocess

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
ROW = re.compile(r"\b([14])T\s+(0|100|1000)B\s+([\d,]+)\s+([\d.]+|-)\s+([\d.]+|-)\s+([\d.]+|-)\s+([\d,]+)")


def run(command):
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=120)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
            except ProcessLookupError:
                pass
            raise
        if process.returncode:
            raise RuntimeError(stdout + stderr)
        return ANSI.sub("", stdout + stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=300000)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--allocators", nargs="+", choices=("debug", "smp"), default=["debug", "smp"])
    parser.add_argument("--plain", action="store_true", help="Raw UDP CON control, not the public Client path")
    args = parser.parse_args()
    if min(args.count, args.repetitions) <= 0:
        parser.error("counts must be positive")
    binaries = {key: path.resolve() for key, path in (("baseline", args.baseline), ("candidate", args.candidate))}
    patch = Path(__file__).with_name("con-buffers-control.patch")
    data = {
        "machine": platform.platform(),
        "zig": subprocess.check_output(["zig", "version"], text=True).strip(),
        "build_mode": "fast", "allocators": args.allocators,
        "base_library_commit": "51d6d76dcfc1be0c345602f4eef95991065c8730",
        "binary_sha256": {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in binaries.items()},
        "control_patch_sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
        "count": args.count, "warmup_per_worker": 1000, "single_window": 32,
        "multi_window_per_worker": 64, "transport": "plain" if args.plain else "dtls",
        "measurement": "common wall interval; validated successful CON responses",
        "plain_control_uses_raw_generator": args.plain,
        "repetitions": args.repetitions, "samples": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for allocator in args.allocators:
        for threads in (1, 4):
            for payload in (0, 100, 1000):
                for repeat in range(args.repetitions):
                    order = ("baseline", "candidate") if repeat % 2 == 0 else ("candidate", "baseline")
                    for backend in order:
                        command = [str(binaries[backend]), "--plain-only" if args.plain else "--dtls-only", "--con-only",
                                   "--single-only" if threads == 1 else "--multi-only", "--threads", "4",
                                   "--window", "32", "--payload-only", str(payload), "--count", str(args.count),
                                   "--warmup", "1000", "--allocator", allocator, "--port", "29680"]
                        output = run(command)
                        if not any(f"build {mode}; client allocator {allocator};" in output
                                   for mode in ("fast", "ReleaseFast")):
                            raise RuntimeError("Build/allocator mismatch: " + output)
                        matches = list(ROW.finditer(output))
                        if len(matches) != 1:
                            raise RuntimeError(output)
                        values = matches[0].groups()
                        rps, errors = int(values[2].replace(",", "")), int(values[6].replace(",", ""))
                        if (int(values[0]), int(values[1])) != (threads, payload) or not rps or errors:
                            raise RuntimeError("Invalid or failed benchmark: " + output)
                        sample = dict(backend=backend, allocator=allocator, threads=threads, payload=payload,
                                      repeat=repeat, rps=rps, p50_us=float(values[3].replace("-", "0")),
                                      p99_us=float(values[4].replace("-", "0")), p999_us=float(values[5].replace("-", "0")),
                                      errors=errors, command=command, output=output)
                        data["samples"].append(sample)
                        args.output.write_text(json.dumps(data, indent=2) + "\n")
                        print(f"{allocator:5} {backend:9} {threads}T {payload:4}B run {repeat + 1}: {rps:,} req/s", flush=True)
    print("\nArithmetic means:")
    for allocator in args.allocators:
        for threads in (1, 4):
            for payload in (0, 100, 1000):
                means = {key: statistics.mean(s["rps"] for s in data["samples"]
                         if (s["backend"], s["allocator"], s["threads"], s["payload"]) ==
                            (key, allocator, threads, payload)) for key in binaries}
                print(f"{allocator:5} {threads}T {payload:4}B: {means['baseline']:,.0f} -> {means['candidate']:,.0f} "
                      f"({means['candidate']/means['baseline']:.3f}x)")


if __name__ == "__main__":
    main()
