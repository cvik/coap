#!/usr/bin/env python3
"""Compare original and fixed DTLS maintenance with identical benchmark clients."""
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
    parser.add_argument("fixed", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=300000)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--plain", action="store_true", help="Plain CON control instead of DTLS")
    args = parser.parse_args()
    if min(args.count, args.repetitions) <= 0:
        parser.error("counts must be positive")
    binaries = {key: value.resolve() for key, value in (("baseline", args.baseline), ("fixed", args.fixed))}
    data = {"machine": platform.platform(), "zig": subprocess.check_output(["zig", "version"], text=True).strip(),
            "binary_sha256": {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in binaries.items()},
            "count": args.count, "warmup": 1000, "single_window": 32, "multi_window_per_worker": 64,
            "transport": "plain" if args.plain else "dtls", "repetitions": args.repetitions, "samples": []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for threads in (1, 4):
        for payload in (0, 100, 1000):
            for repeat in range(args.repetitions):
                order = ("baseline", "fixed") if repeat % 2 == 0 else ("fixed", "baseline")
                for backend in order:
                    command = [str(binaries[backend]), "--plain-only" if args.plain else "--dtls-only", "--con-only",
                               "--single-only" if threads == 1 else "--multi-only", "--threads", "4",
                               "--window", "32", "--payload-only", str(payload), "--count", str(args.count), "--warmup", "1000"]
                    output = run(command)
                    matches = list(ROW.finditer(output))
                    if len(matches) != 1:
                        raise RuntimeError(output)
                    values = matches[0].groups()
                    rps, errors = int(values[2].replace(",", "")), int(values[6].replace(",", ""))
                    if (int(values[0]), int(values[1])) != (threads, payload) or not rps or errors:
                        raise RuntimeError(f"Invalid or failed benchmark: {output}")
                    sample = dict(backend=backend, threads=threads, payload=payload, repeat=repeat,
                                  rps=rps, p50_us=float(values[3].replace("-", "0")),
                                  p99_us=float(values[4].replace("-", "0")), p999_us=float(values[5].replace("-", "0")),
                                  errors=errors, command=command, output=output)
                    data["samples"].append(sample)
                    args.output.write_text(json.dumps(data, indent=2) + "\n")
                    print(f"{backend:8} {threads}T {payload:4}B run {repeat + 1}: {rps:,} req/s", flush=True)
    print("\nArithmetic means:")
    for threads in (1, 4):
        for payload in (0, 100, 1000):
            means = {key: statistics.mean(s["rps"] for s in data["samples"]
                     if (s["backend"], s["threads"], s["payload"]) == (key, threads, payload)) for key in binaries}
            print(f"{threads}T {payload:4}B: {means['baseline']:,.0f} -> {means['fixed']:,.0f} ({means['fixed']/means['baseline']:.3f}x)")


if __name__ == "__main__":
    main()
