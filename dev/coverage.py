#!/usr/bin/env python3
"""Merges the coverage counters the instrumented wirez wrote during the tests
(one GOCOVERDIR per test node) into a text profile and prints the total."""

import argparse
import glob
import os
import subprocess
import sys


def counters(d):
    return glob.glob(os.path.join(d, "covcounters.*"))


def skipped(d):
    return os.path.exists(os.path.join(d, "skipped"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("dirs", nargs="+")
    args = parser.parse_args()
    empty = [d for d in args.dirs if not counters(d) and not skipped(d)]
    if empty:
        # every test node runs the binary at least once unless it skipped,
        # and a skip leaves a marker (tst/lib.py); so an empty directory
        # means its data went missing, not that nothing was measured
        sys.exit("no coverage counters in:\n  " + "\n  ".join(empty))
    for d in args.dirs:
        print(f"{len(counters(d)):4d} processes  {os.path.basename(d)}" + ("  (skips)" if skipped(d) else ""))
    subprocess.run(["go", "tool", "covdata", "textfmt", "-i=" + ",".join(args.dirs), "-o", args.output], check=True)
    summary = subprocess.run(
        ["go", "tool", "cover", f"-func={args.output}"], check=True, capture_output=True, text=True,
    ).stdout
    print(summary.strip().splitlines()[-1])


if __name__ == "__main__":
    main()
