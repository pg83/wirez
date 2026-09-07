#!/usr/bin/env python3
"""Merges the coverage counters the instrumented wirez wrote during the tests
(one GOCOVERDIR per test node) into a text profile and prints the total."""

import argparse
import glob
import os
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("dirs", nargs="+")
    args = parser.parse_args()
    dirs = [d for d in args.dirs if glob.glob(os.path.join(d, "covmeta.*"))]
    if not dirs:
        sys.exit("no coverage data in " + ", ".join(args.dirs))
    subprocess.run(["go", "tool", "covdata", "textfmt", "-i=" + ",".join(dirs), "-o", args.output], check=True)
    summary = subprocess.run(
        ["go", "tool", "cover", f"-func={args.output}"], check=True, capture_output=True, text=True,
    ).stdout
    print(summary.strip().splitlines()[-1])


if __name__ == "__main__":
    main()
