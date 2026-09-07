#!/usr/bin/env python3
"""Fail when any of the given Go files is not gofmt-clean."""

import subprocess
import sys


def main(files):
    result = subprocess.run(
        ["gofmt", "-l", *files],
        check=True,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        sys.stderr.write("gofmt: these files need formatting:\n" + result.stdout)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
