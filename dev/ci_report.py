#!/usr/bin/env python3
"""Turns a failed ./build log into GitHub Actions error annotations, which are
readable through the public API without repository access, and into the job
summary. Usage: ci_report.py --log build.log --title 'Job name'."""

import argparse
import os
import re
import sys


def failures(log):
    """Yields (title, text) for every failed node and every unittest failure."""
    lines = log.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("FAIL $(B)/") or line.startswith("FAIL: ") or line.startswith("ERROR: "):
            title = line[:200]
            block = [line]
            for following in lines[index + 1:index + 60]:
                if following.startswith("----------") and len(block) > 3:
                    break
                if following.startswith(("FAIL $(B)/", "FAIL: ", "ERROR: ", "[IT]", "[UT]", "[GO]", "build:")):
                    break
                block.append(following)
            yield title, "\n".join(block)


def annotation(title, text):
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")[:4000]
    title = title.replace("%", "%25").replace(",", "%2C").replace(":", "%3A")[:200]
    return f"::error title={title}::{text}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--title", default="build")
    args = parser.parse_args()
    with open(args.log, errors="replace") as stream:
        log = stream.read()
    found = list(failures(log))
    if not found:
        tail = "\n".join(log.splitlines()[-40:])
        found = [(f"{args.title}: no test failure found, log tail", tail)]
    for title, text in found:
        print(annotation(f"{args.title}: {title}", text))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as stream:
            stream.write(f"## {args.title}\n\n")
            for title, text in found:
                stream.write(f"### {title}\n\n```\n{text}\n```\n\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
