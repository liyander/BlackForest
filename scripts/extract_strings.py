#!/usr/bin/env python3
"""Extract ASCII and UTF-16LE strings from a file."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def extract(path: Path, min_len: int) -> list[str]:
    data = path.read_bytes()
    found: list[str] = []

    for match in ASCII_RE.finditer(data):
        value = match.group().decode("ascii", errors="ignore")
        if len(value) >= min_len:
            found.append(value)

    for match in UTF16_RE.finditer(data):
        value = match.group().decode("utf-16le", errors="ignore")
        if len(value) >= min_len:
            found.append(value)

    return sorted(set(found), key=str.lower)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--min-len", type=int, default=4)
    args = parser.parse_args()

    for item in extract(args.file, args.min_len):
        print(item)


if __name__ == "__main__":
    main()
