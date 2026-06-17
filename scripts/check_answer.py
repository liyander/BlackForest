#!/usr/bin/env python3
"""Validate the final BlackFrost lab flag."""

from __future__ import annotations

import argparse
import hmac


EXPECTED = "pwndora{pe_studio_strings_unmask_blackfrost}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("flag")
    args = parser.parse_args()

    if hmac.compare_digest(args.flag.strip(), EXPECTED):
        print("Correct flag.")
    else:
        print("Incorrect flag.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
