#!/usr/bin/env python3
"""Generate web/tokens.css from the warden-core design tokens.

Usage: python3 -I -B scripts/tokens.py [--check]

Without arguments, regenerates web/tokens.css. With --check, generates into a temporary
directory and exits 1 when web/tokens.css is missing or differs. warden-core's generator also
writes a Swift file; it is sent to a temporary directory so the submodule stays clean.
"""
import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATOR = os.path.join(ROOT, "external", "warden-core", "design-tokens", "generate.py")
CSS_PATH = os.path.join(ROOT, "web", "tokens.css")


def generate(css_out, swift_out):
    result = subprocess.run(
        [sys.executable, "-I", "-B", GENERATOR, "--css", css_out, "--swift", swift_out],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr or result.stdout)
        sys.stderr.write("tokens: generator failed\n")
        return False
    return True


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if web/tokens.css is stale")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as tmp:
        swift = os.path.join(tmp, "Tokens.swift")
        if not args.check:
            os.makedirs(os.path.dirname(CSS_PATH), exist_ok=True)
            return 0 if generate(CSS_PATH, swift) else 1
        fresh = os.path.join(tmp, "tokens.css")
        if not generate(fresh, swift):
            return 1
        try:
            with open(CSS_PATH, "rb") as fh:
                current = fh.read()
        except FileNotFoundError:
            sys.stderr.write("tokens: web/tokens.css is missing; run scripts/tokens.py\n")
            return 1
        with open(fresh, "rb") as fh:
            expected = fh.read()
        if current != expected:
            sys.stderr.write("tokens: web/tokens.css is stale; run scripts/tokens.py\n")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
