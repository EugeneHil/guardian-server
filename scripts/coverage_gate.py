"""Fail when the line coverage in an `llvm-cov export -summary-only` JSON is below a minimum.

Usage: python3 -I -B scripts/coverage_gate.py <summary.json> --min <percent>
Exit codes: 0 ok, 1 below minimum, 2 unreadable or malformed summary.
"""
import argparse
import json
import sys


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary")
    parser.add_argument("--min", dest="minimum", type=float, required=True)
    args = parser.parse_args(argv)

    try:
        with open(args.summary) as f:
            percent = float(json.load(f)["data"][0]["totals"]["lines"]["percent"])
    except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
        print("malformed coverage summary: %r" % (exc,), file=sys.stderr)
        return 2

    print("line coverage: %.2f%% (minimum %.2f%%)" % (percent, args.minimum))
    return 0 if percent >= args.minimum else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
