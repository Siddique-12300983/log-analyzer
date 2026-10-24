"""Command-line entry point for log-analyzer."""

from __future__ import annotations

import argparse
import sys
from typing import List

from . import __version__
from .analyzer import (
    DEFAULT_BRUTE_THRESHOLD,
    DEFAULT_BRUTE_WINDOW_SECONDS,
    DEFAULT_SPN_FANOUT,
    analyze,
)
from .model import AuthEvent
from .parsers import parse_auth_log, parse_windows_csv
from .report import build_report


def _read(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.readlines()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Flag suspicious authentication activity in Linux and Windows logs.",
    )
    p.add_argument("logfile", help="path to the log file")
    p.add_argument("--format", choices=("auth", "winsec", "auto"), default="auto",
                   help="log format: Linux auth.log, Windows Security CSV, or auto-detect")
    p.add_argument("--year", type=int, default=None,
                   help="year for auth.log timestamps (auth.log has no year); defaults to now")
    p.add_argument("--brute-threshold", type=int, default=DEFAULT_BRUTE_THRESHOLD,
                   help="failed logins from one IP that count as brute force")
    p.add_argument("--brute-window", type=int, default=DEFAULT_BRUTE_WINDOW_SECONDS,
                   help="window in seconds for the brute-force threshold")
    p.add_argument("--spn-fanout", type=int, default=DEFAULT_SPN_FANOUT,
                   help="distinct SPNs from one account that look like Kerberoasting")
    p.add_argument("--version", action="version", version=f"log-analyzer {__version__}")
    return p


def detect_format(path: str, lines: List[str]) -> str:
    if path.lower().endswith(".csv"):
        return "winsec"
    header = lines[0].lower() if lines else ""
    if "eventid" in header and "timecreated" in header:
        return "winsec"
    return "auth"


def run(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        lines = _read(args.logfile)
    except OSError as exc:
        print(f"error: cannot read {args.logfile}: {exc}", file=sys.stderr)
        return 2

    fmt = args.format if args.format != "auto" else detect_format(args.logfile, lines)

    events: List[AuthEvent]
    if fmt == "winsec":
        events = parse_windows_csv(lines)
    else:
        events = parse_auth_log(lines, year=args.year)

    findings = analyze(events,
                       brute_threshold=args.brute_threshold,
                       brute_window=args.brute_window,
                       spn_fanout=args.spn_fanout)
    print(build_report(events, findings))

    # Exit 1 when anything high severity turned up, so it is usable in a pipeline.
    return 1 if any(f.severity == "high" for f in findings) else 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
