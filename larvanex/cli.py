"""Command line interface for Larvanex."""

from __future__ import annotations

import argparse
import glob
import os
import sys

from . import __version__
from .report import Reporter
from .scanner import build_analyzers, scan_bytes, score, verdict

EXIT_CODES = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


def _expand_targets(targets: list[str], recursive: bool) -> list[str]:
    files: list[str] = []
    for target in targets:
        if any(char in target for char in "*?["):
            files.extend(sorted(glob.glob(target, recursive=recursive)))
            continue
        if os.path.isdir(target):
            if recursive:
                for root, _dirs, names in os.walk(target):
                    files.extend(os.path.join(root, name) for name in names)
            else:
                files.extend(
                    os.path.join(target, name)
                    for name in sorted(os.listdir(target))
                    if os.path.isfile(os.path.join(target, name))
                )
            continue
        files.append(target)
    return files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="larvanex",
        description="Larvanex - static malware triage. Detects disguised, embedded and suspicious files.",
    )
    parser.add_argument("targets", nargs="+", help="Files, directories or glob patterns to scan.")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recurse into directories.")
    parser.add_argument("--json", action="store_true", help="Emit a JSON report instead of text.")
    parser.add_argument("--no-network", action="store_true", help="Skip the MalwareBazaar online lookup.")
    parser.add_argument("--blocklist", metavar="PATH", help="Text file of known-bad hashes (one per line).")
    parser.add_argument("--no-color", action="store_true", help="Disable coloured output.")
    parser.add_argument("--version", action="version", version=f"Larvanex {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    files = _expand_targets(args.targets, args.recursive)

    if not files:
        print("larvanex: no files matched the given targets.", file=sys.stderr)
        return 2

    analyzers = build_analyzers(network=not args.no_network, blocklist_path=args.blocklist)
    reporter = Reporter(color=False if args.no_color else None)

    worst = 0
    reports: list[str] = []
    for path in files:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            print(f"larvanex: cannot read {path}: {exc}", file=sys.stderr)
            continue

        ctx = scan_bytes(path, data, analyzers)
        total = score(ctx.findings)
        result = verdict(ctx.findings, total)
        worst = max(worst, EXIT_CODES[result])

        if args.json:
            reports.append(reporter.render_json(ctx, total, result))
        else:
            reports.append(reporter.render_text(ctx, total, result))

    separator = "\n" if args.json else "\n\n"
    print(separator.join(reports))
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
