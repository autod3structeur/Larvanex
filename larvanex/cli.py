"""Command line interface for Larvanex."""

from __future__ import annotations

import argparse
import glob
import os
import sys

from . import __version__
from . import report, tui
from .analyzers.yara import RULES_DIR, collect_rule_files
from .attack_layer import render_layer
from .html_report import render_html
from .scanner import ScanResult, build_analyzers, scan_bytes
from .watch import watch as watch_loop

EXIT_CODES = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
KNOWN_COMMANDS = {"scan", "watch", "rules"}


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


def _add_intel_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-network", action="store_true", help="Skip online threat-intel lookups.")
    parser.add_argument("--blocklist", metavar="PATH", help="Text file of known-bad hashes (one per line).")
    parser.add_argument(
        "--yara", metavar="PATH", action="append", help="Extra YARA rule file or directory (repeatable)."
    )
    parser.add_argument(
        "--extract", metavar="DIR", help="Recursively unpack embedded files and quarantine them to DIR."
    )
    parser.add_argument(
        "--decompose", action="store_true", help="Recursively unpack and scan embedded files (no saving)."
    )
    parser.add_argument("--depth", type=int, default=3, help="Max recursion depth for unpacking (default 3).")
    parser.add_argument("--no-color", action="store_true", help="Disable coloured output.")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="larvanex",
        description="Larvanex - static malware triage: detect disguised, embedded and suspicious files.",
        epilog="Run 'larvanex scan' for the default behaviour.",
    )
    parser.add_argument("--version", action="version", version=f"Larvanex {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan files or directories.")
    scan.add_argument("targets", nargs="+", help="Files, directories or glob patterns.")
    scan.add_argument("-r", "--recursive", action="store_true", help="Recurse into directories.")
    scan.add_argument("--json", action="store_true", help="Emit a JSON report instead of the terminal UI.")
    scan.add_argument("--html", metavar="PATH", help="Write a self-contained HTML report.")
    scan.add_argument(
        "--attack-layer", metavar="PATH", help="Write a MITRE ATT&CK Navigator layer (JSON)."
    )
    scan.add_argument("-v", "--verbose", action="store_true", help="Show full detail for every file.")
    _add_intel_options(scan)

    watcher = sub.add_parser("watch", help="Monitor folders and scan new/changed files.")
    watcher.add_argument("targets", nargs="+", help="Directories or files to watch.")
    watcher.add_argument("--interval", type=float, default=2.0, help="Poll interval in seconds (default 2).")
    _add_intel_options(watcher)

    rules = sub.add_parser("rules", help="List the bundled YARA rules.")
    rules.add_argument("--yara", metavar="PATH", action="append", help="Also list custom rules from PATH.")

    return parser


def _scan_silent(files, analyzers, decompose, extract, depth) -> list[ScanResult]:
    results: list[ScanResult] = []
    for path in files:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            print(f"larvanex: cannot read {path}: {exc}", file=sys.stderr)
            continue
        results.append(
            scan_bytes(path, data, analyzers, decompose=decompose, quarantine_dir=extract, max_depth=depth)
        )
    return results


def _run_scan(args) -> int:
    files = _expand_targets(args.targets, args.recursive)
    if not files:
        print("larvanex: no files matched the given targets.", file=sys.stderr)
        return 2

    analyzers = build_analyzers(
        network=not args.no_network,
        blocklist_path=args.blocklist,
        yara_paths=args.yara,
    )
    decompose = args.decompose or bool(args.extract)

    if args.json:
        results = _scan_silent(files, analyzers, decompose, args.extract, args.depth)
    else:
        console = tui.make_console(args.no_color)
        results = tui.scan_paths(
            console, files, analyzers, decompose=decompose, quarantine_dir=args.extract, max_depth=args.depth
        )

    if args.html:
        with open(args.html, "w", encoding="utf-8") as handle:
            handle.write(render_html(results))
        if not args.json:
            tui.make_console(args.no_color).print(f"[green]HTML report written to {args.html}[/green]")

    if args.attack_layer:
        with open(args.attack_layer, "w", encoding="utf-8") as handle:
            handle.write(render_layer(results))
        if not args.json:
            tui.make_console(args.no_color).print(
                f"[green]ATT&CK Navigator layer written to {args.attack_layer}[/green]"
            )

    if args.json:
        print(report.render_json(results))
    else:
        console = tui.make_console(args.no_color)
        if len(results) == 1:
            tui.render_result(console, results[0])
        else:
            tui.render_summary(console, results)
            for result in results:
                if result.verdict != "LIKELY SAFE" or args.verbose:
                    console.print()
                    tui.render_result(console, result)

    worst = 0
    for result in results:
        worst = max(worst, EXIT_CODES.get(result.verdict, 2))
    return worst


def _run_watch(args) -> int:
    analyzers = build_analyzers(
        network=not args.no_network,
        blocklist_path=args.blocklist,
        yara_paths=args.yara,
    )
    decompose = args.decompose or bool(args.extract)
    console = tui.make_console(args.no_color)
    watch_loop(
        console,
        args.targets,
        analyzers,
        interval=args.interval,
        decompose=decompose,
        quarantine_dir=args.extract,
        max_depth=args.depth,
    )
    return 0


def _run_rules(args) -> int:
    files = collect_rule_files([RULES_DIR, *(args.yara or [])])
    print(f"Bundled rules directory: {RULES_DIR}")
    if not files:
        print("  (none found)")
        return 0
    for path in files:
        print(f"  - {path}")
    print(f"\n{len(files)} rule file(s). Add your own with: larvanex scan --yara /path/to/rules ...")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw:
        _build_parser().print_help()
        return 0
    if raw[0] not in KNOWN_COMMANDS and raw[0] not in {"-h", "--help", "--version"}:
        raw = ["scan", *raw]

    args = _build_parser().parse_args(raw)

    if args.command == "watch":
        return _run_watch(args)
    if args.command == "rules":
        return _run_rules(args)
    if args.command == "scan":
        return _run_scan(args)

    _build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
