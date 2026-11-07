"""Command line interface.

Machine contract: JSON on stdout, exit code 0/1. Human polish (progress bars,
colour, the demo walkthrough) goes to stderr or the demo command only, and is
never mixed into the JSON output.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import zipfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .collect import collect
from .core import VERSION, ProgressCallback
from .demo import run_demo
from .reporting import search, timeline
from .ui import BOLD, CYAN, DIM, ProgressRenderer, color_enabled, colorize, line_printer, step
from .verify import verify


def _keywords(args: dict[str, Any], text: list[str] | None) -> None:
    if not text:
        return
    terms = [term.strip() for chunk in text for term in chunk.split(",")]
    existing = args.pop("keywords", None) or []
    args["keywords"] = existing + [term for term in terms if term]


def _keywords_file(args: dict[str, Any], path: Path | None) -> None:
    if not path:
        return
    terms = [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    existing = args.pop("keywords", None) or []
    args["keywords"] = existing + terms


def _progress_setup(args: dict[str, Any]) -> tuple[ProgressCallback | None, Callable[[], None] | None]:
    """Resolve --verbose/--progress/--no-progress into a progress callback."""
    verbose = args.pop("verbose", False)
    force = args.pop("progress", False)
    off = args.pop("no_progress", False)
    no_color = args.pop("no_color", False)
    if no_color:
        os.environ["NO_COLOR"] = "1"
    if verbose:
        return line_printer(enabled=not no_color), None
    if off or (not force and not sys.stderr.isatty()):
        return None, None
    renderer = ProgressRenderer(force=force)
    return renderer, renderer.finish


def _print_demo_summary(summary: dict[str, str]) -> None:
    enabled = color_enabled(sys.stdout)
    print(colorize("Digital Evidence Lab — demo", BOLD, enabled=enabled))
    print(step("generated fictional source exports", summary["files"] + " files", enabled=enabled))
    print(step("collected with hash-chained custody log", enabled=enabled))
    print(step("verified manifest, handling log and anchors", enabled=enabled))
    print(step("analysed timeline", f"{summary['records']} records, report + HTML view", enabled=enabled))
    print()
    print(f"  Report: {colorize(summary['report'], CYAN, enabled=enabled)}")
    if summary["opened"] == "True":
        print(colorize("  (opened in your browser)", DIM, enabled=enabled))
    else:
        print(colorize("  Open it with your browser, or re-run without --no-open.", DIM, enabled=enabled))
    print(colorize("  All data is synthetic; nothing was collected from a real device.", DIM, enabled=enabled))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Educational logical evidence collection, verification and timeline analysis. "
        "No device access, disk imaging or admissibility claims."
    )
    parser.add_argument("--version", action="version", version=f"digital-evidence-lab {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    p = commands.add_parser("demo", help="generate a fictional case end-to-end and open the report")
    p.add_argument("--dir", type=Path, default=Path("digital-evidence-demo"))
    p.add_argument("--case-id")
    p.add_argument("--no-open", action="store_true", help="do not launch a browser for report.html")
    p.add_argument("--progress", action="store_true")
    p.add_argument("--no-progress", action="store_true")
    p.add_argument("--no-color", action="store_true")

    p = commands.add_parser("collect", help="copy source files into a new case and hash them")
    p.add_argument("source", type=Path)
    p.add_argument("case", type=Path)
    p.add_argument("--operator", required=True)
    p.add_argument("--case-id", required=True)
    p.add_argument("--jobs", type=int, default=1)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--progress", action="store_true")
    p.add_argument("--no-progress", action="store_true")
    p.add_argument("--no-color", action="store_true")

    for name, help_text in (
        ("verify", "check case integrity against its manifest and handling log"),
        ("timeline", "build a verified timeline and analysis report"),
    ):
        p = commands.add_parser(name, help=help_text)
        p.add_argument("case", type=Path)
        p.add_argument("--expected-manifest")
        p.add_argument("--expected-handling")
        p.add_argument("--jobs", type=int, default=1)
        if name == "timeline":
            p.add_argument("output", type=Path)
            p.add_argument("--mapping", type=Path, help="JSON file mapping source fields to timestamp/action/detail")
            p.add_argument("--keywords", action="append", help="comma-separated search terms (repeatable)")
            p.add_argument("--keywords-file", type=Path, help="one search term per line")
            p.add_argument("--regex", action="store_true", help="treat keyword terms as regular expressions")
            p.add_argument("--session-gap", type=int, metavar="SECONDS")
            p.add_argument("--hashset", type=Path, help="CSV with sha256[,label,notes] to classify evidence files")
            p.add_argument("--no-html", action="store_true", help="skip the HTML report")
            p.add_argument("--assume-offset", help="offset like +00:00 for RFC 3164 syslog timestamps")
            p.add_argument("--assume-year", type=int, help="year for RFC 3164 syslog timestamps")
            p.add_argument("--verbose", action="store_true")
            p.add_argument("--progress", action="store_true")
            p.add_argument("--no-progress", action="store_true")
            p.add_argument("--no-color", action="store_true")

    p = commands.add_parser("search", help="keyword search across a verified case")
    p.add_argument("case", type=Path)
    p.add_argument("query")
    p.add_argument("--regex", action="store_true")
    p.add_argument("--mapping", type=Path, help="JSON file mapping source fields to timestamp/action/detail")
    p.add_argument("--expected-manifest")
    p.add_argument("--expected-handling")
    p.add_argument("--jobs", type=int, default=1)
    p.add_argument("--verbose", action="store_true")

    args = vars(parser.parse_args(argv))
    command = args.pop("command")
    _keywords(args, args.pop("keywords", None))
    _keywords_file(args, args.pop("keywords_file", None))
    progress, finish = _progress_setup(args)
    demo_command = command == "demo"
    summary: Any
    try:
        if demo_command:
            summary = run_demo(
                args["dir"], case_id=args.get("case_id"), open_browser=not args["no_open"] and sys.stdout.isatty(), progress=progress
            )
        elif command == "collect":
            summary = collect(
                args["source"], args["case"], operator=args["operator"], case_id=args["case_id"], jobs=args["jobs"], progress=progress
            )
        elif command == "verify":
            summary = verify(
                args["case"], expected_manifest=args["expected_manifest"], expected_handling=args["expected_handling"], jobs=args["jobs"]
            )
        elif command == "timeline":
            summary = timeline(
                args["case"],
                args["output"],
                expected_manifest=args["expected_manifest"],
                expected_handling=args["expected_handling"],
                jobs=args["jobs"],
                mapping_path=args["mapping"],
                keywords=args.get("keywords"),
                regex=args["regex"],
                session_gap=args["session_gap"],
                hashset=args["hashset"],
                html=not args["no_html"],
                assume_offset=args["assume_offset"],
                assume_year=args["assume_year"],
                progress=progress,
            )
        else:
            summary = search(
                args["case"],
                args["query"],
                regex=args["regex"],
                mapping_path=args["mapping"],
                expected_manifest=args["expected_manifest"],
                expected_handling=args["expected_handling"],
                jobs=args["jobs"],
                progress=progress,
            )
    except (ValueError, KeyError, OSError, sqlite3.Error, zipfile.BadZipFile, re.error, TypeError) as error:
        if finish:
            finish()
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 1
    if finish:
        finish()
    if demo_command:
        _print_demo_summary(summary)
    else:
        print(json.dumps({"ok": True, "result": summary}, indent=2))
    return 0
