from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .inspector import inspect_file
from .model import ScanResult
from .report import to_json, to_sarif, to_text
from .scanner import scan_python_file

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", ".mypy_cache"}
PICKLE_EXTS = {".pkl", ".pickle", ".joblib", ".pt", ".pth"}


def collect(root: str, exclude: list[str] | None = None) -> ScanResult:
    exclude = exclude or []
    result = ScanResult(root=root)
    paths: list[str] = []
    if os.path.isfile(root):
        paths = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                paths.append(os.path.join(dirpath, name))
    if exclude:
        paths = [p for p in paths if not any(x in p for x in exclude)]
    for p in sorted(paths):
        ext = os.path.splitext(p)[1].lower()
        if ext == ".py":
            result.files_scanned += 1
            result.findings.extend(scan_python_file(p))
        elif ext in PICKLE_EXTS:
            result.pickle_files_inspected += 1
            result.findings.extend(inspect_file(p))
    return result


def _hub_main(argv: list[str]) -> int:
    from .hub import scan_hub_repo
    ap = argparse.ArgumentParser(
        prog="pickle-sentry hub",
        description="Scan a Hugging Face Hub repository for pickle files and unsafe "
                    "deserialization. Files are inspected by disassembly, never executed.")
    ap.add_argument("repo_id", help="e.g. user/dataset-name")
    ap.add_argument("--repo-type", choices=["dataset", "model", "space"], default="dataset")
    ap.add_argument("--revision", default="main")
    ap.add_argument("--max-size-mb", type=float, default=64.0,
                    help="Per-file inspection cap in MB (default: 64)")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--output", help="Write the report to this file instead of stdout")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                    default="high")
    args = ap.parse_args(argv)
    result = scan_hub_repo(args.repo_id, repo_type=args.repo_type, revision=args.revision,
                           max_bytes=int(args.max_size_mb * 1024 * 1024))
    rendered = {"text": to_text, "json": to_json, "sarif": to_sarif}[args.format](result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    else:
        sys.stdout.write(rendered)
    return 1 if result.meets(args.fail_on) else 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "hub":
        return _hub_main(argv[1:])
    ap = argparse.ArgumentParser(
        prog="pickle-sentry",
        description="Scan code and dataset files for unsafe pickle deserialization "
                    "(incl. CVE-2026-57845). Inspected pickle files are never executed.")
    ap.add_argument("path", help="File or directory to scan")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--output", help="Write the report to this file instead of stdout")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                    default="high",
                    help="Exit 1 if any finding is at or above this severity (default: high)")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Skip paths containing this substring (repeatable, e.g. --exclude /tests/)")
    ap.add_argument("--version", action="version", version=f"pickle-sentry {__version__}")
    args = ap.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"error: no such path: {args.path}", file=sys.stderr)
        return 2

    result = collect(args.path, exclude=args.exclude)
    rendered = {"text": to_text, "json": to_json, "sarif": to_sarif}[args.format](result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    else:
        sys.stdout.write(rendered)
    return 1 if result.meets(args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
