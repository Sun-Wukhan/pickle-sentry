from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .inspector import (DEFAULT_LIMITS, DEFAULT_MAX_OPCODES, InspectionLimits,
                        inspect_file)
from .model import ScanResult
from .report import to_json, to_sarif, to_text
from .scanner import scan_python_file

SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".tox", ".mypy_cache"}
PICKLE_EXTS = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".bin"}
ARTIFACT_EXTS = {".npy", ".npz", ".keras", ".safetensors", ".gguf"}
# Container formats the inspector already knows how to peel (or, for 7z, to
# flag as opaque). Routing by extension alone used to skip these entirely, so
# a standalone malicious1.zip sitting next to the .pkl files was never even
# counted. ".tgz" is listed for clarity; "x.tar.gz" splitexts to ".gz".
ARCHIVE_EXTS = {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z"}
INSPECT_EXTS = PICKLE_EXTS | ARTIFACT_EXTS | ARCHIVE_EXTS

_SNIFF_BYTES = 512  # tar's ustar marker sits at offset 257; 512 covers it
_SEVEN_Z_MAGIC = b"7z\xbc\xaf'\x1c"


def _sniff_inspectable(path: str) -> bool:
    """Magic-byte check for files whose extension routes nowhere.

    Catches containers and pickle streams hiding behind a wrong or unknown
    extension (e.g. a zip named ``weights.txt``). Reads at most the first
    512 bytes and never raises: an unreadable file is simply not sniffed.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(_SNIFF_BYTES)
    except OSError:
        return False
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):  # zip (incl. empty zip)
        return True
    if head[:6] == _SEVEN_Z_MAGIC:  # 7z
        return True
    if head[:2] == b"\x1f\x8b":  # gzip
        return True
    if head[:3] == b"BZh":  # bzip2
        return True
    if head[:6] == b"\xfd7zXZ\x00":  # xz
        return True
    if len(head) > 262 and head[257:262] == b"ustar":  # tar
        return True
    if head[:1] == b"\x80":  # pickle protocol marker (protocols 2+)
        return True
    return False


def collect(root: str, exclude: list[str] | None = None,
            limits: InspectionLimits = DEFAULT_LIMITS) -> ScanResult:
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
        elif ext in INSPECT_EXTS or _sniff_inspectable(p):
            result.pickle_files_inspected += 1
            result.findings.extend(inspect_file(p, limits))
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
    ap.add_argument("--max-total-mb", type=float, default=512.0,
                    help="Total download budget per repo scan in MB (default: 512). "
                         "Files past the budget are reported, not downloaded.")
    ap.add_argument("--max-opcodes", type=int, default=DEFAULT_MAX_OPCODES,
                    help=f"Max pickle opcodes disassembled per stream "
                         f"(default: {DEFAULT_MAX_OPCODES})")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--output", help="Write the report to this file instead of stdout")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                    default="high")
    args = ap.parse_args(argv)
    result = scan_hub_repo(args.repo_id, repo_type=args.repo_type, revision=args.revision,
                           max_bytes=int(args.max_size_mb * 1024 * 1024),
                           max_total_bytes=int(args.max_total_mb * 1024 * 1024),
                           limits=InspectionLimits(max_opcodes=args.max_opcodes))
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
    ap.add_argument("--max-opcodes", type=int, default=DEFAULT_MAX_OPCODES,
                    help=f"Max pickle opcodes disassembled per stream "
                         f"(default: {DEFAULT_MAX_OPCODES}); past the ceiling the "
                         "stream is reported as partially inspected")
    ap.add_argument("--version", action="version", version=f"pickle-sentry {__version__}")
    args = ap.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"error: no such path: {args.path}", file=sys.stderr)
        return 2

    result = collect(args.path, exclude=args.exclude,
                     limits=InspectionLimits(max_opcodes=args.max_opcodes))
    rendered = {"text": to_text, "json": to_json, "sarif": to_sarif}[args.format](result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    else:
        sys.stdout.write(rendered)
    return 1 if result.meets(args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
