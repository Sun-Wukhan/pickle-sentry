"""Scan a Hugging Face Hub repository without executing anything in it.

Lists the repo's files via the Hub API, downloads pickle-family files and
inspects them by disassembly only, and AST-scans any Python files.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error

from .inspector import inspect_pickle_bytes
from .model import Finding, ScanResult
from .scanner import scan_python_source

PICKLE_EXTS = {".pkl", ".pickle", ".joblib", ".pt", ".pth"}
# Model weights in classic PyTorch format are pickle zip archives.
MODEL_PICKLE_NAMES = {"pytorch_model.bin"}
DEFAULT_MAX_BYTES = 64 * 1024 * 1024  # per file


def _default_fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "pickle-sentry/0.2"})
    token = os.environ.get("HF_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def _api_base(repo_type: str) -> str:
    return {"dataset": "https://huggingface.co/api/datasets/",
            "model": "https://huggingface.co/api/models/",
            "space": "https://huggingface.co/api/spaces/"}[repo_type]


def _resolve_base(repo_id: str, repo_type: str, revision: str) -> str:
    prefix = {"dataset": "datasets/", "model": "", "space": "spaces/"}[repo_type]
    return f"https://huggingface.co/{prefix}{repo_id}/resolve/{revision}/"


def scan_hub_repo(repo_id: str, repo_type: str = "dataset", revision: str = "main",
                  max_bytes: int = DEFAULT_MAX_BYTES, fetch=None) -> ScanResult:
    fetch = fetch or _default_fetch
    result = ScanResult(root=f"hub://{repo_type}/{repo_id}@{revision}")
    try:
        info = json.loads(fetch(_api_base(repo_type) + repo_id))
    except (urllib.error.URLError, ValueError) as exc:
        result.findings.append(Finding("HUB-UNREACHABLE", "low", result.root, None,
                                       f"Could not read Hub repo info: {exc}"))
        return result

    siblings = info.get("siblings") or []
    base = _resolve_base(repo_id, repo_type, revision)
    for sib in siblings:
        name = sib.get("rfilename", "")
        ext = os.path.splitext(name)[1].lower()
        display = f"{result.root}/{name}"
        is_pickle = ext in PICKLE_EXTS or os.path.basename(name) in MODEL_PICKLE_NAMES
        if is_pickle:
            result.pickle_files_inspected += 1
            size = sib.get("size")
            if size is not None and size > max_bytes:
                result.findings.append(Finding(
                    "HUB-PICKLE-TOO-LARGE", "high", display, None,
                    f"Pickle-family file of {size/1e6:.1f} MB exceeds the {max_bytes/1e6:.0f} MB "
                    "inspection cap and was NOT downloaded. Inspect it locally before trusting it.",
                    cve="CVE-2026-57845"))
                continue
            try:
                data = fetch(base + urllib.request.quote(name))
            except urllib.error.URLError as exc:
                result.findings.append(Finding("HUB-DOWNLOAD-FAILED", "low", display, None,
                                               f"Could not download for inspection: {exc}"))
                continue
            result.findings.extend(inspect_pickle_bytes(data, display))
        elif ext == ".py":
            result.files_scanned += 1
            try:
                source = fetch(base + urllib.request.quote(name)).decode("utf-8", "replace")
            except urllib.error.URLError:
                continue
            result.findings.extend(scan_python_source(source, display))
    if not siblings:
        result.findings.append(Finding("HUB-EMPTY", "info", result.root, None,
                                       "Hub API returned no files for this repository."))
    return result
