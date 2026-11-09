from __future__ import annotations

import json

from .model import ScanResult, SEVERITY_ORDER

_ICON = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def to_text(result: ScanResult) -> str:
    lines = [
        f"pickle-sentry scan: {result.root}",
        f"  python files scanned: {result.files_scanned}",
        f"  pickle files inspected (never executed): {result.pickle_files_inspected}",
        f"  findings: {len(result.findings)}"
        + (f" (max severity: {result.max_severity})" if result.max_severity else ""),
        "",
    ]
    ordered = sorted(result.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line or 0))
    for f in ordered:
        loc = f.path + (f":{f.line}" if f.line else "")
        lines.append(f"[{_ICON[f.severity]}] {f.rule_id}  {loc}")
        lines.append(f"    {f.message}")
        if f.cve:
            lines.append(f"    CVE: {f.cve}")
    if not result.findings:
        lines.append("No unsafe deserialization patterns found.")
    return "\n".join(lines) + "\n"


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2) + "\n"


def to_sarif(result: ScanResult) -> str:
    runs = [{
        "tool": {"driver": {"name": "pickle-sentry", "version": "0.2.0",
                            "informationUri": "https://github.com/Sun-Wukhan/pickle-sentry"}},
        "results": [
            {
                "ruleId": f.rule_id,
                "level": {"critical": "error", "high": "error", "medium": "warning",
                          "low": "note", "info": "note"}[f.severity],
                "message": {"text": f.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": f.line or 1},
                }}],
                "properties": {"cve": f.cve} if f.cve else {},
            } for f in result.findings
        ],
    }]
    return json.dumps({"version": "2.1.0",
                       "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": runs}, indent=2) + "\n"
