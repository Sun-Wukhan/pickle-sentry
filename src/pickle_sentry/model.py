from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule_id: str
    severity: str  # info | low | medium | high | critical
    path: str
    line: int | None
    message: str
    evidence: str = ""
    cve: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    pickle_files_inspected: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])

    def meets(self, threshold: str) -> bool:
        if threshold == "none" or not self.findings:
            return False
        t = SEVERITY_ORDER[threshold]
        return any(SEVERITY_ORDER[f.severity] >= t for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "pickle_files_inspected": self.pickle_files_inspected,
            "max_severity": self.max_severity,
            "findings": [f.to_dict() for f in self.findings],
        }
