"""AST-based code scanner. Parses Python source; never imports or runs it."""
from __future__ import annotations

import ast

from .model import Finding

PICKLE_MODULES = {"pickle", "cPickle", "_pickle", "dill", "cloudpickle", "marshal", "shelve"}
UNPICKLE_FUNCS = {"load", "loads", "Unpickler"}


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}   # local name -> dotted module/object
        self.from_imports: dict[str, str] = {}  # local name -> full dotted name

    # -- import bookkeeping -------------------------------------------------
    def visit_Import(self, node: ast.Import):
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for a in node.names:
            self.from_imports[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
        self.generic_visit(node)

    # -- helpers ------------------------------------------------------------
    def _dotted(self, node: ast.expr) -> str | None:
        parts: list[str] = []
        cur: ast.expr | None = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            parts.reverse()
            root = self.aliases.get(parts[0], parts[0])
            if parts[0] in self.from_imports:
                return ".".join([self.from_imports[parts[0]]] + parts[1:])
            return ".".join([root] + parts[1:])
        return None

    def _add(self, rule, severity, node, message, cve=None):
        self.findings.append(Finding(
            rule_id=rule, severity=severity, path=self.path,
            line=getattr(node, "lineno", None), message=message, cve=cve))

    # -- calls ---------------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        dotted = self._dotted(node.func) or ""

        # Hugging Face datasets: load_dataset("pandas", ...) — CVE-2026-57845
        if dotted == "load_dataset" or dotted.endswith(".load_dataset"):
            if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "pandas":
                self._add("HF-DATASETS-PANDAS-BUILDER", "critical", node,
                          'load_dataset("pandas", ...) routes files to pandas.read_pickle(). '
                          "A crafted pickle executes code on load (CVE-2026-57845, CVSS 8.8; "
                          "affects datasets <= 5.1.0, no patched release yet). "
                          "Use parquet/csv/json/arrow, or Dataset.from_pandas() for your own DataFrame.",
                          cve="CVE-2026-57845")
            elif not (node.args and isinstance(node.args[0], ast.Constant)
                      and isinstance(node.args[0].value, str)):
                # Dynamic / inferred builder: the extension decides, and .pkl means pandas.
                for kw in node.keywords:
                    if kw.arg == "data_files":
                        self._add("HF-DATASETS-DATA-FILES", "info", node,
                                  "load_dataset(...) with data_files and no explicit safe builder: "
                                  "confirm the builder inferred from the file extensions is not "
                                  "'pandas' and the source is trusted.")

        # pickle-family unpickling: pickle.load/loads, dill.load, marshal.load, shelve.open...
        root = dotted.split(".")[0] if dotted else ""
        leaf = dotted.rsplit(".", 1)[-1] if dotted else ""
        if root in PICKLE_MODULES and leaf in UNPICKLE_FUNCS:
            self._add("UNSAFE-DESERIALIZATION", "high", node,
                      f"{dotted}(...) deserializes pickle-family data. Never call it on "
                      "untrusted input — it is arbitrary code execution by design.")
        elif dotted.endswith(".read_pickle"):
            self._add("PANDAS-READ-PICKLE", "high", node,
                      "pandas.read_pickle(...) executes pickle payloads. Only use on files you "
                      "created; prefer read_parquet / read_csv for shared data.",
                      cve="CVE-2026-57845")

        # joblib.load is pickle under the hood
        if dotted == "joblib.load" or dotted.endswith(".joblib.load"):
            self._add("UNSAFE-DESERIALIZATION", "high", node,
                      "joblib.load(...) is pickle deserialization. Never call it on untrusted files.")

        # torch.load without weights_only=True
        if dotted == "torch.load" or dotted.endswith(".torch.load"):
            wo = None
            for kw in node.keywords:
                if kw.arg == "weights_only":
                    wo = kw.value.value if isinstance(kw.value, ast.Constant) else "dynamic"
            if wo is True:
                pass  # safe form
            elif wo is False:
                self._add("TORCH-LOAD-WEIGHTS-ONLY-FALSE", "high", node,
                          "torch.load(..., weights_only=False) unpickles the checkpoint — "
                          "arbitrary code execution from a crafted file. Use weights_only=True.")
            else:
                self._add("TORCH-LOAD-NO-WEIGHTS-ONLY", "medium", node,
                          "torch.load(...) without an explicit weights_only=True. Older torch "
                          "defaults to full unpickling; set weights_only=True for shared checkpoints.")

        # numpy.load(..., allow_pickle=True) — np.load defaults to allow_pickle=False, so only True is a sink
        if dotted == "numpy.load" or dotted.endswith(".numpy.load"):
            for kw in node.keywords:
                if kw.arg == "allow_pickle" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add("NUMPY-ALLOW-PICKLE", "high", node,
                              "numpy.load(..., allow_pickle=True) unpickles object arrays. "
                              "Never use it on shared .npy/.npz files; save data arrays instead.")

        # yaml.load without SafeLoader
        if dotted in ("yaml.load",) or dotted.endswith(".yaml.load"):
            has_loader = any(kw.arg == "Loader" for kw in node.keywords) or len(node.args) >= 2
            if not has_loader:
                self._add("YAML-UNSAFE-LOAD", "medium", node,
                          "yaml.load(...) without a SafeLoader can construct arbitrary objects. "
                          "Use yaml.safe_load(...).")
        self.generic_visit(node)


def scan_python_source(source: str, path: str) -> list[Finding]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [Finding("PARSE-ERROR", "low", path, exc.lineno,
                        f"Could not parse Python source: {exc.msg}")]
    v = _Visitor(path)
    v.visit(tree)
    return v.findings


def scan_python_file(path: str) -> list[Finding]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return scan_python_source(fh.read(), path)
    except OSError as exc:
        return [Finding("UNREADABLE", "low", path, None, f"Could not read file: {exc}")]
