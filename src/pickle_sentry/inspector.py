"""Inspect pickle byte streams WITHOUT executing them.

Uses pickletools.genops only — a pure disassembler. A malicious pickle's
__reduce__ payload is never run by this module.
"""
from __future__ import annotations

import io
import pickletools
import zipfile

from .model import Finding

# Globals that give a pickle direct code / command execution, file or network access.
DANGEROUS_GLOBALS = {
    "os.system", "os.popen", "os.execv", "os.execve", "os.execvp", "os.spawnl",
    "os.spawnle", "os.spawnlp", "os.spawnve", "os.spawnvp", "posix.system",
    "nt.system", "subprocess.Popen", "subprocess.run", "subprocess.call",
    "subprocess.check_output", "subprocess.check_call", "subprocess.getoutput",
    "builtins.eval", "builtins.exec", "builtins.__import__", "builtins.compile",
    "builtins.open", "builtins.input", "builtins.getattr", "builtins.setattr",
    "__builtin__.eval", "__builtin__.exec", "__builtin__.__import__",
    "pty.spawn", "commands.getoutput", "socket.socket", "urllib.request.urlopen",
    "http.client.HTTPConnection", "shutil.rmtree", "pathlib.Path.write_text",
    "pathlib.Path.write_bytes", "code.InteractiveConsole", "code.eval",
    "runpy.run_module", "runpy.run_path", "importlib.import_module",
    "ctypes.CDLL", "ctypes.cdll", "multiprocessing.Process",
}

# Modules whose mere import inside a pickle is a strong smell.
DANGEROUS_MODULES = {"os", "posix", "nt", "subprocess", "pty", "commands",
                      "socket", "shutil", "runpy", "ctypes"}


def _globals_from_ops(data: bytes) -> tuple[list[str], bool]:
    """Return (global names referenced, whether a REDUCE opcode is present)."""
    globals_found: list[str] = []
    has_reduce = False
    buf: list[str] = []  # for STACK_GLOBAL: two strings pushed before the opcode
    last_strings: list[str] = []
    try:
        for opcode, arg, _pos in pickletools.genops(data):
            if opcode.name == "REDUCE":
                has_reduce = True
            elif opcode.name == "GLOBAL":
                # arg is "module name"
                if isinstance(arg, str):
                    parts = arg.split(" ", 1)
                    if len(parts) == 2:
                        globals_found.append(f"{parts[0]}.{parts[1]}")
            elif opcode.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8"):
                if isinstance(arg, str):
                    last_strings.append(arg)
                    last_strings = last_strings[-2:]
            elif opcode.name == "STACK_GLOBAL":
                if len(last_strings) >= 2:
                    globals_found.append(f"{last_strings[-2]}.{last_strings[-1]}")
                last_strings = []
    except Exception:
        # Truncated / corrupt stream: return what we have; caller reports parse failure.
        return globals_found, has_reduce
    return globals_found, has_reduce


def inspect_pickle_bytes(data: bytes, path: str) -> list[Finding]:
    # Torch checkpoints / model .bin files are zip archives holding a pickle stream.
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                inner: list[Finding] = []
                for name in zf.namelist():
                    if name.endswith("data.pkl") or name.endswith(".pkl"):
                        inner.extend(inspect_pickle_bytes(zf.read(name), f"{path}!{name}"))
                if inner:
                    return inner
        except zipfile.BadZipFile:
            pass
        return [Finding("PICKLE-FILE-PRESENT", "medium", path, None,
                        "Zip-based checkpoint present; no pickle stream could be parsed. "
                        "Treat as untrusted code-bearing data until verified.")]
    findings: list[Finding] = []
    globals_found, has_reduce = _globals_from_ops(data)
    dangerous = sorted({g for g in globals_found if g in DANGEROUS_GLOBALS})
    dangerous_mods = sorted({g for g in globals_found
                             if g.split(".")[0] in DANGEROUS_MODULES and g not in dangerous})

    if dangerous and has_reduce:
        findings.append(Finding(
            rule_id="PICKLE-DANGEROUS-REDUCE",
            severity="critical",
            path=path, line=None,
            message=("Pickle calls a dangerous callable via REDUCE "
                     f"({', '.join(dangerous)}). Loading this file executes code. "
                     "Treat as malicious unless you created it yourself."),
            evidence=", ".join(dangerous),
            cve="CVE-2026-57845",
        ))
    elif dangerous:
        findings.append(Finding(
            rule_id="PICKLE-DANGEROUS-GLOBAL",
            severity="high",
            path=path, line=None,
            message=f"Pickle references dangerous callable(s): {', '.join(dangerous)}.",
            evidence=", ".join(dangerous),
            cve="CVE-2026-57845",
        ))

    if dangerous_mods:
        findings.append(Finding(
            rule_id="PICKLE-SUSPICIOUS-MODULE",
            severity="high" if has_reduce else "medium",
            path=path, line=None,
            message=f"Pickle references OS/subprocess-level module globals: {', '.join(dangerous_mods)}.",
            evidence=", ".join(dangerous_mods),
        ))

    if not findings:
        findings.append(Finding(
            rule_id="PICKLE-FILE-PRESENT",
            severity="medium",
            path=path, line=None,
            message=("Pickle file present. Pickle is code, not data: never load it from an "
                     "untrusted source. Globals seen: "
                     + (", ".join(sorted(set(globals_found))[:8]) or "none parsed")),
            evidence=", ".join(sorted(set(globals_found))[:8]),
        ))
    return findings


def inspect_file(path: str) -> list[Finding]:
    """Inspect a .pkl/.pickle/.joblib file, or a torch .pt/.pth zip archive."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError as exc:
        return [Finding("PICKLE-UNREADABLE", "low", path, None, f"Could not read file: {exc}")]

    # Torch checkpoints are zip archives containing a pickled data.pkl stream.
    if head[:2] == b"PK":
        findings: list[Finding] = []
        try:
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if name.endswith("data.pkl") or name.endswith(".pkl"):
                        findings.extend(inspect_pickle_bytes(zf.read(name), f"{path}!{name}"))
            if findings:
                return findings
        except zipfile.BadZipFile:
            pass
        return [Finding("PICKLE-FILE-PRESENT", "medium", path, None,
                        "Zip-based checkpoint present; no pickle stream could be parsed. "
                        "Treat as untrusted code-bearing data until verified.")]

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return [Finding("PICKLE-UNREADABLE", "low", path, None, f"Could not read file: {exc}")]
    return inspect_pickle_bytes(data, path)
