"""Inspect pickle byte streams WITHOUT executing them.

The analysis core is an abstract interpreter over ``pickletools.genops``
(a pure disassembler): it tracks a symbolic stack so it can resolve *which
callables a pickle actually invokes* through REDUCE / NEWOBJ / INST —
including callables hidden in the memo and retrieved with GET at call time —
instead of merely noticing which globals are mentioned. A malicious pickle's
__reduce__ payload is never run by this module.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import pickletools
import tarfile
import zipfile
import zlib

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

# Globals routinely used to reconstruct ordinary data (DataFrames, tensors,
# datetimes). A REDUCE invoking only these is normal pickle mechanics.
BENIGN_GLOBAL_PREFIXES = (
    "collections.", "copyreg.", "builtins.object", "__builtin__.object",
    "numpy.", "pandas.", "pyarrow.", "torch.", "datetime.", "dateutil.",
    "decimal.", "uuid.", "re.", "codecs.", "typing.", "enum.",
)

# Extensions routed to formats.inspect_artifact_bytes by inspect_bytes().
ARTIFACT_EXTS = {".npy", ".npz", ".keras", ".safetensors", ".gguf"}

_MAX_DEPTH = 3  # container peeling depth and nested-pickle recursion depth

_SEVEN_Z_MAGIC = b"7z\xbc\xaf'\x1c"

# --- Symbolic values -------------------------------------------------------
# A symbol is a tuple: ("global", "module.name") | ("str", value) |
# ("bytes", value) | ("unknown",) | ("other",) | ("mark",).
_UNKNOWN = ("unknown",)
_OTHER = ("other",)
_MARK = ("mark",)


def _global(name: str):
    return ("global", name)


class _Analysis:
    """Everything collected from one pickle stream (plus its nested streams)."""

    def __init__(self) -> None:
        self.globals_referenced: list[str] = []
        self.invocations: list[str] = []
        self.unresolved_invocations: int = 0
        self.truncated: bool = False
        self.opcodes: int = 0
        self.nested_invocations: list[str] = []
        self.nested_globals: list[str] = []

    @property
    def anything_invoked(self) -> bool:
        return bool(self.invocations) or self.unresolved_invocations > 0

    def merge_nested(self, child: "_Analysis") -> None:
        self.globals_referenced.extend(child.globals_referenced)
        self.invocations.extend(child.invocations)
        self.unresolved_invocations += child.unresolved_invocations
        self.nested_globals.extend(child.globals_referenced)
        self.nested_invocations.extend(child.invocations)
        self.nested_globals.extend(child.nested_globals)
        self.nested_invocations.extend(child.nested_invocations)


def _memo_key(arg):
    if isinstance(arg, int):
        return arg
    try:
        return int(arg)
    except (TypeError, ValueError):
        return arg


def _analyze(data: bytes, depth: int = 0) -> _Analysis:
    """Abstractly interpret a pickle stream; never raises."""
    result = _Analysis()
    stack: list = []
    memo: dict = {}

    def push(sym) -> None:
        # A bytes constant that itself looks like a pickle stream is a nested
        # pickle (the classic smuggling shape): analyse and merge it.
        if sym[0] == "bytes" and depth < _MAX_DEPTH and sym[1][:1] == b"\x80":
            child = _analyze(sym[1], depth + 1)
            if child.opcodes >= 1:
                result.merge_nested(child)
        stack.append(sym)

    def pop():
        return stack.pop() if stack else _UNKNOWN

    def pop_to_mark() -> list:
        items = []
        while stack:
            sym = stack.pop()
            if sym == _MARK:
                break
            items.append(sym)
        items.reverse()
        return items

    try:
        for opcode, arg, _pos in pickletools.genops(data):
            result.opcodes += 1
            name = opcode.name

            if name in ("PROTO", "FRAME"):
                continue
            elif name == "STOP":
                break
            elif name == "GLOBAL":
                if isinstance(arg, str) and " " in arg:
                    module, attr = arg.split(" ", 1)
                    full = f"{module}.{attr}"
                elif isinstance(arg, str):
                    full = arg
                else:
                    push(_UNKNOWN)
                    continue
                result.globals_referenced.append(full)
                push(_global(full))
            elif name == "STACK_GLOBAL":
                attr = pop()
                module = pop()
                if module[0] == "str" and attr[0] == "str":
                    full = f"{module[1]}.{attr[1]}"
                    result.globals_referenced.append(full)
                    push(_global(full))
                else:
                    push(_UNKNOWN)
            elif name == "REDUCE":
                args_sym = pop()      # top of stack: normally the args tuple
                callable_sym = pop()  # below it: normally the callable
                invoked_here = []
                if callable_sym[0] == "global":
                    invoked_here.append(callable_sym[1])
                if args_sym[0] == "global":
                    # Evasive / hand-written streams may place the callable
                    # ABOVE its argument tuple — e.g. build the args first,
                    # then fetch the callable from the memo (MEMOIZE/BINGET)
                    # as the last step before REDUCE. CPython's unpickler
                    # rejects that operand order, but it is never ordinary
                    # data either: in a well-formed pickle the top of stack
                    # at REDUCE is always the args tuple, never a bare
                    # global. A global in either operand slot of a REDUCE is
                    # an attempted invocation, so count it.
                    invoked_here.append(args_sym[1])
                if invoked_here:
                    result.invocations.extend(invoked_here)
                else:
                    result.unresolved_invocations += 1
                push(_UNKNOWN)
            elif name == "NEWOBJ":
                pop()  # args tuple
                cls_sym = pop()
                if cls_sym[0] == "global":
                    result.invocations.append(cls_sym[1])
                else:
                    result.unresolved_invocations += 1
                push(_UNKNOWN)
            elif name == "NEWOBJ_EX":
                pop()  # kwargs
                pop()  # args
                cls_sym = pop()
                if cls_sym[0] == "global":
                    result.invocations.append(cls_sym[1])
                else:
                    result.unresolved_invocations += 1
                push(_UNKNOWN)
            elif name == "INST":
                # arg is "module class"; arguments sit on the stack above a MARK.
                if isinstance(arg, str) and " " in arg:
                    module, attr = arg.split(" ", 1)
                    full = f"{module}.{attr}"
                    result.globals_referenced.append(full)
                    result.invocations.append(full)
                else:
                    result.unresolved_invocations += 1
                pop_to_mark()
                push(_UNKNOWN)
            elif name == "OBJ":
                items = pop_to_mark()
                if items and items[0][0] == "global":
                    result.invocations.append(items[0][1])
                else:
                    result.unresolved_invocations += 1
                push(_UNKNOWN)
            elif name == "BUILD":
                pop()  # the state dict; the object under it stays on the stack
            elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                if stack:
                    memo[_memo_key(arg)] = stack[-1]
            elif name == "MEMOIZE":
                if stack:
                    memo[len(memo)] = stack[-1]
            elif name in ("GET", "BINGET", "LONG_BINGET"):
                push(memo.get(_memo_key(arg), _UNKNOWN))
            elif name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE",
                          "BINUNICODE8", "STRING"):
                push(("str", arg) if isinstance(arg, str) else _OTHER)
            elif name in ("SHORT_BINBYTES", "BINBYTES", "BINBYTES8", "BYTEARRAY8"):
                push(("bytes", arg) if isinstance(arg, (bytes, bytearray)) else _OTHER)
            elif name in ("BINSTRING", "SHORT_BINSTRING"):
                push(("bytes", arg) if isinstance(arg, (bytes, bytearray)) else _OTHER)
            elif name == "MARK":
                push(_MARK)
            elif name in ("TUPLE", "LIST", "DICT", "FROZENSET"):
                pop_to_mark()
                push(_OTHER)
            elif name == "TUPLE1":
                pop()
                push(_OTHER)
            elif name == "TUPLE2":
                pop(); pop()
                push(_OTHER)
            elif name == "TUPLE3":
                pop(); pop(); pop()
                push(_OTHER)
            elif name in ("EMPTY_LIST", "EMPTY_DICT", "EMPTY_TUPLE", "EMPTY_SET",
                          "NONE", "INT", "BININT", "BININT1", "BININT2", "LONG",
                          "LONG1", "LONG4", "FLOAT", "BINFLOAT", "NEWTRUE",
                          "NEWFALSE", "PERSID"):
                push(_OTHER)
            elif name == "BINPERSID":
                pop()
                push(_OTHER)
            elif name in ("EXT1", "EXT2", "EXT4"):
                push(_UNKNOWN)
            elif name == "APPEND":
                pop()
            elif name in ("APPENDS", "SETITEMS", "ADDITEMS"):
                pop_to_mark()
            elif name == "SETITEM":
                pop(); pop()
            elif name == "POP":
                pop()
            elif name == "POP_MARK":
                pop_to_mark()
            elif name == "DUP":
                push(stack[-1] if stack else _UNKNOWN)
            elif name == "NEXT_BUFFER":
                push(_OTHER)
            elif name == "READONLY_BUFFER":
                if stack:
                    stack[-1] = _OTHER
            else:
                # Unmodelled opcode: degrade the top of stack to unknown
                # rather than guessing, and keep going.
                if stack and stack[-1] != _MARK:
                    stack[-1] = _UNKNOWN
    except Exception:
        # Truncated / corrupt stream: judge what was collected so far.
        result.truncated = True
    return result


def _judge(analysis: _Analysis, path: str) -> list[Finding]:
    """Turn an _Analysis into findings (rule IDs / severities unchanged)."""
    referenced: list[str] = []
    for g in analysis.globals_referenced:
        if g not in referenced:
            referenced.append(g)
    invoked: list[str] = []
    for g in analysis.invocations:
        if g not in invoked:
            invoked.append(g)

    dangerous_invoked = sorted({g for g in invoked if g in DANGEROUS_GLOBALS})
    dangerous_referenced = sorted({g for g in referenced
                                   if g in DANGEROUS_GLOBALS and g not in dangerous_invoked})
    dangerous_mods = sorted({g for g in referenced
                             if g.split(".")[0] in DANGEROUS_MODULES
                             and g not in dangerous_invoked
                             and g not in dangerous_referenced})
    unknown_invoked = sorted({g for g in invoked
                              if g not in DANGEROUS_GLOBALS
                              and not g.startswith(BENIGN_GLOBAL_PREFIXES)})

    findings: list[Finding] = []
    if dangerous_invoked:
        message = ("Pickle invokes dangerous callable(s) via REDUCE/NEWOBJ "
                   f"({', '.join(dangerous_invoked)}). Loading this file executes code. "
                   "Treat as malicious unless you created it yourself.")
        if any(g in analysis.nested_invocations for g in dangerous_invoked):
            message += (" The invocation occurs inside a nested pickle stream "
                        "embedded in a bytes constant.")
        if analysis.truncated:
            message += " The stream was truncated part-way; this analysis is partial."
        findings.append(Finding(
            rule_id="PICKLE-DANGEROUS-REDUCE",
            severity="critical",
            path=path, line=None,
            message=message,
            evidence=", ".join(dangerous_invoked),
            cve="CVE-2026-57845",
        ))
    elif dangerous_referenced:
        findings.append(Finding(
            rule_id="PICKLE-DANGEROUS-GLOBAL",
            severity="high",
            path=path, line=None,
            message=f"Pickle references dangerous callable(s): {', '.join(dangerous_referenced)}.",
            evidence=", ".join(dangerous_referenced),
            cve="CVE-2026-57845",
        ))

    if unknown_invoked:
        findings.append(Finding(
            rule_id="PICKLE-REDUCE-CALLABLE",
            severity="high",
            path=path, line=None,
            message=("Pickle invokes non-standard callable(s) via REDUCE/NEWOBJ "
                     f"({', '.join(unknown_invoked)}). Loading it runs that code — "
                     "this is the shape of the CVE-2026-57845 PoC payload."),
            evidence=", ".join(unknown_invoked),
            cve="CVE-2026-57845",
        ))

    if dangerous_mods:
        findings.append(Finding(
            rule_id="PICKLE-SUSPICIOUS-MODULE",
            severity="high" if analysis.anything_invoked else "medium",
            path=path, line=None,
            message=f"Pickle references OS/subprocess-level module globals: {', '.join(dangerous_mods)}.",
            evidence=", ".join(dangerous_mods),
        ))

    if not findings:
        if analysis.opcodes == 0:
            findings.append(Finding(
                rule_id="PICKLE-UNPARSEABLE",
                severity="medium",
                path=path, line=None,
                message=("Pickle stream could not be disassembled (no valid pickle "
                         "opcodes could be parsed). The file may be corrupt, "
                         "truncated, or not a pickle at all; because it cannot be "
                         "inspected, do not load it from an untrusted source."),
            ))
        else:
            message = ("Pickle file present. Pickle is code, not data: never load it from an "
                       "untrusted source. Globals seen: "
                       + (", ".join(sorted(set(referenced))[:8]) or "none parsed"))
            if analysis.truncated:
                message += " The stream was truncated part-way; this analysis is partial."
            findings.append(Finding(
                rule_id="PICKLE-FILE-PRESENT",
                severity="medium",
                path=path, line=None,
                message=message,
                evidence=", ".join(sorted(set(referenced))[:8]),
            ))
    return findings


# --- Container peeling -----------------------------------------------------

def _try_peel_compression(data: bytes):
    """Return (inner_bytes, suffix) if data is a known compression wrapper."""
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data), "gzip"
        except Exception:
            return None
    if data[:3] == b"BZh" and data[3:4].isdigit():
        try:
            return bz2.decompress(data), "bz2"
        except Exception:
            return None
    if data[:6] == b"\xfd7zXZ\x00":
        try:
            return lzma.decompress(data), "xz"
        except Exception:
            try:
                return lzma.decompress(data, format=lzma.FORMAT_ALONE), "xz"
            except Exception:
                return None
    if data[:1] == b"\x78":
        try:
            return zlib.decompress(data), "zlib"
        except Exception:
            return None
    return None


def _member_findings(members, path: str, depth: int) -> list[Finding]:
    """Analyse archive members that look like pickle streams.

    members: list of (name, bytes). A member qualifies if its name ends in
    .pkl or its bytes start with the pickle protocol marker b'\\x80'; a member
    matched only by the byte sniff whose contents turn out not to parse as a
    pickle at all is ignored (raw tensor shards can start with 0x80 by chance).
    """
    findings: list[Finding] = []
    for name, member in members:
        by_name = name.lower().endswith(".pkl")
        by_bytes = member[:1] == b"\x80"
        if not (by_name or by_bytes):
            continue
        sub = _inspect_stream(member, f"{path}!{name}", depth + 1)
        if by_bytes and not by_name and sub and all(
                f.rule_id == "PICKLE-UNPARSEABLE" for f in sub):
            continue
        findings.extend(sub)
    return findings


def _inspect_zip(data: bytes, path: str, depth: int):
    """Findings for a zip archive, or None if it is not a readable zip."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return None
    members = []
    with zf:
        for name in zf.namelist():
            try:
                members.append((name, zf.read(name)))
            except Exception:
                continue
    findings = _member_findings(members, path, depth)
    if findings:
        return findings
    return [Finding("PICKLE-FILE-PRESENT", "medium", path, None,
                    "Zip-based checkpoint present; no pickle stream could be parsed. "
                    "Treat as untrusted code-bearing data until verified.")]


def _inspect_tar(data: bytes, path: str, depth: int):
    """Findings for a tar archive, or None if it is not a readable tar."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError:
        return None
    members = []
    with tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            try:
                fh = tf.extractfile(member)
                if fh is not None:
                    members.append((member.name, fh.read()))
            except Exception:
                continue
    findings = _member_findings(members, path, depth)
    if findings:
        return findings
    return [Finding("PICKLE-FILE-PRESENT", "medium", path, None,
                    "Tar archive present; no pickle stream could be parsed inside it. "
                    "Treat as untrusted code-bearing data until verified.")]


def _inspect_stream(data: bytes, path: str, depth: int) -> list[Finding]:
    """Peel containers (depth-capped), then analyse the pickle stream."""
    if depth < _MAX_DEPTH:
        # 7z cannot be read with the standard library; flag it as opaque
        # instead of waving it through — opaque containers are the known
        # Hub-scanner evasion route (the NullifAI bypass used 7z archives).
        if data[:6] == _SEVEN_Z_MAGIC:
            return [Finding(
                "PICKLE-CONTAINER-OPAQUE", "high", path, None,
                "7-Zip archive (7z magic bytes). pickle-sentry cannot inspect "
                "inside 7-Zip archives with the Python standard library, and "
                "opaque containers are the known evasion route against Hub "
                "pickle scanners (the NullifAI bypass hid payloads in a 7z "
                "archive). Extract the archive and scan its contents before "
                "loading anything from it.")]
        peeled = _try_peel_compression(data)
        if peeled is not None:
            inner, suffix = peeled
            return _inspect_stream(inner, f"{path}!{suffix}", depth + 1)
        if data[:4] == b"PK\x03\x04":
            zip_findings = _inspect_zip(data, path, depth)
            if zip_findings is not None:
                return zip_findings
        if len(data) > 262 and data[257:262] == b"ustar":
            tar_findings = _inspect_tar(data, path, depth)
            if tar_findings is not None:
                return tar_findings
    return _judge(_analyze(data), path)


def inspect_pickle_bytes(data: bytes, path: str) -> list[Finding]:
    """Inspect raw pickle-family bytes (containers are peeled first)."""
    return _inspect_stream(data, path, 0)


def inspect_bytes(data: bytes, path: str) -> list[Finding]:
    """Single bytes-level entry point: dispatch on the path's extension.

    Model-artifact extensions (.npy/.npz/.keras/.safetensors/.gguf) go to
    formats.inspect_artifact_bytes; everything else is treated as a pickle
    stream (with container peeling).
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in ARTIFACT_EXTS:
        from .formats import inspect_artifact_bytes
        return inspect_artifact_bytes(data, path)
    return inspect_pickle_bytes(data, path)


def inspect_file(path: str) -> list[Finding]:
    """Inspect a pickle-family or model-artifact file on disk."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return [Finding("PICKLE-UNREADABLE", "low", path, None, f"Could not read file: {exc}")]
    return inspect_bytes(data, path)
