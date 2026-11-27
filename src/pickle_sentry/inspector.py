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
from dataclasses import dataclass

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

# --- Resource limits -------------------------------------------------------
# Inspection must stay bounded no matter how hostile the input is: a scanner
# that can be made to burn unbounded CPU or memory by the file it is checking
# is itself a denial-of-service surface. Every limit that stops an inspection
# short produces a low-severity SCAN-*-LIMIT finding instead of failing
# silently, so a partial result is always labelled as partial.

DEFAULT_MAX_OPCODES = 2_000_000          # pickle opcodes disassembled per stream
DEFAULT_MAX_INFLATED_BYTES = 512 * 1024 * 1024   # decompression output per wrapper
DEFAULT_MAX_ARCHIVE_ENTRY_BYTES = 256 * 1024 * 1024  # per archive member
DEFAULT_MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024 * 1024  # per archive, all members
DEFAULT_MAX_ARCHIVE_RATIO = 100          # declared uncompressed : compressed


@dataclass(frozen=True)
class InspectionLimits:
    """Caps applied to every inspection; see the constants above."""

    max_opcodes: int = DEFAULT_MAX_OPCODES
    max_inflated_bytes: int = DEFAULT_MAX_INFLATED_BYTES
    max_archive_entry_bytes: int = DEFAULT_MAX_ARCHIVE_ENTRY_BYTES
    max_archive_total_bytes: int = DEFAULT_MAX_ARCHIVE_TOTAL_BYTES
    max_archive_ratio: int = DEFAULT_MAX_ARCHIVE_RATIO


DEFAULT_LIMITS = InspectionLimits()

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
        self.opcode_limit_hit: bool = False
        self.nested_invocations: list[str] = []
        self.nested_globals: list[str] = []

    @property
    def anything_invoked(self) -> bool:
        return bool(self.invocations) or self.unresolved_invocations > 0

    def merge_nested(self, child: "_Analysis") -> None:
        self.globals_referenced.extend(child.globals_referenced)
        self.invocations.extend(child.invocations)
        self.unresolved_invocations += child.unresolved_invocations
        self.opcode_limit_hit = self.opcode_limit_hit or child.opcode_limit_hit
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


def _analyze(data: bytes, depth: int = 0,
             limits: InspectionLimits = DEFAULT_LIMITS) -> _Analysis:
    """Abstractly interpret a pickle stream; never raises."""
    result = _Analysis()
    stack: list = []
    memo: dict = {}

    def push(sym) -> None:
        # A bytes constant that itself looks like a pickle stream is a nested
        # pickle (the classic smuggling shape): analyse and merge it.
        if sym[0] == "bytes" and depth < _MAX_DEPTH and sym[1][:1] == b"\x80":
            child = _analyze(sym[1], depth + 1, limits)
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
            if result.opcodes > limits.max_opcodes:
                # Opcode flood: stop disassembling this stream. What was
                # collected so far is still judged, and _judge labels the
                # result partial with SCAN-OPCODE-LIMIT.
                result.opcode_limit_hit = True
                break
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


def _judge(analysis: _Analysis, path: str,
           limits: InspectionLimits = DEFAULT_LIMITS) -> list[Finding]:
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
    if analysis.opcode_limit_hit:
        findings.append(Finding(
            rule_id="SCAN-OPCODE-LIMIT",
            severity="low",
            path=path, line=None,
            message=(f"Disassembly stopped at the opcode ceiling: {analysis.opcodes} "
                     f"opcodes read (limit {limits.max_opcodes}). Inspection of this "
                     "stream is partial; content past the ceiling was not analysed."),
            evidence=f"{analysis.opcodes} opcodes",
        ))
    return findings


# --- Container peeling -----------------------------------------------------

def _decompress_capped(factory, data: bytes, cap: int):
    """Decompress via a file-object factory, reading at most cap+1 bytes.

    Returns (inner_bytes, capped) or None if the stream is not valid for
    that format. Reading through the streaming API means a decompression
    bomb is stopped at the cap instead of being materialised in memory.
    """
    try:
        with factory(io.BytesIO(data)) as fh:
            out = fh.read(cap + 1)
    except Exception:
        return None
    return out[:cap], len(out) > cap


def _try_peel_compression(data: bytes, cap: int):
    """Return (inner_bytes, suffix, capped) if data is a compression wrapper.

    Decompression output is capped at cap bytes; capped=True means the
    wrapper inflates past the cap and inner_bytes holds only the first cap
    bytes (the caller labels the inspection partial).
    """
    if data[:2] == b"\x1f\x8b":
        got = _decompress_capped(lambda bio: gzip.GzipFile(fileobj=bio), data, cap)
        return (got[0], "gzip", got[1]) if got is not None else None
    if data[:3] == b"BZh" and data[3:4].isdigit():
        got = _decompress_capped(lambda bio: bz2.BZ2File(bio), data, cap)
        return (got[0], "bz2", got[1]) if got is not None else None
    if data[:6] == b"\xfd7zXZ\x00":
        got = _decompress_capped(lambda bio: lzma.LZMAFile(bio), data, cap)
        if got is None:
            got = _decompress_capped(
                lambda bio: lzma.LZMAFile(bio, format=lzma.FORMAT_ALONE), data, cap)
        return (got[0], "xz", got[1]) if got is not None else None
    if data[:1] == b"\x78":
        try:
            out = zlib.decompressobj().decompress(data, cap + 1)
        except Exception:
            return None
        return out[:cap], "zlib", len(out) > cap
    return None


def zip_entry_skip_reason(info: zipfile.ZipInfo,
                          limits: InspectionLimits) -> str | None:
    """Why a zip entry must not be inflated, or None if it may be read.

    Judged from the central directory alone: the declared uncompressed size
    and the compression ratio expose a zip bomb before a single byte is
    inflated.
    """
    if info.file_size > limits.max_archive_entry_bytes:
        return (f"declared uncompressed size of {info.file_size} bytes exceeds "
                f"the {limits.max_archive_entry_bytes}-byte per-entry cap")
    if info.compress_size > 0 and info.file_size > 0:
        ratio = info.file_size / info.compress_size
        if ratio > limits.max_archive_ratio:
            return (f"compression ratio of {ratio:.0f}:1 exceeds the "
                    f"{limits.max_archive_ratio}:1 cap")
    return None


def read_zip_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                   limits: InspectionLimits) -> bytes | None:
    """Read one zip entry with a hard cap; None if it grows past the cap.

    The declared size can lie, so the read itself is capped too: at most
    per-entry-cap + 1 bytes are ever materialised for one entry.
    """
    cap = limits.max_archive_entry_bytes
    with zf.open(info) as fh:
        data = fh.read(cap + 1)
    if len(data) > cap:
        return None
    return data


def archive_limit_finding(path: str, skipped: list) -> Finding:
    """One SCAN-ARCHIVE-LIMIT finding summarising entries skipped for limits.

    skipped: list of (entry_name, reason). A single summary finding per
    archive keeps a hostile archive with thousands of entries from flooding
    the report.
    """
    details = "; ".join(f"{name}: {reason}" for name, reason in skipped[:5])
    if len(skipped) > 5:
        details += f"; and {len(skipped) - 5} more entr(ies)"
    return Finding(
        "SCAN-ARCHIVE-LIMIT", "low", path, None,
        "Archive entries were NOT inflated because they exceed the scanner's "
        f"resource limits ({details}). Their contents were not inspected; "
        "extract and scan them separately before trusting this archive.",
        evidence=", ".join(name for name, _ in skipped[:5]))


def _member_findings(members, path: str, depth: int,
                     limits: InspectionLimits = DEFAULT_LIMITS) -> list[Finding]:
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
        sub = _inspect_stream(member, f"{path}!{name}", depth + 1, limits)
        if by_bytes and not by_name and sub and all(
                f.rule_id == "PICKLE-UNPARSEABLE" for f in sub):
            continue
        findings.extend(sub)
    return findings


def _inspect_zip(data: bytes, path: str, depth: int,
                 limits: InspectionLimits = DEFAULT_LIMITS):
    """Findings for a zip archive, or None if it is not a readable zip."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return None
    members = []
    skipped = []
    inflated = 0
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            reason = zip_entry_skip_reason(info, limits)
            if reason is None and inflated + info.file_size > limits.max_archive_total_bytes:
                reason = (f"the archive inflation budget of "
                          f"{limits.max_archive_total_bytes} bytes was already reached")
            if reason is not None:
                skipped.append((info.filename, reason))
                continue
            try:
                member = read_zip_entry(zf, info, limits)
            except Exception:
                continue
            if member is None:
                skipped.append((info.filename,
                                 "entry grew past the "
                                 f"{limits.max_archive_entry_bytes}-byte per-entry "
                                 "cap while being inflated"))
                continue
            inflated += len(member)
            # Only pickle candidates are retained; other entries (raw tensor
            # shards) are dropped as soon as they are sniffed, so a large
            # archive's data payload is never held in memory wholesale.
            if info.filename.lower().endswith(".pkl") or member[:1] == b"\x80":
                members.append((info.filename, member))
    findings = _member_findings(members, path, depth, limits)
    if skipped:
        findings.append(archive_limit_finding(path, skipped))
    if findings:
        return findings
    return [Finding("PICKLE-FILE-PRESENT", "medium", path, None,
                    "Zip-based checkpoint present; no pickle stream could be parsed. "
                    "Treat as untrusted code-bearing data until verified.")]


def _inspect_tar(data: bytes, path: str, depth: int,
                 limits: InspectionLimits = DEFAULT_LIMITS):
    """Findings for a tar archive, or None if it is not a readable tar."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError:
        return None
    members = []
    skipped = []
    inflated = 0
    cap = limits.max_archive_entry_bytes
    with tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if member.size > cap:
                skipped.append((member.name,
                                 f"declared size of {member.size} bytes exceeds "
                                 f"the {cap}-byte per-entry cap"))
                continue
            if inflated + member.size > limits.max_archive_total_bytes:
                skipped.append((member.name,
                                 "the archive inflation budget of "
                                 f"{limits.max_archive_total_bytes} bytes was "
                                 "already reached"))
                continue
            try:
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                blob = fh.read(cap + 1)
            except Exception:
                continue
            if len(blob) > cap:
                skipped.append((member.name,
                                 f"entry grew past the {cap}-byte per-entry cap "
                                 "while being read"))
                continue
            inflated += len(blob)
            if member.name.lower().endswith(".pkl") or blob[:1] == b"\x80":
                members.append((member.name, blob))
    findings = _member_findings(members, path, depth, limits)
    if skipped:
        findings.append(archive_limit_finding(path, skipped))
    if findings:
        return findings
    return [Finding("PICKLE-FILE-PRESENT", "medium", path, None,
                    "Tar archive present; no pickle stream could be parsed inside it. "
                    "Treat as untrusted code-bearing data until verified.")]


def _inspect_stream(data: bytes, path: str, depth: int,
                    limits: InspectionLimits = DEFAULT_LIMITS) -> list[Finding]:
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
        peeled = _try_peel_compression(data, limits.max_inflated_bytes)
        if peeled is not None:
            inner, suffix, capped = peeled
            findings = _inspect_stream(inner, f"{path}!{suffix}", depth + 1, limits)
            if capped:
                findings.insert(0, Finding(
                    "SCAN-ARCHIVE-LIMIT", "low", f"{path}!{suffix}", None,
                    f"Decompression of the {suffix} wrapper reached the "
                    f"{limits.max_inflated_bytes}-byte inflation cap; only the "
                    "bytes up to the cap were inspected, so this result is "
                    "partial. The uncompressed stream is larger than what was "
                    "analysed."))
            return findings
        if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            zip_findings = _inspect_zip(data, path, depth, limits)
            if zip_findings is not None:
                return zip_findings
        if len(data) > 262 and data[257:262] == b"ustar":
            tar_findings = _inspect_tar(data, path, depth, limits)
            if tar_findings is not None:
                return tar_findings
    return _judge(_analyze(data, limits=limits), path, limits)


def inspect_pickle_bytes(data: bytes, path: str,
                         limits: InspectionLimits = DEFAULT_LIMITS) -> list[Finding]:
    """Inspect raw pickle-family bytes (containers are peeled first)."""
    return _inspect_stream(data, path, 0, limits)


def inspect_bytes(data: bytes, path: str,
                  limits: InspectionLimits = DEFAULT_LIMITS) -> list[Finding]:
    """Single bytes-level entry point: dispatch on the path's extension.

    Model-artifact extensions (.npy/.npz/.keras/.safetensors/.gguf) go to
    formats.inspect_artifact_bytes; everything else is treated as a pickle
    stream (with container peeling).
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in ARTIFACT_EXTS:
        from .formats import inspect_artifact_bytes
        return inspect_artifact_bytes(data, path, limits)
    return inspect_pickle_bytes(data, path, limits)


def inspect_file(path: str,
                 limits: InspectionLimits = DEFAULT_LIMITS) -> list[Finding]:
    """Inspect a pickle-family or model-artifact file on disk."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return [Finding("PICKLE-UNREADABLE", "low", path, None, f"Could not read file: {exc}")]
    return inspect_bytes(data, path, limits)
