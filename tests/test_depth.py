"""Depth tests: VM-tracking analysis, container peeling, nested pickles.

The inspector must resolve WHICH callables a pickle actually invokes —
through the memo, through STACK_GLOBAL, through containers — by abstract
interpretation only. Nothing here may ever be unpickled by the inspector.
"""
import gzip
import os
import pickle
import tarfile
import io
import zipfile
import zlib

import pytest

from pickle_sentry.inspector import inspect_pickle_bytes

CANARY = "/tmp/pickle_sentry_depth_canary_must_not_exist"


@pytest.fixture(autouse=True)
def clean_canary():
    if os.path.exists(CANARY):
        os.remove(CANARY)
    yield
    assert not os.path.exists(CANARY), "inspector EXECUTED the pickle — catastrophic failure"


class _Evil:
    def __reduce__(self):
        return (os.system, (f"touch {CANARY}",))


# (1) classic __reduce__ canary
def test_classic_reduce_canary_critical_not_executed():
    findings = inspect_pickle_bytes(pickle.dumps(_Evil()), "evil.pkl")
    assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
    assert findings[0].severity == "critical"


# (2) memo evasion: the callable reaches REDUCE via BINPUT/BINGET, not by
# sitting next to the REDUCE opcode. Bytes-level trick: GLOBAL pushes
# os.system, BINPUT (q\x00) stores that stack top into memo slot 0 without
# popping it, POP-free args are built later, and BINGET (h\x00) pushes
# memo[0] back onto the stack immediately before REDUCE — a scanner that
# only pattern-matches opcodes near REDUCE sees a string, a tuple and a
# memo fetch, never the callable.
def test_memo_evasion_still_critical():
    cmd = f"touch {CANARY}".encode()
    payload = (
        b"\x80\x02"              # PROTO 2
        b"cos\nsystem\n"         # GLOBAL os system -> stack: [global os.system]
        b"q\x00"                 # BINPUT 0 -> memo[0] = os.system (no pop)
        b"0"                     # POP the original reference off the stack
        b"h\x00"                 # BINGET 0 -> stack: [memo[0]] == os.system
        b"\x8c" + bytes([len(cmd)]) + cmd +  # SHORT_BINUNICODE arg
        b"\x85"                  # TUPLE1 -> args tuple
        b"R"                     # REDUCE -> invokes the memo-retrieved callable
        b"."                     # STOP
    )
    findings = inspect_pickle_bytes(payload, "memo.pkl")
    assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
    assert findings[0].severity == "critical"
    assert "os.system" in findings[0].evidence


# (3) STACK_GLOBAL + REDUCE
def test_stack_global_eval_critical():
    payload = (
        b"\x80\x02"
        b"\x8c\x08builtins"      # SHORT_BINUNICODE "builtins"
        b"\x8c\x04eval"          # SHORT_BINUNICODE "eval"
        b"\x93"                  # STACK_GLOBAL -> builtins.eval
        b"\x8c\x031+1"           # arg
        b"\x85"                  # TUPLE1
        b"R"                     # REDUCE
        b"."
    )
    findings = inspect_pickle_bytes(payload, "sg.pkl")
    assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
    assert findings[0].severity == "critical"
    assert "builtins.eval" in findings[0].evidence


# (4) compression-wrapped payloads are peeled before analysis
def test_gzip_wrapped_malicious_critical_with_suffix():
    findings = inspect_pickle_bytes(gzip.compress(pickle.dumps(_Evil())), "g.pkl")
    assert any(f.rule_id == "PICKLE-DANGEROUS-REDUCE" and f.severity == "critical"
               for f in findings)
    assert any("!gzip" in f.path for f in findings)


def test_bz2_xz_zlib_wrapped_malicious_critical():
    import bz2
    import lzma
    raw = pickle.dumps(_Evil())
    for wrapped, suffix in ((bz2.compress(raw), "!bz2"),
                            (lzma.compress(raw), "!xz"),
                            (zlib.compress(raw), "!zlib")):
        findings = inspect_pickle_bytes(wrapped, "w.pkl")
        assert any(f.severity == "critical" for f in findings), suffix
        assert any(suffix in f.path for f in findings), suffix


def test_corrupt_gzip_falls_back_without_raising():
    findings = inspect_pickle_bytes(b"\x1f\x8b" + b"\x00" * 40, "bad.pkl")
    assert findings  # raw fallback judges the bytes (unparseable)
    assert all(f.severity in ("medium", "low") for f in findings)


# (5) 7z is opaque: flagged, never read
def test_seven_zip_flagged_opaque_high():
    findings = inspect_pickle_bytes(b"7z\xbc\xaf'\x1c" + b"\x00" * 64, "a.bin")
    assert len(findings) == 1
    assert findings[0].rule_id == "PICKLE-CONTAINER-OPAQUE"
    assert findings[0].severity == "high"


# zip / tar members are inspected like torch archives
def test_zip_and_tar_members_inspected():
    raw = pickle.dumps(_Evil())
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("inner/evil.pkl", raw)
        zf.writestr("notes.txt", "hello")
    findings = inspect_pickle_bytes(zbuf.getvalue(), "a.zip")
    assert any(f.severity == "critical" and "!inner/evil.pkl" in f.path for f in findings)

    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w") as tf:
        info = tarfile.TarInfo("evil.pkl")
        info.size = len(raw)
        tf.addfile(info, io.BytesIO(raw))
    findings = inspect_pickle_bytes(tbuf.getvalue(), "a.tar")
    assert any(f.severity == "critical" and "!evil.pkl" in f.path for f in findings)


# (6) nested pickle inside a bytes constant
def test_nested_pickle_invocation_merged_and_noted():
    outer = pickle.dumps(pickle.dumps(_Evil()))
    findings = inspect_pickle_bytes(outer, "outer.pkl")
    critical = [f for f in findings if f.severity == "critical"]
    assert critical, findings
    assert "!nested" in critical[0].path or "nested" in critical[0].message


# (7) benign torch-style stream: only a medium presence finding
def test_benign_torch_style_no_finding_above_medium():
    payload = (
        b"\x80\x02"
        b"ctorch\nFloatStorage\n" b"0"                    # referenced, discarded
        b"ccollections\nOrderedDict\n" b")" b"\x81"       # NEWOBJ OrderedDict()
        b"ctorch._utils\n_rebuild_tensor_v2\n" b"(NNNNt" b"R"  # benign REDUCE
        b"."
    )
    findings = inspect_pickle_bytes(payload, "model.pt")
    assert findings
    assert all(f.severity in ("medium", "low", "info") for f in findings)


# (8) precision: a dangerous global that is REFERENCED but never invoked,
# while an unrelated benign invocation runs, must not be reported as an
# invocation (no critical, no PICKLE-REDUCE-CALLABLE for it).
def test_referenced_but_not_invoked_is_not_an_invocation():
    payload = (
        b"\x80\x02"
        b"cos\nsystem\n" b"0"                             # GLOBAL os.system; POP
        b"ccollections\nOrderedDict\n" b")" b"\x81"       # benign NEWOBJ
        b"."
    )
    findings = inspect_pickle_bytes(payload, "prec.pkl")
    assert not any(f.severity == "critical" for f in findings)
    assert any(f.rule_id == "PICKLE-DANGEROUS-GLOBAL" and f.severity == "high"
               for f in findings)
    reduce_callable = [f for f in findings if f.rule_id == "PICKLE-REDUCE-CALLABLE"]
    assert not reduce_callable


# (9) truncated stream: findings, no exception
def test_truncated_pickle_returns_findings():
    full = pickle.dumps({"a": [1, 2, 3], "b": "hello"})
    findings = inspect_pickle_bytes(full[:12], "trunc.pkl")
    assert isinstance(findings, list) and len(findings) >= 1


def test_unparseable_bytes_get_unparseable_finding():
    findings = inspect_pickle_bytes(b"", "empty.pkl")
    assert findings[0].rule_id == "PICKLE-UNPARSEABLE"
    assert findings[0].severity == "medium"
    assert "could not be disassembled" in findings[0].message


# (10) NEWOBJ of an unknown class is a non-standard invocation
def test_newobj_unknown_class_is_high():
    payload = b"\x80\x02" + b"cacme.widgets\nGadget\n" + b")" + b"\x81" + b"."
    findings = inspect_pickle_bytes(payload, "newobj.pkl")
    assert any(f.rule_id == "PICKLE-REDUCE-CALLABLE" and f.severity == "high"
               and "acme.widgets.Gadget" in f.evidence for f in findings)


# INST (protocol 0) instantiation of a dangerous class counts as invocation:
# the INST opcode's operand lines name the callable applied to the args
# sitting above the MARK.
def test_inst_dangerous_counts_as_invocation():
    payload = b"(S'echo hi'\nisubprocess\nPopen\n."
    findings = inspect_pickle_bytes(payload, "inst.pkl")
    assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
    assert findings[0].severity == "critical"
    assert "subprocess.Popen" in findings[0].evidence


# (11) proto-4 MEMOIZE evasion: GLOBAL pushes os.system, MEMOIZE (\x94)
# stores it at memo index len(memo) == 0, POP drops the original, the args
# tuple is built, and BINGET fetches the callable back ON TOP of the args
# immediately before REDUCE. The callable must still be resolved through
# the memo and counted as invoked — regression test for the verified miss
# where this exact stream scored only PICKLE-DANGEROUS-GLOBAL (high).
def test_memoize_fetched_callable_reduce_is_critical():
    if os.path.exists("/tmp/zzz"):
        os.remove("/tmp/zzz")
    body = (b'cos\nsystem\n' + b'\x94' + b'0'
            + b'X\x0e\x00\x00\x00touch /tmp/zzz' + b'\x85' + b'h\x00' + b'R.')
    framed = b'\x80\x04\x95' + len(body).to_bytes(8, 'little') + body
    for payload in (framed, b'\x80\x04' + body):  # framed and unframed
        findings = inspect_pickle_bytes(payload, "memoize.pkl")
        assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
        assert findings[0].severity == "critical"
        assert "os.system" in findings[0].evidence
    assert not os.path.exists("/tmp/zzz"), "inspector EXECUTED the pickle"


# (12) same MEMOIZE shape, but the callable is fetched with LONG_BINGET
# ('j' + int32 LE index) instead of BINGET.
def test_memoize_long_binget_fetch_reduce_is_critical():
    body = (b'cos\nsystem\n' + b'\x94' + b'0'
            + b'X\x0e\x00\x00\x00touch /tmp/zzz' + b'\x85'
            + b'j\x00\x00\x00\x00' + b'R.')
    payload = b'\x80\x04\x95' + len(body).to_bytes(8, 'little') + body
    findings = inspect_pickle_bytes(payload, "memoize_long.pkl")
    assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
    assert findings[0].severity == "critical"
    assert "os.system" in findings[0].evidence


# (13) STACK_GLOBAL whose module and name strings are themselves fetched
# from the memo with BINGET: memoised "builtins" / "eval" strings are
# retrieved, STACK_GLOBAL assembles builtins.eval, and REDUCE invokes it.
def test_stack_global_strings_via_binget_eval_critical():
    payload = (
        b"\x80\x04"
        b"\x8c\x08builtins" b"q\x00" b"0"   # BINPUT 0: memo[0]="builtins"; POP
        b"\x8c\x04eval" b"q\x01" b"0"       # BINPUT 1: memo[1]="eval"; POP
        b"h\x00" b"h\x01"                   # BINGET 0, BINGET 1: the two strings
        b"\x93"                             # STACK_GLOBAL -> builtins.eval
        b"\x8c\x031+1"                      # arg
        b"\x85"                             # TUPLE1
        b"R"                                # REDUCE
        b"."
    )
    findings = inspect_pickle_bytes(payload, "sg_memo.pkl")
    assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
    assert findings[0].severity == "critical"
    assert "builtins.eval" in findings[0].evidence


# (14) memo index interleaving pins CPython's MEMOIZE semantics: MEMOIZE
# stores at len(memo) at execution time, NOT at max-key + 1. Here a BINPUT
# first stores a benign global at explicit index 5 (memo == {5: ...}), so
# the following MEMOIZE of os.system lands at index 1 — and BINGET 1 must
# retrieve os.system. An analyser that numbered MEMOIZE by next-free-slot
# above the highest explicit key would fetch the wrong slot and miss this.
def test_memoize_index_after_explicit_binput_is_len_of_memo():
    body = (
        b"ccollections\nOrderedDict\n" b"q\x05" b"0"  # BINPUT 5; POP
        b"cos\nsystem\n" b"\x94" b"0"                 # MEMOIZE -> memo[1]; POP
        b"h\x01"                                      # BINGET 1 -> os.system
        b"X\x0e\x00\x00\x00touch /tmp/zzz" b"\x85"     # arg, TUPLE1
        b"R."                                         # REDUCE, STOP
    )
    payload = b'\x80\x04\x95' + len(body).to_bytes(8, 'little') + body
    findings = inspect_pickle_bytes(payload, "memo_interleave.pkl")
    assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
    assert findings[0].severity == "critical"
    assert "os.system" in findings[0].evidence
    assert "OrderedDict" not in findings[0].evidence
