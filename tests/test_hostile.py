"""Hostile-input corpus: the scanner must stay bounded on adversarial files.

Every fixture is generated programmatically in-test (no committed binary
blobs, no real malware, nothing downloaded). Each test asserts the scan
completes quickly, raises nothing, and produces either the expected limit
finding or a parse finding - never a hang, a crash, or an unbounded
allocation. The canary fixture also proves the hostile REDUCE payload is
analysed, never executed.
"""
import gzip
import io
import json
import os
import pickle
import time
import zipfile

import pytest

from pickle_sentry.cli import main
from pickle_sentry.hub import scan_hub_repo
from pickle_sentry.inspector import InspectionLimits, inspect_pickle_bytes

CANARY = "/tmp/pickle_sentry_hostile_canary_must_not_exist"
TIME_BUDGET = 5.0  # seconds; every hostile scan must finish well inside this


@pytest.fixture(autouse=True)
def clean_canary():
    if os.path.exists(CANARY):
        os.remove(CANARY)
    yield
    assert not os.path.exists(CANARY), "inspector EXECUTED the pickle - catastrophic failure"


class _Evil:
    def __reduce__(self):
        return (os.system, (f"touch {CANARY}",))


def _timed_scan(data, path, limits=None):
    start = time.monotonic()
    if limits is None:
        findings = inspect_pickle_bytes(data, path)
    else:
        findings = inspect_pickle_bytes(data, path, limits)
    elapsed = time.monotonic() - start
    assert elapsed < TIME_BUDGET, f"scan of {path} took {elapsed:.2f}s"
    assert isinstance(findings, list) and findings
    return findings


def _rule_ids(findings):
    return {f.rule_id for f in findings}


# --- zip bomb: huge declared uncompressed size, tiny compressed payload ----

def test_zip_bomb_entry_skipped_by_ratio_others_still_inspected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 32 MB of zeros deflate to ~32 KB: a ~1000:1 ratio, far past the cap.
        zf.writestr("payload.pkl", b"\x00" * (32 * 1024 * 1024))
        zf.writestr("ok.pkl", pickle.dumps({"a": 1}))
    findings = _timed_scan(buf.getvalue(), "bomb.pt")
    limits_hit = [f for f in findings if f.rule_id == "SCAN-ARCHIVE-LIMIT"]
    assert len(limits_hit) == 1
    assert limits_hit[0].severity == "low"
    assert "payload.pkl" in limits_hit[0].evidence
    # The benign member next to the bomb is still inspected normally.
    assert any(f.rule_id == "PICKLE-FILE-PRESENT" and f.path.endswith("!ok.pkl")
               for f in findings)


def test_zip_entry_over_declared_size_cap_skipped():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("big.pkl", b"\x80\x04N." + b"\x00" * (2 * 1024 * 1024))
    limits = InspectionLimits(max_archive_entry_bytes=1024 * 1024)
    findings = _timed_scan(buf.getvalue(), "big.pt", limits)
    assert "SCAN-ARCHIVE-LIMIT" in _rule_ids(findings)


def test_npz_member_over_ratio_cap_skipped():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.npy", b"\x00" * (16 * 1024 * 1024))
    from pickle_sentry.inspector import inspect_bytes
    start = time.monotonic()
    findings = inspect_bytes(buf.getvalue(), "bomb.npz")
    assert time.monotonic() - start < TIME_BUDGET
    assert "SCAN-ARCHIVE-LIMIT" in _rule_ids(findings)


# --- gzip bomb through the compression peeling path -------------------------

def test_gzip_bomb_inflation_capped_and_labelled_partial():
    bomb = gzip.compress(b"\x00" * (32 * 1024 * 1024))
    assert len(bomb) < 1024 * 1024  # the whole bomb is a few dozen KB
    limits = InspectionLimits(max_inflated_bytes=1024 * 1024)
    findings = _timed_scan(bomb, "bomb.pkl", limits)
    limit = [f for f in findings if f.rule_id == "SCAN-ARCHIVE-LIMIT"]
    assert len(limit) == 1
    assert limit[0].severity == "low"
    assert "partial" in limit[0].message
    # The capped prefix is still judged (here: not a pickle at all).
    assert "PICKLE-UNPARSEABLE" in _rule_ids(findings)


def test_legit_gzip_payload_under_cap_unaffected():
    wrapped = gzip.compress(pickle.dumps(_Evil()))
    findings = _timed_scan(wrapped, "evil.pkl")
    assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
    assert "SCAN-ARCHIVE-LIMIT" not in _rule_ids(findings)


# --- truncated pickle --------------------------------------------------------

def test_truncated_pickle_returns_parse_findings():
    full = pickle.dumps({"rows": [[1, 2, 3], {"nested": "x" * 200}], "n": 42})
    for cut in (len(full) // 3, len(full) - 1):
        findings = _timed_scan(full[:cut], "trunc.pkl")
        assert _rule_ids(findings) <= {
            "PICKLE-FILE-PRESENT", "PICKLE-UNPARSEABLE",
            "PICKLE-DANGEROUS-REDUCE", "PICKLE-REDUCE-CALLABLE",
            "PICKLE-DANGEROUS-GLOBAL", "PICKLE-SUSPICIOUS-MODULE",
            "SCAN-OPCODE-LIMIT"}
        assert not any(f.severity == "critical" for f in findings)


# --- opcode flood -------------------------------------------------------------

def test_opcode_flood_hits_ceiling_and_is_labelled_partial():
    flood = b"\x80\x04" + b"N" * 6000 + b"."  # 6000 NONE opcodes
    limits = InspectionLimits(max_opcodes=1000)
    findings = _timed_scan(flood, "flood.pkl", limits)
    limit = [f for f in findings if f.rule_id == "SCAN-OPCODE-LIMIT"]
    assert len(limit) == 1
    assert limit[0].severity == "low"
    assert "partial" in limit[0].message
    # The partial prefix was still judged on its merits.
    assert "PICKLE-FILE-PRESENT" in _rule_ids(findings)


def test_opcode_flood_under_default_ceiling_is_clean_of_limit():
    flood = b"\x80\x04" + b"N" * 6000 + b"."
    findings = _timed_scan(flood, "flood.pkl")
    assert "SCAN-OPCODE-LIMIT" not in _rule_ids(findings)


def test_normal_files_unaffected_by_opcode_ceiling():
    findings = _timed_scan(pickle.dumps({"a": [1, 2, 3]}), "normal.pkl",
                           InspectionLimits(max_opcodes=1000))
    assert [f.rule_id for f in findings] == ["PICKLE-FILE-PRESENT"]


def test_cli_max_opcodes_flag_wires_through(tmp_path, capsys):
    (tmp_path / "flood.pkl").write_bytes(b"\x80\x04" + b"N" * 500 + b".")
    assert main([str(tmp_path), "--format", "json", "--max-opcodes", "50",
                 "--fail-on", "none"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert any(f["rule_id"] == "SCAN-OPCODE-LIMIT" for f in out["findings"])


# --- memo / graph bombs --------------------------------------------------------

def test_self_referential_graph_completes():
    cyclic = []
    cyclic.append(cyclic)
    findings = _timed_scan(pickle.dumps(cyclic), "cyclic.pkl")
    assert "PICKLE-FILE-PRESENT" in _rule_ids(findings)


def test_deeply_nested_pickle_wrapping_completes():
    # Each layer wraps the previous pickle as a bytes constant; the abstract
    # interpreter recurses into nested streams only to its depth cap, so the
    # evil core at depth 12 is never reached - and nothing hangs or crashes.
    data = pickle.dumps(_Evil())
    for _ in range(12):
        data = pickle.dumps(data)
    findings = _timed_scan(data, "nested.pkl")
    assert "PICKLE-FILE-PRESENT" in _rule_ids(findings)


def test_deeply_nested_gzip_wrapping_completes():
    # Peeling is depth-capped too: after the cap the still-wrapped remainder
    # is judged as raw bytes instead of being peeled forever.
    data = pickle.dumps(_Evil())
    for _ in range(6):
        data = gzip.compress(data)
    findings = _timed_scan(data, "wrapped.pkl")
    assert findings  # raw remainder judged, no exception


# --- header liar ----------------------------------------------------------------

def test_header_liar_binbytes8_claiming_huge_length():
    # BINBYTES8 header claims 2^50 bytes; the stream holds 4.
    payload = b"\x80\x04\x8e" + (1 << 50).to_bytes(8, "little") + b"tiny"
    findings = _timed_scan(payload, "liar.pkl")
    assert _rule_ids(findings) & {"PICKLE-FILE-PRESENT", "PICKLE-UNPARSEABLE"}


def test_header_liar_binbytes_claiming_max_length():
    # BINBYTES header claims ~4 billion bytes; the stream holds 3.
    payload = b"\x80\x03B\xff\xff\xff\xffabc"
    findings = _timed_scan(payload, "liar.pkl")
    assert _rule_ids(findings) & {"PICKLE-FILE-PRESENT", "PICKLE-UNPARSEABLE"}


# --- canary: hostile REDUCE payload is analysed, never executed -----------------

def test_hostile_reduce_in_zip_member_flagged_not_executed():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(_Evil()))
    findings = _timed_scan(buf.getvalue(), "model.pt")
    assert any(f.rule_id == "PICKLE-DANGEROUS-REDUCE" and f.severity == "critical"
               for f in findings)
    # The autouse canary fixture asserts the payload never ran.


def test_hostile_reduce_raw_flagged_not_executed():
    findings = _timed_scan(pickle.dumps(_Evil()), "evil.pkl")
    assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
    assert findings[0].severity == "critical"


# --- hub total download budget ----------------------------------------------------

def _fake_fetch_factory(files):
    def fetch(url):
        if "/api/" in url:
            siblings = [{"rfilename": n, "size": len(d)} for n, d in files.items()]
            return json.dumps({"siblings": siblings}).encode()
        for name, data in files.items():
            if url.endswith(name):
                return data
        raise KeyError(url)
    return fetch


def test_hub_budget_skips_remaining_files_with_notice():
    files = {"a.pkl": pickle.dumps({"x": 1}),
             "b.pkl": pickle.dumps({"y": 2}),
             "c.pkl": pickle.dumps({"z": 3})}
    budget = len(files["a.pkl"]) + 1  # room for exactly one download
    result = scan_hub_repo("user/repo", max_total_bytes=budget,
                           fetch=_fake_fetch_factory(files))
    assert result.files_skipped_budget == 2
    budget_findings = [f for f in result.findings
                       if f.rule_id == "HUB-PICKLE-SKIPPED-BUDGET"]
    assert len(budget_findings) == 2
    assert all(f.severity == "low" for f in budget_findings)
    assert "budget" in budget_findings[0].message
    # The file that fit the budget was still inspected.
    assert any(f.rule_id == "PICKLE-FILE-PRESENT" for f in result.findings)
    assert result.to_dict()["files_skipped_budget"] == 2


def test_hub_default_budget_inspects_everything():
    files = {"a.pkl": pickle.dumps({"x": 1}), "b.pkl": pickle.dumps({"y": 2})}
    result = scan_hub_repo("user/repo", fetch=_fake_fetch_factory(files))
    assert result.files_skipped_budget == 0
    assert not any(f.rule_id == "HUB-PICKLE-SKIPPED-BUDGET"
                   for f in result.findings)
