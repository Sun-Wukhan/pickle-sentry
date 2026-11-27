"""Standalone-archive routing: containers must be inspected, not skipped.

Regression tests for the gap found by the published benchmark
(docs/BENCHMARK.md, miss category 1): cli.collect() used to route only
.pickle-family and model-artifact extensions to the inspector, so a
standalone .zip / .7z / .tar / .gz / .bin file - passed directly or sitting
in a scanned directory - was silently skipped: not counted, no findings,
even though inspector.py already knows how to peel those containers.

Every fixture is generated programmatically in-test (no committed binary
blobs, no real malware). The canary fixture proves the hostile REDUCE
payload inside an archive is analysed, never executed.
"""
import gzip
import io
import os
import pickle
import tarfile
import zipfile

import pytest

from pickle_sentry.cli import collect

CANARY = "/tmp/pickle_sentry_archive_canary_must_not_exist"

_SEVEN_Z_MAGIC = b"7z\xbc\xaf'\x1c"


@pytest.fixture(autouse=True)
def clean_canary():
    if os.path.exists(CANARY):
        os.remove(CANARY)
    yield
    assert not os.path.exists(CANARY), "scanner EXECUTED the pickle - catastrophic failure"


class _Evil:
    def __reduce__(self):
        return (os.system, (f"touch {CANARY}",))


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _rule_ids(result):
    return {f.rule_id for f in result.findings}


# --- extension routing -------------------------------------------------------

def test_zip_with_dangerous_pickle_flagged_not_executed(tmp_path):
    (tmp_path / "weights.zip").write_bytes(
        _zip_bytes({"data.pkl": pickle.dumps(_Evil())}))
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    assert any(f.rule_id == "PICKLE-DANGEROUS-REDUCE" and f.severity == "critical"
               for f in result.findings)
    # The autouse canary fixture asserts the payload never ran.


def test_zip_with_benign_pickle_at_most_medium(tmp_path):
    (tmp_path / "weights.zip").write_bytes(
        _zip_bytes({"data.pkl": pickle.dumps({"a": 1})}))
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    assert result.findings
    assert not any(f.severity in ("high", "critical") for f in result.findings)


def test_standalone_7z_magic_flagged_opaque(tmp_path):
    # The inspector cannot read 7z with the standard library; the routing fix
    # must at least surface the opaque-container finding instead of silence.
    (tmp_path / "model.7z").write_bytes(_SEVEN_Z_MAGIC + b"\x00" * 64)
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    opaque = [f for f in result.findings if f.rule_id == "PICKLE-CONTAINER-OPAQUE"]
    assert len(opaque) == 1
    assert opaque[0].severity == "high"


def test_tar_with_dangerous_pickle_flagged(tmp_path):
    payload = pickle.dumps(_Evil())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("data.pkl")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    (tmp_path / "bundle.tar").write_bytes(buf.getvalue())
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    assert "PICKLE-DANGEROUS-REDUCE" in _rule_ids(result)


def test_tar_gz_with_dangerous_pickle_flagged(tmp_path):
    # splitext("x.tar.gz") is ".gz": the gzip peel must reach the tar inside.
    payload = pickle.dumps(_Evil())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("data.pkl")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    (tmp_path / "bundle.tar.gz").write_bytes(buf.getvalue())
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    assert "PICKLE-DANGEROUS-REDUCE" in _rule_ids(result)


def test_gz_wrapped_pickle_flagged(tmp_path):
    (tmp_path / "model.gz").write_bytes(gzip.compress(pickle.dumps(_Evil())))
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    assert "PICKLE-DANGEROUS-REDUCE" in _rule_ids(result)


def test_bin_with_plain_pickle_inspected(tmp_path):
    (tmp_path / "pytorch_model.bin").write_bytes(pickle.dumps(_Evil()))
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    assert result.max_severity == "critical"


def test_archive_passed_directly_as_file(tmp_path):
    target = tmp_path / "weights.zip"
    target.write_bytes(_zip_bytes({"data.pkl": pickle.dumps(_Evil())}))
    result = collect(str(target))
    assert result.pickle_files_inspected == 1
    assert result.max_severity == "critical"


# --- magic-byte sniffing for unrouted extensions ------------------------------

@pytest.mark.parametrize("name", ["weights.txt", "weights.model", "weights.data"])
def test_zip_bytes_behind_wrong_extension_inspected(tmp_path, name):
    (tmp_path / name).write_bytes(
        _zip_bytes({"data.pkl": pickle.dumps(_Evil())}))
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    assert result.max_severity == "critical"


def test_pickle_stream_behind_unknown_extension_inspected(tmp_path):
    (tmp_path / "weights.model").write_bytes(pickle.dumps(_Evil()))
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    assert result.max_severity == "critical"


def test_7z_magic_behind_unknown_extension_inspected(tmp_path):
    (tmp_path / "weights.blob").write_bytes(_SEVEN_Z_MAGIC + b"\x00" * 64)
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    assert "PICKLE-CONTAINER-OPAQUE" in _rule_ids(result)


# --- negatives: sniffing must not swallow ordinary files -----------------------

def test_plain_text_unknown_extension_not_inspected(tmp_path):
    (tmp_path / "notes.txt").write_text("release notes: nothing to see here\n")
    (tmp_path / "data.weird").write_text("plain text with a made-up extension\n")
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 0
    assert result.findings == []


def test_empty_file_unknown_extension_not_inspected(tmp_path):
    (tmp_path / "empty.blob").write_bytes(b"")
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 0
    assert result.findings == []
