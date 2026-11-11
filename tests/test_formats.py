"""Format tests: .npy/.npz object payloads, .keras Lambda layers,
safetensors and GGUF header checks — all fixtures hand-built with
struct/zipfile/json, no numpy/torch imports."""
import io
import json
import os
import pickle
import struct
import zipfile

from pickle_sentry.cli import collect
from pickle_sentry.formats import inspect_artifact_bytes
from pickle_sentry.hub import scan_hub_repo


class _Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


def _npy_bytes(descr: str, payload: bytes) -> bytes:
    header = "{'descr': %r, 'fortran_order': False, 'shape': (1,), }" % descr
    # numpy pads the header so header + preamble is a multiple of 64.
    total = 10 + len(header) + 1
    header += " " * ((64 - total % 64) % 64) + "\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header.encode("latin1") + payload


def _keras_bytes(config: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("model.weights.h5", b"\x89HDF\r\n")  # not inspected
    return buf.getvalue()


# --- .npy / .npz -----------------------------------------------------------

def test_npy_object_array_payload_is_analysed_as_pickle():
    data = _npy_bytes("|O", pickle.dumps(_Evil()))
    findings = inspect_artifact_bytes(data, "arr.npy")
    assert any(f.rule_id == "PICKLE-DANGEROUS-REDUCE" and f.severity == "critical"
               for f in findings)
    assert any("!npy-payload" in f.path for f in findings)


def test_npy_float32_array_is_info_only():
    data = _npy_bytes("<f4", struct.pack("<4f", 1.0, 2.0, 3.0, 4.0))
    findings = inspect_artifact_bytes(data, "arr.npy")
    assert len(findings) == 1
    assert findings[0].rule_id == "NPY-DATA-ARRAY"
    assert findings[0].severity == "info"


def test_npy_malformed_header_is_low():
    findings = inspect_artifact_bytes(b"\x93NUMPY\x01\x00\x05\x00abc", "bad.npy")
    assert findings[0].rule_id == "NPY-UNPARSEABLE"
    assert findings[0].severity == "low"


def test_npz_with_object_member_is_critical():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("evil.npy", _npy_bytes("|O", pickle.dumps(_Evil())))
        zf.writestr("plain.npy", _npy_bytes("<f4", struct.pack("<f", 1.0)))
        zf.writestr("readme.txt", "ignored")
    findings = inspect_artifact_bytes(buf.getvalue(), "data.npz")
    assert any(f.severity == "critical" and "!evil.npy" in f.path for f in findings)
    assert any(f.rule_id == "NPY-DATA-ARRAY" and "!plain.npy" in f.path for f in findings)


def test_npz_not_a_zip_is_low():
    findings = inspect_artifact_bytes(b"not a zip at all", "data.npz")
    assert findings[0].rule_id == "NPY-UNPARSEABLE"
    assert findings[0].severity == "low"


# --- .keras ----------------------------------------------------------------

def test_keras_lambda_layer_is_high():
    config = {
        "class_name": "Sequential",
        "config": {"name": "m", "layers": [
            {"class_name": "InputLayer", "config": {"name": "in"}},
            {"class_name": "Lambda",
             "config": {"name": "evil_lambda", "function": "marshal-bytes-here"}},
        ]},
    }
    findings = inspect_artifact_bytes(_keras_bytes(config), "model.keras")
    lam = [f for f in findings if f.rule_id == "KERAS-LAMBDA-LAYER"]
    assert len(lam) == 1
    assert lam[0].severity == "high"
    assert "evil_lambda" in lam[0].evidence


def test_keras_without_lambda_is_info():
    config = {"class_name": "Sequential",
              "config": {"layers": [{"class_name": "Dense", "config": {"name": "d"}}]}}
    findings = inspect_artifact_bytes(_keras_bytes(config), "model.keras")
    assert any(f.rule_id == "KERAS-ARCHITECTURE" and f.severity == "info"
               for f in findings)
    assert not any(f.severity in ("high", "critical") for f in findings)


def test_keras_missing_config_is_low():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("weights.bin", b"\x00" * 8)
    findings = inspect_artifact_bytes(buf.getvalue(), "model.keras")
    assert any(f.rule_id == "KERAS-UNPARSEABLE" and f.severity == "low"
               for f in findings)


# --- .safetensors ----------------------------------------------------------

def test_safetensors_valid_info_with_tensor_count():
    header = json.dumps({
        "w1": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
        "w2": {"dtype": "F32", "shape": [1], "data_offsets": [8, 12]},
        "__metadata__": {"format": "pt"},
    }).encode()
    data = struct.pack("<Q", len(header)) + header + b"\x00" * 12
    findings = inspect_artifact_bytes(data, "model.safetensors")
    assert len(findings) == 1
    assert findings[0].rule_id == "SAFETENSORS-FORMAT"
    assert findings[0].severity == "info"
    assert "2" in findings[0].evidence


def test_safetensors_invalid_is_low():
    findings = inspect_artifact_bytes(b"\xff\xff\xff\xff\x00\x00\x00\x00{}", "m.safetensors")
    assert findings[0].rule_id == "SAFETENSORS-INVALID"
    assert findings[0].severity == "low"


# --- .gguf -----------------------------------------------------------------

def test_gguf_v3_header_info_with_counts():
    data = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 5) + struct.pack("<Q", 7)
    assert len(data) == 24
    findings = inspect_artifact_bytes(data, "model.gguf")
    assert findings[0].rule_id == "GGUF-FORMAT"
    assert findings[0].severity == "info"
    assert "5" in findings[0].message and "7" in findings[0].message


def test_gguf_v2_header_info():
    data = (b"GGUF" + struct.pack("<I", 2) + struct.pack("<I", 3)
            + struct.pack("<I", 4) + b"\x00" * 8)
    findings = inspect_artifact_bytes(data, "model.gguf")
    assert findings[0].rule_id == "GGUF-FORMAT"
    assert "version 2" in findings[0].message


def test_gguf_truncated_is_low():
    findings = inspect_artifact_bytes(b"GGUF\x03", "model.gguf")
    assert findings[0].rule_id == "GGUF-INVALID"
    assert findings[0].severity == "low"


# --- integration: CLI collect + Hub ----------------------------------------

def test_collect_routes_artifact_files(tmp_path):
    (tmp_path / "model.gguf").write_bytes(
        b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 1) + struct.pack("<Q", 0))
    (tmp_path / "arr.npy").write_bytes(_npy_bytes("|O", pickle.dumps(_Evil())))
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 2
    assert result.max_severity == "critical"
    assert any(f.rule_id == "GGUF-FORMAT" for f in result.findings)


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


def test_hub_inspects_artifact_formats_but_not_safetensors():
    files = {
        "arr.npy": _npy_bytes("|O", pickle.dumps(_Evil())),
        "model.safetensors": struct.pack("<Q", 2) + b"{}",
    }
    result = scan_hub_repo("user/repo", fetch=_fake_fetch_factory(files))
    # .npy downloaded and its object payload flagged; .safetensors never
    # downloaded in hub mode (too large for a header check).
    assert result.pickle_files_inspected == 1
    assert any(f.severity == "critical" for f in result.findings)
    assert not any("safetensors" in f.path for f in result.findings)
