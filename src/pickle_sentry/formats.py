"""Inspect non-pickle ML artifact formats WITHOUT executing anything.

Checks are format-native and conservative:

- .npy/.npz: the header is parsed with ast.literal_eval only. An object
  array's payload *is* a pickle stream, so it is handed to the pickle
  analysis; a fixed-width data array contains no code at all.
- .keras: a zip whose config.json is parsed with json.loads. Lambda layers
  deserialize Python bytecode (marshal) at load time, so they are flagged;
  the check is config-level only.
- .safetensors/.gguf: header-level validation only. Both formats are
  data-only by design and cannot execute code on load.
"""
from __future__ import annotations

import ast
import io
import json
import os
import struct
import zipfile

from .inspector import inspect_pickle_bytes
from .model import Finding


# ---------------------------------------------------------------------------
# NumPy .npy / .npz

def _descr_is_object(descr) -> bool:
    """True if a numpy dtype descr denotes object arrays (pickled payload)."""
    if isinstance(descr, str):
        return descr.strip() in ("|O", "<O", ">O", "=O", "object")
    if isinstance(descr, (list, tuple)):
        # Structured dtype: [(name, format), ...] or [(name, format, shape), ...]
        for entry in descr:
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                if _descr_is_object(entry[1]):
                    return True
    return False


def _inspect_npy(data: bytes, path: str) -> list[Finding]:
    unparseable = Finding(
        "NPY-UNPARSEABLE", "low", path, None,
        "NumPy .npy file whose header could not be parsed; the file was not "
        "inspected further and should be treated as untrusted.")
    if len(data) < 10 or data[:6] != b"\x93NUMPY":
        return [unparseable]
    major = data[6]
    try:
        if major == 1:
            header_len = struct.unpack("<H", data[8:10])[0]
            header_start = 10
        else:  # v2.0 / v3.0 headers use a uint32 length
            header_len = struct.unpack("<I", data[8:12])[0]
            header_start = 12
        header_bytes = data[header_start:header_start + header_len]
        header = ast.literal_eval(header_bytes.decode("latin1").strip())
        descr = header["descr"]
        shape = header.get("shape")
    except Exception:
        return [unparseable]

    if _descr_is_object(descr):
        payload = data[header_start + header_len:]
        return inspect_pickle_bytes(payload, f"{path}!npy-payload")
    return [Finding(
        "NPY-DATA-ARRAY", "info", path, None,
        f"NumPy data array (dtype {descr!r}, shape {shape}): fixed-width data "
        "only — no object payload, nothing executable to inspect.")]


def _inspect_npz(data: bytes, path: str) -> list[Finding]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return [Finding(
            "NPY-UNPARSEABLE", "low", path, None,
            "NumPy .npz file that is not a readable zip archive; it was not "
            "inspected further and should be treated as untrusted.")]
    findings: list[Finding] = []
    with zf:
        for name in zf.namelist():
            if not name.lower().endswith(".npy"):
                continue
            try:
                member = zf.read(name)
            except Exception:
                continue
            findings.extend(_inspect_npy(member, f"{path}!{name}"))
    return findings


# ---------------------------------------------------------------------------
# Keras .keras

def _find_lambda_layers(node, trail: str, out: list) -> None:
    if isinstance(node, dict):
        if node.get("class_name") == "Lambda":
            config = node.get("config")
            name = config.get("name") if isinstance(config, dict) else None
            out.append((name, trail))
        for key, value in node.items():
            _find_lambda_layers(value, f"{trail}.{key}", out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _find_lambda_layers(value, f"{trail}[{index}]", out)


def _inspect_keras(data: bytes, path: str) -> list[Finding]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return [Finding(
            "KERAS-UNPARSEABLE", "low", path, None,
            "Keras .keras file that is not a readable zip archive; it was not "
            "inspected further and should be treated as untrusted.")]
    config = None
    config_error = False
    pickle_members: list = []
    with zf:
        names = zf.namelist()
        config_name = next((n for n in names
                            if n == "config.json" or n.endswith("/config.json")), None)
        if config_name is None:
            config_error = True
        else:
            try:
                config = json.loads(zf.read(config_name).decode("utf-8"))
            except Exception:
                config_error = True
        for name in names:
            if name.lower().endswith(".pkl"):
                try:
                    pickle_members.append((name, zf.read(name)))
                except Exception:
                    continue

    findings: list[Finding] = []
    lambdas: list = []
    if config is not None:
        _find_lambda_layers(config, "config", lambdas)
    for layer_name, trail in lambdas:
        evidence = layer_name if layer_name else trail
        findings.append(Finding(
            "KERAS-LAMBDA-LAYER", "high", path, None,
            "Keras Lambda layers deserialize Python bytecode (marshal) at load "
            "time — the model is code, trust it like code. "
            f"Lambda layer found at {trail}.",
            evidence=evidence))
    for name, member in pickle_members:
        findings.extend(inspect_pickle_bytes(member, f"{path}!{name}"))
    if config_error:
        findings.append(Finding(
            "KERAS-UNPARSEABLE", "low", path, None,
            "Keras .keras file with a missing or invalid config.json; the "
            "architecture could not be checked and the file should be treated "
            "as untrusted."))
    elif not lambdas:
        findings.append(Finding(
            "KERAS-ARCHITECTURE", "info", path, None,
            "Keras model whose config.json contains no Lambda layers "
            "(config-level check only; weights and any embedded pickle "
            "members are reported separately)."))
    return findings


# ---------------------------------------------------------------------------
# safetensors / GGUF (header-level checks; data-only formats)

def _inspect_safetensors(data: bytes, path: str) -> list[Finding]:
    invalid = Finding(
        "SAFETENSORS-INVALID", "low", path, None,
        "File with a .safetensors extension whose header is not a valid "
        "safetensors header; it does not conform to the data-only format it "
        "claims to be and should be treated as untrusted.")
    if len(data) < 8:
        return [invalid]
    header_len = struct.unpack("<Q", data[:8])[0]
    if not (0 < header_len <= 100_000_000) or len(data) < 8 + header_len:
        return [invalid]
    try:
        header = json.loads(data[8:8 + header_len].decode("utf-8"))
    except Exception:
        return [invalid]
    if not isinstance(header, dict):
        return [invalid]
    tensors = [k for k in header if k != "__metadata__"]
    for key in tensors:
        entry = header[key]
        if not isinstance(entry, dict) or not all(
                field in entry for field in ("dtype", "shape", "data_offsets")):
            return [invalid]
    return [Finding(
        "SAFETENSORS-FORMAT", "info", path, None,
        f"Valid safetensors file: data-only format ({len(tensors)} tensor(s)) "
        "that cannot execute code on load. This is the safe alternative to "
        "pickle-based checkpoints.",
        evidence=f"{len(tensors)} tensors")]


def _inspect_gguf(data: bytes, path: str) -> list[Finding]:
    invalid = Finding(
        "GGUF-INVALID", "low", path, None,
        "File with a .gguf extension whose header is truncated or invalid; "
        "it does not conform to the GGUF format it claims to be and should "
        "be treated as untrusted.")
    if len(data) < 24 or data[:4] != b"GGUF":
        return [invalid]
    version = struct.unpack("<I", data[4:8])[0]
    if version == 0 or version > 100:
        return [invalid]
    if version >= 3:
        tensor_count = struct.unpack("<Q", data[8:16])[0]
        kv_count = struct.unpack("<Q", data[16:24])[0]
    else:
        tensor_count = struct.unpack("<I", data[8:12])[0]
        kv_count = struct.unpack("<I", data[12:16])[0]
    return [Finding(
        "GGUF-FORMAT", "info", path, None,
        f"GGUF model file (version {version}): {tensor_count} tensor(s), "
        f"{kv_count} metadata entr(ies). Header-level check only; GGUF is a "
        "data-only format that does not execute code on load.",
        evidence=f"version {version}, {tensor_count} tensors, {kv_count} metadata entries")]


# ---------------------------------------------------------------------------

def inspect_artifact_bytes(data: bytes, path: str) -> list[Finding]:
    """Inspect a non-pickle model artifact by extension; never executes it."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".npy":
        return _inspect_npy(data, path)
    if ext == ".npz":
        return _inspect_npz(data, path)
    if ext == ".keras":
        return _inspect_keras(data, path)
    if ext == ".safetensors":
        return _inspect_safetensors(data, path)
    if ext == ".gguf":
        return _inspect_gguf(data, path)
    return []
