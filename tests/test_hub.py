import json
import os
import pickle

from pickle_sentry.hub import scan_hub_repo


class Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


def fake_fetch_factory(files):
    """files: {filename: bytes}; serves Hub API info + resolve downloads."""
    def fetch(url):
        if "/api/" in url:
            siblings = [{"rfilename": name, "size": len(data)} for name, data in files.items()]
            return json.dumps({"siblings": siblings}).encode()
        for name, data in files.items():
            if url.endswith(name):
                return data
        raise KeyError(url)
    return fetch


def test_hub_flags_evil_pickle_critical():
    files = {"data/train.pkl": pickle.dumps(Evil()), "README.md": b"hi"}
    result = scan_hub_repo("user/evil", fetch=fake_fetch_factory(files))
    assert result.pickle_files_inspected == 1
    assert any(f.rule_id == "PICKLE-DANGEROUS-REDUCE" and f.severity == "critical"
               for f in result.findings)


def test_hub_scans_python_scripts():
    files = {"load.py": b"import pickle\npickle.load(open('x','rb'))\n",
             "data.parquet": b"PAR1"}
    result = scan_hub_repo("user/code", fetch=fake_fetch_factory(files))
    assert result.files_scanned == 1
    assert any(f.rule_id == "UNSAFE-DESERIALIZATION" for f in result.findings)
    assert not any("parquet" in f.path for f in result.findings)


def test_hub_oversize_pickle_skipped_with_finding():
    files = {"big.pkl": b"x" * 10}
    result = scan_hub_repo("user/big", max_bytes=5, fetch=fake_fetch_factory(files))
    assert any(f.rule_id == "HUB-PICKLE-TOO-LARGE" for f in result.findings)


def test_hub_model_bin_treated_as_pickle():
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(Evil()))
    files = {"pytorch_model.bin": buf.getvalue()}
    result = scan_hub_repo("user/model", repo_type="model", fetch=fake_fetch_factory(files))
    # pytorch_model.bin is a zip holding data.pkl: the inspector opens the zip
    # layer and flags the evil pickle inside as critical.
    assert result.pickle_files_inspected == 1
    assert any(f.severity == "critical" for f in result.findings)
