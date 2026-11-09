import json
import os
import pickle

from pickle_sentry.cli import collect, main


def test_collect_examples_vulnerable_flags_cve():
    root = os.path.join(os.path.dirname(__file__), "..", "examples", "vulnerable")
    result = collect(os.path.normpath(root))
    ids = {f.rule_id for f in result.findings}
    assert "HF-DATASETS-PANDAS-BUILDER" in ids
    assert "UNSAFE-DESERIALIZATION" in ids
    assert "PANDAS-READ-PICKLE" in ids
    assert result.max_severity == "critical"


def test_collect_examples_safe_is_clean():
    root = os.path.join(os.path.dirname(__file__), "..", "examples", "safe")
    result = collect(os.path.normpath(root))
    assert not any(f.severity in ("high", "critical") for f in result.findings)


def test_cli_exit_codes_and_json(tmp_path, capsys):
    bad = tmp_path / "bad.py"
    bad.write_text('from datasets import load_dataset\nload_dataset("pandas", data_files="x.pkl")\n')
    assert main([str(tmp_path), "--format", "json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["max_severity"] == "critical"

    good = tmp_path / "bad.py"
    good.write_text("print('hello')\n")
    assert main([str(tmp_path), "--format", "json"]) == 0


def test_cli_report_only_mode_writes_sarif(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text('from datasets import load_dataset\nload_dataset("pandas", data_files="x.pkl")\n')
    report = tmp_path / "pickle-sentry.sarif"

    assert main([
        str(tmp_path),
        "--format", "sarif",
        "--output", str(report),
        "--fail-on", "none",
    ]) == 0
    data = json.loads(report.read_text())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"] == "HF-DATASETS-PANDAS-BUILDER"


def test_cli_inspects_pickle_files(tmp_path):
    class Evil:
        def __reduce__(self):
            return (os.system, ("echo pwned",))
    (tmp_path / "evil.pkl").write_bytes(pickle.dumps(Evil()))
    result = collect(str(tmp_path))
    assert result.pickle_files_inspected == 1
    assert result.max_severity == "critical"
