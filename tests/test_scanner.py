from pickle_sentry.scanner import scan_python_source


def rules(src):
    return {f.rule_id: f for f in scan_python_source(src, "sample.py")}


def test_hf_datasets_pandas_builder_is_critical_cve():
    f = rules('from datasets import load_dataset\nload_dataset("pandas", data_files="x.pkl")\n')
    assert "HF-DATASETS-PANDAS-BUILDER" in f
    assert f["HF-DATASETS-PANDAS-BUILDER"].severity == "critical"
    assert f["HF-DATASETS-PANDAS-BUILDER"].cve == "CVE-2026-57845"
    assert f["HF-DATASETS-PANDAS-BUILDER"].line == 2


def test_parquet_builder_not_flagged():
    f = rules('from datasets import load_dataset\nload_dataset("parquet", data_files="x.parquet")\n')
    assert "HF-DATASETS-PANDAS-BUILDER" not in f


def test_pickle_load_and_aliases():
    assert "UNSAFE-DESERIALIZATION" in rules("import pickle\npickle.load(f)\n")
    assert "UNSAFE-DESERIALIZATION" in rules("import pickle as pk\npk.loads(b)\n")
    assert "UNSAFE-DESERIALIZATION" in rules("from pickle import load\nload(f)\n")
    assert "UNSAFE-DESERIALIZATION" in rules("import dill\ndill.load(f)\n")
    assert "UNSAFE-DESERIALIZATION" in rules("import joblib\njoblib.load('m')\n")


def test_read_pickle():
    f = rules("import pandas as pd\npd.read_pickle('x.pkl')\n")
    assert f["PANDAS-READ-PICKLE"].severity == "high"


def test_torch_load_variants():
    assert "TORCH-LOAD-NO-WEIGHTS-ONLY" in rules("import torch\ntorch.load('c.pt')\n")
    assert "TORCH-LOAD-WEIGHTS-ONLY-FALSE" in rules("import torch\ntorch.load('c.pt', weights_only=False)\n")
    safe = rules("import torch\ntorch.load('c.pt', weights_only=True)\n")
    assert not any(k.startswith("TORCH-LOAD") for k in safe)


def test_numpy_allow_pickle():
    assert "NUMPY-ALLOW-PICKLE" in rules("import numpy as np\nnp.load('x.npy', allow_pickle=True)\n")
    assert "NUMPY-ALLOW-PICKLE" not in rules("import numpy as np\nnp.load('x.npy')\n")
    assert "NUMPY-ALLOW-PICKLE" not in rules("import numpy as np\nnp.load('x.npy', allow_pickle=False)\n")


def test_yaml_load():
    assert "YAML-UNSAFE-LOAD" in rules("import yaml\nyaml.load(s)\n")
    assert "YAML-UNSAFE-LOAD" not in rules("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n")


def test_syntax_error_reported_not_raised():
    f = scan_python_source("def broken(:\n", "bad.py")
    assert f and f[0].rule_id == "PARSE-ERROR"
