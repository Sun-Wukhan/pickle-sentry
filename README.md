# pickle-sentry

Scan code and dataset files for unsafe pickle deserialization — including the
Hugging Face `datasets` pandas builder RCE, **CVE-2026-57845** (CVSS 8.8).

Pickle is code, not data. Any file, checkpoint, or dataset that passes through
a pickle loader executes whatever its author put in it. `pickle-sentry` finds
those paths in your code, and inspects pickle files by *disassembly only* —
**it never executes the files it inspects** (its test suite proves this with a
canary payload).

## Why now

CVE-2026-57845 (published 23 Oct 2026): Hugging Face `datasets` through 5.1.0 —
the latest release — routes `load_dataset("pandas", data_files=...)` to
`pandas.read_pickle()`. A crafted pickle runs arbitrary Python with the
victim's privileges the moment the dataset loads. The upstream fix
(huggingface/datasets#8879) disables the pandas builder, but no patched
release exists yet. Until one ships, the mitigation is: find every place you
load pickle-backed data, and migrate to Parquet / CSV / JSON / Arrow.

## Install

```bash
pip install -e .
```

Zero dependencies. Python 3.9+.

## Use

```bash
pickle-sentry scan-path/                     # text report, exit 1 on high+
pickle-sentry . --format json --output report.json
pickle-sentry . --format sarif --output report.sarif   # for GitHub code scanning
pickle-sentry . --fail-on critical           # CI: only fail on critical
```

## What it catches

**In Python code (AST scan — parses, never imports your code):**

| Rule | Severity | What |
|---|---|---|
| `HF-DATASETS-PANDAS-BUILDER` | critical | `load_dataset("pandas", ...)` — CVE-2026-57845 |
| `UNSAFE-DESERIALIZATION` | high | `pickle.load/loads`, `dill`, `cloudpickle`, `marshal`, `shelve`, `joblib.load` |
| `PANDAS-READ-PICKLE` | high | `pandas.read_pickle(...)` |
| `TORCH-LOAD-WEIGHTS-ONLY-FALSE` | high | `torch.load(..., weights_only=False)` |
| `TORCH-LOAD-NO-WEIGHTS-ONLY` | medium | `torch.load(...)` with no explicit `weights_only=True` |
| `YAML-UNSAFE-LOAD` | medium | `yaml.load(...)` without a SafeLoader |
| `NUMPY-ALLOW-PICKLE` | high | `numpy.load(..., allow_pickle=True)` |

**In data files (disassembly via `pickletools`, never unpickled):**

| Rule | Severity | What |
|---|---|---|
| `PICKLE-DANGEROUS-REDUCE` | critical | Pickle calls `os.system`, `subprocess.*`, `eval`, `exec`, etc. via `REDUCE` |
| `PICKLE-DANGEROUS-GLOBAL` / `PICKLE-SUSPICIOUS-MODULE` | high/medium | Dangerous globals referenced without a reduce |
| `PICKLE-FILE-PRESENT` | medium | Any other `.pkl` / `.pickle` / `.joblib` file, and pickle streams inside torch `.pt`/`.pth` zip archives |

## Live examples

Scanned two real codebases on 9 Nov 2026 — full results, methodology, and
honest limits in [docs/LIVE-EXAMPLES.md](docs/LIVE-EXAMPLES.md):

- **huggingface/datasets**: 258 files, 24 findings — and exactly **one** in
  production source: the CVE sink itself, `pd.read_pickle(f)` at
  `packaged_modules/pandas/pandas.py:56`.
- **scikit-learn**: 1,037 files, 73 findings — 16 outside tests, concentrated
  in `sklearn/datasets/` loaders unpickling cached copies of remotely fetched
  datasets.

Also included: a composite **GitHub Action** (`action.yml`, use it as
`uses: Sun-Wukhan/pickle-sentry@main`) and a **pre-commit hook**
(`.pre-commit-hooks.yaml`). Use `--exclude /tests/` to cut test-fixture noise.

## Demo

```bash
pickle-sentry examples/vulnerable   # flags the CVE pattern + every sink, exit 1
pickle-sentry examples/safe         # clean, exit 0
pickle-sentry examples/hf-datasets-pandas.py
# ^ the actual upstream datasets pandas builder (verbatim from
#   huggingface/datasets main): flags pd.read_pickle(f) at line 56 —
#   the exact sink behind CVE-2026-57845.
```

## Migrate off pickle

- Datasets: `load_dataset("parquet" | "csv" | "json" | "arrow", ...)`
- Your own DataFrame: `Dataset.from_pandas(df)` instead of a pickle file
- DataFrames on disk: `df.to_parquet(...)` / `pd.read_parquet(...)`
- Torch: `torch.load(path, weights_only=True)`

## Tests

```bash
pip install pytest
pytest
```

The inspector tests build a real malicious pickle (`__reduce__` → `os.system`)
and assert two things: it is flagged critical, and the payload's canary file
**never appears** — i.e. inspection did not execute it.

## Licence

MIT
