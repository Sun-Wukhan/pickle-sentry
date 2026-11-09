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
pip install pickle-sentry
```

For reproducible CI installs, pin the release:

```bash
pip install "pickle-sentry==0.2.0"
```

Zero dependencies. Python 3.9+.

## Use

```bash
pickle-sentry scan-path/                     # text report, exit 1 on high+
pickle-sentry . --format json --output report.json
pickle-sentry . --format sarif --output report.sarif   # for GitHub code scanning
pickle-sentry . --fail-on critical           # CI: only fail on critical
pickle-sentry . --exclude /tests/            # production surface only
```

### Scan a Hugging Face Hub repo (new in 0.2.0)

```bash
pickle-sentry hub stanfordnlp/imdb                          # a dataset
pickle-sentry hub hf-internal-testing/tiny-random-bert --repo-type model
pickle-sentry hub user/repo --max-size-mb 16 --format json
```

Lists the repo's files via the Hub API, downloads pickle-family files
(`.pkl`, `.pickle`, `.joblib`, `.pt`, `.pth`, and classic `pytorch_model.bin`)
and inspects them by disassembly — including the pickle stream inside torch
zip archives — and AST-scans any Python files in the repo. Files over the
size cap are flagged, not downloaded. Set `HF_TOKEN` for private repos.
Nothing downloaded is ever executed.

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
| `PICKLE-REDUCE-CALLABLE` | high | Pickle invokes a non-standard callable via `REDUCE` (the CVE PoC payload's shape) |
| `PICKLE-DANGEROUS-GLOBAL` / `PICKLE-SUSPICIOUS-MODULE` | high/medium | Dangerous globals referenced without a reduce |
| `PICKLE-FILE-PRESENT` | medium | Any other `.pkl` / `.pickle` / `.joblib` file, and pickle streams inside torch `.pt`/`.pth` zip archives |

## Real-life use case

[docs/USE-CASE.md](docs/USE-CASE.md) walks through a real one end to end:
scanning the **actual published CVE-2026-57845 PoC repository** before
touching it. pickle-sentry flags the vulnerable loader (`run_poc.py:139`,
critical) and disassembles the live payload (`attacker-controlled.pkl`,
high) — and the PoC's own `marker.txt` proves the payload never executed
during the scan.

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

## CI/CD

Call pickle-sentry as a pipeline gate in GitHub Actions, GitLab CI, Azure
Pipelines, Jenkins, or any runner with Python 3.9+:

```yaml
- uses: Sun-Wukhan/pickle-sentry@main
  with:
    path: .
    fail-on: high
```

Or call the PyPI package directly:

```bash
python -m pip install "pickle-sentry==0.2.0"
pickle-sentry . --fail-on high
```

Exit `0` means no finding reached the threshold; exit `1` fails the job;
exit `2` means the scan itself could not run. Full examples — including SARIF
upload to GitHub code scanning and Hub scans in a pipeline — are in
[docs/CI-CD.md](docs/CI-CD.md), with copy-ready files under
[examples/cicd](examples/cicd).

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
