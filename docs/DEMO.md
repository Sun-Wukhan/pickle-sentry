# Demo

Thirty seconds, three commands. Outputs below are real captures from
pickle-sentry 0.2.x, trimmed only for length.

## 1. A vulnerable project — the gate fails

```console
$ pickle-sentry examples/vulnerable
pickle-sentry scan: examples/vulnerable
  python files scanned: 1
  pickle files inspected (never executed): 0
  findings: 5 (max severity: critical)

[CRITICAL] HF-DATASETS-PANDAS-BUILDER  examples/vulnerable/app.py:8
    load_dataset("pandas", ...) routes files to pandas.read_pickle(). A crafted
    pickle executes code on load (CVE-2026-57845, CVSS 8.8; affects
    datasets <= 5.1.0, no patched release yet). Use parquet/csv/json/arrow,
    or Dataset.from_pandas() for your own DataFrame.
    CVE: CVE-2026-57845
[HIGH] UNSAFE-DESERIALIZATION  examples/vulnerable/app.py:12
    pickle.load(...) deserializes pickle-family data. Never call it on
    untrusted input — it is arbitrary code execution by design.
[HIGH] PANDAS-READ-PICKLE  examples/vulnerable/app.py:13
[HIGH] TORCH-LOAD-WEIGHTS-ONLY-FALSE  examples/vulnerable/app.py:17
[MEDIUM] TORCH-LOAD-NO-WEIGHTS-ONLY  examples/vulnerable/app.py:16

$ echo $?
1
```

## 2. A safe project — the gate passes

```console
$ pickle-sentry examples/safe
pickle-sentry scan: examples/safe
  python files scanned: 1
  pickle files inspected (never executed): 0
  findings: 0

No unsafe deserialization patterns found.

$ echo $?
0
```

## 3. A live Hugging Face model — inspected, never executed

```console
$ pickle-sentry hub hf-internal-testing/tiny-random-bert --repo-type model
pickle-sentry scan: hub://model/hf-internal-testing/tiny-random-bert@main
  python files scanned: 0
  pickle files inspected (never executed): 1
  findings: 1 (max severity: medium)

[MEDIUM] PICKLE-FILE-PRESENT  hub://model/hf-internal-testing/tiny-random-bert@main/pytorch_model.bin!archive/data.pkl
    Pickle file present. Pickle is code, not data: never load it from an
    untrusted source. Globals seen: collections.OrderedDict,
    torch.FloatStorage, torch.LongStorage, torch._utils._rebuild_tensor_v2

$ echo $?
0
```

The model is a benign test checkpoint, so the scan reports the pickle's
presence and the (ordinary PyTorch) globals it references — medium, below the
default `high` failure threshold. A payload calling `os.system` or an unknown
callable would come back critical/high and fail the gate.

## Try it on something real

```bash
pip install pickle-sentry
pickle-sentry hub <user>/<dataset-or-model> [--repo-type model]
# or scan a package before installing it — see docs/EXISTING-PACKAGE-EXAMPLE.md
```
