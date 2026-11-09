# Live examples — pickle-sentry against real codebases

Run on 9 Nov 2026 with pickle-sentry 0.1.0 against fresh shallow clones.
Numbers below are the tool's actual output, reproduced from the JSON reports.

## 1. huggingface/datasets @ a1269ca — the CVE's own repo

```bash
pickle-sentry /path/to/datasets --format json
```

- Python files scanned: **258**
- Findings: **24** (20 high, 4 info)
- Findings in production source (`src/`): **exactly 1**

That one production finding is the vulnerability itself:

```
[HIGH] PANDAS-READ-PICKLE  src/datasets/packaged_modules/pandas/pandas.py:56
    pa_table = pa.Table.from_pandas(pd.read_pickle(f))
    CVE: CVE-2026-57845
```

The other 19 high findings are all in `tests/` — test code unpickling its own
fixtures, which is expected and safe in context. Lesson built into the tool:
use `--exclude /tests/` when you only want the production surface:

```bash
pickle-sentry . --exclude /tests/ --exclude /benchmarks/
```

## 2. scikit-learn/scikit-learn @ a792a94

- Python files scanned: **1,037**
- Findings: **73** (all high, all `UNSAFE-DESERIALIZATION`)
- Findings outside tests/benchmarks: **16**, concentrated in one pattern —
  `sklearn/datasets/` loaders unpickling cached copies of remotely fetched
  datasets:

```
sklearn/datasets/_twenty_newsgroups.py:305, :549
sklearn/datasets/_rcv1.py:232, :233, :288, :289
sklearn/datasets/_covtype.py:215, :216
sklearn/datasets/_kddcup99.py:364, :365
sklearn/datasets/_california_housing.py:187
sklearn/datasets/_olivetti_faces.py:161
sklearn/datasets/_species_distributions.py:285
```

That pattern — *pickle cache of data that originally came from the network* —
is exactly the shape that turns a poisoned cache or mirror into code
execution. Whether each site is exploitable depends on its cache-integrity
checks; pickle-sentry's job is to make the sites findable in seconds so a
human can triage them.

## 3. Malicious vs benign pickle files

```python
import pickle, os
class Evil:
    def __reduce__(self): return (os.system, ("touch /tmp/canary",))
open("evil.pkl", "wb").write(pickle.dumps(Evil()))
open("benign.pkl", "wb").write(pickle.dumps({"rows": [1, 2, 3]}))
```

```
[CRITICAL] PICKLE-DANGEROUS-REDUCE  evil.pkl
    Pickle calls a dangerous callable via REDUCE (posix.system). Loading this
    file executes code. Treat as malicious unless you created it yourself.
[MEDIUM] PICKLE-FILE-PRESENT  benign.pkl
    Pickle file present. Pickle is code, not data: never load it from an
    untrusted source.
```

The canary file is never created: inspection is disassembly only.

## Honest limits

- This is a *finder*, not a proof of exploitability. Context decides: a
  `pickle.load` on a file the same process just wrote is routine; the same
  call on a downloaded file is a vulnerability. The scanner surfaces the
  sites, with severity and (where known) the CVE, and CI-friendly exit codes.
- AST scanning sees syntactic calls. Heavy indirection (`getattr(pickle, "lo"+"ad")`)
  will evade it — as it evades most static tools.
