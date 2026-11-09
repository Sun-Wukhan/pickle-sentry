# Real-life use case: reproducing a public CVE PoC without getting owned by it

**The situation.** On 9 Nov 2026 a working proof-of-concept for
CVE-2026-57845 (the Hugging Face `datasets` pandas-builder pickle RCE) was
published. You want to study it — clone the researcher's repo, read the code,
maybe write it up. The repo contains a live malicious pickle,
`attacker-controlled.pkl`, whose entire purpose is to execute code when a
victim loads it through `load_dataset("pandas", ...)`. Cloning is safe;
*running anything* is the dangerous part. So: scan first, run never (or only
in a disposable VM, deliberately).

Everything below is real output from 9 Nov 2026, against the actual PoC
repository (`SaiTeja-Erukude/CVE-2026-57845-hf-datasets-rce` @ `51e8cd4`).

## Step 1 — scan the cloned repo before opening the runner

```bash
git clone https://github.com/SaiTeja-Erukude/CVE-2026-57845-hf-datasets-rce
pickle-sentry CVE-2026-57845-hf-datasets-rce
```

```
[CRITICAL] HF-DATASETS-PANDAS-BUILDER  run_poc.py:139
    load_dataset("pandas", ...) routes files to pandas.read_pickle().
    A crafted pickle executes code on load (CVE-2026-57845, CVSS 8.8;
    affects datasets <= 5.1.0, no patched release yet).
    CVE: CVE-2026-57845

[HIGH] PICKLE-REDUCE-CALLABLE  attacker-controlled.pkl
    Pickle invokes non-standard callable(s) via REDUCE
    (__main__._write_marker_and_return_dataframe). Loading it runs that
    code — this is the shape of the CVE-2026-57845 PoC payload.
    CVE: CVE-2026-57845
```

Two findings tell the whole story without executing anything:

- The **loader** (`run_poc.py:139`) is the vulnerable call pattern itself.
- The **payload** (`attacker-controlled.pkl`) is disassembled, not loaded:
  its pickle calls a function `_write_marker_and_return_dataframe` via
  `REDUCE`. In the researcher's design that function writes `marker.txt` as
  proof of execution and returns a valid DataFrame so the load "succeeds".

**Proof the scan did not trigger it:** the repo's committed `marker.txt`
hash was identical before and after the scan, and no new marker appeared in
the working directory. Disassembly is not execution.

## Step 2 — decide what is safe to do

- ✅ Read `run_poc.py`, the README, `fix.md`, and the evidence files.
- ✅ Quote the scanner output in a write-up or advisory.
- ❌ `python run_poc.py` on your real machine — that *is* the exploit firing,
  harmless here (a marker file) only because this researcher is honest.
  The same shape from a stranger is a shell, not a marker.

## Step 3 — the everyday version: before you load a Hub model or dataset

```bash
pickle-sentry hub hf-internal-testing/tiny-random-bert --repo-type model
pickle-sentry hub stanfordnlp/imdb
```

The first inspects the pickle stream inside `pytorch_model.bin` and reports
the (benign) torch storage globals; the second finds no pickle files at all.
Run it *before* the `from_pretrained` / `load_dataset` cell in your notebook,
not after.

## Step 4 — make it permanent: gate your own project

```yaml
# GitHub Actions — fails the build on high+ findings
- uses: Sun-Wukhan/pickle-sentry@main
  with:
    path: .
    fail-on: high
```

or as a pre-commit hook (see `.pre-commit-hooks.yaml` in this repo). The
scanner exits 1 when a finding meets the threshold, so a teammate adding
`load_dataset("pandas", ...)` or committing a `.pkl` gets stopped in review —
which is the whole point: the CVE has no patched release yet, so the defence
is not loading the thing in the first place.
