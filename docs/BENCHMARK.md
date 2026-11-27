# Benchmark: pickle-sentry vs Picklescan, ModelScan, Fickling

Run 2026-11-26. Every scanner in static/check mode; no fixture was ever
loaded or executed by any tool or by us.

## Corpus

The malicious corpus is **not ours**: it is the test fixtures the other
scanners ship in their own public repositories, harvested file-for-file:

- `mmaitre314/picklescan` `tests/data` + `tests/data2` — 109 files,
  including their GHSA bypass regression set (labelled from filenames and
  the repo's own test expectations).
- `protectai/modelscan` `tests/data` — 1 malicious file
  (`unsafe_zip_pytorch.pt`); the rest of ModelScan's cases are generated
  by its test code and were not recreated.
- `trailofbits/fickling` `test/fixtures` — 1 benign file (a real
  TorchScript model). Fickling's malicious cases are likewise
  code-generated in its tests and were not recreated.

Benign corpus (24): the fixtures above labelled benign by their own
repos, plus locally generated sklearn (pickle + joblib), pandas, numpy
and plain-pickle artifacts, plus `pytorch_model.bin` from two small
Hugging Face repos (`hf-internal-testing/tiny-random-bert`,
`sshleifer/tiny-gpt2`). Three ambiguous files were excluded from scoring.

**Read the results with the corpus in mind: 96 malicious files, ~99% of
them Picklescan's own fixtures.** That is home turf for Picklescan — its
GHSA set is the regression corpus its blocklist was built against. The
point of choosing it anyway: nobody can accuse us of crafting cases that
flatter pickle-sentry, and every miss below is a miss on a case a
competitor published.

## Tools and verdict criteria (all default settings)

| Tool | Version | "Flagged" means |
|---|---|---|
| pickle-sentry | 0.4.0 | any finding of severity high or critical (JSON output) |
| Picklescan | 1.0.5 | `Infected files ≥ 1` in the CLI summary |
| ModelScan | 0.8.8 | ≥ 1 issue in the JSON report (`scan -r json`) |
| Fickling | 0.1.13 | `--check-safety` exit 1 ("may be unsafe") |

A file a tool does not claim to support counts as N/A where the tool
reports skipping it; a crash or parse failure counts as an error, never
as a miss.

## Results

| Tool | Malicious caught | Benign falsely flagged | Errors (mal / ben) | N/A (mal / ben) |
|---|---:|---:|---:|---:|
| Picklescan | **92 / 96** | 0 / 24 | 2 / 8 | 1 / 1 |
| Fickling | 86 / 96 | 8 / 24 | 10 / 12 | 0 / 0 |
| pickle-sentry | 71 / 96 | 5 / 24 | 0 / 0 | 0 / 0 |
| ModelScan | 29 / 96 | 0 / 24 | 0 / 0 | 14 / 11 |

Per-file verdicts: the run's raw results are reproducible from the
fixture sets above with the criteria in the table.

## What the numbers do and do not say

- **Picklescan leads on its own corpus**, as it should: the GHSA files
  exist because each one once bypassed it, and its blocklist now names
  them. Its weak spot in this run was operational: the CLI errored on
  every standalone `.npy`/`.npz` in the benign set (8 errors) — its unit
  tests call the numpy scanner directly, but the shipped CLI path
  failed on all of them.
- **Fickling caught everything it could parse** (86 flagged, 0 clean
  misses) but at a price: it also flagged 8 of 24 benign files,
  including plain numpy arrays and real PyTorch models, and errored on
  22 files in formats it does not parse. Its `--check-safety` mode is a
  conservative analysis verdict, not a CI gate.
- **ModelScan's scope is model files, not raw pickles**: it reported no
  issues for most standalone `.pkl` fixtures (53 of 96 malicious files
  came back clean, 14 more N/A). Within formats it targets it raised no
  false flags.
- **pickle-sentry never errored** and was the only tool to return a
  verdict on every file, but it missed 25 malicious files and flagged 5
  benign ones. Both failure modes are specific, and listed below.

## pickle-sentry's misses (25), categorised

1. **Standalone archive files passed directly (8)** — `malicious1.zip`,
   its flag-bit/central-directory/CRC/wrong-extension variants, and
   `malicious1.7z` produced *no findings at all*. The inspector peels
   archives inside torch files and Hub downloads, but a bare `.zip` or
   `.7z` handed to the CLI as a path is not routed to it. Known gap,
   fix planned.
2. **GHSA-class payloads abusing innocuous-looking globals (12)** —
   payloads built on globals such as `uuid`, OS-support modules and
   similar scored medium (`PICKLE-FILE-PRESENT`) only: the VM analysis
   resolves the invoked callable, but the callable itself is not one
   pickle-sentry classifies as dangerous. This is the same class that
   produced the GHSA bypasses against blocklist scanners; invocation
   analysis alone does not settle it.
3. **Other payload globals not classified dangerous (5)** —
   `bad_pytorch.pt`, `malicious6`, `malicious17`, `malicious22`,
   `sys_module_override_sploit.pkl`: medium only, same root cause as
   (2).

## pickle-sentry's false flags (5)

All five are one rule: `PICKLE-REDUCE-CALLABLE` (high) — a pickle that
invokes a non-allowlisted callable via REDUCE. That rule exists because
it is the exact shape of the published CVE-2026-57845 PoC payload
(custom callable, REDUCE-invoked), and it is deliberately strict. It
fires on benign pickles that serialise custom classes the same way:
a locally defined class, scikit-learn estimators (pickle and joblib),
a pandas DataFrame, and Fickling's benign TorchScript model. If your
models pickle only framework-standard classes, you will not see it; if
they pickle your own classes, expect this rule and judge the callable
yourself — the finding names it.

## Re-run after the 0.4.1 routing fix (2026-11-26)

0.4.1 fixed miss category 1 (standalone archives were never routed to
the inspector) and added `.bin` routing plus magic-byte sniffing for
files whose extension lies. Same corpus, same criteria, pickle-sentry
column only:

| pickle-sentry | Malicious caught | Benign falsely flagged |
|---|---:|---:|
| 0.4.0 | 71 / 96 | 5 / 24 |
| 0.4.1 | **75 / 96** | 5 / 24 |

Newly caught: `malicious1.zip` (critical), `malicious1_wrong_ext.zip`
(critical, via sniffing), `malicious1.7z` (high, opaque container), and
the GHSA-jgw4 `.bin` extension-disguise case (high). No regressions and
no new false flags. The five remaining zip variants (encrypted,
patched-data and strong-encryption flag tricks, tampered local header,
bad CRC) now produce a medium `PICKLE-FILE-PRESENT` finding instead of
silence — they are counted and reported, but the payload bytes cannot
be inflated by the Python standard library, so they stay below the
≥high catch criterion. Extracting them anyway would need a tolerant
raw zip reader; that is future work, recorded here rather than hidden.

## Reproducing

Clone the three repos at the versions above, copy their fixture files,
generate any benign model artifacts, and run each tool with the stated
criteria. Verdicts were spot-re-verified by hand against the recorded
results before publication.
