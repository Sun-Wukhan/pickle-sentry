# Changelog

## 0.4.1 — 2026-11-26

Routing fix: standalone archives handed to the scanner are now actually
inspected. Found by the published benchmark (docs/BENCHMARK.md, miss
category 1), where 8 of Picklescan's malicious fixtures - a zip, six zip
variants and a 7z - received no findings at all because the CLI never
routed their extensions to the inspector that already knows how to peel
them.

- `cli.collect()` now routes `.zip`, `.tar`, `.tgz`, `.gz`, `.bz2`, `.xz`
  and `.7z` files to the inspector, and `.bin` joins the inspected set
  (torch/Hugging Face `.bin` files are pickle streams or torch zips; hub
  mode already inspected them). Routed archives count toward
  `pickle_files_inspected` like every other inspected file.
- Magic-byte sniffing for files whose extension routes nowhere: the first
  512 bytes are checked for zip, 7z, gzip, bzip2, xz and tar signatures
  and the pickle protocol marker, so a container hiding behind a wrong
  extension (the benchmark's `malicious1_wrong_ext` shape) is inspected
  instead of skipped.
- The inspector's zip detection also accepts the empty-archive signature
  (`PK\x05\x06`) alongside `PK\x03\x04`.
- 15 new routing tests (tests/test_archive_routing.py), all fixtures
  generated in-test, including a canary proving a hostile REDUCE payload
  inside a zip is flagged, never executed. 94 tests total.

## 0.4.0 — 2026-11-14

Hardening and coverage release: inspection is now explicitly bounded on
hostile input, and the detection evidence is written down.

- Explicit resource limits, each reported rather than silent:
  - Per-stream opcode ceiling in the pickle inspector (new `--max-opcodes`,
    default 2,000,000). A stream past the ceiling stops being disassembled
    and is reported partial with the new rule `SCAN-OPCODE-LIMIT` (low).
  - Archive inflation caps: zip/tar entries are judged by declared
    uncompressed size and compression ratio before inflation, every read is
    hard-capped, and compression wrappers (gzip/bzip2/xz/zlib) decompress
    through a capped streaming read. Skipped or capped content is reported
    with the new rule `SCAN-ARCHIVE-LIMIT` (low); a decompression bomb can
    no longer be materialised in memory. The same caps apply to `.npz` and
    `.keras` archives.
  - Hub mode total download budget (new `--max-total-mb`, default 512):
    files past the budget are reported with the new rule
    `HUB-PICKLE-SKIPPED-BUDGET` (low) instead of being downloaded, and the
    report counts them (`files_skipped_budget`).
- Hostile-input test corpus (`tests/test_hostile.py`, all fixtures
  generated in-test): zip bomb, gzip bomb, truncated pickle, opcode flood,
  self-referential and deeply nested graph bombs, lying length headers,
  plus a canary test that a hostile REDUCE payload is flagged, never
  executed. 79 tests total.
- New `docs/COVERAGE.md`: the method, a known-payload corpus with expected
  versus actual results (including the published CVE-2026-57845 PoC and
  the `datasets==5.1.0` wheel), a field scan of the top 40 Hugging Face
  models by downloads (26 fully scanned, 13 still shipping live pickle,
  102 findings, 0 dangerous invocations), and what the scanner does not
  prove.
- README gains a "What a clean scan does not mean" section: a clean result
  is heuristic evidence, not proof of safety, and complements rather than
  replaces provenance checks and sandboxing.

## 0.3.1 — 2026-11-13

Metadata-only release. No scanner behaviour changes.

- Adds PyPI trove classifiers (Python 3.9–3.13) to the package metadata
  so the Python versions badge renders correctly.
- GitHub Action default `version` input bumped to 0.3.1.
- README action examples pinned to `Sun-Wukhan/pickle-sentry@v0.3.1`.
- SECURITY.md supported versions corrected to 0.3.x.

## 0.3.0 — 2026-11-10

Depth and formats release: the pickle inspector is now an abstract
interpreter, and four non-pickle artifact formats are checked natively.

- VM-tracking pickle analysis: a symbolic stack over `pickletools`
  disassembly resolves which callables a pickle *actually invokes* via
  REDUCE / NEWOBJ / NEWOBJ_EX / INST / OBJ, tracking values through the
  memo (PUT/GET) and STACK_GLOBAL. This defeats the memo evasion (callable
  stored with BINPUT, fetched with BINGET at REDUCE time) and makes the
  invocation rules precise: a dangerous global that is merely referenced
  is reported as `PICKLE-DANGEROUS-GLOBAL`, never as an invocation.
- Nested pickles: pickle streams embedded in bytes constants are analysed
  recursively (depth-capped) and merged into the parent's findings.
- Container peeling before raw analysis (depth-capped): gzip, bzip2, xz,
  and zlib wrappers are decompressed; zip and tar members that look like
  pickle streams are inspected (extending the existing torch-zip
  behaviour). 7-Zip archives cannot be read with the standard library and
  are flagged `PICKLE-CONTAINER-OPAQUE` (high) — the opaque-container
  route used by the NullifAI Hub-scanner evasion.
- New rule `PICKLE-UNPARSEABLE` (medium) for streams that yield no valid
  opcodes; parseable benign pickles still get `PICKLE-FILE-PRESENT`.
- New formats: `.npy` object arrays have their pickle payload analysed
  (fixed-width arrays are info-level `NPY-DATA-ARRAY`); `.npz` members are
  checked per-file; `.keras` configs are checked for marshal-loading
  Lambda layers (`KERAS-LAMBDA-LAYER`, high); `.safetensors` and `.gguf`
  get header-level info checks (`SAFETENSORS-FORMAT`, `GGUF-FORMAT`).
- Hub mode now also downloads and inspects `.npy`, `.npz`, `.keras`, and
  `.gguf` files under the same size cap. `.safetensors` is not downloaded
  in Hub mode (too large for a header check).
- See `docs/FORMATS-AND-DEPTH.md` for how the analysis works and its
  limits. Zero dependencies, as always.

## 0.2.1 — 2026-11-10

Adoption and CI/CD release. No scanner-rule changes.

- GitHub Action hardened: installs the pinned PyPI release instead of an
  unpinned Git checkout; new inputs `output`, `exclude` (comma-separated),
  `version`, and `python-version`; Marketplace branding added.
- CI/CD guide (`docs/CI-CD.md`) with the exit-code contract (0 pass,
  1 threshold reached, 2 scan error) and copy-ready pipelines for GitHub
  Actions (including SARIF upload to code scanning), GitLab CI, Azure
  Pipelines, and Jenkins under `examples/cicd/`.
- Worked supply-chain example: a pipeline that downloads the existing
  `datasets==5.1.0` wheel without installing it, extracts it, and fails on
  the real CVE-2026-57845 sink (`docs/EXISTING-PACKAGE-EXAMPLE.md`).
- Demo (`docs/DEMO.md`, animated terminal in the README) and a README
  comparison table positioning pickle-sentry against model-file scanners.

## 0.2.0 — 2026-11-09

- Hugging Face Hub scanning: `pickle-sentry hub <user/repo>` for datasets,
  models, and spaces — downloads pickle-family files (64 MB cap), inspects
  them by disassembly including the pickle stream inside torch zip archives,
  and AST-scans repository Python files.
- New rule `PICKLE-REDUCE-CALLABLE` (high): pickle files that invoke
  non-standard callables via `REDUCE` — the shape of the published
  CVE-2026-57845 proof-of-concept payload.
- Real-life use case: scanning the published CVE PoC repository
  (`docs/USE-CASE.md`).

## 0.1.0 — 2026-11-09

- Initial release: AST code scan for unsafe deserialization (including the
  CVE-2026-57845 `load_dataset("pandas", ...)` rule) and pickle-file
  inspection by `pickletools` disassembly only — inspected files are never
  executed. Text, JSON, and SARIF output; GitHub Action and pre-commit hook.
