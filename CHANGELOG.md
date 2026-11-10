# Changelog

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
