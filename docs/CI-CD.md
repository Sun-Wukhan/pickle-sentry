# Use pickle-sentry in CI/CD

`pickle-sentry` is designed to be a pipeline gate. Install the released package
from PyPI, point it at a checkout or artifact directory, and let its exit code
decide whether the job passes.

## Exit-code contract

| Exit code | Meaning |
|---:|---|
| `0` | No finding reached the selected `--fail-on` threshold |
| `1` | At least one finding reached the selected `--fail-on` threshold |
| `2` | The scan could not run, for example because the target path does not exist |

The default threshold is `high`. Use `--fail-on critical` for a narrower gate,
or `--fail-on none` when generating a report without failing that step.

Pin the version in real pipelines so a scan is reproducible:

```bash
python -m pip install "pickle-sentry==0.3.0"
pickle-sentry . --fail-on high
```

## Worked example — scan an existing package

To scan a third-party package before it is installed or promoted, download
its archive without installing it, extract it, and scan the extracted source:

```bash
python -m pip install "pickle-sentry==0.3.0"
python -m pip download --no-deps --dest package "datasets==5.1.0"
python -m zipfile -e package/datasets-5.1.0-py3-none-any.whl extracted
pickle-sentry extracted --format json \
  --output pickle-sentry-report.json --fail-on high
```

Verified result for `datasets==5.1.0`: 154 Python files scanned, exactly one
finding — `PANDAS-READ-PICKLE` at
`datasets/packaged_modules/pandas/pandas.py:56` — and exit code `1`, so the
pipeline gate fails. Full walkthrough:
[docs/EXISTING-PACKAGE-EXAMPLE.md](EXISTING-PACKAGE-EXAMPLE.md). Copy-ready
files are `examples/cicd/github-actions-scan-existing-package.yml` and
`examples/cicd/scan-existing-package.sh`.

## GitHub Actions — use the supplied Action

Add this as `.github/workflows/pickle-sentry.yml` in the repository you want to
protect:

```yaml
name: pickle-sentry

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  pickle-sentry:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for unsafe pickle deserialization
        uses: Sun-Wukhan/pickle-sentry@main
        with:
          path: .
          fail-on: high
          exclude: "/tests/,/fixtures/"
```

The Action installs `pickle-sentry` from PyPI rather than from an unpinned Git
checkout. Its inputs are:

| Input | Default | Purpose |
|---|---|---|
| `path` | `.` | File or directory to scan |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, or `none` |
| `format` | `text` | `text`, `json`, or `sarif` |
| `output` | empty | Write the report to this file |
| `exclude` | empty | Comma-separated path substrings to skip |
| `version` | `0.3.0` | PyPI version to install |
| `python-version` | `3.12` | Python version used by the Action |

### GitHub code scanning with SARIF

Generate a SARIF report, upload it even when the scan finds a problem, and let
the scan step's exit code fail the job:

```yaml
name: pickle-sentry

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  pickle-sentry:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan and create SARIF
        uses: Sun-Wukhan/pickle-sentry@main
        with:
          path: .
          fail-on: high
          format: sarif
          output: pickle-sentry.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pickle-sentry.sarif
```

## GitHub Actions — call the CLI directly

If you prefer not to use a third-party Action, install and call the PyPI
package in ordinary steps:

```yaml
name: pickle-sentry

on: [pull_request, push]

jobs:
  pickle-sentry:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install "pickle-sentry==0.3.0"
      - run: pickle-sentry . --fail-on high --exclude /tests/
```

## GitLab CI

```yaml
pickle-sentry:
  image: python:3.12-slim
  script:
    - python -m pip install "pickle-sentry==0.3.0"
    - pickle-sentry . --fail-on high --format json --output pickle-sentry.json
  artifacts:
    when: always
    paths:
      - pickle-sentry.json
```

## Azure Pipelines

```yaml
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.12"
  - script: |
      python -m pip install "pickle-sentry==0.3.0"
      pickle-sentry . --fail-on high
    displayName: "Run pickle-sentry"
```

## Jenkins and other CI systems

Any runner with Python 3.9 or newer can call the same executable:

```bash
python -m pip install "pickle-sentry==0.3.0"
pickle-sentry . --fail-on high
```

For a machine-readable build artifact:

```bash
pickle-sentry . \
  --format json \
  --output pickle-sentry.json \
  --fail-on high
```

## Scan a Hugging Face Hub dependency in a pipeline

Use Hub mode when the risk is an external dataset or model rather than files
already in the checkout. For example, run this as a scheduled job or before a
training job consumes the dependency:

```bash
python -m pip install "pickle-sentry==0.3.0"
pickle-sentry hub organisation/dataset-name --fail-on high
pickle-sentry hub organisation/model-name --repo-type model --fail-on high
```

Set `HF_TOKEN` in the CI secret store when scanning a private Hub repository.
Do not print the token or pass it as a command-line argument.

## Choosing what to scan

- Scan `.` to cover both source code and pickle-family artifacts in the
  checkout.
- Add exclusions only for paths whose findings have been reviewed, such as
  intentional malicious fixtures under `/tests/`.
- Do not exclude a directory merely to make the pipeline green. A finding means
  code or an artifact can execute arbitrary Python when loaded.
- For very large model artifacts in a checkout, remember that local files are
  inspected by disassembly and are never executed. Hub mode applies its
  per-file download cap and flags files above it instead of downloading them.
