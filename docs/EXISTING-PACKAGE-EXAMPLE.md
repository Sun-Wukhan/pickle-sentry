# Worked CI example: scan an existing package

This example uses pickle-sentry as a supply-chain gate for a package that
already exists on PyPI. It does **not** install the target package and does
**not** import it. The pipeline downloads the package archive, extracts it,
and scans the extracted Python source.

The worked target is:

```text
datasets==5.1.0
```

That is the Hugging Face `datasets` release affected by CVE-2026-57845.

## Pipeline

Copy-ready GitHub Actions workflow:
[`examples/cicd/github-actions-scan-existing-package.yml`](../examples/cicd/github-actions-scan-existing-package.yml)

The workflow:

1. Installs the released scanner: `pickle-sentry==0.2.0`.
2. Downloads the target without its dependencies and without installing it:
   `pip download --no-deps datasets==5.1.0`.
3. Extracts the downloaded wheel.
4. Runs pickle-sentry and writes a JSON report.
5. Fails the job when a finding reaches `--fail-on high`.
6. Uploads the JSON report as a build artifact, including when the scan gate
   fails.

The same steps for GitLab CI, Azure Pipelines, Jenkins, or another CI runner
are in [`examples/cicd/scan-existing-package.sh`](../examples/cicd/scan-existing-package.sh).

## Commands

```bash
python -m pip install "pickle-sentry==0.2.0"
python -m pip download --no-deps --dest package "datasets==5.1.0"
python -m zipfile -e package/datasets-5.1.0-py3-none-any.whl extracted

pickle-sentry extracted \
  --format json \
  --output pickle-sentry-report.json \
  --fail-on high
```

## Observed result

Verified on 9 Nov 2026 with the pickle-sentry 0.2.0 package installed from
PyPI:

| Check | Result |
|---|---|
| Package downloaded | `datasets-5.1.0-py3-none-any.whl` |
| Python files scanned | 154 |
| Pickle files inspected | 0 |
| Findings | 1 |
| Maximum severity | high |
| Pipeline exit code | 1 — gate failed as designed |

The single finding was:

```text
[HIGH] PANDAS-READ-PICKLE
datasets/packaged_modules/pandas/pandas.py:56
pa_table = pa.Table.from_pandas(pd.read_pickle(f))
```

That is the exact sink behind CVE-2026-57845: the deprecated pandas packaged
builder passes a user-supplied file to `pandas.read_pickle()`. A crafted pickle
can therefore execute arbitrary code when a dataset is loaded through that
builder.

## How to adapt it

Change the workflow input or shell argument from `datasets==5.1.0` to another
package spec, for example:

```bash
bash scan-existing-package.sh 'some-package==1.2.3' high
```

Use `--fail-on none` for a report-only job, or keep `--fail-on high` when the
pipeline should stop a package from being promoted into an environment.
