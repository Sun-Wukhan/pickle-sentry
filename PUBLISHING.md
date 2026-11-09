# Publishing pickle-sentry to PyPI

Status (9 Nov 2026): the distribution name `pickle-sentry` is **available**
on PyPI (checked: 404). Version 0.2.0 builds cleanly and passes `twine check`
(sdist + wheel); the wheel was install-tested in a clean venv
(`pickle-sentry --version` → 0.2.0, demo scan works).

Publishing uses **Trusted Publishing** (OIDC) — no API token is stored
anywhere. One-time setup is the only step that needs the project owner:

## One-time setup (owner, ~2 minutes)

1. Sign in to [pypi.org](https://pypi.org) (create the account and enable 2FA
   if you have not already).
2. Go to **Publishing → Add a pending publisher** ("Your projects" →
   Publishing, or https://pypi.org/manage/account/publishing/).
3. Enter exactly:
   - **PyPI project name:** `pickle-sentry`
   - **Owner:** `Sun-Wukhan`
   - **Repository:** `pickle-sentry`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `pypi`
4. Save. Nothing else is needed — no secrets go into GitHub.

## Every release after that

Create a GitHub Release from the version tag (or run the
**Publish to PyPI** workflow manually from the Actions tab).
`.github/workflows/publish.yml` builds the sdist/wheel and publishes them
via OIDC. Bump `version` in `pyproject.toml` and `__version__` first —
PyPI never accepts the same version twice.

## Local build (already verified for 0.2.0)

```bash
pip install build twine
python -m build
twine check dist/*
```
