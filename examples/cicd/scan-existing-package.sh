#!/usr/bin/env bash
# Scan an existing Python package in any CI system without installing that
# package into the environment. Usage:
#   bash scan-existing-package.sh 'datasets==5.1.0' high
set -euo pipefail

PACKAGE_SPEC="${1:-datasets==5.1.0}"
FAIL_ON="${2:-high}"

python -m pip install "pickle-sentry==0.2.0"

rm -rf package extracted
mkdir -p package extracted

python -m pip download --no-deps --dest package "${PACKAGE_SPEC}"

for archive in package/*; do
  case "${archive}" in
    *.whl|*.zip)
      python -m zipfile -e "${archive}" extracted
      ;;
    *.tar.gz)
      tar -xzf "${archive}" -C extracted
      ;;
    *)
      echo "Unsupported package archive: ${archive}" >&2
      exit 2
      ;;
  esac
done

pickle-sentry extracted \
  --format json \
  --output pickle-sentry-report.json \
  --fail-on "${FAIL_ON}"
