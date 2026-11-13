# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | ✓ |
| < 0.3 | ✗ |

## Reporting a vulnerability

pickle-sentry exists to find unsafe deserialization, so two kinds of reports
matter most:

1. **A bypass** — a pickle file, torch archive, or code pattern that executes
   code (or would execute code when loaded) but that pickle-sentry reports as
   clean or below the requested `--fail-on` threshold.
2. **A safety failure in the scanner itself** — any way to make pickle-sentry
   execute, import, or deserialize a file it is only supposed to inspect.
   Inspection is disassembly-only by design; a counterexample is a critical
   bug.

Report privately through GitHub's
[security advisory form](https://github.com/Sun-Wukhan/pickle-sentry/security/advisories/new)
("Report a vulnerability") so a fix can be prepared before disclosure. If
that is unavailable to you, open a public issue titled "Security report
request" *without* the payload details and a private channel will be
arranged.

Please include: the pickle-sentry version, the minimal reproducing file or
code snippet (as a disassembly listing or hex, not a live payload link), and
the output you expected versus what you got.

## Response expectations

- Acknowledgement within 7 days.
- Bypasses are treated as bugs in detection, fixed in the next patch release,
  with credit in the changelog unless you prefer otherwise.
- False positives are not vulnerabilities — please file those as regular
  issues.
