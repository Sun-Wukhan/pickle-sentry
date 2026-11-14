# Coverage: what pickle-sentry has been shown to catch

This document records the evidence behind pickle-sentry's detection claims:
the method, a known-payload corpus with expected versus actual results, a
field scan of widely downloaded Hugging Face models, and the limits of what
any of it proves. Claims here are limited to what the cited tests and scans
actually ran.

## (a) Method

pickle-sentry never executes, imports, or unpickles the files it inspects.

- Python source is parsed with the `ast` module and matched against unsafe
  loader patterns. The scanned code is never imported.
- Pickle byte streams are analysed by abstract interpretation over
  `pickletools.genops`, a pure disassembler. A symbolic stack and memo track
  values through the stream, so the analysis resolves which callables a
  pickle actually invokes via REDUCE, NEWOBJ, NEWOBJ_EX, INST, and OBJ -
  including callables fetched from the memo at call time and invocations
  inside nested pickle streams embedded in bytes constants.
- Containers are peeled before analysis, depth-capped: gzip, bzip2, xz, and
  zlib wrappers; zip and tar archive members; torch zip checkpoints. 7-Zip
  archives cannot be read with the standard library and are flagged as
  opaque instead of being waved through.
- Non-pickle artifacts get format-native checks: NumPy `.npy` object-array
  payloads are handed to the pickle analysis, `.npz` members are checked
  per file, `.keras` configs are checked for Lambda layers, and
  `.safetensors` / `.gguf` headers are validated.

The never-executes property is proven, not just asserted: the test suite
builds real malicious pickles whose `__reduce__` would create a canary file
if executed, and asserts on every run that the canary never appears while
the payload is flagged critical.

Resource limits keep inspection bounded on hostile input (0.4.0). A stream
that exceeds the per-stream opcode ceiling (default 2,000,000) stops being
disassembled and is reported partial with `SCAN-OPCODE-LIMIT`. Archive
entries whose declared uncompressed size or compression ratio exceeds the
caps, and compression wrappers that inflate past the inflation cap, are not
inflated further and are reported with `SCAN-ARCHIVE-LIMIT`. Hub scans
additionally cap each downloaded file (default 64 MB, oversize files are
flagged and not downloaded) and the total bytes downloaded per repo
(default 512 MB; files past the budget are reported with
`HUB-PICKLE-SKIPPED-BUDGET`).

## (b) Known-payload corpus

Expected versus actual results. The in-repo rows are covered by the test
suite (`tests/test_inspector.py`, `tests/test_depth.py`,
`tests/test_hostile.py`, `tests/test_formats.py`) and run on every commit.

| Payload | Expected | Actual |
|---|---|---|
| Classic `__reduce__` returning `os.system` | `PICKLE-DANGEROUS-REDUCE`, critical; canary not created | Matches |
| Memo evasion: callable stored with BINPUT, fetched with BINGET at REDUCE time | `PICKLE-DANGEROUS-REDUCE`, critical | Matches |
| Proto-4 MEMOIZE evasion, callable fetched with BINGET or LONG_BINGET after the args tuple | `PICKLE-DANGEROUS-REDUCE`, critical | Matches |
| STACK_GLOBAL assembling `builtins.eval`, then REDUCE | `PICKLE-DANGEROUS-REDUCE`, critical | Matches |
| STACK_GLOBAL with module and name strings themselves fetched from the memo | `PICKLE-DANGEROUS-REDUCE`, critical | Matches |
| INST (protocol 0) instantiating `subprocess.Popen` | `PICKLE-DANGEROUS-REDUCE`, critical | Matches |
| REDUCE invoking a project-local function (the CVE-2026-57845 PoC shape) | `PICKLE-REDUCE-CALLABLE`, high | Matches |
| Dangerous global referenced but never invoked, alongside a benign invocation | `PICKLE-DANGEROUS-GLOBAL`, high; no critical, no invocation finding | Matches |
| Same payloads wrapped in gzip, bzip2, xz, or zlib | Peeled, then flagged critical with the wrapper noted in the path | Matches |
| Malicious pickle as a member of a zip or tar archive (torch checkpoint shape) | Flagged critical at the member path | Matches |
| Nested pickle (evil stream embedded as a bytes constant, within depth cap) | Invocation merged into the parent result, flagged critical | Matches |
| 7-Zip archive | `PICKLE-CONTAINER-OPAQUE`, high; contents not read | Matches |
| Benign torch-style stream (storage rebuilds, OrderedDict) | `PICKLE-FILE-PRESENT`, medium; nothing above medium | Matches |
| Ordinary data pickle (dicts, lists, strings) | `PICKLE-FILE-PRESENT`, medium | Matches |
| Empty or non-pickle bytes in a `.pkl` path | `PICKLE-UNPARSEABLE`, medium | Matches |
| Zip bomb: entry declaring 32 MB of zeros in about 32 KB compressed (about 1000:1) | Entry not inflated; `SCAN-ARCHIVE-LIMIT`, low; other members still inspected | Matches |
| Gzip bomb: 32 MB of zeros in about 33 KB, inflation cap set to 1 MB | Decompression stopped at the cap; `SCAN-ARCHIVE-LIMIT`, low; capped prefix still judged | Matches |
| Truncated pickle (valid header, partial opcode stream) | Parse findings returned, no exception | Matches |
| Opcode flood: 6,000 trivial opcodes against a 1,000-opcode ceiling | `SCAN-OPCODE-LIMIT`, low, result labelled partial; prefix still judged | Matches |
| Header liar: BINBYTES8 header claiming 2^50 bytes in a 9-byte stream | Parse findings returned, no exception, no large allocation | Matches |
| Self-referential (cyclic) list pickle; pickle wrapped in 12 layers of pickles; payload wrapped in 6 layers of gzip | Scan completes within seconds; findings returned; nothing executed | Matches |
| Hostile REDUCE payload as a zip member | `PICKLE-DANGEROUS-REDUCE`, critical; canary not created | Matches |

External payloads, scanned as published (see `docs/USE-CASE.md` and
`docs/EXISTING-PACKAGE-EXAMPLE.md`):

| Payload | Expected | Actual |
|---|---|---|
| Published CVE-2026-57845 PoC repository: loader script `run_poc.py` | `HF-DATASETS-PANDAS-BUILDER`, critical, at line 139 | Matches |
| Same repository: live payload `attacker-controlled.pkl` | `PICKLE-REDUCE-CALLABLE`, high; payload never executed (the PoC's own marker file proves it) | Matches |
| Published `datasets==5.1.0` wheel, scanned without installing it | `PANDAS-READ-PICKLE` at `pandas.py:56`, the CVE sink; pipeline exit code 1 | Matches |

## (c) Field coverage: the top 40 Hugging Face models

On 2026-11-14, pickle-sentry 0.3.1 in Hub mode scanned the 40 most
downloaded models on Hugging Face (ranking and download counts from the
Hub API on that date; about 875 million downloads per month combined).
Files were inspected by disassembly only and never executed.

Results:

- 26 of 40 models were fully scanned (about 694 million downloads per
  month combined). 14 models hit a 180-second per-model wall-clock limit
  used for the sweep and are reported as skipped, never as clean; the
  bottleneck was download time for large legacy checkpoints, not analysis
  time.
- 13 of the 26 scanned models still ship pickle-format weight files with
  live pickle streams; 78 pickle files were inspected in total. Most are
  legacy `pytorch_model.bin` files shipped alongside safetensors. One
  model (hexgrad/Kokoro-82M) ships pickle only: 55 pickle files.
- 13 of the 26 scanned models ship no pickle streams; 12 of those are
  safetensors-only (the rest are GGUF or CoreML distributions).
- 102 findings in total: 90 medium (`PICKLE-FILE-PRESENT`, standard
  PyTorch serialisation globals such as `collections.OrderedDict` and
  `torch._utils._rebuild_tensor_v2`) and 12 high
  (`PICKLE-REDUCE-CALLABLE`, all in Bingsu/adetailer).
- 0 dangerous invocations: a systematic check of every callable in every
  finding found no `os.system`, no `subprocess`, no `eval` or `exec`, no
  `__import__`, and no `popen` anywhere. The 12 high findings invoke only
  the Ultralytics framework's own model classes plus the builtins `set`
  and `getattr`, which is the normal anatomy of a full-object YOLO
  checkpoint: loading it constructs framework classes, but nothing found
  resembles a planted payload.
- Methodology notes: Hub mode downloads candidate files up to a 64 MB
  per-file cap and disassembles pickle streams, including streams nested
  inside torch zip archives. Several skipped models are known from their
  file lists to ship pickle weights too, so the share of the full top 40
  still shipping pickle is higher than the scanned subset shows.
  Truncated-stream findings are partial analyses and are labelled as such
  by the tool.

The field result is a prevalence measurement, not an accusation: pickle
remains common in widely downloaded weights, and in this sweep none of it
was a live payload.

## (d) Limits

What this scanner does not prove:

- A clean scan is not proof that an artifact is safe. The analysis is a
  heuristic over a disassembly; it covers the pickle VM constructs the
  abstract interpreter models and the formats listed above. Formats and
  loader paths outside that set (for example 7-Zip contents, or a `.keras`
  file's weights) are flagged as uninspected or checked only at the level
  documented, not silently passed.
- Partial results are labelled partial: truncated streams, streams stopped
  at the opcode ceiling, archive entries skipped for size or ratio,
  wrappers stopped at the inflation cap, Hub files skipped for size or
  budget, and models skipped in the field sweep. Treat any partial result
  as uninspected for the part that was not read.
- Detection is not provenance. The scanner says what a file would do if
  loaded, not who produced it or whether they were entitled to. Signing,
  hashes from a trusted channel, and publisher verification answer a
  different question and are not replaced by this tool.
- Inspection is not sandboxing. If a file must be loaded and its
  provenance is not established, load it in an isolated environment with
  least privilege; a scan reduces risk, it does not transfer it.
