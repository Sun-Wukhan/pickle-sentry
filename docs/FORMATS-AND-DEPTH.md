# Formats and depth: how inspection works

pickle-sentry never executes, imports, or deserializes the files it
inspects. Everything below is static analysis. This document describes the
0.3.0 analysis engine, the container policy, and the limits of each check.

## The pickle VM analysis

A pickle is a program for a small stack machine. The old inspector read
the `pickletools` disassembly and noted which *globals* a stream mentioned
and whether a `REDUCE` opcode appeared anywhere — an approximation that
could both miss evasions and over-report.

The 0.3.0 inspector instead **abstractly interprets** the stream:

- It maintains a *symbolic stack*. Each slot is one of: a global reference
  (`module.name`), a string constant, a bytes constant, or "unknown".
- `GLOBAL` and `STACK_GLOBAL` push global references (STACK_GLOBAL pops
  two string constants and joins them).
- The memo is modelled: `PUT`/`BINPUT`/`LONG_BINPUT`/`MEMOIZE` store the
  stack top, and `GET`/`BINGET`/`LONG_BINGET` push the stored symbol back.
  A callable hidden in the memo and fetched at call time is still resolved.
- `REDUCE`, `NEWOBJ`, `NEWOBJ_EX`, `INST`, and `OBJ` record an
  **invocation** of the callable/class they apply — but only when the
  callable resolves to a global reference. Invocations of unresolvable
  values are counted but not attributed.
- Container-building opcodes (`MARK`, `TUPLE*`, `LIST*`, `DICT*`,
  `APPEND*`, `SETITEM*`, `POP`, `DUP`, `BUILD`, …) are approximated;
  unmodelled opcodes degrade the affected stack slots to "unknown".
  The analysis never raises: if disassembly fails mid-stream, everything
  collected so far is judged and the partial analysis is noted.

Judgement is then precise about the difference between *mentioning* and
*calling*:

| Situation | Rule | Severity |
|---|---|---|
| A dangerous callable (e.g. `os.system`, `subprocess.Popen`, `eval`) is invoked | `PICKLE-DANGEROUS-REDUCE` | critical |
| A non-standard, non-benign callable is invoked | `PICKLE-REDUCE-CALLABLE` | high |
| A dangerous callable is referenced but never invoked | `PICKLE-DANGEROUS-GLOBAL` | high |
| Globals come from OS-level modules (`os`, `subprocess`, …) | `PICKLE-SUSPICIOUS-MODULE` | high if anything is invoked, else medium |
| A parseable stream with no invocations of note | `PICKLE-FILE-PRESENT` | medium |
| A stream yielding zero valid opcodes | `PICKLE-UNPARSEABLE` | medium |

Well-known reconstruction helpers (`torch.*`, `numpy.*`, `collections.*`,
`copyreg.*`, …) are treated as benign *invocations* — reconstructing a
tensor or an OrderedDict is normal pickle mechanics.

**Nested pickles.** A bytes constant whose contents parse as a pickle
stream is itself analysed, recursively (depth cap 3), and its globals and
invocations are merged into the parent's, with the finding noting the
invocation occurred in a nested stream. Smuggling a payload as a pickled
bytes blob therefore does not hide it.

**Limits.** This is abstract interpretation, not decompilation: the
inspector does not reconstruct source code (that remains Fickling's
specialty), does not evaluate arguments, and cannot see callables assembled
at load time from pieces it cannot resolve (those invocations are counted
as unresolved, which lowers confidence but does not produce a named
finding). Pickle files remain code: a clean report is a strong signal, not
a proof of safety.

## Container policy

Before raw analysis, wrappers are peeled recursively (total depth cap 3).
Inner findings carry path suffixes: `model.pkl!gzip`,
`archive.tar!weights.pkl`, and so on.

| Wrapper | Detection | Handling |
|---|---|---|
| gzip | magic `1f 8b` | decompressed and analysed |
| bzip2 | `BZh` + digit | decompressed and analysed |
| xz / lzma | magic `fd 37 7a 58 5a 00` | decompressed (with `FORMAT_ALONE` fallback) |
| zlib | first byte `0x78`, verified by decompressing | decompressed; on failure the bytes are analysed raw, silently |
| zip (`PK\x03\x04`) | magic | every member whose name ends `.pkl` **or** whose bytes start with `\x80` is analysed (this covers torch checkpoints) |
| tar | `ustar` magic at offset 257 | same member rule |
| 7-Zip | magic `37 7a bc af 27 1c` | **flagged, not read** — see below |

A wrapper that fails to decompress falls back to analysing the raw bytes
(which normally yields `PICKLE-UNPARSEABLE`). A zip/tar with no
pickle-looking members yields `PICKLE-FILE-PRESENT`.

### Why 7z is flagged instead of read

The Python standard library cannot read 7-Zip archives, and pickle-sentry
has zero dependencies. Silently passing an archive it cannot see inside
would be worse than flagging it: opaque containers are the known evasion
route against Hub pickle scanners — the NullifAI bypass (Feb 2025) hid
malicious payloads inside 7z archives that Hugging Face's scanner did not
open. A 7z file therefore gets one `PICKLE-CONTAINER-OPAQUE` finding
(high) advising you to extract it and scan the contents.

## Format checks

### `.npy` — header parsed, object payloads analysed

The header (v1.0: uint16 length at offset 8; v2/v3: uint32) is a Python
dict literal and is parsed with `ast.literal_eval` only. If the dtype
describes object arrays (`|O`, or a structured field of object type), the
payload after the header is a pickle stream and goes through the full
pickle analysis at path `…!npy-payload`. A fixed-width array contains no
objects and gets `NPY-DATA-ARRAY` (info). An unparseable header gets
`NPY-UNPARSEABLE` (low).

### `.npz` — per-member `.npy`

An `.npz` is a zip of `.npy` members; each member gets the `.npy` check at
path `…!member-name`. Non-`.npy` members are ignored.

### `.keras` — config-level Lambda detection

A `.keras` file is a zip whose `config.json` describes the architecture.
The parsed JSON is walked recursively; every dict with
`"class_name": "Lambda"` yields `KERAS-LAMBDA-LAYER` (high), because
Keras Lambda layers deserialize Python bytecode (marshal) when the model
loads — the model *is* code. Any `.pkl` members inside the archive go
through the pickle analysis. With no Lambda layers the result is
`KERAS-ARCHITECTURE` (info). **Limit:** this is a config-level check only;
it does not inspect weights files inside the archive, and Lambda functions
referenced by registered names (rather than embedded bytecode) still
deserve a provenance check.

### `.safetensors` — header validation

The first 8 bytes are a uint64 header length; the JSON header maps tensor
names to `dtype`/`shape`/`data_offsets`. A conforming header yields
`SAFETENSORS-FORMAT` (info, with the tensor count) — the format is
data-only and cannot execute code on load, which is exactly why it is the
recommended pickle replacement. A non-conforming file yields
`SAFETENSORS-INVALID` (low). **Limit:** header-level only; tensor data is
not hashed or otherwise verified.

### `.gguf` — header validation

Magic `GGUF`, a uint32 version, and tensor/metadata counts (uint64 fields
for version ≥ 3, uint32 for versions 1–2) yield `GGUF-FORMAT` (info, with
version and counts). Truncated or implausible headers yield `GGUF-INVALID`
(low). **Limit:** header-level only; the metadata key/value section and
tensor payloads are not parsed.

## Hub mode

`pickle-sentry hub …` downloads and inspects `.npy`, `.npz`, `.keras`, and
`.gguf` files in addition to the pickle family, under the same per-file
size cap (`HUB-PICKLE-TOO-LARGE` above it). **`.safetensors` files are not
downloaded in Hub mode**: they are usually far too large to fetch for a
header check, and the format cannot execute code — run pickle-sentry
locally if you want the header verified.
