# 0054 — Low-allocation built-ins HL7 parser (free-threading keystone)

- **Status:** **Accepted** (2026-06-29) — build started on `feat/builtins-hl7-parser` (BACKLOG #88)
- **Date:** 2026-06-29
- **Related:** [0053](0053-free-threaded-multicore-engine.md) (free-threaded engine — this parser is its
  gating keystone) · [0040](0040-free-threaded-engine-support.md) (the deferral 0053 superseded) ·
  [0052](0052-enterprise-scale-target.md) (the scale target) · BACKLOG #88 ·
  [CLAUDE.md](../../CLAUDE.md) §8 (HL7 conventions — two-tier parsing) · the surface this replaces:
  [`parsing/peek.py`](../../messagefoundry/parsing/peek.py),
  [`parsing/message.py`](../../messagefoundry/parsing/message.py),
  [`parsing/validate.py`](../../messagefoundry/parsing/validate.py),
  [`parsing/tree.py`](../../messagefoundry/parsing/tree.py)

---

## Context

The tolerant hot-path parser is **python-hl7**, which represents a message as a tree of small **class
instances** (`Message[Segment[Field[Repetition[Component]]]]`). ADR 0053's Phase-1 spike (WS3) measured that
representation as the **multi-core-scaling bottleneck** under free-threading (cp314t): per-instance reference
counting + shared type-object access serialize across threads. It is **not** allocation in general (pure
dict/list/str allocation scales 5.7–7.6×) and **not** GC.

**WS3 measured evidence** (synthetic HL7 corpus, 265KF, 8 P-cores, cp314t):

| representation | single-thread | multi-core S(8) |
|---|---|---|
| **built-ins (dict/list/str)** | **~158k msg/s (~14×)** | **6.44×** |
| python-hl7 (today) | ~11k msg/s (1× baseline) | **2.02×** (free-threading ceiling) |
| hl7apy (strict path) | ~46× *slower* | 2.04× (worse on both axes) |

So ADR 0053's free-threaded scale path — and the ADR 0052 enterprise target it serves — **cannot pay off
until the tolerant hot-path parser stops contending.** This parser is that keystone (BACKLOG #88). It is
*also* the single highest-leverage perf item regardless of free-threading: the ~14× single-thread win lifts
the single-process and [ADR 0037](0037-multi-process-sharding-l3.md) sharded paths too.

This change owns the **tolerant peek tier only** (the "python-hl7 half" of two-tier parsing); the opt-in
hl7apy strict tier is untouched. [CLAUDE.md](../../CLAUDE.md) §8 invariants in play, **verbatim**:

> **Two-tier parsing, by design:** **python-hl7** does fast, tolerant field *peek* on the hot path
> (routing/filtering); **hl7apy** does version-aware validation, **opt-in per inbound connection**
> (`validation.strict`) — it's the slow path, kept off routing. Don't route everything through the hl7apy
> object model.

> **Read encoding characters from MSH** (field/component/repetition/escape/subcomponent); don't hardcode
> `|^~\&`.

> **Parse defensively** — real-world HL7 is frequently non-conformant. Route parse/validation failures to
> the error/dead-letter path (logged as `ERROR`); never crash the connection.

> **Never mutate raw HL7 with string slicing.** Work via the parsed model and re-encode.

These bound the design: the new parser must read all five separators from **MSH-1/MSH-2**; keep
`Peek.parse` raising `HL7PeekError` only on no-MSH/empty/unparseable (→ ERROR/dead-letter, the count-and-log
invariant); and back every mutation with model-edit-then-re-encode, never string slicing. The §2 reliability
invariant (pure routers/transforms) is what makes free-threading the prize; this parser is the enabler, not
a change to that invariant.

## Decision

**Replace python-hl7 as the tolerant-tier backing of the *existing* `Peek` and `Message` API with a
low-allocation parser over native `dict`/`list`/`str`, as a behaviour-identical drop-in** — public API and
semantics unchanged; only the in-memory representation changes.

**Data model.** A parsed message is a plain built-in structure with **no per-node custom classes**:

```
ParsedMessage = {
  "segments": [ {"id": str, "fields": list[str | dict]}, ... ],
  "raw": str,
  "seps": (field, component, repetition, subcomponent, escape),
}
```

A field entry is the **raw repetition text (`str`)** until first componentized access; on first
component/subcomponent read it is split on the message's own separators and the breakdown cached in the
entry (`dict`). Component-less fields stay bare strings (branch on "rep is `str`" vs "rep is `dict`" — the
same branch python-hl7 makes today). Writes rebuild the field text at string level (split → edit leaf →
escape → join), update the entry, and mark the message dirty for a lazy `encode()`. **No node shares a
class/type object with another message** — exactly what removes the cross-thread contention WS3 measured.

**Eager vs lazy.** **MSH is parsed eagerly** (MSH-1/MSH-2 are needed to split any other segment and to
route); **all other segments are stored as raw text and split lazily on first field-path touch, then
cached.** A 1k-OBX batch routed on MSH-9 never pays to split OBX-5. Reads unescape only the leaf being read.
`encode()` rebuilds raw by joining on the actual separators **only when dirty**, else returns cached raw.
MSH offset stays hidden as today (`MSH.field(1)='|'`, `MSH.field(2)='^~\&'` returned raw/unescaped,
`MSH.field(3)` is the first real field).

**Drop-in backing.** `Peek.parse()` returns `Peek(message=<dict>, raw=<str>)` — same construction surface;
the `.message` attribute type changes from `hl7.Message` to the dict, but no consumer reaches into
`.message.*` (they call `.field()` and the routing properties, which resolve over the dict). `Message` wraps
the same dict and keeps every read/write/encode method and exact semantics. `parse_path`, `normalize`,
`enforce_size_limits`, the DoS caps, `HL7PeekError`, `TreeNode`/`parse_tree`, and `SegmentGroup` all stay;
group ops delegate to `Message` primitives unchanged. **Strict tier untouched:** `validate()` keeps building
an hl7apy tree; the two trees stay disjoint, sharing only `normalize()` + MSH separator extraction.
`RawMessage` (ADR 0004) is a separate type and is not involved.

## Preserved contract (must not change)

- `Peek.parse(raw, *, max_bytes, max_segments) -> Peek`: normalize → enforce size limits → require MSH →
  `HL7PeekError` on empty/no-MSH/unparseable. `HL7PeekError` subclasses `ValueError`; `parse_path` raises
  `HL7PeekError` (not bare `ValueError`) on a malformed path; caps `DEFAULT_MAX_MESSAGE_BYTES=16 MiB`,
  `DEFAULT_MAX_SEGMENTS=10000` (segments = `\r` count + 1, pre-parse).
- `Peek.field(path)`: first segment occurrence, first repetition; a **whole-field** read returns structural
  text *with* repetition delimiters; a component/subcomponent read returns the **unescaped** leaf; `''` → `None`.
- **The whole-value rule:** a field with no component separator returns the whole value, not its first
  character (`ORC-2.1` of `PLACER123` → `PLACER123`, not `P`).
- **Out-of-range asymmetry:** a valid-structure over-index returns `''`→`None`; an invalid-depth index
  (`.C2` on a non-composite, `.S2` with no Component level) raises `IndexError`, surfaced as `None` at the
  Peek layer.
- **MSH-1 / MSH-2 returned raw and unescaped** — never unescape them.
- All `Peek` routing properties + `routing()` dict keys + `segments()`; `normalize(...)` (`\r\n`/`\n`→`\r`,
  tolerant default, engine inbound passes `errors='strict'`).
- `Message`: `parse` / `field(occurrence, repetition)` / `__getitem__` / `set` / `__setitem__` /
  `repetitions` (returns a **list**) / `add_repetition` / `add_segment` (1-based, `1`=after MSH) /
  `delete_segments` / `count_segments` / `segments` / `groups(boundary='OBR')` / `encode` / `__str__`;
  `content_type='hl7v2'`; the property aliases. **Write semantics:** component/subcomponent writes escape
  structural delimiters (`^ ~ & | \`) as data and pass other chars (CJK/accented) through; a whole-field
  write rejects `|` (`ValueError` XFORM-1); CR/LF in any write raises; missing segment occurrence → `KeyError`.
  Escape format `\F\ \S\ \R\ \T\ \E\` (+ `\X..\`); read MSH-1/MSH-2 via the encoding chars, never hardcoded
  (`ValueError` XFORM-2/3 if undeterminable).
- `SegmentGroup` (from `Message.groups()`): `boundary`, `ordinal` (re-indexes after delete; stale view →
  `LookupError`), `segment_ids`, `__len__`, `count`, `field`, `append_segment`, `clear`, `delete`,
  `rebuild`; `DEFAULT_BOUNDARY='OBR'`; `groups_of` raises `ValueError` on `boundary='MSH'`.
- `validate(...) -> ValidationResult` (hl7apy, **unchanged**) and `parse_tree(raw) -> list[TreeNode]`
  (separators from MSH-1/MSH-2; raises `HL7PeekError` only on no parseable MSH).

## Acceptance Criteria

> EARS, each linked (`→`) to the test that verifies it. These tests are **to be authored with the build**;
> they back the parity guarantee that makes this a safe drop-in.

- **AC-1** — WHEN a message is read by any field path through `Peek.field`/`Message.field`, THE SYSTEM SHALL
  return a value bit-identical to the python-hl7-backed result, for every path + edit combination over the
  golden corpus (every `samples/messages/*.hl7` + `generators/` synthetic output).
  → `tests/test_parsing.py::test_builtin_parity_over_corpus`
- **AC-2** — THE SYSTEM SHALL preserve the field-path return distinction (whole-field = structural text with
  repetition delimiters; component/subcomponent = unescaped leaf) AND return the whole field value, not its
  first character, when the field carries no component separator.
  → `tests/test_message.py::test_whole_field_vs_component_semantics`
- **AC-3** — IF the input is empty, has no MSH, or is unparseable, THEN `Peek.parse` SHALL raise
  `HL7PeekError` (engine records `ERROR`/dead-letters, never accept-and-drop); IF the input is
  odd-but-structurally-parseable (inconsistent field counts, extra separators, missing CR), THEN it SHALL
  parse without raising. → `tests/test_parsing.py::test_tolerant_and_no_msh`
- **AC-4** — THE SYSTEM SHALL read the field/component/repetition/escape/subcomponent separators from the
  message's own MSH-1/MSH-2 for every split, join, and re-encode, never hardcoding `|^~\&` (verified with a
  non-standard encoding-char message, e.g. MSH-2 `@#%&`). → `tests/test_message.py::test_custom_encoding_chars`
- **AC-5** — WHEN a `Message` is read, mutated (`set`/`add_repetition`/`add_segment`/`delete_segments`/group
  ops), and re-encoded, THE SYSTEM SHALL produce a CR-delimited string that round-trips components/structure
  as written and matches the python-hl7-backed `encode` byte-for-byte.
  → `tests/test_message.py::test_encode_roundtrip_parity`
- **AC-6** — WHILE running on cp314t (free-threaded), THE SYSTEM SHALL achieve ≥6× multi-core throughput
  scaling and ~14× single-thread speedup vs the python-hl7 baseline on the WS3/ADR 0052 load harness; IF the
  measured scaling is <6× multi-core or <14× single-thread, THEN the result SHALL block ship pending
  investigation. → `tests/test_benchmark_parser.py::test_freethread_scaling`
- **AC-7** — THE SYSTEM SHALL leave the strict path unchanged: `validate()` continues to build an hl7apy
  tree, and its `ValidationResult` (frozen, `__bool__ == ok`) + version cross-check are unaffected.
  → `tests/test_validate.py::test_strict_path_unchanged`

## Options considered

1. **Built-ins (dict/list/str) drop-in backing the existing `Peek`/`Message` API.** **CHOSEN** — 6.44×
   multi-core / ~158k msg/s, ~14× single-thread; removes the class-tree contention that caps free-threading;
   zero public-API change; strict tier isolated. Cost is reimplementing python-hl7's tolerant semantics
   exactly — mitigated by the parity corpus + the Phase-1 fallback guard.
2. **Keep python-hl7.** Rejected — caps at ~2.02× multi-core (the ceiling ADR 0040/0053 were waiting on a
   parser to lift); no path to the WS3 target without changing the model.
3. **Switch the tolerant tier to hl7apy.** Rejected — worse on both axes (2.04× multi-core *and* ~46× slower
   single-thread) and it violates §8's two-tier design ("Don't route everything through the hl7apy object
   model"). hl7apy stays the strict-only slow path.
4. **Fork python-hl7 to de-ABC its `Container` classes.** Rejected — still object-per-node, so it only
   softens (not removes) the contention, and it takes on fork maintenance for a smaller win than the
   purpose-built built-ins model already measured.

## Consequences

**Positive** — unlocks the ADR 0053/0040 free-threading keystone (the measured parser win deferral was
waiting on); ~14× faster tolerant parse + ~6.4× multi-core scaling for the routing/filter hot path; lower
per-message memory (no per-node class overhead) eases GC/copy pressure; drops python-hl7 from the runtime
dependency surface after the transition; strict validation stays rock-solid (hl7apy untouched, trees
disjoint); **zero public-API/semantic change** — routers/handlers, the filter path, the transform path,
store routing/correlation, and the console parse-tree view are all unaffected.

**Negative / risks** — reimplementing python-hl7's exact tolerant semantics is the bug surface (the
whole-value-no-component rule, MSH-1/MSH-2 raw handling, the unescape heuristic, the `''`-vs-`IndexError`
asymmetry) — guarded by the parity corpus + a Phase-1 python-hl7 fallback; lazy split adds first-touch
latency variance (amortized across a batch; eager-split escape hatch if >80% of messages access non-MSH
fields); held references to internal segment dicts must stay structurally stable across `set()` (mutate
in place, never restructure the lists); a mutated message rebuilds the full raw on `encode()` (no selective
per-dirty-field re-encode in the MVP); the 6.44×/~14× figures are corpus-empirical and must be re-measured
(AC-6) on a provisioned cp314t runner before ship; python-hl7 stays a dependency for the fallback window
(two re-locks: add-window, removal).

## Migration / build order

1. **Phase 1** — implement the new parser in `messagefoundry/parsing/_builtin_hl7.py` (pure, no public
   exports yet) over the dict/list/str model with MSH-eager / rest-lazy split and the existing escape rules.
2. **Phase 1a — golden-corpus parity:** feed every `samples/messages/*.hl7` + `generators/` output through
   both backends and assert bit-identical `Peek.field(*path)` results and `Message.encode()` round-trips for
   every path + edit combo; run `test_parsing.py` + `test_message.py` against both via a parametrize toggle.
   Include adversarial escapes (`O\S\Brien`), custom MSH-2 encoding chars, empty segments/fields, and the
   whole-value-no-component cases.
3. **Phase 1b** — switch `Peek`/`Message` to use `_builtin_hl7` internally behind a fallback guard (try
   built-ins, fall back to python-hl7 on unexpected exception) for the transition window.
4. **Phase 1c — benchmarks:** throughput + latency, single + multi-core on cp314t and cp314, re-confirm the
   ≥6× / ~14× gate (AC-6) before ship; record in `docs/benchmarks/`.
5. **Phase 2** — remove the fallback, retire python-hl7 from requirements (re-lock per DEP-1); keep hl7apy
   for `validate()`. Record the deprecation/removal release.

## Resolved on acceptance (2026-06-29)

- [x] **Eager-vs-lazy:** ship the **MSH-eager / rest-lazy** default as designed; revisit an eager-split
  threshold only if real-corpus touch analysis later shows >80% of messages access non-MSH fields.
- [x] **python-hl7 fallback removal:** the Phase-1 try/except fallback **stays for this build + the next
  minor release**; removal (Phase 2, drop python-hl7 + re-lock) is a **follow-up release** once parity is
  proven on production traffic — out of this build's scope.
- [x] **Module + fixture:** locked — the parser lives at `messagefoundry/parsing/_builtin_hl7.py`; a pytest
  **parametrize fixture** runs `test_parsing.py` + `test_message.py` against **both** backends during the
  parity window.
- [x] **cp314t runner:** the **265KF dev box** (the ADR 0053 spike's free-threaded venv at
  `…\Temp\mefor-ft`) is the AC-6 scaling-re-measure harness.
