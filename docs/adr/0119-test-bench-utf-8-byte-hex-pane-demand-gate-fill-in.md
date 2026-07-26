# ADR 0119 — Test Bench UTF-8 byte hex pane (demand-gate fill-in)

- **Status:** Accepted (2026-07-17) — the DEMAND-GATE-BACKLOG session builds it; scope narrowed on a
  verifier refutation (below). IDE-only, no engine change; phased (one coherent commit per layer),
  pushes/PR owner-approved.
- **Date:** 2026-07-17
- **Related:** BACKLOG [#84](../BACKLOG.md) (Diagnostic panes — hex body view + HL7-aware diff +
  profiling; the hex pane was the demand-gated remainder); [ADR 0028](0028-base64-binary-carriage-codec.md)
  (the `mfb64:v1:` base64 carriage marker — the reason a "decode the whole body" hex pane was
  *considered* and is here **explicitly ruled out**); [ADR 0072](0072-traced-dryrun-mode.md) (the
  traced dry-run the Coverage/Profiling panes consume); CLAUDE.md §9 (PHI rules), §10 (the web
  console is the operator UI; the Test Bench is an IDE authoring surface, not an operator console).

---

## Context

BACKLOG #84 bundled three Test Bench diagnostic panes. Two — the HL7-segment/field-aware before/after
diff (`hl7diff.ts`) and the Coverage/Profiling panes (`traceView.ts`) — shipped earlier. The **hex
body pane** stayed demand-gated: *"build when operators / authors need hex / diff / coverage
diagnostics beyond the current views."* This session's trigger fired for the fill-in.

The obvious framing — "a hex pane for binary / `mfb64:` bodies" — collides with two facts that a
verifier pass surfaced and **refuted**, which narrow the scope:

1. **The Test Bench never sees the true binary bytes.** The Test Bench renders `DryRunRow.raw`, a
   **JSON string** the `dryrun --show-phi --json` CLI produces. The CLI reads the file bytes and
   **UTF-8-decodes them with `errors="replace"`** on the hot path (`parsing/peek.py`) before they
   ever reach JSON — a genuinely binary body is therefore **already lossily corrupted** (every
   invalid sequence has become U+FFFD) by the time the IDE has it. There is no round-trip back to
   the original bytes from `row.raw`.
2. **`row.raw` never carries the `mfb64:v1:` marker.** ADR 0028's base64 carriage marker is a
   **store/ingress** transport detail; the dry-run path does not emit it into `raw`. So a
   "strip the `mfb64:` marker and base64-decode the whole body" pane would have **nothing to
   strip** and nothing to decode — it was designed against bytes that are not present.

A real *binary* hex view (showing the exact wire bytes of a `content_type=dicom`/`x12`/`mfb64`
payload) would require an **engine/CLI read-path change** — a new dry-run mode that carries the
undecoded bytes (e.g. base64) to the IDE. That is out of scope for an IDE-only, demand-gate fill-in
and is **not** what this ADR authorizes; the ADR note must not claim mfb64 whole-body decoding.

CLAUDE.md §9 bounds any new render of message content:

> **Never log full message bodies at INFO or above.** Full payloads go only to the secured store …
> **CLI `dryrun`/`generate` output can contain full message bodies** …

The Test Bench already runs `dryrun --show-phi` and renders full bodies in the before/after panes
(the author's own test messages, in-memory in the webview), so the hex pane adds **no new egress and
no new PHI-at-rest** — it re-renders bytes the panel already holds.

## Decision

**Ship a UTF-8 byte hex pane over `DryRunRow.raw` — a classic `offset · hex · ASCII` dump of the
UTF-8 encoding of the string the Test Bench already has — computed by a new pure, `vscode`-free
`ide/src/hexdump.ts` and rendered in the existing Test Bench webview behind a per-row "Hex" button.**

- **Input = `row.raw` (a string), output = the UTF-8 bytes of that string.** The pane is honest
  about what it shows: the bytes of the message *as the dry-run decoded it*, not the original wire
  bytes (which `raw` no longer contains — see Context). A short pane subtitle states this so an
  author is never misled into thinking a U+FFFD run is the file's real binary content.
- **Pure module, structured output.** `hexdump(text, opts)` returns a data model
  (`{ lines: {offset, hex[], ascii}[], totalBytes, renderedBytes, truncated, bytesPerRow }`) — no
  HTML, no `vscode`. The extension host computes it (mirroring how `diffMessages`/`buildTraceDetail`
  are computed host-side and posted) and the webview renders it. This keeps it unit-testable in
  isolation, exactly like `hl7diff.ts`.
- **Render size is capped** (`maxBytes`, default 16 KiB → 1024 rows at 16 bytes/row). A body longer
  than the cap renders the first `maxBytes` and the pane shows a `truncated` notice with the true
  `totalBytes` — bounding webview DOM and never streaming an unbounded body into the panel.
- **In-memory only.** The decoded/hex representation is built in the extension host and posted to
  the webview; it is **never written to disk** (no temp file, no log) — it lives and dies with the
  panel, honoring §9.

**Must not break:** no new CLI/engine surface; no `mfb64:`/base64 whole-body decode claim; no PHI to
disk or log; the existing before/after + Coverage/Profiling panes and the `--show-phi` posture are
untouched.

## Acceptance Criteria

- **AC-1** — WHEN `hexdump(text)` is called, THE SYSTEM SHALL return rows of the UTF-8 bytes of
  `text` with a monotonically increasing byte `offset`, lowercase two-hex-digit bytes, and an ASCII
  column mapping bytes `0x20–0x7E` to their character and all others to `.`.
  → `ide/src/test/suite/hexdump.test.ts`
- **AC-2** — WHEN the input's UTF-8 length exceeds `maxBytes`, THE SYSTEM SHALL render only the first
  `maxBytes` bytes, set `truncated=true`, and report the true `totalBytes`.
  → `ide/src/test/suite/hexdump.test.ts`
- **AC-3** — WHERE the input contains non-ASCII/multi-byte characters (e.g. `é`, an emoji, or a
  U+FFFD replacement char), THE SYSTEM SHALL hex-dump their actual UTF-8 byte sequence (not the code
  unit) and never throw.
  → `ide/src/test/suite/hexdump.test.ts`

## Options considered

1. **UTF-8 byte hex dump of `row.raw`, pure module + capped render** — honest about the
   already-decoded input, zero new egress, no engine change. **CHOSEN.**
2. **`mfb64:`/base64 whole-body decode → true binary hex** — Rejected: `row.raw` carries neither the
   marker nor the original bytes (verifier-refuted); it would decode nothing. Requires an engine/CLI
   read-path change to carry undecoded bytes — out of scope for a demand-gate IDE fill-in.
3. **A new `dryrun --raw-bytes` mode carrying base64 wire bytes to the IDE** — Rejected *for now*:
   real value for binary payloads, but it is an engine change, not the demand-gated IDE pane #84
   left open. Recorded here as the path a future "true binary hex" item would take.

## Consequences

**Positive** — Authors get a byte-accurate view of what the dry-run actually parsed (invisible
control chars, stray CR/LF, trailing NULs, mojibake from a mis-encoded source) without leaving the
Test Bench. Pure `hexdump.ts` is trivially testable and reusable. No new PHI surface.

**Negative / risks** — The pane shows *decoded* bytes, not wire bytes, for genuinely binary content;
the subtitle mitigates the "is this the real file?" confusion but does not eliminate it. A true
binary hex view remains future work gated on an engine read-path change.

**Out of scope** — mfb64/base64 whole-body decoding; any CLI/engine change; rendering the original
undecoded wire bytes; an operator-console hex view (§10 — the web console is the operator UI).
