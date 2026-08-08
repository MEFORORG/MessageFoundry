# ADR 0121 — Test Bench saved regression collections: PHI-at-rest posture + HL7-aware compare

- **Status:** Accepted (2026-07-17) — the DEMAND-GATE-BACKLOG session builds it. IDE-only, no engine
  change; phased (one coherent commit per layer), pushes/PR owner-approved.
- **Date:** 2026-07-17
- **Related:** BACKLOG [#168](../archive/backlog/BACKLOG-CLOSED.md#168-test-bench-saved-regression-collections) (Test Bench saved regression collections); [ADR
  0030](0030-anonymization-test-harness-tee.md) (de-identification — the framework authors use to
  build PHI-free cases); [ADR 0072](0072-traced-dryrun-mode.md) / the Test Bench before/after diff
  (`hl7diff.ts`, reused here for the compare); CLAUDE.md §9 (PHI rules — this ADR adds a **new
  PHI-at-rest surface**), §10 (the Test Bench is an IDE authoring surface, not an operator console);
  §8 (read encoding chars from MSH; be explicit about HL7 volatility).

---

## Context

Today the Test Bench loads a message set through a one-shot file picker, dry-runs it, and shows a
before/after diff — but it **saves no case and asserts no result**. A migrating analyst who wants to
prove a config change didn't regress a feed must re-select the same files each session and eyeball
the diffs. BACKLOG #168 asks for **persisted, named, groupable collections of cases with recorded
expected outputs and one-click rerun flagging pass/fail**.

Two decisions must be made **up front**, because they are hard to reverse once cases exist:

**1. Where the case bodies live (PHI-at-rest).** A regression collection is self-contained only if it
records each case's **input message body and its expected output body(ies)** — not just file paths,
which move and mutate. Those bodies are **PHI**. CLAUDE.md §9 governs:

> Full payloads go only to the secured store … no PHI leaves the local environment without explicit,
> reviewed configuration.

This is a genuinely **new PHI-at-rest surface** for the IDE — the first that persists message bodies.
The storage location must therefore be **machine-local and never syncable off-box**:

- **NOT** a repo-tracked / committable file — that would let PHI into git and off the machine.
- **NOT** `context.globalState` — VS Code's *Settings Sync* is eligible to sync `globalState` to the
  user's cloud profile, which could carry PHI off-machine.
- **`context.workspaceState`** (machine-local, per-workspace, **not** Settings-Sync-eligible) is the
  correct home, and authors are steered to **synthetic, de-identified cases** (ADR 0030) with an
  explicit in-UI PHI notice.

**2. What "pass" means (compare semantics).** A byte-equality compare of expected vs actual would
**always fail** on a conformant HL7 message: every ACK/message carries volatile fields that legitimately
differ run-to-run — MSH-7 (message date/time) and MSH-10 (message control ID) foremost. A naive diff
would flag these as regressions and make the feature useless. The compare must be **HL7-aware with a
volatile-field ignore policy decided up front**, reusing the existing segment/field-aware alignment
(`hl7diff.diffMessages`) so an inserted/deleted segment doesn't cascade false changes (§8: read the
separators from MSH, never hardcode `|^~\&`).

## Decision

**Persist named regression collections of `{input body, expected output bodies}` cases in
`context.workspaceState`, and judge a rerun with an HL7-aware compare that ignores a fixed default set
of volatile fields (MSH-7, MSH-10).**

- **Model — `ide/src/testCollections.ts` (NEW, pure, `vscode`-free).** Types (`TestCase`,
  `TestCollection`, `ExpectedDelivery`), the `DEFAULT_VOLATILE_FIELDS` policy, and
  `compareMessages(expected, actual, ignore?)` → `{ pass, differences[], diff }`. The compare runs
  `hl7diff.diffMessages` (reused, not reimplemented) and walks the aligned cells: a `same` cell is
  clean; an `added`/`removed` **segment** is always a real difference; a `changed` cell is a real
  difference **only** for changed fields whose `(segment id, split-index)` coordinate is **not** in
  the ignore set. `pass` iff no real difference remains. Pure ⇒ unit-testable like `hl7diff.ts`.
- **Volatile-field policy (fixed default, up front).** `DEFAULT_VOLATILE_FIELDS = MSH-7`
  (message date/time — this is "ACK dates" for an ACK message, whose MSH-7 is its generation time)
  and **MSH-10** (message control ID). Expressed as `{ seg, index }` where `index` is the
  `hl7diff` split index (`fields[6]` = MSH-7, `fields[9]` = MSH-10, because MSH-1 is the separator
  char itself, not a split element). The set is a module constant so tests pin it and a future
  amendment can extend it (e.g. a per-collection override) without changing the compare shape.
- **Persistence.** A collection is `{ name, cases: TestCase[] }`; the whole named map lives under one
  `workspaceState` key. `TestBench` (holding `this.context`) does the CRUD; `testCollections.ts`
  stays storage-agnostic. Saved from the currently-loaded rows: each row's `raw` → `case.input`, its
  `deliveries` → `case.expected`. **Never** written to a repo file or `globalState`.
- **Rerun.** Because the `dryrun` CLI takes only file paths (`--messages`, no stdin), a rerun
  **materializes each case's stored input to a fresh per-run temp directory** (`os.tmpdir()`),
  dry-runs it (`--show-phi`, so expected/actual bodies are full), compares each case's new deliveries
  against its stored `expected` via `compareMessages`, and **deletes the temp directory in a
  `finally`** — PHI on disk is transient and cleaned, never left behind. Pass/fail is shown per case;
  a failing case opens the expected-vs-actual before/after diff.
- **PHI notice.** The collections UI carries a one-line notice steering authors to synthetic,
  de-identified cases (ADR 0030) and stating that bodies are stored machine-locally in workspace
  state.

**Must not break:** no new engine/CLI surface; no PHI to a repo file, `globalState`, or a log; the
temp materialization is always cleaned up; the compare never hardcodes `|^~\&` (reads MSH); the
existing Load / before-after / Coverage-Profiling panes and the `--show-phi` posture are untouched.

## Acceptance Criteria

- **AC-1** — WHEN expected and actual differ **only** in MSH-7 and/or MSH-10, THE SYSTEM SHALL report
  `pass=true` (volatile fields ignored).
  → `ide/src/test/suite/test-collections.test.ts`
- **AC-2** — WHEN a non-volatile field differs (e.g. PID-5 patient name) or a segment is added/removed,
  THE SYSTEM SHALL report `pass=false` and list the differing coordinate in `differences`.
  → `ide/src/test/suite/test-collections.test.ts`
- **AC-3** — WHERE the messages use a non-`|` field separator, THE SYSTEM SHALL read it from MSH and
  still locate MSH-7/MSH-10 correctly (never hardcode `|^~\&`).
  → `ide/src/test/suite/test-collections.test.ts`
- **AC-4** — THE SYSTEM SHALL persist case bodies only in machine-local `workspaceState` — never in a
  repo-tracked file and never in `globalState` (Settings-Sync-eligible). *(Design/review-enforced; the
  storage key is `workspaceState`-scoped in `testBench.ts`.)*

## Options considered

1. **`workspaceState` bodies + HL7-aware compare ignoring MSH-7/MSH-10, temp-file rerun** — self-
   contained, machine-local, no off-box sync, honest pass/fail. **CHOSEN.**
2. **Store file paths only, rerun the original files** — no new PHI-at-rest, but not self-contained
   (files move/mutate); a "regression suite" that silently changes when a file is edited is a trap.
   Rejected.
3. **`globalState` for cross-workspace collections** — Rejected: Settings-Sync-eligible, could carry
   PHI to the user's cloud profile (§9 breach).
4. **Byte-equality compare** — Rejected: always fails on volatile MSH-7/MSH-10; useless.
5. **A committed `.regression.json` in the repo** — Rejected: PHI into git / off the machine (§9).

## Consequences

**Positive** — Analysts save named suites once and re-run with one click; pass/fail is HL7-honest
(volatile fields ignored, segment inserts don't cascade). The pure `testCollections.ts` reuses
`hl7diff` and is unit-testable. Storage is machine-local and non-syncable by construction.

**Negative / risks** — A **new PHI-at-rest surface**: message bodies persist in `workspaceState`
(machine-local, but plaintext in VS Code's per-workspace storage). Mitigated by the synthetic-case
steer (ADR 0030) and the in-UI notice; workspaceState is not encrypted, so authors must not save real
PHI. Rerun writes transient PHI to a temp dir — always cleaned in `finally`, but a hard crash mid-run
could leave a temp file (OS temp reaping bounds the exposure). The volatile policy is a fixed default;
a feed with other volatile fields (e.g. a bespoke timestamp segment) may show a false regression until
a future per-collection override lands.

**Out of scope** — Per-collection custom ignore policies (future amendment); encrypting
`workspaceState`; cross-workspace/shared collections; any engine/CLI change (e.g. a `dryrun` stdin
mode that would avoid temp files); an operator-console regression runner (§10).
