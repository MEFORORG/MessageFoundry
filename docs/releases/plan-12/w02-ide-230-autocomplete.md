# PLAN-12 · Wave 2 · #230 inline autocomplete — message-type ranking + kwarg snippets

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)
> (authored with the plan, 2026-07-16). **This file is the maintainable source of truth for this session's status.**
> Shared rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `ide-230-autocomplete` |
| **Wave** | 2 |
| **Status** | ✅ **Complete** (2026-07-16 — both phases landed in this session's PR; IDE v0.0.33) |
| **Effort** | 1.5 |
| **Backlog items** | #230 (Phases 2 + 3 of 4) — ADR 0104 §2.3 **Step 1** |
| **ADR** | No — executes already-Accepted ADR 0104 §2.3 Step 1 |
| **Store schema / 3-backend** | No (ide lane) |

## Items

| Item | Title | Status |
|---|---|---|
| #230 (P2) | Pure completion-scope module + unit tests | ✅ built (this PR) |
| #230 (P3) | `completion.ts` wiring + `occurrence=`/`repetition=` snippets + version bump | ✅ built (this PR) |

## Owned files / seams

`ide/src/completionScope.ts` (new, **vscode-free**) · `ide/src/completion.ts` · `ide/src/hl7scope.ts` /
`ide/src/hl7schema.ts` (export shared helpers only if needed) · `ide/src/test/suite/completion-scope.test.ts` (new,
modeled on `hl7scope.test.ts`) · `ide/package.json`(+lock) — **takes 0.0.33 after rebasing over #238's merge (W2
ide-hotspot owner)**.

## The work

**Phase 2 — pure module (`completionScope.ts`):**

1. `enclosingHandlerTypes(documentText, line)` — walk up to the nearest column-0 `def`, read its contiguous
   decorator run, extract string literals from `accepts=message_type_of("…", …)` and from the inert `message_type=`
   documentation kwarg (IDE-read-only, sanctioned by ADR 0104 §2.3); returns `string[] | undefined`.
   **Verdict-corrected: the multi-line decorator-run capture is NEW logic** (e.g. bracket-balance across the
   contiguous decorator block) — `symbolIndex.ts` `classify()` is documented **single-line-only** (:35-38); "reuse
   the exact pattern" was refuted. Reuse only its column-0/decorator-classification *approach*.
2. `scopedSegmentSortText(allSegments, structures, acceptsTypes)` — reuse `buildSegmentScope`
   (`hl7scope.ts:65-110`, `sample=[]` — the code editor has no sample context) and map groups onto sortText
   prefixes: in-scope `0…` (COMMON_SEGMENTS sub-order preserved), everything else `2…` with a distinct
   "not in `<STRUCTURE>`" description. Undefined structures / unresolvable type → return `undefined` so
   `completion.ts` keeps today's `segmentSortText` order **byte-identically**.
3. **Hard invariant: rank-never-remove** — every schema segment appears exactly once; misses are visibly labelled,
   never hidden. The ranked scope is the pinned **2.5.1 superset** (as the shipped picker presents it) — never
   per-feed truth.
4. No vscode import, no I/O, no Python. **KWARG_CTX and EVERY unit-tested helper live in this pure module** —
   `completion.ts` imports vscode at line 4 and `npm run test:unit` is plain-node mocha.

**Phase 3 — wiring (`completion.ts`) + snippets + version:**

1. PATH_CTX segment stage (~:34-43): call `enclosingHandlerTypes` at the cursor, resolve via `loadStructures`
   (load once at registration, like `loadSchema` at ~:94), apply `scopedSegmentSortText`; field/component stages
   unchanged.
2. KWARG_CTX: a cursor after the path argument inside `.set(…)`/`.field(…)` offers two `SnippetString` completions —
   `occurrence=${1:2}` / `repetition=${1:1}` — documentation quoting the 1-based semantics from
   `parsing/message.py` (`set()` :248-250, `field()` :100). **Verdict-corrected:** the regex must **exclude a cursor
   inside the value string literal** — the design's illustrative `/\.(?:set|field)\(\s*"[^"]+"\s*,[^)]*$/` matches
   `msg.set("PID-3.1", "abc` and fails its own test; the **single-line-prefix limitation** (no firing on multi-line
   `.set(` calls) is recorded as accepted.
3. Trigger characters `,`/` ` added only if measured necessary (avoid noisy triggering); **no new trigger fires
   inside `Send("…")` or `router="…"` contexts**; no per-keystroke Python (`completion.ts:1-3` header stays true —
   update it to mention the ranking source).
4. Rebase over #238's merge; bump `ide/package.json`(+lock) → **0.0.33** (never hardcode a sibling's version).

## Dependencies

- **Gate: [w01-docs-230-errata](w01-docs-230-errata.md) merged** — the corrected tracker is the defense against
  rebuilding the shipped picker.
- Rebases over [w01-ide-238-setup](w01-ide-238-setup.md)'s merge (ide/package.json).
- `ide/media/hl7structures.json` is committed and CI-synced (recompute-and-compare parsed-JSON equality gate,
  `tests/test_ide_artifacts.py`) — consumed as-is; the `messagefoundry hl7structures` CLI is the only sanctioned
  writer.

## Notes & gotchas

- **Scope-out (do NOT build):** the Steps-view picker (SHIPPED — PR #1001); editable occurrence/repetition in the
  picker/lens (separately ratification-gated); `RawMessage.raw` freeze; lens-adoption telemetry (own item + likely
  own ADR — PHI product); P3 badges in the inline autocomplete (scope creep); any lens/stepsModel rendering change.
- **Hard regression bar:** with no structures artifact or no enclosing typed handler, segment completion output is
  **byte-identical** to today's `segmentSortText` path (regression case in the suite).
- The `@vscode/test-electron` integration suite (`npm test`) runs on the public-mirror windows CI leg — do not rely
  on it locally; manual Extension Development Host smoke instead.

## Verification — Definition of Done

- `cd ide && npm run typecheck && npm run compile && npm run test:unit` — cases: multi-line decorator capture;
  nested/indented defs ignored; `message_type=` read; no decorator → undefined; `ADT^A08 → ADT_A01` via
  triggerToStructure fixture; explicit 3-component spec uses its structure id; multi-spec union; rank-never-remove
  property; undefined-structures byte-identical passthrough; KWARG_CTX fires after `msg.set("PID-3.1", ` and NOT
  inside the path string / value literal / `Send("…")`.
- CI ide leg green (path-gated on `ide/**`) — **manual ide-leg hold** before merge.
- PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; owner approves.

---
_Last reconciled: 2026-07-16 against `origin/main` @ `8e413919`. Master index:
[MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)._
