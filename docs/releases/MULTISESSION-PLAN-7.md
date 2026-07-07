# MessageFoundry — Multisession Execution Plan 7 (2026-07-06)

**Intent.** This plan builds the **"make building easy WITHOUT AI"** DX program: a deterministic, fully-offline on-ramp to code-first authoring for PHI-environment builders who cannot use AI assist. Every deliverable here has an AI sibling today (`/explain`, `/transform`, `/test`, …); this plan ships the **deterministic equivalent** of each so a builder with AI turned off still gets discoverable idioms, live feedback, a cookbook, and a real test bench. It stays strictly inside the code-first bright line: **every snippet, wizard, and cookbook entry emits editable Python** — never a stored declarative artifact, never a visual/field-mapping surface (CLAUDE.md §12 / BACKLOG **#26**, declined-by-design).

**Scope.** Seven buildable lanes across two engine-neutral clusters plus a docs/ADR lane:
1. **Insert Element palette expansion** (extends shipped **#48/#595**, ~16 new idioms + discoverability);
2. **#92 live-debug loop** in two phases — **v1** CodeLens summary over *today's* `dryrun --json` (IDE-only) and **v2** per-statement inline values over a *new* traced-dryrun mode;
3. **Cookbook + Walkthrough** onboarding + solved-problems gallery (new BACKLOG **#104**, the deterministic sibling for `/explain`);
4. **Test Bench depth (#84)** — HL7-segment/field-aware before/after diff (client-side) + profiling/coverage panes (trace-fed);
5. the **traced-dryrun engine mode** (`dryrun --trace json`, **ADR 0072**) — the single shared engine deliverable gating both #92 v2 and #84 profiling/coverage;
6. an **"AI-off completeness" audit** (each chat subcommand → deterministic sibling).

**Out of scope — HARD bright line (CLAUDE.md §12 / BACKLOG #26).** No visual/template/declarative **logic** authoring: no drag-drop transformer, no field-mapping grid, no persisted "configure-a-step" surface, no visual correlation editor (**#79 declined**), no Fix-All auto-repair (**#80 declined**). Every snippet/wizard/cookbook entry emits **editable Python inserted verbatim** via `editor.insertSnippet()` — no input-driven code synthesis, no stored declarative artifact. Transforms stay **pure** — no DB writes in a Handler (only read-only `db_lookup`/`fhir_lookup`); the palette **intentionally omits** `DBInsert/Update/Delete/Call`. Also out of scope: the `/migrate` → deterministic Corepoint-import gap surfaced by the AI-off audit (a larger owner-gated design item with its own future ADR — filed to the deferred tail, not built here).

**Lineage.** Supersedes-forward [`docs/releases/MULTISESSION-PLAN-6.md`](MULTISESSION-PLAN-6.md) (post-`0.2.10` deployment/DR wave — cloud/K8s, frozen installer, self-hosted CI, config-UX). PLAN-6's board is a disjoint deployment surface from this IDE/DX program — no overlap except the shared `docs/adr/` numbering register.

**Autonomy: L1.** Workers build + verify (full quartet) + commit **local**; the **owner** opens/merges PRs and **ratifies ADRs**. Single-writer coordination ledger in AI memory. Worktree-per-lane off `origin/main` @ `0f0ba08`.

**Numbering state.** Next-free ADR = **0072** (highest on disk = `0071-cut-executor-round-trips-b5.md`). ⚠ **ADR 0070 is reserved-elsewhere** — it exists only on the unmerged branch `docs/adr-0070-t17-infra-fault` (Proposed); **do not reuse 0070**. Next-free BACKLOG heading = **`## 104.`** (highest = `## 103.` — ``## 103. Retire the PySide6 desktop console``, added since the workflow ran). L0 must re-run `git log origin/main -- docs/adr/` and re-check the highest `## N.` heading immediately before numbering (parallel-session races are a known gotcha — `mf-handoff-check-existing-prs`).

**Live siblings (do not edit).** The in-flight worktree `feat/adr0071-pr3-dispatch-wiring` (ADR 0071 B5 fusion, PR4 #777 / PR5 landing) owns `pipeline/` dispatch + `wiring_runner.py` + benches. Verified: it touches only `webui/_html.py`, `webui/pages/account.py`, `static/app.css` — **not `pipeline/dryrun.py` or `__main__.py`**, so L5 is collision-free today. L5 re-confirms this before starting; never edit that sibling worktree.

---

## A. Wave items & lane roster (all verified OPEN/PARTIAL on `origin/main` @ 0f0ba08)

### Lane roster (the master table)

| ID | Title | Primary files | ADR | Deps | Parallel-safe-with | Effort |
|---|---|---|---|---|---|---|
| **L0** | COORD / ADR + docs-sync | `docs/adr/0072-*.md`, `docs/adr/README.md`, `docs/BACKLOG.md`, `docs/AI-OFF-MATRIX.md` (new), `CLAUDE.md` §3, `ide/README.md`, `docs/USER-GUIDE.md` | authors **0072** | none | all (single-writer docs) | S (docs) |
| **L1** | Insert Element palette ext (#48/#595) | `ide/snippets/messagefoundry.code-snippets`, `ide/src/insertElement.ts`, `ide/src/editorToolbar.ts`, `ide/src/test/suite/insert-element.test.ts`, `ide/README.md` (+ manifest delta) | none | none | L2, L3, L4, L5 | M |
| **L2** | Live-debug **v1** (#92 v1) | `ide/src/liveDebug.ts` (NEW) (+ manifest + `extension.ts` deltas) | none | none | L1, L3, L4, L5 | M |
| **L3** | Cookbook + Walkthrough (#104) | `ide/src/cookbook.ts` (NEW), `ide/media/*` (NEW) (+ manifest + `extension.ts` deltas) | none | **L0** (#104 blessed to merge) | L1, L2, L4, L5 | M–L |
| **L4** | Test Bench HL7-aware diff (#84 diff) | `ide/src/testBench.ts` | none | none | L1, L2, L3, L5 | M |
| **L5** | Traced-dryrun engine mode (#92 v2 / #84 eng) | `messagefoundry/pipeline/dryrun.py` (+ optional `pipeline/dryrun_trace.py`), `messagefoundry/__main__.py`, `tests/` | **0072** (Accepted first) | **L0** (ADR Accept) | L1, L2, L3, L4 (sole engine editor) | M–L · **critical path** |
| **L6** | Live-debug **v2** inline values (#92 v2) | `ide/src/liveDebug.ts` (extend) (+ manifest delta) | **0072** | **L5 + L2** | L7 | M |
| **L7** | Test Bench profiling/coverage (#84 prof/cov) | `ide/src/testBench.ts` (extend) (+ manifest delta) | **0072** | **L5 + L4** | L6 | M–L |

> **"+ manifest / extension.ts deltas"** = the lane does **not** edit `ide/package.json` or `ide/src/extension.ts` directly. It ships a documented delta snippet in its PR description; a single **coordinator-owned integration commit** applies all deltas at land time (see §D/§E). This is what makes the Wave-1 IDE lanes genuinely parallel rather than a rebase chain (folds Review A #2).

### Wave breakdown

**Wave 0 — ADR + backlog + audit + docs-sync (L0; coordinator-authored, owner-ratified)**

| Output | For | New / existing |
|---|---|---|
| **ADR 0072** Traced-dryrun mode + trace schema (`dryrun --trace json` via `sys.settrace`) | #92 v2, #84 prof/cov | **NEW** — gates L5/L6/L7 |
| **BACKLOG #104** Cookbook + Walkthrough | Cookbook lane | **NEW** heading (land via throwaway worktree, §F) |
| **AI-off completeness matrix** (`docs/AI-OFF-MATRIX.md`) | audit adjacency | **NEW** — confirms siblings; flags `/migrate` gap → deferred |
| **Docs-sync** CLAUDE.md §3 ide-line + `ide/README.md` + `docs/USER-GUIDE.md` enumerate live-debug + Cookbook + palette | doc consistency (LOW-8) | edits |
| **#48/#84/#92 banner reconciliation** in `docs/BACKLOG.md` | reconciliation | folded into L0 commit 1 (§I) |

**Wave 1 — actionable, independent IDE builds (parallel)**

| # | Item | ADR | Lane | Notes |
|---|---|---|---|---|
| #48/#595 ext | ~16 new idioms (→ ~30 total) + editor-title entry + keybinding + CodeLens + cursor-context filter | none | **L1** | Mostly snippet JSON; small TS. No engine touch. |
| #92 **v1** | Live-debug CodeLens **summary** over today's `dryrun --json` | none | **L2** | **Scoped to what today's JSON supports** — see Review A #1 fold below. |
| #104 | Cookbook walkthrough + searchable static-snippet gallery | none | **L3** | Deterministic sibling for `/explain`; static snippets only (MED-5). |
| #84 (diff) | HL7-segment/field-aware before/after diff (client-side TS) | none | **L4** | Profiling/coverage deferred to L7 (needs trace). |

**Wave 1b — ADR-gated engine lane (critical path; folds Review A #3)**

| # | Item | ADR | Lane | Notes |
|---|---|---|---|---|
| #92 v2 / #84 eng | `dryrun --trace json` — per-invocation `(source_line, event, value)` seq + disposition + Sends, PHI-redacted | **0072** | **L5** | Sole engine editor. Cannot start until ADR Accepted — **schedule bottleneck; likely finishes last of the "Wave-1" set.** L6/L7 both block on it. |

**Wave 2 — trace consumers (gated on L5 + their Wave-1 base lane)**

| # | Item | ADR | Lane | Notes |
|---|---|---|---|---|
| #92 v2 | Per-statement inline decorations + hover, consuming the trace | **0072** | **L6** | Extends L2's `liveDebug.ts`. **Wall-clock start = max(L5 merge, L2 merge).** |
| #84 (prof/cov) | Profiling + coverage panes, consuming the trace | **0072** | **L7** | Extends L4's `testBench.ts`. **Wall-clock start = max(L5 merge, L4 merge).** |

**Deferred tail / non-lane (tracked, not agent-buildable now)**

| # | Item | Reason |
|---|---|---|
| `/migrate` → deterministic Corepoint-import tooling | AI-off audit gap | Larger owner-gated design item; needs its own scope + future ADR. L0 files it as a NEW deferred BACKLOG item; **not** in this plan's build waves. |

---

## B. Dependency DAG & wave sequencing

```
Wave 0 ─ L0: ADR 0072 + BACKLOG #104 + AI-off matrix + docs-sync + banner reconciliation
             │
             └──► OWNER RATIFIES ADR 0072 (Proposed → Accepted)  ── unblocks L5/L6/L7
   ┌──────────────┬──────────────┬──────────────┐          ┌──────────────────────────┐
Wave 1 (parallel — no shared-file edits; deltas → integration commit):   Wave 1b (ADR-gated):
  L1 insert-elem   L2 v1         L3 cookbook*    L4 tb-diff        L5 trace-engine (CRITICAL PATH)
  (no ADR)         (no ADR)      (no ADR)        (no ADR)          (ADR 0072 Accepted)
   │               │             │               │                        │
   └───────────────┴─────────────┴───────────────┴──── COORDINATOR ───────┤
                    manifest-integration commit (package.json + extension.ts deltas)
                    → npm run typecheck && npm run compile                 │
                                                                           │
Wave 2 (gated):     L6 v2  ◄────────── needs L2 + L5 ──────────────────────┤
                    L7 prof/cov ◄────── needs L4 + L5 ──────────────────────┘
                    (L6 ∥ L7 — distinct files; each rebases over its base + L5)

  * L3 may build against a Proposed #104 but the heading must be owner-blessed before its PR merges.
```

**Sequence.**
1. **Wave 0 (L0):** author ADR 0072, promote #104, write the AI-off matrix, docs-sync, reconcile banners. **Owner ratifies ADR 0072.**
2. **Wave 1 — parallel:** L1, L2, L3, L4 build on their own files only; each hands a `package.json`/`extension.ts` delta to the coordinator. **Wave 1b:** L5 starts once ADR 0072 is Accepted (collision-free with all IDE lanes).
3. **Integration commit:** coordinator applies the four Wave-1 manifest/registration deltas in one commit and runs `typecheck && compile`.
4. **Wave 2 — gated:** L6 (L2 + L5), L7 (L4 + L5). Parallel-safe with each other; each rebases over its Wave-1 base file + L5's CLI contract.
5. Each lane: full quartet green **before** the owner PRs it. No lane here is store-touching → **no 3-backend parity suite**.

---

## C. Per-lane detail + ready-to-paste worker kickoff prompts

> Grouping rule: **one deliverable = one worker session = one worktree**. `scripts/worktree/new.ps1 -Name <lane>` (isolated checkout + branch + `.venv`); cleanup `remove.ps1`. First action every session: `git fetch && git log origin/main --oneline | head -20 && gh pr list --state all` to rule out an already-merged duplicate.

### Lane L0 — COORD / ADR + docs-sync *(pure docs; builds no product code)*

**Builds:** ADR 0072 (§G); BACKLOG #104; the AI-off completeness matrix; the docs-sync edits (LOW-8); the #48/#84/#92 banner reconciliation (§I). Files the deferred `/migrate` item.

> **Kickoff — branch `docs/plan7-adr0072-trace`:**
> Author `docs/adr/0072-traced-dryrun-mode.md`. Schema: per handler/router invocation → ordered `(source_line, event, value)` records + final disposition + Sends; **trace `value`s redacted unless `--show-phi`** (mirror `_redact` at `__main__.py:1452`); `db_lookup`/`fhir_lookup` raise `DbLookupError` in dry-run → the handler **still terminates (disposition stays ERROR, byte-identical to a non-traced run)**; the tracer only **classifies the terminal exception as a live-lookup skip** and emits a `live_lookup_skipped` annotation record — it does **not** resume the handler. Pin the `sys.settrace` **capture semantics** section: (a) restore `prev = sys.gettrace()` in `finally` (never `None` — coexist with `pytest-cov`/`coverage.py`); (b) tracer scoped to the exact handler/router frame, `return None` for other frames; (c) thread-locality — assert the handler runs on the tracer's thread (or `threading.settrace` appropriately) since `db_lookup`/handler may run off the event-loop thread; (d) Python 3.14 PEP 669 `sys.monitoring` coexistence; (e) value-capture timing (line events fire on line *entry*, so "value after `x = …`" is observed on the *next* line event — pin locals-diff-per-line vs AST-assisted). PHI posture is a **hard requirement**, not prose: values default redacted; the trace JSON is **streamed in-process, never written to a persisted/committable temp file**; the un-redaction is a per-session, non-persisted, explicit opt-in independent of any "on" toggle; drop any "prod/PHI env auto-detect" claim — the concrete guard is "runs only against files under `messageSetsDir`, which must be synthetic."
> **Before numbering, run `git log origin/main -- docs/adr/` and confirm 0072 is still free (skip 0070).** Add the `0072` row to `docs/adr/README.md` (Proposed). Via a **throwaway worktree off fresh `origin/main`**, add BACKLOG `## 104.` (Cookbook) — re-confirm 104 is highest+1 first — and a deferred `/migrate → deterministic Corepoint-import` item. Write `docs/AI-OFF-MATRIX.md` (each `@messagefoundry` subcommand → deterministic sibling: `/explain`→Cookbook #104, `/transform`→Insert Element, `/router`→router idioms, `/review`→validate, `/test`→dryrun/Test Bench; `/migrate`→lone open gap → deferred). **Docs-sync:** update CLAUDE.md §3 ide-line, `ide/README.md` feature list, and `docs/USER-GUIDE.md` to enumerate live-debug + Cookbook + expanded palette. Reconcile the #48/#84/#92 banners (§I) — for #48, word it "**add the *Insert Element…* entry to the existing `editorMenu` submenu**" (the submenu already exists in `package.json` lines 161/167/174; L1 appends an entry, it does not create the dropdown). **Do NOT touch ADR-0017** (no deployment-model change).
> **Done:** markdown renders; `docs/adr/README.md` 0072 row present; BACKLOG heading number correct; AI-off matrix complete; docs-sync applied. No code quartet. Report the exact ADR/BACKLOG numbers claimed to the coord ledger.

### Lane L1 — INSERT-ELEMENT (#48/#595 ext) *(Wave 1, no ADR)*

**Builds:** ~16 new body-level idiom snippets (→ **~30 total**; #595 shipped 14 — Review A #5) mapping Corepoint's Action-List palette: string format (upper/lower/trim/substring/pad), `re.sub` regex replace, numeric compute, `match/case` switch, **`current_ingest_time()`** message-time idiom (re-run-stable), `length_of_stay`, `fhir_lookup` read, fan-out (list of `Send`), non-HL7 body access (`msg.json()`/`text()`), clear-a-field, router idioms (route-by-type, route-to-multiple). Each body is **editable Python**. Plus: editor-title "Insert Element…" entry, a keybinding, a discoverability CodeLens (own line on the shared `editorToolbar.ts` provider), a cursor-context filter (router idioms inside `@router`, handler idioms inside `@handler`).

**Purity guard (folds MED-6):** the **"message time"** idiom defaults to **`current_ingest_time()`** (`config/ingest_time.py`, re-run-stable). `hl7_now()` appears **only** as a separate, explicitly-labeled *"stamp a freshly-built **outbound** message"* snippet whose body carries the caveat comment `# keep out of routing/transform decisions — reads wall-clock, breaks re-run purity`. Note the intentionally-absent `DBInsert/Update/Delete/Call` in `ide/README.md` (purity invariant).

**Files owned:** `ide/snippets/messagefoundry.code-snippets`, `ide/src/insertElement.ts` (add the context filter — `buildPicks()` grouping unchanged), `ide/src/editorToolbar.ts` (extend its provider), `ide/src/test/suite/insert-element.test.ts` (extend asserted-prefix list), `ide/README.md`. **Delta to coordinator:** `package.json` keybinding + `editorMenu` entry (no direct edit).

> **Kickoff — branch `feat/ide-insert-element-palette`:**
> Add ~16 body-level idiom snippets to `ide/snippets/messagefoundry.code-snippets` (string format upper/lower/trim/substring/pad; `re.sub`; numeric compute; `match/case`; **`current_ingest_time()`** message-time; `length_of_stay`; `fhir_lookup` read; fan-out list-of-`Send`; `msg.json()`/`text()`; clear-a-field; route-by-type; route-to-multiple) — each body **editable Python**, `"Category · Label"` descriptions so `buildPicks()` auto-groups. **Message-time defaults to `current_ingest_time()`; add `hl7_now()` only as a separate "stamp an outbound message" snippet with the "breaks re-run purity — keep out of routing/transform" caveat comment.** Note the omitted `DBInsert/Update/Delete/Call` in `ide/README.md`. Add a discoverability CodeLens on `ide/src/editorToolbar.ts`'s existing provider and an `@router`/`@handler` cursor-context filter in `ide/src/insertElement.ts`. Extend the asserted-prefix list in `insert-element.test.ts`. **Do NOT edit `ide/package.json` or `ide/src/extension.ts`** — put the keybinding + `editorMenu` entry in your PR description as a delta snippet for the coordinator integration commit.
> **Verify (in `ide/`):** `npm ci && npm run typecheck && npm run compile && npm test`. Manually confirm each snippet inserts; run `python -m messagefoundry dryrun` on a module using them to confirm they parse.
> **Done:** quartet green; delta snippet handed to coordinator; local commit only. Effort **M**.

### Lane L2 — LIVE-DEBUG-V1 (#92 v1) *(Wave 1, no ADR)*

**Builds:** a status-bar "MEFOR Live" toggle (OFF by default) + a debounced `onDidSaveTextDocument` watcher that cancels superseded runs, shells `messagefoundry dryrun --json` against the selected synthetic sample under `messageSetsDir`, and renders **CodeLens-only** summaries. New `liveDebug.ts` registers its **own** `CodeLensProvider` — do **not** edit `editorToolbar.ts` (VS Code supports multiple providers per language; the two lens rows coexist — Review A note, uncertainty #4).

**Scope correction (folds Review A #1 — the plan's one real dependency error).** Today's `dryrun --json` is **one row per message**: `disposition` is per-message, `handlers` is a flat `string[]`, and `deliveries` (`DeliveryPreview`) has **no `handler` field** — `run_one_handler`'s per-handler deliveries are flattened (`deliveries.extend(ds)`, `dryrun.py:312`), dropping handler→delivery attribution. So an accurate per-`@handler` lens for a **multi-handler** module is **impossible without an engine change in L5's file**. v1 is therefore scoped to what today's JSON supports:
- a per-`@router` lens `▸ routed → [h1, h2]` (from `handlers`);
- a per-message/inbound **disposition** lens;
- a per-`@handler` delivery/Send-count lens **only when the run selected exactly one handler** (unambiguous).
Accurate multi-handler per-statement attribution is documented as a **v2/trace** feature (L6). *(Owner option, §H: if accurate multi-handler v1 lenses are wanted, add a `handler` tag to `DeliveryPreview` inside L5's ADR-0072 scope and make L2 formally depend on L5 — do not pretend v1 is engine-free.)*

**Row typing (folds Review A #4):** `DryRunRow` is a **private** interface in `testBench.ts` (line 13, not exported). L2 **redeclares** the row shape locally, or reuses the shared read-only `runJson<T>` helper from `cli.ts`. This is a decoupling win — L2 gains **no** compile dependency on `testBench.ts` (L4's file).

**Files owned:** `ide/src/liveDebug.ts` (NEW). **Deltas to coordinator:** `package.json` `messagefoundry.toggleLiveDebug` command + debounce `configuration` prop; `extension.ts` `registerLiveDebug(context)` + status-bar item.

> **Kickoff — branch `feat/ide-live-debug-v1-codelens`:**
> Create `ide/src/liveDebug.ts`: a status-bar "MEFOR Live" toggle (OFF by default) + a debounced `onDidSaveTextDocument` watcher that cancels superseded runs and shells `messagefoundry dryrun --json` against the selected synthetic sample under `messageSetsDir`. **Redeclare the row shape locally or use `cli.ts`'s `runJson<T>` — do NOT import the private `DryRunRow` from `testBench.ts`.** Render **CodeLens-only** summaries: per-`@router` `▸ routed → [handler…]`; per-message disposition; per-`@handler` Send count **only when exactly one handler ran** (multi-handler attribution is a v2/trace feature — do not fake it). **Register your OWN `CodeLensProvider` inside `liveDebug.ts`; do NOT edit `editorToolbar.ts`.** Synthetic samples only; toggle OFF by default. **No engine change.** **Do NOT edit `package.json`/`extension.ts`** — hand the `toggleLiveDebug` command + debounce config + `registerLiveDebug` + status-bar deltas to the coordinator.
> **Tests mock the CLI boundary** (folds Review B HIGH-1): integration tests stub the `dryrun` spawn to return canned JSON — no live engine dependency in `npm test`. A local `pip install -e ".[dev,console]"` is a convenience for **manual** `dryrun` smoke-testing only, never a test dependency.
> **Verify (in `ide/`):** `npm ci && npm run typecheck && npm run compile && npm test`.
> **Done:** quartet green with mocked CLI; deltas handed off; local commit only. Effort **M**.

### Lane L3 — COOKBOOK (#104) *(Wave 1, no ADR; new BACKLOG #104 from L0)*

**Builds:** a `contributes.walkthroughs` onboarding flow + a searchable "solved problems" gallery webview (pattern after `ide/src/home.ts`'s `HomeView`) whose entries **insert editable Python** via `editor.insertSnippet()`. Deterministic sibling for `/explain`.

**Bright-line guard (folds MED-5 — L3 is the one lane that owns a webview UI, the one most able to drift into a builder).** Cookbook recipes are **static, editable-Python snippets inserted verbatim**. **NO** input-driven code synthesis, **NO** field-mapping form, **NO** "customize this recipe" inputs that generate code, **NO** persisted declarative artifact. The webview is a **searchable index over static snippets, nothing more** — the same rule as L1's palette, restated because L3 owns a UI surface. All examples synthetic HL7 only.

**Files owned:** `ide/src/cookbook.ts` (NEW), `ide/media/*` (NEW). **Deltas to coordinator:** `package.json` `walkthroughs` array + `messagefoundry.openCookbook` command; `extension.ts` command/provider registration. *(May build against Proposed #104; the heading must be owner-blessed before merge.)*

> **Kickoff — branch `feat/ide-cookbook-walkthrough`:**
> Create `ide/src/cookbook.ts` — a searchable "solved problems" gallery webview (pattern after `ide/src/home.ts`'s `HomeView`) whose entries insert **static editable Python** via `editor.insertSnippet()`. Add `ide/media/*` walkthrough assets. **STRICT: static-snippet index only — no input-driven code synthesis, no field-mapping form, no "customize"/generate inputs, no persisted declarative artifact.** All examples **synthetic HL7 only**. **Do NOT edit `package.json`/`extension.ts`** — hand the `walkthroughs` array + `openCookbook` command + registration deltas to the coordinator.
> Tests mock any CLI boundary (no live engine in `npm test`).
> **Verify (in `ide/`):** `npm ci && npm run typecheck && npm run compile && npm test`; open the walkthrough + gallery and confirm an entry inserts Python.
> **Done:** quartet green; #104 heading confirmed owner-blessed before PR; deltas handed off; local commit only. Effort **M–L** (content-heavy).

### Lane L4 — TESTBENCH-DIFF (#84 diff slice) *(Wave 1, no ADR)*

**Builds:** replaces the webview's naive per-line string-equality diff in `testBench.ts` with an **HL7-segment/field-aware** diff — read MSH encoding chars (don't hardcode `|^~\&`), split segments/fields, align by segment + set-id, highlight at field granularity, render side-by-side. **Client-side TS** (the IDE re-implements minimal segment splitting in TS rather than importing `parsing/`). Add a hex pane for `mfb64:`/binary bodies if in reach. **No engine change** — does not touch `dryrun.py`/`__main__.py` (L5's surface). Profiling/coverage is L7.

**Files owned:** `ide/src/testBench.ts` (sole Wave-1 owner — `showDiff()`, the webview `<script>`, `DryRunRow`). Touches no manifest unless a hex-pane toggle command is added (then that too becomes a coordinator delta).

> **Kickoff — branch `feat/ide-testbench-hl7-diff`:**
> Replace the naive per-line diff in `ide/src/testBench.ts` (`showDiff()` + the webview `<script>`) with an **HL7-segment/field-aware** diff: read MSH encoding chars (don't hardcode `|^~\&`), split segments/fields, align by segment + set-id, highlight at field granularity; render side-by-side. Add a hex pane for `mfb64:`/binary bodies if in reach. **Client-side TS only — do NOT touch `dryrun.py`/`__main__.py` (L5's surface).** No profiling/coverage (that's L7). If you add a hex-pane toggle command, hand it to the coordinator as a `package.json` delta rather than editing the manifest.
> Tests mock any CLI boundary (no live engine in `npm test`).
> **Verify (in `ide/`):** `npm ci && npm run typecheck && npm run compile && npm test`; confirm an inserted/deleted segment no longer cascades false "changed" through following lines.
> **Done:** quartet green; local commit only. Effort **M**.

### Lane L5 — TRACE-ENGINE (#92 v2 / #84 engine dep) *(Wave 1b, ADR 0072; critical path)*

**Builds:** a new `dryrun --trace json` mode. A `sys.settrace`-based tracer wraps the handler/router call inside `dry_run()` and emits, per invocation, a line-addressable sequence of `(source_line, event, value)` records + the final disposition + `Sends`, as the ADR-0072 JSON schema. **No engine LOGIC change** — additive to the preview path only, sole engine editor.

**Live-lookup semantics (folds MED-3 — resolves the byte-identical vs "instead of crashing" contradiction):** `db_lookup`/`fhir_lookup` raise `DbLookupError` in dry-run, which today classifies the whole message **ERROR** (`_dry_run_raw`, `dryrun.py:369`). The traced run **must stay byte-identical** — the handler still terminates at the raise, disposition stays **ERROR**. The tracer only **classifies the terminal exception** as a live-lookup skip and adds a `live_lookup_skipped` annotation record; "graceful, not a crash" means the **IDE UI degrades** ("⚠ live lookup — not evaluated in preview"), **not** that the handler resumes.

**`sys.settrace` robustness (folds MED-4):** restore `prev = sys.gettrace()` in a `finally` (never `sys.settrace(None)` — it clobbers `pytest-cov`/`coverage.py` and corrupts L5's own test run); scope the trace function to the exact handler/router frame (`return None` for other frames); handle thread-locality (`settrace` is per-thread; the handler/`db_lookup` may run off the event-loop thread) — assert the handler runs on the tracer's thread or use `threading.settrace`; state the Python-3.14 PEP 669 `sys.monitoring` coexistence.

**PHI (critical — folds HIGH-2):** trace `value`s are PHI → **redacted by default**, real values only under an explicit, per-session, **non-persisted** opt-in (never auto-`--show-phi`); the trace JSON is **streamed in-process, never written to a persisted/committable temp file** (CLAUDE.md §9); runs only against synthetic corpora.

**Files owned:** `messagefoundry/pipeline/dryrun.py` (+ optional SPDX-headed `pipeline/dryrun_trace.py`), `messagefoundry/__main__.py` (`--trace` flag on the dryrun subparser @156; `_dryrun()` @1458 branches to the trace builder), new `tests/`.

> **Kickoff — branch `feat/dryrun-trace-mode` (ADR 0072 must be Accepted first):**
> Implement `dryrun --trace json` per ADR 0072. Add a `sys.settrace`-based tracer around the handler/router call in `messagefoundry/pipeline/dryrun.py` (or a new SPDX-headed `pipeline/dryrun_trace.py`) emitting ordered `(source_line, event, value)` records + disposition + Sends. **Restore `prev = sys.gettrace()` in `finally` (NOT `None`); scope the trace fn to the exact handler/router frame; handle thread-locality.** `db_lookup`/`fhir_lookup` → the handler **still terminates (disposition stays ERROR, byte-identical)**; the tracer emits a `live_lookup_skipped` annotation only. Add the `--trace` flag to the dryrun subparser (`__main__.py` ~line 156) and branch `_dryrun()` (~line 1458); **redact trace values unless `--show-phi`** (mirror existing gating); **stream in-process, never write a persisted temp file.** New tests under `tests/` MUST assert: (1) a traced run's disposition/Sends are **byte-identical** to a non-traced run; (2) a handler hitting an unstubbed `db_lookup` yields **identical disposition/Sends** with and without `--trace`; (3) a traced run **under `pytest-cov` leaves coverage intact** (prev-tracer restored). Confirm no concurrent `dryrun.py` edit from the ADR-0071 sibling before starting.
> **Verify (repo root, lane venv):** `$env:QT_QPA_PLATFORM="offscreen"; ruff check . ; ruff format --check . ; mypy messagefoundry ; pytest -q` — run the **FULL** suite, not a `tests/test_dryrun*` subset (partial runs have masked cross-file breakage — broke PR #525 CI).
> **Done:** quartet green (full suite); byte-identical + coverage-intact tests pass; local commit only. Effort **M–L**.

### Lane L6 — LIVE-DEBUG-V2 (#92 v2) *(Wave 2, ADR 0072; after L5 + L2)*

**Builds:** per-statement **inline decorations** (`x = msg[..] ▸ "12345"`) + hover full values, driven by `dryrun --trace json`. Extends L2's `liveDebug.ts` (same watcher/debounce/toggle; upgrade the renderer from CodeLens-summary to inline + CodeLens).

**PHI (folds HIGH-2):** inline values are PHI (e.g. `msg["PID-3"]` = MRN) rendered in the gutter, capturable in screenshots/screen-share. Default render is a **redacted placeholder (`▸ ⋯`)**; real values appear **only** under an explicit, per-session, non-persisted "reveal values" opt-in that is **independent of** the "MEFOR Live" toggle and **never auto-passes `--show-phi`**. `live_lookup_skipped` records render "⚠ live lookup — not evaluated in preview" (don't crash the run).

**Files owned:** `ide/src/liveDebug.ts` (extend L2 — rebase over L2). **Delta to coordinator:** any new inline-toggle `package.json` config prop.

> **Kickoff — branch `feat/ide-live-debug-v2-inline` (after L5 + L2 merge):**
> Extend `ide/src/liveDebug.ts` to render per-statement inline decorations + hover, driven by `dryrun --trace json`. **Values render as redacted placeholders (`▸ ⋯`) by default; real values only under an explicit per-session, non-persisted "reveal values" opt-in that is independent of the "MEFOR Live" toggle and never auto-passes `--show-phi`.** Annotate `live_lookup_skipped` records as "⚠ live lookup — not evaluated in preview". Keep the L2 watcher/debounce/toggle. Rebase over L2 (`liveDebug.ts`) and L5 (CLI contract). Hand any new config prop to the coordinator. Tests **mock the trace CLI boundary** (canned trace JSON) — no live engine in `npm test`.
> **Verify (in `ide/`):** `npm ci && npm run typecheck && npm run compile && npm test`.
> **Done:** quartet green with mocked trace; redaction default verified; local commit only. Effort **M**.

### Lane L7 — TESTBENCH-PROFILING (#84 prof/cov slice) *(Wave 2, ADR 0072; after L5 + L4)*

**Builds:** profiling pane (per-line/per-handler timings from the trace) + coverage pane (executed handler/router lines) in Test Bench, consuming `dryrun --trace json`.

**Files owned:** `ide/src/testBench.ts` (extend L4 — rebase over L4). **Delta to coordinator:** pane-toggle commands.

> **Kickoff — branch `feat/ide-testbench-profiling-coverage` (after L5 + L4 merge):**
> Add profiling (per-line/per-handler timings) + coverage (executed lines) panes to `ide/src/testBench.ts`, consuming `dryrun --trace json`. Rebase over L4 (`testBench.ts`) and L5 (CLI contract). Hand pane-toggle commands to the coordinator. Tests **mock the trace CLI boundary** — no live engine in `npm test`.
> **Verify (in `ide/`):** `npm ci && npm run typecheck && npm run compile && npm test`.
> **Done:** quartet green with mocked trace; local commit only. Effort **M–L**.

---

## D. Contention matrix

| File(s) | Lanes | Resolution |
|---|---|---|
| **`ide/package.json`** (`commands`/`menus`/`keybindings`/`configuration`/`walkthroughs`) | **L1**·**L2**·**L3**·(**L4** optional)·**L6/L7** | **Not edited by lanes.** Each lane hands a documented delta snippet to the coordinator; a single **coordinator-owned integration commit** applies all deltas at land time, then runs `npm run typecheck && npm run compile` (folds Review A #2 — promotes the ex-fallback to the primary path, removing the rebase chain and making Wave 1 genuinely parallel). Verified: all four Wave-1 deltas target **disjoint, net-new** keys (the `editorMenu` submenu already exists without an insert-element entry), so this is textual-only. |
| **`ide/src/extension.ts`** (`activate()` registrations) | **L2**·**L3** | **Not edited by lanes.** L2/L3 hand their two-line `context.subscriptions.push(...)` registration deltas to the coordinator integration commit alongside the manifest deltas. **L1 and L4 do NOT touch this file** (`registerInsertElement` line 72 / `TestBench` line 73 already wired — verified). |
| **`ide/src/testBench.ts`** (`showDiff()`, webview `<script>`, `DryRunRow`) | **L4** (Wave 1)·**L7** (Wave 2) | Not concurrent — **L7 rebases over L4**; the wave gap resolves it. |
| **`ide/src/liveDebug.ts`** | **L2** (create)·**L6** (extend) | Not concurrent — **L6 rebases over L2**. |
| **`ide/src/editorToolbar.ts`** (`ConfigCodeLensProvider`, line 62) | **L1** only | L1 sole owner. **L2 registers its OWN provider in `liveDebug.ts`** — VS Code allows multiple CodeLens providers per language, so the lenses coexist (cosmetic stacking above `@handler` — verify no ordering surprise). |
| **`ide/snippets/…code-snippets`** · **`insert-element.test.ts`** | **L1** only | L1 sole owner. |
| **`messagefoundry/pipeline/dryrun.py` + `__main__.py::_dryrun`** | **L5** only | **L5 sole engine editor.** L6/L7 consume the resulting CLI JSON contract; never edit these files. Verified the ADR-0071 sibling touches neither → collision-free (still re-check before L5 starts). |
| `docs/adr/` (NEW 0072 + README row) · `docs/BACKLOG.md` (#104 + banners) · `docs/AI-OFF-MATRIX.md` · CLAUDE.md §3 · `ide/README.md` · `docs/USER-GUIDE.md` | **L0** | Coordinator-owned, single-writer. Land `## 104.` via a throwaway worktree off fresh `origin/main`. |

> **Never edit a sibling worktree.** Shared-manifest edits are handled by the coordinator integration commit — coordinated *before* land, not discovered after.

---

## E. Coordination rules

1. **Worktree per lane**, branched off `origin/main` @ `0f0ba08`. Never edit a sibling worktree. Use the lane's own `.venv` (a shared venv binds to one source path and would silently test the wrong checkout — see `docs/WORKTREES.md`).
2. **ADR-gated:** L5/L6/L7 do not write product code until **ADR 0072 is Accepted** by the owner. L1–L4 need no ADR and may start on `origin/main` immediately.
3. **Single-writer coord ledger** in AI memory — one session writes the live status; others read. One logical lane per session. (AI project memory is shared across worktrees — coordinate writes; don't let two chats write it at once.)
4. **L1 autonomy:** build + verify + commit **local**; the owner opens/merges PRs and ratifies ADRs. Don't push/PR or merge without an explicit owner "go".
5. **Shared manifests via a coordinator integration commit, not lane edits.** L1–L4 (and L6/L7) ship **only their own new/owned files** plus a documented `package.json`/`extension.ts` delta snippet in the PR description. The coordinator applies all deltas in one integration commit and runs `npm run typecheck && npm run compile`. This is what lets Wave-1 IDE lanes build in genuine parallel (folds Review A #2).
6. **IDE integration tests mock the CLI boundary** (folds Review B HIGH-1): the CI `ide` job has **no Python/engine** (`.github/workflows/ci.yml` 185–225: `npm ci → typecheck → compile → npm test`, Windows-only, no `setup-python`/`uv`). Any test that shells `dryrun`/`dryrun --trace` **must stub the spawn to return canned JSON** — a live engine dependency passes locally but is red/unrunnable in CI (false-green). A local `pip install -e ".[dev,console]"` is a **manual smoke-test convenience only**, never a test dependency. *(If a live-engine test is genuinely required, the plan must instead add `setup-python` + `uv` + `pip install -e ".[dev,console]"` to the `ide` job's **Windows leg only** — heavier, call it out explicitly.)*
7. **Land-order:** Wave 0 → Wave 1 (parallel) + Wave 1b (L5, ADR-gated) → integration commit → Wave 2 (L6/L7, each rebasing over its base + L5).
8. **`git add` explicit paths** (the repo guard blocks `git add -A`/`.`/`-u`/`--all` and `git commit -a`). Stage named paths only, and **omit the `Co-Authored-By` trailer** (the CLA bot fails on it — `mf-no-coauthor-trailer`).
9. **Leak-gate discipline:** these lanes are IDE/DX and touch no customer data — but any snippet/cookbook/sample uses **synthetic HL7 only**, never real partner names/IPs/site codes; never commit `migration-local/` or other gitignored customer data.

---

## F. Build gotchas (checklist — apply on every lane)

1. **Check for an already-merged duplicate first.** `git fetch` + `git log origin/main --oneline` + `gh pr list --state all` — a parallel session may have shipped part of #92/#84/#48-ext already (`mf-handoff-check-existing-prs`).
2. **L5 runs the FULL offscreen pytest suite**, not just `tests/test_dryrun*` — partial runs have masked cross-file breakage (broke PR #525 CI).
3. **`.[dev,console]` does NOT unlock the full matrix (LOW-7).** The dryrun/trace tests are in the **core install**, so `.[dev,console]` suffices for **L5's own** tests. The full ~9.5k matrix needs all extras (`dicom`/`webauthn`/`postgres`/SQL-Server) + SS/PG containers that **CI** provides — worktree venvs run only ~3.8k (`mf-ci-test-flakes`). **Local green ≠ full-matrix green; rely on the CI `test` legs for the remainder.** Don't imply `.[dev,console]` unlocks the full suite.
4. **IDE tests must NOT depend on a live engine (Review B HIGH-1).** Mock the `dryrun`/`dryrun --trace` spawn (canned JSON) — see §E.6. The CI `ide` job has no Python.
5. **`sys.settrace` robustness (L5 — MED-4):** restore `prev = sys.gettrace()` in `finally` (not `None`, to preserve `pytest-cov`); scope the trace fn to the exact handler/router frame; handle per-thread locality; state Python-3.14 PEP 669 coexistence; pin value-capture timing (line events fire on line *entry*). A traced run's disposition/Sends must be **byte-identical** to a non-traced run.
6. **PHI streaming, no temp file (L5/L6 — HIGH-2):** trace JSON is streamed in-process, never written to a persisted/committable temp file (CLAUDE.md §9); values redacted by default; un-redaction is an explicit, per-session, non-persisted opt-in — never auto-`--show-phi`.
7. **NEVER commit customer data** — all snippet/cookbook/sample content is **synthetic HL7 only**; no `migration-local/`, no real partner IPs/ports/site codes.
8. **SPDX header on every NEW `.py`** — L5 if it adds `pipeline/dryrun_trace.py`. New `.ts` files (`liveDebug.ts`, `cookbook.ts`) follow the existing `ide/src` header convention, not SPDX.
9. **Crypto-inventory gate:** N/A — no lane imports `hashlib`/`hmac`/`secrets`/`ssl`/`cryptography`/`argon2` (`sys.settrace` is not crypto). If L5 unexpectedly pulls one in, register it in `scripts/security/crypto_inventory_check.py`.
10. **DEP-1 re-lock:** no lane adds a **runtime** Python dep (trace mode is stdlib). If L3 adds an npm devDependency, commit the updated `ide/package-lock.json` (`npm ci`). No `uv lock` unless a `pyproject.toml` runtime dep appears.
11. **BACKLOG `## N.` headings collide across parallel worktrees** — land **#104** via a throwaway worktree off fresh `origin/main`, re-checking the current highest heading first (highest today = `## 103.`). Same for the ADR number (skip 0070; re-check `git log origin/main -- docs/adr/`).
12. **The `ide` CI job is path-gated + not required.** It runs only on `ide/**` (or `ci.yml`) changes, **PR-only**, matrix `ubuntu`+`windows`, `npm test` **Windows-only** (Linux stops after `compile`), and is **not** in `ci-gate`'s `needs` — an IDE-only PR can merge without it blocking. Each lane must still be green locally (this box is win32) before the owner PRs.

---

## G. ADRs (L0; coordinator-authored, owner-ratified)

> **⚠ Re-check the highest ADR on `origin/main` before authoring** — highest on disk = **0071**; **0072** is next free; **0070 is reserved-elsewhere** (unmerged `docs/adr-0070-t17-infra-fault`) — do not reuse it. A sibling worktree may have claimed 0072; re-number if so.

| ADR | Title (working) | For | State / target |
|---|---|---|---|
| **0072** | Traced-dryrun mode + trace schema — `dryrun --trace json` via `sys.settrace`; per-invocation `(source_line, event, value)` sequence + disposition + Sends; **capture semantics** (prev-tracer restore, frame-scoping, thread-locality, PEP 669, line-entry timing); **PHI** redacted-by-default + streamed-not-persisted + explicit non-persisted un-redaction opt-in; `db_lookup`/`fhir_lookup` → handler terminates (**ERROR, byte-identical**) + `live_lookup_skipped` annotation (UI degrades, handler does **not** resume); preview-only, no dispatch/logic change | #92 v2 (L6), #84 prof/cov (L7), engine build (L5) | **NEW** — Proposed → **Accepted before L5 builds**; gates L6/L7 |

**No ADR:** **L1** (additive ext of shipped #48/#595) · **L2 #92 v1** (IDE-only, reads today's `dryrun --json`, scoped to available granularity) · **L3 Cookbook** (IDE content; governed by new BACKLOG **#104**) · **L4 #84 diff** (client-side TS). The **AI-off completeness matrix** is a `docs/` deliverable, not a decision record.

---

## H. Owner / decision-gated callouts

- **ADR 0072 (L5/L6/L7)** — owner ratification of the schema + capture semantics + **PHI posture** (redacted-by-default, non-persisted un-redaction opt-in, streamed-not-persisted, synthetic-corpora-only) is the gate. L5/L6/L7 do not start on plan-approval alone.
- **BACKLOG #104 (L3)** — owner promotion of the Cookbook item; L3 may build against a Proposed #104 but the heading must be owner-blessed before merge.
- **L2 v1 granularity (Review A #1)** — the default keeps v1 **engine-free** (router lens + per-message disposition + single-handler Send count). **Owner option:** if accurate multi-handler per-`@handler` lenses are wanted in v1, add a `handler` tag to `DeliveryPreview` **inside L5's ADR-0072 scope** and make L2 formally depend on L5. **Decide before L2's scope is frozen.**
- **L4 client-side-vs-CLI diff (uncertainty #2)** — L4 does the HL7-aware diff **client-side in TS** to stay Wave-1 engine-collision-free. If the owner prefers CLI-emitted segment-tagged JSON, that pulls L4 into the L5 engine surface / ADR 0072 / Wave 2. **Decide before L4 starts.**
- **`/migrate` → deterministic Corepoint-import (deferred tail)** — owner decides whether/when to scope this larger item; not agent-buildable in this plan. L0 surfaces it from the AI-off matrix as a NEW deferred BACKLOG item.

---

## I. BACKLOG / ADR-index / docs reconciliation — folded into L0 commit 1

No separate reconciliation lane. L0's first commit:
- **`docs/BACKLOG.md`** — under **#48**, mark the "surface *Insert Element…*" follow-up (#593) as **delivered by L1**, worded "**add the *Insert Element…* entry to the existing `editorMenu` submenu**" (the submenu already exists at `package.json` 161/167/174 — L1 appends an entry, it does not create the dropdown; LOW-8). Add the **#104** Cookbook heading + the deferred `/migrate` item. Confirm **#84** (P3) and **#92** (P1, Proposed) banners reflect this plan's phasing (#92 → v1/v2; #84 → diff now / profiling+coverage on the trace).
- **`docs/adr/README.md`** — add the **0072** row (Proposed → Accepted on ratification).
- **`docs/AI-OFF-MATRIX.md`** (new) — the subcommand→sibling table.
- **Docs-sync (LOW-8):** CLAUDE.md §3 ide-line + `ide/README.md` feature list + `docs/USER-GUIDE.md` enumerate live-debug + Cookbook + expanded palette. **ADR-0017 unchanged** (no deployment-model change — the plan is right not to touch it).

Everything else on the IDE/DX board is unchanged; PLAN-6's deployment/DR board is disjoint and untouched.

---

## Verification gate & Definition of Done

**IDE lanes (L1, L2, L3, L4, L6, L7)** — matches the CI `ide` job (`working-directory: ide`):
```
1. npm ci            # clean install from ide/package-lock.json
2. npm run typecheck # tsc --noEmit
3. npm run compile   # node esbuild.js
4. npm test          # @vscode/test-electron headless — Windows leg only (this box is win32)
```
Integration tests **mock the CLI boundary** (canned `DryRunRow`/trace JSON) — **no live engine** in `npm test` (§E.6). Local `pip install -e ".[dev,console]"` is a manual `dryrun`-smoke convenience only.

**Engine lane (L5)** — the Python quartet:
```
1. ruff check .
2. ruff format --check .
3. mypy messagefoundry            # strict
4. $env:QT_QPA_PLATFORM="offscreen"; pytest -q   # FULL suite, not a subset
```
L5's suite must include: (1) traced-vs-untraced **byte-identical** disposition/Sends; (2) unstubbed `db_lookup` **identical** with/without `--trace`; (3) traced run under `pytest-cov` **leaves coverage intact**.

No lane here is store-touching → **no 3-backend parity suite**. **L0** is docs-only → no quartet.

**Definition of Done (every lane):**
- [ ] First action ran `git fetch && git log origin/main --oneline && gh pr list --state all` (no duplicate already merged).
- [ ] Lane's full quartet green locally (IDE quartet or Python quartet).
- [ ] The lane's kickoff "done" criteria met.
- [ ] Shared-manifest edits handed to the coordinator as delta snippets — the lane edited **no** sibling-shared file directly.
- [ ] All sample/snippet/cookbook content is **synthetic HL7 only**; no customer data; no `migration-local/`.
- [ ] (L5/L6) PHI redaction default verified; no persisted trace temp file; no auto-`--show-phi`.
- [ ] Commit is **local**, explicit-path staged, **no `Co-Authored-By` trailer** — awaiting the owner's PR/merge.
- [ ] ADR-gated lanes (L5/L6/L7) confirmed ADR 0072 **Accepted** before writing product code.

---

*This is a planning artifact, not a gate. Nothing is built until the owner gives an explicit "go"; every ADR-gated lane waits for owner ratification (Proposed → Accepted) before any product code is written.*

