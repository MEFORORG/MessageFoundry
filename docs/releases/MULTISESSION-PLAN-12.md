# MessageFoundry — Multisession Execution Plan 12 (2026-07-16)

> 📁 **Per-session phase documents: [`plan-12/`](plan-12/README.md)** (authored with this plan). Each build session
> has its own maintainable doc under `docs/releases/plan-12/` — **when a session's items land, update only its phase
> doc** (and the status cell in the [dir index](plan-12/README.md)), not this file. This master stays the **shared
> index**: wave sequencing (§B), the contention matrix (§C), coordination rules (§D), the ADR/overlap reconciliation
> (§E), and coverage (§F). The §A roster below is an at-a-glance summary; the phase docs are authoritative for
> per-session status.

**Grouping the 4 owner-selected backlog items (#230 · #234 · #235 · #238) into 10 parallel-safe, single-subsystem
build sessions across 4 waves so that no two sessions in the same wave ever co-own a file** (two deliberate
exceptions — `docs/BACKLOG.md`, line-disjoint; `docs/adr/README.md`, row-disjoint — both mitigated in §C). One session (`engine-230-dryrun-parity`) is
**optional** and droppable without weakening anything else. Method: **coordinator + one worker per session in its own
worktree (`scripts/worktree/new.ps1 -Name plan12-<lane>`); workers build + verify + local-commit; the owner opens and
approves every PR.** Every work package below was grounded against the code, designed, and **adversarially verified
(two lenses per item, 2026-07-16)**; all `must_fix` corrections are absorbed into the phase docs and recorded in
§E.b. Status: **COMPLETE (2026-07-16 — all four items ✅; 10/10 sessions; PRs #1073–#1081 + this close-out).**

> **Progress / premise corrections at authoring (2026-07-16, git-verified against `origin/main` @ `8e413919`;
> per-item ✅ banner in `docs/BACKLOG.md` + `CHANGELOG.md` remain authoritative):**
>
> - **#230's tracker text is STALE — do not build what it says.** The ADR 0104 §2.3 Q3 **Steps-view HL7 field picker
>   SHIPPED** (PR #1001, commit `5b90a695`, authored 2026-07-13 UTC, an ancestor of `origin/main`;
>   `ide/src/hl7Picker.ts` + `hl7scope.ts` + Steps-view pickPath wiring). The genuine remainder is **ADR 0104 §2.3
>   Step 1** (inline autocomplete extension) + optional fast-follows. Session `docs-230-errata` corrects the ledger
>   and **must merge before any tracker-guided #230 build starts (S5; the optional, tracker-independent S6 is
>   exempt)**.
> - **#238's coordination premise is STALE — branch from `main`.** The ADR 0112 pill work is **merged**
>   (PR #1067, `c2239a05`, ancestor of `origin/main`); the `pill-engine-lifecycle` worktree tip `eb560f38` is
>   tree-identical to it and **behind** main (missing #1068–#1071 / IDE v0.0.31). BACKLOG #238's "build it as an
>   increment on the pill work, not a parallel branch" is satisfied by branching from `main` — do **not** resume the
>   dormant branch.
> - **#238's three pre-code owner decisions were RATIFIED 2026-07-16** (this authoring session): (a) in-file **ADR
>   0112 amendment** (appended, same commit as this plan); (b) the setup page **does** offer the test-only dev
>   engine (context-honest copy); (c) the lead stays **`canControl`-only**. `ide-238-setup` is clear to build.

> **Close-out (2026-07-16).** Executed same-day, all four waves: #230 ✅ (errata → autocomplete → CLI parity), #238 ✅ (guided setup page, IDE v0.0.32), #235 ✅ (T-SQL port → CI proof on PR #1078's 2022+2025+PG legs → atomic flip + ADR 0006 amendment), #234 ✅ (writer parity → IDE merge fix, v0.0.34 → close-out with corrected casualty accounting). Follow-ups filed as **#240** (GUI write-path hygiene: sibling writers + wizard collision) and **#241** (execution findings roll-up — a deliberate second allocation beyond §D's one, for findings surfaced during the waves). The optional S6 was included. Two mid-flight corrections the process caught: the S7 test battery's shared-DB cipher poisoning (fixed, tests-only) and one unrelated test_mfa CI flake (re-run green; watch-listed in #241).

---

## Start here — immediately actionable (Wave 1, no upstream dependency)

| Item | Session (wave) | Pri | Gate | What |
|---|---|---|---|---|
| #230 | docs-230-errata (W1) | P2 | none — **merge FIRST** | Kill the stale tracker: #230 entry + ADR 0104:3 + ADR 0089 erratum |
| #235 | store-235-port (W1) | P2 | none | T-SQL reference-set port in `store/sqlserver.py`; capability flag stays `False` |
| #234 | config-234-writer (W1) | P1 | none | Derived write schema + parity guard + fail-loud unknown keys + `connection list` canonicalization |
| #238 | ide-238-setup (W1) | P2 | ~~owner ratification~~ **done 2026-07-16** | Pill lead swap + guided setup webview + ADR 0112 amendment build-out |

---

## A. Session roster

| Wave | Session | Items | Effort | Owns (files / seams) | Notes |
|---|---|---|---|---|---|
| 1 | docs-230-errata | #230 (P1 of 4) | 0.5 | `docs/BACKLOG.md` #230 entry (:6811–6829), `docs/adr/0104-…md:3`, `docs/adr/0089-…md:3-5,73`, `docs/adr/README.md` 0104/0089 rows (check) | Docs-only; no numbers allocated. **Must merge before S5, the tracker-guided #230 build (the optional S6 is tracker-independent).** Cite `5b90a695` as 2026-07-13 UTC; the CI artifact test is a recompute-and-compare parsed-JSON equality gate, not "byte-equal". |
| 1 | store-235-port | #235 (P1 of 3) | 1 | `messagefoundry/store/sqlserver.py` | Flag stays `False` — tree stays green. Verdict-corrected: `_encrypt_existing_rows` reference pass IN scope; UTF-16 code-unit key guard (+ `name`); binary collation (`…BIN2`) on `name`/`version`/`[key]`; no raw key in errors (PHI); post-commit cache **and** versions bookkeeping. |
| 1 | config-234-writer | #234 (P1+P2 of 4) | 2 | `messagefoundry/config/connections_edit.py`, `tests/test_connections_file.py`, `tests/test_connections_roundtrip.py` (new), `tests/test_connections_cli.py` | Verdict-corrected arithmetic: read-schema union = **33 distinct keys** (25 in / 16 out, 8 shared; **41 per-direction slots**); casualty = **19 per-direction slots / 16 distinct keys incl. inbound `metadata`**. Adds the absent-key-deletes pin test. `__main__.py` deliberately UNCHANGED. |
| 1 | ide-238-setup | #238 (all) | 2 | `ide/src/engineStatusModel.ts`, `ide/src/engineSetup.ts` (new), `ide/src/engineSetupContent.ts` (new), `ide/src/extension.ts`, `ide/package.json`(+lock), `ide/src/test/suite/engine-control.test.ts`, `engine-setup.test.ts` (new), `docs/adr/0112-…md` (build-state rider), `docs/adr/README.md` 0112 row, `docs/BACKLOG.md` #238 flip | **Branch from `main`** (pill premise stale — see progress note). Ratifications done. Takes `ide/package.json` **0.0.32** (W1 ide-hotspot owner). **Manual ide-leg merge hold** (§D). Dispatch discipline mirrors `statusBar.ts` (execute a known CMD from the content model). |
| 2 | ide-230-autocomplete | #230 (P2+P3 of 4) | 1.5 | `ide/src/completionScope.ts` (new, vscode-free), `ide/src/completion.ts`, `ide/src/hl7scope.ts`, `ide/src/hl7schema.ts`, `ide/src/test/suite/completion-scope.test.ts` (new), `ide/package.json`(+lock) | **Gate: S1 merged.** Rebases over #238's merge → takes **0.0.33**. KWARG_CTX + every unit-tested helper live in the **pure module** (`npm run test:unit` is plain-node mocha). Multi-line decorator-run capture is **new logic** (`symbolIndex.ts` `classify()` is single-line-only). Hard bar: no structures / no typed handler ⇒ byte-identical completion; rank-never-remove. |
| 2 | engine-230-dryrun-parity | #230 (P4, **OPTIONAL**) | 0.5–1 | `messagefoundry/__main__.py` (dryrun ~:2076-2086), `messagefoundry/checks.py` (_check_dryrun region), `messagefoundry/pipeline/dryrun.py` (docstring), **`messagefoundry/pipeline/dryrun_trace.py`** (snapshot passthrough), `tests/test_checks*.py`, `tests/test_dryrun*.py` | Droppable without weakening anything. Verdict-corrected: `dryrun_trace.py` **must** gain the passthrough or `--trace` breaks its byte-identical contract; no-settings fallback = the Settings-model **default (True)**, not False; library defaults stay False (ADR 0104 §8.1). Also fixes the `hl7structures.py:19` "byte-equal" docstring mislabel — **if S6 is dropped, fold that one-line fix into S8's grep-for-stub-prose pass** (else it's orphaned). |
| 2 | store-235-ci-tests | #235 (P2 of 3) | 1 | `tests/test_sqlserver_store.py`, `tests/test_reference_sets.py`, `tests/test_postgres_store.py` | **Gate: S2 merged.** Fixture clean-slate DELETE list += `reference`,`reference_version` (else the exact `== 6` rotation count at `test_sqlserver_store.py:879` breaks). First-ever reference-row **rotation** tests on all three backends; collation round-trip; UTF-16 boundary trio; no-key→key reopen migration; follower converge + `== []` pin. **Owner-approved mid-stream push** — the server-DB CI legs are the only authoritative T-SQL proof. Green legs = HARD GATE for W3. |
| 3 | store-235-flip | #235 (P3 of 3) | 0.5–1 | `messagefoundry/store/sqlserver.py` (flag), `pipeline/wiring_runner.py` + `checks.py` + `store/base.py` + `pipeline/engine.py` (refusal/docstring prose), `docs/CONFIGURATION.md:101`, `docs/adr/0006-…md` (dated amendment), `docs/adr/README.md` 0006 row, `docs/BACKLOG.md` #235 flip, `tests/test_reference_sets.py`, `tests/test_store_capability_matrix.py`, `tests/test_checks.py` | **ONE commit** (the capability-matrix test parses the doc table — pieces break individually). **Gate: S7's sqlserver-store AND postgres-store legs green.** Rebases over S6's `checks.py`/`test_checks.py` edits if S6 ran. Amendment facts verdict-corrected (§E.b). |
| 3 | ide-234-merge-fix | #234 (P3 of 4) | 1 | `ide/src/connectionMerge.ts` (new, pure), `ide/src/connectionEditor.ts`, `ide/src/configEditors.ts`, `ide/src/test/suite/connection-merge.test.ts` (new), `ide/package.json`(+lock) | **Gate: S3 merged** (else the merged post is re-stripped server-side / the feeding list crashes on schedule-bearing files). Takes **0.0.34** (W3 ide-hotspot owner). Merge applies ONLY when `posted.direction === initial.direction` (clone keeps direction editable). **BACKLOG #234 flip deferred to S10** (keeps W3's BACKLOG touch with S8 alone). Name-collision overwrite hole: fix here or explicitly re-scope + drop the "closes the class entirely" claim. |
| 4 | docs-234-closeout | #234 (P4 of 4) | 0.5 | `docs/BACKLOG.md` (#234 flip + **new follow-up item via `alloc.ps1`** — the plan's ONLY number allocation), `docs/CONNECTIONS.md` | Full CLAUDE.md §5 gauntlet on the final merged tree. Publishes the **corrected** casualty accounting (19 per-direction slots / 16 distinct keys incl. inbound `metadata`; `source_ip_allowlist` called out as a security regression). Records that full-replace semantics were deliberately retained (no ADR 0007 flip). Files the sibling-writers follow-up (`codeset_edit.py`/`alerts_edit.py` idiom, + the name-collision hole if S9 re-scoped). |

---

## B. Waves & sequencing

**Wave 1 (4 parallel worktrees).** Four disjoint lanes — docs (`docs-230-errata`), store (`store-235-port`), engine
config (`config-234-writer`), ide (`ide-238-setup`). The only shared files are `docs/BACKLOG.md` (S1 rewrites the
#230 entry at :6811–6829; S4 flips #238 at :6986–7005 — ~175 lines apart, merges clean; serialize the merges anyway)
and `docs/adr/README.md` (S1 checks the 0104/0089 rows; S4 updates the 0112 row — row-disjoint). **S1 merges first,
unconditionally** — it is the defense against the rebuild-the-shipped-picker failure mode. S4 merges next (sole
`extension.ts`/commands-array toucher; claims `ide/package.json` 0.0.32), then S2/S3 in either order (fully disjoint).

**Wave 2 (3 parallel worktrees).** `ide-230-autocomplete` (gate: S1 merged; rebases over S4, takes 0.0.33),
`engine-230-dryrun-parity` (optional; floats free — merging it before S8 keeps the `checks.py` rebase burden on S8,
which expects it), `store-235-ci-tests` (gate: S2 merged; ends in the **hard CI gate** — sqlserver-store + postgres-
store legs green on an owner-approved mid-stream push). File-disjoint: ide completion files vs engine dryrun files vs
store test files.

**Wave 3 (2 parallel worktrees).** `store-235-flip` (gate: S7's legs green; owns this wave's `checks.py`,
`test_checks.py`, `docs/BACKLOG.md` touches) and `ide-234-merge-fix` (gate: S3 merged; ide files only — its BACKLOG
flip is deferred to W4 precisely because the #234/#235 entries are line-**adjacent** at :6922/:6923). S8 rebases over
S6's `checks.py`/`test_checks.py` edits if S6 ran. S8 and S9 are mutually independent.

**Wave 4 (solo).** `docs-234-closeout` sweeps the fully-merged tree, files the follow-up item through the ledger
gate, and publishes the corrected #234 ledger entry.

**Strict chains:** S2→S7→S8 (port → CI-proof → flip) · S3→S9→S10 (writer → IDE half → close-out) · S1→S5 (errata →
autocomplete). Everything else is parallel-safe.

---

## C. Contention matrix

Each hotspot is held to **one owner per wave**:

| Hotspot file | Owner by wave |
|---|---|
| `ide/package.json` (+`package-lock.json`) | W1: ide-238-setup (0.0.32, + commands array) · W2: ide-230-autocomplete (0.0.33) · W3: ide-234-merge-fix (0.0.34) — **never hardcode a sibling's version; later merger rebases and takes the next patch** |
| `docs/BACKLOG.md` | W1: docs-230-errata (#230 entry) + ide-238-setup (#238 entry — line-disjoint, serialize merges) · W3: store-235-flip (#235 entry) · W4: docs-234-closeout (#234 entry + new item; **#234/#235 entries are ADJACENT** — hence the W3/W4 split) |
| `messagefoundry/checks.py` | W2: engine-230-dryrun-parity (`_check_dryrun`) · W3: store-235-flip (`_check_reference_backend` prose) — line-disjoint, **never in the same wave**; S8 rebases |
| `tests/test_checks.py` | W2: engine-230-dryrun-parity · W3: store-235-flip — same rule |
| `messagefoundry/store/sqlserver.py` | W1: store-235-port · W3: store-235-flip (flag `:1044` + comment only) — intra-#235 cross-wave chain; S8 rebases |
| `tests/test_reference_sets.py` | W2: store-235-ci-tests · W3: store-235-flip (`:588` flip) — same chain; S8 rebases |
| `docs/adr/README.md` | W1: docs-230-errata (0104/0089 row check) + ide-238-setup (0112 row — row-disjoint) · W3: store-235-flip (0006 row) |
| `ide/src/extension.ts` | W1: ide-238-setup only (registration block beside cookbook) |

**Non-collisions worth recording so nobody invents them:** `messagefoundry/__main__.py` is edited only by
`engine-230-dryrun-parity` (#234's Phase 2 deliberately leaves it UNCHANGED — list-boundary canonicalization, not a
`_print_json` `default=`). #235 has zero source overlap with the other items outside `checks.py`/`test_checks.py`/
`BACKLOG.md`/adr-README. #230's completion files are disjoint from #238's engine-pill files and #234's editor files.
Store test files are #235-only; connections test files are #234-only.

---

## D. Coordination rules & gotchas

- One worktree / branch / `.venv` per session: `scripts/worktree/new.ps1 -Name plan12-<lane>`
  ([docs/WORKTREES.md](../WORKTREES.md)). Re-check in-flight ownership before starting (`git worktree list`,
  `gh pr list --state all`, `git log origin/main`).
- Every PR: `git merge main` first (the CI gate hangs otherwise). **No `Co-Authored-By: Claude` trailer** (the CLA
  bot fails on it). The finishing PR carries `BACKLOG #N` and flips that item's banner.
- Verify order (engine sessions): `ruff check` + `ruff format --check` → `mypy` (strict) →
  `QT_QPA_PLATFORM=offscreen pytest -q`. IDE sessions: `cd ide && npm run typecheck && npm run compile &&
  npm run test:unit` — and **`npm run test:unit` is plain-node mocha: never export test helpers from a
  vscode-importing module**; every unit-tested helper lives in the pure sibling (`completionScope.ts`,
  `engineSetupContent.ts`, `connectionMerge.ts`).
- **The ide CI leg is NOT a required check and auto-merge is on** — an ide PR can merge with the leg red or still
  running. Every ide PR (S4/S5/S9) gets an explicit **manual hold**: do not enable auto-merge or approve until the
  ide leg reports green. (Proposing to make the leg required is an owner decision, out of scope here.)
- **#235 is a store-schema touch** → server-DB proof via the path-gated **sqlserver-store (2022+2025 image matrix)**
  + **postgres-store** CI legs. Local pytest **silently skips** without `MEFOR_TEST_SQLSERVER=1` — a locally-green
  run proves nothing about the T-SQL. **Never flip `supports_reference_sets` before those legs are green** (flipping
  makes the engine ACCEPT `Reference(...)` graphs on the production backend — fail-closed invariant).
- PHI: reference keys may be PHI for patient-keyed sets — **no raw key in any error text** (set name + key
  length/ordinal/truncated-hash only). Never commit `dryrun`/`generate` stdout; synthetic HL7 only (CLAUDE.md §9).
- Number allocation: the **only** `alloc.ps1` run in this plan is S10's follow-up backlog filing (`-Kind backlog`).
  Errata and in-file ADR amendments allocate **nothing**. ADR amendments (0112 done at authoring; 0006 in S8) update
  their `docs/adr/README.md` index-row Status cell in the **same commit**.
- Do not weaken at-least-once / count-and-log / fail-closed / ACK-on-receipt invariants (CLAUDE.md §2). None of
  these sessions touches the stage handoff or the ACK contract; if scope drifts that way, stop and re-plan.

---

## E. Decisions, ADRs & overlaps

**(a) ADR work in this plan — no new numbers anywhere:**

- **#238 → ADR 0112 in-file amendment** — **ratified + appended 2026-07-16** (with this plan; index row updated same
  commit). S4 builds against it and updates its build-state rider on landing. The three ratified decisions:
  amendment-not-new-ADR; dev-engine offer ON the page (context-honest copy; palette-visibility recorded); gate stays
  `canControl`-only.
- **#235 → ADR 0006 in-file amendment** — **drafted in [w03-store-235-flip](plan-12/w03-store-235-flip.md), appended
  by S8 in the flip commit** (it flips the Backend-support table row to *implemented*, which must not precede the
  proven build). Index-row Status cell updates in the same commit.
- **#230 → no ADR** — executes already-Accepted ADR 0104 §2.3 Step 1; only dated factual **errata** (0104:3 status
  line; ADR 0089's stale `#226–#230` phase mapping).
- **#234 → no ADR** — the fix enforces ADR 0007's existing "one file, two equal editors" contract. The
  merge-on-absent alternative (an ADR 0007 flip) was evaluated and **rejected**; S10 records that full-replace
  semantics were deliberately retained.

**(b) Verdict-corrections register** — every adversarial `must_fix` absorbed (the "what we corrected" record):

- **#230:** `dryrun_trace.py` added to P4 (else `--trace` breaks its byte-identical contract) · no-settings fallback
  = Settings-default **True**, not False · KWARG_CTX + all unit-tested helpers relocated to the vscode-free pure
  module · multi-line decorator-run capture specified as **new** logic (`symbolIndex.ts` `classify()` is documented
  single-line-only) · erratum facts: `5b90a695` is 2026-07-13 **UTC**; `tests/test_ide_artifacts.py` is a
  recompute-and-compare parsed-JSON equality gate (not "byte-equal"); cite `parsing/message.py:248-250` (`set()`)
  alongside `:100` (`field()`) · the illustrative KWARG_CTX regex must exclude a cursor inside the value string
  literal; single-line-prefix limitation recorded as accepted.
- **#238:** branch from **main** (pill premise stale — verified `c2239a05` merged, `eb560f38` tree-identical +
  behind) · dispatch-discipline citation corrected (the message handler is NEW code mirroring `statusBar.ts`'s
  known-CMD dispatch; `cookbook.ts` is mirrored only for the panel shell) · amendment wording: "no lifecycle/setup
  action is offered when `canControl == false`" (unreachable/foreign get copy-start AND Configure-engine-target, not
  "only copyStart") · the `engine-control.test.ts` sweep context `CONTROL({canControl:true,hasStore:false})` already
  exists — **verify, don't add** · context-honest dev-engine copy (palette-visible command, context-blind page) ·
  unenforceable ide-leg merge gate replaced with the manual hold · optional root pytest dropped or run with
  `QT_QPA_PLATFORM=offscreen`.
- **#234:** read-schema union is **33 distinct keys** (25 inbound + 16 outbound, 8 shared; 41 per-direction slots) —
  not 29 · casualty = **19 per-direction slots / 16 distinct keys INCLUDING inbound `metadata`** ·
  `test_upsert_preserves_simulate` lives in `tests/test_outbound_simulate.py:219-240` (not `test_connections_cli.py`)
  · add a test pinning **absent-key-deletes** (`test_upsert_replaces_in_place` does NOT lock it — a merge-on-absent
  writer passes it) · maximal inbound fixture keeps `content_type=hl7v2` (`stream_threshold_bytes` is HL7-specific)
  or splits fixtures · the **pytest** parity test — not the module-level assert (vanishes under `python -O`) — is
  the CI guard of record · unknown-input keys validate against the **direction-appropriate** key set · the
  reload-equality test explicitly accepts date/datetime→string type-narrowing · "untouched-table byte-stability"
  honestly described as comment-substring survival (byte-idempotence is the NEW Phase-2c guarantee) · clone
  direction-flip rule (merge only when `posted.direction === initial.direction`) · ONE stated merge-source policy
  (save-time fresh `connection list`, or a documented staleness window) · the create/clone/wizard **name-collision
  full-replace overwrite hole**: fix in S9 or re-scope explicitly + file in S10.
- **#235:** `_encrypt_existing_rows` reference pass **IN scope** — the "born-encrypted" omission rationale is FALSE
  (under a no-key deployment `IdentityCipher` writes plaintext JSON; the no-key→key transition is that method's
  entire purpose) · over-long-key guard measured in **UTF-16 code units** (`len(key.encode('utf-16-le'))//2 > 450`),
  extended to `name` (NVARCHAR(256)) · guard error **never** contains the raw key (PHI) · **binary collation**
  (`COLLATE Latin1_General_100_BIN2`) on `name`/`version`/`[key]` so key equality is byte-comparison like
  SQLite/Postgres · `write_reference_snapshot` post-commit sets BOTH `_reference_cache[name]` AND
  `_reference_versions[name]` · amendment mechanism facts: the runtime rejector is the **NVARCHAR(450) column
  width** (truncation), not the 1700-byte nonclustered index cap (the cap is why 450 was *chosen*); collation is a
  **second** recorded divergence; cite `pipeline/cluster_sqlserver.py` for the `SqlServerCoordinator` upsert idiom ·
  fixture DELETE list += `reference`/`reference_version` (else `test_sqlserver_store.py:879`'s exact `== 6` breaks) ·
  the authoritative leg is a **2022+2025 image matrix**.

**(c) Reconciliation & live-worktree caution:** `pill-engine-lifecycle` is **dormant** (`eb560f38` ≡ `c2239a05`,
merged as PR #1067) — do **not** resume it; S4 branches from `main` and corrects BACKLOG.md:7001's stale premise in
the #238 close-out. No item here overlaps any other live plan's lane (Plan-11's remaining open sessions carry none of
#230/#234/#235/#238). Re-check in-flight ownership before starting each session.

---

## F. Coverage appendix

- **#230** — docs-230-errata (W1) + ide-230-autocomplete (W2) + engine-230-dryrun-parity (W2, optional)
- **#234** — config-234-writer (W1) + ide-234-merge-fix (W3) + docs-234-closeout (W4)
- **#235** — store-235-port (W1) + store-235-ci-tests (W2) + store-235-flip (W3)
- **#238** — ide-238-setup (W1)

**Coverage: 4/4 built here across 10 sessions (1 optional).**
