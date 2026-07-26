# MessageFoundry — Multisession Execution Plan 13 (2026-07-17)

> 📁 **Per-session phase documents: [`plan-13/`](plan-13/README.md)** (authored with this plan). Each build session
> has its own maintainable doc under `docs/releases/plan-13/` — **when a session's items land, update only its phase
> doc** (and the status cell in the [dir index](plan-13/README.md)), not this file. This master stays the **shared
> index**: wave sequencing (§B), the contention matrix (§C), coordination rules (§D), the reconciliation / banner-rot
> register (§E), and coverage (§F). The §A roster below is an at-a-glance summary; the phase docs are authoritative
> for per-session status.

**Clearing the schedulable backlog: grouping the buildable-now items (#207 · #208/#220 · #229 · #240 · #241 · #245)
into 10 parallel-safe, single-subsystem sessions across 2 waves so that no two sessions in the same wave ever co-own
a file** (two deliberate exceptions — `docs/BACKLOG.md`, line-disjoint per-banner; `docs/adr/README.md`, row-disjoint —
both mitigated in §C). Method: **coordinator + one worker per session in its own worktree
(`scripts/worktree/new.ps1 -Name plan13-<lane>`) branched off `origin/main`; workers build + verify + local-commit;
the owner opens and approves every PR.** Every work package below was grounded against the code, designed, and
**adversarially verified (four lenses, 2026-07-17)**; all blocker/major corrections are absorbed here and recorded in
§E. Status: **AUTHORED (2026-07-17) — ready to dispatch.**

> **The demand-gated majority is not scheduled — by design.** ~85 open items are speculative connectors/codecs/parity
> knobs the project deliberately refuses to build before a real feed/adopter/deployment fires their trigger (its
> identity is code-first, minimal-dependency, on-prem). They are parked with their triggers in the **Appendix**, not
> in any wave.

---

> **Progress — 2026-07-20 (dispatch begun).** An independent 9-agent reconciliation of the full backlog (a separate coordinator
> session, `origin/main` @ `4ba666f5`) re-derived this plan's buildable-now set and confirmed the demand-gate / measured-dead
> parking — **no schedulable work was found outside Plan-13**, so no competing plan was authored (Plan-14 would have duplicated this
> file). Wave-1 dispatch started, each lane in its own worktree off `origin/main` with the same build → independent-adversarial-verify
> pattern, owner-PR'd:
> - **#220 + #208A** (`harness-208-220`) — built, adversarially **CONFIRMED**, PR [#1125](https://github.com/MEFORORG/MessageFoundry/pull/1125) (auto-merge/squash, CI running). Falsifier proven red-first (a joining PID inflated the total `56.0` → correct `4.0`). #208 stays 🔢-open (part B).
> - **#240 a+b** (`config-240`) — built, adversarially **CONFIRMED**, PR [#1126](https://github.com/MEFORORG/MessageFoundry/pull/1126) (auto-merge/squash, CI running incl. the ide-build leg). Surfaced + closed a **live bug**: 4 `AlertRule` fields (`mute`/`content_label`/`escalate`/`schedule`) were silently dropped on every GUI/CLI save. #240 left 🚧 (✅ deferred to W2 ide lane).
> - **#229** (`harness-229`) and **#207 loose-end-1** (`harness-207-txn`) — **building now** (isolated worktrees).
> Remaining W1: `store-241` / `verify-241` (need the SQL Server + Postgres store-trio) and `docs-ledger-reconcile` (needs the §B
> ratifications). Owner-gated: #245 push (`asvs-wp245`), #207-bytes ADR choice, #91 GO/no-go.

## Progress / premise corrections (git-verified against `origin/main` @ `be1fbbab`, 2026-07-17)

The 2026-07-10 ranked table **and** many per-item banners are STALE. Reconciliation found the following — the per-item
✅ banner in `docs/BACKLOG.md` + `CHANGELOG.md` are the status source of truth, and several disagree with the code at
HEAD. **§E lists the exact banner-rot flips to land; the build sessions below assume these corrected states.**

- **#245 (ASVS 7.5.1) IS ALREADY BUILT — do NOT re-build it.** The refuter blocked the drafted W1 "build 7.5.1"
  session: the entire deliverable is committed on branch **`asvs-wp245`** (sibling worktree
  `C:/Users/<you>/Code/MessageFoundry-asvs-wp245`, tip `597d6eb9`, **unpushed**): `ab1bad6f` (7.5.1 part a **and** b +
  the ADR 0077 amendment), `844be7e1` (the last-admin-guard PATCH test follow-up), `597d6eb9` (the 2026-07-17 11-agent
  re-score that already superseded the verdict-of-record and deleted `_wp245-plans/`). `asvs-wp245` is a **clean
  descendant of `origin/main` @ `be1fbbab`** carrying all 8+ WP245 cells. **#246 rides the same branch** (`410349fd`
  folded the delegated proxy-TLS rows into the L3 register). #245 collapses to a single **reconcile-and-flip** session
  (§A `auth-245-reconcile-flip`). The current worktree branch `claude/asvs-drive-to-pass` re-did WP242-244 as
  individual commits (`fd1a6b6a…0942526f`) and is a **superseded parallel line** (squash `ccddf53e` is not its
  ancestor) — do **not** merge it.
- **The Throughput & Scale cluster is largely already answered/shipped or measured-dead — most banners lie.** SHIPPED
  but still 🔢-open: **#209** & **#213** (accepts= seam + H≠D ladder, PR #952 / ADR 0084), **#227** (per-stage claim
  telemetry, PR #1008), **#218** (2-point shard probe C1, PR #868), **#215** (full N-sweep Phase 5 — DECLINING,
  C1–C5). Measured-DEAD, banners still say "build": **#210** (tempdb table-var rewrite WITHDRAWN 2026-07-12,
  ADR 0107/0114), **#217** (group-commit — dead across ADRs 0069/0099/0107/0114), **#212** (fifo_claim_batch stays
  OFF, ADR 0107), **#211** (pooled default settled, ADR 0114 — sweep is characterization-only). Only **#208 (part A)
  / #220** (CPU subtree-membership arithmetic) and **#229** (A4b per-stage strand guard) and **#207** (rendered
  measured txn/msg + owner bytes call) are genuinely buildable-now.
- **#239 (Windows tray), #221 (IDE native-surface polish), #222 (Steps lens), #48 (Insert-Element snippets) all
  SHIPPED** but keep the 🔢-open glyph (#239 shipped tray ADR 0113 / PR #1084-#1088; #221 ADR 0100 / PR #886; #222
  ADR 0076 + 0103/0106/0108; #48 base #595 + L1 #794). ADR 0106's doc-status still reads *Proposed* though its palette
  build shipped (#1013/#1022) — reconcile to Accepted.
- **#102 / #187 / #99 / #237 cores shipped.** #102's empty-store DR hole is closed (`has_prior_backup_history`,
  PR #890); its residual is the separate item **#223** (owner decision). #187's require-MFA-default + strict TOTP skew
  shipped (ADR 0079); its sole residual is Kerberos 7.1.3, closed on the **accept** side by #245's re-score cell
  (`26432cc2`). #99's turnkey polish shipped (ADR 0094); its remainder is infra-gated (a real DC + AD CS + gMSA).
  #237's worktree-gate fix is merged (`730b0ed1`); only a manual operator re-install remains.

---

## Start here — immediately actionable (Wave 1, no upstream code dependency)

| Item | Session (wave) | Gate | What |
|---|---|---|---|
| ledger | docs-ledger-reconcile (W1) | none — **merge FIRST** | Flip the shipped/dead banners the whole plan assumes (#209/#213/#215/#218/#227/#221/#222/#239/#48 → ✅; #210/#217 → ⛔; #211/#212 → owner-closed; ADR 0106 → Accepted) |
| #241 | store-241-atrest-hardening (W1) | none to start; **DB-leg gate before done** | SQL Server `state` at-rest encrypt pass (F1) + fail-closed keyless-open operator error on all 3 backends (F2) |
| #241 | verify-241-snapshot-thread (W1) | none | Thread `[pipeline].snapshot_on_send` into `verify/smoke.py` (F3) |
| #240 | config-240-editor-writers (W1) | none | alerts_edit fail-loud + parity guard (a) + codeset over-wide/collision refusal (b) |
| #208/#220 | harness-208-220-cpu-collector (W1) | none | Per-tick PID-set differencing in `_drain_proc` — the CPU-attribution correctness fix (one PR) |
| #229 | harness-229-a4b-strand-guard (W1) | none | Per-stage strand breakdown for a sound H>D delivery permit |
| #207 | harness-207-txn-per-msg (W1) | none | Rendered **measured** txn/msg beside the analytical `3+2H+2D` (loose end 1) |
| #245/#246 | auth-245-reconcile-flip (W1) | **owner ratification** (build already committed on `asvs-wp245`) | Merge `asvs-wp245` → main; ratify the already-produced re-score; flip #245/#246 banners ✅ |

---

## A. Session roster

| Wave | Session | Items | Effort | Owns (files / seams) | Notes |
|---|---|---|---|---|---|
| 1 | docs-ledger-reconcile | banner-rot (no build item) | 0.75 | `docs/BACKLOG.md` (#209/#213/#215/#218/#227/#221/#222/#239/#48/#210/#211/#212/#217 banners — all disjoint from build-item banners), `docs/adr/0106-*.md` status line + `docs/adr/README.md` 0106 row | Docs-only; **no numbers allocated**. **Merge FIRST.** Does **NOT** touch #207/#208/#220/#229/#240/#241/#245/#246 banners — those belong to build sessions. #210/#217 flip ⛔ / #211/#212 flip owner-closed **only if the owner has ratified** (see §E, ownerDecisions); else annotate with the superseding ADR + "pending ratification". |
| 1 | store-241-atrest-hardening | #241 F1 + F2 | 2 | `messagefoundry/store/sqlserver.py`, `store/postgres.py`, `store/store.py`, `store/crypto.py`, `tests/test_store_encryption.py`, `tests/test_sqlserver_store.py`, `tests/test_postgres_store.py`, `docs/BACKLOG.md` (#241 @7052) | Navigate by **symbol**, not the drifted banner line numbers. F1: inline `state` composite pass in SQL Server `_encrypt_existing_rows` (mirror its own reference loop — **no** `_encrypt_existing_composite` helper on SS); reuse the `value <> '' AND NOT LIKE 'mfenc:%'` guard. F2: RAISE a consistent operator-facing store error on keyless decode across all **6** eager-read seams and **un-mask** SQL Server `_load_state_cache`'s silent-skip. Two coherent commits. **Hard verify: the mssql + Postgres CI legs must be green** (these findings are provable only there; local pytest silently skips). |
| 1 | verify-241-snapshot-thread | #241 F3 | 0.5 | `messagefoundry/verify/smoke.py`, `verify/runner.py`, `tests/test_verify.py` | File-disjoint from store-241 → fully parallel, merges off its own gate. Thread `settings.pipeline.snapshot_on_send` (default True) into `dry_run(reg, msg, inbound=)`; keep the library default when `settings is None`. Does **NOT** touch `docs/BACKLOG.md` (store-241 owns #241). The #230-pointer sub-task is **already landed** — do not redo. F4 (MFA clock freeze) **excluded** (build-only-if-recurs). |
| 1 | config-240-editor-writers | #240 (a) + (b) | 1.5 | `messagefoundry/config/alerts_edit.py`, `config/codeset_edit.py`, `messagefoundry/__main__.py`, `ide/src/codeSetEditor.ts` (conditional), `tests/test_alerts_edit.py`, `tests/test_codeset_edit.py` | (a) keep `_RULE_FIELDS` pinned (do **not** import settings.py at runtime), add fail-loud unknown-key reject + a pytest parity guard vs `AlertRule.model_fields`. (b) `_read_csv_grid` REFUSES an over-wide row at read time (raise `WiringError`); `upsert_code_set(create=...)` refuses a create-flavored save under an existing stem, wired **server-side** via the `_codeset` CLI handler; also tighten `code_sets._load_csv` to reject over-wide (engine/editor symmetry — never accept-and-drop). **Writes the #240 🚧 claim at start** (§D) — it is #240's W1 banner owner — but **defers the ✅ close** to the W2 wizard session that lands part (c). `messagefoundry/__main__.py` here ≠ `harness/__main__.py`. |
| 1 | harness-208-220-cpu-collector | #208 (part A) + #220 | 2.5 | `harness/load/connscale/probe.py`, `connscale/runner.py`, `tests/test_connscale_cpu_probe.py`, `docs/BACKLOG.md` (#220 @6608) | **#208 and #220 are the SAME code** → ONE session / ONE PR. Carry `cpu_pids: frozenset[int]|None` on `ProcSample` (non-None iff `cpu_seconds` non-None; `= None` default + update the `_derive` test helper). Rewrite `_drain_proc` from endpoint-difference to a **piecewise sum over intervals whose PID set is unchanged**, degrade set-change intervals to gaps, gate the peak loop the same way, recompute the flat-gap guard over `covered_span`, degrade to None on zero clean intervals. **Compose with** the shipped flat-CPU-gap guard — never regress a real gap into a plausible 0.00. Flips **#220** banner; **#208 stays 🔢-open** (its whole-box rig reconciliation, part B, is excluded — banner-noted). |
| 1 | harness-229-a4b-strand-guard | #229 | 2 | `harness/load/shardcert.py`, `shardcert_ladder.py`, `tests/test_shardcert_ladder_two_box.py`, `tests/test_shardcert_partitioned.py`, `docs/BACKLOG.md` (#229 @6797) | **Sole owner of `shardcert*.py` this wave.** Factor a pure `_summarize_queue_rows` helper; thread `ingress/routed/outbound_stranded` onto **both** the ENGINE_DRAINED gate **and** ENGINE_RUNG_REPORT payloads + `ShardCertEngineReport`; read with a `<0` sentinel (byte-identical opaque-total fallback); bump `schema_version` 7→8. Replace stage-blind `blocked = max(0, unclear − free)` with a sound per-stage `blocked` (ingress→×D, outbound→×1, routed bounded [0,1]) that reduces **exactly** to `expected − unclear` at H==D. Put the H>D regression test in `test_shardcert_ladder_two_box.py`, **not** the reconcile's rough-file. Flips #229 banner. |
| 1 | harness-207-txn-per-msg | #207 loose end 1 | 1.5 | `harness/load/report.py`, `harness/load/enginepoll.py`, `tests/test_load_report.py`, `tests/test_enginepoll_aggregate.py`, `tests/test_txn_per_message_cost_model.py`, `tests/test_live_cost_counters.py` | Governed by **existing ADR 0051** — no new ADR. In `EngineSummary` add `committed_txns` (delta) + `txn_per_message_measured`; `_engine_summary()` already differences `db_size_bytes`/`out_dead` — add the counter delta and divide by `Counters.acked`, render **beside** the analytical formula; bump `SCHEMA_VERSION` 1→2. **Postgres reads 0 (never wired)** → render None/"not measured", never a fabricated 0/msg. Scoped to the low-contention `report.py`+`enginepoll.py` surface — the two-box **ladder** figure is **excluded** (keeps #229 sole owner of the ladder). **Writes the #207 🚧 claim at start** (§D) — it is #207's W1 banner owner — but **defers the ✅ close** to the W2 bytes session. `harness/load/report.py` ≠ `harness/load/connscale/report.py`. |
| 1 | auth-245-reconcile-flip | #245 + #246 | 0.5 | (sibling worktree) `docs/BACKLOG.md` (#245 @7121, #246), re-score docs — **no source build** | **Build is DONE on `asvs-wp245`.** Operate in the sibling worktree `C:/Users/<you>/Code/MessageFoundry-asvs-wp245` (the nested plan worktree is checkout-blocked by worktree-gate Rule-3). Worker: `git merge main` into `asvs-wp245`, confirm the full-suite + `pytest packaging/messagefoundry-webconsole/tests` legs green. **Owner: approve push → PR → merge; ratify the already-produced re-score (`597d6eb9`) — do NOT re-run it.** Then #245/#246 banners flip ✅ (already updated on-branch). On a known-flaky `sql server (store + connector)` leg (pyodbc/py3.14 segfault, unrelated) → `gh run rerun <id> --failed`. NO `Co-Authored-By: Claude` trailer. |
| 2 | harness-207-bytes-per-msg | #207 loose end 2 | 1.5 | `harness/load/report.py`, `tests/test_bytes_per_message_amplification.py`, `docs/adr/README.md`, `docs/BACKLOG.md` (#207 @6388) | **Gate: harness-207-txn-per-msg MERGED** (shared `report.py`, rebase over its SCHEMA 1→2) **+ OWNER bytes-proxy decision.** Publishing any byte figure **reverses A2's recorded refusal** → **allocate a fresh ADR at build via `alloc.ps1`** (do NOT pre-pick a number; add the README index row in the same commit) pinning WHICH proxy (copies/msg backend-named · db-growth-delta bytes/msg · per-backend estimate) + caveats. Bump SCHEMA 2→3; guard the Postgres-0 case. Flips #207 banner ✅. |
| 2 | ide-240-wizard-collision | #240 (c) | 1 | `ide/src/connectionQuickInput.ts`, `ide/src/connectionWizardModel.ts`, `ide/src/test/suite/connection-wizard.test.ts`, `docs/BACKLOG.md` (#240 @7036) | **Gate: config-240 MERGED** (banner-flip ordering — fix (c) code is itself file-disjoint from a+b). Reuse `planSave`/`findNameCollision`/`nameCollisionError` from `connectionMerge.ts` by **import only** (never owned/edited — the #1081 precedent); the node-tested `planWizardSave` helper must live in the vscode-free `connectionWizardModel.ts`. Flips #240 banner ✅ (all of a+b+c landed). **ide leg is not a required check + auto-merge is on → manual hold** until the ide leg is green. |

**Total: 10 sessions (8 in W1, 2 in W2); ~13.75 build-days; wall-clock ≈ W1 parallel + W2 parallel.**

---

## B. Waves & sequencing

**Wave 1 (8 parallel worktrees, all branched off `origin/main` @ `be1fbbab`).** Eight file-disjoint lanes:
docs (`docs-ledger-reconcile`), three store/config/verify (`store-241-atrest-hardening`, `verify-241-snapshot-thread`,
`config-240-editor-writers`), three harness (`harness-208-220-cpu-collector`, `harness-229-a4b-strand-guard`,
`harness-207-txn-per-msg`), and the owner-gated `auth-245-reconcile-flip`. **`docs-ledger-reconcile` merges first,
unconditionally** — it is the defense against building against a stale ledger (the shipped/dead banners the whole plan
assumes). The only same-wave shared file is `docs/BACKLOG.md`, held to line-disjoint per-banner edits (owner-serialize
the merges; see §C). `verify-241-snapshot-thread` is file-disjoint from `store-241` (verify/ vs store/), so it runs
fully parallel and merges off its own no-DB gate while store-241 waits on its DB-leg proof.

**Wave 2 (2 parallel worktrees).** `harness-207-bytes-per-msg` (gate: harness-207-txn merged — shared `report.py`
rebase — **and** an owner bytes-proxy decision + a new ADR) and `ide-240-wizard-collision` (gate: config-240 merged
for banner-flip ordering; the (c) code is file-disjoint). File-disjoint: harness `report.py` vs ide `.ts`.

**Strict chains:** store-241 → its DB-leg CI proof (hard gate, before "done") · harness-207-txn → harness-207-bytes
(shared `report.py`) · config-240 → ide-240-wizard (banner ordering). Everything else in W1 is parallel-safe.

**Not a wave — owner gates that unblock nothing in-plan:** `auth-245-reconcile-flip` needs owner ratification of the
push/PR/merge + the (already-produced) re-score; it carries no code build and gates no other session. It is placed in
W1 as "ready, owner-driven".

---

## C. Contention matrix

Each hotspot is held to **one owner per wave**. Banner positions verified on disk: #207 @6388 · #208 @6402 ·
#220 @6608 · #229 @6797 · #240 @7036 · #241 @7052 · #245 @7121.

| Shared / hot file | Owner by wave | De-confliction |
|---|---|---|
| `docs/BACKLOG.md` | **W1:** docs-ledger-reconcile (shipped/dead banners — #209/#213/#215/#218/#227/#221/#222/#239/#48/#210/#211/#212/#217, all **disjoint item-numbers** from every build item) · store-241 (#241 @7052) · config-240 (#240 @7036 — 🚧 **claim**) · harness-208-220 (#220 @6608) · harness-229 (#229 @6797) · harness-207-txn (#207 @6388 — 🚧 **claim**) · auth-245-reconcile (#245 @7121, #246). **W2:** harness-207-bytes (#207 @6388 — ✅ close) · ide-240-wizard (#240 @7036 — ✅ close). | **Line-disjoint per-banner; serialize the merges (docs-ledger merges first).** Each build item's banner has **one W1 owner** who writes its 🚧 claim (§D) — config-240 and harness-207-txn now *do* touch BACKLOG in W1 to claim #240/#207, but **defer the ✅ close** to their W2 sibling (different wave, same banner region — no same-wave co-edit). Tightest same-wave gap is now **#240 @7036 ↔ #241 @7052 = 16 lines** (claim edit sits at the top of #240's banner, ~16 lines above #241's) — clean under git's ~3-line context but the tightest pair, so **serialize config-240 and store-241's merges** explicitly. verify-241 never touches BACKLOG (store-241 owns #241); docs-ledger touches **no** build-item banner, so it never co-edits a banner a build session owns. |
| `harness/load/report.py` | **W1:** harness-207-txn (EngineSummary txn field, SCHEMA 1→2) → **W2:** harness-207-bytes (bytes/copies field, SCHEMA 2→3) | Cross-wave chain; 207-bytes rebases over 207-txn. Distinct file from `harness/load/connscale/report.py` (not owned in this plan) — recorded so nobody conflates the two "report.py"s. |
| `harness/load/connscale/runner.py` + `probe.py` + `test_connscale_cpu_probe.py` | **W1:** harness-208-220 only | #208 and #220 are the **same code** — one owner, one PR. No other session touches connscale. |
| `harness/load/shardcert.py` + `shardcert_ladder.py` + two-box/partitioned tests | **W1:** harness-229 only | harness-207-txn is scoped to `report.py`+`enginepoll.py` and the two-box ladder figure is **excluded**, so #207 never co-owns the ladder with #229. |
| `docs/adr/README.md` | **W1:** docs-ledger-reconcile (0106 status row) · **W2:** harness-207-bytes (NEW appended index row for the alloc'd bytes/msg ADR) | Row-disjoint **and** different waves — amending 0106's status touches its own row; the bytes/msg ADR appends a new row. |
| `messagefoundry/__main__.py` vs `harness/__main__.py` | **W1:** config-240 owns `messagefoundry/__main__.py` (`_codeset` create-signal) | DISTINCT files in different packages — recorded so nobody conflates them; `harness/__main__.py` is untouched in this plan. |
| ide `.ts` files | **W1:** config-240 owns `ide/src/codeSetEditor.ts` (conditional) · **W2:** ide-240-wizard owns `connectionQuickInput.ts` + `connectionWizardModel.ts` | Disjoint ide files + different waves. `connectionMerge.ts` is imported/READ by ide-240, never owned. |
| Sibling worktree `C:/Users/<you>/Code/MessageFoundry-asvs-wp245` (`asvs-wp245`, `597d6eb9`, **unpushed**) | **W1:** auth-245-reconcile-flip only | The nested plan worktree (`claude/asvs-drive-to-pass`) is checkout-blocked by worktree-gate Rule-3, forcing all #245 ops into the sibling. Merge unit = `asvs-wp245 → origin/main` (clean descendant of `be1fbbab`); do **NOT** merge `claude/asvs-drive-to-pass`. |

**Non-collisions worth recording so nobody invents them:** store/`*.py` + crypto.py + store tests are **#241-only**;
verify/* (#241 F3) is file-disjoint from store/ (#241 F1/F2), so verify-241 runs parallel with store-241;
auth/* + api/* + `messagefoundry_webconsole/*` are **#245-only (and already committed)**; config/alerts_edit.py +
codeset_edit.py + ide wizard TS are **#240-only**; connscale files are **#208/#220-only**; shardcert files are
**#229-only**; `harness/load/report.py`+`enginepoll.py` are **#207-only**.

**Cross-plan / live-worktree hazards (from `git worktree list`) — rebase-and-coordinate, not intra-plan collisions:**
- `claude/<branch>` (worktree `-docx-npm-install`, `24d49ccd`) touches store/*.py → coordinate
  with store-241 (off the hot claim path; rebase). `git merge main` before push.
- `fix/shardcert-soak-abort-reliability` (worktree `-harness-ratefix`, `2f7918db`) touches shardcert → coordinate with
  harness-229. `git merge main` before push.
- `session-lease` (`9709dd75`) touches auth → moot for #245 (its work is already committed on `asvs-wp245`; the
  reconcile only merges the descendant branch).
- Local `main` (`8e413919`) **trails** `origin/main` (`be1fbbab`) — every worktree must `git fetch` and branch off
  `origin/main`, never off the divergent `claude/asvs-drive-to-pass`.

---

## D. Coordination rules & gotchas

- **One worktree / branch / `.venv` per session:** `scripts/worktree/new.ps1 -Name plan13-<lane>`
  ([docs/WORKTREES.md](../WORKTREES.md)), branched off **`origin/main` @ `be1fbbab`** (`git fetch` first — local `main`
  trails). Re-check in-flight ownership before starting (`git worktree list`, `gh pr list --state all`,
  `git log origin/main`). **#245 is the exception** — it operates in the existing sibling worktree
  `C:/Users/<you>/Code/MessageFoundry-asvs-wp245`, never a fresh one.
- **Claim before you build (🚧) — mandatory:** at session start, *after* `alloc.ps1` any number and *before* writing
  code, flip the item you are building to a **🚧 in-progress claim** in `docs/BACKLOG.md`, in its **own commit**, naming
  the lane — e.g. `> 🚧 **Status — in progress (lane \`plan13-store-241\`, branch off \`origin/main\`).**`. The **banner-
  owning session** (§C) writes the claim, exactly one per item — so **store-241 claims #241, config-240 claims #240,
  harness-208-220 claims #220 (banner-notes #208), harness-229 claims #229, harness-207-txn claims #207**; a session
  building a *part* of an already-claimed item (verify-241 for #241, ide-240-wizard / harness-207-bytes for #240 / #207)
  does **not** write a second claim. `docs-ledger-reconcile` has no build item, and #245/#246 are already ✅ on-branch,
  so neither claims. Update 🚧 → ✅/⛔/🪦 when the work lands. **Why this is non-optional here:** the 🚧 in the shared
  BACKLOG is the *only* signal that stops a sibling worktree double-building the same item — neither the worktree gate
  nor the ledger gate catches duplicated work ([LEDGER-GATE.md](../LEDGER-GATE.md) Limits: "does not stop two sessions
  building the same thing"). The claim write lands in the item's own banner region, line-disjoint from every other
  session's, so it composes with §C (serialize the merges; docs-ledger still merges first).
- **Every PR:** `git merge main` first (the CI gate hangs otherwise). **No `Co-Authored-By: Claude` trailer** (the CLA
  bot fails on it — auto-memory). The finishing PR carries `BACKLOG #N` and flips that item's banner; a `BACKLOG #N`
  engine-code PR **must** also change `docs/BACKLOG.md` (backlog-hygiene gate).
- **Verify order (engine/store/harness sessions):** `ruff check` + `ruff format --check` → `mypy messagefoundry`
  (strict) → `$env:QT_QPA_PLATFORM='offscreen'; pytest -q`. **Harness is OUT of the CI mypy scope** (`mypy messagefoundry
  messagefoundry_webconsole` only) — type-check `harness/load/*` **locally, advisory**. **IDE sessions:**
  `cd ide && npm run typecheck && npm run compile && npm run test:unit` — `test:unit` is plain-node mocha, so **never
  export a test helper from a vscode-importing module** (`planWizardSave` lives in the pure `connectionWizardModel.ts`).
- **The mssql + Postgres CI legs are the ONLY authoritative proof for #241 F1/F2** (SQL Server `state` at-rest + the
  keyless-open errors). Local pytest **silently skips** the T-SQL without `MEFOR_TEST_SQLSERVER=1` — a locally-green
  run proves nothing. Owner-approved mid-stream push to run them; green = HARD GATE before store-241 is "done".
- **The ide CI leg is NOT a required check and auto-merge is on** — an ide PR can merge with the leg red. The one ide
  PR (ide-240-wizard) gets an explicit **manual hold**: do not enable auto-merge or approve until the ide leg is green.
- **Number allocation:** the **only** `alloc.ps1` run in this plan is harness-207-bytes's new ADR (`-Kind adr`),
  allocated **at build time** with its `docs/adr/README.md` index row in the **same commit** — the plan does **not**
  pick the number. The #245 ADR 0077 amendment is **already committed** on `asvs-wp245` (no allocation). docs-ledger's
  errata + the ADR 0106 status flip allocate **nothing**.
- **PHI / invariants:** #241 F1 must not turn a purged `''` into ciphertext (reuse the `value <> '' AND NOT LIKE`
  guard); F2 must **RAISE** (fail-closed), never degrade-open or silently skip — a PHI hard rule. No raw key/body in any
  error text. None of these sessions touches the stage handoff or the ACK contract; if scope drifts there, stop and
  re-plan (CLAUDE.md §2).

---

## E. Reconciliation & banner-rot fixes to land

**(a) Banner-rot flips (owned by `docs-ledger-reconcile`, W1, docs-only — item-numbers disjoint from every build
session):**

| Item | Current banner | Correct state | Evidence |
|---|---|---|---|
| #209 | 🔢 open / P2 | ✅ **SHIPPED** | PR #952 (`0902e530`) — H≠D ladder split; ADR 0084 |
| #213 | 🔢 "build … UNBLOCKED" | ✅ **SHIPPED** | PR #952 (`cf13f698`) — `accepts=` seam + advisory lint; ADR 0084 ratified |
| #227 | 🔢 open / P2 | ✅ **SHIPPED** | PR #1008 (`93155489`) — per-stage claim telemetry (engine emitted per-stage all along; harness regex fixed) |
| #218 | 🔢 P1 / "never varied N" | ✅ **DONE** (C1) | PR #868 (`ad156be7`) — two-point N=1 vs N=4 probe folded into THROUGHPUT-STATUS |
| #215 | 🔢 P1 / "never run" | ✅ **CLOSED — DECLINING** | Phase 5 C1–C5 (2026-07-10/12); ADR 0107 |
| #221 | 🔢 "awaiting scoring" | ✅ **SHIPPED** | ADR 0100 (Accepted) closes it; PR #886 — all 5 native surfaces |
| #222 | 🔢 "awaiting scoring" | ✅ **SHIPPED** | ADR 0076 + 0103/0106/0108; STEPS-PALETTE 27-item Add menu |
| #239 | 🔢 "Filed 2026-07-16" | ✅ **SHIPPED** | Tray ADR 0113, PR #1084-#1088 — built + wheel-packaged |
| #48 | 🔢 (text says "done") | ✅ (flip glyph) | Base #595 + L1 #794 — 36 snippets, quick-pick |
| #210 | 🔢 "build … attacks the wall" | ⛔ **WITHDRAWN** (owner-ratify) | THROUGHPUT-STATUS 2026-07-12 "Do not build it"; ADR 0107/0114 (table-vars retained by design) |
| #217 | 🔢 "build, after claim path" | ⛔ **DECLINED** (owner-ratify) | ADRs 0069/0099/0107/0114 — group-commit measured-dead |
| #212 | 🔢 "decide the default" | ✅ **owner-closed: stays OFF** (owner-ratify) | ADR 0107 sized it ~+4.7% (< +8% bar) |
| #211 | 🔢 "gating #210 / prevent flip" | ✅ **owner-closed: characterization-only** (owner-ratify) | ADR 0114 pooled default settled; sweep off critical path |
| ADR 0106 | doc-status *Proposed* | *Accepted* | palette build shipped (#1013/#1022) |

> `docs-ledger-reconcile` flips the unambiguous ✅ rows in its W1 PR. The four **owner-ratify** rows (#210/#217 → ⛔;
> #211/#212 → owner-closed) flip in the **same** session only if the owner has ratified (ownerDecisions below); otherwise
> the session updates their banner prose to cite the superseding ADR + "pending owner ratification" — no false ✅.

**(b) Corrections absorbed into build sessions (not docs-ledger's to touch):**

- **#207** banner's "neither has ever been measured" is stale (store-side `committed_txns`/`body_copies` shipped
  PR #909) — corrected by `harness-207-txn-per-msg`'s note; the ✅ flip rides `harness-207-bytes-per-msg` (W2) once the
  owner picks the bytes proxy.
- **#208** banner is pre-remediation prose (the A3 collector shipped PR #861); `harness-208-220` flips **#220** and
  banner-notes that #208 stays 🔢-open pending its whole-box **rig** reconciliation (part B, excluded).
- **#241** banner (@7052): store-241 records F1/F2 shipped + points at verify-241 for F3; **F4 deferred** so the item
  does not fully close.
- **#245/#246** banners: already updated on `asvs-wp245` (`597d6eb9`) — they flip ✅ with the branch merge (auth-245).

**(c) ADR work in this plan:** exactly **one** new number — `harness-207-bytes-per-msg`'s bytes/msg ADR, allocated at
build via `alloc.ps1`. The #245 ADR 0077 amendment is already committed on-branch. All other reconciliation is dated
factual errata (no numbers).

---

## F. Coverage appendix

**Buildable-now items → sessions:**
- **#241** — store-241-atrest-hardening (F1+F2, W1) + verify-241-snapshot-thread (F3, W1). *F4 excluded (flake-gated).*
- **#240** — config-240-editor-writers (a+b, W1) + ide-240-wizard-collision (c, W2).
- **#208 / #220** — harness-208-220-cpu-collector (W1, one PR). *#208 part B (whole-box rig reconciliation) excluded.*
- **#229** — harness-229-a4b-strand-guard (W1).
- **#207** — harness-207-txn-per-msg (loose end 1, W1) + harness-207-bytes-per-msg (loose end 2, W2). *Two-box ladder
  figure excluded.*
- **#245 / #246** — auth-245-reconcile-flip (W1, reconcile-only — build already committed on `asvs-wp245`).
- **ledger** — docs-ledger-reconcile (W1) closes the shipped/dead banner rot (§E).

**Coverage: 6 buildable items (+ #246 riding #245) built here across 10 sessions.**

**Excluded from the wave plan (with reason):**
- **#91** (GIL-on-vs-FT A/B) — **owner-decision, not scheduled.** The refuter flagged it as speculative-build-before-
  demand: ADR 0053 desk-Amdahl bounds FT to ~+6-7%, ADR 0107 found the single-engine wall (marshaling + ~11ms RTT)
  "both FT-immune", #90 is ⛔ declined — a likely **paper NO-GO** unless a real feed's transform CPU is >~23%. The
  in-repo code slice (two-interpreter seam + heavy transform + pure S(K) comparator) is only worth building **after**
  the owner funds the campaign (real hot feed + enterprise NVMe-PLP + a genuine GIL-on cp314 control). See
  ownerDecisions.
- **#90** — downstream of #91 (reopens only on a #91 GO); currently ⛔ declined.
- **#208 part B** — whole-box CPU reconciliation on the self-hosted SQL-Server per_lane 28/s rig; no in-repo code, a
  manual measurement + owner ratification.
- **#207 two-box ladder figure** — the item's own "heavier, higher-contention stretch"; excluded to keep shardcert
  single-owner. The clean `report.py` surface carries the measured figure; the ladder value is SQL-Server-rig-only
  anyway.
- **#241 F4** — MFA enroll-verify clock freeze; build-only-if-the-flake-recurs. `tests/test_mfa.py` is owned by no
  session here.

---

## Appendix — Demand-gated parking lot (parked by design, with trigger)

~85 open items are **deliberately not scheduled**: the project refuses to build speculative connectors, codecs, and
parity knobs before a real feed/adopter/deployment fires the trigger (code-first, minimal-dependency, on-prem is its
identity). Full per-item banners: `docs/BACKLOG.md`. **Universal trigger unless noted: a named adopter/live feed that
needs it.**

**1. Connector & transport interop breadth** (build when a partner/feed requires the specific wire behavior):
#62 (VARBINARY body carriage), #67 (stored-proc OUT/return binding), #69 (WSDL import) · #184 (serve own WSDL),
#83 (FTPS/SFTP variants) · #158 (per-message dynamic FTP) · #178 (SFTP cipher/KEX/MAC lists), #85 (cloud object-store /
message-bus outbound), #94 (external BLOB-server offload), #97 (persistent/keep-alive outbound), #108 (BOM
auto-detect), #110 (DICOM UID de-dup on C-STORE), #111 (File UNC alt-credentials), #112/#127/#128 (forward-proxy
address / cred types / local bypass), #113 (outbound source-IP binding), #117 (fire-and-forget no-ACK), #141 (TCP role
independent of direction), #142 (leave-source-file in place), #148 (X12 TA1), #159 (TCP stream-until-close),
#163 (static-string ACK), #172 (gzip/zip codec), #181 (multipart/form-data), #182 (per-message base address),
#183 (SOAP MTOM/XOP), #78 (custom message-definition model + NCPDP codec), #3 (per-key partition ordering).
*#157 (Direct/HIE) — outbound S/MIME PR1 shipped (ADR 0085); inbound + MDN + cert discovery + IHE XDR gated on a live
Direct/XDR feed. #105 (Corepoint import) — deterministic importer+CLI shipped (ADR 0086); gated on a **real** Corepoint
export to validate the synthetic schema.*

**2. Alerting & operational control** (build when an operator hits the specific gap):
#81 (escalation tiers + content alerting), #82 (sender transport-polish bundle), #109 (invalid-credential auto-stop),
#118 (test SMTP), #138 (alert-email templates), #143 (windowed alert mute), #144 (alert-triggered connection control),
#145 (HA/DR failover alert), #146 (per-rule recipients), #156 (alert hysteresis), #147 (per-connection active-window
scheduler), #160 (cron/calendar timer source), #169 (author-appendable message history), #171 (runtime log-verbosity +
viewer).

**3. Console / IDE polish (DX, nobody blocked):**
#76 (metrics charts + flow graph), #84 (hex/diff/coverage panes), #131 (object flagging + filter), #132 (frozen-clock
test override), #133 (per-object display colour), #135 (stats push interval), #136 (waiting-for-reply state),
#137 (server display name), #151 (saved log-search presets), #165 (DB schema browser + query runner), #166 (per-user
console prefs), #167/#168 (Test Bench metadata seeding / regression collections), #173 (segment subtree-copy helper),
#174 (scheduled stats reset), #177 (effective-permission inspector), #95 (engine-brokered AI over a BAA), #231 (Steps
"Block" grouping — **owner representation decision**, revisit trigger now met).

**4. Store / retention / log maintenance / migration:**
#119/#121/#122 (log compression / duration cap / corruption rollover), #124/#125/#126 (batch export / uploaded-logs
page / delete uploaded file), #179 (archive aged rows to a separate store), #180 (cross-backend store migration tool),
#130 (name-shared queues + delete protection), #96 (self-service capacity estimator), #155 (server-to-server migration
runbook — pure docs).

**5. Security / auth / crypto (mostly deployment-delegated):**
#71/#72/#73 (PKCS#12 import / dev-cert gen / FIPS attestation — OS/openssl already covers), #98 (Kerberos EPA
channel-binding — needs an AD lab), #99 (AD/gMSA turnkey — polish shipped; **live domain-lab smoke** gated on a real
enterprise Windows/AD deployment), #246 (ASVS delegated-residual register — **largely landed on `asvs-wp245`**, closes
with the #245 merge), #185 (ASVS L3 tracking index — closes when its children close), #187 residual (Kerberos 7.1.3 —
riding #245's accept).

**6. Throughput / scale (measured-shut or owner-call money-pits):**
#64 (throughput roadmap umbrella), #214 (intra-message concurrent transform — **owner money-pit**; its ~40× premise is
undercut by ADR 0107 elasticity −0.115 + ADR 0114 driver-bound claim — re-validate before any build), #216 (1,500-conn
demo driver — **owner call**; the 45M/day target it serves is measured-shut per Phase 5 DECLINING / ADR 0107). *#210 /
#211 / #212 / #217 are being **closed** via §E, not parked.*

**7. DR / server-DB residuals (owner decisions):**
#223 (server-DB DR restore vintage/completeness — design + risk-acceptance + the small `[dr].restore_token` shipped;
**option (a)** full engine-driven store seed re-opens the #52 DBA boundary, ~4-5d — owner scope-out vs build).

**8. Strategy / recon (no code):**
#87 (competitive intelligence — private notes, ships nothing).
