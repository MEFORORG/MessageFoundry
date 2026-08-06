# MessageFoundry — Multi-Session Backlog Execution Plan

**Baseline:** `origin/main` @ `1400e9ab` (MEFORORG/MessageFoundry, public, post-cutover 2026-07-27). **Date:** 2026-07-28. **Autonomy:** L1 — every session builds, verifies and **commits locally only**; the owner approves every push, PR and merge.

This is a **reconcile wave, not a build wave.** The published `docs/BACKLOG.md` on `origin/main` is a single-commit 2026-07-12 snapshot (`9e4e614e`, PR #6, never updated, ends at item #231) while the *code* on `origin/main` is current through 2026-07-28. Thirty items carry a banner that contradicts the code or contradicts an owner ruling already made — and a stale banner is the mechanism by which merged work gets rebuilt (#213 alone is ~1,500 lines). The plan therefore drains **paperwork first**, lands **one genuinely-open engineering item** (the code-scanning backlog, a live violation of the project's own ADR 0034), and **ports one already-written tool** off a dormant vault branch. Everything else that looks open is demand-gated with an unfired trigger, hard-gated by an ADR, blocked on an owner decision, or blocked on rig/infra the project does not own. Those are enumerated, scoped and ready to fire — but none of them is scheduled here.

---

## 0. Ground truth — what the backlog gets wrong

Two authorities matter and they disagree with the published file:

* **`origin/main` code** — current through 2026-07-28.
* **The owner's live ledger** — `docs/BACKLOG.md` on the vault's `main`. Max item there is **#314**; max item on `origin/main` is **#231**.

  > **Corrected 2026-08-05 — the command this line used to give no longer works, and its description of the ref was wrong when written.** It read *"the vault remote-tracking refs are present in this clone; read them with `git show vault/main:docs/BACKLOG.md`"*. `vault/main` was **not** a remote-tracking ref: `git rev-parse --symbolic-full-name vault/main` resolved it to `refs/vault/main`, and `refs/remotes/vault/main` never existed — nor was any remote named `vault` ever configured here; only `origin` has been. Those refs were deleted from this clone on **2026-08-05**, so the `git show` above now fails. **Read the vault ledger from the separate `MessageFoundry-vault` clone instead** — it is checked out beside this repository: `git -C <path-to-MessageFoundry-vault> show main:docs/BACKLOG.md`. Provenance, the measurement, and what the deletion did and did not cost the allocator: [`docs/LEDGER-GATE.md`](../LEDGER-GATE.md) §*The ref store, and the cleanup of 2026-08-05*. Every other `vault/main:` citation in this document is a **record of what was read on 2026-07-28**, not a command to run — resolve any of them through the vault clone. The §3 kickoff trap still stands: that file fails the leak gate, so cite it and never paste from it.

Every row below was verified against one or both. **Action** is the target glyph for the published file.

### 0a. Banner says OPEN — code is SHIPPED

| Item | Banner on main | Load-bearing evidence on `origin/main` | Action |
|---|---|---|---|
| **#213** accepts= seam | `🔢 8/10 · 7/10 big bet` | `HandlerAccepts` + `Registry.handler_accepts` + `_check_accepts_predicate` in `messagefoundry/config/wiring.py` (~2268-2360, 2754-2848); `_accepted()` in `messagefoundry/pipeline/dryrun.py` 206-264; sandbox parity `messagefoundry/pipeline/_sandbox_worker.py:115`; lint `messagefoundry/checks.py:388`; `tests/test_accepts_seam.py` (749 ln); ADR 0084. **Highest double-build risk in the set.** | **✅** |
| **#220** CPU delta subtree | `🔢` | `ProcSample.cpu_pids` at `harness/load/connscale/probe.py:50-70` (docstring names #220); piecewise `max(0,Δcpu)` in `harness/load/connscale/runner.py:926-1014`; twin at `harness/load/estate/runner.py:513-542`; falsifiers in `tests/test_connscale_cpu_probe.py` | **✅** |
| **#209** routed_fanout ≠ delivered | `🔢` | `handlers`/`delivering` split in `harness/load/shardcert_ladder.py` (`txn_per_message = 3+2H+2D` at 1318/1806/2503/2880); `tests/test_shardcert_config.py:154+` incl. `test_default_shape_is_byte_identical` | **✅** (H=20 rig run is bench time, not code) |
| **#207** txn/msg + bytes/msg | `🔢` | Closed by ADR 0141 ("BACKLOG #207 (this closes it)"). `EngineSummary.committed_txns` + `txn_per_message_measured` `harness/load/report.py:112-113, 676-682`; `Store.committed_txns` `messagefoundry/store/base.py:220-233` | **✅** |
| **#216** 1,500-conn harness mode | `🔢` | Whole mode: `harness/load/estate/{profile,driver,runner,report}.py`, `harness/config/estate/`, `harness/load/profiles/estate-demo.toml` (`count=1500`), CLI `python -m harness --estate` (`harness/__main__.py:167-181`). The item's *"no existing harness covers it"* premise is false. | **✅** + record the two owner-sign-off constants |
| **#102** DR seed verification | `🚧 PARTIAL` | `Store.has_prior_backup_history()` on all three backends (`store/base.py:1401`, `store.py:7463`, `postgres.py:5679`, `sqlserver.py:8366`); gate `messagefoundry/pipeline/dr.py:413-478`; `tests/test_dr_server_seed_gate.py` | **✅** |
| **#223** DR restore vintage | `🚧 DESIGN RECORDED` | `restore_token` `messagefoundry/config/settings.py:3314` + `_no_cloud_restore_token` 3345-3353; `_verify_restore_token` `pipeline/dr.py:480-493`; ADR 0102 Accepted. Option (a) declined 2026-07-20. | **✅** |
| **#187** auth defaults / Kerberos | `🚧` | `require_mfa=True` (`settings.py:1662`), `totp_skew_steps=0` (`:1682`); ADR 0079 now **Accepted**, mechanism 2 built 2026-07-22 (`messagefoundry/auth/reconcile.py`, `api/app.py:5066-5083`, 5 settings at `settings.py:1777-1803`) | **✅** |
| **#48** IDE Insert Element | `🔢` | 36 snippets in `ide/snippets/messagefoundry.code-snippets`; `ide/src/insertElement.ts` (`buildPicks`/`detectContext`) | **✅** |
| **#221** IDE native surface | `🔢` | ADR 0100 Accepted, "Closes BACKLOG #221". 9 walkthrough steps, 3 registered `customEditors`, `ide/src/statusBar.ts`, `ide/src/multiStepInput.ts` (cites "#221e") | **✅** |
| **#222** Steps lens | `🔢` | All 3 phases: `messagefoundry/actions.py` (15 verbs), `messagefoundry/lens.py` + `lens` subcommand `__main__.py:375`, `ide/src/stepsView.ts`; ADRs 0076/0103/0106/0108 | **✅** |
| **#82** sender transport polish | `🔢` (+ a *"Confirmed gap"* note that is **factually false**) | `verify_ack_control_id` `transports/mllp.py:663, 793, 1196, 1215-1226`; `send_min_interval_seconds` `config/wiring.py:763-764, 845-853` | **✅** |
| **#118** alert SMTP test | `🔢` | `POST /alerts/test-email` `messagefoundry/api/app.py:2427`; models `api/models.py:1063, 1072` (docstrings say "BACKLOG #118"); commit `37613ef0` (PR #1200) | **✅** |
| **#144** alert → connection control | `🔢` (*"notify-only"* — false) | ADR 0128. `_ALERT_CONTROL_ACTIONS` `config/settings.py:2472`; dispatch `pipeline/alert_sinks.py:945-947` | **✅** |
| **#145** HA/DR failover alert | `🔢` (*"only log at INFO"* — false) | ADR 0014 amendment. `leadership_acquired`/`lost` `alert_sinks.py:800, 814`; `dr_activated`/`released` `pipeline/alerts.py:215, 223` | **✅** |
| **#143** alert suspend/mute | `🔢` | ADR 0044 amendment. `POST /alerts/{id}/suspend` `api/app.py:2372-2396`; durable `suspended_until` on all 3 backends | **✅** |
| **#142** leave-source-file | `🔢` | ADR 0129. `after_read='leave'` `transports/file.py:298-302, 355`; `ProcessedFileLedger` `transports/base.py:66, 250`; `processed_files` on all 3 backends | **✅** |
| **#97** persistent outbound Tcp/X12 | `🔢` | **MERGED** `6df8f159` (PR #1220, 2026-07-24). `self.persistent` `transports/tcp.py:124`, `x12.py:94`; ADR 0067 §8 now `[x]` + a full §9 amendment. **Corrects the "stranded on dg-s5" framing.** | **✅** |
| **#117** no-wait-for-ACK | `🛠`+`🔢` | **MERGED** (same PR). `self.no_ack` `transports/mllp.py:620`; **ADR 0124 IS on main** with its `docs/adr/README.md:151` row; the #117×#82 guard already exists at `config/wiring.py:3388-3405`, pinned by `tests/test_no_ack_wiring.py:47-60` | **✅** |

### 0b. Banner says OPEN — the **owner already ruled**

| Item | Banner on main | Owner ruling (`vault/main:docs/BACKLOG.md`) | Action |
|---|---|---|---|
| **#218** 2-point shard probe | `🔢` | Ran as C1 2026-07-10; answer DECLINING (11.33 → 15.42 ingress/s = 1.36× for 4× shards). `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md`, artifacts `c1-arm-a-n1.json`/`c1-arm-b-n4.json` | **✅** |
| **#215** full shard curve | `🔢` | Ran (C2/C3/C5); Phase 5 CLOSED, R ∈ [2,3). §8 L1719 **retires the m7i.8xlarge upsize** the item still asks for | **✅** |
| **#212** fifo_claim_batch default | `🔢` | `✅ CLOSED — owner-ratified 2026-07-17` (stays OFF; ADR 0107 priced it ≤ +4.7% vs a +8% bar). Shipped default already matches: `settings.py:295` `default=1` | **✅** |
| **#211** claim-mode lane sweep | `🔢` | `✅ CLOSED — owner-ratified 2026-07-17 (characterization-only; docs-ledger-reconcile, PLAN-13 §E)` | **✅** — **do not re-open, do not fund rig time** |
| **#208** per-PID CPU collector | `🔢` | `✅ SHIPPED 2026-07-20 — the in-repo work is done; Part B is off-repo and does not belong on this ledger` … *"no code change in this repo can close it"* | **✅** — and **publish no ~200-line sampler sizing**, the owner refuted it |
| **#217** group-commit | `🔢 P3` | Dead by measurement three times over: ADR 0069 (commit tier ~9% utilised), ADR 0099 (withdrew ADR 0055), ADR 0107 (−28.5% txns → −0.56%; *"Do not build F2 or F3"*; ADR 0057 `⛔ DO NOT PROMOTE`) | **⛔** |
| **#210** remove tempdb table vars | `🔢 7/10 · 7/10` | `⛔` withdrawn owner-ratified 2026-07-17 — THROUGHPUT-STATUS §Phase 1 *"Do not build it."* ADR 0114 deliberately **preserves** the four table variables (`store/sqlserver.py::_fifo_heads_steps` 701-717) | **⛔** |
| **#157** Direct/HIE | `🔢` | `⛔` owner 2026-07-24 (*"if it is Direct, then close it"*). Outbound S/MIME half ships and **stays** | **⛔** |
| **#87** competitive intelligence | `🔢 P3` | `⛔` owner 2026-07-24 (*"close 87"*) | **⛔** |
| **#91** GIL-vs-FT A/B | `🔢 P2` | `⛔` DECLINED 2026-07-20 on four unavailable rig inputs; ADR 0053 paper NO-GO; ADR 0107/0071 (the single-engine wall is FT-immune) | **⛔** |
| **#231** Steps "Block" grouping | `🔢 Filed` | `⛔` DECLINED 2026-07-20 against the #26 guardrail. **The public file still says Filed — a live double-build trap.** | **⛔** |

### 0c. Banner materially misprices the residual — re-price, do not close

| Item | Banner implies | Truth | Action |
|---|---|---|---|
| **#214** intra-message concurrent transform | `8/10 money pit` | Engine mechanism **merged and tested** (`pipeline/wiring_runner.py::_process_routed_batch` 4791+, `tests/test_transform_concurrency.py` 586 ln). Residual is one settings field. But the code comment at `wiring_runner.py:250` withholds it as **owner-coordinated**, and `vault/main` #214 is `🚧 PARTIAL` with residual (a) **DEFERRED by owner decision 2026-07-24**. | **stays `🚧`**, residuals named. Owner-gated (§5.1) |
| **#105** Corepoint import | *"input schema SYNTHETIC-until-validated"* | Discharged by ADR 0086 **Amendment 2026-07-24 §2(a′)** — the format is validated XML, parsed with `defusedxml` (`messagefoundry/corepoint_import.py:81`). Real gate is **#313** (multi-message Handler model, 2,032 refused statements), invisible from `origin/main`. | **amend** |
| **#94** BLOB offload | `8/10` | ADR 0105/#149 shipped complete 2026-07-13; `messagefoundry/parsing/binary.py` **reserves the deref seam** at 55-62, 252, 266. | **amend, re-score → ~5-6**, ADR-first |
| **#99** AD/gMSA hardening | 6/6 engineering build | Sub-item **(e) only**, and it is provisioning, not code. (g) shipped via #274/ADR 0142 (`oidc_require_mfa_claim` `settings.py:1854`); (b) via #224; (c) is a documented stdlib scope-out. | **amend** |
| **#185** ASVS L3 index | `🔢 P3` index umbrella | All 20 children resolved; superseded by ADR 0115's re-partition (#242-#246, then #277/#280-#307). **But it is still `🔢` on the owner's ledger** — a session may transcribe a ruling, not originate one. | **leave `🔢`** → owner (§5.4) |
| **#10** worktree `-Base` | `✅ DONE` | Correct. `scripts/worktree/new.ps1:30` defaults `origin/main`, `:52` fetches first, `:63-73` warns on a stale explicit base. Residual trap in §6. | none |

### 0d. Non-backlog facts the plan depends on

* **`gh pr list --state open` → `[]`.** `DEBT-openprs` is void.
* **16 stale `origin` refs + ~11 stale locals**, every one verified landed (§4).
* **`origin/cla-signatures` is NOT feature work.** Orphan data branch that `.github/workflows/cla.yml:43` writes the signature store to. **Never delete or merge it** — that breaks a *required* status context.
* **`DEBT-noloss` is fixed** by PRs #17 (`ba324ba`) + #26 (`88373cd`): all three copies read `budget = max(unconfirmed_budget, sent // 2)` (`harness/load/report.py:614`, `connscale/runner.py:838`, `estate/runner.py:444`). Project memory still says otherwise.
* **ASVS 11.3.3 AAD cell-binding is MERGED**, not delegated: `cell_aad()` `store/crypto.py:153`; match counts `store.py` 104 / `sqlserver.py` 127 / `postgres.py` 76; ADR 0019 Amendment 2026-07-17. Branch `asvs-aad-cellbind` exists on **neither** remote. Memory overstates the remaining work by >10×.
* **CISO rows `auth.logout` and AD-disable are closed in code** (`auth/service.py:1537-1542`; `auth/reconcile.py` + ADR 0079 mech 2). `docs/security/CISO-REVIEW.md` is gitignored post-cutover and unreadable from this baseline — closing those rows is owner-side bookkeeping.
* **Highest ADR anywhere** (origin + all local/remote refs incl. `vault*`) is **0153** ⇒ next ADR is **0154**. This holds only while the vault remotes stay fetched in this clone; an unfetched vault branch carrying 0154+ would re-open the hole. **Stale as of 2026-08-05:** the `vault*` term is gone from this clone (see the correction in §0 above), and the number has moved on regardless. **Never take an ADR or BACKLOG number from this line or any other document** — run `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`, which is the only instrument that claims one atomically, and `-ShowFloor` to inspect the floor without spending a number.

---

## 1. Scope — what is actually open

**Closed by paperwork in Wave 1: 30 items** — 24 → `✅`, 6 → `⛔`. Plus 4 re-priced amendments (#214, #105, #94, #99).

**Genuinely open and unblocked: two pieces of work.**

| Work | Tier | Why it is real |
|---|---|---|
| `DEBT-codeql` — 32 open code-scanning alerts | S-M (re-scoped, see §2 Wave 2) | ADR 0034 requires every finding be *"fixed or dismissed with a recorded reason (never silently open/suppressed)"*. 32 silently-open alerts on a **public** repo is a live violation of the project's own policy. No BACKLOG item exists for it. |
| `DEBT-session-rescue` — port `sessions.ps1` + gate rule 4 | M (port + reconcile) | Verified absent on main (`git grep EnterWorktree origin/main` → nothing; no `scripts/worktree/sessions.ps1`). Fully written on the vault branch `salvage/worktree-session-rescue` @ `49cb250c`. Fixes a live data-loss mode. |

Adjacent and cheap, folded into Wave 1: the `#220` **misattribution** in `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` (seven lines that would re-cause a double-build), the `PLAN-ENGINE-ATTRIBUTION.md` §3 correction, the slug-rot prose sweep + ratchet, five project-memory corrections, and the branch cleanup list.

**Explicitly excluded, with the reason:**

| Excluded | Count | Reason |
|---|---|---|
| Already built on `origin/main` | 19 | §0a. Rebuilding is the whole failure mode this plan exists to stop. |
| Owner already ruled (closed / declined) | 11 | §0b. A session transcribes a ruling; it never re-litigates one. |
| Demand-gated, trigger **not** demonstrably fired | 5 (#169, #179, #180, #141, #94) | §5.2. Per the demand-gate protocol, a good score is not a licence to schedule. |
| Hard-gated by an ADR or a sibling item | 3 (#96 ADR 0074 `⛔ BUILD GATED`; #105 → #313; #99(e) → #275) | §5.3 |
| Owner-coordinated / owner-deferred | 1 (#214) | §5.1 |
| Owner-ledger-open, cannot be closed by a session | 1 (#185) | §5.4 |
| Declined-by-design (CLAUDE.md §12) | — | Visual/template authoring (#26), channel/route element, Black, new PySide6 operator surfaces, Serial/ASTM (#27). Nothing in this plan touches any of them. |
| Externally blocked | 1 (`DEBT-pyodbc-retry`) | Upstream `pyodbc#1459`. Schedule a *check*, not capacity. |

**Parallelism ceiling: 3 lanes.** One machine, one inference budget.

---

## 2. The waves

### Wave 0 — Owner pre-flight (no session, ~20 minutes)

1. Answer §5.1 (#214 go/no-go) and §5.4 (#185, the three default flips, SEC-022). Waves 1 and 2 start without them.
2. Approve the branch delete list (§4) — **excluding `origin/cla-signatures` and `origin/main`**.
3. Turn on GitHub *Automatically delete head branches* so 16 stale refs do not re-accumulate.
4. Confirm Wave 1 may start.

---

### WAVE 1 — the paperwork drain · 3 parallel lanes · ~1 day · closes 30 items

The three lanes are **file-disjoint by construction**. `ledger` owns `docs/BACKLOG.md` and the AI memory and nothing else. `bench` owns `docs/benchmarks/**`. `wtree` owns six tooling/test paths. None allocates a number; none needs `claim.ps1` (no `BACKLOG #N` in any commit subject on a code-touching diff).

---

#### Session 1A · lane `ledger` · worktree `..\MessageFoundry-ledger`

| | |
|---|---|
| **Owns (exclusively, for the whole plan)** | `docs/BACKLOG.md` + the AI project memory (`~/.claude/.../memory/`) |
| **Items** | The entire §0 table: 24 `✅`, 6 `⛔`, 4 amendments, plus the ranked-table re-sync |
| **Step-0 claim** | **None.** Docs-only diff ⇒ `claim_check.py` does not fire. Allocates **no** numbers. |
| **Size** | M — mechanical, but high care |

**Why it is first and highest-value:** it is the only control against a session rebuilding #213's ~1,500 lines, re-running #215's five 900-second AWS soaks, or re-deriving #218's published verdict. It also disarms the live #231 trap.

**Build steps**

1. **Write every banner fresh from the code you verify yourself. Never paste vault prose.** The vault's copy of `docs/BACKLOG.md` fails `scripts/security/scan_forbidden.py`, and the hits are **not** confined to the high-numbered range you would expect — several sit inside the `#1-#231` range, including inside `## 231.` itself, the very item this lane must correct. Assume any vault line may carry a token; the gate, not a memorised range, is the authority. `docs/BACKLOG.md` is **not** in the leak gate's `docs/security/*` allowlist.
2. **Edit only the leading `> <glyph>` banner block** of each `## N.` section. Leave the prose below it untouched.
3. **Banner invariant (`scripts/docs/backlog_status_check.py`).** The banner block runs from the heading through every blank-or-`>` line and terminates at the first non-blockquote line. Exactly one such block per item; a CLOSED glyph (`✅ ⛔ 🪦`) must **never** coexist with an OPEN one (`🔢 🚧`); two OPENs are legal. Several items carry two banner lines (#117 has `🛠`+`🔢`, #48 has `🔢`+`🔶`) — remove the stale OPEN one; `🛠`/`🔶` are not status glyphs and may stay. Re-run the checker after **every** commit.
4. **Every banner cites `path:line` or an ADR id.** The checker is structural — its own docstring says *"it cannot know whether a banner is truthful, only that a claim exists and does not contradict itself."* `origin/main` passes it **today**, with all 30 stale banners in place. A fabricated citation also passes. See the DoD.
5. Apply §0a (24 `✅`), §0b (`✅` for #218/#215/#212/#211/#208; `⛔` for #217/#210/#157/#87/#91/#231), §0c amendments (#214 `🚧` with residuals, #105/#94/#99 re-priced). **Do not touch #185** — it is `🔢` on the owner's ledger and only the owner can close it.
6. **Required wording:**
   * **#157** — *"do NOT delete `messagefoundry/transports/direct.py`; the outbound S/MIME half ships and stays."*
   * **#208** — the residual is **off-repo measurement**; no in-repo code can close it. Do not restate any sampler sizing.
   * **#211** — closed as characterization-only; **not** a licence to flip the `claim_mode` default, and not a rig ask.
   * **#212** — *decided: ships OFF*; cite `THROUGHPUT-STATUS §Phase 3(2)` + ADR 0107. Revisit only on a **latency or store-load** rationale.
   * **#216** — record `simple_fraction = 0.72` and `hub_fanout = 3` as **owner-sign-off-required**, and the shape discrepancy (72/28 at fan-out 3 vs the item's "17% hub H=20, N=4").
   * **#214** — mechanism merged; residual = one settings field, **owner-coordinated** (`wiring_runner.py:250`), and residual (a) **deferred by owner decision 2026-07-24**. The lever is **triply dark** (see §5.1).
   * **#209** — code done; the H=20 rig run is bench time.
7. **Ranked tables last.** Rows in the two ranked tables near the top are adjacent — `#169` L161 / `#179` L163, `#96` L167 / `#141` L169 / `#180` L170, `#208` L284 / `#211` L285 — all inside git's 3-line merge context. Nothing else in this plan writes `docs/BACKLOG.md`, so this lane re-syncs both tables as its **final commit**, after all the `## N.` sections. Do **not** set `merge=union` (it duplicates banners and trips the one-status rule). Re-run the leak gate on that commit too.
8. **Memory corrections** (this lane is the only memory writer in the plan; concurrent writes are last-write-wins):
   * `mf-ci-test-flakes` — the `no_loss` "LIVE TAX" is **FIXED** (PRs #17 + #26); all three copies read `budget = max(unconfirmed_budget, sent // 2)`.
   * `mf-asvs-11-3-3-aad-cellbind` — **MERGED on main**; the branch exists on neither remote; only the `[store].aad_bind` default-flip decision remains (`settings.py:373`, ADR 0148:202).
   * `mf-security-scanners-mirror` — "~22 mirror CodeQL alerts" → **32**, on the **public** repo, not a mirror.
   * `mf-handoff-check-existing-prs` — `dg-s5` was **reconciled** (PR #1220, 2026-07-24): #97 and #117 are on main and ADR 0124 exists.
   * **NEW guardrail entry** — *`alloc.ps1 -Kind backlog` derives its floor from `docs/BACKLOG.md` files (not refs). From the public baseline (max #231) it issues **#232**, which already exists in the live ledger (max #314), and **both ledger gates pass**. Never allocate a BACKLOG number from `origin/main`.*
   * Respect `mf-memory-maintenance`: prune don't shave; the size hook fires on entry count; archive-on-add; never demote a guardrail.

**Verification** (each block is one command call — PowerShell state does not persist between calls):

```powershell
python scripts/docs/backlog_status_check.py
```
```powershell
$env:QT_QPA_PLATFORM="offscreen"; pytest -q tests/test_backlog_status_check.py
```
```powershell
$env:MEFOR_REQUIRE_TOKENS="1"; $env:MEFOR_MIN_DETECTORS="names=7,estate=13,site_prefixes=1"; python scripts/security/scan_forbidden.py --path .; "exit=$LASTEXITCODE"
```
```powershell
git diff -U0 origin/main -- docs/BACKLOG.md | Select-String -Pattern '^[+-]\|'
```

**Definition of done**
* `backlog_status_check.py` reports `OK — 229 backlog items, each declaring exactly one status`.
* `tests/test_backlog_status_check.py` green **locally** — on a docs-only PR `ci.yml`'s `changes` job classifies `docs/BACKLOG.md` as noncode, so the three required `test` contexts report green **having installed nothing and run nothing**. The local run is the only real enforcement here.
* **Evidence check:** extract every `path:line` citation from the diff and assert each path resolves — `git cat-file -e HEAD:<path>` for each — then hand-re-verify a random sample of five.
* No ranked-table row changed until the final commit; the `-U0` diff above returns nothing before it, and only intended rows after.
* Leak gate exit **0** from an **unpiped** call, with the printed `loaded names=… estate=… site_prefixes=…` line pasted as evidence.
* Five memory entries corrected. Committed locally on branch `ledger`. **Not pushed.**

**Stop and ask the owner if:** a banner flip would require closing #185, re-opening a `✅ CLOSED — owner-ratified` item, or importing any text from the vault ledger.

---

#### Session 1B · lane `bench` · worktree `..\MessageFoundry-bench`

| | |
|---|---|
| **Owns** | `docs/benchmarks/**` |
| **Items** | The `#220`/`#208` documentation-truth defect |
| **Step-0 claim** | **None** — docs-only, no `BACKLOG #N` in any commit subject |
| **Size** | S |

**Why:** `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` calls #220 *"the residual"* and says the instrument *"must be BUILT"*. That **conflates** #220's already-fixed `_drain_proc` delta bug with #208's off-repo measurement. Nothing in `tests/` or `.github/workflows/` reads this file, so the text is the only gate — reading it as "#220 is open" causes a double-build.

**Build steps**

1. **Fix every `#220` residual attribution.** There are **seven** occurrences, not six: lines **379, 1653, 1698, 1803, 1823, 1897, 2030**. (Line 1698 reads `it to a component (residual **#220**):` and is missing from both earlier drafts of this plan.) Do not work from the fixed list — the line numbers shift as you edit. Work from the grep, and finish when it is empty.
2. Rewrite each so #220 reads **FIXED** (`harness/load/connscale/probe.py:50-70`, `runner.py:926-1014`, `tests/test_connscale_cpu_probe.py`) and the residual is attributed to **#208's off-repo Part B**.
3. **Correct `docs/benchmarks/PLAN-ENGINE-ATTRIBUTION.md` §3.** Its stated prerequisite — *"needs `PoolWaitInfo.count`/`mean_ms` sampled (~2 lines)"* — is **already satisfied**: `harness/load/enginepoll.py` declares `pool_acquire_wait_count` / `pool_acquire_wait_mean_ms` at 105-106 and 172-173, reads them from status at 718-719, rolls them across shards at 637-641, and exposes them via `PoolStats` at 331-332. Only the derived arithmetic is missing.
4. **Do NOT publish any sizing for a shardcert per-PID sampler.** The owner's ledger closed #208 with *"no code change in this repo can close it"*; a `~200-line sampler` claim on a doc that is itself a status source would re-open a settled question.
5. **Do NOT land `store_service_ms`.** It is code in a lane declared docs-only, on an item the owner closed. It moves to §5.5 as a small owner ask.
6. **Do not touch `docs/BACKLOG.md`** (1A owns it — cite items, never edit them) or `harness/load/profiles/pooled_ab.toml` (#211 is closed).

**Note for 2A:** this lane's files are **not** excluded from the slug-rot detector — only `docs/benchmarks/results` is. `HANDOFF-enginebox-step2-step3.md` (3 hits) and `PLAN-PHASE4-GROUP-COMMIT.md` (1) are live `_PROSE` counts. Report your post-edit count to the `sec` lane.

**Verification:** the standing block (§6) plus
```powershell
git show HEAD:docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md | Select-String -Pattern '#220'
```

**Definition of done:** the grep above returns **zero** lines attributing a residual to #220; `PLAN-ENGINE-ATTRIBUTION.md` §3 reflects reality; `git diff --name-only origin/main` shows **no** `docs/BACKLOG.md`; full local suite green; committed locally.

---

#### Session 1C · lane `wtree` · worktree `C:/mfwtree` (short path — see below)

| | |
|---|---|
| **Owns** | `scripts/worktree/sessions.ps1` (new), `scripts/hooks/worktree_gate.ps1`, `scripts/worktree/install-gate.ps1`, `docs/WORKTREES.md`, `tests/test_worktree_gate.py`, `tests/test_install_gate_wiring.py` |
| **Item** | `DEBT-session-rescue` |
| **Step-0 claim** | **None.** Allocate **no** BACKLOG number (§6 rule 3). |
| **Size** | M |

**Why:** relocating a live session into a worktree re-files its transcript under the worktree slug and the chat **vanishes** from its window's list. There is no rescue tool on main.

**Build steps**

1. **Port, do not rebuild.** The work is complete on the vault branch `salvage/worktree-session-rescue` @ `49cb250c2c978de74feab2152809ceb55cbe6658` (2026-07-24, +474 lines / 6 files: `sessions.ps1` 369 new, `worktree_gate.ps1` +29, `install-gate.ps1` +1, `WORKTREES.md` +25, `test_worktree_gate.py` +49, `test_install_gate_wiring.py` +1). All six paths already exist on main.
2. **`git merge-base origin/main 49cb250c` is EMPTY** — the public repo's history is **disjoint** from the vault's (roots `5fa6db9f` vs `ef399475`). It cannot be merged. Cherry-pick it (which works across disjoint histories because every path exists on both sides) or `format-patch` + `am`. **A harness gate refuses any command whose STRING contains merge words — even inside an `echo` or a comment.** Keep merge-worded text out of every command string.
3. **Re-anchor rule 4 by hand.** Main's `scripts/hooks/worktree_gate.ps1` has grown rules 1/2/3/3b (L85-330) since 2026-07-24; the +29-line `EnterWorktree` deny block needs a new insertion point and its rule-numbering comments reconciled.
4. **Merge `tests/test_worktree_gate.py` (+49) into main's diverged copy** — expect a real conflict; do not overwrite.
5. In `docs/WORKTREES.md`, note that `scripts/worktree/rescue.ps1` (already on main) is a **different** tool — it moves uncommitted work out of the primary; it is not the transcript rehome.
6. **⛔ Do not run `scripts/worktree/install-gate.ps1` in any mode.** It is a **user-scope `PreToolUse`** hook (`~/.claude/hooks`, not `.git/hooks`), so installing it mid-wave changes what every concurrent sibling session is permitted to do — and it cannot run from a session anyway: `install-gate.ps1:59` throws *"Refusing to run inside Claude Code"* on `$env:CLAUDECODE -eq "1"`, **before** the `-Status` branch at `:119`. Any earlier plan that asserted on `-Status` output was asserting on an impossible command. Assert on the branch via pytest instead. The owner runs the install from a plain pwsh terminal after the wave.

**Verification:** the standing block plus
```powershell
$env:QT_QPA_PLATFORM="offscreen"; pytest -q tests/test_worktree_gate.py tests/test_install_gate_wiring.py
```

**Definition of done:** six files reconciled; those two test modules green; full local suite green; `install-gate.ps1` deliberately **not** run; committed locally on branch `wtree`, with a one-line handoff telling the owner to run `install-gate.ps1` from a plain terminal after the wave.

> **MAX_PATH:** `new.ps1`'s `pip install -e ".[dev,harness]"` bootstrap dies on Windows MAX_PATH under long worktree paths (PySide6's nested Qt tree). This lane is the one most likely to hit it. Use a short path and the manual venv in the kickoff prompt — and if the full extras set will not install, say so in the DoD ("full suite NOT run locally — CI is authoritative for this lane") rather than reporting a green partial run.

---

### WAVE 2 — the code-scanning backlog · 1 lane · ~1-2 days

Runs after Wave 1 merges, because it owns `.github/workflows/**` and needs a stable `_PROSE` count from 1B.

#### Session 2A · lane `sec` · worktree `..\MessageFoundry-sec`

| | |
|---|---|
| **Owns (exclusively, for the whole plan)** | `.github/workflows/**`, `docs/adr/0034-static-analysis-triage-policy-accepted-risk-register.md`, `tests/test_cutover_slug_rot.py`, `docs/INSTALL-GUIDE.md`, `docs/Secure_AI_Development_Standards.md`, `tests/test_release_pipeline.py`, `tests/test_off_loopback_runbook.py`, `.gitignore`, and every flagged source/test file below |
| **Items** | `DEBT-codeql` (32 alerts) + `DEBT-slugrot-ratchet` |
| **Step-0 claim** | **None.** Allocate **no** BACKLOG number (§6 rule 3); track the work in the ADR 0034 register. |
| **Size** | M |

**Why one lane:** three separate constraints all collapse to a single owner. (i) `.github/workflows/**` must have one owner — `release.yml` carries both `_PROSE` prose hits **and** pip-hash alerts, and with branch protection `strict: false` two lanes editing it can both merge green over each other. (ii) The ADR 0034 register is a **tail-append table**; `scripts/hooks/ledger_check.py`'s own docstring records *"the tail-append hazard shows up as a DROPPED ROW, not as a conflict. Three ADRs were already lost this way."* (iii) The `_PROSE` ratchet must be lowered in the same commit as the sweep, so the sweeper must own every `_PROSE` surface.

**Live inventory** (re-fetch to confirm before acting):

```powershell
gh api "repos/MEFORORG/MessageFoundry/code-scanning/alerts?state=open&per_page=100" --jq '.[] | "\(.number) \(.rule.id) :: \(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)"'
```

| Class | n | Locations |
|---|---|---|
| `PinnedDependenciesID` | 11 | `release.yml:91,131,175,177,214,363`; `security.yml:138,140`; `freethread-smoke.yml:82,83`; `zizmor.yml:42` |
| `TokenPermissionsID` | 1 | `dependabot-auto-merge.yml:44` |
| `py/clear-text-logging-sensitive-data` | 5 | `messagefoundry/pipeline/alerts.py:319,328,336`; `messagefoundry/store/audit_tee.py:73`; `messagefoundry/__main__.py:1535` |
| `py/log-injection` | 4 | `messagefoundry/api/app.py:558,2829`; `messagefoundry/store/audit_tee.py:73`; `messagefoundry/pipeline/engine.py:1499` |
| `py/overly-permissive-file` | 4 | `tests/test_trust_anchors.py:164,166,168`; `tests/test_bootstrap_admin_perms.py:55` |
| `py/incomplete-url-substring-sanitization` | 3 | `tests/test_cert_cli.py:221,222,241` |
| `py/polynomial-redos` | 1 | `messagefoundry/api/multipart.py:73` |
| `py/stack-trace-exposure` | 1 | `messagefoundry_webconsole/routes/account.py:424` |
| `py/insecure-protocol` | 1 | `tests/test_api_tls.py:1154` |
| `js/file-system-race` | 1 | `ide/src/symbolIndex.ts:129` |

**Build steps**

1. **The 12 Scorecard-class alerts are NOT a bulk action-pinning fix.** Verified: every `PinnedDependenciesID` alert reads `score is 5: **pipCommand** not pinned by hash` — they are `pip install` lines, not GitHub Actions. Repo-wide, `grep -rE '^\s*(- )?uses:' .github/workflows/ | grep -vE '@[0-9a-f]{40}'` returns **zero** unpinned actions; every action is already SHA-pinned. And `dependabot-auto-merge.yml:44` **already carries** a `permissions:` block — the finding is `contents: write` at workflow scope, which its `gh pr merge --auto` step requires.
   * The honest fix for the 11 pip alerts is `--require-hashes` installs, which collides with the DEP-1 lock surface (`build`, `sigstore`, `cyclonedx-bom~=7.3`, `zizmor==1.5.2` are all ad-hoc installs today, and a missed lock re-export has reddened every open PR twice). **That is unsized design work — do not attempt it in this lane.** Route all 11 to *dismiss with a recorded reason* citing the DEP-1 coupling, and file the hash-pinning question in §5.5.
   * `TokenPermissionsID` → dismiss with the auto-merge requirement recorded.
   * **These 12 cannot be re-verified on a PR at all.** `scorecard.yml` triggers on `branch_protection_rule`, a weekly cron, `push: [main]` and `workflow_dispatch` — **no `pull_request`**. They only re-scan after merge or on the Monday cron.
2. **The 9 PHI-class alerts get per-path review. Never bulk-dismiss.** They collide directly with CLAUDE.md §9.
   * `messagefoundry/pipeline/alerts.py:319/328/336` — **enumerate every caller before deciding.** There are **two**, not one: `messagefoundry/pipeline/secret_rotation.py:327` passes `secret=_DEK_SECRET_ID` (an identifier, the bandit-B105-on-env-var-NAMES class), but `:439` passes `secret=check.secret`, derived from `SecretRotationRunner`'s generic `secret_source` callable — **not** a constant. An "only caller" dismissal here would be wrong.
   * `messagefoundry/store/audit_tee.py:73` — carries **both** classes on an **audit** path, the highest-consequence line in the set. Read the live alert text before assuming which value is tainted: it reads *"logs sensitive data (**password**)"*, and only `detail` routes through `safe_text()` at `:70` — `actor`, `client`, `action`, `channel_id` do not. Determine which `record` field CodeQL actually taints, then fix with a regression test. **If in doubt, fix — never dismiss an audit path on a hunch.**
   * `messagefoundry/api/app.py:558`, `:2829`, `messagefoundry/pipeline/engine.py:1499` — localized sanitization + regression tests.
   * `messagefoundry/__main__.py:1535` — check whether this is CLAUDE.md §9's documented *"CLI `dryrun`/`generate` output can contain full bodies"* carve-out.
3. `messagefoundry/api/multipart.py:73` (ReDoS) and `messagefoundry_webconsole/routes/account.py:424` (stack-trace exposure) are real, small, on request paths — **fix both with tests**. `ide/src/symbolIndex.ts:129` — review.
4. The 8 test-file alerts are the strongest dismissal candidates — each still needs a **recorded reason** in the register, per ADR 0034's own rule.
5. **Dismissal is outward-facing.** Prepare a table (alert number · rule id · `path:line` · disposition · reason) and write the register rows; **the owner executes the `gh api … -X PATCH` calls.** Do not PATCH from the session.
6. **Slug-rot ratchet, same lane.** `tests/test_cutover_slug_rot.py:71` sets `_PROSE_CEILING = 55`; measured actual on `1400e9ab` is **53** over 1,370 files.
   * **Measure first, in this worktree, after Wave 1 merged.** The earlier inventories are wrong in ways that change the work: `release.yml` has **4** hits (L51, 75, 76, 230) not 5; `docs/INSTALL-GUIDE.md` has **4** not 3; **`docs/adr/` is excluded wholesale by `_HISTORICAL`**, so ADR 0034's "7 hits" are 0 counted hits and the instruction to leave them alone protects nothing; the benchmark HANDOFFs are **not** excluded (only `docs/benchmarks/results` is) — `HANDOFF-enginebox-step2-step3.md` (3) and `PLAN-PHASE4-GROUP-COMMIT.md` (1) count, and lane 1B just edited them; `docs/BACKLOG.md` **is** `_HISTORICAL`-excluded, so lane 1A cannot trip it.
   * Sweep **adopter-facing prose first** (`docs/INSTALL-GUIDE.md`, `docs/Secure_AI_Development_Standards.md`), then `.github/workflows/release.yml` (match the voice already at `release.yml:74` — *"REMOVED at the MEFORORG cutover: …"*).
   * **Lower `_PROSE_CEILING` in the same commit as the sweep — to `measured + 3`, not to zero slack.** `tests/test_cutover_slug_rot.py::test_the_ratchet_is_not_slack` (L170-187) already asserts `slack <= 8`, so the current slack of 2 is legal by design and is why CI is green. Zero slack turns any future `the mirror` / `private repo` phrase from any lane into a red on three required contexts, with no revalidation under `strict: false`.
   * **Do not widen `_SELF` (L78/L85) into a glob** — it is deliberately one path, because the module spells out every phrase it searches for.
7. **`.github/workflows/release.yml` is an owner-approval file.** It has **no `pull_request` or branch trigger** — nothing on any PR executes it, and `tests/test_release_pipeline.py` gives structural guards only. Its first real execution after an edit is a `vX.Y.Z` tag = **two production-PyPI uploads**, and a successful upload burns that version forever (v0.3.1 needed four attempts and a hand-deleted release). Flag every `release.yml` hunk in the handoff and ask the owner to run the `workflow_dispatch` dry-run before the next tag.

**Verification:** the standing block plus
```powershell
bandit -r . --skip B101,B110,B311,B404,B608 --exclude ./tests,./harness,./samples,./ide,./docs/benchmarks/results,./packaging/messagefoundry-webconsole/tests,./.venv,./node_modules
```
```powershell
python scripts/security/crypto_inventory_check.py; zizmor .github/workflows
```
```powershell
$env:QT_QPA_PLATFORM="offscreen"; pytest -q tests/test_cutover_slug_rot.py tests/test_release_pipeline.py tests/test_off_loopback_runbook.py
```
**`semgrep` is CI-only.** It is a *required* context (`semgrep (project SAST rules)`) but its job is `runs-on: ubuntu-latest`, it has no supported Windows install, and the repo records that `semgrep --test` crashes on Windows path-pairing. Do not treat a green local run as evidence for it.

**Definition of done:** every one of the 32 alerts ends in exactly one of two states — **fixed + regression test**, or **register row written in ADR 0034 + on the prepared dismissal list for the owner**. `_PROSE_CEILING` lowered to `measured + 3` in the sweep commit. `bandit` clean (watch the B105-on-env-var-NAMES trap). Full local suite green. Committed locally. **The open-alert query is expected to be non-zero at DoD time** — 12 of the 32 cannot re-scan before merge, and dismissals are the owner's to execute.

**Stop and ask the owner if:** the `audit_tee.py:73` review suggests real PHI reaches the audit log; or a pip-hash-pinning fix starts to require `pyproject.toml`/lock changes.

---

### WAVE 3 — conditional (nothing starts without an explicit go)

| Lane / worktree | Items | Owns | Size | Gate |
|---|---|---|---|---|
| `xform` / `..\MessageFoundry-xform` | **#214** — expose the knob only | `messagefoundry/config/settings.py` (`PipelineSettings`, L1046-1177 only), `messagefoundry/pipeline/engine.py`, `messagefoundry/pipeline/wiring_runner.py` (L251 + L694 only), `docs/CONFIGURATION.md` `[pipeline]` (L622-635), `tests/test_transform_concurrency.py` | S | **§5.1 owner go** |
| `hist` | **#169** author-appendable history | `store/metadata.py` + the 4 `merge_user_metadata` call sites, `api/`, `messagefoundry_webconsole/` | M | demand-gate |
| `blob` | **#94** — **ADR ONLY**, no code | `docs/adr/0154+` | S | demand-gate |
| `rowcopy` | **#179 + #180 together, one ADR** | `store/{base,store,postgres,sqlserver,crypto,keyprovider}.py`, `pipeline/retention.py`, `__main__.py` | L | demand-gate |
| `role` | **#141** TCP role inversion | `transports/{tcp,mllp,x12,base}.py`, `config/wiring.py` | M-L | demand-gate |
| `cpimport` | **#105** residual | `messagefoundry/corepoint_import.py`, `messagefoundry/actions.py` | M-XL | **blocked on #313** |
| — | **#99(e)** AD lab | provisioning | infra + cloud spend | **blocked on #275** |

**Hard ordering if any fire**

1. **`xform` before `rowcopy` and `blob`** — all three edit `config/settings.py` and `docs/CONFIGURATION.md`; `xform`'s diff is ~3 lines. The section bodies (`StoreSettings` 259-654, `PipelineSettings` 1046-1177, `RetentionSettings` 1456-1612, `EgressSettings` 2334-2413) are 400-1900 lines apart and auto-merge; the shared `@model_validator` tails at 560-566 / 1958-1967 / 2037-2041 are the real collision points.
2. **`rowcopy` before `hist`** — both edit all four store files; `rowcopy` adds `_SCHEMA` DDL, `hist` only changes the four `merge_user_metadata` call sites (`store.py:4099`, `postgres.py:2474`, `sqlserver.py:3872`/`:4059`). `_schema_hash()` (`postgres.py:606`, `sqlserver.py:1358`) is content-derived, so ADR 0064 bumps are automatic — the only DDL collision risk is two new tables at the same `_SCHEMA` anchor.
3. **#179 and #180 must be ONE session with ONE ADR.** Both are an offline, disposition-preserving, **re-encrypting** row copy across three backends through `store/crypto.py` + `keyprovider.py`; both add a `sub.add_parser` in `__main__.py`; both need new `Store` protocol methods. Split, they write two copy engines and conflict in all four store files.
4. **`role` before any `blob` build.** Both add per-connection factory kwargs at `config/wiring.py` ~751-885 **and** a mutual-exclusion rule in the same validator block at 3388-3405 (where the #117×#82 guard lives), and both extend `transports/base.py` — where `role` *changes* the contract while `blob` *registers against* it. Keeping `blob` ADR-only satisfies this for free.
5. **`__main__.py` anchors, assigned up front** (all 40+ subparsers are one contiguous block, L62-731): #180's `migrate-store` goes immediately after the `restore-verify` block (~L657).
6. **Store-test trap:** local pytest **silently skips** the SQL Server and Postgres legs. Postgres has **no `outbox` table**; SQL Server does. Any new ciphered table must join **both** the SS and PG fixture reset lists or exact-reencrypt counts go green locally and red in CI.

---

## 3. Reconciles — already-built work that needs landing, not building

### 3.1 `dg-s5` — **already reconciled. Nothing to do.**

The task framing that `#97` and `#117` sit unmerged on a dormant `dg-s5` branch is **wrong as of 2026-07-24**. Verified on `origin/main`:

* `self.persistent` at `messagefoundry/transports/tcp.py:124` (comment cites #97) + `_send_persistent`:210; `messagefoundry/transports/x12.py:94`.
* `self.no_ack` at `messagefoundry/transports/mllp.py:620`, `_send_once_no_ack`:859, `_send_persistent_no_ack`:1007.
* **ADR 0124 is present** — `docs/adr/0124-outbound-mllp-fire-and-forward-no-wait-for-ack-delivery-on-write.md` with its index row at `docs/adr/README.md:151`.
* ADR 0067 §8 checkbox is `- [x]`, plus a full §9 amendment.
* The #117 × #82 incompatibility guard already exists at `config/wiring.py:3388-3405`, with both directions pinned in `tests/test_no_ack_wiring.py:47-60`.
* Merge commit `6df8f159` (PR #1220).

**Do not schedule a dg-s5 reconcile, and do not allocate an ADR for #117** — 0124 is taken. A rebuild would mint a second artifact against an already-amended ADR 0067. The only action is the banner flip in lane 1A.

### 3.2 `salvage/worktree-session-rescue` — the one real port (lane 1C)

**Procedure:**

```bash
git fetch https://github.com/wshallwshall/MessageFoundry 49cb250c2c978de74feab2152809ceb55cbe6658
git show 49cb250c --stat
git cherry-pick 49cb250c        # or: git format-patch -1 49cb250c && git am --3way
```

* **`git merge-base origin/main 49cb250c` is EMPTY.** Roots differ (`5fa6db9f` vs `ef399475`). A merge is impossible; a cherry-pick works because all six paths exist on both sides. **Never type a merge word into a command string** — the harness gate matches the string, not the operation.
* Expect a real conflict in `tests/test_worktree_gate.py` and a hand reconcile of the rule-4 insertion point in `scripts/hooks/worktree_gate.ps1`.
* **No ledger transfer is involved.** There is no BACKLOG number to move — #1055 is CLOSED-superseded and absent from `origin/main` — and this plan allocates none (§6 rule 3).

**Owner approval required for:** running `scripts/worktree/install-gate.ps1` (a user-scope hook governing every session; must be run from a plain pwsh terminal, after the wave), and the push/PR/merge of the branch.

---

## 4. Do not build

| Item | Action | Evidence |
|---|---|---|
| **#213, #220, #207, #209, #216** | Close `✅` | Shipped. #213 ≈ 1,500 lines + ADR 0084; #216 ≈ 1,200 lines + 3 test modules. |
| **#48, #221, #222, #82, #97, #117, #118, #142, #143, #144, #145, #102, #223, #187** | Close `✅` | Shipped; §0a gives `path:line` for each. |
| **#218, #215** | Close `✅` — experiments RAN | #215 is the most expensive possible re-do in the set (multiple 900 s soaks across five N values on a two-box AWS rig). **Do not fund the m7i.8xlarge upsize** — `THROUGHPUT-STATUS` §8 L1719 retires it. |
| **#212** | Close `✅` "decided: ships OFF" | `✅ CLOSED — owner-ratified 2026-07-17`; `settings.py:295` already `default=1`. Do **not** re-run the verification half (the code read is done and recorded). Do **not** mint an ADR — ADR 0107 already records the measurement. |
| **#211** | Close `✅` | `✅ CLOSED — owner-ratified 2026-07-17 (characterization-only)`. No rig time, no `pooled_ab.toml` edit, no P3 re-score onto an OPEN glyph. |
| **#208** | Close `✅` | `✅ SHIPPED 2026-07-20 — Part B is off-repo`; *"no code change in this repo can close it."* Publish no in-repo sizing for it. |
| **#217** group-commit | Decline `⛔` | ADR 0107 measured the whole lever class flat (*"Do not build F2 or F3"*); ADR 0099 withdrew ADR 0055; ADR 0069 ~9% utilised. The carriage-byte trim residual is a **storage** concern — re-file separately so it does not carry the dead rationale. |
| **#210** tempdb table vars | Decline `⛔` | Withdrawn 2026-07-12: *"Do not build it."* ADR 0114 deliberately **preserves** the four table variables and AC-1 golden-text tests pin the batch's **absolute bytes** — any edit breaks those plus the proc-DDL lint tests. The adoptable win is a SQL **config** (`MEMORY_OPTIMIZED TEMPDB_METADATA=ON`, +60%, owner already ruled ADOPT, currently reverted), not a T-SQL rewrite. |
| **#157** Direct/HIE | Decline `⛔` | Owner 2026-07-24. **Do NOT delete `messagefoundry/transports/direct.py`** — the outbound S/MIME half shipped (ADR 0085 PR1) and stays. Needs #23's IMAP/POP source first, which does not exist (`transports/email.py:38`: *"There is no email source yet"*). |
| **#87** competitive intelligence | Decline `⛔` | Owner 2026-07-24. Standing constraint outlives it: the subject competitor's identity stays out of every in-repo document — **the repo is now public**. |
| **#91** GIL-vs-FT | Decline `⛔` | Declined 2026-07-20 on four unavailable rig inputs. The `5/10 quick win` score is badly wrong — it is a funded measurement campaign, D8+ with a blocked-on-external-inputs flag. |
| **#231** Steps "Block" grouping | Correct to `⛔` | Declined 2026-07-20 against the #26 guardrail; the public file still shows `🔢 Filed`. **Live double-build trap.** |
| `DEBT-openprs` | Void | `gh pr list --state open` → `[]`. |
| `DEBT-noloss` | Code effort **0** | Fixed by PRs #17 + #26. Memory correction only (lane 1A). |
| `DEBT-pyodbc-retry` | **Watch, do not schedule** | `scripts/ci/retry-native-crash.sh` is invoked at `.github/workflows/ci.yml` lines **568, 592, 613, 632, 657**, retrying **only** on exit 139/134, never on exit 1 — so it cannot mask a regression. Blocked on upstream **pyodbc#1459**. Removal recipe when fixed: raise the floor in `pyproject.toml`, `uv lock`, **all four** DEP-1 re-exports, delete the 5 invocations and the script. |
| `origin/cla-signatures` | **Never delete or merge** | Orphan data branch; `.github/workflows/cla.yml:43` writes `signatures/version1/cla.json` to it. Deleting it breaks a **required** context. |

**Branch cleanup (owner-executed, Wave 0).** 16 stale `origin` refs, each traced to a merged PR: `claude/code-quality-free-alternative-…` (#18), `claude/freethread-liveness` (#27, = current main tip), `claude/gate-liveness` (#25), `claude/mefor-jdbc-support-…` (#9), `claude/mutmut-killed-count` (#19), `fix-17-misattribution` (#16), `flake-aad-needle` (#8), `flake-monitor-spin` (#5), `leak-gate-bootstrap` (#7), `noloss-budget` (#17), `reconcile-floor` (#26), `release-slug-fix` (#12), `release-v031` (#13), `release-v032` (#20), `slug-refs-fix` (#14), `slug-rot-guard` (#24). Plus ~11 stale locals including `ledger-precommit-hook` (remote gone) and `verify-throwaway`. **Exclude `origin/cla-signatures` and `origin/main`.**

---

## 5. Needs an owner decision before it can be scheduled

### 5.1 #214 — expose `transform_concurrency`? (gates Wave 3 lane `xform`)

The knob was **deliberately withheld**. `messagefoundry/pipeline/wiring_runner.py` at the `_DEFAULT_TRANSFORM_CONCURRENCY` block: *"Kept a module constant / instance attribute — NOT a `[transform]` settings section (**owner-coordinated**); a user-facing knob is a deliberate follow-up."* And `vault/main` #214 is `🚧 PARTIAL`, with residual (a) — the headline ~40× commit collapse — *"**DEFERRED by owner decision 2026-07-24**, pending a measured need."*

The lever is **triply dark**, not doubly. It engages only when **all three** hold: `[store].claim_mode = "per_lane"` (the default pooled runner is unaffected regardless of anything else), `[store].fifo_claim_batch > 1` (default 1, and #212 rules it stays off), and not on the SQL Server fused path (`self._fusion_active`, `wiring_runner.py:4819`).

**Ask:** expose the setting (default 1, byte-identical) — yes or no? If yes: the lane may **not** flip #214 to `✅`; the correct end state is `🚧` with residuals (a) and the per_lane gate still named. Make no throughput claim — ADR 0107 prices this as a lane-ceiling / serial-depth effect, not fleet throughput, and it is unmeasured.

### 5.2 Demand-gated — trigger **not** demonstrably fired

| Item | Trigger (verbatim) | Status | Honest re-score |
|---|---|---|---|
| **#169** | *"build when a Corepoint migration relies on MsgAddHistory breadcrumbs for message-level troubleshooting/audit parity"* | Not demonstrable here — the estate is in the unreachable `the private estate repo`. Absence proven: `add_history\|processing_history\|message_history\|msgaddhistory` → zero on main. | 6/4 → **6/3** if built as an ADR 0081 amendment (the metadata bag + its 3-backend column landed after the score). The real cost is **re-run-safe dedup**, not plumbing. |
| **#179** | *"…relies on CIEArchive-style archived-but-searchable history that retention's delete-only purge would discard"* | Not fired. Every `RetentionSettings` field (`settings.py:1456ff`) is a delete/compress knob; no copy step. | "quick win" is **understated** → **5-6**, and must be scored jointly with #180. |
| **#180** | *"…must promote an in-production SQLite store to a server backend without losing retained history/audit"* | Not fired, with **counter-evidence**: the committed deployment goes to SQL Server from the start — there is no SQLite store to promote. | 6/5 "quick win" is wrong → **6-7**. |
| **#141** | *"…a partner's firewall posture requires the engine to dial out and then receive, or to listen and then send"* | Not fired. Role binding is hard-coded (`open_connection` `tcp.py:182` / `mllp.py:810`; `start_server` `mllp.py:1302` / `tcp.py:423`) with no knob. | Size-plausible, but **"quick win" is wrong** — a listening OUTBOUND has no delivery target until a peer dials, colliding with the ADR 0067 connection cache, per-lane FIFO and the retry path. Needs an ADR. |
| **#94** | *"an adopter with an existing BLOB/object store and a document-heavy feed"* | Not fired. Substrate is no longer greenfield (ADR 0105/#149 complete; `parsing/binary.py` reserves the deref seam). | 6/8 → **~5-6**. Stays **ADR-first**. |

**Recommendation:** hold all five. If exactly one is funded, take **#94's ADR** — it is the cheapest, it resolves four design forks that would otherwise be decided badly under build pressure (pointer representation; the *never a presigned URL, always an opaque non-capability key* rule; reattach-on-outbound; and **where** an offload write runs against the at-least-once purity invariant), and it unblocks nothing else so it cannot cascade.

### 5.3 Hard-gated by a prior decision

* **#96 capacity estimator — `docs/adr/0074-adopter-capacity-estimator.md` reads `⛔ BUILD GATED (2026-07-14)`** after a validity re-check found **14 confirmed blockers**: the no-loss reconcile named as its only success gate **over-reports by 3-5.5×**, and the poller-zero failure mode *satisfies* it. Verbatim: *"Do not build the measurement layer until the owner re-ratifies the revised gate + estimand."* Only the fail-closed guard layer (AC-1/3/5/6) is buildable. The 5/10 difficulty rested on "reuse the existing harness machinery" — exactly what was found to over-report. **Ask: re-ratify a revised gate, or shelve?** Treat as 7+ and decision-blocked.
* **#105 — gated on BACKLOG #313** (multi-message Handler model): 2,032 statements refused for that one reason, plus 650 `$variable`/`MsgTreeCopy`/`MsgLoad`/`MsgCreate` markers. **#313 does not exist in the published backlog** (which ends at #231), so a session working from `origin/main` literally cannot see the gate and will burn out against the documented ceiling. **Ask: decide #313, or authorise only the ungated slices?** (`EnvLogText`→`log_note`, 63 mappings — needs an Action form with no leading `msg` plus a `messagefoundry` vs `messagefoundry.actions` import split, and **half-done it raises on every message**; the dead `False` condition placeholders; `<Connection>` subtree modelling.) Any #105 code commit also requires `scripts\coord\claim.ps1 -Take 105` first.
* **#99(e) AD lab — infra booking, not engineering. #275 hard-blocks it.** #275 is a suspected `kerberos_spn` splitting defect at cell L1; the fix if confirmed is small (split at the first `/` into `service=`/`hostname=` at **both** call sites in `messagefoundry/auth/ldap.py`). `docs/releases/BACKLOG-EXECUTION-PLAN-2026-07-24.md:23-25,105-110`: #275/#98/#99(e)/#274 share **one** throwaway forest — *"as one window, or not at all."* Motivating caveat: every serve-path TLS/proxy assertion monkeypatches `uvicorn.run` and `kerberos_principal` is `# pragma: no cover`, so **the entire AD acceptor path is mock-seam only**.

### 5.4 Ledger + posture calls only the owner can make

* **#185** is `🔢` on the owner's ledger (*"Index-only umbrella that owns no findings and ships nothing runnable"*). All 20 children are resolved and ADR 0115 re-partitioned the programme into #242-#246 (then #277/#280-#307), but **a session may transcribe a ruling, not originate one.** **Ask: close it as superseded?** If yes — explicitly **not** as "ASVS is done"; the programme continued past this baseline, and `docs/security/` is entirely gitignored post-cutover.
* **`[store].aad_bind`** ships **default off** (`settings.py:373`), holding ASVS 11.3.3 at Pass(B). ADR 0148:202: *"needs `aad_bind` default — separate decision."* The crypto and ~307 backend call sites are **merged**. **Flip under the PHI posture?**
* **`[auth].ad_session_recheck_seconds = 0`** (`settings.py:1777`) means the AD-disable reconciler **never runs out of the box**; `docs/SECURITY.md:1321` only *recommends* 300 off-loopback. Related accepted narrowing (ADR 0079, 2026-07-22): `require_step_up` does no directory bind, so a disabled account retains purge/export/bulk-replay/config-reload/`/users*` for up to `step_up_max_age_seconds` (300 s). **Flip, or PHI-posture-gate?**
* **CISO SEC-022 residual:** in `ide/src/aiPolicy.ts::assistantState`, BYO mode with `assistPermitted === null` (RBAC not evaluable offline) returns `{enabled:true}`. **Deliberate and commented.** Either re-accept explicitly in the register or treat a null permission bit as deny. **Do not let an agent "fix" this unilaterally.**
* **#223 option (a):** confirm the 2026-07-20 decline stands — `docs/releases/plan-13/OWNER-DECISIONS.md` §C still shows it undecided (~4-5 d, re-opens the #52 DBA-delegation boundary).
* **CISO register bookkeeping:** `auth.logout` and AD-disable are closed in code but `docs/security/CISO-REVIEW.md` is unreadable from this baseline. Owner-side.

### 5.5 Small follow-ons that fell out of this analysis

* **`store_service_ms = claim_mean_ms − acquire_wait_mean_ms`** — the inputs are already sampled (`harness/load/enginepoll.py` 105-106, 172-173, 637-641, 718-719); only the arithmetic is missing. `PLAN-ENGINE-ATTRIBUTION.md:232` calls it *"a free by-product, not a deliverable"* and requires the ~68-call-site homogeneity caveat be attached **to the report text**. It sits under a closed item (#208). **Ask: land it as a standalone harness fill-in, or drop it?** If landed: return `None`, never a fabricated `0.0`, mirroring `txn_per_message_measured` (`harness/load/report.py:676-682`).
* **Hash-pinned CI pip installs** (the 11 `PinnedDependenciesID` alerts) — the real fix is `--require-hashes`, which couples to the DEP-1 four-lock surface and to today's ad-hoc installs (`build`, `sigstore`, `cyclonedx-bom~=7.3`, `zizmor==1.5.2`). **Ask: fund it as its own scoped item, or accept the risk in the ADR 0034 register?**
* **`#209` H=20 rig run** and **`#216` 1,500-connection demo run** — bench time on the two-box AWS pair, plus owner sign-off on `simple_fraction`/`hub_fanout`. Not scheduled here.

### 5.6 Provisioning this plan needs

**None.** No lane in Waves 0-2 needs a bench rig, an AD forest, a server DB, or cloud spend. Wave 3's `rowcopy`/`hist` lanes would need CI round-trips on the SQL Server and Postgres legs (which skip locally); `#99(e)` needs the throwaway forest; `#209`/`#211`/`#216` need the AWS pair. **Never tear down or stop EC2 — that is the owner's call.**

---

## 6. Standing rules for every session

1. **Autonomy L1.** Build, verify, **commit locally**. Never `git push`, never `gh pr create`, never merge, never `gh api … -X PATCH` against the repo. Report the branch name and stop.
2. **Start the session already inside its worktree.** Never relocate a live session into one — the transcript re-files under the worktree slug and the chat vanishes from its window's list. No rescue tool exists on main until lane 1C lands **and** the owner runs `install-gate.ps1`.
3. **Allocate NO BACKLOG numbers from this baseline.** `scripts/coord/alloc.ps1`'s BACKLOG floor is **file-derived** (it reads `origin/main:docs/BACKLOG.md`, `HEAD:docs/BACKLOG.md` and the worktree file — it does **not** scan refs; only the ADR branch does). Public max is **#231**, live ledger max is **#314**, and the per-clone registry `<git-common-dir>/mefor-coord/alloc/backlog` is empty — so the first call issues **#232**, which already exists (`## 232. IDE engine-link doctor`). **Both ledger gates pass:** `owns()` returns True locally because this worktree really did allocate, and CI's `--ci` mode **skips the ownership check entirely** and only compares against base. The result is two differently-titled `## 232.` headings that merge clean. Use free-text claims (`claim.ps1 -Take codeql-triage`) — `claim_check.py` enforces only *numbered* claims declared in a commit **subject** on a code-touching diff. Only the owner, from a clone whose HEAD carries the vault ledger, can mint a real number.
4. **ADR numbers: `scripts\coord\alloc.ps1 -Kind adr` only, in the worktree that will commit.** Next is **0154**. `ledger_check.py::owns()` is a casefolded **exact** worktree-string comparison — a number allocated elsewhere is permanently uncommittable here. Add the `docs/adr/README.md` index row in the **same commit** or the pre-commit gate rejects it. **Never grep for the next free number.**
5. **One clone, many worktrees.** The alloc/claim registry lives at `<git-common-dir>/mefor-coord/`; a separate clone gets a separate registry and two sessions take the same number.
6. **Claim before code**, and flip `🔢 → 🚧` in its own commit first, for any lane touching non-`docs/`, non-`.github/`, non-`.md` paths. Nothing enforces the banner flip — it is the only anti-double-build control.
7. **Never reuse a worktree lane name.** `new.ps1`'s staleness check lives in the `else` arm only — if the branch already exists it runs `git worktree add $WorktreePath $Name` with no freshness check, silently resurrecting that branch's old tip.
8. **Worktree paths.** `scripts\worktree\new.ps1 -Name <lane>` creates **`..\MessageFoundry-<lane>`**, never `C:/mf<lane>`. Use one form consistently — `owns()` is path-exact. MAX_PATH fallback (PySide6's nested Qt tree kills the bootstrap under long paths): `git worktree add C:/mf<lane> -b <lane> origin/main` + a hand-built venv.
9. **Bootstrap, per worktree:**
   ```powershell
   scripts\worktree\new.ps1 -Name <lane>
   ```
   ```powershell
   cd ..\MessageFoundry-<lane>; .\.venv\Scripts\python.exe -m pip install --constraint constraints.lock -e ".[dev,harness,fhir,dicom,x12,xml,webauthn]" -e packaging/messagefoundry-webconsole
   ```
   ```powershell
   .\.venv\Scripts\python.exe -m pip install pre-commit bandit zizmor; pre-commit install
   ```
   ```powershell
   pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1; pwsh -NoProfile -File scripts\dev\setup-leak-gate.ps1
   ```
   * **`--constraint constraints.lock` is not optional** — CI installs with it (`mypy==2.3.0`, `ruff==0.15.22`, `pytest==9.1.1`); a bare install resolves from `pyproject`'s `>=` floors and produces strict errors CI never sees, or misses ones it does.
   * **A stock `new.ps1` worktree is under-powered.** It installs `.[dev,harness]`; CI installs the full extras set plus the editable webconsole. Everything else `importorskip`s locally and only asserts in CI.
   * **`bandit` and `zizmor` are not in the `dev` extra** — install them or the verification block fails as unknown commands. **`semgrep` is CI-only** (required context, ubuntu-only job, no supported Windows install).
   * **`.git/hooks` is shared across worktrees.** `pre-commit install` points the shared hook at the installing worktree's venv. Run it from **your** worktree immediately before your first commit; if a commit fails with a missing-interpreter error, re-run it.
10. **The verification block, every lane, before "done"** — each as a single command call (PowerShell shell state does **not** persist between calls):
    ```powershell
    ruff check . ; ruff format --check .
    ```
    ```powershell
    mypy messagefoundry messagefoundry_webconsole --exclude 'messagefoundry/tray/' ; mypy --platform win32 messagefoundry
    ```
    ```powershell
    $env:QT_QPA_PLATFORM="offscreen"; pytest -q
    ```
    ```powershell
    $env:QT_QPA_PLATFORM="offscreen"; pytest packaging/messagefoundry-webconsole/tests -q
    ```
    ```powershell
    python scripts/docs/backlog_status_check.py ; python scripts/hooks/ledger_check.py
    ```
    ```powershell
    $env:MEFOR_REQUIRE_TOKENS="1"; $env:MEFOR_MIN_DETECTORS="names=7,estate=13,site_prefixes=1"; python scripts/security/scan_forbidden.py --path .; "exit=$LASTEXITCODE"
    ```
    Run the **full** suite, not just your new test module — two documented CI reds came from running only the new file.
11. **The leak gate lies three ways.** (a) Its exit code **through a pipe is the pipe's** — measured: direct `2`, piped `0`. Never pipe it; read `$LASTEXITCODE` from an unpiped call. (b) A bare invocation scans only `git ls-files` (the index) — a new untracked file is invisible; use `--path .`. (c) Presence ≠ sufficiency: with no token source it degrades to structural-only and exits 0 green, and a partially-mangled list once loaded 1 of 21 detectors and still passed — which is why `MEFOR_MIN_DETECTORS` must be set **in the same command**. Never pass `--show-context` (it copies the leak into the log). Known false positive: a bare X.509 OID literal trips the routable-IPv4 detector (use `x509.SubjectAlternativeName.oid`). The customer name is blocked outside `docs/security/*` — and `docs/BACKLOG.md` is **not** allowlisted.
12. **`setup-leak-gate.ps1` with no switch is a reporter, not a bootstrap** — it changes nothing and exits 1 when structural-only. Record the printed `loaded names=… estate=… site_prefixes=…` line as evidence, not the exit code.
13. **Never `--no-verify`**, never a rename workaround. **Stage explicit paths** — `git add -A|.|-u` and `git commit -a` are refused repo-wide by `scripts/hooks/block-blanket-git-stage.ps1`.
14. **No `Co-Authored-By: Claude` trailer** — the required `cla` context fails on it.
15. **The harness gate matches the COMMAND STRING, not the operation.** A command containing merge words is refused even inside an `echo` or a comment. It also blocks subagent dispatch from the primary checkout. Use `git commit -F <file>` for multi-line messages; keep merge-worded text out of every command string.
16. **PHI / secrets.** Synthetic HL7 only. Never read or write `.env`, secrets, keys, or `*.db`. Never commit customer/partner names, IPs, ports or site codes. **Never paste vault ledger prose** (measured: 102 leak-gate hits).
17. **Any `pyproject.toml` dependency change requires `uv lock` plus ALL FOUR DEP-1 re-exports** (`requirements.lock`, `docker/locks/requirements-core.lock`, `docker/locks/requirements-sqlserver.lock`, `constraints.lock`). A missed `constraints.lock` reddened every open PR twice.
18. **Ask before irreversible or outward-facing actions.** Branch deletes, code-scanning alert dismissals, installs, migrations, `install-gate.ps1`, and anything touching `.github/workflows/release.yml`.
19. **The claim gate and the push guard fail open** with no python on PATH (both generated `#!/bin/sh` hooks end `|| exit 0`). Do not treat their silence as a pass.

**Owner-side merge discipline (`strict: false` on `main`, `enforce_admins: false`).** Up-to-date-before-merge is **OFF**: a branch green against a 20-merge-old base merges without revalidation, so two lanes green on the same file can merge clean and break `main`. Before arming auto-merge on each PR: `gh api -X PUT repos/MEFORORG/MessageFoundry/pulls/<N>/update-branch`, let CI re-run (a bare `gh run rerun` keeps the old base and revalidates nothing), push everything **before** arming, then assert `gh api repos/MEFORORG/MessageFoundry/pulls/<N> --jq .head.sha` equals local HEAD — a commit pushed after arming can be silently dropped while the PR still reports MERGED. Merge in **file-surface order**, not priority order. A direct push to `main` is not blocked server-side for the owner; the only guard is the per-clone `pre-push` hook (`scripts/hooks/push_guard.py`), which **fails open with no python**. After the last PR merges, run `pwsh -NoProfile -File scripts\worktree\install-gate.ps1` from a plain pwsh terminal.

---

## 7. Kickoff prompts

> Start each in a **fresh session opened inside its own worktree**. Never relocate a live session.

### 7.1 — Wave 1A · `ledger`

```text
You are the LEDGER RECONCILE session for MessageFoundry. Autonomy L1: build, verify, COMMIT
LOCALLY ONLY. Never push, never open a PR, never merge. Read CLAUDE.md first.

BOOTSTRAP (from C:/Users/<you>/Code/MessageFoundry):
  scripts\worktree\new.ps1 -Name ledger
  cd ..\MessageFoundry-ledger
  .\.venv\Scripts\python.exe -m pip install --constraint constraints.lock -e ".[dev,harness,fhir,dicom,x12,xml,webauthn]" -e packaging/messagefoundry-webconsole
  .\.venv\Scripts\python.exe -m pip install pre-commit bandit zizmor; pre-commit install
  pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1; pwsh -NoProfile -File scripts\dev\setup-leak-gate.ps1

YOU OWN docs/BACKLOG.md EXCLUSIVELY and you are the ONLY session writing AI memory. You touch
NO other file. You need no claim.ps1 (docs-only diff). You allocate NO numbers.

⛔ TRAP — DO NOT RUN `alloc.ps1 -Kind backlog`. Its BACKLOG floor is FILE-derived (it reads
docs/BACKLOG.md, not refs). This public baseline ends at #231; the live ledger runs to #314.
It would issue #232, which ALREADY EXISTS, and BOTH ledger gates would pass (owns() is true
locally; CI's --ci mode skips the ownership check entirely). That is silent corruption.

⛔ TRAP — DO NOT COPY ANY TEXT FROM THE VAULT LEDGER. Measured: vault/main:docs/BACKLOG.md
fails scripts/security/scan_forbidden.py with 102 hits, and they are NOT confined to the
#232+ range — lines 594, 595, 5815, 5824, 6698 are inside #1-#231, and 5815/5824 sit inside
## 231 itself. WRITE EVERY BANNER FRESH FROM CODE YOU VERIFY YOURSELF.

CONTEXT: origin/main:docs/BACKLOG.md is a single-commit 2026-07-12 snapshot (9e4e614e, PR #6,
never updated, ends at #231) while origin/main's CODE is current through 2026-07-28. Thirty
items contradict the code or an owner ruling. This file is the mechanism by which merged work
gets rebuilt.

CLOSE ✅ — SHIPPED (verify each against the code before writing the banner):
  #48 #82 #97 #102 #117 #118 #142 #143 #144 #145 #187 #207 #209 #213 #216 #220 #221 #222 #223
CLOSE ✅ — EXPERIMENT RAN / OWNER-RATIFIED:
  #218 (C1, 2026-07-10, DECLINING)   #215 (C2/C3/C5; Phase 5 closed, R in [2,3))
  #212 (✅ CLOSED owner-ratified 2026-07-17; settings.py:295 already default=1)
  #211 (✅ CLOSED owner-ratified 2026-07-17, characterization-only)
  #208 (✅ SHIPPED 2026-07-20; Part B is OFF-REPO — "no code change in this repo can close it")
CLOSE ⛔ — DECLINED:
  #217 (ADR 0107/0099/0069)  #210 (withdrawn 2026-07-12, "Do not build it"; ADR 0114 preserves
  the table variables)  #157 (owner 2026-07-24)  #87 (owner 2026-07-24)  #91 (2026-07-20)
  #231 (DECLINED 2026-07-20 against the #26 guardrail — the public file still says 🔢 Filed;
        this is a LIVE double-build trap)
AMEND ONLY (re-price, do NOT close):
  #214 -> mechanism merged + tested; residual is ONE settings field and it is OWNER-COORDINATED
          (wiring_runner.py:250) with residual (a) DEFERRED by owner decision 2026-07-24. Stays
          🚧. Record that the lever is TRIPLY dark: it needs claim_mode="per_lane" AND
          [store].fifo_claim_batch>1 AND not the SQL Server fused path (wiring_runner.py:4819).
  #105 -> ADR 0086 Amendment 2026-07-24 §2(a') DISCHARGES the "synthetic schema" blocker; the
          real gate is #313 (invisible from this baseline).
  #94  -> re-score 8 -> 5-6 (ADR 0105/#149 shipped the substrate 2026-07-13; parsing/binary.py
          reserves the deref seam at 55-62/252/266). Still ADR-first.
  #99  -> only sub-item (e) remains and it is PROVISIONING, not code; (g) shipped via #274/ADR 0142.
LEAVE ALONE ENTIRELY: #185 (it is 🔢 on the OWNER'S ledger — a session transcribes a ruling, it
  never originates one), #169 #179 #180 #141 #96 (demand-gated, triggers not fired).

RULES
1. Edit ONLY the leading `> <glyph>` banner block of each `## N.` section. Leave the prose below.
2. Banner invariant: the block runs from the heading through every blank-or-`>` line and ends at
   the first non-blockquote line. Exactly one block. A CLOSED glyph (✅⛔🪦) must NEVER coexist
   with an OPEN one (🔢🚧). Two OPENs are legal. Some items carry two banner lines (#117 has
   🛠+🔢, #48 has 🔢+🔶) — remove the stale OPEN one; 🛠/🔶 are not status glyphs and may stay.
3. Every banner cites a real path:line or ADR id. Examples to verify yourself:
   #213 -> config/wiring.py ~2268-2360 + pipeline/dryrun.py 206-264 + tests/test_accepts_seam.py
   #97  -> transports/tcp.py:124 + ADR 0067 §9 amendment + merge 6df8f159 (PR #1220)
   #117 -> transports/mllp.py:620 + docs/adr/0124-*.md + the guard at config/wiring.py:3388-3405
   #102 -> store/base.py:1401 + pipeline/dr.py:413-478
   #220 -> harness/load/connscale/probe.py:50-70 + runner.py:926-1014
4. Required wording:
   #157 -> "do NOT delete messagefoundry/transports/direct.py; the outbound S/MIME half ships."
   #208 -> the residual is OFF-REPO measurement. Publish NO in-repo sizing for it.
   #211 -> characterization-only; NOT a licence to flip the claim_mode default; no rig ask.
   #212 -> "decided: ships OFF", citing THROUGHPUT-STATUS §Phase 3(2) + ADR 0107.
   #216 -> simple_fraction=0.72 and hub_fanout=3 still need OWNER SIGN-OFF; note the shape
           discrepancy (72/28 at fan-out 3 vs the item text's "17% hub H=20,N=4").
   #209 -> code done; the H=20 rig run is bench time, not code.
5. ⛔ DO NOT TOUCH EITHER RANKED TABLE until your FINAL commit. Rows there are adjacent
   (#169 L161/#179 L163; #96 L167/#141 L169/#180 L170; #208 L284/#211 L285 — all inside git's
   3-line context). No other session writes this file, so YOU re-sync both tables as your LAST
   commit, after every `## N.` section. Never set merge=union.
6. Commit in 4-6 thematic commits (perf/harness · alerting · transports · security+DR · IDE ·
   declines), then the table re-sync. Run the checker after EVERY commit.

VERIFY (each block is ONE command call — PowerShell state does not persist between calls):
  python scripts/docs/backlog_status_check.py
  $env:QT_QPA_PLATFORM="offscreen"; pytest -q tests/test_backlog_status_check.py
  $env:QT_QPA_PLATFORM="offscreen"; pytest -q
  $env:MEFOR_REQUIRE_TOKENS="1"; $env:MEFOR_MIN_DETECTORS="names=7,estate=13,site_prefixes=1"; python scripts/security/scan_forbidden.py --path .; "exit=$LASTEXITCODE"
  git diff -U0 origin/main -- docs/BACKLOG.md | Select-String -Pattern '^[+-]\|'

⚠️ backlog_status_check.py is STRUCTURAL — its own docstring says it "cannot know whether a
banner is truthful". origin/main PASSES IT TODAY with all 30 stale banners. A fabricated
citation passes too. So ALSO: extract every path:line citation from your diff and assert each
resolves (git cat-file -e HEAD:<path>), then hand-re-verify five at random.
⚠️ On a docs-only PR the three required `test` CI contexts report green having run NOTHING
(ci.yml classifies docs/BACKLOG.md as noncode). Your LOCAL pytest is the only enforcement.
⚠️ The leak gate's exit code through a pipe is the pipe's (measured: direct 2, piped 0). Never
pipe it. Paste its printed "loaded names=… estate=… site_prefixes=…" line as evidence.

THEN write these AI memory corrections (you are the only memory writer):
  - mf-ci-test-flakes: the no_loss "LIVE TAX" is FIXED (PRs #17 + #26); all three copies read
    `budget = max(unconfirmed_budget, sent // 2)` at harness/load/report.py:614,
    connscale/runner.py:838, estate/runner.py:444.
  - mf-asvs-11-3-3-aad-cellbind: MERGED on main (cell_aad store/crypto.py:153; counts store.py
    104 / sqlserver.py 127 / postgres.py 76; ADR 0019 Amendment 2026-07-17). The branch exists
    on NEITHER remote. Only the [store].aad_bind default-flip decision remains. The entry
    currently overstates the remaining work by >10x.
  - mf-security-scanners-mirror: "~22 mirror CodeQL alerts" -> THIRTY-TWO, on the PUBLIC repo.
  - mf-handoff-check-existing-prs: dg-s5 was RECONCILED (PR #1220, 2026-07-24); #97 and #117 are
    on main and ADR 0124 exists.
  - NEW GUARDRAIL: `alloc.ps1 -Kind backlog` derives its floor from BACKLOG.md FILES, not refs.
    From the public baseline it issues #232, which already exists in the live ledger (max #314),
    and BOTH ledger gates pass. Never allocate a BACKLOG number from origin/main.
  Respect mf-memory-maintenance: prune don't shave; the hook fires on ENTRY COUNT; archive-on-add;
  never demote a guardrail.

DONE WHEN: 30 items closed with evidence-bearing banners, 4 amended, ranked tables re-synced in
the final commit, checker + leak gate green, evidence check passed, memory corrected.
STOP AND ASK if a flip would require closing #185 or re-opening an owner-ratified item.
DO NOT PUSH. No Co-Authored-By trailer. Never --no-verify. Stage explicit paths only.
```

### 7.2 — Wave 1B · `bench`

```text
You are the BENCH-DOCS TRUTH session for MessageFoundry. Autonomy L1: COMMIT LOCALLY ONLY.
Never push, never open a PR, never merge. Read CLAUDE.md first.

BOOTSTRAP: scripts\worktree\new.ps1 -Name bench, then cd ..\MessageFoundry-bench and run the
standard block (constraint-pinned full-extras install, pre-commit + bandit + zizmor,
install-git-hooks.ps1, setup-leak-gate.ps1).

YOU OWN: docs/benchmarks/** and nothing else.
⛔ YOU MUST NOT TOUCH docs/BACKLOG.md (another session owns it — cite items, never edit them)
   or harness/load/profiles/pooled_ab.toml (#211 is CLOSED).
⛔ Allocate NO numbers. You need no claim.ps1 — keep this lane docs-only and keep "BACKLOG #N"
   out of every commit SUBJECT.

TASK 1 — fix a documented misattribution that will otherwise cause a double-build.
docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md calls BACKLOG #220 "the residual" and says the
instrument "must be BUILT". That CONFLATES #220's already-FIXED _drain_proc CPU-delta bug with
#208's residual. There are SEVEN occurrences, not six: lines 379, 1653, 1698, 1803, 1823, 1897,
2030. (Line 1698 reads `it to a component (residual **#220**):` and is missed by every earlier
list.) DO NOT work from that fixed list — line numbers shift as you edit. Work from the grep:
  git show HEAD:docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md | Select-String -Pattern '#220'
and finish when it returns zero residual-attributions.
Verify #220 is fixed yourself: harness/load/connscale/probe.py:50-70 (ProcSample.cpu_pids,
docstring names #220), runner.py:926-1014 (piecewise max(0,Δcpu) over pa==pb intervals,
membership-changed intervals degraded to a gap, cpu fields None not a fabricated 0.00),
estate/runner.py:513-542, tests/test_connscale_cpu_probe.py.
Rewrite each citation so #220 reads FIXED and the residual is attributed to #208's OFF-REPO
Part B.

⛔ CRITICAL: #208 is `✅ SHIPPED 2026-07-20` on the owner's ledger — "the in-repo work is done;
Part B is off-repo and does not belong on this ledger … no code change in this repo can close
it." DO NOT publish any sizing for an in-repo shardcert per-PID sampler. The owner refuted that
framing; writing it into a status doc re-opens a settled question.

TASK 2 — correct docs/benchmarks/PLAN-ENGINE-ATTRIBUTION.md §3. It says the store_service_ms
survivor "needs PoolWaitInfo.count/mean_ms sampled (~2 lines)". THAT IS ALREADY DONE:
harness/load/enginepoll.py declares pool_acquire_wait_count / pool_acquire_wait_mean_ms at
L105-106 and L172-173, reads them from status at L718-719, rolls them across shards at
L637-641, and exposes them via PoolStats at L331-332. Only the derived arithmetic is missing.
State that plainly. DO NOT LAND store_service_ms — it is code in a docs-only lane on a closed
item, and it is an owner ask.

TASK 3 — hand off to the security lane. Your files ARE scanned by the slug-rot detector (only
docs/benchmarks/results is excluded). HANDOFF-enginebox-step2-step3.md (3 hits) and
PLAN-PHASE4-GROUP-COMMIT.md (1) are live `_PROSE` counts. Report your post-edit count in the
handoff so the `sec` lane can set the ratchet against a stable number.

VERIFY (each block ONE call):
  ruff check . ; ruff format --check .
  mypy messagefoundry messagefoundry_webconsole --exclude 'messagefoundry/tray/' ; mypy --platform win32 messagefoundry
  $env:QT_QPA_PLATFORM="offscreen"; pytest -q
  git show HEAD:docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md | Select-String -Pattern '#220'
  $env:MEFOR_REQUIRE_TOKENS="1"; $env:MEFOR_MIN_DETECTORS="names=7,estate=13,site_prefixes=1"; python scripts/security/scan_forbidden.py --path .; "exit=$LASTEXITCODE"

DONE WHEN: the #220 grep returns zero residual-attributions, PLAN-ENGINE-ATTRIBUTION §3 matches
reality, `git diff --name-only origin/main` shows NO docs/BACKLOG.md, full local suite green.
DO NOT PUSH. No Co-Authored-By trailer. Never --no-verify. Stage explicit paths only.
```

### 7.3 — Wave 1C · `wtree`

```text
You are the WORKTREE-SESSION-RESCUE PORT session for MessageFoundry. Autonomy L1: COMMIT
LOCALLY ONLY. Never push, never open a PR, never merge. Read CLAUDE.md and docs/WORKTREES.md.

BOOTSTRAP — use a SHORT path; new.ps1's PySide6 install dies on Windows MAX_PATH:
  git worktree add C:/mfwtree -b wtree origin/main
  python -m venv C:/mfwtree/.venv
  C:/mfwtree/.venv/Scripts/python.exe -m pip install --constraint C:/mfwtree/constraints.lock -e "C:/mfwtree[dev,harness,fhir,dicom,x12,xml,webauthn]" -e C:/mfwtree/packaging/messagefoundry-webconsole
  C:/mfwtree/.venv/Scripts/python.exe -m pip install pre-commit bandit zizmor
  cd C:/mfwtree; .\.venv\Scripts\Activate.ps1; pre-commit install
  pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1; pwsh -NoProfile -File scripts\dev\setup-leak-gate.ps1
If the full extras set will not install, say so in your DONE report ("full suite NOT run
locally — CI is authoritative for this lane"). Do NOT report a green partial run as green.

YOU OWN: scripts/worktree/sessions.ps1 (new), scripts/hooks/worktree_gate.ps1,
scripts/worktree/install-gate.ps1, docs/WORKTREES.md, tests/test_worktree_gate.py,
tests/test_install_gate_wiring.py. Nothing else. No claim, no ADR, NO BACKLOG NUMBER —
alloc.ps1 -Kind backlog would issue #232, which already exists in the live ledger, and both
ledger gates would pass. Do not run it.

⛔⛔ DO NOT RUN scripts\worktree\install-gate.ps1 IN ANY MODE, INCLUDING -Status.
It is a USER-SCOPE PreToolUse hook (~/.claude/hooks, NOT .git/hooks): installing it mid-wave
changes what every concurrent sibling session is permitted to do. And it cannot run from a
session anyway — install-gate.ps1:59 throws "Refusing to run inside Claude Code" on
$env:CLAUDECODE -eq "1", BEFORE the -Status branch at :119. Assert on the BRANCH via pytest.
The owner runs the install from a plain pwsh terminal after the wave.

⛔ DO NOT REBUILD — the code exists, fully written and tested, on the private-vault branch
salvage/worktree-session-rescue @ 49cb250c2c978de74feab2152809ceb55cbe6658 (2026-07-24,
+474 lines / exactly those 6 files: sessions.ps1 369 new, worktree_gate.ps1 +29,
install-gate.ps1 +1, WORKTREES.md +25, test_worktree_gate.py +49, test_install_gate_wiring.py
+1). All six paths already exist on main.

PORT PROCEDURE
1. Confirm absence first: `git grep EnterWorktree origin/main` must return NOTHING and
   scripts/worktree/ on main must have no sessions.ps1.
2. git fetch https://github.com/wshallwshall/MessageFoundry 49cb250c2c978de74feab2152809ceb55cbe6658
   git show 49cb250c --stat
3. `git merge-base origin/main 49cb250c` is EMPTY — the public repo's history is DISJOINT from
   the vault's (roots 5fa6db9f vs ef399475). It CANNOT be combined that way. Cherry-pick it
   (which works across disjoint histories because every path exists on both sides), or
   format-patch + am.
   ⛔ A harness gate refuses any command whose STRING contains merge words — even inside an echo
   or a comment. Keep such words out of every command string; use `git commit -F <file>` for
   multi-line messages.
4. Re-anchor rule 4 BY HAND. main's scripts/hooks/worktree_gate.ps1 has grown rules 1/2/3/3b
   (L85-330) since 2026-07-24, so the +29-line EnterWorktree deny block needs a new insertion
   point and its rule-numbering comments reconciled with what is actually there now.
5. MERGE tests/test_worktree_gate.py (+49) into main's diverged copy — expect a real conflict.
   Do not overwrite.
6. In docs/WORKTREES.md, note that scripts/worktree/rescue.ps1 (already on main) is a DIFFERENT
   tool — it moves uncommitted work out of the primary; it is not the transcript rehome.

WHY IT MATTERS: relocating a live session into a worktree re-files its transcript under the
worktree slug and the chat VANISHES from its window's session list. No rescue tool is on main.

VERIFY (each block ONE call):
  ruff check . ; ruff format --check .
  mypy messagefoundry messagefoundry_webconsole --exclude 'messagefoundry/tray/' ; mypy --platform win32 messagefoundry
  $env:QT_QPA_PLATFORM="offscreen"; pytest -q
  $env:QT_QPA_PLATFORM="offscreen"; pytest -q tests/test_worktree_gate.py tests/test_install_gate_wiring.py
  $env:MEFOR_REQUIRE_TOKENS="1"; $env:MEFOR_MIN_DETECTORS="names=7,estate=13,site_prefixes=1"; python scripts/security/scan_forbidden.py --path .; "exit=$LASTEXITCODE"

DONE WHEN: six files reconciled, those two test modules green, full local suite green (or an
explicit statement that it could not run), the install deliberately NOT run, and a one-line
handoff telling the owner to run install-gate.ps1 from a PLAIN pwsh terminal after the wave.
DO NOT PUSH. No Co-Authored-By trailer. Never --no-verify. Stage explicit paths only.
```

### 7.4 — Wave 2 · `sec`

```text
You are the CODE-SCANNING TRIAGE session for MessageFoundry. Autonomy L1: COMMIT LOCALLY ONLY.
Never push, never open a PR, never merge, NEVER PATCH THE GITHUB API. Read CLAUDE.md (esp. §9
PHI) first. Start only after Wave 1 has merged.

BOOTSTRAP: scripts\worktree\new.ps1 -Name sec, then cd ..\MessageFoundry-sec and run the
standard block (constraint-pinned full-extras install, pre-commit + bandit + zizmor,
install-git-hooks.ps1, setup-leak-gate.ps1).

YOU OWN, EXCLUSIVELY FOR THE WHOLE PLAN: .github/workflows/**,
docs/adr/0034-static-analysis-triage-policy-accepted-risk-register.md,
tests/test_cutover_slug_rot.py, docs/INSTALL-GUIDE.md, docs/Secure_AI_Development_Standards.md,
tests/test_release_pipeline.py, tests/test_off_loopback_runbook.py, .gitignore, plus
messagefoundry/pipeline/alerts.py, messagefoundry/pipeline/engine.py,
messagefoundry/store/audit_tee.py, messagefoundry/api/app.py, messagefoundry/api/multipart.py,
messagefoundry/__main__.py, messagefoundry_webconsole/routes/account.py,
ide/src/symbolIndex.ts, tests/test_trust_anchors.py, tests/test_bootstrap_admin_perms.py,
tests/test_cert_cli.py, tests/test_api_tls.py.
⛔ You must not touch docs/BACKLOG.md or docs/benchmarks/**.
⛔ Allocate NO backlog number: alloc.ps1 -Kind backlog derives its floor from the stale
   published BACKLOG.md (max #231) and would issue #232, colliding with the live ledger (max
   #314) — and both ledger gates would pass. Track this work in the ADR 0034 register instead.
   You need no claim.ps1 (keep "BACKLOG #N" out of every commit subject).

CONTEXT: 32 code-scanning alerts are open on the PUBLIC repo. ADR 0034 requires every finding be
"fixed or dismissed with a recorded reason (never silently open/suppressed)". 32 silently-open
alerts is a live violation of the project's own policy.

ENUMERATE (re-fetch; do not trust this list blindly):
  gh api "repos/MEFORORG/MessageFoundry/code-scanning/alerts?state=open&per_page=100" --jq '.[] | "\(.number) \(.rule.id) :: \(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)"'

⛔ THE "BULK-FIXABLE TIER 1" PREMISE IS FALSE — VERIFY THIS YOURSELF BEFORE ACTING.
All 11 PinnedDependenciesID alerts read "score is 5: pipCommand not pinned by hash" — they are
`pip install` LINES (release.yml:91,131,175,177,214,363; security.yml:138,140;
freethread-smoke.yml:82,83; zizmor.yml:42), NOT GitHub Actions. Repo-wide,
  grep -rE '^\s*(- )?uses:' .github/workflows/ | grep -vE '@[0-9a-f]{40}'
returns ZERO — every action is already SHA-pinned. And dependabot-auto-merge.yml:44 ALREADY has
a permissions: block; TokenPermissionsID is about `contents: write` at workflow scope, which its
`gh pr merge --auto` step requires.
=> The honest fix for the 11 pip alerts is --require-hashes installs, which collides with the
DEP-1 four-lock surface and with today's ad-hoc installs (build, sigstore, cyclonedx-bom~=7.3,
zizmor==1.5.2). THAT IS UNSIZED DESIGN WORK — DO NOT ATTEMPT IT HERE. Route all 11 to
dismiss-with-recorded-reason citing the DEP-1 coupling, and flag the question for the owner.
Same for TokenPermissionsID (record the auto-merge requirement).
Also note: scorecard.yml has NO pull_request trigger (branch_protection_rule / weekly cron /
push:[main] / workflow_dispatch only), so these 12 cannot be re-verified before merge at all.

THE 9 PHI-CLASS ALERTS GET PER-PATH REVIEW AND A FIX. NEVER A BLANKET DISMISSAL.
  messagefoundry/pipeline/alerts.py:319/328/336 — ENUMERATE EVERY CALLER FIRST. There are TWO,
    not one: pipeline/secret_rotation.py:327 passes secret=_DEK_SECRET_ID (an IDENTIFIER — the
    same class as the bandit B105-on-env-var-NAMES trap), but :439 passes secret=check.secret,
    derived from SecretRotationRunner's generic secret_source callable, which is NOT a constant.
    An "only caller" dismissal here would be wrong.
  messagefoundry/store/audit_tee.py:73 — carries BOTH classes on an AUDIT path. Read the LIVE
    alert text before assuming which value is tainted: it says "logs sensitive data (password)".
    Only `detail` routes through safe_text() at :70 — actor, client, action and channel_id do
    NOT. Determine which record field CodeQL actually taints, then FIX with a regression test.
    If there is ANY doubt, fix rather than dismiss. This is the highest-consequence line here.
  messagefoundry/api/app.py:558, :2829, messagefoundry/pipeline/engine.py:1499 — localized
    sanitization + regression tests.
  messagefoundry/__main__.py:1535 — check whether this is CLAUDE.md §9's documented "CLI
    dryrun/generate output can contain full bodies" carve-out.
REAL AND SMALL, ON REQUEST PATHS — FIX BOTH WITH TESTS:
  messagefoundry/api/multipart.py:73 (py/polynomial-redos)
  messagefoundry_webconsole/routes/account.py:424 (py/stack-trace-exposure)
REVIEW: ide/src/symbolIndex.ts:129 (js/file-system-race)
STRONGEST DISMISSAL CANDIDATES (still need a recorded reason each): the 8 test-file alerts —
  tests/test_trust_anchors.py:164/166/168, tests/test_bootstrap_admin_perms.py:55,
  tests/test_cert_cli.py:221/222/241, tests/test_api_tls.py:1154.

⛔ DISMISSAL IS OUTWARD-FACING. Produce a table (alert number · rule id · path:line · disposition
· reason) and write the ADR 0034 register rows. THE OWNER executes the
`gh api .../code-scanning/alerts/<n> -X PATCH` calls. Do not PATCH from this session.
You are the ONLY writer of the ADR 0034 register — it is a tail-append table, and
ledger_check.py's own docstring records that "the tail-append hazard shows up as a DROPPED ROW,
not as a conflict. Three ADRs were already lost this way."

SLUG-ROT RATCHET (same lane, because it edits .github/workflows/**):
1. MEASURE FIRST, in this worktree, AFTER Wave 1 merged. Reproduce the detector:
   _PROSE = (?i)(the mirror|public mirror|OSS mirror|private repo|the published mirror),
   minus _RETROSPECTIVE, minus _SELF, over _tracked(). Record the count and per-file spread.
   Earlier inventories are wrong in ways that change the work: release.yml has 4 hits (L51, 75,
   76, 230) not 5; docs/INSTALL-GUIDE.md has 4 not 3; docs/adr/ is EXCLUDED WHOLESALE by
   _HISTORICAL (so ADR 0034's "7 hits" are ZERO counted hits — that instruction protects
   nothing); the benchmark HANDOFFs are NOT excluded (only docs/benchmarks/results is);
   docs/BACKLOG.md IS excluded.
2. Sweep ADOPTER-FACING prose first (docs/INSTALL-GUIDE.md,
   docs/Secure_AI_Development_Standards.md), then .github/workflows/release.yml — match the
   voice already at release.yml:74 ("REMOVED at the MEFORORG cutover: ...").
3. _PROSE_CEILING is at tests/test_cutover_slug_rot.py:71 (NOT :73), currently 55 against a
   measured 53. Lower it IN THE SAME COMMIT as the sweep — to measured + 3, NOT to zero slack.
   test_the_ratchet_is_not_slack (L170-187) already asserts slack <= 8, so 2 is legal by design.
   Zero slack turns any future "the mirror"/"private repo" phrase from any lane into a red on
   three required contexts, with no revalidation under strict:false.
4. ⛔ Do NOT widen _SELF (L78/L85) into a glob — it is deliberately one path.
5. ⚠️ .github/workflows/release.yml has NO pull_request or branch trigger. Nothing on any PR
   executes it; tests/test_release_pipeline.py gives structural guards only. Its first real
   execution after an edit is a vX.Y.Z tag = TWO production-PyPI uploads, and a successful
   upload burns that version forever. FLAG EVERY release.yml HUNK in your handoff and ask the
   owner to run the workflow_dispatch dry-run before the next tag.

VERIFY (each block ONE call):
  ruff check . ; ruff format --check .
  mypy messagefoundry messagefoundry_webconsole --exclude 'messagefoundry/tray/' ; mypy --platform win32 messagefoundry
  $env:QT_QPA_PLATFORM="offscreen"; pytest -q
  $env:QT_QPA_PLATFORM="offscreen"; pytest packaging/messagefoundry-webconsole/tests -q
  bandit -r . --skip B101,B110,B311,B404,B608 --exclude ./tests,./harness,./samples,./ide,./docs/benchmarks/results,./packaging/messagefoundry-webconsole/tests,./.venv,./node_modules
  python scripts/security/crypto_inventory_check.py; zizmor .github/workflows
  $env:QT_QPA_PLATFORM="offscreen"; pytest -q tests/test_cutover_slug_rot.py tests/test_release_pipeline.py tests/test_off_loopback_runbook.py
  $env:MEFOR_REQUIRE_TOKENS="1"; $env:MEFOR_MIN_DETECTORS="names=7,estate=13,site_prefixes=1"; python scripts/security/scan_forbidden.py --path .; "exit=$LASTEXITCODE"
⚠️ semgrep is a REQUIRED CI context but is ubuntu-only and has no supported Windows install —
   do not treat a green local run as evidence for it. Do NOT read a skipped check as a pass.

DONE WHEN: every one of the 32 alerts is either FIXED + regression test, or has a register row
in ADR 0034 AND appears on the prepared dismissal list for the owner. _PROSE_CEILING lowered to
measured+3 in the sweep commit. bandit clean. Full local suite green. The open-alert query is
EXPECTED to still be non-zero — 12 cannot re-scan before merge and dismissals are the owner's.
STOP AND ASK if audit_tee.py:73 suggests real PHI reaches the audit log, or if a pip-hash fix
starts to require pyproject.toml / lock changes.
DO NOT PUSH. No Co-Authored-By trailer. Never --no-verify. Stage explicit paths only.
```

### 7.5 — Wave 3 · `xform` *(only on an explicit owner go — §5.1)*

```text
You are the TRANSFORM-CONCURRENCY KNOB session for MessageFoundry (BACKLOG #214). Autonomy L1:
COMMIT LOCALLY ONLY. Never push, never open a PR, never merge. Read CLAUDE.md first.
DO NOT START without an explicit owner go — the knob was DELIBERATELY WITHHELD.

BOOTSTRAP: scripts\worktree\new.ps1 -Name xform, then cd ..\MessageFoundry-xform and run the
standard block. Cut this branch from a main that already contains the `sec` lane's merge.

YOU OWN: messagefoundry/config/settings.py (PipelineSettings, L1046-1177 ONLY),
messagefoundry/pipeline/engine.py, messagefoundry/pipeline/wiring_runner.py (L251 and L694
ONLY), docs/CONFIGURATION.md ([pipeline], L622-635), tests/test_transform_concurrency.py.

READ FIRST — THE HARD PART IS ALREADY MERGED AND TESTED. DO NOT REBUILD IT. DO NOT TOUCH
L4791-4832. RegistryRunner._process_routed_batch (wiring_runner.py:4791+) already runs sibling
routed rows' PURE transforms concurrently under asyncio.gather + Semaphore(cap) while every
store handoff stays SERIAL in claim order (ADR 0059 per-destination FIFO preserved), and it
freezes one dict(self.store.state_view()) snapshot at run-start for ADR 0005 determinism.
tests/test_transform_concurrency.py is 586 lines. The ONLY missing piece is the user-facing
knob: _DEFAULT_TRANSFORM_CONCURRENCY = 1 at wiring_runner.py:251, assigned at :694, and
`git grep transform_concurrency origin/main -- messagefoundry/config/settings.py` is EMPTY.

STEP 0 (mandatory, before any code):
  pwsh -NoProfile -File scripts\coord\claim.ps1 -Take 214 -Note "expose transform_concurrency as a [pipeline] setting"
  # then, as its OWN commit, flip the #214 banner in docs/BACKLOG.md from 🔢/🚧 to 🚧-in-progress:
  git commit -F <msgfile>    # subject: docs(backlog): claim #214 -- expose the transform-concurrency knob
  python scripts/docs/backlog_status_check.py
Allocate NO ADR (this rides ADRs 0059/0107) and NO backlog number (alloc.ps1 -Kind backlog would
issue #232, which already exists in the live ledger, and both ledger gates would pass).

BUILD
1. Add `transform_concurrency: int = Field(default=1, ge=1, le=32, ...)` to PipelineSettings.
   Default 1 MUST be byte-identical to today (the ADR 0058 §INV-5 precedent).
2. Thread it exactly as fifo_claim_batch already is: pipeline/engine.py:305-306 -> :670 AND
   :1449 (BOTH RegistryRunner construction sites) -> the wiring_runner.py ctor at :694, replacing
   max(1, _DEFAULT_TRANSFORM_CONCURRENCY). Keep the module constant as the fallback default so
   the existing tests still pin it.
3. Document in docs/CONFIGURATION.md [pipeline] AND in the commit body that the lever is TRIPLY
   DARK — it engages only when ALL THREE hold: [store].claim_mode = "per_lane" (the DEFAULT
   POOLED runner is unaffected regardless of anything else), [store].fifo_claim_batch > 1 (also
   default-off and ruled to STAY off by #212), and not the SQL Server fused path
   (self._fusion_active, wiring_runner.py:4819). Anyone setting it alone sees nothing.
4. MAKE NO THROUGHPUT CLAIM. Do NOT restate the ~40x figure — ADR 0107 prices this as a
   LANE-CEILING (serial-depth) effect, not fleet throughput, and it is unmeasured. Record that
   residual (a) was DEFERRED by owner decision 2026-07-24.
5. ⛔ DO NOT flip #214 to ✅. The correct end state is 🚧 with residual (a) and the per_lane gate
   still named. The item is 🚧 PARTIAL on the owner's ledger.

TESTS — the obvious test cannot fail on the most likely defect.
The guard at wiring_runner.py:4819 is
  `if self._transform_concurrency <= 1 or self._fusion_active or ic is None or len(items) < 2:`
so len(items) >= 2 requires fifo_claim_batch > 1. A test that merely sets
[pipeline] transform_concurrency = 4 and asserts it "reaches the runner" PASSES even if the
value is threaded to a new attribute while :694 still assigns the module constant.
REQUIRED: one test that sets fifo_claim_batch >= 2 AND transform_concurrency >= 2 AND observes
overlapping transform execution — and confirm by hand that it REDS when :694 is reverted to the
module constant. Plus a byte-identity test at the default.

⚠️ This diff touches settings.py and wiring_runner.py, both matched by ci.yml's `serverdb` path
filter, so the PR fires sqlserver-store (2022 + 2025) and postgres-store — legs that SILENTLY
SKIP locally and roll into the required "CI gate". A green local run does not cover them.

VERIFY (each block ONE call):
  ruff check . ; ruff format --check .
  mypy messagefoundry messagefoundry_webconsole --exclude 'messagefoundry/tray/' ; mypy --platform win32 messagefoundry
  $env:QT_QPA_PLATFORM="offscreen"; pytest -q tests/test_transform_concurrency.py
  $env:QT_QPA_PLATFORM="offscreen"; pytest -q
  $env:QT_QPA_PLATFORM="offscreen"; pytest packaging/messagefoundry-webconsole/tests -q
  python scripts/docs/backlog_status_check.py ; python scripts/hooks/ledger_check.py
  $env:MEFOR_REQUIRE_TOKENS="1"; $env:MEFOR_MIN_DETECTORS="names=7,estate=13,site_prefixes=1"; python scripts/security/scan_forbidden.py --path .; "exit=$LASTEXITCODE"

DONE WHEN: the knob exists, is threaded, documented and tested; the default is still 1 and a
test proves byte-identical behaviour there; the mutation test above reds on a revert; #214
remains 🚧 with residuals named; full local suite green; committed locally.
DO NOT PUSH. No Co-Authored-By trailer. Never --no-verify. Stage explicit paths only.
```

---

## 8. Residual risks and open questions for the owner

1. **The published backlog will still be incomplete after this wave.** It ends at #231; the live ledger runs to #314. Items #232-#314 — including **#313**, the hard gate on #105 — are invisible from `origin/main`, so a future session working from the public file cannot see them. **Wholesale re-publication is a disclosure decision, not a mechanical one:** `vault/main:docs/BACKLOG.md` fails the leak gate with 102 hits, and `docs/BACKLOG.md` is not in the `docs/security/*` allowlist. Lane 1A therefore does targeted per-item patches, which is safe but partial. **Open: how should the public ledger be kept truthful going forward?**

2. **Nothing in the repo prevents the BACKLOG-number collision from recurring.** `alloc.ps1 -Kind backlog` derives its floor from files, not refs; the local gate passes because the session really did allocate; the CI gate skips ownership entirely. This plan's mitigation is a standing rule and a memory guardrail — both behavioural. **A code fix (make the backlog floor ref-derived, or make `--ci` enforce ownership) is unfiled and unsized.**

3. **`_PROSE_CEILING` is a cross-lane tripwire.** With `strict: false`, a lane that adds one matching phrase after the ratchet lands reds three required contexts on `main` with no revalidation. The plan leaves 3 counts of headroom; that is a judgement, not a proof.

4. **`docs/BACKLOG.md`'s ranked tables carry their own status text** and are invisible to `backlog_status_check.py`, which parses only `^## N.` headings. Lane 1A re-syncs them as its final commit — but nothing gates them, so they will rot again the next time an item's state changes outside that lane.

5. **12 of the 32 code-scanning alerts cannot be verified before merge** (no `pull_request` trigger on `scorecard.yml`), and dismissal is an owner action. The `sec` lane's DoD therefore ends with a *prepared list*, not a zeroed queue. **Open: does the owner want the `--require-hashes` pip-pinning work funded as its own item, or accepted in the register?**

6. **The AD acceptor path is mock-seam only.** Every serve-path TLS/proxy assertion monkeypatches `uvicorn.run`, and `kerberos_principal` is `# pragma: no cover`. Until the #275/#98/#99(e)/#274 forest window runs, no real evidence exists for that surface. **Open: fund the window, or accept the gap?**

7. **`docs/security/` is entirely gitignored post-cutover**, so `CISO-REVIEW.md`, the ASVS assessments and the risk-acceptance register are unreadable from this baseline. Two CISO rows verified closed in code cannot be closed in the register from here. **Open: who reconciles the private register, and when?**

8. **`enforce_admins: false` + `strict: false` means the merge order in §6 is entirely self-imposed.** Nothing serializes it, and the only guard against a direct push to `main` is a per-clone `pre-push` hook that fails open with no python on PATH.

9. **This plan produces roughly one day of parallel work and one to two days of serial work, then stops.** Everything beyond it is gated on the seven decisions in §5. If none of them is answered, the next wave has nothing schedulable in it.

---

# Wave 0 — EXECUTED 2026-07-28

Owner pre-flight is complete. This section is the decision record; where it contradicts §5 above,
**this section wins** (§5 states the questions, this states the answers).

## Repo hygiene — DONE

* **16 merged branches deleted** from `MEFORORG/MessageFoundry`. Every one was confirmed `MERGED`
  through the PR API before deletion, not inferred from commit counts. Remote went **19 → 3 refs**.
* **Retained deliberately:** `main`; `cla-signatures` (excluded by §4); and **`claude/diffcov-probe`**,
  which was *not* in §4's list — it carries **open PR #28**, titled *"TEMPORARY diff-coverage probe —
  do not merge"*. Any future cleanup must keep excluding it while that PR is open.
* **`delete_branch_on_merge = true`** is now set on the repo, so merged head branches are removed
  automatically and the 16 cannot re-accumulate.
* **Local refs were left alone.** Twelve locals are stale, but `blplan` carries this plan's only copy
  (unpushed) and several others are checked out in live worktrees. Local cleanup is
  `scripts\worktree\prune-merged.ps1`, not a ref delete — it is *not* done and is not urgent.

## §5.4 posture — BOTH FLIPS APPROVED (build required)

| Setting | From | To | Note |
|---|---|---|---|
| `[store].aad_bind` (`config/settings.py:373`) | `False` | **on** | Crypto + ~307 backend sites already merged; v1 stays byte-identical and dual-read, so the flip is reversible. Takes ASVS 11.3.3 from Pass(B) to Pass. |
| `[auth].ad_session_recheck_seconds` (`config/settings.py:1777`) | `0` (reconciler never runs) | **set** | `docs/SECURITY.md:1321` recommends 300 off-loopback. |

⚠️ **These are approvals, not completed work.** They are code+test+doc changes and therefore a
**separate lane** — provisionally `posture` — which must **not** be folded into lane 1A. 1A owns
`docs/BACKLOG.md` exclusively and is docs-only by design; a settings diff inside it would break that
guarantee and trip the code-vs-docs CI classification. The `posture` lane is **not yet scheduled**.
Open sub-question the lane must answer, not assume: the exact value for `ad_session_recheck_seconds`
(SECURITY.md recommends 300; the related ADR 0079 narrowing gives a disabled account up to
`step_up_max_age_seconds` = 300 s of retained privilege, so the two interact).

## §5.1 / §5.4 ledger calls — owner delegated to the coordinator

* **#185 — CLOSE as superseded.** *Authorised.* It is an index-only umbrella owning no findings and
  shipping nothing runnable; all 20 children are resolved and ADR 0115 re-partitioned the programme
  into #242–#246. **Required wording:** superseded by the re-partition — explicitly **not** "ASVS is
  done", because the programme continued past this baseline and `docs/security/` is gitignored
  post-cutover. This **overrides** §7.1's "LEAVE ALONE ENTIRELY" and its stop-and-ask on #185.
* **#214 — DO NOT expose `transform_concurrency`.** *Declined.* The lever is triply dark (needs
  `claim_mode="per_lane"` **and** `[store].fifo_claim_batch > 1` **and** not the SQL Server fused
  path), its benefit is unmeasured, and it was withheld as owner-coordinated pending a measured need.
  Public surface for no demonstrated benefit is the wrong trade. §5.1's amend-only treatment stands:
  #214 stays `🚧` with its residuals named. **Wave 3's `xform` lane is cancelled, not deferred.**

## Wave 1 scope — 1A ONLY

Lane **1A `ledger`** is authorised to start. Lanes **1B `bench`** and **1C `wtree`** are **not**
started. 1C's absence leaves the session-relocation data-loss mode live — a session must still be
*started* in its worktree, never relocated into one.

## Already done by the coordinator — do NOT repeat

The five **AI memory corrections** listed at the end of §7.1 are **complete** (entry count unchanged
at 54; `mf-backlog-baseline-against-origin` was rewritten around the alloc trap rather than a new
entry being added). Lane 1A must **skip** that step. Each was verified against `origin/main` first:
the no-loss budget formula in all three copies, `cell_aad` counts per backend, the 32 open alerts,
and the #97/#117 symbols.
