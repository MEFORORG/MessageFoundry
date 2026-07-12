# MessageFoundry — Multisession Execution Plan 9 (2026-07-10)

**Complete the ASVS 5.0 L3 Posture-A remediation + the non-ASVS build batch.**

The next tranche of buildable work after PLAN-8, drawn from the 2026-07-10 ten-level re-score
([`docs/BACKLOG.md`](../BACKLOG.md) → *Ranked backlog*). Eleven lanes / fourteen item refs, each **code-scouted**
(build-state, files, dependencies, and contention with the live sessions verified against the tree by a
13-lane + 2-cross-cutting scout pass at origin/main tip `c74cdb2`). Most **finish the ASVS 5.0 L3 Posture-A
remediation** that PLAN-8's #187/#194/#199/#201/#202/#204 began (classes 1–4); the rest are non-ASVS.

This upgrade turns the strategy doc into a **coordinator-ready, executable** plan: §B is replaced with the
verified live-worktree footprint, §D with the scout-verified exclusion block, and the new lower half carries
a Waves diagram, a **per-lane worker dispatch spec** (the executable core — each self-sufficient, citing the
real file:line seams a scout verified), coordinator operating notes, the one-prompt handoff, and a per-lane
Definition of Done.

> **Naming note.** This is **PLAN-9**, not PLAN-8: `MULTISESSION-PLAN-8.md` is already taken by a parallel
> IDE low-code effort (#221/#222, ADR 0076, merged #865). A separate ASVS/ops "top-backlog build" is in flight
> under hand-off (its live worktrees are enumerated in §B). This plan is the batch **after** both.

**Method.** Coordinator + one worker subagent per lane, each in its own git worktree
(`scripts/worktree/new.ps1 -Name plan9-<lane>`); workers **build + verify + local-commit**; the **owner**
opens and approves every PR. Nothing merges without a green CI gate + owner click. **Autonomy L1:** workers
never push or PR.

> **Status: PLAN — awaiting "go".** No code until the owner approves. Several lanes flip shipping security
> defaults (owner has ruled **secure-by-default-with-org-opt-out** for the PLAN-8 set; the same posture applies
> here). Wave-3 lanes are individually owner-gated (§L).

---

## A. The governing constraint — `config/settings.py` is the choke point

`config/settings.py` is the **structural** collision: one ~1900-line file where every section is a class —
`StoreSettings` (L183), `LoggingSettings` (L785), `RetentionSettings` (L879), `AuthSettings` (L972),
`EgressSettings` (L1198), `AlertsSettings` (L1336), `DiagnosticsSettings` (L734), `IntegritySettings` (L1570) —
so **any two section edits land in the same file.** That alone forces every `settings.py`-touching lane out of
Wave 1.

> **Correction (INFLIGHT scout).** The strategy draft claimed "two sessions editing `settings.py` right now,
> `[auth]`/`[logging]` **and** `[store]`/`[retention]`/`[egress]`/`[alerts]`." **The *live* churn is much
> lighter:** only `plan8-194` currently touches `settings.py`, adding a **single** `[auth]` field
> (`require_action_step_up: bool = True`, ~L984). No live branch touches `[logging]`, `[store]`, `[retention]`,
> `[egress]`, or `[alerts]`. Treat `settings.py` as the **structural** Wave-1 exclusion, not heavy live churn.

**The Wave-2 de-risking move (unchanged):** once PLAN-8 lands, the coordinator makes **one "settings-scaffold"
commit** that adds every new `settings.py` field at once, so the Wave-2 behaviour lanes consume-not-author it
and touch mostly disjoint files. The scaffold adds, in one commit:

- `[diagnostics].message_events` — a verbosity **enum** (`full|lifecycle|errors|off`) added to the *existing*
  `DiagnosticsSettings` (L734) — **not a new section** (STORE #63).
- `[integrity].audit_verify_on_start: bool` on the existing `IntegritySettings` (L1570), ADR-0041 alert-only
  posture (STORE #190 startup auto-verify).
- `[auth].admin_write_rate_limit_{enabled,per_actor,window_seconds}` modelled on the existing
  `phi_read_rate_limit_*` block (L1068–1071) (AUTH #193). *The scaffold's named list must include these — AUTH
  consumes, never authors them.*
- `SecretRotationSettings` mirroring `CertMonitorSettings` (L1485) + its `ServiceSettings` field (near L1876) +
  `'secret_rotation'` in `_ALERT_EVENT_TYPES` (L1276–1288) + the `AlertRule.event_type` docstring (SECRETS #195b).
- `[sandbox]` section (mode `off|restricted|subprocess|container`, resource caps, egress posture) — **none
  exists on origin/main** (SANDBOX #197).
- The new `[api]` TLS knobs (mTLS cert→identity map, Posture-B intra-service-auth mode, declared proxy-TLS/KEX
  floor), near the existing TLS block at ApiSettings L453–473 (TLS #200).

> **Note.** The GATE lane's dual-control WARN gate needs **no** new `settings.py` flag — it reads the already-
> shipped `settings.approvals.enabled` (default `False`, L1599). The strategy draft's §A listing "the dual-
> control WARN gate" among scaffold additions was imprecise; GATE has **no** dependency on the scaffold commit.

---

## B. In-flight (do NOT collide) — verified live-worktree footprint

Verified against origin/main tip `c74cdb2` and the five live worker worktrees (`git worktree list`:
`MessageFoundry-plan8-194/199/201/204/base`). The plan8 branches are **local-only** (absent from
`git branch -r`) — consistent with "workers local-commit only, no push" — so they are genuinely in-flight and
invisible to `gh pr list` (only PRs #862/#823/#649 are open, none plan8/plan9). File lists below are real
`git diff --stat origin/main...<branch>` output; the strategy §B lists **undercount every one of them.**

**`plan8-194` (#194 — action-bound step-up)** — *broader than the draft's "`settings.py` [auth] / `api/security.py` / `auth/**`":*
- `docs/adr/0077-action-bound-step-up.md` **(claims ADR 0077 — see ADR callout)**
- `config/settings.py` — **`[auth]` only**, one field `require_action_step_up: bool = True` (~L984)
- `api/security.py`, `auth/service.py`
- **`api/auth_models.py`, `api/auth_routes.py`, `console/client.py`** ← none listed in the draft
- `docs/security/ASVS-L3-ASSESSMENT.md`, `tests/golden/webconsole_seam.snapshot`, + 4 auth/step-up tests

**`plan8-199` (#199 — egress-suppression / codeset writer)** — *far broader than "codeset CSV writer + `transports/fhir.py`":*
- `config/codeset_edit.py` (the codeset writer)
- **`pipeline/wiring_runner.py`** ← **HOT COLLISION, unflagged**
- **`transports/base.py`** ← connector-registry hub, unflagged
- `transports/{fhir,rest,soap,dicomweb,remotefile}.py` (draft named only `fhir.py`)
- `harness/acceptance/report.py` + 7 transport/codeset tests

**`plan8-201` (#201 — cert-revocation / TLS posture)** — *draft named only `config/tls_policy.py`:*
- **`__main__.py`** ← **HUB COLLISION, unflagged**
- `config/tls_policy.py`
- `docs/adr/0076-certificate-revocation-posture.md` **(DUPLICATE 0076 — collides with merged ADR 0076)**,
  `docs/adr/0002-*.md`, `docs/adr/README.md`, `docs/security/ASVS-L3-ASSESSMENT.md`, + 3 TLS tests
- **Does NOT touch `api/tls.py` or `transports/mllp.py`.**

**`plan8-204` (#204 — fhir_lookup)** — *draft named only `transports/fhir.py`:*
- **`pipeline/wiring_runner.py`** ← **HOT COLLISION (2nd owner)**
- `config/fhir_lookup.py`, `transports/fhir.py`, `transports/smart.py`
- `docs/adr/0043-fhir-read-lookup.md`, `docs/security/ASVS-L3-ASSESSMENT.md`, `tests/test_fhir_lookup.py`

**In-flight cross-collisions (two live branches, same file — a `git merge main` conflict is already baked in):**
- `pipeline/wiring_runner.py` → **plan8-199 + plan8-204**
- `transports/fhir.py` → **plan8-199 + plan8-204**
- `docs/security/ASVS-L3-ASSESSMENT.md` → **plan8-194 + plan8-201 + plan8-204** (serialize point on every ASVS lane)

**NOT in-flight (the draft §B listed these as live locks — they are FREE right now):**
- **`api/tls.py`** — exists, touched by **zero** live branches. The TLS lane (#200) is *not* currently blocked here.
- **`transports/mllp.py`** — touched by zero live branches.
- Items **#187 / #202** (the "Waves 2–3" items tied to `api/tls.py`/`mllp.py`) have **no worktree and no
  branch** → **unstarted, not in-flight.**
- **The entire "PLAN-8 Wave-1 remainder" session (#102/#186/#188/#192)** — retention runner, egress gate,
  `dr_backup.py`, `messagefoundry_webconsole/**`, `scripts/service/*install*`: **zero live branches touch any of
  these files** (the only webconsole hit is a golden `.snapshot` in plan8-194). That session is **not currently
  live** — those files are free (relevant to CONSOLE-RETIRE, which had gated on `scripts/service/*install*`).
- `plan8-metrics` has unmerged commits but **no worktree**, and its payload (`api/metrics.py`, #74) is already
  on origin/main → **stale/superseded, not a live contention.**

---

## C. Lane roster

V/D from the ranked table, cross-checked to each item's `🔢` banner (BACKLOG-ASVS scout). **Two D-scores
corrected below.** `Owns` lists the files a lane *authors/deletes*; files it *consumes* (the settings-scaffold,
shared hubs) are noted in the dispatch spec, not here.

| Wave | Lane | Items | V / D(rem) | Owns | Notes |
|---|---|---|---|---|---|
| **1** | **VALIDATE** | #89 | 5 / 3 | `pipeline/wiring_runner.py`, `config/wiring.py`, `config/models.py`, `docs/security/HL7APY-FORK-ON-CVE-RUNBOOK.md` (new), tests | hl7apy strict-validate wall-clock **timeout** → dead-letter (a hang never dead-letters today) + adversarial fuzz corpus + fork-on-CVE runbook. ⚠ **NOT collision-free** — `wiring_runner.py` is owned by live `plan8-199` **and** `plan8-204`; `git merge main` past both. |
| **1** | **SECMEM** | #198 | **6 / 6** *(was 6/5)* | `store/crypto.py`, `tests/test_store_encryption.py` | In-use memory protection: best-effort `mlock`/`VirtualLock` + `memset`-zeroize the DEK + owned plaintext buffers (13.3.3 / 11.7.1 / 11.7.2). **Core only** — the optional `[store]` toggle is deferred so it never touches `settings.py`. Honest **partial** 13.3.3 (immutable str/bytes + cryptography's internal key copy). |
| **2** | **GATE** | #189 | 5 / 3 | `__main__.py`, `tests/test_cli.py`, `docs/security/ASVS-L3-ASSESSMENT-2026-07-09.md` + `ASVS-L3-ASSESSMENT.md` + `ASVS-L3-STATUS.md` | WARN-at-PHI-exposure serve-gate for dual-control (mirrors the sec-mfa-on block) + record tolerant-peek as a signed L3 deviation reconciling 2.2.1/2.2.3. **Run first** — smallest hub footprint; reads the already-shipped `settings.approvals.enabled`, needs **no** scaffold field. (Approval workflow already ships, `api/approvals.py`.) |
| **2** | **AUTH** | #193, #195a | 5 / 3, (#195 V6) | `auth/ratelimit.py`, `auth/service.py`, `api/security.py`, `docs/SECURITY.md`, tests | Anti-automation admin-write pacing floor (2.4.2) folded into `require_step_up` scoped `request.method != 'GET'` + **audit every authorization decision** — today only *denials* log (`audit_permission_denied`, `service.py:1789`); add the `audit_permission_granted` twin. **Does NOT touch `api/app.py`** (see §E correction). Consumes `[auth].admin_write_rate_limit_*` from the scaffold. |
| **2** | **STORE** | #190, #63 | **6 / 7** *(was 6/6)*, 3 / 4 | `store/store.py`, `store/postgres.py`, `store/sqlserver.py`, `store/crypto.py`, `pipeline/engine.py`, `__main__.py`, tests | HMAC-key the audit hash-chain (single shared `audit_row_hash`, `store.py:693`) + startup auto-verify + AES-GCM invocation counter / rekey-before-2³² (11.3.4/16.4.2); `[diagnostics].message_events` gate at **every** emission path (SQLite `_event` **plus 3 direct inserts** at `store.py:2063/2285/2704`; Postgres `_event`; SQL Server `_event/_event_sync` + 2 batched sites). **One serial lane.** Rebases on SECMEM's `crypto.py`. |
| **2** | **SECRETS** | #196, #195b | 5 / 6, (#195 V6) | `store/keyprovider_vault.py` (new), `pipeline/secret_rotation.py` (new), `pipeline/alerts.py`, `pipeline/alert_sinks.py`, `pipeline/engine.py`, `__main__.py`, `api/app.py`, `pyproject.toml`, tests | External **Vault KeyProvider** (13.3.1) via core `cryptography` transit + a `CertExpiryRunner`-style secret-rotation reminder (13.3.4). **New dep (`hvac`) → DEP-1 re-lock + owner vet first.** The `#196` *connector* SecretProvider (AD/SQL/SMTP off env) is design-only (ADR 0019 §5) — **out of this lane**, filed as a follow-on. |
| **2** | **TLS** | #200 | 6 / 6 | `api/tls.py`, `api/security.py`, `config/tls_policy.py`, `api/app.py`, `__main__.py`, tests | Fail-closed off-loopback Posture-B gate + KEX-under-proxy attestation + mTLS-as-Identity (4.2.1/4.4.1/11.6.2/12.x). **Land last** — re-touches `api/security.py` (after AUTH). `api/tls.py`/`mllp.py` are **free** (see §B). Consumes the scaffold's `[api]` TLS knobs. |
| **3** | **IDE-IMPORT** | #105 | 2 / 6 | `messagefoundry/corepoint_import.py` (new), `__main__.py`, `ide/src/corepointImport.ts` (new) + manifest, tests, ADR | Deterministic (non-AI) Corepoint Action-List → editable Router/Handler Python. ⚠ **Not ide-only** — the mapping grammar belongs engine-side (ADR 0076 §5), so it adds an engine module + `import` subcommand. **Depends on PLAN-8 L2** (`messagefoundry/actions.py` + `lens.py`, **absent on origin/main**) to emit lens-round-trippable handlers. Owner-gated on scope + **a new ADR**. |
| **3** | **DIRECT-HISP** | #157 | 3 / 7 | `transports/direct.py` (new), `config/models.py`, `config/wiring.py`, `transports/__init__.py`, `pipeline/wiring_runner.py` (egress gate), tests, ADR | **Outbound S/MIME-over-SMTP** destination (PR1). **S/MIME rides core `cryptography>=48` `serialization.pkcs7` — NO new dep** (the draft's "S/MIME CMS dep" is wrong). Inbound mail source, MDN, DNS-CERT discovery (`dnspython`, optional), IHE XDR are **deferred phases**. Owner go/no-go + ADR. Own worktree. |
| **3** | **SANDBOX** | #197 | 5 / 8 | `pipeline/sandbox.py` (new), `pipeline/wiring_runner.py`, `pipeline/dryrun.py`, `config/wiring.py`, tests, ADR | Hard-isolation runtime for admin-authored Router/Handler code (15.2.5) — **closes the WP-L3-17 residual**, not a Fail. Architectural, high blast radius. **Waits for #89** (file-contention on `wiring_runner.py`+`config/wiring.py`, not a logical dep). Consumes `[sandbox]` from the scaffold. New **ADR** picks isolation approach. |
| **3** | **CONSOLE-RETIRE** | #103 | 4 / 6 | delete `console/`, new `messagefoundry/apiclient/` + `messagefoundry/service.py`, rehome 4 Qt files → `harness/`, `__main__.py`, `pyproject.toml`, ~12 test files, 5+ docs, ADR | Retire the PySide6 desktop console; extract Qt-free `apiclient/`, rehome shared widgets to `harness/`, move service control to a `messagefoundry service` CLI. ⚠ **Large cross-cutting refactor**, not a 4-path delete. **Gated on #75 web-console parity** (SHIPPED) + owner **pre-acceptance of enumerated parity losses** + Windows CI. |

> **V/D corrections (BACKLOG-ASVS scout, canonical ranked table).** **#198 (SECMEM) D = 6, not 5** (banner
> L6255 `_big bet_`). **#190 (STORE) D = 7, not 6** (banner L6127; the only `V6/D7` row in the table). Neither
> changes lane assignment or wave order (both stay `_big bet_`), but DoD banner/PR text must cite the canonical
> score.
>
> **#195 is ONE backlog item** (`Audit completeness…`, V6/D4, `Closes: 16.3.2, 13.3.4`), split across AUTH
> (**#195a** = 16.3.2 audit clause) and SECRETS (**#195b** = 13.3.4 rotation clause). The per-half D5 is a
> plan-internal estimate above the canonical whole-item D4 — do **not** "correct" the ranked table. Only **one**
> finishing PR (`BACKLOG #195`) may flip the #195 banner, and **only after both halves land** — neither half
> may green-check #195 alone.

---

## D. Excluded (scout-verified — not build lanes)

Each line carries the verified V/D + the item's `Verdict:` field. The draft's §D is substantively accurate —
every excluded item is genuinely non-buildable (owner-decision / already-shipped / index / recon / doc-only);
the corrections below are additive.

- **#91 — owner decision, not a build.** (V6/D5, L166/L3705; Type: measurement/gate; **Reopened** 2026-07-10.)
  The ADR 0053 `[ ] GIL-on-vs-FT A/B` box is unchecked, but free-threading is already recorded NO-GO
  (ADR 0053 / #789). Resolve by running the A/B to formally close the gate, or recording the NO-GO and closing
  #91 — a decision, not worker work.
- **#203 — owner-scoping doc, not a build.** (V5/D3, L194/L6333; **Verdict: owner decision**; `Closes: 13.2.1,
  13.3.2, 8.4.2`.) Its honest close is a delegation-boundary *statement* in `OFF-LOOPBACK-DEPLOYMENT.md` (prefer
  gMSA/Entra, least-privilege secrets, device posture); the 8.4.2 sub-item already ships. Fold the statement
  into whichever ASVS docs lane is open (GATE is the natural anchor — it runs first and edits the ASVS docs).
- **#48 — already shipped.** (V4/D2, L210/L2523; `🔶` base #595 + L1 #794 — 36 idiom snippets, quick-pick,
  keybinding, CodeLens, router/handler filter — done.) *Note: `console/theme.py` doubles as #48's dark-console
  target; CONSOLE-RETIRE relocates it to `harness/theme.py` — reconcile #48's banner when #103 lands.*
- **#185 — index only, ships nothing.** (V1/D1, L267/L6036; Verdict: build (indexed).) Umbrella partitioning
  the 67 ASVS cells across #186–#205; close it when they all resolve.
- **#87 — competitive-intel research, no code.** (V1/D1, L266/L3572; Type: recon, "No code".) *This is the
  gitignored source material IDE-IMPORT (#105) needs a synthetic fixture corpus for.*
- **#191 — ASVS scoping decision, not a build.** (V2/D1, L115/L6141; **Verdict: owner decision**; `Closes:
  9.1.2, 9.2.4, 10.1.1, 10.2.3, 10.4.10`.) Five Partials flip to Pass with zero code because
  `transports/smart.py` is already correct — an owner call.
- **#205 — ASVS closeout doc, not a build.** (V2/D1, L116/L6365; **Verdict: accept + sign off**; `Closes:
  7.1.1, 7.5.2, 11.3.3, 13.4.7`.) A signed risk-acceptance record; residuals stay Partial/Fail after sign-off;
  doc-only, no code.

---

## E. Contention matrix — corrected (real in-flight ownership)

`config/settings.py` is the structural Wave-1 exclusion (§A). Beyond it, the Wave-2 lanes re-collide on a small
set of hub files and must serialize. ⚠ = an in-flight owner the strategy draft did not flag; ✂ = a draft edge
the scouts found **spurious**.

| Hub file | PLAN-9 lanes | Live in-flight owner / resolution |
|---|---|---|
| `config/settings.py` | *(scaffold only)* | Structural exclusion. **Only `plan8-194` is live** (one `[auth]` field). Coordinator's scaffold commit is the sole Wave-2 writer; lanes consume. |
| `pipeline/wiring_runner.py` | VALIDATE, SANDBOX, DIRECT-HISP(egress) | ⚠ **`plan8-199` + `plan8-204`** own it. VALIDATE (`_handle_inbound` :2567 / `_handle_inbound_http` :2423) and SANDBOX (dispatch sites :3129/:3153/:3453/:3549/:3662) each `git merge main` past both. DIRECT-HISP edits only the egress gate (~:4064/:4487), distant from those. |
| `__main__.py` | GATE, STORE, SECRETS, TLS, IDE-IMPORT, CONSOLE-RETIRE | ⚠ **`plan8-201`** owns it — **GATE ("run first") must `git merge main` past it.** GATE lands its serve-gate block first (after :1155); STORE/SECRETS/TLS rebase over GATE; IDE-IMPORT/CONSOLE-RETIRE (Wave 3) rebase over all. |
| `api/security.py` | AUTH, TLS | **`plan8-194`** (flagged). AUTH lands first; **TLS after AUTH** (adds the cert→Identity resolver beside AUTH's `audit_permission_granted` twin). |
| `store/crypto.py` | SECMEM → STORE, SECRETS | Free of in-flight. **SECMEM (Wave-1) lands first**; STORE (`audit_mac_key()` + GCM counter) and SECRETS rebase. Keep the public Cipher seam byte-stable. |
| `pipeline/engine.py` | STORE, SECRETS | Free. Serialize the `Engine.start()` edit (STORE startup-verify ~:682) with SECRETS' runner wiring (~:785/:1289); second lander rebases. |
| `pipeline/alerts.py` + `alert_sinks.py` | SECRETS | Free. `secret_rotation_due` added to the Protocol + `LoggingAlertSink` + `NotifierAlertSink` + 3 test doubles in **one** commit (mypy-strict ripple). |
| `transports/base.py` | DIRECT-HISP registers here | ⚠ **`plan8-199`** owns it (connector registry). DIRECT-HISP is Wave-3; rebase. |
| `config/wiring.py` | VALIDATE, SANDBOX, DIRECT-HISP | VALIDATE additive param threading (:2060/:2249/:2231); SANDBOX Wave-3 waits for #89; DIRECT-HISP appends a `Direct()` factory. |
| `config/models.py` | VALIDATE, DIRECT-HISP | Additive: VALIDATE adds `Validation.strict_timeout_s` (:312); DIRECT-HISP adds one `ConnectorType.DIRECT` enum member. Not concurrent (Wave 1 vs 3). |
| `api/app.py` | STORE(opt), SECRETS, TLS | ✂ **AUTH does NOT touch it** (draft edge dropped). STORE's touch is optional (posture). TLS lands last. |
| `config/tls_policy.py` | TLS | ✂ **STORE has no real edit here** (draft "STORE, TLS → TLS after STORE" is spurious). Effectively **TLS-owned** for the KEX-under-proxy helper. |
| `api/tls.py`, `transports/mllp.py` | TLS | **FREE** (§B) — the draft's "in-flight lock" premise does not hold. |
| `docs/security/ASVS-L3-ASSESSMENT.md` | GATE, AUTH(via SECURITY.md), STORE, TLS | ⚠ **`plan8-194` + `plan8-201` + `plan8-204`** all touch it. Row-scoped edits + land-order; **nominate GATE as the ASVS-docs anchor** (runs first). |
| `docs/adr/README.md` | every ADR-adding Wave-3 lane | Known one-line index conflict; land-order. **See the ADR-number callout in the footer** — 0077 is already claimed by `plan8-194`. |

Wave-3 lanes **IDE-IMPORT** and **DIRECT-HISP** are otherwise collision-free (all-new files); **SANDBOX** and
**CONSOLE-RETIRE** are not (shared `wiring_runner.py`/`config/wiring.py` and `__main__.py`/`scripts/service`
respectively).

---

## F. Sequencing

1. **Wave 1 now:** two independent worktrees — **VALIDATE (#89)** and **SECMEM (#198 core)**. Neither touches
   `settings.py`. (VALIDATE *does* share `wiring_runner.py` with live `plan8-199`/`plan8-204` — merge main past
   them; SECMEM's `crypto.py` is in-flight-free.)
2. **Hold Wave 2** until PLAN-8's live sessions merge. Then land the coordinator's **settings-scaffold commit**
   (all new fields at once, §A). Then, in order: **GATE (#189)** first (seeds the serve-gate pattern, smallest
   hub footprint) → **AUTH**, **STORE**, **SECRETS** in parallel (disjoint after the scaffold + after SECMEM's
   `crypto.py` lands) → **TLS (#200)** last (re-touches AUTH's `api/security.py`).
3. **Wave 3** is owner-gated, any order once greenlit: **IDE-IMPORT** and **DIRECT-HISP** await an ADR + scope
   (IDE-IMPORT additionally awaits **PLAN-8 L2** — `actions.py`/`lens.py` are not yet on main); **SANDBOX**
   awaits #89 + its isolation ADR; **CONSOLE-RETIRE** awaits #75 parity sign-off (the in-flight
   `scripts/service` work is **not currently live**, so it is not a wait — but re-check).

---

## G. Waves diagram

```
Wave 0   (external)  PLAN-8 live sessions land: plan8-194/199/201/204 (+ Wave-1 remainder if started)
                     ── coordinator re-verifies §B against origin/main + open PRs ──▶

Wave 1   VALIDATE (#89) ──────────┐   two independent worktrees, dispatched together.
         SECMEM  (#198 core) ─────┘   Neither touches settings.py.
                                       VALIDATE: git merge main past plan8-199 + plan8-204 (wiring_runner.py).
                                       SECMEM lands crypto.py FIRST (Wave-2 STORE/SECRETS rebase on it).

              │  (after PLAN-8 lands AND SECMEM's crypto.py is on main)
              ▼
         ╔══════════════════════════════════════════════════════════╗
         ║  SETTINGS-SCAFFOLD COMMIT (coordinator, one commit)        ║
         ║  [diagnostics].message_events · [integrity].audit_verify   ║
         ║  [auth].admin_write_rate_limit_* · SecretRotationSettings  ║
         ║  [sandbox] · [api] TLS+mTLS knobs                          ║
         ╚══════════════════════════════════════════════════════════╝
              │
              ▼
Wave 2   GATE (#189) ───────────▶ lands its __main__.py serve-gate block FIRST (after plan8-201 merges)
              │
              ├──▶ AUTH   (#193, #195a) ──┐
              ├──▶ STORE  (#190, #63) ─────┤  parallel — disjoint after the scaffold + SECMEM;
              └──▶ SECRETS(#196, #195b) ──┘  STORE & SECRETS rebase on SECMEM's crypto.py; serialize engine.py
                             │
                             ▼
                         TLS (#200) ──────▶ LAST — rebase over AUTH (api/security.py) + STORE; combined-tree re-verify

Wave 3   (owner-gated, any order once greenlit)
         IDE-IMPORT (#105)   ── ADR + scope + PLAN-8 L2 (actions.py/lens.py) merged
         DIRECT-HISP (#157)  ── owner go/no-go + ADR (outbound S/MIME PR1 only)
         SANDBOX (#197)      ── after #89 lands + isolation ADR Accepted + [sandbox] scaffolded
         CONSOLE-RETIRE (#103) ── after #75 parity-loss sign-off; extract→rehome→CLI GREEN before delete
```

---

## H. Worker dispatch specs (coordinator passes these as Workflow agent prompts)

**Common preamble for every worker (coordinator prepends):** *branch off `origin/main` (fresh fetch); worktree
via `scripts/worktree/new.ps1 -Name plan9-<lane>` (`-Sqlserver` only for STORE); build/use that worktree's own
`.venv` — engine lanes install `[dev,console]` (+ `dicom,fhir` to avoid the ~13 pre-existing DICOM/FHIR mypy-
stub errors a `[dev,console]`-only venv shows, W4 ledger). **First action:** `git fetch && git log origin/main
--oneline -5 && gh pr list --state all --limit 20` to rule out an already-merged duplicate and re-anchor every
file:line below against live main (they WILL drift — the working tree is many commits behind). Commit local
with **explicit paths** (repo hook blocks `git add -A`/`-u`/`.`; no `commit -a`); **omit the `Co-Authored-By`
trailer** (CLA bot fails on it); **no push, no PR**; SPDX header (`# SPDX-License-Identifier: AGPL-3.0-or-later`)
on every new `.py`; synthetic HL7 only. The finishing PR does `git merge main` FIRST, carries `BACKLOG #N`, and
flips that item's banner to ✅.*

### Wave 1 — VALIDATE (#89) · branch `feat/hl7apy-strict-validate-timeout-89`
`scripts/worktree/new.ps1 -Name plan9-validate` (NO `-Sqlserver`).

1. **Config field** — `config/models.py:312`: add `strict_timeout_s: float | None = None` to class `Validation`
   (after `profile`). Docstring: wall-clock seconds a strict hl7apy validate may run before the message dead-
   letters (DoS backstop, #89); `None` inherits the engine default, `<=0` disables.
2. **Plumb factories** — `config/wiring.py`: add the param to `build_inbound_connection()` (:2060, near
   strict/hl7_version :2067) **and** `inbound()` (:2249); forward at :2321; pass into the `Validation(...)`
   construction at :2231. Settable code-first **and** via `connections.toml` (loader desugars through `inbound()`).
3. **Module default** — `wiring_runner.py` near :177: `_STRICT_VALIDATE_TIMEOUT_SECONDS = 5.0` beside
   `_LOOKUP_RESULT_TIMEOUT_SECONDS`, with a comment mirroring its rationale. **FLAG the 5.0s default to owner.**
4. **MLLP call site** — `wiring_runner.py:2567-2572`: wrap `await asyncio.to_thread(validate, …)` in
   `asyncio.wait_for` (mirror `api/app.py:539-543`); resolve `t` from the field-or-default; on `TimeoutError`
   record `MessageStatus.ERROR` with a **PHI-safe, value-free** error `f'strict-validation timed out after {t}s'`,
   build an `AE` NAK if reply, capture the ack, `return ack`. Leave the `if not result.ok:` block (2573-2600).
5. **HTTP call site** — `wiring_runner.py:2423-2426`: same wrap; on `TimeoutError` record `ERROR` then
   `return None` (HTTP owns its 202/4xx; no HL7 ACK). Leave the `if not result.ok:` block (2427-2430).
6. **Correctness note** — `wait_for` frees the listener but **cannot kill the `to_thread` worker** (no thread
   cancellation in CPython); the hl7apy call leaks its thread until it returns. **Accepted-by-design** (mirrors
   the `_run_lookup` precedent), bounded by `enforce_size_limits` (`validate.py:71`, 16 MiB / segment cap fired
   *before* the slow parse). One-line comment at each site + a runbook paragraph.
7. **Fuzz corpus** — `tests/test_parsing.py`: a `@pytest.mark.parametrize` adversarial corpus (deep nesting, huge
   repetition/component counts within the byte cap, truncated segments, bad MSH-12, non-numeric seps, empty/
   oversized) through `validate()`; assert each returns `ok=False` (or is caught by caps) and **never raises**.
   Hand-built, styled on `tests/test_builtin_hl7_hardening.py`. **NO hypothesis** (not in pyproject). The
   existing `--timeout=60 --timeout-method=thread` self-guards a truly-hanging input.
8. **Integration test** — `tests/test_wiring_engine.py` beside `test_strict_validation_nacks` (:566):
   monkeypatch the module-local `validate` (imported at `wiring_runner.py:73`, **not**
   `messagefoundry.parsing.validate.validate`) to block longer than a tiny per-connection `strict_timeout_s`
   (0.05s); assert stored disposition `ERROR` starting `'strict-validation timed out'` + an `AE` NAK. Confirm
   `test_strict_validation_nacks` still passes.
9. **Runbook** — new `docs/security/HL7APY-FORK-ON-CVE-RUNBOOK.md` (#89(a)): fork-on-CVE process (vendor the
   patch only on a CVE), referencing `DEP-CVE-RUNBOOK.md` / `SOUP-DEPENDENCY-HANDLING.md` /
   `DEPENDENCY-INFOSEC-POSTURE-2026-06-23.md`; document the verified blast-radius (caps + timeout + dead-letter +
   accepted thread-leak) and fold in the fuzz-corpus location.

**Verify:** ruff ×2 · mypy strict · `QT_QPA_PLATFORM=offscreen pytest -q` (FULL). **Gates:** owner-tunable 5.0s
default + secure-by-default-ON posture; **no new dep** (hand-built fuzz, not hypothesis); PHI: timeout string
value-free. **DoD:** timeout wrap live at both sites; a hang dead-letters + NAKs AE instead of pinning the
listener (proven by the integration test); field threaded through; fuzz corpus non-raising; runbook authored;
quartet green; adversarial review folded.

### Wave 1 — SECMEM (#198, V6/D6) · branch `plan9-secmem`
`scripts/worktree/new.ps1 -Name plan9-secmem` (NO `-Sqlserver`; crypto is backend-agnostic, tests run in-process
on SQLite).

1. **Primitives** — after `crypto.py:~45` add `import ctypes, sys`. Implement `_secure_zero(buf: bytearray)`
   via `ctypes.memset((ctypes.c_char*n).from_buffer(buf), 0, n)`; best-effort `_lock_memory`/`_unlock_memory`
   guarded like `secrets_dpapi.py:63` — win32 `WinDLL('kernel32', use_last_error=True).VirtualLock/VirtualUnlock`,
   POSIX `CDLL(None).mlock/munlock`. Both **swallow failure** (return `False`/no-op, never raise, never log PHI).
   Keep all ctypes inside guarded functions so the Linux mypy leg stays clean.
2. **Mutable DEK** — `_decode_key` (:221-230): keep the base64 decode + `len==32` check but `return
   bytearray(decoded)`; update the annotation to `bytearray`.
3. **Lock+zero the keyring** — `AesGcmCipher.__init__` (:122-137): best-effort `_lock_memory(key_ba)` before
   `AESGCM(bytes(key_ba))` (:135/:137), then `_secure_zero` + `_unlock_memory` in `try/finally` once AESGCM has
   copied the key. Preserve `_fingerprint` on pre-zero bytes and the exact keyring insertion order. Do **not**
   retain the key bytearray as an attribute.
4. **encrypt/decrypt** (:160-168 / :195-218): build `bytearray` copies the code owns, lock, pass to AESGCM,
   `_secure_zero` in `finally`. **Do not** touch `os.urandom` nonce, base64 layout, or the `mfenc:v1` marker.
   Document inline that the returned str + cryptography's returned bytes are immutable (the honest residual).
5. **Docstring** — extend the module docstring with an "In-use memory protection (13.3.3 / 11.7.1 / 11.7.2)"
   paragraph: best-effort lock+memset; the documented **residual** (CPython immutable str/bytes + cryptography's
   unreachable internal OpenSSL key copy → not a complete wipe); the 11.7.1 disposition (full memory encryption
   = host/hypervisor territory → stated deployment requirement + signed acceptance).
6. **Tests** — `tests/test_store_encryption.py`: `_secure_zero` clears; round-trip after zeroization; spy that
   lock+zero run on the DEK path; forcing `_lock_memory→False` still round-trips; **`test_v1_frozen_fixture_decrypts`
   (:452) passes UNCHANGED** (v1 byte-identity).

**Verify:** ruff ×2 · mypy strict · FULL offscreen pytest · `python scripts/security/crypto_inventory_check.py`
(must pass **unchanged** — `ctypes`/`sys` are not tracked crypto modules). **Gates:** **no new dep** (stdlib);
**owner-decision** — the honest close is a **partial 13.3.3** + an 11.7.1 acceptance statement (surface the
residual in the PR, do not self-mark #198 fully closed); scope = `crypto.py` + its tests **only** (no
`settings.py`, no store backend). **DoD:** quartet green + inventory unchanged; v1 byte-identical; best-effort
lock+zero live with a forced-failure round-trip test; residual documented; public Cipher seam unchanged.

### Wave 2 — GATE (#189) · branch `feat/gate-189-dual-control-warn`
`scripts/worktree/new.ps1 -Name plan9-gate` (NO `-Sqlserver`). Re-read `__main__.py:1129-1157` on live main after
`plan8-201` merges.

1. **Serve-gate** — `__main__.py`: insert a block **after** the sec-mfa-on block (closes :1155) and before the
   `# This instance's environment values` comment (:1157). Mirror the sec-mfa-on structure: reuse `admin_exposed`
   (:1129) + `exposure_desc`; guard `if admin_exposed and not settings.approvals.enabled:` then `if data_class is
   DataClass.PHI:` → emit a **stderr WARNING** naming `[approvals].enabled` + the gated flows (`dead_letter_replay`,
   `connection_purge`) and that every high-value action currently completes on one caller's authority (2.3.5). A
   synthetic instance stays quiet; a loopback default is byte-identical. **Default WARN-only** (the lane title);
   leave a clear TODO marking the prod-refuse as the owner fork.
2. **Tests** — `tests/test_cli.py`: a `# --- dual-control-at-exposure posture ---` section modelled on the MFA
   suite (:504-625). Reuse `_expose_toml`, add `[auth] require_mfa=true` so the sec-mfa-on gate is pre-satisfied
   and only the approvals gate is under test; mock `create_managed_app` + `uvicorn.run`, pre-set the store key.
   Cases: exposed staging PHI + approvals off → rc 0 + `[approvals]` warn; exposed dev synthetic → rc 0 quiet;
   loopback prod → rc 0 quiet (byte-identity); exposed PHI + approvals on → rc 0 no warn.
3. **Docs deviation** — annotate 2.2.1 (L133/L280/L292) + 2.2.3 (L134/L282/L294) in
   `ASVS-L3-ASSESSMENT-2026-07-09.md` as an **adjudicated accepted** tolerant-peek deviation (`Validation.strict`
   opt-in per feed + no shipped default cross-field rule), with the explicit CLAUDE.md §8 design-tension note.
   **Reconcile the living docs:** add a matching `[Accepted deviation — #189]` residual entry in
   `ASVS-L3-ASSESSMENT.md` (template L116-132) and update the "0 open Partials" framing in `ASVS-L3-STATUS.md`
   (:22-24) so no doc claims both "0 Partials" **and** an open 2.2.1/2.2.3 Partial. Cite the symbol
   `Validation.strict` (default `False`), not the stale `models.py:317`. *(Fold #203's delegation-boundary
   statement here — GATE is the ASVS-docs anchor lane.)*

**Verify:** ruff ×2 · mypy strict · FULL offscreen pytest (re-run the sec-mfa-on suite to prove ordering
unperturbed). **Gates:** **run first** in Wave 2, land its `__main__.py` block ahead of STORE/SECRETS/TLS;
**owner decision** — warn-only (default) vs. mirror sec-mfa-on's prod-refuse (bake into the PR body); loopback
byte-identity; **no `settings.py` edit** (reads shipped `settings.approvals.enabled`); **no new dep**. **DoD:**
exposed-PHI warns / synthetic + loopback quiet / approvals-on silent; three ASVS docs reconciled; quartet green.

### Wave 2 — AUTH (#193, #195a) · branch `feat/plan9-auth`
`scripts/worktree/new.ps1 -Name plan9-auth` (NO `-Sqlserver`). **Start only after PLAN-8 Waves 2-3 merge** (owns
`api/security.py` + `auth/**`) — re-anchor every line below.

1. **#195a granted twin (service.py)** — add `async audit_permission_granted(self, identity, permission, path)`
   mirroring `audit_permission_denied` (:1789-1796) → `_audit('auth.permission_granted', …)` → `store.record_audit`
   (no new store method).
2. **#195a emit (security.py)** — emit the granted twin in `require()`'s dependency after the permission loop and
   before `return identity` (currently :88), and in `authorize_ws` before `return identity` (:251). **CRITICAL
   scope decision (owner):** `require()`/`authorize_ws` fire on **every** protected request (console polling +
   `/ws/stats`) — a literal grant-per-request **floods the hash-chained audit log.** Implement a defensible scope
   (recommended: audit grants for the sensitive/step-up + write + config/user-mgmt surface, distinct from the
   already-audited PHI-access rows, plus a documented 16.3.2 read-polling deviation) **or** a default-tunable
   `[auth]` toggle. Dedupe vs. PHI-read rows (require_phi_read wraps require()).
3. **#193 limiter (service.py)** — add `_admin_write_limiter: SlidingWindowRateLimiter | None` built like
   `_phi_read_limiter` (:249-257) from the scaffold's `[auth].admin_write_rate_limit_*`; add `allow_admin_write`
   mirroring `allow_phi_read` (:280-285). A small `per_key` over a ~1s window is the human-timing floor.
4. **#193 gate (security.py)** — fold the pacing into `require_step_up` (:127-153): after `base(request)`, gated
   `request.method != 'GET'` (exempts the sole step-up GET `/messages/search` at `app.py:1849`; every purge/replay/
   config/user-mgmt route is POST/PUT/DELETE), call `allow_admin_write`; on `False` `log.warning` + raise 429 +
   Retry-After (mirror require_phi_read :100-114). **Touches ONLY `security.py` — ZERO `app.py`/`auth_routes.py`
   edits.** Tune the floor so a legit `403 → /me/reauth → retry` burst is not 429'd.
5. **Docs** — flip `docs/SECURITY.md:67-73` from "deliberately not implemented" to the built per-actor admin-write
   pacing floor.
6. **Tests** — granted-audit test (mirror `test_ws_permission_denied_is_audited`, `test_auth_hardening.py:511`);
   admin-write 429 test (mirror `test_api_auth.py:419`); limiter unit test (`test_auth_entry_hardening.py:65`); a
   regression that content-search GET + login + phi-read are **not** pace-limited and the grant scope does not
   flood on repeated monitoring GETs.

**Verify:** ruff ×2 · mypy strict · FULL offscreen pytest. **Gates:** wave-gate behind PLAN-8's merge (re-anchor);
consume `[auth].admin_write_rate_limit_*` from the scaffold (do **not** author `settings.py`); **AUTH before
TLS** (both touch `security.py`); owner sign-off on the #195a grant scope; **no new dep**. **DoD:** #193 fully
closed (every write pace-limited → 429; GET/login/phi-read unaffected; SECURITY.md flipped); #195a delivered at
the agreed scope (audit log not flooded; denial path unchanged; `authorize_ws` twin included). PR body: *"closes
#193; partially closes #195 (#195a audit clause — #195b is the SECRETS lane)"* — **do NOT green #195 here.**

### Wave 2 — STORE (#190, #63) · branch `plan9-store`
`scripts/worktree/new.ps1 -Name plan9-store -Sqlserver` (REQUIRED — 3-backend tests). **`git merge main` after
SECMEM lands** before editing `crypto.py`; consume the scaffold's `[diagnostics].message_events` +
`[integrity].audit_verify_on_start`.

1. **#190-A key the primitive** — `store.py:693`: extend `audit_row_hash(…, key: bytes | None = None)`; `key is
   None` → keep `hashlib.sha256(canonical.encode()).hexdigest()` **byte-identical** (keyless + legacy rows still
   verify); else `hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()`. Add `import hmac`. This one
   shared function serves all 9 call sites.
2. **#190-B derive the MAC key** — `crypto.py`: add `AesGcmCipher.audit_mac_key() -> bytes` = HKDF-SHA256 over
   the active DEK (info `b'mefor/audit-chain/v1'`, 32 bytes; HKDF is in the already-present `cryptography`).
   `IdentityCipher → None` (keyless stays unkeyed). Layer **additively** on SECMEM's DEK-protection edits.
3. **#190-C thread the key** — `base.py:1340` (after `make_cipher`): compute `mac = audit_mac_key(cipher)` and
   pass `audit_mac_key=` into each backend `.open()`; store `self._audit_mac_key` (default `None`); pass into
   every `audit_row_hash` call (SQLite :1528/:4847/:4971, Postgres :1069/:3893/:4004, SQL Server :1047/:5125/:5168).
4. **#190-D migration (OWNER DECISION)** — an existing encrypted store has an **unkeyed** chain; flipping to
   keyed breaks `verify_audit_chain` on every prior row. Implement a **versioned** scheme (keyed-from watermark
   or a forced `rekey-audit` step that runs **only on an operator-verified chain**). **Do NOT silently re-key on
   open** (would re-bless forged rows).
5. **#190-E startup auto-verify** — `engine.py Engine.start()` after `reset_stale_inflight` (~:682): `ok, msg =
   await self.store.verify_audit_chain()`; on failure log WARNING + fire AlertSink; **alert-only default**, gated
   by scaffolded `[integrity].audit_verify_on_start` (never crash startup). Serialize this edit with SECRETS.
6. **#190-F GCM counter** — `crypto.py:160 encrypt`: increment `self._invocations`; soft-warn (~2³¹) and fail-
   closed (`CipherError`) approaching 2³². **Owner decision:** in-memory counter (cheap, resets on restart) vs.
   persisted (accurate, costlier) — note the current random-96-bit-nonce scheme is standard/safe to ~2³², this is
   defense-in-depth.
7. **#63 gate all emission paths (asymmetric)** — Postgres: gate `_event()` (`postgres.py:1260`). SQL Server:
   gate `_event/_event_sync` (:1513/:1525) **and** conditionally omit the group member at the two batched sites
   (:2278/:2490 — can't no-op inside `_event_stmt`). SQLite: gate `_event()` (:6194) **plus the three direct
   inserts that bypass it** (`store.py:2063/2285/2704`) via a shared `_should_record_event(event)` predicate. The
   :2285 `received`/`ingress` insert is on the hot ACK-txn path returning `mid` — suppressing its row must **not**
   touch the messages/queue disposition rows (count-and-log is separate).
8. **#63 compliance floor** — `_should_record_event` **always** keeps `viewed` (PHI-access, `store.py:4824`) and
   terminal `dead`/`error`/`failed`, even at `off` (a blanket off would drop the HIPAA PHI-view trail).
9. **Plumb verbosity** — `[diagnostics]` is top-level `ServiceSettings`, not under `[store]`, and `open_store`
   only receives `StoreSettings` — add a `message_events` param to each backend `.open()` sourced by the caller
   that has `ServiceSettings` (engine/serve), mirroring the `engine._connection_events` caller-gate precedent.
   Add a test that a configured `off`/`errors` actually suppresses via the real serve/open path.
10. **Tests** — extend `tests/test_audit_integrity.py` **parametrized across SQLite + Postgres + SQL Server**
    (SQLite-only today): keyed verify passes; keyless stays byte-identical (frozen fixture on `audit_row_hash(None)`);
    a keyed edit fails verify; the re-key/backfill path; GCM threshold warn/fail; the message_events gate
    (routine suppressed / `viewed`+`dead` retained).

**Verify:** ruff ×2 · mypy strict · FULL pytest **on all three backends** (SQLite + asyncpg + self-hosted win2025
SQL Server leg). **Gates:** SECMEM first; scaffold first; `engine.py` serialized with SECRETS; `-Sqlserver`;
**no new dep** (hmac/hashlib stdlib, HKDF in `cryptography`); TLS lands after STORE. **DoD:** chain HMAC-keyed
with keyless byte-identity + a documented non-silent migration; startup verify (alert-only); GCM rekey-before-2³²;
gate honored at every path with the floor; 3-backend quartet green; PR carries `#190 + #63`.

### Wave 2 — SECRETS (#196, #195b) · branch(es) `feat/plan9-196-vault-keyprovider` (PR-A) + `feat/plan9-195b-secret-rotation` (PR-B)
`scripts/worktree/new.ps1 -Name plan9-secrets` (NO `-Sqlserver` — DEK-sourcing, not a backend). **Split into two
PRs** so the Vault provider isn't blocked on the rotation-ADR decision. Install `[dev,console,vault]`.

0. **Owner gate first (new dep + ADR posture):** vet **`hvac`** (HashiCorp official Vault client, Apache-2.0,
   named in ADR 0019 §3:181). The **Vault KeyProvider needs no new ADR** (ADR 0019 already authorizes per-
   provider follow-on PRs); the **#195b rotation-enforcement policy** + the connector-SecretProvider generalize-
   ation **do** need authorization — owner chooses an ADR 0019 §5 amendment vs. a new ADR (coordinator-assigned
   number; see footer). Do not start engine work until settled.
1. **#196 Vault KeyProvider** — new `store/keyprovider_vault.py` (SPDX) exposing `build_provider(settings:
   StoreSettings) -> KeyProvider`. **Import `hvac` lazily inside** (missing hvac → `KeyProviderError` naming the
   `vault` extra, mirror `keyprovider.py:166`). Implement `active_key()->str|None` + `retired_keys()`; read
   KEK/wrapped-DEK/addr/token from settings/env, call `client.secrets.transit.decrypt_data(name=kek,
   ciphertext=wrapped_dek)`, return the base64 plaintext DEK. **No edit to `keyprovider.py`** — `_load_external_
   provider` (:145) dispatches by name.
2. **Extra + DEP-1** — `pyproject.toml:59`: `vault = ["hvac>=<vetted-floor>"]` with a dep-vet comment mirroring
   `[dicom]`/`[webauthn]`. Then `uv lock` + 3× `uv export`.
3. **Fix the self-break** — `tests/test_keyprovider.py:145`: **drop `'vault'`** from the fail-closed parametrize
   (else this lane's own build fails it). New `tests/test_keyprovider_vault.py`: a faked transit backend returns
   a base64 key → `make_cipher(...)` round-trips ADT (ADR 0019 §3:205); missing-hvac fail-closed; `resolve_key_
   provider(StoreSettings(key_provider='vault'))` wiring.
4. **#195b settings** — consume `SecretRotationSettings` + `'secret_rotation'` in `_ALERT_EVENT_TYPES` from the
   scaffold (do not author `settings.py`).
5. **AlertSink method** — add `secret_rotation_due(name, *, secret, last_rotated, days_overdue)` to the Protocol +
   `LoggingAlertSink` (`alerts.py:78/:176`) + `NotifierAlertSink` (`alert_sinks.py:453`, `type='secret_rotation'`)
   + a no-op to **every in-repo AlertSink test double** (`test_cert_expiry.py`, `test_connection_event_outbound.py`,
   `test_startup_attestation.py`) — **one commit** (mypy-strict Protocol ripple).
6. **#195b runner** — new `pipeline/secret_rotation.py` (SPDX): `SecretRotationRunner` mirroring `CertExpiryRunner`
   (`cert_expiry.py:95`): injected clock + source callable (the `_FILE_SECRET_KEYS` set + store DEK, each with an
   operator-configured last-rotated + max-age), pure `run_once()` emitting `secret_rotation_due` when overdue,
   `enabled` gate + start/stop. **PHI-free: label + dates only, never the secret value.**
7. **Wire** — `engine.py` mirroring `cert_monitor` **verbatim** (ctor :124, self :213, slot :224, build param
   :375/:425, start :785-791, stop :1289-1290, a `_tracked_secrets()` source); thread `settings.secret_rotation`
   from `__main__.py:1268` and `api/app.py:2731/:2854`.
8. **Tests** — `tests/test_secret_rotation.py` mirroring `test_cert_expiry.py` (fixed instant + injected clock +
   recording sink): overdue emits, within-window emits, healthy silent, `enabled=off` spawns no task, synthetic
   labels only.
9. **Docs/ADR** — the owner-chosen §5 amendment or new ADR + README row; document `[secret_rotation]` in
   `docs/CONFIGURATION.md`. **Scope gate: do NOT build the connector SecretProvider here** — file it as a follow-on.

**Verify:** ruff ×2 · mypy strict (hvac has no stubs — contain a `type: ignore`/typed local inside
`keyprovider_vault.py`) · FULL offscreen pytest · DEP-1 lock-sync · `/verify` a live `serve` with
`key_provider=vault` against a faked/local Vault. **Gates:** owner vet hvac + ADR posture; DEP-1 re-lock; high-
traffic `settings.py`/`engine.py`/`__main__.py`/`app.py` — re-anchor at wave start. **DoD:** Vault provider
resolves a real key + faked key round-trips + missing-hvac fail-closed; `test_keyprovider.py:145` fixed; extra
+ lock synced; AlertSink method on all implementers + doubles; runner wired like cert_monitor; ADR landed;
`#196` + `#195b` banners flipped (**#195 only after AUTH's #195a also lands**).

### Wave 2 — TLS (#200) · branch `feat/api-200-tls-failclosed-mtls-identity`
`scripts/worktree/new.ps1 -Name plan9-tls` (NO `-Sqlserver`). Install `[dev,console,dicom,fhir]`. **Land LAST** —
rebase on merged AUTH + STORE, then re-run the FULL quartet on the **combined tree**.

0. **Coordinator contract:** the scaffold must have added the `[api]` fields (mTLS cert→identity map, Posture-B
   intra-service-auth mode, declared proxy-TLS/KEX floor) near `ApiSettings` TLS block (:453-473). **Do not edit
   `config/settings.py`** — consume; if a field is missing, ask the coordinator.
1. **KEX-under-proxy (11.6.2)** — `config/tls_policy.py`: add `validate_proxy_tls_posture(...)` mirroring
   `validate_tls_ciphers` (:77) that validates the operator-declared proxy KEX/min-version floor. Wire a start-
   time assertion into the `tls_terminated_upstream` branch (`__main__.py:969-977`) so Posture-B **refuses**
   (`return 2`) unless the floor is declared. **State honestly** this is operator-**attestation** made fail-
   closed, not runtime inspection (the engine cannot observe the proxy's KEX) — avoid over-claiming 11.6.2.
2. **Fail-closed Posture-B (4.2.1/4.4.1)** — extend the exposed-gate (`__main__.py:962-994`): the
   `tls_terminated_upstream` branch (:969-977) today logs-and-allows unconditionally — add a PHI-production
   **refuse** (`return 2`) unless the intra-service-auth posture is affirmatively declared, mirroring the
   require_mfa PHI-prod fail-closed (:1130-1148: refuse prod PHI, warn non-prod PHI, quiet synthetic). Tighten
   `--allow-insecure-bind` so it cannot bypass a PHI-prod Posture-B.
3. **mTLS-as-Identity (4.2.1/4.4.1/12.3.5)** — `api/tls.py:48-50` already forces `CERT_REQUIRED` when
   `tls_client_ca_file` is set. Add a peer-cert→principal path: **VERIFY the pinned uvicorn exposes the peer cert**
   (Starlette middleware reading `scope` transport `get_extra_info('ssl_object').getpeercert()`) before
   committing; in `api/security.py` beside `require()` (:66) resolve the cert subject/SAN to an `Identity` via the
   scaffold's cert-identity map. Wire the map through `create_app` (:635 param + :691 app.state) and the
   `create_app` call in `__main__.py` (:1280-1300).
4. **Tests** — extend `tests/test_api_tls.py` (reuse `_self_signed` :27, synthetic certs): Posture-B refuses on
   PHI-prod without the intra-service-auth declaration; refuses without a declared KEX floor; a verified client
   cert resolves to the mapped Identity (positive) and an unmapped/spoofed CN is denied (negative); a **loopback
   serve emits no new stderr** (byte-identity).
5. **Docs** — extend ADR 0002 §0/§4 + `docs/security/OFF-LOOPBACK-DEPLOYMENT.md` (:21 proxy→engine row) with the
   new fail-closed preconditions + mTLS-identity model. A **new ADR only on explicit owner request** — #200 is
   not ADR-gated in §L.

**Verify:** ruff ×2 · mypy strict · FULL offscreen pytest · **combined-tree re-run** after rebasing AUTH+STORE.
**Gates:** land last; consume the scaffold (no `settings.py`); **no new dep** (stdlib `ssl` + core `cryptography`);
loopback byte-identity; owner-gate if the mTLS-identity design needs a formal ADR (don't self-author). **DoD:**
Posture-B refuses on PHI-prod without intra-service-auth + without a KEX floor; mTLS resolver positive+negative;
loopback byte-identical; combined-tree quartet green; `#200` banner flipped.

### Wave 3 — IDE-IMPORT (#105) · branch `feat/plan9-ide-import-105`
`scripts/worktree/new.ps1 -Name plan9-ide-import` (NO `-Sqlserver`). **Owner-gated + new ADR + depends on PLAN-8
L2.**

0. **ADR first** — author `docs/adr/<NNNN>-deterministic-corepoint-import.md` (coordinator-assigned number) + a
   README row. It must pin: (a) the Corepoint **export input format** (source = the gitignored #87 recon +
   owner screenshots → a **synthetic fixture corpus** must be defined here); (b) the ~71-action → vocabulary
   **mapping depth** (deterministic vs. hand-finish stubs); (c) the **engine-mapper + CLI, IDE-thin-wrapper**
   ownership split (ADR 0076 §5 "grammar in one place"), overriding the draft's "ide/** only".
1. **Engine mapper** — new `messagefoundry/corepoint_import.py` (SPDX): pure, stdlib-only parser → intermediate
   action model → codegen emitting `@router`/`@handler` modules calling the **ADR 0076 vocabulary**
   (`messagefoundry/actions.py`: `copy_field`/`set_field`/`format_date`/`code_lookup`/…) + `Send(...)` against
   the `Message` API (`parsing/message.py:242 set` / :442 groups / :456 encode). #105 is the **inverse of ADR
   0076 §2** (that table read right-to-left). Unmapped actions emit an in-place `# TODO: Corepoint <ActionClass>
   — hand-finish` + best-effort `msg.set` stub — **never dropped silently** (count-and-log ethos).
2. **Engine CLI** — register an `import` subcommand in `__main__.py` (`sub.add_parser` pattern at :55, mirror
   `init`:285): `messagefoundry import corepoint <export> --out <config-dir> [--json]`, wired through
   `_add_project_root_trio` (:488) like validate/dryrun.
3. **IDE command** — new `ide/src/corepointImport.ts`: register `messagefoundry.importCorepoint` in
   `extension.ts` (:209) + `ide/package.json` (:95); shell `messagefoundry import corepoint … --json` via
   `ide/src/cli.ts` `runJson` (inherits the `isExecGated` workspace-trust gate, SEC-004/ADR 0035); open generated
   modules mirroring `newRoute.ts createRoute()`.
4. **Tests** — `tests/test_corepoint_import.py` golden-pair **synthetic** fixtures: emitted modules pass
   `messagefoundry check` **and round-trip through `lens parse`** (every `@handler` classifies into typed rows,
   no whole-file refusal — the correctness gate). IDE: `ide/src/test/suite/corepoint-import.test.ts` stubs the CLI
   spawn with canned JSON (CI `ide` job has no Python).
5. **Flip trackers** — `BACKLOG #105` banner + `docs/AI-OFF-MATRIX.md:21` `/migrate` row → shipped.

**Verify:** engine quartet (ruff ×2 · mypy strict · FULL pytest) + IDE quartet (`npm ci && npm run typecheck &&
npm run compile && npm test`; headless electron exits 9 — unit-test node logic + mock the CLI boundary).
**Gates:** **owner + new ADR** (input format + mapping depth unpinned on main — not dispatchable without the
fixture corpus); **depends on PLAN-8 L2** (`actions.py`+`lens.py` absent on main) to emit lens-round-trippable
handlers; Wave-3 after PLAN-8 fully lands (shared `__main__.py`/`extension.ts`/`package.json`); **no new dep**
(stdlib parse) unless the ADR pins a non-stdlib format (then DEP-1). **DoD:** emitted modules pass `check` +
lens round-trip; unmapped → in-place stubs; ADR Accepted + indexed; synthetic fixtures only; banner + AI-OFF
row flipped.

### Wave 3 — DIRECT-HISP (#157) · branch `plan9-direct-hisp`
`scripts/worktree/new.ps1 -Name plan9-direct-hisp` (NO `-Sqlserver`). **Owner go/no-go + ADR. PR1 = outbound
S/MIME only.**

1. **ADR first** — `docs/adr/<NNNN>-direct-hisp-smime-connector.md` (coordinator-assigned) + README row. Lock:
   (a) scope = **outbound S/MIME-over-SMTP destination for PR1**; inbound mail source, MDN, DNS-CERT discovery,
   IHE XDR/XDM **deferred**; (b) crypto = **core `cryptography>=48` `serialization.pkcs7` only** (endesive
   **rejected**); (c) `dnspython` deferred; (d) egress: reuse `[egress].allowed_smtp` vs. a new `allowed_direct`.
2. **Enum** — `config/models.py:44`: add `DIRECT = "direct"` to `ConnectorType` (the **only** models.py change —
   Source/Destination stay free-form).
3. **Connector** — new `transports/direct.py` (SPDX): `class DirectDestination(DestinationConnector)`. Validate
   host/sender/recipients like `EmailDestination` (`email.py:80-124`); load signing key+cert + per-partner
   recipient cert + trust anchor via `cryptography.x509`/`serialization` **at construction** (fail loud, `rest.py:171`
   pattern). `send(payload)`: build `EmailMessage`, **SIGN** via `pkcs7.PKCS7SignatureBuilder` then **ENCRYPT**
   via `pkcs7.PKCS7EnvelopeBuilder(recipient cert)`, SMTP off-loop via `asyncio.to_thread` (`email.py:129`); reuse
   the STARTTLS + `refuse_cleartext_credentials` posture + `test_connection/_probe` (`email.py:173`). End with
   `register_destination(ConnectorType.DIRECT, DirectDestination)`.
4. **Register** — add `direct` to the `transports/__init__.py` registration tuple.
5. **Factory** — `config/wiring.py`: add `def Direct(...)` after `Email()` (:1114) returning
   `ConnectionSpec(ConnectorType.DIRECT, {...})` (signing_key/signing_cert/recipient_cert/trust_anchor + host/
   sender/recipients/…; secrets via `env()`). No `connections_file.py` edit (DIRECT is code-first-only like EMAIL).
6. **Egress gate** — `wiring_runner.py`: in `_allowlist_for` (:4064) add `DIRECT → egress.allowed_smtp` (or
   `allowed_direct` per ADR); add a parallel DIRECT branch in the `check_egress_allowed` EMAIL region (~:4487). If
   a new `allowed_direct` list is chosen, add it to `EgressSettings` (`settings.py:1226`) + its normalizer.
7. **Tests** — new `tests/test_direct_transport.py` (SPDX): mirror `_FakeSMTP` (never dials); mint an ephemeral
   self-signed cert+key in-test; assert a real **SIGN→VERIFY and ENCRYPT→DECRYPT round-trip** over a **synthetic**
   HL7 body, cleartext-credential refusal, `DeliveryError` mapping, `check_egress_allowed` match+deny.

**Verify:** ruff ×2 · mypy strict (add `dns.*` to the `[tool.mypy]` override only if `dnspython` is ever admitted)
· FULL offscreen pytest. **DEP-1 only if a new dep is admitted — PR1 adds none.** **Gates:** **owner go/no-go
required before dispatch** (P3 money-pit, zero live feed); ADR ratified; endesive rejected, `dnspython` optional/
deferred; Wave-3, collision-free (all-new files) — re-check `wiring_runner.py`/`config/wiring.py`/`transports/base.py`
have no open PR at wave start (`plan8-199` owns base.py). **DoD:** ADR merged; DirectDestination builds/registers/
authorable via `Direct()`; egress fail-closed; S/MIME round-trip proven (not a smoke test); quartet green; PR1
**no new dep**; `#157` banner flipped (or owner-chosen partial-scope banner).

### Wave 3 — SANDBOX (#197) · branch `plan9-sandbox`
`scripts/worktree/new.ps1 -Name plan9-sandbox` (NO `-Sqlserver`). **Owner + isolation ADR + waits for #89 +
`[sandbox]` scaffolded.**

0. **Gate first (do not build until all true):** (a) the isolation **ADR** (coordinator-assigned) is Accepted;
   (b) **#89 VALIDATE merged** (it edits the same `wiring_runner.py` + `config/wiring.py` — a file-contention
   gate, not a logical dep); (c) the scaffold's `[sandbox]` section is on main. If any is false, STOP and report.
1. **Read the seam end-to-end:** `config/wiring.py:3006` (`_exec_module` — LOAD seam, runs admin top-level code
   at load/reload as the service account, :3019); `dryrun.py:173-260` (`route_only`/`transform_one` — where admin
   `route(payload)` :204 / `handle(payload)` :249 actually run, and the ADR 0072 `tracer` interposition param);
   `dryrun_trace.py:300-330` (the `_TraceHook` install-around-the-call precedent); the four live dispatch sites
   `wiring_runner.py:3129/:3153/:3453/:3549/:3662` (all already **off-loop** via `to_thread`/executor). Pick the
   grain per ADR: **(A) in-process** wrapper around `dryrun.py`'s invocation (light; DEK stays in-address-space —
   documented residual) or **(B) subprocess/container** worker wrapping `route_only`/`transform_one` (removes DEK
   + audit chain from the sandboxed process — satisfies 15.2.5's hard-isolation intent).
2. **Primitive** — new `pipeline/sandbox.py` (SPDX): a `SandboxPolicy` (from `[sandbox]`) + `run_sandboxed(fn,
   payload, *, phase, name)` returning the result **byte-identically when `mode=off`** (parity default) and
   enforcing isolation otherwise. Pure library boundary — no `api`/`console` imports.
3. **Wire dry-run** — interpose in `route_only`/`transform_one` alongside the `tracer` branch (sandbox + tracer
   must **compose**); keep the fail-closed handler/outbound-name validation (`dryrun.py:205-208`/:253-262)
   **engine-side**, not inside the sandbox.
4. **Wire live** — the four dispatch sites; **preserve** the off-loop invariant and the `RunContext`/`run_contexts`
   re-establishment (`config/run_context.py`, :3113/:3142/:3421/:3548 — `to_thread` does not copy contextvars).
   For approach (B): re-marshal RunContext + payload across the boundary and **decide the `db_lookup`/`fhir_lookup`
   story** (they bridge back onto the loop via `run_coroutine_threadsafe`, `wiring_runner.py:969`,:3448-3452 — a
   subprocess boundary **breaks** that: forward over IPC **or** forbid-and-fail-closed).
5. **Load-time** — decide in the ADR whether `_exec_module` (:3019) top-level execution is also sandboxed; at
   minimum thread `SandboxPolicy` through, do not weaken `_assert_safe_config_source` (:2962).
6. **Tests** — `tests/test_sandbox.py`: `mode=off` **byte-identical** parity; an isolation-positive case (a
   forbidden op — importing `store/crypto` or opening a socket — contained/denied); a resource-cap case (a
   pathological Router does not wedge intake); the `db_lookup`/`fhir_lookup` decision. Synthetic HL7 only.
7. **Docs** — flip WP-L3-17 (`ASVS-L3-REMEDIATION-PLAN.md:432`/:496) + `THREAT-MODEL.md:121` to the built state
   (**residual-closure**, not gap-closure); ADR README row; `#197` banner in the finishing PR.

**Verify:** ruff ×2 · mypy strict · FULL offscreen pytest (this lane touches the live pipeline — the **whole**
suite) + combined-tree re-verify after `git merge main` past #89. **Gates:** ADR Accepted before building the
isolation core; sequence after #89; consume `[sandbox]` (don't author `settings.py`); **dep** — RestrictedPython
(if chosen) is a **new dep + owner-vet + DEP-1** and is **not hard isolation** (DEK in same address space); a
subprocess/container path is stdlib (no dep, preferred for 15.2.5). Fail-closed disposition: an isolation denial
routes to ERROR/dead-letter (post-ACK, no NAK) via `_apply_router_internal_error` :2976 / `_apply_transform_
internal_error` :3012 — never accept-and-drop, never crash the connection. **DoD:** `mode=off` byte-identical
(proven); ≥1 isolation-positive + ≥1 resource-cap test; lookup behaviour explicit + tested; RunContext preserved;
ADR Accepted; WP-L3-17 + THREAT-MODEL updated; quartet green on the combined tree.

### Wave 3 — CONSOLE-RETIRE (#103) · branch `feat/plan9-103-console-retire`
`scripts/worktree/new.ps1 -Name plan9-console-retire` (NO `-Sqlserver`; install `[dev]` + the **new `[harness]`
extra** so the offscreen Qt harness tests actually run). **Large cross-cutting refactor — stage extract→rehome→
CLI GREEN before the delete commit.**

0. **Pre-flight gates:** confirm PLAN-8 Wave-1-remainder's `scripts/service/*install*` work **has merged**
   before wrapping `install-service.ps1` (currently **not live** per §B, so likely already free); confirm the
   Wave-2 `__main__.py` lanes merged before adding the `service` subparser (rebase); re-read `BACKLOG.md:3287`
   (#75 **SHIPPED**) + :3353 (parity carve-outs). **Do NOT delete `console/` until the owner signs off the
   enumerated parity LOSSES.**
1. **Extract client (A)** — new `messagefoundry/apiclient/__init__.py` (SPDX, re-export `EngineClient`,
   `ApiError`) + `apiclient/client.py` = verbatim move of `console/client.py:1-733` (VERIFIED Qt-free; keep its
   `api.auth_models`/`api.models` imports; stays Qt- and FastAPI-free; deps httpx + truststore only).
2. **Rehome 4 Qt files (B)** → `harness/` (PEP-420 namespace, `from harness.X`): `harness/_async.py` (verbatim),
   `harness/theme.py`, `harness/widgets.py` (repoint `console._async→harness._async`,
   `console.client→messagefoundry.apiclient.client`, `console.theme→harness.theme`), `harness/login.py`. SPDX each.
3. **Update consumers (C)** — ~15 harness import sites (`monitor.py:39-41`, `compose.py:35`, `receive.py:28`,
   `send.py:24`, `scenarios.py:22`, `__main__.py:233/267/998/1272/1576`, `load/connscale/probe.py:35`,
   `load/enginepoll.py:29`, `load/multishard.py:638/674`, `load/runner.py:18`) → `apiclient`/`harness.widgets`/
   `harness.login`. `git grep messagefoundry.console` over `harness/` must come back empty.
4. **Service CLI (D)** — new `messagefoundry/service.py` (SPDX; body from `console/service_control.py:1-149`
   verbatim — keep `CREATE_NO_WINDOW` **and** the `sys.platform!='win32'` returns-False guard for the Linux mypy
   leg). Add a `service` subparser in `__main__.py` (~:438) `install|start|stop|status` wrapping it;
   `install` uses `install_script_path()`→`scripts/service/install-service.ps1`. Re-point the two live refs:
   `verify/checks.py:203` find_spec → `messagefoundry.service`; `harness/acceptance/probes.py:184` path →
   `messagefoundry/service.py` (and `secrets_dpapi.py:16` docstring, cosmetic).
5. **Delete (E)** — remove the whole `messagefoundry/console/` package (all 33 entries). Verify
   `git grep messagefoundry.console` returns only intentional historical doc/ADR prose.
6. **pyproject (F)** — delete `[project.gui-scripts]` (:145-146); retire `[console]` (:60-64) → new `[harness]`
   extra carrying PySide6>=6.6 + httpx>=0.27 + truststore>=0.10; **DROP keyring** (console-launcher-only). Keep
   `[project.scripts] messagefoundry`. No **new** dep; DEP-1 re-lock only if the extra rename perturbs the lock.
7. **Test surgery (G)** — rehome `test_console_client.py`→`test_apiclient.py`, `test_console_widgets.py`→
   `test_harness_widgets.py`; split `test_console_hardening.py` + `test_console_auth.py` (keep client asserts
   under apiclient, drop `_delete_token` launcher asserts); **delete** the Qt-page tests
   (`test_console_{alerts,dead_letters,event_log,users,sessions,shards,status,step_up,password,theme,icon}.py`);
   update `harness/acceptance/matrix.py` coverage/probe rows; **leave `test_webconsole_{absent,mount,seam_snapshot}.py`
   untouched**; check `test_binary_carriage.py:300`.
8. **Docs + ADR (H)** — new ADR (coordinator-assigned) recording the retirement + **accepted parity losses**
   (OS-keyring token custody, interactive self-signed/mTLS trust prompt, multi-shard fan-out UI, QSettings prefs,
   service-control-moved-to-CLI); **supersede ADR 0032**. Collapse two-console prose (CLAUDE.md §2/§3/§10,
   `ARCHITECTURE.md`, `SECURITY.md`, `MENTAL-MODEL.md`). Flip `#103` banner; reconcile #75's :3353 caveats and
   #48's `theme.py` pointer.

**Verify:** ruff ×2 · mypy strict (service.py keeps the Linux-unreachable guard) · FULL offscreen pytest (the
rehomed Qt tests only run with PySide6 in the worktree venv — install `[harness]`) · **manually inspect the
Windows-CI legs** (`probe_console_no_window` now targets `messagefoundry/service.py`; gui-scripts test gone —
ci-gate does not roll these up on non-Windows). **Gates:** **owner pre-acceptance of parity losses** before the
delete (E); stage extract→rehome→CLI GREEN before delete; `__main__.py` + `scripts/service` contention → late
Wave-3; new ADR. **DoD:** `console/` deleted (grep clean); `apiclient/` Qt-free + FastAPI-free + mypy clean; 4
Qt files rehomed + ~15 imports updated; `messagefoundry service …` works; pyproject reshuffled (no new dep);
tests rehomed/deleted + webconsole untouched; docs collapsed + ADR written + 0032 superseded; quartet green;
Windows legs inspected; `#103` banner flipped.

---

## I. Coordinator operating notes (same discipline as PLAN-8 §E)

- **Interrupted dispatches are normal.** A killed Workflow may leave a lane complete-but-unverified or
  uncommitted-in-worktree: check `git -C <worktree> status/log` before re-dispatching; re-run a lost verify /
  adversarial review as a standalone agent; commit verified work yourself rather than rebuilding.
- **Adversarial review per lane before calling it PR-ready** (build → verify → independent review → fix). A
  separate reviewer agent with **no build context** reviews the lane's full diff against its spec + the
  ADR/backlog item; every finding is folded or explicitly waived in the ledger with a reason — never silently
  skipped.
- **Combined-tree rule.** When a second lane lands on a shared hub (`wiring_runner.py`, `__main__.py`,
  `api/security.py`, `store/crypto.py`, `pipeline/engine.py`, the ASVS docs), verify the **combined** tree
  locally (quartet in the rebased worktree) before declaring green — GitHub "CLEAN" is textual only. This is
  mandatory for TLS (after AUTH+STORE), STORE/SECRETS (after SECMEM), and SANDBOX (after #89).
- **Settings-scaffold de-risking commit.** After PLAN-8's live sessions merge, land **one** commit adding every
  new `settings.py` field at once (§A). Every Wave-2 lane then **consumes, never authors** `settings.py`. If the
  scaffold omits a lane's field (e.g. AUTH's `admin_write_rate_limit_*`), **add it to the scaffold** — never let
  a lane edit `settings.py` itself (re-introduces the choke-point collision).
- **Ledger.** Create memory **`plan9-coord-ledger`** (single-writer, this coordinator) — lanes, worktrees,
  branches, commits, verify results, adversarial-review findings, owner decisions, ADR-number assignments; update
  on every state change. Keep it clearly scoped to PLAN-9 (a `plan8-coord-ledger` and a wild `plan8-metrics`
  branch already exist — avoid cross-wiring).
- **Re-verify §B at every wave start**, including open PRs (not just branches). The five live plan8 worktrees are
  local-only and invisible to `gh pr list`; `api/tls.py`/`mllp.py` are currently **free**; the "Wave-1 remainder"
  files are **free**. These facts can change.
- **Cleanup.** `scripts\worktree\remove.ps1 -Name <lane>` from the main checkout when a lane lands; delete local
  branches; remote deletes need owner auth.

---

## J. Coordinator handoff (the one prompt the owner gives a session)

> **ultracode** — You are the PLAN-9 coordinator. Read `docs/releases/MULTISESSION-PLAN-9.md` (this doc) end to
> end, then run the plan under its §I rules. **First:** re-verify §B against `origin/main` + open PRs (the five
> live `plan8-194/199/201/204/base` worktrees are local-only; `api/tls.py`/`mllp.py` and the "Wave-1 remainder"
> files are currently free — confirm). **Wave 1 now:** create two worktrees and dispatch **VALIDATE (#89)** and
> **SECMEM (#198 core)** in parallel via the Workflow tool (build → verify quartet → adversarial review → fix →
> commit local, per the §H dispatch specs); VALIDATE must `git merge main` past `plan8-199`+`plan8-204`
> (`wiring_runner.py`); land **SECMEM's `crypto.py` first** — Wave-2 STORE/SECRETS rebase on it. **Hold Wave 2**
> until PLAN-8's live sessions merge; then land the **settings-scaffold commit** (all new fields at once, §A);
> then dispatch **GATE (#189) first** (it lands its `__main__.py` serve-gate block ahead of the others, after
> `plan8-201` merges), then **AUTH / STORE / SECRETS in parallel**, then **TLS (#200) last** (rebase over AUTH +
> STORE, combined-tree re-verify). **Wave 3** only on my explicit per-lane go: IDE-IMPORT (#105, ADR + scope +
> PLAN-8 L2 merged), DIRECT-HISP (#157, go/no-go + ADR, outbound PR1 only), SANDBOX (#197, after #89 + isolation
> ADR + `[sandbox]` scaffolded), CONSOLE-RETIRE (#103, after I sign off the #75 parity losses). **Assign each
> ADR-needing lane an explicit ADR number** (0077 is already claimed by in-flight `plan8-194` and there is a
> duplicate 0076 in `plan8-201` — hand out **0078+** in dispatch order and re-check at land time). Recover any
> interrupted lane per §I; run an adversarial review per lane; when a lane is green, report it PR-ready. Single-
> write the **`plan9-coord-ledger`** memory. **Autonomy L1: workers build + verify + commit local only — I open
> and approve every PR.** No `Co-Authored-By: Claude` trailer; every finishing PR `git merge main` first and
> carries its `BACKLOG #N`.

---

## K. Definition of done (per lane)

- [ ] **Quartet green in the lane's own worktree venv** — `ruff check .` + `ruff format --check .` → `mypy
      messagefoundry` (strict) → `QT_QPA_PLATFORM=offscreen pytest -q` (**FULL** suite, never a subset).
- [ ] **STORE (+ any store-touching lane): 3-backend tests pass** — SQLite + Postgres (asyncpg) + SQL Server
      (self-hosted win2025 leg / local container); the audit-chain + `message_events` tests on all three.
- [ ] **Adversarial review** run by a no-build-context reviewer against the lane spec + ADR/backlog item;
      findings folded or explicitly waived (with reason) in `plan9-coord-ledger`.
- [ ] **Combined-tree re-verify** where the lane rebased onto a shared hub (TLS, STORE/SECRETS, SANDBOX) — quartet
      re-run in the rebased worktree; GitHub "CLEAN" is not sufficient.
- [ ] **New `.py` files SPDX-headed** (`# SPDX-License-Identifier: AGPL-3.0-or-later`).
- [ ] **New-dep lanes stop for an owner-visible DEP-1 re-lock** — SECRETS (`hvac`); DIRECT-HISP/SANDBOX only if a
      later phase admits one (`dnspython`/RestrictedPython). `uv lock` + 3× `uv export`; the diff is your dep only.
      **PR1 of DIRECT-HISP and the subprocess SANDBOX path add none.**
- [ ] **Loopback byte-identity on security-default flips (GATE, TLS)** — behaviour changes only off-loopback /
      Posture-B / `data_class=phi` / start-time; a 127.0.0.1 serve emits no new stderr (proven by a test).
- [ ] **`v1` byte-identity preserved (SECMEM, STORE)** — `test_v1_frozen_fixture_decrypts` + the keyless
      `audit_row_hash(None)` frozen fixture pass unchanged.
- [ ] **Ledger updated**; ADR number recorded where the lane authored one.
- [ ] **Commit(s) local, explicit paths, no `Co-Authored-By` trailer**; lane **reported PR-ready** to the owner
      (workers never push/PR). The finishing PR `git merge main` first, carries `BACKLOG #N`, flips that item's
      banner — **except #195, which flips only after BOTH #195a (AUTH) and #195b (SECRETS) land.**

---

## L. Owner / decision-gated callouts

1. **#91** — run the FT A/B or record the NO-GO and close it (§D). Not worker work.
2. **VALIDATE #89 default** — confirm the `_STRICT_VALIDATE_TIMEOUT_SECONDS = 5.0` value and the secure-by-
   default-ON posture (`None` inherits the default; only explicit `<=0` disables).
3. **SECMEM #198 honest close** — approve the **partial 13.3.3** (immutable str/bytes + cryptography's internal
   key copy) + the 11.7.1 full-memory-encryption disposition (deployment-requirement + signed acceptance). Do not
   expect a full 13.3.3 close.
4. **GATE #189 warn-vs-refuse fork** — warn-only (default, matches the lane title) vs. mirror sec-mfa-on's
   **prod-refuse** on production PHI. A wrong guess regresses every exposed prod-PHI deployment's startup.
5. **AUTH #195a grant-audit scope** — literal-16.3.2-all-decisions floods the hash-chained audit log; approve the
   operationally-scoped-to-sensitive+writes design (with a documented read-polling deviation) or a default toggle.
6. **SECRETS new dep + ADR posture** — vet **`hvac`**; the Vault provider needs no new ADR, but the **#195b
   rotation-enforcement policy** (and the deferred connector-SecretProvider) need an **ADR 0019 §5 amendment or a
   new ADR**. The connector SecretProvider is **out of this lane** — a filed follow-on.
7. **TLS #200 scope honesty** — KEX-under-proxy is operator-**attestation** made fail-closed, not runtime
   inspection (the engine can't observe the proxy's KEX); the mTLS-identity resolver depends on the pinned uvicorn
   exposing the peer cert (verify first). A formal ADR only if you want the mTLS-identity model ratified.
8. **IDE-IMPORT #105** — **new ADR + scope**: pin the Corepoint export input format (needs a committed synthetic
   fixture corpus — the #87 source is gitignored) and the ~71-action mapping depth; ratify the engine-mapper +
   IDE-wrapper split. **Depends on PLAN-8 L2** landing. Re-scored V2/D6 "money pit" — most likely a decline.
9. **DIRECT-HISP #157** — **go/no-go** (P3 money-pit, no live feed) + **new ADR**: outbound S/MIME PR1 only,
   core `cryptography` (no new dep for PR1), `dnspython`/inbound/MDN/XDR deferred.
10. **SANDBOX #197** — **isolation ADR**: RestrictedPython (in-process; **not** hard isolation, new dep) vs.
    subprocess/container worker (stdlib; removes the DEK from the sandboxed process — meets 15.2.5's intent). High
    blast radius; closes the WP-L3-17 residual, not a Fail. Waits for #89.
11. **CONSOLE-RETIRE #103** — #75 web console is **SHIPPED**; the open item is **pre-acceptance of the parity
    LOSSES** (OS-keyring token custody, interactive self-signed/mTLS trust prompt, multi-shard fan-out UI,
    QSettings prefs) in the ADR before `console/` is deleted. Owner said stop after web-console L4c.

---

*Source: 2026-07-10 ten-level re-score + a 13-lane / 2-cross-cutting code-scout pass (build-state / files / deps
/ contention verified against `origin/main` tip `c74cdb2` and the five live plan8 worktrees). Companion plans:
`MULTISESSION-PLAN-8.md` (IDE low-code) and the ASVS/ops top-backlog handoffs.*

> **Corrections applied (scout-verified, folded into the sections above).** ① **V/D:** SECMEM #198 → **6/6**
> (was 6/5); STORE #190 → **6/7** (was 6/6). ② **#195 is one backlog item** (V6/D4) split AUTH(16.3.2)/
> SECRETS(13.3.4); single `#195` banner, gated on both halves; the per-half D5 is a plan estimate, not a table
> value. ③ **VALIDATE is not collision-free** — `wiring_runner.py` is owned by live `plan8-199`+`plan8-204`;
> strict-validate lives entirely in `wiring_runner.py`, **not** `mllp.py`; the #89(c) size/segment caps
> (`validate.py:71`) are already built (caps-verify + timeout-build). ④ **AUTH does not touch `api/app.py`**
> (pacing folds into `require_step_up` scoped `method!='GET'`). ⑤ **STORE↔`config/tls_policy.py`** and
> **STORE↔`api/app.py`** edges are spurious; the real cross-lane serialization is **TLS-after-AUTH** on
> `api/security.py`. ⑥ **`api/tls.py` + `transports/mllp.py` are FREE** (not in-flight); items #187/#202 are
> unstarted; the "Wave-1 remainder" files are free. ⑦ **`__main__.py` has a live owner** (`plan8-201`);
> **`wiring_runner.py`** and **`transports/base.py`** are in-flight hubs (`plan8-199`) the draft §E omitted.
> ⑧ **DIRECT-HISP S/MIME needs no new dep** (core `cryptography>=48` `serialization.pkcs7`); only optional
> `dnspython` is new. ⑨ **SECRETS' Vault provider needs no new ADR** (ADR 0019 authorizes per-provider PRs);
> the connector SecretProvider is design-only/out-of-lane. ⑩ **IDE-IMPORT is engine+IDE, not ide-only**, and
> depends on PLAN-8 L2 (`actions.py`/`lens.py`, absent on main). ⑪ **SANDBOX** closes a documented **residual**
> (WP-L3-17), not a Fail; the `[sandbox]` section does not exist yet; the narrowest interposition is
> `dryrun.py:204/:249`. ⑫ **CONSOLE-RETIRE** is a large cross-cutting refactor (rehome 4 Qt files + ~15 imports
> + ~12 test files + pyproject + 5 docs), not a 4-path delete.
>
> **ADR numbering (INFLIGHT scout — supersedes "next-free = 0077").** On `origin/main` the highest ADR is
> **0076** (next-free = **0077**). **But** in-flight local worktrees already claim ahead: `plan8-194` created
> `0077-action-bound-step-up.md`, and `plan8-201` created a **duplicate** `0076-certificate-revocation-posture.md`
> (which must renumber upward on its merge). So **0077 is effectively taken** and the first genuinely-safe number
> is **0078**, itself contingent on `plan8-201`'s renumber target. **The coordinator hands out an explicit,
> distinct ADR number to each ADR-needing Wave-3 lane at dispatch (0078+), re-checked at land time — never
> "grab next-free."** (Next-free BACKLOG heading = **#223**.)