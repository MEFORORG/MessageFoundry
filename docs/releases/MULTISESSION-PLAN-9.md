# MessageFoundry — Multisession Execution Plan 9 (2026-07-10)

**Complete the ASVS 5.0 L3 Posture-A remediation + the non-ASVS build batch.**

The next tranche of buildable work after PLAN-8, drawn from the 2026-07-10 ten-level re-score
([`docs/BACKLOG.md`](../BACKLOG.md) → *Ranked backlog*). Thirteen items, each **code-scouted** (build-state,
files, dependencies, and contention with the live sessions verified against the tree by a 16-agent pass).
Most **finish the ASVS 5.0 L3 Posture-A remediation** that PLAN-8's #187/#194/#199/#201/#202/#204 began
(classes 1–4); the rest are non-ASVS.

> **Naming note.** This is **PLAN-9**, not PLAN-8: `MULTISESSION-PLAN-8.md` is already taken by a parallel
> IDE low-code effort (#221/#222, PR #865). A separate ASVS/ops "top-backlog build" is also in flight under
> hand-off (its items are listed under *In-flight* below). This plan is the batch **after** both.

**Method.** Coordinator + one worker subagent per lane, each in its own git worktree
(`scripts/worktree/new.ps1 -Name plan9-<lane>`); workers **build + verify + local-commit**; the **owner**
opens and approves every PR. Nothing merges without a green CI gate + owner click.

> **Status: PLAN — awaiting "go".** No code until the owner approves. Several lanes flip shipping security
> defaults (owner has ruled secure-by-default-with-org-opt-out for the PLAN-8 set; the same posture applies
> here). Wave-3 lanes are individually owner-gated (below).

---

## A. The governing constraint — `config/settings.py` is the choke point

PLAN-8's two in-flight sessions are editing `config/settings.py` **right now** — the Waves-2-3 session in
`[auth]`/`[logging]`, the Wave-1-remainder session in `[store]`/`[retention]`/`[egress]`/`[alerts]`. So **any
lane that touches `settings.py` cannot be Wave 1.** That alone forces ten of the thirteen items out of the
immediate start. Only two lanes touch neither `settings.py` nor any in-flight file.

**The Wave-2 de-risking move:** once PLAN-8 lands, the coordinator makes **one "settings scaffold" commit**
that adds every new `settings.py` section/flag at once (`[diagnostics]`, `[secret_rotation]`, `[sandbox]`,
the dual-control WARN gate, the TLS knobs). After that, the Wave-2 behavior lanes touch mostly disjoint
files and can run with only light serialization on a few hub files.

## B. In-flight (do NOT collide) — owned by live sessions

- **PLAN-8 Waves 2–3:** `settings.py` [auth]+[logging], `api/security.py`, `auth/**`, `transports/fhir.py`,
  the codeset CSV writer, `config/tls_policy.py`, `api/tls.py`, `transports/mllp.py`. Items #187/#194/#199/#201/#202/#204.
- **PLAN-8 Wave-1 remainder:** `settings.py` [store]/[retention]/[egress]/[alerts], the retention runner,
  the egress gate, `dr_backup.py`, `messagefoundry_webconsole/**`, `scripts/service/*install*`. Items #102/#186/#188/#192.

## C. Lane roster

| Wave | Lane | Items | V / D(rem) | Owns | Notes |
|---|---|---|---|---|---|
| **1** | **VALIDATE** | #89 | 5 / 3 | `pipeline/wiring_runner.py`, `config/wiring.py`, `config/models.py`, tests | hl7apy strict-validate wall-clock **timeout** (a hang never dead-letters today) + adversarial fuzz + fork-on-CVE runbook. Collides with nothing. |
| **1** | **SECMEM** | #198 | 6 / 5 | `store/crypto.py` | In-use memory protection: zeroize + `mlock`/`VirtualLock` the unwrapped DEK + plaintext-PHI buffers (13.3.3 / 11.7.x). **Core only** — the optional `[store]` toggle is deferred so it avoids `settings.py`. |
| **2** | **GATE** | #189 | 5 / 3 | `__main__.py`, docs | WARN-at-PHI-exposure serve-gate for dual-control (mirrors the sec-mfa-on block) + accept tolerant-peek as a signed L3 deviation. **Run first** — smallest hub footprint; seeds the serve-gate pattern. (Approval workflow already ships.) |
| **2** | **AUTH** | #193, #195a | 5 / 3, 6 / 5 | `auth/ratelimit.py`, `auth/service.py`, `api/security.py` | Anti-automation admin-write pacing (2.4.2) + **audit every authorization decision** (today only *denials* are logged — add the `_granted` twin at `api/security.py:84`). |
| **2** | **STORE** | #190, #63 | 6 / 6, 3 / 4 | `store/store.py`, `store/postgres.py`, `store/sqlserver.py`, `store/crypto.py` | Key the audit hash-chain (HMAC + startup auto-verify) + AES-GCM invocation counter / rekey-before-2³² (11.3.4/16.4.2); `[diagnostics].message_events` verbosity gate at each backend's `_event()`. Both rewrite all three backends → **one serial lane**. Rebases on SECMEM's `crypto.py`. |
| **2** | **SECRETS** | #196, #195b | 5 / 6, 6 / 5 | `store/keyprovider_vault.py` (new), `pipeline/secret_rotation.py` (new), `pipeline/alerts.py` | External **HSM/KMS/Vault KeyProvider + SecretProvider** (13.3.1) + a `CertExpiryRunner`-style secret-rotation reminder (13.3.4). **New dep (Vault SDK) → DEP-1 re-lock + owner vet first.** |
| **2** | **TLS** | #200 | 6 / 6 | `api/tls.py`, `api/security.py`, `api/app.py`, `__main__.py` | Fail-closed off-loopback Posture-B gate + KEX-under-proxy validation + mTLS-as-Identity (4.2.1/4.4.1/11.6.2/12.x). **Land last** — re-touches `api/security.py` (after AUTH) and `tls_policy.py`/`api/app.py` (after STORE). |
| **3** | **IDE-IMPORT** | #105 | 2 / 6 | `ide/**` (new) | Deterministic (non-AI) Corepoint Action-List → editable Router/Handler Python. Greenfield, collision-free; owner-gated on scope + ADR only. |
| **3** | **DIRECT-HISP** | #157 | 3 / 7 | `transports/direct.py` (new), `config/models.py`, deps | Whole Direct/HISP S/MIME connector — unbuilt. New deps (S/MIME CMS + dnspython) + ADR + owner go/no-go. Own worktree. |
| **3** | **SANDBOX** | #197 | 5 / 8 | `pipeline/sandbox.py` (new), `wiring_runner.py`, `config/wiring.py` | Hard-isolation runtime for admin-authored Router/Handler code (15.2.5). Architectural, high blast radius; **waits for #89 (VALIDATE)**. |
| **3** | **CONSOLE-RETIRE** | #103 | 4 / 6 | delete `console/`, new `apiclient/`, `__main__.py`, `scripts/service/` | Retire the PySide6 desktop console; extract Qt-free `apiclient/`, rehome shared widgets to `harness/`, add a `messagefoundry service` CLI. **Gated on #75 web-console parity** (owner: stop after L4c) + Windows CI. |

## D. Excluded (scout-verified — not build lanes)

- **#91 — owner decision, not a build.** The ADR 0053 `[ ] GIL-on-vs-FT A/B (#91)` box is unchecked, but
  free-threading is *already recorded* NO-GO (ADR 0053 / #789). So either **run the A/B to formally close
  the gate**, or **record the NO-GO and close #91** — a decision, not worker work. (This item was reopened
  during the 2026-07-10 re-score; this is where the owner resolves the reopen.)
- **#203 — owner-scoping doc, not a build.** Its honest close is a delegation-boundary *statement* in
  `OFF-LOOPBACK-DEPLOYMENT.md` (prefer gMSA/Entra, least-privilege secrets, device posture); its 8.4.2
  sub-item already ships. Fold the statement into whichever ASVS docs lane is open.
- Also not in this plan (verified done/moot by the earlier truth-audit): **#48** (IDE snippets, already
  shipped), **#185** (ASVS tracking index — ships nothing; close it when #186–#205 all resolve), **#87**
  (competitive-intel research), **#191/#205** (ASVS closeout docs, not builds).

## E. Contention matrix

`config/settings.py` is the primary collision (Wave-1 exclusion for ten items — see §A). Beyond it, the
Wave-2 lanes re-collide on a small set of hub files and must serialize on them:

- `__main__.py` — GATE, STORE, SECRETS, TLS
- `api/security.py` — AUTH, TLS  → TLS after AUTH
- `api/app.py` — AUTH, STORE, TLS
- `pipeline/engine.py` — STORE, SECRETS
- `config/tls_policy.py` — STORE, TLS  → TLS after STORE
- `store/crypto.py` — **Wave-1 SECMEM must land before Wave-2 STORE/SECRETS** (it edits crypto.py first)

Wave-3 lanes IDE-IMPORT and DIRECT-HISP are fully collision-free (new files); SANDBOX and CONSOLE-RETIRE are not.

## F. Sequencing

1. **Wave 1 now:** two independent worktrees — **VALIDATE (#89)** and **SECMEM (#198 core)**. Neither
   touches `settings.py` or any in-flight file.
2. **Hold Wave 2** until PLAN-8's two sessions merge. Then land the coordinator's **settings-scaffold commit**
   (all new sections/flags at once). Then, in order: **GATE (#189)** first → **AUTH**, **STORE**, **SECRETS**
   in parallel (disjoint after the scaffold) → **TLS (#200)** last (re-touches AUTH's + STORE's files).
3. **Wave 3** is owner-gated, any order once greenlit: IDE-IMPORT and DIRECT-HISP await an ADR + scope;
   SANDBOX awaits #89; CONSOLE-RETIRE awaits #75 parity + the in-flight `scripts/service` work.

## G. Coordination rules & build gotchas (same discipline as PLAN-8)

- One worktree + branch per lane (`scripts/worktree/new.ps1 -Name plan9-<lane>`, `-Sqlserver` for STORE);
  use that worktree's `.venv`. Workers build + verify + local-commit only; owner pushes/PRs/auto-merges.
- Every PR `git merge main` first (the CI gate hangs otherwise). **No `Co-Authored-By: Claude` trailer**
  (the CLA bot fails on it). A finishing PR carries `BACKLOG #N` + flips that item's banner to ✅.
- **DEP-1 re-lock** for the new-dep lanes (SECRETS Vault SDK; DIRECT-HISP S/MIME CMS + dnspython):
  `uv lock` + the three `uv export`s; verify the diff is your dep only; the repo stores the locks CRLF.
- **3-backend tests** (SQLite + Postgres + SQL Server) for STORE and any store-touching lane; SQL Server is
  the self-hosted win2025 CI leg.
- **Loopback byte-identity** on every security-default flip (GATE, TLS): behaviour changes only off-loopback
  / at `data_class=phi`, or is start-time-gated.
- **Verify order every lane:** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for any Qt tests).

## H. Owner / decision-gated callouts

1. **#91** — run the FT A/B or record the NO-GO and close it (see §D).
2. **SECRETS / DIRECT-HISP new deps** — vet + approve before the lane adds them.
3. **DIRECT-HISP (#157), IDE-IMPORT (#105)** — need an ADR + scope decision before Wave 3.
4. **CONSOLE-RETIRE (#103)** — owner said stop after web-console L4c (#75); confirm parity before deleting `console/`.
5. **SANDBOX (#197)** — architectural, high blast radius; confirm the isolation approach (RestrictedPython vs.
   subprocess/container worker) in an ADR before building.

---

*Source: 2026-07-10 ten-level re-score + a 16-agent code-scout (build-state / files / deps / contention all
verified against `origin/main`). Companion plans: `MULTISESSION-PLAN-8.md` (IDE low-code) and the ASVS/ops
top-backlog handoffs.*
