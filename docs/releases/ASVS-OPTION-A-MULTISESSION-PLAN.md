# MessageFoundry — ASVS "Option A → 0 Open Fails" Multisession Plan

> **Provenance.** Generated 2026-06-18 as a coordinator artifact via multi-agent workflows:
> the lane footprints were grounded in the live code/ADRs, the draft plan was **adversarially
> red-teamed** across 7 lenses (concurrent-file collision, coordinator-gate leak, sibling-worktree
> collision, dependency/ordering deadlock, arithmetic, governance over-claim, execution simulation),
> repaired, then the 8 collision-relevant sibling branches were triaged for an ordered pre-gate.
> Shared across the parallel worktrees per [`../WORKTREES.md`](../WORKTREES.md). Update as items land.

---

## 0. Objective — and the honest caveat the red-team forced

Take the **3 remaining combined ASVS L3 Fails to 0 *open* Fails** — but honestly. The naïve "flip all
three to Pass" is a **self-refuting over-claim**: it would contradict the project's own ratified ADRs
(both Accepted this week):

- **[ADR 0018](../adr/0018-per-message-signatures-accepted-risk.md):47** — *"ASVS 4.1.5 remains a Fail …
  not re-scored to Pass"* (no build authorized).
- **[ADR 0019](../adr/0019-pluggable-keyprovider-hsm-kms-vault.md):237** — on-prem `auto` key_provider
  *"stays a Fail (accepted residual)"*.

So the **only legitimate path to 0 open Fails is to *re-open* those ADRs with genuine justification AND
ship real capability in every lane** — not a relabel. Each flip pairs a built control with the
amendment.

| Scope | Now | After Option A |
|---|---|---|
| L1 + L2 | 146 / 18 / 0 / 89 | **146 / 18 / 0 / 89** (unchanged — all 3 Fails are L3-only) |
| L3-only | 43 / 2 / 3 / 44 | **46 / 2 / 0 / 44** |
| **Combined** | **189 / 20 / 3 / 133** | **192 / 20 / 0 / 133** |

Per-chapter L3-only deltas: **V4** (4.1.5), **V12** (12.1.4), **V13** (13.3.3) each `+1 Pass / −1 Fail`.

> **Honesty rule (load-bearing).** The headline is **"0 *open* Fails — every control is built or
> documented-residual,"** NOT "fully remediated." Each flip keeps an explicit residual line. **4.1.5 is
> the weakest** (opt-in, default-off signing) — Pass-with-documented-residual is defensible *only*
> because a real capability ships; a strict auditor could still argue Partial. If a lane cannot ship a
> real control, its Fail **stays** rather than being relabeled.

---

## 1. Pre-gate (owner-driven, BEFORE any lane worktree is created)

Branch triage (8 branches) found the "collision" risk is almost entirely **already-merged/superseded
local refs** carrying stale tallies. The gate is short:

| # | Branch / PR | Action | Why |
|---|---|---|---|
| 1 | **#369** `docs/asvs-score-reconcile` | **merge** | The `189/20/3/133` baseline the whole plan assumes |
| 2 | **#366** `docs/licensing-accepted-risk` (OPEN) | **rebase → merge** | Only open PR with value; touches just `BACKLOG.md §13`, **zero ASVS score docs** — land it to clear the lone owned-file collision |
| 3 | `docs/adr-0019-keyprovider-seam` (#334 ✅) | **delete ref** | ADR 0019 already byte-identical on `main` |
| 4 | `security/asvs-l3c-tls-kex-min-doc` (#308 ✅) | **delete ref** | KEX code already on `main`; carries stale `177/21/6/141` |
| 5 | `docs/asvs-l3b-verdict-reconcile` (#305 ✅) | **delete ref** | Superseded; stale `175/23/6/141` |
| 6 | `l3-status-memo` (#326 ✅) | **delete ref** | Superseded; stale `178/20/6/141` |
| 7 | `security/beyond-asvs-l3` (#333 ✅) | **delete ref** (local + remote) | ADR 0018 + BEYOND docs already on `main` |
| 8 | `asvs-l3-phase-a` (#276 ✅) | **delete ref** (local + remote) | 78 behind, zero unique content |

`docs-mfa-org-framing` (#325 CLOSED) is **not** in the gate — its 6-line MFA-as-org-mandated prose folds
into the **Coordinator's** `ASVS-L3-REMEDIATION-PLAN.md` pass.

**Notes / blockers.** Deleting refs (esp. the remote ones, #333/#276) and merging #366 are
owner/cross-session actions — recommended here, executed by the owner. Confirm at gate time that **no
other in-flight branch lands `messagefoundry/store/keyprovider.py`** first (verified absent on `main`
today, so Lane B builds it fresh).

---

## 2. The lanes

All three lanes ship a real control, then amend their ADR. **No build lane edits a score doc** (those
are Coordinator-owned). File ownership is fully disjoint.

### Lane A — 12.1.4 TLS certificate revocation *(strongest flip)*
- **Worktree/branch:** `asvs-1214-tls-revocation` (slash-free; the `new.ps1` ValidatePattern rejects `/`).
- **Build:** add `harden_verify_flags(ctx)` to `config/tls_policy.py` ORing `ssl.VERIFY_X509_STRICT`,
  guarded for old interpreters exactly like the existing `harden_kex_groups`; export in `__all__`; call
  it right after `harden_kex_groups` in `api/tls.py` `build_api_ssl_context` and `mllp.py`
  `_mllp_ssl_context` **server branch (before its early return)**; **guard/skip on the MLLP
  `CERT_NONE`/`tls_verify=false` outbound path**. Test asserts the flag is present (not raw byte-equality).
- **ADR:** in `docs/adr/0002-…` ADD a **new** `### Certificate revocation (12.1.4)` subsection
  (delegate revocation to org PKI / OCSP-must-staple at the WP-15 proxy + OS trust store; engine
  attempts no stdlib OCSP). **Do not touch** the existing cert-expiry/mTLS "To resolve on acceptance"
  item.
- **Owns:** `config/tls_policy.py`, `api/tls.py`, `transports/mllp.py`, `docs/adr/0002-*`,
  `tests/test_tls_policy.py`.
- **Verdict intent (for PR description):** 12.1.4 Fail → **Pass-with-documented-residual** (revocation
  delegated; `VERIFY_X509_STRICT` is adjacent chain-strictness hardening, **not** revocation itself).

### Lane B — 13.3.3 KeyProvider seam *(build fresh; amend verdict only)*
- **Worktree/branch:** `asvs-1333-keyprovider`.
- **Build:** CREATE `messagefoundry/store/keyprovider.py` per the **existing** ADR 0019 design (a
  `KeyProvider` interface + `auto`/`env`/`dpapi` providers, default `auto` == today's
  `resolve_active_key` ladder byte-identical, with lazy `aws_kms`/`azure_kv`/`vault` hooks). Route store
  key-sourcing (`resolve_active_key`/`open_store`, `store/crypto.py`) through it. Add
  `[store].key_provider` knob (default `auto`) to `config/settings.py`. SPDX header on new `.py`.
- **ADR:** **AMEND** `docs/adr/0019-…` §13.3.3 verdict mapping from *"stays a Fail"* to
  **Pass-with-documented-residual**, justified by the built isolation seam + operator-activated external
  module (mirrors TLS/16.4.3 delegated activation). Reconcile the stale `178/20/6/141` tally inside the
  ADR **in the same PR**. **Do NOT re-author or redesign** the seam — the design is already landed.
- **Owns:** `store/keyprovider.py` (new), `store/crypto.py`, `store/base.py` (routing site — `resolve_active_key`/`open_store`), `secrets_dpapi.py`,
  `config/settings.py` (`[store]` only), `docs/adr/0019-*`, `tests/test_keyprovider.py`.
- **Verdict intent:** 13.3.3 Fail → **Pass-with-documented-residual**. **Residual:** the unwrapped DEK
  still lives in process heap during use (11.7.1 / WP-BL3-28, separately deferred).

### Lane C — 4.1.5 per-message signatures *(weakest — the build must be real)*
- **Worktree/branch:** `asvs-415-msg-signing`.
- **Build:** an **opt-in per-connection signing surface** on the REST/SOAP outbound destinations —
  a detached-JWS / signature header over the canonical outbound payload, minted in the connector
  `send()` boundary (`pipeline/wiring_runner.py` ~1256), using the already-core `cryptography`
  (RSA/ECDSA — no new dep), plus a verify option. **Off by default;** a per-connection `sign` field in
  `config/models.py` (**not** `config/settings.py`). SPDX on new files.
- **ADR:** **AMEND** `docs/adr/0018-…` from accepted-risk-Fail to **Pass-with-documented-residual** on
  the shipped opt-in capability (activated per partner contract); Status → Amended 2026-06-18 with the
  new decision/consequence.
- **Owns:** `transports/rest.py`, `transports/soap.py`, `pipeline/wiring_runner.py`, `config/models.py`,
  `docs/adr/0018-*`, `tests/test_*signing*`.
- **Verdict intent:** 4.1.5 Fail → **Pass-with-documented-residual**. **Residual:** not enforced on the
  default loopback path; opt-in only. *This is the flip most exposed to reviewer pushback — the build is
  what keeps it from being a hollow relabel.*

### Coordinator — single-writer score-doc sweep *(runs AFTER A+B+C merge)*
- Fresh branch off post-lane `main`. **Pre-flight:** confirm `tls_policy.harden_verify_flags` exists,
  `store/keyprovider.py` exists, and ADR 0018/0019 are amended; if any absent, **STOP**.
- Flip the **three verdict cells** (token + rewrite each rationale to the built-capability narrative,
  cite the amended ADR), recompute to **192/20/0/133** (L3-only 46/2/0/44; V4/V12/V13 each +1 Pass/−1
  Fail; L1+L2 untouched), reframe the headline to **"0 open Fails — all controls built or
  documented-residual,"** reconcile the FAILS-PLAN *"an accepted Fail is still a Fail"* note (now 0
  Fails, with residuals), and fold in the `docs-mfa-org-framing` MFA prose.
- **Edit by anchor** (req-id `| 12.1.4 |`, the `Totals`/`Combined` strings, headings), bottom-up; end
  with a `Pass+Partial+Fail+N/A == total` consistency assertion per scorecard.
- **Owns:** `ASVS-L3-ASSESSMENT.md`, `ASVS-L3-STATUS.md`, `ASVS-L3-REMEDIATION-PLAN.md`,
  `ASVS-FAILS-REMEDIATION-PLAN.md`, the 4 `BEYOND-ASVS-L3*` files, `FEATURE-MAP.md`, `BACKLOG.md`,
  `SECURITY.md`, `PHI.md`.

---

## 3. Contention matrix (every owner is exactly one lane)

| File / area | Owner | Note |
|---|---|---|
| `config/tls_policy.py`, `api/tls.py`, `transports/mllp.py`, ADR 0002 | Lane A | KEX-pinning (#308) already on `main`; build forward |
| `store/keyprovider.py`, `store/crypto.py`, `store/base.py` (routing site — `resolve_active_key`/`open_store`), `secrets_dpapi.py`, `config/settings.py` `[store]`, ADR 0019 | Lane B | settings.py is **Lane B only** |
| `transports/rest.py`, `transports/soap.py`, `pipeline/wiring_runner.py`, `config/models.py`, ADR 0018 | Lane C | models.py is **Lane C only** |
| All ASVS score docs (§2 list) | Coordinator | **No build lane edits these** — each records its verdict-flip intent in its PR description |

No file is owned by two lanes. ADRs are disjoint (A=0002, B=0019, C=0018); `docs/adr/README.md` is
untouched (these are amendments, not new ADRs).

---

## 4. Window prompts (paste one per fresh ultracode window)

> Spawn Lanes A/B/C concurrently after the pre-gate clears. Run the Coordinator last.

**Lane A**
```
ultracode. Create a worktree: scripts/worktree/new.ps1 -Name asvs-1214-tls-revocation -Base origin/main
(origin/main must include merged #369). Branch: asvs-1214-tls-revocation.
GOAL — ASVS 12.1.4 (TLS cert revocation), honest Pass-with-documented-residual:
1. docs/adr/0002-...: ADD a NEW "### Certificate revocation (12.1.4)" subsection (delegate revocation to org
   PKI / OCSP-must-staple at the WP-15 proxy + OS trust store; engine attempts no stdlib OCSP). DO NOT edit the
   existing cert-expiry/mTLS "To resolve on acceptance" item.
2. messagefoundry/config/tls_policy.py: add harden_verify_flags(ctx) ORing ssl.VERIFY_X509_STRICT, guarded for
   old interpreters like the existing harden_kex_groups; add to __all__; call right after harden_kex_groups in
   api/tls.py build_api_ssl_context and mllp.py _mllp_ssl_context server branch (BEFORE its early return);
   GUARD/skip on the MLLP CERT_NONE (tls_verify=false) outbound path. Test asserts the flag is set.
FILES YOU OWN: config/tls_policy.py, api/tls.py, transports/mllp.py, docs/adr/0002-*, tests/test_tls_policy.py.
DO NOT EDIT: any docs/security/ASVS-* file, FEATURE-MAP.md, BACKLOG.md, SECURITY.md, PHI.md, config/settings.py,
store/*, transports/rest.py, soap.py, ADR 0018/0019. Gate: ruff check + ruff format --check -> mypy strict ->
pytest -q (QT_QPA_PLATFORM=offscreen). New behavior ships a test. Open a PR; state intended flip
"12.1.4 Fail -> Pass-with-documented-residual" for the Coordinator. Report back.
```

**Lane B**
```
ultracode. Create a worktree: scripts/worktree/new.ps1 -Name asvs-1333-keyprovider -Base origin/main. Branch: asvs-1333-keyprovider.
GOAL — ASVS 13.3.3. The KeyProvider DESIGN is already in docs/adr/0019-... on main — DO NOT re-author/redesign it.
1. CREATE messagefoundry/store/keyprovider.py per the EXISTING ADR 0019 design: KeyProvider interface +
   auto/env/dpapi providers (default 'auto' == today's resolve_active_key ladder, byte-identical) + lazy
   aws_kms/azure_kv/vault hooks. Route store key-sourcing (resolve_active_key/open_store, store/crypto.py) through
   it. Add [store].key_provider (default 'auto') to config/settings.py. SPDX header on new .py.
2. AMEND docs/adr/0019-...: re-open §13.3.3 from "stays a Fail" to "Pass-with-documented-residual" justified by the
   built isolation seam + operator-activated external module (mirrors TLS/16.4.3 delegated activation); residual =
   DEK in heap during use (11.7.1). Reconcile the stale 178/20/6/141 tally in THIS PR.
FILES YOU OWN: store/keyprovider.py (new), store/crypto.py, store/store.py, secrets_dpapi.py, config/settings.py
([store] only), docs/adr/0019-*, tests/test_keyprovider.py. DO NOT EDIT: any score doc, config/tls_policy.py,
api/tls.py, mllp.py, transports/rest.py, soap.py, ADR 0002/0018, config/models.py. Same gate + SPDX. Open a PR;
state intended flip "13.3.3 Fail -> Pass-with-documented-residual (built seam)" for the Coordinator. Report back.
```

**Lane C** (the weak one — must ship a real control)
```
ultracode. Create a worktree: scripts/worktree/new.ps1 -Name asvs-415-msg-signing -Base origin/main. Branch: asvs-415-msg-signing.
GOAL — ASVS 4.1.5. ADR 0018 currently ratifies this an accepted-risk Fail. To flip it HONESTLY, ship a real
(minimal) capability, then amend the ADR:
1. Opt-in per-connection signing on REST/SOAP outbound: a detached-JWS / signature header over the canonical
   outbound payload, minted in the connector send() boundary (pipeline/wiring_runner.py ~1256), using core
   `cryptography` (RSA/ECDSA — no new dep), plus a verify option. Off by default; per-connection sign field in
   config/models.py (NOT config/settings.py). SPDX on new files.
2. AMEND docs/adr/0018-...: re-open from accepted-risk-Fail to "Pass-with-documented-residual" on the shipped
   opt-in capability (activated per partner contract); residual = not enforced on the default loopback path.
   Status -> Amended 2026-06-18.
FILES YOU OWN: transports/rest.py, transports/soap.py, pipeline/wiring_runner.py, config/models.py,
docs/adr/0018-*, tests/test_*signing*. DO NOT EDIT: any score doc, config/settings.py, config/tls_policy.py,
store/*, ADR 0002/0019. Same gate + SPDX. NOTE: weakest flip — the build must be real, not a stub. Open a PR;
state intended flip "4.1.5 Fail -> Pass-with-documented-residual (opt-in signing shipped)". Report back.
```

**Coordinator** (run last, after A+B+C merge)
```
ultracode. Fresh branch off origin/main (must contain merged Lane A/B/C). Single-writer score-doc sweep.
PRE-FLIGHT: confirm tls_policy.harden_verify_flags exists, store/keyprovider.py exists, ADR 0019 §13.3.3 + ADR
0018 are amended to Pass-with-residual; if any absent, STOP.
Edit ONLY the score docs (ASSESSMENT, STATUS, ASVS-L3-REMEDIATION-PLAN, ASVS-FAILS-REMEDIATION-PLAN, the 4
BEYOND-ASVS-L3*, FEATURE-MAP, BACKLOG, SECURITY.md, PHI.md). For 4.1.5/12.1.4/13.3.3: rewrite each verdict CELL
(token + rationale -> built-capability narrative, cite the amended ADR), then recompute: L3-only 43/2/3/44 ->
46/2/0/44; combined 189/20/3/133 -> 192/20/0/133; L1+L2 146/18/0/89 UNCHANGED; per-chapter L3-only V4/V12/V13 each
+1 Pass -1 Fail. Reframe the headline "0 OPEN Fails — all controls built or documented-residual" (NOT "fully
remediated"); keep an honest residual line per fail. Reconcile the FAILS-PLAN "an accepted Fail is still a Fail"
note. Fold the docs-mfa-org-framing MFA-as-org-mandated prose into ASVS-L3-REMEDIATION-PLAN.md. Edit by anchor
(req-id / "Totals" / headings), bottom-up; end with a Pass+Partial+Fail+N/A == total assertion per scorecard.
Open a PR.
```

---

## 5. Residual risks (carry these honestly into the score docs)

- **4.1.5 is the weak link** — even with the opt-in signing build it is default-off and unenforced on the
  loopback path; a strict auditor could argue **Partial**. The build is what prevents a hollow relabel.
- **13.3.3** — Pass rests on the seam + operator-activated external module; the **DEK still lives in heap
  during use** (11.7.1). Must stay in the residual wording.
- **12.1.4** — `VERIFY_X509_STRICT` is chain-strictness, **not revocation**; revocation is genuinely
  delegated to org PKI / OCSP-must-staple. The cell must say so.
- The **"0 open Fails" headline must read as managed-to-residual, not fully-remediated**, or the
  self-assessment loses credibility.
- Pre-existing stale tallies in **non-cited** docs (`Secure_Development_Standards.md`,
  `SDS-CONFORMANCE-REVIEW-2026-06-12.md`, etc.) are **out of scope** for this pass — separate cleanup
  ticket.

---

## 6. Coordination rules

- **Worktree isolation is mandatory — one window = one worktree.** Each window's **first action** is
  `scripts/worktree/new.ps1 -Name <lane> -Base origin/main` (it fetches, then creates an isolated
  checkout + branch + `.venv`). A window **never** edits the shared main checkout or a sibling worktree.
  Before touching any file, the window **verifies it is isolated and on the right base**, and STOPs if
  any check fails:
  ```
  git rev-parse --show-toplevel    # must be the NEW worktree path, NOT C:/Users/Scott/Code/MessageFoundry
  git rev-parse --abbrev-ref HEAD  # must be the lane branch (asvs-1214-tls-revocation, …)
  git merge-base --is-ancestor origin/main HEAD && echo BASE_OK   # base includes merged #369
  ```
  The **pre-gate** (merge/rebase/delete) runs in the **owner's window / main checkout**, never a lane
  worktree. The **Coordinator** also gets its own worktree (`scripts/worktree/new.ps1 -Name asvs-coord
  -Base origin/main`), run last — it does **not** reuse this plan-doc branch. Clean up with
  `scripts/worktree/remove.ps1` after each PR merges. Concurrent `new.ps1` invocations are safe (distinct
  `-Name` → distinct worktrees; git locks the worktree metadata).
- **Score docs are Coordinator-owned, single-writer.** No build lane edits them; each lane records its
  verdict-flip intent in its PR description.
- **Branch model:** lanes are cut from `origin/main` **after** #369 + #366 land and the stale refs are
  deleted; each lane asserts `git merge-base --is-ancestor origin/main HEAD` rather than eyeballing a tally.
- **One ADR per lane** (A=0002 add-subsection, B=0019 amend-verdict, C=0018 amend); never edit another
  lane's ADR. Lane B/C amendments must leave the ADR internally consistent (no leftover "stays a Fail").
- **Per-PR gate (every lane):** `ruff check` + `ruff format --check` → `mypy` strict → `pytest -q`
  (`QT_QPA_PLATFORM=offscreen` for console). New behavior ships a test. SPDX header on any new `.py`.
- **Cited artifacts must be internally consistent** — Lane B reconciles ADR 0019's in-body tally in the
  same PR that flips its verdict mapping.
- Use **this worktree's `.venv`**, not a sibling's.

---

## 7. Sequencing

```
PRE-GATE (owner):   merge #369  ->  rebase+merge #366 (zero ASVS-doc touch)  ->  delete 6 stale refs
                                          │
NOW (parallel):     Lane A ─┐  Lane B ─┐  Lane C ─┐     (3 ultracode windows, disjoint files)
                            └──────────┴──────────┴──> all 3 PRs merge
                                          │
LAST (coordinator): score-doc sweep -> 192/20/0/133  (this window)
```
