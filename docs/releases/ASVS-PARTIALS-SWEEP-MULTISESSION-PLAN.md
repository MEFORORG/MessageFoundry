# MessageFoundry — ASVS "20 Partials → Pass" Multisession Plan

> **Provenance.** Generated 2026-06-18 as a coordinator artifact. The 20 open ASVS 5.0 L3 Partials
> were each assessed against the live code by a 40-agent assess+verify workflow (one assessor + one
> adversarial verifier per requirement); the verdicts, file-locality, and contention were grounded in
> that pass. This is the **successor** to [`ASVS-OPTION-A-MULTISESSION-PLAN.md`](ASVS-OPTION-A-MULTISESSION-PLAN.md)
> (which closed the 3 Fails): same single-writer score-doc discipline, same worktree-per-window rule
> ([`../WORKTREES.md`](../WORKTREES.md)). Update as items land.

---

## 0. Objective — and the honest caveat

Take the **20 open combined ASVS L3 Partials toward 0** — honestly. Most are upgradeable, but the
verification pass found two distinct realities, and the headline must reflect both:

- **Stale-doc / already-built (≈11):** the scorecard row describes a control as missing when the code
  already ships it; *two rows literally contradict the same document.* These are documentation bugs —
  a doc flip is the *correct* fix regardless of scoring philosophy.
- **Genuine-but-bounded gaps (≈9):** a real (if small or off-loopback) gap. To flip these *honestly* a
  lane must **ship a real control**, then the verdict becomes **Pass-with-documented-residual** — never
  a relabel. Two of these (**5.4.3** remote-file AV, **13.3.2** least-privilege default) the verifier
  explicitly ruled "stays Partial *unless* code ships," so their lanes carry the build.

> **Honesty rule (load-bearing, inherited from OPTION-A).** The headline is **"0 open Partials — every
> control is built or documented-residual,"** NOT "fully remediated." Each conditional flip keeps an
> explicit residual line. The residual-heaviest — **15.2.5** (no hard sandbox), **13.3.1 / 13.2.1**
> (connector secrets), **16.3.4** (handshake audit) — are the ones a strict auditor could still argue
> Partial; the build/seam in their lane is what keeps the flip from being hollow. If a lane cannot ship
> a real control, its Partial **stays**.

### Baseline and target

The baseline assumes the **OPTION-A coordinator (b9332b9) has landed on `main`** (see Pre-gate). Lanes
touch only code, so they do **not** depend on it; only this plan's Coordinator does.

| Scope | Now (post-OPTION-A) | After this sweep (full bar) | Conservative (residual-heavy kept Partial) |
|---|---|---|---|
| L1 + L2 | 146 / 18 / 0 / 89 | **164 / 0 / 0 / 89** | 159 / 5 / 0 / 89 |
| L3-only | 46 / 2 / 0 / 44 | **48 / 0 / 0 / 44** | 48 / 0 / 0 / 44 |
| **Combined** | **192 / 20 / 0 / 133** | **212 / 0 / 0 / 133** | 207 / 5 / 0 / 133 |

> Arithmetic check (full bar): 164+48 = 212 Pass; 0 Partial; 0 Fail; 89+44 = 133 N/A; 212+133 = **345**. ✓
> The "conservative" column keeps 15.2.5 / 16.3.4 / 13.2.1 / 13.3.1 / 13.3.2 as documented Partials — an
> **owner policy choice** (adopt the same conditional-Pass bar already ratified for the 3 Fails, or not).

### Decisions (locked 2026-06-18)

1. **Pre-gate = land OPTION-A's coordinator (b9332b9) to `main` first** (not "Coordinator absorbs the 3
   Fails"). Keeps the owner-ratified ADR/verdict wording intact and avoids two coordinators rewriting the
   same three score files.
2. **Target = the full conditional-Pass bar → 212/0/0/133** (every Partial addressed), **subject to the
   honesty rule**: each conditional flip carries an explicit residual line, and the residual-heaviest
   (15.2.5 sandbox, 16.3.4 handshake audit, 13.2.1 / 13.3.1 connector secrets) stay flagged as the weak
   links — the build/seam in their lane is what keeps the flip honest. If a lane cannot ship a real
   control, its Partial stays rather than being relabeled.

---

## 1. Pre-gate (owner-driven, BEFORE this plan's Coordinator runs)

| # | Action | Why |
|---|---|---|
| 1 | **Land the OPTION-A coordinator PR (`docs/asvs-sweep-0-fails` @ b9332b9) to `main`** | Establishes the **192/20/0/133** baseline (3 Fails closed). Until then `main` reads 189/20/3/133 and this plan's tally is off by the 3 Fails. **This is the only hard pre-gate for the Coordinator.** |
| 2 | Verify `origin/main` contains the 3 controls' code (#376 `harden_verify_flags`, #377 `store/keyprovider.py`, #378 detached-JWS) | Lanes branch off `origin/main`; the code is already merged, so lanes can start immediately. |
| 3 | Confirm no sibling worktree is mid-edit on any **score doc** or on a file this plan assigns to a lane | Score docs are the cross-session contention hot-spot; coordinate per [`../WORKTREES.md`](../WORKTREES.md). |

**Branch-fork note.** This worktree was found on `chore/keyprovider-followup` (@ e7c4c83), and b9332b9 is
on a **divergent** branch (common base `9c00b88`). Do **not** merge b9332b9's *docs* into a lane — this
plan's Coordinator is the single writer of all score docs and supersedes any partial reconcile. Just get
b9332b9 onto `main` (item 1) so the Coordinator builds on 192/20/0/133.

**Lanes can start now** (items 1 is not a blocker for them). Run the Coordinator only after item 1 **and**
all six lane PRs merge.

---

## 2. The lanes

Six build lanes, **fully disjoint file ownership**. **No build lane edits a score doc** (Coordinator-owned).
Each lane ships code + a test, updates only its *local* doc (its ADR / `CONNECTIONS.md` / `SERVICE.md`),
and records its verdict-flip intent in its PR description for the Coordinator.

### Lane 1 — 5.4.3 remote-file content-sniff + AV scan-hook *(Tier-D: real gap)*
- **Worktree/branch:** `asvs-543-file-ingest-av`.
- **Build:** `RemoteFileSource` (SFTP/FTP/FTPS) currently hands raw bytes straight to the handler
  ([`transports/remotefile.py:613`](../../messagefoundry/transports/remotefile.py#L613)) with **no
  content-sniff and no AV** — unlike local `FileSource`. (a) Apply the same `_looks_like_hl7` content
  sniff to the remote path; (b) add an **off-by-default pre-ingest scan-hook seam** (an optional callable
  invoked on raw bytes before emit, default no-op) shared by both `FileSource` and `RemoteFileSource`,
  mirroring the KeyProvider-seam pattern; (c) document the AV/ICAP-gateway delegation for less-trusted
  sources in `CONNECTIONS.md`. Test: assert RemoteFileSource quarantines a non-conformant payload and
  that the scan-hook is invoked.
- **Owns:** `transports/remotefile.py`, `transports/file.py` (extract the shared sniff/seam),
  `docs/CONNECTIONS.md`, `tests/test_*file*`.
- **Verdict intent:** 5.4.3 Partial → **Pass (conditional)** — content-sniff + scan-hook seam built; AV
  delegated to operator/ICAP gateway for less-trusted sources.

### Lane 2 — 6.5.1 single-use TOTP *(Tier-B)*
- **Worktree/branch:** `asvs-651-totp-singleuse`.
- **Build:** TOTP codes are replayable inside their ~30 s step window (recovery codes are already
  single-use). Add a per-user `last_totp_step` column to the users schema in **all three backends**
  ([`store/store.py`](../../messagefoundry/store/store.py), `store/postgres.py`, `store/sqlserver.py`)
  with a `_lock`-guarded compare-and-set accessor mirroring `consume_recovery_code_hash`; have
  `verify_totp` return the matched step; in `_verify_second_factor` reject `matched_step <= last_totp_step`
  and advance it atomically. Test: a second verify of the same code fails.
- **Owns:** `auth/totp.py`, `auth/service.py`, `store/store.py`, `store/postgres.py`, `store/sqlserver.py`,
  `tests/test_totp.py`, `tests/test_mfa.py`.  **(Sole owner of `store/*.py`.)**
- **Verdict intent:** 6.5.1 Partial → **Pass** (clean — TOTP now single-use within its step).

### Lane 3 — 15.3.7 HPP + 4.2.1 framing tests *(Tier-B / Tier-C)*
- **Worktree/branch:** `asvs-api-input-hpp`.
- **Build:** (a) **15.3.7** — every query param is already a validated scalar; add a regression test
  sending duplicate scalar params to a representative route (`?limit=1&limit=999` → bounded → 422;
  `?scope=top&scope=evil` → regex 422); add `Query(max_length=…)` to the two uncapped `/dead-letters`
  params (`channel_id`, `destination_name`) for parity with `/messages`. (b) **4.2.1** — add a
  `Content-Length`+`Transfer-Encoding`-together rejection assertion (the chunked-without-CL→411 test
  already exists). No proxy code — the multi-parser residual is delegated (see Coordinator).
- **Owns:** `api/app.py` (query-param signatures only), `tests/test_api*.py`.  **(Sole owner of `api/app.py`.)**
- **Verdict intent:** 15.3.7 Partial → **Pass**; 4.2.1 Partial → **Pass (conditional)** — single h11 parser
  on the loopback bind; multi-parser framing delegated to the front proxy (sibling 4.1.3 already Pass).

### Lane 4 — 12.3.5 console mTLS client cert *(Tier-C)*
- **Worktree/branch:** `asvs-1235-console-mtls`.
- **Build:** API mTLS (`CERT_REQUIRED`) is already built+tested; the console just never presents a client
  cert (`httpx.Client` built with no `cert=`, [`console/client.py:139`](../../messagefoundry/console/client.py#L139)).
  Add a `[console].tls_client_cert` / `tls_client_key` pair to `config/settings.py` (note: `settings.py:285`
  already reserves `tls_client_ca_file` "mTLS for the console; opt-in, future") and pass
  `cert=(certfile, keyfile)` to `httpx.Client`; thread it from the CLI ctor. Test asserts the cert is sent.
- **Owns:** `console/client.py`, `console/__main__.py`, `config/settings.py` (**sole settings.py owner**),
  `docs/adr/0002-*` (add a short console-mTLS note only), `tests/test_console*.py`.
- **Verdict intent:** 12.3.5 Partial → **Pass (conditional)** — API mTLS built + console can present a
  client cert; PKI/off-loopback identity delegated to org PKI; immaterial on the loopback bind.

### Lane 5 — 12.2.1 https-only webhook *(Tier-B)*
- **Worktree/branch:** `asvs-1221-webhook-https`.
- **Build:** `WebhookTransport._post` accepts `("http","https")`
  ([`pipeline/alert_sinks.py:166`](../../messagefoundry/pipeline/alert_sinks.py#L166)). Tighten to
  **https-only unless `settings.insecure_tls_allowed()`** (the existing `MEFOR_ALLOW_INSECURE_TLS` escape —
  *read-only* import, **do not edit `settings.py`**). Add a test that `http://` is rejected by default and
  permitted with the escape; existing alert-sink tests already use `https://` so they stay green. Honesty
  note for the PR: this is *stricter* than the credentialed-only `http` refusal in REST/SOAP — frame the
  residual as "cleartext-metadata, immaterial on loopback," not "exact 12.3.2 parity."
- **Owns:** `pipeline/alert_sinks.py`, `tests/test_alert_sinks.py`, `tests/test_asvs_phase0.py`.
- **Verdict intent:** 12.2.1 Partial → **Pass** (no insecure HTTP fallback for the webhook sink).

### Lane 6 — 13.2.2 / 13.3.2 / 13.3.1 least-privilege + connector secrets *(Tier-D + Tier-C)*
- **Worktree/branch:** `asvs-13-leastpriv-secrets`.
- **Build (two disjoint parts, both in this lane):**
  - **Install least-privilege (13.2.2 / 13.3.2):** make the least-privilege **virtual service account**
    the *first-class* path — keep `LocalSystem` only as an explicit `-AllowLocalSystem` opt-out, ensure the
    auto-applied config/data ACLs (`Set-ConfigReadAcl` / `Set-SecureDataDirAcl`) cover the repo/venv so a
    virtual account doesn't break installs, and extend the `windows-service-smoke` CI leg to run *with*
    `-ServiceAccount "NT SERVICE\MessageFoundry"` and assert the ACL grants. (CI-validated — can't fully
    run locally; gate via the Windows CI leg per CLAUDE.md.)
  - **Connector-secret seam (13.3.1):** generalize the env-only AD/SQL/SMTP credential path
    ([`config/environments.py`](../../messagefoundry/config/environments.py)) with a small **SecretProvider**
    resolver hook (the `MEFOR_VALUE_*` path → optional external lookup), mirroring the store-key KeyProvider
    seam; default = today's env behavior, byte-identical. Document the deploying-org vault delegation in
    `SERVICE.md`.
- **Owns:** `scripts/service/install-service.ps1`, `.github/workflows/ci.yml`, `docs/SERVICE.md`,
  `config/environments.py`, a new `config/secretprovider.py` (SPDX header), `docs/adr/0019-*` *(append a
  SecretProvider §; do not touch the KeyProvider verdict)*, `tests/test_environments*.py` / `tests/test_secretprovider.py`.
- **Verdict intent:** 13.2.2 → **Pass (conditional)** (least-priv account first-class, CI-proven; residual:
  operator may still choose LocalSystem); 13.3.2 → **Pass (conditional)** (ACL-locked secret assets + DPAPI
  key; residual: env-readable connector creds delegated to vault); 13.3.1 → **Pass (conditional)** (store-key
  KeyProvider + connector SecretProvider seams; external vault lifecycle operator-activated).

---

## 3. Contention matrix (every owner is exactly one lane)

| File / area | Owner | Note |
|---|---|---|
| `transports/remotefile.py`, `transports/file.py`, `docs/CONNECTIONS.md` | Lane 1 | rest.py/soap.py untouched (OPTION-A, merged) |
| `auth/totp.py`, `auth/service.py`, **all `store/*.py`** | Lane 2 | **sole `store/` owner** (TOTP schema add) |
| `api/app.py`, `tests/test_api*` | Lane 3 | **sole `api/app.py` owner** |
| `console/*`, **`config/settings.py`**, ADR 0002 (console note) | Lane 4 | **sole `settings.py` owner** |
| `pipeline/alert_sinks.py` | Lane 5 | reads `settings.insecure_tls_allowed()` (no edit) |
| `scripts/service/*`, `ci.yml`, `SERVICE.md`, `config/environments.py`, `config/secretprovider.py` (new), ADR 0019 (SecretProvider §) | Lane 6 | does **not** touch `store/keyprovider.py` (store DEK ≠ connector creds) |
| **All ASVS score docs + `SECURITY.md` + `PHI.md`** | Coordinator | **no build lane edits these** |

No file is owned by two lanes. `settings.py` = Lane 4 only; `store/*.py` = Lane 2 only; `api/app.py` =
Lane 3 only; ADR 0002 = Lane 4, ADR 0019 = Lane 6 (disjoint). `CONNECTIONS.md` = Lane 1, `SERVICE.md` =
Lane 6 (disjoint). Cross-cutting security docs stay Coordinator-only.

---

## 4. Coordinator — single-writer score-doc sweep *(runs AFTER all 6 lanes merge AND Pre-gate #1)*

- **Worktree/branch:** `scripts/worktree/new.ps1 -Name asvs-partials-coord -Base origin/main` (off
  post-lane, post-b9332b9 `main`). Does **not** reuse this plan-doc branch.
- **Pre-flight (STOP if any fails):** `main` reads **192/20/0/133** (b9332b9 landed); RemoteFileSource has
  the content-sniff + scan-hook; `last_totp_step` exists in all 3 backends; the HPP test exists; the console
  passes `cert=`; the webhook is https-only; least-priv is CI-proven; the SecretProvider seam exists.
- **Flip all 20 Partial cells** in `ASVS-L3-ASSESSMENT.md` (and reconcile `ASVS-L3-STATUS.md`,
  `ASVS-L3-REMEDIATION-PLAN.md`), each citing the merged code, written as the built-capability narrative
  with an honest residual line where conditional. Specifically:
  - **Stale-doc (cite built code, flip to Pass):** 1.2.2, 6.8.1, 11.3.3, 12.3.3, 12.3.4, 14.2.4, 16.2.3, 16.4.2.
  - **Fix two self-contradictions:** 16.4.2 (the row calls "NSSM log-dir ACLs" a TODO while item 37 records
    them shipped); 12.3.4 (contradicts the already-Pass 12.3.2 on the identical engine→DB control).
  - **Reframe 14.2.4** to the doc-vs-code-consistency test (not encryption-completeness).
  - **Conditional, code-backed (after lanes):** 5.4.3, 6.5.1, 12.2.1, 12.3.5, 15.3.7, 4.2.1, 13.2.2, 13.3.1, 13.3.2.
  - **Conditional, doc-only (owner policy — flip under the ratified conditional-Pass bar, else keep Partial):**
    15.2.5 (encapsulation set + least-priv account now built; hard sandbox/container env-delegated),
    16.3.4 (handshake-failure visibility off-loopback-delegated to the TLS terminator/SIEM — **honest
    rationale: not "already shipped off-box," it isn't logged at INFO today**), 13.2.1 (no-static-cred
    SQL path built; static default delegated).
- Recompute tallies — **full bar → 212/0/0/133** (L1+L2 164/0/0/89; L3-only 48/0/0/44); or the conservative
  207/5/0/133 if the owner keeps 15.2.5/16.3.4/13.2.1/13.3.1/13.3.2 Partial. Reframe the headline
  **"0 open Partials — every control built or documented-residual."**
- **Edit by anchor** (req-id `| 6.8.1 |`, the `Totals`/`Combined` strings, chapter headings), bottom-up;
  end with a `Pass+Partial+Fail+N/A == total` assertion per scorecard.
- **Owns:** `ASVS-L3-ASSESSMENT.md`, `ASVS-L3-STATUS.md`, `ASVS-L3-REMEDIATION-PLAN.md`,
  `ASVS-FAILS-REMEDIATION-PLAN.md`, the 4 `BEYOND-ASVS-L3*` files, `FEATURE-MAP.md`, `BACKLOG.md`,
  `SECURITY.md`, `PHI.md`.

---

## 5. Window prompts (paste one per fresh ultracode window)

> Spawn Lanes 1–6 concurrently (Pre-gate #1 is not a blocker for them). Run the Coordinator last.

**Lane 1 — 5.4.3 remote-file AV**
```
ultracode. First action: scripts/worktree/new.ps1 -Name asvs-543-file-ingest-av -Base origin/main
Verify isolation: git rev-parse --show-toplevel must be the NEW worktree (NOT C:/Users/Scott/Code/MessageFoundry);
git rev-parse --abbrev-ref HEAD must be asvs-543-file-ingest-av; git merge-base --is-ancestor origin/main HEAD.
GOAL — ASVS 5.4.3, honest Pass: RemoteFileSource (transports/remotefile.py:613) hands raw bytes to the handler
with NO content-sniff/AV, unlike local FileSource. (a) apply the same _looks_like_hl7 content sniff to the remote
path; (b) add an off-by-default pre-ingest scan-hook seam (optional callable on raw bytes before emit, default
no-op) shared by FileSource + RemoteFileSource; (c) document the AV/ICAP delegation in docs/CONNECTIONS.md. Test:
RemoteFileSource quarantines a non-conformant payload + the scan-hook fires.
FILES YOU OWN: transports/remotefile.py, transports/file.py, docs/CONNECTIONS.md, tests/test_*file*.
DO NOT EDIT: any docs/security/ASVS-* / SECURITY.md / PHI.md, config/*, store/*, api/*, console/*, other transports.
Gate: ruff check + ruff format --check -> mypy strict -> pytest -q (QT_QPA_PLATFORM=offscreen). SPDX on new .py.
Open a PR; state intended flip "5.4.3 Partial -> Pass (conditional, scan-hook + content-sniff; AV delegated)". Report back.
```

**Lane 2 — 6.5.1 single-use TOTP**
```
ultracode. First action: scripts/worktree/new.ps1 -Name asvs-651-totp-singleuse -Base origin/main  (then verify isolation as above).
GOAL — ASVS 6.5.1: TOTP codes are replayable within their ~30s step (recovery codes already single-use). Add a
per-user last_totp_step column to the users schema in ALL THREE backends (store/store.py, postgres.py, sqlserver.py)
+ a _lock-guarded compare-and-set accessor mirroring consume_recovery_code_hash; verify_totp returns the matched
step; _verify_second_factor (auth/service.py) rejects matched_step <= last_totp_step and advances it atomically.
Test: a second verify of the same code fails.
FILES YOU OWN: auth/totp.py, auth/service.py, store/store.py, store/postgres.py, store/sqlserver.py,
tests/test_totp.py, tests/test_mfa.py.  DO NOT EDIT: any score doc, config/*, api/*, console/*, transports/*, pipeline/*.
Same gate + SPDX. Open a PR; state intended flip "6.5.1 Partial -> Pass (TOTP single-use within step)". Report back.
```

**Lane 3 — 15.3.7 + 4.2.1**
```
ultracode. First action: scripts/worktree/new.ps1 -Name asvs-api-input-hpp -Base origin/main  (then verify isolation).
GOAL — (15.3.7) every query param is already a validated scalar; add a regression test sending duplicate scalar
params to a representative route (?limit=1&limit=999 -> bounded -> 422; ?scope=top&scope=evil -> regex 422), and add
Query(max_length=256) to the two uncapped /dead-letters params (channel_id, destination_name) for parity with
/messages. (4.2.1) add a Content-Length+Transfer-Encoding-together rejection test (chunked-without-CL->411 already
tested). No proxy code.
FILES YOU OWN: api/app.py (query-param signatures only), tests/test_api*.py.
DO NOT EDIT: any score doc, config/*, store/*, console/*, transports/*, pipeline/*, auth/*.
Same gate. Open a PR; state intended flips "15.3.7 Partial -> Pass" and "4.2.1 Partial -> Pass (conditional, proxy-delegated)". Report back.
```

**Lane 4 — 12.3.5 console mTLS**
```
ultracode. First action: scripts/worktree/new.ps1 -Name asvs-1235-console-mtls -Base origin/main  (then verify isolation).
GOAL — ASVS 12.3.5: API mTLS (CERT_REQUIRED) is built+tested; the console never presents a client cert
(console/client.py:139 httpx.Client has no cert=). Add [console].tls_client_cert/_key to config/settings.py
(settings.py:285 already reserves tls_client_ca_file as "future") and pass cert=(certfile,keyfile) to httpx.Client;
thread from the CLI ctor (console/__main__.py). Test asserts the cert is sent. Add a SHORT console-mTLS note to
docs/adr/0002-* only.
FILES YOU OWN: console/client.py, console/__main__.py, config/settings.py, docs/adr/0002-*, tests/test_console*.py.
DO NOT EDIT: any score doc, store/*, api/*, transports/*, pipeline/*, auth/*, ADR 0018/0019.
Same gate (console tests need QT_QPA_PLATFORM=offscreen). Open a PR; state intended flip
"12.3.5 Partial -> Pass (conditional, delegated)". Report back.
```

**Lane 5 — 12.2.1 https-only webhook**
```
ultracode. First action: scripts/worktree/new.ps1 -Name asvs-1221-webhook-https -Base origin/main  (then verify isolation).
GOAL — ASVS 12.2.1: WebhookTransport._post (pipeline/alert_sinks.py:166) accepts ("http","https"). Tighten to
https-only UNLESS settings.insecure_tls_allowed() (existing MEFOR_ALLOW_INSECURE_TLS escape — IMPORT/read only,
DO NOT edit settings.py). Test: http:// rejected by default, permitted with the escape; existing https tests stay green.
FILES YOU OWN: pipeline/alert_sinks.py, tests/test_alert_sinks.py, tests/test_asvs_phase0.py.
DO NOT EDIT: config/settings.py (read-only use is fine), any score doc, store/*, api/*, console/*, transports/*, auth/*.
Same gate. PR note: this is stricter than the credentialed-only http refusal in REST/SOAP; frame residual as
"cleartext-metadata, immaterial on loopback". State intended flip "12.2.1 Partial -> Pass". Report back.
```

**Lane 6 — 13.2.2 / 13.3.2 / 13.3.1 least-privilege + connector secrets**
```
ultracode. First action: scripts/worktree/new.ps1 -Name asvs-13-leastpriv-secrets -Base origin/main  (then verify isolation).
GOAL — two disjoint parts:
(A) Install least-privilege (13.2.2/13.3.2): make the least-privilege virtual service account the FIRST-CLASS install
   path in scripts/service/install-service.ps1 (LocalSystem becomes an explicit -AllowLocalSystem opt-out); ensure the
   auto-applied config/data ACLs cover repo/venv so a virtual account doesn't break installs; extend the
   windows-service-smoke leg in .github/workflows/ci.yml to run WITH -ServiceAccount "NT SERVICE\MessageFoundry" and
   assert the ACL grants. Document in docs/SERVICE.md. (CI-validated; can't fully run locally.)
(B) Connector-secret seam (13.3.1): generalize the env-only AD/SQL/SMTP path (config/environments.py, MEFOR_VALUE_*)
   with a small SecretProvider resolver hook in a NEW config/secretprovider.py (default == today's env behavior,
   byte-identical), mirroring the store-key KeyProvider seam; document the vault delegation in SERVICE.md. Append a
   SecretProvider section to docs/adr/0019-* (do NOT touch the KeyProvider verdict). SPDX on new .py.
FILES YOU OWN: scripts/service/install-service.ps1, .github/workflows/ci.yml, docs/SERVICE.md,
config/environments.py, config/secretprovider.py (new), docs/adr/0019-*, tests/test_environments*.py / tests/test_secretprovider.py.
DO NOT EDIT: any score doc, store/* (incl. store/keyprovider.py), config/settings.py, api/*, console/*, transports/*, pipeline/*, ADR 0002/0018.
Same gate + SPDX. Open a PR; state intended flips "13.2.2/13.3.2/13.3.1 Partial -> Pass (conditional, documented residual)". Report back.
```

**Coordinator** (run last)
```
ultracode. First action: scripts/worktree/new.ps1 -Name asvs-partials-coord -Base origin/main  (off post-lane, post-b9332b9 main).
PRE-FLIGHT (STOP if any fails): main reads 192/20/0/133; RemoteFileSource has content-sniff+scan-hook; last_totp_step
in all 3 backends; HPP test present; console passes cert=; webhook https-only; least-priv CI-proven; SecretProvider seam present.
Edit ONLY the score docs (ASSESSMENT, STATUS, ASVS-L3-REMEDIATION-PLAN, ASVS-FAILS-REMEDIATION-PLAN, the 4
BEYOND-ASVS-L3*, FEATURE-MAP, BACKLOG, SECURITY.md, PHI.md). Flip all 20 Partial cells to the built-capability
narrative citing merged code, each with an honest residual line where conditional. Fix the two self-contradictions
(16.4.2 vs item 37; 12.3.4 vs 12.3.2). Reframe 14.2.4 to doc-vs-code consistency. For the doc-only conditionals
(15.2.5, 16.3.4, 13.2.1) apply the ratified conditional-Pass bar OR, per owner choice, keep them Partial. Recompute:
full bar -> 212/0/0/133 (L1+L2 164/0/0/89; L3-only 48/0/0/44) OR conservative 207/5/0/133. Reframe headline
"0 open Partials - every control built or documented-residual" (NOT "fully remediated"). Edit by anchor, bottom-up;
end with a Pass+Partial+Fail+N/A == total assertion per scorecard. Open a PR.
```

---

## 6. Residual risks (carry these honestly into the score docs)

- **15.2.5** — the encapsulation set + least-priv account (Lane 6) are real, but there is still **no hard
  process sandbox/container**; the flip is Pass-with-residual, not full closure.
- **13.3.1 / 13.2.1** — even with the SecretProvider seam, connector creds default to env; external vault is
  operator-activated. Residual must say so.
- **16.3.4** — handshake-failure auditing is **delegated off-loopback** to the TLS terminator/SIEM; the honest
  rationale is delegation, **not** "already shipped off-box" (it isn't logged at INFO today — verifier-confirmed).
- **12.2.1** — https-only webhook is stricter than the credentialed-only http refusal elsewhere; don't claim 12.3.2 parity.
- **13.2.2 / 13.3.2** — flipping the LocalSystem default risks breaking installs with out-of-tree config/venv;
  the lane must keep installs working (ACLs cover repo/venv) and prove it in CI, or the flip is unsafe.
- The **"0 open Partials" headline must read as managed-to-residual, not fully-remediated.**
- Stale tallies in non-cited docs (`Secure_Development_Standards.md`, `SDS-CONFORMANCE-REVIEW-*`) remain a
  **separate cleanup ticket**, out of scope here.

---

## 7. Sequencing

```
PRE-GATE (owner):   land OPTION-A coordinator (b9332b9) -> main = 192/20/0/133   (gates the Coordinator only)
                                          │
NOW (parallel):     L1 ─┐ L2 ─┐ L3 ─┐ L4 ─┐ L5 ─┐ L6 ─┐   (6 ultracode windows, disjoint files; start immediately)
                        └──────┴──────┴──────┴──────┴──────┴──> all 6 PRs merge
                                          │
LAST (coordinator): single-writer score-doc sweep -> 212/0/0/133 (or 207/5/0/133 conservative)
```

---

## 8. Coordination rules (inherited from OPTION-A / WORKTREES.md)

- **One window = one worktree.** First action is `scripts/worktree/new.ps1 -Name <lane> -Base origin/main`
  (fetches origin/main, creates an isolated checkout + branch + `.venv`). A window **never** edits the shared
  main checkout or a sibling worktree. Before touching any file, verify isolation (toplevel path, branch,
  `git merge-base --is-ancestor origin/main HEAD`) and **STOP** if any check fails. `-Name` rejects slashes.
- **Score docs are Coordinator-owned, single-writer.** No build lane edits them; each lane records its
  verdict-flip intent in its PR description.
- **Per-PR gate (every lane):** `ruff check` + `ruff format --check` → `mypy` strict → `pytest -q`
  (`QT_QPA_PLATFORM=offscreen` for console). New behavior ships a test. SPDX header on any new `.py`.
  Lane 6's CI-only behavior is validated via the `windows-service-smoke` CI leg, not locally.
- **Use this worktree's `.venv`,** not a sibling's. Clean up with `scripts/worktree/remove.ps1` after merge.
- **Shared AI memory is single-writer** — this plan's owner records the lane→worktree map in
  [[multisession-backlog-effort]] once; other sessions read only.
- **Commit this plan doc to `main`** so it is visible in every lane worktree (untracked files don't propagate).
```
