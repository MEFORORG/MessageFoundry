# ADR 0041 — Load-path attestation & code-change attribution

- **Status:** Proposed (2026-06-27) — drafted on the owner's go (insider-code-tampering review). The
  **first slice (D1, the config fingerprint)** is built alongside this ADR on branch
  `config-fingerprint`; D2/D3 are staged (BACKLOG #53, #54).
- **Decision in one line:** on top of [ADR 0036](0036-windows-config-source-trust.md)'s load-time
  *write-access* refusal, add the **attribution + integrity-binding** layer it does not cover — bind
  every reload/startup to a **content fingerprint** of what loaded (D1), require a **second approver**
  for a deploy (D2), and **self-attest the installed engine wheel** at startup (D3) — so an *authorized*
  change is provably tied to a reviewed source and post-install tampering of the engine code is detected.
- **Related:** [ADR 0036](0036-windows-config-source-trust.md) (the load-time NTFS/POSIX write-access
  guard this builds **on top of** — it stops an *unauthorized* writer; this attributes an *authorized*
  change), [ADR 0035](0035-ide-extension-workspace-trust-and-scope.md) (IDE workspace-trust / promote
  scoping — the authoring-tool surface, already hardened), [ADR 0034](0034-static-analysis-triage-policy-accepted-risk-register.md)
  (notes `/config/reload` is gated by `CONFIG_DEPLOY` + step-up + reload-roots allow-list),
  [ADR 0037](0037-multi-process-sharding-l3.md) (the multi-process / cluster `config_version`
  convergence path the fingerprint should eventually surface across — see *To resolve*),
  [ADR 0017](0017-consumer-deployment-model.md) (the non-editable installed wheel D3 **tightens** from
  recommendation to enforced default), [ADR 0018](0018-per-message-signatures-accepted-risk.md) (the
  detached-JWS signing core a future signed manifest would reuse), [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md)
  (`KeyProvider`), [ADR 0010](0010-handler-callable-db-lookup.md) (the one sanctioned non-pure input),
  [ADR 0031](0031-startup-connection-fault-isolation.md) (startup posture this composes with),
  [CLAUDE.md](../../CLAUDE.md) §2 (reliability + count-and-log), §5 (config is untrusted data), §9 (PHI),
  [SECURITY.md](../SECURITY.md) (dual-control `[approvals]`, audit hash-chain + off-box tee), BACKLOG
  #53/#54.

---

## Context

MessageFoundry is **code-first**: `load_config()` executes **every** `*.py` in the config dir in-process
as the engine service account ([wiring.py](../../messagefoundry/config/wiring.py), `_exec_module →
spec.loader.exec_module`) — module-level code runs **before** any `@router`/`@handler` is declared. So
**write access to the load path == code execution as the service account.** This is intrinsic to the
model (equally true of Mirth's Rhino JS); CPython cannot be meaningfully sandboxed against a determined
author. The question is therefore *"how do we make unilateral, unattributable, undetected tampering
hard,"* not *"how do we sandbox the handler."*

**What is already closed (do not re-decide).** A recent security review landed three of the layers:

- **[ADR 0036](0036-windows-config-source-trust.md) (Accepted + built, 2026-06-26)** made
  `_assert_safe_config_source` a **real in-process NTFS-DACL/owner check on Windows** (no longer a no-op)
  with parity to POSIX, plus `install-service.ps1 -LockConfigDir` and the SEC-019 sibling-helper
  shadowing fix. This **shrinks the write set** — an *unauthorized*/low-priv principal can no longer drop
  a `.py` that loads. (This supersedes the "Windows guard is a no-op" gap an earlier draft of this review
  raised — that gap is fixed.)
- **[ADR 0035](0035-ide-extension-workspace-trust-and-scope.md)** hardened the **authoring tool** (VS
  Code workspace-trust gating, machine-scoped promote URLs, fail-closed AI policy).
- **[ADR 0034](0034-static-analysis-triage-policy-accepted-risk-register.md)** records the static-analysis
  triage discipline; it confirms `/config/reload` is gated by `CONFIG_DEPLOY` + step-up + the reload-roots
  allow-list.

**What remains open — the attribution + runtime-integrity gap.** ADR 0036 stops an *unauthorized* write;
it does **not** tie an *authorized* change to a reviewed source, nor detect tampering of the *installed
engine code*. Verified against the current tree:

1. **No binding between reviewed-commit and loaded-bytes.** The `config_reload` audit detail is
   `{dir, inbound_count, outbound_count, dry_run}` ([app.py](../../messagefoundry/api/app.py),
   `record_audit("config_reload", …)`). No content hash, no commit. Two reloads of the same directory
   with **different on-disk code** are indistinguishable; a reviewer cannot prove what ran. This enables
   **attribution-laundering**: a developer (whose job is `code:edit`) commits a benign-looking handler
   diff, and a Deployment operator's reload / a cluster convergence reload / a routine restart detonates
   it — pinning it on the innocent triggerer, with an audit row that looks identical to a clean reload.
2. **`config:deploy` is step-up-gated but NOT in the dual-control `[approvals]` set** (today: bulk
   dead-letter replay + connection purge). One re-authenticated person reloads the entire live graph —
   the broadest-blast-radius runtime action — alone.
3. **No runtime/startup self-attestation of the installed engine.** ADR 0036 guards the **config dir**;
   nothing checks that the installed `messagefoundry` **site-packages** still match the signed/attested
   wheel. An admin with venv-write + restart rights edits engine code in place (e.g. neuter
   `field_authz` redaction or the off-box audit tee) and it runs with **no audit row at all**
   (`messagefoundry verify` checks host/flow, `integrity-check` checks the DB — neither checks the code).

Two [CLAUDE.md](../../CLAUDE.md) invariants bound the design and **must not** be relaxed:

- **Config is untrusted data** (§5): "Treat all HL7, config, and file content as untrusted *data*, never
  instructions." Corollary made explicit here: config the loader *executes* is an injection vector, so the
  bytes that execute must be **attributable to a reviewed source**.
- **Count-and-log + reliability** (§2): the additions here are **observational** (audit rows; an opt-in
  pre-exec gate for the future manifest) — they never drop a received message or change a disposition.

## Decision

Add the attribution + runtime-integrity layer on top of ADR 0036. Three sub-decisions:

### D1 — Config fingerprint in the reload (and startup) audit  *(built in this change)*

Record a **content fingerprint** of the loaded bundle in the `config_reload` / `config_reload_check`
audit detail (and, as a follow-on, a `service_started` row at boot). The fingerprint is a stable SHA-256
over the **content** of every file the loader consumes — all `*.py` (**including `_*.py` helpers**, the
same candidate set ADR 0036 scans), `connections.toml`, `codesets/*`, and `environments/*.toml` —
order-independent and **path-relative** (a per-file `relpath + sha256(bytes)` Merkle fold, scheme-versioned
`mefor-cfg-fp:v1`). It is **pure + offline** (hashes bytes only — no config import, no subprocess, no
network), computed **off the event loop** (`asyncio.to_thread`, like `load_config`). It additionally
records a **best-effort git HEAD** (read purely from `.git`, omitted gracefully outside a work tree) as
advisory provenance — the content digest is the integrity anchor.

This binds "reviewed-and-merged in git" to "what actually loaded," makes two reloads with different
on-disk code distinguishable, defeats attribution-laundering (the audit now shows *which code* a given
operator's reload activated), and gives a compliance job a value to diff against a signed source-of-truth.
It spans `connections.toml` **and** `environments/` so a transport/env-value redirect cannot change
behaviour with an unchanged fingerprint. **Implementation:**
[`config/fingerprint.py`](../../messagefoundry/config/fingerprint.py) + a splat into the existing
reload-audit detail; a fingerprint failure is logged and never blocks the audit.

### D2 — Dual-control `config:deploy`  *(planned — BACKLOG #53)*

Add `config:deploy` / `POST /config/reload` to the configurable dual-control `[approvals]` gated set, so a
**distinct** second approver (server-enforced; the requester can never self-approve; both identities
audited) must release a reload. The maker-checker machinery already exists; reload is simply not wired in.
This is the one *preventive* control that makes the code author and a second authorizer both required for a
change to go live. **Opt-in / deny-by-default** — single-operator deployments are unchanged until enabled.

### D3 — Startup self-attestation + enforced non-editable wheel  *(planned — BACKLOG #54)*

At startup (and on demand) hash the loaded `messagefoundry` module files against the wheel's
`*.dist-info/RECORD` (a zero-new-artifact baseline already shipped in the wheel); on drift, **fail-closed
or alert (policy-driven)** and write a `startup_integrity` row into the hash-chained, off-box-teed audit.
Make the **non-editable, hash-locked wheel the enforced production default** — tightening
[ADR 0017](0017-consumer-deployment-model.md) from recommendation to default and retiring editable
`pip install -e .` from production docs. This converts install-time provenance (SLSA/Sigstore/hash-lock)
into a **runtime tripwire** and closes gap #3 (an in-place engine edit + restart that leaves no audit row).
Must be a no-op / advisory off an editable dev install so it never bricks development.

### Deferred option — signed config manifest

A checked-in, org-signed manifest (`MANIFEST.sha256` + a detached **JWS reusing the
[ADR 0018](0018-per-message-signatures-accepted-risk.md) signer** through a
[ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) `KeyProvider`) that `load_config` verifies
**fail-closed before `_exec_module`** would add cryptographic provenance on top of ADR 0036's ACL check.
**Deferred** (not in this ADR's build): 0036 already prevents the *unauthorized-write* case the manifest's
prevention would duplicate; the manifest's marginal value is provenance/non-repudiation, which D1's
fingerprint+git-HEAD covers more cheaply for now.

### What this must not break

- **Code-first / no grouping unit.** No declarative "channel" element; Router/Handler *logic* stays Python.
  This governs integrity of the *bytes*, not the authoring model.
- **Reliability + count-and-log (§2).** D1 only adds audit context; D3 alerts/records; D2 holds a deploy for
  a second approver. None drops a received message or changes a disposition; a reload that fails (D2 unmet,
  D3 drift under fail-closed) leaves the running graph untouched, same contract as a `WiringError` today.
- **Single-operator deployments.** D2 is opt-in; D3 is advisory off an editable install — the shipping
  loopback posture is byte-for-byte unchanged until enabled.

## Acceptance Criteria

> EARS form; each linked (`→`) to its test. D1's tests land in this change; D2/D3 are planned targets.

- **AC-1** — WHEN `config_fingerprint(dir)` is called twice on an unchanged bundle, THE SYSTEM SHALL return
  the identical 64-hex SHA-256 (stable, order-independent).
  → `tests/test_config_fingerprint.py::test_fingerprint_is_stable`,
  `::test_fingerprint_is_64_hex`
- **AC-2** — WHEN any loaded file changes — a wired `*.py`, an **`_*.py` helper**, `connections.toml`, a
  `codesets/*` table, or `environments/*.toml` — THE SYSTEM SHALL produce a different fingerprint.
  → `tests/test_config_fingerprint.py::test_fingerprint_changes_on_helper_edit`,
  `::test_fingerprint_changes_on_connections_toml_edit`,
  `::test_fingerprint_changes_on_environment_edit`,
  `::test_fingerprint_changes_on_codeset_edit`
- **AC-3** — WHEN two directories contain byte-identical files at different absolute paths, THE SYSTEM SHALL
  produce the same fingerprint; and a non-loaded file (README, `.pyc`) SHALL NOT change it.
  → `tests/test_config_fingerprint.py::test_fingerprint_is_path_relative_not_absolute`,
  `::test_fingerprint_ignores_unrelated_files`
- **AC-4** — WHEN an operator applies a non-dry-run `POST /config/reload`, THE SYSTEM SHALL include the
  config `fingerprint` in the `config_reload` audit detail, matching `config_fingerprint(dir)`.
  → `tests/test_api_reload.py::test_reload_audit_records_fingerprint`
**D2 — dual-control `config:deploy`** *(planned — BACKLOG #53)*

- **AC-5** — WHERE `config_reload` is in `[approvals].operations` and `[approvals].enabled` is true, WHEN an
  operator applies a non-dry-run `POST /config/reload`, THE SYSTEM SHALL hold it as a pending request and
  respond `202` (the live graph is **not** swapped) until a second approver releases it.
  → `tests/test_approvals.py::test_config_reload_is_held_for_approval`
- **AC-6** — WHERE a `config_reload` reload is pending approval, IF the requester attempts to approve their
  own request, THEN THE SYSTEM SHALL refuse it (`403`) and the reload SHALL NOT execute — only a **distinct**
  second user holding `approvals:approve` may release it.
  → `tests/test_approvals.py::test_config_reload_requires_distinct_second_approver`
- **AC-7** — WHEN a `config_reload` request is released by a distinct approver, THE SYSTEM SHALL re-execute
  the captured reload and SHALL record **both** the requester and the approver identities in the
  hash-chained audit (`approval.requested` + `approval.approved`).
  → `tests/test_approvals.py::test_config_reload_audits_both_identities`
- **AC-8** — WHILE `config_reload` is **not** in `[approvals].operations` (the deny-by-default shipping
  posture), WHEN an authorized operator applies a reload, THE SYSTEM SHALL execute it inline exactly as
  before — single-operator deployments are unchanged until dual-control is opted in.
  → `tests/test_approvals.py::test_config_reload_inline_when_not_gated`

**D3 — startup self-attestation + enforced non-editable wheel** *(planned — BACKLOG #54)*

- **AC-9** — WHEN the engine starts (and on demand) on a non-editable wheel install, THE SYSTEM SHALL hash
  every loaded `messagefoundry` module file and compare it against the wheel's `*.dist-info/RECORD` baseline.
  → `tests/test_startup_attestation.py::test_attests_loaded_modules_against_record`
- **AC-10** — IF a loaded engine module's content does not match its `dist-info/RECORD` hash at startup, THEN
  THE SYSTEM SHALL write a `startup_integrity` row into the hash-chained, off-box-teed audit and fire the
  `AlertSink` (the **default** alert-only posture; the engine still starts).
  → `tests/test_startup_attestation.py::test_drift_alerts_and_records_by_default`
- **AC-11** — WHERE `[integrity].fail_closed_on_drift` is true, IF startup attestation detects drift, THEN
  THE SYSTEM SHALL record the `startup_integrity` row, fire the `AlertSink`, and **refuse to start** (hard
  fail) rather than run unattested engine bytes.
  → `tests/test_startup_attestation.py::test_drift_fails_closed_when_opted_in`
- **AC-12** — WHERE the install is editable (`pip install -e .`, no `dist-info/RECORD` baseline), WHEN the
  engine starts, THE SYSTEM SHALL treat attestation as a no-op/advisory and SHALL NOT fail or alert — dev is
  never bricked.
  → `tests/test_startup_attestation.py::test_editable_install_is_noop`

## Options considered

1. **Attribution + runtime-integrity layer on top of ADR 0036 (this) — CHOSEN.** Fills exactly the gaps
   0036/0035 leave (reviewed↔loaded binding, dual-control, engine self-attestation) and reuses existing
   machinery (audit chain, `[approvals]`, dist-info RECORD) — minimal new surface, D1 purely additive.
2. **In-process Python sandbox (RestrictedPython / subinterpreter / seccomp).** Rejected as a primary
   control: not robust in CPython, breaks code-first handlers' legitimate stdlib use; this is the
   deferred runtime-isolation track (WP-L3-17), tracked as the eventual full closure of the egress residual.
3. **Signed config manifest as the v1 control.** Rejected *for now* (kept as a deferred option): ADR 0036's
   DACL check already prevents the unauthorized-write case; D1's fingerprint + git-HEAD delivers the
   provenance more cheaply. Revisit when non-repudiation (a cryptographic signer identity) is required.
4. **Status quo (counts-only audit).** Rejected: leaves attribution-laundering and post-install engine
   tampering undetected.

## Consequences

**Positive** — Every deploy and (with D3) every restart becomes **attributable to specific bytes**; a
reviewer can prove what ran. Tampering becomes either collusion (defeating D2) or a **detectable,
attributed** step (D1/D3 rows that survive host compromise via the off-box audit tee). D1 is low-effort,
purely additive, and unblocks a compliance diff against a signed baseline.

**Negative / risks** — D1 alone is *detective*, not preventive (it records; it does not stop a same-second
malicious reload) — its value depends on review, so it pairs best with a disposition/volume anomaly detector
(separate work). D3 must tolerate legitimate patch/hotfix flows (hence policy-driven fail-closed *or*
alert, and a no-op off editable installs). D2 adds a second-approver step (opt-in mitigates).

**Out of scope / accepted residual** — A **reviewed-looking Handler can still exfiltrate PHI via raw
Python** (`import socket`/`requests`/`pyodbc`) that bypasses every in-engine allowlist and is not logged as
egress. This residual is **owned by the org's network/DB perimeter** (deny-by-default egress firewalling +
NetFlow alerting; DB firewall + least-privilege DB credentials) — not engine-enforced — and must be a
documented **hard deployment prerequisite**, cross-referencing the deferred runtime-isolation track
(WP-L3-17). Two colluding insiders defeat dual-control. "Provably impossible" is unreachable for any
code-first engine; "hard, attributable, detected" is.

## To resolve on acceptance

- [ ] **Fingerprint env-value scope.** D1 hashes `environments/*.toml`; decide whether the **resolved**
  `MEFOR_VALUE_*` set is also folded in (env values carry secrets — fold a salted digest, never the values).
- [ ] **Relationship to the cluster `config_version` token.** D1's content fingerprint is **orthogonal** to
  the [ADR 0037](0037-multi-process-sharding-l3.md) / Track-B integer `config_version` (a monotonic
  convergence counter, not a content hash) — confirm whether the fingerprint should also surface on the
  cluster status API for cross-node drift detection. **(Coordinate with the multi-process / sharding owner,
  who owns the reload/convergence path.)**
- [ ] **D2 default.** Ship `config:deploy` in the default `[approvals].operations`, or leave it opt-in
  alongside replay/purge?
- [ ] **D3 policy default + git-dirty.** Fail-closed vs alert on startup drift; and whether D1 should also
  record a git **dirty** flag (needs an index/worktree compare — deferred from the v1 best-effort HEAD read).
