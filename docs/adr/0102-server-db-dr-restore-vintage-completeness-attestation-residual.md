# 0102 — Server-DB DR restore vintage/completeness: accept the residual (+ an opt-in restore-token vintage floor)

- **Status:** Accepted (2026-07-12) — design + risk-acceptance recorded; optional restore-token cross-check built  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-07-12
- **Related:** [ADR 0048](0048-third-tier-disaster-recovery-standby.md) (third-tier DR standby — owns the
  activation refusal this residual lives inside; the `_verify_live_server_seed` gate + the cold-restore
  fail-back runbook) · [ADR 0049](0049-turnkey-dr-backup-restore-verify.md) (turnkey DR backup — produces
  the `dr_backup` audit row whose `archive` anchor this token cross-checks; the config-only server-DB
  backup is the *decoupled* artifact that makes the residual exist) · [ADR 0041](0041-load-path-attestation-and-change-attribution.md)
  (config fingerprint + audit hash-chain) · [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) (KeyProvider
  DEK seam) · [`docs/security/ASVS-L3-RISK-ACCEPTANCE-REGISTER.md`](../security/ASVS-L3-RISK-ACCEPTANCE-REGISTER.md)
  (where this residual is signed off, ASVS-style) · BACKLOG **#223** (this), **#102** (the gate this
  extends), **#60/#61** (backup + DR standby), **#52** (server-DB backup/restore = DBA-delegated) ·
  CLAUDE.md §2 (reliability + count-and-log invariants), §9 (PHI: never log a body; on-prem/no-egress)

---

## Context

BACKLOG **#102** closed a concrete server-DB DR **data-loss** hole. On a Postgres/SQL Server store the #60
backup is **config-only** (`snapshot_to` is DBA-delegated, #52), so `run_restore_verify` returns `PASS` on
the manifest **without ever restoring or inspecting the DBA-managed live `mefor` database**. Before #102,
`POST /dr/activate` could therefore bless priority-feed promotion against a **fresh, unrestored** server
store — non-empty only because engine bootstrap + operator login had written to `audit_log` — silently
dropping the very clinical feeds DR exists to protect.

#102's fix (`messagefoundry/pipeline/dr.py::DrCoordinator._verify_live_server_seed`) fails **closed** unless
**both** hold:

1. an explicit **per-activation DBA attestation** (`dba_attests_restored=true`) — the engine cannot itself
   restore a DBA-managed DB, so activation must be a deliberate act; and
2. a live **restore-provenance probe** (`Store.has_prior_backup_history()` — ≥ 1 `dr_backup` audit row):
   the restored DB must carry backup history, which a passive DR standby (never the backup leader) lacks. A
   mistaken attestation over a fresh DB still fails closed (defense in depth).

This is deliberately **weaker** than the SQLite default (which snapshot-verifies the whole store:
`integrity_check` + per-table row counts). The **residual** #102 itself documents, and #223 tracks:

- **Vintage.** A **stale-but-real** restore passes — an old native backup carrying *old* `dr_backup` rows
  satisfies "≥ 1 `dr_backup` row." The gate cannot tell a fresh restore from last month's.
- **Completeness.** A **partial** restore that carried `audit_log` but not the message tables passes — the
  `dr_backup` rows live in `audit_log`, so the provenance probe is blind to a truncated message store.

The adversarial review (2026-07-10) found **no in-scope engine artifact that can cross-check vintage on a
DBA-managed DB**: the config-only `.mfbak` seed is a **decoupled** artifact from the DBA's native DB backup
(pg_dump / SQL Server `.bak` / PITR), and message/queue row-counts are **unsafe** signals (legitimately `0`
on a drained store, so "counts look low" cannot mean "stale/partial"). The one thing the engine *can*
observe on the restored DB is its own `audit_log` — specifically the `dr_backup` rows ADR 0049 writes on
every backup, each carrying a PHI-free **`archive`** filename (instance + UTC-stamped, monotonic).

This decision is bounded by the standing invariants ([CLAUDE.md](../../CLAUDE.md) §2), quoted **verbatim**:

> **Count-and-log invariant (do not break):** **every received message is persisted before the ACK** … so
> inbound counts still reflect the true received volume and nothing is accepted-and-dropped.

and §9 (PHI): *"Never log full message bodies at INFO or above … no PHI leaves the local environment without
explicit, reviewed configuration."* Any new artifact must be **read-only** against the restored store,
**PHI-free** (a filename anchor only, never a body or key bytes), **local/UNC** (no new egress), and **must
not gate the default path** — a deployment that does not opt in stays byte-identical to #102.

## Decision

**Formally ACCEPT the server-DB DR restore vintage/completeness residual as an attestation-guarded,
runbook-documented risk acceptance (option (c)) — recorded here and signed off ASVS-style in the L3
Risk-Acceptance Register — AND ship a small, opt-in "restore-token" cross-check (option (b)) that gives a
real *vintage floor* when an operator wants one, without gating default behavior. The full engine-driven
server-DB store seed (option (a)) is explicitly deferred as a separate, owner-scheduled decision.**

In one line: #223 is **design + risk-acceptance + an opt-in vintage-floor token**, **not** the large
engine-seed build.

### (c) — the risk acceptance (the primary deliverable)

The residual is real, bounded, and now **owned, dated, and scheduled for review** rather than implicit in a
code comment:

- It is recorded as a residual row in [`ASVS-L3-RISK-ACCEPTANCE-REGISTER.md`](../security/ASVS-L3-RISK-ACCEPTANCE-REGISTER.md)
  (theme *PHI data-plane integrity*), with its compensating controls (attestation + provenance probe, both
  fail-closed) and an explicit **trigger to re-score** ("a stale/partial DBA restore causing a clinical
  data-loss incident, or an adopter contract that mandates engine-verified DR vintage").
- It is made explicit to operators in ADR 0048's **cold-restore runbook**: the per-activation DBA
  attestation is a *deliberate correctness assertion*, and the DBA — not the engine — owns proving the
  native restore is the **intended vintage and complete**.

Accepting a residual **does not** change any scorecard status; it changes it from *silently open* to
*owned*.

### (b) — the opt-in restore-token vintage floor (the low-risk build)

A new **opt-in** `[dr].restore_token` (default `""` = OFF). When set, it is a **local/UNC path** to a small
JSON token file the DBA/operator places on the DR box **as part of the native-restore runbook**, recording
the **expected source-backup anchor**:

```json
{ "expected_backup_archive": "mefor-backup-<instance>-<utc-timestamp>.mfbak" }
```

The `expected_backup_archive` is the **`archive` filename of the most-recent engine `dr_backup`** the
restored `mefor` DB is expected to carry — read from the **primary's** out-of-band backup record (the
`dr_backup` audit row / the `messagefoundry backup` CLI summary), **not** read back from the restored DB
(which would be self-fulfilling and prove nothing).

The #102 gate, **only when the token is configured**, adds a third fail-closed condition after the
attestation and the provenance probe: it reads the token's expected anchor and the restored DB's **own**
latest *successful* `dr_backup` `archive` (via the existing `list_audit(action="dr_backup")`, skipping
FAILURE rows whose detail has no `archive`) and requires them to **match**. A **stale** native restore
carries an *older* latest anchor → mismatch → **abort**; the **wrong** DB carries a different anchor →
mismatch → **abort**. Every failure records a `dr_activation_aborted` audit row and raises
`DrActivationError(kind="seed")`, exactly like the existing #102 conditions.

Precisely what the token **does and does not** prove:

- **Does:** a *vintage floor* — the restored DB is **at least as fresh** as a specific, operator-declared
  backup point, and it is the DB the operator *intended* to restore (not an accidental older `.bak`).
- **Does not:** it is **still an attestation**, now a *specific, cross-checked* one rather than a bare
  boolean. It does **not** prove message-table **completeness** (the `dr_backup` anchor lives in
  `audit_log`, so a partial restore that carried `audit_log` still matches) and it does **not** turn the
  DBA-managed DB into an engine-verifiable artifact. It is a **strictly stronger** posture than a boolean
  attestation, **not** a match for the SQLite full-snapshot default. That gap is (a).

**Scope discipline (do not break):** `restore_token = ""` makes the whole cross-check a **no-op** — the
#102 gate is byte-identical, and SQLite is a no-op throughout (the archive already verified the whole
store). The token is **read-only**, **PHI-free** (a filename anchor), **local/UNC only** (a cloud URL is
rejected at config load, like `seed_archive`), and read **off the event loop**. It **adds no engine seam,
no store schema, no new dependency, no new key** — it reuses `list_audit` + the existing `dr_backup`
audit `archive` field + the existing `_record_aborted` fail-closed path.

### (a) — the full engine-driven server-DB store seed (DEFERRED, owner decision)

The strongest fix is to extend #60 / ADR 0049 so the **engine itself** restores + fingerprints the
server-DB store (e.g. an engine-orchestrated `pg_restore` / native-restore wrapper that stamps a
verifiable vintage fingerprint the gate checks), making vintage **engine-verifiable** end to end. This is
the **largest** option: it re-opens the standing **#52 DBA-delegation** boundary (DB-tier backup/restore is
infra-owned), it must reconcile with heterogeneous DBA tooling (pg_dump/PITR/Always On), and it is a
multi-week engine build. It is **explicitly out of scope for #223** and is flagged as an **owner decision
to schedule separately** — not to be started without owner sign-off (CLAUDE.md §5 planning gate).

## Acceptance Criteria

> EARS — testable, each linked to a test. `messagefoundry adr-analyze` checks each `→` link resolves.

- **AC-1** — WHERE `[dr].restore_token` is unset (`""`) on a server-DB store, THE SYSTEM SHALL behave
  byte-identically to the #102 gate (the token cross-check never runs).
  → `tests/test_dr_server_seed_gate.py::test_restore_token_unset_is_noop`
- **AC-2** — WHEN `[dr].restore_token` is set AND the token's `expected_backup_archive` matches the
  restored DB's latest successful `dr_backup` archive, THE SYSTEM SHALL proceed with activation (the
  vintage floor is satisfied).
  → `tests/test_dr_server_seed_gate.py::test_restore_token_matching_passes`
- **AC-3** — IF `[dr].restore_token` is set AND the token's `expected_backup_archive` does **not** match
  the restored DB's latest successful `dr_backup` archive, THEN THE SYSTEM SHALL abort activation closed
  (record `dr_activation_aborted`, raise `DrActivationError(kind="seed")`, never activate) — a
  stale/wrong-vintage restore is refused.
  → `tests/test_dr_server_seed_gate.py::test_restore_token_mismatch_refused`
- **AC-4** — IF `[dr].restore_token` is set but the token file is absent/unreadable or is not a JSON object
  with a non-empty `expected_backup_archive` string, THEN THE SYSTEM SHALL abort activation closed (an
  opted-in but unsatisfiable check fails closed, never silently passes).
  → `tests/test_dr_server_seed_gate.py::test_restore_token_missing_file_refused`,
    `::test_restore_token_malformed_refused`
- **AC-5** — WHEN `[dr].restore_token` is a cloud URL, THE SYSTEM SHALL fail config load with a clear error
  (local/UNC only — no new egress, like `seed_archive`); a LOCAL path parses and the default `""` is OFF.
  → `tests/test_settings.py::test_invalid_priority_and_dr_settings_rejected`,
    `::test_dr_restore_token_local_path_parses`

## Options considered

1. **(c) Accept the residual formally + (b) an opt-in restore-token vintage floor** — records the gap as an
   owned, dated, ASVS-style risk acceptance AND ships a small, default-off cross-check that turns the bare
   boolean attestation into a *specific, engine-cross-checked* vintage floor. Reuses `list_audit` + the
   `dr_backup` `archive` anchor + the existing fail-closed path; no new seam/schema/dep/key; SQLite and the
   unset path stay byte-identical. Honest about what it does **not** prove (completeness). **CHOSEN.**
2. **(b) alone** — ship the token but leave the residual undocumented. Rejected: the token is *opt-in*, so a
   deployment that does not configure it still carries the exact #102 residual; leaving it implicit in code
   is precisely what #223 exists to fix.
3. **(c) alone** — accept the residual, build nothing. Acceptable and honest, but leaves an operator who
   *wants* a vintage check with no engine help when a cheap, safe one exists. Rejected in favor of also
   shipping (b) as opt-in.
4. **(a) Full engine-driven server-DB store seed** — strongest (engine-verifiable vintage end to end) but
   largest: re-opens the #52 DBA-delegation boundary, must wrap heterogeneous native tooling, multi-week
   build. **Deferred — owner decision to schedule separately** (not rejected; out of scope for #223).
5. **Message/queue row-count freshness signal** — Rejected: row counts are **unsafe** — legitimately `0` on
   a drained store, so "low counts" cannot distinguish stale/partial from correctly-drained. It would add a
   false-abort footgun with no reliable signal.

## Consequences

**Positive**
- The #102 residual is **owned, dated, and review-scheduled** (ASVS-style) instead of implicit in a code
  comment — an auditor sees an accepted risk with compensating controls and a re-score trigger.
- Operators who want a **vintage floor** get one for free: an opt-in token that refuses a stale/wrong native
  restore, turning a bare boolean attestation into a specific, cross-checked one.
- **Zero default-path change.** Unset token + SQLite are byte-identical; no new seam, schema, dependency, or
  key; the token is read-only, PHI-free, local/UNC, off the event loop, and reuses the existing fail-closed
  abort path.

**Negative / risks**
- The token is **still an attestation**, not proof: the operator must source `expected_backup_archive` from
  the primary's out-of-band record; a self-sourced value (read from the restored DB) is self-fulfilling and
  useless — the runbook says so explicitly.
- It does **not** cover **completeness** (a partial restore carrying `audit_log` still matches the anchor) —
  documented, not closed. Only (a) closes completeness.
- A newer engine backup that ran between the operator recording the anchor and the DBA taking the native
  backup shifts the "latest" anchor; the runbook pins the anchor to the **native-backup point-in-time** to
  avoid a false abort.

**Out of scope**
- **(a) The full engine-driven server-DB store seed** — owner decision, scheduled separately; not started
  here.
- **Server-DB (Postgres/SQL Server) native backup/restore/PITR** — DBA-delegated (#52); unchanged.
- **Completeness verification of a DBA-managed native restore** — no in-scope engine artifact; only (a).

## To resolve on acceptance

- [x] Confirm the token anchor is the PHI-free `dr_backup.archive` filename (ADR 0049), cross-checked via
      `list_audit` — no new store seam.
- [x] Confirm the unset-token and SQLite paths stay byte-identical to #102.
- [x] Record the residual + compensating controls + re-score trigger in the ASVS L3 Risk-Acceptance
      Register and make the attestation explicit in ADR 0048's cold-restore runbook.
- [ ] **Owner decision (separate schedule):** whether/when to build (a) — the engine-driven server-DB store
      seed that makes vintage *and* completeness engine-verifiable (re-opening the #52 boundary).
