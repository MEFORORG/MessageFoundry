<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0163 — First-run provisioning without a default account: the not-present arm via an engine-consumed request

- **Status:** Proposed (2026-08-13) — **NO CODE. Nothing here is built.** The arm is settled and the mechanism family is chosen; four decisions in §"What the owner must decide" gate any implementation.
- **Date:** 2026-08-13
- **Related:** [BACKLOG #1136](../BACKLOG.md) (ASVS 6.3.2 research) · [BACKLOG #1236](../BACKLOG.md) (the sole-administrator availability defect, split out of #1131) · [ADR 0063](0063-no-split-store-unified-store-for-sharding.md) (one unified store under engine sharding) · [ADR 0110](0110-vs-code-extension-engine-lifecycle.md) (the IDE's engine-lifecycle model, whose §5 fork hazard cites the behaviour retired here) · [SERVICE.md](../SERVICE.md) · [CONFIGURATION.md](../CONFIGURATION.md) · [CLAUDE.md](../../CLAUDE.md) §0 (not deployed), §9 (PHI)

---

## Context

### The requirement, and why the shipped default does not meet it

ASVS 6.3.2 asks that default user accounts *not be present* **or** *be disabled*. Two arms.

On first run against an empty user table the engine creates an **enabled** Administrator literally
named `admin` (`messagefoundry/auth/service.py:71`, from `_ensure_bootstrap_admin` at `:528`, gated
only on `count_users() == 0` at `:529`). `create_user` takes **no `disabled` parameter** at all
(`messagefoundry/store/base.py:1531-1542`), so the account cannot presently be created disabled.
Disabling is deferred to supersession by a second administrator, or to `bootstrap_expiry_hours`,
which defaults to 72 (`messagefoundry/config/settings.py:1803`). **Neither arm holds at the shipped
default.**

What genuinely mitigates it — and why this is a partial rather than a fail — is that there is no
default *credential* of any kind: the password is per-install CSPRNG through the active policy, the
account carries `must_change_password`, the credential is written to an owner-only file rather than
logged, and the account self-retires. The residual on a first deployment is that **a well-known
privileged username is enumerable by construction** for up to three days after install.

Per [CLAUDE.md §0](../../CLAUDE.md) this is a beta with zero deployments. That removes migration and
compatibility cost entirely — the simple correct end state is available — and it removes nothing else.

### Two arms were evaluated. One is dead on the code.

**The `disabled` arm is not reachable.** Nothing shipped can *enable* a disabled account except
`PATCH /users/{user_id}` behind `require_step_up(Permission.USERS_MANAGE)`
(`messagefoundry/api/auth_routes.py:693-699`) — an authenticated administrator, which is exactly what
does not exist at first run. So the disabled arm needs a new out-of-band surface **anyway**, plus a
`create_user` signature change across the Store protocol and all three backends. And its terminal
state is wrong: once claimed, `_retire_superseded_bootstrap` early-returns on
`not boot.must_change_password` (`auth/service.py:584`), `update_user` cannot rename
(`:2554-2562`), and nothing can delete the account — so the steady state of every correctly-followed
runbook is a present, **enabled** administrator named `admin`. A verdict reading "disabled" over a
state the documented happy path leaves within minutes is a dishonest pass.

**The `not present` arm is reachable and stable.** After removing the auto-provisioned bootstrap, the
users table is empty at first start and the two surviving `create_user` call sites both require an
already-authenticated actor: the AD upsert (`auth/service.py:1213`) runs only after a successful
directory bind, and the admin-created path (`:2535`) sits behind `USERS_MANAGE`.

## Decision

**Adopt the `not present` arm**, and deliver it as an **engine-consumed provisioning request**: the
operator supplies a request; **the engine — the only process that opens the store, the only holder of
the data-encryption key, and the only writer of audit rows — consumes it.**

The mechanism family is the load-bearing part of this decision, and it was chosen by elimination
after a **standalone provisioning CLI was refuted**. That refutation is the most reusable thing in
this ADR, so it is recorded rather than summarised.

### Why a standalone CLI is not viable: one root cause, four consequences

A separate CLI process runs as a **different OS principal, in a different environment**, from the
engine. Everything below follows from that single fact.

1. **Provision-then-start bricks the engine.** `MessageStore.open` unconditionally applies
   `_secure_file` to the db/`-wal`/`-shm` trio on **every** open (`store/store.py:2009-2014`),
   issuing an `icacls` call with `/inheritance:r`, which strips the inherited ACEs the installer set
   for SYSTEM, `BUILTIN\Administrators` and the service account
   (`scripts/service/install-service.ps1:119-132`). A store created by the operator locks the engine
   out of its own database.
2. **Start-then-provision strands the operator.** The same mechanism, run first by the service,
   locks the store to the service account; an elevated CLI is then denied, recoverable only by
   `takeown`/`icacls`. **Consequences 1 and 2 contradict each other, so no ordering of a
   standalone-CLI runbook works.**
3. **The CLI has no data-encryption key.** The key is env-only or a DPAPI file and lives in the
   service environment block (`docs/SERVICE.md:212-216`); `install-service.ps1` sets no `MEFOR_`
   variable. A keyless open writes the first audit rows keyless, after which the engine's later keyed
   open **permanently** skips auto-keying — the tamper-evident audit chain silently downgraded for
   the life of the install, *by the security fix itself*.
4. **On an existing keyed store the keyless open raises after the writes commit**
   (`store/store.py:2280-2283`, mirrored in `postgres.py:1596-1600` and `sqlserver.py:2426-2430`),
   leaving an unretryable state.

Keeping the engine as the sole store-opener makes all four **vacuous** rather than mitigated, which
is the property worth buying. Three independent adversarial reviews confirmed that.

### What is settled

- The arm: **not present**.
- The mechanism family: **the engine consumes; no other process opens the store.**
- The operator-visibility predicate is **role-based, never `count_users()`**. A role-less AD row is
  created on any successful directory bind (`auth/service.py:1209-1219`) and would silence a
  count-based warning while nobody holds ADMINISTRATOR. The correct predicate is *no enabled user
  holds the built-in ADMINISTRATOR role* — and because `CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`
  (`auth/permissions.py:194-201`) contains `USERS_MANAGE`, no custom role can ever grant it, so that
  predicate is exactly "no enabled user can manage users". It is also the predicate
  [#1236](../BACKLOG.md) needs.

## What the owner must decide before any code is written

Adversarial review refuted the *specific* request-file design on four counts that are not
engineering details. They are recorded here as open questions, not as solved problems.

1. **May the trust root invert from READ to WRITE?** Today the channel requires *reading* a file the
   engine wrote. A request file makes *"can create a file in the data directory"* sufficient to mint
   an ADMINISTRATOR while no enabled administrator exists — and the engine's own service account is
   inside that set by construction. Defensible (the window is bounded, and an attacker with engine
   code execution already owns the store) but it is a deliberate trade and must be made deliberately.
2. **Is a standing file-drop-to-administrator channel acceptable, or must it be armed?** Recovery for
   [#1236](../BACKLOG.md) needs the channel available to a *running* engine. Note the trap found in
   review: lockout is modelled as `locked_until`, **not** `disabled` (`auth/service.py:761-769`), so
   a locked-out sole administrator still satisfies "an enabled administrator exists" and any intake
   gated on that predicate never runs — the recovery case it was chosen to serve.
3. **What does ASVS 6.4.5 become?** It must be re-scored **with** 6.3.2, never after — but the
   coupling is *narrower* than the first draft of this ADR claimed, and the correction matters
   because overstating it inflates the apparent cost of a sound change.

   **What dies:** the bootstrap-side half. `bootstrap_expiry_hours` and `bootstrap_warn_hours`, the
   pre-retirement reminder, and the seven tests in `tests/test_auth_service.py` that exercise them
   (headers at `:151` and `:177`). Three of the cell's six evidence anchors go with them.

   **What survives, by explicit construction:** the admin-issued initial/reset credential expiry at
   `auth/service.py:694-701`, keyed on `initial_password_expiry_hours`. The conjunct
   `username != BOOTSTRAP_USERNAME` at `:696` is a **carve-out excluding the bootstrap, not a
   dependency on it** — the comment at `:691-693` says so in terms. Deleting the bootstrap removes
   the *reason for the carve-out*, so that condition gets **simpler**, not absent, and every
   non-bootstrap `must_change_password` user still expires exactly as before. No behaviour change.
   The remaining three anchors survive with it.

   So the re-score is not a re-derivation from nothing: 6.4.5 is re-derived **on its surviving arm**
   and may well hold at its current verdict for a reason it already carries. What forces the
   coupling is that half its evidence dies and its residual's claim that the bootstrap arm is
   covered becomes false the moment this lands. Re-scoring 6.3.2 alone would bank an improvement
   while silently voiding three anchors on a neighbouring cell.
4. **What replaces the HIPAA emergency-access mapping** that currently rests on the bootstrap
   credential?

## Consequences

**Positive.** No default account and no predetermined username at any point; no plaintext credential
written by the engine; no 72-hour clock; and all three legs of [#1236](../BACKLOG.md)'s
sole-administrator dead end close at near-zero extra cost, because the same channel carries unlock,
reset-password and enable.

**Negative, stated plainly.** An operator who never provisions has a running engine that routes HL7
and that nobody can sign into. That is the honest residual cost of this arm. It is bounded — the
state is recoverable at any moment by one operator action — unlike today's failure modes, which the
`count_users() > 0` re-bootstrap gate makes permanent.

**Blast radius, measured rather than estimated.** At least 21 test files, of which three break
structurally the moment `initialize()` returns `None`; `pipeline/alerts.py` and `alert_sinks.py`;
`scaffold.py` and `.gitignore`; `pipeline/dr.py`, whose seed-gate premise names the bootstrap admin
in four comments; the `ide/` extension, including two user-facing strings that would otherwise tell
an operator a launch creates a bootstrap admin **at the moment it asks for consent**, a mocha test
pinning one of those sentences, and [ADR 0110](0110-vs-code-extension-engine-lifecycle.md) §5; and
roughly a dozen documentation files, several read from disk by doc-drift tests so they must land in
the same change or CI reds.

**Evidence anchors on `config/settings.py` carry stale line numbers, and there is no deadline on
fixing them.** The three anchors covering these two cells have each drifted **+31 lines** —
`bootstrap_expiry_hours` 1772 to 1803, `initial_password_expiry_hours` 1784 to 1815,
`bootstrap_warn_hours` 1777 to 1808. All three still resolve, and will continue to however far the
file moves: `ANCHOR_WINDOW` was **retired 2026-08-09** (`scripts/asvs/scorecard.py:107-125`). There is
no tolerance to spend. Uniqueness locates the evidence and the recorded line is reported output that
an advisory corrects — a wrong line is not a failure. **Do not repair them piecemeal:** two of the
three are deleted by this work anyway, so they belong in the coupled re-score.

*(An earlier revision of this ADR asserted a plus-or-minus-40 window with "31 of it spent" and a
cliff ten lines away. That was false — the window does not exist — and it is recorded here rather
than silently removed, because the failure mode is worth more than the fact: a specific figure
attached to an unverified mechanism reads as verified, and it converts a tidy-up into a deadline.)*

**Engine sharding interacts.** Under [ADR 0063](0063-no-split-store-unified-store-for-sharding.md) a
multi-shard fleet shares **one** store, and every shard is a full `serve` subprocess running the
whole API lifespan. Any intake therefore runs concurrently in N processes against one store. The
audit chain is *not* cross-process serialised — `record_audit` reads the head row hash and inserts
its successor under an in-process asyncio lock only, with no `BEGIN IMMEDIATE` and no row lock
(`store/store.py:7313-7360`). Today's `_ensure_bootstrap_admin` has the identical race, so this
neither introduces nor fixes it; a design must not *worsen* it.

## Alternatives rejected

- **Rename `BOOTSTRAP_USERNAME`.** Forbidden by [#1136](../BACKLOG.md) and correctly so: the three
  names in the requirement are examples, so an equally default account under a less obvious name is
  the same account with worse discoverability for the operator.
- **Shorten `bootstrap_expiry_hours`.** Makes the window look small without making the account
  disabled at creation, and trades an availability knob for a verdict.
- **Prompt at engine start.** NSSM never sets `AppStdin`, the process runs in session 0, and it
  auto-starts at boot and after every crash.
- **Supply the first password via the service environment.** The account is still created by the
  application under a default name, so it satisfies neither arm, and it converts a one-time secret
  into a standing one.
- **A standalone provisioning CLI.** See §"Why a standalone CLI is not viable".

## How this was reached

Two multi-agent research passes with adversarial verification. Round one selected a standalone CLI;
three lenses refuted it with the four consequences above. Round two designed three engine-principal
candidates, judged them, and refuted the winner on its authorization model and its recovery
semantics while confirming the architectural core. **No design has yet survived adversarial review
intact, which is why this ADR is Proposed with no code and four owner questions rather than a plan.**
