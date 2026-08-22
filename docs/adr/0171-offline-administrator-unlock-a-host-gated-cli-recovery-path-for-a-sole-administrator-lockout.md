<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0171 — Offline administrator unlock: a host-gated CLI recovery path for a sole-administrator lockout

- **Status:** Accepted (2026-08-22) — built with the change
- **Date:** 2026-08-22
- **Related:** [BACKLOG #1236](../BACKLOG.md) · [`__main__.py`](../../messagefoundry/__main__.py) `_admin_unlock` · [ADR 0170](0170-constant-work-recovery-code-verification-pad-to-the-configured-slot-count-rather-than-short-circuit.md) (the neighbouring auth work) · [CLAUDE.md](../../CLAUDE.md) §0 (not-deployed beta), §9 (PHI guardrails)

---

## Context

A deployment with **one** administrator had no recovery from account lockout. Each exit is
individually deliberate and defensible; the defect is that they close **simultaneously** for that
deployment, and nothing in the code or the docs notices the conjunction. All five re-verified on
`origin/main` before building:

| exit | why it is closed |
|---|---|
| the bootstrap account is literally `admin` | the username an attacker guesses first is the one that cannot recover |
| it is created with **no email** | `SecurityEventNotifier.notify` returns early on a missing address, so the `ACCOUNT_LOCKED` notice never leaves the process |
| self-reset is refused | by design — you may not reset your own account |
| an admin reset needs **another** admin | there is not one |
| re-bootstrap fires only on an **empty** users table | the account exists, so it never fires |
| no CLI managed users | 38 `add_parser` sites, none for users |

### The filed acceptance criterion could not discriminate, and that is why it was amended

#1236 originally asked: recover **without** hand-editing the database and **without** a second
authenticated admin. **The shipped system passes that by waiting** — the lock is time-bounded and
clears itself after `lockout_minutes` (default 15). A test that a defect-free system and the
defective system both pass is not a test.

The 2026-08-21 amendment fixes it: recovery must be reachable **on demand**, **gated**, and **faster
than `lockout_minutes`** — or the item must say plainly that self-expiry is the accepted recovery and
re-scope. This ADR takes the first branch.

## Decision

Ship **`messagefoundry admin-unlock --username <name>`**: an offline subcommand that opens the store
directly and clears the account's lockout state.

### The gate is host access, and it is a real gate rather than an absent one

Reaching this needs the service config, the store path, and on an encrypted store the key material —
which is the operator who installed the engine. **Anyone holding all three already has the database
and does not need an unlock affordance to reach an account.** So the command grants no capability the
trust boundary did not already imply, which is what makes it safe to ship unauthenticated. That is
the argument for *why there is no password prompt*, and it is the load-bearing claim of this ADR: if
it is wrong, the design is wrong.

### It clears the lockout and does NOT reset the password

Deliberately narrower than the obvious fix. The holder still needs their credential afterwards; a
reset would hand whoever ran the command a working account. An unlock is the smallest thing that
resolves a lockout.

### It reuses `record_login_failure` rather than adding a protocol method

`record_login_failure(user_id, failed_attempts=0, locked_until=None)` is exactly "the lockout state
is cleared", and it already ships on all backends — so this needs **no migration and no store
change**. The name reads oddly at a call site that unlocks, which is why the call carries a comment.

**A measured cross-lane fact decided this rather than taste:** a named `clear_lockout` on the Store
protocol would touch four files (`base`, `store`, `postgres`, `sqlserver`), and **all four were
uncommitted in a peer lane's worktree at the time of writing.** Reuse avoided a four-file collision
and a coordination round. If that pressure is absent later, a named method is the cleaner shape and
this is not an argument against it.

### Exit codes follow the `--json` convention, not the M-31 lineage

The file carries two error conventions. `_emit_error` prints a JSON object and returns **1**; a bare
stderr line returns **2**. This command supports `--json`, so it uses `_emit_error` — a caller
passing `--json` and receiving a stderr line would have its parsing broken. Verified: `audit-verify`,
whose M-31 guard this copies, has **no** `--json` flag and correctly uses the other convention.

## Consequences

- A locked-out sole administrator recovers **immediately**, from the host, without a second admin and
  without hand-editing the database.
- **Every use writes an `auth.admin_unlocked` audit row** naming the OS user, because an unlock
  affordance is a control an attacker wants and its use must be recorded.
- The **M-31 guard is carried over**: a SQLite store is created on open, so a typo'd `--db` would
  otherwise yield a fresh empty database and report *"no such account"* — which reads as a wrong
  **username** when the truth is a wrong **database**. Refused instead, and the test asserts the file
  was not created.
- **One of the four tests is the control, and the other three are deliberately insensitive to it.**
  Neutering the clearing call reds *only* the acceptance test. The audit-row test still passes under
  that plant — the row is written whether or not the clear happened — so it evidences the flow ran,
  never that it worked. Stated so nobody reads a green audit test as proof of the unlock.
- **Severity is conditional per CLAUDE.md §0** — zero deployments, so this is what a first deployment
  with one administrator would have hit, not a live exposure.

## Not addressed

The **repetition** limb of #1236. An active lock cannot be extended (`service.py` returns before
`_register_failure`), but the number of lock *cycles* is unbounded, and `docs/SECURITY.md` already
words this as bounding the lock rather than the campaign. This command resolves a lockout on demand;
it does not stop an attacker re-locking the account. That is a separate control and is not claimed
here.
