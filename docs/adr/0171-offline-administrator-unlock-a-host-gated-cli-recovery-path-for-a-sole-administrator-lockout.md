<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors -->

# ADR 0171 — Offline administrator unlock: a host-gated CLI recovery path for a sole-administrator lockout

- **Status:** Accepted (2026-08-22) — built with the change; amended 2026-09-27 (`clear_lockout`, ADR 0197); amended 2026-10-06 — Amendment B, `admin-reset-totp`, by owner ruling (BACKLOG #2226), built with the change
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

## Amendment (2026-09-27) — a named `clear_lockout`, and a second lock to clear (ADR 0197, BACKLOG #1131)

**This amends the decision above and does not supersede it.** The gate is still host access, the
command still needs no credential, and it still does not reset the password. What changed:

- **A named store method replaces the `record_login_failure` reuse.** "It reuses
  `record_login_failure`" above chose reuse only to avoid a four-file collision with a peer lane, and
  said a named method is the cleaner shape once that pressure is absent. It is absent now, and
  [ADR 0197](0197-cap-repeated-lock-cycles-on-one-account-without-making-malicious-lockout-cheaper.md)
  needs a second lock cleared in the same write, so `admin-unlock` calls `clear_lockout` on the
  Store protocol, implemented on all three backends. `record_login_failure` stays as the raw sign-in
  lockout write; no engine code calls it any more.
- **There are two locks to clear.** ADR 0197 split the failure counter into a **sign-in** counter and
  a **second-step** counter, each with its own lock and its own cycle count. `admin-unlock` clears
  both locks and both failure counts, and reports both old expiries and both cycle counts on stdout,
  in `--json`, and in its `auth.admin_unlocked` audit row.
- **It keeps both cycle counts by default.** A campaign that resumes after an unlock then resumes at
  the escalated lock length, which is ADR 0197's recommendation. `--reset-cycles` zeroes them for the
  case where the operator knows the campaign is over.

**The "Not addressed" section above is now partly answered.** ADR 0197 bounds the repetition limb
for the accounts whose owner has a way past the lock, by escalating those locks per cycle. For every
other account the number of lock cycles is still unbounded, and `docs/SECURITY.md` control 1 says
which accounts those are.

## Amendment B (2026-10-06) — `admin-reset-totp`: replace a sole Administrator's TOTP seed from the host (BACKLOG #2226)

**This amends the decision above and does not supersede it.** The 2026-09-27 amendment above is the
first; this one is called B so code can cite it. It adds a second command on the same gate. The
gate, the "run it with the engine stopped" rule and the exit-code convention are unchanged.

### The problem

The TOTP seed has no calendar lifetime: the owner exempted it on 2026-09-27 (BACKLOG #1931), and
the rotation schedule names revocation as the control that remains. For a sole Administrator on an
account that requires MFA, with TOTP as its only factor, revocation had no path:

| route | why it is closed for that account |
|---|---|
| another Administrator's `POST /users/{id}/reset-mfa` | it refuses a self-target (#1022), and there is no other Administrator |
| self-service TOTP removal | the AC-A3a guard in `disable_mfa` refuses TOTP removal for a covered local account, passkeys or not (since engine PR 1770) |
| enrol a passkey, then remove TOTP | open only to a directory Administrator, and only with the `[webauthn]` extra |
| `[security].require_mfa = false` and a restart | turns MFA off for every account for the whole window |
| an offline command | none reset MFA |

So a suspected seed leak could not be answered by replacing the seed. Severity is conditional
(CLAUDE.md section 0): zero deployments, so this is what a first deployment with one Administrator
would meet.

### The ruling

**Owner ruling, 2026-10-06**, given in session to the batch 196 Manager: build a host-gated TOTP
re-enrolment command, `admin-reset-totp`, through an amendment to this ADR. The reasons put to the
owner: it never passes through zero factors, and it follows this ADR's precedent. **Declined:**
relying on "create a second Administrator", which needs `[approvals]` off, and "turn `require_mfa`
off", which turns MFA off for every account during the window.

### What the command does

`messagefoundry admin-reset-totp --username <name>` takes the same arguments as `admin-unlock`
(`--service-config`, `--db`, `--json`) and the same host gate, `_host_gated_store_settings`. In
order:

1. It opens the store and refuses, before any key is shown, at least: an unknown account, an
   account that does not hold the Administrator role, a disabled account, an account with no TOTP
   enrolled, an account with TOTP on but no seed stored, an Administrator who is not the only
   enabled one, and a store whose audit append would be refused (the `admin-unlock` pre-check). It
   pins the account's id and its `totp_enrolled_at`.
2. It generates a new seed in memory and shows the key and its URI on the console device, never on
   stdout or stderr. It uses the same terminal enrolment as `provision-admin` (ADR 0197
   Amendment A). The URI labels the entry `<username> (replaced <date>-<time>)`, so the app lists
   it apart from the old entry, which carries the bare username, and apart from a second run's
   entry; the prompt says which one to delete. There is no colon in it, because the URI's label
   uses one to separate the issuer. The operator adds the seed to the authenticator app and types
   a code. Five wrong codes, or no terminal, refuse with nothing written. The command names the OS
   user for the audit row before the key is shown, so a shell that cannot name one is refused
   before the operator enrols anything. Every refusal after the key was shown tells the operator
   to delete the new entry, whose seed was never stored.
3. It reopens the store, asks the same refusals again, refuses a row whose id changed, and makes
   **one transaction**, `replace_totp_enrolment`. That writes the new seed, new recovery-code hashes
   and the proving code's step, ends every session of the account, and appends the audit row. Its
   UPDATE matches only where TOTP is still on, with a seed, and still enrolled at the pinned
   instant.
4. It shows the new recovery codes on the console device once.
5. It sends the holder an `mfa_enabled` security notice, best effort, as `provision-admin` sends its
   takeover notice. That comes after the audit row, so a notice never announces an unrecorded swap.

### Why the account never has zero factors

The order is prove first, then swap. Until step 3 commits, the old seed is untouched and still signs
in. So every refusal and every interruption before it leaves the account exactly as it was. Step 3's
UPDATE is one statement inside one transaction. It changes the seed, the codes and the step
high-water mark together and never writes `totp_enabled`, so no reader ever sees TOTP off or the
seed empty. It matches only a row where TOTP is on, so it cannot turn TOTP on for an account that
lacked it.

It is also a **compare-and-set on what step 1 read**. The re-check in step 3 would pass for an
account whose TOTP was removed and enrolled again while the operator typed, because TOTP is on with
a seed again. So the UPDATE also requires the pinned `totp_enrolled_at`, which every confirmed
enrolment rewrites, and the command refuses a row whose id changed. A removal, or a newer enrolment,
that lands during the prompt is never overwritten: the write matches nothing and the command says so.

The other design, clearing the seed and forcing enrol-first at the next sign-in, was rejected. It
passes through a state with no factor. `admin_reset_mfa` needs a generated credential to make that
state safe (ADR 0197 Amendment A, N-B2). On a sole Administrator that state is the install's only way
in.

The proving code's step is recorded as spent, so the code typed at the terminal cannot sign in
afterwards. The new seed starts its own step history, as `disable_totp` resets it for the same
reason.

`tests/test_admin_reset_totp.py` checks the property with a SQLite trigger. The trigger records any
UPDATE that leaves the row with TOTP off or no seed. It records nothing during the command, and it
fires once on `disable_totp`, its positive control.

### Recovery codes are replaced, not kept

A leaked seed or a stolen device usually means the recovery codes kept beside it are exposed too. A
seed rotation that left them valid would revoke nothing for whoever holds them. So the old codes stop
working in the same statement that swaps the seed, and a new set is issued. If the console cannot
show the new codes, the command warns and the new seed still works. Running it again issues codes
that can be kept.

Passkeys are left alone. They are a separate factor, and nothing here suspects them. The output
says when the account has one, so an operator who suspects the device holding it too knows to
remove it from the web console.

### Sessions end

Every session of the account ends in the swap's own transaction. A session elevated with the old
seed is what a seed leak buys, so a revocation that left it standing would not revoke much. The
sweep runs after the UPDATE inside that transaction, so a session minted with the old seed just
before the swap is still ended, and a swap can never commit with the sessions left standing.

### Who it accepts

It accepts the **sole enabled Administrator**, local or directory. A directory Administrator's TOTP
seed is engine-held state on the engine's user row (BACKLOG #1144), so the replacement fits it as it
fits a local one. It refuses every other account. An Administrator resets another account's factors
from the web console (Reset MFA). A host-run replacement would leave the new seed with whoever ran
the command, not with the holder. That is the same reason this ADR's unlock does not reset a
password.

**Why only the sole one.** The ruling answers an account with nobody to ask. An Administrator with
an enabled peer has the ordinary route: the peer resets its MFA from the web console. Accepting it
here too would widen a host-run credential change past the gap the ruling closes, and this ADR
argues its unlock as the narrowest thing that resolves its case. So the command refuses, and names
one other enabled Administrator. The predicate is the one `AuthService.is_last_enabled_admin`
applies: enabled, and holding the role in `user_roles`. A disabled Administrator does not count. An
install whose other Administrator is enabled but out of reach gets no help from this command; that
peer, or `[security].require_mfa = false`, is still the route there.

It does not clear a lockout. That stays `admin-unlock`'s job.

### What it audits

Every successful run writes **`auth.admin_totp_reset`**, named like `auth.admin_unlocked`, with the
OS user as the actor (`cli:<os user>`). The detail holds the username, the recovery codes issued,
whether passkeys were kept, the account's provider, and `"sessions_ended": "all"`. The count is
known only inside the transaction, so the operator's output carries it and the row records that the
sweep ran. It never holds the seed or a code. The notice is sent after the row commits, so the row
does not say what became of it. The row is not hidden from readers without `users:manage`. It says
a seed was replaced, which is no password oracle.

**The audit row commits WITH the swap, which is stricter than `admin-unlock`.** `admin-unlock`
checks the append's refusal before its write (`_refuse_an_unauditable_write`) and appends the row
after it, as a second write. A failure between the two leaves the change made and unrecorded. For
an unlock that is the narrowest change there is, and a re-run repeats it harmlessly. Here the change
is a live credential. The first build used the unlock's ordering, and its code review confirmed the
window with a probe that made `record_audit` raise: the new seed stayed in force with no audit row
and no codes shown, reported as a store that could not be opened. So the row joins the swap's
transaction, the shape `create_user` already uses for BACKLOG #2100: the swap and its record land
together or not at all. The pre-check still runs before the key is shown, so the ordinary refusal
costs the operator no enrolment.

**An error does not say whether the commit landed, so the command reads it back.** On a server
backend an error can follow the COMMIT: a lost acknowledgment, or a pool release that fails after
the transaction ended. So when the swap raises, the command re-reads the stored seed before it
says anything.

| the re-read finds | the command says | exit |
|---|---|---|
| the old seed, and the error was a store refusal | nothing was written; the old entry still works; delete the new one | 1 |
| the new seed | the seed WAS replaced, then something failed; the new codes are shown | 3 |
| nothing, because it failed too | the outcome is UNKNOWN; keep both entries and try the new one; the codes are shown | 3 |

A failure after a confirmed commit, the store's close or a Ctrl-C included, takes the second row.
After the commit only the store's close, the codes on the console and the notice are left. The
codes are shown first, then the notice runs, best effort. **Exit 3 is new to this command and
deliberate:** 1 is a refusal that wrote nothing and 2 is "could not start", and a script reading
only the code must not take a replaced seed for either. The `--json` body carries `"replaced":
true` and the report fields beside the error.

### A named store method, on all three backends

`replace_totp_enrolment` joins the Store protocol, on SQLite, PostgreSQL and SQL Server. It takes
the pinned `expected_enrolled_at` and an `AuditAppend`, and returns the number of sessions ended, or
`None` when it wrote nothing. No existing method can swap the seed with TOTP on. `enable_totp`
writes only where TOTP is off, and
`set_totp_secret` leaves the old recovery codes and step. Every composition of the existing methods
passes through a state the property above forbids. The shared TOTP store contract,
`tests/_webauthn_store_contract.py`, covers the method on every backend.

### Not addressed

- The command trusts the host gate, as `admin-unlock` does. Anyone who can run it already holds the
  database, so it grants nothing new. It does not stop such a person enrolling their own seed on the
  Administrator; the audit row and the notice record that it happened.
- "Run it with the engine stopped" is documented, not checked. The compare-and-set write, and the
  session sweep in its transaction, narrow what a live engine could race. They pin the TOTP
  enrolment only. A role removal, a disable or a newly enabled peer Administrator that lands in the
  moment between the second refusal check and the UPDATE is not caught; with the engine stopped
  nothing can make one.
- The sole-Administrator check is a fourth copy of the enabled-Administrator predicate, beside the
  three in `AuthService`, and it reads the roles one user at a time, as `is_last_enabled_admin`
  does. One shared query for the predicate is unbuilt.
- A store key that cannot be resolved exits 2 here, as it does for `provision-admin`.
  `admin-unlock` does not route that error yet.
