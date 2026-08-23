<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0169 — Username identity is case-sensitive, and no identity decision may depend on store collation

- **Status:** Proposed (2026-08-20)
- **Date:** 2026-08-20
- **Related:** [BACKLOG #1268](../BACKLOG.md) · [ADR 0164](0164-record-bootstrap-claimed-ness-never-infer-a-monotonic-lifecycle-fact-from-mutable-credential-state.md) (the other half of the WP-3 bootstrap lifecycle) · [SECURITY.md](../SECURITY.md) §"Auto-retirement (WP-3)" · [CLAUDE.md](../../CLAUDE.md) §0 (not deployed), §11 (SDS-3.7)

---

## Context

### Two places answered "is this the same username?", and they did not agree

`users.username` was the **one identifier column in the SQL Server schema carrying no `COLLATE`
clause**, so it inherited the *database* default — case-**IN**sensitive on a stock install
(`SQL_Latin1_General_CP1_CI_AS`). Every sibling identifier column in the same file already pinned
`COLLATE Latin1_General_100_BIN2`. SQLite (`BINARY`) and Postgres (`TEXT`) are both
case-**SENSITIVE**.

So `Admin` and `admin` were **two accounts on two backends and one account on the third**, under a
`UNIQUE` constraint that reads as if it had settled the question.

That divergence is a portability defect on its own. It became a **security** defect because a second
site answered the same question with a different rule. `_login_local` decided whether to run the
WP-3 bootstrap expiry/supersession enforcement with a **Python** comparison against the caller's
input:

```
auth/service.py:724   if username == BOOTSTRAP_USERNAME:      # case-SENSITIVE
auth/service.py:725       await self._retire_superseded_bootstrap()
auth/service.py:726   user = await self._store.get_user_by_username(username)   # collation-resolved
```

On a case-insensitive store the two disagree **in exactly one direction**: a login as `Admin`
**fails** the Python guard, so retirement never runs, and then **succeeds** at the lookup, handing
back the very row the skipped call would have disabled.

### Measured, before the fix

With an unclaimed bootstrap whose WP-3 window had lapsed, and the ASVS 6.4.1 credential expiry
disarmed so it could not mask the result:

| login as | outcome | account after |
|---|---|---|
| `admin` | refused | `disabled = True` — the control fired |
| `Admin` | **`ok=True`, session issued** | `disabled = False` — the control never ran |

A lapsed, unclaimed first-run credential logging in successfully because one letter was capitalised.
This is **SDS-3.7** exactly — a compensating control resting on a false premise, the premise being
that *the username the gate compared is the username the store matched*.

**No live exposure: there are zero deployments ([CLAUDE.md](../../CLAUDE.md) §0).** This is what a
first deployment against a SQL Server store would hit. SQLite and Postgres deployments would not be
affected, which is what made it easy to look past — the control is genuinely sound on the default
development store, so a green suite there certified nothing.

---

## Decision

**1. Usernames are case-sensitive.** `Admin` and `admin` are different accounts, on every backend.
The SQL Server column now pins `COLLATE Latin1_General_100_BIN2`, matching the convention its own
file already applied to every other identifier column.

**2. No identity decision may be delegated to store collation.** Where the engine must decide
whether some string names a particular account, it compares against **the value the store returned**,
never against the caller's input. The bootstrap gate now reads:

```python
user = await self._store.get_user_by_username(username)
if user is not None and user.username == BOOTSTRAP_USERNAME:
    await self._retire_superseded_bootstrap()
    user = await self._store.get_user(user.id)   # re-read: retirement may have disabled it
```

**Rule 2 is the load-bearing half, and it does not depend on rule 1.** The stored value is canonical
by construction (`_ensure_bootstrap_admin` writes it), so the `==` is exact on purpose. This stays
correct under a collation the engine does **not** control — an operator-supplied database, a restored
dump, a column altered downstream. Rule 1 alone would only make SQL Server behave like the others; it
would leave the gate one `ALTER COLUMN` away from being wrong again, with nothing reporting it.

### Cost

One extra lookup **on the bootstrap path only**. An ordinary login does the single lookup it always
did, plus a string compare — so the original guard's stated intent ("keep normal logins free of the
extra lookups") is preserved, not traded away.

---

## Alternatives rejected

**Normalise usernames case-insensitively (casefold on write and on compare).** Rejected on three
grounds, none of which is "it is more work":

- It requires choosing a canonicalisation and being right about it forever. Unicode case folding is
  not locale-neutral (the Turkish dotless `i` is the standard example), and a normalisation that is
  wrong for one script silently merges two distinct accounts — a strictly worse failure than the one
  being fixed, and one that a `UNIQUE` constraint would enforce rather than catch.
- It would have to be applied consistently across three backends **and** the audit trail, where
  `_audit(..., actor=username)` currently records what was typed. Every one of those is a new place
  for the two rules to diverge again, which is the defect this ADR exists to close.
- Two of the three backends are already case-sensitive, so it is the larger change measured against
  the shipped behaviour, not the smaller one.

**Fix only the column (limb 1) and leave the guard.** Rejected: it makes the gate *accidentally*
correct, contingent on a schema the engine stops controlling the moment an operator restores a dump
or alters the column. The premise would still be false; it would merely happen to hold.

**Fix only the guard (limb 2) and leave the column.** Rejected as incomplete rather than wrong. It
closes the security defect, but leaves account identity store-dependent — `Admin` and `admin` still
one account on SQL Server and two elsewhere — which is a live portability trap for anything else that
compares usernames.

---

## Consequences

- **New SQL Server databases** get the binary collation. The DDL is guarded
  (`IF OBJECT_ID('users','U') IS NULL`), so **an existing database keeps its original column
  collation** — a re-type of a populated column is not attempted here. Per §0 there are zero
  deployments and therefore nothing to migrate; this is recorded so a later reader does not mistake
  the schema-hash bump for a column alteration. Rule 2 is what makes that acceptable: the gate is
  correct on such a database anyway.
- The schema-content hash changes, forcing one full DDL batch run on the next open (ADR 0064). No
  test pins a literal hash value, so nothing else moves.
- **Flagged, not decided here:** two accounts differing only in case are themselves a confusability
  risk, and case-sensitivity preserves rather than removes it. Refusing to *create* a username that
  differs from an existing one only by case is a separate, additive control that does not require
  reopening this decision — it is a registration-time check, not an identity rule. Not built, and not
  filed as an item by this lane.

## Verification

`tests/test_username_identity_collation.py`, four assertions, and the ordering matters:

- The column test carries its own **positive control** — a sibling column in the same statement is
  asserted to already carry the collation, so an unreadable `_SCHEMA` or a renamed table fails loudly
  instead of passing over nothing.
- The gate test is paired with an **exact-case control running against the same proxy**, so when the
  differently-cased login behaves differently the case is the only variable.
- Both gate tests **passed against the unfixed code** in their first form, which is what caught the
  design: they used the *supersession* arm, and `create_local_user` retires the bootstrap eagerly at
  `service.py:2685`, so the account was already disabled before the login ran. Supersession can never
  exercise this defect. The *expiry* arm can — nothing evaluates that window except the call sitting
  behind the guard under test. That retraction is kept in the test file, because a reader who sees
  only the corrected version cannot tell it was ever wrong.
- Limb 2 is pinned on a **simulated** case-insensitive store rather than gated on
  `MEFOR_TEST_SQLSERVER`. The mechanism is the disagreement between two comparisons, not anything SQL
  Server does uniquely, and gating it would mean the assertion that pins the fix does not run in
  normal CI — which is precisely the condition that hid the defect.
