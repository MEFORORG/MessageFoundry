# 0210 -- Session supersession follows a time-bounded retired-hash lineage

- **Status:** Accepted (2026-10-17, on build; the design was set by the batch 257 Manager's brief;
  the owner may overrule at review)
- **Date:** 2026-10-17
- **Related:** vault BACKLOG #3028 (the case this closes), #2146 (engine PR 2028, the atomic
  supersession it extends), #3029 (the same race on `logout` and `revoke_own_session`, not built
  here), #2592 (the session integrity seal), #1146 (ASVS 7.2.4), ADR 0142 (federated sign-in),
  CLAUDE.md section 0 (severity is conditional: there are no deployments)

Built with the change, in the same pull request.

## Context

A console sign-in ends the session its browser presented (ASVS 7.2.4): the new `Set-Cookie`
replaces the old one, so the server is what strands it. Every elevation (MFA, a step-up, a passkey
ceremony, a password re-check) re-keys the session row to a new token hash in place, and the old
hash stops naming any row.

Engine PR 2028 (BACKLOG #2146) made the supersession's read and revoke one store operation, so an
elevation that starts after it fails closed. It left an elevation that FINISHED before it open. The
presented hash then named nothing, the supersession ended nothing, and the session lived on under
its new token. The window is the whole sign-in, and on the federated leg it includes the identity
provider's round trip, because the start leg reads the cookie (the callback is cross-site and the
Strict cookie never reaches it). Nothing recorded which hash replaced which.

The constraint the fix must hold is the row's closing item 2: a retired hash must authenticate
nothing, and be usable for nothing but the lookup that ends its successor.

## Decision

**A rotation records a link from the hash it retired to its successor, and the login supersession,
and only it, follows those links for a bounded time to the live end and revokes that.**

1. **A separate table, `session_lineage`** (`retired_hash` primary key, `successor_hash`,
   `retired_at`, an index on `retired_at`), on SQLite, Postgres and SQL Server. `rotate_session`
   writes one row in the SAME transaction as the re-key, and only when the re-key landed.
2. **The walk is one shared function**, `store/session_lineage.py`'s `revoke_through_lineage`. Each
   step tries to revoke the hash it holds; only when that ends nothing does it read the hash's
   successor and step. Every backend runs it inside one transaction on one connection. SQLite's
   first `UPDATE` takes the database write lock even when it matches nothing, so nothing else can
   re-key a row until the commit. On Postgres (READ COMMITTED) and SQL Server each statement reads
   what has committed when it runs, so a rotation that commits mid-walk costs one more step, never
   the revoke: its link was written in its own transaction. The walk follows at most 32 links.
3. **The bound is the caller's, as `lineage_since`**: a link retired before it is not followed. The
   store reads no settings. `AuthService.supersession_lineage_seconds` is
   `oidc_flow_ttl_seconds` plus 120 seconds, the longest sign-in a rotation can race plus the
   callback's own work after it. With no `lineage_since`, `supersede_session` is the plain revoke
   it was, which `_end_lapsed_session` keeps.
4. **The session reaper purges links past the window**, in the same pass as expired sessions,
   through a new `lineage_seconds` argument to `purge_expired_sessions`.
5. **No session read consults the table.** `get_session`, `list_sessions` and the service's session
   loader read `sessions` only. A test pins, per backend, that only `rotate_session`,
   `supersede_session` and `purge_expired_sessions` name the table or a statement on it, and that
   only `_supersede_session_hash` passes a window.
6. **The links are not sealed** (BACKLOG #2592). A seal stops a database writer forging authority,
   and a link carries none: the most a forged link can do is direct a revoke at a live row, and a
   revoke needs no key on any backend, so that writer could revoke the row directly.
7. **The audit row names the session that ended**, by the hash it ended under, and adds the
   `presented` hash when a link was followed.

## Acceptance Criteria

- **AC-1** -- WHEN an elevation has completed on a session before a sign-in that presents the
  session's old token supersedes it, THE SYSTEM SHALL end the session under its new token.
  -> `tests/test_session_supersession_lineage.py::test_an_elevation_that_finished_before_the_sign_in_does_not_keep_the_session_live`
- **AC-2** -- WHEN several elevations have completed, THE SYSTEM SHALL follow each link to the live
  end.
  -> `tests/test_session_supersession_lineage.py::test_the_link_is_followed_over_several_elevations`
- **AC-3** -- IF a link was retired before the window, THEN THE SYSTEM SHALL NOT follow it.
  -> `tests/test_session_supersession_lineage.py::test_a_link_older_than_the_window_is_not_followed`
- **AC-4** -- THE SYSTEM SHALL authenticate nothing by a retired token, or by a token whose hash a
  link names.
  -> `tests/test_session_supersession_lineage.py::test_a_retired_token_authenticates_nothing_while_its_link_is_live`,
  `tests/test_session_supersession_lineage.py::test_a_token_whose_hash_links_to_a_live_session_authenticates_nothing`
- **AC-5** -- THE SYSTEM SHALL read the lineage only from the supersession, on every backend.
  -> `tests/test_session_supersession_lineage.py::test_only_the_rotation_the_supersession_and_the_purge_touch_the_lineage`
- **AC-6** -- WHEN the reaper runs, THE SYSTEM SHALL delete links past the window and keep the rest.
  -> `tests/_session_rotation_contract.py` (`assert_session_lineage_contract`, run on all three
  backends)

## Options considered

1. **A separate retired-hash table, followed only by the supersession, time-bounded.** CHOSEN.
2. **A `previous_hash` column on `sessions`.** Rejected: one column holds one hop, so a second
   elevation during one sign-in would lose the first link, and a sealed column would put the
   retired hash under the seal and into every session read's row.
3. **Keep the old hash resolving, revoked, as a tombstone row.** Rejected: a retired hash would
   then name a row that every session reader sees, which is the wrong side of closing item 2.
4. **Bound the walk by the sign-in's own start time** instead of a fixed window. Rejected for now:
   the password and Kerberos legs would need their start time carried to the mint, and the
   Manager's brief set a fixed window of at least the flow TTL. It would narrow the second-holder
   case below, and stays open as a refinement.

## Consequences

**Positive** -- The case engine PR 2028 left open is closed for any elevation that finished inside
the window, including several in a row. The walk is one function with a `lineage_since` argument,
so `logout` and `revoke_own_session` (#3029) can follow the same links by passing a window.

**Negative** -- For the length of the window, a retired token gains one power: presented at a
sign-in that succeeds, it ends the session it became. It cannot open or extend one.
`docs/SECURITY.md` states this. Each rotation writes one more row, which the reaper deletes.

**Stated limits** -- An elevation that finished longer ago than the window, such as one a second
holder of the token completed earlier, is not followed, and neither is a sign-in that runs past the
window; that session lives on under its new token until it expires. More than 32 links in one
window ends nothing. `retired_at` and the bound are both wall-clock readings, so a clock step
between the elevation and the sign-in moves the bound by the step, either way. The window adds the
flow TTL even where federated sign-in is off, where every leg is one request; the brief fixed the
window at no less than the flow TTL, and a narrower one there is open as a refinement. The
Postgres and SQL Server legs run only on hosted runners.
