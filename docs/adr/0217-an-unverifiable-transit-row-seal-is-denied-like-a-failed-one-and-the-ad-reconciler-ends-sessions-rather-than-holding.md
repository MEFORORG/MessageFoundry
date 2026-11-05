<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors -->

# 0217 -- An unverifiable Transit row seal is denied like a failed one, and the AD reconciler ends sessions rather than holding

- **Status:** Proposed (2026-11-05) -- design only, no code. Every answer below marked
  `CONTROL DECISION: yes` changes what a sign-in, a reconcile or a write refuses, pages or audits,
  so this ADR is accepted only by an owner ruling, or by a decision recorded under the owner's
  delegation and quoted on vault BACKLOG #4739. Nothing here is built until then.
- **Date:** 2026-11-05
- **Related:** vault BACKLOG #4739 (this design), #2592 (its parent: identity and authorization
  row seals), #4350 and #6357 (the `vault_transit` seal gap; see *The duplicate question*), #3411
  (the store-id pin), #3637 (the console flag) -- engine PR 2565 (draft, parked by the owner ruling
  of 2026-10-28, comment `6474801844`; branch `b435-2592-transit-seals` at
  `e48a5780750ee137c503cdd32082006e695d0368`, the reference implementation this design reads) --
  [ADR 0138](0138-transit-bulk-crypto-provider-dek-out-of-engine-heap-for-asvs-13-3-3-demand-gated.md) (the Transit cipher)

---

## Context

Engine `main` seals identity and authorization rows (sessions, users with their role grants, custom
roles, the two AD directory maps, approvals) with an HMAC keyed from the store key's in-process
authorization root (`messagefoundry/store/row_seal.py`). Under `[store].cipher_provider =
"vault_transit"` there is no in-process root: `TransitCipher.authz_root()` returns `None`, so
`RowSealer.for_cipher` returns no sealer and such a store writes and checks no row seals. That is
#2592's Transit limb. Per CLAUDE.md section 0 there are zero deployments, so this is a defect in
the shipped code that a first deployment choosing `vault_transit` would carry, not a live exposure.

PR 2565 closes the gap with a `TransitRowSealer`: the seal is Transit's own `hmac` under the audit
key, checked with Transit's `verify`, so no seal key enters the heap. That adds a fourth answer to
a seal check. A local sealer answers *holds* or *fails*. A Transit sealer can also be unable to
answer, and the reply does not say why. Seven review rounds on that PR moved the line between the
answers several times, and the last review (comment `6473855599`) found it still weakening
controls. The owner parked the PR and asked for the classification and the AD map behaviour to be
settled on paper first. This ADR does that, and dispositions every carried finding (#4739 items
3 to 19).

**The fact everything below rests on.** Anyone who can write a row in the store can make its seal
*unverifiable* at will: a well-formed `mfseal:v1:<key id>:vault:v<N>:<44 base64 characters>`
naming a version `N` Transit will not check (above the latest, or below
`min_decryption_version`) makes Transit's `verify` answer HTTP 400 while the key still answers.
Transit's reply for that planted seal is the same reply it gives a genuine seal checked against a
node that lags a rotation, and a genuine seal under a version an operator retired. So an
unverifiable answer is reachable by exactly the actor the seals defend against, and **no answer
below may let an unverifiable seal grant, keep or freeze anything a failed seal would not**. That
is the test each answer is held to.

## Decision

### The four answers, defined once

| Answer | What Transit (or the parse) returned | Sealer raises / returns | Decision | Audit action | Alert subject (`integrity_drift`) |
|---|---|---|---|---|---|
| **Holds** | `verify` HTTP 200, `valid: true` | `True` (cached up to 60 s) | allow | none | none |
| **Forged** | `verify` HTTP 200, `valid: false`; or the stored seal fails the well-formed parse (no Transit call) | `False` | deny the row (a session is ended, a user, role or map grants nothing, a write is refused) | `integrity.authority_seal_failed` | `AUTHORITY_SEAL_SUBJECT`, as today |
| **Unverifiable** | `verify` HTTP 400, and the fixed-input key probe (`hmac` over a constant) then answers with a well-formed MAC | `TransitSealUnverifiableError` | **the same deny as Forged**, with the AD map exceptions in (b) and (d) | `integrity.authority_seal_unverifiable` | `authority-seal-transit-unverifiable:<kind>:<ref>`, capped, the two AD maps exempt from the cap |
| **Outage** | any other `verify` failure (network, timeout, 5xx, 403, malformed reply), or a 400 the probe cannot clear | `TransitSealUnavailableError` | refuse the request or roll back the write; end nothing; record no seal failure | none (a throttled ERROR log line) | `authority-seal-transit` |

The API answers an Outage with HTTP 503 and `Retry-After`, an Unverifiable write refusal with HTTP
409 and fixed recovery text, and the CLI each with one error line and a non-zero exit. The
`<ref>` of a session is the first 12 hex characters of its token hash (`SESSION_REF_LEN`), never
the whole hash, everywhere: log line, audit detail, alert subject and exception arguments.

### (a) A `verify` HTTP 400 while the fixed-input probe works

**Answer.** It is **Unverifiable**, a deny class equal in effect to Forged, as round 5 (comment
`6466545392`) made it, and the lagging-node special case stays removed. Lagging, retired and
planted are not separate decisions, because Transit's reply cannot tell them apart and a database
writer can produce any of them. They are told apart only as *triage detail*: the audit row and the
page carry `stored_version` (the integer the stored seal names) and `probe_version` (the integer
the probe's MAC names, the latest version on the node that answered the probe). Both are integers
of at most ten digits parsed from Transit-shaped strings, so they carry no row data. No decision
reads them. The recovery text tells the operator, in this order: check that Vault is healthy and
that every node holds the audit key's latest version, then retry; only then consider a retired
version (lower `min_decryption_version` until the row verifies, save it again, raise it back); and
always that the seal may be planted.

Outage is told apart from Unverifiable by the probe alone: a 400 the probe also fails, or answers
with a MAC of the wrong shape, is an Outage. One probe call per refused check stays (see item 3).

- **Control kept:** an unverifiable row never grants, never keeps a session, and is always
  audited and paged as an integrity event. A planted unheld version is never downgraded to a
  retryable 503 that ends nothing and records nothing.
- **Failure accepted:** a genuine seal checked against a node that lags a key rotation is denied
  for the length of the lag. A user so affected signs in again; a write so refused is retried by
  its caller. After a rotation the window is the replication lag, measured in seconds on the
  deployments Vault documents.
- **Rejected: a lagging-node case that answers Outage when `stored_version` exceeds
  `probe_version`.** A database writer plants `vault:v9999999999:...` and turns a deny-and-audit
  into a 503 that ends no session and writes no integrity row; the next request reads the row
  again and keeps getting 503 while the attacker's session is never ended. That is a loosening,
  and it is what round 5 removed.
- **Rejected: a key-metadata read (`transit/keys/<key>`) to classify by version range.** The
  metadata read and the `verify` can reach different nodes, so the range describes no node that
  refused, and the result would still not decide anything. The probe's own version is enough for
  triage.
- **Rejected: an in-call retry after a short delay.** It catches some lags, but costs every
  planted-seal request a sleep plus two more Transit calls, and it changes no decision.

`CONTROL DECISION: yes` -- it fixes Unverifiable as a deny class with its own audit action and
alert subject, where `main` under `vault_transit` checks nothing.

### (b) AD sign-in and the reconciler while a directory map is unverifiable

**Sign-in. Answer: deny.** A directory sign-in reads the group-to-role map, and for an account the
map does not make an Administrator the group-to-channel map, before it writes anything. If either
is Unverifiable the sign-in is refused, nothing is written, and the account's stored roles and
scope are untouched. This is PR 2565's shape and is kept. (A map that is Forged still reads as
empty and grants nothing, as on `main`.) The refusal is audited under
`auth.login_refused_unverifiable` with reason `directory_map_unverifiable`; (e) says why it is not
`auth.login_failed`.

**Reconciler. Answer: deny, by ending sessions, never by holding.** On a pass where either map is
Unverifiable, the reconciler writes no role or scope row (a write from an empty map would replace
genuine assignments with nothing, and the next verified sign-in would have to rebuild them), and
instead **ends the live sessions** of every PRESENT directory account whose role or scope that map
decides. Those sessions count as revocations against the existing mass-revoke breaker
(`reconcile.breaker_tripped`) exactly as a Forged map's demotions do on `main` today, so a breaker
trip aborts the pass and pages through the breaker's own alert. Accounts read ABSENT or DISABLED
are judged on their probe as on any pass. Because sign-in is refused while the map stays
Unverifiable, an ended session cannot be replaced until the map verifies again.

**The per-map alert latch.** The standing condition "AD map `<name>` is unverifiable: directory
sign-in is refused and reconcile ends sessions" is latched **per map name** (a set, not one
string), and a map enters the set only **after** its page was handed to the sink and the sink
reported delivery. A sink failure leaves the map out of the set, so the next pass pages again. A
map leaves the set when a pass reads it verified; the set empties when both do. Each latched map
pages under its own fixed subject, `authority-seal-transit-unverifiable:adset:<map name>`.

**The cap exemption.** The unverifiable-row cap (`MAX_SUBJECT_ALERTS` distinct subjects per window,
then one shared `:*` subject) **exempts exactly the two map subjects**, whose names are fixed in
code, so no stored value can open an uncapped subject through the exemption. A flood of planted
row seals then folds into the aggregate and never hides a map page.

- **Control kept:** a database writer who makes a map unverifiable can deny directory access (they
  already can, by forging it), but can never freeze a demotion: a demoted account loses its live
  session within one reconcile pass, the same latency as on `main`, and no reconcile pass passes
  silently. Every pass with an unverifiable map pages, uncapped, once per map per hold.
- **Failure accepted:** a Vault fault or lag that makes a map unverifiable at reconcile time signs
  out the directory accounts it decides and refuses their sign-in until the map verifies; in an
  estate large enough to cross both breaker thresholds the breaker aborts the pass instead, as it
  would for a Forged map on `main`. That breaker behaviour is `main`'s and is not changed here.
- **Rejected: hold every diff and revoke nothing (PR 2565 at `e48a5780`).** #4739 item 4: a
  database writer plants an unverifiable map seal and every demotion stops revoking, which is
  privilege retention chosen by the attacker. That is the loosening this ADR exists to remove.
- **Rejected: read an unverifiable map as empty and apply the demotions (the Forged path).** It is
  fail-closed, but it rewrites every directory account's stored roles from data nobody could check,
  and on a lagging node it would trip the no-enabled-Administrator alert (#3229) for a role change
  the directory never made. Ending sessions denies the same access and changes no stored authority.
- **Rejected: hold for a grace period, then end sessions.** The grace is a window an attacker
  chooses to start; one pass is already the demotion latency `main` accepts.

`CONTROL DECISION: yes` -- it changes what a reconcile pass revokes and writes while a map is
unverifiable (sessions ended, no row written), what a directory sign-in refuses, and how the hold
pages.

### (c) Write-path refusals: paging, and keeping unverifiable apart from forged

**Answer.** One shape for every store write that checks a stored seal first (user, role, map,
session, approval, on SQLite, PostgreSQL and SQL Server):

1. The store's helper (`require_seal_for_write`) raises
   `RowSealError(kind, cause, subject)`. `cause` is an enum, `FAILED` or `UNVERIFIABLE`, set where
   `TransitSealUnverifiableError` was caught and never inferred from text. `subject` is
   `seal_row_key(kind, stored_id)`: the id the row holds **as stored**, so one row has one subject
   on a case-insensitive collation, and for a session only its 12-character ref. Those three are
   the exception's whole `args`, so `repr()`, copy and pickle carry no full token hash (item 12).
   An Outage never becomes a `RowSealError`; it propagates as `TransitSealUnavailableError`.
2. **The store pages** an `UNVERIFIABLE` refusal, under the row's own capped subject, through the
   sealer's per-row throttle that every reader and writer shares, so a row refused on a read and a
   write pages once. A `FAILED` refusal is reported as `main` reports it today.
3. **The caller audits.** The auth service and the approval gate write the cause's own action
   (`integrity.authority_seal_failed` or `integrity.authority_seal_unverifiable`) once, through
   their per-row throttle, with the same subject. A write outside a request (the CLI's
   `provision-admin`, bootstrap) maps the typed error to its own refusal text and exit code, and
   never to the CLI's defect report (item 6).
4. **Wording follows the cause.** An unverifiable refusal never says "forged" or "does not
   verify"; it says Vault transit could not verify the seal, and gives the recovery text from (a).
   An Outage says the seal "could not be made or checked through Vault transit", never that Vault
   "did not answer" or that "the request was refused", since it may have answered and there may be
   no request (#4739 item 3, round findings 1 and 2).

- **Control kept:** every refused write is paged and audited under its true cause; neither cause's
  flood throttles the other's subject; a refusal reached from a CLI is still a refusal.
- **Failure accepted:** an unverifiable write refusal pages under the cap with other rows, so past
  five rows in a window an individual row's page folds into the aggregate. Only the two map
  subjects are exempt.
- **Rejected: page in the service only.** A refusal reached from the CLI or a route backstop has no
  service reporter, and would be silent.
- **Rejected: a boolean `unverifiable` on `RowSealError` with a free-form `row_id`.** That is PR
  2565's shape, and its `row_id` carried the whole session token hash in `args` (item 12).

`CONTROL DECISION: yes` -- it fixes which audit action and which alert subject each refused write
gets, and that every write path pages.

### (d) Deleting a custom role while the role map or a holder's row is unverifiable

**Answer: refuse the delete, narrowly; never raw-delete, never re-seal what could not be checked.**

1. Before anything is revoked or written, the service reads the role's holders and the raw pairs of
   the AD role map.
2. If **any raw pair names the role** and the map is Unverifiable, the delete is refused (HTTP
   409, fixed recovery text, paged under the map's subject, audited `role.delete_refused` with
   reason `ad_role_map_unverifiable`). If no pair names the role the delete does not touch the
   map, so the map's seal is irrelevant and the delete proceeds (item 15).
3. If **any holder's user record** is Unverifiable, the delete is refused the same way, reason
   `holder_unverifiable`. Removing that holder's `user_roles` grant without re-sealing the record
   would leave the account reading as Forged once Vault recovers, and the store never re-seals a
   record it could not check (item 16). A holder that is Forged keeps `main`'s behaviour.
4. The store re-checks both inside its write transaction and refuses with the typed
   `RowSealError` if either turned Unverifiable after the service checked.
5. Sessions are revoked after the checks in step 1 to 3 and before the store delete, as on `main`,
   so the deleted permissions cannot linger on a live token. **Every revocation is audited**
   whether or not the delete then commits; a late store refusal in step 4 is audited as
   `role.delete_refused` beside the revocations it followed, and those sessions stay ended (item
   14). Ending a session is the conservative direction, so it is not rolled back.
6. The web console renders the 409's text in the page's error block, never the raw JSON body
   (item 13).

- **Control kept:** no role delete leaves a map or a user record that reads as forged after Vault
  recovers, and no delete re-seals content nobody verified.
- **Failure accepted:** a role that an unverifiable map or holder references cannot be deleted
  until the seal verifies. The remove-the-pairs-first recovery is the operator's: clear the map
  (an empty save, allowed even while unverifiable), delete the role, enter the pairs again.
- **Rejected: re-seal the remaining pairs.** That seals in content nobody could check, which is
  the exact act the store's never-re-seal-a-failing-row rule forbids.
- **Rejected: refuse every delete while the map is unverifiable (PR 2565 at `e48a5780`).** It
  refuses deletes the map has no part in (item 15).

`CONTROL DECISION: yes` -- it changes what a role delete refuses, and adds an audited refusal.

### (e) Which sign-in refusals count toward the sign-in burst signal

**Answer.** The sign-in burst detector (`messagefoundry/pipeline/security_signals.py`) counts
`auth.login_failed` and no other action, at weight 1 (0 for the legacy directory-lock detail).
That stays. Every sign-in refused **because of a seal's state rather than a credential** -- an
unverifiable user row on the local, directory or federated legs, and an unverifiable directory map
-- is audited under one action, `auth.login_refused_unverifiable`, with a `reason` of
`account_unverifiable` or `directory_map_unverifiable`, and so counts at weight 0. This makes PR
2565's exemption consistent: at `e48a5780` only the map refusal was exempt, and an unverifiable
user row still wrote `auth.login_failed` at weight 1 (item 17). A Forged user row keeps `main`'s
audit, unchanged. The response to the client is unchanged in every case (`invalid credentials`,
with the dummy password hash checked, so timing does not tell an unverifiable account from an
unknown one).

- **Control kept:** the burst signal keeps meaning "a client is presenting wrong credentials", and
  a Vault fault that refuses every sign-in does not page as a password attack from every client
  address. The refused rows are still audited one per refusal, and the row itself pages once per
  interval under the integrity subject from (a).
- **Failure accepted:** a client guessing passwords against an account whose row is unverifiable
  is not counted toward that client's burst. Its guesses cannot succeed, since the row is denied
  before any credential decides anything, and the row's integrity page fires.
- **Rejected: count both at weight 1 (as `auth.login_failed`).** A Vault lag would raise a burst
  alert for every client address that retries, under a password-attack subject, and the cap would
  fold real bursts into the same aggregate.
- **Rejected: a new "unverifiable burst" detector.** The per-row integrity page already reports the
  condition; a second detector adds subjects and a cap to reason about for no new decision.

`CONTROL DECISION: yes` -- it changes which audit action an unverifiable user-row refusal writes,
and so what the burst signal counts.

### Items 1 and 2: their own rows, not built here

Both stay owed as their own vault rows citing #4739, as the owner's answers quoted in comment
`6458223670` ask ("Ship as-is, file row" and "Separate row"). Neither is built under this ADR. The
Lander files them (korus `roles/BUILDER.md` 1c routes filings to the Lander):

1. **"A compare-and-swap seal outside the writer locks under vault_transit (SQLite, PG, MSSQL)."**
   The build below keeps PR 2565's shape: read-modify-write sites seal under the writer lock, so a
   Transit call runs while it is held. The audit append already does the same.
2. **"A verify-then-reseal tool for retiring a Transit key version."** It must verify each row
   before it re-seals it and never re-HMAC blindly, and it keeps its own review.

### Disposition of #4739 items 3 to 19

"At `e48a5780`" means engine PR 2565's head. A build is fresh from `main` (see *Build plan*), so
"fixed in build" means the build must do it, whether or not that head already did.

| Item | Finding (short) | Disposition |
|---|---|---|
| 3.5 | Seal checks in loops (roles, sessions, approvals) run one after another | **Kept:** the 60-second success cache bounds the repeat cost; parallel Transit calls are deferred until a measurement shows a loop is slow. |
| 3.6 | `seal_hmac` duplicates `audit_hmac`; `_transit_version` duplicates `store.py`'s `_TRANSIT_MAC_VERSION` | **Fixed in build:** one Transit-HMAC call helper in `crypto_transit.py` and one MAC-shape parser both callers import. |
| 3.7 | `for_cipher` special-cases `TransitCipher` with `isinstance` | **Fixed in build:** a `Cipher` method that returns the cipher's row-seal backend, or none, replaces the `sys.modules` and `isinstance` test. |
| 3.r1 | The Outage alert says Vault "did not answer" | **Fixed in build:** wording in (c) step 4. |
| 3.r2 | It says "the request was refused" outside a request | **Fixed in build:** wording in (c) step 4. |
| 3.r3 | `_key_answers` swallows the probe's exception unlogged | **Fixed in build:** the probe logs its failure at WARNING with Vault's failure text and no input (as `_probe_mac` does at `e48a5780`). |
| 3.r4 | Docstrings say any failure raises `CipherError` | **Fixed in build:** the docstrings name what can escape. |
| 3.r5 | `test_transit_row_seal.py:247` reads `caplog.text` before the redaction filter | **Fixed in build:** the assertion reads the filtered handler's output. |
| 3.r6 | A 400 on a planted seal costs a second Transit round trip, with no negative cache | **Kept:** the probe is the only Outage-versus-Unverifiable discriminator in (a); a negative cache would misfile an Outage inside its window. |
| 3.r7 | The same base64 line at three call sites | **Fixed in build:** with 3.6's helper. |
| 4 | Unverifiable AD map holds every diff; demotions stop revoking; no reconcile alert; page can fold into the cap | **Moot under design:** (b) ends sessions instead of holding, pages per map uncapped, latched after delivery. |
| 5 | Role delete raw-deletes map pairs of an unverifiable map | **Fixed in build:** (d) step 2 refuses it. |
| 6 | `provision-admin` unverifiable refusal falls to the CLI defect report | **Fixed in build:** (c) step 3. |
| 7 | Writes and the approval gate page under the request id | **Fixed in build:** (c) step 1, the stored id. |
| 8 | `directory_map_unverifiable` audited as `auth.login_failed`, weight 1 | **Fixed in build:** (e). |
| 9 | Forgery wording on unverifiable refusals; stale changelog fragment and `docs/PHI.md` lines; simplifications | **Fixed in build:** (c) step 4 wording; the docs slice rewrites the fragment and the `docs/PHI.md` recovery and seal text to this ADR; simplifications are taken where a slice touches the code. |
| 10 | Map-hold latch set before the alert, so a failed page is lost and later ones suppressed | **Fixed in build:** (b), latched only after delivery. |
| 11 | Latch does not record which map, so a move between maps raises no alert | **Fixed in build:** (b), a set keyed by map name. |
| 12 | `RowSealError` keeps the full session token hash in `args` | **Fixed in build (designed out):** (c) step 1, `args` are `(kind, cause, subject)` with the 12-character ref; a test pins that no `RowSealError` raised for a session holds a 64-character hash in `args` or `repr()`. |
| 13 | Web console role delete shows raw JSON on the 409 | **Fixed in build:** (d) step 6. |
| 14 | Sessions revoked before a late store refusal, with no audit row | **Fixed in build:** (d) step 5. |
| 15 | Role delete refused even when no map pair names the role | **Fixed in build:** (d) step 2. |
| 16 | Unverifiable holder's `user_roles` row raw-deleted without a re-seal | **Fixed in build:** (d) step 3. |
| 17 | Unverifiable user row still audits `auth.login_failed`, weight 1 | **Fixed in build:** (e). |
| 18a | Prose on what the scope-map hold revokes | **Moot under design:** there is no hold; (b)'s prose replaces it. |
| 18b | Closed lists of `ad_reconcile_aborted` sources and reasons | **Fixed in build:** the prose says "at least", per CLAUDE.md section 11 (SDS-3.6). |
| 18c | The split audit action | **Fixed in build:** (e) uses one action for every seal-state sign-in refusal. |
| 18d | The duplicate map check (service and store) | **Kept:** the service check refuses before any session is revoked; the store check under the transaction closes the race. Both are stated in (d). |
| 18e | A latent format-string hazard | **Fixed in build:** refusal texts that embed the recovery constant are not passed through `str.format`; only the username is substituted. |
| 19 | Two `tests/test_user_seal.py` loader-census failures: the census expects `_verified`, the head reads through `_verified_checked` | **Fixed in build, with the test unchanged:** `_verified` stays the only user loader and returns the cause itself, so the census holds as written. |

No item from 10 to 17 is kept, so none needs an owner ruling to keep it. The answers they rest on,
(b) to (e), need the ruling the Status line names.

### The duplicate question

#6357 ("Under the vault_transit cipher, authz_root would return None ...") is a **duplicate** of
#4350 as #4350's note of 2026-10-26 widened it (no row seals at all under `vault_transit`), and
both are #2592's Transit limb. #6357 adds one point neither states: no posture entry says that
`vault_transit` runs without row seals. That point is **moot once slice 1 lands**, since seals then
exist; if the build is not dispatched, it is a small build of its own (a `security_loosenings()`
entry while the provider has no sealer). The recommendation is to close #6357 as a duplicate of
#4350 carrying that point, and to close #4350 with #2592's Transit limb when the build merges.

## Build plan

A fresh branch from `main`. PR 2565's branch is a reference only, 217 commits behind; nothing is
cherry-picked wholesale. Slices 1 to 4 merge together in one pull request: slice 1 alone would
read an unverifiable map as a failed one, which is (b)'s rejected second alternative. Every slice
is fail-closed on its own head.

| Slice | What | Paths | Tests |
|---|---|---|---|
| 1 | The Transit sealer and the four answers; async seal seams on every backend; the start probe; `RowSealError(kind, cause, subject)`; the required `transit/verify` capability | `store/row_seal.py`, `store/crypto_transit.py`, `store/crypto.py`, `store/store.py`, `store/postgres.py`, `store/sqlserver.py`, `store/base.py`, `pipeline/engine.py`, `api/app.py`, `privilege_check.py`, `scripts/security/crypto_inventory_check.py` | new `tests/test_transit_row_seal.py` and `tests/_transit_seal_fake.py`; the seal contracts (`tests/_*_seal_contract.py`); `test_row_seal.py`, `test_crypto_transit.py`, `test_postgres_store.py`, `test_sqlserver_transit_row_seal.py`; item 12's args test |
| 2 | Service loaders and reporting: the unverifiable action, subjects and cap with the map exemption, the sign-in refusals of (e), the CLI mapping of (c) step 3 | `auth/service.py`, `pipeline/alerts.py`, `pipeline/security_signals.py`, `cli_common.py`, `api/auth_routes.py`, `api/approvals.py` | `test_user_seal.py` (run unchanged, item 19), `test_session_seal.py`, `test_role_seal.py`, `test_approval_seal.py`, `test_api_auth.py`, `test_security_signals.py`, `test_provision_first_administrator.py` |
| 3 | AD sign-in deny, the reconciler's end-sessions rule and the per-map latch of (b) | `auth/service.py`, `auth/reconcile.py` if the breaker count needs a new input, `api/app.py` (lifespan paging) | `test_ad_session_reconcile.py`, `test_mfa_directory_recheck.py`, `test_reauth_directory_demotion.py`, and new cases: a planted unverifiable map ends a demoted account's session within one pass; a sink failure leaves the map unlatched; a move between maps pages again |
| 4 | Role delete and map edits of (d), the console 409 | `auth/service.py`, `store/store.py`, `store/postgres.py`, `store/sqlserver.py`, `messagefoundry_webconsole/routes/admin.py` | new cases for items 14, 15 and 16; the web console suite under `packaging/messagefoundry-webconsole/tests` |
| 5 | Docs, in the same pull request | `docs/PHI.md`, `docs/SECURITY.md`, the changelog fragment | the doc tests that pin those files |

No step is met by loosening an existing check or test. The hosted PostgreSQL, SQL Server and
`windows-service-smoke` legs must be read on the build's head.

## Consequences

**Positive.** An unverifiable seal, which a database writer can produce at will, is never weaker
than a forged one: it denies, audits and pages. The reconciler can no longer be frozen by a
planted seal. Each refusal is audited under its true cause, and the burst signal stays a
credential signal.

**Negative.** A Vault fault or lag signs directory accounts out and refuses their sign-in; a
genuine row sealed under a version not yet on the answering node is denied for the lag. The
operator's recovery for a retired version is manual (lowering `min_decryption_version`) until the
verify-then-reseal tool (item 2) exists. Read-modify-write writes hold the writer lock across a
Transit call until item 1's row is built.

**Neutral.** `main` without `vault_transit` is unchanged: the local sealer never answers
Unverifiable or Outage.
