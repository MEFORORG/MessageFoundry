<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors -->

# 0217 -- An unverifiable Transit row seal is denied like a failed one, and the AD reconciler ends sessions rather than holding

- **Status:** Accepted (2026-11-06 (UTC), by owner ruling; *Owner rulings*, below, quotes it) --
  design only, no code yet. Every answer below marked `CONTROL DECISION: yes` changes what a
  sign-in, a reconcile or a write refuses, pages or audits. *Owner rulings asked*, below, is the
  list the owner was asked at `94b485c2e1`, with the differences *Owner rulings* names.
- **Date:** 2026-11-05
- **Related:** vault BACKLOG #4739 (this design), #2592 (its parent: identity and authorization
  row seals), #4350 and #6357 (the `vault_transit` seal gap; see *The duplicate question*), #3411
  (the store-id pin) -- engine PR 2565 (draft, parked by the owner ruling
  of 2026-10-28, comment `6474801844`; branch `b435-2592-transit-seals` at
  `e48a5780750ee137c503cdd32082006e695d0368`, the reference implementation this design reads) --
  [ADR 0138](0138-transit-bulk-crypto-provider-dek-out-of-engine-heap-for-asvs-13-3-3-demand-gated.md) (the Transit cipher)

---

## Owner rulings asked

Each is a `CONTROL DECISION: yes` below. Confidence is in the recommendation.

1. **(a) Unverifiable denies like Forged**, with its own audit action and subject, and any 400
   with a working probe is Unverifiable; lagging, retired and planted are triage detail only.
   Recommend: yes. High. Would change if Transit could tell a planted version from a lagging node
   in its reply.
2. **(b) A map that does not hold** (Unverifiable, Forged, or an empty map whose new seal fails;
   Forged and the sealed empty map change `main`): directory sign-in and the certificate leg refuse
   while a map is Unverifiable; the reconciler writes no role row and ends sessions in two steps
   under the unchanged brake: first `main`'s own plan with each such map read as empty, and where
   that trips, the PRESENT accounts whose groups moved since a new sealed record
   (`users.directory_groups_digest`); a trip of the second step applies nothing, as on `main`. A map
   row that reads Outage takes the second step alone. A failing user row is still probed, but its
   outcome feeds only its own revocation, by its own strike count: it is left out of the brake's
   count, of `probed`, of the ADR 0195 hold's counts and latch, and of the outcome record, and
   ranked last for the probe budget, so a planted failing row can at worst revoke itself. An
   Unverifiable or Forged map pages every pass under its own uncapped subject; a map-row Outage
   pages under the shared Outage subject. Unlike `main`, a Forged-map pass whose step 1 trips and
   whose step 2 does not resets no `_reconcile_unconfirmed` and writes no
   `auth.ad_reconcile_aborted`; the per-map page replaces both. Recommend: yes.
   Medium. Would change if the owner reads the step-1 trip as directory evidence (then step 2 is a
   loosening), or if the digest cannot be kept current.
3. **(c) Two sibling refusal types and a catch census**: `RowSealUnverifiableError` is not a
   `RowSealError`, every catch site audits and the service reporter pages, and a narrowing write to
   an Unverifiable row is refused while the account's sessions are ended. Recommend: yes. Medium.
   Would change if the owner would rather seal a disable over unchecked content than lose it after
   a lag.
4. **A session end never rolls back** (b): when an epoch raise cannot be written the sessions are
   still marked revoked and the raise is owed, refusing the account's sessions until a
   long-running engine process's retry lands; sessions stay refused meanwhile; one bad row never rolls back a global sign-out; "sign out everywhere else" ends the
   caller's own session too while the raise is owed. Recommend: yes. Medium. Would change if the
   owner prefers to accept the epoch gap rather than add the owed-raise table.
5. **(d) A role delete takes effect**: while a holder or the map is Unverifiable, the role is
   retired (its permissions emptied, a sealed `retired` flag set) rather than deleted, the
   Unverifiable rows are left untouched and grant nothing through it, no write may touch the role
   row or add a reference to it while such a row names it, and it is deleted once none does; an acknowledged full map replacement (`replace_unverifiable`) whose pairs are
   never served back; an operator's Reject tombstones an Unverifiable pending approval, as #3638
   does for a failed one. Recommend: yes. Medium. Would change if the owner wants no new column or
   API surface, leaving the planted cases to raw recovery.
6. **(e) Seal-state and outage-refused sign-ins write their own actions and count 0** toward the
   burst signal; a sign-in whose credential already failed counts 1 whatever follows. Recommend:
   yes. Medium. Would change if the owner wants every refused sign-in counted, accepting burst
   alerts during a Vault fault.
7. **Residuals accepted by name:** no cross-store binding until #3411; a rollback of a sealed row
   (a user row with a plant, a map to an earlier state, the empty map included, or a deleted
   owed-raise row) is caught only once rollback detection lands (#2592 step 7); up to 60
   seconds of cached trust after a version retirement; Transit time overrunning the sign-in pad; a
   Forged scope map keeps a manual stored scope at sign-in and on the certificate leg, as on
   `main`, recorded on #2592; no carry-across off a retired Transit key while `rotate-key` stays
   refused under Transit (#1165, item 2's tool); failing rows' revocations judged without the
   brake's count or the hold when most rows fail at once; in a large estate with no digests yet,
   step 2 trips and applies no revocation on every pass while a map does not hold, until an
   untripped verified pass writes the digests. Recommend: accept. Medium. Would change if the owner wants the
   rollback case closed before #2592 step 7.

## Owner rulings

The owner ruled on every entry on 2026-11-06 (UTC), in the Manager's chat, on this ADR at
`94b485c2e15f541a5177f6e2fe213140bcf0fff2`; the verbatim record is engine PR 2565 comment
[6676450688](https://github.com/MEFORORG/MessageFoundry/pull/2565#issuecomment-6676450688). The
selections, verbatim:

- Rulings 1, 3 (core), 4, 5 and 6: **"Approve as recommended (Recommended)"**.
- Ruling 2: **"Run step 2 (Recommended)"**.
- Ruling 3, a narrowing write to an unverifiable user row: **"Refuse, end sessions (Recommended)"**.
- Ruling 7: **"Accept as listed (Recommended)"**.

**What differs from the ruled text at `94b485c2e1`** (every difference `git diff 94b485c2e1` shows
in this file, apart from this section, the status line and *Open findings carried to the build*):

1. Ruling 2, its body paragraph on failing rows, the control summary and a slice 3 test: a failing
   user row's outcome is left out of the ADR 0195 hold's `u` and `r`, its latch and
   `_reconcile_outcomes`; a failing UNDETERMINED row is held while the verified rows' hold is on;
   "or a held one" is dropped from the cases where its revocation is not applied. This changes
   what the reconciler holds and revokes. The owner was told: it is the verifier's confirmed
   defect, named in the ruling record as in progress.
2. Ruling 2, the body and the control summary: a sentence that a Forged-map pass whose step 1
   trips and whose step 2 does not resets no `_reconcile_unconfirmed` and writes no
   `auth.ad_reconcile_aborted`. That changes what is audited against `main`, but it adds no
   behaviour: the ruled body already said a step-1 trip is not recorded as a breaker trip, with a
   slice 3 test for it. The owner was not told that it was added to the list.
3. Ruling 4 and the retry paragraph: the "30-second retry" becomes a long-running engine
   process's retry, and the claim that every caller, the CLI included, is covered is replaced by a
   short-lived CLI process's raise landing on a later engine process's retry. This corrects a false
   claim and changes no control. The owner was not told.
4. Ruling 7 and one body sentence: "or the hold" is added to the failing-rows residual, which
   follows from difference 1, and the step-2 window in a large estate with no digests is added to
   the list and named a residual in the body; the ruled body
   already named that window, and the ruling question put to the owner named it. The owner was
   told of both.
5. The retry paragraph: a sentence that `main`'s `revoke_all_sessions` already raises the global
   epoch first (#5091). It states `main` and changes nothing. The owner was not told.
6. *The strict parse*: a sentence that a Transit MAC whose body does not re-encode to the same
   text is Forged. It narrows what is well-formed, so a planted pad-bit variant of a genuine seal
   is Forged with no Transit call. The owner ruled it on 2026-11-07 (below).

Confirmed 2026-11-06 (UTC): the owner was asked about the five differences above, and about the
carried findings below, and selected 'Confirm current text (Recommended)'. Record:
https://github.com/MEFORORG/MessageFoundry/pull/2565#issuecomment-6682609779. Anchors: branch
anchor/adr0217-owner-ruled-20261106 (94b485c2e1) and branch anchor/adr0217-owner-confirmed-20261106
(ae898dc817).

Difference 6 was added to the list after that confirmation. The five it confirmed are differences
1 to 5; difference 6 rests on the owner's ruling of 2026-11-07, recorded next.

**Build rulings, 2026-11-07.** The owner answered three questions the slice 1 build raised, in the
Manager's chat (`AskUserQuestion`), and the Manager relayed them to the build. No PR comment or
anchor records them yet; this paragraph is the record in this file.

- **The strict parse:** "add the sentence" -- difference 6 above.
- **The start probe:** it also makes a fixed-input `transit/verify`, so a token without the verify
  grant on the audit key is refused at start, not at the first request.
- **A session sealed under a retired key:** the store's write check reports it as its own type,
  `RowSealKeyRetiredError`, not `RowSealError`, found in the one check with no further Transit
  call. Asked where the quiet end happens, the owner selected **"Quiet end at callers"**: the
  store raises the type, and the four `AuthService` session sites (`_sealed_stamp`,
  `rotate_session`, `revoke_other_sessions`, `revoke_every_session`) and the store's
  `_keep_or_end_session` end the session quietly with `key_changed=True`, built with the catch
  census on all three backends together. Until then the SQLite session writer turns the type back
  into `RowSealError`, as `main` raises. In that list, `rotate_session` names the rotation site in
  `AuthService`, `_rotate_session_hash`, which calls the store's `rotate_session`.

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
below may let an unverifiable seal grant or keep any authority that the last verified state did not
give, or freeze a revocation a failed seal would not**. That is the test each answer is held to.

## Decision

### The four answers, defined once

| Answer | What Transit (or the parse) returned | Sealer raises / returns | Decision | Audit action | Alert subject (`integrity_drift`) |
|---|---|---|---|---|---|
| **Holds** | `verify` HTTP 200, `valid: true` | `True`, cached (see *The success cache*) | allow | none | none |
| **Forged** | `verify` HTTP 200, `valid: false`; or the stored seal fails the strict well-formed parse (below), with no Transit call | `False` | deny the row (a session is ended, a user, role or map grants nothing, a write is refused) | `integrity.authority_seal_failed` | `AUTHORITY_SEAL_SUBJECT`, as today; a directory map pages under its own subject, (b) |
| **Unverifiable** | `verify` HTTP 400, and the fixed-input key probe (`hmac` over a constant) then answers with a well-formed MAC, whatever version it names | `TransitSealUnverifiableError` | deny the row, with three limits: it never tombstones or raw-deletes a user, role, map or approval where Forged would (ending a session is allowed, since signing in replaces it); the AD maps follow (b) and (d); a write that keeps the row's stored values is refused, while an operator's explicit delete of the row, full replacement of it (a map's only with `replace_unverifiable`, (d)), or Reject of a pending approval (below), which keep none of its values, is allowed and audited | `integrity.authority_seal_unverifiable` | `authority-seal-transit-unverifiable:<kind>:<ref>:<digest suffix>` (*A ref is for reading*), capped; the two Unverifiable AD map subjects, fixed names with no ref or suffix, are exempt from the cap |
| **Outage** | any other `verify` failure (network, timeout, 5xx, 403, malformed reply), or a 400 the probe cannot clear; except that a 400 or 403 on a seal naming a retired key, while the active key's probe works, is Unverifiable (*The key id, and a retired key*) | `TransitSealUnavailableError` | refuse the request or roll back the write; end nothing, except that (c) ends an account's sessions after a refused narrowing write; record no seal failure | none for the row; the refused request itself is audited where the audit append still works (many outages, such as a 403 on `verify` alone or a timeout, leave it working), a refused sign-in as `auth.login_refused_unavailable`, (e); a throttled ERROR log line is the record only when the append fails too | `authority-seal-transit` |

**The seal input is a fixed-length digest.** The sealer sends Transit not the row's encoding but its
SHA-256: `seal = Transit hmac(SHA-256(label || store id || seal_bytes(kind, fields)))`, each part
length-prefixed as today. So every `hmac` and `verify` call carries 32 bytes whatever the row
holds, a database writer cannot inflate a row into a request Vault refuses as too large (HTTP 413)
or too slow (a timeout), and no new refusal of large map saves is needed. The HMAC of a
collision-resistant hash is as strong as the HMAC of the message. The same digest is the success
cache's key part for the input, so nothing is hashed twice. Rejected: a size bound tied to Vault's
request limit, since `max_request_size` is configured per deployment and the engine cannot read
it; one set from Vault's default would still let a writer draw a 413 from a Vault configured
lower. The digest also keeps every token hash and row value out of anything Transit receives, and
so out of any Transit error text a chained exception carries (item 12).

**The strict parse.** A stored seal is well-formed only when it is `mfseal:v1:<key id>:` then
`vault:v<N>:` with `N` of 1 to 10 digits and no leading zero, then base64 that decodes **strictly**
(`validate=True`) to exactly the SHA-256 digest length. Anything else is Forged with no Transit
call, so no malformed body reaches Transit to draw a 400. A Transit MAC whose body does not
re-encode to the same text is Forged (owner ruling 2026-11-07).

**The key id, and a retired key.** `<key id>` is `row_seal_key_id` of the SHA-256 of the Transit
mount and the audit key's name, which is not secret. A seal naming another key id is checked as the
local sealer checks one (`row_seal.py`): the sealer is also given the store's retired Transit key
names (a new `retired_transit_audit_keys` setting, the counterpart of `retired_authz_roots`), and a
seal naming one of them is verified under that key. A 400 or a 403 from that `verify` (Transit
capabilities are granted per key, so a token may hold none on a retired key) is classified by the
probe of the **active** key, as the 400 rule is: Unverifiable while that probe works, so a writer
who names a retired key gets a deny and an integrity record rather than a 503, and an Outage when
it fails. Any other failure (network, timeout, 5xx) stays an Outage. A user row so sealed is
accepted, as `verify_held` accepts one; a session so sealed is never accepted and is ended
quietly, as `sealed_by_retired_key` lets it be. A seal naming a key id the sealer does not hold is
Forged. **Residual: nothing carries a row off a retired Transit key.** `rotate-key` is refused under
`vault_transit` on `main` (`reencrypt_to_active` raises for a non-AES cipher, BACKLOG #1165, before
any re-seal runs), and this ADR does not lift that, so a row stays on the retired key until it is
next written, and the old name must stay listed until then; the verify-then-reseal tool (item 2)
is where a carry-across belongs. The docs slice says to keep `transit/verify` on every listed
retired key, since without it every row under that key reads Unverifiable for as long as it is
listed, and that changing the key without listing the old name denies every row.

**The success cache.** A Holds answer is cached for 60 seconds (within every
`session_idle_timeout_minutes` setting), keyed by a digest of the **seal input's SHA-256 (above), the key id the seal names and the
stored Transit string**, never by a row id or the seal alone, so a change
to any sealed field misses the cache. The cache is emptied whenever a refused check's probe names
a different latest version than the last one did, and a check that began before that emptying
keeps its answer for its own caller only. Every request still reads the row afresh, so a blanked
seal or a bumped epoch takes effect at once.

**The refusal cache.** A Forged or Unverifiable answer is cached the same way for 60 seconds, under
the same key, and it is emptied with the success cache, which is what ties an Unverifiable answer to
the probe's version. A Forged answer is a property of its key, so caching it changes no decision; an
Unverifiable one can outlive the lag that caused it by up to 60 seconds, which only extends a
denial. An Outage is never cached. The cache bounds what planted rows cost Vault: each pays its
Transit calls once per window, not on every scan (item 3.5), and an Unverifiable hit skips the
probe (item 3.r6). The sign-in path checks a user row past both caches, (e) says why; a hit never
skips the audit row or the throttled page a refusal writes.

**The probe rule differs from the audit chain's.** The audit chain reads a 400 as a version
refusal only when the probe names a different version (`crypto_transit._refuses_only_version` on
`main`). A row seal reads **any** 400 with a working probe as Unverifiable, whatever version the
probe names. A planted seal naming the latest version, checked on a lagging node while the probe
reaches a caught-up one, would otherwise read as an Outage: a 503 that ends nothing and writes no
integrity record, the loosening (a) rejects. Item 3.6's shared helper returns the probe's answer and
each caller applies its own rule, so the audit chain's classification does not change. The cost is
that a genuine row checked on a lagging node is denied and recorded as Unverifiable, which (a)
already accepts. With the strict parse and the fixed-length input, no other 400 is known; the
build lists any it finds.

Every throttle on a report, the audit throttle and the per-row page throttle alike, is keyed by
the cause **and** the subject, so a report of one cause never suppresses a report of the other on
the same row.

The API answers an Outage with HTTP 503 and `Retry-After`, an Unverifiable write refusal with HTTP
409 and fixed recovery text, and the CLI each with one error line and a non-zero exit. The
`<ref>` of a session is the first 12 hex characters of its token hash (`main`'s
`_SESSION_REF_LEN` in `auth/service.py`, which the build moves where the store can import it),
never the whole hash, everywhere: log line, audit detail, alert subject, exception arguments, `str()`,
`repr()` and any chained cause a traceback logs. The `<ref>` of any other row is its stored id,
which a database writer chooses, so it is scrubbed of control characters and bounded with
`main`'s one rule for shortening an alert subject (`shorten_with_checksum`) before it reaches a
subject, a reason or an exception. No other field of a row ever does.

**A ref is for reading, never a key.** A 12-character prefix and a shortened id both collide, and a
database writer who can read a genuine row can plant one that shares its ref. So every throttle and
the unverifiable-row cap are keyed by the SHA-256 of the kind and the **whole** stored id, held in
memory only; the whole digest is never written to a subject, a log line, an exception or an audit
row. Every alert subject, a session's included, is `<prefix>:<kind>:<readable ref>:<the first 16
hex characters of that digest>`, so a planted row that copies a genuine ref still pages under a
subject of its own. The digest is of the
stored id, never of a token, so it gives nothing toward a session (item 12's test covers it).

### (a) A `verify` HTTP 400 while the fixed-input probe works

**Answer.** It is **Unverifiable**, a deny class equal in effect to Forged, as round 5 (comment
`6466545392`) made it, and the lagging-node special case stays removed. Lagging, retired and
planted are not separate decisions, because Transit's reply cannot tell them apart and a database
writer can produce any of them. They are told apart only as *triage detail*: the audit row and the
page carry `stored_version` (the integer the stored seal names) and `probe_version` (the integer
the probe's MAC names, the latest version on the node that answered the probe). Both are integers
of at most ten digits parsed from Transit-shaped strings, so they carry no row data. No decision
reads them. The recovery text tells the operator, in this order: the seal may be planted; check
that Vault is healthy and that every node holds the audit key's latest version, then retry; a row
that still does not verify is untrusted and is re-created from an authoritative source (an
account re-provisioned, a role or map entered again from its change record), never from its
stored values. **The recovery never lowers `min_decryption_version`.** Lowering it would re-trust
every retired version for every row, and, since the audit key defaults to the data key, for the
audit chain and for decryption too; a save during that window would re-seal a rolled-back copy the
retirement was meant to invalidate. Rows under a version about to be retired are re-sealed by the
verify-then-reseal tool (item 2) **before** the minimum is raised.

Outage is told apart from Unverifiable by the probe alone, under the probe rule above. One probe
call per refused check stays (see item 3).

- **Control kept:** an unverifiable row never grants, never keeps a session, and is always
  audited and paged as an integrity event. A planted unheld version is never downgraded to a
  retryable 503 that ends nothing and records nothing.
- **Failure accepted:** a genuine seal checked against a node that lags a key rotation is denied
  for the length of the lag: a session so checked is ended, and its user signs in again (on a node
  that has caught up); a write so refused is retried by its caller; an approval is denied, never
  tombstoned. How long a lag lasts depends on the deployment's Vault topology (replication and
  performance nodes can lag further than a single cluster) and is not measured here.
- **Residual: no store binding until #3411.** The seal input carries the store id, but every store
  passes `NO_STORE_ID` until the store-id pin (vault #3411, the owning row) lands, and the Transit
  key is named by configuration. So two stores sealing under the same Transit key (the audit key,
  which defaults to the data key) accept each other's sealed rows: a writer to one store could copy
  in an Administrator row sealed by another. The local sealer has the same property for two stores
  sharing one store key, since it too derives under `NO_STORE_ID`. Until #3411, the docs slice
  tells an operator to give each store its own Transit key or `MEFOR_STORE_TRANSIT_AUDIT_KEY`.
- **Residual: a retirement is trusted from the cache for up to 60 seconds.** The success cache is
  emptied only when a probe sees the latest version move, and raising `min_decryption_version`
  does not move it, so a row under the version just retired keeps answering Holds from the cache
  until its entry expires. Raising the minimum with rows still under the retired versions denies
  every one of them (Administrators included) with re-creation as the only recovery, as the
  Negative consequences say; the verify-then-reseal tool (item 2) is where a census of rows by
  sealed version belongs.
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

**Reconciler. Answer: deny, by ending sessions, never by holding, and never past the brake.** On a
pass where either map **does not hold** (Unverifiable, Forged, an empty map whose seal fails, or an
Outage on the map row), the reconciler writes no role row (a write from an unchecked map would
replace genuine assignments, and the reconciler writes no scope on `main` either, ADR 0198) and
plans to **end the live sessions** of the accounts the map could concern, in two steps, each judged
by `main`'s breaker exactly as `main` judges a pass, together with the pass's ABSENT, DISABLED and
other striking revocations:

1. **`main`'s own plan first.** The pass runs `main`'s plan with each map that does not hold
   read as empty, as `main` reads a Forged map, and drops **only** its role writes. It keeps every
   revocation that plan makes, including the session ends of every holder that empty role map
   would demote and of every account an empty scope map would withdraw from. Where that plan does not trip the brake it is applied, so below the thresholds the
   pass revokes everything `main` revokes on a Forged map, and only the role writes are left out.
2. **Where step 1 trips, the groups-moved set.** This design reads that trip as caused mostly by
   the map's state, which the pass already knows is bad, rather than as evidence about the
   directory, and so plans a narrower set and judges it from scratch; that reading is the question
   owner ruling 2 puts, since step 1's set also holds the pass's offboardings: every PRESENT directory account whose **probed
   groups differ from the groups recorded at its last verified decision**, read without the map's
   pairs, since a writer who planted it chooses them. An account whose groups have not moved since
   then would get the same roles from the same genuine map, and a genuine edit of a map ends every
   directory session (`set_ad_group_map` and `set_ad_group_scope_map` revoke them on `main`), so
   leaving such an account signed in retains nothing a verified pass would take away. Where this
   set trips too, the pass applies nothing, as `main` does on every trip. That trip reads the
   directory and the stored digests, so missing or stale digests can drive it too, as the next
   paragraphs say.

A pass whose maps both hold keeps `main`'s rule unchanged, a verified empty map included. Forged is
in this rule, which changes `main`: there a Forged map's set trips the brake in any estate past
about five accounts and the pass applies nothing, so a writer who chooses Forged over Unverifiable
freezes every revocation of the pass. Step 1 keeps `main`'s answer wherever `main`'s answer
revokes; step 2 replaces only the freeze.

**A map row that reads Outage takes step 2 alone.** Step 2 reads only the probe and the digest,
so it still runs; step 1 needs the map, which was not read, and a single timed-out call must not
sign out every role holder. The map pages under `authority-seal-transit`.

**A user row that does not verify keeps its offboarding.** On `main` the pass builds its candidates
from `_load_users`, which drops a failing row and prunes its strikes. A row can fail and later
verify again, an Unverifiable one after a lag and a Forged one when a writer puts the original seal
string back, so a writer who toggles a disabled account's seal around each pass would keep its
strikes from accruing. So a directory row read Forged, Unverifiable or Outage is **still probed**,
under its raw stored directory key, and its outcome is judged by `main`'s rules (its strike
threshold, and the UNDETERMINED and UNKEYED outcomes alike), with four differences: its result is
used **only to revoke** that account, by its own strike count, never to write, grant or confirm;
it is **left out of the brake's count and of `probed`**, so failing rows a writer inserts can
neither trip the brake nor dilute its fraction; it is **left out of the ADR 0195 hold**, of `u`
and `r` (`reconcile.plan_pass` counts them over the outcome record and every probe, on `main`
only verified rows reach it), of the latch, and of `_reconcile_outcomes`, so two planted failing
UNDETERMINED rows cannot engage or latch the hold and freeze a genuine revocation, and a failing
row read PRESENT cannot raise `r` and loosen it; a failing UNDETERMINED row is itself held
while the hold the verified rows engage is on, and otherwise strikes; and it is **ranked after
every verified candidate** for the per-pass probe budget, so inserted rows cannot starve a genuine
one. Its revocation rides the pass: on a tripped pass nothing is applied, it included.
**Failure accepted:** where most of an estate's rows fail at once (a lag or a partial Vault fault)
while the directory misreports, the failing rows' revocations are judged without the brake's
count or the hold's, so those see only the verified rows; if those alone do not trip or hold, the
failing ones are revoked. A failing row can be used meanwhile on a node that verifies it, so that is a lost
session, not a lost nothing. The
loader reads each row on its own, so one row's Outage never stops the scan; the pass aborts as
`seal_unavailable` (below) only when the probe of the active key fails too.

**A map save keeps `main`'s order and stops on no row.** On `main` the save commits the map and
then lists the accounts to revoke through the seal-checking loader, which drops a failing row and,
under Transit, would stop on one row's Outage after the map had committed. The build keeps the
order (map first, so the #1154 window stays as narrow as `main`'s) and only changes the listing:
accounts are chosen from the raw `users` rows without checking their seals (ending needs no key,
and a wrongly included account only signs in again), so every account whose row fails, Forged or
Unverifiable, is included and no row's Outage stops the loop.

**The group record is new state, and it is sealed.** No such record exists on `main`: `UserRow`
holds no group field, and a probe's `groups` live only for the pass. The build adds one column,
`users.directory_groups_digest`: the SHA-256 of the account's group keys as `main` normalizes them
(`ad_group_keys` in `store/store.py`), sorted and length-prefixed. It is written only on a verified
decision: by a directory sign-in that read both maps verified, in that sign-in's own write, and by
a reconcile pass that read both maps verified and did not trip, which writes it for **every**
probed PRESENT account whose digest differs from the stored one, in a digest-only sealed write of
that user row when the pass writes no role for it. A pass that trips, aborts, or reads a map that
does not hold writes no digest. `USER_SEAL_EXCLUDED` leaves out only `authz_seal`, so the column
is inside the user seal from the start, and a writer who edits it makes the row fail, which denies
the account. An account with no digest yet counts as differing. The digest stores no group name,
and it covers every group, not only the mapped ones, since restricting it would need the mapped
group set stored and sealed as well.

**What step 2 trips on under the default brake.** `main`'s breaker (`reconcile.breaker_tripped`)
trips when a pass would revoke more than `ad_session_revoke_max` (5) **and** more than
`ad_session_revoke_max_fraction` (0.34) of the accounts it probed: 40 probed accounts need at least
14 revocations, and an estate of any size needs at least 6. Step 2 counts accounts whose groups
moved since their last verified decision together with the offboardings, so it **can** trip where
a verified pass would not: 14 of 40 accounts added to an unmapped group revoke nothing on a
verified pass. An account with no digest also counts; the first untripped verified pass writes every
probed account's digest, so that window closes then, and if a map does not hold through the whole
window a large estate trips step 2 on every pass while that lasts, since directory sign-in is
refused too. That window is a residual named in ruling 7: no revocation is applied meanwhile.

**Residual: a rollback with a plant, owned by #2592 step 7.** A writer who restores an older,
genuinely sealed copy of a user row (stale roles, the digest they were decided under, the old
epoch) and a matching session row, and then makes a map fail to hold in an estate large enough
that step 1 trips, keeps that session: its groups have not moved since the restored digest, and
the role diff that would catch the stale roles needs a map that holds. Nothing in this design
closes it. Only rollback detection does (the store binding of #3411 and the rollback check #2592
step 7 owns); a map that holds still catches it on the next pass, as on `main`.

**A tripped pass writes nothing**, as on `main`: no role, no digest and no username rename, since
`main`'s "an aborted pass must leave the store byte-identical" covers renames. A step-1 trip is not recorded as a
breaker trip, because it is not one: step 2 is judged afresh, and `aborted`, the breaker standing
and the episode tracker see only step 2's result. But a pass where a map did not hold judged no
role or scope against a map, so it **confirms nothing**: it removes no account from
`_reconcile_unconfirmed` and sets no `breaker_clear` (`main` counts a PRESENT read on a pass that
did not abort as that evidence), a missed clear and never a false one. The map's own page (below)
is the record that the map did not hold; for a map-row Outage that page is the shared
`authority-seal-transit` one. This changes `main` for a Forged map: there the step-1 set trips,
so the pass resets `_reconcile_unconfirmed` to every keyed account and writes
`auth.ad_reconcile_aborted`; here, where step 2 does not trip, it does neither, and the per-map
page replaces both.

**The apply order.** For each account the pass ends the sessions first and then writes its role
rows and its digest in one sealed write. A role write that fails (an Outage on that row's `hmac`)
is recorded for that account and does not stop the loop, so one row's fault never skips the
revocations after it. On `main` the role write comes first.

**The session end and the epoch.** On `main`, `revoke_user_sessions` marks the account's session
rows revoked (`revoked_at` set, seal blanked) and raises the account's session epoch through
`_write_user` (`_bump_session_epoch`) in one writer transaction; with `except_token_hash` it also
re-seals the kept session through `_write_session`. `_bump_session_epoch` catches only
`RowSealError`, so under Transit an Outage on either `hmac`, or on the kept session's `verify`,
would roll the whole revocation back, and `revoke_all_sessions` raises every account's epoch in
one transaction, so one bad row would roll back a global sign-out. The build keeps the one
transaction and lets **no Transit call in it stop the revocation**:

- When an account's raise cannot be written (an Outage, or a user row that fails, which the store
  never re-seals), the transaction still marks its sessions revoked and writes an **owed raise**
  instead: a row in a new `session_epoch_owed` table, which needs no seal. While an account has an
  owed raise, every session of it is refused on read, so a restored older copy of a revoked session
  row grants nothing.
- When the kept session cannot be re-sealed, for any Transit failure or because its raise is owed,
  `KeptSessionRestamp` declines and `_keep_or_end_session` ends it with the rest, the conservative
  answer: "sign out everywhere else" then signs the caller out too.
- `revoke_all_sessions` raises the global session epoch first, a counter update with no seal, and
  owes the raise of any account whose own cannot be written.

A store task in every process that opens the store retries each owed raise every 30 seconds
while that process runs, raising the epoch and deleting the owed row in one transaction once the
user row verifies and `hmac` answers, and a failing row's raise lands when it verifies. A
short-lived CLI process can exit before its task fires, so its owed raises land on a long-running
engine process's retry, and the account's sessions stay refused meanwhile. `main`'s
`revoke_all_sessions` already raises the global epoch first (#5091). Each failed retry reports under its cause's own subject
(`authority-seal-transit` for an Outage, the row's integrity subject for a failing row), with
repetition left to the sink's re-alert throttle, as for the map page.
**Residual:** the owed row is unsealed, so a writer who deletes it and restores an earlier copy of
the revoked session rows revives them once the user row verifies. That is a rollback of store
state, the class #2592 step 7 owns, and it needs the write access the seals assume an attacker has.

**Other legs that read a map** decide access and write nothing: at least the client-certificate
identity (`identity_for_cert_user_id`), the step-up role test (`_directory_roles_lost`) and the
enrolment and re-bind legs. On the step-up, enrolment and re-bind legs an Unverifiable map takes
`main`'s failing-map branch: `_directory_roles_lost` tells a failing map apart through
`_sealed_ad_map` and refuses with `DIRECTORY_ROLE_MAP_UNSEALED` rather than reading every role as
lost (#3082), so the operator is not told to sign in again while sign-in is refused too. **The
certificate leg refuses the identity** (returns `None`) while either map is Unverifiable, as
sign-in does, because an empty scope map does not narrow: `decide_ad_channel_scope` keeps a manual
stored scope when the mapped set is empty, so "grants nothing" would keep a wider scope than a
holding map gives.

**Residual: a Forged scope map keeps a manual stored scope on `main`, at sign-in and on the
certificate leg.** Both read a Forged scope map as empty, and the same rule keeps a manual stored
scope. This ADR does not change Forged sign-in or certificate behaviour; the build records it as an
item on #2592. An Unverifiable scope map refuses on both legs, so the gap stays the Forged map's.

**Other readers of another row's seal never propagate Unverifiable.** A check that reads rows other
than the one it decides on, at least `admin_guard_counts` (the last-Administrator guard), counts an
Unverifiable row as it counts a Forged one on `main`: as not counting toward any grant, and never
as an error that aborts the check. A guard that would then see no Administrator refuses, as on
`main`.

**A Vault-wide Outage aborts the pass, and is never a trip.** A map row that reads Outage while the
active key's probe works takes step 2 alone, above. Where the probe fails too the Outage is
Vault-wide, and the pass aborts under its own slug,
`seal_unavailable`, which the build adds to `judged_nothing` (a pass that verified no account
judged nothing), so it changes no breaker standing, resets no `_reconcile_unconfirmed` and records
no breaker episode; it is not `OUTAGE_ABORT`, so `directory_outage` and the directory's outage-run
paging never see it. Each such pass writes an `auth.ad_reconcile_aborted` audit row with reason
`seal_unavailable`, and the lifespan task pages it under its own source label,
`directory-reconciler-seal`, beside the referral's and the fault's, with text naming Vault transit.
Its inverse, `seal_clear`, is set on a pass that read every user seal without an Outage, and raises
`ad_reconcile_breaker_cleared("directory-reconciler-seal")` under the same sole-reconciler and
inherited-clear rules as the other clears. No access is retained meanwhile, since every
authenticated request also checks its session's seal past the 60-second success cache and meets
the same Outage.

**The map page has no latch, and an Unverifiable or Forged map always pages as itself.** Every pass
that reads a map Unverifiable or Forged pages it under that map's own fixed subject:
`authority-seal-transit-unverifiable:adset:<map name>` for Unverifiable and
`authority-seal:adset:<map name>` for Forged (on `main` a Forged map pages under the shared
`AUTHORITY_SEAL_SUBJECT` through a 300-second throttle, where a flood of other forged rows can hold
it). Neither goes through the sealer's per-row throttle or a latch; repetition is left to the
sink's own per-subject re-alert throttle. An engine cannot learn whether a page was delivered
(`AlertSink.integrity_drift` returns nothing, and the notifier only enqueues), so a latch that
suppresses later pages can always lose the only one. With none, a lost page is bounded by one sink
re-alert interval: the sink stamps its last-sent time before it enqueues, so an enqueue that fails
costs that page, and the next pass after the interval pages again. A move from one map to the
other is a new subject and pages.

**The empty map is sealed too.** `ad_map_seal_ok` returns True for a map with no pairs whatever its
seal says, so on `main` a writer who deletes every pair gets a map that Holds and never pages, and
on the scope map keeps a manual stored scope through `decide_ad_channel_scope`. The build checks an
empty map's seal like any other: the seal covers the map's name and a pair count of zero, and an
empty map with a missing or wrong seal fails. Store creation with a key writes it for both maps,
and so does every write through the map's one writer (`_write_ad_map`) whose result is empty, a
save, a role delete that removes the last pair, or a re-seal of a map that already verifies.
`reseal_role_records` keeps skipping a map whose stored seal is blank, so no re-seal can seal a map
a writer emptied and blanked. **Failure accepted:** where a store can gain its key after creation,
its blank-sealed empty maps read Forged until an operator saves each once (an empty save seals
it), with every consequence of a map that does not hold: paged every pass, no account confirmed,
no digest written, so every account counts as moved and a step-1 trip makes step 2 trip too. The
docs slice tells the operator to save both maps once after enabling a key. **Residual:** the empty map's seal is the same value every time the
map is empty, so a writer who kept a copy can delete every pair and restore it. That is a rollback
of the map row, the class #2592 step 7 owns, as a rollback to any earlier pair set already is on
`main`.

**The cap exemption.** The unverifiable-row cap (`MAX_SUBJECT_ALERTS` distinct subjects per window,
then one shared `:*` subject) **exempts exactly the two Unverifiable map subjects**, whose names are fixed in
code (the Forged map subjects are not under that cap at all), so no stored value can open an uncapped subject through the exemption.

- **Control kept:** below the brake's thresholds a map that does not hold revokes everything `main`
  revokes on a Forged map; above them it still ends the sessions of accounts whose groups moved,
  where `main` freezes; offboarding freezes only on a step-2 trip, which reads the directory and
  the stored digests; a failing user row is still probed for revocation; and a map save's revocation never
  stops on one row. Every pass that reads a map Unverifiable or Forged pages under that map's own
  uncapped subject; a map-row Outage pages under the shared `authority-seal-transit`.
- **Failure accepted:** below the thresholds an Unverifiable map, a lag included, ends the session
  of every role holder, though no role row is written. Where step 2 trips, every revocation of the
  pass freezes while that lasts, paged by the map's subject (the shared Outage subject for a
  map-row Outage, which the sink may already be holding) and the breaker's alert, and a mass
  change to unmapped groups can cause that trip. Where step 1 trips, an account whose groups have
  not moved keeps its live session while the map does not hold. Until the first untripped verified
  pass after the column lands, every account counts as differing. The two residuals above.
- **Rejected: re-judge the offboardings alone on a trip (the previous revision).** It ran after a
  trip of any pass, a verified one included, whose set is directory evidence, so it applied
  revocations where `main`'s "byte-identical" rule applies none. Step 2 runs only after a trip of
  step 1 on a map that does not hold; whether that trip is directory evidence too is ruling 2.
- **Rejected: the groups-moved set alone, with no step 1.** Below the thresholds it keeps sessions
  `main` ends on a Forged map, a loosening.
- **Rejected: hold every diff and revoke nothing (PR 2565 at `e48a5780`).** #4739 item 4: every
  demotion stops revoking at any estate size, with no reconcile alert.
- **Rejected: apply the demotions of a map read as empty (`main`'s Forged path).** It rewrites
  every directory account's stored roles from data nobody could check, and on a lagging node it
  would trip the no-enabled-Administrator alert (#3229) for a role change the directory never made.
- **Rejected: end the map-decided sessions outside the breaker.** One planted seal or one Vault
  lag could then sign out a whole estate in one pass, the mass action the brake exists to stop.
- **Rejected: a per-map latch set after delivery.** No sink reports delivery.

`CONTROL DECISION: yes` -- it changes what a reconcile pass revokes and writes while a map does not
hold (a Forged map included, which changes `main`), adds the sealed group digest and its writes,
probes failing rows for revocation only and outside the brake's count and the ADR 0195 hold, records
no trip for a Forged-map pass whose step 2 does not trip, lists a map save's
revocations from raw rows,
confirms nothing on a pass where a map did not hold, reorders the apply phase, makes a session end unable to roll back (the owed raise), seals the empty map, refuses the
certificate identity on an unverifiable map, gives a Vault-wide outage its own slug, audit row and
clear, and changes how a map that does not hold pages.

### (c) Write-path refusals: paging, and keeping unverifiable apart from forged

**Answer.** One shape for every store write that checks a stored seal first (user, role, map,
session, approval, on SQLite, PostgreSQL and SQL Server):

1. A new store helper (named `require_seal_for_write` on PR 2565's branch; `main` has none) raises
   one of two sibling types, neither a subclass of the other: `RowSealError(kind, subject)` for a
   Forged row, `main`'s type with a subject added, and `RowSealUnverifiableError(kind, subject)` for
   an Unverifiable one, raised where `TransitSealUnverifiableError` was caught. The type is the
   cause; there is no cause field, so no `RowSealError` can carry an unverifiable row. `subject` is
   built from the kind and the id the row holds **as stored** (a helper PR 2565's branch names
   `seal_row_key`), in the form *A ref is for reading* gives, so one row has one subject on a
   case-insensitive collation, and a session's readable part is only its 12-character ref. Those two
   are the exception's whole `args`, so `repr()`, copy and pickle carry no full token hash (item
   12). An Outage never becomes either; it propagates as `TransitSealUnavailableError`.
2. **The catch census.** Because the sibling is not a `RowSealError`, none of `main`'s existing
   `except RowSealError` sites (about thirty in the three stores, which log, count or raw-delete as
   for a forged row) runs its Forged fallback on an unverifiable row; each that must handle it is
   written for it, and until then it propagates. The Transit sealer's own
   `TransitSealUnverifiableError` and `TransitSealUnavailableError` derive from neither `CipherError`
   nor `RowSealError`, so no `except CipherError` (such as `except audit_write_errors()`) catches a
   seal verdict. A test over the modules on a call path that can raise those types -- at least
   `store/`, `auth/`, `api/`, `messagefoundry/__main__.py` and `cli_common.py`, the list growing
   with any module that adds such a call -- lists every `except` clause that names any of the four types or a base of them (`Exception` and
   `BaseException` included), and every clause whose expression is not a plain name or a tuple of
   names, and asserts each is on a checked-in list with its handling: it names both refusal types
   and reports each, or it re-raises. `cli_common.py`'s top-level `except Exception`, which goes to
   the defect report, is listed as re-raise-never: a refusal type that reaches it is a census
   failure the test drives. A
   listed broad catch that swallows must call the service reporter for both types first, and a new
   broad catch fails the test until it is listed. At least `revoke_other_sessions` and
   `revoke_every_session` (whose end-everything fallback catches both types) and the approval
   gate's broad catches in `api/approvals.py` are on it.
3. **Every catch site reports, and the service reporter pages.** On `main` the store holds no
   `AlertSink`, so the store only raises. The auth service's reporter writes the type's own action
   (`integrity.authority_seal_failed` or `integrity.authority_seal_unverifiable`) once, through a
   throttle keyed by type and subject, and pages an Unverifiable refusal under the row's capped
   subject through the per-row throttle every reader and writer shares, so a row refused on a read
   and a write pages once; a Forged refusal is reported as `main` reports it. The paths with no
   service reporter in hand -- at least the API's backstop handler for both types and the CLI's
   handler for `provision-admin` and bootstrap -- call the same reporter before they answer, and the
   CLI maps the typed error to its own refusal text and exit code, never to the CLI's defect report
   (item 6). The sites are at least `main`'s API backstop (an `add_exception_handler` in
   `api/auth_routes.py`), the CLI's tuple and `isinstance` catches in `messagefoundry/__main__.py`,
   and `rehash_webauthn_credentials`, which catches broadly and counts a refusal silently today. A
   test drives each type through each named path and asserts the audit row, and a new path is added
   to that list by the slice that adds it. In a process with no alert sink, such as the CLI, the
   audit row is written and the page is not; the engine pages the row when it next reads it.
4. **Wording follows the cause.** An unverifiable refusal never says "forged" or "does not
   verify"; it says Vault transit could not verify the seal, and gives the recovery text from (a).
   An Outage says the seal "could not be made or checked through Vault transit", never that Vault
   "did not answer" or that "the request was refused", since it may have answered and there may be
   no request (#4739 item 3, round findings 1 and 2).

- **Control kept:** every refused write is audited under its true cause, and paged wherever an
  alert sink is wired; neither cause's
  reports throttle the other's, on the same row or across rows; a refusal reached from a CLI is
  still a refusal, and still audited.
- **Failure accepted:** an unverifiable row pages under the cap with other rows. Past five
  distinct rows in a window a row's page goes to the shared `:*` subject, which the sink's
  re-alert throttle may already hold, and a database writer who keeps more than five planted rows
  paging can keep every later row there for as long as the planting goes on. No cap rule prevents
  that, so the guaranteed record of each row is its own audit row, and the aggregate subject still
  pages at least once per sink re-alert interval while the flood lasts. Only the AD map subjects
  are exempt from the cap. A refusal in a process with no sink pages only when the engine next
  reads the row.
- **Failure accepted: a narrowing write to an Unverifiable row is refused too.** A disable, a
  password reset or a role removal keeps the row's other stored values and re-seals them, so
  allowing it would seal in content nobody checked (a planted role survives into a row that then
  verifies). So it is refused with HTTP 409, and the service then **ends every session of that
  account** (through `revoke_user_sessions`, which under (b)'s *The session end and the epoch*
  always marks the rows revoked and owes the raise it cannot write) and audits the
  refused narrowing with the account's subject. The same holds when a narrowing write fails for an
  Outage, such as an `hmac`-only fault while sealing the new row: the write rolls back, the service
  ends the account's sessions the same way and answers 503. Access is cut at once, and sign-in stays refused
  while the row is Unverifiable. If the row later verifies (the cause was a lag), the narrowing
  itself is lost and must be made again; the audit row and the 409 say so. Deleting the account,
  which keeps nothing, is allowed meanwhile.
- **Rejected: page from the store.** The store holds no `AlertSink` on `main`, and giving it one
  would make every process that opens a store a notifier; the reporter at the catch site has one
  wherever one exists.
- **Rejected: one type with a cause field.** Every existing `except RowSealError` would then run
  its Forged fallback on an unverifiable row. PR 2565's boolean `unverifiable` with a free-form
  `row_id` had the same flaw, and its `row_id` carried the whole session token hash (item 12).

`CONTROL DECISION: yes` -- it fixes which audit action and which alert subject each refused write
gets, splits the refusal into two types under a catch census, and that every catch site
reports.

### (d) Deleting a custom role while the role map or a holder's row is unverifiable

**Answer: the delete takes effect, retiring the role where it cannot remove it; nothing that
could not be checked is deleted or re-sealed.** A refusal here would let one planted seal on one holder keep a dangerous role granting
to every other holder, a freeze a failed seal does not cause, since on `main` a Forged holder or map
does not stop the delete.

1. Before anything is written, the service reads the role's holders and the raw pairs of the AD
   role map.
2. The sessions of every holder are revoked first, verified or not (ending a session needs no key),
   so the deleted permissions cannot linger on a live token. **Every revocation is audited**, and
   the sessions stay ended whether or not the store write then commits (item 14).
3. The store removes the grants and map pairs held in rows that verify, re-sealing those rows, as
   on `main`. A holder's row or a map that is **Unverifiable is left untouched** (items 5, 15 and
   16). The store then decides from the references it read, never from a foreign-key error,
   because the backends differ: `user_roles.role_id` references `roles(id)` on all three, and
   `ad_group_role_map.role_id` does on SQLite and PostgreSQL but not on SQL Server. Wherever an
   Unverifiable row still names the role, on every backend, the role is **retired** instead: its permission set is
   emptied and a new `retired` column, inside the role seal, is set, in one sealed write of the
   role row. A retired role grants nothing through any reference, the console lists it as retired,
   and its id cannot be reused because the row still exists. **The store's role writer
   refuses any write of a role row, retired or failing, while an Unverifiable row names it**, and
   the API answers that with HTTP 409 and fixed text (not `main`'s 404 for a missing role), so
   neither an edit nor a repair of a failing row can give a retired role permissions back. Every
   write path that validates a role id (a grant, a map save, a `replace_unverifiable` entry)
   treats a retired role as missing, so no new reference to it is made. A Forged holder
   or map keeps `main`'s behaviour, and with no Unverifiable reference the role is deleted as on
   `main`.
4. A retired role is deleted by the first verified write that leaves no row naming it, as far as
   that is in the store's hands: the next
   verified write of each left row drops its reference, and the write that drops the last one
   deletes the role row in the same transaction.
5. The store re-checks inside its write transaction, and a row that turned Unverifiable after the
   service read is left untouched the same way; it is caught as `RowSealUnverifiableError`, never
   as `RowSealError`, so `main`'s Forged fallback does not run on it.
6. The web console renders a 409's text in the page's error block, never the raw JSON body
   (item 13).

**Approvals and the #3638 ruling.** #3638 was closed under the owner ruling of 2026-10-26, which
its banner quotes as "Yes, and list it": a dual-control request that fails its seal is listed and
can be rejected, because with `expiry_hours = 0` nothing else would close it, and engine PR 2536
built `reject_seal_failed_approval`, guarded on `'pending'` and the seal read, with the audit rows in
its transaction. An Unverifiable pending request is treated the same way: an operator's **Reject**
tombstones it, because Reject is an explicit operator act that keeps none of the request's values
and grants nothing, and leaving it pending forever would be a freeze a failed seal does not cause.
What Unverifiable never does is tombstone a request **on its own**, on a read or a gate check;
those only deny. Approving an Unverifiable request is refused.

- **Control kept:** a role delete takes effect, no delete leaves a map or a user record
  that reads as forged after Vault recovers, and no delete re-seals content nobody verified.
- **Failure accepted:** an Unverifiable row keeps its reference to a retired role, which grants
  nothing, until its next verified write, and the retired row stays until then. As on `main`,
  a grant committed concurrently on PostgreSQL or SQL Server can make the role delete fail its
  foreign key and roll back; the operator retries, and the sessions step 2 ended stay ended. If every Administrator
  is a directory account and the role map is unverifiable, no Administrator can sign in; the
  break-glass is `main`'s `provision-admin`, which provisions a local Administrator from the host.
  If the map never verifies (the seal was planted), the recovery is the one in (a): the map is
  replaced in **one save** with a full entry set from its authoritative change record, never from
  the stored or displayed pairs. That needs one new API
  surface: a replacement of an unverifiable map with a non-empty entry set is refused unless the
  request carries an explicit `replace_unverifiable` acknowledgement, and such a save is audited
  under its own detail; the web console never pre-fills the form from an unverifiable map. The
  map read (`list_ad_group_role_map` and its scope twin) withholds an Unverifiable map's pairs as
  `main` withholds a failing map's, and the user read withholds an Unverifiable row's roles, so
  neither the console nor the API serves stored values to copy back. **Residual:** a replacement
  that carries a planted pair is the operator's own content; withholding the pairs is the control.
  Clearing the map with an empty save stays allowed, and the console warns that the next reconcile
  pass applies the empty map as a real demotion of every account it decided.
- **Rejected: re-seal the remaining pairs.** That seals in content nobody could check, which is
  the exact act the store's never-re-seal-a-failing-row rule forbids.
- **Rejected: refuse the delete while a holder or the map is unverifiable (the previous revision,
  and PR 2565 at `e48a5780` for every map state).** One planted seal then keeps the role granting
  to every other holder, which a failed seal does not do.

`CONTROL DECISION: yes` -- it changes what a role delete removes, adds the sealed `retired` role
state, and adds the acknowledged replacement of an unverifiable map.

### (e) Which sign-in refusals count toward the sign-in burst signal

**Answer.** The sign-in burst detector (`messagefoundry/pipeline/security_signals.py`) counts
`auth.login_failed` and no other action, at weight 1 (0 for the legacy directory-lock detail).
That stays. Every sign-in refused **because of a seal's state rather than a credential** -- an
unverifiable user row on the local, directory or federated legs, and an unverifiable directory map
-- is audited under one action, `auth.login_refused_unverifiable`, with a `reason` of
`account_unverifiable` or `directory_map_unverifiable`, and so counts at weight 0. This makes PR
2565's exemption consistent: at `e48a5780` only the map refusal was exempt, and an unverifiable
user row still wrote `auth.login_failed` at weight 1 (item 17). A Forged user row keeps `main`'s
audit, unchanged. The response body is `invalid credentials` in every refused case, with the
dummy password hash checked.

**The padded catch takes both types.** `main`'s sign-in catches `RowSealError` for the user kind
inside the pad (`_equalize_failure`), so a `RowSealUnverifiableError` raised there, for example by
the lockout write's pre-write check on a lagging node, would skip the pad and reach the API
backstop's 409. The build widens that catch to both types and answers `invalid credentials`, padded,
and lists it in the census.

**Account existence and Transit.** Under `vault_transit`, a name that holds a row costs a Transit
`verify` and an unknown name costs none, so latency, and an Outage's HTTP 503 against an unknown
name's 401, would tell them apart. The build closes that the way the dummy password hash closes
it for argon2: a sign-in for a name with no row makes one Transit `verify` over a dummy
seal minted at each start under the key's latest version and, after any refusal of its own
`verify` (a retirement included), minted again by a background task off the request path, so the
request makes exactly one `verify` either way and the dummy verifies whenever a genuine row under
the latest version would (a refusal of the dummy is never reported as a row), and the sign-in
path checks a user row's seal **past the success and refusal caches**, so a recently checked name and an unknown one each make exactly one `verify` and meet the
same Outage. The probe call an Unverifiable row
adds is not equalized: it shows only that a row exists whose seal Transit will not check, which a
database writer who planted it already knows, and which a genuine row shows only during a lag.

**An Outage on a sign-in before any credential decided** is audited as
`auth.login_refused_unavailable`, with no username in
the detail beyond what `auth.login_failed` already records, where the audit append still works;
only when the append fails too is the throttled ERROR line, with the `authority-seal-transit`
page, the record. It is not `auth.login_failed`, so it counts at weight 0: a Vault fault that
refuses every sign-in does not page as a password attack. A sign-in whose credential check
already failed is `auth.login_failed` at weight 1 whatever then happens. If its lockout write
(`failed_attempts`, `locked_until`) meets an `hmac` Outage, the write rolls back but the attempt
still counts toward the burst. **Residual:** lockout does not advance while `hmac` is down; the
burst signal still sees every wrong guess.

**The remaining existence oracle is a residual, and `main` has it already.** A wrong password for
an existing local account writes the account's row (`failed_attempts`, `locked_until`), which
under Transit re-seals through `hmac` under the writer lock; an unknown name writes nothing. The
build adds a dummy `hmac` over fixed input on the unknown-name path whenever a real account would
write, so both make the same Transit calls and an `hmac`-only Outage answers both the same. On
`main` the sign-in pad (`_equalize_failure`) equalizes a refused sign-in's time within its budget,
deferred write included, and lets an exception propagate unpadded. **Residual, new under Transit:**
a Transit round trip under the writer lock, or an Unverifiable row's `verify` plus probe, can
overrun the pad's budget and move a refused answer past it, and an Outage's 503 is unpadded on
both paths. Each tells only that a row exists whose seal Transit is slow or unable to check. The
build measures the overrun against the pad's budget and either sizes the budget from it or records
the measured residual on #4739.

- **Control kept:** the burst signal keeps meaning "a client is presenting wrong credentials", and
  neither a Vault fault (an Outage) nor an unverifiable row pages as a password attack from every
  client address. The refused rows are still audited one per refusal, and the row itself pages once per
  interval under the integrity subject from (a).
- **Failure accepted:** a client guessing passwords against an account whose row is unverifiable
  is not counted toward that client's burst. Its guesses cannot succeed, since the row is denied
  before any credential decides anything, and the row's integrity page fires.
- **Rejected: count both at weight 1 (as `auth.login_failed`).** A Vault lag would raise a burst
  alert for every client address that retries, under a password-attack subject, and the cap would
  fold real bursts into the same aggregate.
- **Rejected: a new "unverifiable burst" detector.** The per-row integrity page already reports the
  condition; a second detector adds subjects and a cap to reason about for no new decision.

`CONTROL DECISION: yes` -- it changes which audit action an unverifiable or outage-refused sign-in
writes, and so what the burst signal counts, keeps a credential failure at weight 1 through an
Outage, and adds the dummy `verify` and `hmac` on an unknown name.

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
| 3.5 | Seal checks in loops (roles, sessions, approvals) run one after another | **Fixed in build, in part:** the refusal cache (*The four answers*) makes a planted row pay its Transit calls once per 60-second window rather than on every scan. **Kept:** the checks still run one after another; bounded concurrency waits on a measurement. |
| 3.6 | `seal_hmac` duplicates `audit_hmac`; `_transit_version` duplicates `store.py`'s `_TRANSIT_MAC_VERSION` | **Fixed in build:** one Transit-HMAC call helper in `crypto_transit.py` and one MAC-shape parser both callers import; the shared helper returns the probe's answer and each caller keeps its own rule (*The probe rule*), so the audit chain's classification does not change. |
| 3.7 | `for_cipher` special-cases `TransitCipher` with `isinstance` | **Fixed in build:** a `Cipher` method that returns the cipher's row-seal backend, or none, replaces the `sys.modules` and `isinstance` test. |
| 3.r1 | The Outage alert says Vault "did not answer" | **Fixed in build:** wording in (c) step 4. |
| 3.r2 | It says "the request was refused" outside a request | **Fixed in build:** wording in (c) step 4. |
| 3.r3 | `_key_answers` swallows the probe's exception unlogged | **Fixed in build:** the probe logs its failure at WARNING with Vault's failure text and no input (as `_probe_mac` does at `e48a5780`). |
| 3.r4 | Docstrings say any failure raises `CipherError` | **Fixed in build:** the docstrings name what can escape. |
| 3.r5 | `test_transit_row_seal.py:247` reads `caplog.text` before the redaction filter | **Fixed in build:** the assertion reads the filtered handler's output. |
| 3.r6 | A 400 on a planted seal costs a second Transit round trip, with no negative cache | **Fixed in build:** the refusal cache holds an Unverifiable answer for 60 seconds, emptied when the probe's version moves, so the probe runs once per window; an Outage is never cached, so none is misfiled. |
| 3.r7 | The same base64 line at three call sites | **Fixed in build:** with 3.6's helper. |
| 4 | Unverifiable AD map holds every diff; demotions stop revoking; no reconcile alert; page can fold into the cap | **Moot under design:** (b) ends `main`'s own set below the brake and the groups-moved set above it, writes no role, and pages every such pass under the map's uncapped subject. |
| 5 | Role delete raw-deletes map pairs of an unverifiable map | **Fixed in build:** (d) step 3 leaves an Unverifiable map untouched. |
| 6 | `provision-admin` unverifiable refusal falls to the CLI defect report | **Fixed in build:** (c) step 3. |
| 7 | Writes and the approval gate page under the request id | **Fixed in build:** (c) step 1, the stored id. |
| 8 | `directory_map_unverifiable` audited as `auth.login_failed`, weight 1 | **Fixed in build:** (e). |
| 9 | Forgery wording on unverifiable refusals; stale changelog fragment and `docs/PHI.md` lines; simplifications | **Fixed in build:** (c) step 4 wording; the docs slice rewrites the fragment and the `docs/PHI.md` recovery and seal text to this ADR; simplifications are taken where a slice touches the code. |
| 10 | Map-hold latch set before the alert, so a failed page is lost and later ones suppressed | **Moot under design:** (b) has no latch; every pass that reads a map Unverifiable pages, and the sink's re-alert throttle governs repetition. |
| 11 | Latch does not record which map, so a move between maps raises no alert | **Moot under design:** no latch, and each map pages under its own fixed subject, so a move is a new subject. |
| 12 | `RowSealError` keeps the full session token hash in `args` | **Fixed in build (designed out):** (c) step 1, `args` are `(kind, subject)`, a session's subject carrying the 12-character ref; the fixed-length input keeps the hash out of anything Transit receives; a test raises one for a session and asserts that no encoding of the token hash appears in `args`, `str()`, `repr()` or the logged traceback with its chained causes: lowercase and uppercase hex, standard and URL-safe base64 of the raw digest and of the hex string, and any 16-character run of the hex; and that the whole throttle key of *A ref is for reading* appears in none of them. |
| 13 | Web console role delete shows raw JSON on the 409 | **Fixed in build:** (d) step 6. |
| 14 | Sessions revoked before a late store refusal, with no audit row | **Fixed in build:** (d) step 2. |
| 15 | Role delete refused even when no map pair names the role | **Fixed in build:** (d) no longer refuses a delete for a seal state. |
| 16 | Unverifiable holder's `user_roles` row raw-deleted without a re-seal | **Fixed in build:** (d) step 3 leaves it untouched, granting nothing. |
| 17 | Unverifiable user row still audits `auth.login_failed`, weight 1 | **Fixed in build:** (e). |
| 18a | Prose on what the scope-map hold revokes | **Moot under design:** there is no hold; (b)'s prose replaces it. |
| 18b | Closed lists of `ad_reconcile_aborted` sources and reasons | **Fixed in build:** the prose says "at least", per CLAUDE.md section 11 (SDS-3.6). |
| 18c | The split audit action | **Fixed in build:** (e) uses one action for every seal-state sign-in refusal. |
| 18d | The duplicate map check (service and store) | **Moot under design:** (d) no longer refuses a delete; the service read chooses what to revoke, and the store's re-check inside its transaction (step 5) leaves a row that turned Unverifiable untouched. |
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

## Open findings carried to the build

Two code reviews after the ruling found these against this text. **Every one is unverified by
the reviewer** (both tags read `dedup (no verify)`), and none is fixed here. The build resolves
each against the code with a test. Any resolution that would change what a ruled control refuses,
revokes, pages or audits goes back to the owner before it merges.

From round-2e3dae12a8 (against `9bc5d7e5f4`, this text's base):

1. A failing row's PRESENT read, or its hold, resets its strikes to 0 under `main`'s rules, so a
   writer who points a disabled account's failing row at an enabled entry keeps it from reaching
   the threshold. Unverified by the reviewer.
2. A failing row's candidacy and its strikes' pruning read its raw provider, disabled and session
   fields, which the writer controls, so one edit can drop it and erase its strikes; a resolution
   that keeps them must respect `reconcile.LEDGER_MAX`, whose prune evicts the lowest counts first
   (round-ec34860473). Unverified by the reviewer.
3. Ruling 2's note names two of at least five things `main` records on a Forged-map trip (also the
   breaker standing, the breaker alert and the episode) and not that, below the thresholds, the
   pass confirms no account; the body's "there the step-1 set trips" omits "past both thresholds".
   Unverified by the reviewer.
4. The hold-escape residual is narrower than its trigger: a wave goes unheld whenever at most one
   verified account is undetermined beside readable ones (or none is), however few rows fail, not
   only "where most rows fail at once" (round-ec34860473 agrees). Unverified by the reviewer.
5. After the global epoch is raised first, a per-account owed raise in `revoke_all_sessions`
   protects nothing (`session_epochs_current` already refuses every older session) and locks the
   account's fresh sign-ins out until a retry lands. Unverified by the reviewer.
6. The digest window does not close on the first untripped verified pass: a pass probes at most
   `ad_session_recheck_max_users`, and an account that signs in while a map does not hold gets no
   digest; a directory sign-in under verified maps also writes one (round-ec34860473). Unverified
   by the reviewer.
7. "The per-map page replaces both" overclaims: a page is not a durable audit row, and the map's
   integrity audit row is under the per-key report throttle, so not every pass leaves one.
   Unverified by the reviewer.
8. The retry does not say a retry deletes the owed row first and raises only if that delete
   removed it, under the write lock, so two engine shards can both raise one owed epoch.
   Unverified by the reviewer.
9. The slice 3 tests do not cover the hold-or-strike rule for a failing UNDETERMINED row, its
   absence from `_reconcile_outcomes`, `probed` and the held count, or a failing DISABLED row on a
   held pass. Unverified by the reviewer.
10. "Two planted rows" understates the hold attack: one planted row beside one genuine
    undetermined account reaches `u` = 2; the test pins only two. Unverified by the reviewer.
11. A permanently failing planted row is revoked and gets an owed raise that never lands, retried
    every 30 seconds forever, where `main`'s `_bump_session_epoch` skips the raise for a failing
    row. Unverified by the reviewer.
12. *Consequences*, Negative, names only a mass change to unmapped groups as a step-2 trip cause
    and not the CLI owed-raise lockout. Unverified by the reviewer.
13. The #5091 fact is stated twice: the `revoke_all_sessions` bullet lists as the build's what the
    retry paragraph says `main` already does. Unverified by the reviewer.
14. Ruling 4 repeats itself ("refusing ... until ... lands; sessions stay refused meanwhile") and
    narrows the retrier to a long-running engine process, while the body runs it in every process
    that opens the store. Unverified by the reviewer.

From round-ec34860473 (against `f3d1aceae1`), those that still apply to this text:

15. A failing UNDETERMINED row the verified hold withholds has no stated place in the
    `auth.ad_reconcile_held` count or alert, so a withheld revocation could leave no record.
    Unverified by the reviewer.
16. `_bump_session_epoch` on `main` catches only `RowSealError`, and (c) makes
    `RowSealUnverifiableError` not one; the catch census does not list it, so an Unverifiable row
    could roll a revoke back against ruling 4. Unverified by the reviewer.
17. A verified account whose row turns Unverifiable leaves the candidate set
    `_forfeit_clears_on_attrition` reads, forfeiting the breaker, hold and referral clears until
    restart. Unverified by the reviewer.
18. `revoke_all_sessions` still attempts a sealed per-account raise for every account, one Transit
    round trip each inside the writer transaction, so a Vault Outage holds the writer lock (and
    every ingress ACK) for one timeout per account. Unverified by the reviewer.

## Build plan

A fresh branch from `main`. PR 2565's branch is a reference only, 217 commits behind; nothing is
cherry-picked wholesale. Slices 1 to 4 merge together in one pull request: slice 1 alone would
read an unverifiable map as a failed one, which is (b)'s rejected read-as-empty path. Every slice
is fail-closed on its own head.

| Slice | What | Paths | Tests |
|---|---|---|---|
| 1 | The Transit sealer and the four answers; async seal seams on every backend; the start probe; `RowSealError(kind, subject)` and its sibling `RowSealUnverifiableError` with the catch census of (c) step 2; the key id and the retired Transit key path; the sealed empty map; the owed epoch raise and its retry task; the required `transit/verify` capability | `store/row_seal.py`, `store/crypto_transit.py`, `store/crypto.py`, `store/store.py`, `store/postgres.py`, `store/sqlserver.py`, `store/base.py`, `pipeline/engine.py`, `api/app.py`, `privilege_check.py`, `scripts/security/crypto_inventory_check.py` | new `tests/test_transit_row_seal.py` and `tests/_transit_seal_fake.py`; the seal contracts (`tests/_*_seal_contract.py`); `test_row_seal.py`, `test_crypto_transit.py`, `test_postgres_store.py`, `test_sqlserver_transit_row_seal.py`; item 12's args test; the census test; a user row under a listed retired key accepted and a session under one ended quietly; `rotate-key` still refused under Transit; a sealed empty map that fails; `revoke_all_sessions` with one Unverifiable row still ends every session; an `hmac` Outage on a raise leaves the rows deleted and an owed raise that refuses the account's sessions until the retry lands; "sign out everywhere else" ends the kept session while the raise is owed |
| 2 | Service loaders and reporting: the unverifiable action, the refusal cache, subjects with the digest suffix and the cap keyed by the whole id, the map exemption, Unverifiable as not-counting in other-row readers, the sign-in refusals and the dummy `verify` of (e), the CLI mapping and the catch-site audit of (c) step 3 | `auth/service.py`, `pipeline/alerts.py`, `pipeline/security_signals.py`, `cli_common.py`, `api/auth_routes.py`, `api/approvals.py` | `test_user_seal.py` (run unchanged, item 19), `test_session_seal.py`, `test_role_seal.py`, `test_approval_seal.py`, `test_api_auth.py`, `test_security_signals.py`, `test_provision_first_administrator.py` |
| 3 | AD sign-in deny, the group digest, the reconciler's two-step end-sessions rule under the brake, the failing-row strikes, the apply order, the Vault-wide Outage slug with its audit row and clear, the certificate refusal and the map paging of (b) | `auth/service.py`, `auth/reconcile.py` (the two steps), `store/store.py`, `store/postgres.py`, `store/sqlserver.py` (the `directory_groups_digest` column, inside the user seal), `pipeline/alerts.py`, `api/app.py` (lifespan paging) | `test_ad_session_reconcile.py`, `test_mfa_directory_recheck.py`, `test_reauth_directory_demotion.py`, and new cases: a planted unverifiable map ends the session of an account whose groups moved and leaves one whose groups did not; an account with no digest counts as moved; below the thresholds a planted map (Unverifiable, Forged, and an empty map whose seal fails) ends every role holder's session; past them step 1 trips, step 2 ends the groups-moved sessions and the offboardings, and a step-2 trip applies nothing; a failing user row toggled around passes is still probed and its DISABLED strikes accrue; a map-row Outage takes step 2 alone; a map save with one Outage user row writes the map and still ends every listed session; inserted failing rows neither trip nor dilute the brake, rank after verified candidates, and are not revoked on a tripped pass; two planted failing UNDETERMINED rows neither engage nor latch the hold on a genuine undetermined account, and a failing row read PRESENT does not loosen it; a retired-key verify refused with 403 reads Unverifiable while the active probe works; a pass where a map did not hold confirms nothing; no digest is written on a tripped or unverified pass; a role-row Outage mid-pass leaves that account's sessions ended and the later accounts processed; a map-row Outage still ends the groups-moved sessions; a Forged map writes no role; a tripped pass writes no rename; a step-1 trip is not recorded as a trip; a map save ends a Forged or Unverifiable account's sessions; `seal_unavailable` is `judged_nothing`, writes its audit row, pages under its own source and is cleared by `seal_clear`; a retired-key seal Vault refuses reads Unverifiable; a Vault-wide Outage aborts under `seal_unavailable`; the certificate leg refuses on an unverifiable map; a forged map pages under its own subject; two consecutive passes each page the map; a move between maps pages under the other subject |
| 4 | Role delete and map edits of (d), the console 409 | `auth/service.py`, `store/store.py`, `store/postgres.py`, `store/sqlserver.py`, `messagefoundry_webconsole/routes/admin.py` | new cases for items 14, 15 and 16, a delete with an Unverifiable holder and map that leaves both rows untouched and their references granting nothing, the retired role deleted by the last verified write, an edit of a retired role refused, and the SQL Server case where only the map names the role; the web console suite under `packaging/messagefoundry-webconsole/tests` |
| 5 | Docs, in the same pull request | `docs/PHI.md`, `docs/SECURITY.md` (including the one-Transit-key-per-store guidance until #3411), the changelog fragment | the doc tests that pin those files |

No step is met by loosening an existing check or test. The hosted PostgreSQL, SQL Server and
`windows-service-smoke` legs must be read on the build's head.

## Consequences

**Positive.** An unverifiable seal, which a database writer can produce at will, grants nothing a
forged one does not: it denies, audits and pages. (It counts 0 toward the sign-in burst where a
Forged row counts 1, (e); the guesses it hides cannot succeed.) A map that does not hold revokes
everything `main` revokes below the brake and more above it, the brake is unchanged, and no
session end rolls back on a Transit fault. Each refusal is audited under its true cause.

**Negative.** Offboarding still freezes when step 2 of (b) trips, which a mass change to unmapped
groups can cause, and when Vault is down everywhere (when no request is served either). Below the
thresholds an Unverifiable map, a lag included, signs out every directory role holder. A Vault fault refuses directory sign-in, and "sign out everywhere else" during one signs the
caller out too. A genuine row sealed under a version not yet on the answering node
is denied for the lag. Until the verify-then-reseal tool (item 2) exists, no row can be carried
across a version retirement, so an operator must not raise `min_decryption_version` on the audit
key while rows are sealed under the versions it would retire. Read-modify-write writes hold the
writer lock across a Transit call until item 1's row is built. Two stores sharing a Transit key
accept each other's rows until #3411.

**Neutral, and what changes off `vault_transit`.** The local sealer never answers Unverifiable or
Outage, so (a) and (e) change nothing under another cipher. At least these do change for every
cipher: `RowSealError`'s arguments and the subject bounding (c), the audit of every revocation on a
role delete and the retired role state (d), the Forged map's two-step rule, the failing-row
probe, the apply order, the owed epoch raise, the sealed empty map, the retired Transit key path, a Forged map's own page
subject and the group digest column (b), the narrowing-write
session ends (c), the `Cipher`-level sealer hook (item 3.7), the refusal cache, and the cause-keyed
throttles keyed by the whole stored id. A reviewer of a
local-cipher store reads those call sites.
