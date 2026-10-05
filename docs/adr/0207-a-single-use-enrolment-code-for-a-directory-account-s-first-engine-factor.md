# 0207 -- A single-use enrolment code for a directory account's first engine factor

- **Status:** Proposed (2026-10-05). Drafted on the owner's direction of 2026-10-05, given in
  session to the batch 194 Manager: design this ceremony as an ADR in status Proposed, for the owner
  to approve at merge. No code may follow until it is Accepted.
- **Date:** 2026-10-05
- **Related:** vault BACKLOG #2609 (its closing item 2; item 1 shipped as engine PR 1918) · vault
  BACKLOG #2711 (no host recovery when every Administrator needs an outside service) · vault BACKLOG
  #2738 item 7 (a factor enrolled before a bind) ·
  [ADR 0142](0142-federated-sso-oidc-authorization-code-pkce-relying-party-hybrid-ad-backed.md)
  Amendment C (which left this to "its own decision") and Amendment B (step-up for an OIDC session) ·
  [ADR 0184](0184-identify-a-federated-login-by-the-idp-namespaced-subject-not-by-the-username-it-claims.md)
  AC-4 (a federated login never binds) ·
  [ADR 0197](0197-cap-repeated-lock-cycles-on-one-account-without-making-malicious-lockout-cheaper.md)
  Amendment A (the generated credential a local account starts with) ·
  [ADR 0171](0171-offline-administrator-unlock-a-host-gated-cli-recovery-path-for-a-sole-administrator-lockout.md)
  (`admin-unlock` and its host gate) ·
  [ADR 0183](0183-provision-the-first-administrator-offline-no-default-account-at-first-run.md)
  (`provision-admin`) ·
  [ADR 0194](0194-refuse-to-start-a-keyless-audit-chain-at-the-store-open-seam.md) (a keyless audit
  chain) · [`docs/SECURITY.md`](../SECURITY.md) · CLAUDE.md section 0

This record names a gap in the shipped code before its fix lands. `docs/SECURITY.md` already states
the gap as a shipped limit, and ADR 0142 Amendment C states it too, so this adds nothing a reader
could not already find. MessageFoundry has zero deployments (CLAUDE.md section 0). Nothing below is a
live exposure: each case is what a deploying site would meet.

---

## Context

Every fact below was read at engine `origin/main` `923277d3e9` on 2026-10-05. Find each one by the
symbol named. Line numbers are left out on purpose.

### How a directory account gets a session today

A directory account is a user row whose `auth_provider` is `ad`. AD password sign-in is retired
(`_dispatch_login`, BACKLOG #1137), so two sign-ins remain.

| Sign-in | Which accounts it serves | The session at mint |
|---|---|---|
| Windows SSO (Kerberos), `_authenticate_kerberos` | unbound accounts only, since ADR 0142 Amendment C | `mfa_verified=False`: one factor proven, none asserted |
| Federated (OIDC), through `_complete_ad_login` | bound accounts only, since ADR 0184 AC-4 | stamped verified when `[auth].oidc_require_mfa_claim` is on (the default); unverified when it is off |

So an unverified directory session comes from two places: every Kerberos sign-in, and every
federated sign-in on a site that turned the claim gate off.

### What that session can do

1. Under `[security].require_mfa` (on by default), `_unverified_session_owes_factor` floors every
   unstamped directory session. It still reaches at least the MFA-exempt routes, the enrolment
   ceremonies, and the session-termination routes that ride the reauth-only gate.
2. The enrolment ceremonies sit behind the reauth-only gate. A Kerberos session re-proves by a live
   bind with the directory password (`_reauth_ad`). An OIDC session goes back to the identity
   provider (ADR 0142 Amendment B).
3. `_factor_binding_is_blocked` refuses only an account that already holds a factor. An account
   with none passes. That carve-out is deliberate: without it, an account with no factor could
   never enrol. The step-up gates of the TOTP begin and confirm routes and of the passkey begin
   route ask it. The web console's passkey finish route, `/ui/account/webauthn/verify`, uses the
   action-less `require_ui_reauth_only`, which does not.
4. `begin_mfa_enrollment` accepts a directory account on purpose (BACKLOG #1144).
   `confirm_mfa_enrollment` then stamps the session MFA-verified and rotates it.
   `finish_webauthn_registration` writes the passkey, then does the same.
5. A passkey can be a directory account's first factor even under `require_mfa`.
   `begin_webauthn_registration` raises `FactorEnrolmentRequired` only when
   `_covered_by_requirement` holds, and that reads local accounts only. So the TOTP-first rule of
   ADR 0197 Amendment A does not reach a directory account, and the passkey path is as open as the
   TOTP path.

That is the chain BACKLOG #2609 ran end to end. Someone who holds only a directory password signs
in by Windows SSO, re-proves the same password, and enrols an authenticator they control. They then
hold a full session, as Administrator if the directory maps the account there. The factor they
bound is now the account's own, so the real holder is shut out of it. On a site with the claim gate
off, the same shape works with only the identity provider's password.

### What is closed, and what is not

- **Closed by engine PR 1918 (item 1).** Windows SSO refuses a bound account, so Kerberos no
  longer goes around the identity provider's own MFA.
- **Not closed (item 2).** An unbound account still enrols its first engine factor on the directory
  credential alone. ADR 0142 Amendment C says so and leaves it to "its own decision". This ADR is
  that decision.
- **A local account has the answer under the shipped posture.** ADR 0197 Amendment A gives each
  local account a generated credential nobody can guess. An Administrator issues it and hands it
  over out of band. Where `require_mfa` covers the account, the holder must enrol a factor before
  replacing that credential. A directory account has no such credential, because the engine never
  holds its password.

What the engine lacks, then, is one thing proven to it that a password holder does not have. For a
local account that is the generated credential. For a directory account nothing plays that part.
The fix is a credential with the same three properties: the engine issues it, an Administrator
hands it over, and the holder proves it once.

## Decision

**A directory account's first engine factor is bound only with a single-use enrolment code. An
Administrator issues the code and hands it over out of band.**

### 1. What the binding step checks

The binding step is the one that writes the factor and stamps the session. When the session is not
stamped MFA-verified (its `mfa_verified_at` is null) and the account's `auth_provider` is `ad`, that
step checks two things itself:

1. **The account still holds no engine factor.** If it now holds TOTP or a passkey
   (`_second_factor_enrolled`), the step refuses: that factor must be proven first. The step asks
   this itself because the passkey finish route's gate does not (Context item 3). Without it, a
   passkey challenge staged while the account had no factor could finish after the real holder
   enrolled, with no code asked.
2. **Otherwise, a valid enrolment code** for this account.

The rule reads the account and what the session proved. It never reads `SessionMechanism`, and it
never reads `kerberos_enabled`.

| Case | What the binding step requires |
|---|---|
| Kerberos session, unbound account, no factor | A code, with `require_mfa` on or off |
| OIDC session, claim gate on | Nothing new. The identity provider asserted MFA, so the session is stamped |
| OIDC session, claim gate off | A code. The session is unstamped |
| Unstamped directory session, the account already holds a factor | A refusal. Prove the factor first |
| A local account | Nothing new. See Context, and *Out of scope* for the postures ADR 0197 leaves open |

**Why also with `require_mfa` off.** There a Kerberos session already reaches everything, so the
code does not change what the session can do. It changes who may bind the account's factor. Without
it, whoever signs in first binds a factor the real holder cannot prove. If the site later turns
`require_mfa` on, the real holder is locked out of their own account.

### 2. Where the control sits

The control sits in `AuthService`, in `confirm_mfa_enrollment` for TOTP and
`finish_webauthn_registration` for a passkey. It does not sit in a route dependency, for a reason
the code makes plain: no single route reaches both. The web console's `ui_mfa_verify` calls
`confirm_mfa_enrollment` directly, its `ui_webauthn_verify` calls `finish_webauthn_registration`
directly, and the engine API has no passkey registration route at all. So the code travels three
ways, and the service checks it on every one:

- the engine API, in the `POST /me/mfa/confirm` body;
- the web console's TOTP confirm form;
- the JSON body the web console's passkey page script sends to `/ui/account/webauthn/verify`.

The begin steps, `begin_mfa_enrollment` and `begin_webauthn_registration`, do not take or consume
the code. A begin binds nothing. They may say early that a code will be needed, as a courtesy, the
way `must_enrol_before_rotating` does for a password change.

### 3. The code

- **Entropy and form.** At least 128 bits from `secrets`, shown as grouped base32 so a person can
  read it aloud. Input is normalised for case, spaces and hyphens.
- **Storage.** Only its `hash_token` digest (SHA-256) is stored, as for a session token. A slow
  hash buys nothing on a code nobody can guess. Recovery codes use Argon2 because they are short.
- **One per account.** Two nullable columns on the `users` row hold the digest and the expiry.
  Issuing a new code replaces an outstanding one, so no new table is needed.
- **Lifetime.** 24 hours from issue, fixed rather than a setting. See *To resolve on acceptance*.
- **Bound to its account.** The check reads the digest on the session's own user row, so a code
  proves nothing for any other account.
- **Single use, spent atomically.** One conditional write clears the digest only where it still
  matches and has not expired. Only a write that changed a row counts, so two racing ceremonies
  cannot both spend one code.
- **The order in `confirm_mfa_enrollment`.** First read the code: present, well formed, and
  matching the account's digest and expiry. A missing or wrong code is refused here, before the TOTP
  step is consumed, so the holder does not lose that step. Then verify and consume the TOTP step.
  Then spend the code. Then stamp and rotate the session, then enable TOTP.
- **The order in `finish_webauthn_registration`.** This method writes the credential
  (`add_webauthn_credential`) before it stamps. So the code is spent before that write, not merely
  before the stamp. A check placed only before the stamp would leave the attacker's passkey bound.
  The label and duplicate checks run before the spend, so a refusal they cause does not cost the
  code.
- **A failure after the spend costs the code.** A session revoked mid-ceremony (BACKLOG #1902), or
  an `enable_totp` that fails after a good rotation, leaves TOTP off and the code spent. Today a
  plain retry recovers from that; with this ADR the holder needs a new code. On the passkey path the
  credential is already written, so the factor is enrolled and the holder proves it at the next
  sign-in. Both fail closed, and both are stated so nobody mistakes them for defects.
- **Never in plaintext at rest, never in a log, never in a URL.** Each reply that carries it sends
  `Cache-Control: no-store` through `_no_store_reply`, as the MFA reset reply already does.

### 4. Who issues it, and how it reaches the holder

- **An Administrator, from either plane.** A new route, `POST /users/{user_id}/enrolment-code`, sits
  behind `require_step_up_action` with a new action constant and `Permission.USERS_MANAGE`. Only
  the Administrator role holds that permission: a custom role may not grant it
  (`CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`, ADR 0045 D1). So the issuing Administrator is MFA-satisfied
  and has just re-proved. The web console gets a button on the user page and a page that shows the
  code once.
- **Never for the caller's own account.** The route refuses self-targeting, as `reset-mfa` and the
  federated-identity routes do. A directory Administrator with no factor therefore cannot issue one
  for itself. Section 6 covers that case.
- **Refused for** a local account, an account that already holds an engine factor ("reset its MFA
  first"), a disabled account, and an unknown account.
- **Revocable.** `DELETE` on the same path clears an outstanding code, for a handover that went
  wrong. It sits behind the same gate, with its own step-up action constant.
- **Shown once.** The reply carries the code and its expiry. The engine keeps only the digest.
- **The engine never sends the code.** An Administrator hands it over.
- **The handover is the control, so it must not run through the directory.** The code is worth
  what the handover checks, and no more. An Administrator must confirm who is asking by something the
  directory password does not give: in person, a call-back to a number on file, or the site's own
  identity check. The code must not go back through the account's own mail or chat, because the same
  password opens them. That is the ground on which alternative 3 fails, and it applies to a person
  replying by mail just as it does to the engine. The engine cannot enforce this. So
  `docs/SECURITY.md` states it as the operator's duty, and the pending-MFA page tells a directory
  user to contact an Administrator through the site's identity check. It does not invite a request
  from whoever holds the session.
- **A notice, as a courtesy and not a control.** Issuing may send the account's `notify_email` a
  notice that a code was issued, naming no code. Nothing rests on it. A new directory account often
  has no address yet, and where one is set it may be a mailbox the same password opens.

### 5. An MFA reset on an enabled directory account issues a code

`admin_reset_mfa` removes every factor and ends every session. On a local account it also issues a
generated credential, returned once (ADR 0197 Amendment A, AC-A4). After a reset, a directory
account needs a code to enrol again. So the reset of an enabled directory account issues one, and
`MfaResetResponse` returns it once. Otherwise the reset leaves the Administrator a second step that
is easy to forget. The reset of a disabled account issues none, because the route would refuse one.

### 6. The first directory Administrator gets a code from a host command

A site can reach a state where nobody can issue a code: every enabled Administrator is a directory
account, and none holds an engine factor. Under `require_mfa`, none of them gets past the floor in
Context item 1, so none can call the issuing route.

**`messagefoundry issue-enrolment-code --username <name> [--json]`** covers that case.

- **It runs on the engine host, behind the guards `admin-unlock` uses.** That is
  `_host_gated_store_settings` for the settings and the missing-store refusal, the keyless-chain
  refusal at `open_store` (`keyless_opt_out_refusal`), and `_refuse_an_unauditable_write` before the
  write (ADR 0194). ADR 0171 states why host access is a real gate: whoever holds the service
  config, the store and its key already holds the database.
- **Its write is one conditional statement.** It sets the digest only where the account is `ad`,
  enabled, and holds no factor. So it has no read-then-write window for a live engine to slip into.
- **Whether it may run beside a live engine is not settled here.** That turns on whether a second
  process may append to the audit chain safely. Until the build shows it can, the command follows
  `admin-unlock`'s rule and runs with the engine stopped. That rule is documented in `admin-unlock`,
  not enforced by it.
- It prints the code once and writes the same audit row as the route. The actor names the OS user.
- It applies the route's refusals except self-targeting, which has no meaning at a terminal.
- It issues for any directory account, not only an Administrator. Host access already grants
  everything, so narrowing it would add a rule with no security gain.

**How this relates to BACKLOG #2711.** The two share a gate and a shape, but they solve different
problems. This command is not #2711's answer.

- #2711 is recovery **during an outage** of the directory or the identity provider. A code does not
  help there: using one needs a session, and a Kerberos session needs the directory.
- This command changes no rule of ADR 0183. `provision-admin` still refuses while any enabled
  Administrator exists, and #2711's step 1 still owes its own decision on that.
- The documented advice stands: keep a local Administrator (`docs/SECURITY.md`, "Keep a local
  Administrator"). A site that does so issues codes from that account and never needs this command.

### 7. Audit

| Audit action | Written when | Detail it carries (never the code or its digest) |
|---|---|---|
| `auth.enrolment_code_issued` | the route, the console, an MFA reset, or the host command issued one | the target account, the expiry, `via` (`api`, `ui`, `reset` or `host`), whether it replaced a code, whether the account is bound |
| `auth.enrolment_code_revoked` | an Administrator cleared one | the target account |
| `auth.enrolment_code_used` | a ceremony spent one | `ceremony`: `totp` or `webauthn` |
| `auth.enrolment_code_refused` | a binding step refused | `reason`: `not_presented`, `none_outstanding` (no code on the account, which is also how a spent code reads), `wrong`, `expired`, or `factor_present` (the account gained a factor; prove it first) |

The engine API's confirm route already draws its per-actor budget (`allow_reauth_attempt`) on every
attempt, before the service runs. The passkey finish route draws the same budget. The service adds
no counter of its own, because a code nobody can guess needs none. The existing `MFA_ENABLED` notice
still fires on success.

### 8. The lockout this makes deliberate

Under `require_mfa`, a directory operator's first session stays behind the floor in Context item 1
until an Administrator issues a code. `_authenticate_kerberos` warns of exactly this: minting at the
minimum is "only safe CO-LANDED with" directory enrolment. This ADR keeps directory enrolment and
puts a code in front of it, so that lockout becomes an onboarding step. The build must say so where
a person meets it, on the pending-MFA page, worded as section 4's handover rule requires. That
comment in `_authenticate_kerberos` changes in the same build.

### What it must not break

- Local accounts: their generated credential, and ADR 0197 Amendment A's enrol-before-rotate order.
- An account that already holds a factor. It proves that factor, as today, and never needs a code.
- A federated sign-in with the claim gate on. It never needs a code.
- `admin_reset_mfa` as the always-available recovery for a lost authenticator.

## Acceptance Criteria

The tests named below are written with the build; none exists yet.

- **AC-1** -- WHEN a Kerberos session on an unbound directory account with no engine factor
  re-proves its directory password and confirms a TOTP enrolment without a code, THE SYSTEM SHALL
  refuse the confirmation, leave TOTP off, and leave the session unstamped. This is #2609's chain,
  and the test must fail on the code before this build.
  → `tests/test_directory_enrolment_code.py`
- **AC-2** -- WHEN the same session presents a valid code for its own account, THE SYSTEM SHALL
  enable TOTP, stamp the session, spend the code, and write `auth.enrolment_code_used`.
  → `tests/test_directory_enrolment_code.py`
- **AC-3** -- IF the code is not presented, wrong, expired, already spent, or issued for another
  account, THEN THE SYSTEM SHALL refuse the binding step before consuming the TOTP step, and write
  `auth.enrolment_code_refused` with the reason section 7 names for that case.
  → `tests/test_directory_enrolment_code.py`
- **AC-4** -- THE SYSTEM SHALL apply AC-1 to AC-3 to a passkey: `finish_webauthn_registration`
  SHALL spend the code before it writes the credential, and a refused code SHALL leave no credential
  row. The TOTP arm SHALL hold on the engine API and the web console; the passkey arm on the web
  console, which is the only plane that registers one.
  → `tests/test_directory_enrolment_code.py`, and a web console test under
  `packaging/messagefoundry-webconsole/tests/`
- **AC-5** -- IF a passkey challenge staged while the account had no factor finishes after the
  account gained one, THEN THE SYSTEM SHALL refuse it with `factor_present`, bind nothing, and stamp
  nothing.
  → `tests/test_directory_enrolment_code.py`
- **AC-6** -- WHEN `oidc_require_mfa_claim` is off, THE SYSTEM SHALL require a code for a federated
  session's first factor; WHEN it is on, THE SYSTEM SHALL NOT.
  → `tests/test_directory_enrolment_code.py`
- **AC-7** -- THE SYSTEM SHALL require the code whether `[security].require_mfa` is on or off, and
  whether `[auth].kerberos_enabled` is on or off.
  → `tests/test_directory_enrolment_code.py`
- **AC-8** -- WHEN an Administrator issues a code, THE SYSTEM SHALL return it once with `no-store`,
  store only its digest, and notify the target's `notify_email` without the code where one is set.
  IF the target is the caller, a local account, an account holding a factor, a disabled account, or
  unknown, THEN THE SYSTEM SHALL refuse.
  → `tests/test_directory_enrolment_code.py`
- **AC-9** -- WHEN an Administrator revokes an outstanding code, THE SYSTEM SHALL require the same
  step-up and permission as issuing, clear the digest, and write `auth.enrolment_code_revoked`.
  → `tests/test_directory_enrolment_code.py`
- **AC-10** -- WHEN two ceremonies present one code at once, THE SYSTEM SHALL let exactly one spend
  it, on every store backend.
  → `tests/test_directory_enrolment_code.py`, with the SQL Server and Postgres legs
- **AC-11** -- WHEN `issue-enrolment-code` runs on the host gate, THE SYSTEM SHALL print the code
  once, audit it naming the OS user, refuse a store that does not exist rather than create one, and
  refuse a store whose audit append would be refused.
  → `tests/test_directory_enrolment_code.py`
- **AC-12** -- WHEN an Administrator resets an enabled directory account's MFA, THE SYSTEM SHALL
  issue a code and return it once in the reset reply; for a disabled account it SHALL issue none.
  → `tests/test_directory_enrolment_code.py`

## Alternatives considered

1. **Password only, as today.** The first factor is bound on the directory credential alone. This is
   the shipped limit ADR 0142 Amendment C records. Rejected: it is the #2609 chain. The only proof is
   the password, and the password holder is the attacker this guards against.
2. **A TOTP-on-directory-password shortcut.** Keep enrolment on the directory password re-proof, and
   tighten it: a short window after first sign-in, one enrolment only, a notice to the holder.
   Rejected: every variant still proves only what the attacker holds, so it stays first-come. A
   window changes when the race runs, not who can win it. A notice is detection after the fact, and
   only where a notifier and an address exist.
3. **An emailed enrolment link.** The engine mails a one-time link to `notify_email`. Rejected on
   four grounds. A directory user's mailbox often sits behind the same directory password, so it
   proves nothing new. It needs a working notifier, which is optional. It puts a secret in a URL. And
   it trains people to follow sign-in links in mail, which is how phishing works.
4. **The Administrator-issued single-use code.** **CHOSEN.** It adds one thing the password holder
   does not have, checked by a person who already holds the power to grant roles. It mirrors the
   generated credential a local account already gets. Its strength rests on the handover in
   section 4, and this ADR says so rather than hiding it.
5. **Gate on `SessionMechanism.KERBEROS`, or on `kerberos_enabled`.** Rejected: both miss the
   federated session with the claim gate off. They also make a settings flag the control, when the
   condition is about the account.
6. **A short code, hashed with Argon2.** Easier to read aloud. Rejected: a guessable code needs a
   guess limit, and ADR 0197 shows a guess limit others can trip is a lockout anyone can cause. A
   code nobody can guess needs no limit.
7. **Take the code at the begin step, or in a route gate.** Rejected as the control. A begin binds
   nothing, and no single route reaches both binding steps (section 2). The begin step may still
   warn early.
8. **The Administrator enrols the factor for the holder.** Rejected: the Administrator would then
   see the holder's TOTP secret, so two people would hold one person's factor.
9. **Let an Administrator issue a code for its own account.** Rejected: an Administrator with no
   factor would bind its own first factor on its own say. The host command covers the case where no
   other Administrator exists.
10. **Refuse `kerberos_enabled` together with `oidc_enabled` at load.** Rejected, as #2609 already
    found: too blunt, and it does not help a Kerberos-only site.

## Consequences

**Positive.** A directory password alone no longer binds an engine factor. The rule covers Kerberos
and the claim-off federated case with one condition. Directory and local accounts now follow the
same pattern: an Administrator-issued secret stands in front of the first factor.

**Negative.**

- The control's strength rests on a human step the engine cannot check: the Administrator's
  identity check at handover.
- Every directory operator needs an Administrator before their first real session, under the default
  `require_mfa`. That is new onboarding work for each person.
- A site with no local Administrator needs the host command once, with the engine stopped until a
  build shows it need not be.
- A code lost mid-ceremony, or after a failure past the spend, means asking for a new one.

**What the build costs.** The filed difficulty, 3/10, covered both items, and the cheap one has
shipped. What remains is a new authentication ceremony: realistically **6/10**, about the size of
ADR 0197 Amendment A's wave 1. It changes a security control, so it gets its own pull request
(CLAUDE.md section 5). It touches at least:

- **the store:** two nullable `users` columns, and issue, spend and clear methods, on all three
  backends (`store/store.py`, `store/sqlserver.py`, `store/postgres.py`) and the `Store` protocol,
  with their migrations, which `messagefoundry store provision-schema` applies on a server store
  (ADR 0192);
- **the auth service:** issue, revoke and spend; both checks in both binding steps; the MFA reset;
  two new step-up actions; four audit actions; one notice kind;
- **the engine API:** the issue and revoke routes, a code field on `POST /me/mfa/confirm`, the reset
  reply, and the MFA status reply saying a code is needed;
- **the web console:** the issue button and one-time page, a code field on the TOTP confirm form and
  in the passkey page script's body, and the pending-MFA notice;
- **the CLI:** `issue-enrolment-code`, and its row in the CLI tier list;
- **documents:** the Kerberos row of the pathway table, the "Limit: an account with no binding is
  unchanged" bullet, and the handover duty, all in `docs/SECURITY.md`, whose pathway rows
  `tests/test_docs_security_pathways.py` checks;
- **tests:** the criteria above, including the SQL Server and Postgres legs, which run only on hosted
  runners.

**Out of scope.**

- Local accounts under a non-default posture: `require_mfa` off, or `require_mfa_scope =
  "administrators"` for a non-Administrator. There the holder may replace the generated credential
  before enrolling, and the first factor is then first-come on a chosen password. ADR 0197
  Amendment A's acceptance left those postures as its residual 1. This ADR does not reach them, so
  directory accounts get a code in a posture where local accounts get none. Extending the code to
  them is a separate decision.
- The passkey finish route's gate not asking `_factor_binding_is_blocked`, for local accounts.
  Section 1 closes it for directory accounts by the step's own check. A local account outside the
  shipped posture has the same race, and that is not decided here.
- Vault BACKLOG #2738 item 7: a factor enrolled first-come before a bind survives a later unbind. It
  has the same root, but closing it is a separate decision. With zero deployments, no such factor
  exists today.
- BACKLOG #2711's step 1, the recovery shape during an outage.
- Whether a Windows acceptor's `DOMAIN\user` name form stops Kerberos sign-in on a Windows host. A
  run against a real domain decides that, as #2609 records.

## To resolve on acceptance

- [ ] Require the code with `[security].require_mfa` off as well. Recommended yes, for the reason in
  Decision section 1.
- [ ] Keep the lifetime fixed at 24 hours. The alternative is an `[auth]` setting, as
  `initial_password_expiry_hours` is for a local credential. Recommended fixed, since the code exists
  for one handover.
- [ ] Have an MFA reset of an enabled directory account issue a code in the same reply. Recommended
  yes.
- [ ] Let the host command issue for any directory account, not only an Administrator. Recommended
  yes.
