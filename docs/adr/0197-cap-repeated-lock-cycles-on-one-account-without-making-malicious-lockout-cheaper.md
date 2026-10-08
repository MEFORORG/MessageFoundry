# 0197 — Cap repeated lock cycles on one account without making malicious lockout cheaper

- **Status:** **Accepted -- 2026-09-27, by an owner ruling given to a Manager seat.** The owner
  answered three questions through AskUserQuestion, put by the Manager seat for batch 121, and
  chose the recommended option each time. The build may start. Option E is adopted with a 24-hour
  ceiling, and control 2's global ceiling is an accepted residual for scoring 6.1.1. BACKLOG #1131
  stays open until the build and the lock-state surface ship. Under *To resolve on acceptance*, three
  items are settled by the rulings and the rest stay open, each with its recommendation.
  The three answers, verbatim, each with the question as the Manager relayed it (elisions are the
  Manager's):
  1. *"Adopt E (Recommended)"*, to *"ASVS 6.1.1 (BACKLOG #1131): ... ADR 0197 ... recommends option
     E ... Adopt E?"*
  2. *"24 hours (Recommended)"*, to *"If E is adopted: which ceiling on the escalating lock?"*
  3. *"Accept as a residual (Recommended)"*, to *"Even with E, the global sign-in rate limit (60 per
     minute across all clients) still refuses the owner during a flood ... Should the 6.1.1 re-score
     treat that global ceiling as an accepted residual, so E can move 6.1.1 once the lock-state
     surface also ships?"*
  > **Superseded status text, kept as a record.** Until 2026-09-27 this line read: *"Proposed
  > (2026-09-27). An options memo with the drafter's recommendation. The owner accepts or rejects it,
  > and no code may follow until it is Accepted. BACKLOG #1131 stays open."*
- **Amended 2026-09-28: Amendment A, Accepted.** An owner ruling of 2026-09-28 declined to count
  residual 1 as an accepted cost for scoring ASVS 6.1.1. Amendment A, at the end of this file,
  designs a way past the lock for a local account with no TOTP. The batch 121 Manager accepted it
  the same day under that ruling; that acceptance is a Manager decision, not an owner ruling.
  Nothing in it is built yet, and the Accepted decision above is unchanged.
  > **Superseded status text, kept as a record.** Until the Manager's acceptance this bullet read:
  > *"Amended 2026-09-28: Amendment A, status Proposed."*
- **Amended 2026-10-06: Amendment B, Accepted by owner ruling.** Two owner rulings of 2026-10-06,
  given in session to the batch 196 Manager, accept two limits of option E as residuals. A combined
  sign-in gets no MFA time floor (BACKLOG #2404). The per-account lockout bound holds within one API
  process, and does not reach a combined sign-in with both factors wrong (BACKLOG #2284). Amendment
  B, at the end of this file, records both. It builds nothing. It ticks the pre-count item under *To
  resolve on acceptance*, and changes neither the Decision nor Amendment A.
- **Date:** 2026-09-27
- **Related:** BACKLOG #1131 (the row this answers; ASVS 6.1.1) · BACKLOG #1236 (closed 2026-09-26;
  its cycle-cap remainder moved to #1131 by owner ruling) · BACKLOG #1138 (re-proof failures count
  toward lockout, and the per-session cap) · BACKLOG #1638 (a lock refuses directory sign-ins) ·
  [ADR 0171](0171-offline-administrator-unlock-a-host-gated-cli-recovery-path-for-a-sole-administrator-lockout.md)
  (`admin-unlock`; option E amends it, see Decision item 8) · [ADR 0068](0068-browser-webauthn-passkeys-offloopback.md) (passkeys) ·
  [`docs/SECURITY.md`](../SECURITY.md), "The documented protection set (ASVS 6.1.1)" ·
  BACKLOG #2404 and #2284 (the two residuals Amendment B records)

---

## Context

Every fact below was read at engine `origin/main` `d5272738d` on 2026-09-27. Line numbers are left
out on purpose. Find each fact by the symbol named.

### Two owner rulings put this question here

1. **2026-09-25, on #1236:** "Close; cap goes to #1131." The cap on repeated lock cycles is now this
   row's. The ruling was relayed by Manager seat-manager-f51f74 and recorded by vault PR 1860.
2. **R1 of 2026-09-23** (vault `docs/security/ASVS-OWNER-RULINGS-2026-09-23-BATCH121.md`) holds ASVS
   6.1.1 at partial. The chosen option names two engine defects: "an attacker can re-lock an account
   without limit, and there is no lock-state surface." This ADR is about the first. The second is a
   separate build.

### The requirement is about malicious lockout, and that is the trap

ASVS 6.1.1 asks that the documentation make clear how the anti-automation controls "are configured
and prevent malicious account lockout." A cap on lock cycles is usually built as a longer lock, or a
permanent one, after N cycles. That shrinks the number of guesses. It also hands any caller who knows
a username a cheaper way to keep the owner out. **A cap built that way answers the guessing half of
R1 by making the 6.1.1 half worse.** This ADR exists to avoid that trade.

### What ships today

- **The policy is one pure function.** `next_lockout_state` in `messagefoundry/store/store.py` runs
  inside each backend's atomic `increment_login_failure` (SQLite under the store lock, PostgreSQL
  under `SELECT ... FOR UPDATE`, SQL Server under `UPDLOCK`). Its docstring says "Nothing here
  accumulates across lock CYCLES" and that "Adding a cross-cycle ceiling means re-deriving that note
  in the same change."
- **One counter, two columns.** The `users` row holds `failed_attempts` and `locked_until`, and
  nothing else about lockout. A lapsed lock restarts the count.
- **Defaults.** `[auth].lockout_threshold = 5`, `lockout_minutes = 15` (`config/settings.py`).
- **Every failure kind feeds that one counter.** Wrong passwords on the local sign-in leg
  (`AuthService.login`), wrong TOTP or recovery codes on the second step (`verify_mfa`), and failed
  step-up and password-change re-proofs by a session holder (#1138, owner ruling R4 of 2026-09-23).
- **The lock refuses before any verify.** `login` refuses a locked account and runs a dummy argon2 to
  keep timing flat. `verify_mfa` and `finish_webauthn_assertion` refuse it too. Kerberos and OIDC
  sign-ins refuse a locked row after the ticket or token verifies (`_directory_login_refusal`, #1638).
  Re-proofs feed the counter but are not refused by it; each session is capped at
  `lockout_threshold` failed re-proofs instead.
- **The caller cannot see the lock.** `POST /auth/login` answers the fixed string
  `"invalid credentials"` whether the password is wrong, the user is unknown, or the account is
  locked. So the lock is not an enumeration signal today, and nothing below may make it one (the
  6.3.8 constraint #1131 names).
- **The signal.** The attempt that locks the account fires `ACCOUNT_LOCKED`: an `auth.account_locked`
  audit row, a row on `GET /me/security-events`, and a mail when a sink, the setting and a notice
  address are all present. It fires once per lock, so a campaign sends one notice per cycle.
- **The remedy.** `messagefoundry admin-unlock` (ADR 0171) clears `failed_attempts` and
  `locked_until` from the host, through `record_login_failure`, after refusing an unauditable write
  (`_refuse_an_unauditable_write`). `set_password` clears them too. Its callers are the
  administrator reset, the holder's own password change, and the login-time rehash in
  `AuthService.login`, which runs at the password step when the argon2 parameters have changed.
  There is no API or console surface that reports lock state.
  > **Update 2026-09-28 (BACKLOG #1131).** A read-only lock-state surface now exists for
  > `users:manage` holders on `GET /users` and the console users pages. There is still no online
  > unlock route. The sentence above is kept as the record of what was true when this ADR was
  > written.
- **Second factors are the default.** `[security].require_mfa` defaults on, and
  `[security].require_mfa_scope` defaults to `"every_local_account"`. TOTP is 6 digits. The second
  step checks it with `window=self._settings.totp_skew_steps` (`_verify_second_factor`), and
  `[auth].totp_skew_steps` defaults to 0, the current step only. So a random guess matches with odds
  of about 1 in a million at the default, and about 3 in a million at a skew of 1.

### What the shipped lock allows, in numbers

Over 24 hours against one local account at the defaults, the lock admits 96 cycles of 5 failures:
**480 guesses a day, 175,200 a year.** Two attackers get that budget, and they are different people:

1. **An attacker who knows only the username** gets 480 password guesses a day. The same attacker
   holds the password sign-in refused around the clock, at a cost of 5 requests every 15 minutes.
   The owner can get in only in the seconds between one lock lapsing and the next. Control 2, the
   sign-in window (10 per client address, 60 in total, per 60 seconds), is far looser than the lock,
   so it bounds neither number.
2. **An attacker who already holds the password** gets 480 TOTP guesses a day on the second step.
   There is no per-session cap on `verify_mfa`. At 1 in a million per guess, that is about a 0.05
   percent chance a day and **about 16 percent over a year** (about 41 percent at a skew of 1). This
   is the drafter's arithmetic over the code as read; no test drove it.

The second number is the stronger reason to cap cycles. It is also the case where a longer lock
costs the owner least, because their password is already known.

**Every figure in this ADR is for a serial attacker.** `AuthService.login` checks the lock on the
row it read before argon2, and the count is written after the verify. So parallel attempts that all
pass that check before any reaches the threshold each get a verdict. A burst spread over enough
sources gets up to control 2's window per cycle, 60 rather than 5. That holds today and under every
option below; the ratios between options hold, the absolute numbers do not. Counting an attempt
before it verifies would close this, but it does not fit E; the last to-resolve item says why.

*Amended 2026-09-27 by BACKLOG #1943, which did not pre-count.* Within one API process the
password-only, combined and second-step checks on one account now run one at a time, so a burst on
those legs gets at most `lockout_threshold` verdicts before the lock refuses the rest. The
paragraph above still holds, in part, across engine shards that each serve an API port (up to one
extra verdict for each process beyond the first), and in full for a combined sign-in with both
factors wrong, which the sign-in lock does not refuse. *Amendment B (2026-10-06) accepts both cases
as residuals, by owner ruling.*

## Decision

**Decided 2026-09-27: option E, with a 24-hour ceiling, by owner ruling (see Status).** Until then
this line read *"Proposed, not decided."* The drafter recommended option E below: split the one failure counter in
two by what the caller has already proved, let a sign-in that carries the password and a TOTP code
in one request pass the lock that a username-only attacker can set, and escalate only the locks
whose cost does not fall on an owner who can still get in.

What it must not break:

- **The atomic increment.** Every counter change stays inside the one store call per backend.
- **No enumeration signal.** Every refusal a sign-in caller can see stays the one fixed string, with
  matching status and timing.
- **R4 of 2026-09-23.** Re-proof failures still count toward lockout.
- **#1638.** A lock still refuses the Kerberos and OIDC sign-ins of the account it is on.
- **ADR 0171.** `admin-unlock` still clears every lock from the host, with no credential.

## Options considered

Each row is one local account, the shipped defaults (5 failures, 15 minutes), and a caller who
never succeeds. A directory account takes no password guesses at all: the local password leg of
`AuthService.login` refuses any account whose `auth_provider` is not local as
`unknown_or_disabled`, before any count, and `docs/SECURITY.md` control 1 says so. "Guesses" counts credential verdicts the attacker gets. The numbers come from a small
simulation of each schedule; the drafter did not drive them through the engine.

| Option | Password guesses, username-only attacker | Code guesses, password holder | Malicious-lockout effect | Store and schema cost |
|---|---|---|---|---|
| Today | 480 a day; 175,200 a year | 480 a day; about 16 percent a year to guess TOTP (41 at a skew of 1) | Owner kept out around the clock for 5 requests per 15 minutes. Tail after the campaign stops: 15 minutes | None |
| A. Double the lock each cycle, up to a ceiling | 24-hour ceiling: 35 on day one, 65 in a week, 1,855 a year. 4-hour ceiling: 50, 230, 10,970 | Same as the password column | Owner still kept out throughout. Cost to hold drops to about 5 requests a day at the ceiling. Tail grows to the ceiling | 1 column (`lock_cycles`) |
| B. A daily failure budget, then lock until the day rolls or `admin-unlock` | 20 a day (with a budget of 20) | 20 a day | One burst of 20 requests keeps the owner out for the rest of the day. Tail up to 24 hours | 2 columns (window start, window count) |
| C. A cycle counter that, past N cycles, demands a second factor or `admin-unlock` instead of a longer lock (as briefed) | With N = 20: 100 in total, spent in under 5 hours, then none | Unbounded, unless the factor path is counted. If counted on the same counter, see the lockout column | For an account with no factor: shut until `admin-unlock` after 100 requests. If factor attempts share the counter, the attacker trips it and shuts the factor path too | 1 column |
| D. Leave the lock alone and add a per-source failure limit | 480 a day, unchanged: the account lock already binds, and 24 sources at 20 each reach it | 480 a day | Unchanged. Worse for an owner behind the same proxy or NAT as the attacker, who inherits the attacker's source block | None in-process (per process, lost on restart); a table if store-backed |
| **E. Split the counter; a password-plus-code sign-in passes the username-only lock; escalate where that is safe** (recommended) | TOTP-enrolled local account: 35 on day one, 1,855 a year while the owner stays out (see Consequences for an owner who signs in daily). Other local accounts: 480 a day, as today. Directory accounts: none, as today | Local account: 35 on day one; about 0.19 percent a year to guess TOTP (0.55 at a skew of 1). Directory account: as today | A username-only attacker can no longer keep a TOTP-enrolled local owner out through the lock, if that owner has the device and a client that sends the code; holding them out then takes control 2's global ceiling, which denies everyone (residual 4). Any other account: as today. A holder of either factor can keep a local owner out up to the ceiling per cycle | 4 columns |
| F. A known-device credential that exempts the owner's past browsers from the lock | Depends on the lock it is paired with | Depends on the pairing | An owner on a known browser gets in. A new browser, or any API client, is locked with everyone else | A new table (device id, hash, counters, expiry), a new cookie, and a revocation surface |

### A. Escalating lock duration

A lock of `lockout_minutes * 2^(k-1)` for cycle k, capped at a ceiling. With a 24-hour ceiling the
cycles start at 0, 15, 45, 105, 225, 465 and 945 minutes, so an attacker needs about 16 hours of
steady work to reach a 16-hour lock. It cuts guesses by more than 90 percent.

**It does not make a sustained campaign deny more, because today's campaign already denies
everything.** What changes is the attacker's cost, which falls from about 480 requests a day to
about 5, and the tail, which grows from 15 minutes to the ceiling. A quiet, cheap campaign draws less
attention in a log. It also scales: the per-account cost of holding an owner out falls about 96
times. Put against control 2's global ceiling of 60 attempts a minute, 86,400 a day, that is about
180 accounts held at once today and about 17,000 at the 24-hour ceiling. Those two figures spend the
whole global budget, a rate at which residual 4 already refuses every sign-in, so read them as the
ratio and not as a separate harm. The ratio is what matters to a quieter attacker, who spends a
small share of that budget: under A the same share holds 96 times as many accounts. Rejected on its
own, because the only people it helps against a username-only attacker are
people who were never at risk of losing access. It becomes safe inside option E, where the owner has
a way past the lock.

### B. Daily attempt budget

The tightest fixed bound on guesses a day. It is also the cheapest denial: 20 requests at the start
of a day shut the account for the day, and the attacker does not need to wait out any lock to get
there. Rejected.

### C. A cycle counter that demands a second factor past N (as briefed)

This is the right idea in the wrong order, and it fails in two ways.

1. **With one counter, the factor path is a new way in or a new way to lock.** If a sign-in that
   carries a code is not counted, a password holder guesses codes as fast as the sign-in window
   allows. At 60 a minute in total that is 86,400 a day, and TOTP falls in about 12 days at the
   default skew (about 4 at a skew of 1). If it is
   counted on the same counter, the username-only attacker trips it with wrong passwords and shuts
   the factor path along with everything else.
2. **Past N, an account with no factor is shut until `admin-unlock`.** That is NIST's shape for a
   hard limit on consecutive failures (the drafter recalls SP 800-63B, revision 3, section 5.2.2,
   capping them at 100; not re-read for this ADR). It is the strongest denial lever of all the
   options.

Once the counter is split so that each path is counted where only the right attacker can reach it,
there is no reason to wait N cycles before offering the factor path. That is option E.

### D. Per-source rate limiting only

The account lock already limits guesses to 480 a day however many sources an attacker uses, so a
per-source limit changes the per-account budget only if it is tighter than the lock from one source.
Address rotation defeats it (the SEC-024 caveat in `docs/SECURITY.md`). It does nothing for malicious
lockout, which is the subject of 6.1.1. An in-process limiter is also per engine process and forgets
on restart. Rejected as the answer. It stays a useful layer, and control 6 (the network allowlist)
already narrows who can reach an account at all.

### F. Known-device credentials

This is OWASP's device-cookie pattern (cited from the drafter's knowledge, not fetched here). It tells
the owner apart from the attacker by a token from a past full sign-in. It is sound, but here it is the
weaker of the two ways to tell them apart. It adds a new long-lived bearer secret, a table on three
backends, and a revocation surface. It protects only browsers the owner has used before, and not API
clients. The second factor in option E, TOTP, is already enrolled on every TOTP-enrolled local
account, and it cannot be replayed. Passkey-only accounts join in the second phase. Rejected for now. It remains the natural add-on for accounts that have no factor.

### E. Split the counter, and let a password-plus-code sign-in pass the username-only lock

**The one thing that stops malicious lockout is telling the owner apart from the attacker before the
lock decides.** A per-account guess bound and a per-account lockout guarantee cannot both hold
otherwise, because the attacker can spend any budget the owner shares. The engine already holds a
discriminator the attacker lacks: the owner's TOTP secret.

1. **Two counters, split by what the caller has already proved.**
   - **The sign-in counter** is today's `failed_attempts` and `locked_until`, renamed in prose only.
     It counts wrong passwords from a caller who has proved nothing, plus the re-proof failures R4
     already sends here. Anyone who knows the username can feed it.
   - **The second-step counter** is new. It counts failures from a caller who has already proved
     one factor: wrong codes on the `verify_mfa` leg, and a combined sign-in where exactly one of the
     password and the code verified. Only someone who holds the password, the TOTP device or secret,
     or a directory sign-in can feed it. A caller who knows only the username feeds it only by
     guessing one factor right.
2. **What each lock refuses.**

   | Leg | Sign-in lock live | Second-step lock live |
   |---|---|---|
   | Password-only sign-in (`POST /auth/login`, `POST /ui/login` with no code) | refused, before any verify (as today) | refused, before any verify |
   | Combined sign-in on a local account with TOTP enrolled: password and TOTP code in one request | **not refused**; verified | refused, before any verify |
   | Combined sign-in on any other account (no TOTP, passkey-only, not yet enrolled) | refused, before any verify, exactly as password-only | refused, before any verify |
   | Second step on an existing session (`verify_mfa`, passkey assertion) | not refused | refused (as today) |
   | Kerberos and OIDC sign-ins | refused after the token verifies (as today, #1638) | refused after the token verifies (as today) |
   | Re-proofs by a session holder | not refused (as today) | not refused (as today) |

3. **The combined sign-in.** `POST /auth/login` and the console's `POST /ui/login` accept an optional
   TOTP code. **It passes the sign-in lock only when the row read before any verify shows a local
   account with TOTP enrolled.** On any other account a request with a code is refused under the
   lock exactly as a password-only one is, after the same dummy argon2. Without that condition, any
   six digits would turn a locked sign-in on a passkey-only or not-yet-enrolled account into a live
   password check, limited only by control 2. **The engine always checks both the password and the
   code, whatever the first one returns,** and routes the outcome:

   | Password | Code | Result |
   |---|---|---|
   | right | right | sign-in completes, second factor satisfied, as `verify_mfa` does today |
   | right | wrong | refused; counted on the second-step counter |
   | wrong | right | refused; the TOTP step is consumed; counted on the second-step counter |
   | wrong | wrong | refused; counted on the sign-in counter (no change while its lock is live) |

   Checking both closes two holes, one each way. If the password were checked first and the code
   only after a right password, a caller holding the TOTP device but not the password could replay
   one code across a whole 30-second step and guess passwords at control 2's rate. If the code were
   checked first and a wrong one not counted, a password holder could set the sign-in lock on purpose
   and then guess codes uncounted. With both checked, a guess at either factor by someone who holds
   the other lands on the escalating second-step counter, and a caller who holds neither changes
   nothing that can lock the owner out.

   The code check is `totp.verify_totp_step` and the store's `consume_totp_step`, never
   `_verify_second_factor`. On a TOTP miss that method also walks the recovery codes, about ten
   argon2 verifies at the defaults, and that extra time would mark the "right password, wrong code"
   outcome. The combined path takes a TOTP code only, for the same reason. Timing parity rests on the
   existing `_equalize_failure` and its `_FAILURE_BUDGET_SECONDS` pad (0.5 seconds), which every
   refused outcome above must land inside.
4. **No oracle.** "Wrong password", "right password, wrong code", "unknown user" and "locked" all
   answer the same fixed string, status and timing. So a username-only attacker who switches to
   combined sign-ins while the sign-in lock is live learns a verdict only when the password and the
   code are both right. The odds per request are the password's odds times about 1 in a million (3
   at a skew of 1).
   **A live lock is never extended or re-escalated.** Today `next_lockout_state` extends a live lock
   when an attempt reaches the store while it is set (a parallel burst). Under E, an attempt that
   reaches the store while that counter's lock is live leaves the expiry and the cycle count alone,
   and is audited. That covers a burst and a combined sign-in where both factors fail under a live
   sign-in lock. The budget for those combined attempts is control 2's, up to 86,400 a day across
   all clients. Each yields a verdict only if the password and the code are both right, and any one
   that gets a single factor right is counted on the second-step counter, which escalates.
5. **Escalate only where the owner has a way past.**
   - The **second-step lock** doubles per cycle up to the ceiling **on a local account**. The
     attacker holds the password or the TOTP device, so one of the owner's two factors is already
     lost, and a longer lock costs the owner little next to that. On a **directory account** it keeps today's fixed
     length. There the first step is a Kerberos ticket or an OIDC session, which anyone acting in the
     owner's signed-in desktop or browser holds, so "the password is already lost" is not true.
   - The **sign-in lock** doubles per cycle up to the ceiling **only on a local account with TOTP
     enrolled**, because only that owner can use the combined sign-in. On any other account it keeps
     today's fixed length. That includes a directory account with TOTP enrolled: its sign-in counter
     is fed only by re-proofs, its lock refuses its Kerberos and OIDC sign-ins, and it has no
     combined sign-in to get past it. The store reads `totp_enabled` and `auth_provider` from the
     same row, under the same lock, as the count. **The escalating owner still needs the device and
     a client that sends the code.** An owner who lost the device (the combined path takes no
     recovery code), or who signs in through a client this build does not update, is in option A's
     position: kept out for up to the ceiling. Residual 2 below names this.
   - The attacker cannot see which accounts escalate, because every refusal reads the same.
6. **Cycle counts.** Each counter gets a cycle count, raised by the attempt that sets its lock. A
   full authentication zeroes both counters and both cycle counts, as `record_login_success` does
   for the columns it clears today.
7. **Notices.** `ACCOUNT_LOCKED` is throttled by time, not by cycle: at most one mail per lock kind
   per account per 24 hours, and always a mail for the first lock after 24 hours with none. The
   throttle cannot key on the `auth.account_locked` row: `_record_suspicious_login` writes that row
   for every lock, before any mail, so the newest one is always the current lock and a 15-minute
   campaign would look mailed forever. Instead the notifier writes its own audit row for each mail it
   sends (the action name is the build's to choose) and reads the newest such row through
   `list_audit`, the way the first-seen login-address check reads its baseline. So the throttle
   needs no column. A cycle-count throttle would go quiet: the count survives
   `admin-unlock` by recommendation and never decays, so a new campaign could start at cycle 97 and
   mail nobody. The mail carries the cycle count and which lock it was. The `auth.account_locked`
   audit row is still written for every cycle. On a TOTP-enrolled local account the sign-in lock
   notice tells the owner they can sign in now by entering their password and their authenticator
   code together. The second-step notice says a caller got one factor right and the other wrong, and
   says which one was right, since only the owner receives it. **Its advice is conditional, "if
   this was not you".** The owner's own typos land here: the console shows the code field on every
   sign-in, so an owner who mistypes the password but enters a valid code feeds this counter.
   Unconditional advice would tell that owner to replace a working authenticator. So the notice
   first asks whether these attempts were the owner's own. Only if they were not does it tell the
   owner to ask an administrator for a password reset, or the host operator for `admin-unlock`, and
   then to replace whichever factor was right.
8. **Administrators.** `admin-unlock` clears both locks and both failure counts. It reports both
   old expiry times and both cycle counts, on stdout and in `--json`, and writes them to its audit
   row. A password change through `set_password`, by the administrator reset or the holder, clears
   both locks and zeroes the second-step cycle count, because the password those failures proved is
   gone. **The login-time rehash must not.** Today it calls `set_password` at the password step, so a
   password holder could shed second-step escalation once per argon2 parameter change, the #1638
   shape. The build gives the rehash a write that touches only the hash.

   **This amends ADR 0171 and does not supersede it.** `admin-unlock` keeps its gate, host access,
   and its no-password rule. It gains a named store method, `clear_lockout`, in place of the
   `record_login_failure` reuse, and a second lock to clear and report. The build adds a dated
   amendment to ADR 0171 saying so.

**What this buys, against the two attackers in Context.** A username-only attacker can no longer
keep a TOTP-enrolled local owner out **through the lock**, if that owner has the device and a client
that sends the code. **The attacker can still keep them out through control 2**, and E does not
change that. `allow_login_attempt` runs in the route before `AuthService.login` (`POST /auth/login`
in `api/auth_routes.py`, `POST /ui/login` in `messagefoundry_webconsole/routes/core.py`), and its
global budget refuses the owner's combined sign-in along with everyone else's. So E does not make
the owner unreachable to deny. It raises the cost of holding one owner out from about 20 requests an
hour against one account, which nobody else notices, to a denial of every sign-in on the engine.
That costs about 3,600 requests an hour from 6 or more addresses (10 each) where client addresses
are real. **Behind an undeclared proxy or a NAT the owner shares, it costs only about 600 an hour:**
`_client` (now `api.security.client_ip`, BACKLOG #2289) reads `request.client.host`, `[api].trusted_proxies` defaults to empty, so every caller
shares one address, and filling that one per-address bucket of 10 a minute refuses everyone. The
limiter does not count refused attempts, so retrying for each freed slot costs the attacker
nothing more. Residual 4 names this.
Against such an account the attacker gets 35 password guesses on day one, then about 5 a day, while
the owner stays out. Against a local account, a password holder gets 35 code guesses on day one, then
about 5 a day: about 0.19 percent a year to guess TOTP at the default skew, down from about 16
percent (0.55 and 41 at a skew of 1). A holder of either factor, the password or the TOTP device,
can keep a local owner out for up to the ceiling per cycle, and the owner is told why. Directory accounts are unchanged.

## Drafter's recommendation

**Choose E, with a 24-hour ceiling. Confidence: medium, about 65 percent that E is the right shape.
High, about 85 percent, that A, B, C as briefed, and D should not ship on their own.** The doubt about
E is in the build, not the idea: a second sign-in path is more code on the most attacked route, and
timing parity across its outcomes has to be measured, not assumed.

### What the owner would have to accept

1. **Accounts with no TOTP keep today's exposure.** A local account with no TOTP enrolled (not yet
   enrolled, or passkey-only, or on a site that narrowed `[security].require_mfa_scope` or turned
   `[security].require_mfa` off) keeps the fixed lock. A caller who knows the username can keep such
   a local account refused for 5 requests every 15 minutes, and gets 480 password guesses a day.
   Directory accounts also keep today's behaviour. They take no password guesses at the local leg,
   which refuses them before any count, and their engine lock is fed only by the TOTP leg and
   re-proofs, as today. The remedy stays `admin-unlock`. Under the shipped defaults every local
   account must enrol a factor. A passkey counts as one (`_second_factor_enrolled`), so a
   passkey-only account meets the default and still keeps this exposure. Otherwise it is a
   not-yet-enrolled account or a non-default posture.
   Passkey-only accounts join E in a second phase: a combined sign-in with a passkey needs a
   challenge minted before the password is sent, which is a larger console change.
2. **A TOTP-enrolled owner without the way past is worse off than today.** The escalated sign-in lock
   keeps out, for up to 24 hours, an owner who lost the device, an owner whose client cannot send the
   code, and an owner who never saw the notice and leaves the code field blank. The build narrows
   this: every first-party client gains the code field, and the console asks for the code beside the
   password on every sign-in. What is left is the lost-device owner, whose remedy is `admin-unlock`.
3. **A holder of one factor can keep a local owner out for up to 24 hours per cycle.** A caller with
   the password, or with the TOTP device or secret, feeds the second-step counter. This is the price
   of bounding guesses at the other factor, and it falls on an owner who has already lost one.
   **At scale this is credential stuffing.** Anyone holding leaked passwords for many local accounts
   can hold each owner out for up to 24 hours, at about 5 requests a day per account once at the
   ceiling. Recovery then needs an administrator password reset per account. `admin-unlock` alone
   does not recover: it keeps the cycle counts, by the recommendation below, and leaves the leaked
   password valid, so the attacker re-locks at the 24-hour ceiling with 5 requests.
4. **The global sign-in ceiling is its own denial lever, and this ADR does not touch it.** 60
   attempts a minute across all clients, from any source, refuse every sign-in on the engine. That
   is control 2's documented behaviour, named here so nobody reads E as closing it. It is also how a
   username-only attacker still keeps a TOTP-enrolled owner out under E, denying everyone: about
   3,600 requests an hour from 6 or more addresses, or about 600 an hour behind an undeclared proxy
   or a shared NAT (see "What this buys"). The same budget bounds
   combined sign-ins made under a live sign-in lock.
5. **The owner's own typos can reach the escalating second-step lock.** A combined sign-in with one
   factor right and one wrong feeds the second-step counter, which on a local account escalates and
   refuses every sign-in. That covers a typo in either factor, a code that missed the current step
   at the default skew of 0, and a reused code: `consume_totp_step` makes each code single-use, so a
   retry with the same code in the same 30-second step reads as "right password, wrong code". One
   password typo followed by a quick retry can therefore cost two counts. That owner waits out the lock or needs `admin-unlock`. The
   notice's "if this was not you" wording keeps it from also telling them to replace a working
   authenticator.

### Which owner questions this raises

> **Ruled 2026-09-27** for E, the ceiling and residual 4; see Status. Residuals 1 to 3 and 5 are not
> ruled; they stay under *To resolve on acceptance*.

- **Accept option E with a 24-hour ceiling?** Recommended: yes.
- **Accept residuals 1 to 5 by name?** Recommended: yes. The alternatives cut both ways. Escalating
  the sign-in lock on every account trades fewer guesses for a longer lockout on exactly the accounts
  with no way past it, which is the trade this ADR exists to refuse. Not escalating it on
  TOTP-enrolled accounts either removes residual 2, but leaves those accounts at 480 password
  guesses a day.

## Acceptance Criteria

> Stated for option E, so that accepting it has a testable meaning. No test exists yet and none is
> linked; each is "to build with the chosen shape". Every arm that checks a lock also checks the
> account row did not change in a way the arm does not name, because a lock test that only asserts a
> refusal passes against a store that never counted.

- **AC-1** — WHEN the sign-in lock is live on a local account with TOTP enrolled, and a sign-in carries
  the right password and a valid TOTP code, THE SYSTEM SHALL complete the sign-in with the second
  factor satisfied. Test: to build with the chosen shape.
- **AC-2** — WHILE the sign-in lock is live, THE SYSTEM SHALL refuse a password-only sign-in before
  any verify, as it does today. Test: to build with the chosen shape.
- **AC-2a** — WHILE the sign-in lock is live on an account that is not a local account with TOTP
  enrolled, IF a sign-in carries a code, THEN THE SYSTEM SHALL refuse it before any verify, exactly as
  a password-only sign-in. Test: to build with the chosen shape, with a passkey-only arm and a
  not-yet-enrolled arm, each asserting that a right password is still refused.
- **AC-3** — WHEN exactly one of a combined sign-in's password and code verifies, THE SYSTEM SHALL
  count the failure on the second-step counter and leave the sign-in counter unchanged; and WHEN the
  code is the one that verified, THE SYSTEM SHALL consume its TOTP step. Test: to build with the
  chosen shape, with one arm for each of the two cases.
- **AC-4** — WHEN neither a combined sign-in's password nor its code verifies, THE SYSTEM SHALL leave
  the second-step counter unchanged. Test: to build with the chosen shape, including an arm that
  sends one valid code with many wrong passwords and asserts only the first is accepted as a code.
- **AC-5** — WHILE the second-step lock is live, THE SYSTEM SHALL refuse the password-only sign-in,
  the combined sign-in, the second step on an existing session, and the Kerberos and OIDC sign-ins.
  Test: to build with the chosen shape.
- **AC-6** — THE SYSTEM SHALL answer a sign-in caller with the same status and body whether the user
  is unknown, the password is wrong, the code is wrong, or either lock is live. Test: to build with
  the chosen shape, plus a timing arm that compares all three refused combined outcomes against the
  `_FAILURE_BUDGET_SECONDS` pad.
- **AC-7** — WHEN a lock is set on cycle k, THE SYSTEM SHALL set it for `lockout_minutes * 2^(k-1)`,
  capped at the ceiling, for the second-step lock on a local account and for the sign-in lock on a
  local account with TOTP enrolled; and for `lockout_minutes` for every other lock, directory
  accounts included.
  Test: to build with the chosen shape, in `tests/_lockout_store_contract.py` so all three backends
  run it.
- **AC-8** — WHEN a full authentication completes, THE SYSTEM SHALL zero both failure counts, both
  lock expiries and both cycle counts in one write. Test: to build with the chosen shape.
- **AC-9** — WHEN `admin-unlock` runs, THE SYSTEM SHALL clear both locks and both failure counts, and
  SHALL report both old expiries and both cycle counts. Test: to build with the chosen shape.
- **AC-10** — WHEN a lock is set, THE SYSTEM SHALL write an `auth.account_locked` audit row, and
  SHALL mail `ACCOUNT_LOCKED` unless it mailed that lock kind for that account in the last 24 hours.
  Test: to build with the chosen shape, including an arm that runs `admin-unlock` and then a new
  lock at a high cycle count and asserts a mail, and an arm that locks every 15 minutes for 25
  hours and asserts exactly two mails.

  *Note, 2026-09-28 (BACKLOG #1131):* the lock rows are read only with `users:manage`, by owner
  ruling 2026-09-28. That covers `auth.account_locked`, `auth.lock_notice`, `auth.login_locked`,
  `auth.admin_unlocked`, and the `reason: locked` refusals of the factor and directory legs. AC-10
  is unchanged: the engine still writes every one, and an Administrator reads them all. A reader
  without `users:manage`, the built-in Auditor included, sees one uniform `auth.login_failed` row
  per refused sign-in in every lock state instead. The list is `messagefoundry/auth/audit_visibility.py`.
- **AC-10a** — WHILE a counter's lock is live, WHEN an attempt reaches the store, THE SYSTEM SHALL
  leave that lock's expiry and cycle count unchanged. Test: to build with the chosen shape, in
  `tests/_lockout_store_contract.py`.
- **AC-10b** — WHEN the login-time rehash rewrites a password hash, THE SYSTEM SHALL leave every
  lockout column unchanged. Test: to build with the chosen shape.
- **AC-11** — WHEN wrong credentials against one account arrive in parallel, THE SYSTEM SHALL count
  every one of them on the counter it belongs to. Test: extend
  `tests/test_mfa.py::test_parallel_wrong_credentials_cannot_evade_the_account_lockout` with a
  combined-sign-in arm.
  *Amended by BACKLOG #1943:* "every one" means every attempt that reaches the counter. An
  attempt queued behind the one that sets a lock, and refused by that lock, is not verified and
  not counted, so a burst of password-only sign-ins, second-step codes or one-factor-right
  combined sign-ins leaves the count AT the threshold. A combined sign-in with both factors
  wrong is not refused by the sign-in lock, so every one of those is still counted.

## Build plan

Two phases. Phase 1 is the whole of option E for TOTP. Phase 2 adds passkeys to the combined
sign-in. Phase 1 ships in one change, because escalation without the combined sign-in is option A,
which this ADR rejects.

### 1. Tests first

Write these red, against the shipped code, before any other change:

- In `tests/_lockout_store_contract.py`, which all three backend suites import: cycle counting,
  doubling to the ceiling, no extension of a live lock, no doubling for a sign-in lock on an account
  with no TOTP or on a directory account, no doubling for a directory account's second-step lock, the
  two
  counters staying apart, and the full-authentication clear. The contract's docstring says it is
  sequential and pins policy only; keep that note true.
- In `tests/test_mfa.py`: AC-1 to AC-6, AC-2a, AC-10b and AC-11, through the real `AuthService` on
  SQLite.
- In `tests/test_cli.py`, beside
  `test_admin_unlock_clears_the_lock_without_waiting_and_leaves_the_password_alone`: AC-9.
- An arm for AC-10 beside the existing `ACCOUNT_LOCKED` notice tests.
- **Each red must be red for the reason named.** Run each against the shipped code and read the
  failure. A test that fails on an import error or a missing column proves nothing about the policy.

### 2. Store columns, on all three backends

Four columns on `users`, each defaulting to "no history", so an existing row needs no backfill:

| Column | SQLite | PostgreSQL | SQL Server |
|---|---|---|---|
| `lock_cycles` | `INTEGER NOT NULL DEFAULT 0` | `INTEGER NOT NULL DEFAULT 0` | `INT NOT NULL DEFAULT 0` |
| `second_step_failed_attempts` | `INTEGER NOT NULL DEFAULT 0` | `INTEGER NOT NULL DEFAULT 0` | `INT NOT NULL DEFAULT 0` |
| `second_step_locked_until` | `REAL` | `DOUBLE PRECISION` | `FLOAT NULL` |
| `second_step_lock_cycles` | `INTEGER NOT NULL DEFAULT 0` | `INTEGER NOT NULL DEFAULT 0` | `INT NOT NULL DEFAULT 0` |

The migration follows the pattern each backend already uses for `channel_scope_source` (#1927):

- **SQLite** (`store/store.py`): add each column to the `users` `CREATE TABLE` in `_SCHEMA`, and to
  the `users` column loop in `_migrate` that runs `ALTER TABLE users ADD COLUMN` when the column is
  missing. Mind the `users` DDL's comment rule: no comma inside a column comment.
- **PostgreSQL** (`store/postgres.py`): add each to the `users` DDL and to the column loop in
  `_migrate_lease_columns`, and **bump `_MIGRATION_REV` from 4 to 5** with a numbered comment beside
  the others. The DDL change moves `_schema_hash` on its own, but the contract written above
  `_MIGRATION_REV` says not to rely on that.
- **SQL Server** (`store/sqlserver.py`): add each to the `users` DDL and add one
  `IF COL_LENGTH('users','<column>') IS NULL ALTER TABLE users ADD <column> <type>` statement per
  column.
- **`UserRecord`** gains the four fields; every `SELECT` that builds one reads them.

No existing row changes meaning. Zero cycles and no second-step lock is exactly today's state.

### 3. The policy function

- `next_lockout_state` takes `lock_cycles`, `max_lockout_seconds` and `escalate: bool`, and returns
  the new cycle count in `LockoutState`. The lock length is `lockout_seconds` when `escalate` is
  false, else `min(lockout_seconds * 2^cycles, max_lockout_seconds)`. Cap the exponent before
  computing, so a large stored count cannot overflow.
- The same function serves both counters. The caller passes which one.
- While the counter's lock is live, return the stored expiry and cycle count unchanged (AC-10a).
  Today's code extends a live lock; that line changes on purpose.
- **Re-derive the docstring in the same change**, as it asks: the sentence "Nothing here accumulates
  across lock CYCLES" becomes false, and the note on the re-lock being unbounded must say which
  accounts it still holds for.
- `lockout_minutes = 0` must still mean "the lock expires at once". Zero times any power of two is
  zero, so the arithmetic keeps it; a test pins it.

### 4. The store protocol

- `increment_login_failure` takes `counter` (`"sign_in"` or `"second_step"`) and
  `max_lockout_seconds`, reads that counter's columns plus `totp_enabled` and `auth_provider` in its
  one locked `SELECT`,
  and writes only that counter's columns. Return the cycle count too, for the notice.
- `record_login_success` zeroes all six lockout columns.
- `set_password` clears both locks and both failure counts, and zeroes `second_step_lock_cycles`.
- A new hash-only write for the login-time rehash, which touches no lockout column (AC-10b).
- Give `admin-unlock` a named `clear_lockout` method on the protocol. ADR 0171 reused
  `record_login_failure` only to avoid a four-file collision that is not present now, and said a
  named method is the cleaner shape.
- Update every caller and pin in the same change. At least: the keyword pins in
  `tests/test_security_doc_rate_limits.py::test_lockout_auto_expires_but_re_locking_is_unbounded`,
  which cover `record_login_failure`, `increment_login_failure` and the reads in `_register_failure`;
  and the store callers in `tests/test_auth_store.py`, `tests/test_postgres_store.py`,
  `tests/test_sqlserver_store.py`, `tests/test_store_backend.py`, `tests/test_reauth_lockout.py` and
  `tests/test_webauthn.py`.

### 5. The auth service

- `_register_failure` takes the counter.
- `login` gains the combined path, **only for a local account with TOTP enrolled on the row read
  before any verify** (AC-2a): verify the password and the code, both always, with
  `totp.verify_totp_step` and `consume_totp_step`, never `_verify_second_factor`; route the outcome
  as the table in Decision item 3 says; on success issue
  a session with the second factor satisfied and seed the step-up window the way `verify_mfa` does.
  The sign-in lock refuses a password-only request before any verify, as today, and does not refuse a
  combined one. The second-step lock refuses both before any verify.
- `verify_mfa` and `finish_webauthn_assertion` check the second-step lock only, and `verify_mfa`
  feeds the second-step counter.
- `_directory_login_refusal` refuses either lock.
- Keep the combined path inside the existing local sign-in method (`_login_local`).
  `tests/test_docs_security_pathways.py` treats any new `_login*` coroutine as a new 6.1.3 pathway,
  so a new one needs its own entry there and in `docs/SECURITY.md`. Staying inside `_login_local`
  adds no pathway, but the **Local** row of the 6.1.3 pathway table in `docs/SECURITY.md` still
  changes: its lockout text gains the two counters, the combined sign-in and what each lock
  refuses.
- Re-proofs keep feeding the sign-in counter, per R4. Their per-session cap is unchanged.
- The notice throttle and the two notice texts, in `pipeline/security_notify.py`.

### 6. API and console

- `LoginRequest` in `api/auth_models.py` gains an optional `totp_code`, bounded to the TOTP digit
  count. Absent means today's two-step flow, unchanged.
- The console sign-in form gains an authenticator-code field beside the password, shown to every
  caller and on every sign-in, so its presence says nothing about an account and an owner under a
  campaign does not have to know to use it.
- Every first-party client that signs in gains the same optional field: `login` in
  `messagefoundry/apiclient/client.py`, the VS Code extension's `ide/src/auth.ts`, and the harness
  sign-in dialog in `harness/_login.py`. A client left out keeps its owners in residual 2.
- No response gains a field. The combined sign-in's answers are today's answers.

### 7. Settings

- `[auth].lockout_max_minutes`, default 1440, validated to be at least `lockout_minutes`. Document it
  in `docs/CONFIGURATION.md` beside `lockout_minutes`.

### 8. Documentation

- **`docs/SECURITY.md`, the documented protection set (ASVS 6.1.1).** Control 1's row splits the two
  counters and states what each refuses. The paragraph "Control 1 bounds the lock, not the campaign"
  is rewritten: for a TOTP-enrolled local account a username-only campaign no longer keeps the owner
  out through the lock, it says control 2 can still deny everyone, and it states residuals 1 to 5
  above by name. The *Signal* paragraph gains the notice
  throttle. The *Recovery* paragraph gains the combined sign-in and the two-lock `admin-unlock`. The
  rate-limit table's "Account lockout" row and the route-to-limiter map gain the combined sign-in.
  The sentence in "What a tripped control looks like" that says control 1 refuses before checking
  the presented credential becomes false for the combined sign-in; rewrite it.
- **`tests/test_security_doc_rate_limits.py`** pins the old wording in
  `test_lockout_auto_expires_but_re_locking_is_unbounded`. Rewrite it to pin the new claims, not to
  delete them.
- **The 6.1.3 pathway table's Local row**, as build step 5 says.
- **ADR 0171**: a dated amendment for the named method and the second lock (Decision item 8).
- **`docs/CONFIGURATION.md`**: the new setting.
- **`CHANGELOG.md`**: a user-visible entry, because the sign-in form and the JSON login change.

### 9. The vault re-score that follows

This ADR changes no cell. After phase 1 merges, a vault Builder re-reads:

- **6.1.1.** The malicious-lockout limb then holds, against the lock, for TOTP-enrolled local
  accounts whose owners have the device and a client that sends the code. That is not every local
  account under the shipped defaults: a passkey counts as a factor (`_second_factor_enrolled`), so a
  passkey-only account meets the default and gets nothing in phase 1. Control 2's global ceiling
  still lets any caller deny every sign-in, the owner's included (residual 4). Residuals 1 to 5 are
  what an assessor weighs against it. The guess figures
  assume an owner who stays out; an owner who signs in daily restarts the escalation. **The lock-state surface, R1's second defect, is not built by this ADR**, so 6.1.1
  cannot reach pass on this change alone. Do not re-score it to pass on this ADR's merge. By owner
  ruling of 2026-09-27, control 2's global ceiling (residual 4) is an **accepted residual for this
  re-score**: it does not by itself hold 6.1.1 short once E and the lock-state surface have both
  shipped. The other residuals are still for the assessor to weigh.
- **6.3.8**, because it records the lockout transition as a possible enumeration signal. AC-6 is the
  evidence to cite.
- **6.3.5**, because the notice now fires on a schedule rather than on every lock.
- #1131's row: this ADR discharges the cycle-cap limb that came from #1236 once it is Accepted and
  built. The row's Verdict and Closing-act are the owning Manager's to change.

## Consequences

**Positive** — A caller who knows only a username can no longer keep a TOTP-enrolled local owner
out through the lock, which is the property 6.1.1 names. The caller can still do it through control
2, but only by refusing every sign-in on the engine: about 3,600 requests an hour from 6 or more
addresses, or about 600 behind an undeclared proxy or a shared NAT, instead of about 20 against one
account (residual 4). While that owner stays out, password guessing on the account
falls from 480 a day to 35 on day one and about 5 a day after. If the owner signs in every day, each
sign-in restarts the escalation: about 35 a day, 12,775 a year, still about 14 times fewer than
today. TOTP guessing by a password holder against a local account falls from about 16 percent a year
to about 0.19 percent at the default skew (41 to 0.55 at a skew of 1), on the same condition. An
owner under a campaign is told, in the notice, how to get in. 96 notices a day become at most two,
one per lock kind.

**Negative / risks** — A second sign-in path on the most attacked route. Timing parity between its
outcomes is a claim to measure, and a slip there becomes a password oracle. Four columns on three
backends. A holder of one factor can hold a local owner out for up to a day per cycle, and a
credential-stuffing list does that to many accounts at once (residual 3). An owner's own typos can
reach the escalating second-step lock (residual 5). A TOTP-enrolled
owner who lost the device waits up to a day or needs `admin-unlock`. Accounts with no TOTP, and
directory accounts, gain nothing against malicious lockout.

**Out of scope** — The lock-state surface (the other ground R1 names). The global sign-in ceiling as
a denial lever. Counting an attempt before it verifies (the last to-resolve item). Known-device credentials (option F), which remain the likely add-on for accounts with
no factor. The `_admin_unlock` audit gap that #1236's closing amendment lists is already closed on
`main`: `_admin_unlock` now calls `_refuse_an_unauditable_write` before the lockout write.

## To resolve on acceptance

- [x] Option E, or another. Recommended: E. **Ruled 2026-09-27: E**, owner answer "Adopt E
      (Recommended)".
- [x] The ceiling. Recommended: 24 hours (`lockout_max_minutes = 1440`). A 4-hour ceiling allows
      10,970 guesses a year instead of 1,855, with a shorter tail. **Ruled 2026-09-27: 24 hours**,
      owner answer "24 hours (Recommended)".
- [x] Residual 4, control 2's global ceiling, for the 6.1.1 re-score. **Ruled 2026-09-27: an
      accepted residual for scoring**, owner answer "Accept as a residual (Recommended)". It does not
      change what E builds; section 9 records what it means for the re-score.
- [ ] Residuals 1 to 3 and 5, accepted by name. Recommended: accept. Not covered by the 2026-09-27
      rulings, which named residual 4 alone.
- [ ] Whether a full authentication should zero the sign-in cycle count. Recommended: yes, matching
      "consecutive failures". The cost: an owner who signs in daily during a campaign restarts the
      attacker's escalation each day, about 35 guesses a day instead of 5, or 12,775 a year.
- [ ] Whether `admin-unlock` should also zero both cycle counts. Recommended: no, keep them, so an
      attacker who re-locks after an unlock resumes at the escalated length. Offer a
      `--reset-cycles` flag for the case where the operator knows the campaign is over.
- [ ] Whether `ACCOUNT_LOCKED` stays one event type with a closed-set detail naming the lock, or
      becomes two. Recommended: one type, with the detail.
- [x] Counting an attempt before it verifies, so a parallel burst gets 5 verdicts per cycle rather
      than up to control 2's window. **Not in phase 1.** It conflicts with E, which picks the counter
      after the verify (the routing table in Decision item 3). It also collides with #1638:
      `_login_local` calls `record_login_success` only when no factor is owed, so a pre-count would
      stand as a failure until the second factor completes (`verify_mfa` and
      `finish_webauthn_assertion` clear it then). Five right-password sign-ins that stop at the code
      step would lock the account. Recommended: file it as a
      separate ledger row, with its own design, and do not cite a number here until one is
      allocated.
      *Amended 2026-09-27 by BACKLOG #1943:* the burst this item names is now bounded within one
      API process without a pre-count, by queueing each account's checks; see the amendment after
      the serial-attacker paragraph under Context. A pre-count is still unbuilt, and the
      both-factors-wrong combined case and the cross-process case stay open as that amendment says.
      *Ruled 2026-10-06, Amendment B (BACKLOG #2284):* no store-side pre-count is built. The owner
      accepted both of those cases as residuals. This box was unticked until then.

---

## Amendment A (2026-09-28) -- a way past the lock for a local account without TOTP

**Status: Accepted (2026-09-28), by the batch 121 Manager, under the owner's 2026-09-28 "No, fix
it" ruling.** The Manager accepted it after the two foreground adversarial rounds recorded below.
This is a Manager decision taken under an owner ruling; it is not itself an owner ruling. The
build may start, in the wave order below. Nothing here is built yet. The Accepted decision above
stands: this amendment adds to option E and changes none of it.

> **Superseded status text, kept as a record.** Until the Manager's acceptance this line read:
> *"Status: Proposed (2026-09-28). A design with the drafter's recommendation. Nothing here is
> built, and no code may follow until the owner accepts it."*

**Manager decisions taken with the acceptance, 2026-09-28.** Neither is an owner ruling.

1. **The scope question is answered no, by the Manager's reading of the ruling's own text.** The
   draft asked the owner whether "a local account without TOTP" includes accounts on a site that
   turned `[security].require_mfa` off or narrowed `require_mfa_scope`. The question the owner
   answered was framed on the shipped default: *"On the shipped default, that covers every new
   local account until it enrols"*, as the Manager relayed that question. So the ruling
   means an account under the shipped posture. Non-default postures stay residual 1 and outside
   the documented protection, and wave 3 (N-C2) is not scheduled.
2. **The built-E audit-record oracle is fixed first**, as its own pull request on branch
   `b121-e10-audit-oracle`, before wave 1. It is in flight, not merged, as this is written.

### Why this amendment exists

The owner ruled on 2026-09-28, through AskUserQuestion put by the batch 121 Manager. The Manager
relayed the question to this drafter in its own words, not verbatim: should the cost this ADR
accepts count when ASVS 6.1.1 is scored? That cost is residual 1. A local account without TOTP
keeps the fixed lock, which anyone who knows the username can re-arm without end, at 5 guesses per
15 minutes. The answer, verbatim: *"No, fix it"*. As relayed, 6.1.1 stays partial until a local
account without TOTP has a way past a lock that wrong passwords set.

The option text carried a direction, which the Manager marked as a suggestion and not a decision:
*"provision-admin enrols TOTP at the terminal, so no account is born without a way past."* It is
weighed below as option N-A, beside the others.

**Two records disagree about residual 1, and this ruling settles it.** `docs/SECURITY.md`, in "The
residuals ADR 0197 names", tags residual (1) *"Accepted with option E, owner ruling 2026-09-27."*
This ADR's *To resolve on acceptance* list says the 2026-09-27 rulings named residual 4 alone. The
2026-09-28 ruling now declines residual 1 for scoring, so the SECURITY.md tag is wrong either way.
Wave 1 below corrects it. This change does not, because another lane holds that file.

### What ships today, measured

Read at engine `origin/main` `05cb4af5f` on 2026-09-28. Find each fact by the symbol named.

1. **Option E is built.** `_login_local` holds the combined sign-in. `lockout_escalates` in
   `store/store.py` escalates the sign-in lock only on a local account with TOTP enrolled. Every
   other local account keeps the fixed lock.
2. **Every account an administrator creates starts with a guessable password and no factor.**
   `create_local_user` stores the password the administrator typed (`UserCreateRequest.password`),
   with `must_change_password` set.
3. **The first sign-in must rotate before it can enrol.** `require` in `api/security.py` runs the
   must-change check before the factor check, and the enrolment routes are not in
   `_MUST_CHANGE_EXEMPT_PATHS`.
   `tests/test_mfa_access_gate.py::test_a_must_change_account_with_no_factor_still_rotates_from_a_pending_session`
   pins that order.
4. **Rotation ends every session, the holder's own included.** `change_password` calls
   `revoke_user_sessions`. `POST /me/password` answers *"password changed; please sign in again"*,
   and the console sends the browser to `/ui/login?e=pwchanged`. **So a holder who does everything
   right still passes through a state with a password they chose, no factor, and no session.**
   Anyone who knows the username can lock the account at that moment, and the holder cannot get
   back in to enrol. This is the hole. No speed on the holder's part closes it.
5. **The first administrator starts in that state.** `provision_first_administrator` sets the
   password typed at the terminal, claimed at birth, and enrols no factor.
6. **The lost-authenticator recovery lands there too.** `admin_reset_mfa` removes TOTP and every
   passkey, keeps the password, and revokes every session.
7. **A passkey-only account has no way past either.** A passkey counts as enrolled
   (`_second_factor_enrolled`), but the combined sign-in takes a TOTP code only.
8. **Two non-default postures leave accounts with no factor for good:** `[security].require_mfa`
   off, or `[security].require_mfa_scope = "administrators"` for a non-administrator.
9. **The engine already confines an unenrolled session.** Until a factor is proved, a session
   reaches only `_MFA_EXEMPT_ROUTES`, the enrolment ceremonies, and the session-termination routes
   that ride the reauth-only gate. The session's idle and absolute timeouts end the session, but
   nothing times out the unenrolled state of the account. The one clock there is
   `[auth].initial_password_expiry_hours` (72 by default), and it applies to an unclaimed issued
   credential only.
10. **The engine already issues credentials nobody can guess.** `admin_reset_password` calls
    `_generate_policy_password`, a 192-bit `secrets.token_urlsafe(24)`.
11. **Passkeys are registered without a discoverable-credential request.**
    `webauthn.registration_options` sets `user_verification` and nothing about `residentKey`, so the
    WebAuthn default ("discouraged") applies. The engine records nothing that says whether a stored
    passkey is discoverable.

### The idea the recommendation rests on

**A lock exists to bound guesses. On a credential nobody can guess, it bounds nothing and costs the
owner everything.** The argument rests on the entropy alone. Even at a million guesses a second for
a year, a 192-bit credential falls with odds near 1 in 10^44, which covers a site with control 2
off or `initial_password_expiry_hours = 0`. With control 2 on, at its global ceiling of 86,400
attempts a day for 72 hours, the odds are near 1 in 10^52.

For a password a person chose, the lock is needed. Then the only way past a lock that anyone can arm
is a second thing the attacker lacks. Option E uses the TOTP secret. So the design is three moves:

1. **Every account is born with a credential nobody can guess, and wrong passwords arm no lock
   while it stands.**
2. **Under the shipped defaults, the holder enrols a factor with a way past before replacing that
   credential.** The rotation that ends every session then never leaves a guessable password
   without one. "Any factor" is not enough: a passkey the engine cannot find without a username has
   no way past (fact 11).
3. **Every factor that counts gets a combined sign-in.** TOTP has one. A discoverable passkey gets
   one in wave 2.

After both waves, under the shipped defaults, no local account holds a guessable password without a
way past the lock.

### Options weighed

Named N-A to N-G so they do not collide with options A to F above. N-A to N-E are the five the brief
named; N-F and N-G are added here.

| Option | What it closes | What it opens | Build cost | Verdict |
|---|---|---|---|---|
| N-A. `provision-admin` enrols TOTP at the terminal | The first administrator is TOTP-enrolled from birth | A TOTP secret and recovery codes on the operator's terminal; nothing a network caller can reach | Small: one prompt, one service step, CLI tests | **Adopt, in wave 1** |
| N-B1. An admin-issued one-time enrolment secret beside the temporary password | New accounts, if the secret passes the lock | A second secret on the same channel as the first, so it adds nothing a generated password lacks | Medium: a new secret, column and route | Reject in favour of N-B2 |
| N-B2. The birth credential is engine-generated; wrong passwords arm no lock while it stands; the holder enrols before rotating | Every created account, every reset account, and the lost-authenticator recovery | No guessing gain (192 bits). A weaker lock signal during the window. Takeover by whoever intercepts the handover, which the reset path already has | Medium: one column on three backends, a policy argument, a gate reorder, the create surfaces | **Adopt, in wave 1** |
| N-C1. A known address passes the username-only lock | Owners who sign in from a stable address | **The lock itself, behind an undeclared proxy or a shared NAT**: every caller shares the owner's known address. No help to a new account, which has no baseline | Small: reuses `_classify_login_address` | Reject |
| N-C2. A known-device token passes the username-only lock | Returning browsers, whatever the posture | A new bearer credential, a table on three backends, a revocation surface. No help to a new account or a new browser | Medium to large | Not scheduled (Manager decision, 2026-09-28): the ruling covers the shipped posture |
| N-D. Lock per (username, source) instead of per username | A remote attacker locks only their own source | **Guessing**: the per-account budget rises from 480 a day toward control 2's 86,400, up to 180 times. Behind an undeclared proxy the owner still shares the attacker's source | Medium: a per-source table | Reject |
| N-E. Shrink the window: force enrolment at first sign-in, time out the unenrolled state | Nothing the lock needs | A timeout is a second way to lose the account | Small | Reject as the fix. The confinement is already built; its order is corrected inside N-B2 |
| N-F. Mail a one-time lock-bypass token with the lock notice | Accounts on a site with a mail channel | A secret in mail. It needs an optional sink, and an assessor would read it close to an email authenticator | Medium | Reject |
| N-G. A combined sign-in with a passkey (this ADR's phase 2), usernameless | Passkey-only accounts whose passkey is discoverable | A pre-auth challenge store to bound; discoverable credentials required and recorded | Medium to large: console, WebAuthn options and a column, `_login_local` | **Adopt, in wave 2** |

#### N-A. `provision-admin` enrols TOTP at the terminal

After the password prompt, and **before any store write**, the command generates a TOTP secret in
memory. It prints the secret as base32 and as an `otpauth://` URI, and reads a code. It checks the
code with `totp.verify_totp_step`, which is pure, at the configured skew, and re-prompts on a wrong
code. Only then does it write: the row, the password, the TOTP secret with its step consumed, the
recovery codes, and the role last. It prints the recovery codes once. The account is then born with
option E's way past. Its password stays typed at the terminal and claimed at birth, as ADR 0183
decided.

- **It keeps ADR 0183's write order.** The role is still written last, so every interruption leaves
  a roleless account that a re-run completes. A mistyped code writes nothing, so it cannot leave a
  half-built row that a re-run then treats as a takeover.
- **The repair branch clears everything the earlier holder could still use.** Before it enrols,
  it removes TOTP, the recovery codes and every passkey, and revokes every session on the row. A
  crash between the TOTP write and the role write leaves a roleless, enrolled row, and
  `begin_mfa_enrollment` would refuse to enrol it again. More important, a row somebody else held
  must not carry their factor, or a session of theirs, onto the new administrator. **Today's repair
  branch revokes no session**, and `_build_identity` re-reads roles on every request. So a live
  session the earlier holder kept becomes an Administrator session when `set_user_roles` runs. That
  is an ADR 0183 defect this change must fix, because it edits that branch.
- **It opens nothing a network caller can reach.** The secret and the codes go to the terminal,
  which the operator already controls with host access, the gate ADR 0171 argues. They never go into
  `--json` output, argv, a file or a log. **One exposure stays:** the IDE's Start flow runs the
  command in a terminal it holds open (`ide/src/engineControlModel.ts`), and a held-open terminal
  keeps its scrollback, which the editor may persist. The IDE flow should close that terminal after
  a successful provision, and the command should tell the operator to clear the scrollback.
  Named as a residual below.
- **When `[security].require_mfa` is off**, the command still enrols by default and accepts
  `--no-totp`. With it on, the flag is refused, because the scope always covers an administrator.
- **Alone it is not enough.** It covers one account. Every account an administrator creates keeps
  the hole, so N-A is paired with N-B2.

Files: `messagefoundry/__main__.py` (`_provision_admin`), `messagefoundry/auth/service.py`
(`provision_first_administrator`), any IDE flow that drives this prompt (`ide/src/engineControlModel.ts`
runs the command), and a dated amendment to ADR 0183.

#### N-B1 and N-B2. Every account is born with a way past

The brief offered two forms. **A first-sign-in enrolment that the lock does not block is safe only
when the credential behind it cannot be guessed.** Otherwise it turns a locked sign-in into a live
password check. So N-B2 makes the credential unguessable, and N-B1 is not needed. Its enrolment
secret would travel on the same channel as the temporary password, so it adds a second thing to
protect and nothing the attacker lacks.

N-B2 has six parts:

1. **The engine generates the birth credential.** `create_local_user` stops taking a password and
   returns an `IssuedCredential`, as `admin_reset_password` does. `UserCreateRequest` loses its
   `password` field, and the console create page shows the issued credential once. There are no
   deployments to migrate (CLAUDE.md section 0).
2. **A new column records that the credential in force is engine-generated.** `users.password_generated`,
   0 or 1, default 0. **Both writers of a hash take it as a required keyword**, so every caller
   states it: `set_password`, and `create_user`, which is where `create_local_user` writes its hash
   today. Missing the second would ship every created account lockable, which is exactly the
   population the ruling names. The generated paths pass 1 and every holder-chosen path passes 0.
   The login-time rehash (`set_password_hash`) leaves it alone. It is an explicit column rather than
   a reading of `must_change_password`, for ADR 0164's reason: record a lifecycle fact, never infer
   it from mutable credential state.
3. **Wrong passwords arm no sign-in lock while that column is set.** `increment_login_failure`
   reads the column in its one locked `SELECT`, beside `totp_enabled` and `auth_provider`, and
   passes `lockable=False` to `next_lockout_state`. The attempt is still counted and audited, and
   it never sets `locked_until`. The second-step counter is unchanged.
4. **Under the shipped defaults the holder enrols a factor with a way past before rotating.** The
   gate keys on "a local account that `[security].require_mfa` covers and that holds no factor with
   a way past", not on `must_change_password`. Round 2 of the review showed why: a site that ran
   for a while with the requirement off, then turned it back on, holds accounts with a chosen
   password, no factor and no must-change flag. For such an account:
   - its session may reach `/me/reauth` and the enrolment ceremonies, and a password change is
     refused with a fixed "enrol an authenticator app first" detail until a factor with a way past
     exists;
   - its **first** enrolment must be that factor. A passkey registration is refused until one
     exists, so the forced enrolment cannot end in a passkey that has no way past.

   In wave 1 only TOTP counts. A passkey does not, because it has no combined sign-in yet, and fact
   11 means it may never get one. From wave 2 a passkey recorded as discoverable counts too. A new
   account moves from "generated credential, no factor" to "generated credential, TOTP", then to
   "chosen password, TOTP", which is option E's case. When the requirement does not cover the
   account, the order stays as today.
   - **The rotation is conditional on the factor, in the store.** `change_password` checks for TOTP
     and then writes, and `admin_reset_mfa` can clear TOTP between the two. So the rotation's
     `UPDATE` carries the condition itself (`totp_enabled = 1`, or from wave 2 a discoverable
     passkey), and a write that matches no row is refused.
   - **The refusal lives in the service, not only in the route gate.** The console's
     `POST /ui/account/password` calls the JSON handler in-process, past its `Depends` gate, so a
     check only in `require` would not reach it. `change_password` refuses, and the console mirrors
     it in `_factor_first`, `rotation_comes_first` and `must_change_target` so it sends the holder to
     enrolment rather than to an error.
   - **The self-service last-factor guard asks the same question.** `disable_mfa` and
     `delete_webauthn_credential` already refuse to remove the last factor while MFA is required.
     They now also refuse a removal that would leave no factor with a way past. In wave 1 that means
     TOTP cannot be removed while the requirement covers the account; from wave 2, not unless a
     discoverable passkey remains. `admin_reset_mfa` stays unguarded, as ADR 0068 requires.
5. **`admin_reset_mfa` on a local account also issues a generated credential**, in the same call,
   and returns it. Without this, the lost-authenticator recovery leaves a chosen password, no
   factor and no session: the hole again. **The credential is written first**, before TOTP and the
   passkeys are cleared, so a crash between the writes leaves a generated credential with factors,
   never a chosen password without them.
6. **A census names every account that is still lockable with no way past.** At startup, and in
   `messagefoundry verify`, the engine lists the local accounts the requirement covers that hold
   `password_generated = 0` and no factor with a way past, and every enabled TOTP secret that fails
   to decrypt. It warns and writes an audit row; it does not refuse to start, since refusing would
   hand an account-level fact a site-wide veto. The TOTP probe matters on its own: a secret the
   engine cannot read turns the owner's combined sign-in into "right password, wrong code", which
   feeds the escalating second-step lock. This is what makes the invariant checkable after a site
   has changed its posture, rather than assumed.

**What it opens, checked one at a time.**

- *Brute force.* The lock stops arming only on a 192-bit credential that dies unclaimed after 72
  hours. Each guess costs the attacker what a guess costs today, at the odds given above.
- *Enumeration.* None. Every refusal keeps the fixed string, status and padded time. A locked
  account and an unlockable one answer alike.
- *A new oracle.* None. The caller learns a verdict only by holding the credential.
- *A new credential to protect.* None. The generated credential replaces the typed one on the same
  handover channel. Whoever intercepts it can claim the account, as with a reset today. **The
  takeover gets quieter, though.** Today an interceptor must rotate, so the holder's credential
  stops working and a `PASSWORD_CHANGED` notice goes out. Under part 4 an interceptor can enrol
  their own TOTP and leave the issued password in place. The holder's credential then still signs
  in, but owes a factor they never set up, and only an administrator's reset recovers the account.
  So the `MFA_ENABLED` notice sent to a must-change account says: if you have not signed in yet,
  contact your administrator. The handover is named as a residual below.
- *A new denial lever.* None. A flood on the account holds its queue (BACKLOG #1943) exactly as a
  flood under a live lock does, since the locked path runs a dummy argon2 too.
- *A weaker signal during the window.* No lock means no `ACCOUNT_LOCKED` mail. The holder learns of
  the campaign through `LOGIN_AFTER_FAILURES` at first sign-in. Administrators see it in the audit
  trail and in the failed-attempt count on the lock-state surface.

Files: `store/base.py`; `store/store.py` (`_SCHEMA`, `_migrate`, `next_lockout_state`,
`increment_login_failure`, `UserRecord`, the conditional rotation write); `store/postgres.py` (DDL,
`_migrate_lease_columns`, `_MIGRATION_REV` from 5 to 6); `store/sqlserver.py` (DDL, a `COL_LENGTH`
guard); `auth/service.py` (`create_local_user`, `admin_reset_password`, `admin_reset_mfa`,
`change_password`, `disable_mfa`, `delete_webauthn_credential`, the enrolment ceremonies, the
census); `api/security.py` (`require`, `_MUST_CHANGE_EXEMPT_PATHS`, the password-change branch);
`api/auth_models.py`; `pipeline/security_notify.py` (the `MFA_ENABLED` wording); `verify/checks.py`
(the census); the console's user-create, password and enrolment routes, `routes/account.py`
(`_factor_first`) and `_auth.py` (`rotation_comes_first`, `must_change_target`).

#### N-C1. A known address passes the username-only lock

It reuses `_classify_login_address` and needs no schema. It fails twice. **Behind an undeclared
proxy or a shared NAT it removes the lock for everyone.** `[api].trusted_proxies` defaults to empty,
so every caller arrives from the proxy's address. That address is known after the owner's first
sign-in, and guessing then runs at control 2's 86,400 a day. **And it does nothing for the accounts
the ruling names.** An account that has never finished a sign-in has no baseline
(`UNEVALUATED_NO_BASELINE`). Rejected.

#### N-C2. A known-device token passes the username-only lock

This is OWASP's device-cookie defence against malicious lockout, cited from the drafter's knowledge
and not fetched here. A full sign-in mints a random token, stored hashed like a session and bound to
the account. It is set as an HttpOnly, Secure, SameSite=Strict cookie scoped to the sign-in route. A
password-only sign-in that carries a live token for the named account passes the sign-in lock and is
verified. Its failures count on the token, which is revoked at `lockout_threshold` of them. A token
for a different name is ignored, so it tells the caller nothing.

It is sound, and it is the only option here that helps an account with no factor at all. But it
helps only a browser that has signed in before. It does nothing for a new account, which is the
population the ruling names, and nothing for a new browser or an API client. It adds a bearer
credential with its own table on three backends, a revocation surface (password change, "end every
session", administrator reset) and a cap on tokens per account. Not scheduled: the Manager read the
ruling as covering the shipped posture only (the decisions under this amendment's Status). It
stays the natural answer if non-default postures are ever brought into scope.

#### N-D. Scope the lock per (username, source)

A remote attacker then locks only their own source. But the guess budget becomes per source. At 480
a day for each source, control 2's per-address limit does not bind; only its global ceiling does, at
86,400 a day. That is up to 180 times today's budget, and the global limiter is an accepted
residual, not a guard to lean on. Behind an undeclared proxy every caller is one source, so the
owner still shares the attacker's lock. Rejected.

#### N-E. Shrink the window

Measured, most of it is already built: a session with no factor is confined to the enrolment routes
(fact 9). What is not built is a timeout, and a timeout does not close the hole. An attacker needs 5
requests at any moment inside the window, however short it is. Disabling an account that did not
enrol in time is also a second way for the owner to lose it. Rejected as the fix. Its useful half,
the order of the first sign-in, is corrected inside N-B2 part 4.

#### N-F. Mail a one-time lock-bypass token

The lock notice would carry a token that lets one password-only sign-in pass the lock. It covers
only a site with a mail sink, which is optional. It puts a secret in mail, and whoever reads that
mailbox gets password guesses past the lock. An assessor would read it close to an email
authenticator, which NIST SP 800-63B does not allow for out-of-band use (recalled, not re-read
here). N-B2 covers new accounts with no channel at all. Rejected.

#### N-G. A combined sign-in with a passkey (phase 2 of this ADR)

A passkey-only owner signs in with the password and a passkey assertion in one request. The
sign-in lock does not refuse it, just as it does not refuse the TOTP combined sign-in.

- **Usernameless, so it adds no enumeration signal.** Registration requests a discoverable
  credential (`residentKey` required), and the store records on each passkey that it was registered
  that way (a `discoverable` column on the passkey table, three backends). Under `required` a
  conforming browser creates a discoverable credential or fails. The column records the
  `credProps.rk` result where the client reports one, and the request otherwise, so on a
  non-conforming client it can still overstate; the census names passkey-only accounts for that
  reason. A sign-in stages an assertion challenge with an empty `allowCredentials` list, so no
  username is sent to get it and the answer does not depend on any account. The assertion's
  `userHandle` must equal the named account's id, or the assertion counts as invalid. A challenge
  keyed by username with a real credential list would tell a caller which accounts hold passkeys,
  so that shape is rejected.
- **Only a discoverable passkey is a way past.** A passkey registered before wave 2, or without the
  column set, cannot be found by an empty `allowCredentials` list. So the combined path, part 4's
  rotation gate and the last-factor guard count only passkeys with `discoverable` set. There are no
  deployments, so nothing registered earlier needs migrating (CLAUDE.md section 0).
- **The challenge store stays bounded and cannot become a new denial lever.** The begin leg is a
  POST that charges control 2 (`allow_login_attempt`) first, and stages the challenge under an opaque
  random handle it sets as an HttpOnly cookie. It is not keyed by client address: behind an
  undeclared proxy every caller shares one address, so an address key would let one caller cancel
  or crowd out the owner's challenge. The sign-in pops the challenge on any outcome, and checks its
  age on arrival, before the account's queue, as `arrived` does for a TOTP code. Pre-auth
  challenges sit in their own pool, apart from control 8's per-user entries, and a full pool
  evicts its oldest rather than refusing. With control 2 on, the pool (4,096 for 120 seconds, as
  control 8) takes about 34 a second to fill, and control 2 admits at most 1 a second. With control
  2 off, a fast enough flood can evict an owner's challenge before they finish; that is named as a
  residual, beside the rest of what control 2 being off already costs. A GET render stages nothing.
- **It runs only when the row read before any verify shows a local account with at least one
  discoverable passkey under the current `rp_id`**, the twin of AC-2a. Both factors are always
  checked, and every refused outcome writes one audit reason, `bad_credentials`, never a slug that
  names the factor that was right (see the finding against built option E below):

  | Password | Assertion | Result |
  |---|---|---|
  | right | valid | sign-in completes, second factor satisfied |
  | right | invalid | refused; counted on the **sign-in** counter, exactly as "wrong, invalid", with no change while its lock is live |
  | wrong | valid | refused; counted on the second-step counter (a device holder guessing passwords) |
  | wrong | invalid | refused; counted on the sign-in counter, with no change while its lock is live |

  **The "right, invalid" cell is routed with "wrong, invalid" on purpose.** The first draft left it
  uncounted, following ADR 0068's rule that no assertion failure counts. The review below showed
  that made it a silent password oracle: a right guess moved no counter, a wrong one moved the
  sign-in count, and the lock-state surface shows both counts. Routed together, the two cells look
  the same in every record. A password holder loses nothing by it, since a signature cannot be
  guessed, and a flaky authenticator costs the owner only the fixed sign-in lock, which this path
  passes anyway. The cost is a lost signal: a right password beside a junk assertion no longer
  tells the owner their password is known. **This routing is not a model for the TOTP path.** A
  TOTP code can be guessed, so uncounting "right password, wrong code" there would hand a password
  holder uncounted code guesses, the hole option C item 1 describes.
- **The sign-in lock keeps its fixed length on a passkey-only account.** Escalating it would need
  the passkey count inside each backend's atomic increment. The ruling asks for a way past, not a
  smaller guess budget, so the fixed length is kept and named as a residual.

Files: `auth/webauthn.py` (registration options, a usernameless assertion), `auth/service.py`
(`_login_local`, a pre-auth begin, the part 4 and last-factor gates), the passkey table on all three
backends, the console login form and a POST begin route, `api/auth_models.py`, and a dated amendment
to ADR 0068 for the discoverable requirement, the pre-auth ceremony and the counted cell.

### Adversarial review

Two rounds, each a general-purpose subagent, on 2026-09-28. The brief both times: find a cheaper
malicious lockout, a cheaper brute force, an enumeration signal, or a case the recommendation leaves
open. Both checked the text against the code at `05cb4af5f`. Round 1 attacked the first draft and
returned two HIGH, four MEDIUM and four LOW findings. Round 2 attacked the revision, found nothing
HIGH, and returned two MEDIUM and seven LOW. Every finding was taken or answered; the text above
carries the fixes.

**Its strongest objection, in its words:** *"The recommendation's central claim is false as written:
after both waves, every local account without TOTP has a way past the lock. The rotation gate
accepts any factor. The engine registers passkeys with no `residentKey` and records no `credProps`.
N-G's usernameless ceremony only works with discoverable credentials, and the engine cannot tell
which passkeys those are."*

**The answer.** The objection was right, and it was measured (fact 11). The draft let any factor
open the rotation gate, so a holder who chose a passkey at first sign-in landed back in the hole,
and wave 2 could not find that passkey. Three changes answer it. Part 4 now asks for a factor with a
way past: TOTP in wave 1, and from wave 2 also a passkey registered as discoverable. N-G records
that fact on each passkey and counts no other. The self-service last-factor guard asks the same
question, so a holder cannot remove their way past.

**Round 2's strongest objection** was that the revised claim held only for an install that had
never left the defaults. The gates keyed on `must_change_password`, and `require_mfa` is a runtime
setting, so an account that dropped its factor while the requirement was off stayed lockable after
it came back on. Answered in N-B2: part 4 now keys on "covered and holding no factor with a way
past", the forced first enrolment must be such a factor, and the census (part 6) names any account
the gates cannot reach.

**The other findings, and where each landed.**

| Round | Severity | Finding | Where it landed |
|---|---|---|---|
| 1 | HIGH | N-G's uncounted "right password, invalid assertion" cell was a silent password oracle | N-G routes it with "wrong, invalid" and writes one audit reason |
| 1 | HIGH | Built option E already leaks the same verdict through audit reasons | Recorded below as a finding against the shipped code; its fix is in flight on `b121-e10-audit-oracle` |
| 1 | MEDIUM | `create_local_user` writes its hash through `create_user`, not `set_password` | N-B2 part 2: both writers take the keyword |
| 1 | MEDIUM | The console's password route calls the JSON handler past its `Depends` gate | N-B2 part 4: the refusal lives in `change_password`, mirrored in the console |
| 1 | MEDIUM | N-A's repair branch must clear every factor and revoke sessions; today it revokes none | N-A, second bullet |
| 1 | MEDIUM | N-A's secret could reach `--json` or held-open IDE scrollback; a wrong code left a half-built row | N-A: verify in memory before any write; never in `--json`; scrollback named as a residual |
| 1 | LOW | N-G's challenge key was unspecified; a per-address key is a denial lever behind a proxy | N-G: an opaque per-begin handle, popped on any outcome |
| 1 | LOW | The brute-force bound leaned on control 2, which is optional | The idea section: the argument rests on the entropy alone |
| 1 | LOW | Enrol-before-rotate makes an interceptor's takeover quieter | N-B2 "A new credential to protect", and residual 4 |
| 1 | LOW | Fact 9 left out the session-termination routes and session timeouts | Fact 9 |
| 2 | MEDIUM | The revised claim held only for an install that never left the defaults | N-B2 part 4 keys on "no factor with a way past"; part 6, the census |
| 2 | MEDIUM | One reason slug does not close the built-E oracle: the row kinds and the lock event differ too | The built-E finding below, corrected |
| 2 | LOW | A slow code-guessing campaign can push a dormant TOTP account into the second-step lock, which refuses the combined sign-in | Residual 9 |
| 2 | LOW | A TOTP secret the engine cannot decrypt turns the owner's escape into a self-lock | N-B2 part 6: the census probes every secret |
| 2 | LOW | Recovery codes could be a way past with a separate, always-walked field | Recorded as a later option under residual 2 |
| 2 | LOW | `change_password` and `admin_reset_mfa` race; part 5's write order could crash into the hole | N-B2 part 4: a conditional rotation write; part 5: the credential first |
| 2 | LOW | With control 2 off, a refusing pre-auth pool is a passkey lockout | N-G: its own pool, evict-oldest; residual 10 |
| 2 | LOW | The `discoverable` column records the request, not the result | N-G: record `credProps.rk` where reported; the census |
| 2 | LOW | Routing "right, invalid" with "wrong, invalid" loses a leaked-password signal, and the TOTP path routes the other way | N-G: the cost named, and why TOTP must not copy it |

**A finding against built option E, outside this amendment's build.** Under a live sign-in lock, a combined
sign-in on a TOTP-enrolled local account is verified, bounded only by control 2, and any six digits
make a request combined. `_route_combined_failure` writes the `auth.login_failed` reason `bad_code`
when the password was right and `bad_password_and_code` when it was wrong. `list_audit` returns that
detail to any `AUDIT_READ` holder, and the built-in Auditor role, which is not an administrator,
holds it. **So an Auditor who arms the sign-in lock with five wrong passwords then gets a password
verdict per request, up to control 2's 86,400 a day, against a design bound of 35.** A
`users:manage` holder sees the same thing in the two counts on the lock-state surface. The drafter
checked the permission grant (`Role.AUDITOR` holds `AUDIT_READ`) and the reason slugs; the attack
was not driven through the engine.

**Round 1 proposed one reason slug; round 2 showed that is not enough.** A right candidate lands on
the second-step counter, so its fifth try sets that lock: an `auth.account_locked` row appears, and
every later try writes `auth.login_locked` instead of `auth.login_failed`. A wrong candidate lands
on the sign-in counter, whose live lock is never extended, so no new kind of row appears. The row
kinds tell the two apart at about 5 requests per candidate, about 17,000 candidates a day at control
2's ceiling. **Round 2's proposed fix is wrong for TOTP, though.** It would route "right password,
wrong code" onto the sign-in counter as N-G does. A TOTP code can be guessed, so that would give a
password holder uncounted code guesses, the hole option C item 1 describes. The fix needs its own
design: who may read which audit rows and lock events, or records that do not depend on which
counter moved. **That fix is in flight as its own pull request, on branch `b121-e10-audit-oracle`,
ahead of wave 1** (Manager decision 2026-09-28). It must land before 6.1.1 is re-read, because an
assessor reading control 1 will reach it. The lock-state counts separate the outcomes for an
administrator too, who can already reset that password; whether that is acceptable belongs to that
fix.

*Update, 2026-09-28:* that branch builds the per-request reason slug. The lock-event half is closed
by owner ruling 2026-09-28, which makes the lock rows `users:manage`-only, on its own branch
stacked on that one (see the note under AC-10). The lock-state counts stay on the `users:manage`
surface, where the administrator reading them can already reset the password.

### Recommendation

**Adopt N-B2 and N-A in wave 1, and N-G in wave 2. Confidence: medium, about 70 percent, that
this combination is the right shape. High, about 85 percent, that N-C1, N-D and N-F should not
ship.** The doubt sits in N-B2 part 4. Reordering the first sign-in touches the gate that the web
console and the API both run, the tests pin the old order on purpose, and round 1 found one bypass
of it (the console's in-process call) that a route-only fix would have missed. Round 1 found the
first draft's central claim false; round 2 found nothing HIGH in the revision, which is why the
figure is not lower. **Wave 1 has a cost the owner should see:** until wave 2 ships, a holder under the requirement must enrol
TOTP even if they would rather use only a passkey, and cannot remove TOTP later. Wave 2 lifts that
for discoverable passkeys.

After both waves, under the shipped defaults, every local account without TOTP has a way past a
lock that wrong passwords set:

| Account | Its way past |
|---|---|
| Created or reset, not yet claimed | Nothing to get past: wrong passwords arm no lock on a generated credential |
| Holder enrolling at first sign-in | Enrols TOTP, or from wave 2 a discoverable passkey, before rotating |
| The first administrator | TOTP from birth, so option E's combined sign-in |
| Lost every factor | The administrator's factor reset also issues a generated credential |
| Passkey-only, with a discoverable passkey | The passkey combined sign-in (wave 2) |
| Passkey-only, with no discoverable passkey | Not reachable under the defaults: part 4 and the last-factor guard never let a holder reach it, and the census names one reached any other way |

### Residuals it still leaves

1. **Non-default postures.** With `require_mfa` off, or the scope narrowed to administrators, a
   claimed account with no factor keeps the fixed lock and no way past. So does an account claimed
   while the requirement was off, after it is turned on, until it enrols TOTP; the census names
   it, and part 4 forces TOTP as its first factor. These postures stay outside the documented
   protection by the Manager's reading of the ruling (decision 1 under Status); N-C2 is not
   scheduled.
2. **An owner without the way past.** A TOTP owner who lost the device (residual 2 above), and its
   passkey twin: a client that cannot run the usernameless ceremony. The remedy is `admin-unlock`,
   or the administrator's factor reset.
3. **Passkey-only accounts keep 480 password guesses a day**, because their sign-in lock does not
   escalate. And a holder whose only authenticator cannot store a discoverable credential cannot
   register it in wave 2, so they keep TOTP.
4. **The handover of an issued credential.** Whoever intercepts it can claim the account. That is
   already true of a reset; N-B2 extends it to account creation, and makes the takeover quieter,
   since an interceptor can enrol a factor without rotating.
5. **A weaker lock signal on an unclaimed account.** A campaign against it sends no
   `ACCOUNT_LOCKED` mail; the holder hears at first sign-in.
6. **Control 2's global ceiling** (residual 4 above), unchanged and already accepted for scoring.
   The passkey challenge leg charges it.
7. **The first administrator's TOTP secret in a held-open terminal.** The IDE's Start flow keeps
   the terminal, and its scrollback, after the command exits. Mitigated, not closed, by closing it on
   success and telling the operator to clear it.
8. **The audit-record oracle in built option E**, until its fix lands. That fix is in flight on
   branch `b121-e10-audit-oracle`, ahead of wave 1 (see the adversarial review). It is not caused
   by this amendment, but it sits on the path this amendment extends.
9. **A slow code-guessing campaign can take a dormant TOTP account's way past.** A caller with a
   wrong password and random codes hits a live code about once in a million tries, and each hit
   feeds the second-step counter, which never decays below its threshold. Five hits set a lock
   that refuses the combined sign-in too. At control 2's ceiling that is about 58 days, while every
   sign-in on the engine is already refused (residual 4 above). A decay window on the second-step
   count would close it; it belongs with the built-E row.
10. **With control 2 off, the passkey path can be flooded.** A fast enough flood evicts an owner's
    pre-auth challenge before they finish. Control 2 off already removes limiter 3 and every bound
    on an account's queue, and this joins that list.

Residual 2 has a later option the review raised: recovery codes as a way past, in their own field
that always walks every code, so its time does not depend on the outcome. At the pinned argon2
cost that walk takes about 0.4 seconds, close to the 0.5-second pad, so it needs its own
measurement before anyone designs it in.

### Owner question

None open. The draft carried one, on whether non-default postures are in scope. The Manager
answered it no on 2026-09-28, by reading the ruling's own framing (decision 1 under Status). That
answer is a Manager decision, not an owner ruling.

### Wave plan

**Wave 1: N-B2 and N-A, in one pull request.** N-B2's parts 3 and 4 need each other. Part 3 alone
still leaves the sessionless gap after rotation. Part 4 alone still leaves a typed password that
can be locked before the first sign-in. Write the tests first, and run each against the shipped code
to see it fail for the reason named:

- `tests/_lockout_store_contract.py`, so all three backends run it: a sign-in failure on a row with
  `password_generated` set counts and never sets `locked_until`; a second-step failure on such a
  row still locks; the rehash write leaves the column alone; `set_password` and `create_user` each
  store what their caller states.
- `tests/test_mfa_access_gate.py`: rewrite
  `test_a_must_change_account_with_no_factor_still_rotates_from_a_pending_session` to its new
  meaning. Under `require_mfa`, a must-change account with no TOTP enrols first, and a password
  change is refused until it does, **on both planes**: `POST /me/password` and the console's
  `POST /ui/account/password`. A passkey alone does not open the gate in wave 1, and a passkey
  registration is refused while the account holds no TOTP. An arm with no must-change flag (an
  account whose TOTP was removed while the requirement was off) gets the same gate. With the
  requirement off, the account rotates as today.
- `tests/_lockout_store_contract.py` or the store suites: the rotation write matches no row, and is
  refused, when TOTP was cleared between the check and the write.
- The census, in `tests/test_mfa.py` and the `verify` suite: it names a covered local account with a
  chosen password and no TOTP, and a TOTP secret that fails to decrypt; it names nothing on a store
  built through the new paths; it warns and does not refuse to start.
- `tests/test_mfa.py`: an account made through `create_local_user` and hammered past
  `lockout_threshold` still signs in with its issued credential (this is the arm that catches a
  `create_user` that forgot the keyword); a walk from creation to a chosen password asserts, at each
  step, that the holder has a way past; `admin_reset_mfa` returns a credential, writes it before it
  clears any factor, and leaves the account unlockable until claimed; `disable_mfa` refuses to
  remove TOTP while the requirement covers the account and no other factor with a way past
  remains.
- `tests/test_cli.py`, beside the provisioning tests: the new administrator has TOTP on and passes a
  live sign-in lock with a combined sign-in; a wrong code at the prompt writes nothing; `--json`
  output carries no secret and no recovery code; `--no-totp` is refused while `require_mfa` is on;
  the repair branch clears TOTP, recovery codes and passkeys and revokes the row's sessions.
- `tests/test_security_doc_rate_limits.py`: the control 1 pins move with the new text.

Files are listed under N-A and N-B2. Documentation: `docs/SECURITY.md` (the control 1 row, the
"Control 1 bounds the lock" bullets, residual (1) and its wrong tag, the administrator reset
section, the 6.1.3 Local row); a dated amendment to ADR 0183; `CHANGELOG.md`, because the create
surface and the first sign-in change.

**Wave 2: N-G.** Tests first, in `tests/test_webauthn.py` and `tests/test_mfa.py`: registration
requests `residentKey` required and sets `discoverable`; the begin leg takes no username, returns
the same options shape for every caller and charges control 2; a passkey-only account under a live
sign-in lock signs in with the password and a valid assertion; one arm per routing cell, including
one that asserts "right, invalid" and "wrong, invalid" leave identical counters and identical audit
rows; a `userHandle` for another account counts as invalid; an account with only a non-discoverable
passkey that sends an assertion under a live lock is refused before any verify; a challenge is
single-use and expires; part 4 and the last-factor guard accept a discoverable passkey and refuse a
non-discoverable one; a timing arm against `_FAILURE_BUDGET_SECONDS`. Documentation: the control 1
and control 8 rows, the Local row, and the ADR 0068 amendment.

**Before wave 1: the finding against built option E**, as its own pull request on branch
`b121-e10-audit-oracle`, in flight now. Its test must compare every record a non-owner can read,
row kinds included, across a right and a wrong candidate password, not only the reason field.

**Wave 3 (N-C2) is not scheduled**, by the Manager's reading of the ruling (decision 1 under
Status).

**What moves 6.1.1.** Under the shipped defaults, wave 1 alone may close the malicious-lockout
limb. Every covered local account is then unclaimed with a generated credential or holds TOTP:
part 4 and the last-factor guard allow no other state to be reached, and the census names any
account that reached one before them, for instance while the site ran with the requirement off.
**Round 2 checked every password writer and factor remover and could not build a counter-example
from a fresh store held at the defaults**; that is one reviewer's reading, not a proof. Wave 2
restores the passkey-only choice that wave 1 takes away; it does not close a hole wave 1 leaves. So
after wave 1 merges, and the census reports no account, a vault Builder re-reads 6.1.1. The
lock-state surface has shipped (the 2026-09-28 update under Context), and control 2's global ceiling
is already accepted for scoring. The built-E finding must be fixed first; its fix is in flight on
branch `b121-e10-audit-oracle`, ahead of wave 1. Residuals 1 to 10 of this amendment are for the
assessor to weigh. Residual 1 is outside the documented protection by the Manager's reading of the
ruling.

### Acceptance criteria for this amendment

> To build with the chosen shape; no test exists yet.

- **AC-A1** -- WHILE an account's credential in force is engine-generated, WHEN a password-only
  sign-in fails, THE SYSTEM SHALL count and audit it and SHALL NOT set the sign-in lock.
- **AC-A2** -- WHEN an administrator creates a local account, THE SYSTEM SHALL generate its
  credential and return it once.
- **AC-A3** -- WHILE `require_mfa` covers a local account that holds no factor with a way past
  (TOTP; from wave 2 also a discoverable passkey), with or without the must-change flag, THE SYSTEM
  SHALL refuse its password change on every plane, SHALL allow its enrolment, and SHALL accept only
  such a factor as its first.
- **AC-A3a** -- WHILE `require_mfa` covers an account, THE SYSTEM SHALL refuse a self-service
  factor removal that would leave it no factor with a way past.
- **AC-A4** -- WHEN `admin_reset_mfa` runs on a local account, THE SYSTEM SHALL issue a generated
  credential in the same call.
> **Note (2026-09-29), a Manager decision prompted by PR 1761 (BACKLOG #1132), not an owner
> ruling. It applies to AC-A2 and AC-A4.** This amendment treated the credential generator as
> unable to fail. Since PR 1761 it screens the site's own context words and raises
> `TemporaryPasswordUnavailable` after `_RESET_GENERATION_ATTEMPTS` misses, so account creation, the
> password reset and the factor reset can answer 503. That happens only on a pathological
> `[auth].password_extra_context_words` list. The screen stays, because #1132's intent is that no
> issued credential fails the policy. The failure is made harmless and early instead. Every path
> that issues a generated credential generates it before any row is written, any factor cleared or
> any session revoked, and a route whose action-bound gate already spent the single-use step-up grant
> gives it back (`AuthService.refund_action_step_up`, which restores only a grant it spent, with its
> original deadline). And the engine probes the generator once at start, logging an ERROR on
> failure, and `messagefoundry verify` reports the same as `auth.credential_generation`. Neither
> refuses to start. `provision-admin` issues no generated credential, since the operator types it,
> so it needed no change for this.

- **AC-A5** -- WHEN `provision-admin` completes while `require_mfa` is on, THE SYSTEM SHALL have
  enabled TOTP on the new administrator before its role is written; and WHEN it repairs a roleless
  row, THE SYSTEM SHALL first clear that row's factors and revoke its sessions.
- **AC-A6** -- (wave 2) WHILE the sign-in lock is live on a local account with a discoverable
  passkey, WHEN a sign-in carries the right password and a valid assertion for that account, THE
  SYSTEM SHALL complete it; and WHEN the password is right and the assertion invalid, THE SYSTEM
  SHALL record it exactly as a wrong password with an invalid assertion.
- **AC-A7** -- (wave 2) THE SYSTEM SHALL stage the pre-auth assertion challenge with no username and
  an empty credential list, after charging control 2.
- **AC-A8** -- Every refusal above SHALL keep AC-6's fixed string, status and padded time.
- **AC-A9** -- WHEN the engine starts, and WHEN `messagefoundry verify` runs, THE SYSTEM SHALL name
  every covered local account that holds a chosen password and no factor with a way past, and
  every enabled TOTP secret it cannot decrypt, and SHALL NOT refuse to start on either.

---

## Amendment B (2026-10-06) -- two residuals of option E, accepted by owner ruling

**Status: Accepted (2026-10-06), by two owner rulings given in session to the batch 196 Manager.**
The Manager relayed them to the drafter in its own words. The wording below is that relay, not the
owner's verbatim answer. This amendment builds nothing. It records two limits of option E as built,
so nobody files them again as open work. The Decision and Amendment A stand unchanged.

It answers BACKLOG #2404 and BACKLOG #2284. Every fact below was read at engine `origin/main`
`c587076a4` on 2026-10-06. Find each by the symbol named. How ASVS scoring weighs either residual is
record work for a Manager, and this amendment does not decide it.

### Residual B1: a combined sign-in gets no MFA time floor (BACKLOG #2404)

**What the code does.** `[auth].mfa_verify_min_elapsed_seconds` (1 s by default) floors the time
between a sign-in and its second factor. `_second_factor_too_early` in `auth/service.py` applies it
only while a session's factor is pending. Only `verify_mfa` and `finish_webauthn_assertion` call it.
A combined sign-in carries the password and a TOTP code in one request. `_login_local` mints its
session with the factor already satisfied, so there is no second step to time.

**The bound.** Any code sent to a TOTP-enrolled local account puts a request on the combined path.
But only a caller with both factors completes it: the password and a live TOTP code. A combined
attempt with one factor right is refused and counts on the second-step counter (Decision item 3).
On a local account that lock escalates (Decision item 5).

**Owner ruling, 2026-10-06: accept as a recorded residual. No nonce, and no refusal.** The Manager
put two reasons to the owner:

1. A script needs both factors to complete a combined sign-in. A script that holds both can wait 1
   second, and a wait that short defeats any timing check.
2. The combined sign-in is how a TOTP-enrolled owner gets past a sign-in lock that someone who knows
   only the username set on purpose. Refusing it would reverse option E.

**Considered and declined.**

- A server-issued, single-use sign-in nonce, whose age the engine checks against the floor. A script
  fetches the nonce, waits out the floor, and signs in, so reason 1 defeats it.
- Refusing the combined form while `mfa_verify_min_elapsed_seconds` is above 0. Reason 2 rules it
  out, since the floor is on by default.

**What would reopen it.** At least these:

- a proposal for a timing check that a script holding both factors cannot pass by waiting;
- option E being superseded, so that the combined sign-in goes away, and this residual with it.

### Residual B2: the lockout bound holds within one API process, and not on a both-wrong combined sign-in (BACKLOG #2284)

**What the code does.** BACKLOG #1943 bounds a burst on one account at `lockout_threshold` verifies,
through a per-account queue (`_account_credential_lock`). The Context amendment after the
serial-attacker paragraph names the two cases outside that bound. The `AuthService.login` docstring
gives the detail:

1. Across processes. Engine shards that each serve their own API port keep their own queues. When
   the lock lands, up to one attempt per extra process can already be past the check.
2. A combined sign-in with both factors wrong, while the sign-in lock is live. That lock does not
   refuse a combined sign-in on a local account with TOTP enrolled, so each such attempt is still
   verified. `_route_combined_failure` sends it to the sign-in counter. `next_lockout_state` counts
   it, but a live lock is never extended (Decision item 4), so none of them moves the lock.

**The bounds.** Case 1 is bounded by the process count: at most one extra verify per extra process
each time the lock lands. Case 2 is not refused by any lock, so control 2, the sign-in limiter,
bounds it: by default 10 attempts a minute per client address and 60 in total. That limiter is
per API process too (`auth/ratelimit.py`), so each engine shard that serves the sign-in API adds its
own window. **With control 2 turned off (`[auth].login_rate_limit_enabled = false`), only the
per-account queue paces case 2.** It answers one failure at a time in each process, and nothing
caps the count. Apart from control 2's own throttle answer, a both-wrong combined attempt gets the
same fixed refusal as every other attempt.

**Owner ruling, 2026-10-06: accept both cases as residuals in this amendment. No store-side
pre-count.** The Manager put two reasons to the owner:

1. A both-wrong combined attempt teaches an attacker nothing, and control 2 still bounds it.
2. A pre-count collides with option E and with #1638. The last item under *To resolve on
   acceptance* says why. E picks the counter after the verify. A pre-count would stand as a failure
   until a right-password sign-in finished its second factor.

**Considered and declined.**

- A store-side reserve-then-refund pre-count, on all three backends. Each attempt would reserve a
  count in the store before it verifies, then keep or refund it once the outcome is known. It would
  hold the bound across processes (case 1). It would not change case 2, which is already counted
  and is open because no lock refuses it. The owner declined it for the reasons above. A refund at
  the verify would avoid the #1638 lock-out that reason 2 names. The reservation would still have to
  pick a counter before the verify, which is where it collides with E.

**What would reopen it.** At least these:

- a pre-count design that picks E's counter correctly and does not lock out an owner who stops at
  the code step;
- a need for the per-account bound to hold across engine shards that serve the sign-in API;
- a proposal to refuse case 2 under a live sign-in lock, which would have to keep the owner's way
  past that lock.
