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
- **Date:** 2026-09-27
- **Related:** BACKLOG #1131 (the row this answers; ASVS 6.1.1) · BACKLOG #1236 (closed 2026-09-26;
  its cycle-cap remainder moved to #1131 by owner ruling) · BACKLOG #1138 (re-proof failures count
  toward lockout, and the per-session cap) · BACKLOG #1638 (a lock refuses directory sign-ins) ·
  [ADR 0171](0171-offline-administrator-unlock-a-host-gated-cli-recovery-path-for-a-sole-administrator-lockout.md)
  (`admin-unlock`; option E amends it, see Decision item 8) · [ADR 0068](0068-browser-webauthn-passkeys-offloopback.md) (passkeys) ·
  [`docs/SECURITY.md`](../SECURITY.md), "The documented protection set (ASVS 6.1.1)"

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
factors wrong, which the sign-in lock does not refuse.

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
`_client` reads `request.client.host`, `[api].trusted_proxies` defaults to empty, so every caller
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
- [ ] Counting an attempt before it verifies, so a parallel burst gets 5 verdicts per cycle rather
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
