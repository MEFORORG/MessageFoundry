# 0183 — Provision the first administrator offline; no default account at first run

- **Status:** Accepted (2026-09-05; amended 2026-09-23 — see Amendment A) — the provisioning command
  is built with this ADR. Retiring the auto-create is the remaining half and is **not** built; see
  *Out of scope*.
- **Amended 2026-09-23:** retiring the auto-create is now **in scope**, by owner ruling, as a planned
  multi-wave build. Waves 0 to 2 are built (Wave 2 on 2026-09-25); waves 3 to 5 are not.
  Amendment A below reverses the first sentence of
  *What it must not break*, states the end state, and lays out the waves.
- **Date:** 2026-09-05
- **Related:** BACKLOG #1136 (ASVS 6.3.2) · [ADR 0171](0171-offline-administrator-unlock-a-host-gated-cli-recovery-path-for-a-sole-administrator-lockout.md)
  (the same host gate, argued there) · [ADR 0164](0164-record-bootstrap-claimed-ness-never-infer-a-monotonic-lifecycle-fact-from-mutable-credential-state.md)
  (`users.password_claimed_at`) · [ADR 0182](0182-split-the-account-mirror-address-from-the-engine-owned-notification-address.md)
  (`users.notify_email`) · BACKLOG #1236 (sole-administrator recovery) ·
  [CLAUDE.md](../../CLAUDE.md) §0, §9

---

## Context

ASVS **6.3.2** asks that *"default user accounts (e.g. \"root\", \"admin\", or \"sa\") are not
present in the application or are disabled"*. Neither arm holds at the shipped default. On an empty
user table `_ensure_bootstrap_admin` creates an **enabled** local account literally named `admin`
holding Administrator, and the disabled arm is unexpressible at two altitudes: `Store.create_user`
carries no `disabled` parameter, and all three backends hardcode the column rather than binding it.
Both are pinned by `tests/test_first_run_default_account.py`.

The mitigations are real — the password is per-install CSPRNG, must-change, written to an owner-only
file and never logged — which is why the cell reads *partial* rather than *fail*. They do not reach
the verb, which is about the **account**.

**This is a beta with zero deployments** (CLAUDE.md §0). So there is no live exposure to describe and
no migration to stage: what follows is what a deploying site would inherit on first run, and the cost
of a breaking change here is zero.

Two moves were ruled out in advance by the backlog item, and both are still the cheapest diffs in
reach. Renaming `BOOTSTRAP_USERNAME` away from `admin` is not a pass — the verb is about default
accounts and the three names are examples, so a renamed default is the same account with worse
discoverability for the operator. Shortening `bootstrap_expiry_hours` is not a pass either: it makes
the window look small without making the account disabled at creation, and it moves an availability
knob to buy a verdict.

## Decision

**The first administrator is named and credentialled by an operator at the host, offline, before the
engine first serves — so the "not present" arm is the arm taken, and no account exists until a human
names one.** `messagefoundry provision-admin --username <name>` creates it.

The way in is **filesystem authority over the store**, not an account. Every operator who installs
the service already holds it; no attacker on the network does. That is the same gate ADR 0171
already ships `admin-unlock` on, and the argument is not restated here.

Four things this decision fixes in place:

1. **The refusal asks for an ENABLED ADMINISTRATOR, not an empty table.** The 2026-08-20 research
   proposed inheriting `_ensure_bootstrap_admin`'s `count_users() == 0` guard on the ground that it
   widens no authority. That guard is safe only while nothing else can put the first row in, and a
   directory sign-in can: `_upsert_ad_user` calls `create_user` and assigns no role, so one completed
   sign-in leaves a roleless row, a non-empty table and no administrator — reached entirely through
   shipped code. An emptiness guard refuses exactly there, which is the state with no way in.
2. **The credential is read from a terminal, and unattended provisioning is refused in terms.** There
   is no `--password` and no `--password-file`; either would put a standing Administrator credential
   in argv, readable by every other process on the host, or on disk. An unattended MSI/Ansible/NSSM
   install has no terminal, so the pressure to add one is structural rather than hypothetical, and
   the refusal is the decision rather than an omission.
3. **The credential is claimed at birth.** `users.password_claimed_at` is stamped by the command, so
   there is no half-claimed state. ASVS 6.4.6's one-time temp governs an admin-**issued** credential
   handed to a second party, and there is no second party here: the operator typed it. The stamp is
   also load-bearing against WP-3 — an operator who names the account `admin` would otherwise satisfy
   `_unclaimed_bootstrap`, and the retirement sweep would disable the deployment's only
   administrator at `bootstrap_expiry_hours`.
4. **Every interruption point leaves a recoverable store, and the test for that is HOLDS NO ROLES.**
   The row is created with **no** password hash, then the credential is set, then the role is
   assigned, so a crash leaves one of exactly two states: *no hash, no roles* or *hash, no roles*.
   Re-running with the same username completes either. Roleless is one signal rather than a
   conjunction, chosen because it is the only one true at **both** points — and it is also what makes
   the takeover safe, since such an account holds no permission to inherit and this branch is
   reachable only when no enabled administrator exists at all.

   **A draft of this ADR got that wrong and it is recorded rather than quietly corrected.** It also
   refused a stamped `password_claimed_at`, which the credential write sets — so the *second*
   interruption point left a row this command could never complete and WP-3 could never retire. That
   is a stranded install, which is the risk the whole design exists to avoid, and it was invisible
   because the test named both states in its docstring and exercised only the first.

**What it must not break.** The shipped default is unchanged: an operator who does not run this still
gets the bootstrap account, and every existing caller of `initialize()` is untouched. The PHI
security-notice start gate stays fail-closed on a zero-address table; only its message changed, to
name this command.

*Amended 2026-09-23: the first sentence of this paragraph is reversed by owner ruling. The shipped
default will change, and `initialize()` will stop creating an account. The gate sentence still
holds. See Amendment A.*

## Acceptance Criteria

- **AC-1** — WHEN an operator provisions the first administrator, THE SYSTEM SHALL leave it usable
  and claimed, and a later start SHALL add no account beside it.
  → `tests/test_provision_first_administrator.py::test_a_provisioned_administrator_is_usable_and_a_start_adds_no_account`
  *(Reworded at Wave 2, 2026-09-25. It read "WHEN an operator provisions the first administrator
  before the engine first serves, THE SYSTEM SHALL create no default account thereafter", against
  `test_provisioning_first_means_no_default_account_is_ever_present`. Once the auto-create went,
  that became true without running the command, so it now pins what the command itself leaves.)*
- **AC-2** — IF an enabled Administrator already exists, THEN THE SYSTEM SHALL refuse to provision.
  → `tests/test_provision_first_administrator.py::test_it_refuses_once_an_enabled_administrator_exists`
- **AC-3** — WHILE the user table holds only roleless rows a directory sign-in created, THE SYSTEM
  SHALL still provision.
  → `tests/test_provision_first_administrator.py::test_the_guard_asks_for_an_administrator_not_an_empty_table`
- **AC-4** — IF an earlier run left the account half-written at **either** interruption point, THEN
  THE SYSTEM SHALL complete it on a re-run, install the newly typed credential, and report that it
  repaired rather than created.
  → `tests/test_provision_first_administrator.py::test_an_interrupted_provision_is_completed_by_re_running`
  (parametrized over both points)
- **AC-5** — IF the named account holds roles, is disabled, or is directory-owned, THEN THE SYSTEM
  SHALL refuse rather than take it over.
  → `tests/test_provision_first_administrator.py::test_it_refuses_to_take_over_an_account_somebody_is_using`
- **AC-6** — IF no terminal is attached, THEN THE SYSTEM SHALL refuse, and THE SYSTEM SHALL expose no
  flag that supplies the password from argv or a file.
  → `tests/test_provision_first_administrator.py::test_cli_refuses_without_a_terminal`,
  `tests/test_provision_first_administrator.py::test_cli_has_no_password_flag`
- **AC-7** — *Retired at Wave 2, 2026-09-25, with the WP-3 sweep it guarded.* It read: WHERE the
  provisioned account is named `admin`, THE SYSTEM SHALL leave it enabled across a restart past
  `bootstrap_expiry_hours`. Its test,
  `test_provisioning_an_account_named_admin_survives_a_restart_past_the_expiry`, was deleted with
  the sweep: no code now treats an account named `admin` differently from any other.
- **AC-8** — WHEN provisioning succeeds, THE SYSTEM SHALL record an audit row naming the actor.
  → `tests/test_provision_first_administrator.py::test_the_provision_is_audited`
- **AC-9** — IF the supplied notification address is blank, THEN THE SYSTEM SHALL treat it as no
  address in every column and in the audit row.
  → `tests/test_provision_first_administrator.py::test_a_blank_address_is_no_address_in_every_column_and_in_the_audit`

**Two planted controls, recorded because a green suite is not evidence on its own.** Setting the
credential with `must_change_password=True` — dropping the claim stamp — reds AC-1 and AC-7 and no
others, and the captured audit log shows `auth.bootstrap_admin_retired` firing on an account named
`admin` that an operator had just provisioned. *(Measured before Wave 2. The sweep that retired the
account is gone and AC-7 with it, so this first plant no longer has that consequence to show.)* Restoring the draft's `password_claimed_at` refusal
reds AC-4's second parameter and nothing else, which is what separates the two interruption points:
without that parameter the plant passes.

## Options considered

1. **Provision offline, refuse on "no enabled administrator". CHOSEN.** Reaches the "not present"
   arm, needs no store-protocol change, and its host gate already ships.
2. **Create the bootstrap account disabled, plus an out-of-band claim step.** Rejected. The disabled
   arm needs a `disabled` parameter on the Store protocol and a bound column in three backends, and
   the claim step is the half that can strand: a claim ceremony has a half-claimed state, and the
   NSSM wrapper restarts the service on boot with nobody present to finish one.
3. **Create disabled, then auto-enable on first login.** Rejected, and it is the newer trap the
   research names. It makes the credential file's permissions the real control while the `disabled`
   column records a state the system does not enforce — a compensating control resting on a false
   premise (CLAUDE.md §11, SDS-3.7).
4. **Inherit the `count_users() == 0` guard.** Rejected on the measurement above: a directory sign-in
   fills the table without producing an administrator.
5. **Require `--email` unconditionally.** Rejected. An operator with no mail relay would type a fake
   address to get past it, which is worse than an empty column, and the PHI start gate is already the
   single authority on deliverability. The command warns and names the flag instead.

## Consequences

**Positive** — an operator who runs one command before the first `serve` has an install with no
default account at all, which is the verb's first arm reached without a knob. The command doubles as
a recovery path when every administrator is lost, on the same host boundary as `admin-unlock`.
`bootstrap-admin.txt` is never written on that path, because no bootstrap credential is minted.

**Negative / risks** — the refusal is **wider than the bootstrap guard by design**, and that is the
part a reader should weigh rather than skim: it makes provisioning available whenever no enabled
administrator exists, not only on a virgin store. That overlaps BACKLOG #1236's subject. It grants
nothing to a network attacker — reaching it needs the config, the store path and, on an encrypted
store, the key material — but it is a new standing affordance and it is recorded as one.

A mistyped `--db` provisions into a store `serve` will never open, and `serve` then mints the default
account anyway. `admin-unlock` answers that shape with M-31's refuse-a-missing-store guard; this
command **cannot**, because creating the store is the ordinary first-run case. It names the target in
its output instead, which is a weaker control and is stated as one. That name is read off the opened
store's cross-backend `path` descriptor, not off `[store].path` — the latter is the SQLite field, and
on Postgres or SQL Server it would confidently name a file the command never touched, so the only
control covering the mistyped-target hazard would misreport on two of three backends.

`provision_first_administrator` is a second implementation of `create_local_user`'s four writes, with
a different order. The order is a durability property here rather than a preference, so it is not
reused — but the two must now be kept in step by attention, and a rule added to local account
creation could land on one and not the other. Unifying them behind a "the credential is holder-typed"
parameter is the deeper fix and is deliberately not taken in this change.

**Out of scope — and this is the half that decides the cell.** Retiring `_ensure_bootstrap_admin` and
the WP-3 lifecycle is **not** done here, so **ASVS 6.3.2 stays partial**: the shipped default still
mints `admin`. The measured cost is `initialize()`'s 197 call sites across 64 files, plus
`bootstrap_expiry_hours` / `bootstrap_warn_hours`, `_emit_bootstrap_admin`,
`_bootstrap_expiry_reminder`, the `bootstrap_admin_expiring` alert, `tests/test_bootstrap_admin_perms.py`,
six documents and four IDE files. Also unresolved: `users.password_claimed_at` has no reader outside
the lifecycle that deletion removes, so a later pass has to decide whether the column survives — this
ADR gives it a **second** writer and reader, which narrows that question but does not settle it.

*Amended 2026-09-23: this half is now in scope, and the measured cost above is superseded by a
re-measurement. See Amendment A.*

## To resolve on acceptance

- [ ] Whether the wider refusal (no enabled administrator, rather than an empty table) should also
      subsume BACKLOG #1236's recovery affordance, or the two stay separate commands.
- [ ] Whether `scripts/` is inside this cell's corpus. The method names three artifacts while the
      ASVS verifier scans four roots, and `scripts/dev/sqlserver-docker.ps1` carries a hard-coded
      default `sa` password that is in scope only under the wider reading.

*Amended 2026-09-23: Amendment A carries a recommendation on each item. Neither is ruled, so both
boxes stay open.*

## Amendment A (2026-09-23) — the default account is retired, by owner ruling

**The owner ruled on 2026-09-23, and the retirement is now in scope.** The ruling was given to the
batch 121 Manager through AskUserQuestion, with the recommended option chosen. Verbatim:

> "ASVS 6.3.2 (BACKLOG #1136): a stock serve on an empty store still creates an enabled
> Administrator named admin. Retire that default account in the direction of ADR 0183
> (provision-admin), as a multi-wave engine build with an ADR amendment, starting after engine PR
> #1445 lands."

Nothing below is built. This amendment records the decision, the end state and the build order.

### It reverses one sentence of this ADR, on purpose

*What it must not break* opens: "The shipped default is unchanged: an operator who does not run
this still gets the bootstrap account, and every existing caller of `initialize()` is untouched."
That sentence was right for the 2026-09-05 change, which added a way in and removed nothing. **It is
now the thing being reversed.** Three reasons make it the decision:

1. **The cell turns on the default, not on an operator's choice.** *Out of scope* above says so:
   6.3.2 stays partial while the shipped default mints `admin`. An account that a careful operator
   can avoid is still an account the application creates.
2. **The way in already exists and is tested.** The 2026-09-05 build is what makes deletion safe.
   The deletion no longer has to invent a way in while carrying the stranding risk.
3. **There are zero deployments (CLAUDE.md section 0).** No site holds a bootstrap account, a
   `bootstrap-admin.txt`, or a service TOML naming the settings this deletes. So there is **no
   migration shim, no deprecation window and no compatibility alias**. A TOML that still names a
   deleted key is refused at load, as `_reject_unknown_file_keys` refuses any unknown key. That is
   the intended end state, not a hazard to cushion.

The rest of the Decision stands: the enabled-administrator guard, the terminal-only credential, the
claim stamp at birth, and the write order. The gate sentence of *What it must not break* also stands.

### The end state

**`AuthService.initialize()` seeds the built-in roles and creates no account.** After the build,
three paths create a user, and each one needs a person to act first:

- `messagefoundry provision-admin` at the host;
- `create_local_user`, behind `USERS_MANAGE`;
- the directory upsert, after a successful bind, which assigns no role.

What a stock `serve` does on an empty store, gate by gate. The refusals below already ship. The build
changes what the ADR 0167 gate says and adds one WARNING.

| Posture | What happens |
|---|---|
| The literal shipped defaults | **`_serve` refuses before any store opens,** at the first of several configuration gates: the keyless at-rest gate, then the egress gate, then the SMTP transport gate. **None of them asks about accounts,** and this build does not touch them. |
| `enforce`, notices on and required, the other gates satisfied | **The ADR 0167 gate refuses in the lifespan.** It is the only gate that asks the account question. By then `serve` has created the store (`create=True`). Its message branches on which half failed: no enabled Administrator names `provision-admin --username <name> --email <address>`; an Administrator with no address names the offline address setter from Wave 1c and the audited waiver. |
| `[security].enforcement = "warn"` | **It starts, routes HL7, and nobody can sign in.** The ADR 0167 gate already logs a warning here; its text names `provision-admin`. |
| Sign-in required (`[security].require_sign_in`), with the notice requirement waived in writing, or notices off | **It starts, routes HL7, and nobody can sign in.** The gate is skipped, so the engine logs one WARNING naming `provision-admin`. With sign-in not required, no Administrator is needed and nothing is logged. |

**Recommendation: add no new refusal. Confidence: medium.** Four reasons, and the second and fourth
hold only if Wave 0 comes back green:

1. **At the shipped posture the account question already has one gate, and it refuses.** The ADR
   0167 gate refuses a store with no addressed Administrator, and an empty store is one. A second
   gate on almost the same question would state one fact twice (SDS-3.5), and they would drift.
2. **The retirement makes that gate's message true.** Today it tells a refused operator that
   `provision-admin` will not help, because the bootstrap account minted a moment earlier is an
   enabled Administrator. After retirement a refused store holds no Administrator, so the command
   succeeds against it. **On a Windows service on SQLite this is the start-then-provision order that
   ADR 0163 says strands the operator,** because the service created the store and holds its only
   ACL entry. Wave 0 measures file access in that order, and Wave 2's hosted check runs it end to end.
3. **A refusal in every posture would tie HL7 routing to account state.** NSSM restarts the service
   at boot and after a crash with nobody present, which Option 2 above already weighs. An operator
   who chose `warn` chose to keep the engine running through a failed precondition. This would be
   the one precondition that ignores that choice.
4. **An engine with no account strands nobody,** if Wave 0 holds: one host action fixes it, on the
   gate ADR 0171 argues. ADR 0163 states this cost as its honest residual.

**If Wave 0 shows either order is broken and no fix lands, this recommendation fails with it.** Then
the only safe end state keeps account creation inside the service process, which is ADR 0163's
engine-consumed design, and this amendment goes back to the owner.

**The address half can strand an install, and the build should give it an offline fix.** The ADR
0167 gate asks for an enabled Administrator **with a notification address**. An Administrator with
no address can arise two ways: `provision-admin` without `--email`, which succeeds with a warning,
or an account made in the web console without one that becomes the only enabled Administrator. Then
the next start is refused, `provision-admin` refuses because an enabled Administrator exists, the web
console cannot be reached, and no CLI sets `notify_email` offline. The operator's only exit today is
the audited waiver (`[alerts].security_notifications_required = false`) or `warn`, which the refusal
names. That exit is real, so this is not a dead end, but it trades a control away to get in.
**Recommendation, confidence medium:** a host-gated offline command, on the same gate as
`admin-unlock`, that sets `notify_email` on an existing enabled Administrator, refuses a blank value,
cannot clear an address, and is audited. The gate's address branch names it. `--email` on
`provision-admin` stays optional, as Option 5 decided: a requirement tied to the gate cannot be
evaluated honestly from the CLI, because the gate does not read the relay settings and the CLI cannot
see the service's NSSM environment (the same trap BACKLOG #1905 fixed for the key).

**Rejected: refuse every `serve` that finds no enabled Administrator.** It duplicates the gate at the
default and overrides the operator's posture everywhere else.

**Rejected: a web console banner saying the instance is unprovisioned.** It would tell any network
caller that the install has no Administrator. The operator who needs that fact reads it in the host
log. Confidence: medium.

**Left open, recommendation low-confidence, and not part of Wave 2:** whether `serve` should stop
creating a missing SQLite store (`create=True`, BACKLOG #1780). After retirement a store that `serve`
creates cannot be signed into until someone provisions it, and on a Windows service it hands the
store's only ACL entry to the service before the operator has acted. Refusing a missing store would
also turn the mistyped-`--db` weakness in *Consequences* into a hard stop. But `windows-service-smoke`,
the IDE Start flow, the lifespan's own open and the #1780 documents all rely on `serve` creating the
store. If Wave 0's result argues for it, it becomes its own wave holding those files.

### What the retirement must not break

- **The ADR 0167 gate stays fail-closed.** Only its message changes.
- **`provision-admin` keeps its refusal predicate.** It still asks for an enabled Administrator.
- **The admin-issued temporary credential still expires.** `initial_password_expiry_hours` and
  `initial_credential_deadline` (ASVS 6.4.1) never depended on the bootstrap, and they stay.
- **The directory sign-in path is unchanged.** It still assigns no role.
- **The store backends need no behaviour change.** `create_user` keeps its signature, because the
  disabled arm is still not the arm taken. Their bootstrap text is comments only, and at least these
  go stale: the `_secure_file_async` docstring and the `password_claim_set` note in `store.py`, the
  `password_claimed_at` migration comments in `store.py`, `postgres.py` and `sqlserver.py`, and the
  `open_store` docstring in `base.py`. Wave 4 holds them.
- **`users.password_claimed_at` stays.** After the build nothing in `auth/` reads it: its one reader
  is `_unclaimed_bootstrap`, which goes. Its writers stay, and the fact it records is still true.
  Dropping it is a schema change on three backends that buys nothing. Recommendation: keep it, and
  say why in the migration comments Wave 4 rewrites. Confidence: medium.
- **The `bootstrap-admin.txt` guards stay:** the `.gitignore` line, the scaffold's generated
  `.gitignore` line, and the `.claude/settings.json` rule. Development checkouts that ran `serve`
  before Wave 2 still hold a live file, and a guard for a file that should not exist costs nothing.

### The cases the ruling has to cover

**An unattended install, with no terminal and no `--password`.** The command still refuses with no
terminal, and it still has no password flag. What changes is the service: today an unattended install
gets a working account through `bootstrap-admin.txt`, and after retirement it gets none until a person
runs the command once at the host. That is the ruling's intended cost. Under the shipped posture NSSM
restarts the refusing service on its throttle, and each log line names what is missing. **Do not add
a password flag, a password file or an environment variable to finish an unattended install.** Item 2
of the Decision stands, and ADR 0163 already rejected "supply the first password via the service
environment".

**The Windows service store ACL, which ADR 0163 raised and this ADR never answered.** ADR 0163
consequences 1 and 2 say that `MessageStore.open` re-secures the SQLite trio on every open with
`icacls /inheritance:r /grant:r <current user>:F`. So whichever identity opens a fresh store first
becomes its only principal. An operator who provisions first locks the service account out, and a
service that starts first locks the operator out. Re-read at this amendment's base in `_secure_file`
(`messagefoundry/store/store.py`): the grant is still the current user alone. **This was read, not
executed.** The bootstrap hides the problem today, because the service creates its own account inside
its own process. After retirement the command is the only way in. So if ADR 0163's reading holds,
**every Windows service install on SQLite under the default virtual account has no working order.**
The hosted `windows-service-smoke` job cannot see this, because it runs with auth off. **Wave 0
measures file access in both orders before anything is deleted.**

A second path to the same lockout: `_provision_admin` opens the store with `create=True` before the
username and password-policy checks run, which happen inside `provision_first_administrator`. So a
refused provision still creates the store and secures it to the operator. Today `serve` then fills
that empty table with the bootstrap; after retirement nothing does. Wave 2 moves those checks ahead
of the open.

ADR 0163's consequence 3, a keyless first audit row, is answered by BACKLOG #1905, which landed in
engine PR 1446 (`01b5dc42b`). That gate refuses before the store opens, which looks like it answers
consequence 4 too; that was not re-measured here.

The server backends have no file ACL but the same question in another form. The command must run as
a database principal with write access to the user, role and audit tables. And open engine PR 1444
makes `external` schema management the server default, so there the order becomes `store
provision-schema`, then `provision-admin`, then `serve`. PR 1444 does not touch `initialize()` or
`auth/service.py`.

**The test suite, measured at engine `58badef96`.** `initialize()` has **255** awaited call sites
across **85** files:

| Where | Call sites | Files |
|---|---|---|
| `messagefoundry/api/app.py`, the lifespan | 1 | 1 |
| `scripts/security/dast_target.py` | 2 | 1 |
| `tests/` | 191 | 61 |
| `packaging/messagefoundry-webconsole/tests/` | 61 | 22 |

**56** of the 254 non-production sites, in **16** files, bind the returned `BootstrapAdmin`. The
other 198 discard it, and their files create their own users. *Out of scope* above records 197 sites
across 64 files, measured on 2026-09-04. The tree has grown since, so plan against these figures.

**A count of call sites is not a count of breakage, so the breakage was measured too.** The full
suite ran with `_ensure_bootstrap_admin` returning `None` as a local plant, never committed, on 16
workers: 141 failed and 10 errored, out of about 20,800. **115 of the failures fall in exactly the
16 files that bind the return value.** The other 36 failures and errors fall in 13 files
(coordination hooks, durability hooks, the connscale smoke), none of which names `AuthService`,
`initialize(` or `bootstrap`. The control that clears them is the plant rerun at low load: those 13
files **with** the plant on 4 workers gave 1 failure, and that one test also fails with no plant at
all. All 16 bootstrap files pass without the plant.

Three dependencies the plant cannot see, so do not read "115 in 16 files" as complete:

- `tests/test_bootstrap_admin_perms.py` drives `_emit_bootstrap_admin` directly, so it stays green.
  It goes with that function in Wave 2.
- The plant leaves WP-3 and the settings in place, so the `bootstrap_username` branch of
  `tests/test_asvs_login_deadline.py` and the tests of the settings and the alert do not fail under it.
- `packaging/messagefoundry-webconsole/tests/test_webui.py::test_users_page_lists_accounts` asserts
  that `"admin"` appears on the users page, as the seeded bootstrap row. It passes on the substring
  in "Administrator" whether or not the row exists, so it will keep passing after its intent is gone.

The plant is local and never runs in CI. So a new test that leans on the bootstrap can land through
any open PR before Wave 2; Wave 2 re-runs the plant at its own base.

**The web console.** It needs no code change. It has no bootstrap-specific path, and a store with no
account shows the ordinary sign-in page, which nobody can pass until an operator provisions.

**The IDE extension.** Its store-less Start flow warns that it creates "a NEW database and a bootstrap
admin", in `ide/src/statusBar.ts`, `ide/src/engineSetupContent.ts`, `ide/src/engineStatusModel.ts`
and `ide/src/engineControlModel.ts`. `ide/src/test/suite/engine-setup.test.ts` asserts that sentence.
After retirement the flow must provision before it serves, and that is more than a string change:
`statusBar.ts` starts the engine with `createTerminal` whose process **is** `serve`, so there is no
shell to chain a command in front of it. Provisioning needs its own terminal, a username prompt, the
same config resolution `serve` uses, and a wait for that terminal to exit before `serve` starts.
Deciding on store presence alone is wrong, because a store can exist with no Administrator in it.
The Start flow should run `provision-admin` whenever it starts a local engine, and treat "an enabled
Administrator already exists" as go-ahead. That works only once `provision-admin` answers that
refusal **before** it prompts for a password, which Wave 2's reordering must include. ADR 0110
section 5 and ADR 0112 describe the old behaviour and need dated notes.

**The documents and stale comments.** At least these state the auto-create as current behaviour or
leave `provision-admin` out of the install order: `docs/SECURITY.md` (*First-run bootstrap admin*,
*Auto-retirement (WP-3)*, *Provisioning the first administrator instead*, its limits table, and the
HIPAA note that the bootstrap admin is not a break-glass path), `docs/CONFIGURATION.md` (the two
settings rows and the alert event list), `docs/EARLY-ADOPTER-GUIDE.md` (section 4.5 and its
checklist), `docs/INSTALL-GUIDE.md`, `README.md`, `docs/SERVICE.md`, `docs/DEPLOYMENT.md`,
`docs/ANTIVIRUS-FIREWALL.md`, `docs/PHI.md`, `docs/VERSION-CONTROL.md`, and
[ADR 0034](0034-static-analysis-triage-policy-accepted-risk-register.md)'s accepted risk for the
clear-text bootstrap password. In code and tests, at least: the `admin-unlock` rationale in
`messagefoundry/__main__.py`, the `_assert_security_notice_is_deliverable` and `has_notifiable_admin`
docstrings, the bootstrap reasoning in `messagefoundry/auth/policy.py` and
`messagefoundry/pipeline/security_notify.py`, the seed-gate comments in
`messagefoundry/pipeline/dr.py`, the store comments listed above, the `auth.bootstrap_admin_created`
rows that the fixtures in `tests/test_dr_server_seed_gate_postgres.py` and
`tests/test_dr_server_seed_gate_sqlserver.py` write, and `tests/test_off_loopback_runbook.py`, which
pins the vault runbook step "Retire the bootstrap Administrator". The ADR convention here is dated
notes rather than same-change rewrites, so none of these is edited by this amendment; each is placed
in a wave below.

### The build, in waves

Each wave leaves `main` green and is sized for one Builder in one turn, except where a row says a
hosted leg needs the Manager. **Order:** Waves 0, 1a and 1c can start now, in parallel. 1b follows
1a. Wave 2 follows 0, 1a, 1b and 1c. Wave 3 follows 2, and Wave 4 follows 3. Wave 5 follows 2 and
runs in parallel with 3 and 4.

| Wave | What it does | Files it holds | Test-first acceptance check | May start when |
|---|---|---|---|---|
| **0 and 0b, one PR** | Measure Windows service store file access in both orders, and fix it if either breaks | `.github/workflows/ci.yml` (an auth-on arm of `windows-service-smoke`, or a sibling job), a helper under `scripts/service/` if needed, and in 0b the fix. The fix's shape is not decided here; one candidate is a named service principal granted Modify on the store trio | The bootstrap is still live here, so the arms measure **file access**, not the end-state flow. Both run as the runner identity through `_provision_admin`'s own open path, with only the password reader patched, since a hosted runner has no terminal. **Provision first:** provision with `--email`, start the NSSM service under the default virtual account, sign in, get a session. **Start first:** start the service on a fresh store and let it refuse, open that store through the CLI's path as the operator, then restart the service and show it can still open the store the operator's open re-secured. The arm configures an SMTP sink and a store key so the earlier gates pass. This job runs only on schedule, `workflow_dispatch` and `merge_group`, never on `pull_request`, and a red leg fails the required CI gate. So the Builder pushes the check, the Manager dispatches the workflow on the branch to see it red, and 0b adds the fix on the same branch before the PR is queued | Now. It must land before Wave 2 |
| **1a** | Move tests off the bootstrap account, with no behaviour change: the four largest files | `tests/test_auth_service.py` (28 failures under the plant), `tests/test_mfa.py` (21), `tests/test_webauthn.py` (18), `tests/test_auth_hardening.py` (7), and a shared helper. The helper must behave the same **with and without** the bootstrap. So it writes through the store (`create_user`, `set_password`, `set_user_roles`), not through `create_local_user`, which ends by running `_retire_superseded_bootstrap` and would disable the bootstrap in one mode only. `provision_first_administrator` after `initialize()` refuses while the bootstrap exists. The helper's username must not be `admin`, which collides with the bootstrap. A test that asserts exact audit rows or user counts must stop counting the bootstrap's. A test whose SUBJECT is the bootstrap or WP-3 is not moved; the Builder lists it for Wave 2 | With the plant, every moved test passes; without it, they still pass | Now. The ruling's gate names PR 1445, which was closed unmerged on 2026-09-24; its commits landed inside engine PR 1446 (`01b5dc42b`). **This seat reads the gate as met by that. The Manager should confirm the reading with the owner if the literal wording matters** |
| **1b** | The same, for the other files | `tests/test_session_rotation_wiring.py` (10), `tests/test_security_notice_deliverability.py` (7), `tests/test_session_token_at_elevation_sites.py` (6), `tests/test_last_admin_guard.py` (4), `tests/test_password_corpus_guard.py` (3), `tests/test_notifiable_admin.py` (3), `tests/test_username_identity_collation.py` (2), `tests/test_asvs_phase0.py` (1), `tests/test_admin_new_ip.py` (1), `packaging/messagefoundry-webconsole/tests/test_ui_mfa_gate.py` (1), and `test_webui.py::test_users_page_lists_accounts` with its neighbouring comments | As 1a, plus `test_users_page_lists_accounts` asserts on a user it created rather than on a substring | After 1a lands, because 1a adds the helper |
| **1c** | Add the offline notification-address setter | `messagefoundry/__main__.py` (a new subcommand on `admin-unlock`'s gate), `messagefoundry/auth/service.py` if the write needs a service method, and a new test file | Provision without `--email` under the shipped posture: the next start is refused; run the setter; the start passes. The setter refuses a blank value, refuses a non-Administrator and a disabled account, cannot clear an address, and writes an audit row naming the OS user | Now. It is useful before retirement, since the strand exists today |
| **2** | Delete the auto-create and the WP-3 lifecycle | `messagefoundry/auth/service.py` (`BOOTSTRAP_USERNAME`, `BootstrapAdmin`, `_ensure_bootstrap_admin`, `_unclaimed_bootstrap`, `_retire_superseded_bootstrap` and its callers in `initialize()`, the login path and `create_local_user`, `bootstrap_expiry_warning`, `bootstrap_deadline_configured`, the `has_notifiable_admin` docstring); `messagefoundry/api/app.py` (`_emit_bootstrap_admin`, `_bootstrap_expiry_reminder` and its task, the skipped-gate WARNING, the gate's branched message and its docstring); `messagefoundry/__main__.py` (`provision-admin` answers "an enabled Administrator exists" and runs the username and policy checks before it prompts or opens; its help, docstring and output; the `admin-unlock` rationale); `scripts/security/dast_target.py` if needed; `tests/test_first_run_default_account.py`, `tests/test_provision_first_administrator.py`, `tests/test_asvs_login_deadline.py`, the WP-3 tests 1a and 1b listed; delete `tests/test_bootstrap_admin_perms.py` | AC-10 to AC-13 and AC-15 below, each red on `main` first. The plant check again at this wave's base. Then the Manager dispatches the Wave 0 job with a third arm, the end-to-end start-first flow across two identities: refused, provisioned, restarted, signed in | Waves 0, 1a, 1b and 1c have landed |
| **3** | Delete the settings and the alert, with the tests and table row that pin them | `messagefoundry/config/settings.py` (`bootstrap_expiry_hours`, `bootstrap_warn_hours`, and `bootstrap_admin_expiring` in the alert event list); `messagefoundry/pipeline/alerts.py`; `messagefoundry/pipeline/alert_sinks.py`; `messagefoundry/scaffold.py` only if it names the deleted settings; `tests/test_alert_sinks.py`, `tests/test_alert_rules.py`, `tests/test_settings.py`; **`tests/test_security_doc_rate_limits.py`, `tests/test_security_doc_drift.py`, and the `bootstrap_expiry_hours` row of `docs/SECURITY.md`'s limits table**, because deleting the field reds those tests and editing the row alone reds them the other way; `docs/CONFIGURATION.md` | A service TOML naming `bootstrap_expiry_hours` is refused at load as an unknown key, and an alert rule naming `bootstrap_admin_expiring` is refused. Leave both keys out of `_REMOVED_KEYS` in `config/settings.py`: that is the loader's named-refusal table, so adding them changes behaviour, and `tests/test_docs_cite_no_refused_config_keys.py` would then flag documents that Wave 4 has not yet rewritten | Wave 2 has landed |
| **4** | Rewrite the operator documents and the stale comments | The rest of `docs/SECURITY.md`, `docs/EARLY-ADOPTER-GUIDE.md`, `docs/INSTALL-GUIDE.md`, `README.md`, `docs/SERVICE.md`, `docs/DEPLOYMENT.md`, `docs/ANTIVIRUS-FIREWALL.md`, `docs/PHI.md`, `docs/VERSION-CONTROL.md`, `CHANGELOG.md`, a dated note on ADR 0034; comments only in `messagefoundry/pipeline/dr.py`, `messagefoundry/auth/policy.py`, `messagefoundry/pipeline/security_notify.py`, `messagefoundry/store/store.py`, `postgres.py`, `sqlserver.py` and `base.py`; the seed-gate fixtures; `tests/test_off_loopback_runbook.py`, with the vault runbook step it pins changed in the vault in step | The doc-drift tests pin the new SECURITY.md prose and fail on the old. The seed-gate tests still pass with a fixture event the build did not delete. The runbook test names no bootstrap step | Wave 3 has landed, since both hold `docs/SECURITY.md` |
| **5** | Change the IDE Start flow | The four `ide/src` files above, `ide/src/test/suite/engine-setup.test.ts`, and dated notes on ADRs 0110 and 0112. If the sequencing is too large for one turn, split it: 5a the plan model and strings, 5b the terminal sequencing in `statusBar.ts` | The mocha suite asserts that the Start plan provisions before it serves, that "an enabled Administrator already exists" counts as go-ahead, and that no string promises a bootstrap admin. Red first. The pure-model tests do not reach the sequencing in `statusBar.ts`, so 5b needs its own check | Wave 2 has landed |

**Open PRs holding the same files, at this writing.** They churn, so the Manager re-reads the open PR
file lists when it dispatches each wave.

| File | Open engine PRs touching it |
|---|---|
| `.github/workflows/ci.yml` | 1443, 1444, 1455 |
| `messagefoundry/auth/service.py` | 1432, 1434, 1457, 1458, 1460 |
| `messagefoundry/api/app.py` | 1442, 1457, 1462 |
| `messagefoundry/__main__.py` | 1442, 1443, 1444, 1449, 1462 |
| `messagefoundry/config/settings.py` | 1432, 1440, 1442, 1443, 1444, 1447, 1457, 1462 |
| `messagefoundry/pipeline/alerts.py`, `alert_sinks.py`, `security_notify.py` | 1442; 1440; 1457 |
| the store backends | 1440, 1442, 1444 |
| `docs/CONFIGURATION.md` | 1432, 1440, 1442, 1443, 1444, 1447, 1458, 1462 |
| `docs/SECURITY.md` | 1432, 1434, 1443, 1447, 1462 |
| `docs/DEPLOYMENT.md`, `docs/PHI.md`, `docs/EARLY-ADOPTER-GUIDE.md`, `README.md` | 1443, 1458; 1442, 1443; 1443; 1443 |
| `CHANGELOG.md` | ten open PRs |
| `tests/test_security_doc_drift.py` | 1432, 1447 |
| `tests/test_password_corpus_guard.py` | 1460 |
| `packaging/messagefoundry-webconsole/tests/test_webui.py` | 1432, 1440, 1456 |
| `ide/src/engineStatusModel.ts` | 1456, which also adds deadline text to the credential surfaces (BACKLOG #1141) |

After the last wave the vault re-scores 6.3.2, and 6.4.5 with it: ADR 0163 question 3 records that
half of 6.4.5's evidence dies with WP-3. That is vault work, not an engine wave. **BACKLOG #1136
stays open until the build and the re-score both land.**

### New acceptance criteria

*Headed "planned and not yet tested" until Wave 2 (2026-09-25), which wrote AC-10 to AC-13, AC-15
and AC-16's message half as tests, each red at its base first.*

- **AC-10** — WHEN `serve` starts on a store with no users, THE SYSTEM SHALL create no account.
  → `tests/test_first_run_default_account.py::test_a_fresh_store_gets_no_account`, which replaces
  `test_fresh_store_gets_an_enabled_account_named_admin`.
- **AC-11** — IF the ADR 0167 gate refuses a store with no enabled Administrator, THEN its message
  SHALL name `provision-admin`, AND provisioning that store SHALL let the next start pass.
  → `tests/test_start_without_an_administrator.py::test_the_gate_refuses_an_empty_store_and_provisioning_it_lets_the_next_start_pass`
  under one identity, and the hosted third arm across two: `windows-service-smoke`, step *Store
  access, auth on -- start first, then provision, end to end*, which runs
  `scripts/service/measure-store-access.ps1 -Order StartFirstEndToEnd`.
- **AC-12** — WHILE sign-in is required and no enabled Administrator exists, WHEN the engine starts and
  the ADR 0167 gate is skipped, THE SYSTEM SHALL log one WARNING naming `provision-admin`.
  → `tests/test_start_without_an_administrator.py::test_a_posture_that_starts_logs_one_warning_naming_provision_admin`
  (warn, waived, notices off), with two controls that must log none.
- **AC-13** — THE SYSTEM SHALL write no `bootstrap-admin.txt` on any path.
  → `tests/test_start_without_an_administrator.py::test_no_start_writes_a_bootstrap_credential_file`
  and `::test_no_engine_code_names_the_bootstrap_credential_file`, plus the hosted third arm.
- **AC-14** — WHERE the store is SQLite under a Windows service, THE SYSTEM SHALL leave a store that
  both the service account and the provisioning operator can open, in either order.
  → planned, Wave 0: the hosted check above.
- **AC-15** — IF `provision-admin` refuses a username or password, OR finds an enabled Administrator,
  THEN THE SYSTEM SHALL refuse before prompting where it can, and SHALL leave no new store file.
  → `tests/test_provision_first_administrator.py::test_an_argument_it_will_refuse_is_refused_before_the_prompt_and_the_open`,
  `::test_a_password_the_policy_refuses_leaves_no_store` and
  `::test_an_existing_administrator_is_refused_before_the_prompt`, with
  `::test_an_existing_store_with_no_administrator_still_prompts_and_provisions` as the control.
- **AC-16** — IF the ADR 0167 gate refuses because no enabled Administrator has an address, THEN its
  message SHALL name the offline address setter, AND running it SHALL let the next start pass.
  → Wave 1c for the setter; Wave 2 for the message:
  `tests/test_start_without_an_administrator.py::test_an_administrator_with_no_address_is_pointed_at_the_offline_setter`.

AC-1 and AC-7 above change meaning once Wave 2 lands. AC-1 becomes true without running the command,
and AC-7 guards a sweep that no longer exists. Wave 2 rewords the first and retires the second with
the sweep. *(Done at Wave 2; see each criterion's own note.)*

### The two open items: recommendations, not rulings

**(a) Should the wider refusal also take over BACKLOG #1236's recovery? Recommendation: no. Keep the
commands separate, and record the overlap. Confidence: medium-high.** `provision-admin` already covers
one #1236 state by construction: every Administrator is disabled or gone, so the command mints a new
one. It does not reach the other two, and it should not:

- **A locked-out sole Administrator.** Lockout is `locked_until`, not `disabled`, so that account is
  still an enabled Administrator and the command refuses. ADR 0163 names this trap.
  `admin-unlock` (ADR 0171) is the answer.
- **An enabled sole Administrator who forgot the password.** Covering it would mean taking over an
  enabled account from the host. ADR 0171 declined exactly that for `admin-unlock`: "a reset would hand
  whoever ran the command a working account".

The retirement changes #1236 in one way only. Its "re-bootstrap fires only on an EMPTY users table"
leg goes, because nothing re-bootstraps. The wider predicate here replaces it. The Wave 1c address
setter sits on the same host gate and is a neighbour of #1236, not part of it.

**(b) Is `scripts/` inside cell 6.3.2's corpus? Recommendation: no. Confidence: medium.** The
assessment method, `docs/ASVS-ASSESSMENT-METHOD.md` section 2, declares scope positively: the engine,
the web console and the IDE extension, "assessed as source". The verifier's four roots are where its
absence instrument searches, and an instrument that searches wider than the scope does not widen the
scope (SDS-3.8). `scripts/dev/sqlserver-docker.ps1` is a developer helper for a loopback container. It
is not in the sdist, whose `only-include` names `messagefoundry` and four metadata files, and it is not
in the wheel. So it cannot be "present in the application". Two cautions keep this at medium:

- The verb's own examples include `sa`, a database principal, and `scripts/service/` holds operator
  install tooling that `docs/SERVICE.md` tells a site to run. A reader could take "the engine,
  assessed as source" to include those.
- The 2026-08-20 V6 research, in its section 7, asked for this boundary to be settled once in the
  method rather than per cell. That is a method edit, and this amendment does not make it.

Fix the literal anyway, as hygiene that moves no verdict: require `MEFOR_STORE_PASSWORD`, or generate
a random password per container.
