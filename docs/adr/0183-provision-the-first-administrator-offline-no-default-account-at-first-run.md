# 0183 — Provision the first administrator offline; no default account at first run

- **Status:** Accepted (2026-09-05) — the provisioning command is built with this ADR. Retiring the
  auto-create is the remaining half and is **not** built; see *Out of scope*.
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

## Acceptance Criteria

- **AC-1** — WHEN an operator provisions the first administrator before the engine first serves, THE
  SYSTEM SHALL create no default account thereafter.
  → `tests/test_provision_first_administrator.py::test_provisioning_first_means_no_default_account_is_ever_present`
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
- **AC-7** — WHERE the provisioned account is named `admin`, THE SYSTEM SHALL leave it enabled across
  a restart past `bootstrap_expiry_hours`.
  → `tests/test_provision_first_administrator.py::test_provisioning_an_account_named_admin_survives_a_restart_past_the_expiry`
- **AC-8** — WHEN provisioning succeeds, THE SYSTEM SHALL record an audit row naming the actor.
  → `tests/test_provision_first_administrator.py::test_the_provision_is_audited`
- **AC-9** — IF the supplied notification address is blank, THEN THE SYSTEM SHALL treat it as no
  address in every column and in the audit row.
  → `tests/test_provision_first_administrator.py::test_a_blank_address_is_no_address_in_every_column_and_in_the_audit`

**Two planted controls, recorded because a green suite is not evidence on its own.** Setting the
credential with `must_change_password=True` — dropping the claim stamp — reds AC-1 and AC-7 and no
others, and the captured audit log shows `auth.bootstrap_admin_retired` firing on an account named
`admin` that an operator had just provisioned. Restoring the draft's `password_claimed_at` refusal
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

## To resolve on acceptance

- [ ] Whether the wider refusal (no enabled administrator, rather than an empty table) should also
      subsume BACKLOG #1236's recovery affordance, or the two stay separate commands.
- [ ] Whether `scripts/` is inside this cell's corpus. The method names three artifacts while the
      ASVS verifier scans four roots, and `scripts/dev/sqlserver-docker.ps1` carries a hard-coded
      default `sa` password that is in scope only under the wider reading.
