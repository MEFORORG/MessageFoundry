<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# 0182 — Split the account mirror address from the engine-owned notification address

- **Status:** Accepted
- **Date:** 2026-09-03
- **Related:** BACKLOG #1139 (ASVS 6.3.7) · BACKLOG #1020 · [ADR 0142](0142-federated-sso-oidc-authorization-code-pkce-relying-party-hybrid-ad-backed.md) · CLAUDE.md §0, §9, §11

---

## Context

ASVS 6.3.7 asks that users be notified after updates to their authentication details. The engine has
the machinery: eleven event types, an audited pull feed, and a notice about an email change addressed
to the OLD address so the legitimate owner hears about a hostile repoint.

One column defeated it. `users.email` was simultaneously two things:

1. the account's profile address, and on a directory account the **mirror** of the directory's `mail`
   attribute, rewritten on every AD or OIDC login by `_upsert_ad_user`; and
2. the **target** every out-of-band security notice is addressed to.

Two consequences follow from that one fact.

**A directory repoint would replace the address the notice about it has to reach.** BACKLOG #1139
states the resulting question and could not answer it: *"is a directory-driven mail overwrite an
update to authentication details the application must notify, and if so to which address, given the
old value is the only one the engine can still reach and the same operation is replacing it?"* The
question is unanswerable because the premise is wrong, not because the answer is hard.

**A clear was permanent exclusion.** `SecurityEventNotifier.notify` opens `if not event.email:
return`, so an account whose address is removed is structurally excluded from every later notice. The
item names the durability limb explicitly: *"Making the address required at creation does not make it
durable: an explicit null still clears afterwards."*

CLAUDE.md §0 binds the shape of the remedy. MessageFoundry has **zero deployments**, so *"the cost of
a breaking change is currently zero"* and the instruction is to *"prefer the simple, correct end state
over a staged migration or compatibility shim"*. §0 also binds the wording of every severity claim
here: nothing below describes a live exposure, because nothing is running.

## Decision

**Split the column. `users.email` stays the profile mirror; `users.notify_email` is the engine-owned
notification address, and no directory-sync statement names it.**

- `update_user_profile` — the one call `_upsert_ad_user` makes against an existing account — keeps
  writing `display_name` and `email` and nothing else. That is what makes the directory unable to
  reach the notification target.
- `notify_email` is **seeded once at account birth** from whatever address `create_user` carried.
  There is exactly one address at that instant and no reason for the two to differ; after it, no
  directory pass can move it.
- After creation the only writer is `set_user_notify_email`. `AuthService.update_user` calls it when an
  administrator supplies a non-blank address, so a repoint on the engine's own admin surface still
  works.
- Every `_notify_security` call site, `has_notifiable_admin`, and the PHI startup gate
  `_assert_security_notice_is_deliverable` read `notify_email`.

**The durability rule is the setter's signature.** `email: str`, not `str | None`, so a clear is
unrepresentable at every call site; `require_notify_email` rejects the whitespace-only string that
would slip past the type and mean the same thing. The notification address is **repointable but not
erasable**.

What this must not break: the EMAIL_CHANGED notice still goes to the address on file *before* the
change, so a mistaken or hostile repoint still alerts the previous holder. And a clear of the profile
address is still announced — it is still a change to the account's contact details — it simply no
longer ends the account's notices.

## Acceptance Criteria

- **AC-1** — WHEN a directory login writes a different `mail` attribute, THE SYSTEM SHALL update
  `users.email` and SHALL leave `users.notify_email` unchanged.
  → `tests/test_auth_store.py::test_the_directory_sync_write_cannot_move_the_notification_address`
- **AC-2** — WHEN an account emits a security notice after a directory repoint, THE SYSTEM SHALL
  address it to `notify_email` and never to the directory's new value.
  → `tests/test_auth_service.py::test_a_directory_repoint_cannot_redirect_the_accounts_notices`
- **AC-3** — IF a caller supplies an empty or whitespace-only notification address, THEN THE SYSTEM
  SHALL raise `ValueError` and leave the stored address standing.
  → `tests/test_auth_store.py::test_the_notification_address_is_repointable_but_not_erasable`
- **AC-4** — WHEN an administrator clears an account's profile address, THE SYSTEM SHALL clear
  `users.email`, SHALL leave `users.notify_email` standing, and the account SHALL still receive later
  notices.
  → `tests/test_auth_service.py::test_clearing_the_profile_address_leaves_the_account_still_notifiable`
- **AC-5** — WHEN an administrator supplies a new address, THE SYSTEM SHALL move `notify_email` to it
  and SHALL address the notice about that change to the previous one.
  → `tests/test_auth_service.py::test_an_admin_can_still_repoint_where_notices_go`
- **AC-6** — THE SYSTEM SHALL decide PHI startup deliverability from `notify_email`, so a profile-only
  write does not satisfy the gate.
  → `tests/test_auth_service.py::test_the_deliverability_gate_reads_the_notification_address`
- **AC-7** — WHEN a database created before this change is opened, THE SYSTEM SHALL add the column and
  seed it from `email`, so no existing account silently stops receiving notices.
  → `tests/test_auth_store.py::test_the_schema_upgrade_seeds_the_new_column_on_a_pre_split_database`
- **AC-8** — THE SYSTEM SHALL expose `set_user_notify_email` on every store backend.
  → `tests/test_store_backend.py::test_messagestore_satisfies_store_protocol`

## Options considered

1. **Two columns, the directory writing only the mirror** — the notice for a directory repoint goes to
   an address that operation is not replacing, and #1139's research question dissolves rather than
   being answered. **CHOSEN**, and it is the path the item's own research nominates.

2. **One column, and refuse the directory write when a human set the value** — keeps the schema, needs
   a provenance flag to tell a human-set address from a directory-set one, and that flag is a second
   column doing the split's job with less clarity. It also leaves the directory able to write the
   notification target on every account nobody has touched. Rejected.

3. **One column, and notify the directory's NEW address on a repoint** — cheap, and wrong in the case
   that matters: whoever repointed the attribute is the party the notice would reach. Rejected; the
   item's cell already rules out counting the audited pull feed as the notice for the same reason.

4. **Make the column NOT NULL, as the durability rule** — the other option the item offers. Rejected
   because accounts may still be created with no address at all: the first-login set-address step that
   would make one mandatory is a follow-on, out of scope here. NOT NULL would therefore need a
   placeholder value, and the notifier treats an empty address as absent anyway — a constraint that
   reads as a guarantee and delivers none. Refusing the clear delivers the guarantee.

5. **A dual-read, a back-compat shim, or a deprecation window** — rejected under CLAUDE.md §0. There is
   nothing deployed to break and nobody to notify, so a staged migration is a real cost paid to protect
   users who do not exist.

## Consequences

**Positive** — A directory repoint can no longer redirect an account's notices, and a clear can no
longer end them. The startup deliverability gate now measures the column a notice is actually
addressed to rather than one adjacent to it (SDS-3.8). `UserSummary.notify_email` makes the split
visible to an operator, who would otherwise read `email` and draw the wrong conclusion.

**Negative / risks** — Two addresses on an account is one more thing to explain, and an operator may
expect editing the profile address to be the only control. `AuthService.update_user` mitigates that by
moving both when a non-blank address is supplied, so the ordinary edit behaves as before; the
difference shows only on a clear and on a directory sync. The Postgres and SQL Server legs run on
hosted runners only, so backend parity is CI's to confirm rather than a local run's.

**Out of scope**, recorded on BACKLOG #1139 as follow-ons rather than done here — the first-login
set-address step in the shape of the forced-change confinement; generalising the startup assertion
from *some enabled Administrator* to every enabled account; passkey-removal notice parity; and the
silent drop in `security_notify.py` when no address is on file.

Also out of scope and worth naming: `AuthService.update_user` writes the notification address from the
same field the profile write uses, so there is no way to set the two independently. That is deliberate
— a separate input is an API and console change with no demand behind it yet — but it means an
operator cannot today point notices somewhere the profile does not say.
