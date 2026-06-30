# ADR 0045 — User-definable custom RBAC roles over the existing Permission catalog

- **Status:** Accepted (2026-06-27, built — 0.2.10)  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-06-27
- **Related:** BACKLOG #57 · **#56 alert-instance migration** (the *other* roles/store migration this
  release — **one store migration per release**, coordinate land-order, §D2 / "To resolve") ·
  [ADR 0017](0017-consumer-deployment-model.md) (org-owned config repo across instances — custom roles
  are admin-state, not config) · [CLAUDE.md](../../CLAUDE.md) §2 (deny-by-default RBAC, audit), §9
  ([docs/SECURITY.md](../SECURITY.md) deny-by-default per-route permissions; [PHI.md](../PHI.md)) ·
  [`auth/permissions.py`](../../messagefoundry/auth/permissions.py) `Permission` /
  `Role` / `BUILTIN_ROLE_PERMISSIONS` / `permissions_for_roles` ·
  [`auth/identity.py`](../../messagefoundry/auth/identity.py) `Identity.build` ·
  [`auth/service.py`](../../messagefoundry/auth/service.py) `_roles_from_ids` / `_seed_roles` /
  `_build_identity` / `set_roles` ·
  [`store/store.py`](../../messagefoundry/store/store.py) `roles` table (line 751) /
  `upsert_role` / `list_roles` / `get_user_role_ids` / `set_user_roles`

---

## Context

RBAC ships with a **fixed** set of six built-in roles
([`auth/permissions.py`](../../messagefoundry/auth/permissions.py) `Role`): `ADMINISTRATOR`,
`OPERATOR`, `DEPLOYMENT`, `CODING`, `VIEWER`, `AUDITOR`. The role→permission policy is a hard-coded
table — `BUILTIN_ROLE_PERMISSIONS` — and the module's own docstring names the gap: *"This version ships
a **fixed** set of built-in `Role`s (**no custom-role builder yet**)."* The catalog of capabilities a
role may grant is the `Permission` enum (`monitoring:read`, `messages:view_raw`, `connections:control`,
`users:manage`, `audit:read`, …): a stable, deny-by-default set of named capabilities.

Resolution today is closed over those built-ins end to end:

- `permissions_for_roles(roles)`
  ([`permissions.py`](../../messagefoundry/auth/permissions.py) line 118) unions
  `BUILTIN_ROLE_PERMISSIONS.get(role, frozenset())` — a role that is **not** a built-in grants
  **nothing**.
- `AuthService._roles_from_ids(ids)`
  ([`service.py`](../../messagefoundry/auth/service.py) line 138) maps stored role ids to the `Role`
  enum and **silently drops any id that isn't an enum member** (`Role(rid)` → `ValueError` → `continue`),
  deny-by-default.
- `Identity.build(... roles=...)`
  ([`identity.py`](../../messagefoundry/auth/identity.py) line 40) flattens the role set to a permission
  set via `permissions_for_roles`, once per request, so the API authorization deps answer
  `has(permission)` without touching the store.

So even though a `roles` **table already exists and is already written** — `_seed_roles`
([`service.py`](../../messagefoundry/auth/service.py) line 271) upserts every built-in `Role` into it on
store open via `upsert_role` ([`store.py`](../../messagefoundry/store/store.py) line 4015), and
`user_roles` is a foreign-key reference into it — a row in that table that is **not** one of the six
enum values is inert: `_roles_from_ids` drops it and it grants no permissions. The `roles` table
(`store.py` line 751: `id`, `display_name`, `description`, `builtin`) records a role's **identity** but
**not its permission set** (the permissions live only in the hard-coded `BUILTIN_ROLE_PERMISSIONS`),
so there is nowhere to persist *what an admin-defined role grants*.

The operator gap is the named **Corepoint custom-role** capability: a site wants, e.g., a
"Lab-Ops" role that can monitor + replay + control connections **but not** view raw PHI bodies, or an
"Integration-Reviewer" that reads the audit trail **and** message summaries — combinations the six fixed
roles don't express. Mirth/Corepoint both let an administrator define a named role as a chosen subset of
the capability catalog; MessageFoundry cannot. This ADR closes that gap **without** widening the trust
surface: a custom role can only ever grant capabilities that **already exist** in the `Permission`
catalog — no new permission kinds, no new privilege.

## Decision

**Add user-definable custom roles as an additive overlay on the existing `Permission` catalog: an
admin-defined named role is a chosen SUBSET of existing `Permission`s, persisted in the existing `roles`
table (extended by a single roles-table migration), gated by `USERS_MANAGE`. The six fixed built-ins
stay verbatim; deny-by-default is preserved; custom roles grant nothing the catalog doesn't already
define.**

### D1 — A custom role = a named subset of the existing `Permission` catalog (no new permission kinds)

A custom role is `(id, display_name, description, permissions ⊆ Permission)`. The admin picks a name and
**a subset of the existing `Permission` enum** — `monitoring:read`, `messages:replay`,
`connections:control`, etc. There is **no** new permission kind, no new capability, and **no** way to
grant anything outside the catalog: a custom role is strictly a re-bundling of capabilities the engine
already gates on. This keeps the deny-by-default per-route model
([SECURITY.md](../SECURITY.md)) intact — every route still checks a fixed `Permission`; custom roles only
change *which set of users hold it*, never *what a permission means* or *which routes exist*.

Two capabilities are **carved out** from custom-role assignment (a custom role may not grant them),
because they are privilege-escalation primitives that the fixed `ADMINISTRATOR` deliberately gates:
`USERS_MANAGE` (the permission that creates/edits roles — a custom role that granted it could mint
itself `ADMINISTRATOR`-equivalent power) and `APPROVALS_APPROVE` (dual-control release). Both stay
admin-only; the validator rejects a custom-role permission set containing either. (This is the one place
"subset of the catalog" is narrowed — settle the exact carve-out list on acceptance.)

### D2 — Persist the permission set in the existing `roles` table (one roles-table migration, coordinated with #56)

The `roles` table ([`store.py`](../../messagefoundry/store/store.py) line 751) already records role
identity (`id`, `display_name`, `description`, `builtin`) and is already FK-referenced by `user_roles`
/ `ad_group_role_map`. **It is the right home** — a custom role is just a `builtin=0` row whose
permission set must be persisted. Add **one** nullable column, `permissions TEXT` (a JSON array of
`Permission` wire values, e.g. `["monitoring:read","messages:replay"]`; `NULL` for a built-in row, whose
permissions stay sourced from `BUILTIN_ROLE_PERMISSIONS`), via the **same ALTER-on-open migration
pattern** the store already uses for additive columns
([`store.py`](../../messagefoundry/store/store.py) `_MESSAGE_MIGRATIONS` line 797 and the
`PRAGMA table_info(...)` → `ALTER TABLE … ADD COLUMN` blocks at lines 1360–1399). `NULL` on every
pre-existing row is byte-identical to today (built-ins resolve from code; no custom rows yet), so the
migration is purely additive.

This is a **store migration**, and **only one store migration ships per release**. **#56's
`alert_instance` migration is the other one this release** — the two **must be coordinated** so exactly
one migration lands: either both columns/tables go in the single release migration step, or they are
sequenced so the release ships one coherent schema bump (see "To resolve"). This must land on **all
store backends** that implement the auth surface (SQLite + Postgres + SQL Server), with a roles-table parity
check, exactly as the existing user/session migrations do.

### D3 — Resolve a custom role's permissions in the existing resolution path (overlay, not a fork)

The resolution path is extended, not replaced:

- **`permissions_for_roles` stays the built-in resolver** — it keeps unioning
  `BUILTIN_ROLE_PERMISSIONS` for the six fixed `Role`s.
- A user's effective permission set becomes **`builtin-role permissions ∪ custom-role permissions`**:
  `AuthService._build_identity` ([`service.py`](../../messagefoundry/auth/service.py) line 725) already
  reads `get_user_role_ids(user.id)`; for each id that is **not** a built-in `Role` enum member, it looks
  up that role's persisted `permissions` JSON from the `roles` table and unions the decoded
  `Permission`s into the identity's flat set. Built-in ids continue through `_roles_from_ids` →
  `permissions_for_roles` unchanged.
- `Identity` ([`identity.py`](../../messagefoundry/auth/identity.py)) needs **no shape change** — it
  already carries a flat `permissions: frozenset[Permission]` and answers `has(permission)`; whether a
  permission arrived via a built-in or a custom role is invisible downstream. The per-channel scope
  (`allowed_channels`) is **orthogonal** and unchanged — custom roles compose with it exactly as
  built-ins do.
- **`_roles_from_ids` deny-by-default is preserved**: an unknown/deleted role id still grants nothing
  (a custom role removed from the `roles` table grants nothing on the next request; FK on `user_roles`
  keeps the reference honest). A custom-role permission value that is no longer in the `Permission`
  enum (catalog shrank) is dropped on decode — same deny-by-default rule as `_roles_from_ids`.

The flattening still happens **once per request** from the session's user, so a custom-role edit takes
effect on the next identity build (and admin role/permission edits revoke the affected users' sessions,
mirroring `set_roles` at [`service.py`](../../messagefoundry/auth/service.py) line 1188, so a permission
*reduction* can't linger on a live token).

### D4 — Admin management, gated by `USERS_MANAGE`, fully audited

Custom-role CRUD (create / update permission set / rename / delete) is an admin action gated by
`Permission.USERS_MANAGE` — the same permission that already gates user/role assignment via `set_roles`
— and every mutation writes an `audit_log` row (role id + the resulting permission *names*, **never** PHI
or message content), exactly as `user.roles_changed` / `user.created` already audit through
`AuthService._audit`. The store gains `create_custom_role` / `update_custom_role` / `delete_custom_role`
(or folds into the existing `upsert_role`, which already does an `INSERT … ON CONFLICT … DO UPDATE`,
[`store.py`](../../messagefoundry/store/store.py) line 4015) plus a `list_roles` that now returns the
permission set so the admin UI can render it. Deleting a custom role removes its `user_roles` rows in the
same transaction so no dangling FK / inert assignment survives.

### What this must not break

- **Deny-by-default.** A custom role grants **only** the catalog `Permission`s in its persisted subset;
  an unknown role id, a malformed/empty permission JSON, or a permission no longer in the catalog grants
  **nothing**. No route's permission requirement changes; no new permission kind is introduced.
- **The six fixed built-ins.** `Role` / `BUILTIN_ROLE_PERMISSIONS` / `permissions_for_roles` are
  untouched; built-in rows keep `permissions = NULL` and resolve from code. `ADMINISTRATOR` still holds
  every permission; the last-enabled-admin guard
  ([`service.py`](../../messagefoundry/auth/service.py) `is_last_enabled_admin`) is unaffected (a custom
  role can never *be* `ADMINISTRATOR`, since `USERS_MANAGE`/`APPROVALS_APPROVE` are carved out — D1).
- **One migration per release.** The single `roles.permissions` ALTER is coordinated with #56's
  `alert_instance` migration so the release ships exactly one coherent schema bump.
- **Built-in-only deployments.** With no custom role defined, every `roles` row is `builtin=1` with
  `permissions = NULL`, `_build_identity` resolves exactly as today, and behaviour is byte-identical.
- **Custom roles are admin state, not config.** They live in the store (admin-managed, audited), **not**
  in the org-owned config repo (ADR 0017) and **not** in `connections.toml` — they are not transport
  config and not Router/Handler logic.

## Acceptance Criteria

> EARS form; each linked (`→`) to its test/fixture. `messagefoundry adr-analyze` checks each `→` resolves.

- **AC-1** — WHERE an admin defines a custom role with a subset of `Permission`s, WHEN a user holding
  that role builds an identity, THE SYSTEM SHALL grant exactly that subset (unioned with any built-in
  role the user also holds) and nothing else.
  → `tests/test_custom_roles.py::test_custom_role_grants_exact_subset`
- **AC-2** — WHEN a custom-role definition includes a permission not present in the current `Permission`
  catalog (or its JSON is malformed/empty), THE SYSTEM SHALL drop the unknown value and grant only the
  recognized catalog permissions (deny-by-default).
  → `tests/test_custom_roles.py::test_unknown_permission_dropped`
- **AC-3** — IF a custom-role permission set contains `users:manage` or `approvals:approve`, THEN THE
  SYSTEM SHALL reject the definition (the privilege-escalation carve-out, D1).
  → `tests/test_custom_roles.py::test_escalation_permissions_rejected`
- **AC-4** — WHEN no custom role is defined, THE SYSTEM SHALL resolve permissions exactly as the fixed
  built-in policy does today (byte-identical; built-in rows keep `permissions = NULL`).
  → `tests/test_custom_roles.py::test_builtin_only_unchanged`
- **AC-5** — THE SYSTEM SHALL leave the six built-in roles and `BUILTIN_ROLE_PERMISSIONS` unmodified
  (a custom role can neither redefine a built-in nor reduce `ADMINISTRATOR`).
  → `tests/test_custom_roles.py::test_builtins_immutable`
- **AC-6** — WHERE a custom role's permission set is edited or the role is deleted, WHEN an assigned
  user's next request is authorized, THE SYSTEM SHALL apply the new (or empty) set, and THE SYSTEM SHALL
  write exactly one `audit_log` row per mutation recording the role id + resulting permission names and
  no PHI.
  → `tests/test_custom_roles.py::test_edit_takes_effect_and_audits`
- **AC-7** — THE SYSTEM SHALL gate every custom-role create/update/delete on `Permission.USERS_MANAGE`
  (deny otherwise).
  → `tests/test_custom_roles.py::test_crud_requires_users_manage`
- **AC-8** — THE SYSTEM SHALL persist and resolve the `roles.permissions` column identically on every
  auth-supporting store backend (SQLite + Postgres + SQL Server), via the additive ALTER-on-open migration.
  → `tests/test_custom_roles.py::test_roles_migration_backend_parity`

## Options considered

1. **Named subset of the existing `Permission` catalog, persisted as `roles.permissions` JSON,
   resolved as an overlay in `_build_identity` — CHOSEN.** Reuses the already-written `roles` table,
   the existing ALTER-on-open migration idiom, and the existing one-request flatten; adds **no** new
   permission kind, no new resolver fork, no new config surface. Minimal new surface; deny-by-default
   preserved; matches the Corepoint custom-role model and BACKLOG #57's stated scope.
2. **Let admins define new *permission kinds* (extend the catalog at runtime).** Rejected: the
   `Permission` enum is the contract every route's authorization dep checks; a runtime-defined permission
   would gate **nothing** (no route requires it) yet expand the trust/audit surface and break the
   "deny-by-default per-route" model. #57 is about *re-bundling* existing capabilities, not inventing
   them.
3. **A separate `role_permissions` join table** (one row per role×permission). Rejected for the MVP: a
   normalized join is more schema (a new table + its own migration + parity) for a handful of small,
   read-mostly sets, when a JSON column on the row already-FK'd by `user_roles` resolves in the same
   `_build_identity` read. (Revisit only if per-permission querying across roles becomes a need.)
4. **Editable built-in roles (let an admin tune `BUILTIN_ROLE_PERMISSIONS`).** Rejected: the six
   built-ins are a stable, documented baseline (and the last-admin / separation-of-duties guards lean on
   `ADMINISTRATOR`/`AUDITOR` semantics); mutating them in place would make the deny-by-default baseline
   non-deterministic across instances. Custom roles are **additive**; built-ins stay fixed.
5. **Custom roles as config (org config repo / `connections.toml`, ADR 0017/0007).** Rejected: roles are
   **admin state** (audited, store-resident, session-revoking on change), not transport config and not
   Router/Handler logic; they belong in the `roles` table beside users/sessions, not in a config file.
6. **Status quo (six fixed roles only).** Rejected: forces every site onto one of six bundles and blocks
   the Corepoint-style least-privilege combinations operators ask for — the explicit owner ask.

## Consequences

**Positive** — Operators get the named Corepoint custom-role lever: define least-privilege bundles
(e.g. "monitor + replay, no raw PHI") from the existing capability catalog, without code changes and
without a new permission kind. It reuses the already-written `roles` table, the existing additive-migration
idiom, the existing one-request identity flatten, and the existing `USERS_MANAGE`-gated + audited admin
path — no new mental model, no new config surface, no new resolver fork. Purely additive: every default
(`permissions = NULL`, no custom rows) is today's behaviour.

**Negative / risks** — `_build_identity` gains a per-non-built-in-id `roles`-table lookup (small, cached
per request; built-in-only deployments take the unchanged path). The carve-out list
(`USERS_MANAGE`/`APPROVALS_APPROVE` not custom-assignable) must stay in lock-step with the `Permission`
catalog as it grows, or a future escalation primitive could slip into a custom role — pinned by AC-3 +
the validator. The `roles.permissions` JSON must be validated on write (subset of the catalog, carve-out
respected) and defensively decoded on read (drop unknowns), since a hand-edited DB row is untrusted
input. The single roles-table migration **shares the release's one-migration budget with #56** — a
land-order coordination cost, not a design cost.

**Out of scope / stays fixed** — The six built-in roles and `BUILTIN_ROLE_PERMISSIONS` (immutable);
the `Permission` catalog itself (no runtime-defined permission kinds — option 2 declined); per-channel
RBAC scope (`allowed_channels`, orthogonal — custom roles compose with it unchanged); AD-group→role
mapping (`ad_group_role_map` already FK's `roles`, so a custom role can be AD-mapped for free, but the
mapping mechanism is untouched here).

## To resolve on acceptance

- [ ] **One migration per release — coordinate with #56.** Confirm the `roles.permissions` ALTER and
  #56's `alert_instance` migration ship as the **single** release store-migration (combined step, or
  sequenced) so neither clobbers the other and the release bumps the schema exactly once. Decide the
  land-order before either touches `store.py`'s open-time migration block.
- [ ] **Carve-out list.** Confirm the exact set of permissions a custom role may **not** grant —
  `USERS_MANAGE` + `APPROVALS_APPROVE` proposed (D1); decide whether `SERVICE_CONFIGURE` /
  `CONFIG_DEPLOY` (privileged-but-not-escalating) join the list or stay assignable.
- [ ] **Built-in id collision.** Confirm a custom role's `id` is namespaced or validated so it can never
  collide with a built-in `Role` value (else `_roles_from_ids` would mis-route it to the built-in
  resolver) — e.g. reject any `id` equal to a `Role` value, or require a `custom:` prefix.
- [ ] **Storage shape.** Confirm `roles.permissions` as a JSON array column (D2) vs a normalized
  `role_permissions` join (option 3) — JSON proposed for the MVP; revisit only if cross-role per-permission
  querying is needed.
- [ ] **API surface + console/IDE.** Confirm the `USERS_MANAGE`-gated CRUD endpoints and whether the
  PySide6 console / VS Code admin UI render the permission-set editor this release or defer to a follow-up.
- [ ] **Session revocation on edit.** Confirm a custom-role permission *reduction* revokes the affected
  users' live sessions (mirroring `set_roles`), so a narrowed role can't linger on an active token.
