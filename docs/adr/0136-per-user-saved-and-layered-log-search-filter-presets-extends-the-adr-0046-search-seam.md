# 0136 — Per-user saved & layered Log-Search filter presets (extends the ADR 0046 search seam)

- **Status:** Accepted (2026-07-18) — DEMAND-GATE-BACKLOG Wave 5 (lane `dg-s8b`); build phased, pushes/PR owner-approved
- **Date:** 2026-07-18
- **Related:** BACKLOG #151 · [ADR 0046](0046-message-content-search.md) (the content-search seam this extends) · [ADR 0064](0064-schema-init-fastpath.md) (schema-hash fast-path — the bump) · [ADR 0045](0045-custom-rbac-roles.md) (3-backend roles-migration precedent) · [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) (store cipher + cell-bound AAD) · [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) (PHI-read hop guard) · CLAUDE.md §9 (PHI)

---

## Context

The ADR 0046 content search (BACKLOG #51) enters its metadata + content filters fresh every time —
nothing names, persists, recalls, or composes a filter set. BACKLOG #151 wants an operator to **save
named Log-Search filter presets** server-side per user, then **recall and layer several into one
combined query** during high-volume triage (Corepoint "save/retrieve, layered searches" parity).

Two constraints bind the design:

- **A saved preset's `content`/`field_value` term is PHI-shaped** — it may itself be an MRN or a
  patient name (ADR 0046 §4). The web console's `routes/search.py` **deliberately DROPS the content
  term across the step-up redirect** (it is a GET query that must not be preserved). A persisted preset
  must not weaken that posture: *"Never log full message bodies … every PHI access is audited"*
  (CLAUDE.md §9).
- **Store-serialized schema.** This adds a table to a store whose server backends fast-path schema
  init on an [ADR 0064](0064-schema-init-fastpath.md) content-hash of their `_SCHEMA` DDL, and it lands
  as the **third/last** store slot in this multi-session build (after S3a `processed_files` + S1b
  `alert_instance`), so its DDL must layer cleanly and correctly across **all three** backends.

## Decision

Add a **per-user `search_presets` table** (SQLite/Postgres/SQL Server) whose PHI-shaped **`criteria`
column is AES-256-GCM-encrypted at rest**, and a **bounded, server-side layered-query composer** over
the ADR 0046 `search_messages` seam. Presets carry the full content-search form state; recall and
layering are **step-up-gated + audited**, and the content term **never round-trips to the client**.

1. **The table (3-backend, id-keyed).** `search_presets(id PK, owner, name, criteria, created_at,
   updated_at, UNIQUE(owner, name))` — SQLite `TEXT`/`REAL`, Postgres `TEXT`/`DOUBLE PRECISION`, SQL
   Server `NVARCHAR`/`FLOAT` with an `IF OBJECT_ID … CREATE TABLE` guard, plus an `ix_search_presets_owner`
   index — following the ADR 0045 roles-migration / ADR 0129 `processed_files` precedent. On SQLite the
   `CREATE TABLE IF NOT EXISTS` goes into `_SCHEMA` (created every open); on the server backends the DDL is
   appended to each `_SCHEMA` list, which **automatically moves `_schema_hash()`** — that *is* the
   [ADR 0064](0064-schema-init-fastpath.md) bump (no `_MIGRATION_REV` change; the DDL is not open-path Python).

   > **Amendment (2026-07-24, BACKLOG #306).** The table gained a nullable **`last_used_at`** column
   > (SQLite `REAL`, Postgres `DOUBLE PRECISION`, SQL Server `FLOAT NULL`) — the last-RECALL stamp,
   > written *only* by `get_search_preset` (best-effort: a stamp failure is logged and swallowed, never
   > raised, so a usage hint can't break the recall it annotates). It exists so
   > [ADR 0027](0027-per-connection-retention.md)'s `purge_search_presets` can key on last-**used**
   > rather than last-**edited**; see that ADR's amendment for the per-dialect greatest-of-two. The
   > column is migrated in the same way this table was added — SQLite via the `PRAGMA table_info`-gated
   > `_migrate` pass, the server backends via a guarded `ADD` inside `_SCHEMA`, which again moves
   > `_schema_hash()` automatically (still no `_MIGRATION_REV` change).

2. **`criteria` encrypted at rest.** The preset's criteria (a JSON blob of the typed search params, which
   may include a PHI-shaped `content`/`field_value`) is written/read through the **store cipher** with
   `cell_aad("search_presets", "criteria", id)`. A single-`id` PK lets it **ride the id-keyed rotation
   loops** — `("search_presets", "criteria")` is added to each backend's `_CIPHER_COLUMNS`, so
   `rotate-key` re-encrypts it for free (ASVS 11.3.3 / [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md)).
   No-key ⇒ identity (plaintext), exactly like every other cipher column.

3. **Per-user, owner-scoped.** Every store method is keyed by `owner = identity.username`. A user sees,
   recalls, and deletes **only their own** presets; `UNIQUE(owner, name)` makes a save-by-name a
   create-or-replace that **preserves the row id** (so the cell-AAD binding stays stable across a replace).
   The CRUD methods live on the `AuthStore` protocol (beside roles/sessions).

4. **Step-up + audit on the PHI-shaped surfaces.** Preset **create** (persists a possibly-PHI criteria)
   and **layered recall** (composes + decrypts, then runs the content scan) require **step-up** and write
   an audit row (`preset.create` / `preset.layered_search`) recording the needle **shape** only (never the
   value, reusing ADR 0046 `_needle_shape`). **List** (names + timestamps, no criteria) and **delete** are
   `messages:read`-gated + audited (`preset.list` / `preset.delete`) — no new permission is minted
   (presets are a per-user extension of the search surface the caller already holds `messages:read` for).

5. **Layering = bounded AND-compose, one content predicate.** The composer loads N (≤ `MAX_PRESET_LAYERS`
   = 8) of the caller's presets and folds them left-to-right into one query over the typed
   `search_messages` params: each metadata scalar (`channel_id`/`status`/`message_type`/`control_id`)
   takes the first non-empty value and **rejects a conflicting second value (400)**; **at most one**
   preset may carry a content needle (`content` or `field_path`+`field_value`) — two ⇒ 400, zero ⇒ 400
   ("layered search needs one content term"). The single needle builds a `SearchSpec` via `make_spec`
   (its ADR 0046 caps unchanged), and the composed metadata + spec run through the **existing**
   `search_messages` (reusing the S7b #124 basic-filter coupling — the composer stays bounded, never a
   new scan path). The content term is loaded **server-side from the encrypted column** and never leaves
   in a URL — so the `routes/search.py` deliberate-drop posture is preserved by construction.

6. **Web console.** The content-search page gains a "Save current search" form (step-up POST) + a saved-
   presets list with checkboxes to "Run layered" (step-up POST → composed results) and a delete. New
   `CoreHandlers` seam handlers (`ENGINE_UI_SEAM` bumps); the layered run renders through the existing
   `message_search` results view.

## Acceptance Criteria

- **AC-1** — WHEN a user saves a preset with `messages:read` + step-up, THE SYSTEM SHALL persist it
  (criteria encrypted when a key is set) owner-scoped and audit `preset.create` (needle shape only). →
  `tests/test_search_presets.py::test_create_encrypts_and_lists`
- **AC-2** — THE SYSTEM SHALL scope every preset read/delete to the caller (a user cannot see or delete
  another user's preset). → `tests/test_search_presets.py::test_presets_are_owner_scoped`
- **AC-3** — WHEN a save-by-name reuses an existing name, THE SYSTEM SHALL replace it in place (same id,
  stable cell-AAD). → `tests/test_search_presets.py::test_save_by_name_replaces`
- **AC-4** — WHEN presets are layered, THE SYSTEM SHALL AND-compose their metadata filters + exactly one
  content predicate and run `search_messages`; conflicting metadata or >1 / 0 content needles → 400. →
  `tests/test_search_presets_api.py::test_layered_compose_and_conflicts`
- **AC-5** — THE `search_presets` table SHALL be present on all three backends and move the server
  schema hashes. → `tests/test_store_schema_hash.py::test_search_presets_table_present_on_all_backends`
- **AC-6** (amendment, BACKLOG #306) — WHEN a preset is recalled by id, THE SYSTEM SHALL stamp
  `last_used_at` (best-effort; a stamp failure SHALL NOT fail the recall), and the column SHALL exist on
  all three backends in both the fresh-DB CREATE and a guarded ADD for an upgraded DB. →
  `tests/test_retention.py::test_get_search_preset_stamps_last_used_at`,
  `tests/test_store_schema_hash.py::test_search_presets_last_used_at_present_on_all_backends`

## Options considered

1. **Encrypt the criteria column + step-up + audit + server-side layered compose — CHOSEN.** Honours the
   full "metadata + content" scope, keeps the content term off the wire, reuses the store cipher/rotation.
2. **Metadata-only presets (drop content/field_value).** Simpler and also PHI-safe (the gotcha's second
   option), but narrows #151's stated scope; rejected in favour of encrypting, which costs little on top
   of the uploaded-logs cipher work already in this lane.
3. **Client-side (`localStorage`) presets.** No server persistence → not cross-device, and would push
   PHI-shaped terms into the browser store; rejected (the item explicitly wants server-side per-user).
4. **A general boolean query language for layering.** Over-scoped; a bounded AND-compose over the typed
   params is the minimal, cap-respecting composition and reuses the single-spec `search_messages`.

## Consequences

**Positive** — Corepoint save/layer parity; the content term stays encrypted at rest and never round-trips;
one clean id-keyed cipher column that rotates for free; no new permission.

**Negative / risks** — A third store slot (schema-hash bump on the server backends; 3-backend parity is a
CI gate). The single-content-predicate rule means a layered run needs exactly one content-bearing preset —
a documented, bounded limitation (metadata-only combining is the plain `/messages` list's job).

**Out of scope** — Sharing presets between users; boolean OR/NOT composition; preset-driven saved *alerts*.

## To resolve on acceptance

- [x] Encrypt vs. metadata-only — resolved: **encrypt the `criteria` column** (id-keyed, rotation-covered).
- [x] Layering semantics — resolved: **bounded AND-compose, exactly one content predicate, ≤ 8 layers**.
