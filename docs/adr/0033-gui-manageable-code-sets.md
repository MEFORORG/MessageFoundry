# ADR 0033 — GUI-manageable code sets (translation tables) as CSV-first config-as-data

- **Status:** Proposed (2026-06-25) — drafted on the owner's go; ratified-on-build. Sibling of
  [ADR 0007](0007-gui-manageable-connections-toml.md): the same "transport/wiring config is data, edited
  by a CLI the GUI shells" pattern, applied to **code sets** (reference lookup tables) instead of
  connections.
- **Built:** Not yet — design record. The CLI + writer (`messagefoundry codeset`) and the VS Code grid
  editor are the build; logic (Routers/Handlers) is untouched.
- **Decision in one line:** add a **`messagefoundry codeset`** CLI (mirroring `connection` 1:1) that
  **owns validation + atomic write** of `codesets/<name>.csv` files, plus a **VS Code webview grid
  editor** that shells it — so an operator can create/edit/rename/delete a translation table from the
  IDE the same way they edit a connection, **CSV-first for v1**.
- **Related:** [ADR 0007](0007-gui-manageable-connections-toml.md) (the connection editor this mirrors —
  CLI-owns-validation, atomic temp+replace, owner-only perms, promote-to-apply), the code-set loader
  ([config/code_sets.py](../../messagefoundry/config/code_sets.py)) whose invariants the writer must
  hold, [CONFIGURATION.md](../CONFIGURATION.md) ("Code sets") + [CODESETS.md](../CODESETS.md) (the
  operator doc), [ADR 0006](0006-external-data-lookups.md) and [ADR 0010](0010-handler-callable-db-lookup.md)
  (the externally-owned data the editor deliberately does **not** touch — see *Out of scope*),
  [CLAUDE.md](../../CLAUDE.md) §1/§8 (reference data + the count-and-log/purity invariants that still
  hold).

## Context

A code set is **read-only reference data** loaded from `codesets/<name>.csv` or `codesets/<name>.toml`
relative to the `--config` dir — an Epic diet code → a food-service value, a facility code → a downstream
mnemonic — looked up purely from a Handler via `code_set("name")` (see
[config/code_sets.py](../../messagefoundry/config/code_sets.py)). Today these tables are **only**
hand-edited: an integration author opens the CSV in an editor, fixes a row, and reloads. That is exactly
the kind of operational data an integration team changes often and least wants to touch raw files for —
the same pressure ADR 0007 records for connection endpoints.

Two CLAUDE.md invariants bound the choice and **must not** be relaxed:

- **The lookup is pure** (CLAUDE.md §8): "Keep transforms **pure where possible**: message in →
  message out." A code set is read-only data shared frozen across transforms; editing it is an
  operator act, not a per-message side effect. The editor changes the *file*, not the running lookup —
  the graph picks up the change only on an explicit, audited reload (below).
- **Fail loud** (CLAUDE.md §8): "Route parse/validation failures to the error/dead-letter path …
  never crash the connection," and code-set loads "fail loud" on a duplicate key or a stem collision.
  The writer's whole job is to **guarantee what it writes will load** — it validates before writing and
  re-loads the written file as the final authority, so an operator can never save a table that would
  then fail loud at reload.

**On "code-first."** ADR 0007 already clarified that code-first is "a default that applies to behavior
(routers/transformers), not an identity rule that binds transport config." A code set is **data**, not
logic — it carries no behavior, only a `key → value` table. Editing it as data is squarely inside that
scoping; the Routers/Handlers that *consult* the table stay code-first and unchanged.

**On format.** CSV is chosen for the GUI's canonical authored format. The grid model is rows × columns
of strings, which **is** CSV — every cell a string, the first column the lookup key (the loader's
contract). TOML code sets remain hand-authored/legacy and are summarized + shown **read-only** in the
grid; round-tripping TOML scalars/nested-tables losslessly through a string grid is out of scope (a
TOML-in-grid editor is a fast-follow, below). This narrows the editable surface deliberately rather than
inventing a lossy bidirectional mapping.

## Decision

### A `messagefoundry codeset` CLI that owns validation + atomic write

A new `codeset` subcommand mirrors the `connection` subcommand 1:1 in CLI conventions — same
`--json`/`_print_json`/`_emit_error` plumbing, same `--config DIR` anchoring (`codesets/` is
`<--config>/codesets`, created on first `upsert`), the same insert-or-replace-by-name semantics. It is
the **single owner of validation**; the GUI never writes a file itself.

| action | input | result |
|---|---|---|
| `list` | — | a JSON array of **SUMMARY** objects (name/format/key/columns/value_columns/shape/entries), sorted by name — both `.csv` and `.toml` summarized; never fails on a valid TOML set |
| `show --name N` | — | a single **DETAIL** grid (`name`/`format`/`columns`/`rows`); `format:"toml"` ⇒ read-only |
| `upsert [--data JSON]` | DETAIL on `--data` or stdin | validate → build CSV → atomic write → **re-load as post-write check**; `{"op":"upsert", …, "entries":N}` |
| `rename --name N --to M` | — | validate `--to` (name-safety + stem-collision) → atomic `os.replace`; `{"op":"rename", …}` |
| `remove --name N` | — | delete `codesets/N.csv` (else `.toml`); `{"op":"remove", …}` |

Key contract points that distinguish it from `connection`:

- **CSV-first, always.** The editor *reads* both `.csv` and `.toml`, but `upsert` **always writes
  `.csv`**. The DETAIL/grid rows are an **array-of-arrays** (`string[][]`, each row aligned to `columns`
  by position) — positional like a grid, round-trips to CSV without per-row key repetition, and
  tolerates duplicate/blank headers mid-edit in the webview. The first column is the lookup key; one
  value column ⇒ a scalar `str` value, 2+ ⇒ a `{header: cell}` dict — exactly the loader's rule.
- **Offline + standalone.** Unlike `connection`, this command loads **no config modules** and runs **no
  egress/`build_check`** — a code set is standalone data, so "valid" means "does this file parse as a
  `CodeSet`," answered by re-running the `code_sets.py` loader on the candidate. There is therefore **no
  `--service-config` flag** and no network, server, or engine start.
- **Failures are machine-readable.** Every error path goes through the shared `_emit_error` (exit 1,
  `{"error": "<message>"}` under `--json`), because the IDE's `runJson()` parses stdout even on a
  non-zero exit and throws when it sees `{"error": …}`. The error **message strings are the loader's own
  literals** (duplicate key, stem collision, "no such code set …") so the same wording an author sees at
  reload is what the grid surfaces inline.

The writer enforces the loader's invariants **before** writing (structural shape faithful to
`_load_csv`, a non-empty key column plus ≥1 value column, unique non-empty headers, all-string cells,
no row longer than `columns`, drop the empty-key row the loader would skip, reject a duplicate key), and
the **name-safety** rules a path-bearing name could otherwise abuse (no separators, no `..`, no absolute
/ drive-prefixed path, no embedded `.csv`/`.toml` extension, and a final `resolve()` check that the
target stays inside `codesets/`) — treating the operator-supplied name as **untrusted data**, per
CLAUDE.md §5.

### How it reuses ADR 0007's machinery (don't rebuild it)

This is the connection editor's pattern applied to a different artifact, so it inherits — not
re-implements — four guarantees:

- **Validate-before-write.** The CLI validates the candidate (structural + name-safety + stem-collision)
  **before** persisting anything, and after writing **re-loads** `codesets/NAME.csv` via the loader's
  `load_code_set()` as the final authority. On **any** failure it rolls back — restoring the prior bytes,
  or unlinking a newly-created file — so a bad save never leaves a half-written or unloadable table.
- **Atomic temp + replace, owner-only perms.** The write reuses the **same** primitives as the
  connection editor: a temp-file write + `os.replace` for atomicity, and the store's `_secure_file`
  for owner-only permissions. A reader of the directory never sees a torn file, and the artifact is no
  more world-readable than the store.
- **Promote/reload to apply.** Editing a file changes nothing live; the running graph adopts a code-set
  change only through the **existing audited `POST /config/reload`** promote path — the very mechanism
  that already reloads code sets with the graph. So a GUI save is an ordinary file edit that the operator
  then promotes DEV→PROD exactly like a connection or a handler change, in git, reviewable, audited.
- **Two equal editors, one file.** `codesets/<name>.csv` stays a first-class human-authored artifact;
  the grid and a hand edit are interchangeable. (CSV carries no comments to clobber, so this is simpler
  than ADR 0007's `tomlkit` comment-preservation — no new dependency: stdlib `csv` writes the file.)

### VS Code grid editor (shells the CLI)

A single `WebviewPanel` (nonce'd CSP, `acquireVsCodeApi()`) mirrors `connectionEditor.ts`: it prefetches
the DETAIL via `codeset show` (or starts empty for create-new) and the existing names via `codeset list`
(for a client-side duplicate-name warning — the CLI stays the authority), embeds them into the HTML, and
posts `save` / `rename` / `delete` / `cancel` back to the extension, which shells the matching `codeset`
action over the shared `runJson()`. A CLI error comes back as an inline `error` message and the grid
stays open so the user can fix it (file unchanged). When the opened set is TOML the grid is **READONLY**
(Save disabled) — view-only until the TOML-in-grid fast-follow.

### The reference-safety caveat (call it out)

A code set is referenced by **name** from a Handler — `code_set("epic_diets")` — and that reference is
resolved at the loader/runner, **not** by `messagefoundry codeset`. So **renaming or removing a code set
through this CLI can break a live handler reference** (a `code_set("old_name")` call now raises at run
time → that message's `ERROR` disposition). The editor deliberately does **not** scan handler source for
references (that would couple a data tool to code parsing and still miss a call-time-computed name).
Instead, the safety net is the existing graph check: a broken reference surfaces in
**`messagefoundry check`** (the commit/CI gate, which runs a **dry-run** that actually executes the
transforms and so triggers the lookup) — **not** in a plain `validate`, which only confirms each file
parses. The operator-facing rule (documented in [CODESETS.md](../CODESETS.md)): **after a rename/remove,
run `messagefoundry check`** before promoting, so a now-dangling `code_set(...)` reference is caught at
the gate rather than at the first message.

## Acceptance Criteria

> EARS form; each linked (`→`) to the verifying test. (Test names are the planned targets in the
> contract's file list — `tests/test_code_sets_edit.py`, `tests/test_cli_codeset.py`.)

- **AC-1** — WHEN `codeset upsert` is given a valid DETAIL, THE SYSTEM SHALL write `codesets/NAME.csv`
  atomically with owner-only perms and re-load it as the post-write check, returning
  `{"op":"upsert","name":…,"format":"csv","entries":N}`.
  → `tests/test_code_sets_edit.py::test_upsert_round_trip`
- **AC-2** — IF a DETAIL would produce a duplicate key, a duplicate/blank header, a non-string cell, or
  a stem collision (`codesets/NAME.toml` also present), THEN THE SYSTEM SHALL reject it **before** any
  write, raising the loader's literal `CodeSetError` message and leaving the directory unchanged.
  → `tests/test_code_sets_edit.py::test_upsert_validation_rejects`
- **AC-3** — IF the post-write re-load fails, THEN THE SYSTEM SHALL roll back (restore prior bytes / unlink
  a new file) and re-raise, never leaving an unloadable file.
  → `tests/test_code_sets_edit.py::test_upsert_rollback_on_bad_reload`
- **AC-4** — WHEN a name (`upsert` `name` or `rename --to`) contains a path separator, `..`, an absolute /
  drive-prefixed path, or an embedded `.csv`/`.toml` extension, THE SYSTEM SHALL reject it with a
  name-safety message and never write outside `codesets/`.
  → `tests/test_code_sets_edit.py::test_name_safety`
- **AC-5** — WHEN `codeset list` enumerates a directory containing a valid `.toml` code set, THE SYSTEM
  SHALL summarize it `format:"toml"` (read-only in the grid) and not fail.
  → `tests/test_code_sets_edit.py::test_list_includes_toml_readonly`
- **AC-6** — WHEN any action fails under `--json`, THE SYSTEM SHALL print `{"error":"<message>"}` (one
  line) and exit 1, so the IDE's `runJson()` throws.
  → `tests/test_cli_codeset.py::test_json_error_shape_exit_1`

## Options considered

1. **CSV-first CLI (`messagefoundry codeset`) + grid webview shelling it — CHOSEN.** Mirrors ADR 0007
   exactly: the CLI owns validation/atomic-write, the GUI is a thin shell, the file stays git-versioned
   and hand-editable, and "apply" is the existing audited reload. The grid model maps 1:1 to CSV.
2. **Edit code sets in the store (DB) via an API CRUD.** Rejected for the same reason ADR 0007 rejected
   store-backed connections: the table would leave the workspace/git (no diff, no review, no file-based
   promote) and **couldn't be hand-edited** — contrary to "a developer can also edit the file."
3. **A bidirectional TOML-and-CSV grid in v1.** Rejected for v1: losslessly round-tripping TOML
   scalars/nested tables through a string grid is real complexity for little gain (TOML sets are
   hand-authored/legacy). Summarize + show TOML read-only now; a TOML-in-grid editor is a fast-follow.
4. **Have the CLI rewrite handler references on rename.** Rejected: it would couple a data tool to
   parsing/rewriting Python, still miss call-time-computed names, and violate the one-way dependency
   direction. The `messagefoundry check` dry-run is the right place to catch a dangling reference.

## Consequences

**Positive** — Ops edits a translation table from a VS Code grid **or** by hand-editing the CSV; both go
through the same validate-before-write and the same audited promote/reload, both in git. Logic stays
code-first and untouched. No new dependency (stdlib `csv`). The writer guarantees what it persists will
load (re-load is the final authority), so "fail loud at reload" can't be triggered by a GUI save.

**Negative / risks** — A rename/remove can break a handler's `code_set(...)` reference; mitigated by the
documented "run `messagefoundry check` before promoting" rule (the dry-run catches it) rather than by
source scanning. TOML sets are read-only in the grid (a documented fast-follow). Two surfaces (file +
grid) edit the same artifact — but unlike ADR 0007 there is no second source of truth (the file *is* the
truth; the grid just reads-modifies-writes it), so no origin label or duplicate-rejection is needed.

**Out of scope** — **Reference sets** ([ADR 0006](0006-external-data-lookups.md)) and **`db_lookup`**
([ADR 0010](0010-handler-callable-db-lookup.md)) are **not** editable here. Their data is **externally
owned** — a reference set is synced from an external file/DB source on a cadence, and a `db_lookup` reads
a live external database — so editing it in this grid would be meaningless (the next sync / the next
query overwrites it) and misleading. This editor governs only the bundle-shipped, operator-owned code
sets. **TOML-in-grid editing** is a fast-follow, not v1.

## To resolve on acceptance

- [x] **ADR number.** The shared contract earmarked `0031`, but `0031` is already taken
  ([0031-startup-connection-fault-isolation.md](0031-startup-connection-fault-isolation.md)); this ADR is
  filed as **0033** (the next free number; 0032 is the highest existing) to avoid clobbering it. The
  CLI/data-shape contract is unchanged — only the ADR's own number differs from the contract's guess.
- [ ] Confirm the v1 read-only treatment of TOML code sets (vs. converting a TOML set to CSV on first
  edit) before flipping to `Accepted`.
