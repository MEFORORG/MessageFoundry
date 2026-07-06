# Code sets — translation tables (operator reference)

A **code set** is read-only reference data a code-first Router/Handler looks up by name — an Epic
diet code → a food-service value, a facility code → a downstream mnemonic. This is the operator
reference for **editing** code sets: the VS Code grid editor and the `messagefoundry codeset` CLI it
shells. For how a Handler *consumes* a code set (`code_set("name")`), the on-disk format, and the
purity/reload semantics, see [CONFIGURATION.md → "Code sets"](CONFIGURATION.md#code-sets--reference-lookup-tables-codesets).
The design record is [ADR 0033](adr/0033-gui-manageable-code-sets.md) (a sibling of the connection
editor, [ADR 0007](adr/0007-gui-manageable-connections-toml.md)).

## Where the files live

Code sets live in `codesets/` **relative to the `--config` dir** — a config bundle carries its own
reference tables and they **reload with the graph** (`POST /config/reload`). The code-set **name** is
the file's stem (`codesets/epic_diets.csv` → `"epic_diets"`). A missing `codesets/` dir is fine (no
code sets); the directory is created on the first `upsert`.

- **CSV** (`<name>.csv`) — the editable, GUI-canonical format. A header row; the **first column is the
  lookup key**. One other column → the value is that scalar (`str`); several other columns → the value
  is a `dict` `{header: cell}`. A duplicate key is a **load error** (fail loud).
- **TOML** (`<name>.toml`) — hand-authored / legacy. Summarized by `list` and shown **read-only** in
  the grid; the CLI never *writes* TOML. (A TOML-in-grid editor is a fast-follow.)

Both editors — a hand edit and a GUI save — write the same `codesets/<name>.csv`, so they are
interchangeable.

## The grid editor (VS Code)

The extension opens a **grid** (rows × columns of strings; the first column is the lookup key) to
**create / edit / rename / delete** a translation table. It never writes a file itself: it shells the
`messagefoundry codeset` CLI, which owns all validation and the atomic write. A CLI error comes back
inline and the grid stays open (file unchanged) so you can fix it. When the opened set is a `.toml`
file the grid is **read-only** (Save disabled).

## The `messagefoundry codeset` CLI

The CLI is **offline** (no engine start, no egress check — a code set is standalone data) and
validates against the **same loader** that runs at startup. Under `--json` it prints a single-line
JSON result on success, or `{"error": "<message>"}` (exit 1) on failure, so the IDE can surface the
loader's own wording inline.

| Command | What it does |
|---|---|
| `messagefoundry codeset list --config DIR` | Summarize every set under `codesets/` (`.csv` **and** `.toml`), sorted by name. |
| `messagefoundry codeset show --config DIR --name N` | The grid for set `N` (headers + rows); `format:"toml"` ⇒ read-only. |
| `messagefoundry codeset upsert --config DIR [--data JSON]` | Validate → write `codesets/N.csv` atomically (temp + replace, owner-only perms) → **re-load the written file as the final check**; a bad save rolls back. DETAIL JSON comes from `--data` or stdin. |
| `messagefoundry codeset rename --config DIR --name N --to M` | Atomic `os.replace` of `codesets/N.<ext>` → `codesets/M.<ext>`; rejects a stem collision. |
| `messagefoundry codeset remove --config DIR --name N` | Delete `codesets/N.csv` (else `.toml`). |

Add `--json` to any command for machine-readable output.

### DETAIL shape (for `upsert` / returned by `show`)

```json
{
  "name": "epic_diets",
  "format": "csv",
  "columns": ["code", "value"],
  "rows": [["A", "Apple"], ["B", "Banana"]]
}
```

`rows` is an **array of arrays** (`string[][]`), each row positionally aligned to `columns`; the
first column is the key. One value column ⇒ a scalar value, two or more ⇒ a `{header: cell}` dict —
exactly the loader's rule.

### The operator-supplied name is untrusted

`upsert`'s `name`, `rename`'s `--to`, **and** the `--name` on `show`/`remove` are all treated as
**untrusted data** (CLAUDE.md §5/§8). The CLI rejects a name that contains a path separator, `..`, an
absolute / drive-prefixed path, or an embedded `.csv`/`.toml` extension, and applies a final
`resolve()` check that the target stays inside `codesets/` — so a name can never read or write a file
outside the code-sets directory.

### Validation rules (mirror the loader exactly)

A bad `upsert` is rejected **before** any file is touched: a non-empty key column plus at least one
value column, unique non-empty headers, all-string cells, no row longer than `columns`, a fully-blank
row dropped while a blank-key row that carries data is rejected (fail loud — never silently dropped),
and no duplicate key. A stem that collides with an existing
`.toml` is rejected (the same ambiguity the loader fails loud on). After the write, the file is
**re-loaded** as the final authority; any failure rolls the prior content back (or unlinks a
brand-new file), so a bad edit never lands.

## Promote to apply — and the rename/remove caveat

Editing a `codesets/` file changes nothing live; the running graph adopts the change only through the
**existing audited `POST /config/reload`** (the IDE promote), exactly like a connection or handler
change.

**Renaming or removing a code set can break a handler reference.** A code set is referenced by **name**
from a Handler (`code_set("epic_diets")`), and that reference is resolved at the loader/runner — not by
`messagefoundry codeset`. So after a rename/remove, a `code_set("old_name")` call raises at run time
(that message's `ERROR` disposition). A plain `validate` only confirms each *file* parses, so it
**won't** catch a now-dangling reference.

> **After a rename or remove, run `messagefoundry check` before promoting.** Its dry-run actually
> executes the transforms, so it triggers the lookup and surfaces a broken `code_set(...)` reference at
> the gate rather than at the first message in production. The editor deliberately does **not** scan
> handler source for references (that would couple a data tool to code parsing and still miss a
> call-time-computed name) — the `messagefoundry check` dry-run is the safety net.

## Out of scope

**Reference sets** ([ADR 0006](adr/0006-external-data-lookups.md)) and **`db_lookup`**
([ADR 0010](adr/0010-handler-callable-db-lookup.md)) are **not** editable here: their data is
externally owned (synced on a cadence, or a live database read), so editing it in this grid would be
overwritten by the next sync/query and is therefore meaningless. This editor governs only the
bundle-shipped, operator-owned code sets.
