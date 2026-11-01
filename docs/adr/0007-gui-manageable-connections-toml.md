# ADR 0007 — GUI-manageable connections as a config-as-data TOML artifact

- **Status:** **Accepted** — drafted on the owner's go (2026-06-13); the ratified-on-build condition
  is met, recorded here 2026-09-09. Supersedes the
  implicit "connections are code-only" stance of earlier ADRs for the *transport/wiring* layer.
  **This line read "Proposed (2026-06-13)" until 2026-09-09.** That was true at drafting; it was left
  behind by the build it was conditioned on — see *Built* below for what shipped and where.
- **Built:** **Yes — Phases 1, 2 and 3 are in the tree; re-verified against the working tree
  2026-09-09.** *Phase 1, read path* — `CONNECTIONS_FILE_NAME` and `load_connections_file` in
  [`config/connections_file.py`](../../messagefoundry/config/connections_file.py), called from both
  loader entry points (`load_config` and `validate_config`) in
  [`config/wiring.py`](../../messagefoundry/config/wiring.py), with a sample
  `samples/config/connections.toml` and `tests/test_connections_file.py`. *Phase 2, CLI write path* —
  the style-preserving `upsert_connection` / `remove_connection` writer in
  [`config/connections_edit.py`](../../messagefoundry/config/connections_edit.py) on `tomlkit`
  (`tomlkit>=0.12` in `pyproject.toml`, its comment naming this ADR), behind the
  `connection list|upsert|remove|schema` subcommand registered and dispatched in
  [`__main__.py`](../../messagefoundry/__main__.py). *Phase 3, VS Code editor* — the engine-derived
  `SCHEMA_VERSION` schema in
  [`config/connection_schema.py`](../../messagefoundry/config/connection_schema.py) plus the
  `connectionEditor` / `connectionForm` / `connectionQuickInput` modules under `ide/src/`.
  The 2026-07-19 amendment below was built and has been reversed: the 2026-10-31 amendment moved
  the flag to the store, so `connections.toml` carries no `flagged` key.
  `Engine.set_connection_flag`
  ([`pipeline/engine.py`](../../messagefoundry/pipeline/engine.py)) behind
  `POST /connections/{name}/flag` ([`api/app.py`](../../messagefoundry/api/app.py)) stays, with
  `tests/test_connection_flag.py`. *Phase 4* is confirmed only in part: the decomposition
  convention is documented ([docs/CONNECTIONS.md](../CONNECTIONS.md) section "Decomposing by role")
  with the `IB_DEMO_ORU_*` sample, but the re-port of the deferred multi-destination fan-out feeds
  sits outside this repository and is **not claimed** here.
  **This line read "Not yet — design record. Build is phased (see *Phasing*); Phase 1 (read path)
  first." until 2026-09-09.** It was accurate on 2026-06-13 and then went stale in silence: the
  *Amendment (2026-07-19)* section below describes code in the tree while this header still said
  nothing was built. The defect is an **under-claim** — a reader planning off the old line would plan
  to build what already exists.
- **Decision in one line:** add an **optional `connections.toml`** data artifact in the config dir
  that the loader reads into the **same** `InboundConnection`/`OutboundConnection` registry entries the
  code-first `inbound()`/`outbound()` factories produce — a flat, hand-editable **and**
  GUI-editable endpoint list. **Routing/transform logic stays code-first Python.**
- **Related:** [CLAUDE.md](../../CLAUDE.md) §1/§4 (the building blocks + "no channel/route element"
  that still holds), [ADR 0004](0004-payload-agnostic-ingress.md) (`content_type` on an inbound, which
  this surfaces as data), the wiring loader ([config/wiring.py](../../messagefoundry/config/wiring.py)),
  the env-value layer ([config/environments.py](../../messagefoundry/config/environments.py)).

## Context

Connections are declared today **only** in code: `inbound(name, spec, router=...)` /
`outbound(name, spec, ...)` with transport factories (`MLLP()`, `File()`, …) in a `.py` module loaded
by `load_config`. Every Corepoint feed has been ported as one bundled module (inbound + router +
handler(s) + outbound).

Two pressures motivate a change:

1. **The estate is a graph, not a tree.** A single Corepoint E Child (transformer) is shared across
   multiple E Processes (routers); the bundled one-file-per-feed model duplicates shared transforms and
   strains on multi-destination (fan-out) feeds.
2. **Connections want to be operationally editable.** Endpoints (host/port), the router binding, and
   delivery knobs are the parts an integration team changes most and least wants to touch code for —
   exactly what Mirth/Corepoint expose in a GUI.

**On "code-first."** The project's differentiator is code-first *logic*. The owner has clarified that
"code-first" is a **default that applies to behavior (routers/transformers), not an identity rule that
binds transport config**. Connection config is data; expressing it as data is acceptable and desirable.
This ADR records that scoping.

**On format.** TOML is chosen — already the project's config format (`environments/<env>.toml`),
read by stdlib `tomllib`, and free of YAML's significant-whitespace / type-coercion footguns. YAML is
**not banned**; a future feature with a concrete YAML case may use it. (This supersedes the blanket
"no YAML" line in CLAUDE.md §12, narrowed to "prefer TOML.")

## Decision

### A `connections.toml` that desugars into the existing registry entries

The loader reads an optional `connections.toml` in the config dir and, per table, maps `transport` to
the **existing** transport factory and calls it with the decoded settings — so a TOML connection
produces a **byte-identical `ConnectionSpec`** to the code-first form and inherits every factory
default and guard. **The factory is the schema**; there is no second source of truth for which
settings a transport accepts. An unknown transport or unexpected setting key fails loud as a
`WiringError` naming the connection + field.

```toml
# connections.toml — transport/wiring config. Logic stays in *.py (routers + handlers).
# Secrets are NEVER here: use { env = "key" } and define the value in environments/<env>.toml
# (non-secret) or MEFOR_VALUE_<KEY> (secret).

[[inbound]]
name      = "IB_ACME_ADT"
transport = "mllp"             # -> the MLLP() factory / ConnectorType.MLLP
router    = "acme_adt_router"  # MUST name a router registered in a *.py module
content_type = "hl7v2"         # default; per ADR 0004
ack_mode  = "original"
  [inbound.settings]
  port = 2600                  # inbound MLLP takes NO host (rejected, same guard as inbound())

[[outbound]]
name      = "OB_ACME_ADT"
transport = "mllp"
ordering  = "fifo"
  [outbound.settings]
  host = { env = "acme_adt_host" }                 # EnvRef encoding (host/secret via env())
  port = { env = "acme_adt_port", cast = "int" }
  [outbound.retry]
  max_attempts = 5
  backoff_seconds = 5.0
```

### EnvRef encoding

`display_settings()` already renders an `EnvRef` as `{"env": key[, "default": d]}` (the JSON view used
by tooling). TOML uses the same shape as an inline table; an inverse `parse_env_setting()` decodes a
table carrying the reserved `env` key back into an `EnvRef`. `cast` is a **bounded named enum**
(`"int" | "float" | "bool" | "str"`) — a GUI cannot author an arbitrary Python callable, and only
`int` is used across the estate. Code-first `env()` keeps the full callable.

### Coexistence and precedence

Code-first `inbound()/outbound()` are **not** deprecated; both populate the same `Registry`. A name
declared in **both** a `.py` module and `connections.toml` is a hard `WiringError` (no silent
precedence) — naming both source locations. The read API/`graph` labels each connection's origin
(`file` vs `code`) so the GUI can lock code-authored rows.

### Hand-edit ↔ GUI: one file, two equal editors

`connections.toml` is a first-class human-authored artifact. The GUI (VS Code extension) edits it via
a Python CLI (`messagefoundry connection upsert|remove|list`) that does a **comment/format-preserving**
read-modify-write using **`tomlkit`** (not `tomli-w`, which drops comments) — so a GUI save never
clobbers a developer's hand-written comments, ordering, or formatting in untouched tables. The CLI
**validates before persisting** (load + `build_check`: unknown router, egress allow-list, port
collision, duplicate-vs-code) and writes atomically (temp + `os.replace`, owner-only perms); the file
is left untouched on any validation failure.

### Validation and security are reused, not rebuilt

- `Registry.validate()` — unknown-router and literal port-collision checks — runs after the merge.
- `RegistryRunner.build_check` — connector build + the fail-closed `[egress].allowed_*` allow-list —
  runs at reload/start. **A TOML outbound pointed at a non-allowlisted host fails the same gate as a
  code one.**
- **Secrets stay in `env()`** — `connections.toml` holds only literals + env-ref markers, never a
  resolved secret; secret-bearing fields accept only the `{ env = ... }` form. The file is as
  repo-versionable and diffable as `environments/<env>.toml`.
- **Trust boundary:** TOML is **parsed, not executed**, so a writable/foreign-owned `connections.toml`
  cannot run code on reload — strictly safer than a `.py` edit. The dir's `_assert_safe_config_source`
  check still applies (the `.py` siblings still execute), and the write endpoint refuses to escape the
  config dir.

### New dependency

`tomlkit` (style-preserving TOML round-trip; the library Poetry uses) — verified real/reputable, added
to `pyproject.toml`, re-locked (`uv lock`/`uv export`) per the dependency rule. The only supply-chain
touch this feature adds.

## Consequences

- Ops can change endpoints/ports/router bindings/delivery knobs from a VS Code form **or** by editing a
  TOML file — both validated, both in git, both promotable DEV→PROD via the existing promote/reload.
- Logic remains code-first; nothing about routers/transformers changes.
- The CI gate (`messagefoundry check`) validates the whole graph including `connections.toml`.
- Two authoring surfaces coexist; the origin label + duplicate-rejection keep the effective graph
  unambiguous.

## Risks / tensions

- **Two sources of truth** (file + code). Mitigated by hard duplicate-rejection and origin labeling;
  default posture is additive (existing code-first feeds keep working untouched).
- **Cast narrowing** for GUI-authored env refs (named casts only) — acceptable; code-first retains
  arbitrary callables.
- **New dependency** (`tomlkit`) — gated on the vetting rule.

## Alternatives rejected

- **Store-backed (DB) connections + API CRUD.** Connections would leave the workspace/git (no diff, no
  review, no file-based promote) and **cannot be hand-edited** — directly contrary to the owner's
  "developer can also edit the file." Rejected.
- **Code-gen'd Python the GUI round-trips.** Editing generated `.py` round-trip is brittle (clobbers
  comments/hand edits, must parse+regenerate code) and keeps "config" as code. Rejected in favor of
  structured data.

## Phasing

0. **This ADR + the CLAUDE.md update** (docs only) — sign-off gate.
1. **Engine read path** — `config/connections_file.py`, extract `build_inbound_connection`/
   `build_outbound_connection` from the factories, `parse_env_setting()`, `load_config`/`validate_config`
   integration, a sample `connections.toml`, tests. No write path.
2. **CLI write path** — `connection list|upsert|remove` + `tomlkit` + validate-before-persist +
   atomic/secured write.
3. **VS Code editor** — create+edit form writing via the CLI, router-binding dropdown,
   `openConnectionSettings` → edit, refresh + promote.
4. **Decomposition convention** (routers/transformers in their own files) + re-port the deferred
   multi-destination fan-out feeds as the first multi-`Send` users.

---

## Amendment (2026-10-31) — The object flag moves to the store, and the engine stops writing config (BACKLOG #2623)

- **Status:** **Accepted (2026-10-31), on a review result the owner may overturn.** Reverses the
  2026-07-19 amendment below, whose text stays as the record of what was built and why.

**What was wrong with the flag in `connections.toml`.** A toggle's validate step called `load_config`
on the live directory, so one toggle ran every config module in the engine's process. That is a
trigger for code execution from a route with no second approver, for a field no engine path reads.
The write also needed the service account to hold write access to the directory it executes code
from, which `install-service.ps1` does not grant, and a cluster node had to refuse the toggle because
it could reach only its own copy.

**Decision.**

1. **`flagged`, and only `flagged`, moves to a new `connection_flag` table on all three store
   backends.** `auto_start` and `deployed` share the old tables, and both act: the runner skips and
   starts listeners on them. They stay in `connections.toml`, inside the ADR 0041 fingerprint.
2. **No seal.** The flag drives no engine path: no start, reload, routing or delivery path reads
   it. It does feed the console's Flagged-only filter, and select-all honours that filter, so a
   database writer with no key can move a marker and could shape a bulk action's target set. The
   owner accepted that reach on 2026-11-01; *Accepted residual* below records what bounds it.
   `tests/test_connection_flag_readers.py` fails on a new reader in the Python it scans, by name. In
   the browser it only counts the literal `getAttribute("data-flagged")` in `static/app.js`, so a
   read spelled any other way, or one that replaces a counted read, passes it. That test is what
   brings the seal question back if the flag ever comes to drive an engine path.
3. **A row is the flag.** A flagged connection has a row, keyed by name and direction, and an
   unflagged one has none. No value is parsed or validated. Nothing in a start or a reload
   reads the table, and the flag is off the `Registry`, so no stored row can refuse either. The
   dashboard read fails soft: a row the driver cannot decode costs every marker, logged once per run
   of failures at WARNING, and never the page. Until the read recovers, each row's flag is unknown
   rather than unset: `ConnectionRow.flagged` is `null`, the row offers no toggle, Flagged only hides
   no row, select-all under it takes no such row, and a notice above the table says why.
4. **The store is the only source.** The `flagged` TOML key and the `flagged=` declaration argument
   are removed, and the loader refuses both. Ignoring the key would leave a hand edit that reads as
   flagging a connection and flags nothing. There are no deployments, so there is nothing to migrate
   and no compatibility to keep.
5. **Any connection in the running graph takes the flag**, code-first included. That is the branch
   the 2026-07-19 scope fork deferred. A name the running graph does not have is refused **409**. A
   cluster node toggles like any other: the store is the one thing the nodes share.
6. **A toggle still writes `connection_flag_set`**, with its actor and client, in the same transaction
   as the flag. If the row fails the flag does not change, and the route answers **503**. A commit
   whose answer was lost answers 503 too, and then both may have landed. The row
   carries no digest and is no start baseline, so `connection_flag_set` left the actions a start reads.
   Left on that list, a row with no digest would read as a degraded baseline and the next start would
   compare nothing.
7. **The route keeps `config:deploy`.** Its reason was the TOML write, and that reason is gone. Lowering
   a gate is a decision of its own, not a side effect of this move.
8. **The engine writes no config file.** The flag was its only such write, so the machinery that kept
   a config write and its baseline row together went with it. `tests/test_config_write_census.py` now
   fails on an engine write through at least the writers it names, and on a direct write whose target
   names the config directory.

**Accepted residual.** A database writer can flip the flag. That changes no fingerprint and writes no
audit row. A stored value that disagrees with the newest `connection_flag_set` row is the only trace,
and nothing compares them. An unusable row never refuses anything. A row also outlives its name: a
connection removed or renamed leaves a row that matches nothing, which no route clears, and a later
connection of that name takes the flag. A row the driver cannot decode fails every read until
someone deletes it by SQL, because no route can name it, so one such row costs every marker and
toggle and turns Flagged only off for the whole estate.

**Accepted residual: the flag reaches a bulk action (owner ruling 2026-11-01).** Flagged only hides
rows, select-all takes only rows no filter hides, and that selection then goes into a bulk action
such as Stop, Restart, Reset or Purge. So a database writer who sets or clears rows could add a
connection to that target set or keep one out of it. Asked whether to accept this, the owner chose
*"Accept, record the reach"*. A failed flag read does not widen it: the filter shows a row of
unknown flag, and under it select-all skips any row not known to be flagged. Those rules narrow
what a failed read could do, and the ruling accepts nothing beyond them. What bounds it: no
filter has hidden a row select-all takes as it is taken, the toolbar counts the selection beside Go,
and an operator must press Go. Purge then adds a confirm page naming each outbound. Every other bulk
action has no such page, a row below the fold is still taken, and a selected row a later refresh
hides stays selected, so it is still acted on. The header box shows the part-selected mark when the
selection holds a row select-all could not take, and that mark covers opposite next clicks. Ticked,
which it also is when a selection has no row left to take, a click clears the whole selection,
hidden rows included. Unticked, a click adds every row it can take and leaves the rest selected.
That states what the box does, and accepts nothing further. The toggle gives the same reach with an
audit row: at least the Deployment role holds `config:deploy` and no bulk-action permission.

**Not changed by this amendment.** A dry-run reload still runs config modules, and is still not held
for an approver, because the IDE promote pre-flight would stall on a second person.
[SECURITY.md](../SECURITY.md) records it, until a dry run can run in a throwaway worker.

- **AC-1** — WHEN `POST /connections/{name}/flag` names a connection in the running graph, THE SYSTEM
  SHALL write the flag and its `connection_flag_set` row in one transaction, and run no config module.
  → `tests/test_connection_flag.py::test_a_toggle_runs_no_config_module`
- **AC-2** — WHEN a toggle lands, THE SYSTEM SHALL leave every file in the config directory unchanged.
  → `tests/test_connection_flag.py::test_a_toggle_changes_nothing_in_the_config_directory`
- **AC-3** — WHEN the store holds a row no toggle could write, THE SYSTEM SHALL start and reload as
  though it were absent.
  → `tests/test_connection_flag.py::test_a_stored_row_refuses_neither_a_start_nor_a_reload`
- **AC-4** — WHEN a Python module the census scans, other than the listed dashboard and console code,
  reads the flag by name, THE build SHALL fail.
  → `tests/test_connection_flag_readers.py`
- **AC-5** — WHEN the flag read fails, THE SYSTEM SHALL answer the dashboard with each row's flag
  unknown, offer no toggle, hide no row under Flagged only, leave such a row out of select-all under
  that filter, and say why on the page.
  → `tests/test_connection_audit_writes.py::test_a_row_the_driver_cannot_read_costs_the_markers_and_not_the_page`,
  `packaging/messagefoundry-webconsole/tests/test_ui_flag_read_failed.py`

---

## Amendment (2026-07-19) — Console-settable object flag + the FIRST console→connections.toml write seam (BACKLOG #131)

- **Status:** **Reversed by the 2026-10-31 amendment above.** Kept as the record of what was built,
  except that the test citations under its criteria were corrected on 2026-11-01, once the tests
  they named were gone. **Accepted (2026-07-19).** Implements [BACKLOG #131](../BACKLOG.md) "object flagging +
  a Flagged Objects filter" (lane `dg-s8a`, Wave 6). Additive to the accepted read/CLI-write design.

**What it adds.**

1. **A `flagged` field** (default `False`) on `InboundConnection` / `OutboundConnection` — authored
   code-first (`inbound(..., flagged=True)` / `outbound(..., flagged=True)`) **and** via
   `connections.toml` (joins `_INBOUND_KEYS`/`_OUTBOUND_KEYS`, the write schema, and the key-parity
   test). Purely a display/annotation marker — the operator's "object of interest" flag; **no runtime
   path reads it**. Surfaced additively on `ConnectionRow.flagged` and rendered in the console (a flag
   glyph + a **Flagged-only** filter over the connections dashboard).

2. **The FIRST console→`connections.toml` write seam.** Until now the ADR-0007 style-preserving writer
   (`config/connections_edit.py`) was wired **only** into the `connection` CLI — there was **no**
   console→TOML write path. The object-flag toggle builds it: a new **`POST /connections/{name}/flag`**
   JSON endpoint (RBAC `config:deploy`, deny-by-default, audited) and its console route
   (`routes/connection_writes.py`) drive `Engine.set_connection_flag`, which (a) round-trips the target
   TOML entry through `connections_edit.upsert_connection` — **validate-before-persist**, atomic
   temp+replace, **comments/formatting preserved** by the existing tomlkit writer — and (b) updates the
   live in-memory `Registry` entry in place (a `dataclasses.replace` of the cosmetic field only; **no**
   connector rebuild, **no** graph reload, **no** delivery-path change) so the dashboard reflects it
   immediately. The write reuses the CLI's exact validate callback shape (`load_config` +
   `build_check_registry` against this instance's `[egress]`/env/posture).

**SCOPE FORK — code-first connections are out of scope (records the `store_schema=false` decision).**
The flag is scoped to **`connections.toml`-managed connections ONLY**. A flag on a *code-first*
(`.py`-authored) connection has no TOML home to persist to, and giving *every* object a durable,
console-settable flag would require a **new name-keyed annotation table across all three store
backends** — which would make S8a **store-serialized** (`store_schema=true`). That is deliberately
**NOT built** here: `set_connection_flag` **refuses (409)** a connection that is not in
`connections.toml`, so this lane makes **no store schema change**. The universal-object-flag branch is
left for a future, owner-chosen, store-serialized effort.

- **AC-1 (amend)** — WHEN `POST /connections/{name}/flag` targets a `connections.toml`-managed
  connection, THE SYSTEM SHALL persist `flagged` via the comment-preserving validate-before-persist
  writer AND reflect it on the live `ConnectionRow.flagged`, constructing no channel/route object and
  making no store schema change.
  → Withdrawn with the behaviour. The 2026-10-31 amendment deleted its test; its own AC-1 to AC-3
  replace this criterion.
- **AC-2 (amend)** — WHEN the flag toggle targets a code-first connection (not in `connections.toml`),
  THE SYSTEM SHALL refuse it (409) and leave `connections.toml` untouched.
  → Withdrawn with the behaviour. The 2026-10-31 amendment deleted its test, and a code-first
  connection now takes the flag: `tests/test_connection_flag.py::test_a_code_first_connection_takes_the_flag`.
- **AC-3 (amend)** — THE `connections_edit` write schema SHALL stay set-equal to the loader's read
  schema per direction (the `flagged` key is in both), so the #234 key-parity test stays green.
  → Set-equal still holds, and `flagged` is now in neither schema:
  `tests/test_connections_file.py::test_write_schema_matches_read_schema_per_direction`.
