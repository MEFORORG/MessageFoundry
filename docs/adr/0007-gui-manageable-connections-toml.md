# ADR 0007 — GUI-manageable connections as a config-as-data TOML artifact

- **Status:** Proposed (2026-06-13) — drafted on the owner's go; ratified-on-build. Supersedes the
  implicit "connections are code-only" stance of earlier ADRs for the *transport/wiring* layer.
- **Built:** Not yet — design record. Build is phased (see *Phasing*); Phase 1 (read path) first.
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
