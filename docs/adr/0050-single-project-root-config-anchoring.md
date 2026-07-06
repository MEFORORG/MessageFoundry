# ADR 0050 — Single project-root config anchoring

- **Status:** Accepted (2026-06-28 — ratified; open items resolved in 'Ratification decisions' below)  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-06-28
- **Related:** [ADR 0017](0017-consumer-deployment-model.md) (consumer deployment model — names the
  "Path-root caveat" §80-92 + the open **Major** engine-work row §161 this resolves) · [ADR 0007](0007-gui-manageable-connections-toml.md)
  (connections-as-data, resolved relative to `--config`) · [`docs/research/config-ux-review.md`](../research/config-ux-review.md)
  (the config-UX review — 31 confirmed findings — this ADR implements its **candidate A**, the split-anchor
  fix; covers F3/C1/C3/DD1) · [BACKLOG #33](../BACKLOG.md) (config-UX consolidation, the review's parent;
  this is **#33-A**) · [`docs/CONFIGURATION.md`](../CONFIGURATION.md) (the settings catalog) ·
  [SERVICE.md](../SERVICE.md) (NSSM deployment — the failure case) · CLAUDE.md §1 (on-prem/no-egress
  default; logic stays code-first), §2 (count-and-log), §9 (PHI never logged at INFO+)

---

## Context

One **logical** configuration bundle (the engine's `--config` graph dir **plus** its sibling
`environments/`, the per-instance `messagefoundry.toml`, and the store DB) is today resolved against
**three independent filesystem roots**. The config-UX review's headline defect, verbatim:

> **The headline defect is the split anchor.** One logical config bundle resolves against **three
> different filesystem roots** (`--config`, CWD-for-`environments/`, bare-CWD-for-`messagefoundry.toml`/
> the DB). … the worst footgun: a `serve` launched from a non-repo CWD (**the NSSM case**) silently
> reads **no** `env()` values and creates the DB in the wrong place, with **no loud startup error**.

The current anchors, confirmed against the code:

| Bundle member | Anchor today | Source-of-truth → consumer (file:line) |
|---|---|---|
| graph `*.py`, `codesets/`, `connections.toml` | the **`--config` dir** (the raw `args.config` string) | `__main__.py` passes `args.config` to `load_config(directory)` / `validate_config(directory)` (`config/wiring.py:2532,2952`); `codesets/`+`connections.toml` resolve under that `directory` (ADR 0007) |
| `environments/<env>.toml` | **`[environments].base_dir`** anchoring **`[environments].dir`** (default `"environments"`); `base_dir` default `""` → `Path.cwd()` | setting: `config/settings.py:521` (`dir`), `:530` (`base_dir`) · resolver: `config/environments.py:42-71` (`resolve_values_base_dir`) · CLI wire-up: `__main__.py:433-435` (`serve --project-root`) |
| `messagefoundry.toml` | **bare CWD** (`_DEFAULT_FILE`) or `--service-config <path>` | `config/settings.py` `load_settings` |
| `[store].path` (the DB) | **CWD** (default `"messagefoundry.db"`) or `serve --db` | `config/settings.py` (default) · `__main__.py:423-424` (`--db` → `[store].path`) |

**Two keys, not one.** `[environments]` splits **`dir`** (the value-dir *name*, default `"environments"`)
from **`base_dir`** (the *anchor* it resolves against, default `""`). This ADR anchors `dir` under the
project root — it does **not** assume the literal `environments/`.

**Why it bites — the NSSM silent miss.** Under NSSM (or any launcher whose working dir is not the
config-repo root), `[environments].base_dir` defaults to `Path.cwd()`, so `load_environment_values`
reads an `<env>.toml` that isn't there and **silently returns `{}`**. This is *by design* today —
`config/environments.py:84-90`, verbatim:

> Reads `<base_dir>/<dir_name>/<environment>.toml` (a flat key→scalar table) if present, then
> overlays `MEFOR_VALUE_<KEY>` env vars (env wins). A missing file is **not** an error here —
> referenced-but-undefined keys fail loud when a connector is built, not at gather time.

So the design is **fail-loud-on-missing-KEY**, not fail-loud-on-missing-FILE: a graph with **zero**
`env()` references and no `<env>.toml` is a legitimate, supported configuration. This ADR **tightens —
does not contradict — that contract** (see Decision §2). Simultaneously `[store].path =
"messagefoundry.db"` creates a DB under that same wrong CWD. The empty-values miss only becomes loud
**later**, at connector build (`resolve_env_settings`), and **only if** a referenced `env()` key lacks a
default; the wrong-DB miss is **never** loud (a fresh empty store opens cleanly at the wrong path,
silently partitioning the count-and-log record across two files). The startup log already prints the
*computed* env-value path (`__main__.py:619-625`) but, per the review (§85-86), **does not** check that
it is reachable or that CWD matches the root.

**A partial fix already shipped, and a gap remains.** `[environments].base_dir` + `serve --project-root`
exist (the *value layer* was anchored — ADR 0017). But:

1. `messagefoundry.toml`, `[store].path`, and the `--config`/`codesets/` graph are still **not** tied to
   one project root — only `environments/` can be pinned, and only via its own flag.
2. `--project-root` / `--env` / `--service-config` are **`serve`-only**. The offline subcommands
   `validate` / `graph` / `dryrun` / `check` take **only** `--config` (`__main__.py:142-171`) and resolve
   `env()` **lazily** — `_validate` calls `validate_config(args.config)`, `_graph`/`_dryrun` call
   `load_config(args.config)`, **none load env values** (those are resolved only inside `serve`'s Engine,
   via the `env_values()` provider at `__main__.py:701-709`). So the commit/CI gate can validate a
   **different** environment view than the one that runs (review finding **C3**).

ADR 0017 §161 lists exactly this as open **Major** engine work — *"Anchor `environments/` +
`messagefoundry.toml` to a project root, not the CWD"* (`config/environments.py`, `__main__.py`,
`config/settings.py`) — and documents the stop-gap contract (§91-92): *"`codesets/` resolves under
`--config`, but `environments/` and `messagefoundry.toml` resolve under the process CWD."* This ADR
resolves that row and **extends** it to `[store].path`, the `--config` graph, and the offline subcommands.

**Constraints bounding the choice (CLAUDE.md invariants in play):**

- **Count-and-log / on-prem-by-default.** A wrong-DB-path miss is *worse* than a crash: it splits the
  durable store across two files, silently partitioning the received-traffic record. The fix must make an
  ambiguous/missing anchor **fail loud**, never silently pick a wrong root — consistent with the
  no-accept-and-drop posture.
- **PHI never logged at INFO+ (CLAUDE.md §9, PHI.md §7).** The new startup advisories log **file paths
  only** — never `env()` values or message bodies — so they are safe at INFO/WARNING.
- **Logic stays code-first; transport config may be data (ADR 0007).** This ADR touches **where files are
  found**, not **how logic is authored** — no declarative graph surface, no "channel" element, no change to
  `inbound`/`outbound`/`@router`/`@handler`.
- **Backward compatibility.** Existing deployments that launch from the repo root with `--config ./config`
  must keep working byte-for-byte. The empty-`base_dir`-is-CWD default and bare-CWD `messagefoundry.toml`/DB
  resolution are the *historical* behavior; this ADR adds a single opt-in anchor **on top**, with the same
  CLI > env > file > default precedence used everywhere.

**Not in scope — a separate follow-up, stated so it isn't conflated.** The config-UX review's **candidate
B** (review finding **F1**: the `MEFOR_*` env parser splits on the *first* `_`, so a multi-word/nested
section like a future dotted `[retention.connections.<name>]` is unreachable — `config/settings.py:1261`
`.partition("_")`) is a **different** follow-up this ADR neither blocks nor fixes. Note for accuracy: the
per-connection retention overlay (BACKLOG #34 / [ADR 0027](0027-per-connection-retention.md)) is still
**Proposed / unbuilt** — there is **no** `[retention.connections.<name>]` section in
`config/settings.py` today (`RetentionSettings` carries only store-wide windows, e.g.
`connection_event_retention_hours`). #34 is merely a *circulation consumer* of candidate B (its dotted
shape would depend on the F1 fix); it has **not** shipped. The future `[secrets]` provider surface is
likewise out of scope. This ADR only adds a path anchor; it does not touch the `MEFOR_*` section parser.

## Decision

**Anchor the whole config bundle to ONE project root — an explicit, opt-in anchor that resolves
`messagefoundry.toml`, `[environments].dir`, `[store].path`, and the `--config` graph consistently — and
**fail loud** on the wrong-DB / wrong-root footgun.** Extend the anchor/env/service-config flags to the
offline subcommands so the gate resolves the same env-value + service view `serve` does. This must **not**
break repo-root launches, must **not** introduce a declarative graph/"channel" surface, and must **not**
change the code-first logic model.

### 1. One project-root anchor — with a buildable precedence seam

Introduce a single **project root** `R` as the bundle anchor. **Precedence (explicit absolute path >
project-root > CWD):**

- The project root itself comes from `--project-root` (CLI) **or** `[environments].base_dir` (env/file).
  *These are the **same merged value*** — `serve --project-root` is written into
  `cli["environments"]["base_dir"]` (`__main__.py:433-435`), so "`--project-root` > `base_dir`" is
  **override-via-the-standard-CLI-merge**, not a separate runtime tiebreak. Unset → no root → every member
  falls back to **CWD**, exactly today's behavior. **Ordering caveat (scoped, ratified below):** the
  members resolved *after* `load_settings` — `[store].path`, the `[environments].dir` value directory, and
  the startup diagnostics — honor the merged root from *either* source; `--config` / `--service-config`
  are resolved *before* `load_settings` (they tell it where to read), so a root set **only** via a
  file/env `[environments].base_dir` cannot retro-anchor those two — use the **CLI** `--project-root` to
  anchor them. A file-only `base_dir` therefore anchors env values + the DB + diagnostics, not `--config`.
- **A relative member resolves under `R`; an *explicit absolute* path always bypasses the root.** The
  honest constraint, confirmed in code: `serve --db <path>` is **not** a separate "explicit path" channel —
  it just overwrites `[store].path` (`__main__.py:423-424`), and likewise an explicit relative
  `--service-config`/`--config` is indistinguishable, post-merge, from a file-set relative path. So
  resolution is done in **one place, before** members are anchored: at the `serve`/offline call sites we
  resolve `args.config`, `args.service_config` (the `messagefoundry.toml` lookup), and `[store].path` to
  absolute — **a relative value (whether from a flag or the file) is taken against `R`; an already-absolute
  value is used as-is.** A deployment that wants the DB on a separate fast volume passes an **absolute**
  `[store].path`/`--db`; a relative one follows the root. (Adding a distinct "explicit-relative-flag beats
  the root" channel would need a new resolution seam this ADR deliberately does **not** introduce — see
  AC-7/AC-8 and *To resolve on acceptance*.)

Concretely, when a project root `R` is set:

- `[environments].dir` resolves under `R` (already true via `resolve_values_base_dir`). **Unchanged.**
- A **relative** `--config` resolves under `R` (today it is taken relative-to-CWD); an **absolute**
  `--config` is honored as-is. This is done by resolving the string **at the call site** *before* it is
  passed to `load_config`/`validate_config` — `load_config(directory)` already accepts whatever path it is
  given, so `config/wiring.py` is **not** modified.
- A **relative** `messagefoundry.toml` lookup resolves `R/messagefoundry.toml`; an explicit
  `--service-config <path>` is resolved per the same relative-under-R / absolute-as-is rule.
- A **relative** `[store].path` resolves under `R`; an absolute `[store].path` (or absolute `--db`) is
  honored as-is.
- `codesets/` / `connections.toml` continue to resolve relative to the resolved `--config` dir (ADR 0007,
  unchanged) — once `--config` is anchored to `R`, they follow it.

The name `--project-root` is **retained and generalized** from "anchor for `environments/`" to "anchor for
the whole bundle"; `[environments].base_dir` remains its env/file source (now slightly narrow but kept for
compatibility — a `[project] root = …` alias may be added later, see *To resolve on acceptance*). Setting
**no** project root preserves every member's current CWD/`--config` behavior exactly.

### 2. Fail loud on the wrong-DB / wrong-root footgun — without reversing the missing-KEY contract

The new diagnostics are emitted **once at `serve` startup**, immediately after `env_base` is resolved
(`__main__.py:616`) and **not** inside the `env_values()` provider (which is **re-invoked on every reload**,
`__main__.py:703-709`) — so a `promote`/reload never re-fires them. They log **resolved file paths only**
(never values), staying clear of the PHI-no-INFO-payload rule.

- **CWD ≠ resolved root (WARNING).** When a project root is set and CWD differs from `R`, emit a single
  WARNING naming the resolved root, `<dir>/<env>.toml`, `messagefoundry.toml`, and `[store].path`, so an
  operator sees the four roots agree. This is **net-new logic** — it must *stat* the resolved member paths
  for existence and *compare* CWD to `R`; it is **not** a reformat of the existing computed-path INFO line
  (which does neither, per review §85-86).
- **NSSM silent-miss (WARNING).** When **no** project root is set, the launch dir is detectably not a config
  root (no `--config` target, no `<dir>/`, no reachable `messagefoundry.toml`), **and** the resolved
  `env()` values are empty, emit a one-line WARNING pointing at `--project-root` — the NSSM diagnosis,
  surfaced at startup instead of as a later connector-build failure (or a silent wrong-DB). This requires
  one eager `env_values()` evaluation at boot (the only place the empty-values state is observable); it
  must **not** re-fire per reload.
- **Missing `<env>.toml` under an *explicit* root, *and the graph references `env()`* (ERROR / non-zero
  exit).** This is the **only** new hard failure, and it is **scoped to preserve the shipped
  fail-loud-on-KEY contract** (`config/environments.py:84-90`): a missing value file is an error **only**
  when (a) a project root is **explicitly** set **and** (b) the loaded graph contains **≥1 `env()`
  reference** — i.e. the operator pinned a root, named an env, and the graph actually needs that file. A
  graph with **zero** `env()` uses, or any **no-root** launch, keeps the **silent-empty** default and never
  regresses. (The exact gate — "≥1 `env()` ref in the loaded graph" — is the proposed boundary; pinned in
  *To resolve on acceptance* so it cannot regress a no-`env()` deployment.)
- **Store DB.** A new DB created under a root that differs from where an existing DB sits relative to CWD is
  *exactly* the wrong-DB footgun — covered by the **CWD ≠ root WARNING** above (we do not auto-migrate; we
  make the split visible).

"Fail loud" = a non-zero exit with a specific stderr message for the one scoped missing-file ERROR; a
WARNING (not a refusal) for the advisory cases, so a deliberate cross-root layout (e.g. an absolute
`[store].path` on a separate volume) is allowed but **announced**.

### 3. Extend the resolution flags to the offline subcommands — value resolution only, *not* serve's posture refusal

Add `--project-root`, `--env`, and `--service-config` to `validate`, `graph`, `dryrun`, and `check` (today
they carry **only** `--config`, plus `--messages`). With these flags the gate resolves the **same project
root and the same active-environment `env()` values** `serve` resolves, so `messagefoundry check` on a CI
runner validates the view that will actually run.

**Explicitly pinned — the offline gate resolves *values*, it does NOT inherit `serve`'s required-env /
explicit-posture *refusal*** (`__main__.py:464-481`). `serve` refuses to start without an active
environment and demands an explicit posture for a custom env name; the offline tools **do not** adopt that
refusal, because doing so would *break* the documented gate invocation `messagefoundry check --config config
--messages messages/sets` (ADR 0017) — that has **no** `--env`. Therefore:

- With **no** `--env`, the offline gate behaves exactly as today (no env values loaded, no posture refusal).
- With `--env`/`--project-root`/`--service-config`, the gate resolves the **identical root + active-env
  `env()` values** as `serve` for those flags, but never enforces the required-env-/posture-refusal.

This is the **larger half** of #33-A. It is **not** the ADR 0017 trio: making the offline paths resolve the
env values `serve` does requires plumbing an `env_values()` provider into the offline `validate`/`dryrun`/
`check` paths — files **beyond** the trio:
`messagefoundry/checks.py` (the `run_checks`/`_check_posture` path),
`messagefoundry/pipeline/dryrun.py` (`dry_run` takes a `Registry` with `EnvRef`s unresolved today),
and the `_validate`/`_graph`/`_dryrun`/`_check` handlers + `validate_config` in `__main__.py`/`config/wiring.py`.

**Reconcile `check`'s existing upward-walk.** `check` **already** auto-discovers `messagefoundry.toml` by
walking up from `config_dir` (then CWD) — `checks.py:278` `_find_service_toml`, documented at
`checks.py:19`. That is the implicit discovery the Decision's Option 4 rejects for the *default* path. The
rule: **when `--service-config`/`--project-root` are passed, they take precedence and the upward-walk is
suppressed; when neither is passed, the existing upward-walk is preserved** (no regression for today's
`messagefoundry check --config config` invocation). So `check` matches `serve` **only when the flags are
given** — which is exactly AC-6.

### What it must not break

- **Repo-root launches** (`cd config-repo && messagefoundry serve --config ./config --env prod`) resolve
  identically — no project root required, CWD is the root, every member found as today.
- **No new declarative surface.** No "channel"/"route" element, no config-bundle object — purely *where
  files are found*. The graph stays a name-wired set of code-first Connections/Routers/Handlers.
- **The `MEFOR_*` env parser is untouched** — candidate B / finding F1 and the `[secrets]` work are out of
  scope.
- **`connections.toml` stays anchored under `--config`** (ADR 0007); we do not move it to the root.

## Acceptance Criteria

> EARS-form, each linked (`→`) to the test that verifies it. **`adr-analyze` note:** every `→` below points
> at a test file that does **not yet exist** — these are proposed shapes that land with the build, so
> `adr-analyze --strict` will report them as missing link-resolutions until then (expected for a `Proposed`
> ADR).

- **AC-1** — WHEN a `--project-root R` is set, THE SYSTEM SHALL resolve a relative `messagefoundry.toml`,
  the `[environments].dir` value directory, and a relative `[store].path` all under `R`, regardless of the
  process working directory.
  → `tests/test_config_anchoring.py::test_project_root_anchors_all_members` *(parametrized over a
  non-default `[environments].dir` name, so the test does not hard-code the literal `environments/`)*
- **AC-2** — WHEN no project root is set, THE SYSTEM SHALL resolve `[environments].dir`,
  `messagefoundry.toml`, and `[store].path` against the working directory exactly as before (no behavior
  change for repo-root launches).
  → `tests/test_config_anchoring.py::test_no_root_preserves_cwd_behavior`
- **AC-3** — IF a project root is **explicitly** set AND the loaded graph contains **≥1 `env()`
  reference** AND the resolved `<dir>/<env>.toml` does not exist, THEN THE SYSTEM SHALL fail loud at startup
  (non-zero exit, naming the resolved path); otherwise (no root, or zero `env()` references) it SHALL keep
  the existing silent-empty behavior of `load_environment_values`.
  → `tests/test_config_anchoring.py::test_explicit_root_with_env_refs_missing_file_fails_loud`
  → `tests/test_config_anchoring.py::test_no_env_refs_missing_file_stays_silent_empty`
- **AC-4** — WHEN a project root is set AND the working directory differs from the resolved root, THE
  SYSTEM SHALL emit a single startup WARNING that names the resolved root, `<dir>/<env>.toml`,
  `messagefoundry.toml`, and `[store].path` (file **paths only**, no values), by stat-ing each member for
  existence and comparing CWD to the root (net-new from the existing computed-path INFO line).
  → `tests/test_config_anchoring.py::test_cwd_mismatch_warns_with_resolved_paths`
- **AC-5** — WHEN no project root is set AND the launch directory is not a config root AND `env()` values
  resolve empty (the NSSM case), THE SYSTEM SHALL emit a startup WARNING pointing at `--project-root`, fired
  **once at boot** and **not** re-fired on a subsequent reload/promote.
  → `tests/test_config_anchoring.py::test_nssm_silent_miss_warns_once_at_startup`
- **AC-6** — WHERE `validate`/`graph`/`dryrun`/`check` are invoked with `--project-root`/`--env`/
  `--service-config`, THE SYSTEM SHALL resolve the identical **project root and active-environment `env()`
  values** that `serve` resolves for the same flags, **without** adopting `serve`'s required-active-env /
  explicit-posture refusal; AND `check` SHALL suppress its `messagefoundry.toml` upward-walk when
  `--service-config`/`--project-root` is supplied.
  → `tests/test_cli_offline_resolution.py::test_check_matches_serve_env_resolution`
  → `tests/test_cli_offline_resolution.py::test_offline_does_not_inherit_serve_posture_refusal`
- **AC-7** — THE SYSTEM SHALL honor an explicit **absolute** `--config`/`--service-config`/`--db`/
  `[store].path` as-is even when a project root is set, AND SHALL resolve a **relative**
  `--db`/`[store].path` (indistinguishable post-merge from a file-set relative path) under the root.
  → `tests/test_config_anchoring.py::test_absolute_paths_override_root_relative_db_follows_root`
- **AC-8** — IF a not-truly-absolute rooted anchor is given (e.g. drive-relative `/repo` on Windows), THEN
  THE SYSTEM SHALL warn that resolution still depends on the launch drive — **preserving the existing
  `resolve_values_base_dir` guard** (`config/environments.py:63-70`), generalized to the whole bundle (not
  net-new work).
  → `tests/test_config_anchoring.py::test_drive_relative_root_warns`
- **AC-9** — WHEN `supervise` runs with `--project-root R` and a **relative** `[store].path` (and no
  explicit `--db`), THE SYSTEM SHALL compose each shard's `<stem>_<shard>.db` under `R` (the per-shard
  composition at `pipeline/supervisor.py:61-70` resolving against the root, not the child CWD).
  → `tests/test_supervisor.py::test_shard_db_composes_under_project_root`

## Options considered

1. **One opt-in project root anchoring the whole bundle, generalizing `--project-root`, with the scoped
   fail-loud above + the flags extended to the offline subcommands (value resolution only).** **CHOSEN.**
   It resolves the ADR 0017 §161 Major row, kills the NSSM silent miss for *both* `env()` values and the DB,
   makes the gate match `serve`, and is backward-compatible (no root → today's behavior). **Honest scope
   split:** the project-root + fail-loud half (Decision §1-2) stays close to the ADR 0017 trio
   (`config/environments.py`, `config/settings.py`, `__main__.py`) because the `--config`/`[store].path`
   anchoring is done by resolving strings **at the call sites** before they reach `load_config`/
   `load_settings` (so `config/wiring.py` is **not** modified); the offline-parity half (Decision §3 / AC-6)
   **additionally** touches `messagefoundry/checks.py`, `messagefoundry/pipeline/dryrun.py`, and the
   `_validate`/`_graph`/`_dryrun`/`_check` handlers + `validate_config`, because those paths resolve `env()`
   lazily and load **no** env values today. *(Do not echo the BACKLOG follow-up-A trio estimate as if it
   covers AC-6 — it doesn't.)*

2. **`[engine].data_dir` as the "base for relative paths."** The catalog *documents* `[engine].data_dir`
   as exactly this anchor (review finding **DD1**) — but `[engine]` **has no model**, is not in
   `_SECTIONS`, and `extra="ignore"` silently drops it, so an operator who sets it gets nothing. Rejected:
   implementing `[engine]` purely to host the anchor adds a section for one key when `[environments].base_dir`
   + `--project-root` already exist; we generalize the existing knob instead and the docs-only follow-up
   (review candidate E) **deletes** the misleading `[engine]` doc.

3. **Per-member flags only (status quo + add `--db`/`--service-config` to more commands), no single root.**
   Rejected: leaves the operator to keep four roots in sync by hand — the very footgun #33 found. It would
   make the gate matchable but not the silent-miss.

4. **Infer the root automatically (walk up for a marker, à la git).** Rejected **for the default path**:
   implicit discovery is its own footgun (which marker? what if two exist?) and conflicts with "fail loud,
   never silently pick." **Reconciliation:** `check` *already* ships one such upward-walk for
   `messagefoundry.toml` (`checks.py:278` `_find_service_toml`); rather than spread it, this ADR makes the
   **explicit** `--service-config`/`--project-root` flags take precedence and **suppress** the walk, keeping
   the walk only as the legacy no-flag fallback (Decision §3). Full auto-discovery can be a later additive
   convenience (*To resolve on acceptance*).

5. **Make `--config` itself the root (everything resolves under the graph dir).** Rejected: `environments/`
   and `messagefoundry.toml` are *siblings* of `--config` in the ADR 0017 recommended layout, not children
   — anchoring under `--config` would force a layout change. The root is the **repo**; `--config` is a child.

## Consequences

**Positive**

- The NSSM / non-repo-CWD silent miss becomes **loud** — empty `env()` values and a wrong DB path are
  surfaced at startup, not discovered weeks later as split message stores or a blank host. Directly upholds
  the count-and-log / on-prem posture.
- The commit/CI gate (`check`) and the offline tools (`validate`/`graph`/`dryrun`) can resolve the **same**
  root + active-env `env()` values `serve` runs, closing the "gate passes, prod differs" gap (finding C3).
- One mental model: "set the project root; everything is found under it." Pairs with the ADR 0017 two-repo
  consumer model and `messagefoundry init` (which can emit the root).
- Resolves the open ADR 0017 §161 Major engine-work row and lets the config-UX review's candidate A close.

**Negative / risks**

- **Fail-loud blast radius (AC-3).** A missing `<env>.toml` becoming a non-zero-exit reverses the documented
  *"A missing file is **not** an error here"* contract (`config/environments.py:84-90`), and AC-3 now also
  applies to the offline subcommands that gain `--project-root`/`--env` — so a previously-green
  `check`/`validate`/`dryrun` over a config dir lacking the selected env file would hard-fail **under an
  explicit root with `env()` references**. Mitigated by the **double scoping**: the hard error fires **only**
  when (a) a root is explicitly set **and** (b) the loaded graph has ≥1 `env()` reference; the legacy
  no-root path and any zero-`env()` graph keep the silent-empty default, so no existing repo-root or
  unanchored launch regresses. The exact ≥1-`env()`-ref boundary stays an open question (below).
- **Relative `[store].path` relocation.** Root-anchoring a relative `[store].path` moves where an existing
  deployment's DB is found **if it both sets a root and uses a relative path** (and no absolute `--db`).
  Mitigated: takes effect only when a root is explicitly set (a new opt-in); the CWD-mismatch WARNING
  (AC-4) makes any move visible; no auto-migration; an absolute `[store].path`/`--db` is unaffected.
- **`supervise` shard-DB composition.** `supervise` composes per-shard DBs as `<stem>_<shard>.db` off the
  `--db`/`[store].path` (`pipeline/supervisor.py:7,61-70`) and forwards `--project-root`/`--env` to each
  shard (`__main__.py:134-140,811`). Root-anchoring a **relative** `[store].path` therefore changes where
  **every shard's** DB lands. Concrete regression risk for an existing sharded deployment that uses a
  relative `[store].path` without an explicit `--db`; covered by AC-9 + the CWD-mismatch WARNING. A deploy
  that passes an explicit `--db`/absolute path is unaffected (the shard stem derives from that explicit
  base).
- **Wider CLI/test surface.** Extending four subcommands widens the matrix. Mitigated by reusing the single
  resolution helper `serve` uses, so the subcommands share one code path (no per-command drift), and by
  scoping the offline change to *value resolution only* (not `serve`'s posture refusal), so the documented
  `messagefoundry check --config config --messages messages/sets` invocation stays green.

**Out of scope**

- The `MEFOR_*` env-parser first-`_`-split fix and `[pipeline]`/`[cert_monitor]` reachability (review
  candidate B / finding **F1**) — a separate follow-up; the per-connection retention overlay (#34 / ADR
  0027, still **Proposed/unbuilt**) is a downstream *consumer* of that fix, not shipped here.
- `connections.toml` inline-secret enforcement (review candidate C / finding F2) and the future `[secrets]`
  provider surface.
- Auto-discovery of the root from a marker file (left as a possible additive convenience, not built here).
- Any change to the code-first authoring model, the graph runner, or a declarative config surface.
- Moving `connections.toml`/`codesets/` out from under `--config` (they stay ADR-0007-anchored to it).

## To resolve on acceptance

> Open questions to settle before this flips to `Accepted`.

- [ ] **Flag/section naming.** Keep `--project-root` + `[environments].base_dir` as the single source, or
  add a clearer `[project] root = …` (with `[environments].base_dir` kept as a deprecated alias)? The
  current name reads as environments-only now that it anchors the whole bundle.
- [ ] **Exact AC-3 boundary.** Confirm the proposed gate — hard error only when a root is explicit **and**
  the loaded graph has **≥1 `env()` reference** — is the right line, and that it cannot regress a
  zero-`env()` deployment. (AC-3 encodes this precondition; this checkbox only ratifies the threshold, it
  does not re-open whether AC-3 fires at all.)
- [ ] **Explicit-relative-flag vs root.** This ADR resolves a relative `--db`/`--service-config`/`--config`
  **under the root** (indistinguishable post-merge from a file value, AC-7). Confirm that is acceptable, or
  decide to introduce a distinct "explicit relative flag is anchored against CWD-at-invocation, beating the
  root" resolution seam (a new channel not built here).
- [ ] **`supervise` interaction.** AC-9 asserts `<stem>_<shard>.db` composes under a root-anchored relative
  `[store].path`; confirm the existing supervise tests still hold and the explicit-`--db` path is unchanged.
- [ ] **Whether to auto-discover the root** (walk up for a marker) as an additive convenience beyond the
  explicit `--project-root`, and how it composes with `check`'s existing `_find_service_toml` upward-walk
  (now suppressed when the flags are passed).


---

## Ratification decisions (2026-06-28)

- **Keep `--project-root` + `[environments].base_dir`** as the single source this slice (no `[project] root` rename / alias — revisit later if the name confuses).
- **Fail-loud boundary (AC-3):** the hard error fires **only** when a project root is *explicitly* set **and** the loaded graph has ≥1 `env()` reference **and** the `<env>.toml` is absent. A zero-`env()` deployment that legitimately ships no value file is never regressed.
- **Precedence:** explicit flag > project-root > CWD; a relative `--db` / `--service-config` resolves under the root.
- **No auto-discovery** (walk-up marker) this slice — keep anchoring explicit; `check`'s existing upward `_find_service_toml` walk is suppressed when `--service-config` / `--project-root` is passed.
