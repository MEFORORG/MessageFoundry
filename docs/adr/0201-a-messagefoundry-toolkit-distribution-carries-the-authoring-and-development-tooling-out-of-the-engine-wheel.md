# 0201 -- A messagefoundry-toolkit distribution carries the authoring and development tooling out of the engine wheel

- **Status:** **Accepted -- 2026-09-29, by an owner ruling given in session to the batch 175
  Manager through AskUserQuestion.** The owner chose *"Accept as written"*: a separate
  `messagefoundry-toolkit` command, lockstep versions, and the toolkit uploaded first. Operators type
  `messagefoundry-toolkit init` instead of `messagefoundry init`, and the production CLI gets no
  plugin surface. The build slices go ahead in order. In the same sitting the owner answered the PyPI
  question: *"I'll do it before slice 2"*, recorded at section 1. No code yet.
  > **Superseded status text, kept as a record.** Until 2026-09-29 this line read: *"Proposed. No
  > code yet. This ADR designs the build that owner ruling R4 of 2026-09-28 asks for. The ruling set
  > the tiers. The layout, the command surface, the gates and the slice order below are this ADR's
  > design choices, not owner rulings. They need the owner's sign-off before any slice starts. The
  > questions acceptance must settle are at the end."*
- **Date:** 2026-09-29
- **Related:** BACKLOG #1192 (ASVS 15.2.3) · owner ruling R4 in vault
  `docs/security/ASVS-OWNER-RULINGS-2026-09-28-BATCH175.md` · engine PR 1775, which added
  [`messagefoundry/cli_surface.py`](../../messagefoundry/cli_surface.py) (`CLI_TIERS`) and
  [`tests/test_cli_surface.py`](../../tests/test_cli_surface.py) ·
  [ADR 0030](0030-anonymization-test-harness-tee.md) (the de-identification package, amended by
  slice 5 below) · [ADR 0065](0065-web-ops-dashboard.md) (the web console, the first sibling
  distribution) · [ADR 0088](0088-apiclient-service-cli-extraction.md) (the `apiclient/` extraction,
  the model for a verbatim move) · [`docs/SUPPLY-CHAIN.md`](../SUPPLY-CHAIN.md) · BACKLOG #1193
  (ASVS 15.2.4, dependency confusion)

---

## Context

### What ASVS 15.2.3 asks, and why the cell is partial

The pinned requirement text is: *"Verify that the production environment only includes
functionality that is required for the application to function, and does not expose extraneous
functionality such as test code, sample snippets, and development functionality."*

The verb is conjunctive. Clause (a) is what the artifact **includes**. Clause (b) is what it
**exposes**. The scorecard cell grades both against the built engine wheel, and it fails both:

- **Clause (a).** The wheel ships `anon/`, `generators/`, `adr_analyze.py`, `scaffold.py` and the
  other authoring modules.
- **Clause (b).** `messagefoundry/__main__.py` registers every subcommand unconditionally, so
  `python -m messagefoundry --help` lists the development tools beside `serve`.

The cell says the requirement is level 2, and so does ledger row #1192. The brief that asked for this
ADR said level 3. This ADR does not settle which. The level changes nothing in the design below.

The cell also names what is **not** an honest pass. Each of these leaves the code in the wheel:

- hiding subparsers with `argparse.SUPPRESS`, which changes only the help text;
- a PEP 621 extra, which adds dependencies and removes no files;
- cutting importers so a package reads as unreachable.

### What the owner ruled

R4 of 2026-09-28 chose *"Draft as surveyed (Recommended)"*. In the ruling's words, ten of the 14
contested subcommands stay in production: `validate`, `graph`, `dryrun`, `check`, `connection`,
`codeset`, `alert`, `security`, `cert inventory` and `ai-policy`. Four move to a separate
`messagefoundry-toolkit` distribution: `impact`, `generate`, `lens` and `import corepoint`. So do
`adr-analyze`, `hl7schema`, `hl7structures`, `init`, `generators/` and `anon/`.

The owner accepted three named costs with it:

1. The harness must depend on the toolkit.
2. INSTALL-GUIDE must say to install the toolkit for `init`.
3. Moving `anon/` amends ADR 0030, in its own PR.

A follow-up owner answer, relayed by the batch 175 Manager, keeps `cert self-signed` in production.
That answer is not yet in a vault rulings file, and `cli_surface.py` still calls the row an open
question. Recording it is an acceptance item below.

PR 1775 built the tier table. `CLI_TIERS` has 46 rows: 12 toolkit and 34 production. Of the 38
top-level rows, 8 are toolkit and 30 production. Its docstring says the table changes nothing that
ships yet. This ADR designs the part that does.

### What the import graph allows, measured

Every edge below comes from an AST import scan over every `.py` file in the tree at engine
`origin/main` `ba38f9309`. The scan follows relative imports and imports inside function bodies. It
does not see a module named in a string, so two searches ran beside it. A search for each dotted
module name inside quotes, over every file outside `tests/`, found none. The `import_module` calls
under `messagefoundry/` (in `__init__.py`, `config/secretprovider.py`, `store/keyprovider.py`,
`auth/ldap.py` and `verify/checks.py`) name no toolkit module. Controls from the AST scan: `pipeline/dryrun` has six non-test importers and
`config/impact` has two, so a zero is the scan's answer and not a blind spot.

| Module | Importers outside `tests/` | Where it goes |
|---|---|---|
| `adr_analyze.py` | `__main__` only | toolkit |
| `scaffold.py` (`init`) | `__main__` only | toolkit |
| `lens.py` | `__main__` only | toolkit |
| `lens_schema.py` | `__main__` only | toolkit |
| `corepoint_import.py` | `__main__` only | toolkit |
| `hl7schema.py` | `__main__`, `hl7structures.py` | toolkit |
| `hl7structures.py` | `__main__`, `generators/adt.py` | toolkit |
| `generators/` | `__main__`, `anon/_pools.py`, five `harness/` files | toolkit |
| `anon/` | only its own files | toolkit |
| `config/impact.py` | `__main__`, **`config/codeset_edit.py`** | **stays** |
| `pipeline/dryrun.py` | `__main__`, `checks.py`, `pipeline/wiring_runner.py`, `pipeline/dryrun_trace.py`, `verify/smoke.py`, `scripts/bench/` | **stays** |
| `actions.py`, `diagnostics.py` | `messagefoundry/__init__.py`, `lens_schema.py` | **stay** |
| `spreadsheet.py` | `api/auth_routes.py`, `config/codeset_edit.py` | **stays** |

Four findings shape the design:

1. **`config/impact.py` stays.** The production `codeset` command reaches it through
   `config/codeset_edit.py`, which calls `impact.apply_rename`, `impact.plan_rename` and
   `impact.delete_impact`. Only the `impact` subcommand's parser and its handler move.
2. **`anon/` depends on `generators/`, not the other way.** `anon/_pools.py` imports
   `messagefoundry.generators._hl7data`. So `anon/` can move first and keep importing the engine's
   `generators/`, since the toolkit may import the engine. `generators/` cannot move first, because
   the engine's `anon/` would then import the toolkit.
3. **The chain `generators/adt.py` to `hl7structures` to `hl7schema` must move as one.**
4. **The harness imports `generators/` and not `anon/`.** The five files are `harness/compose.py`,
   `harness/file_panel.py`, `harness/load/corpus.py`, `harness/scenarios.py` and `harness/send.py`.
   The tee imports neither. It vendors its own `tee/anon/` copy, and `tests/test_anon_parity.py`
   holds that copy byte-identical to `messagefoundry/anon/` and to `generators/_hl7data.py`.

Two older blockers are already gone. `verify/smoke.py` no longer imports `generators/`, because PR
942 inlined its synthetic message. And the release container is unaffected: `docker/` names no
toolkit module, and its image installs only the engine wheel.

**The handlers live in `__main__.py`, with their helpers.** The toolkit handlers are `_init`,
`_import`, `_lens` and its three children, `_generate`, `_adr_analyze`, `_impact`, `_hl7schema` and
`_hl7structures`. Their helpers fall into two groups:

- **Shared with production handlers:** at least `_emit_error`, `_print_json`, `_safe_print`,
  `_load_operator_json` and `_OperatorJsonError`.
- **Used by one toolkit handler only:** `_reference_dict` and `_IMPACT_KINDS` (by `_impact`), and
  the `_read_stdin` closure inside `_lens_rewrite`.

**One production message names a toolkit command.** `config/wiring.py` refuses an empty config with
a line telling the operator to run `messagefoundry init`, and `tests/test_wiring.py` asserts that
substring. `serve`, `validate` and `check` all reach it.

### Two constraints the design must respect

**The PyPI name is unclaimed.** The JSON API returned 404 for `messagefoundry-toolkit` at 2026-09-29
15:39 UTC. The same request for `messagefoundry-harness` returned 200, so the probe works. The name is
already public: `cli_surface.py` on `main` names it, and so does this ADR. ASVS 15.2.4 and BACKLOG
#1193 name the risk. If anyone else registers the name first, any install that resolves it from an
index runs their code. An sdist runs its build backend during `pip install`, before any engine control
exists.

[`tests/test_install_instruction_provenance.py`](../../tests/test_install_instruction_provenance.py)
is already built for this. Its `_UNPUBLISHED_DISTRIBUTIONS` set exists *"for the NEXT
distribution"*, and it refuses shipped text that tells a user to install an unclaimed name. It
matches a `pip install` verb, so it cannot see text that names the distribution without one. The
design below therefore does not rely on it to close the window.

**An "editable" install of a force-included tree is a frozen copy.** Measured in this worktree's
`.venv`: the web console was installed with `-e packaging/messagefoundry-webconsole`, yet
`site-packages/` holds a real `messagefoundry_webconsole/` directory and no `.pth` file for it. The
engine's own `.pth` adds the repository root after `site-packages`, so the copy wins. Edits to the
checkout do not reach what runs until someone reinstalls. The web console has lived with this. A
toolkit cannot: `anon/leak.py` and `anon/surrogates.py` find `scripts/security/` by walking up from
`__file__`, and from `site-packages/` that walk never reaches the repository.

## Decision

**Build a third sibling distribution, `messagefoundry-toolkit`, released in lockstep with the engine.
Move the toolkit modules and their handlers into its own import package, `messagefoundry_toolkit`,
with its own command, `messagefoundry-toolkit`. The engine CLI registers only production rows and
loads no toolkit code.**

The engine must keep working with no toolkit installed. No file under `messagefoundry/` may name
`messagefoundry_toolkit`.

### 1. Package layout, version and name

**Import package.** `messagefoundry_toolkit/` sits at the repository root, beside
`messagefoundry_webconsole/` and `harness/`. A checkout then imports it with no install, as the two
siblings do.

**Distribution.** `packaging/messagefoundry-toolkit/` holds `pyproject.toml` and `README.md`,
modelled on the two sibling tables:

- The build backend is pinned with `requires = ["hatchling==1.32.4"]`, in lockstep with the other
  three tables. `tests/test_packaging.py` already checks that every build system agrees.
- The wheel target force-includes `../../messagefoundry_toolkit` as `messagefoundry_toolkit`, one
  whole-directory mapping as the web console does. The existing
  `test_no_packaged_wheel_force_includes_the_repository_instructions` covers the map.
  `scripts/release/forbidden_members.py` stays the backstop for a nested `CLAUDE.md`.
- **Dev and CI environments do not install the toolkit distribution at all.** An editable install of
  this table would be the frozen copy measured above. Hatchling 1.32.4 has no pyproject option that
  stops it: `force-include-editable` is build data only a hook can set, and `dev-mode-dirs` still
  copies force-included files. That is the second review's reading of hatchling's
  `builders/wheel.py`, reported and not re-read for this ADR. The design below does not depend on it,
  because it installs nothing.

  No install is needed. The engine's editable install already puts the repository root on the import
  path through its `.pth` file, so `import messagefoundry_toolkit` resolves to the checkout in every
  dev venv and in every CI job that installs the engine with `-e .`. Developers and the IDE run
  `python -m messagefoundry_toolkit`. Only the `packaging-build` CI job and the release build the
  toolkit wheel.

  A test pins the property: `messagefoundry_toolkit.__file__` resolves under the repository root.
  A custom build hook that makes a true editable install is possible, and is deferred until someone
  needs the `messagefoundry-toolkit` console script in a dev venv.
- The distribution is not added to `TEST_TOOLING_DISTRIBUTIONS`. No planned member trips the
  test-content rule. A later member that does gets the exemption in its own change, with reasons.
- **Its command.** `[project.scripts]` declares `messagefoundry-toolkit =
  "messagefoundry_toolkit.__main__:main"`, and `python -m messagefoundry_toolkit` runs the same
  entry.

**Version: lockstep, like the harness.** The toolkit reads its version from
`../../messagefoundry/__init__.py` through `[tool.hatch.version].path`, and depends on
`messagefoundry==<that same version>`.

It is lockstep, not independent like the web console, because the toolkit calls engine internals.
Examples are `config.impact`, the registry loader, the signatures `lens_schema` reads from `actions`
and `diagnostics`, and the shared CLI helpers. No stable seam lies between them. An independent
version would need a handshake like the console's `ENGINE_UI_SEAM`, built to protect a version skew
nobody needs.

A version bump then touches three files: `messagefoundry/__init__.py`, the harness pin and the
toolkit pin. `tests/test_packaging.py::test_the_harness_pins_the_engine_at_the_version_it_ships_with`
gains a toolkit twin.

**The pin is not enough by itself.** `pip install -U messagefoundry` upgrades the engine past a
toolkit's `==` pin, prints a resolver warning and exits 0. So the toolkit checks at startup. It
compares its own distribution metadata version with the engine's, both read through
`importlib.metadata`. On a mismatch it prints one line naming both and exits 2.

It compares metadata with metadata, not with the engine's live `__version__`. With no toolkit
metadata at all, which is every dev and CI environment, the check is skipped: the engine and the
toolkit then come from one checkout.

The toolkit declares only the engine pin. Its third-party imports are core engine dependencies:
`hl7apy` in `hl7schema`, `hl7structures`, `generators/_core.py` and `generators/siu.py`; `hl7`
(python-hl7) in `anon/hl7.py`; and `defusedxml` in `corepoint_import`. That list is "at least",
from an AST scan. The exact `==` pin makes the engine's set the toolkit's. The pyproject comment names
them, so a later change to the engine's core set is checked against them.

**The PyPI name is claimed by the toolkit's first upload, and no released engine names the toolkit
before that upload.**

1. **Owner action, one time, just before slice 2 merges.** Configure a pending Trusted Publisher for
   `messagefoundry-toolkit` on PyPI, for repository `MEFORORG/MessageFoundry` and workflow
   `release.yml`, with the environment blank to match the engine. Do not treat the pending publisher
   as a reservation. The claim this design relies on is the first upload.

   The owner agreed to this step on 2026-09-29, in session, to the batch 175 Manager, answering
   *"I'll do it before slice 2"*. So the owner sets up the pending publisher before slice 2 merges.
   The answer is a commitment, not a record that the publisher exists: slice 2 must not merge until
   it is in place.

   A second review raised, from memory and not from Warehouse's code, that PyPI may create the
   project at the first matching token exchange, which could be the engine's own publish step. That
   would claim the name early, which is the safe direction. The build reads Warehouse's behaviour
   before relying on either reading.
2. **The toolkit uploads inside the engine's `release` job, before the engine's own upload step.**
   The steps build the toolkit wheel into its own `toolkit-dist/` directory, never `dist/`. Sharing
   `dist/` would pull the toolkit into the engine smoke install, the `py.typed` check and the staged
   engine upload. The steps then:
   - smoke the wheel with `--no-deps`, and check its `Requires-Dist` pins the engine at the wheel's
     own version, as the harness smoke does for BACKLOG #1585, because `tests/test_packaging.py` does
     not run at tag time;
   - run `forbidden_members.py` over it;
   - publish it through Trusted Publishing, with PEP 740 attestations and `skip-existing: true`.

   A failure stops the job before the engine uploads. So no engine that names the toolkit reaches
   PyPI while the name is unclaimed, and no person has to remember an order.

   **This bends the release job's rule that nothing may fail after an irreversible upload.** If the
   engine upload then fails, PyPI holds a toolkit whose engine pin cannot resolve yet. That is an
   uninstallable version, not an exposure, and a re-run finishes it. `skip-existing` is what keeps
   that re-run from dying on *"File already exists"* at the toolkit step, the deadlock `release.yml`
   records from v0.3.1.

   The GitHub release is created earlier in the same job, so a failed toolkit upload still leaves a
   public GitHub release whose engine names the toolkit. That release carries the engine wheel as a
   file, and nothing in it resolves the toolkit from an index. The window this closes is the PyPI
   one.

   This departs from `release-harness`, a separate job gated on a repository variable. A variable
   that can be unset is the window this closes. `tests/test_release_pipeline.py` pins the release
   job's mutating steps and one smoke per `--wheel` build, so slice 2 updates it.
3. **Slice 2 adds `messagefoundry-toolkit` to `_UNPUBLISHED_DISTRIBUTIONS`.** It also adds
   `messagefoundry_toolkit/**/*.py` and the toolkit README to `_SHIPPED_TEXT_GLOBS`.
4. **After the first tag carrying slice 2,** a probe of that version's JSON API URL
   (`/pypi/messagefoundry-toolkit/<version>/json`), with the harness as a control, shows the upload
   landed. A small change then moves the name to `_PUBLISHED_DISTRIBUTIONS`. From then on, shipped
   text may give a bare-name install.

Two things wait for step 4. One is any shipped text giving a bare-name install of the toolkit. The
other is the harness's dependency on it, because a published harness requiring an unclaimed name is
the confusion primitive itself.

**A token upload, or a placeholder project, is rejected.** It would add a publishing identity outside
Trusted Publishing, and PEP 541 lets PyPI remove a project with no real content.

### 2. Which modules move, and which stay

| Moves to `messagefoundry_toolkit/` | With its subcommands |
|---|---|
| `adr_analyze.py` | `adr-analyze` |
| `scaffold.py` | `init` |
| `lens.py`, `lens_schema.py` | `lens`, `lens parse`, `lens rewrite`, `lens schema` |
| `corepoint_import.py` | `import`, `import corepoint` |
| the `impact` parser and handler, not `config/impact.py` | `impact` |
| `hl7schema.py`, `hl7structures.py` | `hl7schema`, `hl7structures` |
| `generators/` whole, `README.md` included | `generate` |
| `anon/` whole | none |

**Stays in the engine, because production code imports it:** `config/impact.py`,
`pipeline/dryrun.py` with its CLI driver, `checks.py`, `actions.py`, `diagnostics.py` and
`spreadsheet.py`. R4 keeps `dryrun` production, so the dry-run CLI-driver split that ledger row #1192
once proposed is not needed.

**Each handler moves with its parser into `messagefoundry_toolkit/__main__.py`,** together with the
helpers only it uses: `_reference_dict`, `_IMPACT_KINDS` and the `_read_stdin` closure. A handler may
import engine code that has not moved yet. The toolkit may import the engine, so that is legal, and
it is what lets the command surface move before the modules do.

**The shared helpers move once, into an engine module.** Slice 1 moves them into
`messagefoundry/cli_common.py` (name open at build), verbatim, the way ADR 0088 moved
`console/client.py`. Both CLIs import that module. The toolkit never imports
`messagefoundry.__main__`.

**So does the process-wide shell around dispatch.** Today `main()` does more than parse. It hardens
the console streams (BACKLOG #1875). It installs the last-resort hooks for the main thread and every
other thread, which carry the ASVS 16.5.4 promise that no raw traceback quotes a PHI-bearing value.
It gives a subcommand a redacting stderr log sink (#1441, #1489). And it wraps dispatch so an
unexpected error still gives `{"error": ...}` under JSON (#1863).

The toolkit needs all of it: `import corepoint` parses untrusted XML, and the IDE parses `lens`
output as JSON. So slice 1 moves that shell into one function in `cli_common.py`, taking a parser and
a dispatch map, and both `main()` functions call it. The cp1252 gate, which today requires the
hardening call only in its known `__main__.py` files, gains the toolkit's.

**No compatibility re-export is left behind.** A stub `messagefoundry/generators/__init__.py` that
re-exported the toolkit would keep a file in the engine wheel and re-open clause (a). It would also
protect nobody, because CLAUDE.md section 0 records zero deployments. Every importer, in `tests/`,
`harness/`, `tee/` docstrings and the docs, changes in the slice that moves its module.

### 3. The toolkit has its own command, and the engine loads none of it

**Slice 1 extracts `_build_parser()`** from `main()`, returning the parser and the dispatch map with
no behaviour change. `tests/test_cli_surface.py` then calls it directly instead of catching the
parser at `parse_args`.

**The engine registers production rows in its own code, as today.** `CLI_TIERS` stays pure data with
no engine imports, as its docstring promises.

**The toolkit registers toolkit rows in its own parser.** `messagefoundry_toolkit.__main__` builds an
argparse parser, `prog="messagefoundry-toolkit"`, whose subcommands are the toolkit rows. A user runs
`messagefoundry-toolkit init` or `messagefoundry-toolkit lens parse`. A row's key in `CLI_TIERS` is
the same string on either command.

**What the engine prints for a toolkit command.** Before parsing, `main()` looks at the first
argument that is not an option. If it names a top-level toolkit row that the engine does not register,
the engine exits 2, the argparse usage-error code, through `_emit_error`. The message names the
command and says to run it as `messagefoundry-toolkit <command>`, from the separate
`messagefoundry-toolkit` distribution at the engine's own version.

`_emit_error` writes JSON to stdout or text to stderr, **never both**. Both at once would break a
`2>&1` pipe, as `_adr_analyze`'s comment records. JSON mode is on when the argument list has
`--json`, or when the command is `lens`, whose children take JSON mode from `set_defaults` and have
no flag.

> **Corrected at build, slice 2 (2026-09-30).** The sentence above over-reads `lens`. Only
> `lens rewrite` takes JSON mode from `set_defaults`; `lens schema` prints JSON with or without its
> `--json` flag; `lens parse` has the flag and reports an error as text without it. So the built rule
> is `--json`, `lens rewrite` or `lens schema`, in `messagefoundry.cli_common.argv_wants_json`, which
> both commands' pre-parse refusals use. And "the first argument that is not an option" yields to a
> top-level `--help` or `--version` that comes first, because argparse answers those before it reads
> a subcommand; both top-level parsers set `allow_abbrev=False` so those are the only spellings. A
> pre-parse JSON refusal of `lens rewrite` still carries no `"code"` key, which BACKLOG #237 promises
> on every `lens rewrite` refusal; no path reaches it until slice 4 moves `lens`, and that slice owns
> it.

The check keys on "not registered here", not on the tier alone. So while a slice has moved some
toolkit rows and not others, the engine still runs the rows it still carries. The top-level `--help`
gains one epilog line naming the toolkit commands and the distribution. The line names them; it
exposes no functionality. None of this reads package metadata or imports anything.

**The engine's own help text must stop presenting toolkit commands.** `main()` builds its parser
with `description=__doc__`, and the module docstring's usage block lists `messagefoundry generate`,
`messagefoundry hl7schema`, `messagefoundry lens schema` and `messagefoundry init`. Each slice that
moves a command edits that block. From slice 4 a test asserts the description gives no toolkit row as
a `messagefoundry <row>` example. The relsmoke row check cannot see prose, so this test is what
covers it.

**`CLI_TIERS` stays the single source of record,** held by three tests in `tests/test_cli_surface.py`:

- **In every slice.** The engine parser's rows and the toolkit parser's rows are disjoint. Their
  union is exactly the 46 rows, and no production row is in the toolkit parser.
- **From slice 4 on.** The engine parser's rows are exactly the 34 production rows, and the toolkit
  parser's rows are exactly the 12 toolkit rows.
- **Always.** The engine source contains no reference to `messagefoundry_toolkit`, checked as
  described under section 4.

The first test lets a slice move some rows and not others without a hand-kept transition list. The
second binds once the last command has moved.

**Why a separate command and not a plugin loaded by the engine.** A first draft of this ADR had the
engine load toolkit subcommands through an entry-point group, so users kept typing `messagefoundry
init`. An adversarial review found five defects in that loader:

1. Loading at parser build put toolkit code into the `serve` process, and a broken toolkit could stop
   `serve` from starting.
2. The register callable received the engine's live subparser object. So a name check on the entry
   point did not stop it adding other commands.
3. `importlib.metadata` finds a `.dist-info` in the current directory under `python -m`, so the
   distribution-name check proved less than it claimed.
4. Per-row entry points freeze in an editable install's metadata, so each slice that moved a command
   would silently drop commands from existing dev venvs.
5. The runtime `import_module` it needed is an engine-to-toolkit edge that no static boundary test
   can hold.

Each has a fix, but together they add a plugin surface to the production CLI, which is the thing
15.2.3 asks us to shrink. A separate command has none of them. The engine carries no loading code,
the toolkit process imports the engine as any caller does, and the boundary test stays purely static.

The cost is a second command name. CLAUDE.md section 0 makes the migration cost of that change zero,
and the IDE argv and the docs change in the same slices anyway.

### 4. How the engine wheel keeps toolkit code out

**The physical move is the exclusion.** Once a module lives in `messagefoundry_toolkit/`, hatchling
does not pack it into the engine wheel, because the engine wheel packs only `messagefoundry/`.

**The engine wheel target is made explicit.** `pyproject.toml` has no
`[tool.hatch.build.targets.wheel]` table today, so the wheel's contents are hatchling's unconfigured
default, as the cell records. Slice 2 declares it with `packages = ["messagefoundry"]` and no
per-target `exclude`. A per-target `exclude` would replace the global `exclude = ["CLAUDE.md"]`
rather than extend it. The existing
`test_the_engine_excludes_its_nested_instructions_from_every_build_target` keeps that true.

**An exclude list derived from `CLI_TIERS` is rejected,** for three reasons:

1. `CLI_TIERS` keys are command names, not file paths, so the list would need a second, hand-kept
   mapping anyway.
2. Excluding files that still sit under `messagefoundry/` splits the checkout from the wheel. Tests
   run against the checkout would import the modules freely, while the installed wheel raises
   `ImportError`. The split hides exactly the breakage a move must surface.
3. It keeps the code in the engine's source tree, so the sdist allowlist (`only-include =
   ["messagefoundry", ...]`) would still carry it.

**`forbidden_members.py` gains a third rule, keyed on the distribution name in the archive
filename,** the way the test-content rule already is. Like the script's other rules, it matches path
**components**, never a prefix string. An sdist member is `messagefoundry-0.4.0/messagefoundry/...`,
and a prefix match would never fire on it.

- **Engine archives, wheel and sdist.** Refuse a member with a component `messagefoundry_toolkit`.
  Also refuse a member whose components contain a retired engine path as a consecutive run, such as
  `messagefoundry`, `generators` or `messagefoundry`, `adr_analyze.py`. The retired paths are the
  table in section 2. The list lives in the script beside its reason, like `FORBIDDEN_BASENAMES`, and
  grows in the slice that retires each path.
- **Toolkit wheel.** Refuse a member whose first component is `messagefoundry`. A toolkit that writes
  into the engine's package directory is the split-package shape rejected below.

Planted archives in `tests/test_release_member_gate.py` cover the wheel form and the sdist form of
each rule.

**The built-wheel checks run where the real artifacts are.** The `packaging-build` job in
`.github/workflows/ci.yml` builds the toolkit wheel as a fifth artifact, beside the engine sdist and
wheel, the harness and the console, and runs the member gate over it. It adds a positive control: a
copy of the engine wheel poisoned with a path retired **in that same slice** must be refused. In slice 2 that path is `messagefoundry/adr_analyze.py`. Each later
slice may keep it, since a retired path stays retired.

From slice 4 on, `release.yml`'s engine smoke also checks exposure. It already installs the built
engine wheel into `/tmp/relsmoke` with its dependencies and no toolkit. There it asserts that
`_build_parser()` yields exactly the production rows of `CLI_TIERS`. That measures clause (b) on the
artifact a tag would publish, not on a model of it.

**The static gates must walk the new root.** Moving code out of `messagefoundry/` takes it out of
every gate that walks by root. Re-keying a path string is not enough: a stale-entry check that reads
by path stays green while the new tree goes unscanned. One example is the XML allowlist in
`tests/test_security_static.py`. `corepoint_import.py` parses untrusted Corepoint XML, so a bare
`xml.etree` parse added under `messagefoundry_toolkit/` would pass a gate that never walks it.

So slice 2 adds `messagefoundry_toolkit` to every **Python** walk root that already names
`messagefoundry_webconsole`, before any code moves. At least these do:

- `_SOURCE_ROOTS`, `_CRYPTO_ROOTS` and `_XML_ROOTS` in `tests/test_security_static.py`;
- `WALK_ROOTS` in `scripts/security/crypto_inventory_check.py`, which is pinned equal to them.

Not every mention is a Python walk root. `NON_PYTHON_WALK_ROOTS` in the same script walks TypeScript
and JavaScript, and `tests/test_crypto_inventory_scanner.py` pins it exactly, so it does not gain the
toolkit. 48 files under `tests/` and `scripts/` name `messagefoundry_webconsole` at `ba38f9309`. Each
is a candidate, and the slice 2 builder reads each one rather than trusting this list. Gates that walk
only `messagefoundry/`, such as the cp1252 engine walk and the from-None scan, gain the root too.
`bandit` in `.github/workflows/security.yml` scans the whole repository minus named excludes, so it
covers the new root with no change.

**Three more repository rules key on `messagefoundry/` by name, and slice 2 extends each:**

- **Line endings.** `.gitattributes` pins `messagefoundry/**` and `tee/anon/**` to LF. Its comment
  records that an unpinned side fails the byte-for-byte `anon/` parity test on the Windows CI legs
  under `core.autocrlf=true`. So `messagefoundry_toolkit/**` gets the same pin, and
  `tests/test_shipped_line_endings_pinned.py`, which lists only `messagefoundry`, covers it.
- **The tooling partition.** `tests/test_tooling_partition.py` treats a test as an engine test when it
  imports `messagefoundry`, `messagefoundry_webconsole`, `harness` or `tee`. A test that imports only
  `messagefoundry_toolkit` would be pushed into the path-gated tooling job, and stop running on the
  PRs that change the toolkit. The pattern gains `messagefoundry_toolkit`.
- **Type checking.** `ci.yml` runs `mypy messagefoundry`, so it gains `mypy messagefoundry_toolkit`.

**A boundary test holds the direction, and it is a text search.** `tests/test_dependency_boundaries.py`
gains an arm: the identifier `messagefoundry_toolkit` appears nowhere in a file under
`messagefoundry/`, in an import, a string or anywhere else. The refusal line names the command
`messagefoundry-toolkit`, with a hyphen, which is not that identifier. A text search catches an
`importlib.import_module("messagefoundry_toolkit.x")` that an import-statement scanner misses. A
planted file of each form is its positive control.

What it cannot see is a module name the **operator** supplies at run time. `config/secretprovider.py`
and `store/keyprovider.py` load operator-named modules with `import_module`. An operator could name a
toolkit module there. That is operator configuration choosing to load code, not the engine depending
on the toolkit, and this ADR does not change it.

The toolkit is **not** added to `_CLIENT_ROOTS`. It is an engine-side authoring library that may
import any engine package, as the `impact` handler must import `config`. It is not an API client.

### 5. The ADR 0030 amendment moves `anon/`'s home, and lands alone

ADR 0030 section 1 places `anon/` as *"engine-owned"*, *"sitting beside `parsing/`"*, and vendored
byte-identical to `tee/anon/` under a CI parity check. Its Related line says it *"extends that
carve-out to `anon/` on acceptance"*, meaning the pure-library carve-out CLAUDE.md section 4 grants
`parsing/`. The module home was one of the forks the owner ratified before that build.

The amendment says four things:

1. The home becomes `messagefoundry_toolkit/anon/`, in the toolkit distribution.
2. The rule table stays the single authority, and the tee still vendors a byte-identical copy.
3. The parity check re-points to the new path.
4. The carve-out language is withdrawn, because `anon/` stops being an engine package.

What `anon/` does, its rules, its fail-closed behaviour and its limits are unchanged.

**It lands in its own PR, for four reasons:**

1. The owner's chosen option says so.
2. It amends an Accepted ADR's ratified choice. That needs the owner's sign-off on its own, not
   buried in a mechanical diff.
3. The `anon/` move re-keys at least seven path-pinned security guards:
   - `scripts/security/crypto_inventory_check.py`
   - `tests/test_security_static.py`
   - `tests/test_key_lifecycle_coverage.py`
   - `tests/test_cp1252_console_safety.py`
   - `tests/test_from_none_is_not_redaction.py`
   - `tests/test_anon_parity.py`
   - `scripts/quality/licence_header_check.py`

   CLAUDE.md section 5 gives a change to a security control its own PR.
4. Landing the amendment first means the move PR builds against an Accepted record rather than
   ahead of one.

### 6. The harness, the IDE and the docs

**The harness.** `packaging/messagefoundry-harness/pyproject.toml` adds
`messagefoundry-toolkit==<version>` beside its engine pin, in slice 7. That is after the claim,
because the harness is published. Its five `generators` importers change to
`messagefoundry_toolkit.generators`. The harness pin test gains a toolkit assertion.

**The IDE.** The IDE runs `python -m messagefoundry` with the developer's interpreter:

- `lens parse`, `lens rewrite` and `lens schema` in `ide/src/cli.ts`;
- `generate --list` and `generate` in `ide/src/generate.ts`.

In slice 4 both switch to `python -m messagefoundry_toolkit`, with the same arguments. When the
toolkit is missing, Python exits with *"No module named messagefoundry_toolkit"*. The IDE turns that
into a clear message in the Steps view and in the generate command, naming the distribution to
install. `ide/README.md` says the developer interpreter needs the toolkit.

The IDE's bundled `ide/media/hl7schema.json` and `hl7structures.json` are read as files. The IDE
never runs those two commands, so they need no IDE change. `tests/test_ide_artifacts.py`, which
recomputes them, imports the toolkit from the checkout like every other test.

**The scaffold.** `init` writes a `requirements.txt` that pins the engine, and the config repo's CI
installs it. In slice 4 the scaffold also writes a `requirements-dev.txt` that pins the toolkit at the
same version. Authoring machines install it; a deploy from the config repo does not. That keeps the
toolkit off a production host by default, which is the point of the split.

**The docs that change with each move.** Found by a search for each command in `docs/*.md`,
`README.md`, `ide/README.md`, `harness/`, `.github/` and engine source, so read it as at least these:

| Slice | Command or module | Files |
|---|---|---|
| 2 | `adr-analyze` | `docs/adr/README.md` (its "Authoring a new ADR" paragraph), `docs/FEATURE-MAP.md` |
| 4 | `init` | `docs/INSTALL-GUIDE.md`, `docs/USER-GUIDE.md`, `docs/EARLY-ADOPTER-GUIDE.md`, `docs/ADOPTER-CI.md`, `docs/MENTAL-MODEL.md`, `docs/DANGEROUS-FUNCTIONALITY.md`, `README.md`, and the refusal text in `messagefoundry/config/wiring.py` with its assertion in `tests/test_wiring.py` |
| 4 | `import corepoint` | `docs/DANGEROUS-FUNCTIONALITY.md`, `docs/AI-OFF-MATRIX.md` |
| 4 | `lens` | `docs/FEATURE-MAP.md`, `ide/README.md` |
| 4 | `generate` (the command) | `docs/EARLY-ADOPTER-GUIDE.md`, `docs/ADOPTER-CI.md`, `docs/USER-GUIDE.md`, `docs/MENTAL-MODEL.md`, `docs/PHI.md`, `docs/Secure_AI_Development_Standards.md`, `docs/architecture-diagram.md`, `docs/FEATURE-MAP.md`, `ide/README.md`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/SECURITY.md` |
| 4 | `hl7schema`, `hl7structures` (the commands) | `docs/FEATURE-MAP.md`, `ide/README.md` |
| 6 | `anon/` | `docs/PHI.md` section 9, `.github/workflows/fuzz.yml` (comment), the `tee/anon/` docstrings that name `messagefoundry.anon`, the root `CLAUDE.md` sections 3 and 9 |
| 7 | `generators/` (the module) | `docs/ARCHITECTURE.md` (its module table), `harness/README.md`, the root `CLAUDE.md` section 3 |

**`docs/FEATURE-MAP.md` carries a stale count.** Its CLI row says *"34 subcommands"*. At
`ba38f9309` the engine registers 38 top-level subcommands and 8 nested ones. After the move the
engine has 30 top-level subcommands and the toolkit 8. The row drops the number and points to
`cli_surface.py`, because a pinned count in prose goes stale at the next subcommand.

`CHANGELOG.md` gets an entry in every slice that changes what ships.

### 7. Slice order

Each slice is one PR. A slice that changes a security control or amends an ADR stands alone, per
CLAUDE.md section 5. Every file list below is "at least". Two review rounds each found tests the
first lists missed, so each slice's builder runs the whole suite rather than trusting its list.

1. **Extract `_build_parser()`, the shared helpers and the dispatch shell.** No behaviour change.
   Files: `messagefoundry/__main__.py`, the new `messagefoundry/cli_common.py`,
   `tests/test_cli_surface.py`, and any `tests/test_cli*.py` that patches a moved helper or hook.
   **Wait for open PR 1770**, which edits `__main__.py`.
2. **Create the toolkit distribution and move `adr-analyze`.** `adr-analyze` is the one toolkit
   command that no operator doc and no IDE call names, so it proves the machinery on one command.
   **Precondition: the owner action in section 1, step 1.** Files:
   - new: `packaging/messagefoundry-toolkit/pyproject.toml` and `README.md`,
     `messagefoundry_toolkit/__init__.py`, `messagefoundry_toolkit/__main__.py`,
     `messagefoundry_toolkit/adr_analyze.py`;
   - delete: `messagefoundry/adr_analyze.py`;
   - edit: `messagefoundry/__main__.py` (the not-registered-here line and the epilog, one registration
     dropped), `messagefoundry/cli_surface.py` (its docstring: which command registers which rows),
     `pyproject.toml` (the explicit wheel target), `scripts/release/forbidden_members.py`,
     `.github/workflows/release.yml` (the toolkit steps inside the `release` job),
     `.github/workflows/ci.yml` (a `mypy messagefoundry_toolkit` step and the fifth
     `packaging-build` artifact), `.gitattributes`, every walk root in section 4, the slice 2 docs in
     section 6;
   - tests: `tests/test_cli_surface.py`, `tests/test_cli.py` (it asserts `adr-analyze` in the engine's
     `--help`), `tests/test_packaging.py`, `tests/test_install_instruction_provenance.py`,
     `tests/test_dependency_boundaries.py`, `tests/test_release_member_gate.py`,
     `tests/test_release_pipeline.py` (the mutating-step count and one smoke per `--wheel` build),
     `tests/test_tooling_partition.py`, `tests/test_shipped_line_endings_pinned.py`,
     `tests/test_adr_analyze.py`, and a new `tests/test_toolkit_cli.py` (the version check, and the
     import resolving under the repository root).

   **Coordinate on `ci.yml`**, which batch 175's Builder G is editing now.
3. **Confirm the claim.** After the first tag carrying slice 2, probe PyPI with a control, then move
   the name to `_PUBLISHED_DISTRIBUTIONS`. Files: `tests/test_install_instruction_provenance.py`.
4. **Move every remaining toolkit command, and the authoring modules.** After this slice the engine
   registers only production rows, and the strict test and the relsmoke assertion switch on. Files:
   - moved: the handlers and parsers of `init`, `import`, `lens`, `impact`, `generate`, `hl7schema`
     and `hl7structures` into `messagefoundry_toolkit/__main__.py`; the modules `scaffold.py`,
     `lens.py`, `lens_schema.py` and `corepoint_import.py` into `messagefoundry_toolkit/`. The
     `generate`, `hl7schema` and `hl7structures` handlers import the engine's `generators/` and
     `hl7*` modules, which have not moved yet;
   - edit: `messagefoundry/__main__.py`, `messagefoundry/config/wiring.py`, the scaffold templates,
     `ide/src/cli.ts`, `ide/src/generate.ts`, `.github/workflows/release.yml` (the relsmoke
     assertion), `scripts/release/forbidden_members.py`, the slice 4 docs in section 6;
   - tests: `tests/test_cli_surface.py`, `tests/test_wiring.py`, `tests/test_security_static.py`
     (the `corepoint_import` XML allowlist entry), and the lens, Corepoint, scaffold, impact and
     generate test modules. `tests/test_cli.py` uses `hl7schema` and `lens rewrite` as probes for the
     engine's dispatch floor and last-resort hook tests. Those tests need new **production** probes,
     not re-pointed paths, because the property they check belongs to the engine command.

   **Wait for open PR 1797**, which edits `docs/DANGEROUS-FUNCTIONALITY.md` section 8.
5. **Amend ADR 0030.** Files: `docs/adr/0030-anonymization-test-harness-tee.md`,
   `docs/adr/README.md`. Documentation only, and on its own.
6. **Move `anon/`.** Files:
   - moved: `messagefoundry/anon/` to `messagefoundry_toolkit/anon/`. `_pools.py` keeps importing
     `messagefoundry.generators._hl7data` for now;
   - edit: the seven guards in section 5, `scripts/security/scan_forbidden.py` (its comments),
     `tests/test_anon_core.py`, `tests/test_anon_integration.py`, the slice 6 docs in section 6,
     `scripts/release/forbidden_members.py` (one more retired path).

   On its own.
7. **Move `generators/`, `hl7schema.py` and `hl7structures.py`.** Files:
   - moved: those three into `messagefoundry_toolkit/`;
   - edit: `messagefoundry_toolkit/anon/_pools.py` and the moved handlers (re-pointed imports), the
     five `harness/` importers, `packaging/messagefoundry-harness/pyproject.toml`, the slice 7 docs in
     section 6, `scripts/release/forbidden_members.py`;
   - tests: every generator test module (14 import `generators` today), `tests/test_hl7schema.py`,
     `tests/test_hl7structures.py`, `tests/test_anon_parity.py` (the `_hl7data` path),
     `tests/test_ide_artifacts.py`, `tests/test_verify.py` (it imports a generator as a positive
     control), `tests/test_packaging.py` (the harness's toolkit pin).
8. **Re-score 15.2.3.** Vault record work, done by a Manager's vault Builder under the 2026-09-23
   ruling, after a release carries slices 2 to 7. See section 8.

The dependencies between slices:

| Slice | Needs | Why |
|---|---|---|
| 2 | 1, and the owner's PyPI action | The toolkit reuses `cli_common.py`; the first tag must be able to claim the name. |
| 3 | 2 and a tag | The claim is the toolkit's first upload. |
| 4 | 3 | Its docs give a bare-name install of the toolkit. |
| 5 | nothing | Documentation only; it can land at any time. |
| 6 | 2 and 5 | It needs the toolkit package and the amended ADR 0030. |
| 7 | 3, 4 and 6 | The `generate` and `hl7*` handlers must already have left the engine, or the engine would lose them or import the toolkit. `anon/` must leave before `generators/` does (finding 2). And the published harness starts to depend on the toolkit. |

Slice 4 is independent of slices 5 and 6.

### 8. What this does and does not do for 15.2.3's grade

**It moves no verdict.** R4 set tiers. This ADR designs a build. The cell stays `partial` until a
re-score reads the **released** artifacts after slices 2 to 7 land. The cell's own trigger to pass
names more than this build:

- **Clause (a) on the engine wheel.** The build removes every module the cell names. The re-score
  must build or download the released engine wheel, open it, and find none of them.
- **Clause (b) on the console script.** From slice 4 on, a toolkit-free install registers no toolkit
  subcommand and loads no toolkit code. The relsmoke assertion in section 4 measures this on each
  tag, and the re-score should read that result for the released tag.
- **The web console wheel.** The cell requires it to be built and read. This ADR does not touch it.
- **The container image.** It installs only the engine wheel, so it inherits the result. The cell
  reads it without building it, and the re-score decides whether that reading still holds.
- **The rows the owner did not rule on.** `cli_surface.py` says 24 production rows are production
  because the relaying brief put *"everything else"* there, not by owner ruling. The re-score must
  judge them or record that it relies on that placement. `cert self-signed` joins the ruled rows once
  the follow-up answer is recorded.

It does not make the toolkit safe to install on a production host. It makes the choice visible and
separate. A site that installs the toolkit there has chosen to carry development code, and the
INSTALL-GUIDE text written in slice 4 should say so.

## Acceptance Criteria

> Each criterion names the test that will verify it. None exists yet; each is named for the slice
> that writes it.

- **AC-1** -- THE SYSTEM SHALL keep the engine parser's rows and the toolkit parser's rows disjoint,
  with their union equal to every `CLI_TIERS` row, and with no production row in the toolkit parser.
  Verified by: `tests/test_cli_surface.py` (slice 2)
- **AC-2** -- THE SYSTEM SHALL register exactly the production rows of `CLI_TIERS` in the engine
  parser, and exactly the toolkit rows in the toolkit parser.
  Verified by: `tests/test_cli_surface.py` (slice 4), and the relsmoke assertion in `release.yml`
- **AC-3** -- WHEN a user runs a top-level toolkit command on the engine command, and the engine does
  not register it, THE SYSTEM SHALL exit 2 naming `messagefoundry-toolkit <command>`: as
  `{"error": ...}` on stdout alone in JSON mode, and as one line on stderr alone otherwise.
  Verified by: `tests/test_cli_surface.py` (slice 2)
- **AC-4** -- IF the installed toolkit's metadata version differs from the engine's, THEN THE SYSTEM
  SHALL refuse to run any toolkit command and print one line naming both versions.
  Verified by: `tests/test_toolkit_cli.py` (slice 2)
- **AC-5** -- THE SYSTEM SHALL contain no file under `messagefoundry/` that names the identifier
  `messagefoundry_toolkit`, in an import, a string or anywhere else.
  Verified by: `tests/test_dependency_boundaries.py` (a new arm with planted positive controls, slice 2)
- **AC-6** -- IF an engine wheel or sdist carries a member under `messagefoundry_toolkit/` or at a
  retired engine path, or a toolkit wheel carries a member under `messagefoundry/`, THEN THE SYSTEM
  SHALL refuse to publish it.
  Verified by: `tests/test_release_member_gate.py` (planted wheel and sdist archives, slice 2), and
  the `packaging-build` positive control
- **AC-7** -- THE SYSTEM SHALL keep the toolkit's dependency on the engine at exactly the engine's own
  version, and SHALL keep the harness's dependency on the toolkit the same way.
  Verified by: `tests/test_packaging.py` (slices 2 and 7)
- **AC-8** -- WHILE `messagefoundry-toolkit` is in `_UNPUBLISHED_DISTRIBUTIONS`, THE SYSTEM SHALL
  refuse any shipped text that tells a user to install it by bare name.
  Verified by: `tests/test_install_instruction_provenance.py` (slice 2)
- **AC-9** -- WHILE tests run in a dev or CI environment, THE SYSTEM SHALL import
  `messagefoundry_toolkit` from the repository checkout, not from an installed copy.
  Verified by: `tests/test_toolkit_cli.py` (slice 2)

## Options considered

1. **A sibling distribution with its own import package and its own command, released in lockstep,
   with the engine loading none of it.** **CHOSEN.** It removes the code from the engine wheel
   (clause a) and the commands from the engine CLI (clause b). It adds no loading code to the
   production CLI, and it keeps the one tier table as the record.
2. **The same distribution, with the engine loading toolkit subcommands through an entry-point group,
   so the command stays `messagefoundry <command>`.** This ADR's first draft chose it. Rejected after
   adversarial review, for the five defects in section 3. Each can be fixed, but the fixes together
   build a plugin surface into the production CLI.
3. **Toolkit files shipped into the `messagefoundry/` package directory by a second distribution (a
   split package).** Every import path would be kept. Rejected, for four reasons:
   - two distributions would own files in one regular package, which has an `__init__.py` with public
     API and cannot become a namespace package;
   - the checkout would still hold the files under `messagefoundry/`, so the engine wheel would need
     an exclude list, with the checkout-versus-wheel split that section 4 rejects;
   - engine tests would import the modules freely and hide an engine-only regression;
   - `forbidden_members.py` could no longer tell the two distributions apart by path.
4. **The engine loads the toolkit by import, `try: import messagefoundry_toolkit`.** Rejected. It is
   an engine-to-toolkit edge, and it accepts any module of that name on `sys.path`, with no check of
   which distribution provided it.
5. **An engine wheel `exclude` list derived from `CLI_TIERS`, with the modules left in place.**
   Rejected in section 4: the keys are not paths, the checkout and the wheel diverge, and the sdist
   still carries the code.
6. **An independent toolkit version, like the web console's.** Rejected in section 1: no stable seam
   exists between the toolkit's handlers and the engine internals they call.
7. **A separate `release-toolkit` job gated on a repository variable, like the harness.** Rejected in
   section 1: a variable that can be unset leaves a released engine naming an unclaimed name.
8. **Claim the name now by uploading a placeholder with a token.** Rejected in section 1: it adds a
   publishing identity outside Trusted Publishing, and PEP 541 lets PyPI remove a placeholder.
9. **Hide the subparsers (`argparse.SUPPRESS`), gate them behind an environment flag, or move the
   code behind a PEP 621 extra.** Rejected by the cell itself. Each leaves the code in the wheel, so
   clause (a) still fails.

## Consequences

**Positive**

- The engine wheel stops shipping about 11,300 lines of development and test tooling (`wc -l` over
  the moved modules at `ba38f9309`). A deploying operator's install and container stop exposing it.
- The production CLI carries no plugin mechanism. Nothing installed beside the engine can add a
  command to it.
- `CLI_TIERS` becomes a control rather than a description. Two parsers obey it, and a built-wheel
  gate and a smoke assertion check it on the real artifacts.
- The engine can be tested and shipped with no toolkit present, and a static test holds that
  direction.

**Negative / risks**

- Authors learn a second command name, `messagefoundry-toolkit`.
- A third distribution means a third pin to bump on every version change, and more release steps.
- The owner must take a one-time PyPI action before slice 2 can merge.
- Dev and CI environments rely on the engine's editable `.pth` to reach `messagefoundry_toolkit`.
  A CI job that installs the engine without `-e` and then imports the toolkit fails at import. The
  failure is loud, but it is a trap for the next job written.
- In dev there is no `messagefoundry-toolkit` console script, only `python -m messagefoundry_toolkit`.
- Uploading the toolkit before the engine bends the release job's "nothing fails after an upload"
  rule, for the reason section 1 gives.
- The moves touch many path-pinned guards. Slices 4, 6 and 7 are wide diffs even though they are
  mechanical.

**Out of scope**

- The web console wheel's 15.2.3 reading.
- The web console's own frozen editable copy, measured above. It is a real defect for the same reason,
  but it is not this item's.
- Retiring the `dryrun` CLI driver from `pipeline/dryrun.py`, which R4 keeps in production.

## To resolve on acceptance

- [x] The owner approves the layout: import package `messagefoundry_toolkit` at the repository root,
      distribution `messagefoundry-toolkit` in `packaging/`, versioned in lockstep. Resolved
      2026-09-29 by the owner's acceptance.
- [x] The owner approves a separate `messagefoundry-toolkit` command (option 1) over the engine
      loading toolkit subcommands (option 2). Resolved 2026-09-29 by the owner's acceptance.
- [ ] The owner takes the one-time PyPI action in section 1 before slice 2 merges. Not done: an owner
      commitment given 2026-09-29 (*"I'll do it before slice 2"*), to be kept before slice 2 merges.
- [ ] The follow-up answer keeping `cert self-signed` in production is recorded in a vault rulings
      file, and slice 2 updates that row's comment in `cli_surface.py` to cite it.
- [ ] Someone reads the ASVS 5.0.0 source and settles the level: the cell and ledger row #1192 say
      2, and the brief said 3.
- [x] The owner accepts the release-order trade in section 1: the toolkit uploads before the engine.
      Resolved 2026-09-29 by the owner's acceptance.
- [x] The build confirms the helper module's name (`cli_common.py` is a placeholder), and reads
      Warehouse's pending-publisher behaviour before relying on it. Resolved by slices 1 and 2. Slice
      1 kept the name `messagefoundry/cli_common.py`. Slice 2 read two sources on 2026-09-30:
      - **Warehouse.** docs.pypi.org, *Creating a PyPI project with a Trusted Publisher*: a pending
        publisher *"does not create a project or reserve a project's name until it is actually used
        to publish"*, and another user registering the name first invalidates it. Warehouse's
        `warehouse/oidc/views.py` on `main`, `mint_token`: it looks for a matching PENDING publisher
        first, and when one matches it creates the project and reifies the publisher at the token
        exchange, before any upload. So the second review's reading holds: any token exchange from
        `release.yml` whose claims match the pending publisher claims the name, which is the safe
        direction. Read through a fetch that summarised the code, not line by line; the design
        still relies only on the upload.
      - **hatchling 1.32.4**, `builders/wheel.py` from the build cache: `force_include_editable` is
        a build-data key defaulting to empty (`get_default_build_data`), which only a hook can set,
        and both editable paths, `build_editable_detection` and `build_editable_explicit` (the
        `dev-mode-dirs` one), add the force-included files. The second review's reading holds.
