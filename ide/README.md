# MessageFoundry — VS Code extension

<img src="media/icon.png" alt="MessageFoundry" width="96" />

Author and test [MessageFoundry](../README.md) HL7 v2 interfaces from VS Code. (Operating the engine
belongs to the browser web console at `/ui`, which the IDE deep-links to — the IDE's own runtime signals
stop at a reachability pill and opt-in status/count decorations. It *can* start, stop, and restart a
**local** engine from that pill, ADR 0112.)

The extension is a **thin TypeScript UI**; the heavy lifting stays in Python. It shells out to the
`messagefoundry` CLI's JSON subcommands (`validate`, `graph`, `dryrun`, `connection`, `codeset`,
`alert`, `security`, `lens`, `generate`); `media/hl7schema.json` is generated from the CLI's
`hl7schema` ahead of time (see *Develop*).

## Features

- **Home** — an action launchpad at the top of the MessageFoundry sidebar, in four groups. **Wizards**:
  **Route Wizard** steps you through a whole interface (Inbound → Router → Handler → Outbound, wired and
  generated as one module); **Connection Wizard** opens a form (pick a type → fill key fields → it
  generates a config module, auto-named `[TYPE]_[PARTNER]_[MESSAGE]`); **Alert Wizard** opens an editor
  for the operator alert rules (ADR 0014) in the service-settings TOML's `[[alerts.rules]]` — add/remove
  first-match-wins routing/threshold rules (pure data; takes effect on the next engine restart); plus
  **Router Wizard**/**Handler Wizard**. **Test & data**: Open Test Bench, Validate Config, and
  **Generate Samples** (pick a message type → triggers → count; writes a synthetic, conformant corpus
  into `messageSetsDir` via `messagefoundry generate` — no PHI). **Operate**: **Stage → Promote**
  (see below). And a collapsed **Setup**: **Set Up Version Control & Checks** (see below),
  **Config Repo Storage Location**, and Extension Settings. (Operational monitoring stays in the web
  console; a *local* engine is run from the status pill — see below.)
- **Set Up Version Control & Checks** (Home → *Setup*, or the command palette) — a guided, **offline,
  provider-agnostic** flow that puts a code-first project under git and runs MessageFoundry checks on
  every commit. It finds your git (or guides you to install it — `winget`/`git-scm.com`, never
  auto-run), initializes a repo (or respects an existing one), scaffolds an idempotent `.gitignore`,
  installs a local `.mefor-hooks/pre-commit` hook that runs `messagefoundry check` (with a
  `.gitattributes` LF rule so the shebang survives on Windows, and `core.hooksPath` set only if it's
  unset — never clobbering your hooks), optionally adds a remote (any URL or local/UNC path — nothing
  is contacted), and optionally makes the first commit so you watch the checks pass. The hook **fails
  open** if Python isn't available and **fails closed** on a bad config; bypass once with
  `git commit --no-verify`. A one-time prompt offers this when a config project has no repo yet
  (toggle `messagefoundry.sourceControl.autoPrompt`).
- **Stage → Promote** (Home → *Operate*) — apply your local config to a **running** engine,
  environment-aware. It (1) **stages** — runs `messagefoundry validate`; any errors block the promote
  and open in the Problems panel; (2) **picks a target** — one of `messagefoundry.environments`
  (e.g. DEV/PROD, and then which engine instance when that environment lists two or more; if none is
  configured, falls back to `messagefoundry.engineUrl`); (3) **pre-flights** —
  a dry-run `POST /config/reload {dry_run:true}` that validates the graph **against that target's
  environment**, resolving its `env()` values, so a value the target doesn't define (or a bad spec)
  fails *before* anything goes live; (4) asks you to **confirm**; (5) **promotes** — a real
  `POST /config/reload` that **atomically swaps** the live graph (quiesce-and-swap — in-flight
  deliveries keep draining; a bad/empty config is rejected and the running graph is left untouched).
  The same config promotes to every environment — only each engine's own values differ. The engine
  **requires authentication**, so the IDE signs you in on first use (credentials → a token cached in
  VS Code SecretStorage; an expired token re-prompts); a plain-`http` off-box target is refused, and an
  `https` off-box target must be confirmed **by host name** before any credential is sent. Start the
  engine from the status pill (local only), `messagefoundry serve`, or its Windows service
  ([`docs/SERVICE.md`](../docs/SERVICE.md)).
- **Engine status pill + local engine lifecycle** — a status-bar item showing the current target and
  whether it is reachable; clicking it opens a menu of *Sign In* / *Sign Out*, *Re-check*, *Show the
  Engine Log*, **Open the Web Console** (`/ui`), *Copy the Engine Start Command*, and *Configure Engine
  Target*. For a **local, loopback** target in a trusted workspace it also offers **Start / Stop /
  Restart the Engine** and *Set Up Python Environment* (ADR 0112) — Start runs exactly
  `python -m messagefoundry serve --config <configDir>`, with no `--db`/`--env` overrides, so the
  service TOML stays the authority on store and environment. A workspace with no store yet gets the
  guided **Set Up an Engine** page instead.
- **Live HL7-aware autocomplete** (no language server): field paths inside `msg["…"]` /
  `msg.field("…")` / `msg.set("…")` from the bundled `media/hl7schema.json`, and connection/router
  names in `Send("…")` / `router="…"` from the cached graph. General Python completion comes from
  Pylance (install the Python extension).
- **Validate on save** → Problems panel (`messagefoundry validate`).
- **Editor build toolbar** — when a Python file under `configDir` is open, the editor title bar gets
  **View as Steps** (only when the file defines a `@handler`), **Test Bench**, **Validate**, and a
  **MessageFoundry** dropdown (the anvil) holding build actions (Validate, Test Bench, Stage → Promote),
  scaffolds (New Router / New Handler, Insert Element, Open Cookbook), and View as Steps; **CodeLens**
  actions (View as Steps / Test Bench / Validate / Insert Element) also sit above each `@router` /
  `@handler` / `inbound(…)` / `outbound(…)` declaration. These wrap the *real* Python editor
  (Pylance/debugpy intact).
- **Components sidebar** — the wired graph from `messagefoundry graph`, by convention name. The default
  perspective is **element-centric** — four sections, *Inbound Connections / Routers / Handlers /
  Outbound Connections* — and **Toggle Element / Flow View** switches to the by-flow chains, where an
  **Inbound** row expands to its `router → handler → outbound` path (router→handler / handler→outbound
  edges are best-effort: names written as string literals). Click a row to jump to its definition; a
  connection's **⚙ gear** opens its `connections.toml` form, or its source when it is code-authored
  (a row's context menu also offers **Edit** / **Clone Connection**), and a Handler row's inline action
  opens **View as Steps**. Title‑bar buttons: **Filter** (by name — handy at hundreds of connections),
  **Group** (None / by connection Type / by Client‑Partner, parsed from the `[TYPE]_[PARTNER]_[MESSAGE]`
  name), the perspective toggle, Test Bench, Refresh, and **Open Wiring Map**; the active
  filter/grouping shows as a banner above the list. With `messagefoundry.liveStatus.enabled` on, the
  inbound/outbound rows are decorated with live status + message counts polled from the engine's
  `GET /connections` (status words and counts only — never message content).
- **`connections.toml` form editor** — opening a `connections.toml` lands in a form built from **the
  engine you have installed**: pick a transport and it shows every setting that transport actually
  accepts, with type, default, and the engine's own explanation (essentials first, TLS/guards grouped
  and collapsed). A setting the engine marks secret offers only an environment-key box, so the file
  carries `{ env = "KEY" }` and never the value; a blank control omits the key so you inherit the
  engine default; settings this engine's version does not describe are preserved rather than dropped;
  and a save that would produce a bad endpoint, an unknown router, or a host your egress policy forbids
  is refused with the reason, file untouched. *Reopen With → Text Editor* gets the raw TOML.
- **Translation Tables sidebar + grid editor** — the code sets under `codesets/` (via
  `messagefoundry codeset`), each with its entry count and key/shape. A CSV code set opens in a **grid
  form** and gets New / Edit / Rename / Delete; a TOML-authored one opens **read-only** and cannot be
  renamed (the grid only writes CSV — TOML edits stay by hand).
- **Wiring Map** (*MessageFoundry: Open Wiring Map*, or **Show in Wiring Map** from a row) — a
  read-only, focus-first graph panel over the wiring graph: four labelled columns (inbound | router |
  handler | outbound), kind-accented nodes, and provenance-styled edges (solid = declared/literal,
  dashed = heuristic). Select/highlight, open the source, reveal in the tree — no drag-drop and no
  editing of any kind; the `.py` stays the only artifact.
- **View as Steps** (*MessageFoundry: View as Steps*, the editor title bar, or a Handler row) — a
  structured **Steps** view over a Handler `.py`: ordered, nested typed rows (action / lookup / control
  / send) with parameter forms, and read-only `code` rows for anything outside the bounded grammar, so a
  line is never hidden. It gets its structure from `messagefoundry lens parse` and applies edits through
  `messagefoundry lens rewrite` back into the document (undo/redo and hot-exit intact); a whole-file
  parse refusal steps aside to the plain text editor with a notice. Plain `.py` remains the only
  artifact and the only execution path.
- **Test Bench** (beaker icon on the Components view, or *MessageFoundry: Open Test Bench*) — load
  one or more `.hl7` **files** (each may contain **many messages**, split on `MSH` boundaries),
  dry-run them through the config **without sending**, and see each message's disposition. Click
  **Before/After** for an **above/below** view (raw received on top, the would-send payload below,
  changed lines highlighted) — with a **Side by side / Top‑bottom** toggle — or **Debug** to step
  through your Router/Handler under the Python debugger (`debugpy`). **Coverage / Profile** derives two
  views from one `dryrun --trace` run — which lines of each Router/Handler actually executed, and
  per-line / per-handler wall time — and **Hex** dumps the received body's bytes. The load dialog opens
  to `messagefoundry.messageSetsDir`.
- **Live Debug** (*MessageFoundry: Toggle Live Debug*, or the **MEFOR Live** status-bar item) — with it
  on, every save of a config module re-runs a dry-run against a **synthetic** sample and annotates the
  code in place: a routing/disposition summary above each `inbound()` / `@router` / `@handler`, and the
  per-line values each executed line produced. Message-derived values render **redacted by default**;
  *Reveal Values* is a separate toggle and only ever applies to synthetic samples. It never contacts a
  real engine, and the re-run is debounced (`messagefoundry.liveDebug.debounceMs`).
- **Cookbook** (*MessageFoundry: Open Cookbook*) — a searchable gallery of solved HL7 routing/transform
  problems (crosswalk a code, split a batch, enrich via a lookup, fan out to several outbounds, …); each
  entry inserts real, editable Python at the cursor. Fully offline — no model call, and it works with
  the Python CLI absent.
- **Security settings editor** (*MessageFoundry: Edit Security Settings*) — a form over the service
  TOML's `[security]` posture switches via `messagefoundry security show|set`. Every switch defaults to
  its secure position, and moving one to its insecure value shows a plain-language loosening warning in
  place; changes take effect on the next engine restart.
- **Getting-started walkthrough** — VS Code's *Get Started with MessageFoundry*: nine cards from
  pointing at an engine and opening the config dir, through Connection → Route → Insert Element → Test
  Bench → Live Debug → Cookbook, to Stage → Promote.
- **`@messagefoundry` chat participant** — ask MessageFoundry questions in VS Code's Chat view
  (`@messagefoundry`, with `/explain`, `/transform`, `/router`, `/review`, `/migrate`, `/test`).
  **Provider-agnostic**: it uses
  whichever model you've selected in Chat (e.g. GitHub Copilot — which can run under your org's
  HIPAA BAA — or Claude). The extension never bundles a model or ships keys, and only ever sends the
  model **code + the config graph** — never message bodies / PHI. Requires a Chat provider
  (e.g. the GitHub Copilot Chat extension) to host the Chat view.
- **Scaffold snippets**: `meforinbound`, `meforoutbound`, `meforrouter`, `meforhandler` (and matching
  *MessageFoundry: … Wizard* commands).
- **Insert Element** (*MessageFoundry: Insert Element*, `Ctrl+Alt+I` / `Cmd+Alt+I`, a CodeLens above each
  `@router`/`@handler`/`inbound()`/`outbound()`, and the editor-title MessageFoundry submenu) — a
  quick-pick of ~30 Handler/Router idioms, grouped by category (Field, Format, Transform, Decision,
  Date, Lookup, Send, Raw, Router, …), that drops **real, editable Python** at the cursor: field read/
  set/copy/clear, case conversion/trim/substring/pad, regex replace, numeric compute, `match`/`case`
  decisions, code-set/`db_lookup`/`fhir_lookup` lookups, repetition/segment loops, timestamp conversion/
  stamping/length-of-stay, non-HL7 `msg.json()`/`msg.text` access, `Send`/fan-out/split-and-send, and
  route-by-type/route-to-multiple. The quick-pick is **context-aware**: inside a `@router` def it hides
  idioms that need a Handler-only capability (`Send`, `db_lookup`, `fhir_lookup` all raise on a Router —
  ADR 0010/0043) and shows router-only ones (route-by-type, route-to-multiple); inside a `@handler` def
  it's the reverse; elsewhere it shows everything. Each idiom is also a tab-completion snippet
  (`meforget`, `meforcopy`, `meforcodelookup`, `mefordblookup`, `meforfhirlookup`, `mefordate`,
  `meforstamp`, `meforlos`, `meforregex`, `meforcalc`, `meformatch`, `meforsend`, `meforfanout`,
  `meforsplit`, `meforroutetype`, `meforroutemulti`, …). It's a typing accelerator, not a visual/
  declarative builder — you still read and edit the Python. **Deliberately omitted:** DB *write*
  idioms (insert/update/delete/call a stored proc) — transforms stay pure (message in → message out);
  the only sanctioned live DB access is the read-only `db_lookup` carve-out (ADR 0010).
- **Also in the command palette** — *About / Version*, *Show AI Policy*, *Open Config Folder*,
  *Settings*, *New Connection (Keyboard Wizard)*, *Refresh / Filter / Group Components*, *Toggle
  Element / Flow View*, *New Translation Table*, *Refresh Translation Tables*, *Configure Engine
  Target*, *Set Up an Engine*, *Set Up Python Environment*, and the engine actions (*Sign In* /
  *Sign Out*, *Re-check*, *Show the Engine Log*, *Open the Web Console*, *Copy the Engine Start
  Command*, *Start* / *Stop* / *Restart the Engine*). Row-scoped commands (Edit/Clone Connection,
  the Translation-Table row actions, Show in Wiring Map) are context-menu-only by design.

## Settings

- `messagefoundry.pythonPath` (default `python`) — interpreter used to run the CLI. When left at the
  default, the extension auto-detects a workspace `.venv` (`.venv/Scripts/python.exe` on Windows,
  `.venv/bin/python` elsewhere), so no setup is needed in a typical repo checkout. **Machine-scoped**, so
  a checked-in `.vscode/settings.json` cannot swap in another interpreter.
- `messagefoundry.configDir` (default `samples/config`) — config modules directory.
- `messagefoundry.serviceConfig` (default `messagefoundry.toml`) — the service-settings TOML the engine
  loads; the Alert Wizard and the security editor read/write their sections of it.
- `messagefoundry.engineUrl` (default `http://127.0.0.1:8765`) — engine API URL used by
  *Stage → Promote* when no named environments are configured. **Machine-scoped** (a workspace file
  cannot retarget a promote, and with it your credentials, at another host).
- `messagefoundry.environments` (default `[]`) — named promote targets `[{ "name": "DEV", "url": … },
  { "name": "PROD", "url": … }]`; an entry may also list `shards` (engine instances), in which case
  promote asks which instance. When set, *Stage → Promote* asks which to target; each engine
  resolves its own environment values. **Machine-scoped**, same reason as `engineUrl`.
- `messagefoundry.messageSetsDir` (default `samples/messages`) — default folder for the Test Bench's
  *Load Message Set* dialog.
- `messagefoundry.sourceControl.autoPrompt` (default `true`) — offer to set up version control +
  commit-time checks when a config project has no git repo yet.
- `messagefoundry.ai.contextCharLimit` (default `8000`) — how much of the active editor's **code** may
  ride along on a `@messagefoundry` chat request (`0` sends only the graph names). Never message bodies.
- `messagefoundry.liveDebug.debounceMs` (default `400`) — debounce before Live Debug re-runs `dryrun`
  after a save.
- `messagefoundry.liveStatus.enabled` (default `false`) / `messagefoundry.liveStatus.intervalSeconds`
  (default `10`, clamped to ≥5) — opt-in live status + count decorations on the Components view rows,
  polled from the engine's `GET /connections`.
- `messagefoundry.revealViewOnStartup` (default `false`) — reveal the MessageFoundry sidebar instead of
  the Explorer when this workspace opens (best set per-workspace).

## Develop

```bash
cd ide
npm install
npm run compile        # bundle to dist/ (or: npm run watch)
npm run typecheck      # tsc --noEmit
npm run package        # build a VSIX (messagefoundry-<version>.vsix) for `code --install-extension`
npm test               # integration tests: launch a headless VS Code (@vscode/test-electron + mocha)
```

`npm test` downloads a real VS Code build, loads the extension, and asserts it activates and that every
command it contributes is registered and runnable. It needs a machine with **no VS Code already
running** (on Windows a running instance steals the launch args), so it runs on the **Windows `ide`
leg in CI** (`.github/workflows/ci.yml`) rather than in a dev session that has VS Code open.

Then press **F5** ("Run Extension") to launch an Extension Development Host. Open a workspace that
has a `samples/config` (this repo does). The `messagefoundry` CLI must be importable by
`messagefoundry.pythonPath` (e.g. `pip install -e .` in the repo's venv).

To launch the dev host **without changing your current window's folder** (e.g. to keep another VS
Code window open), run from a terminal against the committed workspace file. **Use absolute paths** —
`code` resolves relative arguments unreliably depending on the shell and working directory:

```powershell
# PowerShell, from the repo root (derives absolute paths from the current dir):
code --extensionDevelopmentPath="$PWD\ide" "$PWD\mefor.code-workspace"

# …or spell them out in full:
code --extensionDevelopmentPath="C:\path\to\MessageFoundry\ide" "C:\path\to\MessageFoundry\mefor.code-workspace"
```

```bash
# bash/zsh, from the repo root:
code --extensionDevelopmentPath="$PWD/ide" "$PWD/mefor.code-workspace"
```

`mefor.code-workspace` (repo root) opens the repo as a *workspace* — so it can coexist with a plain
folder window on the same path — and sets Pylance to `basic` type-checking for config authoring.

> Activity-bar icon changes are cached by VS Code; if a new icon doesn't appear, fully **close and
> relaunch** the dev host (a "Reload Window" often isn't enough).

`media/hl7schema.json` is generated from the engine:

```bash
python -m messagefoundry hl7schema --json > ide/media/hl7schema.json
```
