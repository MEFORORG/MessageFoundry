# MessageFoundry — VS Code extension

<img src="media/icon.png" alt="MessageFoundry" width="96" />

Author and test [MessageFoundry](../README.md) HL7 v2 interfaces from VS Code. (Monitoring and engine
control live in the separate MessageFoundry Console, not the IDE.)

The extension is a **thin TypeScript UI**; the heavy lifting stays in Python. It shells out to the
`messagefoundry` CLI's JSON subcommands (`validate`, `graph`, `dryrun`, `hl7schema`).

## MVP features (Phase 2)

- **Home** — an action launchpad at the top of the MessageFoundry sidebar. **New Route Wizard** steps
  you through a whole interface (Inbound → Router → Handler → Outbound, wired and generated as one
  module); **New Connection** opens a form (pick a type → fill key fields → it generates a config
  module, auto-named `[TYPE]_[PARTNER]_[MESSAGE]`); **Set Up Version Control & Checks** (see below);
  **Generate Samples** (pick a message type → triggers → count; writes a synthetic, conformant corpus
  into `messageSetsDir` via `messagefoundry generate` — no PHI); **New Alert** opens an editor for the
  operator alert rules (ADR 0014) in the service-settings TOML's `[[alerts.rules]]` — add/remove
  first-match-wins routing/threshold rules (pure data; takes effect on the next engine restart); plus
  New Router/Handler, Open Test Bench, Validate, and **Stage → Promote** (see below). (Engine run/stop
  and monitoring live in the Console, not here.)
- **Set Up Version Control & Checks** (Home → *Operate*, or the command palette) — a guided, **offline,
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
  (e.g. DEV/PROD; if none configured, falls back to `messagefoundry.engineUrl`); (3) **pre-flights** —
  a dry-run `POST /config/reload {dry_run:true}` that validates the graph **against that target's
  environment**, resolving its `env()` values, so a value the target doesn't define (or a bad spec)
  fails *before* anything goes live; (4) asks you to **confirm**; (5) **promotes** — a real
  `POST /config/reload` that **atomically swaps** the live graph (quiesce-and-swap — in-flight
  deliveries keep draining; a bad/empty config is rejected and the running graph is left untouched).
  The same config promotes to every environment — only each engine's own values differ. The engine
  **requires authentication**, so the IDE signs you in on first use (credentials → a token cached in
  VS Code SecretStorage; an expired token re-prompts). Start the engine via the Console or
  `messagefoundry serve`.
- **Live HL7-aware autocomplete** (no language server): field paths inside `msg["…"]` /
  `msg.field("…")` / `msg.set("…")` from the bundled `media/hl7schema.json`, and connection/router
  names in `Send("…")` / `router="…"` from the cached graph. General Python completion comes from
  Pylance (install the Python extension).
- **Validate on save** → Problems panel (`messagefoundry validate`).
- **Connections sidebar** — the configured connections by their convention name
  (`messagefoundry graph`); click one to jump to its definition, or use the row's **⚙ gear** to open
  its `MLLP()`/`File()` settings in code. **Inbound** rows expand to their `router → handler →
  outbound` flow (router→handler / handler→outbound edges are best-effort: names written as string
  literals); outbound rows are leaves. Title‑bar buttons **Filter** (by name — handy at hundreds of
  connections) and **Group** (None / by connection Type / by Client‑Partner, parsed from the
  `[TYPE]_[PARTNER]_[MESSAGE]` name); the active filter/grouping shows as a banner above the list.
- **Test Bench** (beaker icon on the Connections view, or *MessageFoundry: Open Test Bench*) — load
  one or more `.hl7` **files** (each may contain **many messages**, split on `MSH` boundaries),
  dry-run them through the config **without sending**, and see each message's disposition. Click
  **Before/After** for an **above/below** view (raw received on top, the would-send payload below,
  changed lines highlighted) — with a **Side by side / Top‑bottom** toggle — or **Debug** to step
  through your Router/Handler under the Python debugger (`debugpy`). The load dialog opens to
  `messagefoundry.messageSetsDir`.
- **`@messagefoundry` chat participant** — ask MessageFoundry questions in VS Code's Chat view
  (`@messagefoundry`, with `/explain`, `/transform`, `/router`, `/review`, `/migrate`, `/test`).
  **Provider-agnostic**: it uses
  whichever model you've selected in Chat (e.g. GitHub Copilot — which can run under your org's
  HIPAA BAA — or Claude). The extension never bundles a model or ships keys, and only ever sends the
  model **code + the config graph** — never message bodies / PHI. Requires a Chat provider
  (e.g. the GitHub Copilot Chat extension) to host the Chat view.
- **Scaffold snippets**: `meforinbound`, `meforoutbound`, `meforrouter`, `meforhandler` (and matching
  *MessageFoundry: New …* commands).

## Settings

- `messagefoundry.pythonPath` (default `python`) — interpreter used to run the CLI. When left at the
  default, the extension auto-detects a workspace `.venv` (`.venv/Scripts/python.exe` on Windows,
  `.venv/bin/python` elsewhere), so no setup is needed in a typical repo checkout.
- `messagefoundry.configDir` (default `samples/config`) — config modules directory.
- `messagefoundry.engineUrl` (default `http://127.0.0.1:8765`) — engine API URL used by
  *Stage → Promote* when no named environments are configured.
- `messagefoundry.environments` (default `[]`) — named promote targets `[{ "name": "DEV", "url": … },
  { "name": "PROD", "url": … }]`. When set, *Stage → Promote* asks which to target; each engine
  resolves its own environment values.
- `messagefoundry.messageSetsDir` (default `samples/messages`) — default folder for the Test Bench's
  *Load Message Set* dialog.
- `messagefoundry.sourceControl.autoPrompt` (default `true`) — offer to set up version control +
  commit-time checks when a config project has no git repo yet.

## Develop

```bash
cd ide
npm install
npm run compile        # bundle to dist/ (or: npm run watch)
npm run typecheck      # tsc --noEmit
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
