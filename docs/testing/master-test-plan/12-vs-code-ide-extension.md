[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 11. VS Code IDE Extension (authoring surfaces)

**ID prefix:** `IDE` · **Surface:** IDE
· **Primary risk:** the largest authoring surface in the product (19,121 lines across 61 non-test
TypeScript modules in `ide/src`, plus 8,323 lines of tests) is governed by a CI leg that is
**not required, not in `ci-gate`, and
path-gated to `ide/**`** — so both IDE breakage and a Python-side CLI JSON rename that silently
breaks the tree, the connection form or the Test Bench merge fully green, and no existing plan
artifact owns any of it.

### 11.1 Scope & objectives

**In scope — every authoring surface in `ide/` except the two carve-outs below:**

| Cluster | Modules (all under `ide/src/`) |
|---|---|
| Activation, trust, exec gating, settings | `extension.ts` (469 lines), `cli.ts`, `engineTarget.ts`, `ide/package.json` manifest (50 commands, 12 settings, 3 views, 3 custom editors, 1 chat participant, 9-step walkthrough) |
| Credentials + engine link | `auth.ts` (224), `engineClient.ts`, `engineStatusModel.ts`, `engineLog.ts`, `statusBar.ts` (847), `engineControlModel.ts`, `engineSetup.ts`, `engineSetupContent.ts`, `liveStatus.ts` (134), `liveStatusModel.ts` |
| Graph + navigation | `graphTree.ts`, `graphModel.ts`, `symbolIndex.ts`, `wiringMap.ts`, `wiringMapModel.ts`, `configWatcher.ts`, `configRefresh.ts` |
| Connection authoring | `connectionEditor.ts`, `connectionForm.ts` (605), `connectionSchema.ts`, `connectionSchemaModel.ts`, `connectionMerge.ts`, `connectionQuickInput.ts`, `connectionWizardModel.ts`, `multiStepInput.ts`, `configEditors.ts` (388), `configEditorModel.ts` |
| Other config editors | `codesetsTree.ts`, `codeSetEditor.ts`, `alertEditor.ts`, `securityEditor.ts`, `aiPolicy.ts` |
| Wizards + scaffolding | `newRoute.ts` (327), `insertElement.ts`, `cookbook.ts`, `cookbookRecipes.ts`, `generate.ts`, `home.ts` (198) |
| Test Bench + debug | `testBench.ts` (835), `testCollections.ts`, `traceView.ts`, `hexdump.ts`, `hl7diff.ts`, `liveDebug.ts` |
| HL7 editing aids | `completion.ts`, `completionScope.ts`, `hl7schema.ts`, `hl7scope.ts`, `hl7Picker.ts`, `validate.ts`, `editorToolbar.ts`, `snippets/messagefoundry.code-snippets` |
| AI | `chat.ts` (206) — the `@messagefoundry` participant, both the `vscode.lm` BYO path and the ADR 0135 `managed_endpoint` engine-brokered path |
| Source control | `sourceControl.ts` (600), `git.ts` (76) |
| Test estate + delivery | `src/test/runTest.ts`, `src/test/suite/index.ts`, 35 `*.test.ts` files (156 suites / 560 tests / 8,323 lines), the `ide` CI legs, VSIX packaging, Marketplace/Open VSX publish, VS Code version compatibility |

**Explicitly OUT of scope — cross-reference only, do not re-plan here:**

- **The Steps editor** — `stepsView.ts` (1,142), `stepsModel.ts` (2,328), `media/stepsWebview.js`,
  the `messagefoundry.stepsEditor` custom editor (`ide/package.json` `contributes.customEditors`,
  priority `option`), the `lens parse` / `lens rewrite` CLI seam, and
  `src/test/suite/steps.test.ts` / `steps-edit.test.ts` / `steps-addmenu.test.ts`. ADRs 0076 / 0103 /
  0106. **→ the Steps editor chapter.** This chapter touches `hl7Picker.ts` only for the *pure path
  assembly* (`pickHl7Path`, `hl7Picker.ts:163`); the splice into the buffer belongs to that chapter.
- **Stage → Promote (config deploy to a running engine)** — `promote.ts` (196),
  `promoteTarget.ts` (55), the off-box https confirmation, the environment/engine-shard target
  resolution, `POST /config/reload`. **→ the publishing/promote chapter.** *Note the naming trap:*
  **extension packaging + Marketplace/Open VSX publish IS in this chapter** (IDE-42..IDE-47); the
  *promote* that is elsewhere is config deployment, not artifact publishing.
- **The engine-side halves of every CLI contract** — `messagefoundry graph|connection|codeset|alert|
  security|dryrun|ai-policy|generate|check`. Owned by the CLI subsystem in
  `docs/testing/FEATURE-COVERAGE-PLAN.md:1420` and the config subsystem at `:1379`. This chapter
  owns only the **TypeScript mirror** of those payloads and the **crossing** between them.
- **Windows host / service identity** — `docs/testing/WIN2025-TEST-PLAN.md` and siblings. They never
  mention VS Code and correctly do not; a Windows *runner* need is stated in 11.7, not a host plan.

**Objectives.** (1) Establish an owner for the extension — today there is none. (2) Close the four
zero-test modules that carry every credential and PHI path (`auth.ts`, `testBench.ts`, `newRoute.ts`,
`sourceControl.ts`, plus the `statusBar.ts` / `liveStatus.ts` shells). (3) Pin the IDE↔CLI JSON
contract so a pure-Python PR cannot silently break the authoring surface. (4) Make the packaged VSIX
— not just the dev-host checkout — the thing that is tested. (5) Make the `ide` leg a check that can
actually fail a merge.

### 11.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `.github/workflows/ci.yml:263-317` — `ide build (ubuntu-latest \| windows-latest)` | `npm ci` from `ide/package-lock.json`, `tsc --noEmit` strict type-check, esbuild bundle on both OSes; `npm run test:unit` on every leg; `npm test` (headless VS Code) on the Windows leg only |
| `ide/package.json:822` `test:unit` | 474 of 560 tests run with no Extension Host; a hand-maintained `--ignore` list excludes 8 files (86 tests) whose module-under-test transitively imports `vscode` |
| `src/test/suite/extension.test.ts` | The extension activates with no workspace; every contributed command is registered; one non-interactive command (`showAiPolicy`) executes end to end |
| `src/test/suite/settings-scope.test.ts:23-90` | ADR 0035 AC-2/AC-3 as a **family invariant**: every declared setting is classified, anything whose name matches `/url\|endpoint\|host\|python\|exec\|command\|token\|credential/i` must be `scope: "machine"`, and `capabilities.untrustedWorkspaces.supported === "limited"` |
| `src/test/suite/pythonpath.test.ts` | ADR 0035 AC-1 — `resolvePythonPath` (`cli.ts:25-46`) never prefers a workspace `.venv` when untrusted; an explicit `pythonPath` is honoured verbatim; win32 + posix layouts |
| `src/test/suite/engine-target.test.ts` | ADR 0035 AC-4 — `assertTargetAllowed` (`engineTarget.ts:29-44`) refuses plain `http://` to a non-loopback host; loopback http allowed; unparseable URL fails safe |
| `src/test/suite/ai-policy.test.ts` | ADR 0035 AC-5/AC-6 — no cache + no CLI policy ⇒ disabled `"unverified"`; a cached authoritative `off` survives going offline (`aiPolicy.ts:60-68`) |
| `src/test/suite/engine-doctor.test.ts` | ADR 0110 AC-3/AC-6/AC-8 — the `EngineLink` field allowlist and `PROBE_ENDPOINTS = ["/ai/policy","/config/provenance","/health"]` (`engineStatusModel.ts:124`) are frozen; every `POLL_PLAN` entry is `authenticated:false`; a command link planted in a 403 detail cannot reach the trusted hover |
| `src/test/suite/engine-status.test.ts` | ADR 0110 AC-1/AC-2/AC-5 — `classifyHealth` can never return `ok`; `version:null` vs version-present verdicts; an earned verdict decays; glyph/hover rendering |
| `src/test/suite/engine-client.test.ts` | ADR 0110 AC-4 — an unanswered request rejects tagged `MF_TIMEOUT`; `ECONNREFUSED` is distinct; hung vs dead render differently |
| `src/test/suite/engine-control.test.ts` | ADR 0112 AC-3/AC-6 — the serve argv is `serve --config <dir>` with no `--db`/`--env`/`--port`; the preflight classifier picks the right remedy; `runDirHasEngine` fork guard; `planActions` gating |
| `src/test/suite/engine-setup.test.ts` | Every button on the guided setup page resolves to a known `CMD` id (the webview cannot smuggle an arbitrary command id), ids are unique, `CMD.startEngine` only in the dev-tone section |
| `src/test/suite/connection-merge.test.ts` | Non-rendered `connections.toml` keys survive an edit; a cleared rendered field deletes the key; retry merges field-wise; clone direction-flip drops inapplicable keys; name-collision refusal; `planSave` is the single merge policy for both writers |
| `src/test/suite/connection-form.test.ts` | Grouping/ordering, direction filtering, "nothing on the record is ever dropped", credentials env-only, default-as-placeholder, coercion, schema-version guard, conditional-required never blocks a save |
| `src/test/suite/connection-schema.test.ts` | The `SUPPORTED_SCHEMA_VERSION = 1` guard (`connectionSchemaModel.ts:21`) refuses a newer schema; per-direction params; secret/env flags; memoisation semantics; "engine predates the verb" translation |
| `src/test/suite/connection-wizard.test.ts` | Validators, offered-transport restriction, the explicit completion gate, `buildConnObj` per transport/direction, create-collision gate, argv identical to the webview form |
| `src/test/suite/graph-model.test.ts` | ADR 0091 AC-3..AC-7 — four sections with each element exactly once, visible fan-in, cross-reference targets, dynamic markers, flow-perspective badges, v1-payload normalization |
| `src/test/suite/wiring-map-model.test.ts` | Focus BFS hop bounding (`MAX_HOPS = 3`), column assignment, provenance pass-through, synthetic `?` stubs, deterministic barycenter order, the `NODE_CAP = 150` cap (`wiringMapModel.ts:51-54`) |
| `src/test/suite/live-debug.test.ts` | `buildTraceArgs` omits `--show-phi` by default; inline values redacted unless reveal is on; a superseded run's late result is discarded; Live and reveal are separate commands (#92) |
| `src/test/suite/live-status.test.ts` | Destination rows aggregate per outbound, an unknown status word never masks a known-bad one, malformed rows degrade, the default-OFF / min-5s settings contract |
| `src/test/suite/hl7diff.test.ts` | Encoding chars read from MSH (never hardcoded), insertion does not cascade, single-field localization, repeating segments align by set-id, non-HL7 fallback |
| `src/test/suite/test-collections.test.ts` | ADR 0121 AC-1..AC-3 — MSH-7/MSH-10 volatile ignore, real regressions fail and localize, non-standard separator, delivery-set matching |
| `src/test/suite/hexdump.test.ts` | ADR 0119 AC-1..AC-3 — offsets/hex/ASCII gutter, render cap with true `totalBytes`, multi-byte + U+FFFD never throw |
| `src/test/suite/trace-view.test.ts` | `functionSpan` resolution, executed vs not-executed coverage, per-line profiling sums/ranking, truncated-trace flag, graceful degrade with no source |
| `src/test/suite/completion-scope.test.ts` + `hl7scope.test.ts` | Enclosing-handler type extraction incl. multi-line decorators, rank-never-remove, byte-identical passthrough with no artifact, `KWARG_CTX` never fires inside a string literal (ADR 0104 §2.3) |
| `src/test/suite/symbol-index.test.ts` | Top-level `def` scan + decorator classification, CRLF parity, no false positives, filter/exclude/dedup/order, vendor skip, size cap, every opened descriptor closed (#228) |
| `src/test/suite/config-refresh.test.ts` + `config-editor-model.test.ts` | The 750 ms trailing-edge coalescer, config-dir containment incl. Windows/prefix-sibling boundaries, code-set path mapping/read-only, the webview↔document loop guard |
| `src/test/suite/editor-toolbar.test.ts` + `insert-element.test.ts` | `isConfigFile` containment, `findElements`/`hasHandler`, editor/title + submenu gating, the snippets file parses with descriptions, context-aware idiom filtering |
| `src/test/suite/cookbook.test.ts` | Recipe catalog size/uniqueness/shape, no stray `$`, the leak-gate phrase check, `searchBlob` matching, every walkthrough step links a real command and an on-disk markdown file |
| `src/test/suite/chat.test.ts` | `capCode` line-boundary truncation with a visible marker, hard-cut fallback, `limit 0`, and that `package.json`'s `/command` menu and `COMMAND_TASKS` stay in sync |
| `tests/test_ide_artifacts.py` | `ide/media/hl7schema.json` and `hl7structures.json` are byte-in-sync with their Python generators — the **only** cross-language IDE contract test, and it runs on the REQUIRED pytest leg |
| `tests/test_connections_cli.py` + `tests/test_connections_file.py` | The **Python half** of the `connections.toml` GUI round-trip: comment preservation across a GUI upsert, byte-idempotent re-upsert, rollback on a failed edit, unknown-key rejection with no write, egress deny, read/write schema parity per direction |
| `tests/test_codeset_edit.py`, `tests/test_security_cli.py`, `tests/test_alerts_edit.py` | The Python half of the grid/alert/security editors: CSV quoting + spreadsheet-formula neutralisation, name-safety and traversal rejection, in-place replace, comment-preserving TOML writes |
| `tests/test_graph_static.py`, `tests/test_connection_schema.py`, `tests/test_dryrun_trace.py`, `tests/test_ai_broker.py` | The engine side of the JSON the IDE consumes: graph v2 shape + backward compat, `schemaVersion` emission (`messagefoundry/config/connection_schema.py:45,62`), the dryrun trace shape, and the ADR 0135 broker |
| `.github/workflows/security.yml:84-105` npm-audit (**BLOCKING**) | The `ide/` npm lockfile audits clean at any severity; `ide/package.json` `overrides` is where a triaged transitive advisory is pinned out |
| `.github/workflows/codeql.yml:52-70` (`javascript-typescript`, security-extended) | SAST over the `ide/` TypeScript (public repo only) |
| `.github/workflows/security.yml:150-195` SBOM (CycloneDX, advisory) | A LICENSE-complete SBOM for the `ide/` npm tree is generated and scored (non-blocking) |
| `docs/testing/FEATURE-COVERAGE-PLAN.md:575, 946, 1216, 1379, 1420, 1471, 1521` | **NEGATIVE coverage.** Every subsystem chapter explicitly excludes the VS Code IDE extension as "owner's lane / owner's parallel work", and `:575` records the IDE-lane ADRs (0035/0089/0091-D1-3/0100/0103) as correctly out of scope |
| `docs/testing/WIN2025-TEST-PLAN.md` / `-MATRIX.md` / `-ACCEPTANCE.md` / `VERIFY.md` | **NEGATIVE coverage.** The only mentions are `WIN2025-TEST-PLAN.md:107` and `:1549`, both deferring an *IDE-promote-then-reload* host scenario. Nothing tests the extension |
| `harness/` | **NEGATIVE coverage.** No file under `harness/` references VS Code; it is the PySide6 synthetic send/receive/load rig. There is no IDE rig, fixture, or acceptance-matrix entry |

**Done — do not re-plan.** The **pure model layer is genuinely well covered** and must not be
re-specified here: `connectionMerge`, `connectionForm`, `connectionSchemaModel`, `connectionWizardModel`,
`graphModel`, `wiringMapModel`, `engineStatusModel`, `engineControlModel`, `engineClient`,
`liveStatusModel`, `testCollections`, `hl7diff`, `hexdump`, `traceView`, `completionScope`, `hl7scope`,
`symbolIndex`, `configRefresh`, `configEditorModel`, `editorToolbar`, `cookbookRecipes`, `aiPolicy`'s
`pickOfflinePolicy`/`assistantState`, `capCode`, `resolvePythonPath` and `assertTargetAllowed`. The
**ADR 0035 `ADR0035:SEC-004` / `ADR0035:SEC-005` / `ADR0035:SEC-022` pure guards**, the **ADR 0110
frozen allowlists**, the **ADR 0112 serve-argv and preflight classifier**, and the **entire Python
half of every editor's write path** are
also done. The gap is not the models — it is the **shells** that call them, the **crossings** between
TypeScript and Python, and the **delivery vehicle**.

### 11.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| `ide` leg is advisory only (`ci.yml:265-274`, not in `ci-gate` `needs:` at `ci.yml:1386-1392`) | A red IDE leg merges; a pure-Python PR renaming a CLI JSON field never runs the leg at all | The whole authoring surface stops working with a fully green CI | **No** — by design today | P0 |
| `auth.ts` has zero tests | `signIn`'s pre-prompt `assertTargetAllowed` (`auth.ts:110-115`) is dropped in a refactor; credentials + bearer go in clear to a non-loopback host | Credential exfil (the exact `ADR0035:SEC-005` hole ADR 0035 closed), on a shared clinical workstation | No | P0 |
| `signOut` revoke is unpinned (`auth.ts:73-86`; ADR 0110 AC-9 links to `auth.ts` itself, not a test) | Only the local token is dropped; the engine session lives until the 30-min idle cap | "Signed out" is a lie on a walked-away-from workstation | No | P0 |
| The `@messagefoundry` prompt is assembled inline in the handler (`chat.ts:117-146`), not behind a testable function | A future `parts.push()` of a dry-run row, a Test Bench payload or a message body ships green | **PHI egress to a third-party model provider** — the extension's headline safety claim | No — `chat.test.ts` covers only `capCode` + command wiring | P0 |
| Test Bench collections persist message bodies (`testBench.ts:23` `COLLECTIONS_KEY`, `:136-142`); ADR 0121 AC-4 is explicitly *design/review-enforced* | One word changed from `workspaceState` to `globalState` pushes saved case bodies into VS Code Settings Sync | PHI off-box to the user's cloud profile | No | P0 |
| Transient PHI temp dir (`testBench.ts:233-236` `mkdtempSync("mefor-testbench-")`, `:271-279` `rmSync` in `finally`) | A cleanup regression leaves plaintext message bodies in `os.tmpdir()` | PHI at rest outside the store, unaudited | No | P0 |
| Nothing asserts `run()`/`runWithStdin()`/`runJson()` actually short-circuit (`cli.ts:147-152`, `:183-189`) or that activation execs nothing (`extension.ts:433-461`) | One dropped `isExecGated()` call ⇒ opening a cloned "starter config" repo runs a trojaned `.venv` interpreter on first open | Arbitrary code execution (CWE-426) from merely opening a folder | No — only the pure `resolvePythonPath` is pinned | P0 |
| The packaged VSIX is never built, installed or smoke-tested; every test runs from `extensionDevelopmentPath` (`runTest.ts:13`) | A `.vscodeignore` or asset regression drops `media/hl7schema.json`, `media/hl7structures.json`, `media/stepsWebview.js`, `snippets/`, `media/walkthrough/` or the copied `LICENSE` | An extension that installs and then silently has no autocomplete / no field picker / no walkthrough | No | P0 |
| The IDE↔CLI JSON contract is hand-mirrored in TypeScript; only the two HL7 media artifacts are pinned (`tests/test_ide_artifacts.py`) | A field rename in `graph --json`, `connection schema --json`, `dryrun --json`/`--trace json`, `codeset list\|show`, `alert list`, `security show` or `ai-policy --json` breaks the consumer | Tree, form, Test Bench, code-set grid, alert/security editors — with both suites green | No | P0 |
| The webview → CLI → file → tree write path is never exercised end to end | `connection upsert` is a **FULL REPLACE** (`connectionForm.ts:12-17`); a key the *webview* fails to post is a key the save DELETES, even though `planSave` is unit-tested | Silent loss of `schedule` / `shard` (the engine-shard partition tag, `connections_edit.py:86-88`) / allowlist / retry keys from a live `connections.toml` | No — `planSave` is tested only against synthetic objects | P0 |
| No plan artifact owns the IDE | Every gap above is unassigned | The largest single UI surface has no accountable owner | N/A | P0 |
| `runTest.ts:15` passes no `version` to `runTests()` while `engines.vscode` is `^1.95.0` | A runtime-only newer API breaks every user on the declared minimum | Install-quality gate for the pending Marketplace publish | No | P1 |
| `newRoute.ts` generates the Python the engine executes; `q()` (`:76`) escapes only `\` and `"` | A newline or control char in a name emits a syntactically broken `.py`; a wrong `ibSpec`/`obSpec`/router binding emits a valid-but-miswired graph | Mis-routed clinical messages from an authored artifact the user then promotes | No — zero tests | P1 |
| `git.ts` has **no** `isExecGated()` check (unlike `cli.ts:64`) and `sourceControl.ts` writes files + sets `core.hooksPath` | The version-control flow execs git and mutates a repo in an **untrusted** workspace | Repo mutation on first open of a hostile checkout | No | P1 |
| The generated pre-commit hook fails **OPEN** twice (`sourceControl.ts:42-44` no python, `:55-56` `messagefoundry` not importable) | The commit-time `check` gate silently stops running when the venv moves | A broken config is committed and promoted with no signal | No | P1 |
| `engineLog.logState`/`logAction` (`engineLog.ts:79-92`) have no test; nothing forbids a caller passing a token/username/server `detail` as `detail` | A bearer token or attacker-controlled FastAPI `detail` lands in a channel users paste into public bug reports | Credential leak into a public issue | No — only `logProbe`'s route allowlist is indirectly anchored | P1 |
| `home.ts:88-93` executes an **arbitrary** command id posted by the webview — no `CMD` allowlist, unlike `engineSetup.ts` | Any future path that gets attacker-influenced text into that webview escalates to command execution; the pattern gets copied into the next webview | Command execution from webview content | No | P1 |
| `liveStatus.ts` is a **second, unpinned** poller (`:69-102`) | A regression promoting the background poll to an authenticating call refreshes the engine idle clock on a timer | The 30-minute idle timeout becomes unreachable (CWE-613) — the defect ADR 0110 AC-3 froze for `statusBar` only | No | P1 |
| `statusBar.ts` shell untested (ADR 0112 concedes it): `controlContext` trust+loopback gate (`:446-462`), trust refusal (`:516`), no-store fork-guard modal (`:524-535`), double-launch guard (`:490-501`), terminal ownership for Stop | Creating a rogue empty engine database with a fresh bootstrap admin; or terminating an engine the IDE does not own | Destructive and operator-invisible | No | P1 |
| Activation is `onLanguage:python` + `workspaceContains:**/*.py`, and `validate.ts:29` raises an **error toast** when the CLI is unavailable | Every unrelated Python repo gets three subprocess launches and a red "MessageFoundry: validate failed" toast on open and on every save | The most visible install-quality defect; the most likely one-star review | No | P1 |
| `debugpy` is an undeclared dependency (`testBench.ts:437` launches `type: "debugpy"`; `ide/package.json` declares no `extensionDependencies`) | Without `ms-python.python`, the advertised Test Bench "Debug" button fails with a raw VS Code error | A broken advertised feature on a fresh install | No | P1 |
| The `test:unit` `--ignore` list (`package.json:822`) is hand-maintained, and the split is by **transitive** `vscode` import (e.g. `promote-target.test.ts` is excluded only because `promoteTarget.ts` imports a value from `cli.ts`) | A new test file added without an entry reds the ubuntu leg; a file that stops importing `vscode` stays Windows-only forever. On a fork (ubuntu-only matrix) the 86 excluded tests — **including every ADR 0035 test** — run nowhere | Security tests silently stop running | No | P1 |
| Custom-editor reconciliation hazard, documented but untested (`configEditors.ts:9-14`) | An external change is bypassed when the same file is open dirty in a text view; the form renders stale data and a save full-replaces from it | Loss of a concurrent hand edit or a git-pulled `connections.toml` change | No | P1 |
| **Two authors on one config repo is undefined.** The reconciliation hazard above is scoped to one person with two views; nothing covers author B's change arriving from `git pull` under author A's dirty form, or two people upserting the same `connections.toml` at once | The full-replace save (`connectionForm.ts:12-17`) writes A's stale snapshot over B's entry with no conflict, no prompt and no git conflict marker — the file was never in conflict, one writer simply lost | A colleague's routing change silently disappears from a config repo that then gets promoted; the loss is invisible in the diff of A's own commit | No — every reconciliation test is single-author | P1 |
| No resource-lifetime measurement for the extension host: no test disposes or counts the watchers, poll timers, output channels and webview panels an authoring session accumulates | A retained `FileSystemWatcher` per editor open, or a `setInterval` that survives `deactivate`, degrades the host over a workday of authoring | The IDE gets progressively slower and eventually needs a window reload — the classic "VS Code is slow" report nobody can attribute | No | P2 |
| `completion.ts` itself is untested (only `completionScope`/`hl7scope` are): `PATH_CTX`/`SEND_CTX`/`ROUTER_CTX` (`:122-124`), the 677 KB schema load at registration | A regex regression silently offers nothing, or offers connection names inside an HL7 path; a schema-load failure degrades to no completion with no signal | The most-used feature, first row of FEATURE-MAP §11 | No | P1 |
| Whole-surface behaviour when the engine is unreachable is untested (only individual models are) | A degrade becomes a modal, a hang, or a credential prompt from a background timer, across `statusBar` + `liveStatus` + chat `managed_endpoint` + `aiPolicy` at once | Unreachable is the **normal** state of an authoring checkout (ADR 0112 amendment) | No | P1 |
| `configDir` defaults to `samples/config` and `messageSetsDir` to `samples/messages` — paths that exist only in this repo | On a user's own config repo every CLI call targets a non-existent directory; the only signal is an error toast | Broken first run for every real user | No | P1 |
| Marketplace metadata is unverified: `license: "SEE LICENSE IN LICENSE"` with the file created only by `vscode:prepublish` (`package.json:820`); `ide/README.md:123` still names `messagefoundry-0.0.1.vsix` while `version` is `0.0.34` | A publish with a missing LICENSE or wrong metadata | A public artifact that cannot be cleanly un-published | No | P1 |
| No eslint/prettier and no TS coverage measurement anywhere in `ide/` | 19 k lines governed only by `tsc --noEmit`: floating promises, unused awaits, unsafe casts invisible; no way to see which of 61 modules are untested | Slow quality decay; no coverage signal | No | P2 |
| No perf/scale budget for any IDE surface | Graph tree refresh, the full config-dir `symbolIndex` scan on every save, the 677 KB schema parse at activation, the wiring map at its 150-node cap | The README advertises "handy at hundreds of connections"; a quadratic regression makes the sidebar unusable | No | P2 |
| The Windows electron leg has no retry and a documented environment sensitivity (`ide/README.md:130-132`: needs a machine with no VS Code already running) | A flaky non-required leg trains reviewers to ignore it | The 86 Extension-Host-only tests are exactly the ones at risk | No | P2 |
| No accessibility/theme/high-contrast verification for the 10 hand-written webviews | A `var(--vscode-*)` regression makes a form unreadable in light or high-contrast | Directly relevant to a Marketplace listing quality bar | No | P2 |
| Multi-root undefined — `cli.ts:143` `workspaceDir()` returns `workspaceFolders[0]` only | Every CLI call, watcher, symbol scan and Test Bench run targets the first folder | A user editing config in the second root sees an empty tree and a validate that passes against the wrong project | No | P2 |
| No `extensionKind` declared; the extension mixes `child_process`, `fs`, `os.tmpdir` and terminals with workspace concerns | Under Remote-SSH/WSL, VS Code picks a default; if UI-side, the CLI exec and `.venv` probe target the wrong machine | Confusing failures for remote users | No | P2 |
| Vocabulary defect: `cli.ts:82` "a horizontal shard / replica", `cli.ts:91-97` `shards?`, `promoteTarget.ts:2` "shard-pick" | A bare "shard" is ambiguous between an **engine shard** (ADR 0037/0063 — what these are) and a **database shard** (ADR 0039, shelved) | Operator-facing prompts inherit the ambiguity | No | P2 |
| View naming drift: `package.json` `contributes.views` calls the tree **Components**; `extension.ts`, ADR 0091 and `docs/FEATURE-MAP.md:180` call it the **Connections** view; commands read "Refresh Components" | Docs, ADR acceptance criteria and support answers point at a label the user cannot see | Every AC trace is ambiguous | No | P2 |
| `docs/FEATURE-MAP.md` §11 lists **8** rows against ~25 shipped IDE surfaces; §10 is still titled "Admin Console (PySide6)" (`:162`) and `:21` still says "PySide6 console + VS Code" | Any coverage audit driven off the map under-scopes the IDE by roughly 3× | Systematic under-planning | N/A | P1 |

### 11.4 Test matrix

**Row class (`Cls`).** **T** = *Test* — a falsifiable assertion with an observable pass criterion;
**only T rows count toward the release gate**. **C** = *Characterisation* — it produces a recorded
measurement, finding or dated owner decision but carries no threshold yet, so it **cannot fail** and
must never gate a release; a C row becomes a T row the day its threshold or decision is recorded.
**A** = *Assurance* — an external engagement (pen test, third-party review, DAST), blocking only for
an off-loopback / production-exposure release and excluded from the ordinary P0 count.

This chapter has **71 rows: 65 T, 6 C, 0 A.** The six C rows are **IDE-08** (Remote-SSH/WSL — its
criterion ends "or `extensionKind` is declared and the result is recorded"), **IDE-49** (the hook's
fail-open behaviour is pinned to a Q9 decision that does not exist yet), and the four recorded-checklist
sweeps **IDE-55, IDE-56, IDE-58, IDE-61**. There is no A row: nothing in the IDE lane is an external
engagement (the `codeql` / `npm-audit` legs over `ide/` are existing automated checks, §11.2, not an
engagement). **All 17 P0 rows are T rows**, so the exit gate in 11.8 rests entirely on falsifiable
assertions. The three newest rows — **IDE-69** (two authors on one config repo), **IDE-70**
(extension-host resource footprint) and **IDE-71** (keyboard-only New Route Wizard) — are all **T**:
each was written with a binary criterion rather than a "record the outcome" one, which is why the C
count did not grow when they were added.

**Pointer rows.** One row — **IDE-67** — is a *pointer*: Method `—`, no separate work scoped here,
because the deliverable is owned by another chapter under the plan-wide duplicate-ownership rulings.
It still classes **T** (the owner's row is falsifiable) and still counts, so the IDE exit gate cannot
quietly lose the deliverable; it simply is not built twice.

**Foreign IDs are prefixed.** A bare `IDE-nn` is a row in *this* chapter. An ID owned by another
document carries its source: `FCP:` for a `docs/testing/FEATURE-COVERAGE-PLAN.md` gap ID, `W25:` for a
`docs/testing/WIN2025-*` test ID, and `ADR0035:` (etc.) for an ADR finding id that would otherwise
read as a plan prefix — so ADR 0035's `ADR0035:SEC-004` / `ADR0035:SEC-005` / `ADR0035:SEC-022` are
never confused with the SEC chapter's own `SEC-nn` rows. An ADR acceptance criterion written directly
after its ADR number ("ADR 0110 AC-9", "ADR 0121 AC-4") is already sourced and stays as prose. This
chapter cites `FEATURE-COVERAGE-PLAN.md` and the WIN2025 documents by **line number** rather than by
gap ID, so no `FCP:`/`W25:` reference appears in it today; any future one must carry the prefix.

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| IDE-01 | Every CLI exec entry point short-circuits when the workspace is untrusted | Negative/Security | ide-mocha | container-CI | n/a | T | P0 | With a workspace open and `vscode.workspace.isTrusted === false`, each of `run`, `runWithStdin`, `runJson`, `runJsonWithStdin` resolves `{code:1, stderr:/workspace not trusted/}` **and** a spy on `child_process.execFile` records **0** spawns. A source-level invariant test enumerates every module that imports `node:child_process` (`cli.ts`, `git.ts`, `statusBar.ts`) and asserts each exported exec entry point calls `isExecGated()` first — **this test must FAIL on `git.ts` today** and be fixed, not waived |
| IDE-02 | Activation execs nothing in an untrusted workspace | Negative/Security | ide-mocha | container-CI | n/a | T | P0 | With the untrusted-workspace fixture, after `activate()` completes: 0 `execFile` spawns, 0 error notifications, the Components tree renders its "workspace not trusted" state, and no `messagefoundry` diagnostic collection entries exist |
| IDE-03 | Activation in a non-MessageFoundry Python repo produces no error toast | Negative/Security | ide-mocha | container-CI | n/a | T | P1 | In a **trusted** fixture workspace containing exactly one `foo.py` and no `samples/config`, after activation and after saving `foo.py`: `window.showErrorMessage` is never called; any CLI failure is reported only via the status bar / tree, not a modal or toast |
| IDE-04 | Activation-event breadth matches the documented decision | Compat | ide-mocha | container-CI | n/a | T | P1 | A manifest test asserts `activationEvents` equals the owner-decided set (Q10). Until Q10 is answered the test records today's `["onLanguage:python","workspaceContains:**/*.py"]` and fails on any silent change |
| IDE-05 | Trust transition mid-session re-enables the CLI without a reload | Functional | ide-mocha | container-CI | n/a | T | P1 | Starting untrusted, then granting trust: within one refresh cycle the Components tree populates from `graph --json`, `validate` runs, and no window reload was required |
| IDE-06 | Multi-root workspace behaviour is defined | Functional | ide-mocha | container-CI | n/a | T | P2 | With a two-root fixture where root B holds the config: either (a) the tree/validate/Test Bench target the folder containing `configDir`, or (b) the extension shows one explicit "multi-root is not supported — open the config folder directly" message. A silent folders[0] pick fails the test |
| IDE-07 | First run in a bare workspace guides rather than fails | Usability | ide-mocha | container-CI | n/a | T | P1 | In a fixture with no `samples/config`: no raw CLI error toast; the guided engine-setup page (`engineSetup.ts`) or the getting-started walkthrough is offered exactly once; the Components tree shows an actionable empty state naming `messagefoundry.configDir` |
| IDE-08 | Remote-SSH / WSL / dev-container behaviour | Compat | manual | dev-PC | n/a | C | P2 | Against a WSL and a Remote-SSH target: record where the CLI exec, the `.venv` probe and the Test Bench temp dir actually resolve (local vs remote), as a dated entry in `docs/testing/VERIFY.md`. **C, not T:** the criterion ends in "or `extensionKind` is declared and the result is recorded", so it cannot fail. It becomes a T row once Q5 fixes the supported configuration — then the assertion is "all three resolve on the **remote** machine" |
| IDE-09 | `signIn` refuses a non-loopback plain-http target **before** any credential prompt | Negative/Security | ide-mocha | container-CI | n/a | T | P0 | With `engineUrl = http://10.0.0.5:8765`, `signIn()` returns `undefined`, `showInputBox` is never called, no request is made to `/auth/providers` or `/auth/login`, and an error message containing "refusing to send credentials over plain http" is shown |
| IDE-10 | `signOut` revokes the engine session, and clears the local token even when the engine is unreachable | Negative/Security | ide-mocha + acceptance-probe | dev-PC | n/a | T | P0 | Against a stub engine: `signOut` issues exactly one `POST /auth/logout` carrying the cached bearer, returns `true`, and `ctx.secrets.get(key)` is `undefined` afterwards. Against a closed port: returns `false` **and** `ctx.secrets.get(key)` is still `undefined`. Against a real loopback engine, a subsequent `GET /auth/me` with the old token returns 401 (ADR 0110 AC-9) |
| IDE-11 | `withAuth` retries once on 401 and never on 403 | Negative/Security | ide-mocha | container-CI | n/a | T | P0 | A call that 401s: token cleared, `signIn` invoked once, call re-issued exactly once — 2 total attempts. A call that 403s: `signIn` not invoked, token not cleared, the `HttpError` propagates. A second consecutive 401 propagates rather than looping |
| IDE-12 | The bearer token exists only in SecretStorage | PHI | ide-mocha | container-CI | n/a | T | P0 | After a full sign-in: `ctx.globalState.keys()` and `ctx.workspaceState.keys()` contain no key whose stored value matches the token; the token string appears in no `settings.json`, no output channel line, and no file under the extension's `globalStorageUri`/`storageUri` |
| IDE-13 | The `liveStatus` poll is passive and degrades silently | Negative/Security | ide-mocha | container-CI | n/a | T | P1 | Over 3 poll cycles with no cached token: `showInputBox`/`showQuickPick` never called; `GET /connections` is sent with no `Authorization` header. On 401 with a token: `clearToken` called once. On 403: token retained. On a closed port: `graph.setRuntime(undefined)` and zero notifications |
| IDE-14 | The `liveStatus` poll respects the `ADR0035:SEC-005` target gate | Negative/Security | ide-mocha | container-CI | n/a | T | P1 | With `engineUrl = http://example.internal:8765`, no HTTP request is issued at all and `setRuntime(undefined)` is applied (`liveStatus.ts:80`) |
| IDE-15 | The engine log never emits a credential or server-supplied text | Negative/Security | ide-mocha | container-CI | n/a | T | P1 | Feeding a synthetic bearer `MEFOR-TEST-TOKEN-<uuid>`, a username, a JSON body and a server `detail` string through `logProbe`, `logState` and `logAction`: none of those literals appears in any captured `LogOutputChannel` line. A probe of a route outside `PROBE_ENDPOINTS` produces the refusal line and no URL log |
| IDE-16 | Status-bar lifecycle guards hold | HA/Resilience | ide-mocha | container-CI | n/a | T | P1 | (a) untrusted ⇒ `controlContext().canControl === false` and Start shows the trust refusal, spawning no terminal; (b) non-loopback target ⇒ Start refuses; (c) no service TOML and no `*.db` in the run dir ⇒ the modal fires and cancelling spawns nothing; (d) two `startEngine()` calls awaited concurrently create exactly **one** terminal; (e) Stop with no IDE-owned terminal is a no-op and never kills by port (ADR 0112 AC-1/AC-2/AC-4) |
| IDE-17 | The `@messagefoundry` chat payload contains only PRIMER + graph names + capped editor code | PHI | ide-mocha | container-CI | n/a | T | P0 | Extract `buildChatContext()` from `chat.ts:117-146`. With a synthetic HL7 needle `PID\|1\|\|MRN-NEEDLE-9137` present in a loaded Test Bench row, in a dry-run result, in the store and in a non-active editor, the assembled string contains **zero** occurrences of `MRN-NEEDLE-9137` and its segment count equals PRIMER + optional graph summary + optional capped active-editor code + optional task + user prompt — nothing else |
| IDE-18 | The engine-brokered (`managed_endpoint`) path attaches the same code_only context | PHI | ide-mocha | container-CI | n/a | T | P0 | With `policy.mode === "managed_endpoint"`, the captured `POST /ai/chat` body has exactly the keys `{prompt, data_scope}`, `data_scope === "code_only"`, and `prompt` is byte-identical to the BYO path's `parts.join("\n\n")`. The needle from IDE-17 is absent |
| IDE-19 | Test Bench collections never reach `globalState` | PHI | ide-mocha | container-CI | n/a | T | P0 | After saving two collections: `ctx.workspaceState.get("messagefoundry.testBench.collections")` holds both; `ctx.globalState.keys()` contains no key holding a case body and no key matching `/testBench/`. A source guard asserts `testBench.ts` contains no `globalState` reference (ADR 0121 AC-4, promoted from design-enforced to pinned) |
| IDE-20 | The collection-rerun temp directory is created and removed | PHI | ide-mocha | container-CI | n/a | T | P0 | Running a saved collection: exactly one `mefor-testbench-*` dir appears under `os.tmpdir()` during the run and **zero** remain after it, on both the success path and a forced-CLI-failure path. No case body is written anywhere outside that dir |
| IDE-21 | Live-debug inline values stay redacted unless reveal is on | PHI | ide-mocha | container-CI | n/a | T | P1 | Extension-Host end: with Live on and reveal off, every inline decoration renders `▸ ⋯` and the spawned argv contains no `--show-phi`; toggling reveal on re-runs with `--show-phi` and renders real values; toggling Live off clears all decorations |
| IDE-22 | The Coverage/Profiling trace pass carries no `--show-phi` | PHI | ide-mocha | container-CI | n/a | T | P1 | The argv captured from `ensureTraces()` (`testBench.ts:346-352`) is exactly `["dryrun","--config",<dir>,"--messages",…,"--trace","json"]` — `--show-phi` absent |
| IDE-23 | No IDE output channel or diagnostic carries a message body | PHI | ide-mocha | container-CI | n/a | T | P1 | Running the full authoring loop (validate → graph → Test Bench → collection rerun → live debug) against a corpus seeded with the IDE-17 needle: the needle appears in **no** line of the "MessageFoundry Engine" or "MessageFoundry Checks" channels and in no `vscode.Diagnostic.message` |
| IDE-24 | Connection form → CLI → `connections.toml` → tree, end to end | Functional | ide-mocha + pytest | dev-PC | n/a | T | P0 | Fixture `connections.toml` carrying hand comments plus keys the form does **not** render. Open the custom editor, change one rendered field, save. Assert: (a) the spawned argv is `["connection","upsert","--config",<dir>,"--data",<json>,"--json"]`; (b) every non-rendered key survives byte-identically; (c) every comment survives; (d) re-saving with no change is **byte-idempotent**; (e) the Components tree reflects the change within one 750 ms coalescer window |
| IDE-25 | Code-set grid → `codeset upsert` → CSV, end to end | Functional | ide-mocha | dev-PC | n/a | T | P1 | Editing one cell in the grid writes the CSV with quoting preserved, the row count unchanged, and the Translation Tables tree refreshed. A `.toml` code set opens read-only and posts no `upsert` |
| IDE-26 | Alert editor → `alert add`/`alert remove` → service TOML, end to end | Functional | ide-mocha | dev-PC | n/a | T | P1 | Adding a rule appends one `[[alerts.rules]]` block, preserves surrounding comments, and the reloaded list matches; removing by index removes exactly that rule |
| IDE-27 | Security editor → `security set` → service TOML, end to end | Functional | ide-mocha | dev-PC | n/a | T | P1 | A loosening change surfaces the ADR 0118 warning before writing; on confirm, only the changed keys are written and comments survive; on cancel, the file is byte-unchanged |
| IDE-28 | The form drops nothing against the **real** engine schema | Negative/Security | ide-mocha + pytest fixture | container-CI | n/a | T | P1 | Driving `buildForm` over the live `connection schema --json` for **every** transport × direction the installed engine declares: for each, a record carrying one unknown key, one off-direction key and one credential round-trips through `planSave` with zero key loss. A transport the form cannot classify fails the test rather than degrading |
| IDE-29 | Generated Route Wizard modules load through the wiring loader | Functional | ide-mocha + pytest | container-CI | n/a | T | P1 | Extract `buildRouteModule()` from `newRoute.ts:75-114`. A new `tests/test_ide_route_wizard.py` writes every permutation (mllp-in\|file-in × mllp-out\|file-out) into a temp config dir and asserts `messagefoundry validate --config <dir> --json` returns zero errors and `graph --json` shows the inbound bound to the router, the router naming the handler, and the handler's `Send` naming the outbound |
| IDE-30 | Route Wizard name handling is injection-safe | Negative/Security | ide-mocha | container-CI | n/a | T | P1 | `buildRouteModule()` given names containing `"`, `\`, a newline, a NUL and a `#` produces a module that Python's `ast.parse` accepts (checked by the pytest half of IDE-29) **or** the wizard refuses the name with a visible validation message. A generated module that fails `ast.parse` fails the test |
| IDE-31 | Custom-editor reconciliation with a dirty text view | Functional | ide-mocha | container-CI | n/a | T | P1 | Open `connections.toml` in both a dirty text editor and the custom editor, then change the file externally. Either the form refreshes to the on-disk content, or it visibly blocks the save with a conflict message. A silent full-replace from the stale form fails the test |
| IDE-32 | HL7 field-picker path assembly | Functional | ide-mocha | container-CI | n/a | T | P1 | `pickHl7Path` (`hl7Picker.ts:163`) returns `"PID-3.1"` for segment→field→component picks, `"PID-3"` when the component stage is skipped, and the exact free-text string for a Z-segment typed at any stage (rank-never-remove). No picked value is ever silently rewritten |
| IDE-33 | `completion.ts` contexts fire correctly in a real host | Functional | ide-mocha | container-CI | n/a | T | P1 | Driving `vscode.executeCompletionItemProvider` over a fixture `.py`: inside `msg["` → segment items with `insertText` ending `-` and a retrigger command; inside `Send("` → only outbound connection names; at `router="` → only router names; inside a plain string → no MessageFoundry items; `occurrence=`/`repetition=` kwarg snippets never appear inside a string literal |
| IDE-34 | IDE↔CLI JSON contract conformance (golden fixtures) | Cross-backend | pytest + ide-mocha | container-CI | SQLite | T | P0 | A new `tests/test_ide_contract_fixtures.py` emits golden JSON per consumed verb — `graph`, `connection list`, `connection schema`, `codeset list`, `codeset show`, `alert list`, `security show`, `ai-policy`, `dryrun --json`, `dryrun --trace json`, `validate` — into `ide/src/test/fixtures/contract/` and fails when a committed fixture drifts (the `tests/test_ide_artifacts.py` pattern). A node-side suite parses each fixture against its TS interface and asserts every declared field is present and typed. Renaming any consumed field must red **both** legs |
| IDE-35 | Schema-version guard against a genuinely newer emitter | Negative/Security | ide-mocha | container-CI | n/a | T | P1 | A fixture with `schemaVersion: 2` produces the documented refusal message and **no** form render and **no** save path; `schemaVersion: 1` renders normally (`connectionSchemaModel.ts:21,151-157`) |
| IDE-36 | Graph v2 normalization against the real emitter | Functional | ide-mocha | container-CI | n/a | T | P1 | `buildElementsView`/`buildFlowView` applied to the IDE-34 golden `graph --json` fixture yields four sections with every element exactly once and no `undefined` labels; the same holds for the committed v1 fixture |
| IDE-37 | Dry-run row + trace shape conformance | Functional | ide-mocha | container-CI | n/a | T | P1 | The `DryRunRow` fields the Test Bench reads (`source`, `inbound`, `disposition`, `message_type`, `control_id`, `summary`, `handlers`, `deliveries[].to/.payload`, `error`, `raw`, `path`) and the `TraceEntry` fields `traceView` reads are all present in the golden fixtures; a missing `path` degrades the debug button rather than throwing |
| IDE-38 | The `ide` CI leg can cross the CLI boundary | CI-leg | CI-leg | container-CI | SQLite | T | P1 | The `ide` job installs Python 3.14 + `pip install -e .` (or consumes the IDE-34 fixtures) so IDE-24..IDE-29 run in CI, not only on a dev PC. Decided by Q2; whichever path is chosen, the corresponding rows report a real result in CI |
| IDE-39 | `ide` becomes a gating check | CI-leg | CI-leg | container-CI | n/a | T | P0 | `ide` is added to `ci-gate`'s `needs:` list (`ci.yml:1386-1392`) and to branch protection. A deliberate red IDE leg on a scratch PR blocks merge; a path-skipped `ide` job reports success to the gate rather than wedging it |
| IDE-40 | The `ide` path gate covers the CLI JSON emitters | CI-leg | CI-leg | container-CI | n/a | T | P0 | The `changes.ide` filter (`ci.yml:446-451`) also matches `messagefoundry/__main__.py`, `messagefoundry/config/connection_schema.py`, `messagefoundry/config/connections_edit.py`, `messagefoundry/config/codeset_edit.py`, `messagefoundry/pipeline/dryrun.py` and `messagefoundry/hl7schema.py`/`hl7structures.py`. A PR touching only `__main__.py` runs the `ide` job |
| IDE-41 | The packaged VSIX installs and activates | Compat | CI-leg | container-CI | n/a | T | P0 | New CI step: `npm run package` produces `messagefoundry-<version>.vsix`; a headless VS Code run with `--install-extension <vsix>` then a smoke suite loaded **from the installed extension** (not `extensionDevelopmentPath`) asserts activation succeeds, all 50 contributed commands are registered, and `messagefoundry.showAiPolicy` executes |
| IDE-42 | The VSIX carries every runtime asset | Compat | CI-leg | container-CI | n/a | T | P0 | Unzipping the VSIX, the file list contains `dist/extension.js`, `media/hl7schema.json`, `media/hl7structures.json`, `media/stepsWebview.js`, every `media/*.svg` and `media/icon.png`, all 9 `media/walkthrough/*.md`, `snippets/messagefoundry.code-snippets`, `language-configuration.toml.json`, `LICENSE` and `README.md`; and contains **no** `src/**`, `out/**`, `node_modules/**` or `*.map` (asserting `.vscodeignore` still holds) |
| IDE-43 | VS Code version compatibility floor | Compat | CI-leg | container-CI | n/a | T | P1 | `runTest.ts` accepts a `version` and CI runs the Extension-Host suite over **both** `"1.95.0"` (the `engines` floor) and `"stable"`. Both legs pass, or `engines.vscode` is raised in the same PR |
| IDE-44 | Marketplace metadata is publish-ready | Compat | CI-leg | container-CI | n/a | T | P1 | A packaging assertion fails when: the VSIX `version` differs from the release tag; `ide/README.md` names a `.vsix` filename that differs from the built one (today it says `messagefoundry-0.0.1.vsix` at `:123` against version `0.0.34`); `icon`, `categories`, `repository`, `publisher` are absent; or the `description` claims a capability owned by the web console |
| IDE-45 | The `test:unit` ignore list is derived, not hand-maintained | CI-leg | ide-mocha | container-CI | n/a | T | P1 | A guard resolves each compiled test's **transitive** import graph and computes the set that reaches `vscode`; it asserts that set equals `package.json:822`'s `--ignore` entries. Adding a test file that transitively imports `vscode` without an entry fails; a file that no longer needs the entry also fails |
| IDE-46 | Every webview command dispatch resolves through a known-id table | Negative/Security | ide-mocha | container-CI | n/a | T | P1 | A cross-webview invariant enumerates every `onDidReceiveMessage` handler in `ide/src` and asserts none passes a webview-supplied string to `vscode.commands.executeCommand`. **This must FAIL on `home.ts:88-93` today** and be fixed to the `engineSetup.ts` allowlist discipline |
| IDE-47 | `sourceControl`/`git` exec is trust-gated | Negative/Security | ide-mocha | container-CI | n/a | T | P1 | In an untrusted workspace, invoking `messagefoundry.setupSourceControl` performs 0 `git` spawns, 0 file writes under the workspace, and shows a trust message |
| IDE-48 | The generated pre-commit hook actually blocks a bad config | Functional | harness | dev-PC | n/a | T | P1 | Scripted temp repo: run setup, then `git commit` with a config that fails `messagefoundry check` ⇒ commit rejected, non-zero exit, `check` output visible. Then a good config ⇒ commit succeeds. `core.hooksPath` equals `.mefor-hooks`; an existing hooksPath or an existing `.git/hooks/pre-commit` is left untouched with the documented warning |
| IDE-49 | The pre-commit hook's fail-open behaviour is a decision, not an accident | Negative/Security | harness | dev-PC | n/a | C | P1 | With `python` absent from PATH and no `.venv`, **record** the hook's observed behaviour (today: exit 0 with a stderr notice, `sourceControl.ts:42-44`, `:55-56`) and put it in front of the owner as Q9. **C, not T:** the pass criterion is "matches the owner's Q9 decision" and that decision does not exist yet, so nothing can fail. The day Q9 is answered this becomes a T row whose assertion is the decided behaviour, pinned by the harness rig |
| IDE-50 | Test Bench Debug degrades gracefully without `ms-python.python` | Usability | ide-mocha | container-CI | n/a | T | P1 | With no debug adapter for type `debugpy`, clicking Debug shows a MessageFoundry-authored message naming the required extension, and no unhandled rejection reaches the host log. With the extension present (manual leg), a breakpoint inside a `@handler` is hit |
| IDE-51 | validate-on-save populates and clears the Problems panel | Functional | ide-mocha | container-CI | n/a | T | P1 | Saving a config module with a wiring error yields ≥1 diagnostic with `source === "messagefoundry"` on the right file; fixing and saving clears the collection; a CLI failure produces no diagnostics and (per IDE-03) no error toast |
| IDE-52 | Whole-surface behaviour when the engine is unreachable | HA/Resilience | ide-mocha | container-CI | n/a | T | P1 | With `engineUrl` pointed at a closed loopback port for 60 s with `liveStatus.enabled = true`: zero modal dialogs, zero credential prompts, zero unhandled rejections, the status pill renders the documented `unreachable` copy, Components rows render undecorated, `showAiPolicy` renders the offline/`unverified` state, and no operation blocks the UI thread for >200 ms |
| IDE-53 | Schema-load failure degrades visibly, not silently | HA/Resilience | ide-mocha | container-CI | n/a | T | P1 | With `media/hl7schema.json` corrupted, activation still succeeds, HL7 path completion returns nothing, and exactly one warning is written to the extension log naming the artifact — not a silent no-op |
| IDE-54 | Webview CSP/nonce permits the inline script in a real host | Functional | ide-mocha | container-CI | n/a | T | P2 | For each of the 10 webviews (home, cookbook, engineSetup, connectionEditor, codeSetEditor, alertEditor, securityEditor, newRoute, testBench, wiringMap), the rendered HTML contains a `script-src 'nonce-…'` directive whose nonce matches the single `<script nonce=…>`, is ≥16 chars, and differs between two renders |
| IDE-55 | Theme, high-contrast and keyboard-only sweep | Usability | manual | dev-PC | n/a | C | P2 | Recorded checklist across light / dark / high-contrast dark / high-contrast light for all 10 webviews plus the quick-picks: unreadable text, hardcoded colour, unreachable controls and missing focus rings are **recorded as dated findings** in `docs/testing/VERIFY.md`, each with a BACKLOG entry. **C, not T:** the deliverable is the recorded sweep, not a threshold — there is no agreed a11y/contrast bar to fail against yet. The one falsifiable slice is carved out as IDE-71 (keyboard-only wizard completion), which is a T row |
| IDE-56 | Screen-reader / aria pass on the four data-entry surfaces | Usability | manual | dev-PC | n/a | C | P2 | Home cards, the connection form, the code-set grid and the Wiring Map SVG are driven with a screen reader and what each announces (name, role, text alternative) is written down. **C, not T:** a recorded checklist with no agreed conformance target (WCAG level / VS Code a11y bar) — it produces findings, it cannot fail. It becomes a T row the day a conformance target is named — no question in 11.9 covers that today, which is itself the finding |
| IDE-57 | Sidebar + completion latency at a several-hundred-connection estate | Performance | ide-mocha | container-CI | n/a | T | P2 | Generated fixture with 500 connections / 200 routers / 400 handlers: `buildElementsView` <150 ms, `buildWiringMap` at the 150-node cap <100 ms, `buildSymbolIndex` over the config dir <400 ms, `loadSchema` at registration <250 ms — each asserted as a hard ceiling on the CI runner, measured as the median of 5 |
| IDE-58 | `@messagefoundry` end to end with a real chat provider | Functional | manual | dev-PC | n/a | C | P2 | With a Chat provider extension signed in, exercise each of the 6 `/commands` and record the response quality and the observed outbound request. **C, not T:** "each command returns a response" has no quality bar and the safety property (no message body on the wire) is already the T assertion in IDE-17/IDE-18 — this row exists to record the UX and to catch anything the needle test cannot see. A body observed here is escalated as a P0 defect against IDE-17, not scored on this row |
| IDE-59 | Settings Sync does not carry Test Bench collections | PHI | manual | dev-PC | n/a | T | P1 | Two VS Code installs signed into the same account with Settings Sync on: a collection saved on machine A never appears on machine B. Pairs with the automated IDE-19 |
| IDE-60 | AD / Kerberos provider picker in `signIn` | Functional | manual | AD-lab | n/a | T | P2 | Against an auth-enabled engine with AD configured, `/auth/providers` reporting `ad:true` shows the two-option picker; the AD path yields a working token; `must_change_password` and `mfa_required` each deep-link to the correct `/ui` path (`auth.ts:160-181`) |
| IDE-61 | Engine lifecycle against a real loopback engine | HA/Resilience | manual | dev-PC | SQLite | C | P2 | Start / Stop / Restart from the pill against a real engine, recording what the fork-guard modal, the terminal ownership and a second externally-started engine actually do. **C, not T:** ADR 0112 concedes the shell mechanics are not node-testable, so this is a recorded human observation; the three properties it watches (fork guard, own-terminal-only Stop, double-launch guard) are asserted as T in IDE-16 against a stubbed terminal seam. A divergence here is a defect filed against IDE-16 |
| IDE-62 | Install-from-VSIX first-run on a clean machine | Compat | manual | dev-PC | n/a | T | P1 | On a machine with no repo checkout: `code --install-extension messagefoundry-<version>.vsix`, open an unrelated Python repo ⇒ no error toast (IDE-03), then open a real config repo ⇒ the guided setup path appears and the tree populates after pointing `configDir` at it |
| IDE-63 | Marketplace / Open VSX listing render | Usability | manual | dev-PC | n/a | T | P2 | Pre-publish preview shows the icon, categories, README images and publisher badge correctly on both registries. Blocked on Q4 |
| IDE-64 | eslint + prettier + TS coverage gate on `ide/` | Compat | CI-leg | container-CI | n/a | T | P2 | The `ide` job runs `eslint` (typescript-eslint, at minimum `no-floating-promises`, `await-thenable`, `no-unsafe-*`) with zero errors and emits a coverage report for `npm run test:unit`; per-module coverage is published so untested modules are visible |
| IDE-65 | Electron leg flake control | Compat | CI-leg | container-CI | n/a | T | P2 | The Windows Extension-Host leg runs with an isolated `--user-data-dir` and `--extensions-dir`, retries once on a launch failure only, and records a flake-rate metric. 20 consecutive runs show ≥95% first-attempt pass |
| IDE-66 | Vocabulary + naming lint | Negative/Security | CI-leg | container-CI | n/a | T | P2 | A grep guard over `ide/src` and `ide/package.json` fails on a bare "shard"/"sharding" not qualified as **engine shard** or **database shard** (today: `cli.ts:82`, `cli.ts:91-97`, `promoteTarget.ts:2`), and on a user-visible string using "channel"/"route" as a built element. The guard is written to run over any given path set, and **the current violator being fixed is the PERF chapter's prose, not only `ide/src`** — the same grep is the acceptance check for that fix, so the row is not closed while a bare "shard" survives in the plan text it is pointed at. The Components-vs-Connections view label is unified and pinned by a manifest assertion |
| IDE-67 | `docs/FEATURE-MAP.md` §11 back-fill + manifest↔map guard | Functional | — | any | n/a | T | P1 | **Pointer row.** Covered by the MIG chapter's consolidated FEATURE-MAP drift-guard row (the single new row extending `tests/test_feature_map_claims.py`); no separate work scoped here. The IDE-specific payload that row must carry: §11 lists a row for every shipped IDE surface (~25, up from 8); §10's title and `:21` drop the retired PySide6-console framing; every one of the 50 contributed commands maps to a FEATURE-MAP row or an explicit exemption list |
| IDE-68 | This chapter is the IDE's registered owner | External | external | any | n/a | T | P0 | `docs/testing/FEATURE-COVERAGE-PLAN.md` gains a pointer at each of its six IDE exclusions (`:946`, `:1216`, `:1379`, `:1420`, `:1471`, `:1521`) naming this chapter as the owner, so the exclusions are delegations rather than holes. Verified by grep |
| IDE-69 | Two authors on one config repo: a `git pull` under a dirty editor, and two people writing the same `connections.toml` | Functional | ide-mocha + pytest | dev-PC | n/a | T | P1 | The **two-author** fixture (§11.7 #7): a scratch git repo with a config dir, cloned twice. (a) **Pull under a dirty custom editor** — `connections.toml` is open in the custom editor with unsaved form state; author B's change lands on disk out of band (`git pull`, then a bare `git checkout` of the file). The editor must either reload to the on-disk content or refuse the save with a conflict message naming the file; a save that full-replaces from the stale form and silently drops author B's entry **fails the row**. This is IDE-31's hazard with a *second author* as the source, which is the case the single-editor fixture cannot express. (b) **Two GUI writers, different entries** — author A saves through the form while author B's `connection upsert` for a *different* entry is in flight; afterwards **both** entries are present, every hand comment survives, and the file still round-trips `connection list --json`. (c) **Two GUI writers, same entry** — last-write-wins is acceptable **only** if the losing writer is shown a visible "the file changed on disk" message before or after its save; a silent overwrite fails. (d) In all three cases the Components tree converges to the on-disk content within one 750 ms coalescer window, and no `.toml` is left syntactically invalid |
| IDE-70 | Extension-host resource footprint over a long authoring session | Performance | ide-mocha | container-CI | n/a | T | P2 | One Extension Host, scripted soak: 50 Test Bench runs (load message set → run → re-run a saved collection) interleaved with 50 open/close cycles across the connection, code-set and alert custom editors, plus 50 Components-tree refreshes. Measured after a forced GC and a 10 s settle, against the post-activation baseline: heap+RSS returns to within **+15 %** of baseline, and a linear fit over the last 20 cycles shows ≤ **0.2 MB/cycle** growth. Independently, the live counts of `context.subscriptions`, registered `FileSystemWatcher`s, `setInterval`/poll timers (`liveStatus.ts`, `statusBar.ts`), open `LogOutputChannel`s and retained webview panels each return to their post-activation values, and zero `mefor-testbench-*` dirs remain under `os.tmpdir()` (pairs with IDE-20). **A leaked watcher, timer or panel fails the row even when memory looks flat** — the count assertions, not the RSS ceiling, are the primary signal |
| IDE-71 | Keyboard-only completion of the New Route Wizard | Usability | ide-mocha | container-CI | n/a | T | P2 | The falsifiable slice carved out of IDE-55. With no pointer input at all, the New Route Wizard webview (`newRoute.ts:23` `createWebviewPanel`) is driven from the command palette to a created route using only Tab / Shift-Tab / arrow keys / Space / Enter / Esc: every input, select and button is reachable in a visible, source-order-consistent tab sequence; each focused control renders a focus ring resolved from `var(--vscode-focusBorder)`; focus is **not trapped** (Tab from the last control returns to the editor chrome, and Esc closes the panel without leaving an orphaned `panel` reference — pairs with IDE-70); and the module the wizard writes is **byte-identical** to the module produced by the same choices made with the mouse. An unreachable control, a focus trap, or a byte difference fails the row. **T, not C:** the criterion is binary (the route is created keyboard-only, or it is not) and needs no agreed conformance bar — the bar-dependent sweep stays in IDE-55/IDE-56 |

### 11.5 Detailed scenarios

#### S-1 — IDE-01 / IDE-02: untrusted-workspace exec gate (the CWE-426 guard)

**Why narrative:** the control that matters is the *code* gate, not the manifest capability, and the
fixture is easy to build wrong — VS Code caches trust decisions per folder path, so a reused fixture
silently becomes trusted and the test passes for the wrong reason.

**Preconditions.** Node 24 + `npm ci` in `ide/`. A fixture generated **fresh per run** at a unique
temp path (never a committed folder), containing:
`.venv/Scripts/python.exe` (Windows) or `.venv/bin/python` (POSIX) as a marker script that writes a
sentinel file and exits 0; `samples/config/demo.py` with one `inbound(...)`; one `foo.py`.

**Steps.**
1. `cd ide && npm ci && npm run compile && npm run compile-tests`
2. Launch the Extension Host with the fixture as the folder and a **fresh** `--user-data-dir` plus a
   fresh `--extensions-dir`, so no stored trust decision for that path can leak in and the folder
   opens in Restricted Mode. Do **not** pass `--disable-workspace-trust` — that flag turns the trust
   feature off and would make the whole scenario pass for the wrong reason.
3. In the test: assert `vscode.workspace.isTrusted === false` — if it is `true`, **fail immediately**
   rather than continuing (this is the wrong-reason guard).
4. Await activation. Install an `execFile` spy before activation by requiring the bundled extension
   through a loader shim, or assert indirectly on the marker script's sentinel file.
5. Call `messagefoundry.validate`, `messagefoundry.refreshGraph` and `messagefoundry.openTestBench`.
6. Run the source-level invariant: parse `ide/src/cli.ts`, `ide/src/git.ts` and `ide/src/statusBar.ts`,
   collect every exported function whose body reaches `execFile`, and assert each calls `isExecGated()`
   before it.

**Observation point.** The sentinel file's existence; the `execFile` spy's call count; the captured
`showErrorMessage` calls; the invariant test's failure list.

**Expected result.** Sentinel absent. Spy count 0. Zero error notifications. Each CLI helper resolved
`{code:1, stderr:/workspace not trusted/}`. **The invariant test fails on `git.ts` today** — that is
the finding, and the fix is to add the gate to `git.ts`'s `exec`, not to relax the test.

**Cleanup/rollback.** Delete the temp fixture, the `--user-data-dir` and the `--extensions-dir`. No
repo state is touched. If the marker script did run, treat the machine's `.venv` as untrusted and
delete the fixture before re-running.

---

#### S-2 — IDE-17 / IDE-18: proving the chat participant never sends a message body

**Why narrative:** it is a *negative* proof over an assembled string, and the needle must be planted
everywhere a future regression could pick it up — otherwise the test proves nothing.

**Preconditions.** `chat.ts:117-146`'s prompt assembly extracted into an exported pure
`buildChatContext({primer, graph, activeCode, limit, command, prompt})`. No live model provider is
needed; the model is stubbed.

**Steps.**
1. Generate a synthetic, PHI-free corpus:
   `python -m messagefoundry generate --type adt_a01 --count 5 --out <tmp>/messages`
   then hand-edit one message so `PID-3.1` is the literal needle `MRN-NEEDLE-9137`. (This is
   fabricated data, not PHI.)
2. Plant the needle in every reachable place: a loaded Test Bench row (`this.rows[i].raw`), a saved
   collection in `workspaceState`, a `dryrun --json --show-phi` result held in memory, and a
   **non-active** open editor. Leave the **active** editor as a plain Router module with no needle.
3. Call `buildChatContext(...)` for each of the 6 `/commands` and for a bare prompt.
4. Assert on each returned string: `indexOf("MRN-NEEDLE-9137") === -1`; the block count matches
   PRIMER + optional graph summary + optional `Active editor code:` block + optional `Task:` + the
   `User request:` line — and nothing else.
5. Repeat with `policy.mode = "managed_endpoint"` against a stub HTTP server, capturing the
   `POST /ai/chat` body. Assert `Object.keys(body)` is exactly `["prompt","data_scope"]`,
   `data_scope === "code_only"`, and the same needle assertion on `body.prompt`.
6. Repeat step 4 with the needle **in the active editor** — it must now appear exactly once, inside
   the fenced `python` block, and only up to `messagefoundry.ai.contextCharLimit`.

**Observation point.** The returned string and the captured HTTP body.

**Expected result.** Zero needle occurrences in steps 4–5; exactly one in step 6 (the user's own code
is what `code_only` means).

**Cleanup/rollback.** Delete the temp corpus. Clear the fixture workspace's `workspaceState`. The
corpus must never be committed or redirected into a CI log (`generate` output can contain full bodies).

---

#### S-3 — IDE-24: the full-replace hazard, end to end

**Why narrative:** `connection upsert` is a **full replace** of the settings table
(`connectionForm.ts:12-17`), so the destructive case is a *silent deletion* that only appears when the
webview, `planSave` and the CLI are all in the loop. The unit tests exercise only the middle one.

**Preconditions.** Python 3.14 with `pip install -e .` from the repo root; Node 24 + `npm ci` in
`ide/`. A **fresh temp** workspace (never the repo's own `samples/config`).

**Steps.**
1. Seed `<ws>/samples/config/connections.toml` with an inbound entry that carries: a leading hand
   comment, a rendered field (e.g. `port`), a key the form does **not** render (pick one absent from
   `RENDERED_FIELDS` in `connectionMerge.ts`), and a commented-out sibling entry. Take a byte hash.
2. Baseline the CLI directly:
   `python -m messagefoundry connection list --config samples/config --json` — record the parsed record.
3. In the Extension Host, open `connections.toml` (the `messagefoundry.connectionsEditor` custom
   editor has `priority: "default"`, so it opens in the form).
4. Change **one** rendered field and save. Capture the spawned argv.
5. Re-read the file: hash it, and re-run `connection list --json`.
6. Save again with **no** change and hash a third time.
7. Trigger a save of a `.py` in the config dir and wait 1 s (past the 750 ms coalescer), then read the
   Components tree labels.

**Observation point.** The captured argv; the three file hashes; the two `connection list` outputs;
the tree labels.

**Expected result.** argv is
`["connection","upsert","--config","samples/config","--data",<json>,"--json"]`. After step 5 the
non-rendered key is still present with its original value, every comment (including the commented-out
sibling) survives, and only the edited field changed. Hash(step 5) ≠ hash(step 1); hash(step 6) ==
hash(step 5) — **byte-idempotent**. The tree shows the new value.

**Cleanup/rollback.** Delete the temp workspace. The Python half of this behaviour is already proven
by `tests/test_connections_cli.py` — this scenario adds only the **webview→CLI** crossing, so a failure
here is a TypeScript defect, not a CLI one.

---

#### S-4 — IDE-41 / IDE-42: build, install and smoke the packaged VSIX

**Why narrative:** this is a new CI leg with a real ordering trap — `vsce package` runs
`vscode:prepublish`, which is what copies `LICENSE` into `ide/` (`package.json:820`). Packaging in a
job that skipped that script produces a VSIX that installs and then fails the licence assertion, and
the failure looks like a packaging bug rather than a script-ordering one.

**Preconditions.** The `ide` job, after `npm ci`. No VS Code already running on the runner
(`ide/README.md:130-132`).

**Steps.**
1. `cd ide && npm run package` — expect `messagefoundry-0.0.34.vsix` (version from `package.json:5`).
2. Assert `ide/LICENSE` now exists (created by `vscode:prepublish`) and is byte-identical to the repo
   root `LICENSE`.
3. Unzip the VSIX to a temp dir and assert the presence list and the absence list from IDE-42.
4. Install into an isolated host:
   `code --user-data-dir <tmp>/ud --extensions-dir <tmp>/ext --install-extension messagefoundry-0.0.34.vsix`
5. Run the Extension-Host smoke suite against that host with **no** `extensionDevelopmentPath` — the
   extension must resolve as an *installed* extension via `vscode.extensions.getExtension("messagefoundry.messagefoundry")`.
6. Assert: `isActive` after triggering an activation event; `vscode.commands.getCommands(true)`
   contains all 50 contributed ids; `messagefoundry.showAiPolicy` executes without throwing.
7. Repeat steps 4–6 for VS Code `1.95.0` and `stable` (IDE-43).

**Observation point.** The VSIX file list; the installed-extension activation state; the command list
diff against `package.json` `contributes.commands`.

**Expected result.** All assertions pass on both VS Code versions. A missing `media/hl7schema.json`
must fail step 3, not surface later as "autocomplete stopped working".

**Cleanup/rollback.** Delete the temp user-data/extensions dirs, the unzipped tree and the `.vsix`.
`ide/LICENSE` is generated — confirm it is git-ignored or add it to `ide/.gitignore` in the same PR so
the packaging step never dirties the tree.

---

#### S-5 — IDE-19 / IDE-20: Test Bench collections — the PHI-at-rest posture

**Why narrative:** ADR 0121 AC-4 is explicitly *design/review-enforced*, and the failure mode
(`workspaceState` → `globalState`) is a one-word change that no existing test can see. The temp-dir
half is timing-dependent: the directory only exists **during** the run.

**Preconditions.** A trusted fixture workspace with a config dir and a synthetic corpus:
`python -m messagefoundry generate --type adt_a01 --count 3 --out <ws>/samples/messages`.
Record `os.tmpdir()` before the run.

**Steps.**
1. Open the Test Bench, Load Message Set over the 3 generated files.
2. Save a collection named `smoke`.
3. Assert `ctx.workspaceState.get("messagefoundry.testBench.collections")` has one entry with 3 cases
   carrying `input` bodies.
4. Assert **`ctx.globalState.keys()`** contains no key matching `/testBench/` and no stored value
   containing any case body substring.
5. Run a source guard: `ide/src/testBench.ts` contains zero occurrences of `globalState`.
6. Run the collection. **During** the run (hook the `postMessage` for `collectionRun`, or poll every
   50 ms from a parallel timer), snapshot the `os.tmpdir()` entries matching `mefor-testbench-*` —
   expect exactly 1.
7. After the run resolves, snapshot again — expect 0.
8. Force the failure path: point `pythonPath` at a binary that exits non-zero, re-run, and snapshot
   again after the error toast — expect 0 (the `finally` at `testBench.ts:271-279`).

**Observation point.** The two `ExtensionContext` state maps; the `os.tmpdir()` listing at three
points; the source grep.

**Expected result.** Bodies only in `workspaceState`; `mefor-testbench-*` present exactly during the
run and absent after both the success and failure paths.

**Cleanup/rollback.** `ctx.workspaceState.update(COLLECTIONS_KEY, undefined)`; delete the fixture
workspace and the generated corpus. If step 7 or 8 finds a residue, delete it manually — it contains
synthetic bodies, but the residue itself is the defect to report.

---

#### S-6 — IDE-10: sign-out really revokes the session

**Why narrative:** ADR 0110 AC-9 links to `auth.ts` itself rather than to a test, and the important
half is the *unreachable-engine* branch, where the local token must still be forgotten
(`auth.ts:73-86`'s `finally`). Getting this wrong makes "signed out" a lie on a shared workstation.

**Preconditions.** A real loopback engine with auth enabled and a bootstrap admin:
`python -m messagefoundry serve --config samples/config --db ./messagefoundry.db --env dev`.
Credentials come from the environment (`MEFOR_*`), never from a file in the repo.

**Steps.**
1. From the status pill, Sign in. Confirm a token exists: `peekToken(ctx, url)` is defined.
2. Capture the token value in the test only (never log it).
3. Independently verify the session is live: `GET <url>/auth/me` with that bearer returns 200.
4. Invoke sign-out. Assert exactly one `POST /auth/logout` was issued with that bearer, and the call
   returned `true`.
5. Re-issue `GET /auth/me` with the captured token — expect **401**.
6. Assert `peekToken(ctx, url)` is `undefined`.
7. Sign in again, then **stop the engine**, then sign out. Assert the call returns `false` **and**
   `peekToken(ctx, url)` is `undefined`, and that the user-visible message distinguishes
   "could not reach the engine to revoke" from a clean sign-out.

**Observation point.** The engine's audit log entry for the logout; the 401 on step 5; the
SecretStorage read on steps 6 and 7.

**Expected result.** Steps 5–7 all hold. A `true` return with a still-live session, or a `false`
return that leaves the token cached, are both failures.

**Cleanup/rollback.** Stop the engine; delete `./messagefoundry.db` and its `-wal`/`-shm` siblings
(this is a scratch dev store, not the user's). Clear SecretStorage for the fixture profile.

---

#### S-7 — IDE-48 / IDE-49: the generated pre-commit hook actually gates

**Why narrative:** this mutates a git repo and sets `core.hooksPath`; run in the wrong directory it
rewires the *real* repo. It also has to prove a *rejection*, which means deliberately committing a
broken config.

**Preconditions.** `git` on PATH; Python 3.14 with `messagefoundry` importable. A scratch directory
outside the repo tree.

**Steps.**
1. `mkdir <tmp>/hooktest && cd <tmp>/hooktest && git init -b main` (do **not** run this inside the
   MessageFoundry worktree).
2. Create `samples/config/demo.py` with a valid `inbound`/`@router`/`@handler`/`outbound` graph, and
   `samples/messages/` with one generated synthetic message.
3. Open the folder in the Extension Host and run `messagefoundry.setupSourceControl`, choosing
   local-only storage.
4. Assert: `.mefor-hooks/pre-commit` exists, is executable, and templates the real config/messages
   dirs into the final `exec` line; `git config --get core.hooksPath` returns `.mefor-hooks`;
   `.gitattributes` contains `.mefor-hooks/** text eol=lf`; `.gitignore` contains the marker block.
5. Baseline: `git add -A && git commit -m "baseline"` ⇒ exit 0.
6. Break the config (e.g. bind the inbound to a router name that does not exist).
   `git add -A && git commit -m "broken"` ⇒ **non-zero exit**, no new commit
   (`git rev-parse HEAD` unchanged), and the `messagefoundry check` failure visible in the output.
7. Fix and commit ⇒ exit 0.
8. Negative-branch (IDE-49): remove Python from `PATH` for a subshell and repeat step 6. Record the
   actual behaviour and assert it matches the Q9 decision.
9. Idempotency: re-run setup with `core.hooksPath` already set to something else, and again with an
   existing `.git/hooks/pre-commit` — assert both are left untouched with the documented warning
   (`sourceControl.ts:264-288`).

**Observation point.** `git rev-parse HEAD` before/after; the commit exit code; `git config --get
core.hooksPath`; the captured warnings.

**Expected result.** Step 6 rejects; steps 5 and 7 succeed; step 9 clobbers nothing.

**Cleanup/rollback.** `rm -rf <tmp>/hooktest`. Verify the **real** repo's `core.hooksPath` is
unchanged: `git -C <repo> config --get core.hooksPath` must still be whatever it was (the ledger-gate
hook lives there — clobbering it would disable the ADR/BACKLOG number gate).

---

#### S-8 — IDE-34 / IDE-40: pinning the IDE↔CLI JSON contract

**Why narrative:** this is the structural fix for the highest-frequency silent breakage, and it spans
two languages and two CI legs. Done wrong (fixtures regenerated automatically) it proves nothing.

**Preconditions.** A deterministic config fixture under `tests/fixtures/ide_contract/config/` covering
at least two transports per direction, a code set, an alert rule and a `[security]` block.

**Steps.**
1. New `tests/test_ide_contract_fixtures.py` invokes each consumed verb against the fixture and
   compares the parsed JSON to a **committed** golden under `ide/src/test/fixtures/contract/`:
   `graph --config <f> --json`, `connection list|schema --config <f> --json`,
   `codeset list|show --config <f> --json`, `alert list --service-config <f>/messagefoundry.toml --json`,
   `security show --service-config <f>/messagefoundry.toml --json`, `ai-policy --json`,
   `validate --config <f> --json`, `dryrun --config <f> --messages <f>/messages --json` and the same
   with `--trace json`. The dryrun goldens are generated **without** `--show-phi` so no body is
   committed; the message fixtures are synthetic.
2. The test **fails** on drift and prints the regeneration command. It must not self-heal.
3. New node-side `ide/src/test/suite/contract.test.ts` loads each golden and asserts it satisfies the
   consuming TS interface: every field the consumer reads is present, of the right type, and no
   consumer field is missing. Nullable fields (`message_type`, `control_id`, `summary`, `error`,
   `path`) are asserted as nullable, not as present.
4. Widen the `ide` path gate (IDE-40) so the emitters listed in that row trigger the `ide` job.
5. Falsification: rename a field in `messagefoundry/config/connection_schema.py` on a scratch branch
   and confirm **both** the pytest leg and the `ide` leg go red.

**Observation point.** The two CI legs' results on the scratch branch.

**Expected result.** Both red. If only pytest reddens, the path gate (step 4) is wrong. If only the
`ide` leg reddens, the golden was regenerated by the test — fix step 2.

**Cleanup/rollback.** Delete the scratch branch. Goldens are committed artifacts; regenerating them is
a deliberate, reviewed commit, exactly like `requirements.lock` and `tests/test_ide_artifacts.py`.

### 11.6 Automation disposition

**New pytest modules** (run on the already-REQUIRED `test` leg, so they cross the language boundary
where it matters):

| Module | Covers | Effort |
|---|---|---|
| `tests/test_ide_contract_fixtures.py` | IDE-34 golden emission + drift gate for 11 CLI verbs | **M** |
| `tests/test_ide_route_wizard.py` | IDE-29/IDE-30 — every generated Route Wizard permutation loads through the wiring loader and `ast.parse`s | **S** |

**Extends an existing pytest module:**

| Module | Addition | Effort |
|---|---|---|
| `tests/test_ide_artifacts.py` | Generalise from the two HL7 media artifacts to *every* committed IDE artifact, and cross-link to the new contract fixtures | **S** |
| `tests/test_connections_cli.py` | Add the exact argv the IDE emits (`connection upsert --config … --data … --json`) as a first-class case, so the CLI half and the IDE half share one shape | **S** |

**New node-side suites** (`ide/src/test/suite/`, `ide-mocha`):

| Suite | Covers | Runs where | Effort |
|---|---|---|---|
| `auth.test.ts` | IDE-09..IDE-12 — needs `signIn`/`signOut`/`withAuth` refactored onto an injectable `{secrets, http, prompts}` seam | Extension Host + node | **M** |
| `chat-context.test.ts` | IDE-17/IDE-18 — needs `buildChatContext()` extracted from `chat.ts:117-146` | node | **S** |
| `test-bench.test.ts` | IDE-19/IDE-20/IDE-22 — needs the collections persistence + temp-dir lifecycle extracted onto a seam | Extension Host | **M** |
| `route-wizard.test.ts` | IDE-29/IDE-30 — needs `buildRouteModule()` exported from `newRoute.ts` | node | **S** |
| `contract.test.ts` | IDE-34..IDE-37 — parses the pytest-emitted goldens against the TS interfaces | node | **M** |
| `exec-gate.test.ts` | IDE-01/IDE-02/IDE-47 — the exec-gate family invariant across `cli.ts`, `git.ts`, `statusBar.ts` | Extension Host + node | **M** |
| `webview-dispatch.test.ts` | IDE-46/IDE-54 — the cross-webview command-allowlist and CSP/nonce invariants | node | **S** |
| `engine-log-redaction.test.ts` | IDE-15 — fake `LogOutputChannel`, needle sweep | node | **S** |
| `live-status-shell.test.ts` | IDE-13/IDE-14 — stub engine, poll-step seam | Extension Host | **S** |
| `status-bar-shell.test.ts` | IDE-16 — stubbed terminal/exec seam | Extension Host | **M** |
| `activation.test.ts` | IDE-03/IDE-05/IDE-06/IDE-07/IDE-52/IDE-53 — the fixture-workspace family | Extension Host | **L** |
| `editors-e2e.test.ts` | IDE-24..IDE-28/IDE-31 — the four form→CLI→file round-trips (needs Python on the leg, or the stubbed-CLI variant per Q2) | Extension Host | **L** |
| `completion.test.ts` | IDE-32/IDE-33/IDE-51 | Extension Host | **M** |
| `unit-split-guard.test.ts` | IDE-45 — transitive-import derivation of the `test:unit` ignore list | node | **S** |
| `perf.test.ts` | IDE-57 — N=500 generated graph fixture with asserted ceilings | node | **M** |
| `concurrency.test.ts` | IDE-69 — two-author reconciliation: an out-of-band `git pull` under a dirty custom editor, and two writers against one `connections.toml`. Shares the `editors-e2e` seam and the scripted git rig below | Extension Host | **M** |
| `host-soak.test.ts` | IDE-70 — the resource census (subscriptions / watchers / timers / channels / panels) plus the RSS ceiling across repeated Test Bench runs and editor open/close cycles | Extension Host | **M** |
| `keyboard-nav.test.ts` | IDE-71 — keyboard-only completion of the New Route Wizard, asserting reachability, focus ring, no focus trap, and byte-identical output | Extension Host | **S** |

**New / changed CI legs** (all in `.github/workflows/ci.yml`'s `ide` job unless noted):

| Change | Covers | Effort |
|---|---|---|
| Add `ide` to `ci-gate`'s `needs:` (`ci.yml:1386-1392`) + branch protection | IDE-39 | **S** |
| Widen `changes.ide` (`ci.yml:446-451`) to the CLI JSON emitters | IDE-40 | **S** |
| Install Python 3.14 + `pip install -e .` on the `ide` job (or wire the fixture path) | IDE-38 | **M** |
| `npm run package` + VSIX asset assertions + install-and-smoke from the installed extension | IDE-41/IDE-42 | **M** |
| `runTests({version})` matrix over `"1.95.0"` and `"stable"` | IDE-43 | **S** |
| Marketplace metadata assertions at package time | IDE-44 | **S** |
| eslint (typescript-eslint) + coverage reporter | IDE-64 | **M** |
| Isolated `--user-data-dir`/`--extensions-dir` + single launch retry + flake metric | IDE-65 | **S** |
| Vocabulary/naming grep guard | IDE-66 | **S** |

**New harness capability:** a small scripted git-repo rig for IDE-48/IDE-49/IDE-69 (create temp repo →
run setup → attempt commits → assert exit codes; for IDE-69, clone it twice and land author B's push
on author A's checkout out of band). This belongs beside the existing `harness/` rig as a
**scripted CI/manual probe**, not as a PySide6 surface — `harness/` today has no IDE rig and should not
grow a Qt one. Effort **S**.

**Stays manual, with the reason:**

| Row | Why it cannot be automated here |
|---|---|
| IDE-08 (Remote-SSH/WSL) | Needs a real remote target and a VS Code remote server; no runner provides it |
| IDE-55/IDE-56 (theme, high-contrast, a11y) | No headless browser/AX toolchain exists in this repo, and ADR 0065 deliberately kept the browser-test toolchain at zero — adding one for the IDE alone is not proportionate |
| IDE-58 (chat end to end) | Requires a Chat provider extension, a signed-in account, and observation of the provider's outbound request. IDE-17 automates the safety property; this covers the UX |
| IDE-59 (Settings Sync) | Requires two signed-in VS Code installs |
| IDE-60 (AD/Kerberos) | Requires a domain-joined machine and a real directory |
| IDE-61 (engine lifecycle) | ADR 0112 explicitly concedes the shell mechanics are not node-testable; the terminal/modal path needs a human |
| IDE-62 (clean-machine install) | The property under test is "no repo checkout present", which a CI runner with a checkout cannot express |
| IDE-63 (listing render) | Registry-side rendering, blocked on publisher accounts (Q4) |

**Refactors this chapter depends on** (small, but they gate the automation): export
`buildRouteModule()` from `newRoute.ts`; extract `buildChatContext()` from `chat.ts`; put
`auth.ts`'s secrets/http/prompt access behind an injectable seam; extract the Test Bench collections
persistence and temp-dir lifecycle; add `isExecGated()` to `git.ts`; bring `home.ts`'s dispatch under
the `engineSetup.ts` `CMD` allowlist. None changes behaviour; each converts an untestable shell into a
testable one.

### 11.7 Environment, data & prerequisites

**Runners and hosts**

- **Node 24 + npm**, installing from `ide/package-lock.json` (matches `ci.yml:290-298`).
- **A Windows runner with no VS Code already running** — the current `@vscode/test-electron`
  constraint (`ide/README.md:130-132`); on Windows a running instance steals the launch args.
  Mitigated for IDE-65 by an isolated `--user-data-dir`/`--extensions-dir`.
- **Downloadable VS Code builds** for `1.95.0` (the `engines` floor) and `stable`, with a warmed
  `.vscode-test` cache so the version matrix does not double the leg's wall time.
- **Python 3.14** with `messagefoundry` importable **on the `ide` leg** — today that job installs no
  Python at all, so nothing can cross the CLI boundary. This is the single largest environment change
  this chapter asks for (Q2 decides whether it is that, or pytest-emitted fixtures).
- **A macOS runner** only if cross-platform is in scope; today there is ubuntu build-only + windows
  electron, and no macOS leg anywhere in the repo.
- **A Remote-SSH / WSL / dev-container target** for IDE-08 only.

**Services and accounts**

- **A loopback MessageFoundry engine**, auth-enabled with a bootstrap admin, for IDE-10, IDE-52,
  IDE-61 and the status-pill/deep-probe paths:
  `python -m messagefoundry serve --config samples/config --db ./messagefoundry.db --env dev`.
  Scratch store only — never a real one.
- **A TLS-terminated non-loopback engine** for the `ADR0035:SEC-005` refusal paths (IDE-09/IDE-14). A stub HTTPS
  listener is sufficient; no PHI is involved.
- **An AD/LDAP or Kerberos realm** for IDE-60 (the `AD-lab` env).
- **A customer-managed / self-hosted LLM endpoint** plus `[ai].allowed_endpoints` for the ADR 0135
  `managed_endpoint` path — needed only for the *manual* half; IDE-18 uses a stub HTTP server.
- **A Chat provider extension** (e.g. GitHub Copilot Chat) and an account, for IDE-58.
- **`ms-python.python` + `debugpy`** for the manual half of IDE-50.
- **A git binary + the built-in `vscode.git` extension** and a scratch repo, for IDE-47..IDE-49 and
  IDE-69 (which needs two working copies over one bare origin).
- **VS Code Marketplace publisher account + Open VSX namespace + publish PATs** — recorded as an open
  item at `docs/BACKLOG.md:358` ("add a CI publish leg + publisher accounts"). **Must be procured**
  before IDE-63 and before any publish leg.

**Synthetic data — PHI-free, always**

- Test Bench / live-debug / trace corpora:
  `python -m messagefoundry generate --list` then
  `python -m messagefoundry generate --type <t> --count <n> --out <tmp>/messages`.
  The generated corpus is git-ignored by design; keep it in a temp dir, never in a committed fixture
  and never redirected into a CI log.
- The **needle** message for IDE-17/IDE-23 is a hand-edited synthetic message whose `PID-3.1` is the
  literal `MRN-NEEDLE-9137`. It is fabricated, carries no real identifiers, and exists only in temp
  dirs.
- Contract fixtures (IDE-34): a deterministic config under `tests/fixtures/ide_contract/config/` plus
  synthetic messages. Dry-run goldens are generated **without** `--show-phi`, so no body is committed.
- Perf fixture (IDE-57): a generated 500-connection / 200-router / 400-handler graph JSON — synthetic
  names only, no messages.

**Workspace fixtures to build** (each created fresh per run at a unique temp path, so no VS Code trust
decision leaks between runs)

1. **trusted-config** — a real config dir + `connections.toml` + a code set + `messagefoundry.toml`.
2. **untrusted** — the same, plus a marker `.venv` interpreter (S-1).
3. **bare** — an empty folder with one `.py` and no config dir (IDE-07).
4. **foreign-python** — an unrelated Python repo, no MessageFoundry anything (IDE-03).
5. **two-root** — a `.code-workspace` with the config in the **second** folder (IDE-06).
6. **dirty-doc** — `connections.toml` open in both a dirty text editor and the custom editor (IDE-31).
7. **two-author** — a scratch git repo holding the config dir, cloned to two working copies with a
   shared bare origin, so author B's change can land on author A's checkout out of band while A holds
   unsaved form state (IDE-69). Needs the `git` binary already listed above; no engine and no store.
8. **soak** — the trusted-config fixture plus a 3-message synthetic set, driven for 50 cycles by the
   IDE-70 script. Nothing extra on disk; the fixture exists so the soak never runs against a real
   config repo.

**Nothing in this chapter requires a store backend.** Every row is `Backend: n/a` except IDE-34/IDE-38
(SQLite, because the golden emitters and any end-to-end CLI call open a store) and IDE-61. Cross-backend
store behaviour is owned by the store subsystem in `docs/testing/FEATURE-COVERAGE-PLAN.md:946` and by
`docs/testing/WIN2025-TEST-PLAN.md` — not here.

### 11.8 Exit criteria

The IDE area is signed off for a release when **all** of the following hold and are re-verified on the
release commit:

1. **All 17 P0 rows pass**: IDE-01, IDE-02, IDE-09, IDE-10, IDE-11, IDE-12, IDE-17, IDE-18, IDE-19,
   IDE-20, IDE-24, IDE-34, IDE-39, IDE-40, IDE-41, IDE-42, IDE-68. *(No P0 may be waived; a P0 that
   cannot be automated must be converted to a recorded manual run in `docs/testing/VERIFY.md` with a
   dated result, not dropped.)*
2. **`ide` is a gating check**: it appears in `ci-gate`'s `needs:` and in branch protection, and a
   deliberately-red IDE leg on a scratch PR is observed to block merge.
3. **The path gate is proven**: renaming a field in any of the six listed CLI JSON emitters on a
   scratch branch reddens **both** the pytest leg and the `ide` leg (S-8 step 5).
4. **Zero-test modules are gone**: `auth.ts`, `testBench.ts`, `newRoute.ts`, `sourceControl.ts`,
   `git.ts`, and the `statusBar.ts` / `liveStatus.ts` shells each have at least one suite that fails
   when its documented guard is removed. Verified by mutation, not by file existence.
5. **PHI boundary proven by falsification**: the IDE-17 needle test fails when a message body is
   deliberately added to the chat payload; the IDE-19 guard fails when `workspaceState` is changed to
   `globalState`; the IDE-20 guard fails when the `rmSync` is removed. All three demonstrated once.
6. **The packaged VSIX is the tested artifact**: IDE-41/IDE-42 pass on both VS Code `1.95.0` and
   `stable`, and the smoke suite runs against an *installed* extension, not `extensionDevelopmentPath`.
7. **First-run quality**: IDE-03 (no toast in an unrelated Python repo), IDE-07 (guidance in a bare
   workspace) and IDE-62 (clean-machine install) all pass. This is the publish gate — a Marketplace
   listing must not ship with the activation-toast defect.
8. **Contract fixtures committed and green**: goldens exist for all 11 consumed verbs, the pytest drift
   gate is on the required leg, and the node-side parser suite is green.
9. **Documentation reconciled**: `docs/FEATURE-MAP.md` §11 covers every shipped surface and §10's
   retired-console framing is fixed — delivered by the MIG chapter's consolidated FEATURE-MAP
   drift-guard row, which IDE-67 points at; the IDE gate is satisfied by that row being green with the
   IDE payload in it, not by a second guard built here. Each of the six `FEATURE-COVERAGE-PLAN.md` IDE
   exclusions points at this chapter (IDE-68).
10. **Manual sweep recorded**: IDE-55, IDE-56, IDE-58, IDE-59, IDE-61 and IDE-62 have dated results in
    `docs/testing/VERIFY.md` from the release candidate build — not from an earlier build. For the four
    **C** rows in that list (IDE-55, IDE-56, IDE-58, IDE-61) the gate is that the record **exists and is
    current**, never that its findings are clean: a C row has no threshold, so it cannot fail and must
    not block the release. Findings from those sweeps become BACKLOG entries, and the ones that turn out
    to be defects are filed against the T row that should have caught them (IDE-71, IDE-17/IDE-18,
    IDE-16) — that T row, not the sweep, is what can block.
11. **Every open question in 11.9 is answered**, with the answer reflected in the matrix (a deferred
    answer must be recorded as an explicit, dated deferral, not left blank).
12. **No P1 row is silently open**: each unfinished P1 has an owner and a target release recorded in
    `docs/BACKLOG.md`.

**Explicit non-criteria** (so sign-off is not blocked on the wrong things): the Steps editor's own exit
criteria, the promote/publishing chapter's, and the engine-side halves of the CLI contracts all belong
to their own chapters. Cross-backend store parity is never an IDE criterion.

### 11.9 Open questions

1. **Should `ide` become a required check and join `ci-gate`'s `needs:` (`ci.yml:1386-1392`)?**
   Today a red IDE leg merges and a pure-Python PR never runs the leg. *Blocks:* IDE-39, IDE-40, and
   the credibility of every other row in this chapter — an advisory leg cannot enforce anything.
2. **Should the `ide` CI leg install Python, or should the contract be pinned by pytest-generated
   golden fixtures consumed node-side?** The fixture route (the `tests/test_ide_artifacts.py` pattern)
   is cheaper and keeps the npm project isolated; the Python route is the only way IDE-24..IDE-28 run
   in CI rather than on a dev PC. *Blocks:* IDE-38, and the CI-vs-manual disposition of IDE-24..IDE-29.
3. **Is `^1.95.0` still the intended minimum VS Code, and should `runTests()` pin to it as well as
   `stable`?** *Blocks:* IDE-43, and the publish gate — shipping a floor you never test is a
   post-publish support cost.
4. **Is the Marketplace / Open VSX publish still gated on "planned IDE-focused improvements"
   (`docs/BACKLOG.md:358`)? What is the acceptance bar, and who owns the publisher accounts and PATs?**
   *Blocks:* IDE-44, IDE-63, and the whole packaging cluster's priority — if publish is a year out,
   IDE-41/IDE-42 still matter (asset regressions are invisible today) but IDE-63 does not.
5. **Are Remote-SSH / WSL / dev-containers / Codespaces in scope, and should `extensionKind` be
   declared?** The extension mixes `child_process`/`fs`/`os.tmpdir`/terminals with workspace concerns.
   *Blocks:* IDE-08, and whether it is a P2 manual row or a supported-configuration commitment.
6. **Are multi-root workspaces supported, or should `workspaceDir()`'s `folders[0]`-only behaviour
   (`cli.ts:143`) become an explicit refusal?** *Blocks:* IDE-06's pass criterion — the test cannot be
   written until "correct" is defined.
7. **Should ADR 0121 AC-4 be promoted from design/review-enforced to a pinned test, and should saved
   collections be encrypted at rest given they are a declared PHI-at-rest surface?** *Blocks:* IDE-19's
   scope (guard only, or guard + encryption), and whether a new ADR amendment is needed.
8. **Should `home.ts`'s webview command dispatch (`home.ts:88-93`) be brought under the
   `engineSetup.ts` `CMD`-allowlist discipline, and should that become a cross-webview invariant?**
   *Blocks:* IDE-46 — the test as written fails on today's code, which is either a bug to fix or a
   deliberate exception to document.
9. **Should the generated pre-commit hook fail CLOSED (or warn loudly on every commit) instead of
   exiting 0 when `python` or `messagefoundry` is missing (`sourceControl.ts:42-44`, `:55-56`)?**
   *Blocks:* IDE-49's pass criterion.
10. **Should activation be narrowed (e.g. `workspaceContains:**/connections.toml`) so the published
    extension stops shelling the CLI and toasting errors in unrelated Python repos — and should
    `validate.ts:29`'s failure become a status-bar signal rather than an error toast?** *Blocks:*
    IDE-03, IDE-04, IDE-62, and the publish gate. This is the most likely one-star review.
11. **Do you want an eslint/prettier gate and TS coverage measurement on `ide/` (neither exists today
    for 19 k lines)?** *Blocks:* IDE-64, and the ability to see which of the 61 modules are untested
    without hand-auditing.
12. **Who back-fills `docs/FEATURE-MAP.md` §11 (8 rows against ~25 shipped surfaces) and §10's retired
    "Admin Console (PySide6)" title (`:162`, `:21`), and should a manifest-lint guard require every one
    of the 50 contributed commands to have a FEATURE-MAP row?** *Blocks:* the IDE payload of the MIG
    FEATURE-MAP drift-guard row that IDE-67 points at, and the accuracy of any future coverage audit
    driven off the map.
13. **Vocabulary: confirm the `shards`/`shardsOf` surface in `cli.ts:82-126` and `promoteTarget.ts`
    means an ENGINE shard (ADR 0037/0063) — should the code, the settings schema and the operator-facing
    promote prompts be renamed to say so?** *Blocks:* IDE-66, and it touches a user-visible setting
    (`messagefoundry.environments[].shards`), so it is a compatibility decision, not just a rename.
14. **View naming: is the sidebar tree called "Components" (the shipped `package.json` label) or
    "Connections" (ADR 0091, `extension.ts` comments, `docs/FEATURE-MAP.md:180`)?** *Blocks:* IDE-66's
    manifest assertion and every ADR 0091 acceptance-criterion trace.
