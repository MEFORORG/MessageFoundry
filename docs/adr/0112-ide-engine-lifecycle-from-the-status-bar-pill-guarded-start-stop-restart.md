# ADR 0112 — IDE engine lifecycle from the status-bar pill: guarded start / stop / restart

- **Status:** Accepted (2026-07-15) — owner-directed this session; built (IDE extension v0.0.29). **Amended
  2026-07-16 — store-less pill leads with a guided setup page (BACKLOG #238; ratified, built (IDE extension
  v0.0.32), Plan-12 `ide-238-setup`).**
- **Deciders:** owner (explicit "the pill should do that plus start/stop engine" directive, over the ADR 0110 §5
  decline) + an adversarial self-review pass.
- **Supersedes:** [ADR 0110](0110-ide-engine-link-doctor-the-status-bar-tells-the-truth-about-the-promote-target.md)
  **§5's "Start local engine" decline** (and its v1 "Copy the engine start command" as the only offer). Everything
  else in ADR 0110 stands — the link-state model, the tokenless poll (§2), the earned/decaying green (§2), and the
  **LINK-not-WORKLOAD boundary (§4)**, which this ADR is careful to leave byte-for-byte intact.

## Context

ADR 0110 gave the `MEFOR: <host>` pill an honest diagnosis but left it unable to *act* on the most common finding —
`unreachable`, the engine simply isn't running. Its v1 offered **"Copy the engine start command"** and explicitly
declined to run it, for one concrete, verified reason (ADR 0110 §5):

> a `createTerminal` defaults its cwd to the **workspace folder**, which in a git worktree has no service TOML and no
> store: `serve` would create a **brand-new empty database and a fresh bootstrap admin**, forking the user's engine.

That decline had two costs the owner hit in daily use:

1. **The copy path does not fix the actual failure.** The clipboard hands over `python -m messagefoundry serve --config
   …`; pasted into a fresh terminal, `python` resolves to whatever is first on `PATH` — on Windows, frequently the
   Microsoft Store shim, which has none of the project's dependencies. The reported symptom was exactly this:
   `ModuleNotFoundError: No module named 'pydantic'` — the engine source was importable (cwd on `sys.path`) but its
   dependencies were not installed *for that interpreter*. The extension already knows how to resolve the right
   interpreter (`pythonPath()` auto-detects the workspace `.venv` in a trusted workspace — SEC-004); copying a bare
   `python` throws that knowledge away.
2. **There is no stop / restart at all.** Reloading config after an edit means finding the terminal by hand.

The §5 hazard is real but **solvable**, and — importantly — starting the engine is the *ultimate* LINK repair, squarely
within the doctor's stated mission (ADR 0110: "the IDE renders and **repairs the LINK**"). It is not workload rendering.

## Decision

The pill may now **run** the engine, and stop/restart the one it started. The two safety facts §5 worried about are
enforced structurally, split between the pure model (whether to *offer* an action) and the shell (the guards before it
*acts*).

### 1. Run, don't copy — with the resolved interpreter

The Start action runs the **exact command ADR 0110 blessed** — `python -m messagefoundry serve --config <configDir>`,
**no `--db`/`--env`/`--port` overrides** (the service TOML stays the sole authority on store, environment and bind
port; ADR 0110 §5 rejected a `messagefoundry.engineEnv` setting for precisely this reason) — but with `python` =
`pythonPath()`, the auto-detected workspace `.venv`, launched via `createTerminal({ shellPath, shellArgs, cwd })` so the
interpreter is exec'd directly as argv (no shell re-parse, no quoting hazard). **This alone is the fix for the reported
`ModuleNotFoundError`.** The terminal *is* the engine process; closing it stops the engine.

### 2. The fork hazard is neutralised, not reintroduced

Start is offered and runs only when `canControl` — a **loopback** target (a remote engine reads its own filesystem —
ADR 0110 review M-29), a **trusted** workspace (never exec a possibly repo-supplied `.venv` — SEC-004/CWE-426), and a
workspace to run in. And it **never silently creates a store**: when the run directory holds no service TOML and no
`*.db`, Start shows a modal confirm ("… creates a NEW database and a bootstrap admin") before launching — the §5 fork is
now a labelled, deliberate choice, not an accident of cwd. No new setting is added.

### 3. Stop / Restart act only on a process we own

Stop and Restart are offered only when the IDE holds a **live** engine terminal (`exitStatus === undefined`) it launched,
and they act on **that terminal**, never by port. With parallel git worktrees a port can be shared, so a port-kill could
down another session's engine; the IDE refuses to stop an engine it did not start and says so. Restart waits for the
process to actually close before rebinding.

### 4. Bootstrap the "fresh clone" case

When the resolved interpreter cannot import MessageFoundry (no `.venv`/uninstalled deps), Start offers **"Set up
environment"**: a modal-confirmed `python -m venv .venv` + `pip install` (`-e .` for a source checkout, the published
package for a config repo) typed into a visible terminal — the "works from a fresh clone" path.

### 5. The ADR 0110 §4 boundary is untouched

Lifecycle actions are **command ids** emitted by the pure `planActions` (its new optional `EngineControlContext`
argument defaults to no-control, so every existing call site — the whole engine-doctor suite — is unchanged). No
`EngineLink` **field** is added; **no probe endpoint** is added; **no setting** is added. The two frozen CI allowlists
(`ENGINE_LINK_FIELDS`, `PROBE_ENDPOINTS`) and the settings-scope family invariant are all intact — the IDE still repairs
the LINK and renders no WORKLOAD.

## Acceptance Criteria

- **AC-1** — Start SHALL run only for a loopback target in a trusted workspace with a workspace folder open; otherwise it
  is neither offered nor acts. → `engine-control.test.ts` (`canControl` gating), enforced again in `startEngine`.
- **AC-2** — WHEN the run directory has no service TOML and no `*.db`, Start SHALL require an explicit confirmation before
  launching (no silent new-store fork). → `runDirHasEngine` + the labelled "Start a new engine here…" action.
- **AC-3** — The launched command SHALL be `serve --config <dir>` with NO `--db`/`--env`/`--port` override. →
  `engine-control.test.ts` asserts the argv omits all three (the TOML is authority).
- **AC-4** — Stop/Restart SHALL act only on a terminal this IDE started and never terminate an engine by port. →
  offered only when `weStartedIt`; `stopEngine` refuses when it owns no live terminal.
- **AC-5** — The change SHALL add no `EngineLink` field, no probe endpoint and no setting, keeping the ADR 0110 §4
  boundary and the settings-scope invariant intact. → `engine-doctor.test.ts` + `settings-scope.test.ts` (unchanged, green).
- **AC-6** — The interpreter used SHALL be the resolved workspace `.venv` (`pythonPath()`), not a bare `PATH` `python`. →
  `buildServeInvocation` takes the resolved interpreter; a preflight import classifies a missing interpreter vs missing deps.

## Consequences

- The pill's most common state (engine down) now offers a **one-click Start that actually works** — the reported
  `ModuleNotFoundError` is fixed because the launch uses the workspace interpreter, not whatever the terminal resolves.
- The extension gains **Stop / Restart / Set up environment** commands (palette-visible), each guarded so it cannot fork
  or cross-kill an engine.
- **ADR 0110 §5 is superseded**; its "Copy the engine start command" remains as a secondary/fallback action (and the
  only offer for a remote or untrusted target, where the IDE still must not run anything).
- No new setting, no `EngineLink` field, no probe endpoint — the operator-console boundary and SEC-005 settings-scope
  invariant are untouched.
- The shell's terminal-lifecycle mechanics are Extension-Host code (not node-testable); the **decisions** (offer gating,
  invocation, preflight classification, bootstrap plan, fork-guard predicate) are pure and pinned in `engine-control.test.ts`.

## Alternatives considered

- **Keep copy-only (ADR 0110 §5 as-is)** — rejected: it does not fix the interpreter bug (the whole reported failure) and
  offers no lifecycle. The §5 hazard it avoided is neutralised here by the loopback+trust gate and the no-store confirm.
- **Pass `--port`/`--db`/`--env` to match `engineUrl`** — rejected: it violates ADR 0110's "the service TOML is the
  authority" and would let a setting override authoritative config (the same reason `messagefoundry.engineEnv` was
  declined). A port mismatch is a config fault the doctor already surfaces.
- **A `messagefoundry.serve.cwd` pin for a checkout-≠-workspace layout** — deferred: the presence guard already makes the
  default (workspace cwd) safe, and adding an execution-location setting is surface the daily-driver (single checkout)
  does not need. Revisit if a real separated-checkout demand appears.
- **Stop by killing whatever listens on the port** — rejected: with parallel worktrees sharing a port it could terminate
  another session's engine. The IDE only stops a process it owns.

## Amendment (2026-07-16) — store-less pill leads with a guided setup page, not the create-DB start (BACKLOG #238)

**Ratified 2026-07-16 (owner, Plan-12 authoring session); build scheduled as
Plan-12 session `ide-238-setup` (Wave 1); built (IDE extension
v0.0.32).** Three decisions were put to the
owner and ratified: **(a)** record this as an in-file amendment to this ADR, not a new ADR; **(b)** the setup page
**does** offer the test-only developer engine; **(c)** the new lead stays **`canControl`-only**.

### Context

Owner feedback (2026-07-15, BACKLOG #238): in a **config-only / authoring** workspace with no store (no service TOML,
no `*.db` — e.g. a conversion estate), the pill's lead action while the engine is unreachable is §2's labelled
create-DB start ("Start a new engine here… — this creates a new database and a bootstrap admin"). That is accurate but
wrong-footed: it surfaces a first-time-setup / dev-only action as the *lead* choice in a workspace never meant to host
a running engine — in production the engine runs **as a service** ([`docs/SERVICE.md`](../SERVICE.md)), so "nothing is
running here" is the normal state of an authoring checkout.

### Decision

1. **The store-less lead becomes a guided page.** In `lifecycleActions()`/`planActions()`, WHEN
   `canControl && !engineIsUp && !hasStore` the pill SHALL NOT offer the labelled create-DB start; it offers a single
   **"Set up an engine…"** action dispatching a new `CMD.openEngineSetup`, which opens an `engineSetup`
   **WebviewPanel** (room to explain, unlike a cramped QuickPick): the production-as-a-service posture, pointing the
   IDE at an existing engine (engine-target settings), the copy-start fallback, "Set up environment" (§4), and the
   dev-engine section below. The `hasStore == true` branch keeps today's plain "Start the engine" unchanged.
2. **The page offers the test-only developer engine — clearly labelled, context-honest.** A visually separated section
   dispatches the existing guarded `CMD.startEngine`; §2's modal create-DB confirm remains the guard (the §5 fork stays
   a labelled, deliberate choice). Because the command is palette-visible and the page is static/context-blind, the
   copy states the conditional truth: *if no engine store exists here, you'll be asked to confirm creating a NEW
   database and a bootstrap admin; if one exists, this starts that engine* (`runDirHasEngine` guards only the
   store-less case, so a `hasStore == true` launch shows no modal). The palette visibility of
   `messagefoundry.openEngineSetup` is deliberate and recorded here.
3. **Gate unchanged — `canControl`-only.** No lifecycle/setup action is offered when `canControl == false`;
   unreachable/foreign targets keep their current actions (copy-start and Configure engine target). A read-only
   informational page for no-control states was considered and deferred.
4. **Webview discipline (unchanged boundaries).** The panel shell mirrors `cookbook.ts` (nonce, `default-src 'none'`
   CSP, quote-escaping `esc()`, reveal-if-open); the page's buttons live in a **vscode-free content model**
   (`engineSetupContent.ts`), and the message handler executes ONLY a known `CMD` looked up in that model — mirroring
   the `statusBar.ts` dispatch discipline — never a command string taken from the webview message. **No `EngineLink`
   field, no probe endpoint, no setting** — §5 and the ADR 0110 §4 boundary stay intact; the IDE still repairs the
   LINK and renders no WORKLOAD.

### AC restatement

- **AC-2 (restated)** — WHEN the run directory has no service TOML and no `*.db`, engine creation SHALL require the
  explicit modal confirmation before launching (no silent new-store fork). Evidence: `runDirHasEngine` + the
  `startEngine` modal confirm — no longer the (removed) labelled pill action; the labelled-choice surface now lives
  behind the setup page's dev-engine button and the palette command.
- **AC-7 (new)** — WHEN `canControl && !engineIsUp && !hasStore`, the pill's lead action SHALL be "Set up an engine…"
  (`CMD.openEngineSetup`) and `CMD.startEngine` SHALL NOT be offered from the pill; WHEN `hasStore == true` the plain
  Start is unchanged. → `engine-control.test.ts` (rewritten store-less assertion + the known-CMD sweep),
  `engine-setup.test.ts` (content-model commands ⊆ `Object.values(CMD)`; dev-engine button === `CMD.startEngine`).
