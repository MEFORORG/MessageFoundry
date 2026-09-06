# CLAUDE.md: sections that belong elsewhere, or that fire never

> Split out of [CLAUDE.md](../CLAUDE.md) on 2026-09-05. **Nothing here has been edited.**
> Architecture and layout reference, command cheat-sheets, restatements of rules stated
> once elsewhere, and rules the file itself records as retired. Each block needs a
> destination chosen by the owner: a doc, a nested CLAUDE.md, or deletion.


MessageFoundry routes, transforms, and validates HL7 v2.x messages between **connections**,
with routing and handling expressed as **code-first Python**. The engine runs headless; a
browser **web console** (`/ui`) monitors and operates it over a localhost HTTP/WebSocket API.

- **Connection** — an endpoint that **receives** (inbound) or **sends** (outbound) messages
  (MLLP, file, TCP, HTTP, DB; more planned). Lives under `transports/`. **Every message a connection
  takes in or puts out is counted and logged** — nothing is silently dropped. Naming convention
  (`[TYPE]_[PARTNER]_[MESSAGE]`, e.g. `IB_ACME_ADT`) + per-connector settings:
  [`docs/CONNECTIONS.md`](../docs/CONNECTIONS.md).
- **Router** — a **code-first Python script** bound to an *inbound* connection. It sees **every**
  received message and decides where it goes (forward to one or more Handlers); it may also
  filter. A filtered/unrouted message is still logged, never silently discarded.
- **Handler** — a **code-first Python script** that takes a message from a Router, **filters →
  transforms**, then hands it to one or more *outbound* connections.
- **Message store** — durable persistence + queue for received/processed/errored messages
  (SQLite, WAL). Each inbound message is recorded with its disposition: `RECEIVED`/`PROCESSED`
  (routed), `UNROUTED` (no handler took it), `FILTERED` (router dropped it), `ERROR`
  (parse/validation failure).

**Client/server split, not a monolithic GUI app:**
- **Engine** = a headless **asyncio** service (FastAPI/uvicorn). It owns the store and
  supervises one runner per inbound connection. **No GUI imports** — testable headless and
  runnable as a service.
- **Web console** = the operator UI, a **browser SPA served same-origin at `/ui`** by the engine's
  own FastAPI app (`messagefoundry_webconsole`, mounted in-process via `mount_ui`; ADR 0065). It talks
  to the engine only over the localhost **HTTP/WebSocket API** ([`api/app.py`](../messagefoundry/api/app.py)),
  never importing the engine or touching the DB. It is the **sole operator console** — the former
  PySide6 desktop console was retired (BACKLOG #103, ADR 0032 retired; ADR 0088 extracted its reusable
  Qt-free client). PySide6 now lives only in the standalone **test harness** (`harness/`), which reuses
  a few view widgets rehomed from the old console.
- **Authentication + RBAC are built** ([`auth/`](../messagefoundry/auth/), enforced by the API and
  web console — see [`docs/SECURITY.md`](../docs/SECURITY.md)): local + AD (LDAP/Kerberos) users, fixed
  built-in roles, deny-by-default per-route permissions, opaque sessions, native TOTP MFA + browser
  WebAuthn passkeys (WP-14/WP-14b, ADR 0068 — `[webauthn]` extra) for local
  accounts (AD MFA delegated), full audit. The API binds `127.0.0.1` by default and **always
  serves TLS** ([ADR 0172](../docs/adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md)):
  an operator-supplied `[api].tls_cert_file` wins if set, otherwise the engine mints and reuses a
  self-signed pair on first run. **One topology is deliberately excluded:**
  `[api].tls_terminated_upstream` declares a reverse proxy terminating TLS in front and speaking
  plaintext to the engine, so the engine mints nothing there -- serving https underneath that
  proxy would break the proxy's own hop. *Always serves TLS* therefore means the engine never
  leaves a hop unprotected, **not** that it terminates TLS everywhere. Remote network exposure
  (opening the bind beyond loopback) is still a separate, later question from whether the hop
  itself is encrypted.

**Staged pipeline (ADR 0001, Step B).** The store is a **generic staged queue** on SQLite (WAL)
with a `stage` discriminator. A received message flows through three persisted stages: **`ingress`**
(the raw message, committed before the ACK) → **`routed`** (one row per handler the router selected,
carrying the raw, awaiting transform) → **`outbound`** (one row per destination). The inbound
**listener** decodes/parses/(strict-)validates synchronously then commits the raw to the ingress
stage and ACKs; a **router worker** (one per inbound) runs the **Router** (`route_only`) and hands off
to the routed stage; a **transform worker** (one per inbound) runs each handler's **transform**
(`transform_one`) and hands off to the outbound stage; the per-outbound **delivery workers** drain
those rows. Splitting routing from transform means a slow/failing transform can no longer block
routing. See [`docs/adr/0001-staged-pipeline-architecture.md`](../docs/adr/0001-staged-pipeline-architecture.md).

**Concurrency = asyncio** (not Qt threads): one listener + a **router worker** + a **transform
worker** per inbound connection, one delivery worker per outbound connection, listeners/pollers/
retry-timers as asyncio tasks supervised by the `RegistryRunner` so a crash in one is isolated.

**Deployment:** the engine runs as a **Windows service via NSSM** — see
[`docs/SERVICE.md`](../docs/SERVICE.md).

---


```
messagefoundry/
  __main__.py      # CLI entrypoint: `messagefoundry serve ...`
  logging_setup.py # stdlib logging config (NSSM captures stdout to files)
  config/          # connector models (models.py) + code-first wiring (wiring.py) + service settings (settings.py)
  pipeline/        # engine.py (Engine), wiring_runner.py (RegistryRunner), dryrun.py
  transports/      # base.py (connector registry), mllp.py, file.py, dicom.py (C-STORE SCP + SCU/C-ECHO), dicomweb.py (STOW-RS, ADR 0025), smart.py (SMART Backend Services token provider, ADR 0024)   ← "connectors"
  parsing/         # peek.py (python-hl7, hot path), tree.py, validate.py (hl7apy, strict); x12/ (X12 EDI codec, ADR 0012), dicom/ (DICOM codec, ADR 0025), binary.py (base64 carriage, ADR 0028)
  anon/            # de-identification framework (ADR 0030; vendored to tee/anon/)
  store/           # base.py (Store protocol + open_store factory), store.py (SQLite WAL inbox/outbox), sqlserver.py, postgres.py
  auth/            # authn + RBAC core (no FastAPI): permissions/roles, Identity, passwords, tokens, ldap, service.py
  api/             # FastAPI app.py + models.py + security.py (auth deps) + auth_routes.py (the engine's only external surface)
  apiclient/       # Qt-free / FastAPI-free engine-client library (ADR 0088) — the shared HTTP client (httpx)
  generators/      # conformant synthetic HL7 generators (adt.py, …) — `messagefoundry generate`; corpus git-ignored
  security/        # security assets shipped in the wheel (ADR 0144)
  support/         # support-bundle assembly + redaction (bundle.py, redact.py)
  verify/          # deployment verifier — `messagefoundry verify` (checks.py, smoke.py, federation.py)
  tray/            # Windows tray service-manager (ADR 0113) — stdlib ctypes, no PySide6; wraps service/service_status only
  checks.py        # `messagefoundry check` commit/CI gate (validate + dryrun + advisory lint)
ide/               # VS Code extension (TypeScript): setup, promote, test bench, AI commands
environments/      # per-environment <env>.toml value files for env() lookups (dev/staging/prod)
samples/           # config/ (example Connection/Router/Handler modules) + send_mllp.py sender
harness/           # standalone PySide6 send/receive test harness (+ config/ disposition-coverage graph; reuses console-rehomed Qt widgets in _console_widgets.py/_login.py)
scripts/service/   # NSSM install/uninstall PowerShell scripts
docs/              # ARCHITECTURE.md, SERVICE.md, CONNECTIONS.md, CONFIGURATION.md (service settings)
tests/             # pytest suite
```

> **Direction:** Routers and Handlers authored as Python scripts wiring named Connections (no
> enclosing "channel" object) is the model **today**. The future target is a read-only **component
> SDK** users **fork to customize** (a registry resolving forks over shipped components). Keep new
> building blocks small and composable so they fit this model.

---

**Two clauses here were retired on 2026-09-04 and are kept named rather than deleted, because seats
still quote them.** *"No workflow notifies a Reviewer that a PR is waiting"* was overtaken first:
`unread-signal.yml` shipped for BACKLOG #1413 and is on `origin/main`, and it comments on and labels a
green, unread PR. *"Nothing reports unread ones"* went with it. Then the review gate itself was retired
-- so what `unread-signal.yml` announces is now a PR missing a label that **gates nothing**. Neither
clause describes the machine today.
- **Put the prompt FIRST when you spawn, or close the flags with `--`.** At least `--allowedTools`,
  `--disallowedTools`, `--tools`, `--add-dir`, `--mcp-config`, `--betas` and `--file` take lists, so
  `claude --bg --allowedTools Bash Edit "do the work"` swallows the prompt as a third tool name. The
  session starts with nothing to do, exits 0, then lists as `state=blocked`, which is also what a
  real permission block looks like. The lane reads as alive and does nothing.
- **In the `--allowedTools` FLAG, grant tools by BARE NAME, never scoped to a command.**
  `--allowedTools Bash PowerShell` works.
  `--allowedTools "PowerShell(pwsh:*)"` silently disables the PowerShell tool: every command it
  sends comes back `Command contains malformed syntax that cannot be parsed: pwsh exited with code
  1: The command line is too long.` Consistent with the tool spawning `pwsh` to test a command
  against a scoped pattern, and that spawn failing when the inherited environment is near the
  8191-byte command-line limit. Nobody has read the tool's source, so the mechanism is inferred;
  the paired test establishes only that the GRANT FORM is causal. An environment block is
  per-PROCESS, not per-machine: one session measured 8105 bytes, and the size varies with config
  root, worktree path and inherited `PATH`. A bare grant needs no parse.
  **The careful spelling is the broken one**, which is why this cost four Builder launches before
  anyone looked. Measured 2026-09-02, one variable, environment held constant. Bash is unaffected.
  **The two rule sources are known asymmetrically, so do not generalise:** command-scoping is
  measured to break BOTH the flag and a `settings.json` rule (a matching `Bash(git add:*)` executed
  while its `PowerShell` twin died at the parse). A BARE name is measured to work **in the flag
  only** -- nobody has put a bare tool name in a `settings.json` `permissions.allow` and spawned
  without a flag. Do not "fix" a config root by bare-naming its rules on the strength of this line.
  Three refusals that must not be conflated: `malformed syntax ... too long` is the parse dying and
  says nothing about your rules; `This command requires approval` is a real permission decision;
  `The term 'X' is not recognized` means the command RAN and the PATH is wrong.
- **The merge is the Lander's. THE `reviewed` LABEL NO LONGER BLOCKS IT -- owner ruling 2026-09-04,
  in their words: "the reviewer requirement is retired."** `a reviewer has read this` came off `main`
  branch protection and `.github/workflows/review-gate.yml` was deleted, so nothing posts that check,
  nothing strips the label on a push, and a PR merges without it. **This bullet previously read** "what
  blocks it is the `reviewed` label. Any seat can apply that label ... so label after your last push".
  It is recorded rather than deleted because it was live long enough that seats still quote it.
  **What survives is the reason it was never worth much**: the gate recorded that a step *happened*,
  not that an independent party looked, so labelling your own PR unread satisfied the machine and
  defeated the point. Reading a diff before merging it is still the job; no check now asks whether you
  did.

```
# tests (PySide6 harness/Qt tests need the offscreen platform)
# testpaths now also collects packaging/messagefoundry-webconsole/tests, so this covers the web console suite too.
QT_QPA_PLATFORM=offscreen pytest -q          # PowerShell: $env:QT_QPA_PLATFORM="offscreen"; pytest -q

# format / lint / types
ruff format .
ruff check .
mypy messagefoundry

# run the engine (headless) — loads config modules, opens the store, serves the API + the web console at /ui
python -m messagefoundry serve --config samples/config --db ./messagefoundry.db --env dev

# open the web console (operator UI) — browse to the engine's /ui (e.g. http://127.0.0.1:8765/ui)

# launch the standalone PySide6 test harness (separate process; attaches to the API)
python -m harness

# send a test HL7 message over MLLP
python samples/send_mllp.py samples/messages/adt_a01.hl7
```

---

  **Why this is a correctness rule and not a style preference.** A glyph's meaning is *positional*, and
  that is invisible to anyone who learns it from examples rather than from its definition. Measured
  2026-08-04: the backlog's `✅` means "this item is closed" **only** in the leading blockquote — quoted
  in an item's prose it is narrative. Two parsers of the same file disagreed on exactly that, one
  reading "the glyph appears in this item" and the other "this item declares closed status", and they
  **agreed on the current corpus by luck** because no item happens to have the discriminating shape.
  Words carry their scope in the sentence around them; a bare glyph does not, so it invites
  presence-equals-meaning reading and hides the ambiguity from review.

  Secondary but real: emoji need variation-selector handling (`️`) in every regex that touches
  them, and they raise `UnicodeEncodeError` on a stock Windows cp1252 console — which cost four
  separate failures in one session.

  **THE WARNING SIGN (U+26A0) IS NOT A SIXTH HOLDOUT — owner-ruled 2026-08-14, "not sanctioned".** It
  is in neither `_CLOSED` nor `_OPEN`, so `parse_items` ignores it and it carries no status semantics
  anywhere; it is decoration, which the rule above forbids outright. **The measured population is
  recorded here so nobody re-derives the false zero that stalled this question once already: 496
  occurrences across 80 files** at `ae76b9f9` — 447 under `docs/` (121 in `BACKLOG.md`, 93 in
  `BACKLOG-CLOSED.md`, 35 in `docs/adr/`), 10 in `tests/`, 4 in `ide/`, 3 in engine source, and **zero
  in `scripts/`, in the web console, and in this file**. Retiring them is **BACKLOG #1265**, a filed
  migration — *not* a licence to start editing those 496 lines, and not a cp1252 hazard (the cp1252
  gate covers `scripts/**/*.py`, which contains none of them). **Census this population only with the
  ledger counts as a positive control** — the first attempt returned a false zero off a broken shell
  escape, and a pattern that finds nothing anywhere is indistinguishable from a clean repo.
- When asked for tabular results, provide the final table directly — not code that generates it.

**Do**
- Plan first; implement after approval / an explicit "go".
- Parse with python-hl7 on the hot path; use hl7apy for opt-in strict validation.
- Keep the engine free of GUI imports; reach it from the web console / harness via the HTTP API.
- Preserve the raw message; **log every received message with its disposition** (route bad
  messages to the error/dead-letter path — never accept-and-drop).
- Use **Connection / Router / Handler** vocabulary; read separators from MSH; be explicit about
  HL7 version.

**Don't**
- Don't manipulate HL7 with raw string slicing.
- Don't block the asyncio event loop; don't update widgets from worker threads.
- Don't log full PHI payloads (INFO+).
- Don't import PySide6 (or FastAPI) inside the engine packages (`pipeline/`, `transports/`,
  `parsing/`, `store/`, `config/`).
- Don't build a **"channel"/"route" element** (an object, runner, or config surface that bundles
  the graph) — the words are fine as descriptive language, the deployed element is not. Don't
  accept-and-drop a received message.
- Don't keep grinding in a polluted context — `/clear` after repeated failures.
- Don't use **glyphs or emoji** in prose, comments, commit messages, PR bodies or replies — say the
  word (§11). The backlog status-banner alphabet is the one machine-parsed holdout; read it with
  `parse_items`, never a hand-rolled scan, and introduce no new glyph vocabulary anywhere.
