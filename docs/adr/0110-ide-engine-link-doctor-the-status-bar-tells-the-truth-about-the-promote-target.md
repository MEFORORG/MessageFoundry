# ADR 0110 — IDE engine-link doctor: the status bar tells the truth about the promote target

- **Status:** Accepted (2026-07-14) — owner-directed this session; built (IDE extension v0.0.28, BACKLOG #232).
- **Deciders:** owner (report + "do it all" directive) + a 23-agent design/adversarial pass.
- **Extends:** [ADR 0100](0100-ide-native-surface-polish-and-open-to-messagefoundry-startup-experience-backlog-221.md)
  (the native surface, whose §1 enumerates this status-bar item — and records it as one that *"opens
  engine settings"*, a drift this ADR reconciles), and [ADR 0035](0035-ide-extension-workspace-trust-and-scope.md)
  (machine-scoped engine target + the pre-prompt target refusal, whose reach a standalone sign-in command
  extends). **Bounded by** [ADR 0065](0065-web-ops-dashboard.md): the web
  console is the **sole operator console**. Relates to BACKLOG #221(c).

## Context

The right-aligned `MEFOR: <host>` item is the IDE's only window onto the engine it promotes to. **It was
lying**, by default, in the owner's daily-driver state.

`httpProbe` called `GET /health` and **threw the response body away**; `classifyProbe` folded *every* HTTP
answer — explicitly including a **401** — into `"reachable"`; and `formatEngineStatus` painted that green.
So "green" meant *a socket answered*, not *the IDE can use this engine*. Because `AuthSettings.enabled`
defaults to `True` and the owner's service TOML has no `[auth]` section, a plain `serve` produces an engine
that is up, an IDE that holds **no session**, every authenticated call 401ing — **and a confident green
check.** A live probe of the owner's own running engine returns:

```
GET /health  ->  200 {"status":"ok","version":null}
GET /        ->  404 {"detail":"Not Found"}      # there is no "/" route in api/app.py
GET /ui      ->  303 -> /ui/login                # the console IS served
```

`version: null` is the decisive tell: `/health` is tokenless but discloses the build version **only to an
authenticated caller** (`api/app.py`, WP-L3-07 / ASVS 13.4.6). The evidence was in a body the code already
fetched and discarded.

The click was no better. It opened a `showQuickPick` whose only "status" was the engine URL echoed into a
`placeHolder` (grey filter-box hint text that vanishes the moment you type), offering three actions, none of
which diagnoses or repairs anything — and one of which, **"Open engine URL in browser"**, opened the *bare*
engine URL and landed the user on a FastAPI 404. The owner's report was: *"clicking it appears to do nothing …
it should pop up something to let me see the connection to the engine and fix whatever's wrong."* The click
was in fact firing; the quick-input widget renders top-center, ~1000px from the item clicked in the corner.
**The complaint is valid regardless: the extension had no diagnosis to show.** It also had no engine log at
all — a refused socket, a 5s timeout, a 401 and a cleared token each vanished without a trace the user could
read.

Two engine facts constrain any fix, and both **invalidate the obvious design**:

1. **`optional_identity` applies no RBAC and no must-change gate** (`api/security.py`, verbatim: *"The
   ``must_change_password`` gate is intentionally *not* applied"*). A token that is 403'd on every real route
   still gets `version` back from `/health` — and `/auth/me` is in `_MUST_CHANGE_EXEMPT_PATHS` and answers
   **200** for that same locked-out user. **Neither endpoint can establish that a session is usable.**
2. **`identity_for_token(token, *, activity: bool = True)`** documents that the default *"refreshes the
   session's idle clock; pass activity=False for background re-checks … so a passively-polled token still ages
   out against real user activity (AUTH-IDLE)"* — and `optional_identity` calls it with the default. **A bearer
   on a 15-second timer would make the engine's 30-minute idle timeout mathematically unreachable** (CWE-613),
   on the very client the automatic-logoff control exists for.

CLAUDE.md §2 is the outer fence: the web console *"is the **sole operator console**"* (the PySide6 desktop
console was retired). The file under repair already drew the same line in its own comments — *"a liveness
hint, not a monitor (that's the Console)"* — and BACKLOG #221(c) chartered exactly three things: target URL /
environment / reachable. **This ADR adds only what makes those three honest.**

## Decision

### 1. Green means "the IDE can USE this engine", not "a socket answered"

`Reachability` (`reachable`/`unreachable`/`unknown`) is replaced by a closed union in the vscode-free
`engineStatusModel`, unit-tested node-side: **`unreachable{code}` / `foreign` / `signedOut` / `unverified` /
`blocked{reason}` / `drifted` / `ok`**. Every state names a *different* fault with a *different* remedy; the
old model had one bucket covering four of them.

The tokenless 15s poll now **reads the `/health` body** (zero extra HTTP — it was already being fetched):
`status !== "ok"` ⇒ `foreign` (something else is on the port). Crucially, `version` **present** ⇒
**`unverified`, never `ok`** — per Context §1, a returned version proves only that *a* session exists.

**`version: null` is decisive only when we hold no token, and getting this wrong was a real (caught) bug.**
Because the poll is tokenless, an auth-enabled engine returns `version: null` to it *always* — including
when the IDE holds a perfectly good session. Reading that as "signed out" told a signed-in user to sign in
**and destroyed the `ok` verdict the deep probe had just earned, 15 seconds after every sign-in**. So the
shallow classifier takes `hasSession` (a **SecretStorage read** — it sends no bearer, so the idle clock in
§2 is untouched): `version: null` + no token ⇒ `signedOut`; `version: null` + a token ⇒ `unverified`
("up, and this probe cannot see my session"), leaving the earned verdict to expire by **decay**, not by
being forgotten on the next tick. A tokenless probe simply cannot observe our own session state, and the
model must not pretend otherwise.

### 2. The poll stays TOKENLESS; "usable" is EARNED and DECAYS

Attaching a bearer to the timer is a **hard prohibition**, not a preference (Context §2). The cheap poll may
therefore only ever prove the **negative**, and the design says so.

A green check is issued **only** after a **user-initiated** probe (click / activation / post-promote — all real
user activity, so the bearer it sends does not falsify the idle clock) succeeds against a **non-must-change-exempt,
permission-gated route**: `GET /config/provenance` (`monitoring:read`, no step-up). It is the cheapest call whose
success *means* something, and it returns **`drift`** for free — the highest-value signal the IDE can get about
the engine it authors for. A 403 is sub-classified from its already-stable `detail` string (`"password change
required"` / `"missing permission: …"` / step-up / MFA), which `httpErrorMessage` already extracts — **no response-header
widening is needed to classify.** A green verdict **ages out** back to `unverified`: a status-bar tooltip is a
**value, not a provider**, and must never keep asserting a fact it has not re-checked.

### 3. Native chrome, deliberately NOT a webview

A **`MarkdownString` hover** is the primary diagnosis — it renders *at* the item, under a cursor already there,
needing **no command dispatch at all**, so it works even for a user who never realises the click opens anything.
Plus a **state-gated QuickPick** on click (with a `title:`, never a `placeHolder:`), a **`$(sync~spin)` flip at the
click site** (the only feedback that appears where the user actually clicked), and the extension's **first engine
`LogOutputChannel`** ("MessageFoundry Engine") — one line per probe/action carrying URL, status or errno, duration
and verdict, and **never a body, never a token** (CLAUDE.md §9; it is wired at the status-bar layer, *not* inside
the shared `engineClient`, which would silently capture whatever every future caller sends).

A webview panel is **rejected**: it opens from the same command dispatch (so it fixes a missed click no better), it
is an unbounded canvas into which queue depths and message lists creep, and its HTML+postMessage surface is the one
thing in this extension the node-side mocha convention cannot assert.

### 4. The boundary is EXECUTABLE: the IDE renders and repairs the LINK; it never renders the WORKLOAD

Three stacked devices, so this stops being a docstring:

- **(a) Container poverty** — a hover, a QuickPick and an OutputChannel *physically cannot host* a connections
  table or a start/stop control.
- **(b) The pure model emits COMMAND IDS, never data** — `planActions(link) → {label, command, args}`, and the
  QuickPick handler's only permitted body is `executeCommand(...)`. There is no channel through which workload data
  could reach the UI even if someone fetched it.
- **(c) Two frozen allowlists, asserted in CI** — an `EngineLink` **field** allowlist with no field for a
  connection, message, queue depth, count or rate (plus a compile-time exhaustiveness check, so a new field cannot
  be added without tripping it); and a **probe-endpoint** allowlist naming only `/health`, `/ai/policy`,
  `/config/provenance`. `/messages`, `/connections`, `/stats`, `/dead-letters`, `/alerts`, `/approvals` **break the
  build**.

Everything operational deep-links to `<engineUrl>/ui`.

### 5. Two real repairs — and honesty about the rest

`messagefoundry.engineSignIn` / `engineSignOut` expose flows that were **already written and merely unreachable**
(`login()` was private, reachable only via promote; `clearToken()` only from a 401 handler — there was **no
user-facing way to clear a stuck token**). `signIn()` already calls `assertTargetAllowed()` **before any credential
prompt**, so ADR 0035's SEC-005 refusal is *inherited, not re-implemented*.

**Sign-out REVOKES.** It calls `POST /auth/logout` (must-change-exempt, so it works even for an account that is
403'd on everything else) and only then forgets the local token. Dropping the local copy alone is not signing out —
it leaves the session alive on the engine until it idles out, so telling a user who may have just stepped away from
a shared machine that they are "signed out" would be a lie. If the engine is unreachable we clear locally anyway
(refusing to sign out because the engine is down is worse) and **say which of the two happened**.

Deliberately **not** built, each for a verified reason:

- **A "Reload engine config" button** — `POST /config/reload` is `require_step_up(CONFIG_DEPLOY)` with a **300-second**
  window while `withAuth` retries only 401 and **never 403**, so the button would fail in the common case. Config
  **drift delegates to the existing `messagefoundry.promote` command**; no second engine-config-mutating path is minted.
- **Inline change-password / MFA / step-up flows** — credential management is the console's job (ADR 0065). These states
  are **detected and named**, then deep-linked to `<url>/ui/login`.
- **"Start local engine"** — a `createTerminal` defaults its cwd to the **workspace folder**, which in a git worktree has
  no service TOML and no store: `serve` would create a **brand-new empty database and a fresh bootstrap admin**, forking
  the user's engine. v1 offers **"Copy the engine start command"** (no `--db`/`--env` overrides — the service TOML is the
  authority).
- **A `messagefoundry.engineEnv` setting** — the service TOML already sets `[ai] environment`; a setting would *override*
  the authoritative config. The environment is **read** (tokenless `/ai/policy`) and displayed, never set.

### 6. Signed-out is a STATE, not an alarm

It gets a distinct glyph (`$(lock)`) and **no background colour**. Being signed out is the author's harmless steady state
(live status is off by default; promote prompts anyway). A permanently amber item is a permanently *ignored* item — and
then it cannot warn about the states that do block an action: `unreachable`/`foreign` (error background) and
`blocked`/`drifted` (warning).

## Acceptance Criteria

- **AC-1** — WHEN the tokenless `/health` probe returns `{"status":"ok","version":null}`, THE EXTENSION SHALL render
  **signed-out** and SHALL NOT render `$(pass-filled)`. → `ide/src/test/suite/engine-status.test.ts`
- **AC-2** — WHEN `/health` returns a `version`, THE EXTENSION SHALL render **unverified** (never `ok`) until a deep probe
  against a non-exempt protected route succeeds. → `engine-status.test.ts`
- **AC-3** — THE PERIODIC POLL SHALL NOT send a bearer token (AUTH-IDLE / CWE-613); only a user-initiated probe may.
  → `engine-doctor.test.ts` asserts every `POLL_PLAN` entry is `authenticated: false`. This is a **control, not a
  comment**: `statusBar.runProbe` attaches a bearer **iff the plan entry says so**, so the assertion is what actually
  holds the line. (An earlier draft had the rule only in prose — a reviewer correctly pointed out that a rule with no
  executable guard is a wish.)
- **AC-4** — WHEN the probe fails at the transport layer, THE EXTENSION SHALL surface the **classified** reason (refused /
  hung / DNS / TLS), not a bare "unreachable". → `engine-client.test.ts`
- **AC-5** — A verified verdict SHALL decay to `unverified` past its freshness window, and SHALL survive an intervening
  tokenless poll (it must expire by decay, never by being forgotten). → `engine-status.test.ts`
- **AC-6** — THE SURFACE SHALL NOT render message content, message lists, queue depths, connection rows or connection
  controls, and its probe plan SHALL name only the allowlisted endpoints; operational views SHALL deep-link to
  `<engineUrl>/ui`. → `engine-doctor.test.ts` (two frozen allowlists)
- **AC-7** — THE LOG CHANNEL SHALL record only URLs, status codes, error codes, durations and OUR OWN verdicts — never a
  response body, never server-supplied text, never a bearer token. → `engineLog.ts` (route allowlist; `logState` logs the
  state and our `blocked`/`code` vocabulary, **never `reason`**, which carries the engine's `detail` verbatim)
- **AC-8** — Server-supplied text SHALL be escaped before entering the **trusted** hover, whose `enabledCommands` include
  `messagefoundry.promote`. → `engine-doctor.test.ts` (a `[…](command:…)` planted in a 403 `detail` must not survive)
- **AC-9** — Sign-out SHALL **revoke the session on the engine** (`POST /auth/logout`), not merely forget the local token;
  if the engine is unreachable the user SHALL be told the session remains active there. → `auth.ts`
- **AC-10** — The vscode-free suites SHALL execute in CI **on the repo where PRs land**. → `.github/workflows/ci.yml`
  (`npm run test:unit`, every leg). Without this, ACs 1–8 are asserted by tests that never run: `npm test` is
  Windows-only and the private repo's `ide` matrix is ubuntu-only, so the entire node-side estate (328 tests) was
  type-checked and **never executed**. "Asserted in CI" was false until this line existed.

## Consequences

- The status-bar item **stops lying in its most common state.** Green now carries a claim the IDE has actually verified,
  and it expires rather than going stale into a false assurance.
- The extension gains its **first engine log surface**; a refused socket, a timeout, a 401 and a cleared token stop
  vanishing without a trace.
- **"Open engine URL in browser" is fixed** — it opened the API root (a live 404) and now opens the web console at `/ui`.
- Poll cost is unchanged (one tokenless GET). The deep probe is user-initiated only, so **no third poller** joins
  `statusBar` and `liveStatus`, and no background timer touches a session's idle clock.
- ADR 0100 §1's record of this item ("opens engine settings") is **superseded**: the click now opens a state-gated action
  menu, and the diagnosis lives in the hover.
- `messagefoundry.engineSignIn` is **net-new credential-entry surface**, extending ADR 0035's SEC-005 reach; it is
  test-pinned to the pre-prompt `assertTargetAllowed()` refusal rather than merely code-reviewed.
- `settings-scope.test.ts` is hardened from three hard-coded key assertions into a **family invariant** (every declared
  setting must be classified; anything naming a target must be machine-scoped) — it was weaker than assumed and would not
  have caught a new un-scoped URL setting.
- **The IDE's node-side tests now actually run in CI on this repo** (`npm run test:unit`, 328 tests across 19 suites, on
  every leg). They previously ran nowhere here — `npm test` needs a downloaded VS Code and is gated to the Windows leg,
  which the private repo's `ide` matrix does not include. This benefits far more than ADR 0110: the graph, steps, HL7 and
  wiring-map model suites were all being compiled and discarded too.
- The hover is a **trusted** MarkdownString, so all server-supplied text (`reason`, which carries a 403 `detail`
  verbatim; `version`; `environment`) is escaped and bounded before it is interpolated. A hostile listener on that port —
  which is exactly what `foreign` means — must not be able to plant `[Click me](command:messagefoundry.promote)` into a
  hover the user is invited to click. Defence in depth *behind* the command allowlist, not instead of it.
- Some failures remain **explain-only, and the surface says so** rather than offering a button it cannot honour: an RBAC
  403 (an administrator must grant the role), TLS/self-signed (there is no CA-trust setting in the IDE and this ADR does
  not add one), and a bootstrap admin that has **auto-retired** (`bootstrap_expiry_hours`, default 72h) — for which there
  is **no supported in-place recovery**; the honest remedy is a fresh store.
- **#26 (no visual/declarative authoring) is untouched — #26-clean:** this surface authors nothing, projects to no `.py`,
  and executes no logic. No PySide6. No "channel"/"route" element.

## Alternatives considered

- **A webview "Engine Doctor" panel** — rejected: opens from the same command dispatch (fixes a missed click no better);
  it is the unbounded container a second operator console grows inside (the proposal for it leaked a `/connections` row
  while being written); and its HTML + postMessage surface cannot be asserted by the node-side test convention.
- **Attach the cached bearer to the 15s poll to learn the auth state cheaply** — rejected: it defeats the engine's own
  idle-session timeout (AUTH-IDLE / CWE-613). The cheap poll may only ever prove the negative.
- **Use `GET /auth/me` as the is-my-session-usable probe** — rejected: it is in `_MUST_CHANGE_EXEMPT_PATHS` and returns
  **200** for a user locked out of everything. It cannot establish usability.
- **A one-click "Reload engine config" button** — rejected: `require_step_up` + a 300s window + `withAuth` never retrying a
  403 means it fails in the common case, and dual-control can return a 202 the client mis-renders. Delegate to promote.
- **A bespoke "fix my engine target" form** — rejected: it must choose a `ConfigurationTarget`, and Workspace scope would
  silently revert ADR 0035's SEC-005/CWE-918 machine-scoping. **Refusing to build the form is the security decision.**
- **Paint "signed out" with a warning background** — rejected: it is the author's harmless steady state; a permanently
  amber item gets ignored, and then it cannot warn when something is actually broken.
