# 0208 -- A Theia desktop app gives interface analysts a simpler Steps-only editor

- **Status:** Proposed (2026-10-07). Design only; no code exists. Accepting it needs the owner.
- **Date:** 2026-10-07
- **Related:** [ADR 0076](0076-typed-action-vocabulary-action-list-lens.md) (the Steps view and its
  grammar; Amendments A, C, D, E and F apply, B was declined; this ADR proposes Amendment G) -
  [ADR 0103](0103-steps-view-row-context-menu.md),
  [ADR 0106](0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md),
  [ADR 0108](0108-steps-view-accumulator-send-fan-out-copy-on-send-authoring.md) (Steps editing as
  built) - [ADR 0045](0045-custom-rbac-roles.md) (custom roles) -
  [ADR 0017](0017-consumer-deployment-model.md) (the config repository) -
  [ADR 0201](0201-a-messagefoundry-toolkit-distribution-carries-the-authoring-and-development-tooling-out-of-the-engine-wheel.md)
  (`lens` is toolkit-tier) - [ADR 0035](0035-ide-extension-workspace-trust-and-scope.md) (IDE trust) -
  CLAUDE.md section 2 and BACKLOG #103 (the web console is the sole operator console) - CLAUDE.md
  section 12 and BACKLOG #26 (the Steps-view carve-out) - companion specification
  [`docs/design/theia-analyst-editor.md`](../design/theia-analyst-editor.md)

> Deployment status (CLAUDE.md section 0): MessageFoundry has no deployed instances, and nothing here
> is built. Every statement about analysts and sites describes what a deploying site *would* run.

---

## Context

### The ask

Interface analysts who do not write Python need a simpler editor than VS Code. They should be able to
edit a Router or Handler through typed Steps rows, and no more. Developers keep full Python.

The owner's drafts of 2026-10-02 proposed a hosted Theia server that enforced this on the server. A
four-lens review of those drafts (2026-10-07; 41 of 44 raw findings survived adversarial
verification, merged into R1 to R34) returned "rework before acceptance". A second four-lens review
of this ADR's first rewrite followed the same day; spec Appendix B lists where each of its findings
landed.

### Rulings and decisions

**Owner rulings, 2026-10-07.**

1. Theia exists to give low-code analysts a simpler interface than VS Code. Enforcement is not the
   motivation.
2. A desktop app comes first. A hosted, browser version comes later.
3. The editor's role-based check is the **primary** control limiting analysts to typed Steps edits. A
   repository-side check is an **optional** control a site can turn on.
4. Developers keep the full IDE layout in the Theia build, with a Steps / Split / Code switch. They
   may also stay on VS Code and `ide/`.
5. **Typed-only mode.** `paste_block` and a one-line raw `test` stay available by default. A flag on
   `lens rewrite` (working name `--typed-only`) refuses both with the generic `refused` code. The
   analyst build always sets it.
6. **The repository check's reading.** A Steps-only change passes. Any other change passes only with
   approval from a `code:edit` reviewer.
7. **Analyst is a built-in role**: Steps editing, no `code:edit`.
8. **Licence.** The Theia analyst editor extension and its desktop builds are AGPL-3.0-or-later, the
   same as the repository.

**Manager decisions under the owner's delegation, 2026-10-07.**

- **Pre-commit hook.** The repository check also ships as an optional pre-commit hook running the
  same classifier. It is a convenience, not a control: a local hook is bypassable. The CI check is
  the control.
- **Drag-a-field.** It is inside the BACKLOG #26 carve-out only as entry of a path parameter on a
  step, producing the same typed `lens rewrite` edit as typing it. A drag that creates a
  field-to-field mapping, or a step from a mapping gesture, stays declined.
- **Source location.** The editor's source lives in this repository, beside `ide/`, so the lens row
  contract and the editor version together (review R14).

**Manager decisions 2026-10-07, after adversarial review.**

- **D-A.** The developer build applies no per-user limits; it is a full IDE for whoever installs it,
  no weaker than VS Code with `ide/`. The analyst limits live in the analyst build alone, which is
  capped at the Steps level for everyone. A user without `code:edit` is given the analyst build.
- **D-B.** Analyst Test takes a generator spec (message type and seed), never a file. A small engine
  change lets `dryrun`, or a thin wrapper, generate that message in-process and show its values
  unredacted for that generated input only. The editor never passes `--show-phi`.
- **D-C.** The repository check passes and fails exactly as ruling 6 says and reads the `code:edit`
  approval itself. The documents recommend the site's ordinary review on every pull request, as
  guidance, not as a requirement of the check.

### What already exists

- **The Steps view is built and edits**, in `ide/` (ADR 0076 phase 3; ADRs 0103, 0106 and 0108).
  Every edit is a row-scoped splice computed by `lens rewrite`.
- **`lens rewrite` does not yet limit an edit to typed rows** (finding R1). The answer is the R1 fix
  plus typed-only mode (D6). Both are being built separately, on their own branch. Neither has
  landed, and this ADR does not claim either is done.
- **The roles half-exist.** `Role.CODING` holds `code:edit`, which no endpoint enforces. No permission
  describes the Steps level.
- **Promote ships no files.** For a remote engine, the reload reads the engine's own `--config`
  directory, filled out of band (`ide/src/promote.ts`, the comment above `configDirForTarget`).

### The premise behind the primary control, tested

On a desktop install the `.py` files sit on the analyst's own disk. A role check inside the analyst
build decides what the analyst build offers. It cannot stop a change made with another tool, and the
developer build and VS Code with `ide/` are other tools (D-A). No engine route sees the edit before
it reaches the repository, because promote ships no files.

The review and the drafts were checked for a place the role check is enforced where an analyst cannot
bypass it. There is none for the desktop. The drafts' only such design was the hosted read-only mount
with a server-side broker, which this phase does not build.

So, stated plainly per SDS-3.7: **the primary control is a guardrail for analysts who use the
analyst build as intended. The control that would hold against a deliberate or tool-assisted change
is the optional repository check, and only when the site sets it up as spec section 5.4 says.**

## Decision

**Ship a Theia desktop app in two builds. The analyst build shows a native Steps extension and little
else, is capped at the Steps level, and turns editing on only for a user the engine says holds
`code:steps` or `code:edit`. The developer build is a full IDE with no per-user limits. A site may add
a repository check that would hold the Steps limit against a deliberate change, whatever tool made
it, only when the site meets spec section 5.4.**

- **D1 -- Purpose.** The analyst build exists to be simpler than VS Code for an analyst. Enforcement
  is described honestly in D5 and is not the reason to build it.
- **D2 -- Desktop first.** Both builds are Electron desktop apps, Windows first. A hosted version
  needs its own ADR. The 2026-10-02 hosted design is its starting point, and spec Appendix A marks the
  review findings that ADR inherits.
- **D3 -- Both builds use a native Theia Steps extension.** The reasons are surface reduction and no
  VS Code API: `@theia/plugin-ext` depends on the terminal, tasks, debug, SCM and AI packages, and
  Theia's build keeps transitive extensions (review R6). Filtering a plugin-ext build was weighed and
  not chosen (spec 11.1). Monaco ships in the analyst build, because Theia's document model uses it;
  the analyst build rebinds Theia's `EditorManager` so a `.py` opens only in the Steps view and
  removes *Open With* (AC-G1, spike S-2). The analyst build also needs `@theia/preferences`, with
  `@theia/userstorage`, or it hangs on a missing `PreferenceProvider` binding; that brings in
  `@theia/markers`, `@theia/outline-view` and `@theia/variable-resolver` (Manager decision 2026-10-07, from spike S-1). The port is the
  main cost (spec section 11). Spike S-1 measured the reuse: `ide/media/stepsWebview.js` renders
  unchanged through an `acquireVsCodeApi` shim, and about 84.1% of `ide/src/stepsModel.ts` by bytes
  carries over.
- **D4 -- `code:steps` and a built-in Analyst role.** `code:steps` is added to the permission catalog
  and is **advisory**: the analyst build reads it, and no engine route checks it. `Coding` gains it.
  A new built-in Analyst role holds it and not `code:edit` (ruling 7). "`code:edit` implies
  `code:steps`" is the analyst build's rule for choosing the level, not an engine rule. These are
  the only engine API changes, plus the `dryrun` generator-spec change (D10) and, only if no existing
  route fits, one start-up probe route. The other engine changes (the R1 fix, typed-only mode, the
  capability probe, the repository-check command) are listed in spec section 14.
- **D5 -- The role check is the primary control, in the analyst build, and it is a guardrail.** The
  analyst build signs in through the engine and finishes every session gate (MFA, password change,
  factor enrolment, notification address) before it stores a token or reads permissions. On start-up
  and before each save it proves the session on a route that none of the gates exempts and that is
  not an `mfa_gate=False` route (review R2), never on a timer (review R3). It signs the user out when
  the token is refused or a gate is open; an unreachable engine shows a banner instead. It stops an
  analyst changing
  Python through the analyst build. It does
  not stop a change made with another tool. The developer build needs no engine session (D-A).
- **D6 -- R1 is a precondition, answered by changes landing separately.** The R1 fix and typed-only
  mode (ruling 5) are stated once, in ADR 0076 Amendment G: G.6 for typed-only mode, G.7 for the
  R1 fix and its *inert* rule, and G.5 for the R1 payloads. They are being built separately and
  have not landed.
  Typed-only mode is off by default, so the developer build and `ide/` keep both hatches. The analyst
  build passes it on every `lens rewrite` call and offers no way to turn it off. The analyst build
  does not ship until both land with the R1 payloads as refusal tests.
- **D7 -- The repository check is optional, and the project ships it.** It decides whether a change is
  Steps-only, comparing every `code` row, every control header and each typed row's full statement
  against base by content, allowing only the lens's sanctioned generated shapes, and treating any change outside the def bodies or to
  another file as not Steps-only (spec FR-40). A Steps-only change passes; any other passes only when
  a `code:edit` reviewer has approved the head commit, which the check reads itself (ruling 6, D-C).
  It holds against a deliberate change only when its definition, its engine version and its re-run
  on approval all come from the base branch (the GitHub mechanism for the re-run is settled at build,
  spec 5.4), it reads the change's files as data only, and code-owner
  review covers the CI directory and the engine pin (spec 5.4). The same classifier ships as an
  optional pre-commit hook, which is a
  convenience and not a control.
- **D8 -- The analyst build drops three ADR 0076 guardrails.** No *Reopen With: Python*, no
  text-editor fallback on a parse failure, and the Steps view is the only way to open a Router or
  Handler. ADR 0076 Amendment G records this. The developer build keeps every guardrail.
- **D9 -- Edits save through the document model**, as `ide/` does, so undo and dirty state keep
  working. There is no hot-exit in this phase: spike S-1 measured that Theia 1.76 has none, so a
  dirty buffer is lost on reload. It is a future item (Manager decision 2026-10-07, from spike S-1). There is no server-side broker in this
  phase.
- **D10 -- Analyst Test uses a generated message and never `--show-phi`.** Test takes a message type
  and seed, saves the buffer, and runs `dryrun` or a thin wrapper that generates the message
  in-process. Values are shown unredacted only for that generated input (D-B). For a message type
  with no generator, Test is unavailable, and the analyst build says why. There is no Test Bench and
  no route to open or paste a sample (review R13).
- **D11 -- The source lives beside `ide/`.** The editor's source, a shared view-model package and the
  Theia application form one workspace in this repository, so the lens row contract and the editor
  version together (review R14).
- **D12 -- Drag-a-field is path entry only.** A drop onto a path parameter issues the same
  `set_params` edit, byte for byte, as typing the path. A field-to-field mapping, or a step created
  from a mapping gesture, stays declined under BACKLOG #26 (Amendment G, G.3).

**What this must not break:** the `.py` stays the only artifact and the only execution path, with no
stored Steps model; routers and transforms stay pure; the web console stays the sole operator console
(the editor authors and does not monitor); no PHI reaches the editor (generated messages only);
promote stays `POST /config/reload` with step-up and the site's dual control unchanged.

## Acceptance Criteria

> Proposed tests. None exists yet. The editor's source lives beside `ide/` (D11), and its test paths
> are set when that tree is created, so those lines name the test and leave the path open. Every
> criterion below names the build it applies to.

- **AC-1** -- THE SYSTEM SHALL expose `code:steps` in the permission catalog, grant it to `Coding`
  and to a new built-in `Analyst` role that does not hold `code:edit`, and allow it in a custom role.
  -> `tests/test_custom_roles.py::test_code_steps_permission_catalog_and_roles`
- **AC-2** -- WHEN the signed-in user holds `code:steps` or `code:edit`, THE ANALYST BUILD SHALL turn
  on Steps-level editing; OTHERWISE it SHALL show a read-only Steps view. It SHALL never offer more
  than the Steps level.
  -> editor test *level selection* (path open)
- **AC-3** -- THE lens SHALL meet ADR 0076 Amendment G's AC-G6 and AC-G9, which state the typed-only
  refusals, the R1 fix's refusals and the R1 payloads.
  -> the lens refusal tests the R1 fix adds (being built separately; path set when it lands)
- **AC-3a** -- THE ANALYST BUILD SHALL pass typed-only mode on every `lens rewrite` call.
  -> editor test *typed-only argv* (path open)
- **AC-4** -- THE ANALYST BUILD SHALL offer no route that opens a `.py` file in a text editor, and
  WHEN a file fails `lens parse` it SHALL show the read-only banner instead.
  -> editor test *no text route* and spike S-2 (path open)
- **AC-5** -- IF the probe route refuses the token as invalid, expired or revoked, or because a
  session gate is open (MFA pending, password change required, factor enrolment required, or
  notification address required), including for a token
  stored by an earlier run, THEN THE ANALYST BUILD SHALL treat the user as signed out and name the
  gate. IF the engine cannot be reached, or answers with any other 403, a 429 or a 5xx, THEN it SHALL
  show the read-only banner and SHALL NOT sign the user out (spec FR-6).
  -> editor test *gated session* (path open)
- **AC-6** -- THE ANALYST BUILD SHALL pass the row-contract version on every `lens` call, and IF the
  engine command rejects it, THEN it SHALL show the refusal and SHALL NOT retry.
  -> editor test *explicit contract* (path open)
- **AC-7** -- THE ANALYST BUILD SHALL never pass `--show-phi`, and Test SHALL accept only a generator
  spec, never a file or pasted message.
  -> editor test *Test argv* (path open)
- **AC-8** -- THE ANALYST BUILD SHALL never push to the config repository's default branch.
  -> editor test *submit targets a review branch* (path open)
- **AC-9** -- WHERE a site turns on the repository check, THE CHECK SHALL fail a change that is not
  Steps-only unless a `code:edit` reviewer approved its head commit, and SHALL pass an ordinary Steps
  edit and each sanctioned generated shape (spec FR-41).
  -> repository-check test (path set with the command) and spike S-4
- **AC-10** -- THE ANALYST BUILD SHALL contain no `@theia/plugin-ext`, terminal, task, debug, SCM or
  AI package. It SHALL contain `@theia/preferences` and `@theia/userstorage`, and the test SHALL
  expect `@theia/markers`, `@theia/outline-view` and `@theia/variable-resolver`, which come in with
  them (D3).
  -> editor build test *analyst package set* (path open)
- **AC-11** -- WHEN the lens refuses an edit, THE ANALYST BUILD SHALL show the refusal on the step it
  concerns, in the Steps panel.
  -> editor test *refusal on the step* (path open)
- **AC-12** -- IF a delete or move in the analyst build would break the structure rule of ADR 0076
  Amendment G, G.6, THEN it SHALL refuse it.
  -> editor test *block with code is fixed* (path open)
- **AC-13** -- WHEN the default branch's tip is not an ancestor of the review branch's head (spec
  FR-39), THE ANALYST BUILD SHALL commit first, then update the review branch from the default branch
  by a merge, then run `messagefoundry check`, before it pushes (spec FR-34). It SHALL push nothing
  while any of those steps fails, including a conflict (AC-14) or a missing git or credential
  (AC-15).
  -> editor test *stale base* (path open)
- **AC-14** -- IF a merge conflicts, THEN THE ANALYST BUILD SHALL push nothing and say "ask a
  developer".
  -> editor test *conflict* (path open)
- **AC-15** -- IF git or its credential is missing, THEN THE ANALYST BUILD SHALL push nothing and say
  which is missing.
  -> editor test *missing credential* (path open)
- **AC-16** -- THE ANALYST BUILD SHALL show every message in the Steps panel; a scripted walk of its
  actions SHALL find no pop-up notification. A route row SHALL list its handler names (`Unrouted` for
  an unrouted return), and each header SHALL read "Handler: name" or "Router: name".
  -> editor test *no toast* and *row labels* (path open)
- **AC-17** -- No message the analyst build shows SHALL contain "code view", "View as Code", Python
  source, a traceback, or a function or variable name from the code other than a component name,
  outside the "details" toggle.
  Component names (handler, router, connection, code set) are allowed.
  -> editor test *plain messages* (path open)
- **AC-18** -- WHEN a field is dropped on a path parameter, THE ANALYST BUILD SHALL issue a
  `set_params` edit byte-identical to typing that path; WHEN dropped elsewhere, it SHALL write
  nothing.
  -> editor test *drag equals typing* (path open)
- **AC-19** -- A keyboard-only walk SHALL reach every analyst action, and an automated accessibility
  check of the analyst build SHALL pass.
  -> editor test *keyboard walk* (path open)

## Options considered

1. **Theia desktop app, analyst and developer builds, role check plus optional repository check.**
   **CHOSEN.** It gives analysts the simpler layout the owner asked for, needs no server, and keeps
   token custody on each user's own machine. Its control is honest about its limit (D5) and offers the
   stronger check as an option (D7).
2. **Hosted Theia with a read-only workspace mount and a server-side edit broker** (the 2026-10-02
   design). **Deferred** to a later phase by owner ruling 2. It is the only design on record that
   enforces the Steps limit inside the editing session. Its costs are a gateway, per-user sandboxes,
   central custody of engine tokens, and the review findings that spec Appendix A carries to the
   hosted ADR.
3. **An analyst build that runs the `ide/` extension under `@theia/plugin-ext`, filtered.** Rejected.
   It saves the port, but keeps a VS Code API surface whose every route to a text editor would have
   to be found and kept closed across Theia releases (review R6; spec 11.1).
4. **Per-user limits in the developer build.** Rejected (D-A). They would make the developer build
   weaker than VS Code with `ide/` while stopping nobody, because both are other tools on the same
   disk. The analyst build is the one capped build.
5. **VS Code plus `ide/` for analysts too.** Rejected for analysts on the owner's purpose: VS Code's
   layout suits programmers, and VS Code cannot remove built-in commands per user. It stays a
   supported choice for developers (ruling 4).
6. **A Steps editor inside the web console at `/ui`.** Rejected. Re-weighed against option 1 (review
   R23):

   | | Option 1, Theia desktop | Option 6, web console |
   |---|---|---|
   | Simpler for analysts | Yes | Yes |
   | Server-side role check | No (D5) | Yes, engine RBAC on each route |
   | Where edits land | The analyst's git working copy, then review | The engine would have to write and push git, which it does not do today |
   | Authoring on the operator console | No | Yes. The console is the operator UI (CLAUDE.md section 2), and this would add authoring and git writes to it |
   | PHI host | Not involved | The console runs on the engine host, beside the store |
   | Toolkit split (ADR 0201) | `lens` stays toolkit-tier on the analyst's machine | Pulls authoring tooling back into the engine's served app |
   | Steps view rebuild | Native Theia port | A second port, in a different stack |
   | Developer level | Developer build, or VS Code | Nothing; developers stay on VS Code |

   Its one real advantage, a server-side check, is outweighed by putting git writes and authoring on
   the PHI host.
7. **Make the repository check mandatory** (the first review's strongest alternative, R8). Not
   adopted: the owner ruled it optional (ruling 3). The project still ships it (D7).
8. **Theia Cloud on Kubernetes.** **Deferred** with the hosted phase. It already provides session
   lifecycle, timeouts, volumes and a per-session auth proxy. It would still need an engine-login
   bridge and the broker, and it needs Kubernetes while the engine's primary target is a Windows
   service (review R31).

## Consequences

**Positive** -- Analysts get an editor with one job. Nothing new runs on a server. Each token stays on
its user's machine. The engine API changes are one permission and one built-in role, plus the
generator-spec input to `dryrun` and, only if no existing route fits, a start-up probe route. A
site that needs the Steps limit to hold against other tools can turn on the repository check, set up
as spec section 5.4 says, without the hosted design.

**Negative / risks** -- The Steps view must be ported to a native Theia extension and then kept in
step with `ide/` (spec section 11). Without the repository check, the Steps limit holds only for
analysts who use the analyst build as intended; with it, it holds only as far as spec section 5.4 is
set up. A Steps-only change can still redirect a send, run a literal lookup, raise or filter (spec
5.2), so the site's ordinary review stays the safeguard for those. The `code:edit` reviewer group is
kept in step with engine roles by hand. Until the R1 fix and typed-only mode land, the analyst build
cannot ship.

**Out of scope** -- Listed once, in spec section 14.

## To resolve on acceptance

- [ ] The R1 fix and typed-only mode land in `messagefoundry/lens.py`, with the four payloads as
      refusal tests (D6).
- [ ] Spikes S-1 to S-4 in the specification, section 17, all pass. Spec section 16 is the test
      strategy.
- [ ] ADR 0076 Amendment G accepted by the owner.
- [ ] The start-up probe route, an implementation detail settled at build (spec section 15).
