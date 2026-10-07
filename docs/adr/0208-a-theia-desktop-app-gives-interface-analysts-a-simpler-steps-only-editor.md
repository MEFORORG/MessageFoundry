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

> Deployment status (CLAUDE.md section 0): MessageFoundry has no deployed instances. Every statement
> about analysts and sites describes what a deploying site *would* run.

---

## Context

### The ask

Interface analysts who do not write Python need a simpler editor than VS Code. They should be able to
edit a Router or Handler through typed Steps rows, and no more. Developers keep full Python.

The owner's drafts of 2026-10-02 proposed a hosted Theia server that enforced this on the server. A
four-lens review of those drafts (2026-10-07; 41 of 44 raw findings survived adversarial
verification, merged into R1 to R34) returned "rework before acceptance". The owner then ruled, on
2026-10-07:

1. Theia exists to give low-code analysts a simpler interface than VS Code. Enforcement is not the
   motivation.
2. A desktop app comes first. A hosted, browser version comes later.
3. The editor's role-based check is the **primary** control limiting analysts to typed Steps edits. A
   repository-side check is an **optional** control a site can turn on: CI runs `lens parse` before
   and after and fails if a `code` row changed, plus a required review from a `code:edit` holder.
4. Developers keep the full IDE layout in the Theia build, with a Steps / Split / Code switch. They
   may also stay on VS Code and `ide/`.

This ADR rewrites the drafts on those rulings. The specification carries the detail and a disposition
for every review finding.

### What already exists

- **The Steps view is built and edits**, in `ide/` (ADR 0076 phase 3; ADRs 0103, 0106 and 0108).
  Every edit is a row-scoped splice computed by `lens rewrite`.
- **`lens rewrite` does not yet limit an edit to typed rows.** The review probed it and found that
  `paste_block`, a raw `if` test and `{"expr": ...}` values all write arbitrary Python (finding R1).
  The drafts' claim that a typed-row edit cannot inject Python is false today. A fix is being built
  separately; this ADR does not claim it is done.
- **The roles half-exist.** `Role.CODING` holds `code:edit`, which no endpoint enforces. No permission
  describes the Steps level.
- **Promote ships no files.** For a remote engine, the reload reads the engine's own `--config`
  directory, filled out of band (`ide/src/promote.ts`, the comment above `configDirForTarget`).

### The premise behind the primary control, tested

On a desktop install the `.py` files sit on the analyst's own disk. A role check inside the editor
decides what the editor offers. It cannot stop the analyst from editing the file with another tool
and committing it. No engine route sees the edit before it reaches the repository, because promote
ships no files.

The review and the drafts were checked for a place the editor's check is enforced where an analyst
cannot bypass it. There is none for the desktop. The drafts' only such design was the hosted read-only
mount with a server-side broker, which this phase does not build.

So, stated plainly per SDS-3.7: **the primary control is a guardrail for analysts who use the editor
as intended. The control that holds against a deliberate or tool-assisted change is the optional
repository check.** Spec section 5 sets this out and says when a site should turn the check on.

## Decision

**Ship a Theia desktop app in two builds. The analyst build shows a native Steps extension and little
else. The developer build is a full IDE with a Steps / Split / Code switch. The editor reads the
user's engine permissions and offers only the editing they allow. A site may add a repository check
that holds the Steps limit whatever tool made the change.**

- **D1 -- Purpose.** The analyst build exists to be simpler than VS Code for an analyst. Enforcement
  is described honestly in D5 and is not the reason to build it.
- **D2 -- Desktop first.** Both builds are Electron desktop apps, Windows first. A hosted version
  needs its own ADR. The 2026-10-02 hosted design is its starting point, and spec Appendix A marks the
  review findings that ADR inherits.
- **D3 -- Two builds; the analyst build uses a native Steps extension.** `@theia/plugin-ext`, which
  runs VS Code extensions, depends on the terminal, tasks, debug, SCM, Monaco and AI packages, so an
  analyst build that ran `ide/` as a plugin could not leave them out (review R6). The analyst build
  therefore ports the Steps view to a native Theia extension. That port is the main cost of this
  decision (spec section 9). The developer build may run either.
- **D4 -- New permission `code:steps`.** It is added to the permission catalog. `Coding` gains it.
  `code:edit` means the Code level and implies the Steps level. An *Analyst* role is a custom role
  under ADR 0045 until the owner decides otherwise. It is the only engine API change. The other engine
  changes are the separately built R1 fix (D6) and the repository-check command (D7); spec section 11
  lists them.
- **D5 -- The role check is the primary control, and it is a guardrail.** The editor signs in
  through the engine, finishes MFA and any required password change before it stores a token or reads
  permissions, and on start-up proves a stored token on a route that is not MFA-exempt (review R2).
  It re-reads them before each save rather than on a timer (review R3), and turns on only the editing
  they allow. It stops an analyst changing Python through the editor. It does not stop a
  change made with another tool. In the analyst build it also refuses a delete or move of a control
  block that holds a `code` row or an unrecognized test, which `ide/` allows today (Amendment G).
- **D6 -- R1 is a precondition.** The analyst build does not ship until the lens refuses
  `paste_block`, a raw control test and any `{expr}` value at the Steps level, with the four R1
  payloads as refusal tests. The analyst build also offers none of those operations itself.
- **D7 -- The repository check is optional, and the project ships it.** A CI step decides whether a
  change is Steps-only: only existing Router or Handler modules changed; no byte changed outside the
  def bodies, which `lens parse` does not partition; the ordered hand-written source in each body
  (`code` rows and unrecognized control tests, compared by content, not line) is unchanged; every
  new or changed typed parameter is a literal or a template; and every `send` and `route` row matches
  base or is fully literal, since the lens projects a computed `Send` argument or a dynamic route with
  no typed parameters. A Steps-only change passes. Any other change passes only
  with an approval from a review group whose members hold `code:edit`, behind the site's branch
  protection. That reading of ruling 3 is this ADR's, not a ruling (spec FR-27a). The
  config-repository template (ADR 0017) carries the step commented out. Spec section 5.4 says when to
  turn it on.
- **D8 -- The analyst build drops three ADR 0076 guardrails, for that build only.** No *Reopen With:
  Python*, no text-editor fallback on a parse failure, and the Steps view is the default editor rather
  than opt-in. ADR 0076 Amendment G records this. The developer build keeps every guardrail for a
  `code:edit` holder, and applies the analyst limits to a user without it.
- **D9 -- Edits save through the document model.** As `ide/` does today, so undo, dirty state and
  hot-exit keep working. There is no server-side broker in this phase.
- **D10 -- Analyst Test never reveals PHI.** The analyst build runs Test against synthetic samples
  without `--show-phi` and shows results in place. It has no Test Bench (review R13).

**What this must not break:** the `.py` stays the only artifact and the only execution path, with no
stored Steps model; routers and transforms stay pure; the web console stays the sole operator console
(the editor authors and does not monitor); no PHI reaches the editor (synthetic samples, redaction
on); promote stays `POST /config/reload` with step-up and the site's dual control unchanged.

## Acceptance Criteria

> Proposed tests. None exists yet. The editor's own tests get a path when its source location is
> decided (the source-location item under To resolve), so those lines name the test and leave the
> path open.

- **AC-1** -- THE SYSTEM SHALL expose `code:steps` in the permission catalog, grant it to `Coding`,
  and allow it in a custom role.
  -> `tests/test_custom_roles.py::test_code_steps_permission_catalog_and_roles`
- **AC-2** -- WHEN the signed-in user holds `code:edit`, THE EDITOR SHALL offer the Code level; WHEN
  the user holds `code:steps` without `code:edit`, the Steps level; OTHERWISE a read-only Steps view.
  -> editor test *level selection* (path open)
- **AC-3** -- IF a Steps-level edit is a `paste_block`, a raw control test, or carries an `{expr}`
  value anywhere, THEN `lens rewrite` SHALL refuse it and write
  nothing.
  -> the lens refusal tests the R1 fix adds (being built separately; path set when it lands)
- **AC-4** -- THE ANALYST BUILD SHALL offer no route that opens a `.py` file in a text editor, and
  WHEN a file fails `lens parse` it SHALL show a read-only notice instead.
  -> editor test *no text route* and spike S-2 (path open)
- **AC-5** -- IF the engine session has proven only the password (MFA pending, or a password change
  required), including a token stored by an earlier run, THEN THE EDITOR SHALL treat the user as
  signed out.
  -> editor test *password-only session* (path open)
- **AC-6** -- THE EDITOR SHALL pass the row-contract version on every `lens` call, and IF the engine
  command rejects it, THEN THE EDITOR SHALL show the refusal and SHALL NOT retry at the default.
  -> editor test *explicit contract* (path open)
- **AC-7** -- THE ANALYST BUILD SHALL never pass `--show-phi` to `dryrun`.
  -> editor test *Test argv* (path open)
- **AC-8** -- THE ANALYST BUILD SHALL never push to the config repository's default branch.
  -> editor test *submit targets a review branch* (path open)
- **AC-9** -- WHERE a site turns on the repository check, THE CHECK SHALL fail a change that is not
  Steps-only (D7) unless a `code:edit` reviewer approved its head, and SHALL pass an ordinary Steps
  edit, including an insert above a `code` row.
  -> repository-check test (path set with the command, D7) and spike S-4
- **AC-10** -- THE ANALYST BUILD SHALL contain no `@theia/plugin-ext`, terminal, task, debug, SCM or
  AI package.
  -> editor build test *analyst package set* (path open)
- **AC-11** -- WHEN the lens refuses an edit, THE EDITOR SHALL show the refusal on the step it
  concerns.
  -> editor test *refusal on the step* (path open)
- **AC-12** -- IF an analyst-build delete or move targets a control block that contains a `code` row
  or has an unrecognized test, THEN THE EDITOR SHALL refuse it.
  -> editor test *block with code is fixed* (path open)

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
3. **An analyst build that runs the `ide/` extension under `@theia/plugin-ext`.** Rejected. It saves
   the port but cannot leave out the terminal, tasks, debug, SCM, Monaco or AI (review R6), so the
   analyst build would not be simpler.
4. **VS Code plus `ide/` for analysts too, gated by role.** Rejected for analysts on the owner's
   purpose: VS Code's layout suits programmers, and VS Code cannot remove built-in commands per user.
   It stays a supported choice for developers (ruling 4).
5. **A Steps editor inside the web console at `/ui`.** Rejected. Re-weighed against option 1 (review
   R23):

   | | Option 1, Theia desktop | Option 5, web console |
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
6. **Make the repository check mandatory** (the review's strongest alternative, R8). Not adopted: the
   owner ruled it optional (ruling 3). The project still ships it (D7), and spec section 5.4 tells a
   site when it needs it.
7. **Theia Cloud on Kubernetes.** **Deferred** with the hosted phase. It already provides session
   lifecycle, timeouts, volumes and a per-session auth proxy. It would still need an engine-login
   bridge and the broker, and it needs Kubernetes while the engine's primary target is a Windows
   service (review R31).

## Consequences

**Positive** -- Analysts get an editor with one job. Nothing new runs on a server. Each token stays on
its user's machine. The only engine API change is one permission. A site that needs a hard boundary
can turn one on without the hosted design.

**Negative / risks** -- The Steps view must be ported to a native Theia extension and then kept in
step with `ide/` (spec section 9). Without the repository check, the Steps limit holds only for
analysts who use the editor as intended. The required-review half depends on a git-host group kept in
step with engine roles by hand. Licensing between EPL-2.0 Theia and AGPL-3.0 MessageFoundry needs
review. Until R1 is fixed, the analyst build cannot ship.

**Out of scope** -- Listed once, in spec section 11.

## To resolve on acceptance

- [ ] R1 fixed in `messagefoundry/lens.py`, with the four payloads as refusal tests (D6).
- [ ] Spikes S-1 to S-4 in the specification, section 13, all pass.
- [ ] ADR 0076 Amendment G accepted by the owner.
- [ ] Where the editor's source lives: a tree in this repository, or its own repository.
- [ ] *Analyst* as a built-in role, or a custom-role recipe.
- [ ] Licence for the native extension and the builds (owner legal review).
- [ ] Owner confirms the repository check's reading of ruling 3 (spec FR-27a, question 7).
- [ ] The start-up route for proving a stored token (spec question 6); an engine route if none fits.
- [ ] Owner confirms that drag-a-field-onto-a-step is parameter entry inside the BACKLOG #26
      carve-out (spec section 12, question 4).
