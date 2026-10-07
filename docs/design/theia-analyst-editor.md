# Specification: a Theia desktop editor for interface analysts

- **Status:** Proposed. Design only; no code exists. Accepting it needs the owner.
- **Date:** 2026-10-07
- **Decision record:**
  [ADR 0208](../adr/0208-a-theia-desktop-app-gives-interface-analysts-a-simpler-steps-only-editor.md).
  The guardrail changes are [ADR 0076](../adr/0076-typed-action-vocabulary-action-list-lens.md),
  Amendment G.
- **Replaces:** the owner's drafts of 2026-10-02, *"Hosted Theia authoring with two editing levels"*
  (ADR and spec, never committed). Appendix B lists what changed and why.

> Deployment status (CLAUDE.md section 0): MessageFoundry has no deployed instances. Every statement
> below about analysts, sites and data describes what a deploying site *would* run.

---

## 1. Purpose

Interface analysts who do not write Python need a simpler editor than VS Code. VS Code's layout suits
programmers. An analyst who opens it meets a file tree, a terminal, a debugger, extensions, git and a
Python editor before they reach the one view they need: the Steps view (ADR 0076).

This spec describes a desktop app, built on Eclipse Theia, whose analyst layout shows the Steps view
and little else. Developers get the full IDE layout in the same product, or keep using VS Code with
the `ide/` extension.

**Enforcement is not the motivation** (owner ruling 2026-10-07). The 2026-10-02 drafts argued for
hosting because a desktop editor cannot stop a user from editing their own disk. That argument is
correct, and section 5 keeps it. But the reason to build this is the simpler interface.

The `.py` file stays the only artifact and the only execution path (ADR 0076 section 2). The analyst
layout is a view over that file. It is not a second authoring format.

## 2. Owner rulings this spec is built on

Given by the owner on 2026-10-07.

1. **Purpose.** Theia exists to give low-code analysts a simpler interface than VS Code.
   Enforcement is not the motivation.
2. **Desktop first.** A desktop app ships first. A hosted, browser version comes later and is out of
   scope here.
3. **Two controls.** The editor's role-based check is the **primary** control that limits analysts to
   typed Steps edits. A repository-side check is an **optional** control an implementing site can
   turn on: CI runs `lens parse` before and after a change and fails if a `code` row changed, and a
   required review comes from a `code:edit` holder.
4. **Developers keep the full IDE.** The Theia developer build has a Steps / Split / Code switch.
   Developers may also stay on VS Code and `ide/`.

## 3. Terms

- **Analyst build.** The Theia desktop application for analysts. It shows the Steps view, a sample
  message panel, and *Submit for review*. Section 8 lists what it leaves out.
- **Developer build.** The Theia desktop application for developers. A full IDE layout with a
  Steps / Split / Code switch above each Router or Handler.
- **Steps level.** Editing typed rows only, through the Steps view. Granted by `code:steps`.
- **Code level.** Editing any file in the config repository. Granted by `code:edit`.
- **Role check.** The editor reads the signed-in user's permissions from the engine and turns on
  only the editing that those permissions allow.
- **Repository check.** The optional CI step plus required review described in section 6.7.
- **Config repository.** The site's git repository of Routers, Handlers and connections (the "HC
  config repo" of ADR 0017).

## 4. Permissions and roles

The engine stays the identity and role authority. The editor holds no user database.

| Permission | Status today | Meaning under this spec |
|---|---|---|
| `code:steps` | **New** (the only engine API change in this phase; section 11 lists the others) | Edit typed rows through the Steps view. Grants the Steps level. |
| `code:edit` | Declared in `messagefoundry/auth/permissions.py`; no endpoint enforces it | Grants the Code level. Implies everything `code:steps` allows. |
| `config:validate` | Declared; no endpoint enforces it (`docs/SECURITY.md`, permission table) | Shows Validate in the editor. The gate is advisory: the editor runs validate locally. |
| `config:deploy` | Enforced on `POST /config/reload` | Promote. Unchanged. The analyst build offers no promote. |
| `ai:assist` | Reported by `GET /ai/policy`; the IDE honours it | Unused in this phase. Both builds leave AI out. |

- The built-in `Coding` role gains `code:steps` beside the `code:edit` it has.
- An analyst gets the Steps level through a custom role (ADR 0045). An example *Analyst* role is
  `monitoring:read` + `code:steps` + `config:validate`. Whether *Analyst* becomes a built-in role is
  open question 1.
- **Level selection.** `code:edit` gives the Code level. `code:steps` without `code:edit` gives the
  Steps level. Neither, or no sign-in, gives a read-only Steps view.

## 5. What each control does, and what it does not

This section is the one a site security reviewer should read first. Each control is described by
what a reader can rely on it to stop (SDS-3.7: a control must not rest on a false premise).

### 5.1 The premise, tested

On a desktop install the analyst's working copy of the config repository is on their own disk. The
`.py` files are ordinary files that the analyst's operating-system account can write. So:

- The role check runs inside the editor. It decides what **the editor** offers.
- It cannot stop a write that does not go through the editor: Notepad, another IDE, a script, or
  `git` on the command line.
- Nothing on the engine side checks these files at save time. A promote to a remote engine sends no
  files: the engine reloads from its own `--config` directory, which a site fills out of band
  (`ide/src/promote.ts`, the comment above `configDirForTarget`). So no remote engine sees an
  analyst's edit before it reaches the repository. (A local engine reloads straight from the working
  copy's path, with no repository step. The analyst build offers no promote, so it does not take that
  path.)

This reading was checked against the 2026-10-02 drafts and the review. Neither shows the Steps limit
enforced anywhere an analyst on a desktop install cannot bypass. The drafts' only such design was the
hosted read-only mount plus server-side broker, which the desktop phase does not have.

### 5.2 The two controls side by side

| | Role check in the editor (primary) | Repository check (optional) |
|---|---|---|
| **Where it runs** | In the analyst's editor | In the config repository's CI and branch protection |
| **Stops** | An analyst changing Python **through the editor**: by accident, by using an editor feature, or by an edit the lens would otherwise accept | A change that is not Steps-only (FR-27) reaching the protected branch without a `code:edit` holder's approval, **whatever tool made it** |
| **Does not stop** | An analyst who edits the `.py` file with any other tool and commits it | A change a `code:edit` holder approves. A push straight to a branch that branch protection leaves open. A Steps-only change that is wrong but well-formed: that is the review's job |
| **Depends on** | R1 fixed (section 5.3); the engine's permission catalog; the session being fully signed in (FR-2) | The site's git host enforcing branch protection and required review; a mapping from engine `code:edit` holders to a git-host reviewer group, kept by hand |
| **Kind of control** | A guardrail for analysts who use the editor as intended | A boundary that holds against a deliberate or tool-assisted change |

What already gates what **runs**, under both: a change reaches a running engine only when someone with
`config:deploy` reloads it, under the existing step-up and the site's `[approvals]` dual control. That
controls who deploys. It does not check whether a Steps-level author changed Python.

### 5.3 R1 is a precondition, not a solved problem

The review found that `lens rewrite` accepts edits that write arbitrary Python: `paste_block`, a raw
`if` test, and `{"expr": ...}` values on an inserted row or a send row's `to` (review finding R1). A
fix to `messagefoundry/lens.py` is being built separately. Until it lands, the role check would not
hold even inside the editor, because a typed-row edit could carry code.

The analyst build must therefore not ship before:

- the lens offers a Steps-level operation set that refuses `paste_block`, a raw test, and any `{expr}`
  value (FR-9); and
- the four R1 payloads are refusal tests in the engine suite (AC in the ADR).

### 5.4 When a site should turn on the repository check

Turn it on when any of these holds:

1. The site needs the Steps limit to hold against an analyst acting deliberately, or against a tool
   other than the editor. Change control or audit rules often ask for this.
2. Analysts can push to a branch that reaches the engine's config without a developer's review.
3. Analysts and developers share one git-host group, so review alone does not separate them.
4. The site cannot rule out other editors on analyst machines.

A site where every analyst change already goes through a developer's pull-request review has the
review half already. The CI half then adds a check the reviewer cannot miss.

**Without the repository check, the Steps limit holds only for analysts who use the editor as
intended.** A site that turns it off accepts that.

## 6. Functional requirements

Written in EARS form, like the ADR's acceptance criteria.

### 6.1 Sign-in and the role check

- **FR-1.** WHEN a user signs in, THE EDITOR SHALL sign in through the engine's `POST /auth/login`
  (local or directory account), finish `POST /auth/mfa-verify` when the response asks for it, and
  finish any required password change.
- **FR-2.** THE EDITOR SHALL choose the level only after FR-1 is complete. `GET /auth/me` alone does
  not prove it: that route is exempt from the MFA gate and the must-change gate and returns every
  permission with no pending flag (review R2; `messagefoundry/api/security.py`, `_MFA_EXEMPT_ROUTES`
  and `_MUST_CHANGE_EXEMPT_PATHS`). So the editor stores a token only once FR-1 is complete. WHEN it
  starts with a stored token, it SHALL first call a route that is on neither exempt list and that
  every editor user may call; the route is chosen at build, and if none fits, the engine needs one
  (open question 6). IF the session has proven only the password, THEN THE EDITOR SHALL treat the
  user as signed out.
- **FR-3.** WHILE no session is signed in, THE EDITOR SHALL show the Steps view read-only.
- **FR-4.** THE EDITOR SHALL re-read the user's permissions before each save and SHALL NOT poll them
  on a timer. A save is real user activity, so moving the engine's idle clock on a save is correct. A
  timer poll would keep an abandoned session alive (review R3).
- **FR-5.** IF a permission read fails or the engine session has ended, THEN THE EDITOR SHALL keep
  the unsaved edit in the buffer, refuse the save, and ask the user to sign in again.
- **FR-6.** THE EDITOR SHALL keep the engine token in the operating system's credential store, as the
  `ide/` extension keeps it in `SecretStorage` today.

### 6.2 The analyst build's layout

- **FR-7.** THE ANALYST BUILD SHALL open a Router or Handler module in the Steps view. It SHALL offer
  no route that opens a `.py` file in a text editor (Amendment G, G.1).
- **FR-8.** WHEN a file fails `lens parse`, THE ANALYST BUILD SHALL show a read-only notice that a
  developer must fix the file, instead of falling back to a text editor (Amendment G).
- **FR-9.** THE ANALYST BUILD SHALL offer only the Steps-level operations: set a typed parameter,
  insert a typed row from the palette, delete, move, and edit a note. It SHALL NOT offer
  `paste_block`, a raw control test, or an `{expr}` value. `code` rows and control tests stay
  read-only. (This is the editor half of R1. The lens half is section 5.3.)
- **FR-9a.** IF a delete or move targets an `if`/`for` block that contains a `code` row or has an
  unrecognized test, THEN THE ANALYST BUILD SHALL refuse it. Today `ide/` deletes or moves a whole
  block from its header row, nested `code` rows included (`isRowDeletable` and `isRowMovable` in
  `ide/src/stepsModel.ts`), which would remove or reorder hand-written Python (Amendment G, AC-G5).
- **FR-10.** THE ANALYST BUILD SHALL show connections and code sets read-only. Their editors write
  through `upsert` commands (`ide/src/connectionEditor.ts`, `ide/src/codeSetEditor.ts`), which are
  Code-level edits (review R27). An analyst who needs a connection or code-set change asks a
  developer.

### 6.3 Editing and saving

- **FR-11.** THE EDITOR SHALL apply each row edit through the editor's document model, as `ide/` does
  with a `WorkspaceEdit` today (`ide/src/stepsView.ts`, file header). Undo, redo, dirty state and
  hot-exit then work as they do in `ide/`. A desktop save writes the local file. There is no broker in
  this phase, so review R7's broker editing model does not arise (it is carried to the hosted phase).
- **FR-12.** THE EDITOR SHALL pass the row-contract version explicitly on every `lens parse` and
  `lens rewrite` call, and SHALL refuse with a visible message when the engine command rejects that
  version. It SHALL NOT silently retry at the default contract, because contract 1 does not project
  `@router` defs (review R14; `ide/src/cli.ts` retries today).
- **FR-13.** THE EDITOR SHALL run the `lens` command from the pinned `messagefoundry` install. `lens`
  is toolkit-tier by ADR 0201 but is still registered on the `messagefoundry` command
  (`messagefoundry/__main__.py`), not on `messagefoundry-toolkit` (review R26).
- **FR-14.** WHEN the lens refuses an edit, THE EDITOR SHALL show the refusal on the step it was made
  on, not in a pop-up notification (section 7.1, gap 3).

### 6.4 Test and live values

- **FR-15.** THE ANALYST BUILD SHALL run Test with `dryrun` against synthetic samples and SHALL NOT
  pass `--show-phi`. Today the `ide/` Steps view's live values never pass it, but its Test button opens
  the Test Bench, which passes `--show-phi` on every test-case run (`ide/src/testBench.ts`; review
  R13). The
  analyst build has no Test Bench.
- **FR-16.** THE ANALYST BUILD SHALL show Test results in place: the sample message before and after
  the selected step, with changed values marked (section 7.2, practice 4).
- **FR-17.** Live values stay save-gated, as ADR 0076 Amendment F requires: a change-triggered
  re-projection attaches no live values.

### 6.5 Submit for review

- **FR-18.** WHEN an analyst selects *Submit for review*, THE ANALYST BUILD SHALL commit the changed
  files and push them to a review branch (`analyst/<user>/<topic>`), using the git credential already
  on the analyst's machine. Analysts do not type git commands.
- **FR-19.** THE ANALYST BUILD SHALL never push to the config repository's default branch.
- **FR-20.** THE SUBMIT SCREEN SHALL show the change as steps (added, changed, removed), with the
  Python diff folded below for the reviewer, and the Test results.
- **FR-21.** The commit author is the user's engine identity. Git authorship is free text, so it is a
  record, not proof of who made the change (review R22). The repository check and the git host's own
  push log are what a reviewer relies on.

### 6.6 The developer build

- **FR-22.** THE DEVELOPER BUILD SHALL offer a Steps / Split / Code switch above each Router or
  Handler, remembered per file.
- **FR-23.** In Split, selecting a step SHALL highlight its lines, and selecting a line SHALL select
  its step.
- **FR-24.** In Code, the developer build SHALL show a small steps outline beside the text and a
  *View as Steps* link above each `@handler` and `@router` def.
- **FR-25.** WHILE the user lacks `code:edit`, THE DEVELOPER BUILD SHALL offer only the Steps layout,
  with the analyst build's limits, including no route to a text editor for `.py` (Amendment G,
  AC-G1, AC-G2 and AC-G5).
- **FR-26.** For a `code:edit` holder, the developer build keeps every ADR 0076 guardrail,
  including *Reopen With: Python* and the text-editor fallback. It provides the Python editor with an open language server, git, a
  terminal and the debugger. Pylance is licensed for Microsoft products only, so the choice is an open
  server such as basedpyright (spike S-1).

### 6.7 The optional repository check

- **FR-27.** THE PROJECT SHALL ship a check a site can add to its config repository's CI. It decides
  whether a change is **Steps-only**. A change is Steps-only when all of these hold:
  1. Every changed path is an existing Router or Handler module. A new file, a `_`-prefixed helper,
     `connections.toml`, a code set or an environment file is not Steps-only.
  2. Outside the `@handler` and `@router` def bodies, the module's bytes are unchanged. `lens parse`
     partitions def bodies only (ADR 0076 A.5, *"No module scope"*), so imports, module-level code and
     other functions are compared as bytes.
  3. Inside each def body, the ordered sequence of hand-written source is unchanged: every `code` row's
     text, and the `test_src` of every control row the lens marks unrecognized (`lens.py` emits an
     unbounded `if` or `for` that way, not as a `code` row), compared by content and nesting, never by
     line number. A change from one recognized test to another passes: a recognized test stays inside
     the bounded grammar of ADR 0076 section 4, so it carries no arbitrary code. Only the analyst build's
     UI keeps tests read-only (FR-9). An insert above a `code` row therefore passes, and a moved,
     added, removed or edited `code` row fails.
  4. Every typed parameter that is new or changed between base and head is a literal or a template.
     A developer-written dynamic parameter the change leaves alone does not fail it.
  5. Every `send` and `route` row either matches base by content or is fully literal: one literal
     destination per `Send`, the message argument a plain name, no `SetState` expression, and a
     route's `handlers` non-empty or `unrouted`. The lens projects a `Send` with a computed
     argument, or a dynamic route, as an ordinary row with no typed parameters (`_send_outbounds` and
     `_route_row` in `messagefoundry/lens.py`), so items 3 and 4 alone would miss it.
  The command's name and home are settled at build (ADR 0201 decides the tier).
- **FR-27a.** Owner ruling 3 says the check *"fails if a `code` row changed"*. Read literally, it
  would fail every developer change too. This spec reads it as: the check passes a Steps-only change,
  and passes any other change only when a member of the `code:edit` reviewer group (FR-29) has
  approved the head commit. The reading is the author's, not a ruling (open question 7).
- **FR-28.** The check SHALL classify each of the four R1 payloads as not Steps-only, and SHALL pass an
  ordinary Steps edit, including an insert above a `code` row (spike S-4).
- **FR-29.** THE PROJECT SHALL document the required-review half: branch protection on the default
  branch, plus a required review from a git-host group whose members hold `code:edit` in the engine.
  The project cannot keep that group in step with engine roles; the site does it by hand.
- **FR-30.** The config-repository template of ADR 0017 SHALL carry the check as a commented-out CI
  step, so turning it on is one edit.

### 6.8 AI

- **FR-31.** Both builds leave out Theia AI packages and the `ide/` chat participant in this phase.
  A later AI feature must honour `GET /ai/policy` and `ai:assist` (`docs/AI.md`).

## 7. Analyst interface design

The design follows the owner's wireframes of 2026-10-07 (four artboards: analyst editor, add a step,
submit for review, developer build). The wireframes are a private artifact; this section records what
they decide.

### 7.1 Gaps in today's Steps view the analyst build fixes

Each was re-checked against `ide/` at `ddf350e1d0`.

| # | Gap today | Evidence | Analyst build |
|---|---|---|---|
| 1 | A route row does not show the handlers it routes to | `rowSubtitle` and `rowParams` in `ide/src/stepsModel.ts` have no `route` case, and the engine's route row carries `handlers` but no `params`, so the row renders its title only | The route row lists its handler names |
| 2 | An element's header does not say Handler or Router | `renderHandlerHtml` renders the def name and its line only, though the view model carries `role` | The header says Handler or Router |
| 3 | Refusals and warnings appear as pop-up notifications, not on the step | `ide/src/stepsView.ts` raises about 20 `show*Message` notifications. The one in-page hint found is the field picker's hold-back hint in `ide/media/stepsWebview.js` | The refusal shows on the step it concerns (FR-14) |
| 4 | Test opens a separate Test Bench panel | The `test` message runs `messagefoundry.openTestBench` (`ide/src/stepsView.ts`). Live values do show inline, but redacted and save-gated | Test results show in place (FR-16) |

Fixing gaps 1 and 2 in `ide/` too is cheap and would help VS Code users. That is a separate item.

### 7.2 Practices the design follows

From the research behind the wireframes (Power Query, MakeCode, InterSystems DTL, Mirth, n8n, SwiftUI
previews, Logic Apps, Blockly). Each row says whether this phase adopts it.

| # | Practice | Seen in | This phase |
|---|---|---|---|
| 1 | One text file; the visual view is a way of looking at it | Power Query, MakeCode, DTL, SwiftUI | **Adopted.** The `.py` stays the only artifact |
| 2 | Code the visual editor cannot show becomes a locked block | MakeCode grey blocks, DTL code action, Mirth JavaScript steps | **Adopted as today:** a read-only `code` row. Today a code row cannot be moved, and this phase keeps that |
| 3 | A comment above a step becomes its description | Power Query | **Not adopted.** ADR 0076 A.5 forbids attaching a comment to the following statement; that needs its own amendment and is gated on BACKLOG #1758 |
| 4 | Show the sample message after the selected step | Power Query, n8n, DTL test tool | **Adopted** (FR-16) |
| 5 | Drag a field from a message tree onto a step | Mirth | **Adopted as parameter entry only:** the drag fills a typed parameter, as the existing field picker does. It creates no mapping artifact and no canvas (Amendment G, G.3) |
| 6 | Show what a change does before it goes in | Power Query Online script-change review | **Adopted** (FR-20) |
| 7 | Code and visual side by side, with linked selection | SwiftUI previews | **Adopted in the developer build** (FR-23) |
| 8 | The visual view never quietly rewrites code it does not understand | Logic Apps and Power Query are known for this failure | **Already a rule:** ADR 0076 section 5's row-scoped splice and its byte-stability test |
| 9 | Full keyboard use from day one | Blockly | **Adopted.** Every analyst action reachable by keyboard, and screen-reader labels on rows |

The research found little on three questions: undo across both views, role-based views, and
templates. This phase takes one undo history on the text file (FR-11).

## 8. Build composition

Theia applications are assembled from npm packages at build time. A package left out of a build is
not in the shipped app.

| Capability | Analyst build | Developer build |
|---|---|---|
| Steps view | Native Theia extension | Native extension, or the `ide/` extension under `@theia/plugin-ext` |
| `@theia/plugin-ext` (VS Code extension host) | **No** (see 9.1) | Yes |
| Text editor for `.py` | No | Yes |
| Terminal, tasks, debugger | No | Yes |
| Git UI | No (*Submit for review* does the git work) | Yes, through the built-in `vscode.git` (`@theia/git` is deprecated, review R32) |
| Extension installation, Open VSX | No | Vendored at build time, pinned by content hash, with transitive packs resolved; no runtime registry access (review R21) |
| Theia AI | No | No (this phase) |
| File explorer | Feeds list only | Yes |

On a desktop the build split is about simplicity. It is not a security boundary: the analyst can
install other software. Test in either build runs `dryrun`, which executes the config modules on the
user's machine, as `ide/` does today (review R12). Section 5 says what the security controls are.

## 9. Reuse of the `ide/` extension, and the real cost

### 9.1 A native Steps extension is the real cost

The `ide/` Steps view is a VS Code extension. Theia runs VS Code extensions through
`@theia/plugin-ext`, and that package depends on the terminal, tasks, debug, SCM, Monaco and Theia AI
packages. Theia's build keeps transitive extensions (review R6, citing `@theia/plugin-ext` 1.76.0 and
Theia's extension-package collector). So an analyst build that runs `ide/` as a plugin cannot leave
those out.

The analyst build therefore needs a **native Theia extension** for the Steps view. That is the main
cost of this design:

- The engine half is shared: `lens parse`, `lens rewrite`, `lens schema` and `dryrun` stay engine
  commands, and the native extension calls them the way `ide/` does.
- The view-model and HTML code in `ide/src/stepsModel.ts` (about 3,500 lines) is mostly free of
  `vscode` imports and could become a shared package. Spike S-1 measures how much.
- The provider in `ide/src/stepsView.ts` (about 1,350 lines) and the webview script are written
  against `vscode.CustomTextEditorProvider` and the webview API. These are rewritten for Theia.
- The two Steps views must then stay in step. ADR 0076 already runs a differential test between the
  provider and the webview mirror (`ide/src/test/suite/steps-mirror.test.ts`); a third copy needs the
  same.

### 9.2 What changes from `ide/`, beyond the port

- The text-editor fallbacks (`fallBackToText`, the `openText` message, priority `option` in
  `ide/package.json`) are removed in the analyst build (review R20, Amendment G).
- Test runs in place and never passes `--show-phi` (FR-15).
- Sign-in moves from the extension's own flow to the editor's (FR-1, FR-6). Promote is not offered in
  the analyst build.
- The chat participant is left out; it needs `vscode.chat` and `vscode.lm`.

## 10. Non-functional requirements

- **Platform.** Windows desktop first, because a site's engine runs as a Windows service (ADR 0017,
  `docs/SERVICE.md`) and its analysts are most likely on Windows. Theia's Electron target also builds
  for macOS and Linux.
- **Version.** Pin one Theia version and record it with spike S-1 (review R33).
- **No PHI.** The editor works on config code and synthetic samples only. Test never passes
  `--show-phi` in the analyst build. ADR 0017's config-repository rules apply: no captured messages,
  no secrets.
- **Network.** The editor talks to the engine API over TLS with certificate verification, and to the
  site's git host. Nothing else.
- **Accessibility.** Keyboard use and screen-reader labels on every analyst action (practice 9).
- **Licensing.** Theia is `EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0`; MessageFoundry is
  AGPL-3.0 plus a commercial licence. The licence for the native extension and the builds needs the
  owner's legal review (open question 4). Two facts for that review: `CLA.md` grants a relicensing
  right, and `ide/` has no `LICENSE` file although its `package.json` says `SEE LICENSE IN LICENSE`.

## 11. Out of scope for this phase

- A hosted, browser-served editor. It needs its own ADR. Appendix A marks which review findings that
  ADR inherits.
- Steps-level editing of `connections.toml`, code sets, environments and `_`-prefixed helpers.
- Creating a new Router or Handler file at the Steps level.
- Promote from the analyst build.
- AI in either build.
- Theia Cloud.
- Any engine change beyond three: the `code:steps` permission, the separately built R1 fix to
  `messagefoundry/lens.py`, and the repository-check command (FR-27). A route for FR-2's start-up
  probe would be a fourth, only if no existing route fits (open question 6).

## 12. Open questions for the owner

1. Should *Analyst* be a built-in role, or a documented custom-role recipe?
2. Where does the editor's source live: a tree in this repository, or its own repository?
3. Which licence do the native extension and the builds carry? Needs legal review.
4. Is drag-a-field-onto-a-step (practice 5) inside the BACKLOG #26 carve-out? This spec reads it as
   parameter entry, like the existing field picker, so inside. The reading is the author's, not a
   ruling.
5. Should the repository check also ship as a pre-commit hook for sites that want an earlier
   warning? A hook runs on the analyst's machine, so it is advice, not a control.
6. Which route does the editor call at start-up to prove a stored token is fully signed in (FR-2)?
   If no existing route is both non-exempt and open to every editor user, the engine needs one.
7. Does the repository check read ruling 3 as FR-27a does: pass a Steps-only change, and pass any
   other change only with a `code:edit` reviewer's approval?

## 13. Spikes required before the ADR is accepted

| Spike | Question | Pass condition |
|---|---|---|
| S-1 | How much of `ide/src/stepsModel.ts` moves into a shared package, and does a native Theia Steps extension render and edit `samples/config`? | Parse, render, edit, undo and Test work in a pinned Theia build; the shared share is measured; the Theia version and language server are recorded |
| S-2 | Does the analyst build contain no text-editor route for `.py`? | A scripted walk of every command and menu opens no `.py` in Monaco |
| S-3 | Does the analyst build install and run on a stock Windows analyst machine? | A documented yes or no, with installer size and memory use recorded |
| S-4 | The repository check as a CI step on a sample config repository | It classifies all four R1 payloads, a hand-edited `code` row, a changed unrecognized test, a changed import and a new helper file as not Steps-only, and passes ordinary Steps edits, including an insert above a `code` row |

---

## Appendix A: disposition of the review findings

The review of 2026-10-07 read the 2026-10-02 drafts through four lenses. Forty-one of forty-four raw
findings survived adversarial verification; the synthesis merged them into R1 to R34. "Hosted ADR"
means the finding applies only to a hosted design and is carried to the later ADR that designs it.

| Finding | Severity | Disposition | Where |
|---|---|---|---|
| R1 | blocker | **Open, being fixed separately.** A precondition for the analyst build | Section 5.3, FR-9, ADR D6 and AC-3 |
| R2 | major | Addressed | FR-1, FR-2, ADR AC-5 |
| R3 | major | Addressed for desktop: no timer poll. Hosted ADR keeps the engine-change question | FR-4 |
| R4 | major | Not applicable to desktop: no central token store; each token stays on its owner's machine. Hosted ADR | FR-6, section 11 |
| R5 | major | Not applicable to desktop: the analyst pushes with their own git credential. Default-branch protection is a precondition of the repository check. Hosted ADR | FR-18, FR-19, FR-29 |
| R6 | major | Addressed: native Theia Steps extension, no plugin-ext in the analyst build | Section 9.1, ADR D3 |
| R7 | major | Not applicable to desktop: edits go through the document model, no broker. Hosted ADR | FR-11 |
| R8 | major | Addressed by owner ruling 3: the repository check is an option, with guidance on when to turn it on | Section 5.4, ADR options |
| R9 | major | Addressed: ADR 0076 Amendment G, with the BACKLOG #26 note and the corrected amendment citation | Amendment G, FR-7, FR-8 |
| R10 | minor | Addressed: every engine change is listed (`code:steps`, the R1 fix, the check command, and a start-up route only if none fits); the reload-commit requirement is dropped | Section 11, ADR D4 |
| R11 | minor | Addressed: `config:validate` marked declared, not enforced | Section 4 |
| R12 | minor | Partly applicable: dry-run runs config code on the analyst's machine, as it does in `ide/` today. On a desktop the user can run code anyway. Hosted ADR | Section 8 note |
| R13 | minor | Addressed | FR-15, ADR AC-7 |
| R14 | minor | Addressed | FR-12, ADR AC-6 |
| R15 | minor | Not applicable to desktop: no broker receives a client path. Hosted ADR | |
| R16 | minor | Not applicable to desktop: one writer, the document model. Hosted ADR | |
| R17 | minor | Not applicable to desktop: each editor signs in from its own address. Hosted ADR | |
| R18 | minor | Addressed for this design's rules | ADR acceptance criteria |
| R19 | minor | Not applicable to desktop: no gateway serves webview origins. Hosted ADR | |
| R20 | minor | Addressed | Section 9.2, FR-7, spike S-2 |
| R21 | minor | Addressed | Section 8 |
| R22 | minor | Addressed | FR-21 |
| R23 | minor | Addressed: option 5 re-weighed in the ADR | ADR options |
| R24 | minor | Addressed by owner ruling 4: developers keep the full IDE on the desktop, not hosted | Section 6.6 |
| R25 | minor | Not applicable: no hosting cost threshold arises on the desktop | |
| R26 | minor | Addressed | FR-13 |
| R27 | note | Addressed | FR-10 |
| R28 | note | Addressed: one out-of-scope list, in section 11; the ADR points to it | Section 11 |
| R29 | note | Addressed: the sole-console rule cites CLAUDE.md section 2 and BACKLOG #103; "out of band" cites `ide/src/promote.ts` | Section 5.1, ADR Related |
| R30 | note | Not applicable to desktop: no sandbox uid. Hosted ADR | |
| R31 | note | Addressed: Theia Cloud stays deferred, with both sides listed | ADR options |
| R32 | note | Addressed | Section 8 |
| R33 | note | Addressed | Section 10, spike S-1 |
| R34 | note | Not applicable: concerned the review's own inputs | |

**Counts:** 22 addressed (R3 for the desktop only; R8 and R24 by owner ruling), 1 partly applicable
(R12), 10 not applicable to the desktop phase, 1 open (R1). The hosted ADR inherits R3, R4, R5, R7,
R12, R15, R16, R17, R19 and R30.

Three raw findings were refuted in verification and need no action: dual control on reload is
conditional (the drafts said "unchanged", which is true); a licensing claim left to the owner's legal
review (its two facts are recorded in section 10); and an operating-cost objection the drafts
already named.

## Appendix B: what changed from the 2026-10-02 drafts

| Draft | This spec | Why |
|---|---|---|
| Hosted in a browser behind a gateway | Desktop app first; hosting later | Owner ruling 2 |
| Enforcement was the reason to host | A simpler interface is the reason | Owner ruling 1 |
| Read-only mount plus server-side broker as the control | Role check in the editor (primary) plus an optional repository check, with section 5 saying what each does | Owner ruling 3; SDS-3.7 |
| Hosted Code build with a shell | Developer build on the desktop, or VS Code and `ide/` | Owner ruling 4; review R24 |
| Steps view as the `ide/` plugin or a native extension | Native extension in the analyst build | Review R6 |
| Claimed a typed-row edit cannot inject Python | States R1 as an open precondition | Review R1 |
| Cited ADR 0076 Amendments A to E | Amendments A, C, D, E and F apply; B was declined | Review R9 |
| "Studio" working name | Dropped | The product is two builds of one editor; no name is needed yet |
