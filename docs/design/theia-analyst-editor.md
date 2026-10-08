# Specification: a Theia desktop editor for interface analysts

- **Status:** Proposed. Design only; no editor code exists. The lens changes it depends on landed in
  PR 2155 (section 5.3). Accepting it needs the owner.
- **Date:** 2026-10-07
- **Decision record:**
  [ADR 0208](../adr/0208-a-theia-desktop-app-gives-interface-analysts-a-simpler-steps-only-editor.md).
  The guardrail changes are [ADR 0076](../adr/0076-typed-action-vocabulary-action-list-lens.md),
  Amendment G.
- **Replaces:** the owner's drafts of 2026-10-02, *"Hosted Theia authoring with two editing levels"*
  (ADR and spec, never committed). Appendix C lists what changed and why.

> Deployment status (CLAUDE.md section 0): MessageFoundry has no deployed instances. The editor this
> spec describes is not built. Every statement about analysts, sites and data describes what a deploying site
> *would* run.

---

## 1. Purpose

Interface analysts who do not write Python need a simpler editor than VS Code. VS Code's layout suits
programmers. An analyst who opens it meets a file tree, a terminal, a debugger, extensions, git and a
Python editor before they reach the one view they need: the Steps view (ADR 0076).

This spec describes a desktop app, built on Eclipse Theia, in two builds. The **analyst build** shows
the Steps view and little else. The **developer build** is a full IDE. Developers may also keep using
VS Code with the `ide/` extension.

**Enforcement is not the motivation** (owner ruling 1). The 2026-10-02 drafts argued for hosting
because a desktop editor cannot stop a user from editing their own disk. That argument is correct,
and section 5 keeps it. The reason to build this is the simpler interface.

The `.py` file stays the only artifact and the only execution path (ADR 0076 section 2). The analyst
build is a view over that file. It is not a second authoring format.

## 2. Rulings and decisions this spec is built on

**Owner rulings, 2026-10-07.**

1. **Purpose.** Theia exists to give low-code analysts a simpler interface than VS Code.
   Enforcement is not the motivation.
2. **Desktop first.** A desktop app ships first. A hosted, browser version comes later and is out of
   scope here.
3. **Two controls.** The editor's role-based check is the **primary** control that limits analysts to
   typed Steps edits. A repository-side check is an **optional** control a site can turn on.
4. **Developers keep the full IDE.** The Theia developer build has a Steps / Split / Code switch.
   Developers may also stay on VS Code and `ide/`.
5. **Typed-only mode.** `paste_block` and a one-line raw `test` can still write code that runs. A
   flag on `lens rewrite`, `--typed-only` (PR 2155 shipped it under that name), refuses both with the generic `refused` code.
   It is off by default, so developers and today's IDE keep both. The analyst build always sets it.
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
  contract and the editor version together.

**Manager decisions 2026-10-07, after adversarial review.**

- **D-A. The developer build has no per-user limits.** It is a full IDE for whoever installs it, no
  weaker than VS Code with `ide/`. The analyst limits (typed-only mode, no text route, the block
  refusal, the Steps level only) live in the analyst build alone, which is capped at the Steps level
  for everyone. A user without `code:edit` is given the analyst build. Owner ruling 3 still stands:
  the role check is the primary control, in the analyst build.
- **D-B. Analyst Test takes a generator spec, never a file.** The analyst picks a message type and a
  seed. A small engine change lets `dryrun`, or a thin wrapper, generate that message in-process and
  show its values unredacted, for that generated input only. The editor never passes `--show-phi`.
  For a message type with no generator, Test is unavailable.
- **D-C. Review.** The repository check passes and fails exactly as ruling 6 says, and reads the
  `code:edit` approval itself. The documents recommend the site's ordinary review, by any reviewer,
  on every pull request, as guidance and not as a requirement of the check.

## 3. Terms

- **Analyst build.** The Theia desktop application for analysts. It shows a feeds list, the Steps
  view, a sample panel and *Submit for review*. Section 10 lists what it leaves out.
- **Developer build.** The Theia desktop application for developers: a full IDE with a Steps / Split /
  Code switch above each Router or Handler. It applies no per-user limits (D-A).
- **Steps level.** Editing typed rows only, through the Steps view.
- **Role check.** The analyst build reads the signed-in user's permissions from the engine and turns
  on editing only for a user who holds `code:steps` or `code:edit`.
- **Repository check.** The optional CI check plus required approval described in section 7.8.
- **Steps-only change.** A change the repository check classifies as one the analyst build could have
  made (FR-40).
- **Config repository.** The site's git repository of Routers, Handlers and connections (the "HC
  config repo" of ADR 0017).

## 4. Permissions and roles

The engine stays the identity and role authority. The editor holds no user database.

| Permission | Status today | Meaning under this spec |
|---|---|---|
| `code:steps` | **New.** Advisory: the analyst build reads it, and no engine route checks it | Turns on editing in the analyst build |
| `code:edit` | Declared in `messagefoundry/auth/permissions.py`; no endpoint enforces it | Names who may approve a non-Steps-only change (FR-43). The developer build does not read it (D-A) |
| `config:validate` | Declared; no endpoint enforces it (`docs/SECURITY.md`, permission table) | Not used by the analyst build, which runs `messagefoundry check` locally at submit (FR-34) |
| `config:deploy` | Enforced on `POST /config/reload` | Promote. Unchanged. The analyst build offers no promote |
| `ai:assist` | Enforced on `POST /ai/chat`, and reported by `GET /ai/policy` | Unused in this phase. Both builds leave AI out |

- **`code:steps` is advisory.** Only the analyst build reads it. It gates nothing on the engine, and
  the `docs/SECURITY.md` permission table would have to say so in its row.
- **"`code:edit` implies `code:steps`" is an editor rule**, not an engine one: the analyst build turns
  on editing for a user who holds either.
- The built-in `Coding` role would gain `code:steps` beside the `code:edit` it has.
- A new built-in **Analyst** role would hold `code:steps` and not `code:edit` (owner ruling 7). Its
  other permissions are set at build; `monitoring:read` is the likely one. A site can still build a
  narrower custom role under ADR 0045.
- **Adding the role** means a new `Role` enum member, a `ROLE_METADATA` entry and a
  `BUILTIN_ROLE_PERMISSIONS` entry in `messagefoundry/auth/permissions.py`. The role seed,
  `AuthService._seed_roles`, loops over `Role` and needs no change.
- **Text that names "six" fixed built-in roles would change to seven**, at least: the
  `messagefoundry/auth/permissions.py` comment on the additive overlay; the `builtin` field
  description in `messagefoundry/api/auth_models.py`; the roles list docstring in
  `messagefoundry_webconsole/pages/admin.py`; and the module docstring and the `_service` helper
  comment in `tests/test_custom_roles.py`.

## 5. What each control does, and what it does not

This section is the one a site security reviewer should read first. Each control is described by
what a reader can rely on it to stop (SDS-3.7: a control must not rest on a false premise).

### 5.1 The premise, tested

On a desktop install the analyst's working copy of the config repository is on their own disk. The
`.py` files are ordinary files that the analyst's operating-system account can write. So:

- The role check runs inside the analyst build. It decides what **the analyst build** offers.
- It cannot stop a write that does not go through the analyst build. **"Other tools" include the
  developer build and VS Code with `ide/`**, as well as Notepad, any other editor, a script and `git`
  on the command line. The developer build applies no limits (D-A), so an analyst who installs it has
  a full IDE.
- Nothing on the engine side checks these files at save time. A promote to a remote engine sends no
  files: the engine reloads from its own `--config` directory, which a site fills out of band
  (`ide/src/promote.ts`, the comment above `configDirForTarget`). So no remote engine sees an
  analyst's edit before it reaches the repository. (A local engine reloads straight from the working
  copy's path. The analyst build offers no promote, so it does not take that path.)

Neither the 2026-10-02 drafts nor the review shows the Steps limit enforced anywhere an analyst on a
desktop install cannot bypass. The drafts' only such design was the hosted read-only mount plus a
server-side broker, which this phase does not build.

### 5.2 The two controls side by side

| | Role check in the analyst build (primary) | Repository check (optional) |
|---|---|---|
| **Where it would run** | In the analyst build | In the config repository's CI, under branch protection |
| **Would stop** | An analyst changing Python **through the analyst build**: by accident, through an editor feature, or through an edit the lens would otherwise accept | A change that is not Steps-only reaching the protected branch without a `code:edit` holder's approval of its head commit, **whatever tool made it**, when the preconditions of section 5.4 hold |
| **Would not stop** | Any change made with another tool, the developer build and VS Code included | A change a `code:edit` holder approves. A push to a branch that branch protection leaves open. A Steps-only change that is wrong but well-formed (see below) |
| **Depends on** | The R1 fix and typed-only mode (section 5.3); the permission catalog; a fully signed-in session (FR-6) | The section 5.4 preconditions; a git-host group mapped to engine `code:edit` holders, kept by hand |
| **Kind of control** | A guardrail for analysts who use the analyst build as intended | A boundary against a deliberate or tool-assisted change, if section 5.4 holds; otherwise it stops an accidental change, not a deliberate one |

**What a Steps-only change could still do**, at least. It would pass the repository check, so the
site's ordinary review is what would catch these (D-C):

- redirect a send to any existing outbound connection;
- issue a lookup with literal arguments against any database or FHIR server the egress allow-lists
  permit;
- raise an error, or filter the message so nothing is delivered;
- insert a typed step that changes data an unchanged `code` row below it later reads;
- delete a developer-written dynamic row. The analyst build would refuse this (ADR 0076 Amendment
  G, G.6 rule 4), but a change made with another tool would pass the repository check (FR-40 item
  3);
- leave a read of a binding unbound: delete a binding (G.6 defines the kinds) while a row reads
  its name, move a binding so it no longer dominates a read, or move a reading row out from under
  its bindings, such as a row using `occurrence=i` moved out of its For Each loop. G.6 rule 6
  defines dominance. The analyst build would refuse each. It would also refuse, more
  conservatively, any move or delete of a block that holds a Read Field or assigned lookup row. The
  repository check would not test for an unbound read. Since PR 2155, the lens refuses a move that
  would leave a read unbound in either mode, and under typed-only mode a delete that would. Measured
  at `main` on 2026-10-08, that covers a lookup's `assign_to` as well as a Read Field row.
  What the lens implementation enforces is recorded by PR 2155's tests (Amendment G, "Where
  the code stands").

**What already gates what runs, under both:** a change reaches a running engine only when someone with
`config:deploy` reloads it, under the existing step-up and the site's `[approvals]` dual control. That
controls who deploys. It does not check whether a Steps-level author changed Python.

### 5.3 R1 is a precondition, answered by changes that landed in PR 2155

The review found that `lens rewrite` accepted edits that write arbitrary Python (review finding R1).
The answer is the R1 fix and typed-only mode in `messagefoundry/lens.py`. **They landed in PR 2155,
merged 2026-10-08 as `8280c3f42b`.** ADR 0076 Amendment G states them once: G.6 for typed-only mode,
G.7 for the R1 fix and its *inert* rule, and G.5 for the R1 payloads. This spec does not restate
them. G.7, "What still differs at `main`", records where the code and those rules still differ;
the stricter of the two governs, and each difference is a defect until it is reconciled.

The analyst build must not ship before the lens meets the payloads as refusal tests (ADR AC-3), and
before it passes typed-only mode on every `lens rewrite` call (FR-25).

### 5.4 Preconditions for the repository check to hold against a deliberate change

The check can only be as strong as the place it runs. **The general rule:** the check's definition,
its engine version and the decision to re-run it must all come from the base branch, never from the
change under review, and it must treat the change's files as data only. The site would need all of
these:

1. **The check runs from a definition the change cannot edit.** On GitHub that means a ruleset's
   required workflow; it is also the only way to bind a required status to one workflow file, so a
   same-named status from another job cannot satisfy it.
2. **The head's files are read as data only.** The check never installs, imports or runs code from
   the change. The `messagefoundry` version it runs is pinned **from the base branch** (FR-44). On
   GitHub, a `pull_request_target` workflow would be one way; it must never install or import the
   head's code.
3. **It re-runs when an approval arrives, through a mechanism whose definition comes from the base
   branch.** On GitHub, a `pull_request_review` workflow on its own runs the head's copy, so it is not
   that. Which GitHub mechanism does it (for example a `workflow_run` workflow, which runs from the
   default branch's definition, re-running the required check through the API) is settled at build
   and verified by spike S-4. A ruleset required workflow may need an organization ruleset and a paid
   plan; that is checked at build too.
4. **Code owners.** CODEOWNERS names the `code:edit` group for the CI directory and the engine
   version pin, and branch protection requires review from code owners.
5. Branch protection on the default branch with the review settings of FR-43.

Without these, the repository check would stop an accidental change but not a deliberate one.

### 5.5 When a site should turn on the repository check

Turn it on when any of these holds:

1. The site needs the Steps limit to hold against an analyst acting deliberately, or against another
   tool. Change control or audit rules often ask for this.
2. Analysts can push to a branch that reaches the engine's config without a developer's review.
3. Analysts and developers share one git-host group, so review alone does not separate them.
4. The site cannot rule out other editors, the developer build included, on analyst machines.

Whether or not it is on, the documents recommend the site's ordinary review on every pull request
(D-C).

**Without the repository check, the Steps limit holds only for analysts who use the analyst build as
intended.** A site that turns it off accepts that.

## 6. The analyst's work, end to end

Each step names the requirement that covers it.

1. **Set up.** The installer, or a site administrator, sets the engine URL and its certificate trust
   and clones the config repository (FR-1, FR-2).
2. **Sign in.** The analyst signs in to the engine (FR-5, FR-6).
3. **Get latest.** The analyst build fetches the default branch and starts the change from it (FR-37).
4. **Find the feed.** The feeds list shows each inbound connection with its Router and Handlers
   (FR-12).
5. **Edit.** The analyst changes typed steps (FR-18 to FR-24).
6. **Test.** The analyst picks a message type and seed and sees the message before and after the
   selected step (FR-30 to FR-33).
7. **Submit.** The analyst build commits the edited modules, brings the review branch up to date,
   runs `messagefoundry check`, pushes and opens a pull request (FR-34 to FR-37).
8. **See review status.** The submit panel shows the pull request's state (FR-38).
9. **Revise.** The analyst edits and submits again on the same branch (FR-38).
10. **Next change.** After merge, the next change starts from a fresh default branch (FR-37).

## 7. Functional requirements

Written in EARS form. Every requirement is for the analyst build unless it says otherwise.

### 7.1 Setup, the engine and sign-in

- **FR-1.** THE INSTALLER, or a site administrator, SHALL set the engine URL. THE ANALYST BUILD SHALL
  NOT let the analyst change it.
- **FR-2.** THE ANALYST BUILD SHALL trust the engine's certificate only through a site-distributed CA
  or certificate file, or a fingerprint pinned at first connect. The engine mints a self-signed
  certificate when none is supplied (ADR 0172), so the operating system's store alone would not
  verify it.
- **FR-3.** All engine calls SHALL run in the build's backend (section 9), never in the browser
  layer.
- **FR-4.** WHEN the engine cannot be reached, THE ANALYST BUILD SHALL say "The engine cannot be
  reached" in plain words, with the details behind a toggle.
- **FR-5.** WHEN a user signs in, THE ANALYST BUILD SHALL sign in through `POST /auth/login` (a local
  or directory password account) and finish every session gate before it stores a token or reads
  permissions. The gates are named in `messagefoundry/api/security.py`:

  | Gate | What the analyst sees and does |
  |---|---|
  | MFA pending (`_MFA_EXEMPT_ROUTES`) | A code prompt in the build; `POST /auth/mfa-verify` |
  | Password change required (`_MUST_CHANGE_EXEMPT_PATHS`) | A plain message and a link that opens `/ui/account/password` in the browser, as `ide/src/auth.ts` does |
  | Enrol a factor first (`_ENROL_FIRST_ROUTES`) | A plain message and a link to `/ui/account`, as `ide/src/auth.ts` does for MFA |
  | Notification address required (`_NOTIFY_EMAIL_EXEMPT_ROUTES`) | A plain message and a link to `/ui/account` |

  Sign-in through OIDC is out of scope for this phase; an OIDC-only site cannot use the analyst build.
- **FR-6.** `GET /auth/me` alone does not prove a session is past these gates: it is exempt from them
  and returns every permission with no pending flag (review R2). WHEN the analyst build starts with a
  stored token, it SHALL first call a route that is on none of the exempt lists, is not one of the
  `mfa_gate=False` routes (`messagefoundry/api/security.py` exempts those without listing them: TOTP
  enrolment and confirm, and session termination), and that every editor user may call. The route is
  chosen at build; if none fits, the engine needs one (section 15). The analyst build SHALL read the
  probe's answer as follows (Manager decision 2026-10-07, after review):

  | Probe answer | What the analyst build does |
  |---|---|
  | Success | The session is good |
  | 401 (the token is invalid, expired or revoked) | Treat the user as signed out |
  | 403 naming a session gate | Treat the user as signed out and name the gate, as in FR-5. Read the gate from the `X-MFA-Required` and `X-Notify-Email-Required` headers and from the password-change detail. `classifyForbidden` in `ide/src/engineStatusModel.ts` matches the detail text only and has no notification-address case, so it cannot be reused unchanged |
  | Any other 403, such as a missing permission or a step-up demand | Keep the session, show the Steps view read-only, and show the FR-13 banner for no Steps permission. Do not sign the user out |
  | 429 (rate limited) | Keep the session, stay read-only, and show the FR-13 banner with Retry, enabled once any `Retry-After` time has passed. No automatic retry |
  | A 5xx answer, a timeout, or no connection | Keep the session and show the FR-13 banner for an unreachable engine. Do not sign the user out |

  In every row but the first, a save is refused (FR-9).
- **FR-7.** WHILE no session is signed in, THE ANALYST BUILD SHALL show the Steps view read-only.
- **FR-8.** THE ANALYST BUILD SHALL re-check the session before each save **through the same probe
  route as FR-6**, and SHALL NOT poll on a timer. A save is real user activity, so moving the engine's
  idle clock then is correct; a timer poll would keep an abandoned session alive (review R3).
- **FR-9.** After the probe passes, each save SHALL also re-read `GET /auth/me`, the route that returns
  permissions. IF the probe fails, or the user no longer holds `code:steps` or `code:edit`, THEN THE
  ANALYST BUILD SHALL refuse the save, keep the edit in the buffer, and show the banner of FR-13.
- **FR-10.** THE ANALYST BUILD SHALL keep the engine token in the operating system's credential
  store, through the backend.
- **FR-11.** The analyst build needs the engine **only** for FR-5 to FR-9. Once signed in, editing a
  buffer needs no engine call. Saving does, and so does Test, because Test saves first (FR-31). This
  is deliberate: saving is where the role check runs.

### 7.2 What the analyst sees

- **FR-12. Feeds list.** THE ANALYST BUILD SHALL show a read-only list derived from the wiring graph:
  each inbound connection, its Router, and the Handlers that Router routes to. Choosing a Router or
  Handler opens it in the Steps view. A route row's handler names open those Handlers. WHEN an inbound
  connection has no Router, or a Router routes to no Handler, the list SHALL say so and say "ask a
  developer".
- **FR-13. Read-only banner.** WHILE the Steps view is read-only, THE ANALYST BUILD SHALL show a
  persistent banner naming the cause, with one action each: not signed in (Sign in); engine
  unreachable (Retry); no Steps permission (ask an administrator); file failed to parse (ask a
  developer).
- **FR-14.** THE ANALYST BUILD SHALL open a Router or Handler in the Steps view, and SHALL offer no
  route that opens a `.py` file in a text editor (Amendment G, AC-G1).
- **FR-15.** WHEN a file fails `lens parse`, THE ANALYST BUILD SHALL show the FR-13 banner instead of
  a text editor (Amendment G, AC-G2).
- **FR-16. Plain rows.** A `code` row SHALL collapse to "Developer code (N lines), read-only", with
  the source behind an expander. A recognized control row SHALL read as a plain sentence, not its
  `test_src`. A route row SHALL list its handler names, and an `unrouted` route SHALL read
  "Unrouted" (gap 1). Each header SHALL read "Handler: name" or "Router: name" (gap 2).
- **FR-17. Messages in the panel.** Every message the analyst build shows SHALL appear in the Steps
  panel, never as a pop-up notification (gap 3). Each refusal code SHALL have its own message: what
  was not changed, the plain reason, "ask a developer" where it applies, and the engine's detail
  behind "details". Messages MAY name components: handler, router, connection and code-set names.
  No message SHALL contain "code view", "View as Code", Python source, a traceback, or a function or
  variable name from the code other than a component name, outside the "details" toggle. Dialogs
  are messages too. Two sit on the Steps path: the save prompt when a dirty tab closes, and the
  browser's leave-page prompt. A message that offers an action SHALL offer it as a button in the
  panel (Manager decision 2026-10-07, from spike S-2). A native dialog the analyst build cannot
  draw in the panel, such as the leave-page prompt, is exempt from the panel rule only, and still
  meets the wording rules. What the Electron build shows in its place is settled at build.

### 7.3 Steps-level operations

- **FR-18.** THE ANALYST BUILD SHALL offer only these operations: set a typed parameter, insert a
  typed row from the palette (including the If, Else If, Else, For Each, Filter, Raise, Send and, in a
  Router, Route templates, without a raw `test`), delete, move, and edit a note. It SHALL NOT offer
  `paste_block`, a raw control `test`, or a free-text expression. Copy, cut and paste are absent,
  because typed-only mode refuses `paste_block`.
- **FR-18a.** Today's `ide/` palette sends an `{"expr": ...}` value for Substring, Pad, Arithmetic,
  Split, DB Lookup and FHIR Lookup (`ide/src/stepsModel.ts`, the prompts marked `expr`, and the `{}`
  params seeds). THE ANALYST BUILD SHALL offer these steps with typed inputs instead of free text: a
  number field for an index, width or operand; a list of field paths for Split; and a key/value table
  for lookup params, with literal keys and literal or field-read values. Each input is serialised to an
  `{"expr": ...}` that the R1 fix's *inert* rule admits (ADR 0076 Amendment G, G.7). A value the rule
  refuses gets an FR-17 message, and nothing is written.
- **FR-19.** `code` rows and control headers stay read-only.
- **FR-20.** IF a delete or move would break the structure rule of ADR 0076 Amendment G, G.6, THEN
  THE ANALYST BUILD SHALL refuse it (AC-G5). The lens refuses the same under typed-only mode since
  PR 2155, except the case Amendment G, G.7, "What still differs at `main`", names. Today `ide/` deletes or moves a whole block from its header row, nested `code`
  rows included (`isRowDeletable` and `isRowMovable` in `ide/src/stepsModel.ts`).
- **FR-21. Drag a field.** The drag source SHALL be the sample panel or the schema tree. A drop onto
  a path parameter SHALL issue the same `set_params` edit, byte for byte, as typing that path. A drop
  anywhere else SHALL write nothing. The field picker SHALL be the keyboard path to the same edit.
  WHEN no schema bundle is installed, the schema tree is absent and the sample panel is the only
  source.
- **FR-22.** Connections and code sets SHALL be read-only. Their `ide/` editors write through
  `upsert` commands (`ide/src/connectionEditor.ts`, `ide/src/codeSetEditor.ts`), which are not
  Steps-level edits (review R27). An analyst who needs one changed asks a developer.
- **FR-23.** *Duplicate step* is a named future item. It would re-emit a recognized row from its
  typed parameters. The lens has no such op today.
- **FR-24.** Every analyst action SHALL be reachable by keyboard, with screen-reader labels on rows
  and controls.

### 7.4 Editing and saving

- **FR-25.** THE ANALYST BUILD SHALL pass typed-only mode on every `lens rewrite` call and SHALL offer
  no way to turn it off (owner ruling 5; ADR AC-3a).
- **FR-26.** THE ANALYST BUILD SHALL apply each row edit through Theia's document model, as `ide/`
  does with a `WorkspaceEdit` (`ide/src/stepsView.ts`, file header). Undo, redo and dirty state work
  through it. Hot-exit is not in this phase: spike S-1 measured that Theia 1.76 has none, and a
  dirty buffer is lost on reload, with no backup support in any `@theia` package. Hot-exit is a
  future item (Manager decision 2026-10-07, from spike S-1).
- **FR-27.** THE ANALYST BUILD SHALL pass the row-contract version explicitly on every `lens parse`
  and `lens rewrite` call, and SHALL refuse with a visible message when the engine command rejects
  it. It SHALL NOT retry on an unknown-argument error, which `ide/src/cli.ts` does today (review R14).
- **FR-28. Capability probe.** At start, THE ANALYST BUILD SHALL ask the bundled engine for its
  supported row contracts, whether it supports typed-only mode, and its vocabulary version. `lens
  schema` reports none of these today, so this is an engine change (section 14). IF the engine is
  older than the build's minimum, THEN THE ANALYST BUILD SHALL refuse to edit and say why.
- **FR-29.** THE ANALYST BUILD SHALL run `lens` from the bundled, pinned `messagefoundry` install.
  `lens` is toolkit-tier by ADR 0201 but is still registered on the `messagefoundry` command (review
  R26).

### 7.5 Test

- **FR-30.** Test SHALL take a generator spec: a message type and a seed. There SHALL be no route to
  open a file or paste a message as a sample (D-B).
- **FR-31.** WHEN the analyst runs Test, THE ANALYST BUILD SHALL save the buffer first, then run
  `dryrun`, or its thin wrapper, with the generator spec. The engine generates the message
  in-process and shows its values unredacted **only for that generated input**. The analyst build
  SHALL NOT pass `--show-phi` (ADR AC-7). The generator-spec input is an engine change (section 14).
- **FR-32.** THE ANALYST BUILD SHALL show the result in the Steps panel: the message before and after
  the selected step, with changed values marked. It SHALL open no other panel (gap 4).
- **FR-33.** WHERE a message type has no generator, Test SHALL be unavailable for it, and the analyst
  build SHALL say why: Test runs only on a generated message, and none exists for that type.
  `messagefoundry/generators/` covers a fixed set of types; any other type falls here.
- Test errors SHALL read as a plain summary, with the details behind a toggle (section 9).

### 7.6 Submit for review

- **FR-34.** WHEN the analyst selects *Submit for review*, THE ANALYST BUILD SHALL take these steps
  in order, and stop at the first that fails (Manager decision 2026-10-07, after review, so a merge
  never runs over uncommitted edits):
  1. Commit the edited modules (FR-35). Skip this step when there is nothing new to commit, as on a
     resubmit after an earlier submit committed and then failed.
  2. If the base is stale, update the review branch from the default branch (FR-39).
  3. Run `messagefoundry check` on the resulting tree, and show any failure in plain words.
  4. Push (FR-37).

  It SHALL NOT push while any step fails. A commit made in step 1 stays on the local review branch,
  so the analyst can revise and submit again.
- **FR-35.** THE ANALYST BUILD SHALL commit, by explicit pathspec, only the Router and Handler modules
  edited through the Steps view in this session. IF anything else is staged, THEN it SHALL refuse.
  It SHALL never stage an untracked file.
- **FR-36.** Test samples are generated (FR-30), so none live in the config working copy. Test output
  SHALL never be attached to a commit or pull request.
- **FR-37.** THE ANALYST BUILD SHALL push to a review branch, `analyst/<user>/<topic>`, where `<user>`
  is made ref-safe (a directory name such as `DOMAIN\user` becomes `domain-user`). It SHALL never
  push to the default branch. It SHALL open a pull request through the git host's API where the site
  configures one, or show the link to open it. Each new change SHALL start from a freshly fetched
  default branch.
- **FR-38.** THE SUBMIT PANEL SHALL show the change as steps (added, changed, removed), with the
  Python diff folded below for the reviewer, the Test results, and the pull request's review status.
  A revision SHALL be pushed to the same branch.
- **FR-39.** The base is **stale** when, after a fresh fetch, the default branch's tip on the git
  host is not an ancestor of the review branch's head (`git merge-base --is-ancestor` fails). The
  test resets itself: once the default branch is merged in, its tip is an ancestor again (Manager
  decision 2026-10-07, after review). WHEN the base is stale at submit, THE ANALYST BUILD SHALL
  update the review branch from the current default branch by a merge before it pushes, so the
  pushed review branch never needs a force-push. IF that update conflicts, THEN it SHALL abort the
  merge, push nothing and say "ask a developer". IF git or its credential is missing, THEN it SHALL
  push nothing and say which. The commit author is the user's engine identity, and the git email is
  set by the site. Git authorship is free text, so it is a record, not proof (review R22).

### 7.7 The developer build (D-A)

- The developer build SHALL offer a Steps / Split / Code switch above each Router or Handler,
  remembered per file. In Split, selecting a step highlights its lines and selecting a line selects
  its step. In Code, a small steps outline sits beside the text with a *View as Steps* link above each
  def.
- Its Steps view is the same native extension as the analyst build's (ADR D3).
- It applies **no per-user limits**, keeps every ADR 0076 guardrail, and offers the Python editor with
  an open language server, git, a terminal and the debugger. Pylance is licensed for Microsoft
  products only, so the server would be an open one such as basedpyright. Spike S-1 did not record
  one; that leg is open.
- It needs no engine session to edit or save.
- It opens a Router or Handler in the Code view by default, with the Steps view one switch away, so
  ADR 0076's opt-in entry holds in it (AC-G3).

### 7.8 The optional repository check

- **FR-40.** THE PROJECT SHALL ship a check that decides whether a change is **Steps-only**. A change
  is Steps-only when all of these hold. *Generator-shaped* means AST-equal to what the lens generator
  emits from literal inputs. Text marked "from spike S-4" is a Manager decision 2026-10-07, from spike
  S-4, which built this check as a prototype and found where the earlier text was wrong.
  1. Every changed path is an existing Router or Handler module. A new file, a `_`-prefixed helper,
     `connections.toml`, a code set or an environment file is not Steps-only.
  2. Outside the `@handler` and `@router` def bodies, the module's bytes are unchanged, except for the
     lens's sanctioned generated shapes: an added `from messagefoundry import <name>` line, or an added
     `NAME = code_set("<literal>")` line with the blank line `insert_code_lookup` puts before it (ADR
     0106 section 5 items (H) and (I), and section 6). Each passes only when generator-shaped, and
     an added import only when `<name>` is not bound anywhere else in the module. `lens parse`
     partitions def bodies only (ADR 0076 section 3's coverage invariant, and A.5 *"No module
     scope"*), so the rest is compared as bytes. From spike S-4: each def's decorators and signature
     are compared by AST, not bytes, and blank or comment-only lines between the signature and the
     first statement count as body.
  3. Inside each def body, the ordered sequence of `code` rows is unchanged, each compared by content
     and by its suite path, never by line number. So a hand-written line moved from under one
     condition to another fails. *Suite path*, *dynamic row* and *hand-written header* are defined
     once, in ADR 0076 Amendment G, G.6. From spike S-4:
     - Changing a generated `if` test that encloses a hand-written line is not Steps-only, because
       the line's suite path changes. This is intended (Manager decision 2026-10-07, from spike S-4).
     - A `pass` statement is ignored on either side, so the `pass` seed of an If or For Each template
       or an Else If or Else clause (`_apply_insert_clause`) neither adds nor removes a row.
     - G.6 rule 3 holds between base and head. A dynamic row keeps its order relative to `code` rows
       and hand-written headers, and its suite path, but may be deleted: the check would pass that,
       while the analyst build would refuse it (G.6 rule 4, and section 5.2).

     The other sanctioned exception is the `sends = []` / `sends.append(...)` / `return sends`
     accumulator scaffold (ADR 0108), only when generator-shaped, with `return sends` only as the
     last statement of the body (from spike S-4).
  4. **Every control header** (`if`, `elif`, `for`, and the `raise` expression) is compared by content
     against base, like a `code` row, with its suite path. A changed or added header is Steps-only
     only when generator-shaped. A removed or moved header passes only when the base header was
     itself generator-shaped. G.6 rule 3 also holds. `recognized` is not evidence: it is
     a deny-list (`_is_bounded`, `_emit_if` and `_is_message_iteration` in `messagefoundry/lens.py`,
     and the raise branch), so `if os.system("calc"):`, `for g in msg.groups(os.system("calc")):` and
     `raise ValueError(os.system("calc"))` read back as recognized today.
  5. Every typed parameter that is new or changed is a literal or an inert value under ADR 0076
     Amendment G, G.7, as the lens's own predicate decides (from spike S-4: For Each writes
     `occurrence=i`, which is not a literal). A module-level `NAME = code_set("<literal>")` binding,
     in the exact scope G.7 states, passes only as `code_lookup`'s `table` argument, which
     `insert_code_lookup` writes, and fails anywhere else (Manager decision 2026-10-07, after
     review). The four value params ADR 0076 E.11 rule 4
     admits (`set_field.value`, `add_repetition.value`, `append_to_field.suffix`,
     `replace_literal.new`) may also be a template. A template anywhere else, such as a `db_lookup`
     statement or a `log_note` operand, is not Steps-only even though it reads back `templated`.
     Every new or changed `assign_to` meets G.7. A developer-written dynamic parameter the change
     leaves alone does not fail it.

     **5a. A typed row is compared by its full statement**: the callee, every positional argument
     (`msg` included), every keyword and any assignment target. A new or changed row must have the
     generator's skeleton: a bare vocabulary callee or a `msg.<method>` callee, with `msg` as the
     literal name in the message position. Comparing `params` alone is not enough, because `lens
     parse` drops the `msg` positional from `params` (`_rendered_param_nodes`) and reads any `X.attr`
     callee by its last name (`_callee_name`); see Amendment G, G.7, on that gap (Manager decision
     2026-10-07, after review).
  6. Every `send` and `route` row either matches base by content, or is new or was literal at base
     and is fully literal at head: one literal destination per `Send`, where `Send` is the bare name
     `Send` and the message argument is `msg`; no `SetState` expression; and a route's `handlers`
     non-empty or `unrouted`. A row that was dynamic at base and is literal at head is not
     Steps-only. The check is per element: a `Send` that was dynamic at base is gone and a literal
     one appeared in the same Router or Handler (from spike S-4). Since PR 2155, the lens also
     refuses `set_params` on such a route row (G.7). The lens projects a `Send` with a computed
     argument, or a dynamic route, with no typed parameters (`_send_outbounds` and `_route_row` in
     `lens.py`).

  **A known false failure, not a hole.** To find what is "new or changed", the check pairs each head
  row with a leftover base row of the same skeleton. A pairing can miss, and the check then treats
  every parameter as new. That fails a change that was Steps-only, which is safe but noisy; a
  `code:edit` approval clears it (FR-42). The check also assumes the accumulator is named `sends`,
  so a hand-written accumulator under another name fails the same way (spike S-4).

  **A product check needs a public lens surface.** The spike reads these private lens helpers:
  `_ACTION_PARAMS`, `_param_mode`, `_range_count_segment`, `_msg_field_source`, `_codeset_binding`,
  `_name_in_scope`, `_str_lit` and `_is_bounded_message_read`, at least. A product classifier would
  need each one exposed as a public, versioned lens surface, so the check cannot drift from the
  grammar it checks.
- **FR-41.** The check SHALL classify these as not Steps-only:
  - the R1 payloads (ADR 0076 Amendment G, G.5);
  - a hand-edited `code` row, and a `code` row moved under a different condition;
  - a typed row whose `assign_to` rebinds `msg`;
  - the three recognized-header shapes of item 4, and a removed hand-written header;
  - a template in a `db_lookup` statement;
  - a dynamic route made literal;
  - a changed import, and a new helper file;
  - from item 5a and G.7 (Manager decision 2026-10-07, after review):
    `trim_field(__import__("os").getcwd() or msg, "PID-5.1")`; `set_field(__import__("os").getcwd()
    or msg, "PID-5.1", "X")`; `anything.Send("OB", msg)`; an added `SEEN = []` at module level; and,
    with `SEEN = []` already at base, a new `checkpoint` label or `log_note` template of `{"expr":
    "SEEN"}`;
  - with `SEEN = []` (and a `SEEN.append(...)`) and a module-level `NAME = code_set("<literal>")`
    at base: `NAME` as a `checkpoint` label, in a `log_note` template, as a lookup-params value, as
    `FhirToken("MRN", NAME)` or in a value param; and `SEEN` as a lookup-params value, as
    `FhirToken("MRN", SEEN)` or in a value param (G.7; Manager decision 2026-10-07, after review).

  FR-41 does not list a row using `occurrence=i` moved out of its For Each loop. The repository
  check has no FR-40 item that tests for an unbound read (section 5.2), so it would pass that move.
  G.6 rule 6 refuses it in the lens (Amendment G).

  It SHALL pass an ordinary Steps edit, an insert above a `code` row, and one of each sanctioned shape
  in items 2 and 3 (spike S-4).
- **FR-42.** THE CHECK SHALL pass a Steps-only change. It SHALL pass any other change only when a
  member of the `code:edit` reviewer group has approved **the head commit**; the check reads that
  approval itself through the git host's API (owner ruling 6, D-C).
- **FR-43.** THE PROJECT SHALL document the setup: the section 5.4 preconditions, and branch
  protection that requires review from code owners, dismisses stale approvals and requires approval
  of the latest push. The `code:edit` reviewer group is kept in step with engine roles by the site,
  by hand.
- **FR-44.** The check SHALL run the `messagefoundry` version pinned on the base branch, and SHALL
  refuse to run below the minimum version (FR-28). The analyst build should bundle that same version;
  the two can differ while an installer lags.
- **FR-45.** The config-repository template of ADR 0017 SHALL carry the check as a commented-out
  workflow, so turning it on is one edit plus the section 5.4 settings.
- **FR-46.** THE PROJECT SHALL also ship the same classifier as an optional pre-commit hook. It is a
  convenience that warns early. It is not a control: it runs on the author's machine and can be
  skipped. The CI check is the control.

### 7.9 AI

- Both builds leave out Theia AI packages and the `ide/` chat participant in this phase. A later AI
  feature must honour `GET /ai/policy` and `ai:assist` (`docs/AI.md`).

## 8. Analyst interface design

The design follows the owner's wireframes of 2026-10-07 (four artboards: analyst editor, add a step,
submit for review, developer build). The wireframes are a private artifact; this section records what
they decide.

### 8.1 Gaps in today's Steps view the analyst build would fix

Each was re-checked against `ide/` at `ddf350e1d0`.

| # | Gap today | Evidence | Analyst build |
|---|---|---|---|
| 1 | A route row does not show the handlers it routes to | `rowSubtitle` and `rowParams` in `ide/src/stepsModel.ts` have no `route` case, and the engine's route row carries `handlers` but no `params` | FR-16 |
| 2 | An element's header does not say Handler or Router | `renderHandlerHtml` renders the def name and its line only, though the view model carries `role` | FR-16 |
| 3 | Refusals and warnings appear as pop-up notifications | `ide/src/stepsView.ts` raises about 20 `show*Message` notifications; the one in-page hint is the field picker's | FR-17 |
| 4 | Test opens a separate Test Bench panel | The `test` message runs `messagefoundry.openTestBench` in `ide/src/stepsView.ts` | FR-32 |

Spike S-1 confirmed gap 1 in Theia. The `ide/` page it reused also still shows Test, Pick Sample and
View as Code; the analyst build drops or replaces each (Manager decision 2026-10-07, from spike S-1).

### 8.2 Practices the design follows

| # | Practice | Seen in | This phase |
|---|---|---|---|
| 1 | One text file; the visual view is a way of looking at it | Power Query, MakeCode, DTL, SwiftUI | **Adopted.** The `.py` stays the only artifact |
| 2 | Code the visual editor cannot show becomes a locked block | MakeCode, DTL code action, Mirth JavaScript steps | **Adopted:** a collapsed, read-only `code` row (FR-16). Moves and deletes follow the structure rule of ADR 0076 Amendment G, G.6 (FR-20) |
| 3 | A comment above a step becomes its description | Power Query | **Not adopted.** ADR 0076 A.5 forbids attaching a comment to the following statement. The planned fix is gated on BACKLOG #1758 and needs its own amendment |
| 4 | Show the sample message after the selected step | Power Query, n8n, DTL | **Adopted** (FR-32) |
| 5 | Drag a field from a message tree onto a step | Mirth | **Adopted as path entry only** (FR-21; Manager decision) |
| 6 | Show what a change does before it goes in | Power Query Online | **Adopted** (FR-38) |
| 7 | Code and visual side by side, with linked selection | SwiftUI previews | **Developer build only** (section 7.7) |
| 8 | The visual view never quietly rewrites code it does not understand | Logic Apps, Power Query | **Already a rule:** ADR 0076 section 5's row-scoped splice |
| 9 | Full keyboard use from day one | Blockly | **Adopted** (FR-24) |

**A measured risk to the purpose.** Spike S-1 counted the rows over `samples/config`: 67 rows, 15
of them `code` rows (22.4% of rows and 38.4% of lines), and **no action or lookup rows at all**.
Every sample transform is a `code` row, so an analyst opening the samples would find nothing to edit
but sends, routes and control headers. Samples written in the typed vocabulary are needed before the
analyst build can be shown or tested on realistic work (Manager decision 2026-10-07, from spike S-1).

## 9. How the analyst build is put together

- **Backend services.** Spawning Python and git, the credential store, and engine HTTPS calls run in
  Theia's Node backend, exposed to the frontend as JSON-RPC interfaces. The frontend never runs a
  process or holds the token.
- **Process spawn.** Every engine command runs as `<interpreter> -I -X utf8 -m messagefoundry
  ...`: an absolute interpreter path, no shell, a minimal environment, input on stdin with size
  caps, and a timeout. `-I` is load-bearing: without it, `-m` would put the working directory on
  `sys.path`, so a file in the repository could shadow an engine module. Spike S-1 used this pattern
  (Manager decision 2026-10-07, from spike S-1).
- **Python resolution.** An administrator setting, then the bundled runtime. Nothing else: no `PATH`
  fallback. It never runs an interpreter the repository supplies, the rule `ide/src/cli.ts` calls
  SEC-004. It refuses to run an engine below the build's minimum version (FR-28).
- **Workspace trust.** The analyst build trusts only the repository it cloned at setup, with no
  prompt. It opens no other folder. Theia's workspace-trust dialog blocks the interface by default,
  so the analyst build sets `security.workspace.trust.enabled` to false, or an equivalent (Manager
  decision 2026-10-07, from spike S-1).
- **Installer.** It bundles the Python runtime and the pinned engine. The analyst never sees a
  virtual environment or `PATH`.
- **Errors.** Every failure reads as a plain summary, with the details behind a toggle.

## 10. Build composition

Theia applications are assembled from npm packages at build time.

| Capability | Analyst build | Developer build |
|---|---|---|
| Steps view | Native Theia extension | The same native extension |
| `@theia/plugin-ext` (VS Code extension host) | No | Yes |
| Monaco | **Ships**, because Theia's document model uses it; no `.py` editor is reachable (FR-14) | Yes |
| Terminal, tasks, debugger | No | Yes |
| Git UI | No (*Submit for review* does the git work) | Yes, through the built-in `vscode.git` (`@theia/git` is deprecated, review R32) |
| Extension installation, Open VSX | No | Vendored at build time, pinned by content hash, transitive packs resolved; no runtime registry access (review R21) |
| Theia AI | No | No (this phase) |
| `@theia/preferences` (with `@theia/userstorage`) | **Required.** Without it the app hangs on a missing `PreferenceProvider` binding. It brings in `@theia/markers`, `@theia/outline-view` and `@theia/variable-resolver` | Yes |
| File explorer | Feeds list only (FR-12). Upload, and drop into the navigator, are removed or guarded | Yes |
| `@theia/messages` | Yes | Yes |
| `@theia/file-search` | **No.** If it shipped, Quick Open would be one more route to test | Yes |

Spike S-1 found the `@theia/preferences` need and its transitive packages (Manager decision
2026-10-07, from spike S-1).

**How "no `.py` editor" is enforced** (AC-G1). Spike S-2 built and tested four layers (Manager
decision 2026-10-07, from spike S-2):

1. **Opener priority.** `EditorManager.canHandle` declines a `.py`, so the Steps view is the only
   opener. Without this, `workbench.editorAssociations` gives the text editor priority 100000.
2. **`EditorManager.open` refuses** a `.py`, and a rebound `OpenWithService` offers no text
   editor for one (`AnalystOpenWithService` in the spike's `analyst-frontend-module.ts`).
3. **`TextEditorProvider` refuses** a `.py`, because layout restore and reopen-closed-editor skip
   the opener.
4. **The blocked commands are never registered:** `navigator.openWith`,
   `workbench.action.files.newUntitledFile`, `workbench.action.files.pickNewFile`, `file.saveAs`,
   `file.compare`, `compare:first` and `compare:second`.

The analyst build must also stop a `.py` being **written** without being opened. The routes include
at least an untitled buffer, *Save As* and *Compare* (closed by layer 4), a rename or copy from a
file that is not a `.py` into a `.py` (closed by a `FileService` rebind), and an upload, a drop into
the navigator, and a move or copy of one `.py` over another. The spike's `FileService` rebind guards
only a move or copy from a file that is not a `.py` into a `.py`, and its walk skipped upload, so
the last three were open on the browser build. Spike S-2b, below, closed upload and drop on the
Electron build. The rebind, not a file-operation participant, is the mechanism, because a participant cannot block a
move: Theia logs the participant's error and carries on. A shipped build SHALL NOT expose test hooks
on `window`.

**What the Electron build adds** (Manager decision 2026-10-08, from spike S-2b). Spike S-2b ran the
same walk against the installed Electron app: branch `claude/theia-spike-s2b-electron` at
`7a1f6ba72e`, not merged. The installed app passed 5 of 5 runs, and the browser rerun passed 3 of 3.
It found more routes and closed them in the spike. The analyst build would carry these measures:

1. **A main-process guard, as well as the page guard.** It would close at least these
   Electron-only routes: *Open With System Editor*, *Reveal in File Explorer*, `shell.openExternal`
   and `showItemInFolder`, `window.open` on a `file:` URL, Developer Tools, Electron's default menu,
   the native menu bar and context menus, and native file dialogs.
2. **An upload or drop of a `.py` into the navigator would be refused.** A check that a name is a
   `.py` would also catch the Windows spellings `x.py.`, `x.py ` and `x.py:stream`. Upload would
   be guarded at the backend write, not only in the page.
3. **Electron fuses would be set** through electron-builder's `electronFuses` option, because
   `@theia/electron` 1.76 has no fuse setting. With the RunAsNode fuse off, Theia's backend does not
   start unless the app runs with `--no-cluster`, so the build would run with it.
4. **The launcher would refuse `--remote-debugging-port`.**
5. **The end-to-end test would run a separately signed test variant**, because Playwright's
   Electron launch needs `--inspect`.
6. **Every walk check would carry a control that fires**, so a zero count is a real reading. A menu
   read that returns no entries would fail the walk rather than pass it.

Still open after S-2b, at least:

- `--remote-debugging-port`: the launcher refusal is proposed and not built;
- the backend upload endpoint, which the spike guards in the page only;
- `devTools: false`, which needs an `ElectronMainApplication` rebind;
- the single-instance lock;
- a move or copy of one `.py` over another, which neither spike reports closed.

Spike S-3 reported that `NODE_OPTIONS` with `--require` redirects the app. S-2b did not reproduce
that.

On a desktop the build split is about simplicity, not a security boundary. Test in either build runs
config code on the user's machine, as `ide/` does today (review R12). Section 5 says what the
controls are.

## 11. Reuse of the `ide/` extension, and the real cost

### 11.1 Why a native extension

The analyst build uses a native Theia extension for two reasons: **surface reduction** and **no VS
Code API**. `@theia/plugin-ext` depends on the terminal, tasks, debug, SCM and AI packages, and
Theia's build keeps transitive extensions (review R6). Running `ide/` under it would bring that
surface back.

The alternative was weighed: keep `@theia/plugin-ext` and filter what it contributes. It saves the
port, but the analyst build would then carry a VS Code API surface whose every route to a text editor
must be found and closed, and stay closed across Theia releases. Spike S-1 is not asked to make that
route work.

### 11.2 What the port costs

- The engine half is shared: `lens parse`, `lens rewrite`, `lens schema` and `dryrun` stay engine
  commands.
- `ide/src/stepsModel.ts` (about 3,500 lines) could become a shared view-model package. Spike S-1
  measured it: every line bundles outside VS Code, and one types-only chain reaches `vscode`
  (`stepsModel.ts` to `liveDebugModel` to `editorToolbar`'s `ElementKind`), so the shared package
  moves `ElementKind` into a module free of `vscode`. About 84.1% of the file's bundled bytes is the
  share a full port links; that is not the share that carries over. The whole file carries over,
  because every line bundles. The rest is code the VS Code provider (`ide/src/stepsView.ts`) does
  not import; other `ide/` modules, such as `ide/src/cli.ts`, use some of it (Manager decision
  2026-10-07, from spike S-1).
- `ide/media/stepsWebview.js` reaches the host only through `acquireVsCodeApi()`. Spike S-1 rendered
  it unchanged in a sandboxed iframe with a shim that supplies that function. The page shell, toolbar
  and CSS live in `ide/src/stepsView.ts`, so they move to the shared package too.
- The provider, `ide/src/stepsView.ts` (about 1,350 lines), is written against
  `vscode.CustomTextEditorProvider` and would be rewritten.
- The Steps views must stay in step. ADR 0076 already runs a differential test between the provider
  and the webview mirror (`ide/src/test/suite/steps-mirror.test.ts`); a third consumer needs the
  same.

### 11.3 What changes from `ide/`, beyond the port

- The text-editor fallbacks (`fallBackToText`, the `openText` message, priority `option` in
  `ide/package.json`) are absent (review R20, Amendment G).
- Test takes a generator spec and runs in place (FR-30 to FR-32).
- Sign-in runs in the backend (FR-5, FR-10). Promote is not offered.
- The chat participant is left out; it needs `vscode.chat` and `vscode.lm`.
- Every `lens rewrite` call passes typed-only mode (FR-25).

## 12. Build, CI and release

- **Layout.** One workspace holds `ide/`, a shared view-model package, and the Theia application,
  beside each other in this repository (Manager decision). The lens row contract and the editor
  change in one pull request.
- **VSIX.** `ide/` keeps building its `.vsix` as today.
- **Audit.** A separate, **non-required** audit job runs over the Theia tree's dependencies. A high
  finding in a runtime dependency of a shipped build is triaged within a release; a finding only in
  build tooling is triaged at the next Theia bump. Spike S-1's `npm audit` found 35 findings in the
  full tree (1 critical, 11 high) and 16 moderate in the runtime tree, all through `@theia`
  dependencies, which is why the job is non-required and triaged rather than a gate (Manager
  decision 2026-10-07, from spike S-1).
- **SBOM and updates.** Each installer ships with an SBOM. Dependabot covers the Theia tree.
- **Installers.** Built in CI, Authenticode-signed, and published as release assets beside the
  engine's (section 13).

## 13. Non-functional requirements

- **Platform.** Windows desktop first, because a site's engine would run as a Windows service (ADR
  0017, `docs/SERVICE.md`) and its analysts would most likely use Windows. Theia's Electron target
  also builds for macOS and Linux.
- **Install.** The analyst build installs and runs Test on a managed Windows image without
  administrator rights (spike S-3).
- **Signing and updates.** Installers are Authenticode-signed. Updates come from a site-controlled
  channel the administrator points at; the analyst build never updates itself from the internet.
- **Version.** Pin one Theia version and record it with spike S-1 (review R33).
- **No PHI.** The analyst build works on config code and generated messages only, and never passes
  `--show-phi`. ADR 0017's config-repository rules apply: no captured messages, no secrets.
- **Network.** The engine API over TLS (FR-2), and the site's git host. Nothing else.
- **Accessibility.** FR-24.
- **Licence.** MessageFoundry's code in the builds is AGPL-3.0-or-later (owner ruling 8). Third-party
  components keep their own licences and are listed in `NOTICE`.

## 14. Engine changes, and what is out of scope

**Engine changes this design needs.** All but the R1 fix are still to be built:

- the `code:steps` permission and the built-in Analyst role (section 4). With the `dryrun`
  generator-spec change below and, only if no existing route fits, one start-up probe route (FR-6),
  these are the only engine API changes;
- the R1 fix and typed-only mode in `messagefoundry/lens.py` (section 5.3). These are built: they
  landed in PR 2155, and Amendment G, G.7, records what still differs;
- the `dryrun` generator-spec input (FR-31, D-B);
- the capability probe (FR-28);
- the repository-check command and its pre-commit hook (FR-40 to FR-46).

**Out of scope for this phase:**

- a hosted, browser-served editor (its own ADR; Appendix A marks which findings it inherits);
- Steps-level editing of `connections.toml`, code sets, environments and `_`-prefixed helpers;
- creating a new Router or Handler file at the Steps level;
- promote from the analyst build;
- OIDC sign-in in the analyst build;
- hot-exit (FR-26);
- AI in either build;
- Theia Cloud.

## 15. Open questions

1. **Implementation detail, settled at build.** Which route does the analyst build call to prove a
   stored token is past every gate (FR-6, FR-8)? If no existing route is on none of the exempt lists
   and open to every editor user, the engine needs one.

Everything else is decided in section 2.

## 16. Test strategy

Manager decision 2026-10-07. Nothing here exists yet; this is how the editor would be tested, layer
by layer.

| Layer | Tool | What it would cover |
|---|---|---|
| 1. Shared view model | mocha in Node, as `ide/`'s `test:unit` | Row rendering and edit building, including the block refusal (FR-20, ADR AC-12). `ide/src/test/suite/steps-mirror.test.ts` would gain the Theia editor as a third consumer, checked against the same fixtures |
| 2. Lens contract | pytest (exists), plus golden editor payloads recorded from the editor | A lens change that breaks the editor would fail in Python CI. Amendment G's AC-G6 and AC-G9 (ADR AC-3) live here |
| 3. Backend services | mocha against each service in Theia's inversify container, with fake processes and a fake engine | Process spawn, git, engine HTTPS, certificate trust, the probe and sign-in: FR-1 to FR-11, FR-25 to FR-29, FR-34 to FR-39; ADR AC-3a (typed-only argv), AC-5, AC-6, AC-7 (no `--show-phi`), AC-8 (no default-branch push), AC-13 to AC-15 |
| 4. End-to-end UI | Playwright's Electron launch against the Electron build that ships, on a Windows runner; this is the run that counts for every criterion in this row. `@theia/playwright`, the Theia project's own end-to-end package, against the browser build is a faster supplement only, never evidence for a criterion (Manager decision 2026-10-07, after review) | The section 6 analyst flow; spike S-2's no-text-route walk (ADR AC-4); no pop-up (ADR AC-16); plain messages (AC-17); drag equals typing (AC-18); the keyboard-only walk (AC-19); FR-12 to FR-24, FR-30 to FR-33 |
| 5. Accessibility | `@axe-core/playwright`, inside the end-to-end run | ADR AC-19's accessibility check |
| 6. Real engine | `messagefoundry serve` with `samples/config` on localhost in CI, users seeded from fixtures | ADR AC-1 (also a pytest) and AC-2 (level selection); sign-in and the session gates against a real engine, trusting its self-signed certificate the way the installer would (FR-2) |

The repository check (FR-40 to FR-46, ADR AC-9) would be tested in Python, with spike S-4's sample
config repository as its fixture. Build composition (ADR AC-10) would be a test over the analyst
build's resolved package list.

In CI these would start as separate, **non-required** jobs (section 12). Spike S-1 confirmed that
`@theia/playwright` 1.76.0 works, with `@playwright/test` 1.63.0 against an installed Edge.

## 17. Spikes required before the ADR is accepted

| Spike | Question | Pass condition |
|---|---|---|
| S-1 | Does a native Theia Steps extension render and edit `samples/config`, and how much of `ide/` does it reuse? | Parse, render, edit, undo and Test work in a pinned Theia build; hot-exit is verified or dropped from FR-26; the shared share of `stepsModel.ts` and the `acquireVsCodeApi` shim are measured; the typed-row versus `code`-row share over `samples/config` is recorded; the Theia version and language server are recorded; @theia/playwright runs at that version (section 16). **Met except the Test and language-server legs**, measured on a browser target: branch `claude/theia-spike-s1` at `cd97e6b1b4`, under `theia-spike/`, not merged, on Theia 1.76.0. Hot-exit was dropped (FR-26). Test is open because it needs the D-B generator-spec engine change, which is not built. No language server was recorded. The Electron build is checked by spike S-3 (Manager decision 2026-10-07, after review) |
| S-2 | Does the analyst build have no text-editor route for `.py`? | A scripted walk of every command, menu and *Open With* entry opens no `.py` in Monaco, and finds no pop-up notification (FR-17). **Met on the browser build and on Electron.** Browser: branch `claude/theia-spike-s2` at `d35ae64158`, under `theia-spike/`, not merged. Electron, spike S-2b: branch `claude/theia-spike-s2b-electron` at `7a1f6ba72e`, on the S-3 installer base with S-2 merged in, not merged. The installed packaged app passed 5 of 5: the walk enumerated 609 commands and ran 237, and found no `.py` text editor and no toast, while the toast control fired. The browser rerun passed 3 of 3. Section 10 lists what S-2b closed and what is still open (Manager decision 2026-10-08, from spike S-2b) |
| S-3 | Does the analyst build install and run on a managed Windows image? | It installs and runs Test without administrator rights, as the Electron build; installer size and memory use are recorded. It was planned as the first check of the Electron target, which spike S-1 did not run. Spike S-2b, built on the S-3 installer base, has since run the installed Electron app for S-2's walk; S-3's own pass condition is not recorded here as met. S-2b did not reproduce a claim from the S-3 work that `NODE_OPTIONS` with `--require` redirects the app (Manager decision 2026-10-08, from spike S-2b) |
| S-4 | The repository check as a CI step on a sample config repository | It meets FR-41, run from a base-ref workflow per section 5.4. **Classifier half met by the spike against FR-41 as it stood then**: branch `claude/theia-spike-s4-steps-only` at `673faa7c60`, `scripts/theia_spike/steps_only.py` with 80 tests in `tests/test_theia_steps_only_spike.py`, not merged. The FR-41 cases added later (the lookup-params, `FhirToken` and value-param cases for `SEEN` and a `code_set` name) are untested. The base-ref workflow half is untested |

---

## Appendix A: disposition of the first review's findings

The review of 2026-10-07 read the 2026-10-02 drafts through four lenses. Forty-one of forty-four raw
findings survived adversarial verification; the synthesis merged them into R1 to R34. "Hosted ADR"
means the finding applies only to a hosted design and is carried to the later ADR that designs it.

| Finding | Severity | Disposition | Where |
|---|---|---|---|
| R1 | blocker | **Answered by design; the lens half landed in PR 2155 (2026-10-08).** The R1 fix plus typed-only mode; Amendment G, G.7 records what still differs. A precondition for the analyst build | Section 5.3, FR-18, FR-25, ADR D6, AC-3, AC-3a, Amendment G (G.6, G.7) |
| R2 | major | Addressed: every session gate named, a non-exempt probe | FR-5, FR-6, ADR AC-5 |
| R3 | major | Addressed for desktop: no timer poll. Hosted ADR keeps the engine-change question | FR-8 |
| R4 | major | Not applicable to desktop: no central token store. Hosted ADR | FR-10 |
| R5 | major | Not applicable to desktop: the analyst pushes with their own git credential. Hosted ADR | FR-37, section 5.4 |
| R6 | major | Addressed: native extension in both builds | Section 11.1, ADR D3 |
| R7 | major | Not applicable to desktop: no broker. Hosted ADR | FR-26 |
| R8 | major | Addressed by owner rulings 3 and 6 | Sections 5.4, 5.5, 7.8 |
| R9 | major | Addressed: ADR 0076 Amendment G | Amendment G, FR-14, FR-15 |
| R10 | minor | Addressed: every engine change listed | Section 14, ADR D4 |
| R11 | minor | Addressed: `config:validate` marked declared, not enforced, and unused | Section 4 |
| R12 | minor | Partly applicable: Test runs config code on the user's machine, as `ide/` does. Hosted ADR | Section 10 |
| R13 | minor | Addressed: Test takes a generator spec; no `--show-phi` | FR-30, FR-31, ADR D10, AC-7 |
| R14 | minor | Addressed | FR-27, FR-28, section 12, ADR D11 |
| R15 | minor | Not applicable to desktop: no broker path. Hosted ADR | |
| R16 | minor | Not applicable to desktop: one writer. Hosted ADR | |
| R17 | minor | Not applicable to desktop: no shared gateway address. Hosted ADR | |
| R18 | minor | Addressed | ADR acceptance criteria |
| R19 | minor | Not applicable to desktop: no gateway. Hosted ADR | |
| R20 | minor | Addressed | Section 11.3, FR-14, spike S-2 |
| R21 | minor | Addressed | Section 10 |
| R22 | minor | Addressed | FR-39 |
| R23 | minor | Addressed: the web-console option, now option 6, re-weighed in the ADR | ADR options |
| R24 | minor | Addressed by owner ruling 4 | Section 7.7 |
| R25 | minor | Not applicable: no hosting cost threshold on the desktop. Hosted ADR | |
| R26 | minor | Addressed | FR-29 |
| R27 | note | Addressed | FR-22 |
| R28 | note | Addressed: one out-of-scope list | Section 14 |
| R29 | note | Addressed | Section 5.1, ADR Related |
| R30 | note | Not applicable to desktop. Hosted ADR | |
| R31 | note | Addressed: Theia Cloud deferred | ADR options |
| R32 | note | Addressed | Section 10 |
| R33 | note | Addressed | Section 13, spike S-1 |
| R34 | note | Not applicable: concerned the review's own inputs | |

**Counts:** 22 addressed (R3 for the desktop only; R8 and R24 by owner ruling), 1 answered by design
whose lens half landed in PR 2155 (R1), 1 partly applicable (R12), 10 not applicable to the desktop phase. The hosted
ADR inherits R3, R4, R5, R7, R12, R15, R16, R17, R19, R25 and R30.

Three raw findings were refuted in verification and need no action: dual control on reload is
conditional; a licensing claim, settled by owner ruling 8; and an operating-cost objection the drafts
already named.

## Appendix B: review round 2 (2026-10-07)

Four lenses reviewed `ffd5c47210`, and an adversarial pass verified each finding against the tree.
Each surviving finding landed here. S6 and S7 were not in the surviving set handed to this round, so
they have no row.

| Finding | Where it landed |
|---|---|
| S1 | FR-40 item 4, FR-41, spike S-4 |
| S2 | Section 5.4, section 5.2 last row |
| S3, C1 | Section 5.3, ADR D6 and AC-3, Amendment G G.7 and AC-G9 |
| S4, C2 | FR-40 items 2 and 3, FR-41 |
| S5 | D-C, section 5.2, section 5.5 |
| S8 | FR-35, FR-36 |
| S9, C13, A12 | FR-5, FR-6, FR-8, section 14 (OIDC out of scope) |
| S10, A16 | Section 4 |
| S11 | FR-42, FR-43 |
| S12 | Section 5.3 (`assign_to`), section 5.2 |
| S13, C6, C7 | Section 5.3, Amendment G G.6 |
| A5, U11, U14 | Section 9 |
| A6, U6 | FR-1 to FR-4, FR-11 |
| A7 | FR-27, FR-28, FR-44 |
| A8 | Section 11.1, 11.2, ADR D3 |
| A9 | Section 12 |
| A10, U3 | Section 6, FR-34 to FR-39, ADR AC-13 to AC-15 |
| A11 | Section 13, spike S-3 |
| A13, C11 | Section 10, ADR D3 |
| A14 | FR-26, spike S-1 |
| A15, C14 | Section 13; ADR 0076 index row |
| A17, U12, U16 | FR-12 |
| U2 | FR-31 |
| U4 | FR-16, FR-17, FR-32, ADR AC-11, AC-16 |
| U5 | FR-17, ADR AC-17 |
| U7 | FR-13, FR-9 |
| U8 | FR-16, section 8.2, spike S-1 |
| U9 | FR-18, FR-23 (future item: the lens has no duplicate op) |
| U10 | FR-21, ADR AC-18 |
| U13 | FR-34 |
| U15 | FR-24, ADR AC-19 |
| C3 | Amendment G introduction names the E.11 pointer; G.6 wording fixed |
| C4, C5 | D-A; every ADR criterion scoped to one build |
| C8 | Section 14, ADR D4 |
| C9 | FR-40 item 2 |
| C10 | Section 8.2, practice 2 |
| C12 | Section 13, platform |
| D-A, D-B, D-C | Section 2, and throughout |

### Review round 3 (2026-10-07)

An independent review of `e845ed2589`, which also read the R1 branch at `be2b886db1`, found these.
Each was checked against the tree and that branch.

| Finding | Where it landed |
|---|---|
| 1. Inert rule restated and narrower than the branch | Amendment G, G.7 states it once with "at least" and names the R1 tests as the source of record; G.5 holds the payloads; ADR D6, AC-3 and spec 5.3 point there |
| 2. Templates outside E.11 rule 4's params | FR-40 item 5 |
| 3. Where the check runs | Section 5.4 (general rule first, GitHub specifics marked), FR-43, FR-44 |
| 4. A dynamic send or route made literal | FR-40 item 6, FR-41; the lens refusal in G.7 |
| 5. Block protection keyed on "unrecognized test"; removed or moved headers | FR-20, FR-40 item 4, ADR AC-12, AC-G5, G.6 |
| 6. Palette steps that send `{"expr"}` today | FR-18, FR-18a |
| 7. `PATH` fallback; minimum engine version | Section 9 |
| 8. `mfa_gate=False` routes; sign-out only for an open gate | FR-6, ADR D5 and AC-5 |
| 9. Stale base undefined | FR-39, ADR AC-13 |
| 10. Test for a type with no generator | FR-33, ADR D10 |
| 11. Component names in messages | FR-17, ADR AC-17 |
| 12. "Can still do" list | Section 5.2 |
| 13. Appendix A | R23 and R25 rows, counts |
| 14. Blank line; `ai:assist` on `POST /ai/chat` | FR-40 item 2, section 4 |
| Test strategy (Manager decision) | Section 16 |

### Review round 4 (2026-10-07)

The Lander held PR 2154 at `f381613ba3` after a code review of the repair delta, with findings F1 to
F15. Spike S-4 then built FR-40 as a prototype and reported where its text was wrong, and spike S-1
reported its measurements. Each finding
was checked against `messagefoundry/lens.py` at `origin/main` and on the R1 branch at `8df2bcf210`.

| Finding | Where it landed |
|---|---|
| F1. Typed rows compared by `params` only | FR-40 item 5a, FR-41; the lens's own gap is open work, Amendment G, G.7 |
| F2. A palette block's `pass` seed blocks its own delete | Amendment G, G.6 structure rule; FR-40 item 3 |
| F3. Merge before commit | FR-34, section 6 step 7 |
| F4. Deleting an `if` skips its `elif` and `else` | Amendment G, G.6 structure rule 5 |
| F5. Refusal keyed on the moved row | Amendment G, G.6 structure rule 2, stated as an invariant |
| F6. A mutable module-level name read as inert | Amendment G, G.7; FR-41 |
| F7. AC-G7 against `_validated_raw_test` | Amendment G, AC-G7 |
| F8. The inert list used as a gate | Amendment G, G.7; FR-40 item 5 |
| F9. Layer 4 on the browser build | Section 16, layer 4 |
| F10. AC-13 against FR-34 and AC-15 | ADR AC-13 |
| F11. Probe answers left undefined | FR-6 table, ADR AC-5 |
| F12. ADR 0103 Delete and Move, ADR 0089 block-cut | Amendment G, G.6 |
| F13. Stale-base test never resets | FR-39 |
| F14. Block rule restated; stale index rows | Amendment G, G.6 states it once; G.1, AC-G5, FR-20, section 8.2, ADR AC-12 point there; `docs/adr/README.md` rows |
| F15. Deleted-lookup residual | Amendment G, G.6 rule 6 |
| Spike S-4 findings | FR-40 items 2 to 6, the false-failure and public-surface notes, FR-41, section 17 |
| Spike S-1 findings | FR-26, sections 8.1, 8.2, 9, 10, 11.2, 12, 16 and 17; ADR D3, D9 and AC-10 |
| Spike S-2 findings | FR-17, section 10, section 17; Amendment G AC-G1 |
| Spike S-2b findings (2026-10-08) | Section 10, section 17; Amendment G AC-G1 |
| Review of `af7f0a73e8`: a `code_set` name is shared mutable storage | Amendment G, G.7 (only as `code_lookup`'s `table`), AC-G9; FR-40 item 5, FR-41 |
| Review of `af7f0a73e8`: binding rows and dynamic rows under G.6 | Amendment G, G.6 rules 4 to 6; section 5.2 |
| Review of `af7f0a73e8`: other findings | S-1 and S-3 rows, section 7.7, section 11.2, ADR D3 and AC-14, FR-40 items 3 to 5, this table, README rows |

## Appendix C: what changed from the 2026-10-02 drafts

| Draft | This spec | Why |
|---|---|---|
| Hosted in a browser behind a gateway | Desktop app first; hosting later | Owner ruling 2 |
| Enforcement was the reason to host | A simpler interface is the reason | Owner ruling 1 |
| Read-only mount plus server-side broker as the control | Role check in the analyst build (primary) plus an optional repository check, with section 5 saying what each does | Owner ruling 3; SDS-3.7 |
| Hosted Code build with a shell | Developer build on the desktop with no per-user limits, or VS Code and `ide/` | Owner ruling 4; D-A |
| Steps view as the `ide/` plugin or a native extension | Native extension in both builds | Review R6; ADR D3 |
| Claimed a typed-row edit cannot inject Python | States R1 as a precondition, answered by two changes that landed in PR 2155 | Review R1; owner ruling 5 |
| Cited ADR 0076 Amendments A to E | Amendments A, C, D, E and F apply; B was declined | Review R9 |
| "Studio" working name | Dropped | Two builds of one editor need no name yet |
