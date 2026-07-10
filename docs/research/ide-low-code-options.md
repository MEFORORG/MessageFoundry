# IDE low-code & wizard options — VS Code integration deep-research (research)

**Date:** 2026-07-10 · **Status:** research / findings (no code) · **Owner action:** see *Ranked
recommendation* + *Backlog candidates* below.

**Driving question (owner, 2026-07-10):** the `ide/` extension is hitting VS Code UX design
limitations ([UX guidelines](https://code.visualstudio.com/api/ux-guidelines/overview)). The goal is
"the best of a coding IDE, but also a helpful toolbar and wizards" — interface setup intuitive for
healthcare interface analysts who **don't know Python** — up to and including a low-code option,
**without** the overhead of a full standalone Corepoint-style configuration studio. Corepoint's
Action-List editor (ribbon of typed actions: ItemCopy/ItemReplace/If-Else/ForEach/DBSelect…, with a
Test button) is the concrete reference, including its **non-visual, structured-script-editor**
character. The owner is explicitly open to revisiting the #26 visual-authoring decline.

**Method.** Two adversarially-verified research passes (2026-07-10): a 104-agent deep-research
workflow (5 angles → 22 sources fetched → 107 claims extracted → top-25 verified: **24 confirmed,
1 refuted**), plus a targeted 33-agent second round on the 11 claims this report leans on that the
first pass left unverified (3 lenses each — source fidelity, counter-evidence, currency: **10
survived, 1 killed** for misattribution; 2 survived with corrections, honored below). Extension
ground truth re-checked against `origin/main @ 954bd22`.

---

## 1. The VS Code constraint, precisely (all verified 3-0 against primary sources)

- **No ribbon, no global toolbar — ever.** Extension UI is items slotted into an enumerated set of
  containers; toolbar contributions are limited to view toolbars, the sidebar toolbar, and editor
  actions. The long-running upstream requests for a customizable global toolbar
  ([microsoft/vscode#18042](https://github.com/microsoft/vscode/issues/18042),
  [#41309](https://github.com/microsoft/vscode/issues/41309)) were declined/left unimplemented. A
  native Corepoint ribbon is architecturally impossible in an extension.
- **The editor area is the sanctioned freeform surface.** Custom Editors and Webviews may render
  "almost any HTML content" there — this is where every successful designer precedent lives.
- **`CustomTextEditorProvider` is the documented form-over-file mechanism**
  ([custom editors guide](https://code.visualstudio.com/api/extension-guides/custom-editors)):
  registered by filename glob, it replaces the text editor when the file opens; the real
  `TextDocument` is the data model (the on-disk file stays the single source of truth), VS Code
  provides save/backup/hot-exit/undo, and the user can always "Reopen With" the plain text editor.
  Stable API since 1.44 (2020).
- **Webviews carry documented costs** ([webview guide](https://code.visualstudio.com/api/extension-guides/webview),
  [webview UX guidelines](https://code.visualstudio.com/api/ux-guidelines/webviews)): officially a
  last resort ("used sparingly and only when VS Code's native API is inadequate" — the guidelines
  literally list *wizards* among webview don'ts, though a designer over a domain file passes the
  "native API inadequate" test per the shipped precedents below); content is **destroyed when the
  tab backgrounds** unless state is persisted (`getState`/`setState`) or `retainContextWhenHidden`
  (documented "significant memory overhead") is paid; sandboxed async `postMessage` only; strict
  CSP; and a documented **webview↔document infinite-update-loop hazard** the extension must guard.
- **Refuted claim worth recording:** "webviews are an officially endorsed escape hatch" died 0-3.
  They are *permitted-but-discouraged*. A webview-heavy designer must justify itself under the docs'
  own inadequacy test — the precedents below show a domain designer does.

## 2. Precedents: designers shipped inside VS Code (verified 3-0 unless noted)

| Precedent | Architecture | What it proves |
|---|---|---|
| **Kaoto** (Red Hat, Apache-2.0, v2.11.0 2026-06, ~18.3K installs) — [repo](https://github.com/KaotoIO/vscode-kaoto) · [site](https://kaoto.io/) | Custom editor (React webview) over real `*.camel.yaml`/`*.camel.xml` files; node click → config form; 300+ component catalog; DataMapper | A low/no-code designer for a **code-first integration engine**, explicitly for users "without deep Camel knowledge"; YAML stays the reviewable source of truth. Side-by-side design+source toggle exists but is opt-in (2-1 vote — default open is visual alone) |
| **Apache Camel Karavan** (v4.18.1 2026-06, ~16.7K installs) — [marketplace](https://marketplace.visualstudio.com/items?itemName=camel-karavan.karavan) | Same shape; created "to make Camel accessible for Non-Java Developers and Citizen-Integrators" (2021 launch post now 404s — verified via apache/camel-website repo + Wayback) | Second independent citizen-integrator designer over a code-first engine, from the Camel project itself |
| **AWS Step Functions Workflow Studio** — [docs](https://docs.aws.amazon.com/toolkit-for-vscode/latest/userguide/stepfunctions-workflowstudio.html) · aws-toolkit-vscode `workflowStudioEditorProvider.ts` | `CustomTextEditorProvider`, **default editor** for `*.asl.json`/`*.asl.yaml` (opt-out via `workbench.editorAssociations`); Design mode (drag-drop states browser, design toolbar with undo/delete/zoom, properties inspector, **in-editor test-state UI**) + Code mode over the same file | "Best of a coding IDE plus toolbars and wizards" is achievable **inside** a custom editor's webview — the rich chrome lives in the editor surface, not workbench chrome. Caveat: documented feature cuts vs. its web-console sibling (no Config mode) |
| **InterSystems low-code editors** (healthcare!) — [docs](https://docs.intersystems.com/components/csp/docbook/DocBook.UI.Page.cls?KEY=GVSCO_lowcode) | Rule Editor (IRIS 2023.1) → DTL (2025.1) → BPL (2026.1), custom editors over real class documents, opened via a "Reopen in Low-Code Editor" **CodeLens**; server-backed | A healthcare integration vendor rebuilt its low-code editors **as VS Code custom editors**, staged simplest-first, with honest guardrails: low-code edits sync to the text document **only on save**; documented **one-editor-at-a-time** warning; graceful modal-and-fallback to the text editor when the low-code view can't load |
| **Ballerina** (WSO2) — [why-graphical](https://ballerina.io/why-ballerina/graphical/) | Sequence/flow diagrams + service designers + Data Mapper **derived from real source code** (no separate model file), in the official VS Code extension | The one code-derived-visual precedent — and it required a language **designed** for bidirectional syntax↔visual mapping, which Python was not. Also the sole verified data point on "standalone studio vs. VS Code": Ballerina **deprecated** its standalone Composer and folded graphical editing *into* the extension |

## 3. What analysts respond to in the commercial engines (verified, 2nd round)

- **Iguana (closest analog — code-first Lua).** The Translator re-runs the script on every edit
  against imported sample messages and renders an **annotation block beside each executed line
  showing the actual data** flowing through it; anything that makes annotations stale (script or
  sample edit) hides them until re-execution; drill-down dialogs show the HL7 as a parsed node tree
  ([v6 docs](https://help.interfaceware.com/v6/annotations), verified 3-0; feature carried forward
  as a headline capability of Iguana X per current docs). Third-party comparisons credit **this
  loop, not drag-drop**, as the productivity differentiator. Vendor's own framing of the
  non-expert problem: autocomplete against the parsed message tree + templates + prebuilt modules +
  a product-tuned AI assistant ([blog](https://www.interfaceware.com/blog/you-dont-need-to-be-a-lua-expert-to-build-in-iguana)).
- **Corepoint.** Authoring is a **typed action library chained in a structured list editor** — a
  non-visual structured *script* editor, not a canvas. Verified practitioner testimony
  ([Clovertech thread](https://clovertech.infor.com/forums/topic/corepoint-any-pros-or-cons/) —
  note: 2014, product now Rhapsody Corepoint 7.3, same authoring model): usable by "a lot more
  people" than programmer-oriented engines, **but** the ceiling is the documented complaint — "the
  interface analyst is insulated from most of the workings… I felt a bit fenced in", "hands were
  tied" on creative tasks, "seemingly simple tasks took lots of steps", complex work leaks a
  **regex-skill** requirement, and sample-driven message-structure inference was called "very
  flaky". The praised operational feature: **one-click bundle-and-promote-to-Live** (the `ide/`
  promote flow is already on this track). *Correction honored (2-1 vote):* Corepoint is not
  entirely escape-hatch-free — edge cases route to custom **C# outside the product** / SQL procs
  (vendor claims ~99.7% of interfaces stay native); and Mirth has no-code Mapper/Message-Builder
  steps before JavaScript — "requires JS" softened to "defaults to JS beyond simple mappings".
- **Synthesis.** Corepoint's approachability comes from **typed actions**; its frustration comes
  from **no code underneath in-product**. Iguana's praise comes from **making code legible**. MessageFoundry
  can be the engine that has both — the live loop **already shipped** (#92 v1 #793 / v2 #805, ADR
  0072); the typed-action layer is the open gap.

## 4. Round-trip guardrails (what keeps a low-code lens honest)

Verified against the code-generation literature and the shipped editors:

1. **Structural round-trips; behavioral doesn't.** Structural constructs map bidirectionally;
   behavioral code generated from higher abstractions cannot be reverse-engineered once hand edits
   break the pattern ([arXiv 1509.04498](https://arxiv.org/pdf/1509.04498);
   [LieberLieber 2015](https://blog.lieberlieber.com/2015/09/05/why-round-trip-engineering-does-not-work/) —
   vendor conceptual argument). *Attribution correction from verification:* the famous "after two
   or three iterations it typically fails" quote is a separate practitioner report about Visual
   Paradigm's C++ round-trip ([forum, 2021](https://forums.visual-paradigm.com/t/shortcomings-of-c-round-trip-engineering/16760)),
   **not** the LieberLieber post.
2. **Protected regions can't guarantee hand edits survive regeneration; separate files can**
   (arXiv survey: the only mechanism with the guarantee). The loader's `_`-prefixed-helpers
   convention already supports scaffold-vs-hand-code file separation.
3. **Sync on save only · one editor at a time · guard the update loop · degrade gracefully to the
   text editor** — InterSystems documents all four; VS Code documents the loop hazard.
4. **Refuse to represent what you can't parse** — render unrecognized code read-only or bail to
   the text editor with a notice; never guess.

## 5. Where `ide/` stands (origin/main @ 954bd22)

~6.2K LOC TS, 26 commands, activity-bar Home (action-card webview), Connections/Translation-Tables
trees, form webviews for `connections.toml` (ADR 0007) / code sets (ADR 0033) / alerts (ADR 0014),
5-step Route Wizard webview, an editor-area build toolbar (editor/title Validate / Test Bench /
Promote + the `messagefoundry.editorMenu` submenu, per-`@router`/`@handler` CodeLens), the Insert
Element palette (#48), a shipped "Get Started" walkthrough + Cookbook (PR #798), Test Bench (dryrun
+ before/after diff + debugpy), validate→Problems, staged promote flow, `@messagefoundry` chat
participant, HL7-path completion — and the **shipped live-debug loop** (`ide/src/liveDebug.ts`,
which carries its own lane status-bar items): v1 on-save dryrun watcher + CodeLens summaries, v2
per-statement inline values + hover via traced dry-run (ADR 0072), PHI-redacted by default,
synthetic samples only.

**Genuinely unused high-leverage surfaces:** no `customEditors` registration (the form editors are
command-opened, not file-associated), no status-bar **engine** indicator (target/env/health), no
TOML language association, no native QuickInput wizard path, all webviews hand-rolled
vanilla-JS/HTML; the shipped walkthrough lacks engine-setup / live-debug / promote steps.
Marketplace publish is a do-next explicitly waiting on "planned IDE-focused improvements".

## 6. Options inside VS Code

**A — Native polish + onboarding (small, do regardless).** Extend the shipped Get Started
walkthrough (PR #798) with the missing point-at-engine / open-config-dir / live-debug / promote
steps; register the
existing connection/code-set forms as `customEditors` by glob (double-clicking `connections.toml`
opens the form; "Reopen With" keeps the text path — the AWS default-editor-with-opt-out pattern);
status-bar engine indicator; TOML language association; native multi-step QuickInput wizard
(official `multiStepInput` pattern) as a keyboard-first fallback. Makes the extension feel like a
product instead of a bag of commands. Risk ≈ 0. → **Backlog #221.**

**B — Live loop.** **Shipped** (#92 v1+v2). Residual slivers live in #92/#84's own follow-ups
(sample picker breadth, store-import of samples, Test Bench panes) — no new item filed here.

**C — Corepoint-style structured action-list lens over real Python (the flagship gap).** Two-part,
phased: **(1)** a typed action vocabulary on the `messagefoundry` surface (`copy`, `replace`,
`format_date`, `split`, `convert`, `code_lookup` → code sets, `db_lookup` exists, if/else +
for-each-segment idioms) — plain Python, valuable standalone as the scaffold vocabulary for
snippets/completion/AI; **(2)** a `CustomTextEditorProvider` over Handler `.py` files that
AST-parses (server-side via the CLI, InterSystems-style) and renders any *parseable* handler as a
Corepoint-style ordered action-list view with parameter forms, an in-editor toolbar, and a Test
button — typed rows for vocabulary code, in-place read-only code rows for anything else, whole-file
bail to the text editor only on parse failure;
**(3)** editing: form edits emit AST-based rewrites of the same file, sync-on-save,
one-editor-at-a-time, "Reopen With: Python" always. The analyst sees the familiar action-list view —
**and** the shipped live-debug annotations (PHI-redacted by default, synthetic samples only) can
render live values beside each action row — a combination neither Corepoint (no code in-product)
nor Iguana (no typed actions) offers. Constraining the lens
to a *typed vocabulary* (structural) rather than arbitrary Python (behavioral) is the load-bearing
decision per §4 — resist widening it. Formally revisits #26, narrowly: no opaque runtime object, no
declarative interpreter, no second execution path — the engine still runs plain Python; the action
list is a **lens**. → **Backlog #222 + #26 amendment; ADR-gated.**

**D — Wiring-graph canvas (structural-only, later).** A custom-editor canvas over the
Connection→Router→Handler graph (`graph --json` exists): drag to create/bind endpoints, node click
opens the form or the code, creating a handler scaffolds a file. Logic bodies stay code — the
canvas edits only structure, the part that round-trips losslessly (Kaoto/Karavan's exact
division). Drifts toward #26's failure mode only if it grows logic nodes.

**E — AI-assisted authoring (cheap force-multiplier).** Wire `@messagefoundry` (`/transform`,
`/router`) into the wizards: describe the mapping in English → generated handler **using the
Option C vocabulary** → live loop shows it working. Iguana X ships the same idea. Governed by the
existing AI policy gate (`code_only`).

## 7. Outside VS Code — the "better way" alternatives, costed (verified)

| Path | Evidence | Verdict |
|---|---|---|
| **Theia branded "MessageFoundry Studio"** | Arduino IDE 2.x precedent ([Eclipse adopter story](https://blogs.eclipse.org/post/john-kellerman/theia-adopter-story-new-arduino-ide-20)): reduced initial effort; custom toolbars/workbench chrome straightforward "in contrast to VS Code"; Monaco+LSP editing for free. Runs VS Code extensions (Open VSX; ~1-month compat lag per [EclipseSource](https://eclipsesource.com/blogs/2024/12/17/is-it-a-good-idea-to-fork-vs-code/)); ongoing upstream engagement cost | The credible exit. **Parked** — the extension investment carries over, so building §6 is also building toward this |
| **Fork VS Code** | Loses Marketplace + proprietary MS extensions (C++/Live Share/Remote Dev; Copilot backend still closed despite Copilot Chat going MIT 2025); "started smoothly, became a nightmare" (EclipseSource customer projects) | No |
| **code-server / openvscode-server in the web console** | MS VS Code Server license forbids embedding ([code-server discussion #6256](https://github.com/coder/code-server/discussions/6256)); MIT Code-OSS derivatives are the legal path, Open VSX only | Plausible later as a *delivery* mechanism for the same extension next to the shipped web ops console — not a UX solution itself |
| **Monaco + custom UI in the console** | CoderPad first-hand ([blog](https://coderpad.io/blog/development/developer-diaries-how-we-built-coderpad-monaco-ide/)): TextMate-quality highlighting required forking monaco-editor + WASM Oniguruma; LSP server-side; permanent wrapper layer. (No extension ecosystem — general knowledge, not from that source) | Only for a narrow embedded editor (one handler from the console), never the primary experience |
| **Standalone Qt/Electron designer** | Web stacks are the de facto tool standard even for desktop-shipped tools ([EclipseSource 2025](https://eclipsesource.com/blogs/2025/02/27/how-to-build-a-custom-ide-or-tool/)); forfeits the coding-IDE half of the goal | No — this is the Corepoint-overhead path the owner already suspected |

## 8. Ranked recommendation

1. **#221 (Option A) now** — small, and it's most of the "make VS Code friendlier" ask; also the
   cheap half of the marketplace-publish gate.
2. **#222 (Option C) phased as the flagship** — the vocabulary first (standalone value, low risk),
   the read-only lens second, editing last; ADR before phase 2. With #92 shipped, this is the
   remaining genuine gap between MessageFoundry and the Corepoint-analyst experience — and the
   combination (typed actions + live values + real Python underneath) is one no rival ships.
3. **Option E alongside** — wire the chat participant into the wizards once the vocabulary exists.
4. **Option D later, structural-only** — demo value; B/C do more for real authoring.
5. **Theia: parked, deliberately** — revisit only on a wall the custom-editor surface genuinely
   can't express; nothing above is stranded by the move.

## 9. Evidence confidence

VS Code platform claims and every named precedent: verified 3-0 against primary sources
(2026-07-10 snapshot; the cited APIs stable since 2020, all precedent extensions with 2026
releases). Corepoint testimony verified-as-existing but **dates to 2014** (now Rhapsody Corepoint
7.3, same model) — the owner's daily first-hand Corepoint experience supersedes it where they
conflict. Kaoto/Karavan/Ballerina "for non-coders" claims are **vendor intent, not measured analyst
outcomes** — no adoption studies survived verification. Corepoint/Rhapsody official docs remain
customer-gated. One first-pass claim refuted (webviews-as-endorsed-escape-hatch, 0-3); one
second-pass claim killed for misattribution (the "2-3 iterations" quote — corrected in §4).

## Backlog candidates (drafted alongside this doc)

- **#26 amendment** — narrow the decline: carve out the structured action-list *lens* (artifact
  stays plain Python); declarative logic execution + drag-drop canvas logic authoring remain
  declined. Mirrored by a CLAUDE.md §12 clarifier.
- **#221** — IDE native-surface polish (walkthrough, registered custom editors, status bar, TOML
  association, QuickInput wizard).
- **#222** — typed action vocabulary + action-list custom-editor lens (phased, ADR-gated).
