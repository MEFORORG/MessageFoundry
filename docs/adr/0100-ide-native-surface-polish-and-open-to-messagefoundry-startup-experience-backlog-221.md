# ADR 0100 — IDE native-surface polish and open-to-MessageFoundry startup experience (BACKLOG #221)

- **Status:** Accepted (2026-07-12) — the native surface shipped incrementally; the startup +
  code-view-toolbar + brand-icon additions built this session (#967/#972). Closes BACKLOG #221.
- **Deciders:** owner-directed (this session's screenshots + directives)
- **Extends:** [ADR 0089](0089-recognition-first-lens-native-idioms.md) /
  ADR 0076 (the Steps action-list lens this chrome surrounds),
  [ADR 0091](0091-element-centric-connections-view.md) (the CONNECTIONS view + Wiring Map),
  [ADR 0007](0007-gui-manageable-connections-toml.md) (the connections.toml custom editor); brand
  rules in [`docs/BRAND.md`](../BRAND.md)

## Context

BACKLOG #221 ("IDE native-surface polish") bundled the VS Code extension's host-integration surface —
the affordances that make it feel native rather than a bolt-on. Most shipped incrementally and was
never recorded as a decision; this ADR enumerates WHAT the native surface is and captures the
startup / code-view-toolbar / brand decisions added this session, so #221 closes with a record rather
than being silently absorbed. It is IDE **chrome around the code-first model** — every affordance is
navigation, a view, a native editor, or a structured edit that projects to real `.py`. None is a
visual authoring canvas: **#26 (no visual/declarative authoring) is untouched** — the Steps lens
itself is ADR 0076/0089; this ADR is the surrounding surface.

## Decision

### 1. Native host surface (shipped, #221)

- **Custom editors** — `connections.toml` opens in a form editor and code sets in a grid editor
  (ADR 0007), each with "Reopen With → Text Editor" always available; `.py` opts into the Steps custom
  editor at `priority: "option"` (never the default, so Python files keep the user's own tooling).
- **Walkthroughs** — a Get-Started walkthrough (point-at-engine, new-connection, new-route,
  insert-element, test-bench, promote, cookbook, live-debug, open-config-dir).
- **Status bar** — an engine-target item (`MEFOR: <host>`) that opens engine settings, plus the
  live-debug `MEFOR Live` toggle (live-debug is ADR-covered separately).
- **TOML language association** + a branded MessageFoundry editor-title submenu, gated on the
  `messagefoundry.isConfigFile` context (a config-dir `.py`).
- **Connection wizards** — a webview form and a keyboard-first QuickInput wizard, both desugaring
  through the same `connections.toml` factories.

### 2. Open-to-MessageFoundry startup experience (this session)

VS Code has no native "default sidebar view" setting, so an **opt-in, per-workspace**
`messagefoundry.revealViewOnStartup` (default `false`) runs `workbench.view.extension.messagefoundry`
on activation (config workspaces already activate at startup via `workspaceContains:**/*.py`). Set it
per-workspace in `.vscode/settings.json` so only a MessageFoundry config repo opens straight to the
sidebar; every other window is unaffected. The Home view gains a **"Setup"** group (collapsed by
default, at the bottom) that tucks one-time setup (version-control setup, repo-storage location) out
of the everyday action items, and carries an **"Extension Settings"** item (a new
`messagefoundry.openSettings` → the Settings UI filtered to `@ext:messagefoundry.messagefoundry`) so
the extension's settings (liveStatus, configDir, engine target) are discoverable without `Ctrl+,`.

### 3. Code-view action toolbar (this session)

The Steps **webview** can carry a rich button toolbar; the **code** view is VS Code's native text
editor, which cannot host injected chrome. So the native equivalents: an editor-title **icon cluster**
(View as Steps / Test Bench / Validate, hidden while the Steps editor is active) and a consolidated
inline **CodeLens action row** above each `@handler` (View as Steps · Test Bench · Validate · Insert
Element), with one provider owning the order. **Rejected:** hosting Monaco in a webview to get a
custom code toolbar — it would be a *standalone* Monaco without Pylance/IntelliSense/diagnostics, a net
regression for editing real Python.

### 4. Brand — signature action icons in molten amber (this session)

VS Code renders codicon toolbar icons monochrome (`icon-foreground`) with no manifest color hook, so
MessageFoundry's **distinctive** actions (View as Steps, Test Bench, Validate, Open/Show in Wiring
Map) are brand-coloured by vendoring amber (`#f59e0b`) SVGs (CC BY 4.0 codicon recolours, attributed
in each file) and pointing the commands at them. Generic utilities (refresh/filter/add/gear) stay
themeable codicons. Per `docs/BRAND.md`, amber marks the brand's own affordances, not every UI verb
(accent scarcity; amber on light themes is borderline for small marks).

## Consequences

- #221 closes **honestly** — the native surface is enumerated and the startup/toolbar/brand additions
  have a recorded rationale.
- The extension reads as a first-class MessageFoundry surface **without** crossing into visual
  authoring (#26): every affordance is navigation, a view, a native editor, or a structured `.py` edit.
- Amber SVGs do not theme-adapt (always amber) — acceptable for a small branded set, borderline on
  light themes (documented trade-off).
- `revealViewOnStartup` is opt-in and per-workspace, so it never hijacks an unrelated VS Code window.

## Alternatives considered

- **Monaco-in-webview for a custom code toolbar** — rejected: a standalone Monaco loses
  Pylance/IntelliSense/diagnostics; you would rebuild a worse editor to gain a toolbar.
- **Colour every MessageFoundry toolbar icon amber** — rejected: dilutes the accent and reads poorly
  on light themes (`docs/BRAND.md`); only the distinctive actions are amber.
- **Auto-reveal the sidebar for any config workspace** — rejected: hijacks the sidebar globally; the
  opt-in per-workspace setting is non-intrusive.
- **A declarative "default view" setting** — no such VS Code API exists; hence the activation-time
  `workbench.view.extension.*` reveal.
