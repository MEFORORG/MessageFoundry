# ADR 0103 — Steps view row context menu (right-click) over the existing row operations

- **Status:** Accepted (2026-07-12) — owner-directed this session; built (IDE extension v0.0.22 —
  v0.0.21 first cut fixed a submenu overlap where a focused + a hovered parent both revealed).
- **Deciders:** owner + IDE/DX (this session's directives)
- **Extends:** [ADR 0076](0076-typed-action-vocabulary-action-list-lens.md) /
  [ADR 0089](0089-recognition-first-lens-native-idioms.md) (the structured Steps view this menu acts on),
  [ADR 0100](0100-ide-native-surface-polish-and-open-to-messagefoundry-startup-experience-backlog-221.md)
  (whose code note named "a right-click row menu … a follow-up"). Relates to BACKLOG **#222**.

## Context

The Steps view (a `CustomTextEditorProvider` webview over a Handler `.py`) already exposes row-scoped
structural operations through three surfaces: the top-of-lens **Insert** dropdown + Add, the per-row
**↑ / ↓ / 🗑** buttons, and keyboard verbs (Ctrl+Z/Y undo/redo, Ctrl+C/X/V copy/cut/paste). When the
redundant toolbar buttons for those keyboard verbs were removed to keep the bar lean, the code left an
explicit marker: *"a right-click row menu for those verbs is a follow-up."* Users instinctively
right-click a row to operate on it (VS Code trains this on every tree row); today a right-click on a step
does nothing. This ADR records that follow-up.

The operation the toolbar Insert dropdown offers is also spatially divorced from its target — you commit
the action at the top of the view but it lands at a row that may be scrolled far below. A row context
menu co-locates the operation with the row it acts on.

## Decision

**1. A webview-rendered context menu, not VS Code's `menus` contribution.** The Steps rows are DOM inside
a custom-editor webview; VS Code's `menus` / `view/item/context` contributions target tree views and
native editors, not arbitrary webview DOM. The menu is therefore rendered **inside the webview**. To stay
within the strict webview CSP (no inline `innerHTML` markup building), it is emitted **server-side as a
single hidden `<div>` template** (`renderStepsContextMenuHtml`, a pure helper), whose insert catalog is
the same `INSERT_ACTION_LABELS` single source of truth the toolbar uses. The external webview script only
shows/positions (clamped to the viewport, submenus flip near the right edge), greys, dismisses (outside
click / Escape / scroll / resize / blur), and keyboard-navigates it.

**2. It reuses the existing execution paths — no second surface.** Each item posts the **same** messages
the toolbar Add and the per-row buttons already post: `insertToolbar`, `deleteRow`, and `moveTo` (derived
from the shared `walkMove`). So the byte-stable `lens rewrite` path, the F7 stale-coordinate guard, and
the one-edit-at-a-time projection are all unchanged. There is **no new engine surface** and no new
provider execution path.

**3. Item set.** *Insert before ▸* / *Insert after ▸* (each a submenu of the native, import-free
insertable actions — Set Field / Copy Field / Delete Segment), *Delete*, *Move up*, *Move down*.
Copy / Cut / Paste stay **keyboard-served** and are deliberately **out** of this menu (owner decision this
session). Enablement is a pure, unit-tested matrix (`contextMenuEnablement`) mirrored in the webview:
Insert before is always available; **Insert after is suppressed on a `send` row** (a step after the
return would be dead code — the same rule the toolbar Add already derives); Delete is offered only on an
editable `action`/`lookup`/`send` row (a `code`/`control` row is read-only — the §4 degradation ladder);
↑/↓ follow the walk (greyed at a suite edge / on a non-movable / sole-child row).

**4. Explicit before/after insert.** The menu inserts *before* or *after* the target explicitly, which the
engine's `insert_row` op already supports via its `position` field. `buildToolbarInsertRequest` and the
`insertToolbar` message gain an **optional** `position`; when present it wins, when absent the toolbar Add
derives it from the anchor kind exactly as before — **backward compatible** (the toolbar path is
byte-identical, its tests unchanged). An insert relative to a read-only `code`/`control` row is safe: the
engine uses the row only as a position and `_assert_reparses` refuses any op that would produce invalid
Python (a clear toast, never corruption).

**5. The toolbar Insert dropdown + Add is untouched.** ADR 0100's "insert-collapse" (tucking the toolbar
Insert affordance away) is **deferred by owner decision**; this menu is purely additive. A paired UX fix
ships with it: an empty **editable** param input now shows a `[blank]` **placeholder** (a hint, never a
value — the saved value stays empty) so a freshly-inserted template reads as "fill me in" without the
analyst erasing a literal token.

## Consequences

- Row operations are reachable by the standard right-click gesture, co-located with the target row.
- No engine change; the projection/rewrite/stale-guard invariants are preserved because the menu rides the
  existing message paths.
- The enablement rules are pure and unit-tested (`contextMenuEnablement`), matching the existing
  discipline of a pure model mirrored by the webview (`walkMove` / `captureBlock`).
- Discoverability of insert now has a second home (right-click) alongside the unchanged toolbar dropdown.
- Ships as IDE extension **v0.0.22**. Submenu reveal is JS-controlled + mutually exclusive (exactly one
  open) rather than CSS `:hover`/`:focus-within`, which allowed a focused parent and a hovered sibling to
  both open and overlap.

## Alternatives considered

- **VS Code `menus` / `view/item/context` contribution** — rejected: it cannot target webview DOM rows;
  the Steps view is a custom-editor webview, not a tree.
- **Flatten insert into the menu (no submenus)** — rejected: six "Insert <action> before/after" leaves
  clutter the menu; two before/after submenus of the action catalog are cleaner.
- **Remove the toolbar Insert dropdown now (the ADR 0100 insert-collapse)** — deferred to the owner; this
  iteration is additive only.
- **Add Copy/Cut/Paste to the menu** — deferred; they remain keyboard-served this iteration.
