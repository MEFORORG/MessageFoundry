// "Insert Element" — a code-first quick-pick that drops the most-used Handler/Router idioms (field
// copy, lookups, loops, date conversion, Send, …) as real, editable Python. The element catalog is the
// bundled `snippets/messagefoundry.code-snippets` file — the SAME source the editor uses for prefix
// tab-completion — so there is one source of truth, no drift. This is a typing accelerator, not a
// visual/declarative builder (BACKLOG #48; #26 stays declined).
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";

import { findElements } from "./editorToolbar";

interface SnippetDef {
  prefix?: string;
  body: string | string[];
  description?: string;
  // Restricts the idiom to inside a `@router` or `@handler` def (e.g. `Send`/`db_lookup`/`fhir_lookup`
  // are Handler-only capabilities that raise on a Router — ADR 0010/0043; a Router-returned handler
  // name list is meaningless inside a Handler). Absent = context-agnostic, always shown.
  context?: "router" | "handler";
}

/** The cursor's enclosing element, for filtering the picks — `null` outside any router/handler def
 * (e.g. top-level connection wiring, or a file with none), the fallback case that shows every idiom. */
export type CursorContext = "router" | "handler" | null;

export interface ElementPick extends vscode.QuickPickItem {
  body?: string; // the snippet text to insert (absent on separator rows)
}

/** Read the bundled snippet definitions (shared with the editor's prefix tab-completion). */
export function loadSnippets(extensionPath: string): Record<string, SnippetDef> {
  const file = path.join(extensionPath, "snippets", "messagefoundry.code-snippets");
  return JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, SnippetDef>;
}

/**
 * Turn the snippet map into a category-grouped quick-pick list. Category is the text before `" · "` in
 * each snippet's description (snippets without the delimiter fall under "Scaffold"); the rest of the
 * description is the item label and the prefix shows as the detail. Separator rows carry no `body`.
 * Pure (apart from the `vscode` enum) so it is unit-testable.
 */
export function buildPicks(snippets: Record<string, SnippetDef>): ElementPick[] {
  const byCategory = new Map<string, ElementPick[]>();
  for (const def of Object.values(snippets)) {
    const body = Array.isArray(def.body) ? def.body.join("\n") : def.body;
    const desc = def.description ?? "";
    const sep = desc.indexOf(" · ");
    const category = sep >= 0 ? desc.slice(0, sep) : "Scaffold";
    const label = sep >= 0 ? desc.slice(sep + 3) : desc;
    const list = byCategory.get(category) ?? [];
    list.push({ label, detail: def.prefix ? `prefix: ${def.prefix}` : undefined, body });
    byCategory.set(category, list);
  }
  const picks: ElementPick[] = [];
  for (const [category, items] of byCategory) {
    picks.push({ label: category, kind: vscode.QuickPickItemKind.Separator });
    picks.push(...items);
  }
  return picks;
}

/**
 * Which enclosing element (if any) `cursorLine` (0-based) sits inside — reusing the editor toolbar's
 * simple line-scan `findElements` locator: the nearest router/handler/inbound/outbound declaration at
 * or above the cursor defines the scope until the next one (an `inbound`/`outbound` line, or leaving a
 * `router`/`handler` for a later one, resets the scope). Not a full Python parse — a deliberately
 * simple heuristic, same spirit as `findElements` itself. Pure so it is unit-testable.
 */
export function detectContext(text: string, cursorLine: number): CursorContext {
  let current: CursorContext = null;
  for (const el of findElements(text)) {
    if (el.line > cursorLine) {
      break;
    }
    current = el.kind === "router" || el.kind === "handler" ? el.kind : null;
  }
  return current;
}

/**
 * Narrow the snippet catalog to those valid in `cursorContext`. A snippet with no `context` tag is
 * context-agnostic and always kept; one tagged `"router"`/`"handler"` is kept only when it matches (or
 * when `cursorContext` is `null` — outside any router/handler def, where every idiom is offered as a
 * fallback). Pure so it is unit-testable.
 */
export function filterSnippetsForContext(
  snippets: Record<string, SnippetDef>,
  cursorContext: CursorContext,
): Record<string, SnippetDef> {
  if (cursorContext === null) {
    return snippets;
  }
  const out: Record<string, SnippetDef> = {};
  for (const [name, def] of Object.entries(snippets)) {
    if (!def.context || def.context === cursorContext) {
      out[name] = def;
    }
  }
  return out;
}

export function registerInsertElement(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("messagefoundry.insertElement", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.languageId !== "python") {
        void vscode.window.showInformationMessage(
          "MessageFoundry: open a Python config file to insert an element.",
        );
        return;
      }
      let picks: ElementPick[];
      try {
        const cursorContext = detectContext(editor.document.getText(), editor.selection.active.line);
        picks = buildPicks(filterSnippetsForContext(loadSnippets(context.extensionPath), cursorContext));
      } catch (e) {
        void vscode.window.showErrorMessage(`MessageFoundry: could not load snippets — ${String(e)}`);
        return;
      }
      const choice = await vscode.window.showQuickPick(picks, {
        placeHolder: "Insert a MessageFoundry element…",
        matchOnDetail: true,
      });
      if (choice?.body) {
        await editor.insertSnippet(new vscode.SnippetString(choice.body));
      }
    }),
  );
}
