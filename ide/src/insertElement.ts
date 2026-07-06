// "Insert Element" — a code-first quick-pick that drops the most-used Handler/Router idioms (field
// copy, lookups, loops, date conversion, Send, …) as real, editable Python. The element catalog is the
// bundled `snippets/messagefoundry.code-snippets` file — the SAME source the editor uses for prefix
// tab-completion — so there is one source of truth, no drift. This is a typing accelerator, not a
// visual/declarative builder (BACKLOG #48; #26 stays declined).
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";

interface SnippetDef {
  prefix?: string;
  body: string | string[];
  description?: string;
}

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
        picks = buildPicks(loadSnippets(context.extensionPath));
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
