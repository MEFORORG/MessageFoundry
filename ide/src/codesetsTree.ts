// Sidebar tree "Translation Tables" — every code set under codesets/ from `messagefoundry codeset
// list --json`, each shown as name + entry count (and key/shape detail). A code set is read-only
// reference data (CSV-first; the first column is the lookup key); the GUI grid editor (codeSetEditor.ts)
// shells `codeset upsert` to author/edit it. CSV code sets get inline edit/rename/delete actions; a
// TOML-authored code set is hand-authored/legacy, so it gets a view-only (open) action and no rename
// (the grid only writes CSV — TOML edits stay by hand).
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";

// §2 SUMMARY — one per code set, as `codeset list` emits it.
interface Summary {
  name: string;
  format: "csv" | "toml";
  key: string;
  columns: string[];
  value_columns: string[];
  shape: "scalar" | "dict";
  entries: number;
}

const NONE = vscode.TreeItemCollapsibleState.None;

// A code-set row. contextValue selects which inline/context actions apply (CSV vs TOML vs the
// info/empty placeholder rows, which carry none).
class CodeSetNode extends vscode.TreeItem {
  constructor(
    public readonly summary: Summary | undefined,
    label: string,
    icon: string,
    description?: string,
    contextValue?: string,
  ) {
    super(label, NONE);
    this.iconPath = new vscode.ThemeIcon(icon);
    if (description) {
      this.description = description;
    }
    if (contextValue) {
      this.contextValue = contextValue;
    }
  }
}

export class CodeSetsProvider implements vscode.TreeDataProvider<CodeSetNode> {
  private readonly _changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._changed.event;
  private summaries: Summary[] | undefined;
  private error: string | undefined;

  async refresh(): Promise<void> {
    const cwd = workspaceDir();
    this.error = undefined;
    if (!cwd) {
      this.summaries = undefined;
    } else {
      try {
        this.summaries = await runJson<Summary[]>(["codeset", "list", "--config", configDir()], cwd);
      } catch (e) {
        // Surface the error in the tree (e.g. a malformed file), keep the view usable.
        this.summaries = undefined;
        this.error = String(e);
      }
    }
    this._changed.fire();
  }

  getTreeItem(node: CodeSetNode): vscode.TreeItem {
    return node;
  }

  getChildren(node?: CodeSetNode): CodeSetNode[] {
    if (node) {
      return []; // flat list — code sets have no children
    }
    if (!workspaceDir()) {
      return [new CodeSetNode(undefined, "Open a workspace folder", "info")];
    }
    if (this.error) {
      return [new CodeSetNode(undefined, this.error, "error")];
    }
    const list = this.summaries;
    if (!list) {
      return [new CodeSetNode(undefined, "No code sets loaded", "info")];
    }
    if (list.length === 0) {
      return [new CodeSetNode(undefined, "No translation tables yet", "info")];
    }
    return [...list]
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((s) => {
        const noun = s.entries === 1 ? "entry" : "entries";
        const desc =
          s.format === "toml"
            ? `${s.entries} ${noun} · toml (read-only)`
            : `${s.entries} ${noun} · ${s.shape}`;
        // A CSV code set is grid-editable; a TOML one is view-only here.
        const ctx = s.format === "toml" ? "meforCodeSetToml" : "meforCodeSetCsv";
        const node = new CodeSetNode(s, s.name, "list-flat", desc, ctx);
        node.tooltip = `${s.name} — key "${s.key}", columns: ${s.columns.join(", ")}`;
        // Clicking the row opens the grid editor (the command's args carry the name).
        node.command = {
          command: "messagefoundry.editCodeSet",
          title: "Edit Translation Table",
          arguments: [node],
        };
        return node;
      });
  }
}
