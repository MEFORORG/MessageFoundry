// Editor-area "build toolbar" for MessageFoundry config files. Two non-intrusive surfaces around the
// REAL Python editor (Pylance, debugpy, our completion all untouched):
//   * editor/title actions (Validate / Test Bench / Promote) — declared in package.json, gated on the
//     `messagefoundry.isConfigFile` context key kept in sync here;
//   * CodeLens actions above each @router / @handler / inbound() / outbound() declaration.
// This is the platform-native pattern (per the VS Code UX guidelines) — no custom editor/webview that
// would cost us the native code-editing experience.
import * as path from "node:path";
import * as vscode from "vscode";
import { configDir, workspaceDir } from "./cli";

/**
 * True when `fileFsPath` is a Python module under the configured config dir of `workspaceFsPath`.
 * Pure (no vscode/fs) so it is unit-testable; containment is tested with path.relative so a sibling
 * sharing a name prefix (".../config-other" vs ".../config") does not false-match.
 */
export function isConfigFile(
  fileFsPath: string,
  workspaceFsPath: string | undefined,
  configDirRel: string,
): boolean {
  if (!workspaceFsPath || !fileFsPath.toLowerCase().endsWith(".py")) {
    return false;
  }
  const dir = path.resolve(workspaceFsPath, configDirRel);
  const rel = path.relative(dir, fileFsPath);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

export type ElementKind = "router" | "handler" | "inbound" | "outbound";
export interface ConfigElement {
  line: number; // 0-based
  kind: ElementKind;
}

const DECORATOR_RE = /^\s*@(router|handler)\b/;
const CONNECTION_RE = /^\s*(?:[A-Za-z_]\w*\s*=\s*)?(inbound|outbound)\s*\(/;

/**
 * The config "elements" a CodeLens attaches to — `@router`/`@handler` decorators and
 * `inbound(...)`/`outbound(...)` connection definitions — located by line. A deliberately simple line
 * scan (not a Python parse): enough to anchor non-destructive lenses, and narrow enough that it won't
 * match a substring like `process_inbound(` or an `import inbound` line.
 */
export function findElements(text: string): ConfigElement[] {
  const out: ConfigElement[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const dec = DECORATOR_RE.exec(lines[i]);
    if (dec) {
      out.push({ line: i, kind: dec[1] as ElementKind });
      continue;
    }
    const conn = CONNECTION_RE.exec(lines[i]);
    if (conn) {
      out.push({ line: i, kind: conn[1] as ElementKind });
    }
  }
  return out;
}

class ConfigCodeLensProvider implements vscode.CodeLensProvider {
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this.changed.event;

  refresh(): void {
    this.changed.fire();
  }

  dispose(): void {
    this.changed.dispose();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    if (!isConfigFile(document.uri.fsPath, workspaceDir(), configDir())) {
      return [];
    }
    const lenses: vscode.CodeLens[] = [];
    for (const el of findElements(document.getText())) {
      const range = new vscode.Range(el.line, 0, el.line, 0);
      lenses.push(
        new vscode.CodeLens(range, {
          title: "$(beaker) Test Bench",
          tooltip: `Dry-run messages through the config (${el.kind})`,
          command: "messagefoundry.openTestBench",
        }),
        new vscode.CodeLens(range, {
          title: "$(check) Validate",
          tooltip: "Validate the config",
          command: "messagefoundry.validate",
        }),
      );
    }
    return lenses;
  }
}

/**
 * Wire the editor-area toolbar: keep the `messagefoundry.isConfigFile` context key (which the
 * editor/title `when` clauses use) in sync with the active editor + the configDir setting, and register
 * the CodeLens provider.
 */
export function registerEditorToolbar(context: vscode.ExtensionContext): void {
  const update = (editor: vscode.TextEditor | undefined): void => {
    const on = !!editor && isConfigFile(editor.document.uri.fsPath, workspaceDir(), configDir());
    void vscode.commands.executeCommand("setContext", "messagefoundry.isConfigFile", on);
  };
  update(vscode.window.activeTextEditor);

  const lenses = new ConfigCodeLensProvider();
  context.subscriptions.push(
    lenses,
    vscode.window.onDidChangeActiveTextEditor(update),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("messagefoundry.configDir")) {
        update(vscode.window.activeTextEditor);
        lenses.refresh();
      }
    }),
    vscode.languages.registerCodeLensProvider({ language: "python" }, lenses),
  );
}
