// Run `messagefoundry validate --json` and surface problems in the Problems panel.
import * as path from "node:path";
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";

interface Diagnostic {
  message: string;
  file: string | null;
  severity: string;
}

export interface Validator {
  run(): Promise<void>;
}

export function createValidator(context: vscode.ExtensionContext): Validator {
  const collection = vscode.languages.createDiagnosticCollection("messagefoundry");
  context.subscriptions.push(collection);

  async function run(): Promise<void> {
    const cwd = workspaceDir();
    if (!cwd) {
      return;
    }
    let diags: Diagnostic[];
    try {
      diags = await runJson<Diagnostic[]>(["validate", "--config", configDir()], cwd);
    } catch (e) {
      void vscode.window.showErrorMessage(`MessageFoundry: validate failed — ${String(e)}`);
      return;
    }

    collection.clear();
    const fallback = path.join(cwd, configDir());
    const byFile = new Map<string, vscode.Diagnostic[]>();
    for (const d of diags) {
      const file = d.file ?? fallback;
      const severity =
        d.severity === "warning"
          ? vscode.DiagnosticSeverity.Warning
          : vscode.DiagnosticSeverity.Error;
      const diag = new vscode.Diagnostic(new vscode.Range(0, 0, 0, 0), d.message, severity);
      diag.source = "messagefoundry";
      const list = byFile.get(file) ?? [];
      list.push(diag);
      byFile.set(file, list);
    }
    for (const [file, list] of byFile) {
      collection.set(vscode.Uri.file(file), list);
    }
  }

  return { run };
}
