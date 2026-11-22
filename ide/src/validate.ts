// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Run `messagefoundry validate --json` and surface problems in the Problems panel.
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";
import { diagnosticLocation, type ValidateDiagnostic } from "./validateDiagnostics";

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
    const dir = configDir();
    let diags: ValidateDiagnostic[];
    try {
      diags = await runJson<ValidateDiagnostic[]>(["validate", "--config", dir], cwd);
    } catch (e) {
      void vscode.window.showErrorMessage(`MessageFoundry: validate failed — ${String(e)}`);
      return;
    }

    collection.clear();
    // Keyed by the Uri's own string, which is how the collection tells files apart: two spellings of
    // one file (a drive letter's case, say) would otherwise be two entries, and the second set() wins.
    const byFile = new Map<string, { uri: vscode.Uri; list: vscode.Diagnostic[] }>();
    for (const d of diags) {
      const { file, line } = diagnosticLocation(d, cwd, dir);
      const uri = vscode.Uri.file(file);
      const severity =
        d.severity === "warning"
          ? vscode.DiagnosticSeverity.Warning
          : vscode.DiagnosticSeverity.Error;
      const diag = new vscode.Diagnostic(new vscode.Range(line, 0, line, 0), d.message, severity);
      diag.source = "messagefoundry";
      const key = uri.toString();
      const entry = byFile.get(key) ?? { uri, list: [] };
      entry.list.push(diag);
      byFile.set(key, entry);
    }
    for (const { uri, list } of byFile.values()) {
      collection.set(uri, list);
    }
  }

  return { run };
}
