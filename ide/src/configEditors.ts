// Custom editors (#221b): register the EXISTING connection form and code-set grid as
// `CustomTextEditorProvider`s so opening connections.toml / a codesets/*.csv lands in the form by
// default, with VS Code's automatic "Reopen With → Text Editor" always available (the AWS Workflow
// Studio default-editor-with-opt-out pattern). The form/grid HTML is REUSED verbatim from
// connectionEditor.ts / codeSetEditor.ts — this file only adapts them to a document-backed editor and
// guards the webview↔document update loop. Writes still go through the `messagefoundry connection|
// codeset upsert` CLI (comment-preserving, validated), the same as the command-opened forms.
//
// Write model (F6): edits are saved by shelling the comment-preserving CLI, NOT a vscode.WorkspaceEdit
// — so the on-disk file keeps its comments/formatting, but the editor tab's undo stack stays empty and
// the document is never marked dirty. Reconciliation after an external change relies on VS Code
// reloading the (clean) document from disk, which is BYPASSED if the same file is also open, dirty, in
// a text view.
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";
import { ConnObj, connectionFormHtml } from "./connectionEditor";
import { Detail, codeSetFormHtml } from "./codeSetEditor";
import {
  ConnectionListItem,
  codeSetNameFromPath,
  isReadOnlyCodeSet,
  isUnderConfigDir,
  pickCurrentConnection,
  shouldPushDocumentChange,
} from "./configEditorModel";

/** Fail-safe delay (ms) after which the webview↔document loop guard's "saving" flag is dropped even if
 *  no echo change-event arrived (a byte-identical CLI write fires none). Comfortably above VS Code's
 *  file-watcher debounce so a real echo is still swallowed first, well below any human re-edit. */
const SAVE_GUARD_RESET_MS = 1500;

/**
 * F3 guard: if `document` is NOT under the configured config dir, reopen it in the plain text editor
 * (with a notice) and return true. Both providers read/write via the CLI's `--config <configDir>`, so
 * a same-named file elsewhere in the workspace (the selector globs are workspace-wide) would otherwise
 * be shown — and saved — as the config-dir file. Returns false (proceed with the custom editor) for the
 * canonical in-config-dir file, or when there is no workspace folder (a relative configDir can't be
 * resolved, and the CLI-backed editor is already inert there).
 */
function reopenAsTextIfOutsideConfigDir(
  document: vscode.TextDocument,
  panel: vscode.WebviewPanel,
  label: string,
): boolean {
  const ws = workspaceDir();
  if (!ws || isUnderConfigDir(document.uri.fsPath, ws, configDir())) {
    return false;
  }
  void vscode.window.showInformationMessage(
    `MessageFoundry: this ${label} is outside the configured config dir (messagefoundry.configDir) — ` +
      "opening it as text. The form only edits the config-dir file.",
  );
  // Reopen the same resource with the built-in text editor (viewType "default"), replacing this panel.
  void vscode.commands.executeCommand("vscode.openWith", document.uri, "default");
  // Leave a static notice in the about-to-be-replaced webview in case the reopen is slow.
  panel.webview.html =
    "<!DOCTYPE html><body style=\"font-family:sans-serif;padding:1rem\">" +
    "This file is outside the configured MessageFoundry config dir; opening it as text…</body>";
  return true;
}

// ---- connections.toml → the connection form (one file, many connections + a picker) -----------------

export class ConnectionsCustomEditorProvider implements vscode.CustomTextEditorProvider {
  static readonly viewType = "messagefoundry.connectionsEditor";

  constructor(private readonly routers: () => string[]) {}

  resolveCustomTextEditor(
    document: vscode.TextDocument,
    panel: vscode.WebviewPanel,
    _token: vscode.CancellationToken,
  ): void {
    if (reopenAsTextIfOutsideConfigDir(document, panel, "connections.toml")) {
      return; // F3: not the config-dir file — fell back to the text editor
    }
    panel.webview.options = { enableScripts: true };
    let desired: string | undefined; // the connection the user selected in the picker (undefined → first/new)
    let savingFromWebview = false;
    let guardTimer: ReturnType<typeof setTimeout> | undefined;
    let lastRendered: string | undefined;
    // The webview↔document loop guard (F5). `markSaving` is called around each CLI write and arms a
    // fail-safe timer; `clearGuard` drops the flag + cancels the timer. Resetting on the timer (not
    // only when an echo change-event is swallowed below) is what stops a byte-identical write — which
    // fires no change-event — from latching the flag and eating the next real external edit.
    const clearGuard = (): void => {
      savingFromWebview = false;
      if (guardTimer) {
        clearTimeout(guardTimer);
        guardTimer = undefined;
      }
    };
    const markSaving = (): void => {
      savingFromWebview = true;
      if (guardTimer) {
        clearTimeout(guardTimer);
      }
      guardTimer = setTimeout(clearGuard, SAVE_GUARD_RESET_MS);
    };

    const render = async (): Promise<void> => {
      const ws = workspaceDir();
      let entries: ConnObj[] = [];
      let listError: string | undefined;
      if (ws) {
        try {
          entries = await runJson<ConnObj[]>(["connection", "list", "--config", configDir()], ws);
        } catch (e) {
          listError = e instanceof Error ? e.message : String(e);
        }
      }
      const items: ConnectionListItem[] = entries.map((c) => ({
        name: c.name,
        direction: c.direction,
        transport: c.transport,
      }));
      const current = pickCurrentConnection(items, desired);
      const initial = current ? entries.find((c) => c.name === current) : undefined;
      panel.webview.html = connectionFormHtml(panel.webview, this.routers(), initial, {
        names: items.map((i) => i.name),
        current: current ?? null,
      });
      lastRendered = document.getText();
      if (listError) {
        // F7: posted right after setting the html, so it can race the webview's own message listener
        // (registered during script parse) and be dropped. A "ready" handshake would mean editing the
        // shared form HTML in connectionEditor.ts; left as-is — a dropped load error is non-fatal (the
        // form is still usable and any refresh re-posts it).
        panel.webview.postMessage({ command: "error", message: listError });
      }
    };

    panel.webview.onDidReceiveMessage(
      async (m: { command?: string; conn?: ConnObj; name?: string | null }) => {
        const ws = workspaceDir();
        if (!ws) {
          return;
        }
        if (m?.command === "select") {
          desired = m.name ?? undefined; // null → the "＋ New connection" blank form
          await render();
        } else if (m?.command === "save" && m.conn) {
          markSaving();
          try {
            await runJson(["connection", "upsert", "--config", configDir(), "--data", JSON.stringify(m.conn)], ws);
          } catch (e) {
            clearGuard();
            panel.webview.postMessage({ command: "error", message: e instanceof Error ? e.message : String(e) });
            return;
          }
          desired = m.conn.name; // stay on the just-saved connection
          await render();
          void vscode.window.showInformationMessage(`MessageFoundry: saved ${m.conn.name} to connections.toml.`);
        } else if (m?.command === "delete" && m.name) {
          const confirm = await vscode.window.showWarningMessage(
            `Remove connection "${m.name}" from connections.toml?`,
            { modal: true },
            "Remove",
          );
          if (confirm !== "Remove") {
            return;
          }
          markSaving();
          try {
            await runJson(["connection", "remove", "--config", configDir(), "--name", m.name], ws);
          } catch (e) {
            clearGuard();
            panel.webview.postMessage({ command: "error", message: e instanceof Error ? e.message : String(e) });
            return;
          }
          desired = undefined;
          await render();
        }
        // 'cancel' is a no-op here — the custom editor IS the tab; close it to dismiss.
      },
    );

    const sub = vscode.workspace.onDidChangeTextDocument((e) => {
      if (e.document.uri.toString() !== document.uri.toString()) {
        return;
      }
      if (!shouldPushDocumentChange({ savingFromWebview, changedText: e.document.getText(), lastRenderedText: lastRendered })) {
        clearGuard(); // swallow exactly the echo of our own CLI write (and cancel the fail-safe timer)
        return;
      }
      void render(); // a genuine external edit — refresh the form/list
    });
    panel.onDidDispose(() => {
      sub.dispose();
      if (guardTimer) {
        clearTimeout(guardTimer);
      }
    });

    void render();
  }
}

// ---- codesets/<name>.csv → the code-set grid (one file = one code set) -----------------------------

export class CodeSetCustomEditorProvider implements vscode.CustomTextEditorProvider {
  static readonly viewType = "messagefoundry.codeSetEditor";

  resolveCustomTextEditor(
    document: vscode.TextDocument,
    panel: vscode.WebviewPanel,
    _token: vscode.CancellationToken,
  ): void {
    if (reopenAsTextIfOutsideConfigDir(document, panel, "code-set file")) {
      return; // F3: not under the config dir — fell back to the text editor
    }
    panel.webview.options = { enableScripts: true };
    const name = codeSetNameFromPath(document.fileName);
    const readonly = isReadOnlyCodeSet(document.fileName);
    let savingFromWebview = false;
    let guardTimer: ReturnType<typeof setTimeout> | undefined;
    let lastRendered: string | undefined;
    // The webview↔document loop guard (F5) — see the connections provider above for the rationale.
    const clearGuard = (): void => {
      savingFromWebview = false;
      if (guardTimer) {
        clearTimeout(guardTimer);
        guardTimer = undefined;
      }
    };
    const markSaving = (): void => {
      savingFromWebview = true;
      if (guardTimer) {
        clearTimeout(guardTimer);
      }
      guardTimer = setTimeout(clearGuard, SAVE_GUARD_RESET_MS);
    };

    const render = async (): Promise<void> => {
      const ws = workspaceDir();
      let detail: Detail | null = null;
      let existing: string[] = [];
      let showError: string | undefined;
      if (ws) {
        try {
          detail = await runJson<Detail>(["codeset", "show", "--config", configDir(), "--name", name], ws);
        } catch (e) {
          // A brand-new / not-yet-loadable file: start an empty grid rather than a hard error.
          showError = e instanceof Error ? e.message : String(e);
          detail = { name, format: "csv", columns: ["key", "value"], rows: [["", ""]] };
        }
        try {
          const summaries = await runJson<{ name: string }[]>(["codeset", "list", "--config", configDir()], ws);
          existing = summaries.map((s) => s.name);
        } catch {
          existing = [];
        }
      }
      panel.webview.html = codeSetFormHtml(panel.webview, detail, readonly || detail?.format === "toml", existing);
      lastRendered = document.getText();
      if (showError && detail && detail.rows.length === 1) {
        // Only surface the load error when we truly fell back to an empty grid (not a populated one).
        // F7: like the connections provider, this can race the webview's listener and be dropped — a
        // non-fatal load hint, so it is not worth a "ready" handshake into the shared grid HTML.
        panel.webview.postMessage({ command: "error", message: showError });
      }
    };

    panel.webview.onDidReceiveMessage(
      async (m: { command?: string; detail?: Detail; name?: string; to?: string }) => {
        const ws = workspaceDir();
        if (!ws) {
          return;
        }
        if (m?.command === "save" && m.detail) {
          markSaving();
          try {
            await runJson(["codeset", "upsert", "--config", configDir(), "--data", JSON.stringify(m.detail)], ws);
          } catch (e) {
            clearGuard();
            panel.webview.postMessage({ command: "error", message: e instanceof Error ? e.message : String(e) });
            return;
          }
          await render();
          void vscode.window.showInformationMessage(`MessageFoundry: saved code set ${m.detail.name}.`);
        } else if (m?.command === "delete" && m.name) {
          const confirm = await vscode.window.showWarningMessage(
            `Remove code set "${m.name}"?`,
            { modal: true },
            "Remove",
          );
          if (confirm !== "Remove") {
            return;
          }
          try {
            await runJson(["codeset", "remove", "--config", configDir(), "--name", m.name], ws);
          } catch (e) {
            panel.webview.postMessage({ command: "error", message: e instanceof Error ? e.message : String(e) });
            return;
          }
          void vscode.window.showInformationMessage(`MessageFoundry: removed code set ${m.name}.`);
        }
        // 'rename'/'cancel' are no-ops in the custom editor (rename is a file op; close to dismiss).
      },
    );

    const sub = vscode.workspace.onDidChangeTextDocument((e) => {
      if (e.document.uri.toString() !== document.uri.toString()) {
        return;
      }
      if (!shouldPushDocumentChange({ savingFromWebview, changedText: e.document.getText(), lastRenderedText: lastRendered })) {
        clearGuard(); // swallow exactly the echo of our own CLI write (and cancel the fail-safe timer)
        return;
      }
      void render();
    });
    panel.onDidDispose(() => {
      sub.dispose();
      if (guardTimer) {
        clearTimeout(guardTimer);
      }
    });

    void render();
  }
}

/** Register both custom editors. `routers` supplies the live router names for the connection form's
 *  router dropdown (from the graph provider). */
export function registerConfigEditors(context: vscode.ExtensionContext, routers: () => string[]): void {
  context.subscriptions.push(
    vscode.window.registerCustomEditorProvider(
      ConnectionsCustomEditorProvider.viewType,
      new ConnectionsCustomEditorProvider(routers),
      { webviewOptions: { retainContextWhenHidden: true }, supportsMultipleEditorsPerDocument: false },
    ),
    vscode.window.registerCustomEditorProvider(
      CodeSetCustomEditorProvider.viewType,
      new CodeSetCustomEditorProvider(),
      { webviewOptions: { retainContextWhenHidden: true }, supportsMultipleEditorsPerDocument: false },
    ),
  );
}
