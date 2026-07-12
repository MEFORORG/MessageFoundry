// Config-dir FileSystemWatcher (ADR 0091 follow-through): an EXTERNAL edit to the config — a git
// pull, a checkout, another tool writing connections.toml or a code set — now refreshes the
// CONNECTIONS tree, Problems, and Translation Tables without a manual refresh. Events funnel into
// the caller-supplied trigger (the shared RefreshCoalescer in extension.ts), so a multi-file storm
// and the save handler's own echo coalesce to one validate+refresh pass. The pure containment
// logic lives in configRefresh.ts (watchableConfigDir); this file is the Extension-Host shell.
import * as vscode from "vscode";
import { configDir, workspaceDir } from "./cli";
import { watchableConfigDir } from "./configRefresh";

/** What in the config dir feeds the tree/validator: config modules, the data-authored connections
 *  (ADR 0007), and code sets. A brace glob keeps it to ONE watcher. */
const CONFIG_GLOB = "{**/*.py,connections.toml,codesets/**/*.csv}";

/**
 * Watch the resolved config dir and call `onEvent` on every create/change/delete. Rebuilds the
 * watcher when `messagefoundry.configDir` changes; creates none (gracefully) when the config dir
 * resolves outside the workspace folder. All disposables ride context.subscriptions.
 */
export function registerConfigWatcher(
  context: vscode.ExtensionContext,
  onEvent: () => void,
): void {
  let current: vscode.Disposable[] = [];

  const rebuild = (): void => {
    for (const d of current) {
      d.dispose();
    }
    current = [];
    const dir = watchableConfigDir(workspaceDir(), configDir());
    if (!dir) {
      return; // no workspace, or configDir outside it — no watcher (manual refresh still works)
    }
    const watcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(vscode.Uri.file(dir), CONFIG_GLOB),
    );
    current = [
      watcher,
      watcher.onDidCreate(onEvent),
      watcher.onDidChange(onEvent),
      watcher.onDidDelete(onEvent),
    ];
  };

  rebuild();
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("messagefoundry.configDir")) {
        rebuild();
      }
    }),
    // Wrap (don't push `current` itself): rebuild() swaps the array, and disposal must catch the
    // watcher that is live at shutdown, not the one that existed at registration.
    { dispose: () => current.forEach((d) => d.dispose()) },
  );
}
