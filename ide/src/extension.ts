// MessageFoundry VS Code extension — Phase 2 skeleton:
//   * live HL7-aware completion (no server)
//   * validate-on-save -> Problems
//   * Connections sidebar (the wired graph)
//   * scaffold snippets for inbound/outbound/@router/@handler
// (Engine run/stop + monitoring deliberately live in the Console, not the IDE. To run a local
//  engine for dev, use `messagefoundry serve` or the Console.)
import * as vscode from "vscode";
import { openAlertEditor } from "./alertEditor";
import { showAiPolicy } from "./aiPolicy";
import { workspaceDir } from "./cli";
import { registerCompletion } from "./completion";
import { registerChat } from "./chat";
import { generateSamples } from "./generate";
import { openConnectionEditor } from "./connectionEditor";
import { GraphProvider } from "./graphTree";
import { HomeView } from "./home";
import { openNewRoute } from "./newRoute";
import { promote } from "./promote";
import { maybeSuggestSourceControl, setupSourceControl } from "./sourceControl";
import { TestBench } from "./testBench";
import { createValidator } from "./validate";

const SNIPPETS: Record<string, string> = {
  newRouter:
    '@router("${1:router_name}")\ndef ${2:route}(msg):\n' +
    '\tif msg["MSH-9.1"] != "${3:ADT}":\n\t\treturn []  # routed nowhere -> UNROUTED\n' +
    '\treturn ["${4:handler_name}"]',
  newHandler:
    '@handler("${1:handler_name}")\ndef ${2:handle}(msg):\n' +
    "\t${3:# filter / transform}\n" +
    '\treturn Send("${4:outbound_name}", msg)',
};

async function insertSnippet(key: keyof typeof SNIPPETS): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showInformationMessage("MessageFoundry: open a Python file first.");
    return;
  }
  await editor.insertSnippet(new vscode.SnippetString(SNIPPETS[key]));
}

export function activate(context: vscode.ExtensionContext): void {
  const graph = new GraphProvider();
  // Router names from the live graph, for the connection editor's router-binding dropdown.
  const routerNames = (): string[] => graph.getGraph()?.routers.map((r) => r.name) ?? [];
  const graphView = vscode.window.createTreeView("messagefoundry.graph", { treeDataProvider: graph });
  context.subscriptions.push(graphView);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("messagefoundry.home", new HomeView()),
  );

  const validator = createValidator(context);
  registerCompletion(context, graph);
  registerChat(context, graph);
  const testBench = new TestBench(context);

  context.subscriptions.push(
    vscode.commands.registerCommand("messagefoundry.openTestBench", () => testBench.open()),
    vscode.commands.registerCommand("messagefoundry.validate", () => validator.run()),
    vscode.commands.registerCommand("messagefoundry.refreshGraph", () => graph.refresh()),
    vscode.commands.registerCommand("messagefoundry.filterConnections", async () => {
      const value = await vscode.window.showInputBox({
        prompt: "Filter connections by name (blank to clear)",
        value: graph.getFilter(),
        placeHolder: "e.g. ACME or IB_",
      });
      if (value === undefined) {
        return; // cancelled — leave the current filter
      }
      graph.setFilter(value);
      graphView.message = graph.statusMessage();
    }),
    vscode.commands.registerCommand("messagefoundry.groupConnections", async () => {
      const pick = await vscode.window.showQuickPick(
        [
          { label: "None", mode: "none" as const },
          { label: "By connection Type", mode: "type" as const },
          { label: "By Client / Partner", mode: "partner" as const },
        ],
        { placeHolder: "Group connections by…" },
      );
      if (!pick) {
        return;
      }
      graph.setGrouping(pick.mode);
      graphView.message = graph.statusMessage();
    }),
    vscode.commands.registerCommand(
      "messagefoundry.openSource",
      async (file: string, line: number) => {
        const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(file));
        const pos = new vscode.Position(Math.max(0, (line ?? 1) - 1), 0);
        await vscode.window.showTextDocument(doc, { selection: new vscode.Range(pos, pos) });
      },
    ),
    // Gear action on a connection row. A connections.toml (data-authored) connection opens the
    // editor; a code-authored one jumps to its .py definition (it isn't GUI-editable — ADR 0007).
    vscode.commands.registerCommand("messagefoundry.openConnectionSettings", (node?: vscode.TreeItem) => {
      const args = node?.command?.arguments;
      const file = args && typeof args[0] === "string" ? args[0] : undefined;
      const name = typeof node?.label === "string" ? node.label : undefined;
      if (file && file.endsWith("connections.toml") && name) {
        void openConnectionEditor(context, { routers: routerNames(), editName: name, onSaved: () => graph.refresh() });
      } else if (file) {
        void vscode.commands.executeCommand("messagefoundry.openSource", file, args?.[1] ?? 1);
      }
    }),
    // Edit a data-authored connection from its context menu (informs if it's code-authored).
    vscode.commands.registerCommand("messagefoundry.editConnection", (node?: vscode.TreeItem) => {
      const name = typeof node?.label === "string" ? node.label : undefined;
      void openConnectionEditor(context, { routers: routerNames(), editName: name, onSaved: () => graph.refresh() });
    }),
    vscode.commands.registerCommand("messagefoundry.newConnection", () =>
      openConnectionEditor(context, { routers: routerNames(), onSaved: () => graph.refresh() }),
    ),
    vscode.commands.registerCommand("messagefoundry.newRoute", () =>
      openNewRoute(context, () => graph.refresh()),
    ),
    vscode.commands.registerCommand("messagefoundry.newRouter", () => insertSnippet("newRouter")),
    vscode.commands.registerCommand("messagefoundry.newHandler", () => insertSnippet("newHandler")),
    vscode.commands.registerCommand("messagefoundry.setupSourceControl", () =>
      setupSourceControl(context),
    ),
    // Author a [[alerts.rules]] entry in the service-settings TOML (ADR 0014; webview shells the CLI).
    vscode.commands.registerCommand("messagefoundry.newAlert", () => openAlertEditor(context)),
    vscode.commands.registerCommand("messagefoundry.generateSamples", () => generateSamples()),
    vscode.commands.registerCommand("messagefoundry.promote", () => promote(context)),
    vscode.commands.registerCommand("messagefoundry.showAiPolicy", () => showAiPolicy()),
  );

  // Re-validate + refresh the graph (and thus completion names) whenever a Python file is saved.
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (doc.languageId === "python") {
        void validator.run();
        void graph.refresh();
      }
    }),
  );

  if (workspaceDir()) {
    void validator.run();
    void graph.refresh();
  }

  // One-time nudge to put a MessageFoundry project under version control + commit-time checks.
  void maybeSuggestSourceControl(context);
}

export function deactivate(): void {
  // nothing to clean up beyond context.subscriptions
}
