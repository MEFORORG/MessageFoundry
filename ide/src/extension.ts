// MessageFoundry VS Code extension — Phase 2 skeleton:
//   * live HL7-aware completion (no server)
//   * validate-on-save -> Problems
//   * Connections sidebar (the wired graph)
//   * scaffold snippets for inbound/outbound/@router/@handler
// (Engine run/stop + monitoring deliberately live in the Console, not the IDE. To run a local
//  engine for dev, use `messagefoundry serve` or the Console.)
import * as path from "node:path";
import * as vscode from "vscode";
import { openAlertEditor } from "./alertEditor";
import { registerSteps } from "./stepsView";
import { showAiPolicy } from "./aiPolicy";
import { configDir, isExecGated, workspaceDir } from "./cli";
import { RefreshCoalescer } from "./configRefresh";
import { registerConfigWatcher } from "./configWatcher";
import { registerLiveStatus } from "./liveStatus";
import { CookbookPanel } from "./cookbook";
import { registerCompletion } from "./completion";
import { registerChat } from "./chat";
import { registerConfigEditors } from "./configEditors";
import { newConnectionWizard } from "./connectionQuickInput";
import { registerEditorToolbar } from "./editorToolbar";
import { registerEngineStatusBar } from "./statusBar";
import { registerInsertElement } from "./insertElement";
import { generateSamples } from "./generate";
import { registerLiveDebug } from "./liveDebug";
import { openCodeSetEditor } from "./codeSetEditor";
import { CodeSetsProvider } from "./codesetsTree";
import { openConnectionEditor } from "./connectionEditor";
import { codesetRemove, codesetRename } from "./cli";
import { GraphProvider } from "./graphTree";
import { HomeView } from "./home";
import { openNewRoute } from "./newRoute";
import { promote } from "./promote";
import { maybeSuggestSourceControl, setRepoStorage, setupSourceControl } from "./sourceControl";
import { TestBench } from "./testBench";
import { createValidator } from "./validate";
import { WiringMapPanel } from "./wiringMap";
import type { MapFocus } from "./wiringMapModel";

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
  // The perspective (element sections vs the legacy flow chain, ADR 0091 D2) survives restarts.
  graph.setPerspective(
    context.workspaceState.get<"elements" | "flow">("messagefoundry.graphPerspective", "elements"),
  );
  const graphView = vscode.window.createTreeView("messagefoundry.graph", { treeDataProvider: graph });
  graphView.message = graph.statusMessage();
  context.subscriptions.push(graphView);
  // Translation Tables (code sets) tree — its own provider, refreshed on save.
  const codeSets = new CodeSetsProvider();
  const codeSetsView = vscode.window.createTreeView("messagefoundry.codesets", {
    treeDataProvider: codeSets,
  });
  context.subscriptions.push(codeSetsView);
  // Helper: read a code-set name off a tree node (its label) for the item-context commands.
  const codeSetName = (node?: vscode.TreeItem): string | undefined =>
    typeof node?.label === "string" ? node.label : undefined;
  // Home hosts the persistent Connections search box (a TreeView can't host an input): typing drives
  // the same graph filter as the funnel command — and thus the #228 handler/router/transform matches.
  const home = new HomeView(
    (text) => {
      graph.setFilter(text);
      graphView.message = graph.statusMessage();
    },
    () => graph.getFilter(),
  );
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("messagefoundry.home", home),
  );

  // Opt-in per workspace: open straight to the MessageFoundry sidebar instead of the Explorer.
  // Config workspaces activate us at startup (workspaceContains:**/*.py), so this fires on open.
  if (vscode.workspace.getConfiguration("messagefoundry").get<boolean>("revealViewOnStartup", false)) {
    void vscode.commands.executeCommand("workbench.view.extension.messagefoundry");
  }

  const validator = createValidator(context);
  registerCompletion(context, graph);
  registerChat(context, graph);
  registerEditorToolbar(context);
  registerInsertElement(context);
  // Live-debug v1 (#92): status-bar toggle + on-save dryrun → CodeLens summaries (off by default).
  registerLiveDebug(context);
  // Engine status bar (#221c): promote-target URL/environment + reachability poll. Distinct from the
  // left-side live-debug toggles above — this reflects the real engine, not the offline dry-run loop.
  registerEngineStatusBar(context);
  // Custom editors (#221b): connections.toml + codesets/*.csv open in the form/grid by default, with
  // "Reopen With → Text Editor" always available. Reuses the existing form rendering; the router names
  // feed the connection form's router dropdown.
  registerConfigEditors(context, routerNames);
  // Action-list lens (#222, ADR 0076 phase 2b): a read-only, opt-in Corepoint-style typed Steps
  // view over a Handler .py (CodeLens "Reopen in Steps view" + command). Registered at
  // priority "option" — NOT the default editor for .py — so Python files stay with the user's tooling.
  registerSteps(context);
  const testBench = new TestBench(context);
  const cookbook = new CookbookPanel(context);
  // ADR 0091 D3: the read-only, focus-first Wiring Map panel — pulls the graph from (and re-renders
  // with) the CONNECTIONS provider.
  const wiringMap = new WiringMapPanel(context, graph);

  context.subscriptions.push(
    vscode.commands.registerCommand("messagefoundry.openTestBench", () => testBench.open()),
    vscode.commands.registerCommand("messagefoundry.openCookbook", () => cookbook.open()),
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
      home.setFilterText(value); // keep the persistent search box in sync
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
    // ADR 0091 D2: flip between the element-centric sections (default) and the legacy flow chain.
    vscode.commands.registerCommand("messagefoundry.toggleGraphPerspective", () => {
      const next = graph.getPerspective() === "elements" ? "flow" : "elements";
      graph.setPerspective(next);
      void context.workspaceState.update("messagefoundry.graphPerspective", next);
      graphView.message = graph.statusMessage();
    }),
    // A cross-reference row reveals its target element (the by-name navigation the wire-by-name
    // model calls for). A filtered-out target clears the filter rather than failing silently.
    vscode.commands.registerCommand(
      "messagefoundry.revealElement",
      async (kind: "inbound" | "router" | "handler" | "outbound", name: string) => {
        let node = graph.findElement(kind, name);
        if (!node && graph.getFilter().trim()) {
          graph.setFilter("");
          graphView.message = graph.statusMessage();
          node = graph.findElement(kind, name);
        }
        if (!node) {
          return;
        }
        // reveal() scrolls minimally, so a downward jump docks the target at the BOTTOM edge.
        // The API has no reveal-at-top option; revealing the section's last element first makes
        // the second reveal scroll UP, which docks the target at the top of the viewport.
        const tail = graph.sectionTail(kind);
        if (tail && tail !== node) {
          try {
            await graphView.reveal(tail, { select: false, focus: false });
          } catch {
            // Scroll positioning is best-effort — never let it break the actual reveal.
          }
        }
        await graphView.reveal(node, { select: true, focus: false, expand: true });
      },
    ),
    vscode.commands.registerCommand(
      "messagefoundry.openSource",
      async (file: string, line: number) => {
        const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(file));
        const pos = new vscode.Position(Math.max(0, (line ?? 1) - 1), 0);
        await vscode.window.showTextDocument(doc, { selection: new vscode.Range(pos, pos) });
      },
    ),
    // ADR 0091 D3: open the read-only Wiring Map, focused. Callable three ways: with an explicit
    // (kind, name); from a tree row's context menu (VS Code passes the row as the first arg); or
    // bare — then the CONNECTIONS selection is used if it is an element row, else a QuickPick
    // across all elements. Always focused: the whole estate is never rendered by default.
    vscode.commands.registerCommand(
      "messagefoundry.openWiringMap",
      async (kindOrNode?: unknown, name?: string) => {
        const kinds = ["inbound", "router", "handler", "outbound"];
        const fromNode = (v: unknown): MapFocus | undefined => {
          const vm = (v as { vm?: { kind?: string; elementKind?: MapFocus["kind"]; elementName?: string } } | undefined)?.vm;
          return vm?.kind === "element" && vm.elementKind && vm.elementName
            ? { kind: vm.elementKind, name: vm.elementName }
            : undefined;
        };
        let focus: MapFocus | undefined;
        if (typeof kindOrNode === "string" && kinds.includes(kindOrNode) && typeof name === "string") {
          focus = { kind: kindOrNode as MapFocus["kind"], name };
        } else {
          focus = fromNode(kindOrNode) ?? fromNode(graphView.selection[0]);
        }
        if (!focus) {
          const g = graph.getGraph();
          const items = !g
            ? []
            : [
                ...g.inbound.map((c) => ({ label: `inbound: ${c.name}`, focus: { kind: "inbound", name: c.name } as MapFocus })),
                ...g.routers.map((r) => ({ label: `router: ${r.name}`, focus: { kind: "router", name: r.name } as MapFocus })),
                ...g.handlers.map((h) => ({ label: `handler: ${h.name}`, focus: { kind: "handler", name: h.name } as MapFocus })),
                ...g.outbound.map((o) => ({ label: `outbound: ${o.name}`, focus: { kind: "outbound", name: o.name } as MapFocus })),
              ];
          if (items.length === 0) {
            void vscode.window.showInformationMessage(
              "MessageFoundry: no wired elements to map — refresh the Connections view first.",
            );
            return;
          }
          const pick = await vscode.window.showQuickPick(items, { placeHolder: "Focus the Wiring Map on…" });
          if (!pick) {
            return; // cancelled — never fall back to an unfocused whole-estate render
          }
          focus = pick.focus;
        }
        wiringMap.open(focus);
      },
    ),
    // Context-menu label wrapper ("Show in Wiring Map" on a tree row) — forwards the row it is
    // invoked on; hidden from the palette (package.json commandPalette when:false).
    vscode.commands.registerCommand("messagefoundry.showInWiringMap", (node?: vscode.TreeItem) =>
      vscode.commands.executeCommand("messagefoundry.openWiringMap", node),
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
    // Clone a data-authored connection into a new one, pre-filled from its config (#175); a new name
    // is required before save. Mirrors editConnection's name extraction from the tree node.
    vscode.commands.registerCommand("messagefoundry.cloneConnection", (node?: vscode.TreeItem) => {
      const name = typeof node?.label === "string" ? node.label : undefined;
      void openConnectionEditor(context, {
        routers: routerNames(),
        cloneFrom: name,
        onSaved: () => graph.refresh(),
      });
    }),
    vscode.commands.registerCommand("messagefoundry.newConnection", () =>
      openConnectionEditor(context, { routers: routerNames(), onSaved: () => graph.refresh() }),
    ),
    // Keyboard-first alternative to the webview form (#221e): a native multi-step QuickInput wizard
    // writing via the same `connection upsert` CLI.
    vscode.commands.registerCommand("messagefoundry.newConnectionQuickInput", () =>
      newConnectionWizard({ routers: routerNames(), onSaved: () => graph.refresh() }),
    ),
    // ---- Translation Tables (code sets) ----
    vscode.commands.registerCommand("messagefoundry.refreshCodeSets", () => codeSets.refresh()),
    vscode.commands.registerCommand("messagefoundry.newCodeSet", () =>
      openCodeSetEditor(context, { onSaved: () => codeSets.refresh() }),
    ),
    // Edit a code set (grid editor). A row click / context action passes the node; the editor opens
    // read-only for a TOML code set (it only writes CSV).
    vscode.commands.registerCommand("messagefoundry.editCodeSet", (node?: vscode.TreeItem) => {
      const name = codeSetName(node);
      if (!name) {
        void vscode.window.showInformationMessage("MessageFoundry: pick a translation table to edit.");
        return;
      }
      void openCodeSetEditor(context, { editName: name, onSaved: () => codeSets.refresh() });
    }),
    // Rename a code set's file (keeps its extension). Name-safety is enforced by the CLI.
    vscode.commands.registerCommand("messagefoundry.renameCodeSet", async (node?: vscode.TreeItem) => {
      const name = codeSetName(node);
      if (!name) {
        return;
      }
      const ws = workspaceDir();
      if (!ws) {
        return;
      }
      const to = await vscode.window.showInputBox({
        prompt: `Rename code set "${name}" to…`,
        value: name,
        placeHolder: "new_name (a bare stem, no extension)",
      });
      if (!to || to === name) {
        return; // cancelled or unchanged
      }
      try {
        await codesetRename(name, to, ws);
      } catch (e) {
        void vscode.window.showErrorMessage(`MessageFoundry: rename failed — ${String(e)}`);
        return;
      }
      void codeSets.refresh();
      void vscode.window.showInformationMessage(`MessageFoundry: renamed code set ${name} → ${to}.`);
    }),
    // Delete a code set from the tree: modal confirm, then shell `codeset remove`.
    vscode.commands.registerCommand("messagefoundry.deleteCodeSet", async (node?: vscode.TreeItem) => {
      const name = codeSetName(node);
      if (!name) {
        return;
      }
      const ws = workspaceDir();
      if (!ws) {
        return;
      }
      const confirm = await vscode.window.showWarningMessage(
        `Remove code set "${name}"?`,
        { modal: true },
        "Remove",
      );
      if (confirm !== "Remove") {
        return;
      }
      try {
        await codesetRemove(name, ws);
      } catch (e) {
        void vscode.window.showErrorMessage(`MessageFoundry: remove failed — ${String(e)}`);
        return;
      }
      void codeSets.refresh();
      void vscode.window.showInformationMessage(`MessageFoundry: removed code set ${name}.`);
    }),
    vscode.commands.registerCommand("messagefoundry.newRoute", () =>
      openNewRoute(context, () => graph.refresh()),
    ),
    vscode.commands.registerCommand("messagefoundry.newRouter", () => insertSnippet("newRouter")),
    vscode.commands.registerCommand("messagefoundry.newHandler", () => insertSnippet("newHandler")),
    vscode.commands.registerCommand("messagefoundry.setupSourceControl", () =>
      setupSourceControl(context),
    ),
    vscode.commands.registerCommand("messagefoundry.setRepoStorage", () => setRepoStorage()),
    // Author a [[alerts.rules]] entry in the service-settings TOML (ADR 0014; webview shells the CLI).
    vscode.commands.registerCommand("messagefoundry.newAlert", () => openAlertEditor(context)),
    vscode.commands.registerCommand("messagefoundry.generateSamples", () => generateSamples()),
    vscode.commands.registerCommand("messagefoundry.promote", () => promote(context)),
    vscode.commands.registerCommand("messagefoundry.showAiPolicy", () => showAiPolicy(context)),
    // A discoverable version check (the Steps toolbar also shows it): confirm which build is loaded.
    vscode.commands.registerCommand("messagefoundry.showVersion", () => {
      const v = String(context.extension.packageJSON.version ?? "?");
      void vscode.window.showInformationMessage(`MessageFoundry extension — v${v}`);
    }),
    // Walkthrough helpers (#221a): open engine settings / reveal the config dir in the Explorer.
    vscode.commands.registerCommand("messagefoundry.openEngineSettings", () =>
      vscode.commands.executeCommand("workbench.action.openSettings", "messagefoundry.engineUrl"),
    ),
    // Open the Settings UI filtered to all of this extension's settings (liveStatus, configDir, engine
    // target, …) — the discoverable home for the toggles that don't belong among the sidebar's actions.
    vscode.commands.registerCommand("messagefoundry.openSettings", () =>
      vscode.commands.executeCommand("workbench.action.openSettings", "@ext:messagefoundry.messagefoundry"),
    ),
    vscode.commands.registerCommand("messagefoundry.openConfigDir", async () => {
      const ws = workspaceDir();
      if (!ws) {
        void vscode.window.showInformationMessage("MessageFoundry: open a workspace folder first.");
        return;
      }
      const dir = configDir();
      const abs = path.isAbsolute(dir) ? dir : path.join(ws, dir);
      try {
        await vscode.commands.executeCommand("revealInExplorer", vscode.Uri.file(abs));
      } catch {
        void vscode.window.showInformationMessage(`MessageFoundry: config dir is ${abs}.`);
      }
    }),
  );

  // --- ADR 0091 follow-through: one debounced refresh pass, fed by saves AND external edits ---
  // Both an in-editor save and a config-dir FileSystemWatcher event (git pull, another tool writing
  // connections.toml / a code set) funnel into ONE ~750ms coalescer, so a save's own watcher echo
  // and a multi-file checkout cost a single validate + graph + code-sets refresh. Skipped when exec
  // is gated (untrusted workspace) — cli.run() would refuse anyway; the early return just avoids a
  // noisy error toast per event (SEC-004).
  const refreshAll = (): void => {
    if (isExecGated()) {
      return;
    }
    void validator.run();
    void graph.refresh();
    void codeSets.refresh();
  };
  const refreshCoalescer = new RefreshCoalescer(refreshAll);
  context.subscriptions.push(
    { dispose: () => refreshCoalescer.dispose() },
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (doc.languageId === "python") {
        refreshCoalescer.trigger();
      }
    }),
  );
  registerConfigWatcher(context, () => refreshCoalescer.trigger());
  // Live decorations (ADR 0091): opt-in engine poll → status/count suffixes on connection rows.
  registerLiveStatus(context, graph);

  // Auto-run the CLI on activation only in a trusted workspace — never launch a workspace-supplied
  // interpreter just because the folder was opened (SEC-004). The cli.ts gate also enforces this;
  // this early return avoids firing three failing CLI calls in an untrusted workspace.
  if (workspaceDir() && !isExecGated()) {
    void validator.run();
    void graph.refresh();
    void codeSets.refresh();
  }

  // One-time nudge to put a MessageFoundry project under version control + commit-time checks.
  void maybeSuggestSourceControl(context);
}

export function deactivate(): void {
  // nothing to clean up beyond context.subscriptions
}
