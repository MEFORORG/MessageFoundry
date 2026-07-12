// Sidebar tree of the wired graph, from `messagefoundry graph --json` (v2). Also the name source
// for completion (Send(...) / router="..."), so it's refreshed on save. Rendering is the pure
// view-model in graphModel.ts (ADR 0091 D2): an element-centric four-section perspective (default)
// and a legacy by-flow chain perspective, toggled from the view title. Every element row jumps to
// its definition; every cross-reference row reveals its target element in the tree.
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";
import {
  buildElementsView,
  buildFlowView,
  runtimeEquals,
  type ElementKind,
  type Graph,
  type GroupingMode,
  type Perspective,
  type RuntimeMap,
  type VmNode,
} from "./graphModel";

export type { Graph, GroupingMode, Perspective };

class Node extends vscode.TreeItem {
  constructor(
    public readonly vm: VmNode,
    public readonly parent: Node | undefined,
  ) {
    super(
      vm.label,
      vm.collapsible === "none"
        ? vscode.TreeItemCollapsibleState.None
        : vm.collapsible === "expanded"
          ? vscode.TreeItemCollapsibleState.Expanded
          : vscode.TreeItemCollapsibleState.Collapsed,
    );
    this.id = vm.id;
    this.description = vm.description;
    if (vm.icon) {
      this.iconPath = new vscode.ThemeIcon(vm.icon);
    }
    if (vm.contextValue) {
      this.contextValue = vm.contextValue;
    }
    if (vm.kind === "ref" && vm.elementKind && vm.elementName) {
      this.tooltip = `Reveal ${vm.elementKind} '${vm.elementName}' in the tree`;
      this.command = {
        command: "messagefoundry.revealElement",
        title: "Reveal Element",
        arguments: [vm.elementKind, vm.elementName],
      };
    } else if (vm.open) {
      this.command = {
        command: "messagefoundry.openSource",
        title: "Open Definition",
        arguments: [vm.open.file, vm.open.line],
      };
    }
    this.children = vm.children.map((c) => new Node(c, this));
  }

  readonly children: Node[];
}

export class GraphProvider implements vscode.TreeDataProvider<Node> {
  private readonly _changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._changed.event;
  private graph: Graph | undefined;
  private error: string | undefined;
  private grouping: GroupingMode = "none";
  private filter = "";
  private perspective: Perspective = "elements";
  private roots: Node[] | undefined;
  private runtime: RuntimeMap | undefined;

  getGraph(): Graph | undefined {
    return this.graph;
  }

  getFilter(): string {
    return this.filter;
  }

  setFilter(text: string): void {
    this.filter = text;
    this.invalidate();
  }

  setGrouping(mode: GroupingMode): void {
    this.grouping = mode;
    this.invalidate();
  }

  getPerspective(): Perspective {
    return this.perspective;
  }

  setPerspective(p: Perspective): void {
    this.perspective = p;
    this.invalidate();
  }

  /** Live per-connection runtime facts from the engine poll (ADR 0091 live decorations), or
   *  undefined to drop back to the undecorated tree. Skips the rebuild when the picture is
   *  unchanged so the steady-state poll doesn't flicker the view every interval. */
  setRuntime(map: RuntimeMap | undefined): void {
    if (runtimeEquals(this.runtime, map)) {
      return;
    }
    this.runtime = map;
    this.invalidate();
  }

  /** A one-line banner for the view (active perspective/grouping/filter), or undefined at defaults. */
  statusMessage(): string | undefined {
    const parts: string[] = [];
    if (this.perspective === "flow") {
      parts.push("Flow view");
    }
    if (this.grouping === "type") {
      parts.push("Grouped by type");
    } else if (this.grouping === "partner") {
      parts.push("Grouped by partner");
    }
    if (this.filter.trim()) {
      parts.push(`Filter: "${this.filter.trim()}"`);
    }
    return parts.length ? parts.join(" · ") : undefined;
  }

  async refresh(): Promise<void> {
    const cwd = workspaceDir();
    this.error = undefined;
    if (!cwd) {
      this.graph = undefined;
    } else {
      try {
        this.graph = await runJson<Graph>(["graph", "--config", configDir()], cwd);
      } catch (e) {
        // Keep the last good graph so name completion still works while the config is mid-edit /
        // temporarily invalid; just surface the error in the tree.
        this.error = String(e);
      }
    }
    this.invalidate();
  }

  private invalidate(): void {
    this.roots = undefined;
    this._changed.fire();
  }

  private info(message: string, icon: string): Node[] {
    return [
      new Node(
        { id: `info:${message}`, label: message, kind: "info", icon, collapsible: "none", children: [] },
        undefined,
      ),
    ];
  }

  private buildRoots(): Node[] {
    if (this.error) {
      return this.info(this.error, "error");
    }
    const g = this.graph;
    if (!g) {
      return this.info("No config loaded", "info");
    }
    const vms =
      this.perspective === "elements"
        ? buildElementsView(g, this.filter, this.runtime)
        : buildFlowView(g, this.filter, this.grouping);
    const roots = vms.map((vm) => new Node(vm, undefined));
    if (roots.length === 0) {
      const f = this.filter.trim();
      return this.info(f ? `No elements match "${f}"` : "No connections", "info");
    }
    return roots;
  }

  getTreeItem(node: Node): vscode.TreeItem {
    return node;
  }

  getParent(node: Node): Node | undefined {
    return node.parent;
  }

  getChildren(node?: Node): Node[] {
    if (node) {
      return node.children;
    }
    if (!this.roots) {
      this.roots = this.buildRoots();
    }
    return this.roots;
  }

  /** The element row for (kind, name) in the ELEMENTS perspective — the reveal target. */
  findElement(kind: ElementKind, name: string): Node | undefined {
    if (this.perspective !== "elements") {
      return undefined;
    }
    if (!this.roots) {
      this.roots = this.buildRoots();
    }
    for (const sectionNode of this.roots) {
      for (const el of sectionNode.children) {
        if (el.vm.elementKind === kind && el.vm.elementName === name) {
          return el;
        }
      }
    }
    return undefined;
  }

  /** The LAST element row of the section holding `kind` — revealed first so that revealing the
   *  real target scrolls upward and docks it at the top of the viewport (see revealElement). */
  sectionTail(kind: ElementKind): Node | undefined {
    if (this.perspective !== "elements" || !this.roots) {
      return undefined;
    }
    const section = this.roots.find((s) => s.children.some((el) => el.vm.elementKind === kind));
    return section?.children[section.children.length - 1];
  }
}
