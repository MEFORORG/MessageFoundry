// Sidebar tree of the wired graph, from `messagefoundry graph --json` (v2). Also the name source
// for completion (Send(...) / router="..."), so it's refreshed on save. Rendering is the pure
// view-model in graphModel.ts (ADR 0091 D2): an element-centric four-section perspective (default)
// and a legacy by-flow chain perspective, toggled from the view title. Every element row jumps to
// its definition; every cross-reference row reveals its target element in the tree.
import * as path from "node:path";
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
import { buildSymbolIndex, matchSymbols, type SymbolDef, type SymbolKind } from "./symbolIndex";

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
  private symbols: SymbolDef[] = [];

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
    // The name-search index (#228) is a pure file scan, independent of the CLI graph fetch — refreshed
    // alongside it so a save picks up added/renamed transforms. Cheap and never throws.
    this.symbols = cwd ? buildSymbolIndex(path.join(cwd, configDir())) : [];
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
    // While searching, append a "Definitions" section for handler/router/transform *symbols* matched by
    // name (#228) — the graph view only reaches element names, so a transform (`def xform_…`) or a
    // differently-named handler function inside a role-combined feed is otherwise unfindable. Names
    // already shown as element rows are excluded so nothing double-lists.
    const f = this.filter.trim();
    if (f) {
      const defs = matchSymbols(this.symbols, f, collectElementNames(vms));
      if (defs.length > 0) {
        roots.push(new Node(definitionsSection(defs), undefined));
      }
    }
    if (roots.length === 0) {
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

const SYMBOL_ICON: Record<SymbolKind, string> = {
  handler: "symbol-method",
  router: "git-branch",
  transform: "symbol-function",
};

/** Every graph-element name currently shown (any perspective), so the Definitions section can exclude
 *  names that already appear as element rows and not double-list them. */
function collectElementNames(vms: VmNode[]): Set<string> {
  const names = new Set<string>();
  const walk = (n: VmNode): void => {
    if (n.kind === "element" && n.elementName) {
      names.add(n.elementName);
    }
    n.children.forEach(walk);
  };
  vms.forEach(walk);
  return names;
}

/** The "Definitions" search section: one row per matched symbol, each opening its file at the def line.
 *  A handler/router row also carries its (kind, name) so reveal / open-wiring-map work on it; a
 *  transform is a pure jump (it is not a graph element). */
function definitionsSection(defs: SymbolDef[]): VmNode {
  return {
    id: "section:definitions",
    label: `Definitions (${defs.length})`,
    kind: "section",
    icon: "search",
    collapsible: "expanded",
    children: defs.map((d, i) => ({
      id: `def:${d.kind}:${d.name}:${d.file}:${d.line}:${i}`,
      label: d.name,
      kind: "element",
      description: `${d.kind} · ${path.basename(d.file)}`,
      icon: SYMBOL_ICON[d.kind],
      collapsible: "none",
      children: [],
      ...(d.kind === "transform" ? {} : { elementKind: d.kind, elementName: d.name }),
      open: { file: d.file, line: d.line },
    })),
  };
}
