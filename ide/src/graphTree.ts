// Sidebar tree of the wired graph, from `messagefoundry graph --json`. Also the name source for
// completion (Send(...) / router="..."), so it's refreshed on save. Connections are a flat (or
// grouped/filtered) list; each inbound expands to its router → handler → outbound flow (edges are
// best-effort from the CLI). Every node is clickable and jumps to its definition.
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";

interface Located {
  file?: string | null;
  line?: number | null;
}

export interface Graph {
  inbound: ({ name: string; type: string; router: string } & Located)[];
  outbound: ({ name: string; type: string } & Located)[];
  routers: ({ name: string; handlers?: string[] } & Located)[];
  handlers: ({ name: string; sends?: string[] } & Located)[];
}

class Node extends vscode.TreeItem {
  constructor(
    label: string,
    collapsible: vscode.TreeItemCollapsibleState,
    public readonly children: Node[] = [],
    icon?: string,
    description?: string,
  ) {
    super(label, collapsible);
    if (icon) {
      this.iconPath = new vscode.ThemeIcon(icon);
    }
    if (description) {
      this.description = description;
    }
  }
}

const NONE = vscode.TreeItemCollapsibleState.None;
const COLLAPSED = vscode.TreeItemCollapsibleState.Collapsed;
const EXPANDED = vscode.TreeItemCollapsibleState.Expanded;

export type GroupingMode = "none" | "type" | "partner";

// Group keys parsed from the [TYPE]_[PARTNER]_[MESSAGE] convention name.
function typeCode(name: string): string {
  const i = name.indexOf("_");
  return i > 0 ? name.slice(0, i) : "(other)";
}

function partnerName(name: string): string {
  const parts = name.split("_");
  return parts.length >= 2 && parts[1] ? parts[1] : "(none)";
}

function openCommand(loc: Located): vscode.Command | undefined {
  return loc.file
    ? { command: "messagefoundry.openSource", title: "Open Definition", arguments: [loc.file, loc.line ?? 1] }
    : undefined;
}

interface Maps {
  routers: Map<string, Graph["routers"][number]>;
  handlers: Map<string, Graph["handlers"][number]>;
  outbound: Map<string, Graph["outbound"][number]>;
}

function buildMaps(g: Graph): Maps {
  return {
    routers: new Map(g.routers.map((r) => [r.name, r])),
    handlers: new Map(g.handlers.map((h) => [h.name, h])),
    outbound: new Map(g.outbound.map((o) => [o.name, o])),
  };
}

function outboundRefNode(name: string, maps: Maps): Node {
  const o = maps.outbound.get(name);
  const node = new Node(name, NONE, [], "arrow-up", o ? `outbound · ${o.type}` : "outbound");
  node.command = openCommand(o ?? {});
  return node;
}

function handlerNode(name: string, maps: Maps): Node {
  const h = maps.handlers.get(name);
  const outs = (h?.sends ?? []).map((s) => outboundRefNode(s, maps));
  const node = new Node(name, outs.length ? COLLAPSED : NONE, outs, "symbol-method", "handler");
  node.command = openCommand(h ?? {});
  return node;
}

function routerNode(name: string, maps: Maps): Node {
  const r = maps.routers.get(name);
  const handlers = (r?.handlers ?? []).map((h) => handlerNode(h, maps));
  const node = new Node(name, handlers.length ? COLLAPSED : NONE, handlers, "git-branch", "router");
  node.command = openCommand(r ?? {});
  return node;
}

// Inbound: expands to router → handler → outbound. Outbound: a leaf. Both carry contextValue
// "meforConnection" so the title/inline "settings" action applies, and a command to jump to their def.
function inboundNode(c: Graph["inbound"][number], maps: Maps): Node {
  const node = new Node(c.name, COLLAPSED, [routerNode(c.router, maps)], "arrow-right", `inbound · ${c.type} → ${c.router}`);
  node.command = openCommand(c);
  node.contextValue = "meforConnection";
  return node;
}

function outboundNode(c: Graph["outbound"][number]): Node {
  const node = new Node(c.name, NONE, [], "arrow-up", `outbound · ${c.type}`);
  node.command = openCommand(c);
  node.contextValue = "meforConnection";
  return node;
}

export class GraphProvider implements vscode.TreeDataProvider<Node> {
  private readonly _changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._changed.event;
  private graph: Graph | undefined;
  private error: string | undefined;
  private grouping: GroupingMode = "none";
  private filter = "";

  getGraph(): Graph | undefined {
    return this.graph;
  }

  getFilter(): string {
    return this.filter;
  }

  setFilter(text: string): void {
    this.filter = text;
    this._changed.fire();
  }

  setGrouping(mode: GroupingMode): void {
    this.grouping = mode;
    this._changed.fire();
  }

  /** A one-line banner for the view (active grouping/filter), or undefined when both are default. */
  statusMessage(): string | undefined {
    const parts: string[] = [];
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
    this._changed.fire();
  }

  getTreeItem(node: Node): vscode.TreeItem {
    return node;
  }

  getChildren(node?: Node): Node[] {
    if (node) {
      return node.children;
    }
    if (this.error) {
      return [new Node(this.error, NONE, [], "error")];
    }
    const g = this.graph;
    if (!g) {
      return [new Node("No config loaded", NONE, [], "info")];
    }
    const maps = buildMaps(g);
    let conns = [...g.inbound.map((c) => inboundNode(c, maps)), ...g.outbound.map((c) => outboundNode(c))];
    const f = this.filter.trim().toLowerCase();
    if (f) {
      conns = conns.filter((n) => String(n.label).toLowerCase().includes(f));
    }
    conns.sort((a, b) => String(a.label).localeCompare(String(b.label)));
    if (conns.length === 0) {
      return [new Node(f ? `No connections match "${this.filter}"` : "No connections", NONE, [], "info")];
    }
    if (this.grouping === "none") {
      return conns;
    }
    // Group into expandable buckets keyed off the convention name (type code or partner).
    const keyOf = this.grouping === "type" ? typeCode : partnerName;
    const groups = new Map<string, Node[]>();
    for (const n of conns) {
      const key = keyOf(String(n.label));
      const bucket = groups.get(key);
      if (bucket) {
        bucket.push(n);
      } else {
        groups.set(key, [n]);
      }
    }
    return [...groups.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([key, children]) => new Node(key, EXPANDED, children, "folder", String(children.length)));
  }
}
