// Symbol index for the sidebar search (BACKLOG #228). The wired-graph tree matches element names —
// inbound/outbound/router/handler — but a *transform* (a plain `def xform_…` helper the handler calls)
// is not a graph element, and in a role-combined feed module the @handler/@router function name is a
// Python symbol INSIDE a file whose *filename* is the connection. So searching a transform / handler /
// router by name finds nothing (and Ctrl+P misses it too — it's a symbol, not a filename). This scans
// the config dir's `.py` source for top-level `def` names and lets the tree surface them as a
// "Definitions" section that jumps to file:line.
//
// It also indexes the outbound connection each `Send("…", msg)` targets, so searching an outbound name
// reaches the CALL SITES that send to it — the graph view already reaches the outbound's own element
// row, but not the lines that address it.
//
// The scan is a pure text pass (scanModuleSymbols) with a thin fs wrapper (buildSymbolIndex), mirroring
// graphModel.ts so it's unit-tested node-side with no vscode import. Reading source is side-effect-free
// (no interpreter exec), so it is safe even when the CLI is exec-gated in an untrusted workspace.
// `definitionsSection` (the rendered view-model for those hits) lives here rather than in graphTree.ts
// for the same reason: graphTree.ts imports `vscode`, which would put the row shape — and the menu
// contract that hangs off its contextValue — out of reach of the node-side unit runner that every CI
// leg runs. The VmNode import below is TYPE-ONLY and erases at compile; no runtime edge.
import * as fs from "node:fs";
import * as path from "node:path";
import { type VmNode } from "./graphModel";

export type SymbolKind = "handler" | "router" | "transform" | "send";

export interface SymbolDef {
  /** The symbol's own name — for a `send`, the connection name it targets (not the calling def). */
  name: string;
  kind: SymbolKind;
  /** Absolute path (ready for vscode.Uri.file). */
  file: string;
  /** 1-based, to match the messagefoundry.openSource contract. For a `send`, the CALL-SITE line. */
  line: number;
}

// A top-level (column-0) function def. The `^` with no leading-whitespace class is deliberate: it
// excludes indented method/nested defs, so only module-level handlers/routers/transforms are indexed.
const DEF_RE = /^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/;
// The trailing (dotted) name of a decorator, e.g. `@handler`, `@router("X")`, `@messagefoundry.handler`.
const DECORATOR_RE = /^@\s*(?:[A-Za-z_]\w*\s*\.\s*)*([A-Za-z_]\w*)/;

// A `Send(…)` call site. This is deliberately a SEPARATE pass rather than a wider DEF_RE: a Send lives
// INSIDE a def body, while DEF_RE is anchored at column 0 to exclude nested defs, so no widening of the
// def regex could ever reach one. Global + an exec loop so two Sends on one line each yield a row.
// Alternative 1: a quoted literal target (`Send("OB_X", msg)`); alternative 2: a bare identifier
// (`Send(OB_X, msg)`), resolved against the module-constant map below or else dropped.
const SEND_RE = /\bSend\s*\(\s*(?:(['"])([^'"\r\n]{1,128})\1|([A-Za-z_]\w*))/g;
// A module-level `NAME = "literal"` constant at column 0. Connection names are conventionally
// SCREAMING_CASE, which keeps this narrow enough to skip ordinary module state.
const MODULE_CONST_RE = /^([A-Z][A-Z0-9_]*)\s*=\s*(['"])([^'"\r\n]{1,128})\2\s*$/;
// A plausible connection name. Hyphens are allowed on purpose — `samples/config/adt.py:53` sends to
// `FILE-OUT_Test_ADT`. Anything else (an f-string fragment, a path, an expression) is dropped rather
// than indexed as a phantom name.
const CONNECTION_NAME_RE = /^[A-Za-z_][\w.-]{0,127}$/;

/**
 * Scan ONE module's source for its top-level `def` symbols and its `Send(…)` targets (pure — no IO).
 * `file` is echoed onto each result so callers pass an absolute path. A def is classified by the
 * decorators immediately above it: `@handler` → handler, `@router` → router, otherwise a plain
 * transform/helper. (Classification only inspects contiguous single-line decorators directly above the
 * def — the usual form in this codebase; a rare multi-line decorator call degrades to "transform",
 * which mislabels the icon but never hides the symbol.)
 *
 * Send extraction is best-effort by construction. It reaches AT LEAST a quoted literal target and a
 * module-level `NAME = "literal"` constant referenced by name. It drops, rather than guesses, at least:
 * a computed, imported, or f-string target; and a call whose target does not sit on the same line as
 * `Send(` (the scan is line-scoped, so a ruff-wrapped multi-line call is invisible to it).
 *
 * Two bounds worth stating plainly, because both are places a reader could over-read this:
 *
 * 1. This is NOT the `graph --json` bound. That extractor is AST-first and, when it cannot resolve a
 *    target, marks the element `dynamic` and SURFACES it — ADR 0091 AC-3, "never a silently truncated
 *    chain". This scan has no such channel: an unresolvable target is simply absent from the search
 *    index. (`dynamic` is also a per-element flag there, not a `provenance` value — provenance is
 *    `declared`/`literal`/`heuristic`.) The graph views remain the authority on resolved wiring.
 * 2. The module-constant resolution here is a flat last-binding text scan. It applies NONE of the
 *    whole-module disqualification `messagefoundry/config/graph.py` requires of the same construct (a
 *    `global NAME`, or any second module-scope binding, demotes that extractor's candidate to
 *    `heuristic`). So a rebound name can resolve to the wrong literal here — the cost is a search row
 *    that opens the right file at the right call site under a stale name.
 *
 * A `Send("X")` written inside a docstring still indexes: the comment guard is quote-aware and
 * line-scoped, so it strips a real `#` comment (leading OR trailing) but does not track triple-quoted
 * strings. The cost is one extra search row that opens the file at that line, and a real tokenizer
 * would be out of proportion to that.
 */
export function scanModuleSymbols(file: string, text: string): SymbolDef[] {
  const lines = text.split(/\r?\n/);
  const constants = moduleConstants(lines);
  const out: SymbolDef[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = DEF_RE.exec(lines[i]);
    if (m) {
      out.push({ name: m[1], kind: classify(lines, i), file, line: i + 1 });
    }
    for (const target of sendTargets(lines[i], constants)) {
      out.push({ name: target, kind: "send", file, line: i + 1 });
    }
  }
  return out;
}

/** Module-level `NAME = "literal"` constants, name → literal. Collected in a full pre-pass because a
 *  Python constant may be defined textually BELOW the def that uses it (the def body runs later), so
 *  the samples' `OB_DEMO_ORU = "OB_DEMO_ORU"` must resolve regardless of where it sits in the file. */
function moduleConstants(lines: string[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of lines) {
    const m = MODULE_CONST_RE.exec(codePart(line));
    if (m) {
      out.set(m[1], m[3]);
    }
  }
  return out;
}

/**
 * The code part of ONE line: everything before the first `#` that is not inside a string literal.
 *
 * Quote-aware on purpose. A whole-line `#` guard would be the obvious thing here and it is not enough:
 * `return Send("OB_REAL", msg)  # was Send("OB_GHOST", msg)` is a live call site AND a dead one on the
 * same line, and only the trailing half is a comment. Conversely a naive split at the first `#` would
 * truncate `Send("OB_A", msg) if "#" in text else Send("OB_B", msg)` and silently drop a real call
 * site — so the scan tracks quotes (honouring backslash escapes) and only cuts outside a literal.
 *
 * Line-scoped like the rest of the scan, so it does not track triple-quoted strings: a `#` inside a
 * docstring line ends that line early. That direction is the safe one — it drops a would-be row rather
 * than inventing a phantom connection name.
 */
function codePart(line: string): string {
  let quote: string | undefined;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote !== undefined) {
      if (c === "\\") {
        i++; // an escaped character cannot close the literal
      } else if (c === quote) {
        quote = undefined;
      }
    } else if (c === "'" || c === '"') {
      quote = c;
    } else if (c === "#") {
      return line.slice(0, i);
    }
  }
  return line;
}

/** Every connection name `Send(…)` addresses on ONE line, left to right. Comments are not call sites. */
function sendTargets(rawLine: string, constants: ReadonlyMap<string, string>): string[] {
  const line = codePart(rawLine);
  const out: string[] = [];
  SEND_RE.lastIndex = 0; // the regex is module-level and stateful (/g) — reset before every line
  let m: RegExpExecArray | null;
  while ((m = SEND_RE.exec(line)) !== null) {
    const target = m[2] ?? (m[3] !== undefined ? constants.get(m[3]) : undefined);
    if (target !== undefined && CONNECTION_NAME_RE.test(target)) {
      out.push(target);
    }
  }
  return out;
}

function classify(lines: string[], defIdx: number): SymbolKind {
  // Walk backward over the contiguous decorator run directly above the def (Python forbids a blank line
  // between a decorator and its def, so a non-`@` line ends the run).
  for (let j = defIdx - 1; j >= 0; j--) {
    const t = lines[j].trim();
    if (!t.startsWith("@")) {
      break;
    }
    const name = DECORATOR_RE.exec(t)?.[1];
    if (name === "handler") {
      return "handler";
    }
    if (name === "router") {
      return "router";
    }
    // some other decorator (e.g. @functools.cache) — keep looking up the run
  }
  return "transform";
}

const IGNORED_DIRS = new Set([".venv", "node_modules", "__pycache__", ".git", ".mypy_cache", ".ruff_cache"]);

/** Recursively collect `.py` files under `root` (absolute paths), skipping vendor/cache dirs and any
 *  dotfolder. Bounded by `maxFiles` so a pathological tree can't stall the save-triggered refresh. */
function listPyFiles(root: string, maxFiles: number): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length && out.length < maxFiles) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable dir — skip, never throw out of a refresh
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!IGNORED_DIRS.has(e.name) && !e.name.startsWith(".")) {
          stack.push(full);
        }
      } else if (e.isFile() && e.name.endsWith(".py")) {
        out.push(full);
        if (out.length >= maxFiles) {
          break;
        }
      }
    }
  }
  return out;
}

export interface ScanLimits {
  /** Cap on files scanned (default 2000). */
  maxFiles?: number;
  /** Skip a single file larger than this many bytes (default 1 MiB) — a generated blob isn't a feed. */
  maxBytes?: number;
}

/**
 * Read `file` as UTF-8, or `undefined` if it is unreadable or bigger than `maxBytes`.
 *
 * The path is resolved ONCE, and the size check and the read then run against that one descriptor
 * (CodeQL js/file-system-race). The previous `statSync(path)` + `readFileSync(path)` pair was two
 * independent path lookups with a window between them, so the file that got READ need not be the file
 * that was size-CHECKED. `fstatSync(fd)` / `readFileSync(fd)` cannot disagree about which file they
 * touched — that is an IDENTITY guarantee, and it is the whole of what this buys.
 *
 * It is deliberately NOT a hard size bound. `readFileSync(fd)` re-stats the descriptor itself and
 * reads whatever length it then finds, so a file appended to in place between the `fstatSync` and the
 * read is still read in full. `maxBytes` stays what it always was — a best-effort resource guard ("a
 * generated blob isn't a feed"), never an authorization decision — and the residual is contained: the
 * cost is memory for one oversized regex pass, and `scanModuleSymbols` returns only
 * `{name, kind, file, line}`, never file content, so nothing can leak through it. Making the cap
 * sound would take a bounded `readSync` into a pre-sized buffer.
 */
function readCapped(file: string, maxBytes: number): string | undefined {
  let fd: number | undefined; // outside the try so `finally` can release it on EVERY exit path
  try {
    fd = fs.openSync(file, "r");
    if (fs.fstatSync(fd).size > maxBytes) {
      return undefined;
    }
    return fs.readFileSync(fd, "utf8");
  } catch {
    return undefined; // unreadable/vanished file — skip, never throw out of a refresh
  } finally {
    // readFileSync does NOT close a descriptor it was handed, and the oversize `return undefined` above
    // would leak one outright — `finally` runs before either return takes effect, so this covers both.
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        /* already gone — nothing left to release */
      }
    }
  }
}

/**
 * Build the symbol index by scanning every `.py` under `configDirAbs` (an ABSOLUTE path). Includes
 * `_`-prefixed modules on purpose: the wiring loader skips `_*`, but that is exactly where decomposed
 * feeds keep their `_<feed>_transforms.py` helpers, which we DO want findable. Never throws — an
 * unreadable file/dir is skipped.
 */
export function buildSymbolIndex(configDirAbs: string, limits: ScanLimits = {}): SymbolDef[] {
  const maxFiles = limits.maxFiles ?? 2000;
  const maxBytes = limits.maxBytes ?? 1024 * 1024;
  const out: SymbolDef[] = [];
  for (const f of listPyFiles(configDirAbs, maxFiles)) {
    const text = readCapped(f, maxBytes);
    if (text === undefined) {
      continue;
    }
    out.push(...scanModuleSymbols(f, text));
  }
  return out;
}

/**
 * Symbols whose name contains `filter` (case-insensitive), minus any already shown as a graph element
 * (so a handler/router that IS an element isn't listed twice — but a transform, or a handler whose
 * function name differs from its registered element name, still surfaces). Deduped by (name,file,line)
 * and sorted for a stable view. An empty/blank filter matches nothing (the section only exists while
 * searching).
 *
 * `send` rows are exempt from the exclusion, and that exemption is what makes them reachable at all.
 * The exclusion means "a handler/router that IS an element must not double-list"; a send row is a CALL
 * SITE, not the element. Its name is by definition an outbound connection name, i.e. always present in
 * `excludeNames` whenever the graph loaded — so without the carve-out every send row would be filtered
 * out and the feature would render nothing while looking built. The compiler cannot see this.
 */
export function matchSymbols(index: SymbolDef[], filter: string, excludeNames?: ReadonlySet<string>): SymbolDef[] {
  const f = filter.trim().toLowerCase();
  if (!f) {
    return [];
  }
  const seen = new Set<string>();
  const out: SymbolDef[] = [];
  for (const s of index) {
    if (!s.name.toLowerCase().includes(f)) {
      continue;
    }
    if (s.kind !== "send" && excludeNames?.has(s.name)) {
      continue;
    }
    const key = `${s.name} ${s.file} ${s.line}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(s);
  }
  out.sort((a, b) => a.name.localeCompare(b.name) || a.file.localeCompare(b.file) || a.line - b.line);
  return out;
}

// ---------------------------------------------------------------------------
// The "Definitions" search section (the rendered view-model)
// ---------------------------------------------------------------------------
// The three maps below are EXHAUSTIVE `Record<SymbolKind, …>` on purpose: widening SymbolKind cannot
// compile until every one of them has an entry for the new kind, so the type is impossible to
// half-widen. `send` reuses the outbound arrow graphModel gives outbound rows, so a call-site row
// reads as a reference to an outbound.

export const SYMBOL_ICON: Record<SymbolKind, string> = {
  handler: "symbol-method",
  router: "git-branch",
  transform: "symbol-function",
  send: "arrow-up",
};

/** The `contextValue` a Definitions row carries, i.e. which row actions VS Code renders on it.
 *
 *  A handler row gets `meforSymbolHandler`, a value of its OWN rather than graphModel's
 *  `meforElementHandler`, and the distinction is load-bearing rather than cosmetic. graphModel's
 *  vocabulary means "this row IS that graph element", and two commands are gated on it: "View as
 *  Steps", which resolves through the row's FILE, and "Show in Wiring Map", which resolves through the
 *  row's element NAME. A Definitions row is a SOURCE SYMBOL, and its name is the Python function name
 *  — `def handle`, not the registered `@handler("acme_adt_handler")`. Every sample in `samples/config/`
 *  pairs a distinct registered name with a differently-named function, so borrowing
 *  `meforElementHandler` here would render a "Show in Wiring Map" action that could only ever land on
 *  "The focused element no longer exists in the graph". Steps is the action remainder (a) asks for and
 *  the only one that resolves, so the row carries a value that gates exactly that one
 *  (`package.json` `view/item/context`, `openStepsFromNode`).
 *
 *  A `transform` deliberately gets NONE: "View as Steps" is gated on a file defining a `@handler`
 *  (see the editor/title `messagefoundry.activeFileHasHandler` clause), and a `_<feed>_transforms.py`
 *  has none, so offering Steps there would open an empty view. A `router` gets none because Steps
 *  renders Handlers, not Routers (ADR 0076), and the wiring map cannot resolve its function name. A
 *  `send` gets none because a call site is not an element. `undefined` is a no-op — the tree only
 *  assigns contextValue when it is truthy. */
export const SYMBOL_CONTEXT: Record<SymbolKind, string | undefined> = {
  handler: "meforSymbolHandler",
  router: undefined,
  transform: undefined,
  send: undefined,
};

/** The role word in a row's description. */
const SYMBOL_DESC: Record<SymbolKind, string> = {
  handler: "handler",
  router: "router",
  transform: "transform",
  send: "sends to",
};

/**
 * The "Definitions" search section: one row per matched symbol, each opening its file at the def line
 * (for a `send`, at the call site) via `messagefoundry.openSource`.
 *
 * NO row claims a graph-element identity — no `elementKind`/`elementName` — and that is deliberate,
 * because the identity these rows CAN offer is not the one every consumer of those fields resolves.
 * A row's name is the Python symbol: `def handle`, `def route`, `def xform_…`, or a `Send(…)` target.
 * The registered element name is the decorator argument (`@handler("acme_adt_handler")`), which every
 * sample in `samples/config/` deliberately makes different from the function name. So a row carrying
 * `{elementKind: "handler", elementName: "handle"}` is claiming an element that does not exist, and
 * both consumers of those fields resolve BY NAME against the loaded graph:
 * `extension.ts`'s `openWiringMap` (`fromNode` → `buildWiringMap` → `focusMissing`) and
 * `graphTree.ts`'s `findElement` (the reveal target). Withholding the fields makes `fromNode` return
 * `undefined`, so "Open Wiring Map" falls through to its element QuickPick — an honest "pick one"
 * instead of a false "the focused element no longer exists in the graph".
 *
 * Resolving the decorator argument instead is NOT the fix: `matchSymbols`' `excludeNames` would then
 * correctly drop those rows as already-shown elements, which is exactly the search hit this item
 * exists to produce.
 *
 * What a row does carry is `contextValue` (see SYMBOL_CONTEXT) and `open`. That is enough for
 * remainder (a): `openStepsFromNode` reads the row's `command.arguments[0]` — the FILE — never a name.
 */
export function definitionsSection(defs: SymbolDef[]): VmNode {
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
      description: `${SYMBOL_DESC[d.kind]} · ${path.basename(d.file)}`,
      icon: SYMBOL_ICON[d.kind],
      contextValue: SYMBOL_CONTEXT[d.kind],
      collapsible: "none",
      children: [],
      open: { file: d.file, line: d.line },
    })),
  };
}
