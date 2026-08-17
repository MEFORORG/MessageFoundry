// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";
import * as fs from "node:fs";
import * as path from "node:path";

import { definitionsSection, SYMBOL_ICON, type SymbolDef, type SymbolKind } from "../../symbolIndex";
import { type VmNode } from "../../graphModel";

// BACKLOG #228 remainder (a): a Definitions hit must open straight into the Steps view. The claim under
// test is "the inline **View as Steps** action RENDERS on a handler Definitions row" — NOT "the row has
// some contextValue string". Those are different sentences, so this file evaluates the REAL
// package.json `view/item/context` `when` clauses against each row's contextValue and asserts on which
// commands come out. Node-side (no vscode import), so it runs on every ide CI leg — not only the
// Windows-only Extension Host leg.

const PACKAGE_JSON = path.join(__dirname, "..", "..", "..", "package.json");

interface MenuEntry {
  command: string;
  when: string;
}

function contextMenus(): MenuEntry[] {
  const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, "utf8")) as {
    contributes: { menus: Record<string, MenuEntry[]> };
  };
  return pkg.contributes.menus["view/item/context"];
}

interface WhenCtx {
  view: string;
  viewItem: string;
}

/** Split on `op` at paren depth 0. */
function splitTop(clause: string, op: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < clause.length; i++) {
    const c = clause[i];
    if (c === "(") {
      depth++;
    } else if (c === ")") {
      depth--;
    } else if (depth === 0 && clause.startsWith(op, i)) {
      parts.push(clause.slice(start, i));
      i += op.length - 1;
      start = i + 1;
    }
  }
  parts.push(clause.slice(start));
  return parts;
}

function evalTerm(text: string, ctx: WhenCtx): boolean {
  const m = /^([A-Za-z][\w.]*)\s*==\s*([\w.]+)$/.exec(text.trim());
  if (!m) {
    throw new Error(`unsupported when-term: ${JSON.stringify(text)}`);
  }
  if (m[1] === "view") {
    return ctx.view === m[2];
  }
  if (m[1] === "viewItem") {
    return ctx.viewItem === m[2];
  }
  throw new Error(`unsupported when-key: ${m[1]}`);
}

/**
 * Evaluate the subset of the VS Code `when` grammar this manifest actually uses: `key == value` terms,
 * `&&` conjunction, and a parenthesized `||` disjunction of terms.
 *
 * ANYTHING ELSE THROWS, deliberately. `false` is precisely the answer these tests measure ("the menu
 * item does not render"), so an evaluator that quietly returned `false` for a clause it did not
 * understand could only ever confirm the answer it was asked for. If package.json later adopts a richer
 * grammar this fails LOUDLY and the evaluator gets extended — the correct failure direction.
 */
export function evalWhen(clause: string, ctx: WhenCtx): boolean {
  return splitTop(clause, "&&").every((part) => {
    const p = part.trim();
    if (p.startsWith("(") && p.endsWith(")")) {
      const inner = p.slice(1, -1);
      if (inner.includes("(") || inner.includes(")")) {
        throw new Error(`unsupported nested when-group: ${JSON.stringify(p)}`);
      }
      return splitTop(inner, "||").some((t) => evalTerm(t, ctx));
    }
    return evalTerm(p, ctx);
  });
}

/** The commands VS Code would render on a graph row carrying `viewItem`. */
function renderedOn(viewItem: string | undefined): string[] {
  const ctx: WhenCtx = { view: "messagefoundry.graph", viewItem: viewItem ?? "" };
  return contextMenus()
    .filter((m) => evalWhen(m.when, ctx))
    .map((m) => m.command);
}

const FIXTURE: SymbolDef[] = [
  { name: "handle_acme_mfn", kind: "handler", file: "/c/IB_FILE_ACME_MFN.py", line: 9 },
  { name: "route_acme", kind: "router", file: "/c/IB_FILE_ACME_MFN.py", line: 4 },
  { name: "xform_acme_to_premier", kind: "transform", file: "/c/_acme_transforms.py", line: 12 },
  { name: "OB_ACME_ADT", kind: "send", file: "/c/IB_FILE_ACME_MFN.py", line: 29 },
];

const rows = definitionsSection(FIXTURE).children;
const row = (label: string): VmNode => {
  const r = rows.find((c) => c.label === label);
  assert.ok(r, `fixture row '${label}' is missing — every assertion below would be vacuous`);
  return r;
};

suite("Definitions section — the row actions VS Code renders (#228 remainder (a))", () => {
  test("the manifest really carries the menu contract under test", () => {
    // Anti-vacuity: a scan that found nothing passes a `filter(...).includes(...)` check exactly like a
    // correct one, so prove the haystack exists before measuring the needle.
    const menus = contextMenus();
    assert.ok(Array.isArray(menus) && menus.length > 0, "view/item/context is empty — nothing to evaluate");
    assert.ok(
      menus.some((m) => m.command === "messagefoundry.openStepsFromNode"),
      "no openStepsFromNode entry in the real manifest — the render assertions would be unfalsifiable",
    );
    console.log(`  [when-eval] scanned ${menus.length} view/item/context entries from ${PACKAGE_JSON}`);
  });

  test("a HANDLER row renders 'View as Steps'", () => {
    // Also exercises the evaluator's parenthesized `||` branch, and does so on the SECOND disjunct, so
    // the OR grammar is proven rather than assumed.
    assert.strictEqual(row("handle_acme_mfn").contextValue, "meforSymbolHandler");
    assert.ok(
      renderedOn(row("handle_acme_mfn").contextValue).includes("messagefoundry.openStepsFromNode"),
      "a Definitions handler hit must open straight into the Steps view",
    );
  });

  test("a TRANSFORM row does NOT render 'View as Steps'", () => {
    // A `_<feed>_transforms.py` defines no @handler, so openSteps would render an empty Steps view.
    assert.deepStrictEqual(row("xform_acme_to_premier").contextValue, undefined);
    assert.ok(!renderedOn(row("xform_acme_to_premier").contextValue).includes("messagefoundry.openStepsFromNode"));
  });

  test("a ROUTER row renders NOTHING — Steps renders Handlers, and the wiring map cannot resolve it", () => {
    assert.deepStrictEqual(row("route_acme").contextValue, undefined);
    assert.deepStrictEqual(renderedOn(row("route_acme").contextValue), [], "only Handlers render as Steps");
  });

  // THE regression pin for the defect this section was first built with. Borrowing graphModel's
  // `meforElement`/`meforElementHandler` made "Show in Wiring Map" render on handler and router rows,
  // where it can only ever land on "The focused element no longer exists in the graph": the row's name
  // is the FUNCTION name (`def handle`) and the graph is keyed by the registered decorator name
  // (`@handler("acme_adt_handler")`), which every sample deliberately makes different. Asserting the
  // ABSENCE across every row means a future contextValue change cannot quietly re-open it.
  test("NO Definitions row renders 'Show in Wiring Map' — its name is a symbol, not an element name", () => {
    for (const r of rows) {
      assert.ok(
        !renderedOn(r.contextValue).includes("messagefoundry.showInWiringMap"),
        `row '${r.label}' (contextValue ${JSON.stringify(r.contextValue)}) offers a wiring-map focus it cannot resolve`,
      );
    }
  });

  test("the wiring-map menu contract this row shape avoids really exists", () => {
    // Anti-vacuity for the test above: prove the manifest DOES gate showInWiringMap on the element
    // vocabulary, so "absent" is a measured outcome and not a menu that was never contributed.
    assert.ok(
      contextMenus().some(
        (m) => m.command === "messagefoundry.showInWiringMap" && m.when.includes("meforElementHandler"),
      ),
      "no meforElementHandler-gated showInWiringMap entry — the absence assertions would be unfalsifiable",
    );
    assert.ok(
      renderedOn("meforElementHandler").includes("messagefoundry.showInWiringMap"),
      "a real graph handler row must still render it — the fix must not have disabled the action itself",
    );
  });

  test("the when-evaluator throws on a clause it does not understand", () => {
    // If it returned false instead, "does not render" would be indistinguishable from "not parsed" —
    // and "does not render" is the measurement two tests above depend on.
    assert.throws(
      () => evalWhen("view == messagefoundry.graph && !listMultiSelection", { view: "messagefoundry.graph", viewItem: "x" }),
      /unsupported when-term/,
    );
  });
});

suite("Definitions section — row shape", () => {
  test("a SEND row points at the CALL SITE, not at the outbound's own definition", () => {
    // The row is the line that addresses the connection — a different file and line from the outbound
    // element row the graph view already renders, which is why it is exempt from excludeNames without
    // double-listing anything.
    const send = row("OB_ACME_ADT");
    assert.strictEqual(send.description, "sends to · IB_FILE_ACME_MFN.py");
    assert.strictEqual(send.icon, "arrow-up", "reads as a reference to an outbound");
    assert.deepStrictEqual(send.open, { file: "/c/IB_FILE_ACME_MFN.py", line: 29 });
  });

  test("NO row claims a graph-element identity — not even a handler or router", () => {
    // extension.ts's openWiringMap (fromNode) and graphTree's findElement both resolve these two fields
    // BY NAME against the loaded graph. A Definitions row's name is the Python function name, so any
    // value here is a claim on an element that does not exist. Withholding them makes fromNode return
    // undefined, which falls through to the element QuickPick instead of a false "no longer exists".
    for (const r of rows) {
      assert.strictEqual(r.elementKind, undefined, `row '${r.label}' claims an elementKind`);
      assert.strictEqual(r.elementName, undefined, `row '${r.label}' claims an elementName`);
    }
  });

  test("a HANDLER row still opens its definition, and reads as a handler", () => {
    const h = row("handle_acme_mfn");
    assert.deepStrictEqual(h.open, { file: "/c/IB_FILE_ACME_MFN.py", line: 9 });
    assert.strictEqual(h.description, "handler · IB_FILE_ACME_MFN.py");
    assert.strictEqual(h.icon, "symbol-method");
  });

  test("every SymbolKind in the fixture resolves to a non-empty icon", () => {
    const kinds = new Set<SymbolKind>(FIXTURE.map((d) => d.kind));
    assert.strictEqual(kinds.size, 4, "the fixture must cover all four kinds or this canary is partial");
    for (const k of kinds) {
      assert.ok(SYMBOL_ICON[k], `SymbolKind '${k}' has no icon — a widened kind would render blank`);
    }
  });
});
