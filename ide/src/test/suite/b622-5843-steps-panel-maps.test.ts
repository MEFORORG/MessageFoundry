// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { StepsPanelProjection } from "../../stepsPanel";
import type { LensParseResult } from "../../stepsModel";

// BACKLOG #5843. One StepsEditorProvider serves every open Steps editor. It kept each element's message
// type and role in two provider fields that every panel's render() reassigned wholesale, so with two
// Steps editors open the HL7 picker scope and the Router purity check of one panel read the projection
// the OTHER panel rendered last. Both now live on a per-panel StepsPanelProjection.

const STEPS_VIEW_TS = path.join(__dirname, "..", "..", "..", "src", "stepsView.ts");

const routerFile: LensParseResult = {
  module: "routers.py",
  handlers: [{ handler: "route_adt", module: "routers.py", def_line: 3, rows: [], role: "router" }],
};

const handlerFile: LensParseResult = {
  module: "handlers.py",
  handlers: [
    {
      handler: "route_adt", // the same name, a different element in a different file
      module: "handlers.py",
      def_line: 5,
      rows: [],
      role: "handler",
      accepts_types: ["ORU^R01"],
      inferred_type: { code: "ORU", trigger: "R01" },
    },
  ],
};

suite("BACKLOG #5843: Steps handler roles and message types are per panel", () => {
  test("a second panel's render does not change the first panel's role or message type", () => {
    const a = new StepsPanelProjection();
    const b = new StepsPanelProjection();
    a.update(routerFile);
    b.update(handlerFile); // the other panel renders last
    assert.strictEqual(a.roleOf("route_adt"), "router", "panel A's Router stays a Router");
    assert.strictEqual(a.typeOf("route_adt")?.acceptsTypes, undefined, "panel A has no ORU scope");
    assert.strictEqual(b.roleOf("route_adt"), "handler");
    assert.deepStrictEqual(b.typeOf("route_adt")?.acceptsTypes, ["ORU^R01"]);
  });

  test("an element the projection does not know reads as a Handler, as the provider did", () => {
    const p = new StepsPanelProjection();
    assert.strictEqual(p.roleOf("nope"), "handler");
    p.update(routerFile);
    assert.strictEqual(p.roleOf("nope"), "handler");
  });

  test("update replaces the projection wholesale", () => {
    const p = new StepsPanelProjection();
    p.update(handlerFile);
    p.update(routerFile);
    assert.strictEqual(p.roleOf("route_adt"), "router");
    assert.strictEqual(p.typeOf("route_adt")?.inferredType, undefined);
  });

  test("a contract-1 payload with no role reads as a Handler", () => {
    const p = new StepsPanelProjection();
    p.update({
      module: "m.py",
      handlers: [{ handler: "h", module: "m.py", def_line: 1, rows: [] }],
    });
    assert.strictEqual(p.roleOf("h"), "handler");
  });

  // stepsView.ts imports vscode, so the provider cannot be loaded node-side; pin its wiring by scan.
  test("the provider holds no provider-wide role or message-type map", () => {
    const src = fs.readFileSync(STEPS_VIEW_TS, "utf8");
    assert.ok(
      !/this\.handler(Roles|Types)\b/.test(src),
      "stepsView.ts must not read or write a provider-wide handlerRoles/handlerTypes field",
    );
    const resolve = src.slice(src.indexOf("resolveCustomTextEditor("));
    assert.ok(
      /const panelState = new StepsPanelProjection\(\)/.test(resolve),
      "each resolved panel must own its StepsPanelProjection",
    );
    assert.ok(/panelState\.roleOf\(m\.handler\)/.test(src), "the Router check reads this panel's role");
    assert.ok(
      /scopeFor\(panelState\.typeOf\(coords\.handler\)\)/.test(src),
      "the picker scope reads this panel's message type",
    );
  });
});
