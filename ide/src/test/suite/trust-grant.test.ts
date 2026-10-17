// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// A workspace-trust grant re-runs the activation steps an untrusted workspace skipped (vault
// BACKLOG #3166). The runner is exercised vscode-free; the wiring in extension.ts is read from the
// source, because VS Code's grant event cannot be fired from a node-side test.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { runTrustGrantSteps, type TrustGrantSteps } from "../../trustGrant";

type StepName = keyof TrustGrantSteps;

function recordingSteps(ran: StepName[], fail?: { step: StepName; async: boolean }): TrustGrantSteps {
  const step = (name: StepName) => (): unknown => {
    ran.push(name);
    if (fail?.step !== name) {
      return undefined;
    }
    if (fail.async) {
      return Promise.reject(new Error(`${name} broke`));
    }
    throw new Error(`${name} broke`);
  };
  return {
    refreshViews: step("refreshViews"),
    repaintStatusBar: step("repaintStatusBar"),
    refreshEngineTrust: step("refreshEngineTrust"),
    suggestSourceControl: step("suggestSourceControl"),
  };
}

suite("trustGrant — runTrustGrantSteps", () => {
  test("every step runs exactly once, views first", () => {
    const ran: StepName[] = [];
    runTrustGrantSteps(recordingSteps(ran), () => assert.fail("no step failed"));
    assert.deepStrictEqual(ran, [
      "refreshViews",
      "repaintStatusBar",
      "refreshEngineTrust",
      "suggestSourceControl",
    ]);
  });

  test("a step that throws is reported and the steps after it still run", () => {
    const ran: StepName[] = [];
    const errors: string[] = [];
    runTrustGrantSteps(recordingSteps(ran, { step: "refreshViews", async: false }), (step, err) =>
      errors.push(`${step}: ${(err as Error).message}`),
    );
    assert.deepStrictEqual(errors, ["refreshViews: refreshViews broke"]);
    assert.strictEqual(ran.length, 4, JSON.stringify(ran));
  });

  test("a step whose promise rejects is reported, not left as an unhandled rejection", async () => {
    const ran: StepName[] = [];
    const errors: string[] = [];
    runTrustGrantSteps(recordingSteps(ran, { step: "refreshEngineTrust", async: true }), (step, err) =>
      errors.push(`${step}: ${(err as Error).message}`),
    );
    assert.strictEqual(ran.length, 4, JSON.stringify(ran));
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepStrictEqual(errors, ["refreshEngineTrust: refreshEngineTrust broke"]);
  });

  test("a rejecting thenable that is not a native Promise is reported too", async () => {
    const errors: string[] = [];
    const thenable = { then: (_ok: unknown, fail: (e: Error) => void) => fail(new Error("no")) };
    runTrustGrantSteps(
      { ...recordingSteps([]), suggestSourceControl: () => thenable },
      (step, err) => errors.push(`${step}: ${(err as Error).message}`),
    );
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepStrictEqual(errors, ["suggestSourceControl: no"]);
  });
});

suite("trustGrant — extension.ts wiring", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "extension.ts"), "utf8");

  test("the only trust-grant subscription hands every step its real callee", () => {
    const at = src.indexOf("onDidGrantWorkspaceTrust(");
    assert.ok(at >= 0, "no trust-grant subscription in extension.ts");
    assert.strictEqual(src.indexOf("onDidGrantWorkspaceTrust(", at + 1), -1, "a second subscription");
    const end = src.indexOf("engineLog().error", at);
    assert.ok(end > at, "the handler's error sink moved; re-cut this slice");
    const handler = src.slice(at, end);
    assert.match(handler, /runTrustGrantSteps\(/);
    // A step mapped to a no-op would still compile, so each is pinned to what it must call.
    for (const [step, callee] of [
      ["refreshViews", "refreshCoalescer.trigger()"],
      ["repaintStatusBar", "engineStatusBar.repaint()"],
      ["refreshEngineTrust", "refreshEngineTrustThenRecheck()"],
      ["suggestSourceControl", "maybeSuggestSourceControl(context)"],
    ]) {
      assert.ok(handler.includes(`${step}: () => ${callee}`), `${step} is not wired to ${callee}`);
    }
  });
});
