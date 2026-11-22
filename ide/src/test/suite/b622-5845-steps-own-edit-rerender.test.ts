// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { EditLoopGuard, drainEdits, type EditMessage } from "../../stepsModel";

// BACKLOG #5845. The Steps provider's onDidChangeTextDocument listener asked the update-loop guard
// BEFORE its panel-focus check. A param edit typed in the webview applies its WorkspaceEdit while the
// edit slot is held, so the provider's OWN edit was noted as a suppressed change, and releaseEdit then
// paid that debt as a full re-render after every edit: the webview HTML was replaced and focus and any
// half-typed input were lost. The focus check now runs first.

const STEPS_VIEW_TS = path.join(__dirname, "..", "..", "..", "src", "stepsView.ts");

const EDIT: EditMessage = {
  command: "edit",
  handler: "h",
  lineStart: 3,
  lineEnd: 3,
  name: "value",
  value: "X",
  expectSrc: 'set_field(msg, "PID-5", "Y")',
};

/** The listener body as stepsView.ts runs it, after the uri and zero-change returns. */
function onChange(guard: EditLoopGuard, panelActive: boolean, scheduleRowsOnly: () => void): void {
  if (panelActive) {
    return;
  }
  if (!guard.shouldReactToDocumentChange()) {
    guard.noteSuppressedChange();
    return;
  }
  scheduleRowsOnly();
}

/** Drive one typed edit whose apply fires the document change, as vscode.workspace.applyEdit does. */
async function typedEdit(panelActive: boolean): Promise<{ owed: number; rowsOnly: number }> {
  const guard = new EditLoopGuard();
  let owed = 0;
  let rowsOnly = 0;
  await drainEdits(
    guard,
    EDIT,
    async () => {
      onChange(guard, panelActive, () => rowsOnly++);
    },
    undefined,
    () => owed++,
  );
  return { owed, rowsOnly };
}

suite("BACKLOG #5845: the provider's own edit does not force a Steps re-render", () => {
  test("an edit typed in the focused webview owes no re-projection", async () => {
    assert.deepStrictEqual(await typedEdit(true), { owed: 0, rowsOnly: 0 });
  });

  test("a change that races a rewrite while the webview is not focused is still deferred", async () => {
    assert.deepStrictEqual(await typedEdit(false), { owed: 1, rowsOnly: 0 });
  });

  test("a change with the slot free and the webview unfocused re-projects rows only", () => {
    let rowsOnly = 0;
    const guard = new EditLoopGuard();
    onChange(guard, false, () => rowsOnly++);
    assert.strictEqual(rowsOnly, 1);
    assert.strictEqual(guard.hasSuppressedChange, false);
  });

  // stepsView.ts imports vscode, so the provider cannot be loaded node-side; pin the order by scan.
  test("stepsView.ts checks panel focus before it notes a suppressed change", () => {
    const text = fs.readFileSync(STEPS_VIEW_TS, "utf8");
    const at = text.indexOf("onDidChangeTextDocument(");
    assert.ok(at >= 0, "stepsView.ts no longer subscribes to document change");
    const body = text.slice(at, text.indexOf("panel.onDidDispose", at));
    const focus = body.indexOf("if (panel.active)");
    const note = body.indexOf("guard.noteSuppressedChange()");
    assert.ok(focus >= 0 && note >= 0, `the change handler lost a check; handler was:\n${body}`);
    assert.ok(
      focus < note,
      `the focus check must run before the guard records the provider's own edit as owed; handler was:\n${body}`,
    );
  });
});
