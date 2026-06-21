import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { capCode, COMMAND_TASKS } from "../../chat";

// Pure-function tests for the AI-context size cap (messagefoundry.ai.contextCharLimit). No editor or
// engine needed — capCode is the mechanical truncation used before any code is attached to a request.
suite("capCode", () => {
  test("passes code that fits through untouched", () => {
    const code = "def route(msg):\n    return ['H1']\n";
    const r = capCode(code, 8000);
    assert.strictEqual(r.truncated, false);
    assert.strictEqual(r.text, code);
    assert.strictEqual(r.shownChars, code.length);
    assert.strictEqual(r.totalChars, code.length);
  });

  test("truncates on a line boundary, never mid-line, and marks it", () => {
    const lines = Array.from({ length: 50 }, (_, i) => `line_${i} = ${i}`);
    const code = lines.join("\n");
    const r = capCode(code, 40);

    assert.strictEqual(r.truncated, true);
    const kept = r.text.split("\n# ")[0]; // strip the appended "# … (truncated …)" marker
    assert.ok(code.startsWith(kept), "kept text must be a prefix of the original");
    for (const ln of kept.split("\n")) {
      assert.ok(lines.includes(ln), `a partial line leaked: ${JSON.stringify(ln)}`);
    }
    assert.strictEqual(r.shownChars, kept.length);
    assert.ok(r.text.includes("truncated"), "marker present");
    assert.ok(
      r.text.includes("messagefoundry.ai.contextCharLimit"),
      "marker names the setting to raise",
    );
    assert.ok(r.text.includes(`of ${code.length} chars`), "marker reports the original size");
  });

  test("falls back to a hard cut for a single over-long line", () => {
    const code = "x".repeat(5000); // no newline anywhere in the window
    const r = capCode(code, 100);
    assert.strictEqual(r.truncated, true);
    assert.strictEqual(r.shownChars, 100);
    assert.ok(r.text.startsWith("x".repeat(100)));
  });

  test("limit 0 keeps no code", () => {
    const r = capCode("def f():\n    pass\n", 0);
    assert.strictEqual(r.shownChars, 0);
    assert.strictEqual(r.truncated, true);
  });
});

// The `/` command menu (package.json → chatParticipants) and the task-primer map (COMMAND_TASKS)
// must list the exact same commands — a command wired in only one place silently misbehaves (the
// menu shows it but it gets no task primer, or vice-versa). This guards the pairing as commands are
// added (/router, /migrate, /test, …).
suite("chat command wiring", () => {
  function packageCommandNames(): string[] {
    const pkgPath = path.join(__dirname, "..", "..", "..", "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    const participant = pkg.contributes.chatParticipants.find(
      (p: { id: string }) => p.id === "messagefoundry.chat",
    );
    return (participant.commands as { name: string }[]).map((c) => c.name);
  }

  test("the command menu and COMMAND_TASKS list the same commands", () => {
    const menu = packageCommandNames().sort();
    const tasks = Object.keys(COMMAND_TASKS).sort();
    assert.deepStrictEqual(tasks, menu, "the /command menu and COMMAND_TASKS must stay in sync");
  });

  test("the new commands are wired in both places", () => {
    const menu = new Set(packageCommandNames());
    for (const cmd of ["router", "migrate", "test"]) {
      assert.ok(COMMAND_TASKS[cmd], `COMMAND_TASKS missing /${cmd}`);
      assert.ok(menu.has(cmd), `package.json menu missing /${cmd}`);
    }
  });
});
