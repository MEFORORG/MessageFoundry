// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 532 remainder (BACKLOG #5404 items 1 and 2, #5409 item 1). cli.ts, sourceControl.ts and
// testBench.ts import vscode, so their wiring is pinned by reading their source on the node-side leg;
// the pure decisions they call are driven directly.
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { DEFAULT_CONTEXT_CHAR_LIMIT, contextCharLimitOf } from "../../aiPolicyModel";
import { INTERPRETER_OPTIONS } from "../../engineControlModel";
import { committedRelativePath, containedPathSetting, resolveInsideWorkspace } from "../../workspaceContainment";

const SRC = path.join(__dirname, "..", "..", "..", "src");
const ROOT = path.join(SRC, "..");

/** `src` with its comments stripped, so a comment cannot satisfy or defeat a scan. String and
 *  template literals are matched first and kept. */
function stripComments(src: string): string {
  return src.replace(
    /("(?:\\[\s\S]|[^"\\\n])*"|'(?:\\[\s\S]|[^'\\\n])*'|`(?:\\[\s\S]|[^`\\])*`)|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,
    (m, literal: string | undefined) => literal ?? "",
  );
}

function code(file: string): string {
  return stripComments(fs.readFileSync(path.join(SRC, file), "utf8")).replace(/\r\n/g, "\n");
}

/** The text of the function or method `head` opens, up to the closing brace at its own indent. */
function body(src: string, head: string): string {
  const start = src.indexOf(head);
  assert.ok(start >= 0, `${head} not found`);
  const lineStart = src.lastIndexOf("\n", start) + 1;
  const indent = /^[ ]*/.exec(src.slice(lineStart))?.[0] ?? "";
  const end = src.indexOf(`\n${indent}}\n`, start);
  assert.ok(end > start, `end of ${head} not found`);
  return src.slice(start, end);
}

suite("b532r: a workspace may only lower ai.contextCharLimit (BACKLOG #5404 item 2)", () => {
  test("a workspace value above the user's is ignored, one below it applies", () => {
    assert.strictEqual(contextCharLimitOf({ defaultValue: 8000, globalValue: 2000, workspaceValue: 1_000_000 }), 2000);
    assert.strictEqual(contextCharLimitOf({ defaultValue: 8000, globalValue: 2000, workspaceValue: 500 }), 500);
    assert.strictEqual(contextCharLimitOf({ defaultValue: 8000, workspaceValue: 0 }), 0);
  });

  test("with no user value the default is the ceiling", () => {
    assert.strictEqual(contextCharLimitOf({ defaultValue: 8000, workspaceValue: 50_000 }), 8000);
    assert.strictEqual(contextCharLimitOf({ workspaceValue: 50_000 }), DEFAULT_CONTEXT_CHAR_LIMIT);
    assert.strictEqual(contextCharLimitOf(undefined), DEFAULT_CONTEXT_CHAR_LIMIT);
  });

  test("the user may raise their own bound; an invalid value at any scope is ignored", () => {
    assert.strictEqual(contextCharLimitOf({ defaultValue: 8000, globalValue: 20_000 }), 20_000);
    assert.strictEqual(contextCharLimitOf({ defaultValue: 8000, globalValue: 1000, workspaceValue: "x" }), 1000);
    assert.strictEqual(contextCharLimitOf({ defaultValue: 8000, globalValue: -5, workspaceValue: Infinity }), 8000);
    assert.strictEqual(contextCharLimitOf({ defaultValue: 8000, globalValue: 1234.9 }), 1234);
  });

  test("cli.ts reads the setting's scopes through contextCharLimitOf, not a merged get", () => {
    const fn = body(code("cli.ts"), "export function aiContextCharLimit(");
    assert.ok(fn.includes('contextCharLimitOf(config().inspect("ai.contextCharLimit"))'), fn);
    assert.ok(!/\.get\s*</.test(fn) && !fn.includes(".get("), fn);
  });

  test("the setting stays out of restrictedConfigurations, which would drop a tightening value", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
      capabilities: { untrustedWorkspaces: { restrictedConfigurations: string[] } };
    };
    assert.ok(
      !pkg.capabilities.untrustedWorkspaces.restrictedConfigurations.includes("messagefoundry.ai.contextCharLimit"),
    );
  });
});

suite("b532r: writers check the real path of a path setting (BACKLOG #5404 item 1)", () => {
  test("writerSetting refuses a link escape after the spelling check", () => {
    const cli = code("cli.ts");
    const writer = body(cli, "function writerSetting(");
    assert.ok(/if \(escapesByLink\(workspaceDir\(\), s\.value\)\)/.test(writer), writer);
    assert.ok(writer.includes("linkEscapeRefusal(key)"), writer);
    assert.ok(writer.indexOf("s.dropped !== false") < writer.indexOf("escapesByLink"), writer);
    const escapes = body(cli, "function escapesByLink(");
    // The spelling test runs first, with no I/O, so a path spelled outside the folder is never opened.
    assert.ok(escapes.indexOf("committedRelativePath(ws, value)") < escapes.indexOf("resolveInsideWorkspace"), escapes);
    assert.ok(escapes.includes("resolveInsideWorkspace(ws, value) === undefined"), escapes);
    // writerPathSetting and writerConfigTarget both go through writerSetting.
    assert.ok(body(cli, "export function writerPathSetting(").includes("writerSetting(key)"));
    assert.ok(body(cli, "export function writerConfigTarget(").includes('writerSetting("serviceConfig")'));
  });

  test("a junction inside the folder passes the spelling check and fails the real-path one", function () {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "b532r-ide-"));
    try {
      const ws = path.join(base, "ws");
      const outside = path.join(base, "outside");
      fs.mkdirSync(ws);
      fs.mkdirSync(outside);
      try {
        fs.symlinkSync(outside, path.join(ws, "cfg"), "junction");
      } catch {
        this.skip(); // a platform where no link can be made here
      }
      // Control: the reader's containment, which compares spellings, accepts the link.
      assert.strictEqual(containedPathSetting({ workspaceValue: "cfg" }, ws, "d").dropped, false);
      assert.notStrictEqual(committedRelativePath(ws, "cfg"), undefined);
      // The check escapesByLink makes refuses it, and a missing file under it too.
      assert.strictEqual(resolveInsideWorkspace(ws, "cfg"), undefined);
      assert.strictEqual(resolveInsideWorkspace(ws, "cfg/new.toml"), undefined);
      // A plain folder and a missing file inside the folder still pass.
      fs.mkdirSync(path.join(ws, "plain"));
      assert.strictEqual(resolveInsideWorkspace(ws, "plain"), path.join(ws, "plain"));
      assert.strictEqual(resolveInsideWorkspace(ws, "messagefoundry.toml"), path.join(ws, "messagefoundry.toml"));
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });
});

suite("b532r: sameDir does not block the extension host (BACKLOG #5404 item 1)", () => {
  const sc = code("sourceControl.ts");

  test("sameDir is asynchronous, makes no synchronous realpath call, and skips I/O on a UNC spelling", () => {
    const fn = body(sc, "async function sameDir(");
    assert.ok(!fn.includes("realpathSync"), fn);
    assert.ok(fn.includes("fs.promises.realpath("), fn);
    assert.ok(fn.indexOf("isUncSpelling(") < fn.indexOf("fs.promises.realpath("), fn);
    assert.ok(!sc.includes("realpathSync"), "no synchronous realpath anywhere in sourceControl.ts");
  });

  test("every call site awaits it", () => {
    const calls = sc.match(/sameDir\(/g) ?? [];
    const awaited = sc.match(/await sameDir\(/g) ?? [];
    // One extra match is the declaration.
    assert.strictEqual(awaited.length, calls.length - 1, sc);
    assert.ok(awaited.length >= 2);
  });
});

suite("b532r: the Test Bench debug launch takes -P (BACKLOG #5409 item 1)", () => {
  test("debugRow passes the CLI bridge's interpreter options to debugpy", () => {
    const fn = body(code("testBench.ts"), "private async debugRow(");
    assert.ok(fn.includes('type: "debugpy"'), fn);
    assert.ok(fn.includes("pythonArgs: [...INTERPRETER_OPTIONS]"), fn);
    assert.ok(INTERPRETER_OPTIONS.includes("-P"));
  });
});
