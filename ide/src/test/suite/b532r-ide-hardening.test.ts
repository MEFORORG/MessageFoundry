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
import {
  containedPathSetting,
  escapesByLink,
  hasTrailingDotOrSpaceName,
  linkEscapeRefusal,
  resolveInsideWorkspace,
} from "../../workspaceContainment";

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

/** The manifest default of the setting `key`. */
function pkgDefault(key: string): unknown {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
    contributes: { configuration: { properties: Record<string, { default?: unknown }> } };
  };
  return manifest.contributes.configuration.properties[key]?.default;
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

  const pkg = (): {
    capabilities: { untrustedWorkspaces: { restrictedConfigurations: string[] } };
    contributes: { configuration: { properties: Record<string, { default?: unknown }> } };
  } => JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

  test("the setting stays out of restrictedConfigurations, which would drop a tightening value", () => {
    assert.ok(
      !pkg().capabilities.untrustedWorkspaces.restrictedConfigurations.includes("messagefoundry.ai.contextCharLimit"),
    );
  });

  test("the chat's advice to raise the limit names user settings and the workspace's lower-only rule", () => {
    const fn = body(code("chat.ts"), "export function capCode(");
    assert.ok(fn.includes("raise messagefoundry.ai.contextCharLimit in user settings"), fn);
    assert.ok(fn.includes("remove any lower workspace value"), fn);
    const handler = body(code("chat.ts"), "export function registerChat(");
    assert.ok(handler.includes("`messagefoundry.ai.contextCharLimit` in user settings"), handler);
    assert.ok(handler.includes("can only lower the limit"), handler);
  });

  test("the fallback default is the manifest's default", () => {
    const prop = pkg().contributes.configuration.properties["messagefoundry.ai.contextCharLimit"];
    assert.strictEqual(prop.default, DEFAULT_CONTEXT_CHAR_LIMIT);
  });
});

suite("b532r: writers check the real path of a path setting (BACKLOG #5404 item 1)", () => {
  test("writerSetting refuses a link escape after the spelling check, in a trusted window only", () => {
    const cli = code("cli.ts");
    const writer = body(cli, "function writerSetting(");
    // Only a trusted window reads a real path, so an untrusted one touches no file before its refusal.
    assert.ok(writer.includes("if (!isExecGated() && escapesByLink(workspaceDir(), checked))"), writer);
    assert.ok(writer.includes("linkEscapeRefusal(key, blank ? checked : undefined)"), writer);
    assert.ok(writer.indexOf("s.dropped !== false") < writer.indexOf("escapesByLink"), writer);
    // The predicate is the shared one, driven below; cli.ts keeps no copy of it.
    assert.ok(!cli.includes("function escapesByLink("), "cli.ts defines its own escapesByLink");
    // writerPathSetting and writerConfigTarget both go through writerSetting.
    assert.ok(body(cli, "export function writerPathSetting(").includes("writerSetting(key)"));
    assert.ok(body(cli, "export function writerConfigTarget(").includes('writerSetting("serviceConfig")'));
  });

  /** A temporary workspace folder `ws` beside a folder `outside`, removed after `fn`. */
  function withWorkspace(fn: (ws: string, outside: string) => void): void {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "b532r-ide-"));
    try {
      const ws = path.join(base, "ws");
      const outside = path.join(base, "outside");
      fs.mkdirSync(ws);
      fs.mkdirSync(outside);
      fn(ws, outside);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  }

  /** Links `at` to `target` as a junction (a directory symlink off Windows), or skips the test. */
  function link(ctx: Mocha.Context, target: string, at: string): void {
    try {
      fs.symlinkSync(target, at, "junction");
    } catch {
      ctx.skip(); // a platform where no link can be made here
    }
  }

  test("a junction inside the folder passes the spelling check and is refused", function () {
    withWorkspace((ws, outside) => {
      link(this, outside, path.join(ws, "cfg"));
      // Control: the reader's containment, which compares spellings, accepts the link.
      assert.strictEqual(containedPathSetting({ workspaceValue: "cfg" }, ws, "d").dropped, false);
      assert.strictEqual(escapesByLink(ws, "cfg"), true);
      assert.strictEqual(escapesByLink(ws, "cfg/new.toml"), true);
      // A plain folder, a missing file inside the folder and the folder itself still pass.
      fs.mkdirSync(path.join(ws, "plain"));
      assert.strictEqual(escapesByLink(ws, "plain"), false);
      assert.strictEqual(escapesByLink(ws, "plain/new.toml"), false);
      assert.strictEqual(escapesByLink(ws, "messagefoundry.toml"), false);
      assert.strictEqual(escapesByLink(ws, "."), false);
    });
  });

  test("on Windows, the CLI would follow a junction through `cfg.`, which the real-path check passes", function () {
    if (process.platform !== "win32") {
      this.skip(); // the control needs Windows path handling; the refusal itself is driven below
    }
    withWorkspace((ws, outside) => {
      link(this, outside, path.join(ws, "cfg"));
      // THE CONTROL: Node reads `cfg.` as written, finds nothing and walks up to the folder, so the
      // real-path check alone passes the name the CLI's Win32 open would follow through `cfg`.
      assert.notStrictEqual(resolveInsideWorkspace(ws, "cfg."), undefined);
      assert.strictEqual(escapesByLink(ws, "cfg."), true);
    });
  });

  /** Runs `fn` with the synchronous file-system reads workspaceContainment makes replaced by spies that
   *  record the call and throw, and returns what was recorded. */
  function fsCalls(fn: () => void): string[] {
    const mod: Record<string, unknown> = require("node:fs");
    const names = ["realpathSync", "lstatSync", "statSync", "existsSync"];
    const originals = names.map((n) => mod[n]);
    const calls: string[] = [];
    for (const n of names) {
      const spy = (p: unknown): never => {
        calls.push(`${n} ${String(p)}`);
        throw Object.assign(new Error(`stubbed ${n}`), { code: "EACCES" });
      };
      mod[n] = Object.assign(spy, { native: spy });
    }
    try {
      fn();
    } finally {
      names.forEach((n, i) => (mod[n] = originals[i]));
    }
    return calls;
  }

  test("a name ending in a dot or a space and a '..' are refused before any file-system call", () => {
    const ws = path.resolve(path.sep, "b532r-ide-no-such-ws");
    const refused = [
      ["cfg.", true],
      ["cfg ", true],
      ["cfg./new.toml", true],
      ["messagefoundry.toml.", true],
      ["messagefoundry.toml ", true],
      ["a. /b", true],
      ["plain/../x", false],
      ["plain\\..\\x", true],
    ] as const;
    for (const [v, win32] of refused) {
      let answer: boolean | undefined;
      const calls = fsCalls(() => (answer = escapesByLink(ws, v, win32)));
      assert.strictEqual(answer, true, JSON.stringify(v));
      assert.deepStrictEqual(calls, [], `${JSON.stringify(v)} touched the file system`);
    }
    // THE CONTROL: a plain name goes on to the real-path read, which the spies refuse.
    let plain: boolean | undefined;
    const calls = fsCalls(() => (plain = escapesByLink(ws, "messagefoundry.toml", true)));
    assert.strictEqual(plain, true);
    assert.notDeepStrictEqual(calls, []);
  });

  test("off Windows those names are names, and the folder itself is not refused by spelling", () => {
    withWorkspace((ws) => {
      for (const v of ["messagefoundry.toml.", "cfg "]) {
        assert.strictEqual(escapesByLink(ws, v, false), false, JSON.stringify(v));
      }
      assert.strictEqual(escapesByLink(ws, "messagefoundry.toml", true), false);
      assert.strictEqual(escapesByLink(ws, "./messagefoundry.toml", true), false);
      assert.strictEqual(escapesByLink(ws, ".", true), false);
      assert.strictEqual(escapesByLink(ws, "..conf"), false);
    });
  });

  test("a value spelled outside the folder, or no folder open, is not checked", () => {
    // The operator's own user value may point anywhere. The spies refuse every read, so a false
    // answer means no read was made.
    const ws = path.resolve(path.sep, "b532r-ide-no-such-ws");
    for (const v of [path.resolve(path.sep, "b532r-ide-elsewhere", "cfg."), "../away"]) {
      let answer: boolean | undefined;
      const calls = fsCalls(() => (answer = escapesByLink(ws, v, true)));
      assert.strictEqual(answer, false, JSON.stringify(v));
      assert.deepStrictEqual(calls, []);
    }
    assert.strictEqual(escapesByLink(undefined, "cfg"), false);
  });

  test("hasTrailingDotOrSpaceName reads every component, on Windows only", () => {
    assert.strictEqual(hasTrailingDotOrSpaceName("a.\\b", true), true);
    assert.strictEqual(hasTrailingDotOrSpaceName("a/b ", true), true);
    assert.strictEqual(hasTrailingDotOrSpaceName(".", true), false);
    assert.strictEqual(hasTrailingDotOrSpaceName("./a", true), false);
    assert.strictEqual(hasTrailingDotOrSpaceName("a/.b/c.toml", true), false);
    assert.strictEqual(hasTrailingDotOrSpaceName("a./b", false), false);
  });

  test("a blank serviceConfig has the CLI's own fallback file checked, and named", () => {
    const fn = body(code("cli.ts"), "function writerSetting(");
    assert.ok(fn.includes('const blank = key === "serviceConfig" && s.value.trim() === ""'), fn);
    assert.ok(fn.includes("const checked = blank ? PATH_FALLBACK.serviceConfig : s.value"), fn);
    assert.ok(fn.includes("if (!isExecGated() && escapesByLink(workspaceDir(), checked))"), fn);
    assert.ok(fn.includes("linkEscapeRefusal(key, blank ? checked : undefined)"), fn);
    const text = linkEscapeRefusal("serviceConfig", "messagefoundry.toml");
    assert.ok(text.includes("serviceConfig is blank, so the CLI opens messagefoundry.toml, a path inside"), text);
    assert.strictEqual(
      pkgDefault("messagefoundry.serviceConfig"),
      "messagefoundry.toml",
      "the manifest default is the file the CLI falls back to",
    );
  });

  test("the refusal's remedy names a fix every writer accepts first, and the two that decline the other", () => {
    const text = linkEscapeRefusal("configDir");
    assert.ok(text.includes("messagefoundry.configDir names a path inside"), text);
    assert.ok(text.includes("ends in a dot or a space, or its real path cannot be read"), text);
    assert.ok(text.includes("make the workspace folder readable"), text);
    const plain = text.indexOf("so the path is a plain folder or file inside the workspace folder.");
    const absolute = text.indexOf("absolute path in user settings");
    assert.ok(plain > 0 && absolute > plain, text);
    // The New Route wizard refuses an absolute path outside the folder, and version-control setup
    // commits no hook for one, so the second remedy names both.
    assert.ok(text.includes("Commands other than New Route and the commit hook"), text);
  });
});

suite("b532r: sameDir does not block the extension host (BACKLOG #5404 item 1)", () => {
  const sc = code("sourceControl.ts");

  test("sameDir is asynchronous, makes no synchronous realpath call, and skips I/O on a UNC spelling", () => {
    const fn = body(sc, "async function sameDir(");
    assert.ok(!fn.includes("realpathSync"), fn);
    assert.ok(fn.includes("fs.promises.realpath("), fn);
    // The repository's side, spelled as a share, is compared by spelling and never opened.
    assert.ok(fn.includes("isUncSpelling(spelledTheirs) ? Promise.resolve(fold(spelledTheirs)) : real(spelledTheirs)"), fn);
    assert.ok(!sc.includes("realpathSync"), "no synchronous realpath anywhere in sourceControl.ts");
  });

  test("every call site awaits it, with the extension's own path first", () => {
    const calls = sc.match(/sameDir\(/g) ?? [];
    const awaited = sc.match(/await sameDir\(/g) ?? [];
    // One extra match is the declaration.
    assert.strictEqual(awaited.length, calls.length - 1, sc);
    assert.ok(sc.includes("await sameDir(ws, topDir)"), sc);
    assert.ok(sc.includes("await sameDir(path.join(ws, HOOKS_DIR), path.resolve(topDir, current))"), sc);
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
