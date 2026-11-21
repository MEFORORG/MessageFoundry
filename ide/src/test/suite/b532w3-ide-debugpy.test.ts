// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 532 wave 3 (BACKLOG #5409 item 2): the Test Bench Debug launch keeps the workspace off the
// import path on every debugpy build. debugpy 1.8.21 and older insert the working directory into
// `sys.path` when they run a MODULE, whatever `-P` says (debugpy commit 7959635126, first released
// in 1.8.22, added the `safe_path` check), so the launch hands debugpy a PROGRAM the extension
// writes into its own storage folder, for which those builds add only that folder. testBench.ts
// imports vscode, so its wiring is pinned by reading its source; the program itself is run under a
// stand-in for both debugpy 1.8.21 runners.
import * as assert from "assert";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { INTERPRETER_OPTIONS, TEST_BENCH_DEBUG_PROGRAM } from "../../engineControlModel";

const SRC = path.join(__dirname, "..", "..", "..", "src");

/** `src` with its comments stripped, so a comment cannot satisfy or defeat a scan. String and
 *  template literals are matched first and kept. */
function stripComments(src: string): string {
  return src.replace(
    /("(?:\\[\s\S]|[^"\\\n])*"|'(?:\\[\s\S]|[^'\\\n])*'|`(?:\\[\s\S]|[^`\\])*`)|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,
    (m, literal: string | undefined) => literal ?? "",
  );
}

/** The text of the method `head` opens, up to the closing brace at its own indent. */
function body(src: string, head: string): string {
  const start = src.indexOf(head);
  assert.ok(start >= 0, `${head} not found`);
  const lineStart = src.lastIndexOf("\n", start) + 1;
  const indent = /^[ ]*/.exec(src.slice(lineStart))?.[0] ?? "";
  const end = src.indexOf(`\n${indent}}\n`, start);
  assert.ok(end > start, `end of ${head} not found`);
  return src.slice(start, end);
}

function testBench(): string {
  return stripComments(fs.readFileSync(path.join(SRC, "testBench.ts"), "utf8")).replace(/\r\n/g, "\n");
}

/** debugpy 1.8.21's `run_module` (src/debugpy/server/cli.py at tag v1.8.21), reduced to its
 *  sys.path step and the run: it inserts "" with no check of `sys.flags.safe_path`. */
const OLD_RUN_MODULE = [
  "import runpy, sys",
  "sys.argv = ['messagefoundry'] + sys.argv[1:]",
  'sys.path.insert(0, "")',
  "runpy.run_module('messagefoundry', run_name='__main__', alter_sys=True)",
].join("\n");

/** debugpy 1.8.21's `run_file`, reduced the same way: it inserts the target file's folder. */
const OLD_RUN_FILE = [
  "import os, runpy, sys",
  "target = sys.argv[1]",
  "sys.argv = sys.argv[1:]",
  "if os.path.isfile(target):",
  "    sys.path.insert(0, os.path.dirname(target))",
  "runpy.run_path(target, run_name='__main__')",
].join("\n");

/** A Python 3.11 or later on PATH, which `-P` needs, or undefined. */
function python(): string | undefined {
  for (const exe of process.platform === "win32" ? ["python", "py"] : ["python3", "python"]) {
    const r = spawnSync(exe, ["-c", "import sys; print(sys.version_info >= (3, 11))"], { encoding: "utf8" });
    if (r.status === 0 && r.stdout.trim() === "True") {
      return exe;
    }
  }
  return undefined;
}

suite("b532w3: the Test Bench Debug launch keeps -P on every debugpy build (BACKLOG #5409 item 2)", () => {
  test("debugRow hands debugpy the written program, not the module, and keeps the interpreter options", () => {
    const fn = body(testBench(), "private async debugRow(");
    assert.ok(fn.includes('type: "debugpy"'), fn);
    assert.ok(fn.includes("pythonArgs: [...INTERPRETER_OPTIONS]"), fn);
    assert.ok(fn.includes("program = await this.debugProgram()"), fn);
    assert.ok(/\n\s*program,\n/.test(fn), fn);
    assert.ok(!/\bmodule\s*:/.test(fn), `debugRow still names a module: ${fn}`);
    // A failed write refuses the launch rather than falling back to the module form.
    assert.ok(fn.indexOf("return;", fn.indexOf("catch (e)")) < fn.indexOf("startDebugging"), fn);
    assert.ok(INTERPRETER_OPTIONS.includes("-P"));
  });

  test("the program is written alone into its own folder under the extension's global storage", () => {
    const fn = body(testBench(), "private async debugProgram(");
    assert.ok(
      fn.includes("vscode.Uri.joinPath(this.context.globalStorageUri, TEST_BENCH_DEBUG_PROGRAM.folder)"),
      fn,
    );
    assert.ok(fn.includes("vscode.Uri.joinPath(dir, TEST_BENCH_DEBUG_PROGRAM.file)"), fn);
    assert.ok(fn.includes("TEST_BENCH_DEBUG_PROGRAM.source"), fn);
    // One write: every debugpy build may put the folder on the import path, so nothing else goes in it.
    assert.strictEqual((fn.match(/writeFile\(/g) ?? []).length, 1, fn);
    assert.strictEqual(path.basename(TEST_BENCH_DEBUG_PROGRAM.folder), TEST_BENCH_DEBUG_PROGRAM.folder);
    assert.ok(TEST_BENCH_DEBUG_PROGRAM.file.endsWith(".py"));
  });

  test("under debugpy 1.8.21's runners, the module form is shadowed by the workspace and the program is not", function () {
    const exe = python();
    if (exe === undefined) {
      this.skip(); // no Python 3.11 or later on PATH; the wiring is pinned above
    }
    this.timeout(30000);
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "b532w3-ide-debugpy-"));
    try {
      // The workspace, the launch's working directory, holds a module named like the package.
      const ws = path.join(base, "ws");
      fs.mkdirSync(ws);
      fs.writeFileSync(path.join(ws, "messagefoundry.py"), "print('SHADOWED')\n");
      // The installed package stands in on PYTHONPATH, which `-P` keeps.
      const site = path.join(base, "site");
      fs.mkdirSync(path.join(site, "messagefoundry"), { recursive: true });
      fs.writeFileSync(path.join(site, "messagefoundry", "__init__.py"), "");
      fs.writeFileSync(path.join(site, "messagefoundry", "__main__.py"), "import sys\nprint('INSTALLED', sys.argv[1:])\n");
      // The program, as debugProgram writes it.
      const dir = path.join(base, "storage", TEST_BENCH_DEBUG_PROGRAM.folder);
      fs.mkdirSync(dir, { recursive: true });
      const program = path.join(dir, TEST_BENCH_DEBUG_PROGRAM.file);
      fs.writeFileSync(program, TEST_BENCH_DEBUG_PROGRAM.source);
      const env = { ...process.env, PYTHONPATH: site, PYTHONSAFEPATH: "" };
      const run = (code: string, args: string[]): string => {
        const r = spawnSync(exe!, [...INTERPRETER_OPTIONS, "-c", code, ...args], { cwd: ws, env, encoding: "utf8" });
        assert.strictEqual(r.status, 0, r.stderr);
        return r.stdout.trim();
      };
      // THE CONTROL: the module form, which the launch used before, runs the workspace's module.
      assert.strictEqual(run(OLD_RUN_MODULE, ["dryrun"]), "SHADOWED");
      // The program runs the installed package, with the launch's arguments.
      assert.strictEqual(run(OLD_RUN_FILE, [program, "dryrun", "--show-phi"]), "INSTALLED ['dryrun', '--show-phi']");
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });
});
