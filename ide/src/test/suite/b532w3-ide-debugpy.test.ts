// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 532 wave 3 (BACKLOG #5409 item 2): debugpy adds no working directory to the Test Bench Debug
// launch's import path on any build. debugpy 1.8.21 and older insert the working directory into
// `sys.path` when they run a MODULE, whatever `-P` says (debugpy commit 7959635126, first released
// in 1.8.22, added the `safe_path` check), so the launch hands debugpy a PROGRAM the extension
// writes into its own storage folder, for which those builds add only that folder. testBench.ts
// imports vscode, so its wiring is pinned by reading its source; the program itself is run under
// stand-ins for the two runner shapes debugpy has shipped from 1.8.0 on: 1.8.0 to 1.8.21, and 1.8.22
// to `main` as read on 2026-11-23, which honour `-P`. No build before 1.8.0 is covered (the floor
// TEST_BENCH_DEBUG_PROGRAM names). A PYTHONPATH entry, which `-P` keeps, is out of scope
// (TEST_BENCH_DEBUG_PROGRAM's open limit). The write itself is vscode-free (testBenchDebugProgram.ts),
// so it is run against a real temporary folder, with one fs call made to fail where a case needs it.
import * as assert from "assert";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { INTERPRETER_OPTIONS } from "../../engineControlModel";
import {
  LOCAL_STORAGE_SCHEMES,
  TEST_BENCH_DEBUG_PROGRAM,
  debugProgramFileName,
  writeDebugProgram,
  type DebugProgramFs,
  type LocalStorageUri,
} from "../../testBenchDebugProgram";

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
 *  sys.path step and the run: it inserts "" with no check of `sys.flags.safe_path`. The sys.path
 *  steps of `run_module` and `run_file` read the same at tag v1.8.0, so these stand in for 1.8.0
 *  to 1.8.21; no tag before v1.8.0 was read. */
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

/** debugpy 1.8.22's `_skip_sys_path_prepend`, which `run_module` and `run_file` consult from that
 *  release on (identical at debugpy `main`, read 2026-11-23): Python's own rule for `-I` and `-P`. */
const SKIP_PREPEND = [
  "def _skip_sys_path_prepend():",
  "    return sys.flags.isolated or getattr(sys.flags, 'safe_path', False)",
].join("\n");

/** debugpy 1.8.22's `run_module`, reduced the same way: "" goes in only when `-P` is off. */
const NEW_RUN_MODULE = [
  "import runpy, sys",
  SKIP_PREPEND,
  "sys.argv = ['messagefoundry'] + sys.argv[1:]",
  "if not _skip_sys_path_prepend():",
  '    sys.path.insert(0, "")',
  "runpy.run_module('messagefoundry', run_name='__main__', alter_sys=True)",
].join("\n");

/** debugpy 1.8.22's `run_file`, reduced the same way: the file's folder goes in only when `-P` is off. */
const NEW_RUN_FILE = [
  "import os, runpy, sys",
  SKIP_PREPEND,
  "target = sys.argv[1]",
  "sys.argv = sys.argv[1:]",
  "if os.path.isfile(target):",
  "    if not _skip_sys_path_prepend():",
  "        sys.path.insert(0, os.path.dirname(target))",
  "runpy.run_path(target, run_name='__main__')",
].join("\n");

/** Runs a runner stand-in as the debuggee's interpreter would, and returns its output lines. */
type Runner = (code: string, args: string[], options?: readonly string[]) => string[];

/** A Python 3.11 or later on PATH, which `-P` needs, or undefined. */
function python(): string | undefined {
  for (const exe of process.platform === "win32" ? ["python", "py"] : ["python3", "python"]) {
    const r = spawnSync(exe, ["-c", "import sys; print(sys.version_info >= (3, 11))"], {
      encoding: "utf8",
      timeout: 20000,
    });
    if (r.status === 0 && r.stdout.trim() === "True") {
      return exe;
    }
  }
  return undefined;
}

suite("b532w3: debugpy adds no working directory to the Test Bench Debug launch (BACKLOG #5409 item 2)", () => {
  test("debugRow hands debugpy the written program, not the module, and keeps the interpreter options", () => {
    const fn = body(testBench(), "private async debugRow(");
    assert.ok(fn.includes('type: "debugpy"'), fn);
    assert.ok(fn.includes("pythonArgs: [...INTERPRETER_OPTIONS]"), fn);
    assert.ok(fn.includes("program = await writeDebugProgram(this.context.globalStorageUri)"), fn);
    assert.ok(/\n\s*program,\n/.test(fn), fn);
    assert.ok(!/\bmodule\s*:/.test(fn), `debugRow still names a module: ${fn}`);
    // A failed write refuses the launch rather than falling back to the module form.
    const caught = /try \{\s*program = await writeDebugProgram\(this\.context\.globalStorageUri\);\s*\} catch \(e\) \{([\s\S]*?)\n\s*\}\n/.exec(fn);
    assert.ok(caught, fn);
    assert.ok(/\breturn;\s*$/.test(caught[1]), caught[1]);
    // The notice shows an fs error's code, not its message, which names the home folder's path.
    assert.ok(!caught[1].includes("String(e)"), caught[1]);
    assert.ok(caught[1].includes("(e as { code?: unknown })?.code"), caught[1]);
    assert.ok(fn.indexOf(caught[0]) < fn.indexOf("startDebugging"), fn);
    assert.ok(fn.includes("cwd: folder.uri.fsPath"), fn);
    assert.ok(INTERPRETER_OPTIONS.includes("-P"));
  });

  test("testBench writes the program only through writeDebugProgram, handed the global storage URI", () => {
    const src = testBench();
    assert.ok(!src.includes("private async debugProgram("), "the in-class write is back");
    assert.ok(!src.includes('scheme !== "file"'), "testBench refuses a storage scheme itself");
    assert.strictEqual((src.match(/writeDebugProgram\(/g) ?? []).length, 1, "one call, in debugRow");
    assert.strictEqual(path.basename(TEST_BENCH_DEBUG_PROGRAM.folder), TEST_BENCH_DEBUG_PROGRAM.folder);
  });

  test("the accepted storage schemes are file and vscode-userdata, which a local desktop window gets", () => {
    // VS Code 1.142.0's local extension host takes globalStorageHome from the default profile, which
    // is revived under userRoamingDataHome's scheme, vscode-userdata (testBenchDebugProgram.ts cites
    // where).
    assert.deepStrictEqual([...LOCAL_STORAGE_SCHEMES], ["file", "vscode-userdata"]);
  });

  test("the program's source is exactly the runpy call, so a change to it is a reviewed test change", () => {
    // The source is Python held in a TypeScript string, which neither crypto-inventory arm parses as
    // Python, so it is pinned here word for word.
    assert.strictEqual(
      TEST_BENCH_DEBUG_PROGRAM.source,
      "# Written by the MessageFoundry extension for the Test Bench Debug launch (BACKLOG #5409 item 2).\n" +
        "import runpy\n\n" +
        'runpy.run_module("messagefoundry", run_name="__main__", alter_sys=True)\n',
    );
  });

  /**
   * A temporary launch: a workspace, the working directory, holding a `messagefoundry.py`; the
   * installed package standing in on PYTHONPATH, which `-P` keeps; and the program as
   * writeDebugProgram writes it. `run` starts the interpreter as the debug adapter's launcher does,
   * the launch's `python` with its `pythonArgs` first (debugpy's launcher/handlers.py at `main`),
   * then a script in a folder of its own in place of the debugpy server's folder, so the
   * interpreter itself adds no working directory and only the runner stand-in can. The installed `__main__` prints its
   * arguments, then whether the working directory, `""` or the program's folder is on `sys.path`.
   */
  function launch(exe: string, body: (l: { ws: string; program: string; run: Runner }) => void): void {
    const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "b532w3-ide-debugpy-")));
    try {
      const ws = path.join(base, "ws");
      fs.mkdirSync(ws);
      fs.writeFileSync(path.join(ws, "messagefoundry.py"), "print('SHADOWED')\n");
      const site = path.join(base, "site");
      fs.mkdirSync(path.join(site, "messagefoundry"), { recursive: true });
      fs.writeFileSync(path.join(site, "messagefoundry", "__init__.py"), "");
      const dir = path.join(base, "storage", TEST_BENCH_DEBUG_PROGRAM.folder);
      fs.writeFileSync(
        path.join(site, "messagefoundry", "__main__.py"),
        [
          "import os, sys",
          "print('INSTALLED', sys.argv[1:])",
          `seen = {os.path.normcase(os.path.abspath(p or os.getcwd())) for p in sys.path}`,
          `print('CWD' if os.path.normcase(os.getcwd()) in seen else 'NO-CWD',`,
          `      'DIR' if os.path.normcase(${JSON.stringify(dir)}) in seen else 'NO-DIR')`,
          "",
        ].join("\n"),
      );
      fs.mkdirSync(dir, { recursive: true });
      const program = path.join(dir, debugProgramFileName(TEST_BENCH_DEBUG_PROGRAM.source));
      fs.writeFileSync(program, TEST_BENCH_DEBUG_PROGRAM.source);
      const env = { ...process.env, PYTHONPATH: site, PYTHONSAFEPATH: "" };
      const server = path.join(base, "debugpy");
      fs.mkdirSync(server);
      let runs = 0;
      const run: Runner = (code, args, options = INTERPRETER_OPTIONS) => {
        const runner = path.join(server, `runner${runs++}.py`);
        fs.writeFileSync(runner, code);
        const r = spawnSync(exe, [...options, runner, ...args], { cwd: ws, env, encoding: "utf8", timeout: 20000 });
        assert.strictEqual(r.status, 0, r.stderr);
        return r.stdout.trim().split(/\r?\n/);
      };
      body({ ws, program, run });
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  }

  test("under debugpy 1.8.0 to 1.8.21's runners, the module form is shadowed by the workspace and the program is not", function () {
    const exe = python();
    if (exe === undefined) {
      this.skip(); // no Python 3.11 or later on PATH; the wiring is pinned above
    }
    this.timeout(30000);
    launch(exe!, ({ program, run }) => {
      // THE CONTROL: the module form, which the launch used before, runs the workspace's module.
      assert.deepStrictEqual(run(OLD_RUN_MODULE, ["dryrun"]), ["SHADOWED"]);
      // The program runs the installed package, with the launch's arguments. These builds put the
      // program's folder on the import path, never the working directory.
      assert.deepStrictEqual(run(OLD_RUN_FILE, [program, "dryrun", "--show-phi"]), [
        "INSTALLED ['dryrun', '--show-phi']",
        "NO-CWD DIR",
      ]);
    });
  });

  test("under debugpy 1.8.22 and later's runners, the launch's -P keeps both the working directory and the program's folder off the import path", function () {
    const exe = python();
    if (exe === undefined) {
      this.skip(); // no Python 3.11 or later on PATH; the wiring is pinned above
    }
    this.timeout(30000);
    launch(exe!, ({ program, run }) => {
      // THE CONTROL: without -P, these builds put "" first for a module too, so the workspace's
      // module wins. It is -P from pythonArgs that turns the prepend off.
      const noP = INTERPRETER_OPTIONS.filter((o) => o !== "-P");
      assert.ok(noP.length === INTERPRETER_OPTIONS.length - 1, "INTERPRETER_OPTIONS holds no -P");
      assert.deepStrictEqual(run(NEW_RUN_MODULE, ["dryrun"], noP), ["SHADOWED"]);
      // With the launch's options, the module form is not shadowed either.
      assert.deepStrictEqual(run(NEW_RUN_MODULE, ["dryrun"]), ["INSTALLED ['dryrun']", "NO-CWD NO-DIR"]);
      // The program the launch hands debugpy runs the installed package, with nothing added.
      assert.deepStrictEqual(run(NEW_RUN_FILE, [program, "dryrun", "--show-phi"]), [
        "INSTALLED ['dryrun', '--show-phi']",
        "NO-CWD NO-DIR",
      ]);
    });
  });
});

/** An fs error with `code`, as Node raises one. */
function fsError(code: string): NodeJS.ErrnoException {
  const e: NodeJS.ErrnoException = new Error(`${code}: stand-in`);
  e.code = code;
  return e;
}

suite("b532w3: writeDebugProgram puts the Debug program on disk (BACKLOG #5409 item 2)", () => {
  let base: string;
  setup(() => {
    base = fs.mkdtempSync(path.join(os.tmpdir(), "b532w3-ide-write-"));
  });
  teardown(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  /** A storage URI stand-in whose `file` form's fsPath is `fsPath`. */
  const uri = (scheme: string, fsPath: string): LocalStorageUri => ({ scheme, with: () => ({ fsPath }) });
  const local = () => uri("file", base);
  /** What the program folder holds, so a leftover temporary entry shows. */
  const listing = (): string[] => fs.readdirSync(path.join(base, TEST_BENCH_DEBUG_PROGRAM.folder)).sort();

  test("vscode-userdata storage, which a local desktop window gets, is written like file storage", async () => {
    for (const scheme of ["file", "vscode-userdata"]) {
      const file = await writeDebugProgram(uri(scheme, path.join(base, scheme)));
      assert.strictEqual(fs.readFileSync(file, "utf8"), TEST_BENCH_DEBUG_PROGRAM.source, scheme);
      assert.strictEqual(path.dirname(file), path.join(base, scheme, TEST_BENCH_DEBUG_PROGRAM.folder));
    }
  });

  test("the folder is read from the URI's file form, which keeps a UNC share's server", async () => {
    // VS Code drops the authority from fsPath for any scheme but file, so a vscode-userdata URI on
    // \\server\share reports a path with no server; its file form keeps it.
    const right = path.join(base, "right");
    const storage = {
      scheme: "vscode-userdata",
      fsPath: path.join(base, "wrong"),
      with: (change: { scheme: string }) => ({ fsPath: change.scheme === "file" ? right : path.join(base, "wrong") }),
    };
    const file = await writeDebugProgram(storage);
    assert.strictEqual(path.dirname(file), path.join(right, TEST_BENCH_DEBUG_PROGRAM.folder));
    assert.ok(!fs.existsSync(path.join(base, "wrong")));
  });

  test("a scheme with no local path is refused before anything is written", async () => {
    for (const scheme of ["vscode-remote", "vscode-vfs", "untitled"]) {
      await assert.rejects(writeDebugProgram(uri(scheme, base)), /not on this machine's file system/);
    }
    assert.ok(!fs.existsSync(path.join(base, TEST_BENCH_DEBUG_PROGRAM.folder)));
  });

  test("launches in one millisecond never share a temporary file, and leave none behind", async () => {
    // Every write reaches its rename before any rename runs, as two quick clicks can.
    const n = 8;
    let waiting = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const fsp: DebugProgramFs = {
      ...fs.promises,
      rename: async (from, to) => {
        if (++waiting === n) {
          release();
        }
        await gate;
        return fs.promises.rename(from, to);
      },
    };
    // The clock is frozen so a temporary name built from the time, as the write's earlier form did,
    // collides here; the write must not depend on it.
    const now = Date.now;
    Date.now = () => 1700000000000;
    try {
      const files = await Promise.all(Array.from({ length: n }, () => writeDebugProgram(local(), undefined, fsp)));
      assert.strictEqual(new Set(files).size, 1);
      assert.strictEqual(fs.readFileSync(files[0], "utf8"), TEST_BENCH_DEBUG_PROGRAM.source);
    } finally {
      Date.now = now;
    }
    assert.deepStrictEqual(listing(), [debugProgramFileName(TEST_BENCH_DEBUG_PROGRAM.source)]);
  });

  test("a temporary folder that cannot be removed after a good rename is logged, not a failed launch", async () => {
    const fsp: DebugProgramFs = { ...fs.promises, rm: async () => Promise.reject(fsError("EBUSY")) };
    // The warning goes through the injected warn: a stub on the global console installs nothing in
    // the Extension Host (webview-receivers.test.ts records that).
    const warned: string[] = [];
    const file = await writeDebugProgram(local(), undefined, fsp, (m) => void warned.push(m));
    assert.strictEqual(fs.readFileSync(file, "utf8"), TEST_BENCH_DEBUG_PROGRAM.source);
    assert.strictEqual(warned.length, 1, warned.join("\n"));
    assert.ok(warned[0].includes("EBUSY"), warned[0]);
    // The log names the folder below the storage root, never the path under the home folder.
    assert.ok(!warned[0].includes(base), warned[0]);
    assert.ok(warned[0].includes(path.join(TEST_BENCH_DEBUG_PROGRAM.folder, ".tmp-")), warned[0]);
  });

  test("different program texts get different files, so one version never rewrites another's", async () => {
    const a = "# a\n";
    const b = "# b\n";
    assert.notStrictEqual(debugProgramFileName(a), debugProgramFileName(b));
    const fa = await writeDebugProgram(local(), a);
    const fb = await writeDebugProgram(local(), b);
    assert.strictEqual(fs.readFileSync(fa, "utf8"), a);
    assert.strictEqual(fs.readFileSync(fb, "utf8"), b);
    assert.match(path.basename(fa), /^mefor_testbench_debug_[0-9a-f]{8}\.py$/);
  });

  test("EPERM on the rename is success when another launch already wrote the identical program", async () => {
    // Windows can refuse a rename over a file another launch's debuggee holds open.
    const fsp: DebugProgramFs = {
      ...fs.promises,
      rename: async (_from, to) => {
        await fs.promises.writeFile(to, TEST_BENCH_DEBUG_PROGRAM.source);
        throw fsError("EPERM");
      },
    };
    const file = await writeDebugProgram(local(), undefined, fsp);
    assert.strictEqual(fs.readFileSync(file, "utf8"), TEST_BENCH_DEBUG_PROGRAM.source);
    assert.deepStrictEqual(listing(), [path.basename(file)]);
  });

  test("EPERM on the rename refuses the launch when the program does not hold the source", async () => {
    const fsp: DebugProgramFs = { ...fs.promises, rename: async () => Promise.reject(fsError("EPERM")) };
    await assert.rejects(writeDebugProgram(local(), undefined, fsp), /EPERM/);
    assert.deepStrictEqual(listing(), [], "a temporary entry was left behind");
  });

  test("a first launch whose rename a scanner briefly blocks is retried, not refused", async () => {
    // No program exists yet, so the identical-file check cannot rescue the failure.
    let failures = 2;
    const fsp: DebugProgramFs = {
      ...fs.promises,
      rename: async (from, to) => {
        if (failures-- > 0) {
          throw fsError("EBUSY");
        }
        return fs.promises.rename(from, to);
      },
    };
    const file = await writeDebugProgram(local(), undefined, fsp);
    assert.strictEqual(fs.readFileSync(file, "utf8"), TEST_BENCH_DEBUG_PROGRAM.source);
    assert.deepStrictEqual(listing(), [path.basename(file)]);
  });

  test("a program that cannot be read for the moment is written again, not a refused launch", async () => {
    let reads = 0;
    const fsp: DebugProgramFs = {
      ...fs.promises,
      readFile: (async (...args: Parameters<typeof fs.promises.readFile>) => {
        if (reads++ === 0) {
          throw fsError("EBUSY");
        }
        return fs.promises.readFile(...args);
      }) as typeof fs.promises.readFile,
    };
    const file = await writeDebugProgram(local(), undefined, fsp);
    assert.strictEqual(fs.readFileSync(file, "utf8"), TEST_BENCH_DEBUG_PROGRAM.source);
  });

  test("a program that already holds the source is not written again", async () => {
    const file = await writeDebugProgram(local());
    const fsp: DebugProgramFs = { ...fs.promises, writeFile: async () => Promise.reject(fsError("EACCES")) };
    assert.strictEqual(await writeDebugProgram(local(), undefined, fsp), file);
  });
});
