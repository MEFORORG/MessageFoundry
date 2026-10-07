// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// "Set Up Version Control & Checks" refuses in an untrusted workspace (vault BACKLOG #2791).
//
// Setup runs `git init`, writes `.mefor-hooks/pre-commit` and sets `core.hooksPath`, and that hook
// prefers the folder's own `.venv` interpreter on every later commit. In a folder the user chose not
// to trust, that is the workspace-supplied-interpreter hazard cli.ts already refuses (SEC-004). The
// exec gate in cli.ts covers `run()` only, not `git()` or the file writes, so both entry points carry
// their own trust check, and this suite drives each one with the trust flag off and then on.
//
// Each refusal is paired with a trusted control on the SAME folder that reaches the next step. A
// refusal assertion alone would also pass if the stub were not wired (no workspace, say), which is
// the silent-pass this pairing exists to rule out.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

type Call = { api: string; args: unknown[] };

let stubWorkspace: string | undefined;
let stubTrusted = true;
/** Every stubbed vscode call that prompts, touches the filesystem, or reaches for git. */
let calls: Call[];
/** Every child-process launch. git.ts runs git through `execFile`, so this is every git command. */
let launches: { file: string; args: string[] }[];

function record(api: string) {
  return (...args: unknown[]): Promise<undefined> => {
    calls.push({ api, args });
    return Promise.resolve(undefined);
  };
}

const memento = { get: (): boolean => false, update: (): Promise<void> => Promise.resolve() };
const context = { globalState: memento, workspaceState: memento };

const vscodeStub = {
  workspace: {
    get workspaceFolders(): { uri: { fsPath: string } }[] | undefined {
      return stubWorkspace === undefined ? undefined : [{ uri: { fsPath: stubWorkspace } }];
    },
    get isTrusted(): boolean {
      return stubTrusted;
    },
    getConfiguration: () => ({ get: (_key: string, fallback: unknown): unknown => fallback }),
    fs: {
      stat: (uri: { fsPath: string }): Promise<fs.Stats> => {
        calls.push({ api: "fs.stat", args: [uri.fsPath] });
        return fs.promises.stat(uri.fsPath);
      },
      readDirectory: async (uri: { fsPath: string }): Promise<[string, number][]> => {
        calls.push({ api: "fs.readDirectory", args: [uri.fsPath] });
        const entries = await fs.promises.readdir(uri.fsPath, { withFileTypes: true });
        return entries.map((e) => [e.name, e.isFile() ? 1 : 2]);
      },
      readFile: (uri: { fsPath: string }): Promise<Buffer> => {
        calls.push({ api: "fs.readFile", args: [uri.fsPath] });
        return fs.promises.readFile(uri.fsPath);
      },
      writeFile: record("fs.writeFile"),
      createDirectory: record("fs.createDirectory"),
    },
  },
  window: {
    showInformationMessage: record("showInformationMessage"),
    showWarningMessage: record("showWarningMessage"),
    showErrorMessage: record("showErrorMessage"),
    showQuickPick: record("showQuickPick"),
    showInputBox: record("showInputBox"),
    createOutputChannel: () => ({ appendLine: (): void => {}, show: (): void => {} }),
    createTerminal: () => ({ show: (): void => {}, sendText: (): void => {} }),
  },
  extensions: {
    getExtension: (id: string): undefined => {
      calls.push({ api: "extensions.getExtension", args: [id] });
      return undefined;
    },
  },
  env: { openExternal: record("env.openExternal") },
  commands: { executeCommand: record("commands.executeCommand") },
  Uri: {
    file: (p: string): { fsPath: string } => ({ fsPath: p }),
    parse: (p: string): { fsPath: string } => ({ fsPath: p }),
  },
  FileType: { File: 1, Directory: 2 },
};

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

/** True inside the Extension Host, where the REAL `vscode` API resolves (see engine-trust-shell). */
function insideExtensionHost(): boolean {
  try {
    const api = realLoad.call(loader, "vscode", module, false) as {
      version?: unknown;
      env?: { appName?: unknown };
    };
    return typeof api?.version === "string" && typeof api?.env?.appName === "string";
  } catch {
    return false;
  }
}

const NODE_SIDE = !insideExtensionHost();

type SourceControl = typeof import("../../sourceControl");
type ChildProcess = { execFile: typeof import("node:child_process").execFile };

let sc!: SourceControl;
let childProcess!: ChildProcess;
let realExecFile!: typeof import("node:child_process").execFile;

if (NODE_SIDE) {
  // sourceControl.js reads the workspace through cli.js and runs git through git.js. Another node-side
  // suite may already have loaded cli.js bound to ITS vscode stub, and a cached copy would answer
  // "no workspace" here, which makes every refusal below pass for the wrong reason. So these three are
  // loaded fresh against this stub, and whatever the cache held before is put back afterwards, so
  // the other suite keeps the bindings it loaded.
  const fresh = ["../../sourceControl", "../../cli", "../../git"].map((m) => require.resolve(m));
  const saved = new Map(fresh.map((f) => [f, require.cache[f]]));
  for (const f of fresh) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    sc = require("../../sourceControl") as SourceControl;
    childProcess = require("node:child_process") as ChildProcess;
  } finally {
    loader._load = realLoad;
    for (const [f, entry] of saved) {
      if (entry) {
        require.cache[f] = entry;
      } else {
        delete require.cache[f];
      }
    }
  }
  realExecFile = childProcess.execFile;
}

const trustSuite = NODE_SIDE ? suite : suite.skip;

trustSuite("Set Up Version Control & Checks needs a trusted workspace (vault BACKLOG #2791)", () => {
  let ws: string;

  setup(() => {
    // The shape the review names: config modules, no `.git`, and a planted workspace interpreter.
    ws = fs.mkdtempSync(path.join(os.tmpdir(), "mf-source-control-"));
    fs.mkdirSync(path.join(ws, "samples", "config"), { recursive: true });
    fs.writeFileSync(path.join(ws, "samples", "config", "feed.py"), "# a config module\n");
    fs.mkdirSync(path.join(ws, ".venv", "bin"), { recursive: true });
    fs.writeFileSync(path.join(ws, ".venv", "bin", "python"), "#!/bin/sh\nexit 0\n");
    stubWorkspace = ws;
    stubTrusted = true;
    calls = [];
    launches = [];
    // Every launch fails, so a trusted run that reaches git stops at "git not found" and launches
    // nothing further: the control needs to see git reached, never to run it.
    childProcess.execFile = ((
      file: string,
      args: string[],
      _options: unknown,
      done: (err: Error, stdout: string, stderr: string) => void,
    ) => {
      launches.push({ file, args });
      done(Object.assign(new Error("stubbed"), { code: 1 }), "", "");
      return undefined;
    }) as unknown as typeof childProcess.execFile;
  });

  teardown(() => {
    childProcess.execFile = realExecFile;
    fs.rmSync(ws, { recursive: true, force: true });
    stubWorkspace = undefined;
  });

  /** Nothing setup could leave behind exists in the folder. */
  function assertFolderUntouched(): void {
    for (const name of [".git", ".mefor-hooks", ".gitignore", ".gitattributes"]) {
      assert.ok(!fs.existsSync(path.join(ws, name)), `${name} was created`);
    }
  }

  test("the activation nudge stays silent and touches nothing when the workspace is untrusted", async () => {
    stubTrusted = false;
    await sc.maybeSuggestSourceControl(context as never);

    assert.deepStrictEqual(calls, [], "the nudge prompted or read the folder in an untrusted workspace");
    assert.deepStrictEqual(launches, []);
    assertFolderUntouched();
  });

  test("control: the same folder, trusted, IS offered setup", async () => {
    await sc.maybeSuggestSourceControl(context as never);

    const prompts = calls.filter((c) => c.api === "showInformationMessage");
    assert.strictEqual(prompts.length, 1, `expected the setup offer, saw ${JSON.stringify(calls)}`);
    assert.match(String(prompts[0].args[0]), /under version control/);
  });

  test("the command refuses with a trust message and runs no git when the workspace is untrusted", async () => {
    stubTrusted = false;
    await sc.setupSourceControl(context as never);

    assert.deepStrictEqual(launches, [], "setup launched a process in an untrusted workspace");
    const apis = calls.map((c) => c.api);
    assert.deepStrictEqual(apis, ["showWarningMessage"], `unexpected calls: ${JSON.stringify(calls)}`);
    assert.match(String(calls[0].args[0]), /trust this workspace/);
    assertFolderUntouched();
  });

  test("Config Repo Storage Location refuses and runs no git when the workspace is untrusted", async () => {
    stubTrusted = false;
    await sc.setRepoStorage();

    assert.deepStrictEqual(launches, [], "the storage command launched a process in an untrusted workspace");
    assert.deepStrictEqual(calls.map((c) => c.api), ["showWarningMessage"]);
    assert.match(String(calls[0].args[0]), /trust this workspace/);
  });

  test("control: Config Repo Storage Location, trusted, reaches git", async () => {
    await sc.setRepoStorage();

    assert.ok(launches.some((l) => l.args.includes("--version")), JSON.stringify(launches));
  });

  test("control: the same folder, trusted, reaches git", async () => {
    await sc.setupSourceControl(context as never);

    assert.ok(
      launches.some((l) => l.args.includes("--version")),
      `expected a git probe, saw ${JSON.stringify(launches)}`,
    );
    assert.ok(
      calls.every((c) => !String(c.args[0]).includes("trust this workspace")),
      "a trusted workspace was told to trust itself",
    );
  });
});
