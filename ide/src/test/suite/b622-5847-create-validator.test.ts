// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 622 (BACKLOG #5847): createValidator itself, driven against a vscode stub and a stub of the
// `./cli` seam it imports, so `validate --json` output goes straight into the Problems-panel calls it
// makes. b622-5847-validate-location.test.ts pins the location helper; this file pins that
// createValidator uses it, for each limb of the row: a relative `file`, an absolute configDir as the
// no-file fallback, and the engine's own "at line N". It needs no helper that the fix added, so it
// also runs against the createValidator the fix replaced.
import * as assert from "assert";
import * as path from "node:path";

interface StubRange {
  startLine: number;
  endLine: number;
}
interface StubDiagnostic {
  range: StubRange;
  message: string;
  severity: number;
  source?: string;
}
interface Wire {
  message: string;
  file: string | null;
  severity: string;
}

let stubWorkspace: string | undefined;
let stubConfigDir = "config";
let stubDiags: Wire[] = [];
/** Every collection.set(uri, list) the validator made, in order. */
let sets: { fsPath: string; list: StubDiagnostic[] }[] = [];

const vscodeStub = {
  languages: {
    createDiagnosticCollection: () => ({
      clear: (): void => {
        sets = [];
      },
      set: (uri: { fsPath: string }, list: StubDiagnostic[]): void => {
        sets.push({ fsPath: uri.fsPath, list });
      },
      dispose: (): void => {},
    }),
  },
  window: { showErrorMessage: (): Promise<undefined> => Promise.resolve(undefined) },
  DiagnosticSeverity: { Error: 0, Warning: 1 },
  Range: class {
    constructor(
      public startLine: number,
      _startCharacter: number,
      public endLine: number,
    ) {}
  },
  Diagnostic: class {
    source?: string;
    constructor(
      public range: StubRange,
      public message: string,
      public severity: number,
    ) {}
  },
  Uri: { file: (p: string): { fsPath: string } => ({ fsPath: p }) },
};

const cliStub = {
  configDir: (): string => stubConfigDir,
  workspaceDir: (): string | undefined => stubWorkspace,
  runJson: (): Promise<Wire[]> => Promise.resolve(stubDiags),
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
type Validate = typeof import("../../validate");
let createValidator!: Validate["createValidator"];

if (NODE_SIDE) {
  // Loaded fresh against the stubs, and the cache put back afterwards, so another node-side suite's
  // modules keep what they were bound to (see source-control-trust.test.ts). Any module first loaded
  // inside the window is dropped from the cache too, so none stays bound to these stubs.
  const fresh = require.resolve("../../validate");
  const saved = require.cache[fresh];
  const before = new Set(Object.keys(require.cache));
  delete require.cache[fresh];
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return vscodeStub;
    }
    return request === "./cli" ? cliStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    createValidator = (require("../../validate") as Validate).createValidator;
  } finally {
    loader._load = realLoad;
    for (const key of Object.keys(require.cache)) {
      if (!before.has(key)) {
        delete require.cache[key];
      }
    }
    if (saved) {
      require.cache[fresh] = saved;
    } else {
      delete require.cache[fresh];
    }
  }
}

const validatorSuite = NODE_SIDE ? suite : suite.skip;

validatorSuite("b622 #5847 createValidator places each diagnostic", () => {
  // Absolute on this host, and never the process cwd, so a path resolved against the cwd or the
  // filesystem root cannot pass for one resolved against the workspace.
  const ws = path.resolve(path.sep, "b622-5847-ws");
  const cfgAbs = path.resolve(path.sep, "b622-5847-elsewhere", "cfg");

  async function validate(diags: Wire[], configDir = "config"): Promise<typeof sets> {
    stubWorkspace = ws;
    stubConfigDir = configDir;
    stubDiags = diags;
    sets = [];
    const context = { subscriptions: [] as unknown[] };
    await createValidator(context as never).run();
    return sets;
  }

  suiteSetup(() => {
    assert.notStrictEqual(ws, process.cwd(), "the workspace must differ from the cwd, or this proves nothing");
  });

  teardown(() => {
    stubWorkspace = undefined;
  });

  test("the stubs are wired: an absolute file with no line lands as given, on line 0", async () => {
    const abs = path.join(ws, "config", "a.py");
    const out = await validate([{ message: "boom", file: abs, severity: "error" }]);
    assert.deepStrictEqual(
      out.map((s) => [s.fsPath, s.list.map((d) => [d.range.startLine, d.message, d.source])]),
      [[abs, [[0, "boom", "messagefoundry"]]]],
    );
  });

  test("a relative file resolves against the workspace, not the filesystem root", async () => {
    const out = await validate([{ message: "boom", file: path.join("config", "a.py"), severity: "error" }]);
    assert.deepStrictEqual(
      out.map((s) => s.fsPath),
      [path.join(ws, "config", "a.py")],
    );
  });

  test("with no file, an absolute configDir is the fallback as it stands", async () => {
    const out = await validate([{ message: "no inbound", file: null, severity: "warning" }], cfgAbs);
    assert.deepStrictEqual(
      out.map((s) => s.fsPath),
      [cfgAbs],
    );
    assert.strictEqual(out[0].list[0].severity, vscodeStub.DiagnosticSeverity.Warning);
  });

  test("with no file, a relative configDir (the default's shape) resolves against the workspace", async () => {
    const out = await validate([{ message: "no inbound", file: null, severity: "error" }], "samples/config");
    assert.deepStrictEqual(
      out.map((s) => s.fsPath),
      [path.join(ws, "samples", "config")],
    );
  });

  // Windows only: the key folds case only where path.sep is a backslash (pathIdentity.ts).
  (process.platform === "win32" ? test : test.skip)(
    "on Windows two spellings of one file share one set() call, so neither replaces the other",
    async () => {
      const out = await validate([
        { message: "first", file: path.join(ws, "Config", "a.py"), severity: "error" },
        { message: "second", file: path.join(ws, "config", "A.PY"), severity: "error" },
      ]);
      assert.deepStrictEqual(
        out.map((s) => s.list.map((d) => d.message)),
        [["first", "second"]],
      );
    },
  );

  test("the engine's own 'at line N' puts the diagnostic on that line, 0-based", async () => {
    const abs = path.join(ws, "config", "syn.py");
    const m = "error loading config module syn.py: SyntaxError at line 7 (its message is withheld)";
    const out = await validate([{ message: m, file: abs, severity: "error" }]);
    assert.deepStrictEqual(
      out.map((s) => s.list.map((d) => [d.range.startLine, d.range.endLine])),
      [[[6, 6]]],
    );
  });
});
