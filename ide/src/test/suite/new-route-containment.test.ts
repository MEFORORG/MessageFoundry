// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The New Route wizard writes its module only in a trusted workspace and only inside the workspace
// folder, whatever the window-scoped `messagefoundry.configDir` says (BACKLOG #5410).
//
// The containment helper is driven directly; the wizard itself is driven through its webview message
// handler against a vscode stub, and every refusal is paired with a trusted, contained control on the
// same folder that DOES write, so a refusal cannot pass because the stub was not wired.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { resolveInsideWorkspace } from "../../workspaceContainment";

suite("resolveInsideWorkspace keeps a configured folder inside the workspace (BACKLOG #5410)", () => {
  let root: string;
  let ws: string;
  let outside: string;

  setup(() => {
    root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-contain-")));
    ws = path.join(root, "ws");
    outside = path.join(root, "outside");
    fs.mkdirSync(path.join(ws, "samples", "config"), { recursive: true });
    fs.mkdirSync(outside);
  });

  teardown(() => fs.rmSync(root, { recursive: true, force: true }));

  test("a relative folder inside the workspace resolves, existing or not", () => {
    assert.strictEqual(resolveInsideWorkspace(ws, "samples/config"), path.join(ws, "samples", "config"));
    assert.strictEqual(resolveInsideWorkspace(ws, "new/dir"), path.join(ws, "new", "dir"));
    assert.strictEqual(resolveInsideWorkspace(ws, "."), ws);
    assert.strictEqual(resolveInsideWorkspace(ws, path.join(ws, "samples")), path.join(ws, "samples"));
  });

  test("a climb, an absolute outside path and a sibling sharing the prefix are refused", () => {
    assert.strictEqual(resolveInsideWorkspace(ws, "../outside"), undefined);
    assert.strictEqual(resolveInsideWorkspace(ws, "samples/../../outside"), undefined);
    assert.strictEqual(resolveInsideWorkspace(ws, outside), undefined);
    fs.mkdirSync(`${ws}-sibling`);
    assert.strictEqual(resolveInsideWorkspace(ws, `${ws}-sibling`), undefined);
  });

  test("a link inside the workspace that points outside it is refused", () => {
    // A junction needs no privilege on Windows; elsewhere the type is ignored and a symlink is made.
    fs.symlinkSync(outside, path.join(ws, "escape"), "junction");
    assert.strictEqual(resolveInsideWorkspace(ws, "escape"), undefined);
    assert.strictEqual(resolveInsideWorkspace(ws, "escape/deeper"), undefined);
  });

  test("a dangling link inside the workspace is refused, not taken for a folder to create", () => {
    fs.symlinkSync(path.join(outside, "missing"), path.join(ws, "dangling"), "junction");
    assert.strictEqual(resolveInsideWorkspace(ws, "dangling"), undefined);
    assert.strictEqual(resolveInsideWorkspace(ws, "dangling/deeper"), undefined);
  });

  test("a workspace opened through a link resolves under the workspace's own spelling", () => {
    const linked = path.join(root, "wslink");
    fs.symlinkSync(ws, linked, "junction");
    assert.strictEqual(
      resolveInsideWorkspace(linked, "samples/config"),
      path.join(linked, "samples", "config"),
    );
    assert.strictEqual(resolveInsideWorkspace(linked, "../outside"), undefined);
  });
});

// ---- the wizard, against a vscode stub ----

let stubWorkspace: string | undefined;
let stubTrusted = true;
let stubConfigDir = "samples/config";
let writes: string[];
let messages: { level: string; text: string }[];
let handler: ((m: unknown) => Promise<void>) | undefined;

const panelStub = {
  webview: {
    cspSource: "vscode-resource:",
    html: "",
    onDidReceiveMessage: (cb: (m: unknown) => Promise<void>): void => {
      handler = cb;
    },
  },
  onDidDispose: (cb: () => void): void => {
    disposePanel = cb;
  },
  reveal: (): void => {},
  dispose: (): void => disposePanel?.(),
};
let disposePanel: (() => void) | undefined;

function say(level: string) {
  return (text: string): Promise<undefined> => {
    messages.push({ level, text });
    return Promise.resolve(undefined);
  };
}

const vscodeStub = {
  workspace: {
    get workspaceFolders(): { uri: { fsPath: string } }[] | undefined {
      return stubWorkspace === undefined ? undefined : [{ uri: { fsPath: stubWorkspace } }];
    },
    get isTrusted(): boolean {
      return stubTrusted;
    },
    getConfiguration: () => ({
      get: (key: string, fallback: unknown): unknown => (key === "configDir" ? stubConfigDir : fallback),
    }),
    fs: {
      stat: (uri: { fsPath: string }): Promise<fs.Stats> => fs.promises.stat(uri.fsPath),
      writeFile: async (uri: { fsPath: string }, data: Uint8Array): Promise<void> => {
        writes.push(uri.fsPath);
        await fs.promises.mkdir(path.dirname(uri.fsPath), { recursive: true });
        await fs.promises.writeFile(uri.fsPath, data);
      },
    },
    openTextDocument: (uri: unknown): Promise<unknown> => Promise.resolve(uri),
  },
  window: {
    createWebviewPanel: (): typeof panelStub => panelStub,
    showTextDocument: (): Promise<undefined> => Promise.resolve(undefined),
    showInformationMessage: say("info"),
    showWarningMessage: say("warning"),
    showErrorMessage: say("error"),
    createOutputChannel: () => ({ appendLine: (): void => {}, show: (): void => {} }),
  },
  Uri: { file: (p: string): { fsPath: string } => ({ fsPath: p }) },
  ViewColumn: { Active: -1 },
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
type NewRoute = typeof import("../../newRoute");
let nr!: NewRoute;

if (NODE_SIDE) {
  // Loaded fresh against this stub, and the cache put back afterwards, so another node-side suite's
  // cli.js keeps the stub it was bound to (see source-control-trust.test.ts).
  const fresh = ["../../newRoute", "../../cli", "../../webviewMessaging"].map((m) => require.resolve(m));
  const saved = new Map(fresh.map((f) => [f, require.cache[f]]));
  for (const f of fresh) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    nr = require("../../newRoute") as NewRoute;
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
}

const wizardSuite = NODE_SIDE ? suite : suite.skip;

wizardSuite("The New Route wizard writes only inside a trusted workspace (BACKLOG #5410)", () => {
  let root: string;
  let ws: string;
  const payload = {
    ib: { kind: "mllp-in", name: "IB_ACME_ADT", port: "2575" },
    router: "acme_router",
    handler: "acme_handler",
    ob: { kind: "file-out", name: "OB_ACME_ADT", directory: "./out", filename: "{MSH-10}.hl7" },
  };

  setup(() => {
    root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-new-route-")));
    ws = path.join(root, "ws");
    fs.mkdirSync(path.join(ws, "samples", "config"), { recursive: true });
    stubWorkspace = ws;
    stubTrusted = true;
    stubConfigDir = "samples/config";
    writes = [];
    messages = [];
    handler = undefined;
  });

  teardown(() => {
    panelStub.dispose();
    fs.rmSync(root, { recursive: true, force: true });
    stubWorkspace = undefined;
  });

  async function create(): Promise<void> {
    nr.openNewRoute({ subscriptions: [] } as never);
    assert.ok(handler, "the wizard registered no message handler");
    await handler({ command: "create", payload });
  }

  test("trusted and contained: the control writes the module", async () => {
    await create();
    assert.deepStrictEqual(writes, [path.join(ws, "samples", "config", "IB_ACME_ADT.py")]);
  });

  test("an untrusted workspace writes nothing", async () => {
    stubTrusted = false;
    await create();
    assert.deepStrictEqual(writes, []);
    assert.ok(messages.some((m) => m.level === "warning" && /trust this workspace/.test(m.text)));
  });

  test("a configDir outside the workspace writes nothing", async () => {
    for (const dir of ["../outside", path.join(root, "elsewhere")]) {
      stubConfigDir = dir;
      writes = [];
      await create();
      assert.deepStrictEqual(writes, [], `wrote for configDir ${dir}`);
      panelStub.dispose();
    }
    assert.ok(!fs.existsSync(path.join(root, "outside")));
    assert.ok(!fs.existsSync(path.join(root, "elsewhere")));
  });
});
