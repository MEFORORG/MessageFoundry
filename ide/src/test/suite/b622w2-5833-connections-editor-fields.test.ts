// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5833. The connections.toml custom editor shares the connection form with the
// command-opened editor. When the form's transport or direction changes, the page posts a `fields`
// request and redraws its schema-driven fields from the reply. The custom editor's provider had no
// branch for that request, so the form kept the previous transport's fields. This drives the REAL
// provider through its webview message handler against a vscode stub, with the CLI replaced by a
// recorded-shape answer, and pairs the request with the render's own page token so a reply that
// the provider drops for a stale page cannot be what passes.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

let stubWorkspace: string | undefined;
let handler: ((m: unknown) => Promise<void>) | undefined;
let posts: Record<string, unknown>[] = [];

const webview = {
  cspSource: "vscode-resource:",
  html: "",
  options: {},
  asWebviewUri: (u: unknown): unknown => u,
  postMessage: (m: Record<string, unknown>): Promise<boolean> => {
    posts.push(m);
    return Promise.resolve(true);
  },
  onDidReceiveMessage: (cb: (m: unknown) => Promise<void>): void => {
    handler = cb;
  },
};
const disposable = (): { dispose(): void } => ({ dispose: (): void => {} });
const panelStub = { webview, onDidDispose: disposable, onDidChangeViewState: disposable };
const vscodeStub = {
  workspace: {
    get workspaceFolders(): { uri: { fsPath: string } }[] | undefined {
      return stubWorkspace === undefined ? undefined : [{ uri: { fsPath: stubWorkspace } }];
    },
    isTrusted: true,
    getConfiguration: () => ({
      get: (key: string, fallback: unknown): unknown => (key === "configDir" ? "samples/config" : fallback),
      inspect: (key: string): Record<string, unknown> | undefined =>
        key === "configDir" ? { defaultValue: "samples/config", globalValue: "samples/config" } : undefined,
    }),
    onDidChangeTextDocument: disposable,
    onDidChangeConfiguration: disposable,
  },
  window: {
    showInformationMessage: (): Promise<undefined> => Promise.resolve(undefined),
    showWarningMessage: (): Promise<undefined> => Promise.resolve(undefined),
    showErrorMessage: (): Promise<undefined> => Promise.resolve(undefined),
    createOutputChannel: () => ({ appendLine: (): void => {}, show: (): void => {} }),
  },
  commands: { executeCommand: (): Promise<undefined> => Promise.resolve(undefined) },
  Uri: { file: (p: string): { fsPath: string; scheme: string } => ({ fsPath: p, scheme: "file" }) },
  ViewColumn: { Active: -1 },
  EventEmitter: class {
    event = disposable;
    fire(): void {}
    dispose(): void {}
  },
};

/** A catalogue in the shape `connection schema --json` emits: two transports with disjoint fields,
 *  so a reply for the new transport is told apart from the old transport's form. */
const SCHEMA = {
  schemaVersion: 1,
  transports: {
    mllp: {
      doc: "MLLP.",
      params: {
        port: {
          type: "int", choices: null, default: null, required: true, requiredHint: false,
          env: false, secret: false, direction: null, help: "",
        },
      },
    },
    file: {
      doc: "File.",
      params: {
        directory: {
          type: "str", choices: null, default: null, required: true, requiredHint: false,
          env: false, secret: false, direction: null, help: "",
        },
      },
    },
  },
  directionKeys: {
    inbound: ["name", "transport", "settings", "router"],
    outbound: ["name", "transport", "settings", "retry"],
  },
};

async function fakeRunJson(args: string[]): Promise<unknown> {
  if (args[0] === "connection" && args[1] === "schema") {
    return SCHEMA;
  }
  if (args[0] === "connection" && args[1] === "list") {
    return [];
  }
  throw new Error(`unexpected CLI call in test: ${args.join(" ")}`);
}

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

function insideExtensionHost(): boolean {
  try {
    const api = realLoad.call(loader, "vscode", module, false) as { version?: unknown; env?: { appName?: unknown } };
    return typeof api?.version === "string" && typeof api?.env?.appName === "string";
  } catch {
    return false;
  }
}

const NODE_SIDE = !insideExtensionHost();
type ConfigEditors = typeof import("../../configEditors");
let ce!: ConfigEditors;

if (NODE_SIDE) {
  // Loaded fresh against this stub, and the cache put back afterwards, so another node-side suite's
  // modules keep the stub they were bound to (see new-route-containment.test.ts). Every module of the
  // extension's own is dropped, not a named list, so none that configEditors pulls in transitively
  // stays cached bound to this stub and to the fake CLI below.
  const outDir = path.resolve(__dirname, "..", "..");
  const ours = (f: string): boolean => f.startsWith(outDir) && !f.includes(`${path.sep}test${path.sep}`);
  const saved = new Map(Object.entries(require.cache).filter(([f]) => ours(f)));
  for (const f of saved.keys()) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    ce = require("../../configEditors") as ConfigEditors;
    // The provider and the schema fetch call the CLI through this module's export at call time.
    (require("../../cli") as { runJson: unknown }).runJson = fakeRunJson;
  } finally {
    loader._load = realLoad;
    for (const f of Object.keys(require.cache).filter(ours)) {
      delete require.cache[f];
    }
    for (const [f, entry] of saved) {
      require.cache[f] = entry;
    }
  }
}

const providerSuite = NODE_SIDE ? suite : suite.skip;

providerSuite("connections custom editor answers the form's fields request (BACKLOG #5833)", function () {
  this.timeout(10000);
  let root: string;

  setup(() => {
    root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-5833-")));
    fs.mkdirSync(path.join(root, "samples", "config"), { recursive: true });
    fs.writeFileSync(path.join(root, "samples", "config", "connections.toml"), "");
    stubWorkspace = root;
    handler = undefined;
    posts = [];
    webview.html = "";
  });

  teardown(() => {
    stubWorkspace = undefined;
    fs.rmSync(root, { recursive: true, force: true });
  });

  // Bounded by wall time, not by a count of timer ticks, which are coarse on Windows.
  async function settle(done: () => boolean): Promise<void> {
    const deadline = Date.now() + 1000;
    while (!done() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  async function open(): Promise<string> {
    const file = path.join(root, "samples", "config", "connections.toml");
    const document = {
      uri: { scheme: "file", fsPath: file, toString: (): string => `file://${file}` },
      fileName: file,
      getText: (): string => "",
    };
    new ce.ConnectionsCustomEditorProvider(() => []).resolveCustomTextEditor(
      document as never,
      panelStub as never,
      {} as never,
    );
    assert.ok(handler, "the provider registered no message handler");
    await settle(() => /const MF_CHANNEL = "/.test(webview.html));
    const token = /const MF_CHANNEL = "([^"]+)"/.exec(webview.html)?.[1];
    assert.ok(token, "the rendered form carries no page token");
    return token;
  }

  // The handler awaits the rebuild and then posts or drops the reply before it resolves, so no wait
  // is needed after it.
  const ask = (token: string): Promise<void> =>
    handler!({ command: "fields", transport: "file", direction: "inbound", settings: {}, __mfChannel: token });

  test("a transport change is answered with the new transport's field groups", async () => {
    await ask(await open());
    const reply = posts.find((p) => p.command === "fields");
    assert.ok(reply, `no fields reply was posted; posts: ${JSON.stringify(posts)}`);
    const keys = JSON.stringify(reply.groups);
    assert.match(keys, /"directory"/, "the reply carries the file transport's fields");
    assert.doesNotMatch(keys, /"port"/, "the reply does not carry the previous transport's fields");
  });

  test("a request from a page that is no longer showing gets no reply", async () => {
    const token = await open();
    await ask("stale");
    assert.ok(!posts.some((p) => p.command === "fields"), "a stale page's request was answered");
    // Control: the same request from the page that is showing IS answered, so the silence above is
    // the stale-page drop and not a rebuild that failed.
    await ask(token);
    assert.ok(posts.some((p) => p.command === "fields"), "the live page's request was not answered");
  });
});
