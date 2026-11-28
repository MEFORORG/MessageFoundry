// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5565, remainder #8243 item 18. The connection form draws only the reply to its latest
// "fields" request, matched by the id the request carries (connectionEditorWebview.ts). This pins
// that BOTH hosts echo that id, with the transport and direction the groups were built for, and
// answer a request they cannot rebuild with an "error" naming the same id, so the page stops
// waiting. It drives the REAL message handlers of the command-opened editor (connectionEditor.ts)
// and the connections.toml custom editor (configEditors.ts) against a vscode stub, with the CLI
// replaced by a recorded-shape answer. The stub and loader are copied from
// b622w2-5833-connections-editor-fields.test.ts, not shared, so this branch owns its own file.
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
const panelStub = { webview, onDidDispose: disposable, onDidChangeViewState: disposable, dispose: (): void => {} };
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
    createWebviewPanel: (): unknown => panelStub,
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

/** Two transports with disjoint fields, in the shape `connection schema --json` emits. */
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

// When set, `connection schema` fails, as it does when the engine cannot describe itself.
let schemaFails = false;

async function fakeRunJson(args: string[]): Promise<unknown> {
  if (args[0] === "connection" && args[1] === "schema") {
    if (schemaFails) {
      throw new Error("synthetic schema failure");
    }
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
type ConnectionEditor = typeof import("../../connectionEditor");
type SchemaModule = typeof import("../../connectionSchema");
let ce!: ConfigEditors;
let editor!: ConnectionEditor;
let schemaModule!: SchemaModule;

if (NODE_SIDE) {
  // Loaded fresh against this stub, and the cache put back afterwards, so another node-side suite's
  // modules keep the stub they were bound to.
  const outDir = path.resolve(__dirname, "..", "..");
  const testDir = path.join(outDir, "test") + path.sep;
  const ours = (f: string): boolean => f.startsWith(outDir + path.sep) && !f.startsWith(testDir);
  const saved = new Map(Object.entries(require.cache).filter(([f]) => ours(f)));
  for (const f of saved.keys()) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    ce = require("../../configEditors") as ConfigEditors;
    editor = require("../../connectionEditor") as ConnectionEditor;
    schemaModule = require("../../connectionSchema") as SchemaModule;
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

const hostSuite = NODE_SIDE ? suite : suite.skip;

hostSuite("both connection form hosts echo the fields request's id (BACKLOG #8243 item 18)", function () {
  this.timeout(10000);
  let root: string;

  setup(() => {
    root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-b20008e-")));
    fs.mkdirSync(path.join(root, "samples", "config"), { recursive: true });
    fs.writeFileSync(path.join(root, "samples", "config", "connections.toml"), "");
    stubWorkspace = root;
    handler = undefined;
    posts = [];
    webview.html = "";
    schemaFails = false;
    schemaModule.resetConnectionSchemaCache();
  });

  teardown(() => {
    stubWorkspace = undefined;
    schemaFails = false;
    schemaModule.resetConnectionSchemaCache();
    fs.rmSync(root, { recursive: true, force: true });
  });

  async function settle(done: () => boolean): Promise<void> {
    const deadline = Date.now() + 1000;
    while (!done() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  function pageToken(): string {
    const token = /const MF_CHANNEL = "([^"]+)"/.exec(webview.html)?.[1];
    assert.ok(token, "the rendered form carries no page token");
    return token;
  }

  async function openCustomEditor(): Promise<string> {
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
    assert.ok(handler, "the custom editor registered no message handler");
    await settle(() => /const MF_CHANNEL = "/.test(webview.html));
    return pageToken();
  }

  async function openCommandEditor(): Promise<string> {
    await editor.openConnectionEditor({ subscriptions: [] } as never, { routers: [] });
    assert.ok(handler, "the command-opened editor registered no message handler");
    return pageToken();
  }

  const hosts: [string, () => Promise<string>][] = [
    ["the connections.toml custom editor", openCustomEditor],
    ["the command-opened editor", openCommandEditor],
  ];

  for (const [name, open] of hosts) {
    test(`${name}: the fields reply echoes the request's id, transport and direction`, async () => {
      const token = await open();
      await handler!({ command: "fields", seq: 7, transport: "file", direction: "inbound", settings: {}, __mfChannel: token });
      const reply = posts.find((p) => p.command === "fields");
      assert.ok(reply, `no fields reply was posted; posts: ${JSON.stringify(posts)}`);
      assert.strictEqual(reply.seq, 7, "the reply does not name the request it answers");
      assert.strictEqual(reply.transport, "file");
      assert.strictEqual(reply.direction, "inbound");
      assert.match(JSON.stringify(reply.groups), /"directory"/, "the reply carries the file transport's fields");
    });

    test(`${name}: a request the engine cannot answer gets an error naming its id`, async () => {
      const token = await open();
      posts = [];
      schemaFails = true;
      schemaModule.resetConnectionSchemaCache();
      await handler!({ command: "fields", seq: 4, transport: "file", direction: "inbound", settings: {}, __mfChannel: token });
      assert.ok(!posts.some((p) => p.command === "fields"), "a fields reply was posted with no fields");
      const error = posts.find((p) => p.command === "error");
      assert.ok(error, `the failed request got no answer; posts: ${JSON.stringify(posts)}`);
      assert.strictEqual(error.seq, 4, "the error does not name the request it answers");
      assert.match(String(error.message), /file transport: synthetic schema failure/, "the error does not say why");
    });

    test(`${name}: a request with no valid id gets no reply, since the page would discard it`, async () => {
      const token = await open();
      posts = [];
      for (const seq of [undefined, "1", 1.5]) {
        await handler!({ command: "fields", seq, transport: "file", direction: "inbound", settings: {}, __mfChannel: token });
      }
      assert.deepStrictEqual(posts, [], "a request with no valid id was answered");
    });
  }
});
