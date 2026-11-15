// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Restart refuses a remote target and an untrusted workspace before it touches the filesystem
// (BACKLOG #5566, PR 2966 hold).
//
// Why the order matters is stated once, at the top of `restartEngine` in statusBar.ts.
//
// This drives the real `restartEngine` against a stubbed `vscode` and spied sync `fs` calls. The spies
// are installed only for Restart's synchronous part, which runs every check before its first await;
// an async `fs` call is not spied, and nor is a sync one outside SPIED below. It runs
// node-side only, as its siblings do: the Extension Host opens no folder and cannot shut workspace
// trust (live-debug.test.ts records the same), so no untrusted workspace with the setting can exist
// there. Each refusal is paired with a trusted control that DOES stat the configured path, so a
// refusal assertion cannot pass because the stub was not wired.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// The REAL node:fs module object, patched the way symbol-index.test.ts patches it: statusBar.js reads
// `fs` through a namespace copy whose members are forwarding getters onto this object.
const FS_MODULE: Record<string, unknown> = require("node:fs");

/** A value an untrusted repository could plant; `.invalid` never resolves, and the spy never delegates. */
const UNC_SETTING = "\\\\attacker.invalid\\share\\messagefoundry.toml";
const LOOPBACK = "https://127.0.0.1:8765";
const REMOTE = "https://prod.example.com:8765";
const TRUST_REFUSAL = "MessageFoundry: trust this workspace to let the IDE run the engine.";
const REMOTE_REFUSAL = `MessageFoundry: ${REMOTE} is a remote engine — the IDE can only start a local (loopback) engine.`;

let stubWorkspace: string | undefined;
let stubTrusted = true;
/** The workspace value of `messagefoundry.serviceConfig`, or undefined for a setting left unset. */
let stubSetting: string | undefined;
let notices: string[];
/** The `onDidCloseTerminal` listeners Restart's stop is waiting on. */
const closeListeners = new Set<(t: unknown) => void>();

const vscodeStub = {
  workspace: {
    get workspaceFolders(): { uri: { fsPath: string } }[] | undefined {
      return stubWorkspace === undefined ? undefined : [{ uri: { fsPath: stubWorkspace } }];
    },
    get isTrusted(): boolean {
      return stubTrusted;
    },
    // The setting as a workspace's own settings.json sets it: a workspace value, so it counts as set.
    getConfiguration: () => ({
      get: (key: string, fallback: unknown): unknown =>
        key === "serviceConfig" && stubSetting !== undefined ? stubSetting : fallback,
      inspect: (key: string) =>
        key === "serviceConfig"
          ? { defaultValue: "messagefoundry.toml", workspaceValue: stubSetting }
          : undefined,
    }),
  },
  window: {
    showInformationMessage: (message: string): Promise<undefined> => {
      notices.push(message);
      return Promise.resolve(undefined);
    },
    onDidCloseTerminal: (listener: (t: unknown) => void) => {
      closeListeners.add(listener);
      return { dispose: (): void => void closeListeners.delete(listener) };
    },
  },
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

type StatusBarModule = typeof import("../../statusBar");
let statusBar!: StatusBarModule;

if (NODE_SIDE) {
  // statusBar.js reads the workspace and the setting through cli.js, and another node-side suite may
  // already hold cli.js bound to ITS stub. So every extension module (out/, not out/test/) is loaded
  // fresh against this stub, and the cache is put back exactly as it was afterwards.
  const outDir = path.resolve(__dirname, "..", "..");
  const testDir = path.join(outDir, "test") + path.sep;
  const isExtensionModule = (f: string): boolean => f.startsWith(outDir + path.sep) && !f.startsWith(testDir);
  const saved = new Map(
    Object.keys(require.cache)
      .filter(isExtensionModule)
      .map((f) => [f, require.cache[f]]),
  );
  for (const f of saved.keys()) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    statusBar = require("../../statusBar") as StatusBarModule;
  } finally {
    loader._load = realLoad;
    for (const f of Object.keys(require.cache).filter(isExtensionModule)) {
      delete require.cache[f];
    }
    for (const [f, entry] of saved) {
      require.cache[f] = entry;
    }
  }
}

const restartSuite = NODE_SIDE ? suite : suite.skip;

restartSuite("Restart refuses before it stats the service config (BACKLOG #5566)", () => {
  // Never created: every stat is stubbed, so the folder only has to be a path to resolve against.
  const ws = path.resolve(os.tmpdir(), "mf-restart-trust-unused");

  setup(() => {
    stubWorkspace = ws;
    stubTrusted = true;
    stubSetting = UNC_SETTING;
    notices = [];
  });

  teardown(() => {
    stubWorkspace = undefined;
    closeListeners.clear();
  });

  /** At least the sync `fs` entry points a check could reach a path through; `existsSync` answers
   *  false. Not every one: a call through another is not recorded. */
  const SPIED = [
    "statSync",
    "lstatSync",
    "existsSync",
    "accessSync",
    "readdirSync",
    "readFileSync",
    "openSync",
    "realpathSync",
  ];

  /** What one Restart did: each `fs` call as "<function> <path>", and whether it stopped or started
   *  the engine. */
  async function restart(url: string): Promise<{ statted: string[]; stopped: boolean; started: boolean }> {
    const statted: string[] = [];
    let stopped = false;
    let started = false;
    // A running engine this IDE owns, so a Restart that got past its checks would stop it.
    const owner = {
      currentUrl: (): string => url,
      engineAlive: (): boolean => true,
      engineTerminal: {
        exitStatus: undefined,
        dispose(): void {
          stopped = true;
          // The terminal closes a tick later, as a real one does, so Restart's wait for it ends.
          setImmediate(() => [...closeListeners].forEach((l) => l(this)));
        },
      },
      startEngine: (): Promise<void> => {
        started = true;
        return Promise.resolve();
      },
    };
    const originals = new Map(SPIED.map((name) => [name, FS_MODULE[name]]));
    // Records and refuses every call, never reaching the real filesystem: a stat of the UNC value
    // would otherwise go to the network on Windows.
    for (const name of SPIED) {
      FS_MODULE[name] = (p: fs.PathLike): boolean => {
        statted.push(`${name} ${String(p)}`);
        if (name === "existsSync") {
          return false;
        }
        throw Object.assign(new Error(`ENOENT: stubbed ${name} '${String(p)}'`), { code: "ENOENT" });
      };
    }
    let pending: Promise<void>;
    try {
      // Every check runs before Restart's first await, so the spies come off once this call returns,
      // before the stop's wait and delay hand the event loop to anything else in the process.
      pending = statusBar.EngineStatusBar.prototype.restartEngine.call(owner as never);
    } finally {
      for (const [name, original] of originals) {
        FS_MODULE[name] = original;
      }
    }
    await pending;
    return { statted, stopped, started };
  }

  test("an untrusted workspace: Restart refuses, and the configured path is never statted", async () => {
    stubTrusted = false;
    const run = await restart(LOOPBACK);

    // Nothing statted at all, so not the configured path either.
    assert.deepStrictEqual(run.statted, [], "Restart touched the filesystem before its trust check");
    assert.deepStrictEqual(notices, [TRUST_REFUSAL]);
    assert.strictEqual(run.stopped, false, "a refused Restart must not stop the engine");
    assert.strictEqual(run.started, false);
  });

  test("a remote target: Restart refuses, and the configured path is never statted", async () => {
    const run = await restart(REMOTE);

    assert.deepStrictEqual(run.statted, [], "Restart touched the filesystem before its target check");
    assert.deepStrictEqual(notices, [REMOTE_REFUSAL]);
    assert.strictEqual(run.stopped, false);
    assert.strictEqual(run.started, false);
  });

  test("control: the same setting, trusted and local, IS statted and refused as no file", async () => {
    const run = await restart(LOOPBACK);

    assert.deepStrictEqual(run.statted, [`statSync ${path.resolve(ws, UNC_SETTING)}`]);
    assert.strictEqual(notices.length, 1, JSON.stringify(notices));
    assert.match(notices[0], /which is not a file in this workspace/);
    assert.strictEqual(run.stopped, false, "the refusal still comes before the stop");
    assert.strictEqual(run.started, false);
  });

  // With the setting unset there is no service config refusal, so only the two refusals stand
  // between a running engine and its stop: a Restart that got past them would act as Stop.
  for (const [what, url, trusted, notice] of [
    ["an untrusted workspace", LOOPBACK, false, TRUST_REFUSAL],
    ["a remote target", REMOTE, true, REMOTE_REFUSAL],
  ] as const) {
    test(`${what}, setting unset: Restart refuses and does not stop the engine`, async () => {
      stubSetting = undefined;
      stubTrusted = trusted;
      const run = await restart(url);

      assert.deepStrictEqual(notices, [notice]);
      assert.strictEqual(run.stopped, false, "a refused Restart must not stop the engine");
      assert.strictEqual(run.started, false);
    });
  }

  test("control: setting unset, trusted and local, Restart stops the engine and starts it again", async () => {
    stubSetting = undefined;
    const run = await restart(LOOPBACK);

    assert.deepStrictEqual(run.statted, []);
    assert.deepStrictEqual(notices, []);
    assert.strictEqual(run.stopped, true);
    assert.strictEqual(run.started, true);
  });
});
