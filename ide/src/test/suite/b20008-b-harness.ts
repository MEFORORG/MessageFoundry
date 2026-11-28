// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// A node-side harness that drives the REAL status bar's Start, Restart and copy-start command against a
// stubbed `vscode`, for b20008-b-start-wiring.test.ts (BACKLOG #5566, #5939) and
// b20008-b-start-trust.test.ts (BACKLOG #5837). Not a test file itself: the mocha glob is *.test.js.
//
// What is faked, and nothing else: the `vscode` API, `child_process.execFile` (the preflight, the
// admin probe and engine trust's `cert inventory`), `https.request` (every engine request fails at once
// with a chosen error code), and, inside {@link captureProbes} only, the re-probe timers
// `scheduleProbes` sets. The workspace is a real temporary folder, so the fork guard and the service
// config check stat real files. Every extension module is loaded fresh against the stub, as
// restart-trust.test.ts does, and the require cache is put back exactly as it was.
import * as fs from "node:fs";
import { EventEmitter } from "node:events";
import * as path from "node:path";

/** The loopback engine every Start here targets. */
export const LOOPBACK = "https://127.0.0.1:8765";

/** The settings' defaults, read from the manifest, so the stub answers what VS Code would. */
const DEFAULTS: Readonly<Record<string, unknown>> = (() => {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(__dirname, "..", "..", "..", "package.json"), "utf8"),
  ) as { contributes: { configuration: { properties: Record<string, { default?: unknown }> } } };
  const out: Record<string, unknown> = {};
  for (const [key, spec] of Object.entries(manifest.contributes.configuration.properties)) {
    out[key.replace(/^messagefoundry\./, "")] = spec.default;
  }
  return out;
})();

type Listener = (e: unknown) => void;
type Callback = (err: unknown, stdout: string, stderr: string) => void;

/** A terminal the stub hands out. `dispose` closes it a tick later, as VS Code does. */
export class FakeTerminal {
  exitStatus: { code: number | undefined } | undefined;
  private closed = false;
  constructor(
    readonly name: string,
    readonly creationOptions: { shellPath?: string; shellArgs?: string[]; cwd?: string },
  ) {}
  show(): void {}
  sendText(): void {}
  /** Close it with `code`, firing onDidCloseTerminal on the next tick. */
  close(code: number | undefined): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.exitStatus = { code };
    setImmediate(() => [...state.closeListeners].forEach((l) => l(this)));
  }
  dispose(): void {
    this.close(undefined);
  }
}

/** Everything the stub records, and the answers it gives. {@link reset} restores it. */
export const state = {
  workspace: undefined as string | undefined,
  trusted: true,
  /** Settings the user set, by key under `messagefoundry.`; an absent key is at its default. */
  settings: new Map<string, unknown>(),
  execCalls: [] as { command: string; args: string[]; cwd: string | undefined }[],
  /** The `--json` error message each admin probe answers with, in turn; empty, an Administrator exists. */
  probeAnswers: [] as string[],
  /** What `cert inventory --json` prints; undefined, it exits 1 with no output. */
  inventory: undefined as unknown,
  terminals: [] as FakeTerminal[],
  warnings: [] as string[],
  notices: [] as string[],
  clipboard: [] as string[],
  commands: new Map<string, (...args: unknown[]) => unknown>(),
  /** Every executeCommand id, in order. Recorded, never dispatched. */
  executed: [] as string[],
  configListeners: new Set<Listener>(),
  closeListeners: new Set<Listener>(),
  /** Each event in order: "request <url>" per engine request, "handler <url>" per trust-handler call. */
  events: [] as string[],
  /** Each engine request with the trust anchor it carried. */
  requests: [] as { url: string; ca: unknown }[],
  /** The error code every engine request fails with. Unreachable by default, with a code whose error
   *  text names no start-command hint: the hint is engine-control.test.ts's subject, and this way a
   *  run against the unfixed engineControlModel.ts never reaches it. */
  requestError: "EHOSTUNREACH",
  /** Status-bar tooltips in the order they were set. */
  tooltips: [] as unknown[],
};

export function reset(): void {
  state.workspace = undefined;
  state.trusted = true;
  state.settings.clear();
  state.execCalls = [];
  state.probeAnswers = [];
  state.inventory = undefined;
  state.terminals = [];
  state.warnings = [];
  state.notices = [];
  state.clipboard = [];
  state.commands.clear();
  state.executed = [];
  state.configListeners.clear();
  state.closeListeners.clear();
  state.events = [];
  state.requests = [];
  state.requestError = "EHOSTUNREACH";
  state.tooltips = [];
}

const disposable = (fn: () => void = () => {}): { dispose(): void } => ({ dispose: fn });

/** Any member is a no-op function: the engine log's output channel. */
const noOps = new Proxy(
  {},
  // Not `then`: a channel answering it would be a thenable that never settles if anything awaited it.
  { get: (_t, key) => (key === "then" ? undefined : () => undefined) },
);

class MarkdownString {
  isTrusted: unknown;
  constructor(readonly value: string = "") {}
}

class ThemeColor {
  constructor(readonly id: string) {}
}

const vscodeStub = {
  StatusBarAlignment: { Left: 1, Right: 2 },
  MarkdownString,
  ThemeColor,
  Uri: { parse: (s: string) => ({ toString: () => s }), file: (p: string) => ({ fsPath: p }) },
  env: {
    clipboard: {
      writeText: (text: string): Promise<void> => {
        state.clipboard.push(text);
        return Promise.resolve();
      },
    },
    openExternal: (): Promise<boolean> => Promise.resolve(true),
  },
  commands: {
    registerCommand: (id: string, fn: (...args: unknown[]) => unknown) => {
      state.commands.set(id, fn);
      return disposable(() => state.commands.delete(id));
    },
    // Recorded, not dispatched: engine trust asks for a re-check after a refresh, and a re-check this
    // harness did not start would race the probes a test runs.
    executeCommand: (id: string): Promise<undefined> => {
      state.executed.push(id);
      return Promise.resolve(undefined);
    },
  },
  workspace: {
    get workspaceFolders(): { uri: { fsPath: string } }[] | undefined {
      return state.workspace === undefined ? undefined : [{ uri: { fsPath: state.workspace } }];
    },
    get isTrusted(): boolean {
      return state.trusted;
    },
    getConfiguration: () => ({
      get: (key: string, fallback?: unknown): unknown =>
        state.settings.has(key) ? state.settings.get(key) : key in DEFAULTS ? DEFAULTS[key] : fallback,
      inspect: (key: string) => ({
        key: `messagefoundry.${key}`,
        defaultValue: DEFAULTS[key],
        globalValue: state.settings.get(key),
      }),
    }),
    onDidChangeConfiguration: (l: Listener) => {
      state.configListeners.add(l);
      return disposable(() => state.configListeners.delete(l));
    },
  },
  window: {
    createStatusBarItem: () => {
      const item: Record<string, unknown> = { show() {}, hide() {}, dispose() {} };
      Object.defineProperty(item, "tooltip", {
        get: () => state.tooltips[state.tooltips.length - 1],
        set: (v: unknown) => void state.tooltips.push(v),
      });
      return item;
    },
    createOutputChannel: () => noOps,
    createTerminal: (opts: { name: string; shellPath?: string; shellArgs?: string[]; cwd?: string }) => {
      const term = new FakeTerminal(opts.name, opts);
      state.terminals.push(term);
      // provision-admin's terminal exits 0 on its own, as one where the user typed a password would.
      if (/provision/i.test(opts.name)) {
        setImmediate(() => term.close(0));
      }
      return term;
    },
    onDidCloseTerminal: (l: Listener) => {
      state.closeListeners.add(l);
      return disposable(() => state.closeListeners.delete(l));
    },
    showInformationMessage: (message: string): Promise<undefined> => {
      state.notices.push(message);
      return Promise.resolve(undefined);
    },
    showErrorMessage: (message: string): Promise<undefined> => {
      state.notices.push(message);
      return Promise.resolve(undefined);
    },
    // Every modal is recorded; one offering "Provision administrator" gets it. A test reads
    // `warnings` to tell which modal that was.
    showWarningMessage: (message: string, ...items: unknown[]): Promise<string | undefined> => {
      state.warnings.push(message);
      return Promise.resolve(items.includes("Provision administrator") ? "Provision administrator" : undefined);
    },
    showInputBox: (opts: { prompt?: string }): Promise<string | undefined> =>
      Promise.resolve(/username/i.test(opts.prompt ?? "") ? "alice" : "alice@example.test"),
    showQuickPick: (): Promise<undefined> => Promise.resolve(undefined),
  },
};

const CHILD = require("node:child_process") as Record<string, unknown>;
const HTTPS = require("node:https") as Record<string, unknown>;

/** The fake `execFile`: the preflight passes, the admin probe answers from `state.probeAnswers`,
 *  `cert inventory` prints `state.inventory`, and anything else exits 1 with no output. */
function fakeExecFile(command: string, args: string[], opts: unknown, maybeCb?: Callback): unknown {
  const cb = (typeof opts === "function" ? opts : maybeCb) as Callback;
  const cwd = typeof opts === "object" && opts !== null ? (opts as { cwd?: string }).cwd : undefined;
  state.execCalls.push({ command, args: [...args], cwd });
  const exit1 = Object.assign(new Error("exit 1"), { code: 1 });
  setImmediate(() => {
    if (args.includes("-c")) {
      cb(null, "", "");
    } else if (args.includes("provision-admin")) {
      cb(exit1, `${JSON.stringify({ error: state.probeAnswers.shift() ?? adminExists() })}\n`, "");
    } else if (args.includes("inventory") && state.inventory !== undefined) {
      cb(null, JSON.stringify(state.inventory), "");
    } else {
      cb(exit1, "", "");
    }
  });
  return { stdin: undefined, kill: () => true, on: () => undefined };
}

/** The fake `https.request`: recorded, then failed with `state.requestError` as a socket error. */
function fakeRequest(url: URL | string, options?: { ca?: unknown }): EventEmitter {
  state.events.push(`request ${String(url)}`);
  state.requests.push({ url: String(url), ca: options?.ca });
  const req = new EventEmitter() as EventEmitter & Record<string, unknown>;
  req.setTimeout = () => req;
  req.write = () => true;
  req.destroy = (err?: unknown) => void (err !== undefined && req.emit("error", err));
  req.end = () =>
    void setImmediate(() =>
      req.emit("error", Object.assign(new Error(`fake ${state.requestError}`), { code: state.requestError })),
    );
  return req;
}

let saved: { execFile: unknown; request: unknown } | undefined;

/** Install the `execFile` and `https.request` fakes; {@link uninstallFakes} puts the real ones back.
 *  A second install before the uninstall is refused, so the fakes can never be saved as the real ones. */
export function installFakes(): void {
  if (saved !== undefined) {
    throw new Error("the harness fakes are already installed");
  }
  saved = { execFile: CHILD.execFile, request: HTTPS.request };
  CHILD.execFile = fakeExecFile;
  HTTPS.request = fakeRequest;
}

export function uninstallFakes(): void {
  if (saved !== undefined) {
    CHILD.execFile = saved.execFile;
    HTTPS.request = saved.request;
    saved = undefined;
  }
}

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

/** The harness runs node-side only; inside the Extension Host the suites using it are skipped. */
export const NODE_SIDE = !insideExtensionHost();

export interface Modules {
  statusBar: typeof import("../../statusBar");
  engineClient: typeof import("../../engineClient");
  engineTrust: typeof import("../../engineTrust");
  engineControlModel: typeof import("../../engineControlModel");
}

/** The extension modules, loaded once against the stub and sharing one engineClient. */
export const mods = {} as Modules;

if (NODE_SIDE) {
  const outDir = path.resolve(__dirname, "..", "..");
  const testDir = path.join(outDir, "test") + path.sep;
  const isExtensionModule = (f: string): boolean => f.startsWith(outDir + path.sep) && !f.startsWith(testDir);
  const cached = new Map(
    Object.keys(require.cache)
      .filter(isExtensionModule)
      .map((f) => [f, require.cache[f]]),
  );
  for (const f of cached.keys()) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    mods.statusBar = require("../../statusBar") as Modules["statusBar"];
    mods.engineClient = require("../../engineClient") as Modules["engineClient"];
    mods.engineTrust = require("../../engineTrust") as Modules["engineTrust"];
    mods.engineControlModel = require("../../engineControlModel") as Modules["engineControlModel"];
  } finally {
    loader._load = realLoad;
    for (const f of Object.keys(require.cache).filter(isExtensionModule)) {
      delete require.cache[f];
    }
    for (const [f, entry] of cached) {
      require.cache[f] = entry;
    }
  }
}

/** The probe answer meaning an enabled Administrator exists, built on the model's own fragment. */
export function adminExists(): string {
  return `refusing: this store ${mods.engineControlModel.ADMIN_EXISTS_REFUSAL}`;
}

/** The probe answer meaning the store needs one, built on the model's own fragment. */
export function noAdmin(): string {
  return `${mods.engineControlModel.NO_TERMINAL_REFUSAL}: stdin is not a terminal`;
}

/** An extension context with no stored token, and the subscriptions it collected. */
export function makeContext(): { ctx: import("vscode").ExtensionContext; dispose(): void } {
  const subscriptions: { dispose(): unknown }[] = [];
  const ctx = {
    subscriptions,
    secrets: {
      get: () => Promise.resolve(undefined),
      store: () => Promise.resolve(),
      delete: () => Promise.resolve(),
      onDidChange: () => disposable(),
    },
  } as unknown as import("vscode").ExtensionContext;
  return { ctx, dispose: () => subscriptions.splice(0).forEach((d) => d.dispose()) };
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Resolve once `cond` holds, or fail after `ms`. */
export async function waitFor(cond: () => boolean, what: string, ms = 3000): Promise<void> {
  const until = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > until) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await sleep(5);
  }
}

/** The bar's in-flight flags {@link idle} waits on. Checked present, so a rename fails loudly
 *  rather than letting every wait return at once. */
const IN_FLIGHT = ["busy", "probing", "verifying"] as const;

/** Resolve once the bar has no re-check, poll or verify in flight. */
export function idle(bar: object): Promise<void> {
  for (const flag of IN_FLIGHT) {
    if (typeof (bar as Record<string, unknown>)[flag] !== "boolean") {
      throw new Error(`EngineStatusBar has no boolean ${flag}; the harness needs updating`);
    }
  }
  const b = bar as Record<(typeof IN_FLIGHT)[number], boolean>;
  return waitFor(() => IN_FLIGHT.every((f) => !b[f]), "the status bar to go idle");
}

/** The delays `scheduleProbes` re-probes after (statusBar.ts). */
const PROBE_DELAYS = [1500, 4000, 8000];

/**
 * Run `fn` with the re-probe timers captured instead of set, and return their callbacks in the order
 * they were set. A timer is captured only when its delay is one of {@link PROBE_DELAYS} AND its
 * callback calls `recheck`, so another timer at one of those delays still runs for real.
 */
export async function captureProbes(fn: () => unknown): Promise<(() => void)[]> {
  const real = globalThis.setTimeout;
  const captured: (() => void)[] = [];
  const fake = (cb: () => void, ms?: number, ...rest: unknown[]): unknown => {
    if (ms !== undefined && PROBE_DELAYS.includes(ms) && /\brecheck\(/.test(String(cb))) {
      captured.push(cb);
      return { ref: () => undefined, unref: () => undefined, hasRef: () => false };
    }
    return (real as (...a: unknown[]) => unknown)(cb, ms, ...rest);
  };
  globalThis.setTimeout = fake as unknown as typeof setTimeout;
  try {
    await fn();
  } finally {
    globalThis.setTimeout = real;
  }
  return captured;
}

/** Fire every settings listener with a change to `messagefoundry.<key>` only. */
export function changeSetting(key: string): void {
  const e = { affectsConfiguration: (s: string) => s === `messagefoundry.${key}` };
  [...state.configListeners].forEach((l) => l(e));
}

/**
 * Tear down what a suite's setup built, in an order that cannot leave the fakes installed: the wait
 * for the bar may fail, and everything after it still runs.
 */
export async function tearDown(bar: object | undefined, ctx: { dispose(): void } | undefined, ws: string | undefined): Promise<void> {
  try {
    if (bar !== undefined) {
      await idle(bar);
    }
  } finally {
    try {
      ctx?.dispose();
    } finally {
      uninstallFakes();
      reset();
      if (ws !== undefined) {
        fs.rmSync(ws, { recursive: true, force: true });
      }
    }
  }
}
