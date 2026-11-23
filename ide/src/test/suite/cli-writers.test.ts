// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The cli.ts writers, writerPathSetting and writerConfigTarget, refuse a path setting whose spelling
// lies inside the workspace folder but whose real path leaves it (BACKLOG #5404), driven here for at
// least configDir, serviceConfig and messageSetsDir. The other suites
// pin their wiring by reading cli.ts's source or drive escapesByLink alone; this one runs the real
// cli.ts against a stubbed `vscode` and a real temporary folder, so it fails on a writer that checks
// the spelling only. The refusals have controls on the same folder that the writer accepts, so a
// refusal cannot pass because the stub was not wired. Node-side only, as new-route-containment.test.ts
// is: the Extension Host resolves the real `vscode`.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { unlinkLinks } from "../unlinkLinks";

type Scope = "globalValue" | "workspaceValue";

let stubWorkspace: string | undefined;
let stubTrusted = true;
/** The values set for each messagefoundry.* key, by scope. */
let settings: Record<string, Partial<Record<Scope, unknown>>>;
let errors: string[];

const DEFAULTS: Readonly<Record<string, string>> = {
  configDir: "samples/config",
  serviceConfig: "messagefoundry.toml",
  messageSetsDir: "samples/messages",
};

const vscodeStub = {
  workspace: {
    get workspaceFolders(): { uri: { fsPath: string } }[] | undefined {
      return stubWorkspace === undefined ? undefined : [{ uri: { fsPath: stubWorkspace } }];
    },
    get isTrusted(): boolean {
      return stubTrusted;
    },
    getConfiguration: () => ({
      get: (key: string, fallback: unknown): unknown =>
        settings[key]?.workspaceValue ?? settings[key]?.globalValue ?? DEFAULTS[key] ?? fallback,
      inspect: (key: string): Record<string, unknown> => ({ defaultValue: DEFAULTS[key], ...settings[key] }),
    }),
  },
  window: {
    showErrorMessage: (text: string): Promise<undefined> => {
      errors.push(text);
      return Promise.resolve(undefined);
    },
    showWarningMessage: (): Promise<undefined> => Promise.resolve(undefined),
  },
};

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

/** True inside the Extension Host, where the REAL `vscode` API resolves. */
function insideExtensionHost(): boolean {
  try {
    const api = realLoad.call(loader, "vscode", module, false) as { version?: unknown; env?: { appName?: unknown } };
    return typeof api?.version === "string" && typeof api?.env?.appName === "string";
  } catch {
    return false;
  }
}

const NODE_SIDE = !insideExtensionHost();
type Cli = typeof import("../../cli");
let cli!: Cli;

if (NODE_SIDE) {
  // Every extension module is loaded fresh against this stub and the cache put back afterwards, as
  // promote-target-gate.test.ts does, so a sibling suite's stubbed copies are unaffected.
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
    cli = require("../../cli") as Cli;
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

const writerSuite = NODE_SIDE ? suite : suite.skip;

writerSuite("cli.ts writers refuse a path setting whose real path leaves the workspace (BACKLOG #5404)", () => {
  let root: string;
  let ws: string;
  let outside: string;

  setup(() => {
    root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-cli-writers-")));
    ws = path.join(root, "ws");
    outside = path.join(root, "outside");
    fs.mkdirSync(path.join(ws, "cfg"), { recursive: true });
    fs.mkdirSync(outside);
    // A junction needs no privilege on Windows; elsewhere the type is ignored and a symlink is made.
    fs.symlinkSync(outside, path.join(ws, "escape"), "junction");
    stubWorkspace = ws;
    stubTrusted = true;
    settings = {};
    errors = [];
  });

  teardown(() => {
    // The links go first: a recursive rmSync can follow a junction into its target (unlinkLinks.ts).
    unlinkLinks(root);
    fs.rmSync(root, { recursive: true, force: true });
  });

  /** The one refusal shown, which must name `key` and not quote `value`; clears the shown errors
   *  for the next call. */
  function refusedNaming(key: string, value?: string): void {
    assert.strictEqual(errors.length, 1, errors.join("\n"));
    assert.ok(errors[0].includes(`messagefoundry.${key}`), errors[0]);
    // The value and the link's target are not quoted back (docs/REVIEW-STANDARDS.md R12).
    assert.ok(!errors[0].includes(outside), errors[0]);
    if (value !== undefined) {
      assert.ok(!errors[0].includes(value), errors[0]);
    }
    errors = [];
  }

  for (const scope of ["globalValue", "workspaceValue"] as const) {
    test(`a ${scope} configDir that is a plain folder inside the workspace is the control`, () => {
      settings.configDir = { [scope]: "cfg" };
      assert.strictEqual(cli.writerPathSetting("configDir"), "cfg");
      assert.deepStrictEqual(errors, []);
    });

    test(`a ${scope} configDir spelled inside the workspace but linked out of it is refused`, () => {
      for (const value of ["escape", "escape/deeper"]) {
        settings.configDir = { [scope]: value };
        assert.strictEqual(cli.writerPathSetting("configDir"), undefined, value);
        refusedNaming("configDir", value);
        assert.strictEqual(cli.writerConfigTarget(), undefined, value);
        refusedNaming("configDir", value);
      }
    });
  }

  test("writerPathSetting refuses a linked serviceConfig and messageSetsDir too, beside a plain control", () => {
    for (const key of ["serviceConfig", "messageSetsDir"] as const) {
      settings[key] = { workspaceValue: "cfg/x" };
      assert.strictEqual(cli.writerPathSetting(key), "cfg/x", key);
      assert.deepStrictEqual(errors, []);
      settings[key] = { workspaceValue: "escape/x" };
      assert.strictEqual(cli.writerPathSetting(key), undefined, key);
      refusedNaming(key, "escape/x");
    }
  });

  test("writerConfigTarget returns both values for a contained config folder and service config", () => {
    settings.configDir = { workspaceValue: "cfg" };
    settings.serviceConfig = { workspaceValue: "cfg/messagefoundry.toml" };
    assert.deepStrictEqual(cli.writerConfigTarget(), { configDir: "cfg", serviceConfig: "cfg/messagefoundry.toml" });
    assert.deepStrictEqual(errors, []);
  });

  test("writerConfigTarget refuses a service config linked out of the workspace, after a clean configDir", () => {
    settings.configDir = { workspaceValue: "cfg" };
    settings.serviceConfig = { workspaceValue: "escape/messagefoundry.toml" };
    assert.strictEqual(cli.writerConfigTarget(), undefined);
    refusedNaming("serviceConfig", "escape/messagefoundry.toml");
  });

  test("a blank serviceConfig checks the file the CLI opens in its place, the workspace's messagefoundry.toml", () => {
    settings.configDir = { workspaceValue: "cfg" };
    settings.serviceConfig = { globalValue: "" };
    // The control: no such file yet, so the fallback lies inside the folder and nothing is sent.
    assert.deepStrictEqual(cli.writerConfigTarget(), { configDir: "cfg", serviceConfig: undefined });
    assert.deepStrictEqual(errors, []);
    fs.symlinkSync(outside, path.join(ws, "messagefoundry.toml"), "junction");
    assert.strictEqual(cli.writerConfigTarget(), undefined);
    refusedNaming("serviceConfig");
  });

  test("the manifest default is checked too, since the repository supplies the link", () => {
    // The control: with nothing set and no link yet, the defaults are accepted.
    assert.deepStrictEqual(cli.writerConfigTarget(), { configDir: "samples/config", serviceConfig: undefined });
    assert.deepStrictEqual(errors, []);
    fs.mkdirSync(path.join(ws, "samples"));
    fs.symlinkSync(outside, path.join(ws, "samples", "config"), "junction");
    assert.strictEqual(cli.writerPathSetting("configDir"), undefined);
    refusedNaming("configDir");
  });

  test("a `..` component is refused even where its spelling stays inside the folder", () => {
    settings.configDir = { workspaceValue: "escape/../cfg" };
    assert.strictEqual(cli.writerPathSetting("configDir"), undefined);
    refusedNaming("configDir", "escape/../cfg");
  });

  (process.platform === "win32" ? test : test.skip)(
    "on Windows, a name the Win32 open reads as another entry or a device is refused",
    () => {
      for (const value of ["escape.", "escape ", "cfg:stream", "nul", "cfg/CON.toml"]) {
        settings.configDir = { workspaceValue: value };
        assert.strictEqual(cli.writerPathSetting("configDir"), undefined, value);
        // A short device name also appears in the refusal's own text, so only the longer values are
        // checked for being quoted back.
        refusedNaming("configDir", ["nul"].includes(value) ? undefined : value);
      }
    },
  );

  test("an untrusted window makes no link check: the writer returns the value and the exec gate is on", () => {
    // isExecGated refuses the writer's CLI call there. A writer that writes without the CLI must
    // refuse an untrusted window itself, as cli.ts writerSetting's doc says; this test does not show it.
    stubTrusted = false;
    settings.configDir = { globalValue: "escape" };
    assert.strictEqual(cli.writerPathSetting("configDir"), "escape");
    assert.ok(cli.isExecGated());
  });

  test("a workspace value spelled outside the folder is refused by its spelling", () => {
    settings.configDir = { workspaceValue: "../outside" };
    assert.strictEqual(cli.writerPathSetting("configDir"), undefined);
    refusedNaming("configDir", "../outside");
  });
});
