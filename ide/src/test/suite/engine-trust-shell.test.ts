// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The SHELL half of engine trust — BACKLOG #1695, review follow-up. `engine-trust.test.ts` covers the
// model; this file covers the COMPOSITION, because both defects below lived there and neither was
// reachable from a model test:
//
//   1. the certificate `messagefoundry.serviceConfig` describes was registered as the trust anchor for
//      whatever `messagefoundry.engineUrl` named, local or not. That setting is a workspace-relative
//      path to the LOCAL engine's TOML, so it describes a DIFFERENT server than a remote target — and
//      `tlsOptions` puts the anchor in `ca`, which REPLACES Node's default root store for that
//      request. A remote engine on a perfectly valid public chain therefore stopped verifying.
//   2. `cert inventory` runs in the WORKSPACE, and the engine passes an operator's relative
//      `[api].tls_cert_file` through unchanged (`plan_api_tls_material`), so `certs/server.pem`
//      arrives verbatim. The extension then opened it against its OWN cwd — inventory reported the
//      certificate present, and the extension silently installed nothing.
//
// It drives the real `refreshEngineTrust` against real files in a temp workspace. Only the two things
// a node-side test cannot have are stubbed: the `vscode` module and the CLI subprocess.
import * as assert from "assert";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";

import { CAFILE_REFUSED_CODE, CAFILE_UNREAD_CODE } from "../../engineTrustModel";

/** What the stubbed `vscode.workspace.getConfiguration("messagefoundry")` answers. */
interface StubConfig {
  engineUrl: string;
  serviceConfig: string;
  environments: unknown[];
}

let stubConfig: StubConfig;
let stubWorkspace: string | undefined;
/** The object the stubbed `messagefoundry cert inventory --json` prints. */
let stubInventory: unknown;
/** Every CLI invocation, so a test can assert WHICH directory the reading was taken in. */
let invocations: { args: string[]; cwd: string | undefined }[];
/** Every line written to the engine log. The log IS the user-facing output of this path. */
let logged: string[];
/** Called with each logged line, so a test can act at a known point inside a running refresh. */
let onLog: ((line: string) => void) | undefined;
type ConfigListener = (e: { affectsConfiguration(section: string): boolean }) => void;
/** The settings-change listener `registerEngineTrust` subscribed last, so a test can fire it. */
let configListener: ConfigListener | undefined;

function log(line: string): void {
  logged.push(line);
  onLog?.(line);
}

const vscodeStub = {
  workspace: {
    get workspaceFolders(): { uri: { fsPath: string } }[] | undefined {
      return stubWorkspace === undefined ? undefined : [{ uri: { fsPath: stubWorkspace } }];
    },
    isTrusted: true,
    getConfiguration: () => ({
      get: (key: string, fallback: unknown): unknown =>
        key in stubConfig ? (stubConfig as unknown as Record<string, unknown>)[key] : fallback,
    }),
    onDidChangeConfiguration: (listener: ConfigListener) => {
      configListener = listener;
      return { dispose: (): void => {} };
    },
  },
  window: {
    createOutputChannel: () => ({
      info: log,
      warn: log,
      error: log,
      show: (): void => {},
      dispose: (): void => {},
    }),
  },
  commands: { executeCommand: (): Promise<undefined> => Promise.resolve(undefined) },
};

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

/**
 * True inside the Extension Host, where the REAL `vscode` API resolves.
 *
 * This suite substitutes the module, and under the Extension Host that substitution would be handed
 * to every module it loads and then SHARED with the rest of the run through the require cache — the
 * integration legs would start testing a stub. `test:unit` runs on every CI leg, so skipping there
 * costs no coverage.
 *
 * IT ASKS FOR THE API, NOT MERELY FOR RESOLUTION, and that is the difference between a control and a
 * hole. "Does `vscode` resolve" answers true for any package of that name — the deprecated `vscode`
 * npm helper, a shim in node_modules, a `mocha --require` — and every one of those would turn all
 * seven tests below pending on BOTH legs with CI still green, which is the silent-skip this suite
 * exists to avoid. `version` and `env.appName` are the real API's and nothing else here supplies
 * them, so a stray package leaves NODE_SIDE true and the tests run.
 */
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

type TrustShell = typeof import("../../engineTrust");
type EngineClient = typeof import("../../engineClient");
type ChildProcess = { execFile: typeof import("node:child_process").execFile };

let trust!: TrustShell;
let engineClient!: EngineClient;
let childProcess!: ChildProcess;
let realExecFile!: typeof import("node:child_process").execFile;

if (NODE_SIDE) {
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    // Required, not imported: an `import` is hoisted above the substitution above and would resolve
    // `vscode` for real (which fails here) before this file's first statement ran.
    trust = require("../../engineTrust") as TrustShell;
    engineClient = require("../../engineClient") as EngineClient;
    childProcess = require("node:child_process") as ChildProcess;
  } finally {
    // The interception ends here, synchronously, before any other suite's hooks run. THE LOADER is
    // restored; what it already loaded is not — `out/cli.js`, `out/engineTrust.js` and
    // `out/engineLog.js` stay bound to the stub in the require cache for the rest of this process.
    // Nothing else under `test:unit` imports them (the two suites that do are in package.json's
    // --ignore list), but a future one would get the stub rather than a failure, so teardown below
    // leaves the stub's state coherent rather than pointing at a deleted directory.
    loader._load = realLoad;
  }
  realExecFile = childProcess.execFile;
}

/** `fs.promises`, whose `open` the round-4 tests intercept to hold a certificate read open. */
const fsPromises = (require("node:fs") as { promises: { open: (...a: unknown[]) => Promise<unknown> } })
  .promises;
const realOpen = fsPromises.open;
/** When set and it returns a promise, that promise stands in for opening the (normalized) file. */
let openHook: ((file: string) => Promise<unknown> | undefined) | undefined;

const shellSuite = NODE_SIDE ? suite : suite.skip;

shellSuite("engine trust — pairing a certificate with a target (BACKLOG #1695)", () => {
  const PEM = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n";
  const LOOPBACK = "https://127.0.0.1:8765";
  const REMOTE = "https://prod.example.com:8765";
  /** What the unanchored-target warning says; both tests that read that warning use it. */
  const UNANCHORED = "with no trust anchor";

  let ws: string;
  /** Releases for reads and CLI runs a round-4 test holds open; teardown calls any left. */
  const held: (() => void)[] = [];

  /** The stubbed CLI: records the call and answers at once with {@link stubInventory}. */
  const answeringCli = ((
    _file: string,
    args: string[],
    options: { cwd?: string },
    done: (err: null, stdout: string, stderr: string) => void,
  ) => {
    invocations.push({ args, cwd: options.cwd });
    done(null, JSON.stringify(stubInventory), "");
    return undefined;
  }) as unknown as typeof childProcess.execFile;

  /** A payload in the shape `cert inventory --service-config … --json` prints. */
  function inventoryFor(cert: string, source: "generated" | "operator"): unknown {
    return { certs: [], api_tls: { scheme: "https", source, cert, cert_present: true } };
  }

  /** Write a PEM into the temp workspace at `relative`, and return its absolute path. */
  function plantCert(relative: string): string {
    const absolute = path.join(ws, relative);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, PEM);
    return absolute;
  }

  setup(() => {
    ws = fs.mkdtempSync(path.join(os.tmpdir(), "mf-engine-trust-"));
    stubWorkspace = ws;
    stubConfig = { engineUrl: LOOPBACK, serviceConfig: "messagefoundry.toml", environments: [] };
    invocations = [];
    logged = [];
    stubInventory = undefined;
    onLog = undefined;
    trust.forgetEngineTrust();
    childProcess.execFile = answeringCli;
    openHook = undefined;
    fsPromises.open = (file: unknown, ...rest: unknown[]): Promise<unknown> =>
      openHook?.(path.normalize(String(file))) ?? realOpen(file, ...rest);
  });

  teardown(async () => {
    onLog = undefined;
    openHook = undefined;
    for (const release of held.splice(0)) {
      release();
    }
    childProcess.execFile = answeringCli;
    // A released CLI child queues its refresh a few callbacks later; let it, then wait it out, so
    // nothing from this test runs into the next one.
    for (let i = 0; i < 10; i++) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    await trust.engineTrustSettled();
    childProcess.execFile = realExecFile;
    fsPromises.open = realOpen;
    trust.forgetEngineTrust();
    fs.rmSync(ws, { recursive: true, force: true });
    // The modules loaded above keep reading this stub. Leaving it pointing at the directory just
    // deleted would hand a later suite a workspace that does not exist; no workspace at all is the
    // state those modules already handle (`refreshEngineTrust` returns at its first guard).
    stubWorkspace = undefined;
  });

  test("the loopback engine's certificate IS anchored — the case this feature exists for", async () => {
    // The control for every narrowing below: if this stops passing, the fix broke the self-signed
    // local engine that BACKLOG #1695 exists to reach.
    stubInventory = inventoryFor(plantCert(path.join("state", "api-cert.pem")), "generated");

    assert.strictEqual(await trust.refreshEngineTrust(), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("a LOCAL certificate is never anchored for a REMOTE engine", async () => {
    stubInventory = inventoryFor(plantCert(path.join("state", "api-cert.pem")), "generated");
    stubConfig.engineUrl = REMOTE;
    const anchored = await trust.refreshEngineTrust();

    assert.strictEqual(
      engineClient.tlsOptions(new URL(REMOTE)).ca,
      undefined,
      "the workspace's own engine certificate was registered as the trust anchor for an unrelated " +
        "remote host — `ca` replaces Node's default root store, so a remote engine holding a valid " +
        "public chain stops verifying",
    );
    assert.strictEqual(anchored, false, "nothing was anchored, so there is nothing to re-probe");
  });

  test("an operator chain is refused for a remote target too, not just the minted pair", async () => {
    // `source` does not enter the decision — what disqualifies the file is that `serviceConfig`
    // describes the LOCAL engine, whichever way that engine got its certificate.
    stubInventory = inventoryFor(plantCert(path.join("certs", "chain.pem")), "operator");
    stubConfig.engineUrl = REMOTE;
    const anchored = await trust.refreshEngineTrust();

    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined);
    assert.strictEqual(anchored, false);
  });

  test("a RELATIVE certificate path is read from the workspace, not the extension host's cwd", async () => {
    plantCert(path.join("certs", "server.pem"));
    stubInventory = inventoryFor("certs/server.pem", "operator");

    // ARM THE CONTROL. This test proves nothing if the host process's own cwd happens to hold the
    // same relative path — the unresolved read would then succeed for the wrong reason.
    assert.ok(
      !fs.existsSync(path.resolve("certs", "server.pem")),
      "the process cwd holds certs/server.pem, so this test would pass without resolving anything",
    );

    const anchored = await trust.refreshEngineTrust();

    assert.strictEqual(
      engineClient.tlsOptions(new URL(LOOPBACK)).ca,
      PEM,
      "the relative path was opened against the extension host's own cwd, so the certificate the " +
        "engine reported PRESENT was never installed and the request still fails unverified",
    );
    assert.strictEqual(anchored, true);
    assert.strictEqual(
      invocations[0]?.cwd,
      ws,
      "the reading was not taken in the workspace, so resolving against it would be a guess",
    );
  });

  test("an ABSOLUTE path outside the workspace is used as given", async () => {
    // The generated pair lands beside `[store].path`, which need not be under the workspace at all.
    // Resolving must not rewrite a path that is already absolute.
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "mf-engine-state-"));
    try {
      const cert = path.join(stateDir, "api-generated-cert.pem");
      fs.writeFileSync(cert, PEM);
      stubInventory = inventoryFor(cert, "generated");

      assert.strictEqual(await trust.refreshEngineTrust(), true);
      assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  test("a path that resolves to nothing anchors nothing, rather than half-configuring the client", async () => {
    stubInventory = inventoryFor("certs/absent.pem", "operator");

    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);
  });

  test("an older engine, answering with no api_tls key, anchors nothing and does not throw", async () => {
    stubInventory = { certs: [] };

    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);
  });

  test("a loopback target is never told its address is not loopback", async () => {
    // The remote explanation is keyed on the REASON the model declined, not on "no PEM came back".
    // Keyed on the latter, an unreadable certificate on a loopback engine printed `could not read
    // the engine certificate …` and then, immediately after it, `https://127.0.0.1:8765 is not a
    // loopback address` — two contradictory lines, the second sending the user to install a CA for a
    // self-signed leaf sitting on their own machine.
    stubInventory = inventoryFor("certs/absent.pem", "operator");

    await trust.refreshEngineTrust();

    assert.ok(
      logged.some((line) => line.includes("could not read the engine certificate")),
      `nothing reported the unreadable file, so this test proves nothing: ${JSON.stringify(logged)}`,
    );
    assert.ok(
      !logged.some((line) => line.includes("not a loopback address")),
      `a loopback URL was reported as non-loopback: ${JSON.stringify(logged)}`,
    );
  });

  test("a remote target IS told why its certificate was not taken — the control for the test above", async () => {
    stubInventory = inventoryFor(plantCert(path.join("state", "api-cert.pem")), "generated");
    stubConfig.engineUrl = REMOTE;

    await trust.refreshEngineTrust();

    assert.ok(
      logged.some((line) => line.includes(`${REMOTE} is not a loopback address`)),
      `the branch never fired, so the test above passes for the wrong reason: ${JSON.stringify(logged)}`,
    );
  });

  test("a readable file that is not a certificate is refused, not reported as trusted", async () => {
    // Node's tls.createSecureContext reads a FALSY `ca` as "use the default roots", so an empty file
    // would register an anchor that does nothing while the log claimed the engine was trusted and
    // the status bar re-probed on the strength of it.
    const empty = path.join(ws, "certs", "empty.pem");
    fs.mkdirSync(path.dirname(empty), { recursive: true });
    fs.writeFileSync(empty, "");
    stubInventory = inventoryFor(empty, "operator");

    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);
    assert.ok(
      !logged.some((line) => line.includes("trusting the engine certificate")),
      `reported success for a file with no certificate in it: ${JSON.stringify(logged)}`,
    );
  });

  test("dropping a live anchor counts as a change, so the stale verdict gets re-probed", async () => {
    // Retargeting from the loopback engine to a remote one registers nothing, but it DOES clear what
    // the client trusted a moment ago. Reporting "nothing happened" there leaves the status bar on
    // its previous verdict until the next 15-second poll.
    stubInventory = inventoryFor(plantCert(path.join("state", "api-cert.pem")), "generated");
    assert.strictEqual(await trust.refreshEngineTrust(), true);

    stubConfig.engineUrl = REMOTE;
    assert.strictEqual(await trust.refreshEngineTrust(), true, "the drop was reported as a no-op");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);

    // The control: with nothing left to drop, a second remote refresh really is a no-op.
    assert.strictEqual(await trust.refreshEngineTrust(), false);
  });

  // ---- residual (a): an explicit per-target caFile in messagefoundry.environments ----

  const RENEWED = "-----BEGIN CERTIFICATE-----\nrenewed\n-----END CERTIFICATE-----\n";

  /** Let every background refresh finish, a late follow-up included. */
  function settle(): Promise<void> {
    return trust.engineTrustSettled();
  }

  test("a caFile pins a REMOTE environment target — the case serviceConfig cannot cover", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.engineUrl = REMOTE;
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];

    assert.strictEqual(await trust.refreshEngineTrust(), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);
    assert.ok(
      !logged.some((line) => line.includes(UNANCHORED)),
      `a pinned target was reported unanchored: ${JSON.stringify(logged)}`,
    );
  });

  test("a pin applies with no workspace open, and spawns nothing", async () => {
    // The setting is machine-scoped, so the file is the machine user's choice; the CLI and the
    // workspace guard that protects it have nothing to do with it.
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    stubWorkspace = undefined;

    assert.strictEqual(await trust.refreshEngineTrust(), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);
    assert.strictEqual(invocations.length, 0);
  });

  test("a RELATIVE caFile is refused and logged, even when the file exists in the workspace", async () => {
    plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile: "pki/prod-ca.pem" }];

    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined);
    assert.ok(
      logged.some((line) => line.includes(`not pinning ${REMOTE}`)),
      `the refusal was silent: ${JSON.stringify(logged)}`,
    );
  });

  test("a target with no caFile is named in the log as unanchored", async () => {
    stubConfig.environments = [{ name: "PROD", url: REMOTE }];

    await trust.refreshEngineTrust();

    assert.ok(
      // The fragment carries the URL rather than testing a bare URL substring on its own, which
      // CodeQL reads as incomplete URL sanitization (alert 298).
      logged.some((line) => line.includes(`${UNANCHORED} (${REMOTE}`)),
      `an unanchored target went unreported: ${JSON.stringify(logged)}`,
    );
  });

  test("a caFile for the loopback engine wins over the certificate serviceConfig names", async () => {
    stubInventory = inventoryFor(plantCert(path.join("state", "api-cert.pem")), "generated");
    const caFile = path.join(ws, "pki", "local-ca.pem");
    fs.mkdirSync(path.dirname(caFile), { recursive: true });
    fs.writeFileSync(caFile, RENEWED);
    stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile }];

    await trust.refreshEngineTrust();

    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, RENEWED);
    assert.strictEqual(invocations.length, 1, "the CLI still runs, for its scheme check");
  });

  // ---- residual (c): following a certificate the engine renewed ----

  test("a renewed certificate in the same file is followed without spawning the CLI", async () => {
    const cert = plantCert(path.join("state", "api-cert.pem"));
    stubInventory = inventoryFor(cert, "generated");
    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);

    fs.writeFileSync(cert, RENEWED); // the engine renews at startup, into the same file
    const spawned = invocations.length;

    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, PEM), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, RENEWED);
    assert.strictEqual(invocations.length, spawned, "a re-read of a known file must not spawn");
  });

  test("a renewed caFile is followed for a remote target too", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();

    fs.writeFileSync(caFile, RENEWED);

    assert.strictEqual(await trust.followCertificateChange(REMOTE, PEM), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, RENEWED);
  });

  test("an unchanged file is not a reason to retry — the control", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();

    assert.strictEqual(await trust.followCertificateChange(REMOTE, PEM), false);
    assert.strictEqual(invocations.length, 1, "a remote target must never fall back to the CLI");
  });

  test("an engine that minted its certificate after the window opened is picked up, rate-limited", async () => {
    // The first-run gap: at activation the engine had not run, so there was nothing to anchor.
    stubInventory = {
      api_tls: { scheme: "https", source: "generated", cert: "/nowhere.pem", cert_present: false },
    };
    assert.strictEqual(await trust.refreshEngineTrust(), false);

    stubInventory = inventoryFor(plantCert(path.join("state", "api-cert.pem")), "generated");
    // The refresh runs in the BACKGROUND: it spawns a CLI that may run for up to its own timeout, and
    // a request awaiting it would stop honouring its own. So this request is not retried; the anchor
    // lands shortly after.
    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, undefined), false);
    await settle();
    assert.strictEqual(invocations.length, 2, "the background refresh never ran");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);

    // The rate limit: a second failure straight away does not spawn the CLI again.
    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, PEM), false);
    await settle();
    assert.strictEqual(invocations.length, 2);
  });

  test("a caFile that is not a regular file is refused, not read", async () => {
    // A directory, which any reader refuses. The POSIX test below holds the cases that matter.
    const dir = path.join(ws, "pki");
    fs.mkdirSync(dir, { recursive: true });
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile: dir }];

    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined);
    assert.ok(
      logged.some((line) => line.includes("could not read") && line.includes(`not pinning ${REMOTE}`)),
      `the refusal was silent: ${JSON.stringify(logged)}`,
    );
  });

  test("a loopback engineUrl claimed by a REFUSED caFile never spawns the CLI on failure", async () => {
    // The claim keeps the serviceConfig certificate off that host, so a CLI refresh can never anchor
    // it; spawning one a minute would be a loop with no possible success.
    stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile: "relative/ca.pem" }];
    await trust.refreshEngineTrust();
    const spawned = invocations.length;

    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, undefined), false);
    await settle();
    assert.strictEqual(invocations.length, spawned);
  });

  test("a loopback target that is not engineUrl's host never spawns the CLI", async () => {
    // The CLI anchors only engineUrl's host:port, so for this target a spawn could never succeed and
    // would repeat once a minute for the life of the window.
    stubConfig.environments = [{ name: "LOCAL", url: "https://localhost:8765" }];
    await trust.refreshEngineTrust();
    const spawned = invocations.length;

    assert.strictEqual(await trust.followCertificateChange("https://localhost:8765", undefined), false);
    await settle();
    assert.strictEqual(invocations.length, spawned);
  });

  test("a caFile unreadable at refresh time is read when a request to it fails", async () => {
    const caFile = path.join(ws, "pki", "late-ca.pem"); // e.g. a share not mounted at activation
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined);

    plantCert(path.join("pki", "late-ca.pem"));

    assert.strictEqual(await trust.followCertificateChange(REMOTE, undefined), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);
  });

  test("an unusable loopback caFile leaves NO anchor rather than the serviceConfig certificate", async () => {
    // The user pinned this host so a workspace-chosen file would not decide it.
    stubInventory = inventoryFor(plantCert(path.join("state", "api-cert.pem")), "generated");
    stubConfig.environments = [
      { name: "LOCAL", url: LOOPBACK, caFile: path.join(ws, "pki", "missing.pem") },
    ];

    await trust.refreshEngineTrust();

    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);
    // The control: drop the caFile and the same inventory anchors the loopback engine.
    stubConfig.environments = [];
    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("a refresh keeps the previous anchors in force while the CLI runs", async () => {
    stubInventory = inventoryFor(plantCert(path.join("state", "api-cert.pem")), "generated");
    await trust.refreshEngineTrust();

    let caDuringCli: unknown = "not observed";
    const answer = childProcess.execFile;
    childProcess.execFile = ((...args: unknown[]) => {
      caDuringCli = engineClient.tlsOptions(new URL(LOOPBACK)).ca;
      return (answer as (...a: unknown[]) => unknown)(...args);
    }) as unknown as typeof childProcess.execFile;
    await trust.refreshEngineTrust();

    assert.strictEqual(caDuringCli, PEM, "the anchor was dropped while the subprocess ran");
  });

  test("a pinned LOOPBACK target whose file is unchanged never falls back to the CLI", async () => {
    // The pin wins over the CLI's answer, so asking the engine again could change nothing.
    const caFile = plantCert(path.join("pki", "local-ca.pem"));
    stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile }];
    await trust.refreshEngineTrust();
    const spawned = invocations.length;

    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, PEM), false);
    assert.strictEqual(invocations.length, spawned);
  });

  test("an unpinned remote target follows nothing and spawns nothing", async () => {
    assert.strictEqual(await trust.followCertificateChange(REMOTE, undefined), false);
    assert.strictEqual(invocations.length, 0);
  });

  // ---- round 3: the refresh gate, the CLI timeout, and the http claim ----

  /** An engine that has not minted its certificate yet. */
  const NO_CERT_YET = {
    api_tls: { scheme: "https", source: "generated", cert: "/nowhere.pem", cert_present: false },
  };

  /** An engine that has minted its certificate: plant it and answer with it. */
  function plantedEngine(): unknown {
    return inventoryFor(plantCert(path.join("state", "api-cert.pem")), "generated");
  }

  /** The answering CLI, running `before` first, while the CLI is still "running". */
  function cliThatFirst(before: () => void): typeof childProcess.execFile {
    return ((...args: unknown[]) => {
      before();
      return (answeringCli as (...a: unknown[]) => unknown)(...args);
    }) as unknown as typeof childProcess.execFile;
  }

  test(
    "a caFile naming /dev/zero or a FIFO is refused without hanging",
    async function () {
      if (process.platform === "win32") {
        this.skip(); // neither exists there; the directory case above is what Windows can run
      }
      // fstat reports size 0 for both, so a reader that trusts the size reads /dev/zero forever, and
      // a blocking open of a FIFO waits for a writer that never comes. Mocha's timeout is the bound.
      const fifo = path.join(ws, "pki.fifo");
      (require("node:child_process") as typeof import("node:child_process")).execFileSync("mkfifo", [
        fifo,
      ]);
      for (const caFile of ["/dev/zero", fifo]) {
        logged = [];
        stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
        assert.strictEqual(await trust.refreshEngineTrust(), false, caFile);
        assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined, caFile);
        assert.ok(
          logged.some((line) => line.includes(`could not read the engine certificate at ${caFile}`)),
          `${caFile}: the refusal was silent: ${JSON.stringify(logged)}`,
        );
      }
    },
  );

  test("a CLI that never answers is killed at a timeout, and later refreshes still run", async () => {
    let hung: ((err: Error, stdout: string, stderr: string) => void) | undefined;
    let timeout: unknown;
    childProcess.execFile = ((
      _file: string,
      args: string[],
      options: { cwd?: string; timeout?: number },
      done: (err: Error, stdout: string, stderr: string) => void,
    ) => {
      invocations.push({ args, cwd: options.cwd });
      timeout = options.timeout;
      hung = done;
      return undefined;
    }) as unknown as typeof childProcess.execFile;

    const first = trust.refreshEngineTrust();
    for (let i = 0; i < 5 && hung === undefined; i++) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.ok(hung !== undefined, "the refresh never reached the CLI");
    try {
      assert.ok(
        typeof timeout === "number" && timeout > 0 && timeout <= 60_000,
        `cert inventory runs with no bounded timeout (${String(timeout)}), so one hung run stalls ` +
          `every refresh queued behind it`,
      );
    } finally {
      // What Node's execFile reports when its timeout kills the child. In `finally`, so a failed
      // assertion above does not leave this refresh hung under every later test.
      hung(Object.assign(new Error("killed"), { killed: true, signal: "SIGTERM" }), "", "");
    }
    assert.strictEqual(await first, false);

    // The count is back to 0, so a failure starts a refresh, and that one anchors the engine.
    childProcess.execFile = answeringCli;
    stubInventory = plantedEngine();
    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, undefined), false);
    await settle();
    assert.strictEqual(invocations.length, 2, "the failure-started refresh never ran");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  /** A remote pin, so the refresh reads a file AFTER its CLI answered and logs that it did. */
  function remotePinLoggedAfterTheCli(): string {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    return `trusting ${caFile} for ${REMOTE}`;
  }

  test("a failure after the refresh's CLI answered runs one more refresh when it finishes", async () => {
    // The pending refresh asked the engine before the certificate existed, so it cannot pick it up.
    stubInventory = NO_CERT_YET;
    const marker = remotePinLoggedAfterTheCli();
    onLog = (line): void => {
      if (line.includes(marker) && invocations.length === 1) {
        // The engine mints its certificate now, after its CLI answered, and a request fails.
        stubInventory = plantedEngine();
        void trust.followCertificateChange(LOOPBACK, undefined);
      }
    };

    await trust.refreshEngineTrust();
    await settle();

    assert.strictEqual(invocations.length, 2, "the late failure was dropped");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("a failure the refresh itself fixes runs no follow-up — the control", async () => {
    const planted = plantedEngine();
    childProcess.execFile = cliThatFirst(() => {
      // While the CLI runs: the failure is noted, and the answer below already has the certificate.
      void trust.followCertificateChange(LOOPBACK, undefined);
      stubInventory = planted;
    });

    await trust.refreshEngineTrust();
    await settle();

    assert.strictEqual(invocations.length, 1, "a refresh that fixed the cause ran again anyway");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("a failure while the CLI runs is followed up when that refresh does not fix it", async () => {
    // The CLI reads the engine's state partway through its run, so a certificate minted after that
    // read and before the answer is invisible to it.
    stubInventory = NO_CERT_YET;
    // The failure arrives AFTER the spawn returned, while the child is running, and the CLI answers
    // after it: delivering it inside execFile would run it before the refresh records the child.
    stubCli((done) => {
      const first = invocations.length === 1;
      setImmediate(() => {
        if (first) {
          void trust.followCertificateChange(LOOPBACK, undefined);
        }
        setImmediate(() => done(null, JSON.stringify(stubInventory), ""));
      });
    });

    await trust.refreshEngineTrust();
    await settle();

    assert.strictEqual(invocations.length, 2, "the failure during the CLI run was dropped");
  });

  test("a refresh does not undo a rotation a request followed while it was reading", async () => {
    const cert = plantCert(path.join("state", "api-cert.pem"));
    stubInventory = inventoryFor(cert, "generated");
    // Pins read after the engine's file, so the request's one read finishes before this refresh
    // commits; that is the order in which an older read could overwrite a newer one.
    stubConfig.environments = Array.from({ length: 20 }, (_, i) => ({
      name: `E${i}`,
      url: `https://h${i}.example.com:8765`,
      caFile: plantCert(path.join("pki", `ca-${i}.pem`)),
    }));
    await trust.refreshEngineTrust();

    let followed: Promise<boolean> | undefined;
    onLog = (line): void => {
      if (followed === undefined && line.includes(`trusting the engine certificate at ${cert}`)) {
        // This refresh has read PEM. The engine renews now, and a request fails and follows it.
        fs.writeFileSync(cert, RENEWED);
        followed = trust.followCertificateChange(LOOPBACK, PEM);
      }
    };
    await trust.refreshEngineTrust();
    assert.ok(followed !== undefined, "the follow never ran, so this test proves nothing");
    assert.strictEqual(await followed, true);
    await settle();

    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, RENEWED);
  });

  test("late failures run one follow-up, never a chain", async () => {
    // The engine never mints: each refresh, the follow-up included, sees a failure after its CLI.
    stubInventory = NO_CERT_YET;
    const marker = remotePinLoggedAfterTheCli();
    onLog = (line): void => {
      if (line.includes(marker)) {
        void trust.followCertificateChange(LOOPBACK, undefined);
      }
    };

    await trust.refreshEngineTrust();
    await settle();

    assert.strictEqual(invocations.length, 2);
  });

  test("a failed re-read still retries when a refresh registered a different anchor meanwhile", async () => {
    const cert = plantCert(path.join("state", "api-cert.pem"));
    stubInventory = inventoryFor(cert, "generated");
    await trust.refreshEngineTrust();
    fs.rmSync(cert); // mid-rewrite: the re-read fails

    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, RENEWED), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
    // The control: the request carried what is registered, so there is nothing new to retry with.
    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, PEM), false);
  });

  test("a caFile rotated while the CLI runs is not overwritten by an older read", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    childProcess.execFile = cliThatFirst(() => fs.writeFileSync(caFile, RENEWED));

    await trust.refreshEngineTrust();

    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, RENEWED);
  });

  test("a refresh whose own read failed keeps a renewal a request read after it", async () => {
    const cert = plantCert(path.join("state", "api-cert.pem"));
    stubInventory = inventoryFor(cert, "generated");
    stubConfig.environments = Array.from({ length: 20 }, (_, i) => ({
      name: `E${i}`,
      url: `https://h${i}.example.com:8765`,
      caFile: plantCert(path.join("pki", `ca-${i}.pem`)),
    }));
    await trust.refreshEngineTrust();

    // The engine is mid-renewal when this refresh reads: the file holds no certificate yet.
    childProcess.execFile = cliThatFirst(() => fs.writeFileSync(cert, "partial"));
    let followed: Promise<boolean> | undefined;
    onLog = (line): void => {
      if (followed === undefined && line.includes(`${cert} is not PEM`)) {
        fs.writeFileSync(cert, RENEWED); // the renewal completes; a request fails and follows it
        followed = trust.followCertificateChange(LOOPBACK, PEM);
      }
    };
    await trust.refreshEngineTrust();
    assert.ok(followed !== undefined, "the refresh's read did not fail, so this test proves nothing");
    assert.strictEqual(await followed, true);
    await settle();

    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, RENEWED);
  });

  test("a caFile on an http:// entry does not take the anchor from an https engineUrl", async () => {
    // Host keys carry no scheme, so a claim from the http entry would land on the https engine.
    stubInventory = plantedEngine();
    const caFile = plantCert(path.join("pki", "dev-ca.pem"));
    stubConfig.environments = [{ name: "DEV", url: "http://127.0.0.1:8765", caFile }];

    await trust.refreshEngineTrust();

    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
    assert.ok(
      logged.some((line) => line.includes("caFile applies only to an https:// url")),
      `the http entry's caFile was not refused: ${JSON.stringify(logged)}`,
    );
  });

  test("nor does it stop a failure from asking the CLI again", async () => {
    stubInventory = NO_CERT_YET;
    stubConfig.environments = [
      { name: "DEV", url: "http://127.0.0.1:8765", caFile: plantCert(path.join("pki", "dev-ca.pem")) },
    ];
    await trust.refreshEngineTrust();
    stubInventory = plantedEngine();

    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, undefined), false);
    await settle();

    assert.strictEqual(invocations.length, 2);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  // ---- round 4: one merge rule per host key. A refresh ends each key in exactly one of three
  // ways: a certificate it read (fresh), no source naming it any more (dropped), or an answer that
  // proves nothing (kept, as registered at commit time). ----

  /** Let queued callbacks run, so a refresh queued from one is counted before {@link settle}. */
  async function ticks(): Promise<void> {
    for (let i = 0; i < 10; i++) {
      await new Promise((resolve) => setImmediate(resolve));
    }
  }

  /** Hold every read of `files` open until teardown; returns how many opens each one saw, and the
   *  most that were held at once. */
  function holdReads(files: readonly string[]): { opens: Map<string, number>; most: () => number } {
    const wanted = new Set(files.map((f) => path.normalize(f)));
    const opens = new Map<string, number>();
    let running = 0;
    let most = 0;
    openHook = (file) => {
      if (!wanted.has(file)) {
        return undefined;
      }
      opens.set(file, (opens.get(file) ?? 0) + 1);
      most = Math.max(most, ++running);
      return new Promise((_resolve, reject) => {
        held.push(() => {
          running--;
          reject(new Error("EHOSTDOWN"));
        });
      });
    };
    return { opens, most: () => most };
  }

  type Done = (err: Error | null, stdout: string, stderr: string) => void;

  /** A stubbed CLI that records each call and hands its completion callback to `onCall`. */
  function stubCli(onCall: (done: Done) => void): void {
    childProcess.execFile = ((
      _file: string,
      args: string[],
      options: { cwd?: string },
      done: Done,
    ) => {
      invocations.push({ args, cwd: options.cwd });
      onCall(done);
      return undefined;
    }) as unknown as typeof childProcess.execFile;
  }

  /** A CLI that does not answer until the returned function (or teardown) is called; it then fails,
   *  once. */
  function hungCli(): () => void {
    let answer: (() => void) | undefined;
    stubCli((done) => {
      answer = () => done(Object.assign(new Error("killed"), { killed: true }), "", "");
      held.push(answer);
    });
    return () => {
      const release = answer;
      answer = undefined;
      if (release !== undefined) {
        const at = held.indexOf(release);
        if (at >= 0) {
          held.splice(at, 1);
        }
        release();
      }
    };
  }

  test("pin, fresh: a caFile read again replaces the anchor", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();
    fs.writeFileSync(caFile, RENEWED);

    assert.strictEqual(await trust.refreshEngineTrust(), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, RENEWED);
  });

  test("pin, dropped: a caFile removed from the setting takes its anchor with it", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();

    stubConfig.environments = [{ name: "PROD", url: REMOTE }];
    assert.strictEqual(await trust.refreshEngineTrust(), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined);
  });

  test("pin, kept: a caFile read slower than the refresh allows keeps the anchor read before", async () => {
    // Dropping it would put a pinned host back on the default roots, which trust more than the pin.
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();
    trust.setEngineTrustLimitsForTest({ refreshReadMs: 50 });
    holdReads([caFile]);

    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);
    assert.ok(
      logged.some((line) => line.includes(`keeping the certificate read earlier from ${caFile}`)),
      `the keep was silent: ${JSON.stringify(logged)}`,
    );
  });

  test("pin, kept: an unreadable caFile keeps its earlier read, but never another file's", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();
    fs.rmSync(caFile); // a share that dropped, or a rotation caught mid-write

    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);

    // The control: the user pointed the pin at a different file, so the old read no longer applies.
    const other = path.join(ws, "pki", "new.pem");
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile: other }];
    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined);
  });

  test("CLI, fresh: a certificate the CLI now names elsewhere replaces the anchor", async () => {
    stubInventory = plantedEngine();
    await trust.refreshEngineTrust();
    const moved = path.join(ws, "state2", "api-cert.pem");
    fs.mkdirSync(path.dirname(moved), { recursive: true });
    fs.writeFileSync(moved, RENEWED);
    stubInventory = inventoryFor(moved, "generated");

    assert.strictEqual(await trust.refreshEngineTrust(), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, RENEWED);
  });

  test("CLI, dropped: a CLI that answers with no certificate drops the loopback anchor", async () => {
    stubInventory = plantedEngine();
    await trust.refreshEngineTrust();
    stubInventory = NO_CERT_YET;

    assert.strictEqual(await trust.refreshEngineTrust(), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);
  });

  test("CLI, kept: a CLI that does not answer in time keeps the loopback anchor", async () => {
    stubInventory = plantedEngine();
    await trust.refreshEngineTrust();
    trust.setEngineTrustLimitsForTest({ cliAnswerMs: 50 });
    hungCli();

    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("CLI, kept: only the CLI's own anchor — a removed loopback pin is not kept by a silent CLI", async () => {
    const caFile = plantCert(path.join("pki", "local-ca.pem"));
    stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile }];
    await trust.refreshEngineTrust();
    stubConfig.environments = [];
    trust.setEngineTrustLimitsForTest({ cliAnswerMs: 50 });
    hungCli();

    assert.strictEqual(await trust.refreshEngineTrust(), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);
  });

  test("CLI, kept: a CLI that fails keeps the loopback anchor", async () => {
    stubInventory = plantedEngine();
    await trust.refreshEngineTrust();
    stubCli((done) => done(Object.assign(new Error("exit 2"), { code: 2 }), "", ""));

    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(invocations.length, 2, "the failing CLI never ran");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("CLI, kept: a certificate read that does not finish keeps the loopback anchor", async () => {
    const cert = plantCert(path.join("state", "api-cert.pem"));
    stubInventory = inventoryFor(cert, "generated");
    await trust.refreshEngineTrust();
    trust.setEngineTrustLimitsForTest({ refreshReadMs: 50 });
    holdReads([cert]);

    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("CLI, kept: a skipped CLI keeps the anchor, and the child's exit applies a setting changed meanwhile", async () => {
    stubInventory = plantedEngine();
    await trust.refreshEngineTrust();
    trust.setEngineTrustLimitsForTest({ cliAnswerMs: 50 });
    const exit = hungCli();
    await trust.refreshEngineTrust(); // gives up on the child, which stays alive

    // The user points serviceConfig at another TOML while that child is still alive.
    const moved = path.join(ws, "other", "api-cert.pem");
    fs.mkdirSync(path.dirname(moved), { recursive: true });
    fs.writeFileSync(moved, RENEWED);
    stubConfig.serviceConfig = "other.toml";
    stubInventory = inventoryFor(moved, "generated");
    await trust.refreshEngineTrust();
    assert.strictEqual(invocations.length, 2, "a second CLI started beside the live one");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM, "the skip dropped the anchor");

    childProcess.execFile = answeringCli;
    exit();
    await ticks();
    await settle();

    assert.strictEqual(invocations.length, 3, "the child's exit queued no refresh");
    assert.ok(invocations[2].args.includes("other.toml"), JSON.stringify(invocations[2].args));
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, RENEWED);
  });

  test("a failure while an abandoned CLI child is alive waits for its exit, then asks", async () => {
    stubInventory = NO_CERT_YET;
    trust.setEngineTrustLimitsForTest({ cliAnswerMs: 50 });
    const exit = hungCli();
    await trust.refreshEngineTrust(); // gives up on the child, which stays alive
    const before = logged.length;

    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, undefined), false);
    await ticks();
    await settle();
    const skipped = logged.slice(before).filter((line) => line.includes("has not exited"));
    assert.deepStrictEqual(skipped, [], "a refresh started only to skip the CLI");

    // The engine minted its certificate meanwhile; the child's exit asks again and picks it up.
    stubInventory = plantedEngine();
    childProcess.execFile = answeringCli;
    exit();
    await ticks();
    await settle();
    assert.strictEqual(invocations.length, 2, "the child's exit did not ask for the failure");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("pin, dropped: a caFile replaced by something that is not a certificate drops the anchor", async () => {
    // Replaced (DER, anything else) is an answer, not a failure: keeping the old certificate would go
    // on trusting a CA the user just took away.
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();

    // The control: EMPTY is what a file rewritten in place looks like mid-write, so it proves nothing.
    fs.writeFileSync(caFile, "");
    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);

    fs.writeFileSync(caFile, Buffer.from([0x30, 0x82, 0x01, 0x0a])); // the start of a DER certificate
    assert.strictEqual(await trust.refreshEngineTrust(), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined);
  });

  /**
   * A refresh whose pin read is held open while a request follows a renewal of the engine's file,
   * so the follow registers BEFORE the refresh commits. `cliFileFirst` is what the refresh's own
   * read of the engine's file sees.
   */
  async function followDuringRefresh(cliFileFirst: string): Promise<void> {
    const cert = plantCert(path.join("state", "api-cert.pem"));
    stubInventory = inventoryFor(cert, "generated");
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();

    let followed: Promise<boolean> | undefined;
    // Resolves when the refresh's own read of the engine's file has closed it, so the follow below
    // starts a read of its own rather than joining that one (a timer here was flaky on a slow runner).
    let certClosed!: () => void;
    const certRead = new Promise<void>((resolve) => (certClosed = resolve));
    childProcess.execFile = cliThatFirst(() => fs.writeFileSync(cert, cliFileFirst));
    openHook = (file) => {
      if (file === path.normalize(cert)) {
        return realOpen(file).then((opened) => {
          const handle = opened as { close: () => Promise<void> };
          const close = handle.close.bind(handle);
          handle.close = () => close().finally(certClosed);
          return handle;
        });
      }
      if (file !== path.normalize(caFile) || followed !== undefined) {
        return undefined;
      }
      followed = (async () => {
        await certRead;
        await new Promise((resolve) => setImmediate(resolve)); // let that read leave the in-flight map
        fs.writeFileSync(cert, RENEWED);
        return trust.followCertificateChange(LOOPBACK, PEM);
      })();
      return followed.then(() => realOpen(file));
    };
    await trust.refreshEngineTrust();
    assert.ok(followed !== undefined, "the follow never ran, so this test proves nothing");
    assert.strictEqual(await followed, true);
  }

  test("a refresh's older read does not replace a renewal a request registered before its commit", async () => {
    await followDuringRefresh(PEM);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, RENEWED);
  });

  test("a refresh whose own read failed keeps a renewal a request registered before its commit", async () => {
    await followDuringRefresh("partial");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, RENEWED);
  });

  test("CLI, kept: an answer with no api_tls (an older engine) keeps the loopback anchor", async () => {
    stubInventory = plantedEngine();
    await trust.refreshEngineTrust();
    stubInventory = { certs: [] };

    assert.strictEqual(await trust.refreshEngineTrust(), false);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("before the first commit, a caFile removed while the follow read it is not registered", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    let release: (() => void) | undefined;
    openHook = (file) =>
      file === path.normalize(caFile)
        ? new Promise((resolve) => {
            release = () => resolve(realOpen(file));
          })
        : undefined;

    const followed = trust.followCertificateChange(REMOTE, undefined);
    stubConfig.environments = [{ name: "PROD", url: REMOTE }];
    assert.ok(release !== undefined, "the follow never opened the file, so this test proves nothing");
    release();

    assert.strictEqual(await followed, false);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined);
  });

  test("certificate reads are bounded: at most two run at once, abandoned ones included", async () => {
    const files = [0, 1, 2, 3].map((i) => plantCert(path.join("pki", `ca-${i}.pem`)));
    stubConfig.environments = files.map((caFile, i) => ({
      name: `E${i}`,
      url: `https://h${i}.example.com:8765`,
      caFile,
    }));
    trust.setEngineTrustLimitsForTest({ refreshReadMs: 50 });
    const reads = holdReads(files);

    await trust.refreshEngineTrust();
    await trust.refreshEngineTrust(); // the first refresh's reads are still running
    assert.strictEqual(reads.most(), 2, `not capped at two: ${JSON.stringify([...reads.opens])}`);
  });

  test("a file still being read is not opened again by a later refresh", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    trust.setEngineTrustLimitsForTest({ refreshReadMs: 50 });
    const reads = holdReads([caFile]);

    await trust.refreshEngineTrust();
    await trust.refreshEngineTrust();
    assert.strictEqual(reads.opens.get(path.normalize(caFile)), 1);
  });

  test("a read that started before the refresh asked is not what the refresh registers", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();

    // A request's re-read opens the file while it still holds PEM, and finishes only after the
    // refresh has joined it; meanwhile the file is rotated.
    let stale: (() => void) | undefined;
    openHook = (file) => {
      if (file !== path.normalize(caFile) || stale !== undefined) {
        return undefined;
      }
      return new Promise((resolve) => {
        stale = () => resolve(servingHandle(PEM));
      });
    };
    childProcess.execFile = cliThatFirst(() => {
      void trust.followCertificateChange(REMOTE, PEM);
      fs.writeFileSync(caFile, RENEWED);
      setTimeout(() => stale?.(), 20);
    });

    await trust.refreshEngineTrust();
    await settle();

    assert.ok(stale !== undefined, "the request's read never started, so this test proves nothing");
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, RENEWED);
  });

  test("before the first refresh commits, a failure reads the configured caFile", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];

    assert.strictEqual(await trust.followCertificateChange(REMOTE, undefined), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);
  });

  // ---- round 5: a caFile-pinned host never falls back to the default roots ----

  /**
   * A loopback TCP listener that counts connections and drops each one, so a test can tell a request
   * refused before it was sent (no connection) from one sent and failed. It is not TLS, so a request
   * that IS sent fails its handshake; that failure is the control's evidence, not a defect.
   */
  async function countingListener(): Promise<{ url: string; connections: () => number }> {
    let count = 0;
    const server = net.createServer((socket) => {
      count++;
      socket.destroy();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    held.push(() => server.close());
    return {
      url: `https://127.0.0.1:${(server.address() as net.AddressInfo).port}`,
      connections: () => count,
    };
  }

  /** Install the production failure handler for one test; teardown puts the old one back. */
  function withFollowHandler(): void {
    const previous = engineClient.setTrustFailureHandler(trust.followCertificateChange);
    held.push(() => engineClient.setTrustFailureHandler(previous));
  }

  test("a pinned host with no anchor is refused before it is sent, not verified against the default roots", async () => {
    const target = await countingListener();
    const caFile = path.join(ws, "pki", "late-ca.pem");
    stubConfig.environments = [{ name: "PROD", url: target.url, caFile }];
    withFollowHandler();
    await trust.refreshEngineTrust();

    await assert.rejects(
      () => engineClient.getJson(target.url, "/health", undefined, 2000),
      (e: unknown) =>
        e instanceof engineClient.NetworkError &&
        e.code === CAFILE_UNREAD_CODE &&
        e.message.includes("messagefoundry.environments"),
    );
    await assert.rejects(
      () => engineClient.postJson(target.url, "/config/reload", {}, undefined, 2000),
      (e: unknown) => e instanceof engineClient.NetworkError && e.code === CAFILE_UNREAD_CODE,
    );
    assert.strictEqual(target.connections(), 0, "a request to a pinned host was sent with no anchor");
  });

  test("an unpinned remote still goes out on the default roots, and loopback is unchanged: the controls", async () => {
    const target = await countingListener();
    stubConfig.environments = [{ name: "PROD", url: target.url }];
    stubInventory = plantedEngine();
    await trust.refreshEngineTrust();

    await assert.rejects(
      () => engineClient.getJson(target.url, "/health", undefined, 2000),
      (e: unknown) => e instanceof engineClient.NetworkError && e.code !== CAFILE_UNREAD_CODE,
    );
    assert.strictEqual(target.connections(), 1, "an unpinned host must be sent as before");
    assert.strictEqual(engineClient.tlsOptions(new URL(target.url)).ca, undefined);
    assert.strictEqual(engineClient.pinRefusal(new URL(REMOTE)), undefined);
    // The loopback engine keeps the certificate serviceConfig names, and is not refused.
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
    assert.strictEqual(engineClient.pinRefusal(new URL(LOOPBACK)), undefined);
  });

  test("the refusal is a trust failure: the follow reads the caFile and the retry goes out with it", async () => {
    const target = await countingListener();
    const caFile = path.join(ws, "pki", "late-ca.pem");
    stubConfig.environments = [{ name: "PROD", url: target.url, caFile }];
    withFollowHandler();
    await trust.refreshEngineTrust();
    plantCert(path.join("pki", "late-ca.pem")); // the share mounted after the refresh

    await assert.rejects(
      () => engineClient.getJson(target.url, "/health", undefined, 2000),
      // Sent, with the anchor; it fails only because the listener is not TLS.
      (e: unknown) => e instanceof engineClient.NetworkError && e.code !== CAFILE_UNREAD_CODE,
    );
    assert.strictEqual(target.connections(), 1, "the follow never read the caFile, so nothing was retried");
    assert.strictEqual(engineClient.tlsOptions(new URL(target.url)).ca, PEM);
    assert.strictEqual(engineClient.pinRefusal(new URL(target.url)), undefined);
  });

  test("a refused POST is sent once the follow reads the caFile: it never left, so it cannot repeat", async () => {
    const target = await countingListener();
    const caFile = path.join(ws, "pki", "late-ca.pem");
    stubConfig.environments = [{ name: "PROD", url: target.url, caFile }];
    withFollowHandler();
    await trust.refreshEngineTrust();
    plantCert(path.join("pki", "late-ca.pem"));

    await assert.rejects(
      () => engineClient.postJson(target.url, "/config/reload", {}, undefined, 2000),
      (e: unknown) =>
        e instanceof engineClient.NetworkError &&
        !(e instanceof engineClient.CertificateChangedError) &&
        e.code !== CAFILE_UNREAD_CODE,
    );
    assert.strictEqual(target.connections(), 1);
  });

  test("a pin added since the last refresh is read by a failing request, not only by that refresh", async () => {
    await trust.refreshEngineTrust();
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];

    assert.strictEqual(await trust.followCertificateChange(REMOTE, undefined), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);
  });

  test("pinning a host drops the certificate serviceConfig gave it, at once", async () => {
    stubInventory = plantedEngine();
    const subscriptions: { dispose(): unknown }[] = [];
    held.push(() => subscriptions.forEach((d) => d.dispose()));
    trust.registerEngineTrust({ subscriptions } as unknown as import("vscode").ExtensionContext);
    await settle();
    const listener = configListener as ConfigListener | undefined;
    assert.ok(listener !== undefined, "no settings listener was subscribed");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);

    const caFile = path.join(ws, "pki", "missing.pem");
    stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile }];
    listener({ affectsConfiguration: (s) => s === "messagefoundry.environments" });

    assert.strictEqual(engineClient.pinRefusal(new URL(LOOPBACK))?.code, CAFILE_UNREAD_CODE);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);
  });

  test("an anchor dropped by a new pin re-probes the status bar", async () => {
    stubInventory = plantedEngine();
    const subscriptions: { dispose(): unknown }[] = [];
    held.push(() => subscriptions.forEach((d) => d.dispose()));
    trust.registerEngineTrust({ subscriptions } as unknown as import("vscode").ExtensionContext);
    await settle();
    const listener = configListener as ConfigListener | undefined;
    assert.ok(listener !== undefined, "no settings listener was subscribed");
    let rechecks = 0;
    const realExecute = vscodeStub.commands.executeCommand;
    vscodeStub.commands.executeCommand = () => {
      rechecks++;
      return Promise.resolve(undefined);
    };
    held.push(() => (vscodeStub.commands.executeCommand = realExecute));

    stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile: path.join(ws, "pki", "missing.pem") }];
    listener({ affectsConfiguration: (s) => s === "messagefoundry.environments" });
    await settle();
    for (let i = 0; i < 5; i++) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    assert.ok(rechecks > 0, "the verdict earned with the dropped anchor was left on screen");
  });

  test("a refresh that started before a pin was added does not commit another source for that host", async () => {
    stubInventory = plantedEngine();
    const caFile = path.join(ws, "pki", "missing.pem");
    childProcess.execFile = cliThatFirst(() => {
      stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile }];
    });

    await trust.refreshEngineTrust();

    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);
  });

  test("a loopback host pinned since the last refresh never spawns the CLI on failure", async () => {
    stubInventory = NO_CERT_YET;
    await trust.refreshEngineTrust();
    const spawned = invocations.length;
    stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile: path.join(ws, "pki", "missing.pem") }];

    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, undefined), false);
    await settle();
    assert.strictEqual(invocations.length, spawned);
  });

  test("a host whose caFile was refused is not told to set a caFile", async () => {
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile: "pki/prod-ca.pem" }];
    await trust.refreshEngineTrust();
    assert.ok(
      !logged.some((line) => line.includes(`${UNANCHORED} (${REMOTE}`)),
      `told to set the caFile it has: ${JSON.stringify(logged)}`,
    );
  });

  test("a caFile caught holding only a BOM, a line break or the start of the marker keeps its anchor", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();
    // Then: a BOM caught after one or two of its three bytes (decoded as U+FFFD), and a rewrite caught
    // a few bytes in, before the marker is whole.
    const partials: (string | Buffer)[] = [
      String.fromCharCode(0xfeff),
      "\r\n",
      Buffer.from([0xef]),
      Buffer.from([0xef, 0xbb]),
      "-",
      "\r\n-----BEGIN CERTIF",
    ];
    for (const partial of partials) {
      fs.writeFileSync(caFile, partial);
      await trust.refreshEngineTrust();
      assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM, JSON.stringify(partial));
    }
    // The control: real content that is not PEM is an answer, and drops it.
    fs.writeFileSync(caFile, "not a certificate");
    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined);
    // And bytes that are not UTF-8 at all (a UTF-16 BOM) are more than one partial BOM: an answer too.
    fs.writeFileSync(caFile, PEM);
    await trust.refreshEngineTrust();
    fs.writeFileSync(caFile, Buffer.from([0xff, 0xfe]));
    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, undefined);
  });

  test("a pin is in force from the setting, before any file read or CLI answer", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    let duringCli: unknown = "not observed";
    childProcess.execFile = cliThatFirst(() => {
      duringCli = engineClient.pinRefusal(new URL(REMOTE))?.code;
    });

    await trust.refreshEngineTrust();

    assert.strictEqual(
      duringCli,
      CAFILE_UNREAD_CODE,
      "a pinned host was open to the default roots while the refresh ran",
    );
    assert.strictEqual(engineClient.pinRefusal(new URL(REMOTE)), undefined, "the read landed");
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);
  });

  test("activation publishes the pins synchronously, before its first refresh has read anything", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    const subscriptions: { dispose(): unknown }[] = [];
    held.push(() => subscriptions.forEach((d) => d.dispose()));

    trust.registerEngineTrust({ subscriptions } as unknown as import("vscode").ExtensionContext);

    assert.strictEqual(engineClient.pinRefusal(new URL(REMOTE))?.code, CAFILE_UNREAD_CODE);
    await settle();
    assert.strictEqual(engineClient.pinRefusal(new URL(REMOTE)), undefined);
  });

  test("a pin added in the settings is in force at once, before the refresh it starts reads it", async () => {
    const subscriptions: { dispose(): unknown }[] = [];
    held.push(() => subscriptions.forEach((d) => d.dispose()));
    configListener = undefined;
    trust.registerEngineTrust({ subscriptions } as unknown as import("vscode").ExtensionContext);
    await settle();
    const listener = configListener as ConfigListener | undefined;
    assert.ok(listener !== undefined, "no settings listener was subscribed");
    assert.strictEqual(engineClient.pinRefusal(new URL(REMOTE)), undefined);

    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    listener({ affectsConfiguration: (s) => s === "messagefoundry.environments" });

    assert.strictEqual(engineClient.pinRefusal(new URL(REMOTE))?.code, CAFILE_UNREAD_CODE);
    await settle();
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);
  });

  test("removing the pin returns the host to the default roots", async () => {
    const DR = "https://dr.example.com:8765";
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [
      { name: "PROD", url: REMOTE, caFile },
      { name: "DR", url: DR, caFile: path.join(ws, "pki", "missing.pem") },
    ];
    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);
    assert.strictEqual(engineClient.pinRefusal(new URL(DR))?.code, CAFILE_UNREAD_CODE);

    stubConfig.environments = [
      { name: "PROD", url: REMOTE },
      { name: "DR", url: DR },
    ];
    await trust.refreshEngineTrust();

    for (const url of [REMOTE, DR]) {
      assert.strictEqual(engineClient.tlsOptions(new URL(url)).ca, undefined, url);
      assert.strictEqual(engineClient.pinRefusal(new URL(url)), undefined, url);
    }
  });

  // ---- round 6: a refused https caFile fails closed, and two repair lines get their own tests ----

  /** Refused caFile values on an https entry, each with a fragment of the reason it is refused for. */
  const REFUSED_VALUES: readonly (readonly [unknown, string])[] = [
    ["pki/prod-ca.pem", "pki/prod-ca.pem is not"],
    ["~/pki/prod-ca.pem", "~/pki/prod-ca.pem is not"],
    [42, "caFile is not a string"],
  ];

  test("an https caFile that is refused marks its host, with the reason; an http:// one does not", async () => {
    for (const [caFile, reason] of REFUSED_VALUES) {
      stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
      await trust.refreshEngineTrust();
      const refused = engineClient.pinRefusal(new URL(REMOTE));
      assert.strictEqual(refused?.code, CAFILE_REFUSED_CODE, JSON.stringify(caFile));
      assert.ok(refused.message.includes(reason), `${JSON.stringify(caFile)}: ${refused.message}`);
    }
    // The control: an http:// entry has no handshake to pin, so its bad caFile claims nothing, and an
    // https engine on the same host:port is not refused.
    stubConfig.environments = [{ name: "PLAIN", url: "http://plain.example.com:8765", caFile: "pki/ca.pem" }];
    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.pinRefusal(new URL("https://plain.example.com:8765")), undefined);
    // And a full path that is merely unread is the other code.
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile: path.join(ws, "pki", "missing.pem") }];
    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.pinRefusal(new URL(REMOTE))?.code, CAFILE_UNREAD_CODE);
  });

  test("a refused https caFile is refused for GET and POST with no connection, and reads nothing", async () => {
    const target = await countingListener();
    const unpinned = await countingListener();
    stubConfig.environments = [
      { name: "PROD", url: target.url, caFile: "pki/prod-ca.pem" },
      { name: "OTHER", url: unpinned.url },
    ];
    withFollowHandler();
    await trust.refreshEngineTrust();
    const spawned = invocations.length;
    let opened = 0;
    openHook = () => {
      opened++;
      return undefined;
    };

    for (const send of [
      () => engineClient.getJson(target.url, "/health", undefined, 2000),
      () => engineClient.postJson(target.url, "/config/reload", {}, undefined, 2000),
    ]) {
      await assert.rejects(
        send,
        (e: unknown) =>
          e instanceof engineClient.NetworkError &&
          e.code === CAFILE_REFUSED_CODE &&
          e.message.includes("pki/prod-ca.pem is not"),
      );
    }
    await ticks();
    await settle();
    assert.strictEqual(target.connections(), 0, "a host a refused caFile claims was sent on the default roots");
    assert.strictEqual(opened, 0, "a refused caFile has no file, yet the follow opened one");
    assert.strictEqual(invocations.length, spawned, "a refused caFile started a refresh");
    const key = new URL(target.url).host;
    assert.ok(
      logged.some((line) => line.includes(`Requests to ${key} are refused`)),
      `the log does not say the host is refused: ${JSON.stringify(logged)}`,
    );

    // The control: an unpinned host beside it still goes out.
    await assert.rejects(
      () => engineClient.getJson(unpinned.url, "/health", undefined, 2000),
      (e: unknown) => e instanceof engineClient.NetworkError && e.code !== CAFILE_REFUSED_CODE,
    );
    assert.strictEqual(unpinned.connections(), 1, "an unpinned host must be sent as before");
  });

  test("an http:// entry with a bad caFile is still sent: the control", async () => {
    const target = await countingListener();
    const plain = target.url.replace("https:", "http:");
    stubConfig.environments = [{ name: "PLAIN", url: plain, caFile: "pki/prod-ca.pem" }];
    await trust.refreshEngineTrust();

    await assert.rejects(
      () => engineClient.getJson(plain, "/health", undefined, 2000),
      (e: unknown) => e instanceof engineClient.NetworkError && e.code !== CAFILE_REFUSED_CODE,
    );
    assert.strictEqual(target.connections(), 1);
  });

  test("a refused caFile corrected to a valid one is read by the failing request, which then goes out", async () => {
    const target = await countingListener();
    stubConfig.environments = [{ name: "PROD", url: target.url, caFile: "pki/prod-ca.pem" }];
    withFollowHandler();
    await trust.refreshEngineTrust();
    // Corrected in the settings; no refresh has run since, so engineClient still holds the refusal.
    stubConfig.environments = [{ name: "PROD", url: target.url, caFile: plantCert(path.join("pki", "prod-ca.pem")) }];

    await assert.rejects(
      () => engineClient.postJson(target.url, "/config/reload", {}, undefined, 2000),
      // Sent, with the anchor; it fails only because the listener is not TLS. Never sent before, so
      // not a CertificateChangedError either.
      (e: unknown) =>
        e instanceof engineClient.NetworkError &&
        !(e instanceof engineClient.CertificateChangedError) &&
        e.code !== CAFILE_REFUSED_CODE,
    );
    assert.strictEqual(target.connections(), 1, "the corrected caFile was not read, so nothing was retried");
    assert.strictEqual(engineClient.tlsOptions(new URL(target.url)).ca, PEM);
  });

  test("a refresh that started before a caFile was refused does not commit the CLI's certificate", async () => {
    // The refused value claims the host as an accepted pin would, so a refresh that read the settings
    // before it gives that host nothing.
    stubInventory = plantedEngine();
    childProcess.execFile = cliThatFirst(() => {
      stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile: "relative/ca.pem" }];
    });

    await trust.refreshEngineTrust();

    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);
    // The control: with no caFile the same answer anchors the loopback engine.
    stubConfig.environments = [];
    childProcess.execFile = answeringCli;
    await trust.refreshEngineTrust();
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("a refused caFile set in the settings drops the CLI's certificate at once", async () => {
    stubInventory = plantedEngine();
    const subscriptions: { dispose(): unknown }[] = [];
    held.push(() => subscriptions.forEach((d) => d.dispose()));
    configListener = undefined;
    trust.registerEngineTrust({ subscriptions } as unknown as import("vscode").ExtensionContext);
    await settle();
    const listener = configListener as ConfigListener | undefined;
    assert.ok(listener !== undefined, "no settings listener was subscribed");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);

    stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile: "relative/ca.pem" }];
    listener({ affectsConfiguration: (s) => s === "messagefoundry.environments" });

    assert.strictEqual(engineClient.pinRefusal(new URL(LOOPBACK))?.code, CAFILE_REFUSED_CODE);
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined);
  });

  test("a refused caFile added or removed on an unanchored host re-probes the status bar", async () => {
    // No anchor moves (a host only a refused value claims never has one), yet whether its requests
    // are sent changed both times, so the verdict on screen is stale both times.
    stubConfig.environments = [{ name: "PROD", url: REMOTE }];
    const subscriptions: { dispose(): unknown }[] = [];
    held.push(() => subscriptions.forEach((d) => d.dispose()));
    configListener = undefined;
    trust.registerEngineTrust({ subscriptions } as unknown as import("vscode").ExtensionContext);
    await settle();
    const listener = configListener as ConfigListener | undefined;
    assert.ok(listener !== undefined, "no settings listener was subscribed");
    let rechecks = 0;
    const realExecute = vscodeStub.commands.executeCommand;
    vscodeStub.commands.executeCommand = () => {
      rechecks++;
      return Promise.resolve(undefined);
    };
    held.push(() => (vscodeStub.commands.executeCommand = realExecute));
    const change = async (environments: unknown[]): Promise<number> => {
      const before = rechecks;
      stubConfig.environments = environments;
      listener({ affectsConfiguration: (s) => s === "messagefoundry.environments" });
      await settle();
      await ticks();
      return rechecks - before;
    };

    assert.ok((await change([{ name: "PROD", url: REMOTE, caFile: "pki/ca.pem" }])) > 0, "added");
    assert.ok((await change([{ name: "PROD", url: REMOTE }])) > 0, "removed");
    // The control: a settings change that moves nothing does not re-probe.
    assert.strictEqual(await change([{ name: "PROD", url: REMOTE }]), 0, "nothing moved");
  });

  /** A file handle that serves `text` once, standing in for an open that finished long ago. Hoisted,
   *  so the round-4 test above uses it too. */
  function servingHandle(text: string): unknown {
    const bytes = Buffer.from(text);
    let served = false;
    return {
      stat: async () => ({ isFile: () => true, size: bytes.length }),
      read: async (buffer: Buffer, offset: number) => {
        const bytesRead = served ? 0 : bytes.copy(buffer, offset);
        served = true;
        return { bytesRead };
      },
      close: async () => undefined,
    };
  }

  test("a stale failed read is not an answer when the refresh's own re-read is cut short", async () => {
    // readSince's cut-short return: the refresh joins a read that began before it asked, so it reads
    // again; that re-read does not finish in time. The joined read saw something that is not a
    // certificate, but it is stale, so it must not drop the pin's anchor.
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();
    trust.setEngineTrustLimitsForTest({ refreshReadMs: 150, followReadMs: 5_000 });

    let releaseStale: (() => void) | undefined;
    let opens = 0;
    openHook = (file) => {
      if (file !== path.normalize(caFile)) {
        return undefined;
      }
      opens++;
      if (opens === 1) {
        return new Promise((resolve) => (releaseStale = () => resolve(servingHandle("garbage"))));
      }
      return new Promise((_resolve, reject) => held.push(() => reject(new Error("EHOSTDOWN"))));
    };
    const followed = trust.followCertificateChange(REMOTE, PEM);
    childProcess.execFile = cliThatFirst(() => setTimeout(() => releaseStale?.(), 20));

    await trust.refreshEngineTrust();
    await followed;

    assert.strictEqual(opens, 2, "the refresh never read again, so this test proves nothing");
    assert.strictEqual(
      engineClient.tlsOptions(new URL(REMOTE)).ca,
      PEM,
      "an older failed read was taken as the answer and dropped the pin's anchor",
    );
  });

  test("a pin anchor a request registered while a refresh ran is kept, though that refresh never read it", async () => {
    // commit's first loop: the refresh read settings with no pin, the pin arrived meanwhile and a
    // request read it, so the refresh's silence about that host is not an answer.
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    let followed: Promise<boolean> | undefined;
    stubCli((done) => {
      stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
      followed = trust.followCertificateChange(REMOTE, undefined);
      void followed.then(() => done(null, JSON.stringify(stubInventory), ""));
    });

    await trust.refreshEngineTrust();

    assert.ok(followed !== undefined, "the follow never ran, so this test proves nothing");
    assert.strictEqual(await followed, true);
    assert.strictEqual(
      engineClient.tlsOptions(new URL(REMOTE)).ca,
      PEM,
      "the refresh dropped an anchor from the file the settings pin now",
    );
  });

  // ---- round 8: the follow path after the Lander's covering review of 2026-10-27 ----

  /** Pin REMOTE to a caFile holding PEM, refresh (anchoring it only when `anchored`; otherwise the
   *  file appears after that refresh), then make every later open of that file take `delayMs`, longer
   *  than a request may wait; returns the file and a count of its opens. */
  async function slowPinnedFile(
    delayMs: number,
    anchored = true,
  ): Promise<{ caFile: string; opens: () => number }> {
    const caFile = path.join(ws, "pki", "slow-ca.pem");
    if (anchored) {
      plantCert(path.join("pki", "slow-ca.pem"));
    }
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();
    plantCert(path.join("pki", "slow-ca.pem"));
    trust.setEngineTrustLimitsForTest({ followReadMs: 20 });
    let opens = 0;
    openHook = (file) => {
      if (file !== path.normalize(caFile)) {
        return undefined;
      }
      opens++;
      return new Promise((resolve) => setTimeout(resolve, delayMs)).then(() => realOpen(file));
    };
    return { caFile, opens: () => opens };
  }

  test("a pinned host whose anchor is stale follows a CA rotated in place on a slow share", async () => {
    // Finding 1: the background re-read ran only for a pinned host with NO anchor, so a host holding
    // the old CA failed every request until the window reloaded.
    const { caFile } = await slowPinnedFile(80);
    fs.writeFileSync(caFile, RENEWED);

    assert.strictEqual(await trust.followCertificateChange(REMOTE, PEM), false);
    await settle();
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, RENEWED);
  });

  test("a stale joined read of the old CA, then a re-read cut short, is still followed in the background", async () => {
    // Round 8 review: readSince hands back the stale read when the re-read is cut short, so the
    // request did not count as cut short and nothing finished the re-read.
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();
    trust.setEngineTrustLimitsForTest({ followReadMs: 40 });
    let releaseStale: (() => void) | undefined;
    openHook = (file) => {
      if (file !== path.normalize(caFile)) {
        return undefined;
      }
      if (releaseStale === undefined) {
        return new Promise((resolve) => (releaseStale = () => resolve(servingHandle(PEM))));
      }
      return new Promise((resolve) => setTimeout(resolve, 120)).then(() => realOpen(file));
    };
    const earlier = trust.followCertificateChange(REMOTE, PEM); // its read began before the rotation
    assert.ok(releaseStale !== undefined, "the earlier read never started, so this test proves nothing");
    fs.writeFileSync(caFile, RENEWED);
    const later = trust.followCertificateChange(REMOTE, PEM); // joins it, then reads again, slowly
    releaseStale();

    assert.strictEqual(await later, false);
    await earlier;
    await settle();
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, RENEWED);
  });

  test("a deactivated extension's queued refresh does not spawn the CLI, and keeps its anchor", async () => {
    stubInventory = plantedEngine();
    const subscriptions: { dispose(): unknown }[] = [];
    held.push(() => subscriptions.forEach((d) => d.dispose()));
    trust.registerEngineTrust({ subscriptions } as unknown as import("vscode").ExtensionContext);
    await settle();
    const base = invocations.length;
    subscriptions[0].dispose();

    await trust.refreshEngineTrust();
    assert.strictEqual(invocations.length, base, "the CLI was spawned after deactivation");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);
  });

  test("a slow pin's background re-read spawns no CLI and reads the file once", async () => {
    // Findings 5 and 6: it was a full refresh, which asked the CLI every time (about once a minute for
    // a share that stays slow) and joined the request's read only to read the file a second time.
    // An unanchored pin, which that path already covered, so this isolates its cost from finding 1.
    const { opens } = await slowPinnedFile(80, false);
    const spawned = invocations.length;
    assert.strictEqual(spawned, 1, "the CLI was never asked, so this test proves nothing");

    assert.strictEqual(await trust.followCertificateChange(REMOTE, undefined), false);
    await settle();
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM, "nothing was followed");
    assert.strictEqual(invocations.length, spawned, "a slow pin spawned the engine's CLI");
    assert.strictEqual(opens(), 1, "a slow caFile was read more than once");
  });

  test("a slow pin's background re-read re-probes the status bar when it registers", async () => {
    const { caFile } = await slowPinnedFile(80);
    fs.writeFileSync(caFile, RENEWED);
    let rechecks = 0;
    const realExecute = vscodeStub.commands.executeCommand;
    vscodeStub.commands.executeCommand = () => {
      rechecks++;
      return Promise.resolve(undefined);
    };
    held.push(() => (vscodeStub.commands.executeCommand = realExecute));

    await trust.followCertificateChange(REMOTE, PEM);
    await settle();
    assert.ok(rechecks > 0, "the verdict earned with the stale anchor was left on screen");
  });

  test("a stale FAILED read a request joins is read again, not taken as the answer", async () => {
    // Finding 4: a joined read that began before this request failed, and that failed itself, was
    // accepted, so a CA already rotated in place was not followed by this request.
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];
    await trust.refreshEngineTrust();
    let releaseStale: (() => void) | undefined;
    openHook = (file) => {
      if (file !== path.normalize(caFile) || releaseStale !== undefined) {
        return undefined;
      }
      return new Promise((resolve) => (releaseStale = () => resolve(servingHandle("garbage"))));
    };
    const earlier = trust.followCertificateChange(REMOTE, PEM); // its read hangs, then fails
    assert.ok(releaseStale !== undefined, "the earlier read never started, so this test proves nothing");
    fs.writeFileSync(caFile, RENEWED);

    const later = trust.followCertificateChange(REMOTE, PEM); // joins that read
    releaseStale();

    assert.strictEqual(await later, true, "a stale failed read answered a request");
    await earlier;
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, RENEWED);
  });

  test("after deactivation a late failure starts no follow-up refresh", async () => {
    // Finding 7.
    stubInventory = NO_CERT_YET;
    const subscriptions: { dispose(): unknown }[] = [];
    held.push(() => subscriptions.forEach((d) => d.dispose()));
    trust.registerEngineTrust({ subscriptions } as unknown as import("vscode").ExtensionContext);
    await settle();
    const base = invocations.length;
    stubCli((done) => {
      setImmediate(() => {
        // The failure is noted first, so the refresh would run a follow-up; then the extension
        // deactivates while that refresh is still running.
        void trust.followCertificateChange(LOOPBACK, undefined).then(() => {
          subscriptions[0].dispose();
          setImmediate(() => done(null, JSON.stringify(stubInventory), ""));
        });
      });
    });

    await trust.refreshEngineTrust();
    await ticks();
    await settle();
    assert.strictEqual(invocations.length, base + 1, "a follow-up refresh ran after deactivation");
  });

  test("a settings change that drops an anchor re-probes at once, not after a slow refresh", async () => {
    // Finding 10: the re-probe waited for the queued refresh, which may take the CLI's whole
    // allowance plus the read allowance (about 45 s) before the stale verdict was replaced.
    stubInventory = plantedEngine();
    const subscriptions: { dispose(): unknown }[] = [];
    held.push(() => subscriptions.forEach((d) => d.dispose()));
    configListener = undefined;
    trust.registerEngineTrust({ subscriptions } as unknown as import("vscode").ExtensionContext);
    await settle();
    const listener = configListener as ConfigListener | undefined;
    assert.ok(listener !== undefined, "no settings listener was subscribed");
    let rechecks = 0;
    const realExecute = vscodeStub.commands.executeCommand;
    vscodeStub.commands.executeCommand = () => {
      rechecks++;
      return Promise.resolve(undefined);
    };
    held.push(() => (vscodeStub.commands.executeCommand = realExecute));
    hungCli(); // the refresh the change queues does not finish during this test

    stubConfig.environments = [{ name: "LOCAL", url: LOOPBACK, caFile: path.join(ws, "pki", "missing.pem") }];
    listener({ affectsConfiguration: (s) => s === "messagefoundry.environments" });
    await ticks();

    assert.ok(rechecks > 0, "the verdict earned with the dropped anchor stayed on screen");
  });
});
