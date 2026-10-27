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
import * as os from "node:os";
import * as path from "node:path";

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
    onDidChangeConfiguration: () => ({ dispose: (): void => {} }),
  },
  window: {
    createOutputChannel: () => ({
      info: (line: string): void => void logged.push(line),
      warn: (line: string): void => void logged.push(line),
      error: (line: string): void => void logged.push(line),
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

const shellSuite = NODE_SIDE ? suite : suite.skip;

shellSuite("engine trust — pairing a certificate with a target (BACKLOG #1695)", () => {
  const PEM = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n";
  const LOOPBACK = "https://127.0.0.1:8765";
  const REMOTE = "https://prod.example.com:8765";

  let ws: string;

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
    trust.forgetEngineTrust();
    childProcess.execFile = ((
      _file: string,
      args: string[],
      options: { cwd?: string },
      done: (err: null, stdout: string, stderr: string) => void,
    ) => {
      invocations.push({ args, cwd: options.cwd });
      done(null, JSON.stringify(stubInventory), "");
      return undefined;
    }) as unknown as typeof childProcess.execFile;
  });

  teardown(() => {
    childProcess.execFile = realExecFile;
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

  /** Let a background refresh finish: the stubbed CLI answers synchronously, so a few turns do. */
  async function settle(): Promise<void> {
    for (let i = 0; i < 5; i++) {
      await new Promise((resolve) => setImmediate(resolve));
    }
  }

  test("a caFile pins a REMOTE environment target — the case serviceConfig cannot cover", async () => {
    const caFile = plantCert(path.join("pki", "prod-ca.pem"));
    stubConfig.engineUrl = REMOTE;
    stubConfig.environments = [{ name: "PROD", url: REMOTE, caFile }];

    assert.strictEqual(await trust.refreshEngineTrust(), true);
    assert.strictEqual(engineClient.tlsOptions(new URL(REMOTE)).ca, PEM);
    assert.ok(
      !logged.some((line) => line.includes("with no trust anchor")),
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
      logged.some((line) => line.includes("with no trust anchor") && line.includes(REMOTE)),
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
    // The refresh runs in the BACKGROUND: it spawns a CLI with no timeout, and a request awaiting it
    // would stop honouring its own. So this request is not retried; the anchor lands shortly after.
    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, undefined), false);
    await settle();
    assert.strictEqual(invocations.length, 2, "the background refresh never ran");
    assert.strictEqual(engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM);

    // The rate limit: a second failure straight away does not spawn the CLI again.
    assert.strictEqual(await trust.followCertificateChange(LOOPBACK, PEM), false);
    await settle();
    assert.strictEqual(invocations.length, 2);
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
});
