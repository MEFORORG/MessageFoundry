// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5837, a reviewed not-a-bug. The claim: Start and Restart from the status bar do not refresh
// the IDE's trust anchor, so the probes after a start fail verification against a newly minted
// self-signed certificate until a reload. The reading: they need no refresh call of their own. After
// either one, `serveEngine` schedules re-probes; each goes through the bar's default fetch to
// `getJson`, whose `withRenewalRetry` hands a verification failure to the trust failure handler. The
// handler activation installs is engine trust's `followCertificateChange` (engineTrust.ts says when it
// does what). Its two answers are pinned here, each after Start and after Restart:
//   * an anchor changed: it answers true and the request runs again at once (a spy stands in for it,
//     put where `registerEngineTrust` put it, which the first test checks);
//   * the first run, an engine minting its certificate only once started: it answers false and starts
//     the CLI refresh, which registers the new certificate, so the next re-probe carries it with no
//     reload (the real handler, with `cert inventory` faked).
// An open limit the first-run pin does not cover: that refresh runs at most once per
// FAILURE_REFRESH_MIN_MS (60 s, engineTrust.ts). If a verification failure spent it in the minute
// before Start, as one from another engine on the same port can, the re-probes after Start are refused
// a refresh, and the anchor is picked up by the first failing probe after that minute, the 15 s poll's
// included. A delay of at most that minute, not a reload. The suite's setup resets the limit.
//
// This drives the real Start and Restart (b20008-b-harness.ts), with every engine request failing as
// a self-signed certificate does. Behaviour, not source text, apart from one scan of activation's call.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  LOOPBACK,
  NODE_SIDE,
  captureProbes,
  idle,
  installFakes,
  makeContext,
  mods,
  reset,
  state,
  tearDown,
  waitFor,
} from "./b20008-b-harness";

const trustSuite = NODE_SIDE ? suite : suite.skip;

/** A workspace with a default service TOML, so the fork guard finds a store and Start asks nothing. */
function openWorkspace(): string {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "mf-b20008-b-trust-"));
  fs.writeFileSync(path.join(ws, "messagefoundry.toml"), "");
  return ws;
}

/** Run the registered Start, and return the re-probes it scheduled. */
async function runStart(): Promise<(() => void)[]> {
  const start = state.commands.get("messagefoundry.startEngine");
  assert.ok(start !== undefined, "the Start command is registered");
  return captureProbes(() => start());
}

/** Run Start, then the registered Restart, and return the re-probes Restart scheduled. */
async function runRestart(): Promise<(() => void)[]> {
  await runStart();
  const first = state.terminals.find((t) => t.name === "MessageFoundry Engine");
  const restart = state.commands.get("messagefoundry.restartEngine");
  assert.ok(restart !== undefined, "the Restart command is registered");
  const probes = await captureProbes(() => restart());
  assert.strictEqual(state.terminals.filter((t) => t.name === "MessageFoundry Engine").length, 2, "Restart started serve again");
  assert.ok(first?.exitStatus !== undefined, "Restart stopped the first serve");
  return probes;
}

/** Run re-probe `n`, once the bar is idle, and return the events it caused once the bar is idle again. */
async function runProbe(bar: object, probes: (() => void)[], n: number, until: (events: string[]) => boolean): Promise<string[]> {
  assert.strictEqual(probes.length, 3, "serve schedules its three re-probes");
  await idle(bar);
  const from = state.events.length;
  probes[n]();
  await waitFor(() => until(state.events.slice(from)), `re-probe ${n} to reach its end`);
  await idle(bar);
  return state.events.slice(from);
}

trustSuite("the probes after Start and Restart reach the trust failure handler and retry (BACKLOG #5837)", function () {
  // Above the harness's own 3 s waits, so a wait that runs out fails with its own message.
  this.timeout(10_000);
  let ws: string | undefined;
  let ctx: ReturnType<typeof makeContext> | undefined;
  let bar: object | undefined;
  /** What engine trust installed, read back when the spy took its place. */
  let installed: unknown;

  setup(async () => {
    reset();
    mods.engineTrust.forgetEngineTrust();
    ws = openWorkspace();
    state.workspace = ws;
    state.requestError = "DEPTH_ZERO_SELF_SIGNED_CERT";
    installFakes();
    ctx = makeContext();
    mods.engineTrust.registerEngineTrust(ctx.ctx);
    await mods.engineTrust.engineTrustSettled();
    // The spy answers true, as followCertificateChange does once it has registered a new anchor.
    installed = mods.engineClient.setTrustFailureHandler((url) => {
      state.events.push(`handler ${url}`);
      return Promise.resolve(true);
    });
    bar = mods.statusBar.registerEngineStatusBar(ctx.ctx);
    await idle(bar);
  });

  teardown(async () => {
    try {
      await mods.engineTrust.engineTrustSettled();
    } finally {
      await tearDown(bar, ctx, ws);
      mods.engineTrust.forgetEngineTrust();
      bar = ctx = ws = undefined;
    }
  });

  const handled = (events: string[]): boolean => events.some((e) => e.startsWith("handler "));

  /** The re-probe failed verification, the handler was told which engine, and the request ran again. */
  function assertFollowedAndRetried(events: string[]): void {
    const at = events.findIndex((e) => e.startsWith("handler "));
    assert.ok(at > 0, events.join("\n"));
    assert.strictEqual(events[at], `handler ${LOOPBACK}`, events.join("\n"));
    const failed = events[at - 1];
    assert.ok(failed.startsWith(`request ${LOOPBACK}/`), events.join("\n"));
    assert.strictEqual(events[at + 1], failed, `the same request again after the handler:\n${events.join("\n")}`);
  }

  test("registerEngineTrust installs followCertificateChange as the trust failure handler, and activation calls it", () => {
    assert.strictEqual(installed, mods.engineTrust.followCertificateChange);
    const src = fs
      .readFileSync(path.join(__dirname, "..", "..", "..", "src", "extension.ts"), "utf8")
      .replace(/\r\n/g, "\n");
    // activate's body only: from its signature to the first top-level closing brace after it.
    const start = src.indexOf("export function activate(");
    assert.ok(start >= 0, "extension.ts has no activate");
    const end = src.indexOf("\n}\n", start);
    assert.ok(end > start, "activate has no closing brace at column 0");
    const activate = src.slice(start, end);
    assert.match(activate, /\n {2}registerEngineTrust\(context\);/);
  });

  test("a probe after Start reaches the handler through withRenewalRetry, and retries", async () => {
    const probes = await runStart();
    assertFollowedAndRetried(await runProbe(bar!, probes, 0, handled));
  });

  test("a probe after Restart reaches the handler through withRenewalRetry, and retries", async () => {
    const probes = await runRestart();
    assertFollowedAndRetried(await runProbe(bar!, probes, 0, handled));
  });

  test("control: an unreachable engine is not a trust failure, so the handler is not told", async () => {
    state.requestError = "EHOSTUNREACH";
    const probes = await runStart();
    // The probe's own end: its request was made, and the bar went idle after it.
    const events = await runProbe(bar!, probes, 0, (e) => e.some((x) => x.startsWith("request ")));
    assert.ok(!handled(events), events.join("\n"));
    assert.strictEqual(events.filter((e) => e.startsWith("request ")).length, 1, events.join("\n"));
  });
});

trustSuite("on the first run, the next probe after Start or Restart carries the certificate serve minted (BACKLOG #5837)", function () {
  this.timeout(10_000);
  const PEM = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n";
  let ws: string | undefined;
  let ctx: ReturnType<typeof makeContext> | undefined;
  let bar: object | undefined;
  let cert: string;

  setup(async () => {
    reset();
    mods.engineTrust.forgetEngineTrust();
    ws = openWorkspace();
    state.workspace = ws;
    // No engine yet, so the probes before Start find nothing listening (the harness default). A
    // verification failure then would spend the refresh's rate limit before Start.
    cert = path.join(ws, "state", "api-cert.pem");
    // At activation the engine has never run, so it has no certificate to anchor.
    state.inventory = { certs: [], api_tls: { scheme: "https", source: "generated", cert, cert_present: false } };
    installFakes();
    ctx = makeContext();
    mods.engineTrust.registerEngineTrust(ctx.ctx);
    await mods.engineTrust.engineTrustSettled();
    assert.strictEqual(mods.engineClient.tlsOptions(new URL(LOOPBACK)).ca, undefined, "nothing anchored yet");
    bar = mods.statusBar.registerEngineStatusBar(ctx.ctx);
    await idle(bar);
  });

  teardown(async () => {
    try {
      await mods.engineTrust.engineTrustSettled();
    } finally {
      await tearDown(bar, ctx, ws);
      mods.engineTrust.forgetEngineTrust();
      bar = ctx = ws = undefined;
    }
  });

  /** serve is up and has minted its pair: the file exists, `cert inventory` reports it, and a request
   *  with no anchor for it fails verification. */
  function mint(): void {
    state.requestError = "DEPTH_ZERO_SELF_SIGNED_CERT";
    fs.mkdirSync(path.dirname(cert), { recursive: true });
    fs.writeFileSync(cert, PEM);
    state.inventory = { certs: [], api_tls: { scheme: "https", source: "generated", cert, cert_present: true } };
  }

  /** The first re-probe fails with no anchor and starts the CLI refresh; the second carries the anchor. */
  async function assertPickedUp(probes: (() => void)[]): Promise<void> {
    const inventories = (): number => state.execCalls.filter((c) => c.args.includes("inventory")).length;
    const rechecks = (): number => state.executed.filter((id) => id === "messagefoundry.engineRecheck").length;
    const before = { inventories: inventories(), rechecks: rechecks() };
    const failed = state.requests.length;
    await runProbe(bar!, probes, 0, (e) => e.some((x) => x.startsWith("request ")));
    const route = state.requests[failed];
    assert.strictEqual(route.ca, undefined, "the first re-probe had no anchor to carry");
    await mods.engineTrust.engineTrustSettled();
    assert.strictEqual(inventories(), before.inventories + 1, "the failure started one cert inventory refresh");
    assert.strictEqual(mods.engineClient.tlsOptions(new URL(LOOPBACK)).ca, PEM, "the refresh anchored the new pair");
    assert.strictEqual(rechecks(), before.rechecks + 1, "the refresh asked the bar to re-check");
    const next = state.requests.length;
    await runProbe(bar!, probes, 1, (e) => e.some((x) => x === `request ${route.url}`));
    // The second re-probe's own request to the same route, not any other request made meanwhile.
    const carried = state.requests.slice(next).find((r) => r.url === route.url);
    assert.ok(carried !== undefined, "the second re-probe sent its request");
    assert.strictEqual(carried.ca, PEM, "the second re-probe carried the new certificate");
  }

  test("after Start", async () => {
    const probes = await runStart();
    mint();
    await assertPickedUp(probes);
  });

  test("after Restart", async () => {
    // The first serve never minted; the Restart's serve does.
    const probes = await runRestart();
    mint();
    await assertPickedUp(probes);
  });
});
