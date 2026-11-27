// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5837, a reviewed not-a-bug. The claim: Start and Restart from the status bar do not refresh
// the IDE's trust anchor, so the probes after a start fail verification against a newly minted
// self-signed certificate until a reload. The reading: they need no refresh call of their own. After
// either one, `serveEngine` schedules re-probes; each goes through the bar's default fetch to
// `getJson`, whose `withRenewalRetry` hands a verification failure to the trust failure handler and
// retries once when it answers true. The handler extension activation installs is engine trust's
// `followCertificateChange`, which re-reads the certificate file, or for a loopback engine with no
// anchor yet starts the CLI refresh (engineTrust.ts says when).
//
// This drives the real Start and Restart (b20008-b-harness.ts), with every engine request failing as
// a self-signed certificate does. The handler is a spy put where `registerEngineTrust` put
// `followCertificateChange`, which the first test checks. Behaviour, not source text: the pin goes red
// if the retry wiring, the re-probe, or the default fetch is removed.
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
  uninstallFakes,
  waitFor,
} from "./b20008-b-harness";

const trustSuite = NODE_SIDE ? suite : suite.skip;

trustSuite("the probes after Start and Restart reach the trust failure handler and retry (BACKLOG #5837)", function () {
  // Above the harness's own 3 s waits, so a wait that runs out fails with its own message.
  this.timeout(10_000);
  let ws: string;
  let ctx: ReturnType<typeof makeContext>;
  let bar: object;
  /** What engine trust installed, read back when the spy took its place. */
  let installed: unknown;

  setup(async () => {
    reset();
    ws = fs.mkdtempSync(path.join(os.tmpdir(), "mf-b20008-b-trust-"));
    // A default service TOML, so the fork guard finds a store and Start asks nothing about one.
    fs.writeFileSync(path.join(ws, "messagefoundry.toml"), "");
    state.workspace = ws;
    state.requestError = "DEPTH_ZERO_SELF_SIGNED_CERT";
    installFakes();
    ctx = makeContext();
    mods.engineTrust.registerEngineTrust(ctx.ctx);
    // The spy answers true, as followCertificateChange does once it has registered a new anchor.
    installed = mods.engineClient.setTrustFailureHandler((url) => {
      state.events.push(`handler ${url}`);
      return Promise.resolve(true);
    });
    bar = mods.statusBar.registerEngineStatusBar(ctx.ctx);
    await idle(bar);
  });

  teardown(async () => {
    await idle(bar);
    ctx.dispose();
    uninstallFakes();
    reset();
    fs.rmSync(ws, { recursive: true, force: true });
  });

  /** Run the first captured re-probe, and the events it caused. */
  async function runProbe(probes: (() => void)[]): Promise<string[]> {
    assert.strictEqual(probes.length, 3, "serve schedules its three re-probes");
    await idle(bar);
    const from = state.events.length;
    probes[0]();
    await waitFor(() => state.events.slice(from).some((e) => e.startsWith("handler ")), "the trust handler");
    await idle(bar);
    return state.events.slice(from);
  }

  /** The re-probe failed verification, the handler was told which engine, and the request ran again. */
  function assertFollowedAndRetried(events: string[]): void {
    const at = events.findIndex((e) => e.startsWith("handler "));
    assert.ok(at > 0, events.join("\n"));
    assert.strictEqual(events[at], `handler ${LOOPBACK}`, events.join("\n"));
    const failed = events[at - 1];
    assert.ok(failed.startsWith(`request ${LOOPBACK}/`), events.join("\n"));
    assert.strictEqual(events[at + 1], failed, `the same request again after the handler:\n${events.join("\n")}`);
  }

  test("extension activation installs followCertificateChange as the trust failure handler", () => {
    assert.strictEqual(installed, mods.engineTrust.followCertificateChange);
  });

  test("a probe after Start reaches the handler through withRenewalRetry, and retries", async () => {
    const start = state.commands.get("messagefoundry.startEngine");
    assert.ok(start !== undefined);
    const probes = await captureProbes(() => start());
    assert.strictEqual(state.terminals.filter((t) => t.name === "MessageFoundry Engine").length, 1);
    assertFollowedAndRetried(await runProbe(probes));
  });

  test("a probe after Restart reaches the handler through withRenewalRetry, and retries", async () => {
    const start = state.commands.get("messagefoundry.startEngine");
    const restart = state.commands.get("messagefoundry.restartEngine");
    assert.ok(start !== undefined && restart !== undefined);
    await captureProbes(() => start());
    const first = state.terminals.find((t) => t.name === "MessageFoundry Engine");
    const probes = await captureProbes(() => restart());
    const serves = state.terminals.filter((t) => t.name === "MessageFoundry Engine");
    assert.strictEqual(serves.length, 2, "Restart started a second serve");
    assert.ok(first?.exitStatus !== undefined, "Restart stopped the first serve");
    assertFollowedAndRetried(await runProbe(probes));
  });
});
