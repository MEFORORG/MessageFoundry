// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The extensionTestsPath `runOsTrustProbe.ts` launches, once per value of `http.systemCertificates`
// (BACKLOG #4576). It runs INSIDE VS Code's Extension Host because that is where the setting acts:
// VS Code's module loader hands an extension its proxy-agent copy of `http`/`https`, and plain Node
// never sees it. This file sits in the extension's own folder, so the loader treats it, and the
// `engineClient.js` it imports, as the extension's code. That `engineClient.js` is the tsc build of
// the same source esbuild bundles into dist/extension.js, and both keep its `node:https` specifier.
//
// It asserts nothing. It makes three requests, writes what each did to MF_OS_TRUST_PROBE_OUT, and
// the launcher judges the run.
import * as fs from "node:fs";
import * as nodeHttps from "node:https";
import * as os from "node:os";
import * as path from "node:path";

// The bare specifier on purpose: VS Code's loader substitutes it. See osTrustProbeModel.ts.
import * as bareHttps from "https";
import * as vscode from "vscode";

import { getJson, pinRefusal, setTrustFailureHandler, tlsOptions } from "../engineClient";
import { outcomeOf, TRUSTED } from "./osTrustProbeModel";
import type { HostReport, Outcome } from "./osTrustProbeModel";
import { getOutcome, PROBE_TIMEOUT_MS } from "./osTrustProbeRequest";

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set; run this through runOsTrustProbe.js`);
  }
  return value;
}

/** The version of the proxy agent VS Code bundles, best effort: it lives in an asar archive the
 *  Extension Host may or may not be able to read. */
function proxyAgentVersion(): string {
  for (const dir of ["node_modules", "node_modules.asar"]) {
    try {
      const file = path.join(vscode.env.appRoot, dir, "@vscode", "proxy-agent", "package.json");
      const version = (JSON.parse(fs.readFileSync(file, "utf8")) as { version?: unknown }).version;
      if (typeof version === "string") {
        return version;
      }
    } catch {
      // Try the next location; "unknown" is an honest answer.
    }
  }
  return "unknown";
}

/** "yes" when `request` is the builtin `https.request`, fetched with `process.getBuiltinModule`,
 *  which no `Module._load` hook sees; "unknown" on a Node too old to have it. */
function sameAsBuiltin(request: unknown): string {
  const host = process as { getBuiltinModule?: (id: string) => unknown };
  const builtin = host.getBuiltinModule?.("node:https") as typeof nodeHttps | undefined;
  if (builtin === undefined) {
    return "unknown";
  }
  return builtin.request === request ? "yes" : "no";
}

export async function run(): Promise<void> {
  const target = required("MF_OS_TRUST_PROBE_URL");
  const caPem = fs.readFileSync(required("MF_OS_TRUST_PROBE_CA"), "utf8");
  const outFile = required("MF_OS_TRUST_PROBE_OUT");
  const health = `${target}/health`;
  const http = vscode.workspace.getConfiguration("http");

  // This module instance of the client has no anchors, pins or failure handler: the extension's own
  // copy lives in dist/extension.js. Clearing the handler anyway keeps a follow-up re-read out of it.
  // So `pin` describes THIS copy, the one the request below goes through, not the installed
  // extension's; it guards against a future client that finds an anchor on its own.
  setTrustFailureHandler(undefined);
  const url = new URL(target);
  const pin = tlsOptions(url).ca === undefined && pinRefusal(url) === undefined ? "none" : "present";
  const settingRead: unknown = http.get("systemCertificates");

  // The measurement goes first, so no earlier request to the same server can have left a session or
  // a pooled socket behind for it to reuse.
  const client: Outcome = await getJson<unknown>(target, "/health", undefined, PROBE_TIMEOUT_MS).then(
    () => TRUSTED,
    outcomeOf,
  );
  const bare = await getOutcome(bareHttps.get, health, {});
  const explicitCa = await getOutcome(nodeHttps.get, health, { ca: caPem });

  const report: HostReport = {
    context: [
      ["os", process.platform],
      ["osRelease", os.release()],
      ["arch", process.arch],
      ["vscode", vscode.version],
      ["electron", process.versions.electron ?? "none"],
      ["node", process.versions.node],
      ["proxyAgent", proxyAgentVersion()],
      ["http.systemCertificates", String(settingRead)],
      ["http.systemCertificatesNode", String(http.get("systemCertificatesNode"))],
      ["http.experimental.systemCertificatesV2", String(http.get("experimental.systemCertificatesV2"))],
      ["http.proxySupport", String(http.get("proxySupport"))],
      // Diagnostics only: whether each specifier's `request` is the builtin's own, read past VS Code's
      // loader. "no" means the loader substituted that specifier; "yes" for both means it substituted
      // neither, or patched the builtin itself. The result fields, not these, are the measurement.
      ["httpsIsBuiltin", sameAsBuiltin(bareHttps.request)],
      ["nodeHttpsIsBuiltin", sameAsBuiltin(nodeHttps.request)],
    ],
    settingRead,
    records: [
      { path: "engine-client", pin, outcome: client },
      { path: "bare-https-control", pin: "n/a", outcome: bare },
      { path: "explicit-ca-control", pin: "n/a", outcome: explicitCa },
    ],
  };
  fs.writeFileSync(outFile, JSON.stringify(report, null, 2), "utf8");
}
