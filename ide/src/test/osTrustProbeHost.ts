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
// It asserts nothing. It makes three requests and runs one store control, writes what each did to
// MF_OS_TRUST_PROBE_OUT, and the launcher judges the run.
import { X509Certificate } from "node:crypto";
import * as fs from "node:fs";
import * as nodeHttps from "node:https";
import * as os from "node:os";
import * as path from "node:path";

// The bare specifier on purpose: VS Code's loader substitutes it. See osTrustProbeModel.ts.
import * as bareHttps from "https";
import * as vscode from "vscode";

import { getJson, pinRefusal, setTrustFailureHandler, tlsOptions } from "../engineClient";
import { outcomeOf, TRUSTED } from "./osTrustProbeModel";
import type { HostReport, Outcome, StoreControl } from "./osTrustProbeModel";
import { getOutcome, PROBE_TIMEOUT_MS } from "./osTrustProbeRequest";

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set; run this through runOsTrustProbe.js`);
  }
  return value;
}

/** Where VS Code may keep its bundled proxy-agent: unpacked, or in an asar archive. */
function proxyAgentDirs(): string[] {
  return ["node_modules", "node_modules.asar"].map((dir) =>
    path.join(vscode.env.appRoot, dir, "@vscode", "proxy-agent"),
  );
}

/** `err`'s message on one line, so it fits one `IDE-OS-TRUST-PROBE` line. */
function oneLine(err: unknown): string {
  return (err instanceof Error ? err.message : String(err)).replace(/\s+/g, " ").trim();
}

/** The version of the proxy agent VS Code bundles, best effort: it lives in an asar archive the
 *  Extension Host may or may not be able to read. */
function proxyAgentVersion(): string {
  for (const dir of proxyAgentDirs()) {
    try {
      const file = path.join(dir, "package.json");
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

/** The SHA-256 fingerprint of a PEM certificate, or undefined when it does not parse. */
function fingerprint(pem: string): string | undefined {
  try {
    return new X509Certificate(pem).fingerprint256;
  } catch {
    return undefined;
  }
}

/** How long the store control may take; past it the control is graded broken and the report is
 *  still written with every measurement already taken. */
const STORE_TIMEOUT_MS = 60_000;

type LoadSystemCertificates = (params: {
  loadSystemCertificatesFromNode: () => boolean | undefined;
  log: Record<"trace" | "debug" | "info" | "warn" | "error", (...args: unknown[]) => void>;
}) => Promise<string[]>;

/** The bundled proxy-agent's `loadSystemCertificates`, from the first location that has it. */
function loadSystemCertificatesFn(): LoadSystemCertificates {
  const errors: string[] = [];
  for (const dir of proxyAgentDirs()) {
    try {
      const agent = require(dir) as { loadSystemCertificates?: unknown };
      if (typeof agent.loadSystemCertificates === "function") {
        return agent.loadSystemCertificates as LoadSystemCertificates;
      }
      errors.push(`${path.basename(path.dirname(path.dirname(dir)))}: no loadSystemCertificates`);
    } catch (err) {
      errors.push(oneLine(err));
    }
  }
  throw new Error(`the bundled proxy-agent could not be loaded (${errors.join("; ")})`);
}

/**
 * The store control: is the test CA among the certificates proxy-agent's `loadSystemCertificates`
 * returns, called the way VS Code calls it, with `http.systemCertificatesNode` choosing Node's reader
 * or the platform's? It makes no request, so it stands apart from every request it vouches for. It
 * shows what that loader returns when asked; it does not read the set VS Code holds in memory, and in
 * a launch with the setting off VS Code loads none. The loader logs a reader failure rather than
 * throwing, so `error()` lines are kept and reported.
 */
async function storeControl(caPem: string, fromNode: boolean | undefined): Promise<StoreControl> {
  const wanted = fingerprint(caPem);
  if (wanted === undefined) {
    return { source: "none", caPresent: undefined, error: "the test CA does not parse" };
  }
  const logged: string[] = [];
  const ignore = (): void => {};
  const log = {
    trace: ignore,
    debug: ignore,
    info: ignore,
    warn: ignore,
    error: (...args: unknown[]) => logged.push(args.map(oneLine).join(" ")),
  };
  const errorText = (): string | undefined =>
    logged.length === 0 ? undefined : `proxy-agent logged: ${logged.join(" | ")}`;
  let timer: NodeJS.Timeout | undefined;
  try {
    const load = loadSystemCertificatesFn();
    const expired = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error(`timed out after ${STORE_TIMEOUT_MS / 1000} s`)),
        STORE_TIMEOUT_MS,
      );
    });
    const certs = await Promise.race([
      load({ loadSystemCertificatesFromNode: () => fromNode, log }),
      expired,
    ]);
    const caPresent = certs.some((pem) => fingerprint(pem) === wanted);
    const error = errorText();
    return error === undefined
      ? { source: "proxy-agent", caPresent }
      : { source: "proxy-agent", caPresent, error };
  } catch (err) {
    const error = [oneLine(err), errorText()].filter((e) => e !== undefined).join("; ");
    return { source: "none", caPresent: undefined, error };
  } finally {
    clearTimeout(timer);
  }
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
  // Both values. The user-settings one shows settings.json was read (the default is true, so the
  // effective value alone could not tell on the `on` launch); the effective one is what VS Code acts
  // on, and a policy or default override could make it differ.
  const settingRead: unknown = http.inspect("systemCertificates")?.globalValue;
  const settingEffective: unknown = http.get("systemCertificates");

  // The measurement goes first, so no earlier request to the same server can have left a session or
  // a pooled socket behind for it to reuse.
  const client: Outcome = await getJson<unknown>(target, "/health", undefined, PROBE_TIMEOUT_MS).then(
    () => TRUSTED,
    outcomeOf,
  );
  const bare = await getOutcome(bareHttps.get, health, {});
  const explicitCa = await getOutcome(nodeHttps.get, health, { ca: caPem });
  const certificatesNode: unknown = http.get("systemCertificatesNode");
  const store = await storeControl(
    caPem,
    typeof certificatesNode === "boolean" ? certificatesNode : undefined,
  );

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
      ["http.systemCertificates.effective", String(settingEffective)],
      ["storeSource", store.source],
      ["caInSystemStore", String(store.caPresent)],
      ["http.systemCertificatesNode", String(certificatesNode)],
      ["http.experimental.systemCertificatesV2", String(http.get("experimental.systemCertificatesV2"))],
      ["http.proxySupport", String(http.get("proxySupport"))],
      // Diagnostics only: whether each specifier's `request` is the builtin's own, read past VS Code's
      // loader. "no" means the loader substituted that specifier; "yes" for both means it substituted
      // neither, or patched the builtin itself. The result fields, not these, are the measurement.
      ["httpsIsBuiltin", sameAsBuiltin(bareHttps.request)],
      ["nodeHttpsIsBuiltin", sameAsBuiltin(nodeHttps.request)],
    ],
    settingRead,
    settingEffective,
    storeControl: store,
    records: [
      { path: "engine-client", pin, outcome: client },
      { path: "bare-https-control", pin: "n/a", outcome: bare },
      { path: "explicit-ca-control", pin: "n/a", outcome: explicitCa },
    ],
  };
  fs.writeFileSync(outFile, JSON.stringify(report, null, 2), "utf8");
}
