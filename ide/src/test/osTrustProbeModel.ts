// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The pure half of the OS trust store probe (BACKLOG #4576, the last step of #1695). No `vscode`, no
// I/O, so the unit suite can pin it. `runOsTrustProbe.ts` is the launcher and `osTrustProbeHost.ts`
// runs inside VS Code's Extension Host; `.github/workflows/ide-os-trust-probe.yml` is the only caller.
//
// THE QUESTION. Does a CA in the OS certificate store verify the extension's engine client, for a
// target with no `caFile` and no local anchor, with `http.systemCertificates` on? And with it off?
//
// WHAT TURNS THE RUN RED, AND WHAT DOES NOT. The answer is a finding, whichever way it falls, so a
// "refused" for the engine client never fails the run. Only a broken instrument does: the CA trusted
// where nothing but the OS store should make it trusted, a setting VS Code did not read back, a
// positive control that failed, or a case that produced no report. {@link instrumentProblems} lists
// them, and an empty list is the only green.

import { TLS_TRUST_CODES } from "../engineTrustModel";

/** The first word of every summary line, so a reader can grep a job log for them. */
export const PROBE_TAG = "IDE-OS-TRUST-PROBE";

/**
 * Which request a line reports.
 *
 * - `engine-client`: the measurement. The extension's own `getJson`, from `engineClient.ts`, which
 *   imports `node:https`, against a target it holds no anchor and no pin for.
 * - `bare-https-control`: a plain `https.get` with no `ca`, through the bare `https` specifier. VS
 *   Code's Extension Host substitutes its proxy-agent module for that specifier, so this line says
 *   whether the setting reaches a request at all, apart from how the client imports the module.
 * - `explicit-ca-control`: a request carrying the test CA as its `ca`. Must be trusted, or the server
 *   or the certificates are broken and no other line means anything.
 * - `plain-node-control`: the launcher's own request, in plain Node outside VS Code, with no `ca`.
 *   Must be refused: a trusted one means something other than the OS store trusts the CA (Node's
 *   bundled roots, `NODE_EXTRA_CA_CERTS`), so a "trusted" in VS Code could not be credited to it.
 */
export type ProbePath =
  | "engine-client"
  | "bare-https-control"
  | "explicit-ca-control"
  | "plain-node-control";

/** The three paths each Extension Host launch reports, in the order it runs them. */
const HOST_PATHS: readonly ProbePath[] = [
  "engine-client",
  "bare-https-control",
  "explicit-ca-control",
];

/** How one request ended. `refused` is a certificate the client would not verify; `error` is
 *  anything else, which means the instrument, not the trust decision, failed. */
export type Outcome = { result: "trusted" } | { result: "refused" | "error"; code: string };

/** The outcome of a request that threw `err`, or of one that succeeded when `err` is `undefined`. */
export function outcomeOf(err: unknown): Outcome {
  if (err === undefined) {
    return { result: "trusted" };
  }
  const raw = (err as { code?: unknown } | null)?.code;
  const code = typeof raw === "string" && raw.length > 0 ? raw : "NO_CODE";
  return TLS_TRUST_CODES.includes(code) ? { result: "refused", code } : { result: "error", code };
}

/** One request's line in a launch's report. */
export interface ProbeRecord {
  path: ProbePath;
  /** Whether the extension's client held a trust anchor or a `caFile` pin for the target. Only the
   *  engine-client record reads it; the controls bypass the client and carry `n/a`. */
  pin: "none" | "present" | "n/a";
  outcome: Outcome;
}

/** What one Extension Host launch writes for the launcher to read. */
export interface HostReport {
  /** Name/value pairs describing where it ran, already in print order. */
  context: Array<[string, string]>;
  /** `http.systemCertificates` as the Extension Host read it back. */
  settingRead: unknown;
  records: ProbeRecord[];
}

/** One launch as the launcher saw it: the value it wrote, and the report or why there was none. */
export interface Launch {
  settingWritten: boolean;
  report: HostReport | undefined;
  failure: string | undefined;
}

/** A value made safe for a `name=value` field: no whitespace, never empty. */
export function fieldValue(value: unknown): string {
  const text = typeof value === "string" ? value : JSON.stringify(value) ?? "undefined";
  const flat = text.replace(/\s+/g, "_");
  return flat.length > 0 ? flat : "-";
}

/** The summary line for one record: the tag, then `name=value` fields, the result last. */
export function probeLine(context: ReadonlyArray<[string, string]>, record: ProbeRecord): string {
  const fields: Array<[string, string]> = [
    ...context,
    ["path", record.path],
    ["pin", record.pin],
    ["result", record.outcome.result],
  ];
  if (record.outcome.result !== "trusted") {
    fields.push(["code", record.outcome.code]);
  }
  return [PROBE_TAG, ...fields.map(([name, value]) => `${name}=${fieldValue(value)}`)].join(" ");
}

/** The words a line uses for a value of `http.systemCertificates` the launcher wrote. */
export function settingWord(on: boolean): string {
  return on ? "on" : "off";
}

/**
 * Every reason the run cannot be read, or an empty list when it can. See the file header: a refused
 * engine client is a finding and never appears here.
 */
export function instrumentProblems(plainNode: Outcome, launches: readonly Launch[]): string[] {
  const problems: string[] = [];
  if (plainNode.result !== "refused") {
    const code = plainNode.result === "trusted" ? "" : ` (${plainNode.code})`;
    problems.push(
      `plain-node-control was ${plainNode.result}${code}, not refused: something other than the ` +
        "OS store trusts the test CA, so no VS Code line can be credited to the store",
    );
  }
  for (const on of [true, false]) {
    if (!launches.some((l) => l.settingWritten === on)) {
      problems.push(`no launch ran with http.systemCertificates ${settingWord(on)}`);
    }
  }
  for (const launch of launches) {
    const label = `http.systemCertificates ${settingWord(launch.settingWritten)}`;
    if (launch.report === undefined) {
      problems.push(`${label}: no report (${launch.failure ?? "no reason given"})`);
      continue;
    }
    const { report } = launch;
    if (report.settingRead !== launch.settingWritten) {
      problems.push(
        `${label}: VS Code read the setting back as ${fieldValue(report.settingRead)}, so the launch ` +
          "did not run with the value written",
      );
    }
    for (const path of HOST_PATHS) {
      const matching = report.records.filter((r) => r.path === path);
      if (matching.length !== 1) {
        problems.push(`${label}: ${matching.length} ${path} records, expected 1`);
        continue;
      }
      const [record] = matching;
      if (path === "explicit-ca-control" && record.outcome.result !== "trusted") {
        problems.push(
          `${label}: explicit-ca-control was not trusted, so the server or the CA is broken`,
        );
      }
      if (path !== "explicit-ca-control" && record.outcome.result === "error") {
        problems.push(
          `${label}: ${path} failed with ${record.outcome.code}, which is not a certificate refusal`,
        );
      }
      if (path === "engine-client" && record.pin !== "none") {
        problems.push(`${label}: the engine client held a pin or anchor for the target`);
      }
    }
  }
  return problems;
}
