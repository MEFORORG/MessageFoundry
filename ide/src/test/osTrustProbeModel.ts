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
// "refused" for the engine client never fails the run. Only a broken instrument does, at least: a
// control that went the wrong way, a setting VS Code did not read back, a launch that failed or wrote
// no report, or a shipped bundle that imports `https` differently from the copy the probe measures.
// {@link instrumentProblems} and {@link specifierProblems} are the judges, and the launcher adds
// failures of its own setup. An empty list is the only green.

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
 *   Must be refused. It rules out Node's bundled roots and the environment the launcher refuses
 *   (`NODE_EXTRA_CA_CERTS` and the rest), which VS Code inherits. It runs outside VS Code's runtime,
 *   so it cannot rule out a route only that runtime takes; the `off` launch is the comparison for
 *   that, and a "trusted" there is a finding about the setting, not a broken instrument.
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

/** A request that completed with a 2xx. */
export const TRUSTED: Outcome = { result: "trusted" };

/**
 * The outcome of a request that failed with `err`, whatever `err` is: a rejection is never trusted.
 * An error carrying an HTTP `status` (the client's `HttpError`) reads as `HTTP_<status>`, the code
 * the controls give the same answer.
 */
export function outcomeOf(err: unknown): Outcome {
  const { code: raw, status } = (err ?? {}) as { code?: unknown; status?: unknown };
  let code = "NO_CODE";
  if (typeof raw === "string" && raw.length > 0) {
    code = raw;
  } else if (typeof status === "number") {
    code = `HTTP_${status}`;
  }
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

/** True when `value`, parsed from a report file, has the shape {@link HostReport} names. */
export function isHostReport(value: unknown): value is HostReport {
  const v = value as Partial<HostReport> | null;
  return (
    typeof v === "object" &&
    v !== null &&
    Array.isArray(v.context) &&
    Array.isArray(v.records) &&
    v.records.every((r) => typeof r === "object" && r !== null && "path" in r && "outcome" in r)
  );
}

/** One launch as the launcher saw it: the value it wrote, its report, and what went wrong, if
 *  anything. A failure counts even beside a report: a launch that failed is not a clean reading. */
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
    if (launch.failure !== undefined) {
      problems.push(`${label}: ${launch.failure}`);
    }
    if (launch.report === undefined) {
      if (launch.failure === undefined) {
        problems.push(`${label}: no report`);
      }
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

/** The `https` specifiers a compiled CommonJS file requires: `https`, `node:https`, or both. */
export function httpsSpecifiers(source: string): string[] {
  const found = new Set<string>();
  for (const m of source.matchAll(/require\("((?:node:)?https)"\)/g)) {
    found.add(m[1]);
  }
  return [...found].sort();
}

/**
 * Why the measured copy of the client cannot stand for the shipped one, or an empty list. The probe
 * runs the tsc build (`out/engineClient.js`); the extension ships the esbuild bundle. VS Code's
 * loader may treat the two specifiers differently, so both builds must require the same one, or the
 * probe measures code the extension does not ship.
 */
export function specifierProblems(bundle: string, measured: string): string[] {
  const shipped = httpsSpecifiers(bundle).join(",");
  const probed = httpsSpecifiers(measured).join(",");
  if (probed === "") {
    return ["the measured engineClient.js requires no https module, so it is not the client"];
  }
  if (shipped === probed) {
    return [];
  }
  return [
    `the shipped bundle requires ${shipped || "no https module"} but the measured client requires ` +
      `${probed}, so the probe would measure code the extension does not ship`,
  ];
}
