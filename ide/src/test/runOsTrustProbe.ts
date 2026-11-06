// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The OS trust store probe's launcher (BACKLOG #4576). `.github/workflows/ide-os-trust-probe.yml`
// runs it on a hosted runner, after that job has imported a disposable test CA into the runner's OS
// store. It is not part of `npm test`, and the CA import it relies on must never be done on a real
// machine: without that import it measures nothing worth recording.
//
// It serves TLS on 127.0.0.1 under a leaf the test CA signed, makes one plain-Node control request,
// then launches VS Code twice, with `http.systemCertificates` written on and then off in a fresh
// profile's user settings, running osTrustProbeHost.ts in each. It prints one IDE-OS-TRUST-PROBE line
// per request, and exits non-zero only when the instrument is broken (osTrustProbeModel.ts says
// which cases those are). A refused engine client is a finding and exits 0.
//
// Inputs, all from the environment:
//   MF_OS_TRUST_PROBE_DIR     a directory holding ca.pem, leaf.pem and leaf.key (the job makes them)
//   MF_OS_TRUST_PROBE_VSCODE  the VS Code build to launch: "stable" (the default) or X.Y.Z
import * as fs from "node:fs";
import * as https from "node:https";
import type { AddressInfo } from "node:net";
import * as path from "node:path";

import { downloadAndUnzipVSCode, runTests } from "@vscode/test-electron";

import {
  instrumentProblems,
  isHostReport,
  PROBE_TAG,
  probeLine,
  settingWord,
  specifierProblems,
} from "./osTrustProbeModel";
import type { HostReport, Launch } from "./osTrustProbeModel";
import { getOutcome } from "./osTrustProbeRequest";

const VERSION_RE = /^(stable|\d+\.\d+\.\d+)$/;

/**
 * Variables that can make a Node TLS client trust the test CA, or skip verification, by a route that
 * is not the setting under test. VS Code inherits the launcher's environment, so each would reach
 * the Extension Host too. At least these; `NODE_OPTIONS` covers the command-line forms.
 */
const REFUSED_ENV = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_OPTIONS",
  "NODE_USE_SYSTEM_CA",
  "NODE_TLS_REJECT_UNAUTHORIZED",
];

/** The compiled launcher lives at out/test/, so ../../ is the ide/ extension root. */
const EXTENSION_ROOT = path.resolve(__dirname, "../../");

function errorText(err: unknown, withStack = false): string {
  if (!(err instanceof Error)) {
    return String(err);
  }
  return withStack && err.stack !== undefined ? err.stack : err.message;
}

function listen(server: https.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
  });
}

/** Launch VS Code once with `http.systemCertificates` written as `on`, and read what it reported. */
async function launchOnce(
  on: boolean,
  dir: string,
  target: string,
  vscodeExecutablePath: string,
): Promise<Launch> {
  const profile = path.join(dir, `profile-${settingWord(on)}`);
  const userData = path.join(profile, "user-data");
  const outFile = path.join(profile, "report.json");
  let failure: string | undefined;
  try {
    fs.mkdirSync(path.join(userData, "User"), { recursive: true });
    const settings = {
      "http.systemCertificates": on,
      "update.mode": "none",
      "telemetry.telemetryLevel": "off",
    };
    fs.writeFileSync(path.join(userData, "User", "settings.json"), JSON.stringify(settings), "utf8");
    fs.rmSync(outFile, { force: true });
    // runTests adds its own fixed flags, `--no-sandbox` among them, to every launch.
    await runTests({
      vscodeExecutablePath,
      extensionDevelopmentPath: EXTENSION_ROOT,
      extensionTestsPath: path.resolve(__dirname, "./osTrustProbeHost"),
      launchArgs: [`--user-data-dir=${userData}`, `--extensions-dir=${path.join(profile, "extensions")}`],
      extensionTestsEnv: {
        MF_OS_TRUST_PROBE_URL: target,
        MF_OS_TRUST_PROBE_CA: path.join(dir, "ca.pem"),
        MF_OS_TRUST_PROBE_OUT: outFile,
      },
    });
  } catch (err) {
    failure = `the VS Code launch failed: ${errorText(err)}`;
  }
  let report: HostReport | undefined;
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(outFile, "utf8"));
    if (isHostReport(parsed)) {
      report = parsed;
    } else {
      failure ??= "the report is not in the shape the host writes";
    }
  } catch (err) {
    failure ??= `no readable report: ${errorText(err)}`;
  }
  return { settingWritten: on, report, failure };
}

/** Everything the run measured and judged, as lines; a setup failure is a problem like any other. */
async function probe(lines: string[], problems: string[]): Promise<void> {
  const dir = process.env.MF_OS_TRUST_PROBE_DIR;
  if (!dir) {
    problems.push("MF_OS_TRUST_PROBE_DIR is not set");
    return;
  }
  const version = process.env.MF_OS_TRUST_PROBE_VSCODE?.trim() || "stable";
  if (!VERSION_RE.test(version)) {
    problems.push(`MF_OS_TRUST_PROBE_VSCODE is ${JSON.stringify(version)}; expected stable or X.Y.Z`);
    return;
  }
  const set = REFUSED_ENV.filter((name) => process.env[name]);
  if (set.length > 0) {
    problems.push(`${set.join(", ")} set; unset, or no result could be credited to the setting`);
    return;
  }
  problems.push(
    ...specifierProblems(
      fs.readFileSync(path.join(EXTENSION_ROOT, "dist", "extension.js"), "utf8"),
      fs.readFileSync(path.join(EXTENSION_ROOT, "out", "engineClient.js"), "utf8"),
    ),
  );

  const server = https.createServer(
    {
      key: fs.readFileSync(path.join(dir, "leaf.key")),
      cert: fs.readFileSync(path.join(dir, "leaf.pem")),
    },
    (_req, res) => {
      // `Connection: close`, so no request can ride a socket an earlier one verified.
      res.writeHead(200, { "Content-Type": "application/json", Connection: "close" });
      res.end('{"status":"ok"}');
    },
  );
  const target = `https://127.0.0.1:${await listen(server)}`;
  try {
    // No `ca` and no agent: Node's own bundled roots alone decide.
    const plainNode = await getOutcome(https.get, `${target}/health`, { agent: false });
    const plainContext: Array<[string, string]> = [
      ["os", process.platform],
      ["node", process.versions.node],
    ];
    lines.push(probeLine(plainContext, { path: "plain-node-control", pin: "n/a", outcome: plainNode }));

    const vscodeExecutablePath = await downloadAndUnzipVSCode(version);
    const launches: Launch[] = [];
    for (const on of [true, false]) {
      const launch = await launchOnce(on, dir, target, vscodeExecutablePath);
      launches.push(launch);
      const context: Array<[string, string]> = [
        ["written", settingWord(on)],
        ...(launch.report?.context ?? []),
      ];
      for (const record of launch.report?.records ?? []) {
        lines.push(probeLine(context, record));
      }
    }
    problems.push(...instrumentProblems(plainNode, launches));
  } finally {
    server.close();
  }
}

/** Print the lines and the verdict to stdout and, on a runner, to the job summary. */
function emit(lines: readonly string[], problems: readonly string[]): void {
  const verdict = `${PROBE_TAG} instrument=${problems.length === 0 ? "sound" : "BROKEN"}`;
  const text = [...lines, verdict, ...problems.map((p) => `${PROBE_TAG} problem: ${p}`)].join("\n");
  process.stdout.write(`${text}\n`);
  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary) {
    const heading = `### IDE OS trust store probe (${process.platform})`;
    fs.appendFileSync(summary, `${heading}\n\n\`\`\`\n${text}\n\`\`\`\n`, "utf8");
  }
}

async function main(): Promise<void> {
  const lines: string[] = [];
  const problems: string[] = [];
  try {
    await probe(lines, problems);
  } catch (err) {
    problems.push(`the probe stopped: ${errorText(err, true)}`);
  }
  emit(lines, problems);
  // exitCode, not exit(): stdout may be a pipe still draining the lines above.
  process.exitCode = problems.length === 0 ? 0 : 1;
}

void main();
