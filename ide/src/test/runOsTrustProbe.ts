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

import { instrumentProblems, PROBE_TAG, probeLine, settingWord } from "./osTrustProbeModel";
import type { HostReport, Launch } from "./osTrustProbeModel";
import { getOutcome } from "./osTrustProbeRequest";

const VERSION_RE = /^(stable|\d+\.\d+\.\d+)$/;

function fail(message: string): never {
  console.error(`${PROBE_TAG} ERROR ${message}`);
  process.exit(1);
}

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
  fs.mkdirSync(path.join(userData, "User"), { recursive: true });
  const settings = {
    "http.systemCertificates": on,
    "update.mode": "none",
    "telemetry.telemetryLevel": "off",
  };
  fs.writeFileSync(path.join(userData, "User", "settings.json"), JSON.stringify(settings), "utf8");
  const outFile = path.join(profile, "report.json");
  fs.rmSync(outFile, { force: true });

  let failure: string | undefined;
  try {
    await runTests({
      vscodeExecutablePath,
      // The compiled launcher lives at out/test/, so ../../ is the ide/ extension root.
      extensionDevelopmentPath: path.resolve(__dirname, "../../"),
      extensionTestsPath: path.resolve(__dirname, "./osTrustProbeHost"),
      launchArgs: [
        `--user-data-dir=${userData}`,
        `--extensions-dir=${path.join(profile, "extensions")}`,
        // Ubuntu 24.04 refuses Chromium's sandbox to an unprivileged process. The sandbox guards
        // renderers; the Extension Host, where the requests run, is not one.
        ...(process.platform === "linux" ? ["--no-sandbox"] : []),
      ],
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
    report = JSON.parse(fs.readFileSync(outFile, "utf8")) as HostReport;
  } catch (err) {
    failure ??= `no readable report: ${errorText(err)}`;
  }
  return { settingWritten: on, report, failure };
}

async function main(): Promise<void> {
  const dir = process.env.MF_OS_TRUST_PROBE_DIR;
  if (!dir) {
    fail("MF_OS_TRUST_PROBE_DIR is not set");
  }
  const version = process.env.MF_OS_TRUST_PROBE_VSCODE?.trim() || "stable";
  if (!VERSION_RE.test(version)) {
    fail(`MF_OS_TRUST_PROBE_VSCODE is ${JSON.stringify(version)}; expected stable or X.Y.Z`);
  }
  // Either can hand the test CA to every Node TLS client by a route that is not the OS store.
  for (const name of ["NODE_EXTRA_CA_CERTS", "NODE_OPTIONS"]) {
    if (process.env[name]) {
      fail(`${name} is set; unset it, or no result could be credited to the OS store`);
    }
  }

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

  // No `ca` and no agent: Node's own bundled roots alone decide.
  const plainNode = await getOutcome(https.get, `${target}/health`, { agent: false });
  const lines = [
    probeLine(
      [
        ["os", process.platform],
        ["node", process.versions.node],
      ],
      { path: "plain-node-control", pin: "n/a", outcome: plainNode },
    ),
  ];

  const vscodeExecutablePath = await downloadAndUnzipVSCode(version);
  const launches: Launch[] = [];
  for (const on of [true, false]) {
    launches.push(await launchOnce(on, dir, target, vscodeExecutablePath));
  }
  server.close();

  for (const launch of launches) {
    const context: Array<[string, string]> = [
      ["written", settingWord(launch.settingWritten)],
      ...(launch.report?.context ?? []),
    ];
    for (const record of launch.report?.records ?? []) {
      lines.push(probeLine(context, record));
    }
  }
  const problems = instrumentProblems(plainNode, launches);
  lines.push(`${PROBE_TAG} instrument=${problems.length === 0 ? "sound" : "BROKEN"}`);
  lines.push(...problems.map((p) => `${PROBE_TAG} problem: ${p}`));

  const text = `${lines.join("\n")}\n`;
  process.stdout.write(text);
  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary) {
    const heading = `### IDE OS trust store probe (${process.platform})`;
    fs.appendFileSync(summary, `${heading}\n\n\`\`\`\n${text}\`\`\`\n`, "utf8");
  }
  if (problems.length > 0) {
    process.exit(1);
  }
}

main().catch((err: unknown) => fail(errorText(err, true)));
