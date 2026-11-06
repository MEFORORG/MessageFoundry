// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The pure judging half of the OS trust store probe (BACKLOG #4576). The probe itself runs only in
// `.github/workflows/ide-os-trust-probe.yml`; these pin what it prints and when it calls itself
// broken.
import * as assert from "assert";

import {
  fieldValue,
  httpsSpecifiers,
  instrumentProblems,
  isHostReport,
  outcomeOf,
  probeLine,
  specifierProblems,
  TRUSTED,
} from "../osTrustProbeModel";
import type { HostReport, Launch, Outcome, ProbePath, ProbeRecord } from "../osTrustProbeModel";

const trusted: Outcome = TRUSTED;
const refused: Outcome = { result: "refused", code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" };

type Overrides = Partial<Record<ProbePath, ProbeRecord>>;

function report(settingRead: unknown, client: Outcome, overrides: Overrides = {}): HostReport {
  const records: ProbeRecord[] = [
    overrides["engine-client"] ?? { path: "engine-client", pin: "none", outcome: client },
    overrides["bare-https-control"] ?? { path: "bare-https-control", pin: "n/a", outcome: client },
    overrides["explicit-ca-control"] ?? {
      path: "explicit-ca-control",
      pin: "n/a",
      outcome: trusted,
    },
  ];
  return { context: [["os", "linux"]], settingRead, records };
}

function launch(on: boolean, client: Outcome, overrides?: Overrides): Launch {
  return { settingWritten: on, report: report(on, client, overrides), failure: undefined };
}

/** Every problem the judge names for a run whose plain-Node control was refused. */
function problemsOf(...launches: Launch[]): string {
  return instrumentProblems(refused, launches).join("\n");
}

suite("OS trust store probe model (BACKLOG #4576)", () => {
  test("a certificate code is refused, and any other failure, even an empty one, is an error", () => {
    assert.deepStrictEqual(outcomeOf(undefined), { result: "error", code: "NO_CODE" });
    assert.deepStrictEqual(outcomeOf({ status: 404 }), { result: "error", code: "HTTP_404" });
    assert.deepStrictEqual(outcomeOf({ code: "SELF_SIGNED_CERT_IN_CHAIN" }), {
      result: "refused",
      code: "SELF_SIGNED_CERT_IN_CHAIN",
    });
    assert.deepStrictEqual(outcomeOf({ code: "ECONNREFUSED" }), {
      result: "error",
      code: "ECONNREFUSED",
    });
    assert.deepStrictEqual(outcomeOf(new Error("no code")), { result: "error", code: "NO_CODE" });
    assert.deepStrictEqual(outcomeOf(null), { result: "error", code: "NO_CODE" });
  });

  test("a pin refusal is an error, not a refusal: the probe target must carry no pin", () => {
    assert.strictEqual(outcomeOf({ code: "MF_CAFILE_UNREAD" }).result, "error");
  });

  test("a line carries the context, path and pin, and a code only when not trusted", () => {
    const context: Array<[string, string]> = [
      ["os", "win32"],
      ["http.systemCertificates", "true"],
    ];
    const head = "IDE-OS-TRUST-PROBE os=win32 http.systemCertificates=true path=engine-client pin=none";
    assert.strictEqual(
      probeLine(context, { path: "engine-client", pin: "none", outcome: trusted }),
      `${head} result=trusted`,
    );
    assert.strictEqual(
      probeLine(context, { path: "engine-client", pin: "none", outcome: refused }),
      `${head} result=refused code=UNABLE_TO_VERIFY_LEAF_SIGNATURE`,
    );
  });

  test("a field value never splits a line or comes out empty", () => {
    assert.strictEqual(fieldValue("Ubuntu 24.04\tLTS"), "Ubuntu_24.04_LTS");
    assert.strictEqual(fieldValue(""), "-");
    assert.strictEqual(fieldValue(undefined), "undefined");
    assert.strictEqual(fieldValue(true), "true");
  });

  test("either answer for the engine client is a finding, not a broken instrument", () => {
    for (const [on, off] of [
      [trusted, refused],
      [refused, refused],
      [trusted, trusted],
      [refused, trusted],
    ]) {
      assert.strictEqual(problemsOf(launch(true, on), launch(false, off)), "");
    }
  });

  test("a plain-Node control that is not refused, trusted or failed, makes the run unreadable", () => {
    for (const plain of [trusted, { result: "error", code: "ECONNREFUSED" } as Outcome]) {
      const problems = instrumentProblems(plain, [launch(true, trusted), launch(false, refused)]);
      assert.strictEqual(problems.length, 1);
      assert.match(problems[0], new RegExp(`plain-node-control was ${plain.result}`));
    }
  });

  test("a launch that failed is broken even when it left a report", () => {
    const failed: Launch = { ...launch(false, refused), failure: "the VS Code launch failed: exit 1" };
    assert.match(
      problemsOf(launch(true, trusted), failed),
      /^http.systemCertificates off: the VS Code launch failed: exit 1$/,
    );
  });

  test("a control's own non-certificate error is broken, for both in-host controls", () => {
    const bareError = launch(true, trusted, {
      "bare-https-control": {
        path: "bare-https-control",
        pin: "n/a",
        outcome: { result: "error", code: "MF_TIMEOUT" },
      },
    });
    assert.match(problemsOf(bareError, launch(false, refused)), /bare-https-control failed with MF_TIMEOUT/);
    const caError = launch(true, trusted, {
      "explicit-ca-control": {
        path: "explicit-ca-control",
        pin: "n/a",
        outcome: { result: "error", code: "ECONNRESET" },
      },
    });
    assert.match(problemsOf(caError, launch(false, refused)), /explicit-ca-control was not trusted/);
  });

  test("a parsed report must carry context and records arrays", () => {
    assert.ok(isHostReport(report(true, trusted)));
    assert.ok(!isHostReport({ context: [], settingRead: true }));
    assert.ok(!isHostReport({ context: [], records: [1] }));
    assert.ok(!isHostReport(null));
  });

  test("the measured client and the shipped bundle must require the same https specifier", () => {
    const nodePrefixed = 'var a = require("node:https"); var b = require("node:http");';
    assert.deepStrictEqual(httpsSpecifiers(nodePrefixed), ["node:https"]);
    assert.deepStrictEqual(specifierProblems(nodePrefixed, nodePrefixed), []);
    assert.match(
      specifierProblems('require("https")', nodePrefixed).join("\n"),
      /shipped bundle requires https but the measured client requires node:https/,
    );
    assert.match(specifierProblems(nodePrefixed, "").join("\n"), /requires no https module/);
  });

  test("a launch that did not read back the value written is broken", () => {
    const misread: Launch = {
      settingWritten: false,
      report: report(true, trusted),
      failure: undefined,
    };
    assert.match(
      problemsOf(launch(true, trusted), misread),
      /^http.systemCertificates off: VS Code read the setting back as true/,
    );
  });

  test("a failed explicit-CA control, a non-certificate error, or a pinned client is broken", () => {
    const badControl = launch(true, trusted, {
      "explicit-ca-control": { path: "explicit-ca-control", pin: "n/a", outcome: refused },
    });
    assert.match(problemsOf(badControl, launch(false, refused)), /explicit-ca-control was not trusted/);

    const unreachable = launch(true, { result: "error", code: "ECONNREFUSED" });
    assert.match(
      problemsOf(unreachable, launch(false, refused)),
      /engine-client failed with ECONNREFUSED/,
    );

    const pinned = launch(true, trusted, {
      "engine-client": { path: "engine-client", pin: "present", outcome: trusted },
    });
    assert.match(problemsOf(pinned, launch(false, refused)), /held a pin or anchor/);
  });

  test("a missing case, a missing report, or a duplicated record is broken", () => {
    assert.match(problemsOf(launch(true, trusted)), /no launch ran with http.systemCertificates off/);

    const noReport: Launch = { settingWritten: false, report: undefined, failure: "exit code 1" };
    assert.match(problemsOf(launch(true, trusted), noReport), /off: exit code 1$/);
    const silent: Launch = { settingWritten: false, report: undefined, failure: undefined };
    assert.match(problemsOf(launch(true, trusted), silent), /off: no report$/);

    const doubled = launch(true, trusted);
    doubled.report?.records.push({ path: "engine-client", pin: "none", outcome: trusted });
    assert.match(problemsOf(doubled, launch(false, refused)), /2 engine-client records, expected 1/);
  });
});
