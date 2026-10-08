// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Every line on the "MessageFoundry Checks" channel carries a UTC time stamp, and the one path that
// commits past a failed required check leaves a stamped record that says so (vault BACKLOG #2349,
// #2353). Pure: a fixed clock and an array for the channel, no Extension Host.
import * as assert from "assert";
import * as fs from "node:fs";
import * as path from "node:path";

import { BASELINE_BYPASS_RECORD, stampLines, writeStamped } from "../../checksLog";

// 03:04:05.678 UTC. Built from UTC parts, so the expected text does not depend on the host's zone.
const FIXED = new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 678));
const STAMP = "2026-01-02T03:04:05.678Z";
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z( |$)/;

function collect(text: string): string[] {
  const lines: string[] = [];
  writeStamped({ appendLine: (line) => lines.push(line) }, text, () => FIXED);
  return lines;
}

suite("checksLog: UTC stamps on the Checks channel", () => {
  test("a single line is stamped with the clock's instant in UTC", () => {
    assert.deepStrictEqual(collect("--- pre-flight: messagefoundry check ---"), [
      `${STAMP} --- pre-flight: messagefoundry check ---`,
    ]);
  });

  test("every line of a multi-line block carries a stamp, whatever the line ending", () => {
    const lines = collect("PASS validate\r\nFAIL dryrun\n  detail\rlast");
    assert.deepStrictEqual(lines, [
      `${STAMP} PASS validate`,
      `${STAMP} FAIL dryrun`,
      `${STAMP}   detail`,
      `${STAMP} last`,
    ]);
  });

  test("a blank line inside a block is still stamped, with no trailing space", () => {
    assert.deepStrictEqual(collect("a\n\nb"), [`${STAMP} a`, STAMP, `${STAMP} b`]);
  });

  test("the default clock is the wall clock, and its stamp is UTC with a Z", () => {
    const lines: string[] = [];
    const before = Date.now();
    writeStamped({ appendLine: (line) => lines.push(line) }, "x");
    const after = Date.now();
    assert.strictEqual(lines.length, 1);
    assert.match(lines[0], ISO_UTC);
    const at = Date.parse(lines[0].split(" ")[0]);
    assert.ok(at >= before && at <= after, lines[0]);
  });

  test("stampLines is pure: the same input and instant give the same lines", () => {
    assert.deepStrictEqual(stampLines("a\nb", FIXED), stampLines("a\nb", FIXED));
  });
});

suite("checksLog: the baseline bypass record", () => {
  test("it says the hooks were skipped, by the user's choice, with --no-verify", () => {
    assert.ok(BASELINE_BYPASS_RECORD.includes("SKIPPED"));
    assert.ok(BASELINE_BYPASS_RECORD.includes("user's choice"));
    assert.ok(BASELINE_BYPASS_RECORD.includes("Commit baseline anyway"));
    assert.ok(BASELINE_BYPASS_RECORD.includes("--no-verify"));
    assert.ok(!/[\r\n]/.test(BASELINE_BYPASS_RECORD), "one line, so one stamp covers it");
  });
});

// sourceControl.ts needs a `vscode` host and its commit path is not exported, so these read the
// source. They pin the two properties a later edit could silently undo.
suite("sourceControl.ts: every Checks channel write is stamped", () => {
  const SRC = path.join(__dirname, "..", "..", "..", "src", "sourceControl.ts");
  const source = fs.readFileSync(SRC, "utf8");
  // Comments may name `appendLine`; only code may not call it.
  const code = source
    .split(/\r?\n/)
    .filter((line) => !line.trimStart().startsWith("//"))
    .join("\n");

  test("control: the file read is the real one", () => {
    assert.ok(code.includes('createOutputChannel("MessageFoundry Checks")'));
    assert.ok(code.includes("writeStamped(out(), text)"));
  });

  test("no direct appendLine: the channel has one writer, and it stamps", () => {
    assert.ok(!code.includes("appendLine"), "write to the Checks channel through log()");
    // out() may be used to reveal the channel, and by log() itself. Nothing else.
    const uses = code.match(/\bout\(\)(\.\w+)?/g) ?? [];
    assert.deepStrictEqual([...new Set(uses)].sort(), ["out()", "out().show"]);
  });

  test("the channel stays plain, so the editor adds no second stamp", () => {
    assert.ok(!/createOutputChannel\("MessageFoundry Checks",/.test(code));
  });

  test("the bypass record is logged before the --no-verify commit runs", () => {
    const record = code.indexOf("log(BASELINE_BYPASS_RECORD)");
    const commit = code.indexOf('"--no-verify"');
    assert.ok(record > 0, "the bypass record is no longer logged");
    assert.ok(commit > record, "the record must precede the commit it describes");
    assert.strictEqual(code.split('"--no-verify"').length - 1, 1, "one bypass path, one record");
  });
});
