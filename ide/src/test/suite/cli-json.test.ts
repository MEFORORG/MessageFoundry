// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// cliJson.parseJsonResult: a failed CLI result never quotes the CLI's output (ASVS 14.2.6, vault
// BACKLOG #1187, ground d2). Every caller of runJson shows this message somewhere: the Live Debug lens
// title and status tooltip, and the Test Bench Run, Load and trace toasts among them.
import * as assert from "assert";

import {
  CliOutputError,
  UNTRUSTED_WORKSPACE_STDERR,
  commandLabel,
  parseJsonResult,
  type CliResult,
} from "../../cliJson";
import { isEnginePredatesSchema } from "../../connectionSchemaModel";
import { isUnknownArgumentError } from "../../stepsModel";

// A synthetic patient name, in the shape a Handler's `print(msg["PID-5"])` writes.
const PRINTED = "SYNTH^TEST^Q";
const JSON_BODY = '[{"source": "a.hl7", "disposition": "PROCESSED"}]';
const ARGS = ["dryrun", "--config", "cfg", "--messages", "/samples/a.hl7", "--trace", "json"];

function result(over: Partial<CliResult>): CliResult {
  return { stdout: "", stderr: "", code: 0, ...over };
}

function failure(res: CliResult): CliOutputError {
  try {
    parseJsonResult(res, ARGS);
  } catch (e) {
    assert.ok(e instanceof CliOutputError, `expected a CliOutputError, got ${String(e)}`);
    return e;
  }
  assert.fail("parseJsonResult did not throw");
}

suite("cliJson.parseJsonResult never quotes CLI output (vault BACKLOG #1187, ground d2)", () => {
  test("a handler's print ahead of the JSON: measured shape, and Node's own error quotes it", () => {
    // The dry-run runs Routers and Handlers in the CLI's own process, so a print lands on stdout
    // first. Measured at the engine: stdout began with the printed value, then the JSON.
    const stdout = `${PRINTED}\n${JSON_BODY}\n`;
    // Positive control: the bare JSON.parse the old code used quotes the value, so the absence
    // asserted below is the fix and not a parser that happens to stay quiet.
    assert.throws(() => JSON.parse(stdout.trim()), (e: Error) => e.message.includes("SYNTH"));
    const err = failure(result({ stdout }));
    assert.ok(!err.message.includes("SYNTH"), err.message);
    assert.ok(err.message.includes(`printed ${Buffer.byteLength(stdout)} bytes`), err.message);
    assert.ok(err.message.startsWith("messagefoundry dryrun "), err.message);
    assert.strictEqual(err.argumentRejected, false);
  });

  test("the same JSON with no print parses (control arm)", () => {
    assert.deepStrictEqual(parseJsonResult(result({ stdout: JSON_BODY }), ARGS), [
      { source: "a.hl7", disposition: "PROCESSED" },
    ]);
  });

  test("empty stdout: the stderr text stays out, and its size and the exit code are given", () => {
    const stderr = `Traceback (most recent call last):\nValueError: no mapping for ${PRINTED}\n`;
    const err = failure(result({ stderr, code: 1 }));
    assert.ok(!err.message.includes("SYNTH"), err.message);
    assert.ok(!err.message.includes("Traceback"), err.message);
    assert.ok(err.message.includes("exited with code 1"), err.message);
    assert.ok(err.message.includes(`(${Buffer.byteLength(stderr)} bytes)`), err.message);
  });

  test("the untrusted-workspace refusal is our own text, so it still reads as itself", () => {
    const err = failure(result({ stderr: UNTRUSTED_WORKSPACE_STDERR, code: 1 }));
    assert.strictEqual(err.message, UNTRUSTED_WORKSPACE_STDERR);
  });

  test('the CLI\'s composed {"error": ...} body still passes through', () => {
    assert.throws(
      () => parseJsonResult(result({ stdout: '{"error": "no such file or directory: x.hl7"}' }), ARGS),
      (e: Error) => !(e instanceof CliOutputError) && e.message === "no such file or directory: x.hl7",
    );
  });
});

suite("cliJson argument rejection travels as a flag, not as quoted text", () => {
  const argparse = "usage: messagefoundry [-h]\nmessagefoundry: error: unrecognized arguments: --contract 2\n";

  test("an argparse rejection on stderr is classified for both readers", () => {
    const err = failure(result({ stderr: argparse, code: 2 }));
    assert.ok(!err.message.includes("--contract"), err.message);
    assert.strictEqual(err.argumentRejected, true);
    assert.strictEqual(isUnknownArgumentError(err), true);
    assert.strictEqual(isEnginePredatesSchema(err), true);
  });

  test("a usage blob on stdout is classified too", () => {
    const err = failure(result({ stdout: argparse, code: 2 }));
    assert.strictEqual(err.argumentRejected, true);
    assert.strictEqual(isEnginePredatesSchema(err), true);
  });

  test("any other failure is not an argument rejection (control arm)", () => {
    const err = failure(result({ stderr: "ValueError: bad sample\n", code: 1 }));
    assert.strictEqual(err.argumentRejected, false);
    assert.strictEqual(isUnknownArgumentError(err), false);
    assert.strictEqual(isEnginePredatesSchema(err), false);
  });
});

suite("cliJson.commandLabel", () => {
  test("names the subcommand words only, never a flag's value", () => {
    assert.strictEqual(commandLabel(ARGS), "dryrun");
    assert.strictEqual(commandLabel(["codeset", "upsert", "--data", '{"rows": []}']), "codeset upsert");
    assert.strictEqual(commandLabel(["lens", "parse", "-", "--contract", "2"]), "lens parse");
    assert.strictEqual(commandLabel([]), "command");
  });
});
