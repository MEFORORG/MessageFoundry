// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The serve limb of BACKLOG #5566 and #5939, pinned whole. The status bar judges a store present from
// `messagefoundry.serviceConfig`, so serve, and the start command it copies, must name the same file.
// provision-admin-argv.test.ts pins provision-admin and its probe the same way.
//
// The expected argv is read from ide/src/test/fixtures/b20008-b-serve-argv.json, the file
// tests/test_b20008_b_ide_serve_argv.py hands the engine's own parser. One file, so the two suites
// cannot pin different argv.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { buildServeInvocation, serveCommandLine } from "../../engineControlModel";

const FIXTURE = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "test", "fixtures", "b20008-b-serve-argv.json"), "utf8"),
) as { serviceConfig: string; configDir: string; serve: string[]; serveDefault: string[]; copyLine: string };
const SC = FIXTURE.serviceConfig;

// Passed `as never`, and serveCommandLine through a loose signature, so this file also compiles
// against the code before the flag existed (engine 5fdb7bceaa, the parent of PR 2966's merge). There
// the pins with SC set fail on the argv itself, and the default pin passes.
const serveOpts: Record<string, string> = { python: "p", configDir: FIXTURE.configDir, serviceConfig: SC };
const serveDefaultOpts: Record<string, string | undefined> = {
  python: "p",
  configDir: FIXTURE.configDir,
  serviceConfig: undefined,
};
const copyLine = serveCommandLine as unknown as (configDir: string, serviceConfig?: string) => string;

/** The pin: the whole argv, element for element. */
function pin(actual: readonly string[], expected: readonly string[]): void {
  assert.deepStrictEqual([...actual], [...expected]);
}

suite("serve opens the service TOML the guard judged, pinned whole (BACKLOG #5566, #5939)", () => {
  test("serve's whole argv, the --service-config element included", () => {
    const inv = buildServeInvocation(serveOpts as never);
    assert.strictEqual(inv.command, "p");
    pin(inv.args, FIXTURE.serve);
  });

  test("serve's whole argv with serviceConfig at its default, no --service-config element", () => {
    const inv = buildServeInvocation(serveDefaultOpts as never);
    assert.strictEqual(inv.command, "p");
    pin(inv.args, FIXTURE.serveDefault);
  });

  test("the copied start command is serve's argv as one line, the --service-config element included", () => {
    assert.strictEqual(copyLine(FIXTURE.configDir, SC), FIXTURE.copyLine);
  });

  test("negative control: the pin refuses an element before serve, one appended, and the flag missing", () => {
    const good = buildServeInvocation(serveOpts as never).args;
    const before = [...good.slice(0, 5), "--db=other.db", ...good.slice(5)];
    const after = [...good, "--db=other.db"];
    const dropped = good.filter((a) => !a.startsWith("--service-config"));
    for (const bad of [before, after, dropped]) {
      assert.throws(() => pin(bad, FIXTURE.serve), assert.AssertionError, bad.join(" "));
    }
    // Control: the unmutated argv passes the same pin, and the two fixture lists are not one list.
    pin(good, FIXTURE.serve);
    assert.throws(() => pin(FIXTURE.serveDefault, FIXTURE.serve), assert.AssertionError);
    assert.notStrictEqual(copyLine(FIXTURE.configDir), FIXTURE.copyLine);
  });
});
