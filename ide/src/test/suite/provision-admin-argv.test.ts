// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The provision-admin limb of BACKLOG #5566, pinned whole (#8243 items 36, 38 and 49). The status bar
// judges a store present from `messagefoundry.serviceConfig`, so provision-admin and its probe must
// open the same file. The pins below compare the WHOLE argv, so an element before `provision-admin`
// or one pushed after the list fails them, and each pin has a negative control showing it would.
//
// The expected argv is read from ide/src/test/fixtures/provision-admin-argv.json, the file
// tests/test_ide_provision_admin_argv.py hands the engine's own parser, which shows
// `--service-config=<file>` reaches provision-admin as its service-config file. One file, so the two
// suites cannot pin different argv.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { buildAdminProbeInvocation, buildProvisionInvocation } from "../../engineControlModel";

const FIXTURE = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "test", "fixtures", "provision-admin-argv.json"), "utf8"),
) as { serviceConfig: string; provision: string[]; probe: string[]; probeDefault: string[] };
const SC = FIXTURE.serviceConfig;

// Typed as records and handed to the builders `as never`, so no call here names `serviceConfig` in a
// builder's parameter type, and this file also compiles against the code before the flag existed.
// There the pins with SC set fail on the argv itself; the default-probe pin passes, because that
// code built the same argv with no --service-config.
const provisionOpts: Record<string, string> = { python: "p", username: "alice", email: "alice@example.test", serviceConfig: SC };
const probeOpts: Record<string, string> = { python: "p", serviceConfig: SC };
// The call shape statusBar.ts uses with `messagefoundry.serviceConfig` at its default: the property
// present and undefined.
const probeDefaultOpts: Record<string, string | undefined> = { python: "p", serviceConfig: undefined };

/** The provision-admin argv the IDE runs for alice with SC set. */
const PROVISION_ARGV: readonly string[] = FIXTURE.provision;

/** The admin probe's argv with SC set: provision-admin for the probe account, answering in JSON. */
const PROBE_ARGV: readonly string[] = FIXTURE.probe;

/**
 * The admin probe's argv with `messagefoundry.serviceConfig` at its default, so no --service-config.
 * tests/test_ide_start_plan_probe_contract.py runs this list through the engine's `main` in-process;
 * its module docstring says how.
 */
const PROBE_DEFAULT_ARGV: readonly string[] = FIXTURE.probeDefault;

/** The pin: the whole argv, element for element. */
function pin(actual: readonly string[], expected: readonly string[]): void {
  assert.deepStrictEqual([...actual], [...expected]);
}

suite("provision-admin and its probe open the service TOML the guard judged (BACKLOG #5566)", () => {
  test("provision-admin's whole argv, the --service-config element included", () => {
    const inv = buildProvisionInvocation(provisionOpts as never);
    assert.strictEqual(inv.command, "p");
    pin(inv.args, PROVISION_ARGV);
  });

  test("the probe's whole argv, the --service-config element included", () => {
    const inv = buildAdminProbeInvocation(probeOpts as never);
    assert.strictEqual(inv.command, "p");
    pin(inv.args, PROBE_ARGV);
  });

  test("the probe's whole argv with serviceConfig at its default, no --service-config element", () => {
    const inv = buildAdminProbeInvocation(probeDefaultOpts as never);
    assert.strictEqual(inv.command, "p");
    pin(inv.args, PROBE_DEFAULT_ARGV);
  });

  test("negative control: the pin refuses an element before provision-admin, one appended, and none missing", () => {
    const good = buildProvisionInvocation(provisionOpts as never).args;
    const before = [...good.slice(0, 5), "--db=other.db", ...good.slice(5)];
    const after = [...good, "--db=other.db"];
    const dropped = good.filter((a) => !a.startsWith("--service-config"));
    for (const bad of [before, after, dropped]) {
      assert.throws(() => pin(bad, PROVISION_ARGV), assert.AssertionError, bad.join(" "));
    }
    // Control: the unmutated argv passes the same pin.
    pin(good, PROVISION_ARGV);
  });

  test("negative control: the two probe pins refuse an element before provision-admin, one appended, and --json missing", () => {
    for (const [good, expected] of [
      [buildAdminProbeInvocation(probeOpts as never).args, PROBE_ARGV],
      [buildAdminProbeInvocation(probeDefaultOpts as never).args, PROBE_DEFAULT_ARGV],
    ] as const) {
      const before = [...good.slice(0, 5), "--db=other.db", ...good.slice(5)];
      const after = [...good, "--db=other.db"];
      const dropped = good.filter((a) => a !== "--json");
      for (const bad of [before, after, dropped]) {
        assert.throws(() => pin(bad, expected), assert.AssertionError, bad.join(" "));
      }
      // Control: the unmutated argv passes the same pin.
      pin(good, expected);
    }
    // The default probe is not the one with serviceConfig set, so the two pins are not one pin twice.
    assert.throws(() => pin(PROBE_DEFAULT_ARGV, PROBE_ARGV), assert.AssertionError);
  });
});
