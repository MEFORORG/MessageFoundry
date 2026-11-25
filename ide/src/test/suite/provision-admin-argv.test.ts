// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The provision-admin limb of BACKLOG #5566, pinned whole (#8243 items 36, 38 and 49). The status bar
// judges a store present from `messagefoundry.serviceConfig`, so provision-admin and its probe must
// open the same file. The pins below compare the WHOLE argv, so an element before `provision-admin`
// or one pushed after the list fails them, and each pin has a negative control showing it would.
//
// The argv literals here are the ones tests/test_ide_provision_admin_argv.py hands the engine's own
// parser, which shows `--service-config=<file>` reaches provision-admin as its service-config file.
// Change one and change the other.
import * as assert from "assert";

import { buildAdminProbeInvocation, buildProvisionInvocation } from "../../engineControlModel";

const SC = "deploy/prod/messagefoundry.toml";

// Built without the `serviceConfig` property in the type, so this file also compiles against the
// code before the flag existed, where the pins below then fail on the argv itself.
const provisionOpts: Record<string, string> = { python: "p", username: "alice", email: "alice@example.test", serviceConfig: SC };
const probeOpts: Record<string, string> = { python: "p", serviceConfig: SC };

/** The provision-admin argv the IDE runs for alice with SC set. */
export const PROVISION_ARGV: readonly string[] = [
  "-P",
  "-X",
  "disable-remote-debug",
  "-m",
  "messagefoundry",
  "provision-admin",
  "--username=alice",
  "--email=alice@example.test",
  `--service-config=${SC}`,
];

/** The admin probe's argv with SC set: provision-admin for the probe account, answering in JSON. */
export const PROBE_ARGV: readonly string[] = [
  "-P",
  "-X",
  "disable-remote-debug",
  "-m",
  "messagefoundry",
  "provision-admin",
  "--username=probe",
  "--email=probe@example.invalid",
  `--service-config=${SC}`,
  "--json",
];

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
});
