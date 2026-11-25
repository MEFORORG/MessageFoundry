// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5411, #8237 item 24. The Alert Wizard, the connection editors and the certificate inventory
// passed `messagefoundry.serviceConfig` to the CLI in split form, and the alert list, the inventory
// and the offline AI policy handed it over with no link check. Each now binds the value with `=`
// through one helper, as Start does, and those readers run a link check first.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { connectionRemoveArgs, connectionUpsertArgs, serviceConfigArgs } from "../../connectionWizardModel";

const SRC = path.join(__dirname, "..", "..", "..", "src");
// Read raw, comments included: a comment-stripping regex would also strip from a `/*` inside a
// string such as a glob, hiding real code from the scan.
const code = (f: string): string => fs.readFileSync(path.join(SRC, f), "utf8");

/** The `"--service-config",` split element: the flag as its own argv entry, its value the next. */
const SPLIT = /"--service-config"\s*,/;

suite("--service-config is bound with = everywhere the IDE runs the CLI (BACKLOG #5411)", () => {
  test("no IDE source passes --service-config as a split argv element", () => {
    const files = fs.readdirSync(SRC).filter((f) => f.endsWith(".ts"));
    // Control: the scan reads the files that run the CLI with the flag.
    for (const f of ["alertEditor.ts", "engineTrust.ts", "connectionWizardModel.ts", "engineControlModel.ts"]) {
      assert.ok(files.includes(f), f);
      assert.ok(/serviceConfigArgs/.test(code(f)), `${f} does not use the shared binding`);
    }
    for (const f of files) {
      assert.ok(!SPLIT.test(code(f)), `${f} passes --service-config split`);
    }
  });

  test("control: the pre-fix split form fails the scan", () => {
    assert.ok(SPLIT.test('["alert", "list", "--service-config", serviceConfig()]'));
  });

  test("the shared binding keeps a dash-leading value as the flag's value, and adds nothing when undefined", () => {
    assert.deepStrictEqual(serviceConfigArgs("-odd.toml"), ["--service-config=-odd.toml"]);
    assert.deepStrictEqual(serviceConfigArgs(undefined), []);
    const conn = { name: "IB_X" } as never;
    for (const args of [
      connectionUpsertArgs("c", "-odd.toml", conn),
      connectionRemoveArgs("c", "-odd.toml", "IB_X", "inbound"),
    ]) {
      assert.ok(args.includes("--service-config=-odd.toml"), JSON.stringify(args));
      assert.ok(!args.includes("-odd.toml"), JSON.stringify(args));
    }
  });

  /** Whether `before` occurs in `src`, and first occurs ahead of `after`. */
  const ahead = (src: string, before: string, after: string): boolean =>
    src.indexOf(before) >= 0 && src.indexOf(after) >= 0 && src.indexOf(before) < src.indexOf(after);

  test("the alert list, the certificate inventory and the offline AI policy run a link check before the CLI", () => {
    const alert = code("alertEditor.ts");
    const list = alert.slice(alert.indexOf("async function refresh("), alert.indexOf("async function add("));
    assert.ok(ahead(list, "readerPathEscapesByLink(setting)", '"alert", "list"'), list);
    assert.ok(ahead(code("engineTrust.ts"), "readerPathEscapesByLink(setting)", '"cert", "inventory"'));
    const ai = code("aiPolicy.ts");
    assert.ok(ahead(ai, 'pathSettingLinkEscape("serviceConfig", s) === undefined', "aiPolicyCliPlan(s.value"), ai);
  });

  test("control: the order check refuses a reader that runs the CLI first", () => {
    assert.ok(!ahead('runJson(["alert", "list"]); readerPathEscapesByLink(setting)', "readerPathEscapesByLink(setting)", '"alert", "list"'));
  });
});
