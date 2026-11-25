// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5411, #8237 item 24. The Alert Wizard, the connection editors and the certificate inventory
// passed `messagefoundry.serviceConfig` to the CLI in split form, and the alert list and the
// inventory handed it over with no link check. Each now binds the value with `=`, as Start and the
// Security editor do, and the two readers run the writers' link check first.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import { connectionRemoveArgs, connectionUpsertArgs } from "../../connectionWizardModel";

const SRC = path.join(__dirname, "..", "..", "..", "src");
const code = (f: string): string =>
  fs.readFileSync(path.join(SRC, f), "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "");

/** The `"--service-config",` split element: the flag as its own argv entry, its value the next. */
const SPLIT = /"--service-config"\s*,/;

suite("--service-config is bound with = everywhere the IDE runs the CLI (BACKLOG #5411)", () => {
  test("no IDE source passes --service-config as a split argv element", () => {
    const files = fs.readdirSync(SRC).filter((f) => f.endsWith(".ts"));
    // Control: the scan reads the files that run the CLI.
    for (const f of ["alertEditor.ts", "engineTrust.ts", "connectionWizardModel.ts"]) {
      assert.ok(files.includes(f), f);
      assert.ok(code(f).includes("--service-config="), `${f} names the flag`);
    }
    for (const f of files) {
      assert.ok(!SPLIT.test(code(f)), `${f} passes --service-config split`);
    }
  });

  test("control: the pre-fix split form fails the scan", () => {
    assert.ok(SPLIT.test('["alert", "list", "--service-config", serviceConfig()]'));
  });

  test("a connection edit keeps a dash-leading service config as the flag's value", () => {
    const conn = { name: "IB_X" } as never;
    for (const args of [
      connectionUpsertArgs("c", "-odd.toml", conn),
      connectionRemoveArgs("c", "-odd.toml", "IB_X", "inbound"),
    ]) {
      assert.ok(args.includes("--service-config=-odd.toml"), JSON.stringify(args));
      assert.ok(!args.includes("-odd.toml"), JSON.stringify(args));
    }
  });

  test("the alert list and the certificate inventory run the writers' link check before the CLI", () => {
    const alert = code("alertEditor.ts");
    const list = alert.slice(alert.indexOf("async function refresh("), alert.indexOf("async function add("));
    assert.ok(list.indexOf('pathSettingLinkEscape("serviceConfig"') >= 0, list);
    assert.ok(list.indexOf('pathSettingLinkEscape("serviceConfig"') < list.indexOf('"alert", "list"'), list);
    const trust = code("engineTrust.ts");
    assert.ok(trust.indexOf('pathSettingLinkEscape("serviceConfig"') >= 0);
    assert.ok(trust.indexOf('pathSettingLinkEscape("serviceConfig"') < trust.indexOf('"cert", "inventory"'));
  });
});
