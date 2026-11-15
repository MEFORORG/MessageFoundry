// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  saveUpdatesProblem,
  securityConfigTarget,
  securitySetArgs,
  securityShowArgs,
} from "../../securityEditorModel";
import { FIELDS } from "../../securityEditorWebview";

// BACKLOG #5411: the Security Settings editor's host-side checks, run vscode-free. The editor writes
// the [security] posture, so each check fails closed: the service-settings path must stay inside
// the workspace, each argv value is bound to its flag with `=`, and a save message is checked for
// shape before anything is written.

const real = (p: string): string => fs.realpathSync.native(p);

suite("security editor host checks", () => {
  let ws: string;
  let outside: string;

  setup(() => {
    ws = fs.mkdtempSync(path.join(os.tmpdir(), "mf-secedit-ws-"));
    outside = fs.mkdtempSync(path.join(os.tmpdir(), "mf-secedit-out-"));
  });
  teardown(() => {
    fs.rmSync(ws, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  });

  test("a path inside the workspace resolves to its absolute file, existing or not", () => {
    // THE CONTROL for every refusal below.
    for (const setting of ["messagefoundry.toml", "conf/sub/messagefoundry.toml", "./a/../b.toml"]) {
      const t = securityConfigTarget(ws, setting, real);
      assert.deepStrictEqual(t, { ok: true, path: path.resolve(ws, setting) }, setting);
    }
    fs.writeFileSync(path.join(ws, "messagefoundry.toml"), "");
    assert.ok(securityConfigTarget(ws, path.join(ws, "messagefoundry.toml"), real).ok, "an absolute path inside");
  });

  test("a path outside the workspace is refused", () => {
    const sibling = ws + "-other";
    for (const setting of [
      "../messagefoundry.toml",
      "conf/../../x.toml",
      path.join(outside, "messagefoundry.toml"),
      path.join(sibling, "messagefoundry.toml"),
      ".",
      "",
      "   ",
    ]) {
      const t = securityConfigTarget(ws, setting, real);
      assert.strictEqual(t.ok, false, `${JSON.stringify(setting)} was accepted`);
    }
    for (const setting of [undefined, null, 5, ["messagefoundry.toml"]]) {
      assert.strictEqual(securityConfigTarget(ws, setting, real).ok, false, `${JSON.stringify(setting)} was accepted`);
    }
  });

  test("a path that leaves the workspace through a symbolic link is refused", function () {
    const link = path.join(ws, "linked");
    try {
      fs.symlinkSync(outside, link, "junction");
    } catch {
      // Creating a link can need a privilege the runner lacks; the lexical cases still ran.
      this.skip();
    }
    assert.strictEqual(securityConfigTarget(ws, "linked/messagefoundry.toml", real).ok, false, "a new file through the link");
    fs.writeFileSync(path.join(outside, "messagefoundry.toml"), "");
    assert.strictEqual(securityConfigTarget(ws, "linked/messagefoundry.toml", real).ok, false, "an existing file through the link");
    // THE CONTROL: a link that stays inside the workspace is accepted.
    fs.mkdirSync(path.join(ws, "inner"));
    fs.symlinkSync(path.join(ws, "inner"), path.join(ws, "inlink"), "junction");
    assert.ok(securityConfigTarget(ws, "inlink/messagefoundry.toml", real).ok, "a link inside the workspace");
  });

  test("each argv value is bound to its flag with =, so a leading dash is never read as a flag", () => {
    const file = path.join(ws, "-messagefoundry.toml");
    assert.deepStrictEqual(securityShowArgs(file), ["security", "show", `--service-config=${file}`]);
    assert.deepStrictEqual(securitySetArgs(file, { require_mfa: null }), [
      "security",
      "set",
      `--service-config=${file}`,
      `--data=${JSON.stringify({ require_mfa: null })}`,
    ]);
  });

  test("a well-formed save message passes the shape check", () => {
    // THE CONTROL: every switch at once, one value of each type, and null.
    const updates: Record<string, unknown> = {};
    for (const f of FIELDS) {
      updates[f.key] = f.type === "int" ? 0 : f.type === "string" ? "x" : f.type === "tristate" ? null : true;
    }
    assert.strictEqual(saveUpdatesProblem(updates, FIELDS), null);
    assert.strictEqual(saveUpdatesProblem({}, FIELDS), null);
    assert.strictEqual(saveUpdatesProblem(Object.assign(Object.create(null), { require_mfa: false }), FIELDS), null);
  });

  test("a malformed save message is refused", () => {
    const cases: [string, unknown][] = [
      ["missing", undefined],
      ["null", null],
      ["a string", "require_mfa"],
      ["an array", [["require_mfa", false]]],
      ["not a plain object", new Date()],
      ["an unknown key", { enforcement: "warn" }],
      ["a __proto__ key", JSON.parse('{"__proto__": {"require_mfa": false}}')],
      ["a bool as text", { require_mfa: "false" }],
      ["a tristate as text", { production_instance: "true" }],
      ["a string as a number", { listen_address: 0 }],
      ["an int as text", { delete_message_bodies_after_days: "0" }],
      ["a negative int", { delete_message_bodies_after_days: -1 }],
      ["a fraction", { max_session_hours: 1.5 }],
      ["an unsafe int", { max_session_hours: 2 ** 60 }],
      ["NaN", { max_session_hours: Number.NaN }],
      ["an int as a bool", { sign_out_after_idle_minutes: true }],
    ];
    for (const [why, updates] of cases) {
      assert.notStrictEqual(saveUpdatesProblem(updates, FIELDS), null, `${why} was accepted`);
    }
  });
});
