// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  ShownFile,
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

const real = { realpath: fs.realpathSync.native, lstat: fs.lstatSync, readlink: fs.readlinkSync };

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
    for (const setting of ["messagefoundry.toml", "conf/sub/messagefoundry.toml", "./a/../b.toml", "..conf/messagefoundry.toml", "..messagefoundry.toml"]) {
      const t = securityConfigTarget(ws, setting, true, real);
      // Links resolved, so the expected path is under the workspace's real path.
      assert.deepStrictEqual(t, { ok: true, path: path.resolve(fs.realpathSync.native(ws), setting) }, setting);
    }
    fs.writeFileSync(path.join(ws, "messagefoundry.toml"), "");
    assert.ok(securityConfigTarget(ws, path.join(ws, "messagefoundry.toml"), true, real).ok, "an absolute path inside");
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
      const t = securityConfigTarget(ws, setting, true, real);
      assert.strictEqual(t.ok, false, `${JSON.stringify(setting)} was accepted`);
    }
    for (const setting of [undefined, null, 5, ["messagefoundry.toml"]]) {
      assert.strictEqual(securityConfigTarget(ws, setting, true, real).ok, false, `${JSON.stringify(setting)} was accepted`);
    }
  });

  test("a value from user settings may name a file outside the workspace, but never a blank one", () => {
    const file = path.join(outside, "messagefoundry.toml");
    // A path that never reaches the workspace keeps its spelling, so every editor locks one folder.
    assert.deepStrictEqual(securityConfigTarget(ws, file, false, real), { ok: true, path: file });
    for (const setting of ["", "  ", undefined, 5]) {
      assert.strictEqual(securityConfigTarget(ws, setting, false, real).ok, false, `${JSON.stringify(setting)} was accepted`);
    }
  });

  test("a containment refusal does not quote the setting's value back", () => {
    const t = securityConfigTarget(ws, "../secret-name.toml", true, real);
    assert.ok(!t.ok && !t.problem.includes("secret-name"), JSON.stringify(t));
  });

  test("a read error other than not-found refuses rather than passing", () => {
    const denied = {
      realpath: (): string => {
        throw Object.assign(new Error("denied"), { code: "EACCES" });
      },
      lstat: () => ({ isSymbolicLink: () => false }),
      readlink: (): string => "",
    };
    assert.strictEqual(securityConfigTarget(ws, "messagefoundry.toml", true, denied).ok, false);
  });

  test("a path that leaves the workspace through a symbolic link is refused", function () {
    const link = path.join(ws, "linked");
    try {
      fs.symlinkSync(outside, link, "junction");
    } catch {
      // Creating a link can need a privilege the runner lacks; the lexical cases still ran.
      this.skip();
    }
    assert.strictEqual(securityConfigTarget(ws, "linked/messagefoundry.toml", true, real).ok, false, "a new file through the link");
    // Whatever the scope: a user-set or default path inside the workspace is checked for links too.
    assert.strictEqual(securityConfigTarget(ws, "linked/messagefoundry.toml", false, real).ok, false, "a user-set path through the link");
    fs.writeFileSync(path.join(outside, "messagefoundry.toml"), "");
    assert.strictEqual(securityConfigTarget(ws, "linked/messagefoundry.toml", true, real).ok, false, "an existing file through the link");
    // A dangling link, whose target does not exist yet, is refused too: it could be made later.
    const dangling = path.join(ws, "dangling");
    fs.symlinkSync(path.join(outside, "not-yet"), dangling, "junction");
    assert.strictEqual(securityConfigTarget(ws, "dangling/messagefoundry.toml", true, real).ok, false, "a dangling link");
    // THE CONTROL: a link that stays inside the workspace is accepted.
    fs.mkdirSync(path.join(ws, "inner"));
    fs.symlinkSync(path.join(ws, "inner"), path.join(ws, "inlink"), "junction");
    const viaInner = securityConfigTarget(ws, "inlink/messagefoundry.toml", true, real);
    assert.ok(viaInner.ok, "a link inside the workspace");
    // The CLI is handed the resolved path, so it opens the folder that was checked.
    assert.strictEqual(viaInner.path, path.join(fs.realpathSync.native(path.join(ws, "inner")), "messagefoundry.toml"));
  });

  test("a user-set path that reaches the workspace by an alias gets the workspace's link rules", function () {
    // An alias (a link, a mapped drive, an 8.3 name) into the workspace is lexically outside it, so
    // containment is decided on the resolved path, against the workspace's own resolved path.
    const alias = path.join(outside, "alias");
    const away = fs.mkdtempSync(path.join(os.tmpdir(), "mf-secedit-away-"));
    try {
      try {
        fs.symlinkSync(ws, alias, "junction");
        fs.symlinkSync(away, path.join(ws, "linked"), "junction");
      } catch {
        this.skip();
      }
      // THE CONTROL: a file the alias reaches inside the workspace is accepted, as the resolved path.
      assert.deepStrictEqual(securityConfigTarget(ws, path.join(alias, "messagefoundry.toml"), false, real), {
        ok: true,
        path: path.join(fs.realpathSync.native(ws), "messagefoundry.toml"),
      });
      // Through the alias and then out by a link the repository holds: refused, as it is lexically.
      assert.strictEqual(
        securityConfigTarget(ws, path.join(alias, "linked", "messagefoundry.toml"), false, real).ok,
        false,
        "through the alias",
      );
      // An alias pointing straight at that link: realpath resolves the chain to its end, outside the
      // workspace, so only following each hop sees that it passes through.
      const chained = path.join(outside, "chained");
      fs.symlinkSync(path.join(ws, "linked"), chained, "junction");
      const t = securityConfigTarget(ws, path.join(chained, "messagefoundry.toml"), false, real);
      assert.strictEqual(t.ok, false, "an alias to a repository link");
      assert.ok(!t.ok && t.problem.includes("set in user settings"), "the refusal names the user scope");
      // The alias naming the workspace folder itself is refused, as the folder is.
      assert.strictEqual(securityConfigTarget(ws, alias, false, real).ok, false, "the folder by its alias");
    } finally {
      fs.rmSync(away, { recursive: true, force: true });
    }
  });

  test("a user-set path whose links or whose workspace cannot be read is refused", () => {
    const file = path.join(outside, "messagefoundry.toml");
    const failing = (bad: (p: string) => boolean) => ({
      realpath: (p: string): string => {
        if (bad(p)) {
          throw Object.assign(new Error("denied"), { code: "EACCES" });
        }
        return real.realpath(p);
      },
      lstat: real.lstat,
      readlink: real.readlink,
    });
    // THE CONTROL: the same path, with every read succeeding, is accepted.
    assert.ok(securityConfigTarget(ws, file, false, failing(() => false)).ok);
    // The workspace folder cannot be resolved.
    assert.strictEqual(securityConfigTarget(ws, file, false, failing((p) => p === path.resolve(ws))).ok, false, "the root");
    // An ancestor of the target cannot be read while walking it for an alias.
    const parent = path.dirname(outside);
    assert.strictEqual(securityConfigTarget(ws, file, false, failing((p) => p === parent)).ok, false, "an ancestor");
  });

  test("the file a panel shows is its own, and a disposed panel neither sets it nor saves through it", () => {
    const a = new ShownFile();
    const b = new ShownFile();
    a.set("a.toml");
    // THE CONTROL: a live panel saves only to the file it shows.
    assert.ok(a.matches("a.toml"));
    assert.ok(!a.matches("b.toml"));
    // A second panel's state is apart from the first's.
    assert.ok(!b.matches("a.toml"), "one panel's file leaked into another's");
    b.set("b.toml");
    assert.ok(a.matches("a.toml") && b.matches("b.toml"));
    // A late refresh after dispose sets nothing, and the panel cannot save.
    a.dispose();
    assert.ok(!a.matches("a.toml"), "a disposed panel still saves");
    a.set("a.toml");
    assert.ok(!a.matches("a.toml"), "a late refresh set a disposed panel's file");
    assert.ok(a.disposed);
    assert.ok(b.matches("b.toml"), "disposing one panel cleared another's");
    b.clear();
    assert.ok(!b.matches("b.toml"));
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
