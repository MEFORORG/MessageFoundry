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
// the [security] posture, so each check fails closed: the service-settings path follows the rules
// in the securityConfigTarget docblock, each argv value is bound to its flag with `=`, and a save
// message is checked for shape before anything is written.

const real = { lstat: fs.lstatSync, realpath: fs.realpathSync.native };

/** A model file system: each listed path lstats as a link or not, or throws the listed code; any
 *  other path does not exist. realpath returns `realpaths[p]`, else the path itself, or throws the
 *  code `realpaths[p]` names when that starts with E. It records every path it is asked about. */
function modelFs(entries: Record<string, string>, realpaths: Record<string, string> = {}) {
  const calls: string[] = [];
  const fail = (code: string) => Object.assign(new Error(code), { code });
  return {
    calls,
    lstat: (p: string) => {
      calls.push(p);
      const e = entries[path.resolve(p)];
      if (e === undefined) {
        throw fail("ENOENT");
      }
      if (e !== "link" && e !== "plain") {
        throw fail(e);
      }
      return { isSymbolicLink: () => e === "link" };
    },
    realpath: (p: string): string => {
      calls.push(`realpath ${p}`);
      const r = realpaths[path.resolve(p)] ?? path.resolve(p);
      if (/^E[A-Z]+$/.test(r)) {
        throw fail(r);
      }
      return r;
    },
  };
}

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

  test("a path inside the workspace resolves to its absolute file, existing or not, at either scope", () => {
    // THE CONTROL for every refusal below.
    for (const setting of ["messagefoundry.toml", "conf/sub/messagefoundry.toml", "./a/../b.toml", "..conf/messagefoundry.toml", "..messagefoundry.toml"]) {
      for (const fromWorkspace of [true, false]) {
        const t = securityConfigTarget(ws, setting, { fromWorkspace, trusted: true }, real);
        assert.deepStrictEqual(t, { ok: true, path: path.resolve(ws, setting) }, `${setting} ${fromWorkspace}`);
      }
    }
    fs.mkdirSync(path.join(ws, "conf"));
    fs.writeFileSync(path.join(ws, "conf", "messagefoundry.toml"), "");
    assert.ok(securityConfigTarget(ws, path.join(ws, "conf", "messagefoundry.toml"), { fromWorkspace: true, trusted: true }, real).ok, "an existing file, by absolute path");
  });

  test("rule 2: a workspace-set path outside the workspace folder is refused", () => {
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
      const t = securityConfigTarget(ws, setting, { fromWorkspace: true, trusted: true }, real);
      assert.strictEqual(t.ok, false, `${JSON.stringify(setting)} was accepted`);
    }
    for (const setting of [undefined, null, 5, ["messagefoundry.toml"]]) {
      assert.strictEqual(securityConfigTarget(ws, setting, { fromWorkspace: true, trusted: true }, real).ok, false, `${JSON.stringify(setting)} was accepted`);
    }
  });

  test("rule 3: a user-set path outside the workspace folder is accepted as written, with no file-system call", () => {
    const file = path.join(outside, "messagefoundry.toml");
    const spy = modelFs({});
    assert.deepStrictEqual(securityConfigTarget(ws, file, { fromWorkspace: false, trusted: true }, spy), { ok: true, path: file });
    assert.deepStrictEqual(spy.calls, [], "a user-set path outside the folder touched the file system");
    // The folder itself, and a blank or non-text value, are refused at this scope too.
    for (const setting of [".", ws, "", "  ", undefined, 5]) {
      assert.strictEqual(securityConfigTarget(ws, setting, { fromWorkspace: false, trusted: true }, real).ok, false, `${JSON.stringify(setting)} was accepted`);
    }
  });

  test("a refusal does not quote the setting's value back", () => {
    const t = securityConfigTarget(ws, "../secret-name.toml", { fromWorkspace: true, trusted: true }, real);
    assert.ok(!t.ok && !t.problem.includes("secret-name"), JSON.stringify(t));
  });

  test("rule 1: an untrusted workspace is refused before any file-system call", () => {
    // The Lander's hold on PR 2968, finding 22: in Restricted Mode the check makes no file-system
    // call, so it traverses none of the repository's links.
    const calls: string[] = [];
    const spy = {
      lstat: (p: string) => {
        calls.push(`lstat ${p}`);
        return real.lstat(p);
      },
      realpath: (p: string): string => {
        calls.push(`realpath ${p}`);
        return real.realpath(p);
      },
    };
    // THE CONTROL: the same setting in a trusted workspace is accepted, and the spy sees the reads.
    assert.ok(securityConfigTarget(ws, "messagefoundry.toml", { fromWorkspace: true, trusted: true }, spy).ok);
    assert.ok(calls.length > 0, "the spy recorded no call, so it proves nothing");
    for (const [setting, fromWorkspace] of [
      ["messagefoundry.toml", true],
      ["messagefoundry.toml", false],
      [path.join(outside, "messagefoundry.toml"), false],
      ["", true],
    ] as const) {
      calls.length = 0;
      const t = securityConfigTarget(ws, setting, { fromWorkspace: fromWorkspace, trusted: false }, spy);
      assert.ok(!t.ok && t.problem.includes("not trusted"), JSON.stringify(t));
      assert.deepStrictEqual(calls, [], `${JSON.stringify(setting)} touched the file system`);
    }
  });

  test("rules 2 and 3: a link at any existing path below the workspace folder is refused", () => {
    const root = path.resolve(path.sep, "mf-secedit-model", "ws");
    const at = (...p: string[]) => path.join(root, ...p);
    const setting = path.join("conf", "sub", "messagefoundry.toml");
    // THE CONTROL: every path a plain folder, and the file not there yet.
    const plain = { [root]: "plain", [at("conf")]: "plain", [at("conf", "sub")]: "plain" };
    for (const fromWorkspace of [true, false]) {
      const scope = { fromWorkspace, trusted: true };
      const control = modelFs(plain);
      assert.deepStrictEqual(securityConfigTarget(root, setting, scope, control), { ok: true, path: at(setting) });
      assert.deepStrictEqual(
        control.calls,
        [at("conf"), at("conf", "sub"), at(setting), `realpath ${root}`, `realpath ${at("conf", "sub")}`],
        "the walk checks each path below the folder, then resolves the deepest existing one",
      );
      // A link at each path in turn, the file included, is refused. The model does not follow
      // links, so this holds for a dangling one too.
      for (const linked of [at("conf"), at("conf", "sub"), at(setting)]) {
        const t = securityConfigTarget(root, setting, scope, modelFs({ ...plain, [linked]: "link" }));
        assert.strictEqual(t.ok, false, `${linked} ${fromWorkspace}`);
      }
      // The workspace folder itself may be a link: the repository cannot make it one.
      assert.ok(securityConfigTarget(root, setting, scope, modelFs({ ...plain, [root]: "link" })).ok, "the folder as a link");
      // A `..` is collapsed as text before the check, so the link at `away` is never consulted, and
      // the CLI is handed the collapsed path.
      const dotted = modelFs({ ...plain, [at("away")]: "link" });
      assert.deepStrictEqual(securityConfigTarget(root, ["away", "..", setting].join(path.sep), scope, dotted), { ok: true, path: at(setting) });
      assert.ok(!dotted.calls.some((c) => c.endsWith(at("away"))), "the collapsed component was read");
    }
  });

  test("rule 2: a path lstat does not report as a link is refused when realpath leads elsewhere", () => {
    // At least a junction onto a volume GUID path lstats as a plain folder, while the OS follows it.
    const root = path.resolve(path.sep, "mf-secedit-model", "ws");
    const setting = path.join("conf", "messagefoundry.toml");
    const plain = { [root]: "plain", [path.join(root, "conf")]: "plain" };
    const scope = { fromWorkspace: true, trusted: true };
    // THE CONTROL: the workspace folder resolving elsewhere, as through a link above it, is accepted
    // when the path below it resolves with it.
    const moved = path.resolve(path.sep, "elsewhere", "ws");
    assert.ok(securityConfigTarget(root, setting, scope, modelFs(plain, { [root]: moved, [path.join(root, "conf")]: path.join(moved, "conf") })).ok);
    const away = path.resolve(path.sep, "elsewhere", "Users");
    assert.strictEqual(securityConfigTarget(root, setting, scope, modelFs(plain, { [path.join(root, "conf")]: away })).ok, false, "a hidden reparse point");
    for (const where of [root, path.join(root, "conf")]) {
      assert.strictEqual(securityConfigTarget(root, setting, scope, modelFs(plain, { [where]: "EACCES" })).ok, false, `realpath fails at ${where}`);
    }
  });

  test("rule 2: an lstat error other than not-found refuses, and not-found ends the walk", () => {
    const root = path.resolve(path.sep, "mf-secedit-model", "ws");
    const setting = path.join("conf", "messagefoundry.toml");
    const scope = { fromWorkspace: true, trusted: true };
    // THE CONTROL: a path that does not exist, or is below a file, ends the walk and passes.
    for (const code of ["ENOENT", "ENOTDIR"]) {
      const fsx = modelFs({ [root]: "plain", [path.join(root, "conf")]: code });
      assert.ok(securityConfigTarget(root, setting, scope, fsx).ok, code);
      assert.deepStrictEqual(fsx.calls, [path.join(root, "conf"), `realpath ${root}`, `realpath ${root}`], `${code} did not end the walk`);
    }
    for (const code of ["EACCES", "EPERM", "ELOOP", "EIO"]) {
      for (const where of [path.join(root, "conf"), path.join(root, setting)]) {
        const fsx = modelFs({ [root]: "plain", [path.join(root, "conf")]: "plain", [where]: code });
        assert.strictEqual(securityConfigTarget(root, setting, scope, fsx).ok, false, `${code} at ${where}`);
      }
    }
  });

  test("a real link inside the workspace folder is refused, a dangling one and one that stays inside included", function () {
    try {
      fs.symlinkSync(outside, path.join(ws, "linked"), "junction");
    } catch {
      // Creating a link can need a privilege the runner lacks; the model tests above still ran.
      this.skip();
    }
    // THE CONTROL: a plain folder beside it is accepted.
    fs.mkdirSync(path.join(ws, "plain"));
    assert.ok(securityConfigTarget(ws, "plain/messagefoundry.toml", { fromWorkspace: true, trusted: true }, real).ok);
    fs.symlinkSync(path.join(outside, "not-yet"), path.join(ws, "dangling"), "junction");
    fs.symlinkSync(path.join(ws, "plain"), path.join(ws, "inlink"), "junction");
    for (const fromWorkspace of [true, false]) {
      const scope = { fromWorkspace, trusted: true };
      for (const via of ["linked", "dangling", "inlink"]) {
        assert.strictEqual(securityConfigTarget(ws, `${via}/messagefoundry.toml`, scope, real).ok, false, `${via} ${fromWorkspace}`);
      }
    }
  });

  test("the open limit: a user-set alias into the workspace folder is accepted as written", function () {
    // Rule 3 compares spellings only. This pins the documented limit: an alias outside the folder
    // that leads into it, and then out through a link the repository holds, is not caught.
    const alias = path.join(outside, "alias");
    try {
      fs.symlinkSync(ws, alias, "junction");
      fs.symlinkSync(outside, path.join(ws, "linked"), "junction");
    } catch {
      this.skip();
    }
    const file = path.join(alias, "linked", "messagefoundry.toml");
    assert.deepStrictEqual(securityConfigTarget(ws, file, { fromWorkspace: false, trusted: true }, real), { ok: true, path: file });
    // The same path set in workspace settings is still refused, as it is outside the folder as spelled.
    assert.strictEqual(securityConfigTarget(ws, file, { fromWorkspace: true, trusted: true }, real).ok, false);
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
