// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  ShownFile,
  saveUpdatesProblem,
  securityConfigInput,
  securityConfigTarget,
  securitySetArgs,
  securityShowArgs,
} from "../../securityEditorModel";
import { FIELDS } from "../../securityEditorWebview";
import { containedPathSetting, type PathSettingScopes } from "../../workspaceContainment";
import { unlinkLinks } from "../unlinkLinks";

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

/** The 8.3 short spelling of the existing folder `long`, as cmd's `%~s` prints it, with every
 *  component that has a short name shortened, or undefined where `long` holds a character cmd
 *  would expand, cmd fails, or it prints no folder that exists, as for a name its code page cannot
 *  print. It is `long` itself where no component has a short name. */
function shortName(long: string): string | undefined {
  if (/[%*?"^&]/.test(long)) {
    return undefined;
  }
  const r = spawnSync("cmd.exe", ["/d", "/s", "/c", `"for %I in ("${long}") do @echo %~sI"`], {
    encoding: "utf8",
    windowsVerbatimArguments: true,
  });
  const out = r.status === 0 ? r.stdout.trim() : "";
  return out !== "" && fs.existsSync(out) ? out : undefined;
}

suite("security editor host checks", () => {
  let ws: string;
  let outside: string;

  setup(() => {
    ws = fs.mkdtempSync(path.join(os.tmpdir(), "mf-secedit-ws-"));
    outside = fs.mkdtempSync(path.join(os.tmpdir(), "mf-secedit-out-"));
  });
  teardown(() => {
    try {
      for (const dir of [ws, outside]) {
        if (fs.existsSync(dir)) {
          unlinkLinks(dir);
        }
      }
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
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

  test("a value cli.ts's containment dropped is refused, not swapped for the file used in its place (BACKLOG #5404)", () => {
    // The editor's own pipeline: inspect() -> containedPathSetting -> securityConfigInput -> securityConfigTarget.
    const judge = (seen: PathSettingScopes) => {
      const { value, fromWorkspace } = securityConfigInput(seen, containedPathSetting(seen, ws, "messagefoundry.toml"));
      return securityConfigTarget(ws, value, { fromWorkspace, trusted: true }, real);
    };
    const userFile = path.join(ws, "mine.toml");
    // A workspace value outside the folder, with a usable user value and default below it.
    const dropped = judge({ defaultValue: "messagefoundry.toml", globalValue: userFile, workspaceValue: path.join(outside, "x.toml") });
    assert.strictEqual(dropped.ok, false, "the dropped workspace value was swapped for the user's");
    assert.match(dropped.ok ? "" : dropped.problem, /set in workspace settings, names a path outside/);
    // A user value that is not text, with a usable default below it.
    const notText = judge({ defaultValue: "messagefoundry.toml", globalValue: 5 });
    assert.strictEqual(notText.ok, false, "the non-text user value was swapped for the default");
    assert.match(notText.ok ? "" : notText.problem, /blank or is not text/);
    // Controls: nothing dropped, so the value used is the one judged.
    assert.deepStrictEqual(judge({ defaultValue: "messagefoundry.toml", globalValue: userFile }), { ok: true, path: userFile });
    assert.deepStrictEqual(judge({ defaultValue: "messagefoundry.toml", workspaceValue: "conf/a.toml" }), {
      ok: true,
      path: path.join(ws, "conf", "a.toml"),
    });
    // The workspace scope is reported for a workspace value, so rule 2 applies to it.
    assert.deepStrictEqual(securityConfigInput({ workspaceValue: "a.toml" }, containedPathSetting({ workspaceValue: "a.toml" }, ws, "d")), {
      value: "a.toml",
      fromWorkspace: true,
    });
    // An unread scope counts as the workspace's.
    assert.strictEqual(securityConfigInput(undefined, containedPathSetting(undefined, ws, "d")).fromWorkspace, true);
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
      // The workspace folder itself may be a link: it is taken as given and not checked, as the
      // securityConfigTarget docblock says, a folder a repository's `.code-workspace` chose included.
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

  test("a workspace folder under an 8.3 short-name ancestor is checked against its realpath, which spells it in full", () => {
    // os.tmpdir() on the CI runner spells the profile folder by its 8.3 short name (RUNNER~1), and
    // realpath spells it in full. Both sides of the realpath comparison go through realpath, so the
    // short spelling of the folder passes and every refusal below it still holds.
    const short = path.resolve(path.sep, "Users", "RUNNER~1", "ws");
    const long = path.resolve(path.sep, "Users", "runneradmin", "ws");
    const setting = path.join("conf", "messagefoundry.toml");
    const conf = path.join(short, "conf");
    const plain = { [short]: "plain", [conf]: "plain" };
    const realpaths = { [short]: long, [conf]: path.join(long, "conf") };
    for (const fromWorkspace of [true, false]) {
      const scope = { fromWorkspace, trusted: true };
      // THE CONTROL: the folder spelled short is accepted, and the path returned keeps its spelling.
      assert.deepStrictEqual(securityConfigTarget(short, setting, scope, modelFs(plain, realpaths)), { ok: true, path: path.join(short, setting) });
      const linked = modelFs({ ...plain, [conf]: "link" }, realpaths);
      assert.strictEqual(securityConfigTarget(short, setting, scope, linked).ok, false, `a link below the folder ${fromWorkspace}`);
      const away = modelFs(plain, { ...realpaths, [conf]: path.resolve(path.sep, "elsewhere") });
      assert.strictEqual(securityConfigTarget(short, setting, scope, away).ok, false, `a path below resolving elsewhere ${fromWorkspace}`);
    }
  });

  test("a real workspace folder reached through an 8.3 short-name ancestor is accepted, and a link below it refused", function () {
    if (process.platform !== "win32") {
      this.skip();
    }
    const longDir = path.join(ws, "mf-secedit-long-folder-name");
    fs.mkdirSync(path.join(longDir, "ws", "conf"), { recursive: true });
    const same = (a: string, b: string) => path.relative(a, b) === "";
    const shortDir = shortName(longDir);
    let base: string;
    if (shortDir !== undefined && !same(shortDir, longDir)) {
      base = shortDir;
    } else if (ws.split(path.sep).some((part) => /~\d+$/.test(part)) && !same(real.realpath(ws), ws)) {
      // Nothing got a short name now, but os.tmpdir() already spells an ancestor in the 8.3 form,
      // as the CI runner's RUNNER~1, and realpath spells it otherwise, so the long folder is itself
      // reached through one.
      base = longDir;
    } else {
      // Measured: cmd's %~s printed no short name for the new folder, and no ancestor is spelled
      // as an alias, so this volume gives the test no 8.3 spelling. The model test above still ran.
      this.skip();
    }
    try {
      fs.symlinkSync(outside, path.join(longDir, "ws", "linked"), "junction");
    } catch {
      this.skip();
    }
    const root = path.join(base, "ws");
    const setting = path.join("conf", "messagefoundry.toml");
    for (const fromWorkspace of [true, false]) {
      const scope = { fromWorkspace, trusted: true };
      // THE CONTROL: the folder spelled short, as os.tmpdir() spells the runner's, is accepted.
      assert.deepStrictEqual(securityConfigTarget(root, setting, scope, real), { ok: true, path: path.join(root, setting) });
      assert.strictEqual(securityConfigTarget(root, "linked/messagefoundry.toml", scope, real).ok, false, `${fromWorkspace}`);
    }
  });

  test("on Windows, a component ending in a dot or a space is refused before any file-system call", function () {
    // Node reads such a component verbatim and finds nothing, while the CLI's open can drop the
    // ending, at least one trailing dot from a folder name, and follow a link the repository holds
    // (round 2 review, finding 1). A folder name ending in a space is refused too.
    if (process.platform !== "win32") {
      this.skip();
    }
    const root = path.resolve(path.sep, "mf-secedit-model", "ws");
    const plain = { [root]: "plain", [path.join(root, "linked")]: "link" };
    for (const fromWorkspace of [true, false]) {
      const scope = { fromWorkspace, trusted: true };
      // THE CONTROL: the same names with nothing trailing pass the spelling check.
      assert.ok(securityConfigTarget(root, "conf\\messagefoundry.toml", scope, modelFs(plain)).ok);
      for (const setting of ["linked.\\messagefoundry.toml", "linked \\messagefoundry.toml", "conf\\messagefoundry.toml.", "conf\\messagefoundry.toml "]) {
        const spy = modelFs(plain);
        assert.strictEqual(securityConfigTarget(root, setting, scope, spy).ok, false, `${JSON.stringify(setting)} ${fromWorkspace}`);
        assert.deepStrictEqual(spy.calls, [], `${JSON.stringify(setting)} touched the file system`);
      }
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

  test("known open limit, recorded and not desired: a user-set alias into the workspace folder is not checked", function () {
    // This records a KNOWN OPEN LIMIT, not a wanted outcome. Rule 3 compares spellings only, so an
    // alias outside the folder that leads into it, and then out through a link the repository
    // holds, is not caught; the securityConfigTarget docblock documents it. A change that closes
    // the limit should replace this assertion with a refusal, not be reverted to keep it green.
    const alias = path.join(outside, "alias");
    try {
      fs.symlinkSync(ws, alias, "junction");
      fs.symlinkSync(outside, path.join(ws, "linked"), "junction");
    } catch {
      this.skip();
    }
    const file = path.join(alias, "linked", "messagefoundry.toml");
    // The documented behaviour today: returned as written, with no link check.
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
      // An int at its own minimum (the session limits take 1), or 0 where it declares none.
      updates[f.key] = f.type === "int" ? (f.min ?? 0) : f.type === "string" ? "x" : f.type === "tristate" ? null : true;
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
      ["a session limit below 1", { max_session_hours: 0 }],
      ["an idle limit below 1", { sign_out_after_idle_minutes: 0 }],
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
