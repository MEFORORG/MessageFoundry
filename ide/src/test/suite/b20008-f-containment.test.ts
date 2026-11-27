// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 20008 branch F: the Security Settings editor's path containment and its siblings (BACKLOG
// #5411, #8237 items 16, 24, 57 and 102).
//
// Item 16: a user-set serviceConfig that reaches the workspace folder by another spelling, a UNC
// loopback admin share (`\\localhost\C$\...`) or a junction outside the folder, was accepted as
// written, so no link the repository holds was checked on it. The editor now reads the device and
// file id of each folder on the path and checks the part below the workspace folder. Item 57: in a
// window opened from a `.code-workspace` file, that file chooses the workspace folder and holds the
// workspace settings, so a workspace-set value is refused unless the folder lies inside the folder
// holding the file. Item 102: the real-path compare in resolveInsideWorkspace folds ASCII case only,
// so a junction onto a KELVIN SIGN sibling is not inside. Item 24: the connection edits bind
// `--service-config` with `=`, driven through an entry point the pre-fix code had.
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { connectionRemoveArgs, connectionUpsertArgs } from "../../connectionWizardModel";
import { securityConfigTarget, type LinkFs } from "../../securityEditorModel";
import { escapesByLink, resolveInsideWorkspace } from "../../workspaceContainment";
import { unlinkLinks } from "../unlinkLinks";

// The tests drive securityConfigTarget and its LinkFs only, which the pre-fix module had, so a run
// against it fails on an assertion rather than on a missing symbol. securityFileId is new, so it is
// read off the module at run time.
const model = require("../../securityEditorModel") as { securityFileId?: (p: string) => string };

const user = { fromWorkspace: false, trusted: true };
const workspaceScope = { fromWorkspace: true, trusted: true };
const fail = (code: string): Error => Object.assign(new Error(code), { code });

/** `scope` in a window opened from the `.code-workspace` file `workspaceFile`. */
function inWindow<S extends object>(scope: S, workspaceFile: string): S & { readonly workspaceFile: string } {
  return { ...scope, workspaceFile };
}

/** A file's device and file id as text, as the editor's fileId reads them from fs.statSync. */
function statId(p: string): string {
  const st = fs.statSync(p, { bigint: true });
  return `${st.dev}:${st.ino}`;
}

/** A LinkFs over spelled paths: `ids` maps a path to its file id (any other path does not exist
 *  for fileId, or throws the code its id names when that starts with E), `links` lstat as links,
 *  every other lstat is a plain entry, and realpath returns `realpaths[p]` or the path itself. It
 *  records every fileId call. */
function idFs(
  ids: Readonly<Record<string, string>>,
  links: readonly string[] = [],
  realpaths: Readonly<Record<string, string>> = {},
): LinkFs & { readonly asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    lstat: (p: string) => ({ isSymbolicLink: () => links.includes(p) }),
    realpath: (p: string): string => realpaths[p] ?? p,
    fileId: (p: string): string => {
      asked.push(p);
      const id = ids[p];
      if (id === undefined) {
        throw fail("ENOENT");
      }
      if (/^E[A-Z]+$/.test(id)) {
        throw fail(id);
      }
      return id;
    },
  };
}

const windowsSuite = process.platform === "win32" ? suite : suite.skip;

windowsSuite("b20008 F: a user-set path that reaches the workspace by another spelling is checked (#8237 item 16)", () => {
  const ws = "C:\\ws";
  const unc = "\\\\localhost\\C$\\ws";
  // The UNC loopback spelling and the drive spelling are one folder by id, as measured on Windows 11.
  const ids = { "C:\\": "1:1", "C:\\ws": "1:2", "\\\\localhost\\C$\\": "1:1", [unc]: "1:2", [`${unc}\\cfg`]: "1:3" };

  test("a UNC loopback alias that then leaves through a link the repository holds is refused", () => {
    const got = securityConfigTarget(ws, `${unc}\\cfg\\messagefoundry.toml`, user, idFs(ids, ["C:\\ws\\cfg"]));
    assert.ok(!got.ok && got.problem.includes("passes through a link"), JSON.stringify(got));
  });

  test("control: the same alias onto a plain folder is accepted, spelled from the workspace folder", () => {
    const got = securityConfigTarget(ws, `${unc}\\cfg\\messagefoundry.toml`, user, idFs(ids));
    assert.deepStrictEqual(got, { ok: true, path: "C:\\ws\\cfg\\messagefoundry.toml" });
  });

  test("the alias gets rule 2's name checks too: a device name below it is refused", () => {
    const got = securityConfigTarget(ws, `${unc}\\nul`, user, idFs(ids));
    assert.ok(!got.ok && got.problem.includes("device name"), JSON.stringify(got));
    const itself = securityConfigTarget(ws, unc, user, idFs(ids));
    assert.ok(!itself.ok && itself.problem.includes("workspace folder itself"), JSON.stringify(itself));
  });

  test("a path whose folders are another folder is accepted as written, the walk stopping where it ends", () => {
    const fsx = idFs({ ...ids, "D:\\": "2:1", "D:\\elsewhere": "2:5" });
    const got = securityConfigTarget(ws, "D:\\elsewhere\\new\\messagefoundry.toml", user, fsx);
    assert.deepStrictEqual(got, { ok: true, path: "D:\\elsewhere\\new\\messagefoundry.toml" });
    // The walk read the workspace folder, then each folder down to the first that does not exist.
    assert.deepStrictEqual(fsx.asked, ["C:\\ws", "D:\\", "D:\\elsewhere", "D:\\elsewhere\\new"]);
  });

  test("a folder on the path that cannot be read, or a workspace whose id cannot, refuses", () => {
    for (const code of ["EACCES", "EIO", "ENOFILEID"]) {
      const got = securityConfigTarget(ws, "D:\\elsewhere\\x.toml", user, idFs({ ...ids, "D:\\": "2:1", "D:\\elsewhere": code }));
      assert.ok(!got.ok && got.problem.includes("could not be read"), `${code} ${JSON.stringify(got)}`);
    }
    const noRoot = securityConfigTarget(ws, "D:\\elsewhere\\x.toml", user, idFs({ "D:\\": "2:1" }));
    assert.strictEqual(noRoot.ok, false, JSON.stringify(noRoot));
    // And a caller that passes no fileId refuses, rather than accept a path it cannot place.
    const blind: LinkFs = { lstat: () => ({ isSymbolicLink: () => false }), realpath: (p: string) => p };
    assert.strictEqual(securityConfigTarget(ws, "D:\\elsewhere\\x.toml", user, blind).ok, false);
  });

  test("a workspace-set alias is still refused by its spelling, before any read", () => {
    const fsx = idFs(ids);
    const got = securityConfigTarget(ws, `${unc}\\cfg\\messagefoundry.toml`, workspaceScope, fsx);
    assert.ok(!got.ok && got.problem.includes("outside the workspace folder"), JSON.stringify(got));
    assert.deepStrictEqual(fsx.asked, []);
  });
});

suite("b20008 F: securityFileId (#8237 item 16)", () => {
  test("a file id of 0 throws rather than match another entry; a real id is device and file id", () => {
    // The module object itself, which the model's import reads through, not this file's import wrapper.
    const nodeFs = require("node:fs") as { statSync: unknown };
    const real = nodeFs.statSync;
    nodeFs.statSync = () => ({ dev: 7n, ino: 0n });
    try {
      assert.throws(() => model.securityFileId!("anything"), (e: { code?: unknown }) => e.code === "ENOFILEID");
    } finally {
      nodeFs.statSync = real;
    }
    const st = fs.statSync(os.tmpdir(), { bigint: true });
    assert.strictEqual(model.securityFileId!(os.tmpdir()), `${st.dev}:${st.ino}`);
    assert.throws(() => model.securityFileId!(path.join(os.tmpdir(), "mf-b20008-does-not-exist")), (e: { code?: unknown }) => e.code === "ENOENT");
  });
});

windowsSuite("b20008 F: the UNC loopback alias on a real folder (#8237 item 16)", () => {
  let base: string;
  let ws: string;

  setup(() => {
    base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-b20008-unc-")));
    ws = path.join(base, "ws");
    fs.mkdirSync(ws);
    fs.mkdirSync(path.join(base, "outside"));
  });

  teardown(() => {
    unlinkLinks(base);
    fs.rmSync(base, { recursive: true, force: true });
  });

  test("a junction reached through \\\\localhost\\<drive>$ is refused; a plain folder there is not", function () {
    const unc = `\\\\localhost\\${ws[0]}$${ws.slice(2)}`;
    try {
      if (statId(unc) !== statId(ws)) {
        this.skip(); // the admin share reports another id here, so there is no alias to place
      }
    } catch {
      this.skip(); // no admin share on this box (it needs the Server service and an administrator)
    }
    fs.symlinkSync(path.join(base, "outside"), path.join(ws, "linked"), "junction");
    fs.mkdirSync(path.join(ws, "plain"));
    const fsx: LinkFs = { lstat: fs.lstatSync, realpath: fs.realpathSync.native, fileId: statId };
    const got = securityConfigTarget(ws, `${unc}\\linked\\messagefoundry.toml`, user, fsx);
    assert.ok(!got.ok && got.problem.includes("passes through a link"), JSON.stringify(got));
    assert.deepStrictEqual(securityConfigTarget(ws, `${unc}\\plain\\messagefoundry.toml`, user, fsx), {
      ok: true,
      path: path.join(ws, "plain", "messagefoundry.toml"),
    });
  });
});

suite("b20008 F: a .code-workspace file cannot choose the folder a workspace value is read against (#8237 item 57)", () => {
  let base: string;

  setup(() => {
    base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-b20008-wsfile-")));
  });

  teardown(() => {
    unlinkLinks(base);
    fs.rmSync(base, { recursive: true, force: true });
  });

  const real: LinkFs = { lstat: fs.lstatSync, realpath: fs.realpathSync.native, fileId: statId };

  test("a workspace folder outside the folder holding the .code-workspace file refuses a workspace value", () => {
    const repo = path.join(base, "repo");
    const chosen = path.join(base, "chosen");
    fs.mkdirSync(repo);
    fs.mkdirSync(chosen);
    const workspaceFile = path.join(repo, "project.code-workspace");
    const got = securityConfigTarget(chosen, "messagefoundry.toml", inWindow(workspaceScope, workspaceFile), real);
    assert.ok(!got.ok && got.problem.includes(".code-workspace"), JSON.stringify(got));
    // A user value is the operator's, and is not refused for it.
    assert.deepStrictEqual(securityConfigTarget(chosen, "messagefoundry.toml", inWindow(user, workspaceFile), real), {
      ok: true,
      path: path.join(chosen, "messagefoundry.toml"),
    });
  });

  test("control: the folder holding the file, or one inside it, takes the workspace value", () => {
    const repo = path.join(base, "repo");
    fs.mkdirSync(path.join(repo, "sub"), { recursive: true });
    const workspaceFile = path.join(repo, "project.code-workspace");
    for (const folder of [repo, path.join(repo, "sub")]) {
      assert.deepStrictEqual(securityConfigTarget(folder, "messagefoundry.toml", inWindow(workspaceScope, workspaceFile), real), {
        ok: true,
        path: path.join(folder, "messagefoundry.toml"),
      });
    }
    // And with no .code-workspace file the folder is taken as given, as before.
    assert.ok(securityConfigTarget(path.join(repo, "sub"), "messagefoundry.toml", workspaceScope, real).ok);
  });

  test("a folder spelled inside but linked outside is refused, and so is a real path that cannot be read", function () {
    const repo = path.join(base, "repo");
    const elsewhere = path.join(base, "elsewhere");
    fs.mkdirSync(repo);
    fs.mkdirSync(elsewhere);
    const linked = path.join(repo, "linked");
    try {
      fs.symlinkSync(elsewhere, linked, "junction");
    } catch {
      this.skip();
    }
    const workspaceFile = path.join(repo, "project.code-workspace");
    const got = securityConfigTarget(linked, "messagefoundry.toml", inWindow(workspaceScope, workspaceFile), real);
    assert.ok(!got.ok && got.problem.includes(".code-workspace"), JSON.stringify(got));
    const unreadable: LinkFs = {
      ...real,
      realpath: (p: string): string => {
        throw fail(p === repo ? "EACCES" : "EIO");
      },
    };
    const blind = securityConfigTarget(repo, "messagefoundry.toml", inWindow(workspaceScope, workspaceFile), unreadable);
    assert.ok(!blind.ok && blind.problem.includes(".code-workspace"), JSON.stringify(blind));
  });

  test("the editor passes VS Code's workspaceFile, and none for an untitled workspace", () => {
    const src = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "securityEditor.ts"), "utf8");
    assert.match(src, /const file = vscode\.workspace\.workspaceFile;/);
    assert.match(src, /file === undefined \|\| file\.scheme === "untitled" \? undefined : file\.fsPath/);
    assert.match(src, /securityConfigTarget\(ws, value, \{ fromWorkspace, trusted: vscode\.workspace\.isTrusted, workspaceFile \}/);
    assert.match(src, /fileId: securityFileId/);
  });
});

windowsSuite("b20008 F: the real-path compare in resolveInsideWorkspace folds ASCII case only (#8237 item 102)", () => {
  let base: string;

  setup(() => {
    base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-b20008-kelvin-")));
  });

  teardown(() => {
    unlinkLinks(base);
    fs.rmSync(base, { recursive: true, force: true });
  });

  test("a junction inside the workspace onto a KELVIN SIGN sibling is not inside it", function () {
    const ws = path.join(base, "kit");
    const sibling = path.join(base, "\u212Ait");
    fs.mkdirSync(ws);
    if (fs.existsSync(sibling)) {
      this.skip(); // this file system folds KELVIN SIGN onto k, so there is no sibling to reach
    }
    fs.mkdirSync(path.join(sibling, "cfg"), { recursive: true });
    fs.mkdirSync(path.join(ws, "plain"));
    try {
      fs.symlinkSync(path.join(sibling, "cfg"), path.join(ws, "cfg"), "junction");
      fs.symlinkSync(path.join(ws, "plain"), path.join(ws, "inside"), "junction");
    } catch {
      this.skip();
    }
    // The spelling is inside, so only the real-path compare can refuse it.
    assert.strictEqual(resolveInsideWorkspace(ws, "cfg"), undefined);
    assert.strictEqual(escapesByLink(ws, "cfg"), true);
    // THE CONTROL: a junction that stays inside the folder resolves.
    assert.strictEqual(resolveInsideWorkspace(ws, "inside"), path.join(ws, "inside"));
  });
});

suite("b20008 F: the connection edits bind --service-config with = (#8237 item 24)", () => {
  test("a dash-leading service config stays the flag's value in upsert and remove", () => {
    const conn = { name: "IB_X" } as never;
    for (const args of [
      connectionUpsertArgs("samples/config", "-svc.toml", conn),
      connectionRemoveArgs("samples/config", "-svc.toml", "IB_X", "inbound"),
    ]) {
      assert.ok(args.includes("--service-config=-svc.toml"), JSON.stringify(args));
      assert.ok(!args.includes("--service-config"), JSON.stringify(args));
    }
    // THE CONTROL: no service config adds no flag.
    assert.ok(!connectionUpsertArgs("samples/config", undefined, conn).some((a) => a.startsWith("--service-config")));
  });
});
