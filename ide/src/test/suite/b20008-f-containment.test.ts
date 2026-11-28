// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 20008 branch F: the Security Settings editor's path containment and its siblings (BACKLOG
// #5411, #8237 items 16, 24, 57 and 102).
//
// Item 16: a user-set serviceConfig that reaches the workspace folder by another spelling, a UNC
// loopback admin share (`\\localhost\C$\...`) or a junction outside the folder onto it or a folder
// below it, was accepted as written, so no link the repository holds was checked on it. The editor
// now reads each folder on the path, by real path and by device and file id, and checks the part
// below the workspace folder. Item 57: in a window opened from a `.code-workspace` file, that file
// chooses the workspace folder and holds the workspace settings, so a path inside that folder is
// refused unless the folder lies inside the folder holding the file. Item 102: the real-path compare
// in resolveInsideWorkspace folds ASCII case only, so a junction onto a KELVIN SIGN sibling is not
// inside. Item 24: the connection edits bind `--service-config` with `=`, driven through an entry
// point the pre-fix code had.
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { connectionRemoveArgs, connectionUpsertArgs } from "../../connectionWizardModel";
import { securityConfigTarget, type LinkFs } from "../../securityEditorModel";
import { escapesByLink, resolveInsideWorkspace } from "../../workspaceContainment";
import { unlinkLinks } from "../unlinkLinks";

// The tests drive securityConfigTarget and its LinkFs, which the pre-fix module had, so a run
// against it fails on an assertion rather than on a missing symbol. The helpers this branch adds
// are read off the module at run time.
const model = require("../../securityEditorModel") as {
  securityFileId?: (p: string) => string;
  workspaceFilePath?: (file: { scheme: string; fsPath: string } | undefined) => string | undefined;
};

const user = { fromWorkspace: false, trusted: true };
const workspaceScope = { fromWorkspace: true, trusted: true };
const fail = (code: string): Error => Object.assign(new Error(code), { code });

/** `scope` in a window opened from the `.code-workspace` file `workspaceFile`. */
function inWindow<S extends object>(scope: S, workspaceFile: string): S & { readonly workspaceFile: string } {
  return { ...scope, workspaceFile };
}

/** A file's device and file id as text, read from fs.statSync: the editor's own securityFileId
 *  where the module has it, else the same read without its file-id-0 guard. */
function statId(p: string): string {
  if (model.securityFileId !== undefined) {
    return model.securityFileId(p);
  }
  const st = fs.statSync(p, { bigint: true });
  return `${st.dev}:${st.ino}`;
}

/**
 * A model file system over spelled paths. A path exists when `ids` or `realpaths` names it, or it is
 * in `links`. `ids` gives its file id, or the error code fileId throws when the value starts with
 * E; `realpaths` gives its real path, or the code realpath throws; a path that exists with no
 * `realpaths` entry is its own real path. `links` lstat as links, and so do the `dangling` ones,
 * which do not exist. Every fileId call is recorded.
 */
function modelFs(
  opts: {
    ids?: Readonly<Record<string, string>>;
    realpaths?: Readonly<Record<string, string>>;
    links?: readonly string[];
    dangling?: readonly string[];
  } = {},
): LinkFs & { readonly asked: string[] } {
  const ids = opts.ids ?? {};
  const realpaths = opts.realpaths ?? {};
  const links = opts.links ?? [];
  const dangling = opts.dangling ?? [];
  const exists = (p: string): boolean => p in ids || p in realpaths || links.includes(p);
  const asked: string[] = [];
  return {
    asked,
    lstat: (p: string) => {
      if (!exists(p) && !dangling.includes(p)) {
        throw fail("ENOENT");
      }
      return { isSymbolicLink: () => links.includes(p) || dangling.includes(p) };
    },
    realpath: (p: string): string => {
      const r = realpaths[p] ?? (exists(p) ? p : "ENOENT");
      if (/^E[A-Z]+$/.test(r)) {
        throw fail(r);
      }
      return r;
    },
    fileId: (p: string): string => {
      asked.push(p);
      const id = ids[p] ?? "ENOENT";
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
  // The UNC loopback spelling and the drive spelling are one folder by id, as measured on Windows 11,
  // and Node's real path keeps the UNC spelling.
  const ids = {
    "C:\\": "1:1",
    "C:\\ws": "1:2",
    "C:\\ws\\cfg": "1:3",
    "\\\\localhost\\C$\\": "1:1",
    [unc]: "1:2",
    [`${unc}\\cfg`]: "1:3",
  };

  test("a UNC loopback alias that then leaves through a link the repository holds is refused", () => {
    const got = securityConfigTarget(ws, `${unc}\\cfg\\messagefoundry.toml`, user, modelFs({ ids, links: ["C:\\ws\\cfg"] }));
    assert.ok(!got.ok && got.problem.includes("passes through a link"), JSON.stringify(got));
  });

  test("control: the same alias onto a plain folder is accepted, and kept as written, being placed by id alone", () => {
    const got = securityConfigTarget(ws, `${unc}\\cfg\\messagefoundry.toml`, user, modelFs({ ids }));
    assert.deepStrictEqual(got, { ok: true, path: `${unc}\\cfg\\messagefoundry.toml` });
  });

  test("the alias gets rule 2's name checks too: a device name below it, or the folder itself, is refused", () => {
    const got = securityConfigTarget(ws, `${unc}\\nul`, user, modelFs({ ids }));
    assert.ok(!got.ok && got.problem.includes("device name"), JSON.stringify(got));
    const itself = securityConfigTarget(ws, unc, user, modelFs({ ids }));
    assert.ok(!itself.ok && itself.problem.includes("workspace folder itself"), JSON.stringify(itself));
  });

  test("a junction outside the folder onto a folder below it is placed by real path, and spelled from the folder", () => {
    const fsx = (links: string[]) =>
      modelFs({ ids: { ...ids, "D:\\": "2:1", "C:\\ws\\sub": "1:4", "C:\\ws\\sub\\cfg": "1:5" }, realpaths: { "D:\\alias": "C:\\ws\\sub" }, links });
    const linked = securityConfigTarget(ws, "D:\\alias\\cfg\\x.toml", user, fsx(["C:\\ws\\sub\\cfg"]));
    assert.ok(!linked.ok && linked.problem.includes("passes through a link"), JSON.stringify(linked));
    // THE CONTROL: with no link below, the path is the workspace's own file.
    assert.deepStrictEqual(securityConfigTarget(ws, "D:\\alias\\cfg\\x.toml", user, fsx([])), {
      ok: true,
      path: "C:\\ws\\sub\\cfg\\x.toml",
    });
  });

  test("a path whose folders are another folder is accepted as written, the walk stopping where it ends", () => {
    const fsx = modelFs({ ids: { ...ids, "D:\\": "2:1", "D:\\elsewhere": "2:5" } });
    const got = securityConfigTarget(ws, "D:\\elsewhere\\new\\messagefoundry.toml", user, fsx);
    assert.deepStrictEqual(got, { ok: true, path: "D:\\elsewhere\\new\\messagefoundry.toml" });
    // The walk read the workspace folder's id, then each existing folder's once.
    assert.deepStrictEqual(fsx.asked, ["C:\\ws", "D:\\", "D:\\elsewhere"]);
  });

  test("a dangling link, a folder that cannot be read, or a workspace that cannot, refuses", () => {
    const base = { ...ids, "D:\\": "2:1" };
    const dangling = securityConfigTarget(ws, "D:\\dang\\x.toml", user, modelFs({ ids: base, dangling: ["D:\\dang"] }));
    assert.ok(!dangling.ok && dangling.problem.includes("dangling link"), JSON.stringify(dangling));
    for (const fsx of [
      modelFs({ ids: { ...base, "D:\\elsewhere": "EACCES" } }),
      modelFs({ ids: { ...base, "D:\\elsewhere": "2:5" }, realpaths: { "D:\\elsewhere": "EIO" } }),
      modelFs({ ids: { "D:\\": "2:1" } }), // the workspace folder itself does not exist
    ]) {
      const got = securityConfigTarget(ws, "D:\\elsewhere\\x.toml", user, fsx);
      assert.ok(!got.ok && got.problem.includes("could not read"), JSON.stringify(got));
    }
    // A long-path or device prefix does not split into folders, so it is refused, not walked.
    for (const spelled of ["\\\\?\\D:\\elsewhere\\x.toml", "\\\\.\\D:\\elsewhere\\x.toml"]) {
      const got = securityConfigTarget(ws, spelled, user, modelFs({ ids: { ...base, "D:\\elsewhere": "2:5" } }));
      assert.ok(!got.ok && got.problem.includes("could not read"), `${spelled} ${JSON.stringify(got)}`);
    }
    // And a caller that passes no fileId refuses, rather than accept a path it cannot place.
    const blind: LinkFs = { lstat: () => ({ isSymbolicLink: () => false }), realpath: (p: string) => p };
    assert.strictEqual(securityConfigTarget(ws, "D:\\elsewhere\\x.toml", user, blind).ok, false);
  });

  test("an entry with no file id is placed by real path only, not refused", () => {
    const noIds = { ...ids, "D:\\": "ENOFILEID", "D:\\elsewhere": "ENOFILEID", "C:\\ws": "ENOFILEID" };
    assert.deepStrictEqual(securityConfigTarget(ws, "D:\\elsewhere\\x.toml", user, modelFs({ ids: noIds })), {
      ok: true,
      path: "D:\\elsewhere\\x.toml",
    });
    // A junction onto the folder is still found by real path when the workspace keeps no file id.
    const viaJunction = modelFs({ ids: noIds, realpaths: { "D:\\alias": "C:\\ws" }, links: ["C:\\ws\\cfg"] });
    assert.strictEqual(securityConfigTarget(ws, "D:\\alias\\cfg\\x.toml", user, viaJunction).ok, false);
  });

  test("a workspace-set alias is still refused by its spelling, before any read", () => {
    const fsx = modelFs({ ids });
    const got = securityConfigTarget(ws, `${unc}\\cfg\\messagefoundry.toml`, workspaceScope, fsx);
    assert.ok(!got.ok && got.problem.includes("outside the workspace folder"), JSON.stringify(got));
    assert.deepStrictEqual(fsx.asked, []);
  });
});

suite("b20008 F: securityFileId and workspaceFilePath (#8237 items 16 and 57)", () => {
  test("a file id of 0 throws ENOFILEID rather than match another entry; a real id is device and file id", () => {
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

  test("workspaceFilePath names a .code-workspace file, and none for an untitled workspace or a folder window", () => {
    const f = model.workspaceFilePath!;
    assert.strictEqual(f({ scheme: "file", fsPath: "C:\\repo\\p.code-workspace" }), "C:\\repo\\p.code-workspace");
    assert.strictEqual(f({ scheme: "untitled", fsPath: "Untitled-1" }), undefined);
    assert.strictEqual(f(undefined), undefined);
  });

  test("the editor passes VS Code's workspaceFile through it, and the editor's own fileId", () => {
    const src = fs.readFileSync(path.join(__dirname, "..", "..", "..", "src", "securityEditor.ts"), "utf8");
    assert.match(src, /workspaceFilePath\(vscode\.workspace\.workspaceFile\)/);
    assert.match(src, /securityConfigTarget\([^)]*\bworkspaceFile\b/);
    assert.match(src, /fileId:\s*securityFileId/);
  });
});

windowsSuite("b20008 F: aliases of a real workspace folder (#8237 item 16)", () => {
  let base: string;
  let ws: string;
  let outside: string;

  setup(() => {
    base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-b20008-alias-")));
    ws = path.join(base, "ws");
    outside = path.join(base, "outside");
    fs.mkdirSync(path.join(ws, "sub", "plain"), { recursive: true });
    fs.mkdirSync(outside);
  });

  teardown(() => {
    unlinkLinks(base);
    fs.rmSync(base, { recursive: true, force: true });
  });

  const real = (): LinkFs => ({ lstat: fs.lstatSync, realpath: fs.realpathSync.native, fileId: statId });

  test("a junction reached through \\\\localhost\\<drive>$ is refused; a plain folder there is not", function () {
    const unc = `\\\\localhost\\${ws[0]}$${ws.slice(2)}`;
    try {
      if (statId(unc) !== statId(ws)) {
        this.skip(); // the admin share reports another id here, so there is no alias to place
      }
    } catch {
      this.skip(); // no admin share on this box (it needs the Server service and an administrator)
    }
    fs.symlinkSync(outside, path.join(ws, "linked"), "junction");
    const got = securityConfigTarget(ws, `${unc}\\linked\\messagefoundry.toml`, user, real());
    assert.ok(!got.ok && got.problem.includes("passes through a link"), JSON.stringify(got));
    assert.deepStrictEqual(securityConfigTarget(ws, `${unc}\\sub\\plain\\messagefoundry.toml`, user, real()), {
      ok: true,
      path: `${unc}\\sub\\plain\\messagefoundry.toml`,
    });
  });

  test("a junction outside the folder onto a folder below it, then out through a repository link, is refused", function () {
    try {
      fs.symlinkSync(path.join(ws, "sub"), path.join(outside, "alias"), "junction");
      fs.symlinkSync(outside, path.join(ws, "sub", "linked"), "junction");
      fs.symlinkSync(path.join(ws, "sub", "not-yet"), path.join(outside, "dangling"), "junction");
    } catch {
      this.skip();
    }
    const linked = securityConfigTarget(ws, path.join(outside, "alias", "linked", "x.toml"), user, real());
    assert.ok(!linked.ok && linked.problem.includes("passes through a link"), JSON.stringify(linked));
    const dangling = securityConfigTarget(ws, path.join(outside, "dangling", "x.toml"), user, real());
    assert.ok(!dangling.ok && dangling.problem.includes("dangling link"), JSON.stringify(dangling));
    // THE CONTROL: a plain folder through the same alias is the workspace's own file.
    assert.deepStrictEqual(securityConfigTarget(ws, path.join(outside, "alias", "plain", "x.toml"), user, real()), {
      ok: true,
      path: path.join(ws, "sub", "plain", "x.toml"),
    });
  });

  test("known open limit, recorded and not desired: an alias onto a folder that is itself a repository link", function () {
    // This records a KNOWN OPEN LIMIT, not a wanted outcome (the securityConfigTarget docblock,
    // "Open limits"). A real path follows every link at once, so an alias onto ws\held, where held
    // is a link the repository holds, is placed where held leads and held is never checked. A
    // change that follows each link one hop at a time should turn this assertion into a refusal.
    const victim = path.join(base, "victim");
    fs.mkdirSync(victim);
    try {
      fs.symlinkSync(victim, path.join(ws, "held"), "junction");
      fs.symlinkSync(path.join(ws, "held"), path.join(outside, "onto-held"), "junction");
    } catch {
      this.skip();
    }
    const file = path.join(outside, "onto-held", "x.toml");
    assert.deepStrictEqual(securityConfigTarget(ws, file, user, real()), { ok: true, path: file });
    // At any depth below the repository's link too: an alias onto ws\held\deeper.
    fs.mkdirSync(path.join(victim, "deeper"));
    fs.symlinkSync(path.join(ws, "held", "deeper"), path.join(outside, "onto-deeper"), "junction");
    const deeper = path.join(outside, "onto-deeper", "x.toml");
    assert.deepStrictEqual(securityConfigTarget(ws, deeper, user, real()), { ok: true, path: deeper });
    // The same link reached through the workspace folder's own spelling is refused.
    assert.strictEqual(securityConfigTarget(ws, path.join(ws, "held", "x.toml"), user, real()).ok, false);
  });

  test("a directory symbolic link outside the folder onto a folder below it is placed by real path", function () {
    try {
      fs.symlinkSync(path.join(ws, "sub"), path.join(outside, "symalias"), "dir");
    } catch {
      this.skip(); // a directory symbolic link needs a privilege or Developer Mode on Windows
    }
    fs.symlinkSync(outside, path.join(ws, "sub", "linked"), "junction");
    const linked = securityConfigTarget(ws, path.join(outside, "symalias", "linked", "x.toml"), user, real());
    assert.ok(!linked.ok && linked.problem.includes("passes through a link"), JSON.stringify(linked));
    // THE CONTROL: a plain folder through the same symbolic link is the workspace's own file.
    assert.deepStrictEqual(securityConfigTarget(ws, path.join(outside, "symalias", "plain", "x.toml"), user, real()), {
      ok: true,
      path: path.join(ws, "sub", "plain", "x.toml"),
    });
  });

  test("an alias spelled with a trailing dot is refused, not walked (round-d1ff257d finding 1)", function () {
    // Node reads `ws.` as written and finds nothing there; the CLI's Win32 open drops the dot and
    // follows the repository's link out of the folder.
    try {
      fs.symlinkSync(outside, path.join(ws, "linked"), "junction");
      fs.symlinkSync(ws, path.join(outside, "alias"), "junction");
    } catch {
      this.skip();
    }
    const unc = `\\\\localhost\\${ws[0]}$${ws.slice(2)}`;
    for (const spelled of [`${ws}.\\linked\\x.toml`, `${outside}\\alias.\\linked\\x.toml`, `${unc}.\\linked\\x.toml`, `${ws} \\linked\\x.toml`]) {
      const got = securityConfigTarget(ws, spelled, user, real());
      assert.ok(!got.ok && got.problem.includes("dot or a space"), `${spelled} ${JSON.stringify(got)}`);
    }
    // THE CONTROL: the same alias without the dot reaches the folder and is refused by the link walk,
    // and a plain folder through it is accepted.
    const plainAlias = securityConfigTarget(ws, `${outside}\\alias\\linked\\x.toml`, user, real());
    assert.ok(!plainAlias.ok && plainAlias.problem.includes("passes through a link"), JSON.stringify(plainAlias));
    assert.ok(securityConfigTarget(ws, `${outside}\\alias\\sub\\plain\\x.toml`, user, real()).ok);
  });
});

windowsSuite("b20008 F: every name on a user-set path is checked before any read (round-d1ff257d finding 1)", () => {
  const none: LinkFs = {
    lstat: () => {
      throw new Error("lstat called");
    },
    realpath: () => {
      throw new Error("realpath called");
    },
    fileId: () => {
      throw new Error("fileId called");
    },
  };

  test("a trailing dot or space, a colon or a device name anywhere on the path refuses with no file-system call", () => {
    for (const [spelled, said] of [
      ["C:\\ws.\\linked\\x.toml", "dot or a space"],
      ["C:\\ws \\x.toml", "dot or a space"],
      ["\\\\localhost\\C$\\ws.\\x.toml", "dot or a space"],
      ["D:\\elsewhere\\cfg:s\\x.toml", "colon"],
      ["D:\\elsewhere\\nul\\x.toml", "device name"],
      ["D:\\elsewhere\\x.toml.", "dot or a space"],
    ]) {
      const got = securityConfigTarget("C:\\ws", spelled, user, none);
      assert.ok(!got.ok && got.problem.includes(said), `${spelled} ${JSON.stringify(got)}`);
    }
  });

  test("in a .code-workspace window, a trailing-dot spelling of the chosen folder is refused, not accepted", () => {
    const got = securityConfigTarget("C:\\chosen", "C:\\chosen.\\messagefoundry.toml", inWindow(user, "C:\\repo\\p.code-workspace"), none);
    assert.ok(!got.ok && got.problem.includes("dot or a space"), JSON.stringify(got));
  });
});

suite("b20008 F: a .code-workspace file cannot choose the folder a path is read against (#8237 item 57)", () => {
  let base: string;

  setup(() => {
    base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "mf-b20008-wsfile-")));
  });

  teardown(() => {
    unlinkLinks(base);
    fs.rmSync(base, { recursive: true, force: true });
  });

  const real: LinkFs = { lstat: fs.lstatSync, realpath: fs.realpathSync.native, fileId: statId };

  test("a workspace folder outside the folder holding the .code-workspace file refuses a path inside it", () => {
    const repo = path.join(base, "repo");
    const chosen = path.join(base, "chosen");
    fs.mkdirSync(repo);
    fs.mkdirSync(chosen);
    const workspaceFile = path.join(repo, "project.code-workspace");
    // A workspace value, and the default or a relative user value, all resolve against the chosen folder.
    for (const scope of [workspaceScope, user]) {
      const got = securityConfigTarget(chosen, "messagefoundry.toml", inWindow(scope, workspaceFile), real);
      assert.ok(!got.ok && got.problem.includes(".code-workspace"), JSON.stringify(got));
    }
    // On Windows the chosen folder spelled with a trailing dot, which the CLI's open drops, is
    // refused too. Elsewhere no open drops the dot and the backslash is part of the name, so it
    // names a file beside the chosen folder and is accepted as written.
    const dottedPath = `${chosen}.\\messagefoundry.toml`;
    const dotted = securityConfigTarget(chosen, dottedPath, inWindow(user, workspaceFile), real);
    if (process.platform === "win32") {
      assert.ok(!dotted.ok && dotted.problem.includes("dot or a space"), JSON.stringify(dotted));
    } else {
      assert.deepStrictEqual(dotted, { ok: true, path: dottedPath });
    }
    // An absolute user path outside the chosen folder is the operator's, and is not refused for it.
    const mine = path.join(base, "mine.toml");
    assert.deepStrictEqual(securityConfigTarget(chosen, mine, inWindow(user, workspaceFile), real), { ok: true, path: mine });
  });

  test("control: the folder holding the file, or one inside it, takes the value", () => {
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

  test("a file that chose a folder below its own still has its own folder checked for a user path", function () {
    const repo = path.join(base, "repo");
    const victim = path.join(base, "victim");
    fs.mkdirSync(path.join(repo, "empty"), { recursive: true });
    fs.mkdirSync(path.join(repo, "plain"));
    fs.mkdirSync(victim);
    try {
      fs.symlinkSync(victim, path.join(repo, "cfg"), "junction");
    } catch {
      this.skip();
    }
    const workspaceFile = path.join(repo, "evil.code-workspace");
    const chosen = path.join(repo, "empty");
    const got = securityConfigTarget(chosen, path.join(repo, "cfg", "messagefoundry.toml"), inWindow(user, workspaceFile), real);
    assert.ok(!got.ok && got.problem.includes("passes through a link"), JSON.stringify(got));
    // An alias of the file's folder is placed in it as well (round-d1ff257d finding 3): a junction
    // outside onto it, and the UNC loopback admin share where this box has one.
    fs.mkdirSync(path.join(base, "out"));
    fs.symlinkSync(repo, path.join(base, "out", "repo-alias"), "junction");
    const viaJunction = securityConfigTarget(chosen, path.join(base, "out", "repo-alias", "cfg", "m.toml"), inWindow(user, workspaceFile), real);
    assert.ok(!viaJunction.ok && viaJunction.problem.includes("passes through a link"), JSON.stringify(viaJunction));
    const unc = `\\\\localhost\\${repo[0]}$${repo.slice(2)}`;
    let shared = false;
    try {
      shared = statId(unc) === statId(repo);
    } catch {
      shared = false; // no admin share on this box
    }
    if (shared) {
      const viaUnc = securityConfigTarget(chosen, `${unc}\\cfg\\m.toml`, inWindow(user, workspaceFile), real);
      assert.ok(!viaUnc.ok && viaUnc.problem.includes("passes through a link"), JSON.stringify(viaUnc));
    }
    // THE CONTROL: a plain folder in the file's folder is accepted, and outside it nothing changes.
    const plain = path.join(repo, "plain", "messagefoundry.toml");
    assert.deepStrictEqual(securityConfigTarget(chosen, plain, inWindow(user, workspaceFile), real), { ok: true, path: plain });
    const mine = path.join(base, "mine.toml");
    assert.deepStrictEqual(securityConfigTarget(chosen, mine, inWindow(user, workspaceFile), real), { ok: true, path: mine });
  });

  test("a relative user value that climbs out of the folder the file chose is refused (round-55360875 finding 2)", () => {
    const repo = path.join(base, "repo");
    const chosen = path.join(base, "chosen");
    fs.mkdirSync(path.join(repo, "below"), { recursive: true });
    fs.mkdirSync(chosen);
    const workspaceFile = path.join(repo, "project.code-workspace");
    const up = `..${path.sep}messagefoundry.toml`;
    const climbs = [up];
    if (process.platform === "win32") {
      // Each of these Node reads on the chosen folder's drive (round-0d26a789 finding 1): a rooted
      // path with no drive, and a doubled or tripled separator with no server and share.
      const rest = path.relative(path.parse(base).root, base);
      climbs.push(`\\${rest}\\x.toml`, "\\\\x.toml", `\\\\\\${rest}\\x.toml`, "//x.toml", `///${rest.replace(/\\/g, "/")}/x.toml`);
    }
    for (const setting of climbs) {
      const got = securityConfigTarget(chosen, setting, inWindow(user, workspaceFile), real);
      assert.ok(!got.ok && got.problem.includes("not a full path"), `${setting} ${JSON.stringify(got)}`);
    }
    // THE CONTROL: with no .code-workspace file the operator opened the folder, and the climb is
    // theirs, as before; a full path is accepted in the window; a relative value that stays inside
    // the folder is not this check's.
    assert.deepStrictEqual(securityConfigTarget(chosen, up, user, real), { ok: true, path: path.join(base, "messagefoundry.toml") });
    const full = path.join(base, "messagefoundry.toml");
    assert.deepStrictEqual(securityConfigTarget(chosen, full, inWindow(user, workspaceFile), real), { ok: true, path: full });
    const inside = securityConfigTarget(path.join(repo, "below"), `sub${path.sep}..${path.sep}m.toml`, inWindow(user, workspaceFile), real);
    assert.deepStrictEqual(inside, { ok: true, path: path.join(repo, "below", "m.toml") });
  });

  test("a climb from a folder inside the file's own folder is accepted, as on main (round-0d26a789 finding 3)", () => {
    const repo = path.join(base, "repo");
    fs.mkdirSync(path.join(repo, "below"), { recursive: true });
    // `folders: ['.']`, the commonest layout, and a folder the file chose below its own.
    const workspaceFile = path.join(repo, "self.code-workspace");
    const out = path.join(base, "x.toml");
    for (const [folder, setting] of [
      [repo, `..${path.sep}x.toml`],
      [path.join(repo, "below"), `..${path.sep}..${path.sep}x.toml`],
    ] as const) {
      assert.deepStrictEqual(securityConfigTarget(folder, setting, inWindow(user, workspaceFile), real), { ok: true, path: out }, `${folder} ${setting}`);
    }
  });

  (process.platform === "win32" ? test : test.skip)("the name checks still run first, with no file-system call", () => {
    const none: LinkFs = {
      lstat: () => {
        throw new Error("lstat called");
      },
      realpath: () => {
        throw new Error("realpath called");
      },
    };
    const workspaceFile = path.join(base, "elsewhere", "p.code-workspace");
    for (const [setting, said] of [
      ["nul", "device name"],
      ["cfg:x", "colon"],
      ["cfg.", "dot or a space"],
    ]) {
      const got = securityConfigTarget(path.join(base, "chosen"), setting, inWindow(workspaceScope, workspaceFile), none);
      assert.ok(!got.ok && got.problem.includes(said), `${setting} ${JSON.stringify(got)}`);
    }
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
