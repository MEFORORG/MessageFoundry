// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 532 remainder (BACKLOG #5404 item 1): on Windows a writer refuses a path setting with a
// folder or file name holding a colon. A Win32 open reads `cfg:x` as an NTFS stream on `cfg`, so with
// `cfg` a junction out of the folder the CLI's write would land on the folder outside, while the
// real-path check can pass the name.
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { securityConfigTarget, type LinkFs } from "../../securityEditorModel";
import {
  escapesByLink,
  hasColonInName,
  linkEscapeRefusal,
  resolveInsideWorkspace,
} from "../../workspaceContainment";

/** Runs `fn` with the synchronous file-system reads workspaceContainment makes replaced by spies that
 *  record the call and throw, and returns what was recorded. */
function fsCalls(fn: () => void): string[] {
  const mod: Record<string, unknown> = require("node:fs");
  const names = ["realpathSync", "lstatSync", "statSync", "existsSync"];
  const originals = names.map((n) => mod[n]);
  const calls: string[] = [];
  for (const n of names) {
    const spy = (p: unknown): never => {
      calls.push(`${n} ${String(p)}`);
      throw Object.assign(new Error(`stubbed ${n}`), { code: "EACCES" });
    };
    mod[n] = Object.assign(spy, { native: spy });
  }
  try {
    fn();
  } finally {
    names.forEach((n, i) => (mod[n] = originals[i]));
  }
  return calls;
}

/** A LinkFs that records every call and refuses it, so an answer reached with none recorded was
 *  reached by spelling alone. */
function recordingFs(calls: string[]): LinkFs {
  return {
    lstat: (p: string) => {
      calls.push(`lstat ${p}`);
      throw Object.assign(new Error("stubbed lstat"), { code: "EACCES" });
    },
    realpath: (p: string) => {
      calls.push(`realpath ${p}`);
      throw Object.assign(new Error("stubbed realpath"), { code: "EACCES" });
    },
  };
}

suite("b532r: a name holding a colon is refused on Windows (BACKLOG #5404 item 1)", () => {
  // Measured in review, 2026-11-19, on Windows 11 with Node 24: Python 3.14.7's open, the CLI's opener, of `ws\cfg:x` with
  // `cfg` a junction wrote the stream `outside:x`. Node 24's own open of that path fails with ENOENT,
  // so the write is not reproduced here; the control below is the half Node can show.
  test("on Windows, the real-path check passes `cfg:x` through a junction, and the writer check refuses it", function () {
    if (process.platform !== "win32") {
      this.skip(); // the control needs a Win32 open and NTFS streams; the refusal is driven below
    }
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "b532r-ide-colon-"));
    try {
      const ws = path.join(base, "ws");
      const outside = path.join(base, "outside");
      fs.mkdirSync(ws);
      fs.mkdirSync(outside);
      try {
        fs.symlinkSync(outside, path.join(ws, "cfg"), "junction");
      } catch {
        this.skip(); // no junction can be made here
      }
      // THE CONTROL: the real-path check alone passes the name.
      assert.notStrictEqual(resolveInsideWorkspace(ws, "cfg:x"), undefined);
      assert.strictEqual(escapesByLink(ws, "cfg:x"), true);
      assert.notStrictEqual(resolveInsideWorkspace(ws, "cfg:x/new.toml"), undefined);
      assert.strictEqual(escapesByLink(ws, "cfg:x/new.toml"), true);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  test("escapesByLink refuses a colon in any name before any file-system call, on Windows only", () => {
    const ws = path.resolve(path.sep, "b532r-ide-no-such-ws");
    for (const v of ["cfg:x", "cfg::$DATA", "sub/cfg:x", "sub\\cfg:x\\new.toml", "messagefoundry.toml:s", ":x"]) {
      let answer: boolean | undefined;
      const calls = fsCalls(() => (answer = escapesByLink(ws, v, true)));
      assert.strictEqual(answer, true, JSON.stringify(v));
      assert.deepStrictEqual(calls, [], `${JSON.stringify(v)} touched the file system`);
    }
    // THE CONTROL: off Windows a colon is part of a name, so the check goes on to the real-path read,
    // which the spies refuse.
    let posix: boolean | undefined;
    const calls = fsCalls(() => (posix = escapesByLink(ws, "cfg:x", false)));
    assert.strictEqual(posix, true);
    assert.notDeepStrictEqual(calls, []);
  });

  test("a colon in the drive of an absolute value inside the folder is not a name", function () {
    if (process.platform !== "win32") {
      this.skip(); // no drive letter to spell off Windows
    }
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "b532r-ide-colon-"));
    try {
      assert.strictEqual(escapesByLink(base, path.join(base, "messagefoundry.toml")), false);
      // THE CONTROL: the same absolute spelling with a colon in a name is refused.
      assert.strictEqual(escapesByLink(base, path.join(base, "messagefoundry.toml:s")), true);
      // A one-letter name holding a colon, spelled so Node keeps it inside the folder, is refused too.
      assert.strictEqual(escapesByLink(base, ".\\x:y"), true);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  test("hasColonInName reads every component, on Windows only", () => {
    assert.strictEqual(hasColonInName("a:b", true), true);
    assert.strictEqual(hasColonInName("a\\b:c", true), true);
    assert.strictEqual(hasColonInName("a/b/c:", true), true);
    assert.strictEqual(hasColonInName("a/b/c.toml", true), false);
    assert.strictEqual(hasColonInName(".", true), false);
    assert.strictEqual(hasColonInName("a:b", false), false);
    // A leading `x:` in a relative path is a one-letter name holding a colon, not a drive.
    assert.strictEqual(hasColonInName("x:y", true), true);
  });

  test("securityConfigTarget refuses a colon in a name inside the folder before any file-system call", function () {
    if (process.platform !== "win32") {
      this.skip(); // the editor reads the platform; the shared helper is driven above
    }
    const ws = path.resolve(path.sep, "b532r-ide-no-such-ws");
    for (const fromWorkspace of [true, false]) {
      for (const v of ["cfg:x", "sub\\messagefoundry.toml:s"]) {
        const calls: string[] = [];
        const t = securityConfigTarget(ws, v, { fromWorkspace, trusted: true }, recordingFs(calls));
        assert.strictEqual(t.ok, false, JSON.stringify(v));
        assert.ok(!t.ok && t.problem.includes("holds a colon"), JSON.stringify(t));
        assert.deepStrictEqual(calls, [], `${JSON.stringify(v)} touched the file system`);
      }
    }
    // THE CONTROL: a plain name goes on to the link walk, which the recording fs refuses.
    const calls: string[] = [];
    const t = securityConfigTarget(ws, "messagefoundry.toml", { fromWorkspace: true, trusted: true }, recordingFs(calls));
    assert.strictEqual(t.ok, false);
    assert.notDeepStrictEqual(calls, []);
  });

  test("the refusal names the colon, and says a workspace value must go before a user path applies", () => {
    const text = linkEscapeRefusal("configDir");
    assert.ok(text.includes("holds a colon"), text);
    const absolute = text.indexOf("absolute path in user settings");
    const workspace = text.indexOf("once any value for the setting in workspace settings is removed");
    assert.ok(absolute > 0 && workspace > absolute, text);
  });
});
