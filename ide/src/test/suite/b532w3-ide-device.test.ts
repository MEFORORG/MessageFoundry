// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 532 wave 3 (BACKLOG #5404 item 3): on Windows a writer refuses a path setting with a folder
// or file name that is a reserved DOS device name. A Win32 open of `nul` or `com1` reaches the
// device, not a file in the workspace folder, while Node's real-path read finds no entry by that
// name and the real-path check can pass it.
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { securityConfigTarget, type LinkFs } from "../../securityEditorModel";
import { escapesByLink, linkEscapeRefusal } from "../../workspaceContainment";

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

/** Device names the check must refuse: bare, in any case, with an extension, with spaces before
 *  the extension, as a folder, with either separator, and the superscript COM and LPT digits. */
const DEVICE_SPELLINGS = [
  "nul",
  "NUL",
  "con",
  "Prn",
  "aux",
  "COM1",
  "com9",
  "com0",
  "LPT0.toml",
  "lpt1",
  "LPT9",
  "CONIN$",
  "conout$",
  "com\u00b9",
  "LPT\u00b3",
  "nul.txt",
  "con.toml",
  "Com1.x.y",
  "con .toml",
  "aux  .py",
  "nul/messagefoundry.toml",
  "sub\\CON\\new.toml",
  "sub/lpt2.d/x.toml",
];

/** Names that are not device names, though some start like one. */
const PLAIN_SPELLINGS = [
  "messagefoundry.toml",
  "config",
  "console",
  "connections.toml",
  "nul_",
  "nully.toml",
  "com10",
  "lpt",
  "auxiliary/x.toml",
  "prnt.toml",
  ".con",
  "a.nul",
  "sub/x.com1",
];

suite("b532w3: a reserved device name is refused on Windows (BACKLOG #5404 item 3)", () => {
  test("escapesByLink refuses a device name in any component before any file-system call, on Windows", () => {
    const ws = path.resolve(path.sep, "b532w3-ide-no-such-ws");
    for (const v of DEVICE_SPELLINGS) {
      let answer: boolean | undefined;
      const calls = fsCalls(() => (answer = escapesByLink(ws, v, true)));
      assert.strictEqual(answer, true, JSON.stringify(v));
      assert.deepStrictEqual(calls, [], `${JSON.stringify(v)} touched the file system`);
    }
  });

  test("THE CONTROL: a plain name goes on to the real-path read, on Windows and off it", () => {
    const ws = path.resolve(path.sep, "b532w3-ide-no-such-ws");
    for (const v of PLAIN_SPELLINGS) {
      const calls = fsCalls(() => escapesByLink(ws, v, true));
      assert.notDeepStrictEqual(calls, [], `${JSON.stringify(v)} was refused by spelling`);
    }
    // Off Windows a device name is an ordinary file name, so the check goes on to the real-path read.
    for (const v of ["nul", "con.toml", "COM1"]) {
      const calls = fsCalls(() => escapesByLink(ws, v, false));
      assert.notDeepStrictEqual(calls, [], `${JSON.stringify(v)} was refused by spelling off Windows`);
    }
  });

  test("on a real folder, a device name is refused and a plain file beside it is not", function () {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "b532w3-ide-device-"));
    try {
      fs.writeFileSync(path.join(base, "messagefoundry.toml"), "");
      fs.mkdirSync(path.join(base, "config"));
      // THE CONTROL: plain names inside a real folder pass.
      assert.strictEqual(escapesByLink(base, "messagefoundry.toml"), false);
      assert.strictEqual(escapesByLink(base, "config"), false);
      assert.strictEqual(escapesByLink(base, "config/new.toml"), false);
      if (process.platform !== "win32") {
        this.skip(); // the refusal is a Windows rule; the spelling half is driven above
      }
      for (const v of ["nul", "con", "COM1", "CONIN$", "nul.toml", "config/aux.toml"]) {
        assert.strictEqual(escapesByLink(base, v), true, JSON.stringify(v));
      }
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  test("securityConfigTarget refuses a device name inside the folder before any file-system call", function () {
    if (process.platform !== "win32") {
      this.skip(); // the editor reads the platform; the shared helper is driven above
    }
    const ws = path.resolve(path.sep, "b532w3-ide-no-such-ws");
    for (const fromWorkspace of [true, false]) {
      for (const v of ["nul", "CON.toml", "sub\\com1\\messagefoundry.toml", "conin$"]) {
        const calls: string[] = [];
        const t = securityConfigTarget(ws, v, { fromWorkspace, trusted: true }, recordingFs(calls));
        assert.strictEqual(t.ok, false, JSON.stringify(v));
        assert.ok(!t.ok && t.problem.includes("device name"), JSON.stringify(t));
        assert.deepStrictEqual(calls, [], `${JSON.stringify(v)} touched the file system`);
      }
    }
    // THE CONTROL: a plain name goes on to the link walk, which the recording fs refuses.
    const calls: string[] = [];
    const t = securityConfigTarget(ws, "console.toml", { fromWorkspace: true, trusted: true }, recordingFs(calls));
    assert.strictEqual(t.ok, false);
    assert.notDeepStrictEqual(calls, []);
  });

  test("the refusal names a device name, and keeps the remedy that renames it", () => {
    const text = linkEscapeRefusal("configDir");
    assert.ok(text.includes("is a Windows device name such as nul or com1"), text);
    assert.ok(text.includes("rename the folder or file"), text);
  });
});
