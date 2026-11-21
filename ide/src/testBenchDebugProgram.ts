// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The program the Test Bench's Debug launch hands debugpy, and the write that puts it on disk
// (BACKLOG #5409 item 2). vscode-free, so the write is unit-tested node-side; testBench.ts passes in
// the extension's global storage URI.
import * as fs from "node:fs";
import * as path from "node:path";

/**
 * The program the Test Bench's Debug launch hands debugpy in place of `module: "messagefoundry"`:
 * its folder below the extension's global storage, and its source. `-P` alone does not hold for a
 * module: a debugpy older than 1.8.22, which includes the 1.8.21 the Python Debugger extension
 * bundles at the time of writing, inserts the working directory, the workspace, into `sys.path`
 * when it runs a module, whatever `-P` says. For a program it adds at most the program's own
 * folder. That folder holds what {@link writeDebugProgram} puts there: one program per program
 * text, each named `mefor_testbench_debug_<checksum>.py`, so extension versions with different
 * texts share a file only if their checksums collide (see textChecksum). It also holds `.tmp-`
 * folders, one per write, which a failed removal or a killed extension host can leave behind and
 * no import statement can name. Nothing is ever pruned there, and nothing checks what else is
 * there. It also holds whatever another process running as the same OS user puts there, such as a
 * stdlib-named module. Under a debugpy before 1.8.22, which puts the folder on `sys.path`, such a
 * module shadows a module of that name that the debuggee has not yet imported. This code does not
 * defend against a writer running as the same OS user: that writer can already change the
 * extension, the interpreter and the workspace. Neither docs/SECURITY.md nor .github/SECURITY.md
 * states this for the extension. None of the names
 * writeDebugProgram writes is one the launch imports. The program runs the installed
 * package through `runpy`, so no debugpy build puts the working directory on the import path. The
 * source is written at launch rather than shipped, because the extension package holds no Python
 * (the crypto inventory's ide/ arm reads only TypeScript).
 *
 * Open limit: `-P` does not remove a PYTHONPATH entry, and the Python Debugger extension loads an
 * env file into the debuggee, the workspace's `.env` by default. At least a PYTHONPATH that env file
 * sets, whichever file `python.envFile` names, or one the window inherits, can still put a workspace
 * folder on the import path for this launch.
 */
export const TEST_BENCH_DEBUG_PROGRAM = {
  folder: "testbench-debug",
  source: [
    "# Written by the MessageFoundry extension for the Test Bench Debug launch (BACKLOG #5409 item 2).",
    "import runpy",
    "",
    'runpy.run_module("messagefoundry", run_name="__main__", alter_sys=True)',
    "",
  ].join("\n"),
} as const;

/**
 * The storage URI schemes whose `fsPath` is a path on this machine that the debuggee's interpreter
 * can open. A local desktop window hands the extension host a global storage URI with the
 * `vscode-userdata` scheme, not `file`: the workbench's `userRoamingDataHome` is the settings folder
 * with that scheme, the profiles are revived under it, and the local extension host's
 * `globalStorageHome` is the default profile's (read from VS Code 1.142.0's
 * `workbench.desktop.main.js`; in VS Code's source, `src/vs/platform/environment/common/
 * environmentService.ts` and `src/vs/workbench/services/extensions/electron-browser/
 * localProcessExtensionHost.ts`). Any other scheme, such as `vscode-remote`, names no local path.
 */
export const LOCAL_STORAGE_SCHEMES: readonly string[] = ["file", "vscode-userdata"];

/** A 32-bit FNV-1a checksum of `text`'s UTF-16 code units, as 8 hex digits. It names a file by its
 *  text, so two texts share a name only on a checksum collision. Then the content check in
 *  {@link writeDebugProgram} rewrites the file at each launch, and two windows launching at once can
 *  still run each other's text; at 32 bits that is not expected to happen. It is no security
 *  control, which is why it is not node:crypto's createHash: that would be a crypto-inventory entry
 *  with no crypto purpose. */
function textChecksum(text: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h = Math.imul(h ^ text.charCodeAt(i), 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** The program's file name, named by its text (see textChecksum). */
export function debugProgramFileName(source: string): string {
  return `mefor_testbench_debug_${textChecksum(source)}.py`;
}

/** How many times a rename that fails with EBUSY or EPERM is tried again. */
const RENAME_RETRIES = 3;

/** The part of a `vscode.Uri` {@link writeDebugProgram} reads. */
export interface LocalStorageUri {
  readonly scheme: string;
  with(change: { scheme: string }): { readonly fsPath: string };
}

/** The fs calls {@link writeDebugProgram} makes, so a test can make one of them fail. */
export type DebugProgramFs = Pick<typeof fs.promises, "readFile" | "mkdir" | "mkdtemp" | "writeFile" | "rename" | "rm">;

/** Whether `file` holds exactly `bytes`. A missing file is false; any other read error throws. */
async function holds(fsp: DebugProgramFs, file: string, bytes: Buffer): Promise<boolean> {
  try {
    return (await fsp.readFile(file)).equals(bytes);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw e;
  }
}

/**
 * Puts `source` in its own folder under the extension's global storage and returns its path, which
 * the debuggee's interpreter opens, so the storage must have one of {@link LOCAL_STORAGE_SCHEMES}. A
 * file that already holds the source is left alone. Otherwise the source is written into a folder
 * `mkdtemp` makes, so two launches in one millisecond never share a temporary file, and renamed over
 * the program with Node's rename, which replaces the target in one step, so a launch from another
 * window never runs a half-written file. A failed rename is success when the program already holds
 * the source. On Windows a rename can fail with EPERM or EBUSY while another process, such as a
 * scanner, the indexer or a concurrent launch's rename, holds the target or the new temporary file,
 * so that failure is retried {@link RENAME_RETRIES} times 100 ms apart, as collectionCaseFiles.ts
 * retries an unlink. The temporary folder is removed; failing to remove it is logged, never a failed
 * launch.
 *
 * The path is read from `storage.with({ scheme: "file" }).fsPath`, not `storage.fsPath`: VS Code
 * keeps a URI's authority in `fsPath` only for the `file` scheme, so a `vscode-userdata` URI on a
 * UNC share would otherwise lose its server and name a folder on the current drive.
 */
export async function writeDebugProgram(
  storage: LocalStorageUri,
  source: string = TEST_BENCH_DEBUG_PROGRAM.source,
  fsp: DebugProgramFs = fs.promises,
): Promise<string> {
  if (!LOCAL_STORAGE_SCHEMES.includes(storage.scheme)) {
    throw new Error(`the extension's storage folder (scheme "${storage.scheme}") is not on this machine's file system`);
  }
  const dir = path.join(storage.with({ scheme: "file" }).fsPath, TEST_BENCH_DEBUG_PROGRAM.folder);
  const file = path.join(dir, debugProgramFileName(source));
  const bytes = Buffer.from(source, "utf8");
  // A file that cannot be read now, as while a scanner holds it, is written again rather than
  // refusing the launch; the write reports its own error if that fails too.
  if (await holds(fsp, file, bytes).catch(() => false)) {
    return file;
  }
  await fsp.mkdir(dir, { recursive: true });
  const tempDir = await fsp.mkdtemp(path.join(dir, ".tmp-"));
  try {
    const temp = path.join(tempDir, "program.py");
    await fsp.writeFile(temp, bytes, { flag: "wx" });
    for (let attempt = 0; ; attempt++) {
      try {
        await fsp.rename(temp, file);
        break;
      } catch (e) {
        if (await holds(fsp, file, bytes).catch(() => false)) {
          break;
        }
        const code = (e as NodeJS.ErrnoException).code;
        if (attempt >= RENAME_RETRIES || (code !== "EBUSY" && code !== "EPERM")) {
          throw e;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
  } finally {
    try {
      await fsp.rm(tempDir, { recursive: true, force: true });
    } catch (e) {
      console.warn(`MessageFoundry: could not remove the temporary folder ${tempDir}: ${String(e)}`);
    }
  }
  return file;
}
