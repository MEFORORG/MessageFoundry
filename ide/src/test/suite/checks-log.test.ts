// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Every line on the "MessageFoundry Checks" channel carries a UTC time stamp, and the one path that
// commits past a failed required check leaves a stamped record that says so (vault BACKLOG #2349,
// #2353).
//
// Two halves. The first drives the pure stamper with a fixed clock. The second drives the real
// "Set Up Version Control & Checks" command against a stubbed `vscode` and a stubbed `execFile`, down
// the "Commit baseline anyway" path, and reads what reached the channel and in what order.
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { baselineBypassRecord, writeStamped } from "../../checksLog";

// 03:04:05.678 UTC. Built from UTC parts, so the expected text does not depend on the host's zone.
const FIXED = new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 678));
const STAMP = "2026-01-02T03:04:05.678Z";
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z( |$)/;

function collect(text: string, clock?: () => Date): string[] {
  const blocks: string[] = [];
  writeStamped({ appendLine: (block) => blocks.push(block) }, text, clock);
  // One block goes to the channel in one write. Split it the way the channel shows it.
  assert.strictEqual(blocks.length, 1, "one call to writeStamped is one write to the channel");
  return blocks[0].split("\n");
}

suite("checksLog: UTC stamps on the Checks channel", () => {
  test("a single line is stamped with the clock's instant in UTC", () => {
    assert.deepStrictEqual(collect("--- pre-flight: messagefoundry check ---", () => FIXED), [
      `${STAMP} --- pre-flight: messagefoundry check ---`,
    ]);
  });

  test("every line of a multi-line block carries a stamp, whatever the line ending", () => {
    assert.deepStrictEqual(collect("PASS validate\r\nFAIL dryrun\n  detail\rlast", () => FIXED), [
      `${STAMP} PASS validate`,
      `${STAMP} FAIL dryrun`,
      `${STAMP}   detail`,
      `${STAMP} last`,
    ]);
  });

  test("a blank line inside a block is still stamped, with no trailing space", () => {
    assert.deepStrictEqual(collect("a\n\nb", () => FIXED), [`${STAMP} a`, STAMP, `${STAMP} b`]);
  });

  test("the default clock is the wall clock, and its stamp is UTC with a Z", () => {
    const before = Date.now();
    const lines = collect("x");
    const after = Date.now();
    assert.strictEqual(lines.length, 1);
    assert.match(lines[0], ISO_UTC);
    const at = Date.parse(lines[0].split(" ")[0]);
    assert.ok(at >= before && at <= after, lines[0]);
  });

  test("the bypass record is one line that names the skip, the choice, the flag and the exit code", () => {
    const record = baselineBypassRecord(3);
    for (const word of ["SKIPPED", "user's choice", "Commit baseline anyway", "--no-verify", "code 3"]) {
      assert.ok(record.includes(word), word);
    }
    assert.ok(!/[\r\n]/.test(record), "one line, so one stamp covers it");
  });
});

// ---- The real command, node-side -----------------------------------------------------------------

/** What reached the Checks channel and which processes were launched, in the order it happened. */
type Event = { kind: "write"; text: string } | { kind: "launch"; args: string[] };
let events: Event[];
let stubWorkspace: string | undefined;
/** What the stubbed `messagefoundry check` exits with: 1 is a failed required check. */
let checkCode = 1;

const CHECK_STDOUT = "FAIL dryrun\r\n  synthetic detail line\nPASS validate";

const nothing = (): Promise<undefined> => Promise.resolve(undefined);
const vscodeStub = {
  workspace: {
    get workspaceFolders(): { uri: { fsPath: string } }[] | undefined {
      return stubWorkspace === undefined ? undefined : [{ uri: { fsPath: stubWorkspace } }];
    },
    isTrusted: true,
    getConfiguration: () => ({ get: (_key: string, fallback: unknown): unknown => fallback }),
    fs: {
      stat: (uri: { fsPath: string }): Promise<fs.Stats> => fs.promises.stat(uri.fsPath),
      readFile: (uri: { fsPath: string }): Promise<Buffer> => fs.promises.readFile(uri.fsPath),
      writeFile: (uri: { fsPath: string }, data: Uint8Array): Promise<void> =>
        fs.promises.writeFile(uri.fsPath, data),
      createDirectory: async (uri: { fsPath: string }): Promise<void> => {
        await fs.promises.mkdir(uri.fsPath, { recursive: true });
      },
    },
  },
  window: {
    // The two prompts on the path under test are answered; every other prompt is dismissed.
    showInformationMessage: (message: string): Promise<string | undefined> =>
      Promise.resolve(message.startsWith("Make the first commit") ? "Run checks & commit" : undefined),
    showWarningMessage: (message: string): Promise<string | undefined> =>
      Promise.resolve(
        message.startsWith("A required check hasn't passed") ? "Commit baseline anyway" : undefined,
      ),
    showErrorMessage: nothing,
    showQuickPick: nothing,
    showInputBox: nothing,
    // `appendLine` and `show` only. A write that went around the stamper through `append` or
    // `replace` would throw here, so it cannot pass unseen.
    createOutputChannel: (name: string, options?: unknown) => {
      assert.strictEqual(name, "MessageFoundry Checks");
      assert.strictEqual(options, undefined, "the Checks channel must stay a plain channel");
      return {
        appendLine: (text: string): void => void events.push({ kind: "write", text }),
        show: (): void => {},
      };
    },
  },
  extensions: { getExtension: (): undefined => undefined },
  Uri: {
    file: (p: string): { fsPath: string } => ({ fsPath: p }),
    joinPath: (base: { fsPath: string }, ...parts: string[]): { fsPath: string } => ({
      fsPath: path.join(base.fsPath, ...parts),
    }),
  },
  FileType: { File: 1, Directory: 2 },
};

interface Loader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}
const loader = require("node:module") as Loader;
const realLoad = loader._load;

/** True inside the Extension Host, where the REAL `vscode` API resolves (see engine-trust-shell). */
function insideExtensionHost(): boolean {
  try {
    const api = realLoad.call(loader, "vscode", module, false) as {
      version?: unknown;
      env?: { appName?: unknown };
    };
    return typeof api?.version === "string" && typeof api?.env?.appName === "string";
  } catch {
    return false;
  }
}

const NODE_SIDE = !insideExtensionHost();

type SourceControl = typeof import("../../sourceControl");
type ChildProcess = { execFile: typeof import("node:child_process").execFile };

let sc!: SourceControl;
let childProcess!: ChildProcess;
let realExecFile!: typeof import("node:child_process").execFile;

if (NODE_SIDE) {
  // Loaded fresh against THIS stub, and the cache put back afterwards, for the reason
  // source-control-trust.test.ts gives: another suite's copy is bound to another suite's stub.
  const fresh = ["../../sourceControl", "../../checksChannel", "../../cli", "../../git"].map((m) =>
    require.resolve(m),
  );
  const saved = new Map(fresh.map((f) => [f, require.cache[f]]));
  for (const f of fresh) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    sc = require("../../sourceControl") as SourceControl;
    childProcess = require("node:child_process") as ChildProcess;
  } finally {
    loader._load = realLoad;
    for (const [f, entry] of saved) {
      if (entry) {
        require.cache[f] = entry;
      } else {
        delete require.cache[f];
      }
    }
  }
  realExecFile = childProcess.execFile;
}

const commandSuite = NODE_SIDE ? suite : suite.skip;

commandSuite("Set Up Version Control & Checks: what reaches the Checks channel", () => {
  let ws: string;

  setup(() => {
    ws = fs.mkdtempSync(path.join(os.tmpdir(), "mf-checks-log-"));
    stubWorkspace = ws;
    events = [];
    checkCode = 1;
    // No process runs. git answers as an existing repository with no remote and no hooks path, and
    // `messagefoundry check` answers with `checkCode` and a multi-line block.
    childProcess.execFile = ((
      _file: string,
      args: string[],
      _options: unknown,
      done: (err: Error | null, stdout: string, stderr: string) => void,
    ) => {
      events.push({ kind: "launch", args });
      if (args.includes("check")) {
        const err = checkCode === 0 ? null : Object.assign(new Error("stubbed"), { code: checkCode });
        done(err, CHECK_STDOUT, "");
      } else if (args.includes("--is-inside-work-tree")) {
        done(null, "true\n", "");
      } else if (args[0] === "commit") {
        done(null, "[main (root-commit) 0000000] Initial commit\n", "");
      } else {
        done(null, "", "");
      }
      return undefined;
    }) as unknown as typeof childProcess.execFile;
  });

  teardown(() => {
    childProcess.execFile = realExecFile;
    fs.rmSync(ws, { recursive: true, force: true });
    stubWorkspace = undefined;
  });

  /** Every line the channel shows: a write may hold a block of several. */
  const lines = (): string[] => events.flatMap((e) => (e.kind === "write" ? e.text.split("\n") : []));
  const indexOfLaunch = (flag: string): number =>
    events.findIndex((e) => e.kind === "launch" && e.args.includes(flag));

  test("every line carries a UTC stamp, the lines of the check's own output included", async () => {
    await sc.setupSourceControl({} as never);

    const written = lines();
    // Control: the run reached the channel and wrote the check's block, so the loop below is not
    // passing on an empty list.
    assert.ok(written.some((l) => l.endsWith("  synthetic detail line")), JSON.stringify(written));
    assert.ok(written.some((l) => l.endsWith("Set Up Version Control & Checks:")));
    assert.ok(written.some((l) => l.includes("core.hooksPath:")), JSON.stringify(written));
    for (const line of written) {
      assert.match(line, ISO_UTC, line);
    }
  });

  test("the bypass is recorded, stamped, BEFORE the --no-verify commit runs", async () => {
    await sc.setupSourceControl({} as never);

    // The stubbed check exits 1, and the record carries that code.
    const expected = baselineBypassRecord(1);
    const record = events.findIndex((e) => e.kind === "write" && e.text.endsWith(expected));
    const commit = indexOfLaunch("--no-verify");
    assert.ok(commit >= 0, `the bypass commit did not run: ${JSON.stringify(events)}`);
    assert.ok(record >= 0, "no bypass record reached the channel");
    assert.ok(record < commit, "the record must be written before the commit it describes");
    assert.match(lines().find((l) => l.endsWith(expected)) ?? "", ISO_UTC);
    assert.ok(lines().some((l) => l.endsWith("--- baseline commit (hooks skipped): git exit code 0 ---")));
  });

  test("the setup notes are stamped before the commit they came before", async () => {
    await sc.setupSourceControl({} as never);

    const notes = events.findIndex((e) => e.kind === "write" && e.text.includes("core.hooksPath:"));
    const commit = events.findIndex((e) => e.kind === "launch" && e.args[0] === "commit");
    assert.ok(notes >= 0 && commit >= 0, JSON.stringify(events));
    assert.ok(notes < commit, "the hook install was logged after the commit it preceded");
  });

  test("control: when the check passes, the commit runs the hooks and no bypass is recorded", async () => {
    checkCode = 0;
    await sc.setupSourceControl({} as never);

    assert.ok(events.some((e) => e.kind === "launch" && e.args[0] === "commit"), "no commit ran");
    assert.strictEqual(indexOfLaunch("--no-verify"), -1);
    assert.ok(lines().every((l) => !l.includes("SKIPPED")), JSON.stringify(lines()));
  });
});
