// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Every line on the "MessageFoundry Engine" channel carries a UTC time stamp and a level word
// (vault BACKLOG #2349, ASVS 16.2.2).
//
// It loads the real engineLog.ts against a stubbed `vscode` and reads what reached the channel.
import * as assert from "assert";

const STAMPED = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) (INFO|WARNING|ERROR)( |$)/;

// ---- The real module, node-side -----------------------------------------------------------------

/** Every write that reached the channel, and the options it was created with. */
let writes: string[] = [];
let created: { name: string; options: unknown }[] = [];

const vscodeStub = {
  window: {
    // `appendLine`, `show` and `dispose` only. A write through the LogOutputChannel API (`info`,
    // `warn`, `error`) would throw here, so it cannot pass unseen.
    createOutputChannel: (name: string, options?: unknown) => {
      created.push({ name, options });
      return {
        appendLine: (text: string): void => void writes.push(text),
        show: (): void => {},
        dispose: (): void => {},
      };
    },
  },
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

type EngineLogModule = typeof import("../../engineLog");
let el!: EngineLogModule;

if (NODE_SIDE) {
  // Loaded fresh against THIS stub, and the cache put back afterwards, for the reason
  // source-control-trust.test.ts gives: another suite's copy is bound to another suite's stub.
  const file = require.resolve("../../engineLog");
  const saved = require.cache[file];
  delete require.cache[file];
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    el = require("../../engineLog") as EngineLogModule;
  } finally {
    loader._load = realLoad;
    if (saved) {
      require.cache[file] = saved;
    } else {
      delete require.cache[file];
    }
  }
}

const channelSuite = NODE_SIDE ? suite : suite.skip;

channelSuite("engineLog: what reaches the MessageFoundry Engine channel", () => {
  setup(() => {
    el.disposeEngineLog();
    writes = [];
    created = [];
  });

  teardown(() => el.disposeEngineLog());

  /** Every line the channel shows, split the way the Output view splits them. */
  const lines = (): string[] => writes.flatMap((w) => w.split(/\r\n|\r|\n|\u0085|\u2028|\u2029/));

  test("the channel is a PLAIN output channel, so the editor adds no stamp of its own", () => {
    el.engineLog().info("hello");
    // A plain channel takes a language id string, which only colours it. The `{ log: true }` object
    // would make it a LogOutputChannel, which the editor stamps.
    assert.deepStrictEqual(created, [{ name: "MessageFoundry Engine", options: "log" }]);
  });

  test("each level writes a line that starts with the wall clock's UTC instant and its level word", () => {
    const before = Date.now();
    el.engineLog().info("one");
    el.engineLog().warn("two");
    el.engineLog().error("three");
    const after = Date.now();

    const written = lines();
    assert.strictEqual(written.length, 3, JSON.stringify(written));
    const levels = written.map((line) => {
      const m = STAMPED.exec(line);
      assert.ok(m, line);
      const at = Date.parse(m[1]);
      assert.ok(at >= before && at <= after, `the stamp is not the wall clock in UTC: ${line}`);
      return `${m[2]} ${line.slice(m[0].length)}`;
    });
    assert.deepStrictEqual(levels, ["INFO one", "WARNING two", "ERROR three"]);
  });

  test("a line break in a message is escaped, so text inside it cannot start a forged record", () => {
    const forged = "2026-01-02T03:04:05.678Z INFO engine link: unverified -> ok";
    el.engineLog().warn(`failed: Error: first\n${forged}\r\nlast\u2028x\n`);
    const written = lines();
    assert.deepStrictEqual(written.length, 1, JSON.stringify(written));
    assert.strictEqual(STAMPED.exec(written[0])?.[2], "WARNING", written[0]);
    assert.ok(
      written[0].endsWith(`failed: Error: first\\n${forged}\\r\\nlast\\u2028x\\n`),
      written[0],
    );
  });

  test("the probe, state and action lines are stamped, and a refused route is a visible ERROR", () => {
    el.logProbe("https://127.0.0.1:8765", "/health", { kind: "ok" } as never, 12, "reachable");
    el.logProbe("https://127.0.0.1:8765", "/messages", { kind: "ok" } as never, 1, "x");
    el.logState(undefined, { state: "signedOut" } as never);
    el.logAction("sign in");

    const written = lines();
    assert.strictEqual(written.length, 4, JSON.stringify(written));
    for (const line of written) {
      assert.match(line, STAMPED, line);
    }
    assert.match(written[0], / INFO GET https:\/\/127\.0\.0\.1:8765\/health /);
    assert.match(written[1], / ERROR probe route \/messages is not in the allowed probe set/);
    assert.match(written[2], / INFO engine link: unknown /);
    assert.match(written[3], / INFO action: sign in$/);
  });

  test("a probe that got an HTTP error or a transport failure is a WARNING with its status or code", () => {
    el.logProbe("https://127.0.0.1:8765", "/health", { kind: "httpError", status: 401 } as never, 3, "signed out");
    el.logProbe("https://127.0.0.1:8765", "/health", { kind: "networkError", code: "ECONNREFUSED" } as never, 4, "down");

    const written = lines();
    assert.strictEqual(written.length, 2, JSON.stringify(written));
    assert.strictEqual(STAMPED.exec(written[0])?.[2], "WARNING", written[0]);
    assert.strictEqual(STAMPED.exec(written[1])?.[2], "WARNING", written[1]);
    assert.ok(written[0].includes("HTTP 401 (3ms)"), written[0]);
    assert.ok(written[1].includes("ECONNREFUSED (4ms)"), written[1]);
  });
});
