// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Every line on the "MessageFoundry Engine" channel carries a UTC time stamp and a level word
// (vault BACKLOG #2349, ASVS 16.2.2).
//
// Two halves. The first drives the stamper's label with a fixed clock. The second loads the real
// engineLog.ts against a stubbed `vscode` and reads what reached the channel.
import * as assert from "assert";

import { writeStamped } from "../../checksLog";

// 03:04:05.678 UTC. Built from UTC parts, so the expected text does not depend on the host's zone.
const FIXED = new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 678));
const STAMP = "2026-01-02T03:04:05.678Z";
const STAMPED = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) (INFO|WARN|ERROR)( |$)/;

suite("engineLog: the stamper's level label", () => {
  test("the label follows the stamp on every line, and a blank line gets no trailing space", () => {
    const blocks: string[] = [];
    writeStamped({ appendLine: (b) => blocks.push(b) }, "first\r\n\nthird", () => FIXED, "WARN");
    assert.deepStrictEqual(blocks, [`${STAMP} WARN first\n${STAMP} WARN\n${STAMP} WARN third`]);
  });

  test("control: with no label the line is the stamp and the text, as on the Checks channel", () => {
    const blocks: string[] = [];
    writeStamped({ appendLine: (b) => blocks.push(b) }, "x", () => FIXED);
    assert.deepStrictEqual(blocks, [`${STAMP} x`]);
  });
});

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
  const fresh = ["../../engineLog"].map((m) => require.resolve(m));
  const saved = new Map(fresh.map((f) => [f, require.cache[f]]));
  for (const f of fresh) {
    delete require.cache[f];
  }
  loader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    return request === "vscode" ? vscodeStub : realLoad.call(this, request, parent, isMain);
  };
  try {
    el = require("../../engineLog") as EngineLogModule;
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
}

const channelSuite = NODE_SIDE ? suite : suite.skip;

channelSuite("engineLog: what reaches the MessageFoundry Engine channel", () => {
  setup(() => {
    el.disposeEngineLog();
    writes = [];
    created = [];
  });

  teardown(() => el.disposeEngineLog());

  /** Every line the channel shows: a write may hold a block of several. */
  const lines = (): string[] => writes.flatMap((w) => w.split("\n"));

  test("the channel is a PLAIN output channel, so the editor adds no stamp of its own", () => {
    el.engineLog().info("hello");
    assert.deepStrictEqual(created, [{ name: "MessageFoundry Engine", options: undefined }]);
  });

  test("each level writes a line that starts with a UTC instant and its level word", () => {
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
    assert.deepStrictEqual(levels, ["INFO one", "WARN two", "ERROR three"]);
  });

  test("every line of a multi-line message carries the stamp and the level", () => {
    el.engineLog().warn("failed: Error: first\n    at second");
    const written = lines();
    assert.strictEqual(written.length, 2, JSON.stringify(written));
    for (const line of written) {
      assert.match(line, STAMPED, line);
      assert.ok(line.includes(" WARN "), line);
    }
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
});
