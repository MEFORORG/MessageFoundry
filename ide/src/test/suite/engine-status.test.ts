import * as assert from "assert";

import {
  classifyProbe,
  formatEngineStatus,
  hostLabel,
  resolveEngineStatusTarget,
} from "../../engineStatusModel";

// Pure engine status-bar logic (#221c) — exercised vscode-free (no Extension Host): the target
// resolver folds (engineUrl, environments) into the probed instance; classifyProbe maps a probe
// outcome to reachability; formatEngineStatus renders the item text/tooltip.
suite("engineStatusModel — target resolution", () => {
  test("no environments → the engineUrl, labelled host:port", () => {
    const t = resolveEngineStatusTarget("http://127.0.0.1:8765", []);
    assert.strictEqual(t.name, "127.0.0.1:8765");
    assert.strictEqual(t.url, "http://127.0.0.1:8765");
    assert.deepStrictEqual(t.all, [{ name: "engine", url: "http://127.0.0.1:8765" }]);
  });

  test("one environment → that environment", () => {
    const t = resolveEngineStatusTarget("http://127.0.0.1:8765", [
      { name: "DEV", url: "https://dev:8765" },
    ]);
    assert.strictEqual(t.name, "DEV");
    assert.strictEqual(t.url, "https://dev:8765");
  });

  test("several environments → first is primary, name carries a (+N) suffix", () => {
    const t = resolveEngineStatusTarget("http://127.0.0.1:8765", [
      { name: "DEV", url: "https://dev:8765" },
      { name: "PROD", url: "https://prod:8765" },
      { name: "STAGE", url: "https://stage:8765" },
    ]);
    assert.strictEqual(t.name, "DEV (+2)");
    assert.strictEqual(t.url, "https://dev:8765");
    assert.strictEqual(t.all.length, 3);
  });

  test("malformed environment entries are dropped", () => {
    const envs = [
      { name: "DEV", url: "https://dev:8765" },
      { name: 123 } as unknown,
      null as unknown,
    ] as { name: string; url: string }[];
    const t = resolveEngineStatusTarget("http://127.0.0.1:8765", envs);
    assert.strictEqual(t.name, "DEV");
  });

  test("hostLabel falls back to the raw string for an unparseable URL", () => {
    assert.strictEqual(hostLabel("::not a url::"), "::not a url::");
    assert.strictEqual(hostLabel("https://host"), "host");
  });
});

suite("engineStatusModel — probe classification", () => {
  test("2xx is reachable", () => {
    assert.strictEqual(classifyProbe({ kind: "ok" }), "reachable");
  });

  test("a non-2xx HTTP answer is still reachable (the engine responded)", () => {
    assert.strictEqual(classifyProbe({ kind: "httpError", status: 401 }), "reachable");
    assert.strictEqual(classifyProbe({ kind: "httpError", status: 404 }), "reachable");
  });

  test("a transport failure is unreachable", () => {
    assert.strictEqual(classifyProbe({ kind: "networkError" }), "unreachable");
  });
});

suite("engineStatusModel — rendering", () => {
  const target = resolveEngineStatusTarget("http://127.0.0.1:8765", []);

  test("reachable → filled icon, tooltip names the URL", () => {
    const s = formatEngineStatus(target, "reachable");
    assert.ok(s.text.startsWith("$(pass-filled)"));
    assert.ok(s.text.includes("MEFOR: 127.0.0.1:8765"));
    assert.ok(s.tooltip.includes("reachable"));
    assert.ok(s.tooltip.includes("http://127.0.0.1:8765"));
  });

  test("unreachable → disconnect icon + a start hint", () => {
    const s = formatEngineStatus(target, "unreachable");
    assert.ok(s.text.startsWith("$(debug-disconnect)"));
    assert.ok(s.tooltip.includes("not reachable"));
  });

  test("unknown → hollow icon + checking", () => {
    const s = formatEngineStatus(target, "unknown");
    assert.ok(s.text.startsWith("$(circle-outline)"));
    assert.ok(s.tooltip.includes("checking"));
  });

  test("multi-environment tooltip lists every configured target", () => {
    const multi = resolveEngineStatusTarget("http://127.0.0.1:8765", [
      { name: "DEV", url: "https://dev:8765" },
      { name: "PROD", url: "https://prod:8765" },
    ]);
    const s = formatEngineStatus(multi, "reachable");
    assert.ok(s.tooltip.includes("DEV"));
    assert.ok(s.tooltip.includes("PROD"));
    assert.ok(s.tooltip.includes("https://prod:8765"));
  });
});
