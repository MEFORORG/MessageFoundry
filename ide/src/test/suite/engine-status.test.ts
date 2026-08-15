// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";

import {
  ago,
  classifyHealth,
  formatEngineStatus,
  hostLabel,
  resolveEngineStatusTarget,
  withStaleness,
  VERIFY_TTL_MS,
  type EngineLink,
} from "../../engineStatusModel";

// Pure engine status-bar logic — exercised vscode-free (no Extension Host): the target resolver folds
// (engineUrl, environments) into the probed instance; classifyHealth maps a TOKENLESS probe outcome to a
// link state; formatEngineStatus renders the item text / hover / background.
//
// The suite below is written against ONE rule, and most of it exists to stop that rule regressing:
//   a green check means "the IDE can USE this engine", NOT "a socket answered".
// The previous model folded every HTTP answer — including a 401 — into "reachable" and painted it green,
// which is why the status bar sat on a confident green check against an engine the IDE had no session
// with. See engine-doctor.test.ts for the deep probe that is allowed to earn the green.

const T = resolveEngineStatusTarget("http://127.0.0.1:8765", []);
const NOW = 1_000_000;

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
    assert.strictEqual(resolveEngineStatusTarget("http://127.0.0.1:8765", envs).name, "DEV");
  });

  test("hostLabel falls back to the raw string for an unparseable URL", () => {
    assert.strictEqual(hostLabel("::not a url::"), "::not a url::");
    assert.strictEqual(hostLabel("https://host"), "host");
  });
});

suite("engineStatusModel — the tokenless /health probe cannot lie", () => {
  test("version: null ⇒ signedOut — the engine is up and the IDE is anonymous", () => {
    // THE BUG THIS WHOLE CHANGE EXISTS FOR. /health is tokenless but discloses `version` ONLY to an
    // authenticated caller (api/app.py, WP-L3-07), so a null version is DECISIVE: auth is on and we have
    // no session. The old model called this "reachable" and painted it green.
    const link = classifyHealth({ kind: "ok", body: { status: "ok", version: null } }, T, NOW, false);
    assert.strictEqual(link.state, "signedOut");
    assert.strictEqual(link.version, undefined);
    assert.ok(/not signed in/i.test(link.reason ?? ""));
  });

  test("version present ⇒ unverified — NOT ok, and NOT green", () => {
    // The other half of the same bug. `optional_identity` applies no RBAC and no must-change gate, so a
    // version merely proves that *a* session exists — a bootstrap admin locked out of every route still
    // gets one back. Only a protected route can earn `ok` (see classifyDeep).
    const link = classifyHealth({ kind: "ok", body: { status: "ok", version: "0.3.0" } }, T, NOW, false);
    assert.strictEqual(link.state, "unverified");
    assert.strictEqual(link.version, "0.3.0");
    assert.notStrictEqual(link.state, "ok");
    // The rendered item must not claim success either.
    assert.ok(!formatEngineStatus(link, NOW).text.startsWith("$(pass-filled)"));
  });

  test("a 200 whose body is not ours ⇒ foreign, not healthy", () => {
    const link = classifyHealth({ kind: "ok", body: { hello: "world" } }, T, NOW, false);
    assert.strictEqual(link.state, "foreign");
    assert.ok(/not a MessageFoundry engine/i.test(link.reason ?? ""));
  });

  test("a non-2xx from the tokenless /health ⇒ foreign (a real engine always answers it)", () => {
    const link = classifyHealth({ kind: "httpError", status: 401, detail: "x" }, T, NOW, false);
    assert.strictEqual(link.state, "foreign");
  });

  test("a transport failure ⇒ unreachable, named by its errno", () => {
    const refused = classifyHealth({ kind: "networkError", code: "ECONNREFUSED" }, T, NOW, false);
    assert.strictEqual(refused.state, "unreachable");
    assert.strictEqual(refused.code, "ECONNREFUSED");
    assert.ok(/nothing is listening/i.test(refused.reason ?? ""));

    const hung = classifyHealth({ kind: "networkError", code: "MF_TIMEOUT" }, T, NOW, false);
    assert.strictEqual(hung.state, "unreachable");
    assert.ok(/hung/i.test(hung.reason ?? ""));

    const dns = classifyHealth({ kind: "networkError", code: "ENOTFOUND" }, T, NOW, false);
    assert.ok(/does not resolve/i.test(dns.reason ?? ""));

    // Every one of these used to render as the same undifferentiated "not reachable".
    assert.notStrictEqual(refused.reason, hung.reason);
    assert.notStrictEqual(refused.reason, dns.reason);
  });

  test("classifyHealth NEVER returns ok — a green check cannot come from a tokenless probe", () => {
    const outcomes = [
      { kind: "ok" as const, body: { status: "ok", version: "0.3.0" } },
      { kind: "ok" as const, body: { status: "ok", version: null } },
      { kind: "ok" as const, body: {} },
      { kind: "httpError" as const, status: 200, detail: "" },
      { kind: "networkError" as const, code: "ECONNREFUSED" },
    ];
    for (const o of outcomes) {
      for (const hasSession of [true, false]) {
        assert.notStrictEqual(classifyHealth(o, T, NOW, hasSession).state, "ok");
      }
    }
  });
});

suite("engineStatusModel — a tokenless probe cannot see OUR session (regression)", () => {
  // THE BUG THIS SUITE EXISTS FOR. The poll is tokenless, so on an auth-enabled engine /health returns
  // version:null to it ALWAYS — even when the IDE holds a perfectly good session. Reading that as "signed
  // out" told a signed-in user to sign in, AND destroyed the `ok` verdict the deep probe had just earned,
  // 15 seconds after every sign-in. The green check lived for one poll interval and then lied.
  const body = { status: "ok", version: null };

  test("version: null WITH a session held ⇒ unverified, NOT signedOut", () => {
    const link = classifyHealth({ kind: "ok", body }, T, NOW, true);
    assert.strictEqual(link.state, "unverified");
    assert.notStrictEqual(link.state, "signedOut");
    assert.ok(/cannot confirm/i.test(link.reason ?? ""));
  });

  test("version: null with NO session held ⇒ signedOut (still decisive)", () => {
    assert.strictEqual(classifyHealth({ kind: "ok", body }, T, NOW, false).state, "signedOut");
  });

  test("an earned verdict survives the next tokenless poll, and expires by DECAY not by forgetting", () => {
    // This is the exact sequence that used to break: verify() earns `ok`, then the 15s poll lands.
    const earned: EngineLink = { state: "ok", target: T, checkedAt: NOW, verifiedAt: NOW };
    const polled = classifyHealth({ kind: "ok", body }, T, NOW + 15_000, true);
    assert.strictEqual(polled.state, "unverified", "the poll must not claim signedOut while we hold a token");

    // The shell restores the earned verdict on exactly this condition (statusBar.poll), so assert the
    // condition it keys on actually holds — that guard was previously unreachable.
    assert.ok(polled.state === "unverified" && earned.verifiedAt !== undefined);

    // And it still expires honestly, on time.
    assert.strictEqual(withStaleness(earned, NOW + VERIFY_TTL_MS + 1).state, "unverified");
  });

  test("after sign-out the session is gone, so the SAME body reads as signedOut and drops the green", () => {
    const link = classifyHealth({ kind: "ok", body }, T, NOW, /* hasSession */ false);
    assert.strictEqual(link.state, "signedOut");
    assert.strictEqual(link.verifiedAt, undefined, "a signed-out link carries no earned verdict");
  });
});

suite("engineStatusModel — a verified verdict decays", () => {
  const verified: EngineLink = {
    state: "ok",
    target: T,
    version: "0.3.0",
    checkedAt: NOW,
    verifiedAt: NOW,
  };

  test("inside the freshness window it stays ok", () => {
    assert.strictEqual(withStaleness(verified, NOW + VERIFY_TTL_MS - 1).state, "ok");
  });

  test("past the window it decays to unverified — the tooltip stops asserting a stale fact", () => {
    const stale = withStaleness(verified, NOW + VERIFY_TTL_MS + 1);
    assert.strictEqual(stale.state, "unverified");
    assert.ok(!formatEngineStatus(verified, NOW + VERIFY_TTL_MS + 1).text.startsWith("$(pass-filled)"));
  });

  test("an ok with no verifiedAt at all cannot survive rendering", () => {
    // Defensive: nothing should construct this, but if it did it must not paint green.
    const bogus: EngineLink = { state: "ok", target: T, checkedAt: NOW };
    assert.strictEqual(withStaleness(bogus, NOW).state, "unverified");
  });

  test("ago() is honest about staleness", () => {
    assert.strictEqual(ago(undefined, NOW), "never");
    assert.strictEqual(ago(NOW - 12_000, NOW), "12s ago");
    assert.strictEqual(ago(NOW - 4 * 60_000, NOW), "4m ago");
    assert.strictEqual(ago(NOW - 2 * 3600_000, NOW), "2h ago");
  });
});

suite("engineStatusModel — rendering", () => {
  test("only a verified session gets the filled check", () => {
    const ok: EngineLink = { state: "ok", target: T, checkedAt: NOW, verifiedAt: NOW };
    assert.ok(formatEngineStatus(ok, NOW).text.startsWith("$(pass-filled)"));
    assert.ok(formatEngineStatus(ok, NOW).text.includes("MEFOR: 127.0.0.1:8765"));
  });

  test("signed out is a STATE, not an alarm — a distinct glyph and NO background colour", () => {
    // Being signed out is the author's harmless steady state (live status is off by default; promote
    // prompts for a sign-in anyway). A permanently amber status bar is a permanently ignored one, and
    // then it cannot warn about the states that actually block something.
    const s = formatEngineStatus(classifyHealth({ kind: "ok", body: { status: "ok", version: null } }, T, NOW, false), NOW);
    assert.ok(s.text.startsWith("$(lock)"));
    assert.strictEqual(s.background, undefined);
  });

  test("unreachable and foreign are errors; blocked and drifted are warnings", () => {
    const unreachable = classifyHealth({ kind: "networkError", code: "ECONNREFUSED" }, T, NOW, false);
    assert.strictEqual(formatEngineStatus(unreachable, NOW).background, "error");

    const blocked: EngineLink = {
      state: "blocked",
      target: T,
      blocked: "mustChangePassword",
      checkedAt: NOW,
    };
    assert.strictEqual(formatEngineStatus(blocked, NOW).background, "warning");

    const drifted: EngineLink = { state: "drifted", target: T, checkedAt: NOW, verifiedAt: NOW };
    assert.strictEqual(formatEngineStatus(drifted, NOW).background, "warning");
  });

  test("the hover names the target, the reason and the staleness", () => {
    const link = classifyHealth({ kind: "networkError", code: "ECONNREFUSED" }, T, NOW, false);
    const md = formatEngineStatus(link, NOW + 30_000).tooltipMarkdown;
    assert.ok(md.includes("http://127.0.0.1:8765"));
    assert.ok(/nothing is listening/i.test(md));
    assert.ok(md.includes("30s ago"));
  });

  test("a multi-environment hover lists every configured target", () => {
    const multi = resolveEngineStatusTarget("http://127.0.0.1:8765", [
      { name: "DEV", url: "https://dev:8765" },
      { name: "PROD", url: "https://prod:8765" },
    ]);
    const md = formatEngineStatus({ state: "unknown", target: multi }, NOW).tooltipMarkdown;
    assert.ok(md.includes("DEV") && md.includes("PROD") && md.includes("https://prod:8765"));
  });
});
