// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";

import {
  ASSIST_GATE_PLAN,
  CMD,
  DEEP_PROBE_ROUTE,
  ENGINE_LINK_FIELDS,
  ENVIRONMENT_PLAN,
  POLICY_ROUTE,
  POLL_PLAN,
  PROBE_ENDPOINTS,
  VERIFY_PLAN,
  classifyDeep,
  classifyForbidden,
  escapeMarkdown,
  formatEngineStatus,
  planActions,
  readVersion,
  resolveEngineStatusTarget,
  type EngineLink,
} from "../../engineStatusModel";

// The engine-link DOCTOR: the deep (authenticated, user-initiated) probe that is the only thing allowed
// to earn a green check, the action menu it drives, and — most importantly — the two frozen allowlists
// that hold the architectural boundary.
//
// THE BOUNDARY (ADR — engine-link doctor): the IDE renders and repairs the IDE↔engine LINK; it never
// renders the engine's WORKLOAD. The web console at /ui is the sole operator console (CLAUDE.md §2; the
// PySide6 desktop console was retired). The two allowlist tests below are what make that enforceable:
// growing this surface into a monitor requires editing a frozen list, which turns a quiet 20-line diff
// into a red test and an ADR conversation.

const T = resolveEngineStatusTarget("http://127.0.0.1:8765", []);
const NOW = 1_000_000;

suite("engine doctor — the boundary, as CI", () => {
  test("the EngineLink field allowlist is frozen", () => {
    assert.deepStrictEqual(
      [...ENGINE_LINK_FIELDS],
      [
        "blocked",
        "checkedAt",
        "code",
        "environment",
        "reason",
        "state",
        "target",
        "verifiedAt",
        "version",
      ],
    );
  });

  test("every EngineLink field is declared in the allowlist", () => {
    // Compile-time exhaustiveness: adding a field to EngineLink without adding it to ENGINE_LINK_FIELDS
    // is a TYPE error here, and adding it to ENGINE_LINK_FIELDS trips the frozen-list test above. There
    // is no way to widen the link state quietly.
    const declared: Record<keyof EngineLink, true> = {
      blocked: true,
      checkedAt: true,
      code: true,
      environment: true,
      reason: true,
      state: true,
      target: true,
      verifiedAt: true,
      version: true,
    };
    assert.deepStrictEqual(Object.keys(declared).sort(), [...ENGINE_LINK_FIELDS].sort());
  });

  test("no link field names a WORKLOAD concept", () => {
    // A field called `messages`, `queueDepth`, `connections` or `rate` is how an indicator becomes a
    // monitor. If you are here because this test failed: the answer is a deep-link to /ui, not a field.
    // `stats`, not `stat` — the latter also matches the legitimate `state` field. (It did.)
    const forbidden = /connection|message|queue|count|rate|alert|dead|letter|throughput|stats/i;
    for (const f of ENGINE_LINK_FIELDS) {
      assert.ok(!forbidden.test(f), `EngineLink.${f} names engine workload — that belongs in the Console`);
    }
  });

  test("the probe-endpoint allowlist is frozen and contains nothing operational", () => {
    assert.deepStrictEqual([...PROBE_ENDPOINTS], ["/ai/policy", "/config/provenance", "/health"]);
    const operational = ["/messages", "/connections", "/stats", "/dead-letters", "/alerts", "/approvals"];
    for (const route of operational) {
      assert.ok(
        !(PROBE_ENDPOINTS as readonly string[]).includes(route),
        `${route} is the Console's job — the IDE must not probe it`,
      );
    }
  });

  test("AC-3: the PERIODIC poll may never send a bearer token (AUTH-IDLE / CWE-613)", () => {
    // This is the control, not the comment above it. identity_for_token(..., activity=True) refreshes a
    // session's idle clock, so a bearer on a 15-second timer from an open editor window would keep the
    // session alive forever and make the engine's 30-minute idle timeout mathematically unreachable — on
    // the exact client the automatic-logoff requirement exists for. statusBar.runProbe attaches the token
    // IFF the plan entry says `authenticated`, so this assertion is what actually holds the line.
    assert.ok(POLL_PLAN.length > 0);
    for (const entry of POLL_PLAN) {
      assert.strictEqual(
        entry.authenticated,
        false,
        `the periodic poll must not authenticate (${entry.route}) — it would defeat AUTH-IDLE`,
      );
      assert.ok(
        (PROBE_ENDPOINTS as readonly string[]).includes(entry.route),
        `${entry.route} is not an allowed probe endpoint`,
      );
    }
  });

  test("T7: the status bar's /ai/policy environment read stays TOKENLESS (CWE-613)", () => {
    // statusBar.readEnvironment runs off the same 15s timer as the poll, via runProbe — which attaches a
    // bearer IFF the plan entry says `authenticated`. Flipping this to true would put a bearer on the
    // timer and make the engine's 30-minute idle timeout unreachable, on the exact client the
    // automatic-logoff control exists for. It wants `environment`, which is identity-INDEPENDENT, so it
    // has nothing to gain from a token in the first place.
    assert.ok(ENVIRONMENT_PLAN.length > 0);
    for (const entry of ENVIRONMENT_PLAN) {
      assert.strictEqual(
        entry.authenticated,
        false,
        `the status bar's environment read must not authenticate (${entry.route}) — it is on a timer`,
      );
      assert.ok(
        (PROBE_ENDPOINTS as readonly string[]).includes(entry.route),
        `${entry.route} is not an allowed probe endpoint`,
      );
    }
    assert.strictEqual(ENVIRONMENT_PLAN[0].route, POLICY_ROUTE);
  });

  test("T8: aiPolicy's gate read DOES authenticate — same route, opposite answer, on purpose", () => {
    // BACKLOG #330. `assist_permitted` is computed from the acting identity (api/app.py), so a tokenless
    // read can only ever answer null and the ai:assist deny branch can never fire. Unlike the status
    // bar's read, this one is user-initiated only (a chat turn / the Show AI Policy command), so it sits
    // under VERIFY_PLAN's rationale rather than POLL_PLAN's: refreshing the idle clock there is honest
    // activity, not a forgery.
    assert.strictEqual(ASSIST_GATE_PLAN.length, 1);
    assert.strictEqual(ASSIST_GATE_PLAN[0].authenticated, true);
    assert.ok(
      (PROBE_ENDPOINTS as readonly string[]).includes(ASSIST_GATE_PLAN[0].route),
      `${ASSIST_GATE_PLAN[0].route} is not an allowed probe endpoint`,
    );
    // The distinction itself, asserted — so a later reader who finds two plans for one route cannot
    // "unify" them without turning this red. Same route; the ANSWER is what differs, and it differs
    // because the two callers want different FIELDS of the same document.
    assert.strictEqual(
      ENVIRONMENT_PLAN[0].route,
      ASSIST_GATE_PLAN[0].route,
      "both plans read the same route",
    );
    assert.notStrictEqual(
      ENVIRONMENT_PLAN[0].authenticated,
      ASSIST_GATE_PLAN[0].authenticated,
      "the timer-driven read and the user-initiated read must NOT agree about the bearer",
    );
  });

  test("the user-initiated deep check MAY authenticate — and only it may", () => {
    // A click / activation / promote IS real user activity, so refreshing the idle clock there is honest.
    assert.ok(VERIFY_PLAN.some((e) => e.authenticated));
    for (const entry of VERIFY_PLAN) {
      assert.ok(
        (PROBE_ENDPOINTS as readonly string[]).includes(entry.route),
        `${entry.route} is not an allowed probe endpoint`,
      );
    }
    // The version is only ever disclosed to an authenticated caller, so it must be learned here.
    assert.ok(VERIFY_PLAN.some((e) => e.route === "/health" && e.authenticated));
    assert.strictEqual(readVersion({ status: "ok", version: "0.3.0" }), "0.3.0");
    assert.strictEqual(readVersion({ status: "ok", version: null }), undefined);
  });

  test("the deep probe hits a route that can actually prove usability", () => {
    // NOT /health and NOT /auth/me: both are must-change-exempt (api/security.py's
    // _MUST_CHANGE_EXEMPT_PATHS) and answer 200 for a user who is locked out of every real route, so
    // neither can establish that a session works. /config/provenance is permission-gated (monitoring:read)
    // with no step-up — the cheapest route whose success MEANS something.
    assert.strictEqual(DEEP_PROBE_ROUTE, "/config/provenance");
    assert.notStrictEqual(DEEP_PROBE_ROUTE, "/health");
    assert.notStrictEqual(DEEP_PROBE_ROUTE, "/auth/me");
  });
});

suite("engine doctor — the deep probe earns (or refuses) the green check", () => {
  const unverified: EngineLink = {
    state: "unverified",
    target: T,
    version: "0.3.0",
    checkedAt: NOW,
  };

  test("200 ⇒ ok, and the verification is timestamped", () => {
    const link = classifyDeep({ kind: "ok", body: { loaded: true, drift: false } }, unverified, NOW);
    assert.strictEqual(link.state, "ok");
    assert.strictEqual(link.verifiedAt, NOW);
    assert.strictEqual(link.version, "0.3.0"); // what the shallow probe learned is not lost
  });

  test("200 with drift ⇒ drifted (still verified — the session works, the config doesn't match)", () => {
    const link = classifyDeep({ kind: "ok", body: { loaded: true, drift: true } }, unverified, NOW);
    assert.strictEqual(link.state, "drifted");
    assert.strictEqual(link.verifiedAt, NOW);
  });

  test("401 ⇒ signedOut, and the green is revoked", () => {
    const wasOk: EngineLink = { ...unverified, state: "ok", verifiedAt: NOW - 1000 };
    const link = classifyDeep({ kind: "httpError", status: 401, detail: "not authenticated" }, wasOk, NOW);
    assert.strictEqual(link.state, "signedOut");
    assert.strictEqual(link.verifiedAt, undefined);
  });

  test("403 ⇒ blocked, sub-classified so the RIGHT remedy is offered", () => {
    const mustChange = classifyDeep(
      { kind: "httpError", status: 403, detail: "password change required" },
      unverified,
      NOW,
    );
    assert.strictEqual(mustChange.state, "blocked");
    assert.strictEqual(mustChange.blocked, "mustChangePassword");
    assert.strictEqual(mustChange.verifiedAt, undefined);

    const perm = classifyDeep(
      { kind: "httpError", status: 403, detail: "missing permission: monitoring:read" },
      unverified,
      NOW,
    );
    assert.strictEqual(perm.blocked, "permission");
  });

  test("a transport failure during the deep probe ⇒ unreachable, not blocked", () => {
    const link = classifyDeep({ kind: "networkError", code: "ECONNREFUSED" }, unverified, NOW);
    assert.strictEqual(link.state, "unreachable");
    assert.strictEqual(link.verifiedAt, undefined);
  });

  test("403 detail strings map to the reason the engine actually means", () => {
    assert.strictEqual(classifyForbidden("password change required"), "mustChangePassword");
    assert.strictEqual(classifyForbidden("step-up re-verification required"), "stepUp");
    assert.strictEqual(classifyForbidden("MFA enrolment required"), "mfa");
    assert.strictEqual(classifyForbidden("missing permission: config:deploy"), "permission");
    assert.strictEqual(classifyForbidden("something else entirely"), "forbidden");
  });
});

suite("engine doctor — the action menu is gated on the state", () => {
  const commandsFor = (link: EngineLink): string[] => planActions(link, NOW).map((a) => a.command);

  test("signed out ⇒ Sign in is offered, Sign out is not", () => {
    const cmds = commandsFor({ state: "signedOut", target: T, checkedAt: NOW });
    assert.ok(cmds.includes(CMD.signIn));
    assert.ok(!cmds.includes(CMD.signOut));
  });

  test("verified ⇒ Sign out is offered, Sign in is not", () => {
    const cmds = commandsFor({ state: "ok", target: T, checkedAt: NOW, verifiedAt: NOW });
    assert.ok(cmds.includes(CMD.signOut));
    assert.ok(!cmds.includes(CMD.signIn));
  });

  test("unreachable ⇒ start/configure, and NOT 'open it in a browser'", () => {
    // The old menu's headline action opened the bare engine URL — which has no route and answers a
    // FastAPI 404 — and it offered it even when nothing was listening at all.
    const cmds = commandsFor({ state: "unreachable", target: T, code: "ECONNREFUSED", checkedAt: NOW });
    assert.ok(cmds.includes(CMD.copyStart));
    assert.ok(cmds.includes(CMD.settings));
    assert.ok(!cmds.includes(CMD.openConsole), "a dead engine's console is not worth opening");
  });

  test("drifted ⇒ the FIRST action is promote (the existing command — no second deploy path)", () => {
    const actions = planActions({ state: "drifted", target: T, checkedAt: NOW, verifiedAt: NOW }, NOW);
    assert.strictEqual(actions[0].command, CMD.promote);
  });

  test("blocked on a credential problem ⇒ deep-link to the console, which owns credentials", () => {
    const actions = planActions(
      { state: "blocked", target: T, blocked: "mustChangePassword", checkedAt: NOW },
      NOW,
    );
    assert.strictEqual(actions[0].command, CMD.openConsole);
    assert.deepStrictEqual(actions[0].args, ["/ui/login"]);
  });

  test("blocked on a missing PERMISSION ⇒ explained, not faked with a button we can't honour", () => {
    const actions = planActions(
      { state: "blocked", target: T, blocked: "permission", checkedAt: NOW },
      NOW,
    );
    assert.ok(/lacks the permission/i.test(actions[0].label));
    assert.ok(/administrator/i.test(actions[0].detail ?? ""));
  });

  test("every state can re-check and read the log", () => {
    const states: EngineLink["state"][] = [
      "unknown",
      "unreachable",
      "foreign",
      "signedOut",
      "unverified",
      "blocked",
      "drifted",
      "ok",
    ];
    for (const state of states) {
      const cmds = commandsFor({ state, target: T, checkedAt: NOW, verifiedAt: NOW });
      assert.ok(cmds.includes(CMD.recheck), `${state} must be re-checkable`);
      assert.ok(cmds.includes(CMD.showLog), `${state} must be able to show the log`);
    }
  });

  test("no action carries engine data — only a command id and (rarely) a path", () => {
    // The model emits COMMAND IDS, never data. That is what makes it structurally impossible for engine
    // workload to reach this surface: there is no channel for it, even if someone fetched it.
    const states: EngineLink["state"][] = ["unreachable", "signedOut", "unverified", "blocked", "ok"];
    for (const state of states) {
      for (const a of planActions({ state, target: T, checkedAt: NOW, verifiedAt: NOW }, NOW)) {
        assert.ok(
          Object.values(CMD).includes(a.command as (typeof CMD)[keyof typeof CMD]),
          `${a.command} is not a known engine command`,
        );
        for (const arg of a.args ?? []) {
          assert.strictEqual(typeof arg, "string", "an action argument may only be a path string");
        }
      }
    }
  });

  test("server-supplied text cannot inject a command link into the TRUSTED hover", () => {
    // The hover is a trusted MarkdownString whose enabledCommands include messagefoundry.promote, and
    // `reason` carries the engine's 403 `detail` VERBATIM. Whatever is answering on that port is not
    // necessarily our engine — that is precisely what the `foreign` state means — so a hostile listener
    // must not be able to plant a link the user is being invited to click.
    const hostile = 'nope [Click here](command:messagefoundry.promote) `x`';
    const blocked: EngineLink = {
      state: "blocked",
      target: T,
      blocked: "forbidden",
      reason: hostile,
      checkedAt: NOW,
    };
    const md = formatEngineStatus(blocked, NOW).tooltipMarkdown;
    assert.ok(!md.includes("](command:"), "a command link survived into the trusted hover");
    assert.ok(md.includes("\\["), "the link syntax should be escaped, not stripped");

    // And the escaper itself, directly.
    assert.ok(!escapeMarkdown("[a](command:x)").includes("](command:"));
    assert.strictEqual(escapeMarkdown("a\n\nb"), "a b"); // newlines flattened — no injected blocks
    assert.ok(escapeMarkdown("x".repeat(500)).length <= 301); // bounded
  });

  test("a stale green cannot produce an 'ok' menu", () => {
    // planActions applies the same decay as the renderer, so the menu and the item can never disagree.
    const stale: EngineLink = { state: "ok", target: T, checkedAt: NOW, verifiedAt: NOW - 10 * 60_000 };
    const cmds = commandsFor(stale);
    assert.ok(cmds.includes(CMD.recheck));
    assert.ok(!cmds.includes(CMD.signIn), "a stale-but-present session should be re-verified, not re-signed-in");
  });
});
