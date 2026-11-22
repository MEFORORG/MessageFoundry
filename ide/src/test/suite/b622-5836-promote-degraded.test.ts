// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { promoteOutcomeMessage, type ReloadResult } from "../../promoteOutcome";

// BACKLOG #5836: a live reload the engine marked degraded (ReloadResult.degraded, with each failed
// follow-on step in `failures`, messagefoundry/api/models.py) is a WARNING naming the steps, never
// a clean "promoted". Before the fix the message read neither field, so a degraded swap with an
// empty restart_required reported plain success. Node-only, on the test:unit leg.
suite("b622 #5836 promote reports a degraded reload", () => {
  const clean: ReloadResult = {
    inbound: 2,
    outbound: 3,
    routers: 1,
    handlers: 4,
    running: true,
    dry_run: false,
    degraded: false,
    failures: [],
    restart_required: [],
  };
  const graph = "to PROD — live graph: 2 inbound, 3 outbound, 1 routers, 4 handlers, running.";
  const message = (body: Record<string, unknown>) =>
    promoteOutcomeMessage("PROD", { kind: "done", body: { ...clean, ...body } as ReloadResult });

  test("control: a clean reload is plain success", () => {
    assert.deepStrictEqual(message({}), { level: "info", text: `MessageFoundry: promoted ${graph}` });
  });

  test("a degraded reload is a WARNING that leads with the failed steps", () => {
    const msg = message({ degraded: true, failures: ["reference_sync", "audit"] });
    assert.strictEqual(msg.level, "warning");
    assert.strictEqual(
      msg.text,
      "MessageFoundry: check the engine's log: these follow-on steps failed after the swap: " +
        `reference_sync, audit. The new graph is live. Promoted ${graph}`,
    );
  });

  // Only the lead survives a collapsed notification, so the stale-CA restart leads.
  test("a degraded reload that also needs a restart reports both, restart first", () => {
    const msg = message({
      degraded: true,
      failures: ["cluster_propagate"],
      restart_required: ["[auth].ad_tls_ca_cert_file"],
    });
    assert.strictEqual(msg.level, "warning");
    assert.ok(msg.text.startsWith("MessageFoundry: restart the engine for [auth].ad_tls_ca_cert_file: "), msg.text);
    assert.ok(
      msg.text.endsWith("Check the engine's log: this follow-on step failed after the swap: " +
        "cluster_propagate. The new graph is live."),
      msg.text,
    );
  });

  // An unreadable restart list knows of no stale CA, so the known failure leads.
  test("a degraded reload with an unreadable restart list leads with the failed step", () => {
    const msg = message({ degraded: true, failures: ["audit"], restart_required: null });
    assert.strictEqual(msg.level, "warning");
    assert.ok(
      msg.text.startsWith("MessageFoundry: check the engine's log: this follow-on step failed after the swap: audit."),
      msg.text,
    );
    assert.ok(msg.text.endsWith("the engine's list of them could not be read."), msg.text);
  });

  for (const [name, body] of [
    ["no degraded field", { degraded: undefined }],
    ["a degraded that is a string", { degraded: "true" }],
    ["a clean reply that names a failed step", { degraded: false, failures: ["reference_sync"] }],
    ["a clean reply with failures missing", { failures: undefined }],
    ["degraded with no failures", { degraded: true, failures: [] }],
    ["degraded with failures missing", { degraded: true, failures: undefined }],
    ["degraded with a link in failures", { degraded: true, failures: ["[x](command:y)"] }],
    ["degraded with a non-string failure", { degraded: true, failures: [1] }],
  ] as const) {
    test(`${name} warns that the report could not be read, and prints none of it`, () => {
      const msg = message(body);
      assert.strictEqual(msg.level, "warning");
      assert.strictEqual(
        msg.text,
        "MessageFoundry: check the engine's log for whether a follow-on step failed after the swap: " +
          `the engine's report of them could not be read. Promoted ${graph}`,
      );
    });
  }
});
