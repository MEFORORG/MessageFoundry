// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";

import {
  READ_SCHEMA_KEYS,
  RENDERED_FIELDS,
  findNameCollision,
  mergeFormIntoInitial,
  nameCollisionError,
  planSave,
  type ConnObj,
} from "../../connectionMerge";

// #234 Phase 3 — the pure save-merge behind BOTH connections.toml writers. The webview form posts
// only the fields it renders; `connection upsert` is a full replace; these tests pin that the merge
// preserves every non-rendered key, deletes cleared rendered keys, merges retry field-wise, applies
// the clone direction-flip intersection, and refuses a name-collision overwrite.

/** A maximal inbound connection as `connection list` returns it — every non-rendered key populated
 *  (the #234 casualty set: schedule, shard, source_ip_allowlist, …). */
function maximalInbound(): ConnObj {
  return {
    direction: "inbound",
    name: "IB_ACME_ADT",
    transport: "mllp",
    settings: { port: 2575 },
    router: "adt_router",
    ack_mode: "enhanced",
    ack_after: "ingest",
    strict: true,
    hl7_version: "2.5.1",
    strict_timeout_s: 5.0,
    content_type: "hl7v2",
    metadata: { owner: "integration-team" },
    bind_address: "10.0.0.5",
    source_ip_allowlist: ["10.0.0.1", "10.0.0.2"],
    capture_ack: true,
    capture_connection_errors: false,
    messages_days: 30,
    prune_documents_after: 7,
    prune_documents_min_bytes: 65536,
    stream_threshold_bytes: 1048576,
    max_message_bytes: 10485760,
    priority: "critical",
    shard: "shard-1",
    schedule: { windows: [{ days: [0, 1, 2, 3, 4], start: "07:00:00", end: "19:00:00", timezone: "UTC" }] },
    auto_start: false,
    deployed: false,
  };
}

/** A maximal outbound connection — retry carries the non-rendered backoff fields alongside the
 *  form-rendered max_attempts. */
function maximalOutbound(): ConnObj {
  return {
    direction: "outbound",
    name: "OB_ACME_ADT",
    transport: "mllp",
    settings: { host: "acme.example", port: 2575 },
    ordering: "fifo",
    retry: { max_attempts: 5, backoff_seconds: 2.5, backoff_multiplier: 3.0, max_backoff_seconds: 120.0 },
    internal_error: "stop",
    buildup: { max_depth: 100, max_oldest_seconds: 120.0 },
    stall: { max_oldest_seconds: 600.0 },
    batch: { max_count: 10, max_wait_ms: 250 },
    simulate: true,
    dead_letter_days: 14,
    priority: "low",
    metadata: { owner: "integration-team" },
    schedule: { windows: [{ days: [1], start: "08:00:00", end: "17:00:00", timezone: "UTC" }] },
    auto_start: true,
    deployed: false,
  };
}

/** What the form's build() posts for an inbound edit: identity fields + the rendered set only. */
function postedInbound(overrides: Partial<ConnObj> = {}): ConnObj {
  return {
    direction: "inbound",
    name: "IB_ACME_ADT",
    transport: "mllp",
    settings: { port: 2576 },
    router: "adt_router",
    ack_mode: "enhanced",
    strict: true,
    ...overrides,
  };
}

suite("connectionMerge — same-direction edit preserves non-rendered keys", () => {
  test("an inbound edit keeps schedule/shard/allowlist/metadata/lifecycle flags", () => {
    const initial = maximalInbound();
    const merged = mergeFormIntoInitial(initial, postedInbound());
    // The posted (rendered) fields land…
    assert.deepStrictEqual(merged.settings, { port: 2576 });
    assert.strictEqual(merged.router, "adt_router");
    // …and every non-rendered key survives untouched.
    assert.deepStrictEqual(merged.schedule, initial.schedule);
    assert.strictEqual(merged.shard, "shard-1");
    assert.deepStrictEqual(merged.source_ip_allowlist, ["10.0.0.1", "10.0.0.2"]);
    assert.deepStrictEqual(merged.metadata, { owner: "integration-team" });
    assert.strictEqual(merged.bind_address, "10.0.0.5");
    assert.strictEqual(merged.content_type, "hl7v2");
    assert.strictEqual(merged.hl7_version, "2.5.1");
    assert.strictEqual(merged.ack_after, "ingest");
    assert.strictEqual(merged.auto_start, false);
    assert.strictEqual(merged.deployed, false); // a not-deployed connection must NOT silently redeploy
    assert.strictEqual(merged.messages_days, 30);
    assert.strictEqual(merged.stream_threshold_bytes, 1048576);
  });

  test("an outbound edit keeps buildup/stall/batch/simulate/dead_letter_days/schedule", () => {
    const initial = maximalOutbound();
    const posted: ConnObj = {
      direction: "outbound",
      name: "OB_ACME_ADT",
      transport: "mllp",
      settings: { host: "acme.example", port: 2576 },
      ordering: "unordered",
      retry: { max_attempts: 3 },
    };
    const merged = mergeFormIntoInitial(initial, posted);
    assert.strictEqual(merged.ordering, "unordered");
    assert.deepStrictEqual(merged.buildup, { max_depth: 100, max_oldest_seconds: 120.0 });
    assert.deepStrictEqual(merged.stall, { max_oldest_seconds: 600.0 });
    assert.deepStrictEqual(merged.batch, { max_count: 10, max_wait_ms: 250 });
    assert.strictEqual(merged.simulate, true);
    assert.strictEqual(merged.dead_letter_days, 14);
    assert.deepStrictEqual(merged.schedule, initial.schedule);
    assert.strictEqual(merged.internal_error, "stop");
    assert.strictEqual(merged.deployed, false);
  });
});

suite("connectionMerge — a cleared rendered field DELETES the key (absent = read-schema default)", () => {
  test("unchecked strict + cleared ack_mode disappear from the merged object", () => {
    const initial = maximalInbound();
    // build() omits ack_mode when the select is blank and strict when unchecked.
    const posted = postedInbound();
    delete posted.ack_mode;
    delete posted.strict;
    const merged = mergeFormIntoInitial(initial, posted);
    assert.ok(!("ack_mode" in merged), "cleared ack_mode must be deleted, not carried");
    assert.ok(!("strict" in merged), "unchecked strict must be deleted, not carried");
    // Non-rendered siblings still survive.
    assert.strictEqual(merged.shard, "shard-1");
  });

  test("removing every settings row deletes the settings table; cleared ordering deletes the key", () => {
    const initial = maximalOutbound();
    const posted: ConnObj = { direction: "outbound", name: "OB_ACME_ADT", transport: "mllp" };
    const merged = mergeFormIntoInitial(initial, posted);
    assert.ok(!("settings" in merged), "no posted settings rows → the table is deleted");
    assert.ok(!("ordering" in merged), "cleared ordering must be deleted (FIFO default)");
    assert.deepStrictEqual(merged.schedule, initial.schedule); // non-rendered keys still survive
  });

  test("posted settings win WHOLESALE (the form renders every row — no per-key merge)", () => {
    const initial = maximalInbound();
    initial.settings = { port: 2575, tls: true };
    const merged = mergeFormIntoInitial(initial, postedInbound({ settings: { port: 9999 } }));
    assert.deepStrictEqual(merged.settings, { port: 9999 }, "a deleted settings row must not resurrect");
  });
});

suite("connectionMerge — retry merges FIELD-WISE (only max_attempts is form-owned)", () => {
  test("posted max_attempts overlays; the backoff fields survive", () => {
    const initial = maximalOutbound();
    const posted: ConnObj = {
      direction: "outbound",
      name: "OB_ACME_ADT",
      transport: "mllp",
      settings: { host: "acme.example", port: 2575 },
      retry: { max_attempts: 3 },
    };
    const merged = mergeFormIntoInitial(initial, posted);
    assert.deepStrictEqual(merged.retry, {
      max_attempts: 3,
      backoff_seconds: 2.5,
      backoff_multiplier: 3.0,
      max_backoff_seconds: 120.0,
    });
  });

  test("a blanked max_attempts deletes ONLY that field; other retry knobs stay", () => {
    const initial = maximalOutbound();
    const posted: ConnObj = {
      direction: "outbound",
      name: "OB_ACME_ADT",
      transport: "mllp",
      settings: { host: "acme.example", port: 2575 },
      // blank input → build() posts no retry at all
    };
    const merged = mergeFormIntoInitial(initial, posted);
    assert.deepStrictEqual(merged.retry, {
      backoff_seconds: 2.5,
      backoff_multiplier: 3.0,
      max_backoff_seconds: 120.0,
    });
  });

  test("an emptied retry table drops the key entirely (absent = inherit [delivery])", () => {
    const initial = maximalOutbound();
    initial.retry = { max_attempts: 5 }; // max_attempts was the only field
    const posted: ConnObj = {
      direction: "outbound",
      name: "OB_ACME_ADT",
      transport: "mllp",
      settings: { host: "acme.example", port: 2575 },
    };
    const merged = mergeFormIntoInitial(initial, posted);
    assert.ok(!("retry" in merged), "an emptied retry table must not linger as {}");
  });
});

suite("connectionMerge — clone (same direction) preserves non-rendered fields", () => {
  test("a clone of a scheduled/sharded connection carries the schedule and shard under the new name", () => {
    const initial = maximalInbound();
    const merged = mergeFormIntoInitial(initial, postedInbound({ name: "IB_ACME_ADT_COPY" }));
    assert.strictEqual(merged.name, "IB_ACME_ADT_COPY");
    assert.deepStrictEqual(merged.schedule, initial.schedule);
    assert.strictEqual(merged.shard, "shard-1");
    assert.deepStrictEqual(merged.source_ip_allowlist, ["10.0.0.1", "10.0.0.2"]);
    assert.strictEqual(merged.deployed, false);
  });
});

suite("connectionMerge — clone direction-flip carries NO inapplicable keys", () => {
  test("inbound→outbound: inbound-only keys are dropped; direction-neutral keys survive", () => {
    const initial = maximalInbound();
    const posted: ConnObj = {
      direction: "outbound",
      name: "OB_FROM_IB",
      transport: "mllp",
      settings: { host: "acme.example", port: 2575 },
      ordering: "fifo",
      retry: { max_attempts: 3 },
    };
    const merged = mergeFormIntoInitial(initial, posted);
    // Every key must be legal in the OUTBOUND read schema (else the loader's _reject_unknown /
    // the writer's _validate_input fails the save — the clone-flip regression this rule prevents).
    for (const key of Object.keys(merged)) {
      if (key === "direction") {
        continue;
      }
      assert.ok(READ_SCHEMA_KEYS.outbound.has(key), `inapplicable key carried into outbound: ${key}`);
    }
    // Inbound-only keys are gone…
    for (const gone of ["router", "ack_mode", "ack_after", "strict", "hl7_version", "content_type",
      "bind_address", "source_ip_allowlist", "shard", "capture_ack", "messages_days",
      "stream_threshold_bytes", "max_message_bytes"]) {
      assert.ok(!(gone in merged), `${gone} must not survive an inbound→outbound flip`);
    }
    // …direction-neutral keys survive the flip…
    assert.deepStrictEqual(merged.schedule, initial.schedule);
    assert.deepStrictEqual(merged.metadata, { owner: "integration-team" });
    assert.strictEqual(merged.priority, "critical");
    assert.strictEqual(merged.auto_start, false);
    assert.strictEqual(merged.deployed, false);
    // …and the posted outbound fields land.
    assert.deepStrictEqual(merged.retry, { max_attempts: 3 });
    assert.strictEqual(merged.ordering, "fifo");
  });

  test("outbound→inbound: outbound-only keys are dropped; the posted inbound fields land", () => {
    const initial = maximalOutbound();
    const posted: ConnObj = {
      direction: "inbound",
      name: "IB_FROM_OB",
      transport: "mllp",
      settings: { port: 2575 },
      router: "adt_router",
    };
    const merged = mergeFormIntoInitial(initial, posted);
    for (const key of Object.keys(merged)) {
      if (key === "direction") {
        continue;
      }
      assert.ok(READ_SCHEMA_KEYS.inbound.has(key), `inapplicable key carried into inbound: ${key}`);
    }
    for (const gone of ["retry", "ordering", "internal_error", "buildup", "stall", "batch",
      "simulate", "dead_letter_days"]) {
      assert.ok(!(gone in merged), `${gone} must not survive an outbound→inbound flip`);
    }
    assert.strictEqual(merged.router, "adt_router");
    assert.deepStrictEqual(merged.schedule, initial.schedule);
    assert.strictEqual(merged.deployed, false);
  });
});

suite("connectionMerge — name-collision refusal (the silent full-replace overwrite hole)", () => {
  const names = ["IB_ACME_ADT", "OB_ACME_ADT"];

  test("create/clone under an existing name collides; a fresh name does not", () => {
    assert.strictEqual(findNameCollision(names, "IB_ACME_ADT"), "IB_ACME_ADT");
    assert.strictEqual(findNameCollision(names, "IB_NEW"), undefined);
  });

  test("an in-place edit may replace exactly its own name", () => {
    assert.strictEqual(findNameCollision(names, "IB_ACME_ADT", "IB_ACME_ADT"), undefined);
    // …but not a sibling's (defensive — the form locks the name input in edit mode).
    assert.strictEqual(findNameCollision(names, "OB_ACME_ADT", "IB_ACME_ADT"), "OB_ACME_ADT");
  });

  test("the refusal message names the collision", () => {
    assert.ok(nameCollisionError("IB_ACME_ADT").includes('"IB_ACME_ADT"'));
  });

  test("planSave refuses a colliding create and does NOT merge", () => {
    const entries = [maximalInbound()];
    const posted = postedInbound(); // same name, but a CREATE (no editingName)
    const plan = planSave(entries, posted, {});
    assert.strictEqual(plan.collision, "IB_ACME_ADT");
  });

  test("planSave refuses a clone posted under its own source name", () => {
    const entries = [maximalInbound()];
    const plan = planSave(entries, postedInbound(), { mergeFrom: "IB_ACME_ADT" });
    assert.strictEqual(plan.collision, "IB_ACME_ADT");
  });
});

suite("connectionMerge — planSave (the one merge-source policy for both writers)", () => {
  test("edit: merges the post over the fresh-list entry it edits", () => {
    const entries = [maximalInbound(), maximalOutbound()];
    const plan = planSave(entries, postedInbound(), {
      mergeFrom: "IB_ACME_ADT",
      editingName: "IB_ACME_ADT",
    });
    assert.strictEqual(plan.collision, undefined);
    assert.deepStrictEqual(plan.conn.schedule, maximalInbound().schedule);
    assert.strictEqual(plan.conn.shard, "shard-1");
    assert.deepStrictEqual(plan.conn.settings, { port: 2576 });
  });

  test("clone: merges from the source under the new name", () => {
    const entries = [maximalInbound()];
    const plan = planSave(entries, postedInbound({ name: "IB_COPY" }), { mergeFrom: "IB_ACME_ADT" });
    assert.strictEqual(plan.collision, undefined);
    assert.strictEqual(plan.conn.name, "IB_COPY");
    assert.strictEqual(plan.conn.shard, "shard-1");
  });

  test("merge source vanished externally → the post stands alone (nothing left to preserve)", () => {
    const plan = planSave([], postedInbound(), {
      mergeFrom: "IB_ACME_ADT",
      editingName: "IB_ACME_ADT",
    });
    assert.strictEqual(plan.collision, undefined);
    assert.deepStrictEqual(plan.conn, postedInbound());
  });

  test("create: no merge source, posted-only", () => {
    const plan = planSave([maximalOutbound()], postedInbound(), {});
    assert.strictEqual(plan.collision, undefined);
    assert.deepStrictEqual(plan.conn, postedInbound());
  });
});

suite("connectionMerge — RENDERED_FIELDS matches what build() renders (documented reality)", () => {
  test("per-direction rendered sets", () => {
    // Verified against connectionEditor.ts build(): inbound posts settings/router/ack_mode/strict;
    // outbound posts settings/ordering/retry (retry rendered as max_attempts only → field-wise).
    assert.deepStrictEqual([...RENDERED_FIELDS.inbound], ["settings", "router", "ack_mode", "strict"]);
    assert.deepStrictEqual([...RENDERED_FIELDS.outbound], ["settings", "ordering", "retry"]);
  });

  test("every rendered field is read-schema-legal for its direction", () => {
    for (const key of RENDERED_FIELDS.inbound) {
      assert.ok(READ_SCHEMA_KEYS.inbound.has(key), `inbound renders unknown key ${key}`);
    }
    for (const key of RENDERED_FIELDS.outbound) {
      assert.ok(READ_SCHEMA_KEYS.outbound.has(key), `outbound renders unknown key ${key}`);
    }
  });
});
