// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The pure half of live-debug, run by the unit suite (no Extension Host). The controller-level arms of
// the same rules live in live-debug.test.ts, which needs a VS Code host.
import * as assert from "assert";

import {
  buildLiveLenses,
  inboundTooltip,
  maskedMessagesOf,
  revealPickItems,
  revealedEntry,
  revealedLabel,
  summarize,
  type LiveDryRunRow,
  type LiveTraceEntry,
  type NamedElement,
} from "../../liveDebugModel";

// A synthetic field value of the shape a Handler's own `raise` can quote, and that the CLI's masked
// scrubber is documented to let through whole (a lone identifier with no HL7 delimiter).
const QUOTED = "unmapped patient 900123456";

const ELEMENTS: NamedElement[] = [
  { line: 2, kind: "inbound", name: "IB_ACME_ADT" },
  { line: 5, kind: "router", name: "acme_adt_router" },
];

function row(over: Partial<LiveDryRunRow>): LiveDryRunRow {
  return {
    inbound: "IB_ACME_ADT",
    disposition: "ERROR",
    handlers: [],
    deliveries: [],
    error: QUOTED,
    ...over,
  };
}

function inboundLens(revealed: boolean, rows: LiveDryRunRow[]): string {
  const lenses = buildLiveLenses(ELEMENTS, summarize(rows), "adt.hl7", revealed);
  const lens = lenses.find((l) => l.line === 2);
  assert.ok(lens, "the inbound line must carry a lens");
  return lens.tooltip ?? "";
}

suite("liveDebugModel inbound tooltip (ASVS 14.2.6, vault BACKLOG #1187, ground d1)", () => {
  test("a masked run shows only how many messages failed, and that a reveal exists", () => {
    const tip = inboundLens(false, [row({}), row({ error: "second" }), row({ error: null })]);
    assert.ok(!tip.includes(QUOTED), `masked tooltip quoted the error: ${tip}`);
    assert.ok(!tip.includes("second"), `masked tooltip quoted the error: ${tip}`);
    assert.ok(tip.startsWith("2 of 3 message(s) failed."), tip);
    assert.ok(tip.includes("Reveal Values for One Run"), tip);
  });

  test("a revealed run shows the error text (control arm)", () => {
    const tip = inboundLens(true, [row({})]);
    assert.strictEqual(tip, `Errors: ${QUOTED}`);
  });

  test("the count is per message, not per distinct text", () => {
    const s = summarize([row({}), row({})]);
    assert.deepStrictEqual(s.errors, [QUOTED]);
    assert.strictEqual(s.errorCount, 2);
    assert.ok(inboundTooltip(s, "adt.hl7", false).startsWith("2 of 2 message(s) failed."));
  });

  test("a run with no error reads the same masked or revealed", () => {
    const clean = [row({ error: null, disposition: "PROCESSED" })];
    const want = "Live dry-run of adt.hl7 (1 message(s)).";
    assert.strictEqual(inboundLens(false, clean), want);
    assert.strictEqual(inboundLens(true, clean), want);
  });
});

function entry(source: string, error: string | null): LiveTraceEntry {
  return {
    source,
    inbound: "IB_ACME_ADT",
    disposition: error ? "ERROR" : "PROCESSED",
    handlers: [],
    sends: [],
    error,
    invocations: [],
  };
}

// Three messages from one sample file, each carrying a different synthetic value in its error.
const THREE = [entry("adt.hl7 [1]", "SYNTH-ONE"), entry("adt.hl7 [2]", "SYNTH-TWO"), entry("adt.hl7 [3]", null)];

suite("liveDebugModel one reveal, one message (vault BACKLOG #1187, ground e)", () => {
  test("a focus keeps exactly the message it names", () => {
    assert.strictEqual(revealedEntry(THREE, { index: 1, total: 3 }), THREE[1]);
    assert.strictEqual(revealedEntry(THREE, { index: 0, total: 3 }), THREE[0]);
  });

  test("with no focus, only a one-message run is revealed", () => {
    assert.strictEqual(revealedEntry([THREE[0]], undefined), THREE[0]); // control: one message
    assert.strictEqual(revealedEntry(THREE, undefined), null);
  });

  test("a sample that changed since the pick reveals nothing", () => {
    assert.strictEqual(revealedEntry(THREE, { index: 1, total: 2 }), null);
    assert.strictEqual(revealedEntry(THREE.slice(0, 2), { index: 1, total: 3 }), null);
    assert.strictEqual(revealedEntry(THREE, { index: 3, total: 3 }), null);
    assert.strictEqual(revealedEntry(THREE, { index: -1, total: 3 }), null);
  });

  test("the pick lists file names and dispositions, never a value", () => {
    const items = revealPickItems(maskedMessagesOf(THREE));
    assert.deepStrictEqual(
      items.map((i) => [i.label, i.description, i.index]),
      [
        ["Message 1 of 3", "adt.hl7 [1] · ERROR", 0],
        ["Message 2 of 3", "adt.hl7 [2] · ERROR", 1],
        ["Message 3 of 3", "adt.hl7 [3] · PROCESSED", 2],
      ],
    );
    assert.ok(!JSON.stringify(items).includes("SYNTH"));
  });

  test("a revealed label names the message only when the sample held several", () => {
    assert.strictEqual(revealedLabel("adt.hl7", { index: 1, total: 3 }), "adt.hl7 message 2 of 3");
    assert.strictEqual(revealedLabel("adt.hl7", { index: 0, total: 1 }), "adt.hl7");
    assert.strictEqual(revealedLabel("adt.hl7", null), "adt.hl7");
  });
});
