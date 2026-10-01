// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The pure half of live-debug, run by the unit suite (no Extension Host). The controller-level arms of
// the same rules live in live-debug.test.ts, which needs a VS Code host.
import * as assert from "assert";

import {
  buildLiveLenses,
  inboundTooltip,
  summarize,
  type LiveDryRunRow,
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
