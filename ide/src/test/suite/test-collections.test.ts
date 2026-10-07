// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import {
  compareCase,
  compareMessages,
  DEFAULT_VOLATILE_FIELDS,
  heldAfterIncoming,
  heldAfterPost,
  isVolatile,
  judgeCollectionRun,
  pickCaseDetail,
  releaseRun,
  type ExpectedDelivery,
} from "../../testCollections";

// Segments joined by \r (the real HL7 terminator).
function hl7(...segments: string[]): string {
  return segments.join("\r");
}

const MSH = (dt: string, ctrl: string) => `MSH|^~\\&|APP|FAC|RCV|RFAC|${dt}|SEC|ADT^A01|${ctrl}|P|2.5`;

suite("testCollections.isVolatile / DEFAULT_VOLATILE_FIELDS", () => {
  test("MSH-7 (index 6) and MSH-10 (index 9) are the default volatile fields", () => {
    assert.ok(isVolatile("MSH", 6));
    assert.ok(isVolatile("MSH", 9));
    assert.ok(!isVolatile("MSH", 5));
    assert.ok(!isVolatile("PID", 6));
    assert.strictEqual(DEFAULT_VOLATILE_FIELDS.length, 2);
  });
});

suite("testCollections.compareMessages — volatile fields ignored (AC-1)", () => {
  test("differing ONLY in MSH-7 and MSH-10 passes", () => {
    const expected = hl7(MSH("20200101010101", "CTRL001"), "PID|1||A^SMITH");
    const actual = hl7(MSH("20991231235959", "CTRL999"), "PID|1||A^SMITH");
    const res = compareMessages(expected, actual);
    assert.strictEqual(res.pass, true, "MSH-7/MSH-10 drift must not fail");
    assert.deepStrictEqual(res.differences, []);
  });
});

suite("testCollections.compareMessages — real regressions fail (AC-2)", () => {
  test("a changed non-volatile field (PID-5 name) fails and is localized", () => {
    const expected = hl7(MSH("20200101010101", "CTRL001"), "PID|1||MRN1^^^HOSP||SMITH^JOHN");
    const actual = hl7(MSH("20200101010101", "CTRL001"), "PID|1||MRN1^^^HOSP||JONES^JOHN");
    const res = compareMessages(expected, actual);
    assert.strictEqual(res.pass, false);
    assert.strictEqual(res.differences.length, 1);
    const d = res.differences[0];
    assert.strictEqual(d.seg, "PID");
    assert.strictEqual(d.index, 5); // PID-5
    assert.strictEqual(d.before, "SMITH^JOHN");
    assert.strictEqual(d.after, "JONES^JOHN");
  });

  test("an added segment fails (whole-segment difference, index -1)", () => {
    const expected = hl7(MSH("20200101010101", "CTRL001"), "PID|1||A");
    const actual = hl7(MSH("20200101010101", "CTRL001"), "PID|1||A", "NK1|1|DOE^JANE");
    const res = compareMessages(expected, actual);
    assert.strictEqual(res.pass, false);
    const nk1 = res.differences.find((d) => d.seg === "NK1");
    assert.ok(nk1, "the added NK1 is reported");
    assert.strictEqual(nk1?.index, -1);
    assert.strictEqual(nk1?.before, "");
  });

  test("a removed segment fails", () => {
    const expected = hl7(MSH("20200101010101", "CTRL001"), "PID|1||A", "PV1|1|I");
    const actual = hl7(MSH("20200101010101", "CTRL001"), "PID|1||A");
    const res = compareMessages(expected, actual);
    assert.strictEqual(res.pass, false);
    const pv1 = res.differences.find((d) => d.seg === "PV1");
    assert.strictEqual(pv1?.index, -1);
    assert.strictEqual(pv1?.after, "");
  });
});

suite("testCollections.compareMessages — non-standard separator (AC-3)", () => {
  test("reads the field separator from MSH and still locates MSH-7/MSH-10", () => {
    // '#' field separator; only MSH-7 differs → should pass (volatile).
    const expected = "MSH#^~\\&#APP#FAC#RCV#RFAC#20200101#SEC#ADT^A01#CTRL1#P#2.5";
    const actual = "MSH#^~\\&#APP#FAC#RCV#RFAC#20991231#SEC#ADT^A01#CTRL1#P#2.5";
    const res = compareMessages(expected, actual);
    assert.strictEqual(res.pass, true, "MSH-7 is volatile even with a '#' separator");
  });

  test("a non-volatile change under a '#' separator still fails", () => {
    const expected = "MSH#^~\\&#APP#FAC#RCV#RFAC#20200101#SEC#ADT^A01#CTRL1#P#2.5\rPID#1#X";
    const actual = "MSH#^~\\&#APP#FAC#RCV#RFAC#20200101#SEC#ADT^A01#CTRL1#P#2.5\rPID#1#Y";
    const res = compareMessages(expected, actual);
    assert.strictEqual(res.pass, false);
  });
});

suite("testCollections.compareCase — delivery-set matching", () => {
  const dl = (to: string, payload: string): ExpectedDelivery => ({ to, payload });
  const body = (ctrl: string) => hl7(MSH("20200101010101", ctrl), "PID|1||A");

  test("all deliveries match (volatile-only drift) → pass", () => {
    const expected = [dl("OB_A", body("C1")), dl("OB_B", body("C2"))];
    const actual = [dl("OB_A", body("C9")), dl("OB_B", body("C8"))];
    const res = compareCase(expected, actual);
    assert.strictEqual(res.pass, true);
    assert.deepStrictEqual(
      res.deliveries.map((d) => d.status),
      ["match", "match"],
    );
  });

  test("a missing expected delivery fails", () => {
    const expected = [dl("OB_A", body("C1")), dl("OB_B", body("C2"))];
    const actual = [dl("OB_A", body("C1"))];
    const res = compareCase(expected, actual);
    assert.strictEqual(res.pass, false);
    assert.strictEqual(res.deliveries.find((d) => d.to === "OB_B")?.status, "missing");
  });

  test("an unexpected extra delivery fails", () => {
    const expected = [dl("OB_A", body("C1"))];
    const actual = [dl("OB_A", body("C1")), dl("OB_B", body("C2"))];
    const res = compareCase(expected, actual);
    assert.strictEqual(res.pass, false);
    assert.strictEqual(res.deliveries.find((d) => d.to === "OB_B")?.status, "unexpected");
  });

  test("a mismatched payload fails with the differences carried through", () => {
    const expected = [dl("OB_A", hl7(MSH("20200101010101", "C1"), "PID|1||A^SMITH"))];
    const actual = [dl("OB_A", hl7(MSH("20200101010101", "C1"), "PID|1||A^JONES"))];
    const res = compareCase(expected, actual);
    assert.strictEqual(res.pass, false);
    const d = res.deliveries[0];
    assert.strictEqual(d.status, "mismatch");
    assert.ok(d.differences.some((x) => x.seg === "PID"));
  });
});

// ASVS 14.2.6 (BACKLOG #2437): the host posts every summary at once and one detail per click, so a
// summary must carry no field value and no error text.
suite("testCollections.judgeCollectionRun — summaries carry no values", () => {
  const dl = (to: string, payload: string): ExpectedDelivery => ({ to, payload });
  const pid = (v: string) => hl7(MSH("20200101010101", "C1"), `PID|1||${v}`);
  const cases = [
    { name: "same", input: pid("A"), expected: [dl("OB_A", pid("A"))] },
    { name: "changed", input: pid("A"), expected: [dl("OB_A", pid("SMITH"))] },
    { name: "no row", input: pid("A"), expected: [dl("OB_A", pid("A"))] },
  ];
  const run = judgeCollectionRun(cases, [
    { disposition: "received", error: null, deliveries: [dl("OB_A", pid("A"))] },
    { disposition: "received", error: "failed near JONES", deliveries: [dl("OB_A", pid("JONES"))] },
    undefined,
  ]);

  test("each summary is name, pass and disposition, and nothing else", () => {
    assert.deepStrictEqual(run.summaries, [
      { name: "same", pass: true, disposition: "received" },
      { name: "changed", pass: false, disposition: "received" },
      { name: "no row", pass: false, disposition: "NO RESULT" },
    ]);
    const text = JSON.stringify(run.summaries);
    for (const v of ["SMITH", "JONES"]) {
      assert.ok(!text.includes(v), `a summary carries ${v}`);
    }
    assert.strictEqual(run.passed, 1);
  });

  test("each detail carries that case's differences and error, aligned by index", () => {
    assert.strictEqual(run.details.length, 3);
    assert.strictEqual(run.details[0].error, null);
    assert.strictEqual(run.details[0].deliveries[0].status, "match");
    assert.strictEqual(run.details[1].error, "failed near JONES");
    const d = run.details[1].deliveries[0].differences[0];
    assert.deepStrictEqual([d.before, d.after], ["SMITH", "JONES"]);
    assert.strictEqual(run.details[2].error, "no dry-run row produced for this case");
    assert.strictEqual(run.details[2].deliveries[0].status, "missing");
  });
});

// The host half of ADR 0121 "Reveal on click": which detail, if any, a caseDetail request gets.
suite("testCollections.pickCaseDetail — the host answers only a request for a held case", () => {
  const details = [
    { error: null, deliveries: [] },
    { error: "boom", deliveries: [] },
  ];
  const held = { id: 4, details };

  test("a request naming the held run and one of its cases gets that one case", () => {
    assert.strictEqual(pickCaseDetail(held, 4, 1), details[1]);
    assert.strictEqual(pickCaseDetail(held, 4, 0), details[0]);
  });

  test("anything else gets nothing", () => {
    const refused: [string, unknown, unknown, typeof held | null][] = [
      ["no run held", 4, 0, null],
      ["another run", 3, 0, held],
      ["a string run id", "4", 0, held],
      ["an index past the end", 4, 2, held],
      ["a negative index", 4, -1, held],
      ["a fractional index", 4, 0.5, held],
      ["a string index", 4, "0", held],
      ["an inherited property as the index", 4, "length", held],
      ["no index", 4, undefined, held],
    ];
    for (const [why, run, index, h] of refused) {
      assert.strictEqual(pickCaseDetail(h, run, index), null, why);
    }
  });
});

// BACKLOG #2441: the webview's leaveRun releases the held run, and only on an exact id match.
suite("testCollections.releaseRun — leaving the run view stops the host answering for it", () => {
  const details = [{ error: null, deliveries: [] }];
  const held = { id: 4, details };

  test("the held run's id releases it, so its caseDetail gets no answer", () => {
    assert.strictEqual(pickCaseDetail(held, 4, 0), details[0], "control: answered before the leave");
    assert.strictEqual(pickCaseDetail(releaseRun(held, 4), 4, 0), null);
  });

  test("any other value keeps the held run answerable", () => {
    const kept: [string, unknown][] = [
      ["an older run", 3],
      ["a newer run", 5],
      ["a string run id", "4"],
      ["no run id", undefined],
      ["null", null],
      ["an object", { id: 4 }],
    ];
    for (const [why, run] of kept) {
      assert.strictEqual(releaseRun(held, run), held, why);
      assert.strictEqual(pickCaseDetail(releaseRun(held, run), 4, 0), details[0], why);
    }
  });

  test("nothing held stays nothing held", () => {
    assert.strictEqual(releaseRun(null, 4), null);
  });
});

// BACKLOG #2441, the host's own half: a replacing view releases the run when posted, with no leaveRun
// needed from the webview. (A fresh page load's ready is answered by dropRun() in testBench.ts.)
suite("testCollections.heldAfterPost / heldAfterIncoming — the host drops the run on its own", () => {
  const details = [{ error: null, deliveries: [] }];
  const held = { id: 4, details };

  test("posting any view but caseDetail or collectionRun releases the run (control: those two keep it)", () => {
    // "aNewView" stands for a view type added later: it must release by default, not keep.
    for (const type of ["detail", "trace", "hex", "collections", "aNewView"]) {
      assert.strictEqual(pickCaseDetail(heldAfterPost(held, type), 4, 0), null, type);
    }
    for (const type of ["caseDetail", "collectionRun"]) {
      assert.strictEqual(heldAfterPost(held, type), held, `control: ${type}`);
      assert.strictEqual(pickCaseDetail(heldAfterPost(held, type), 4, 0), details[0], `control: ${type}`);
    }
  });

  test("leaveRun releases only an exact id match, as releaseRun does", () => {
    assert.strictEqual(heldAfterIncoming(held, { command: "leaveRun", run: 4 }), null);
    assert.strictEqual(heldAfterIncoming(held, { command: "leaveRun", run: "4" }), held);
    assert.strictEqual(heldAfterIncoming(held, { command: "leaveRun" }), held);
  });

  test("any other message, or no object at all, keeps the held run", () => {
    const kept: [string, unknown][] = [
      ["a caseDetail request", { command: "caseDetail", run: 4, index: 0 }],
      ["a load request", { command: "load" }],
      // The host answers ready with dropRun() instead, which also bumps viewGen; see heldAfterIncoming.
      ["ready", { command: "ready" }],
      ["null", null],
      ["undefined", undefined],
      ["a string", "ready"],
      ["an array", ["ready"]],
    ];
    for (const [why, m] of kept) {
      assert.strictEqual(heldAfterIncoming(held, m), held, why);
    }
  });
});
