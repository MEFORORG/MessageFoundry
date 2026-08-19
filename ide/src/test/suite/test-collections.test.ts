// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";

import {
  compareCase,
  compareMessages,
  DEFAULT_VOLATILE_FIELDS,
  isVolatile,
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
