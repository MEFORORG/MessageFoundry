import * as assert from "assert";

import { diffMessages, parseEncoding, parseMessage, type DiffCell } from "../../hl7diff";

// Segments joined by \r (the real HL7 terminator) — diffMessages must tolerate this and \n / \r\n.
function hl7(...segments: string[]): string {
  return segments.join("\r");
}

// The segment ids visible on one side, in order, skipping gap placeholders — a compact way to
// assert the alignment.
function segIds(cells: DiffCell[]): string[] {
  return cells.filter((c) => c.seg).map((c) => c.fields[0]?.t ?? "");
}

// Find the aligned row whose segment id (on the given side) matches, and return that cell.
function cellFor(cells: DiffCell[], id: string): DiffCell | undefined {
  return cells.find((c) => c.seg && c.fields[0]?.t === id);
}

suite("hl7diff.parseEncoding", () => {
  test("reads the field/component separators from MSH — not hardcoded |^~\\&", () => {
    const enc = parseEncoding("MSH|^~\\&|APP|FAC");
    assert.strictEqual(enc.field, "|");
    assert.strictEqual(enc.component, "^");
    assert.strictEqual(enc.repetition, "~");
    assert.strictEqual(enc.subcomponent, "&");
  });

  test("honours a non-standard field separator", () => {
    // A feed using '#' as the field separator and '@' as the component separator.
    const enc = parseEncoding("MSH#@~\\&#APP#FAC");
    assert.strictEqual(enc.field, "#");
    assert.strictEqual(enc.component, "@");
  });

  test("splits fields on the message's own separator", () => {
    const { segments, enc } = parseMessage("MSH#@~\\&#APP#FAC\rPID#1#X");
    assert.strictEqual(enc.field, "#");
    const pid = segments.find((s) => s.id === "PID");
    assert.deepStrictEqual(pid?.fields, ["PID", "1", "X"]);
  });
});

suite("hl7diff.diffMessages — insertion does not cascade", () => {
  const before = hl7("MSH|^~\\&|APP|FAC", "PID|1||A", "PV1|1|I");
  // NK1 inserted between PID and PV1; PID and PV1 are otherwise identical.
  const after = hl7("MSH|^~\\&|APP|FAC", "PID|1||A", "NK1|1|DOE^JANE", "PV1|1|I");

  const diff = diffMessages(before, after);

  test("the inserted segment is the only added row; siblings still align", () => {
    assert.deepStrictEqual(segIds(diff.before), ["MSH", "PID", "PV1"]);
    assert.deepStrictEqual(segIds(diff.after), ["MSH", "PID", "NK1", "PV1"]);

    const nk1 = cellFor(diff.after, "NK1");
    assert.strictEqual(nk1?.status, "added");
    // A gap holds NK1's place on the before side so the two panes stay in register.
    assert.strictEqual(diff.before.length, diff.after.length);
    assert.ok(
      diff.before.some((c) => !c.seg && c.status === "added"),
      "a before-side gap should mark the insertion point",
    );
  });

  test("PID and PV1 are NOT marked changed by the insert (no cascade)", () => {
    assert.strictEqual(cellFor(diff.before, "PID")?.status, "same");
    assert.strictEqual(cellFor(diff.after, "PID")?.status, "same");
    assert.strictEqual(cellFor(diff.before, "PV1")?.status, "same");
    assert.strictEqual(cellFor(diff.after, "PV1")?.status, "same");
  });
});

suite("hl7diff.diffMessages — a single changed field is localized", () => {
  const before = hl7("MSH|^~\\&|APP|FAC", "PID|1||A^SMITH|DOB");
  const after = hl7("MSH|^~\\&|APP|FAC", "PID|1||A^JONES|DOB"); // only PID-3 changed

  const diff = diffMessages(before, after);

  test("the segment is 'changed' but only the differing field is flagged", () => {
    const pidB = cellFor(diff.before, "PID");
    const pidA = cellFor(diff.after, "PID");
    assert.strictEqual(pidB?.status, "changed");
    assert.strictEqual(pidA?.status, "changed");

    // fields: [PID, 1, "", A^SMITH -> A^JONES, DOB]; only index 3 differs.
    const changedIdx = (pidA?.fields ?? [])
      .map((f, i) => (f.c ? i : -1))
      .filter((i) => i >= 0);
    assert.deepStrictEqual(changedIdx, [3], "only the changed field is highlighted");
    assert.strictEqual(pidA?.fields[3].t, "A^JONES");
    assert.strictEqual(pidB?.fields[3].t, "A^SMITH");
  });

  test("MSH (unchanged) stays 'same'", () => {
    assert.strictEqual(cellFor(diff.before, "MSH")?.status, "same");
  });
});

suite("hl7diff.diffMessages — repeating segments align by set-id", () => {
  // A new OBX (set-id 2) inserted between the two existing observations; the trailing OBX keeps its
  // set-id 3, so it must align to its own counterpart rather than cascade.
  const before = hl7("MSH|^~\\&|APP|FAC", "OBX|1|NM|GLU||100", "OBX|3|NM|K||4.0");
  const after = hl7(
    "MSH|^~\\&|APP|FAC",
    "OBX|1|NM|GLU||100",
    "OBX|2|NM|NA||140",
    "OBX|3|NM|K||4.0",
  );

  const diff = diffMessages(before, after);

  test("only the new OBX|2 is added; OBX|1 and OBX|3 stay 'same'", () => {
    const added = diff.after.filter((c) => c.seg && c.status === "added");
    assert.strictEqual(added.length, 1);
    assert.strictEqual(added[0].fields[1].t, "2", "the added OBX is set-id 2");

    const sames = diff.after.filter((c) => c.seg && c.status === "same" && c.fields[0].t === "OBX");
    assert.deepStrictEqual(
      sames.map((c) => c.fields[1].t).sort(),
      ["1", "3"],
      "the pre-existing OBX rows are unchanged",
    );
  });
});

suite("hl7diff.diffMessages — deletion and non-HL7 fallback", () => {
  test("a deleted segment is marked removed with a gap opposite it", () => {
    const before = hl7("MSH|^~\\&|APP|FAC", "PID|1||A", "PV1|1|I");
    const after = hl7("MSH|^~\\&|APP|FAC", "PV1|1|I"); // PID dropped
    const diff = diffMessages(before, after);
    assert.strictEqual(cellFor(diff.before, "PID")?.status, "removed");
    assert.strictEqual(diff.before.length, diff.after.length);
    assert.ok(diff.after.some((c) => !c.seg && c.status === "removed"));
  });

  test("a body with no MSH degrades to line-level cells without crashing", () => {
    const diff = diffMessages("hello world", "(no message would be sent — UNROUTED)");
    assert.strictEqual(diff.before.length, diff.after.length);
    // No shared identity → the line is removed and the placeholder added.
    assert.ok(diff.before.some((c) => c.seg && c.status === "removed"));
    assert.ok(diff.after.some((c) => c.seg && c.status === "added"));
  });
});
