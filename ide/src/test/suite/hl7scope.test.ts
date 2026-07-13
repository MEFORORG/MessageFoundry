import * as assert from "assert";
import type { Hl7Structures } from "../../hl7schema";
import { buildSegmentScope, resolveStructureIds, sampleSegments } from "../../hl7scope";

const STRUCT: Hl7Structures = {
  version: "2.5.1",
  triggerToStructure: { "ADT^A01": "ADT_A01", "ADT^A08": "ADT_A01", "ORU^R01": "ORU_R01" },
  structureSegments: {
    ADT_A01: ["MSH", "EVN", "PID", "PV1"],
    ORU_R01: ["MSH", "PID", "OBR", "OBX"],
    ADT_A05: ["MSH", "PID", "IN1"],
  },
};
const ALL = ["MSH", "PID", "PV1", "EVN", "OBR", "OBX", "IN1", "NK1"];

suite("hl7scope — field-picker message-type scope (ADR 0104 §2.3 P2)", () => {
  test("resolveStructureIds: accepts spec, explicit 3rd component, inferred, code-only unresolvable", () => {
    assert.deepStrictEqual(resolveStructureIds(STRUCT, ["ADT^A01"], undefined), ["ADT_A01"]);
    assert.deepStrictEqual(resolveStructureIds(STRUCT, ["ADT^A08"], undefined), ["ADT_A01"]); // collapse
    assert.deepStrictEqual(resolveStructureIds(STRUCT, ["ADT^A01^ADT_A05"], undefined), ["ADT_A05"]); // explicit
    assert.deepStrictEqual(resolveStructureIds(STRUCT, undefined, { code: "ADT", trigger: "A08" }), ["ADT_A01"]);
    assert.deepStrictEqual(resolveStructureIds(STRUCT, undefined, { code: "ADT" }), []); // code-only
    assert.deepStrictEqual(resolveStructureIds(STRUCT, ["ZZZ^Q99"], undefined), []); // unknown
  });

  test("sampleSegments: distinct 3-char leaders, junk ignored", () => {
    assert.deepStrictEqual(
      sampleSegments("MSH|^~\\&|x\rPID|1\rZAL|z\rPID|2\rnot-a-segment\r"),
      ["MSH", "PID", "ZAL"],
    );
    assert.deepStrictEqual(sampleSegments(""), []);
  });

  test("buildSegmentScope ranks in-scope, unions Z/sample, keeps All-segments escape, distinct miss (AC-9)", () => {
    const scope = buildSegmentScope(ALL, STRUCT, ["ADT^A01"], undefined, ["MSH", "PID", "OBR", "ZAL"]);
    assert.ok(scope, "a resolvable type yields a scope");
    assert.deepStrictEqual(scope.structureIds, ["ADT_A01"]);
    const find = (seg: string) => scope.groups.find((g) => g.segment === seg);

    // In-scope (ADT_A01 = MSH/EVN/PID/PV1) first, no marker.
    for (const seg of ["MSH", "EVN", "PID", "PV1"]) {
      assert.strictEqual(find(seg)?.group, "In this message type", `${seg} in scope`);
      assert.strictEqual(find(seg)?.description, "", `${seg} carries no marker`);
    }
    // A Z-segment from the sample is unioned in with its own distinct description.
    assert.strictEqual(find("ZAL")?.description, "Z-segment · site-custom");
    // A standard segment in the sample but not in the structure is labelled "in sample".
    assert.strictEqual(find("OBR")?.description, "in sample");
    // A scope MISS reads distinctly ("not in ADT_A01") under the always-present "All segments".
    assert.strictEqual(find("NK1")?.group, "All segments");
    assert.strictEqual(find("NK1")?.description, "not in ADT_A01");
    assert.strictEqual(find("OBX")?.description, "not in ADT_A01");

    // Rank, never remove: every standard segment appears exactly once (Z is the only addition).
    const standard = scope.groups.filter((g) => g.segment !== "ZAL").map((g) => g.segment);
    assert.deepStrictEqual([...standard].sort(), [...ALL].sort());
    // The three fallback descriptions are distinct strings (a miss is never a sanctioned Z fallback).
    assert.notStrictEqual("Z-segment · site-custom", "in sample");
    assert.notStrictEqual("in sample", "not in ADT_A01");
  });

  test("no resolvable type, or no structures artifact -> undefined (generic, unscoped picker)", () => {
    assert.strictEqual(buildSegmentScope(ALL, STRUCT, undefined, undefined, []), undefined);
    assert.strictEqual(buildSegmentScope(ALL, STRUCT, ["ADT"], undefined, []), undefined); // code-only
    assert.strictEqual(buildSegmentScope(ALL, undefined, ["ADT^A01"], undefined, []), undefined);
  });
});
