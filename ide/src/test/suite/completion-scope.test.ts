import * as assert from "assert";
import {
  KWARG_SNIPPETS,
  enclosingHandlerTypes,
  kwargContext,
  scopedSegmentSortText,
} from "../../completionScope";
import type { Hl7Structures } from "../../hl7schema";
import { segmentSortText } from "../../hl7schema";

const STRUCT: Hl7Structures = {
  version: "2.5.1",
  triggerToStructure: { "ADT^A01": "ADT_A01", "ADT^A08": "ADT_A01", "ORU^R01": "ORU_R01" },
  structureSegments: {
    ADT_A01: ["MSH", "EVN", "PID", "PV1"],
    ORU_R01: ["MSH", "PID", "OBR", "OBX"],
    ADT_A05: ["MSH", "PID", "IN1"],
  },
};
const ALL = ["MSH", "PID", "PV1", "EVN", "OBR", "OBX", "IN1", "NK1", "ZAL"];

function doc(...lines: string[]): string {
  return lines.join("\n");
}

suite("completionScope — enclosingHandlerTypes (ADR 0104 §2.3 Step 1)", () => {
  test("single-line @handler accepts=message_type_of", () => {
    const text = doc(
      '@handler("adt_to_epic", accepts=message_type_of("ADT^A01"))',
      "def adt_to_epic(msg):",
      '    msg.set("',
    );
    assert.deepStrictEqual(enclosingHandlerTypes(text, 2), ["ADT^A01"]);
  });

  test("multi-line decorator run captured whole (bracket balance, comments tolerated)", () => {
    const text = doc(
      "from messagefoundry import Send, handler, message_type_of",
      "",
      "@handler(",
      '    "adt_to_epic",',
      "    accepts=message_type_of(",
      '        "ADT^A01",',
      '        "ADT^A08",  # legacy feeds send A08 too )',
      "    ),",
      ")",
      "def adt_to_epic(msg):",
      '    msg.set("',
    );
    assert.deepStrictEqual(enclosingHandlerTypes(text, 10), ["ADT^A01", "ADT^A08"]);
  });

  test("nested/indented defs are ignored — the column-0 def wins", () => {
    const text = doc(
      '@handler("oru", accepts=message_type_of("ORU^R01"))',
      "def oru(msg):",
      "    def helper(v):",
      "        return v",
      '    msg.set("',
    );
    assert.deepStrictEqual(enclosingHandlerTypes(text, 4), ["ORU^R01"]);
  });

  test("the inert message_type= documentation kwarg is read", () => {
    const text = doc(
      '@handler("adt_doc", message_type="ADT^A01")',
      "def adt_doc(msg):",
      '    msg.set("',
    );
    assert.deepStrictEqual(enclosingHandlerTypes(text, 2), ["ADT^A01"]);
  });

  test("no decorator -> undefined; untyped decorator -> undefined", () => {
    const plain = doc("def helper(msg):", '    msg.set("');
    assert.strictEqual(enclosingHandlerTypes(plain, 1), undefined);
    const untyped = doc('@handler("h")', "def h(msg):", '    msg.set("');
    assert.strictEqual(enclosingHandlerTypes(untyped, 2), undefined);
  });

  test("module-level cursor (column-0 code above) -> undefined, even below a typed handler", () => {
    const text = doc(
      '@handler("x", accepts=message_type_of("ADT^A01"))',
      "def h(msg):",
      "    return []",
      "",
      "CONST = 1",
      'value = build("',
    );
    assert.strictEqual(enclosingHandlerTypes(text, 5), undefined);
  });

  test("multi-line def signature: the column-0 ') -> …:' line does not end the walk", () => {
    const text = doc(
      '@handler("x", accepts=message_type_of("ORU^R01"))',
      "def h(",
      "    msg,",
      ") -> list:",
      '    msg.set("',
    );
    assert.deepStrictEqual(enclosingHandlerTypes(text, 4), ["ORU^R01"]);
  });

  test("a balanced multi-line NON-decorator block above the run does not leak in", () => {
    const text = doc(
      "X = build(",
      '    "not-a-type",',
      ")",
      '@handler("h", accepts=message_type_of("ADT^A08"))',
      "def h(msg):",
      '    msg.set("',
    );
    assert.deepStrictEqual(enclosingHandlerTypes(text, 5), ["ADT^A08"]);
  });
});

suite("completionScope — scopedSegmentSortText (rank, never remove)", () => {
  test("ADT^A08 resolves to ADT_A01 via triggerToStructure; in-scope '0…' keeps COMMON sub-order", () => {
    const rank = scopedSegmentSortText(ALL, STRUCT, ["ADT^A08"]);
    assert.ok(rank, "a resolvable type yields a rank map");
    // In-scope (ADT_A01 = MSH/EVN/PID/PV1): tier '0', COMMON_SEGMENTS sub-order preserved.
    const inScope = ["MSH", "PID", "PV1", "EVN"];
    for (const seg of inScope) {
      assert.strictEqual(rank.get(seg)?.sortText, `0${segmentSortText(seg)}`, seg);
      assert.strictEqual(rank.get(seg)?.description, "", `${seg} carries no miss marker`);
    }
    const ordered = [...inScope].sort((a, b) =>
      (rank.get(a)?.sortText ?? "").localeCompare(rank.get(b)?.sortText ?? ""),
    );
    assert.deepStrictEqual(ordered, ["MSH", "PID", "PV1", "EVN"]); // COMMON_SEGMENTS order
    // Everything else: tier '2' with the distinct "not in <STRUCTURE>" description.
    assert.strictEqual(rank.get("OBR")?.sortText, `2${segmentSortText("OBR")}`);
    assert.strictEqual(rank.get("OBR")?.description, "not in ADT_A01");
    assert.strictEqual(rank.get("ZAL")?.description, "not in ADT_A01");
    // Every out-of-scope sortText sorts after every in-scope one.
    for (const seg of ALL) {
      if (!inScope.includes(seg)) {
        assert.ok((rank.get(seg)?.sortText ?? "").startsWith("2"), seg);
      }
    }
  });

  test("explicit 3-component spec uses its structure id directly", () => {
    const rank = scopedSegmentSortText(ALL, STRUCT, ["ADT^A01^ADT_A05"]);
    assert.ok(rank);
    assert.strictEqual(rank.get("IN1")?.description, ""); // ADT_A05 = MSH/PID/IN1
    assert.strictEqual(rank.get("PV1")?.description, "not in ADT_A05");
    assert.strictEqual(rank.get("EVN")?.description, "not in ADT_A05");
  });

  test("multi-spec union: both structures' segments are in scope; miss names both", () => {
    const rank = scopedSegmentSortText(ALL, STRUCT, ["ADT^A01", "ORU^R01"]);
    assert.ok(rank);
    for (const seg of ["MSH", "EVN", "PID", "PV1", "OBR", "OBX"]) {
      assert.strictEqual(rank.get(seg)?.description, "", seg);
    }
    assert.strictEqual(rank.get("NK1")?.description, "not in ADT_A01, ORU_R01");
  });

  test("rank-never-remove: every schema segment is ranked exactly once", () => {
    const rank = scopedSegmentSortText(ALL, STRUCT, ["ADT^A01"]);
    assert.ok(rank);
    assert.strictEqual(rank.size, ALL.length); // a Map key is unique — one entry per segment
    assert.deepStrictEqual([...rank.keys()].sort(), [...ALL].sort());
  });

  test("undefined structures / absent or unresolvable types -> undefined (byte-identical passthrough)", () => {
    assert.strictEqual(scopedSegmentSortText(ALL, undefined, ["ADT^A01"]), undefined);
    assert.strictEqual(scopedSegmentSortText(ALL, STRUCT, undefined), undefined);
    assert.strictEqual(scopedSegmentSortText(ALL, STRUCT, []), undefined);
    assert.strictEqual(scopedSegmentSortText(ALL, STRUCT, ["ADT"]), undefined); // code-only
    assert.strictEqual(scopedSegmentSortText(ALL, STRUCT, ["ZZZ^Q99"]), undefined); // unknown
    // REGRESSION BAR: on undefined, completion.ts falls back to `segmentSortText(seg)` — the very
    // function the pre-#230 segment stage called. Pin its exact bytes so the fallback stays
    // byte-identical to today's order.
    assert.strictEqual(segmentSortText("MSH"), "000");
    assert.strictEqual(segmentSortText("PID"), "001");
    assert.strictEqual(segmentSortText("PV1"), "002");
    assert.strictEqual(segmentSortText("AIS"), "017");
    assert.strictEqual(segmentSortText("ZAL"), "1ZAL");
    assert.strictEqual(segmentSortText("ABS"), "1ABS");
  });
});

suite("completionScope — KWARG_CTX (occurrence=/repetition= position)", () => {
  test("fires after the path argument of .set(/.field(", () => {
    assert.deepStrictEqual(kwargContext('msg.set("PID-3.1", '), { partial: "", present: [] });
    assert.deepStrictEqual(kwargContext('msg.field("PID-3", '), { partial: "", present: [] });
    // A part-typed identifier is carried out so the caller can set the replacement range.
    assert.deepStrictEqual(kwargContext('msg.set("PID-3.1", occ'), { partial: "occ", present: [] });
    // After a closed value + comma it fires again (the legal kwarg slot).
    assert.deepStrictEqual(kwargContext('msg.set("PID-3.1", "abc", '), { partial: "", present: [] });
    // A closed nested call before the comma is fine.
    assert.deepStrictEqual(kwargContext('msg.set("PID-3.1", fn(x), '), { partial: "", present: [] });
  });

  test("never fires inside a string literal — path or VALUE (the naive regex's failure case)", () => {
    assert.strictEqual(kwargContext('msg.set("PID-3'), undefined); // path literal
    assert.strictEqual(kwargContext('msg.set("PID-3.1", "abc'), undefined); // value literal
    assert.strictEqual(kwargContext('msg.set("PID-3.1", "occurrence='), undefined);
  });

  test("never fires inside Send(\"…\") or router=\"…\" contexts", () => {
    assert.strictEqual(kwargContext('    return [Send("OB_'), undefined);
    assert.strictEqual(kwargContext('    return [Send("OB_X", '), undefined); // callee is not .set/.field
    assert.strictEqual(kwargContext('inbound("IB_X", router="'), undefined);
    assert.strictEqual(kwargContext('inbound("IB_X", router="adt_router", '), undefined);
  });

  test("never fires on the path argument, mid-value, in an open nested call, or in a comment", () => {
    assert.strictEqual(kwargContext("msg.set("), undefined); // path slot — PATH_CTX's turf
    assert.strictEqual(kwargContext('msg.set("PID-3.1", occurrence='), undefined); // kwarg VALUE slot
    assert.strictEqual(kwargContext('msg.set("PID-3.1", occurrence=2'), undefined);
    assert.strictEqual(kwargContext('msg.set("PID-3.1", fn(x'), undefined); // inner call is not .set
    assert.strictEqual(kwargContext('msg.set("PID-3.1", "v" '), undefined); // no comma after the value
    assert.strictEqual(kwargContext('# msg.set("PID-3.1", '), undefined); // comment
    assert.strictEqual(kwargContext('msg.reset("PID-3.1", '), undefined); // .reset is not .set
    assert.strictEqual(kwargContext('set("PID-3.1", '), undefined); // bare set() is not .set
  });

  test("already-written kwargs are reported so the caller can skip duplicates", () => {
    assert.deepStrictEqual(kwargContext('msg.set("PID-3.1", "v", occurrence=2, '), {
      partial: "",
      present: ["occurrence"],
    });
    assert.deepStrictEqual(kwargContext('msg.set("PID-3.1", "v", occurrence=2, rep'), {
      partial: "rep",
      present: ["occurrence"],
    });
  });

  test("snippet data quotes the 1-based semantics of parsing/message.py", () => {
    assert.deepStrictEqual(
      KWARG_SNIPPETS.map((s) => s.name),
      ["occurrence", "repetition"],
    );
    for (const s of KWARG_SNIPPETS) {
      assert.ok(s.doc.includes("1-based"), `${s.name} doc states 1-based`);
      assert.ok(s.doc.includes("parsing/message.py"), `${s.name} doc cites the source`);
      assert.ok(s.insert.startsWith(`${s.name}=`), `${s.name} snippet inserts the kwarg`);
    }
  });
});
