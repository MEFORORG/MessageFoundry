// Pure, dependency-free model + compare for Test Bench saved regression collections (BACKLOG #168,
// ADR 0121). No `vscode` import (persistence via workspaceState lives in testBench.ts), so this is
// unit-testable in isolation — the same discipline as hl7diff.ts / hexdump.ts. The compare REUSES
// hl7diff.diffMessages (segment/field-aware alignment) rather than reimplementing it.

import { diffMessages, type MessageDiff } from "./hl7diff";

/** A recorded expected output: which outbound it went to, and the exact payload. */
export interface ExpectedDelivery {
  to: string;
  payload: string;
}

/** One regression case: an input body and the outputs it is expected to produce. */
export interface TestCase {
  name: string; // label (the source, e.g. the original file name)
  input: string; // the raw received body (PHI — stored machine-local only; see ADR 0121)
  expected: ExpectedDelivery[];
}

/** A named, self-contained regression collection. */
export interface TestCollection {
  name: string;
  cases: TestCase[];
}

/**
 * A volatile field to ignore when judging pass/fail. `index` is the hl7diff SPLIT index into a
 * segment's `fields[]` — NOT the HL7 field number — because MSH-1 is the separator character itself,
 * not a split element: for MSH, `fields[6]` is MSH-7 and `fields[9]` is MSH-10.
 */
export interface VolatileField {
  seg: string;
  index: number;
}

/**
 * The fixed default volatile-field policy (ADR 0121, decided up front): every conformant message
 * carries a message date/time and a control ID that legitimately differ run-to-run, so a byte-equality
 * compare would always fail. MSH-7 is also the "ACK date" for an ACK message (its generation time).
 */
export const DEFAULT_VOLATILE_FIELDS: readonly VolatileField[] = [
  { seg: "MSH", index: 6 }, // MSH-7 — message date/time
  { seg: "MSH", index: 9 }, // MSH-10 — message control ID
];

/** A concrete field-level difference that counts as a regression (a volatile field is never listed). */
export interface FieldDifference {
  seg: string; // segment id, e.g. "PID"
  index: number; // split index into fields[]; -1 marks a whole added/removed segment
  before: string; // expected value ("" when the field/segment is absent on the expected side)
  after: string; // actual value ("" when absent on the actual side)
}

/** The HL7-aware compare of one expected body vs one actual body. */
export interface CompareResult {
  pass: boolean; // true iff no non-volatile difference remains
  differences: FieldDifference[];
  diff: MessageDiff; // the aligned before/after cells, for rendering
}

export type DeliveryStatus = "match" | "mismatch" | "missing" | "unexpected";

/** The outcome of comparing one expected delivery against the rerun's actual deliveries. */
export interface DeliveryComparison {
  to: string;
  status: DeliveryStatus;
  differences: FieldDifference[]; // non-volatile diffs (empty for match/missing/unexpected)
}

/** The outcome of rerunning one case: per-delivery comparisons + an overall pass. */
export interface CaseResult {
  pass: boolean;
  deliveries: DeliveryComparison[];
}

/** True when `(seg, index)` is in the ignore policy. */
export function isVolatile(
  seg: string,
  index: number,
  ignore: readonly VolatileField[] = DEFAULT_VOLATILE_FIELDS,
): boolean {
  return ignore.some((v) => v.seg === seg && v.index === index);
}

/** Join a diff cell's fields back to a segment string, for reporting an added/removed whole segment. */
function joinCell(fields: { t: string }[], sep: string): string {
  return fields.map((f) => f.t).join(sep);
}

/**
 * HL7-aware compare of two message bodies, ignoring the volatile-field policy. Reuses
 * `diffMessages` so an inserted/deleted segment aligns (no cascade) and the field separator is read
 * from MSH (never hardcoded `|^~\&`). A `same` cell is clean; an added/removed SEGMENT is always a
 * real difference; a `changed` cell is a real difference only for changed fields not in `ignore`.
 */
export function compareMessages(
  expected: string,
  actual: string,
  ignore: readonly VolatileField[] = DEFAULT_VOLATILE_FIELDS,
): CompareResult {
  const diff = diffMessages(expected, actual); // before = expected side, after = actual side
  const differences: FieldDifference[] = [];

  for (let i = 0; i < diff.before.length; i++) {
    const b = diff.before[i];
    const a = diff.after[i];
    const status = b.seg ? b.status : a.status;
    if (status === "same") {
      continue;
    }
    if (status === "added") {
      // Segment present only in the actual output.
      differences.push({
        seg: a.fields[0]?.t ?? "",
        index: -1,
        before: "",
        after: joinCell(a.fields, a.sep),
      });
      continue;
    }
    if (status === "removed") {
      // Segment present only in the expected output.
      differences.push({
        seg: b.fields[0]?.t ?? "",
        index: -1,
        before: joinCell(b.fields, b.sep),
        after: "",
      });
      continue;
    }
    // changed: both sides have the segment; localize to the differing fields.
    const seg = b.fields[0]?.t ?? a.fields[0]?.t ?? "";
    const max = Math.max(b.fields.length, a.fields.length);
    for (let k = 0; k < max; k++) {
      const bf = b.fields[k];
      const af = a.fields[k];
      const changed = Boolean(bf?.c) || Boolean(af?.c);
      if (!changed || isVolatile(seg, k, ignore)) {
        continue;
      }
      differences.push({ seg, index: k, before: bf?.t ?? "", after: af?.t ?? "" });
    }
  }

  return { pass: differences.length === 0, differences, diff };
}

/**
 * Compare the recorded expected deliveries of one case against the rerun's actual deliveries. Matched
 * by outbound `to` (first-come within a repeated `to`); a missing expected delivery or an unexpected
 * extra actual delivery fails the case, as does any non-volatile payload difference.
 */
export function compareCase(
  expected: readonly ExpectedDelivery[],
  actual: readonly ExpectedDelivery[],
  ignore: readonly VolatileField[] = DEFAULT_VOLATILE_FIELDS,
): CaseResult {
  const remaining = actual.slice();
  const deliveries: DeliveryComparison[] = [];

  for (const exp of expected) {
    const idx = remaining.findIndex((d) => d.to === exp.to);
    if (idx === -1) {
      deliveries.push({ to: exp.to, status: "missing", differences: [] });
      continue;
    }
    const act = remaining.splice(idx, 1)[0];
    const cmp = compareMessages(exp.payload, act.payload, ignore);
    deliveries.push({
      to: exp.to,
      status: cmp.pass ? "match" : "mismatch",
      differences: cmp.differences,
    });
  }

  // Anything left over was produced but not expected.
  for (const extra of remaining) {
    deliveries.push({ to: extra.to, status: "unexpected", differences: [] });
  }

  return { pass: deliveries.every((d) => d.status === "match"), deliveries };
}
