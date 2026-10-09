// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Pure, dependency-free model + compare for Test Bench saved regression collections (BACKLOG #168,
// ADR 0121). No `vscode` import (persistence lives in collectionStore.ts), so this is
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

// The members live in a const so a webview page can be handed the same list its host is typed by
// (ASVS 3.5.5, BACKLOG #1123). The type is derived from it, so the two cannot drift.
export const DELIVERY_STATUSES = ["match", "mismatch", "missing", "unexpected"] as const;
export type DeliveryStatus = (typeof DELIVERY_STATUSES)[number];

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

/** What one case's rerun produced, as the host reads it off the dry-run row. `undefined`: no row. */
export interface CaseRerun {
  disposition: string;
  error: string | null;
  deliveries: readonly ExpectedDelivery[];
}

/** The part of one case's result the run view shows at once: no field value, no error text. */
export interface CaseRunSummary {
  name: string;
  pass: boolean;
  disposition: string;
}

/** The part shown only when that one case is clicked (ADR 0121, "Reveal on click"). */
export interface CaseRunDetail {
  error: string | null;
  deliveries: DeliveryComparison[];
}

/** One collection rerun, split so the summaries can go to the view and the details stay behind. */
export interface CollectionRunResult {
  passed: number;
  summaries: CaseRunSummary[];
  details: CaseRunDetail[]; // aligned 1:1 with `summaries` by index
}

/**
 * Judge every case of a collection against its rerun, and split each result in two: summaries, which
 * carry no `before`/`after` value and no error text, and details, which carry both (ADR 0121, "Reveal
 * on click"). `reruns[i]` is case `i`'s rerun, or `undefined` when the dry-run produced no row for it,
 * which fails the case.
 */
export function judgeCollectionRun(
  cases: readonly TestCase[],
  reruns: readonly (CaseRerun | undefined)[],
  ignore: readonly VolatileField[] = DEFAULT_VOLATILE_FIELDS,
): CollectionRunResult {
  const summaries: CaseRunSummary[] = [];
  const details: CaseRunDetail[] = [];
  cases.forEach((c, i) => {
    const rerun = reruns[i];
    const cmp = compareCase(c.expected, rerun ? rerun.deliveries : [], ignore);
    summaries.push({
      name: c.name,
      pass: rerun ? cmp.pass : false,
      disposition: rerun?.disposition ?? "NO RESULT",
    });
    details.push({
      error: rerun ? rerun.error : "no dry-run row produced for this case",
      deliveries: cmp.deliveries,
    });
  });
  return { passed: summaries.filter((s) => s.pass).length, summaries, details };
}

/**
 * The detail to post for a `caseDetail` request, or `null` to post nothing. The request comes from the
 * webview, so both fields are untrusted: `run` must name the held run, and `index` must be an integer
 * naming one of its cases.
 */
export function pickCaseDetail(
  held: { id: number; details: readonly CaseRunDetail[] } | null,
  run: unknown,
  index: unknown,
): CaseRunDetail | null {
  if (!held || run !== held.id || typeof index !== "number" || !Number.isSafeInteger(index)) {
    return null;
  }
  return index >= 0 && index < held.details.length ? held.details[index] : null;
}

/**
 * The held run after the webview says it left the view for `run` (BACKLOG #2441), so a later
 * `caseDetail` for that run gets no answer. `run` comes from the webview and is untrusted: only an
 * exact match on the held id releases it. Any other value, including a newer run's id, keeps what is
 * held, so a stale or duplicate message cannot drop the run now on screen.
 */
export function releaseRun<T extends { id: number }>(held: T | null, run: unknown): T | null {
  return held && run === held.id ? null : held;
}

/**
 * The host-to-webview message types that keep the run view on screen. Every other type replaces it,
 * so a view type added later releases the held run by default rather than keeping it answerable.
 */
export const RUN_VIEW_KEEPERS: readonly string[] = ["caseDetail", "collectionRun"];

/**
 * The held run after the host posts a message of `type` (BACKLOG #2441). Any view that replaces the
 * run view releases it, so the host does not depend on the webview reporting the change. Take this at
 * the moment of the post: the webview renders posts in order, so a run posted after this view still
 * holds. A `collectionRun` keeps what is held, because the host sets the new run just before posting.
 */
export function heldAfterPost<T>(held: T | null, type: string): T | null {
  return RUN_VIEW_KEEPERS.includes(type) ? held : null;
}

/**
 * The held run after a webview-to-host message (BACKLOG #2441). `m` is untrusted. `leaveRun` releases
 * only an exact id match (see releaseRun); anything else keeps what is held. `ready` is NOT handled
 * here: the host answers it with dropRun(), which also bumps viewGen so a run in flight across a
 * webview reload lands nowhere, and a pure release here could not do that.
 */
export function heldAfterIncoming<T extends { id: number }>(held: T | null, m: unknown): T | null {
  if (typeof m !== "object" || m === null) {
    return held;
  }
  const msg = m as { command?: unknown; run?: unknown };
  return msg.command === "leaveRun" ? releaseRun(held, msg.run) : held;
}
