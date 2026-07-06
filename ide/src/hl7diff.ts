// Pure, dependency-free HL7 v2 before/after diff for the Test Bench. No `vscode` import, so it is
// unit-testable in isolation and cannot pull the extension host into a test. The engine's
// `parsing/` package is intentionally NOT imported (§4 keeps the IDE off the engine internals);
// this re-implements just the segment/field splitting the diff view needs.
//
// The diff is SEGMENT- and FIELD-aware, not line-positional:
//   * a message is split into segments on the HL7 segment terminator (\r, tolerant of \n / \r\n);
//   * the field separator is read from MSH-1 (the char right after "MSH") and the remaining
//     encoding characters from MSH-2 — never hardcoded, because real feeds vary (a non-`|`
//     separator, a custom component/repetition set, etc.);
//   * segments are ALIGNED by identity key (segment id + numeric set-id, e.g. OBX-1) with an LCS,
//     so an inserted or deleted segment shows as add/remove instead of cascading a false "changed"
//     down every following segment;
//   * matched segments are compared field-by-field, so a single changed field is localized.

export interface EncodingChars {
  field: string; // MSH-1 (the field separator)
  component: string; // MSH-2[0]
  repetition: string; // MSH-2[1]
  escape: string; // MSH-2[2]
  subcomponent: string; // MSH-2[3]
}

export interface Segment {
  id: string; // segment id, e.g. "PID" ("" for a blank/degenerate line)
  fields: string[]; // fields[0] === id; fields[1] === <SEG>-1, etc. (split-index, not HL7 number)
  raw: string; // the original segment text
}

export interface DiffField {
  t: string; // field text
  c: boolean; // changed vs the aligned counterpart
}

export type LineStatus = "same" | "changed" | "added" | "removed";

export interface DiffCell {
  seg: boolean; // true = a real segment on this side; false = a gap opposite an add/remove
  status: LineStatus;
  fields: DiffField[]; // rendered joined by `sep`; empty when seg === false
  sep: string; // field separator used to re-join fields for display
}

export interface MessageDiff {
  before: DiffCell[]; // aligned rows: before[i] lines up with after[i]
  after: DiffCell[];
}

// Only a fallback for a body that carries no MSH/BHS/FHS header (e.g. a non-HL7 RawMessage payload
// or the "(no message would be sent …)" placeholder). Real HL7 always overrides this from MSH-1.
const DEFAULT_FIELD_SEP = "|";

const SEG_SEP = /\r\n|\r|\n/;

/** Read the encoding characters straight off the message header — never assume `|^~\&`. */
export function parseEncoding(text: string): EncodingChars {
  for (const line of text.split(SEG_SEP)) {
    if (
      (line.startsWith("MSH") || line.startsWith("BHS") || line.startsWith("FHS")) &&
      line.length > 3
    ) {
      const field = line.charAt(3); // MSH-1 is the char immediately after the segment id
      const enc = line.slice(4).split(field)[0] ?? ""; // MSH-2, e.g. "^~\&"
      return {
        field,
        component: enc.charAt(0) || "^",
        repetition: enc.charAt(1) || "~",
        escape: enc.charAt(2) || "\\",
        subcomponent: enc.charAt(3) || "&",
      };
    }
  }
  return {
    field: DEFAULT_FIELD_SEP,
    component: "^",
    repetition: "~",
    escape: "\\",
    subcomponent: "&",
  };
}

/** Split a message into segments, splitting fields on the message's own MSH-1 separator. */
export function parseMessage(text: string): { segments: Segment[]; enc: EncodingChars } {
  const enc = parseEncoding(text);
  const segments: Segment[] = [];
  for (const raw of text.split(SEG_SEP)) {
    if (raw.length === 0) {
      continue; // drop the empty tail after a trailing terminator (and stray blank lines)
    }
    const fields = raw.split(enc.field);
    segments.push({ id: fields[0] ?? "", fields, raw });
  }
  return { segments, enc };
}

/**
 * Identity key for alignment. Repeating segments (OBX/NTE/DG1/OBR/…) carry a numeric Set ID in
 * field 1; folding it into the key aligns each instance to its own counterpart instead of matching
 * repeats by position (which is what makes a mid-list insert cascade). MSH-2 is the encoding block,
 * not a set-id, so MSH keys on the id alone — the `\d+` guard handles that automatically.
 */
function segKey(seg: Segment): string {
  const setId = seg.fields[1];
  if (setId && /^\d+$/.test(setId)) {
    return seg.id + ":" + setId;
  }
  return seg.id;
}

interface AlignOp {
  a: number | null; // index into the before segments (null = not present on the before side)
  b: number | null; // index into the after segments (null = not present on the after side)
}

/** Longest-common-subsequence alignment of two key lists → matched / removed / added ops. */
function lcsAlign(aKeys: string[], bKeys: string[]): AlignOp[] {
  const n = aKeys.length;
  const m = bKeys.length;
  // dp[i][j] = LCS length of aKeys[i:] and bKeys[j:].
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] =
        aKeys[i] === bKeys[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const ops: AlignOp[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (aKeys[i] === bKeys[j]) {
      ops.push({ a: i, b: j });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      ops.push({ a: i, b: null }); // removed (present only in before)
      i++;
    } else {
      ops.push({ a: null, b: j }); // added (present only in after)
      j++;
    }
  }
  while (i < n) {
    ops.push({ a: i, b: null });
    i++;
  }
  while (j < m) {
    ops.push({ a: null, b: j });
    j++;
  }
  return ops;
}

function diffFields(
  fa: string[],
  fb: string[],
): { beforeFields: DiffField[]; afterFields: DiffField[]; changed: boolean } {
  const max = Math.max(fa.length, fb.length);
  const beforeFields: DiffField[] = [];
  const afterFields: DiffField[] = [];
  let changed = false;
  for (let k = 0; k < max; k++) {
    const c = (fa[k] ?? "") !== (fb[k] ?? "");
    if (c) {
      changed = true;
    }
    if (k < fa.length) {
      beforeFields.push({ t: fa[k], c });
    }
    if (k < fb.length) {
      afterFields.push({ t: fb[k], c });
    }
  }
  return { beforeFields, afterFields, changed };
}

/**
 * Build an aligned, field-granular diff of two HL7 (or arbitrary) message bodies. `before[i]` and
 * `after[i]` always line up: an inserted segment gets a gap cell on the before side (and vice
 * versa), so the side-by-side view stays in register and no following segment is falsely "changed".
 */
export function diffMessages(beforeText: string, afterText: string): MessageDiff {
  const a = parseMessage(beforeText);
  const b = parseMessage(afterText);
  const ops = lcsAlign(a.segments.map(segKey), b.segments.map(segKey));
  const aSep = a.enc.field;
  const bSep = b.enc.field;

  const before: DiffCell[] = [];
  const after: DiffCell[] = [];
  for (const op of ops) {
    if (op.a !== null && op.b !== null) {
      const { beforeFields, afterFields, changed } = diffFields(
        a.segments[op.a].fields,
        b.segments[op.b].fields,
      );
      const status: LineStatus = changed ? "changed" : "same";
      before.push({ seg: true, status, fields: beforeFields, sep: aSep });
      after.push({ seg: true, status, fields: afterFields, sep: bSep });
    } else if (op.a !== null) {
      // Removed: present only in before; a gap holds its place on the after side.
      const fields = a.segments[op.a].fields.map((t) => ({ t, c: true }));
      before.push({ seg: true, status: "removed", fields, sep: aSep });
      after.push({ seg: false, status: "removed", fields: [], sep: bSep });
    } else if (op.b !== null) {
      // Added: present only in after; a gap holds its place on the before side.
      const fields = b.segments[op.b].fields.map((t) => ({ t, c: true }));
      before.push({ seg: false, status: "added", fields: [], sep: aSep });
      after.push({ seg: true, status: "added", fields, sep: bSep });
    }
  }
  return { before, after };
}
