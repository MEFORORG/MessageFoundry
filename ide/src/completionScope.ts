// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
// Pure completion-scope helpers for the code-view inline autocomplete (ADR 0104 §2.3 Step 1,
// BACKLOG #230 P2/P3). Every unit-tested helper lives HERE — completion.ts imports vscode at its
// line 4 and `npm run test:unit` is plain-node mocha — so: no vscode import, no I/O, no Python.
//
// Two jobs:
//  1. Message-type ranking for the SEGMENT completion stage: read the enclosing @handler's
//     declared types straight from the document text (`accepts=message_type_of("…")` and the
//     inert, IDE-read-only `message_type=` kwarg — ADR 0104 §2.3), resolve them through the
//     bundled version-pinned hl7structures artifact, and map hl7scope's groups onto sortText
//     prefixes. Hard invariants: RANK-NEVER-REMOVE (every schema segment is offered exactly
//     once; a miss is visibly labelled, never hidden), and the ranked scope is the pinned 2.5.1
//     superset as the shipped Steps picker presents it — never per-feed truth. No artifact / no
//     resolvable type → `undefined`, and the caller keeps today's segmentSortText order
//     byte-identically.
//  2. KWARG_CTX: decide when the cursor sits in the keyword-argument position of
//     `.set(…)`/`.field(…)` — after the path argument and NOT inside any string literal — so
//     completion.ts can offer the `occurrence=`/`repetition=` snippets. Single-line prefix only
//     (a `.set(` call spread across lines does not fire) — an accepted limitation.
import type { Hl7Structures } from "./hl7schema";
import { segmentSortText } from "./hl7schema";
import { buildSegmentScope } from "./hl7scope";

// --- enclosing-handler message types --------------------------------------------------------------

// A top-level (column-0) function def, like symbolIndex.ts's DEF_RE: the `^` with no leading-
// whitespace class deliberately excludes indented method/nested defs.
const DEF_RE = /^(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(/;

/** `line` with single-line string-literal contents blanked (quotes kept) and any `#` comment
 *  dropped, so bracket counting and `@` head detection can't be fooled by quoted/commented text.
 *  A triple-quoted string inside a decorator is out of (accepted) scope for this text pass. */
function maskLine(line: string): string {
  let out = "";
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === "\\" && i + 1 < line.length) {
        out += "  ";
        i++;
        continue;
      }
      if (ch === quote) {
        quote = null;
        out += ch;
        continue;
      }
      out += " ";
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      out += ch;
      continue;
    }
    if (ch === "#") {
      return out; // comment — the rest of the line is inert
    }
    out += ch;
  }
  return out;
}

/** Net bracket balance of a masked line: `([{` minus `)]}`. */
function bracketDelta(masked: string): number {
  let d = 0;
  for (const ch of masked) {
    if (ch === "(" || ch === "[" || ch === "{") {
      d++;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      d--;
    }
  }
  return d;
}

/** Every string literal directly or transitively inside the call whose open paren precedes
 *  `openIdx` (i.e. scan starts at depth 1), stopping at the matching close. `#` comments inside a
 *  multi-line call are skipped to end-of-line. */
function stringLiteralsInCall(text: string, openIdx: number): string[] {
  const out: string[] = [];
  let depth = 1;
  let i = openIdx;
  while (i < text.length && depth > 0) {
    const ch = text[i];
    if (ch === '"' || ch === "'") {
      const q = ch;
      let lit = "";
      i++;
      while (i < text.length && text[i] !== q) {
        lit += text[i] === "\\" && i + 1 < text.length ? text[++i] : text[i];
        i++;
      }
      i++; // past the closing quote
      if (lit) {
        out.push(lit);
      }
      continue;
    }
    if (ch === "#") {
      const nl = text.indexOf("\n", i);
      i = nl < 0 ? text.length : nl;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") {
      depth++;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      depth--;
    }
    i++;
  }
  return out;
}

/** Message-type specs declared in a captured decorator run: every string literal inside
 *  `accepts=message_type_of(…)` plus the inert `message_type="…"` documentation kwarg (both are
 *  read here by the IDE only — never interpreted into engine behavior). */
function typesFromRun(run: string[]): string[] | undefined {
  if (run.length === 0) {
    return undefined;
  }
  const text = run.join("\n");
  const specs: string[] = [];
  const acceptsRe = /\baccepts\s*=\s*message_type_of\s*\(/g;
  while (acceptsRe.exec(text) !== null) {
    specs.push(...stringLiteralsInCall(text, acceptsRe.lastIndex));
  }
  // `message_type_of` never matches here: its "message_type" is followed by "_of", not "=".
  const kwargRe = /(?<![\w.])message_type\s*=\s*(["'])([^"'\\]*)\1/g;
  let m: RegExpExecArray | null;
  while ((m = kwargRe.exec(text)) !== null) {
    if (m[2]) {
      specs.push(m[2]);
    }
  }
  const unique = [...new Set(specs)];
  return unique.length ? unique : undefined;
}

/**
 * The message-type specs (`"ADT^A01"`-style, deduped) declared on the handler enclosing
 * 0-based `line`, or `undefined` when there is no enclosing typed handler (→ the caller keeps the
 * generic, unscoped completion).
 *
 * Pure text pass (no interpreter): walk up to the nearest column-0 `def` — indented (nested) defs
 * never match, and any other column-0 code line first means the cursor is at module level (a
 * column-0 `)`-led line is tolerated: ruff formats a long signature's `) -> …:` at column 0).
 * Then capture the CONTIGUOUS decorator run above it. Unlike symbolIndex.ts's classify() (a
 * documented single-line pass), the capture balances brackets across lines, so a multi-line
 * `@handler(…)` call is read whole; blank/comment lines inside the run are tolerated. A column-0
 * line inside a module-level triple-quoted string can end the walk early — accepted for a text
 * pass; the failure mode is only the generic (unscoped) order.
 */
export function enclosingHandlerTypes(documentText: string, line: number): string[] | undefined {
  const lines = documentText.split(/\r?\n/);
  if (lines.length === 0) {
    return undefined;
  }
  const at = Math.min(Math.max(line, 0), lines.length - 1);

  let defIdx = -1;
  for (let i = at; i >= 0; i--) {
    if (DEF_RE.test(lines[i])) {
      defIdx = i;
      break;
    }
    if (/^[^\s#@)\]}]/.test(lines[i])) {
      return undefined; // column-0 code before any def — the cursor is not inside a handler body
    }
  }
  if (defIdx < 0) {
    return undefined;
  }

  // Capture the contiguous decorator run above the def, bottom-up. `pending` holds the lines of a
  // multi-line construct being balanced upward; `need` is how many opens are still required above.
  const run: string[] = [];
  let pending: string[] | null = null;
  let need = 0;
  for (let i = defIdx - 1; i >= 0; i--) {
    const raw = lines[i];
    const masked = maskLine(raw);
    if (pending) {
      pending.unshift(raw);
      need -= bracketDelta(masked);
      if (need <= 0) {
        if (!/^\s*@/.test(pending[0])) {
          break; // a balanced multi-line block that is NOT a decorator ends the run
        }
        run.unshift(...pending);
        pending = null;
        need = 0;
      }
      continue;
    }
    const t = masked.trim();
    if (t === "") {
      continue; // blank / pure-comment lines are legal between decorators and the def
    }
    const delta = bracketDelta(masked);
    if (delta < 0) {
      pending = [raw]; // the last line of a multi-line construct — balance it upward
      need = -delta;
      continue;
    }
    if (delta === 0 && t.startsWith("@")) {
      run.unshift(raw); // a complete single-line decorator
      continue;
    }
    break; // any other code line ends the contiguous decorator run
  }
  return typesFromRun(run);
}

// --- segment ranking -------------------------------------------------------------------------------

/** One segment's completion rank + label extras under a resolved message-type scope. */
export interface SegmentRank {
  /** Replaces segmentSortText: `0…` in-scope, `2…` otherwise — each tier wrapping today's
   *  segmentSortText so the COMMON_SEGMENTS-first sub-order is preserved inside the tier.
   *  (`1…` is deliberately left free between the tiers.) */
  sortText: string;
  /** `""` for an in-scope segment; the visible `not in <STRUCTURE>` miss marker otherwise. */
  description: string;
}

/**
 * Rank the schema's segments for a handler's declared message types (rank, never remove). Reuses
 * the shipped picker's buildSegmentScope with `sample=[]` — the code editor has no sample context —
 * which yields exactly two tiers: in-scope (empty description) and the labelled misses; the
 * `not in <STRUCTURE>` text is authored in hl7scope.ts alone, so the two surfaces cannot drift.
 * Returns `undefined` (no structures artifact / unresolvable or absent types) so the caller keeps
 * today's segmentSortText order BYTE-IDENTICALLY.
 */
export function scopedSegmentSortText(
  allSegments: string[],
  structures: Hl7Structures | undefined,
  acceptsTypes: string[] | undefined,
): Map<string, SegmentRank> | undefined {
  const scope = buildSegmentScope(allSegments, structures, acceptsTypes, undefined, []);
  if (!scope) {
    return undefined;
  }
  const out = new Map<string, SegmentRank>();
  for (const g of scope.groups) {
    out.set(g.segment, {
      sortText: (g.description === "" ? "0" : "2") + segmentSortText(g.segment),
      description: g.description,
    });
  }
  return out;
}

// --- KWARG_CTX -------------------------------------------------------------------------------------

/** A cursor in the keyword-argument position of `.set(…)`/`.field(…)`. */
export interface KwargContext {
  /** The partially-typed identifier at the cursor (`""` straight after `", "`). */
  partial: string;
  /** Kwarg names already written inside the call — the caller must not offer a duplicate. */
  present: string[];
}

const KWARG_NAMES = ["occurrence", "repetition"] as const;

/**
 * Fire iff the single-line `prefix` ends inside a `.set(…)`/`.field(…)` call, past the path
 * argument (≥ 1 top-level comma), NOT inside any string literal (neither the path nor a value
 * literal like `msg.set("PID-3.1", "abc` — the naive regex's own failure case), not in a comment,
 * and with nothing but a bare (part-typed) identifier in the current argument slot (so it never
 * fires after `occurrence=` or a closed expression). `Send("…")`/`router="…"` never match: the
 * callee must be exactly `.set`/`.field`. Multi-line `.set(` calls don't fire (single-line-prefix
 * limitation, accepted).
 */
export function kwargContext(prefix: string): KwargContext | undefined {
  interface Frame {
    callee: string;
    commas: number;
    argStart: number; // index just past the last top-level comma (or the open paren)
    start: number; // index just past the open paren
  }
  const stack: Frame[] = [];
  let masked = ""; // prefix with string contents blanked, index-aligned with prefix
  let quote: string | null = null;
  for (let i = 0; i < prefix.length; i++) {
    const ch = prefix[i];
    if (quote) {
      if (ch === "\\" && i + 1 < prefix.length) {
        masked += "  ";
        i++;
        continue;
      }
      if (ch === quote) {
        quote = null;
        masked += ch;
        continue;
      }
      masked += " ";
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      masked += ch;
      continue;
    }
    if (ch === "#") {
      return undefined; // the cursor is in a comment
    }
    masked += ch;
    if (ch === "(") {
      // The callee token immediately before the paren (whitespace tolerated), dot-qualified.
      let j = i - 1;
      while (j >= 0 && /\s/.test(prefix[j])) {
        j--;
      }
      const end = j;
      while (j >= 0 && /\w/.test(prefix[j])) {
        j--;
      }
      const name = prefix.slice(j + 1, end + 1);
      stack.push({
        callee: j >= 0 && prefix[j] === "." ? `.${name}` : name,
        commas: 0,
        argStart: i + 1,
        start: i + 1,
      });
    } else if (ch === "[" || ch === "{") {
      stack.push({ callee: "", commas: 0, argStart: i + 1, start: i + 1 });
    } else if (ch === ")" || ch === "]" || ch === "}") {
      stack.pop();
    } else if (ch === "," && stack.length > 0) {
      const f = stack[stack.length - 1];
      f.commas++;
      f.argStart = i + 1;
    }
  }
  if (quote) {
    return undefined; // inside a string literal — the path (PATH_CTX's turf) or a value
  }
  const top = stack[stack.length - 1];
  if (!top || (top.callee !== ".set" && top.callee !== ".field") || top.commas < 1) {
    return undefined; // not in a .set/.field call, or still on the path argument
  }
  const partial = /[A-Za-z_]\w*$/.exec(prefix)?.[0] ?? "";
  const argSoFar = masked.slice(top.argStart, masked.length - partial.length).trim();
  if (argSoFar !== "") {
    return undefined; // mid-value (`occurrence=…`, a closed expression, …) — a kwarg is not legal here
  }
  const present = KWARG_NAMES.filter((n) =>
    new RegExp(`\\b${n}\\s*=`).test(masked.slice(top.start)),
  );
  return { partial, present };
}

/** The two keyword-only kwargs of `Message.set()`/`Message.field()` offered in KWARG_CTX. Pure
 *  data (completion.ts turns them into SnippetString items); docs quote the 1-based semantics
 *  from `messagefoundry/parsing/message.py` (`set()` / `field()`). */
export interface KwargSnippet {
  name: (typeof KWARG_NAMES)[number];
  label: string; // what the suggest list shows / filters on
  insert: string; // VS Code snippet body
  detail: string;
  doc: string; // markdown
}

export const KWARG_SNIPPETS: readonly KwargSnippet[] = [
  {
    name: "occurrence",
    label: "occurrence=",
    insert: "occurrence=${1:2}",
    detail: "which segment of that id (1-based)",
    doc:
      "**1-based**, keyword-only, default `1` — selects which segment of that id the read/write " +
      "targets. From `Message.set()`/`Message.field()` (`messagefoundry/parsing/message.py`): " +
      "“`occurrence` (1-based) selects which segment of that id to write — `occurrence=2` edits " +
      "the **second** `OBX`.”",
  },
  {
    name: "repetition",
    label: "repetition=",
    insert: "repetition=${1:1}",
    detail: "which field repetition (1-based)",
    doc:
      "**1-based**, keyword-only, default `None` — scopes the read/write to one field repetition. " +
      "From `Message.set()`/`Message.field()` (`messagefoundry/parsing/message.py`): “`repetition` " +
      "(1-based) scopes the write to one field repetition: a component write edits that repetition " +
      "(padding earlier reps if needed) and preserves the others”; the default keeps whole-field / " +
      "first-repetition behavior.",
  },
];
