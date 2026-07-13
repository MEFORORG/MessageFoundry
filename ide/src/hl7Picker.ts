// The Steps-view HL7 field picker (ADR 0104 §2.3): a native cascading segment -> field -> component
// quick-pick that produces a path literal (e.g. "PID-3.1"). It NEVER blocks a path — free-text is
// reachable at every stage, so Z-segments / site-custom / cross-version paths are always typeable
// (rank, never remove). The picked string is written through the SAME `lens rewrite` splice a typed
// edit uses (see stepsView.ts `applyPickedEdit`), so there is no new artifact and no new .py execution
// path (ADR 0089/0076). P2 (scope ranking) and P3 (round-trip badges) plug into the marked hooks.
import * as vscode from "vscode";
import {
  Hl7Schema,
  Hl7Structures,
  componentsOf,
  fieldsOf,
  segmentsOf,
} from "./hl7schema";

/** One segment offered at the first stage, already grouped/labelled by P2 scope (rank, never remove). */
export interface SegItem {
  segment: string;
  group: string; // separator label this segment sits under (e.g. "In this message type", "All segments")
  description: string; // distinct per group so a scope MISS reads differently from a Z/sample fallback
}
/** Precomputed P2 ranking; `undefined`/empty groups => the generic (unscoped) segment list. */
export interface PickScope {
  structureIds: string[];
  groups: SegItem[];
}
export interface PickOpts {
  mode?: "path" | "segment"; // "segment" = a segment-only slot (e.g. delete_segment); no field/component
  scope?: PickScope; // P2
  verified?: Hl7Structures["verified"]; // P3 — segment -> round-trip-proven fields/components (for the badge)
  seed?: string; // the slot's current value, used to seed the manual free-text escape
}

const MANUAL_LABEL = "$(edit) Enter path manually…";
const UNVERIFIED = "⚠ unverified round-trip"; // ⚠ — P3 badge on a path not proven to round-trip

function manualItem(): vscode.QuickPickItem {
  return { label: MANUAL_LABEL, alwaysShow: true };
}
function separator(label: string): vscode.QuickPickItem {
  return { label, kind: vscode.QuickPickItemKind.Separator };
}

async function freeText(seed: string, prompt: string): Promise<string | undefined> {
  const v = await vscode.window.showInputBox({ value: seed, prompt, ignoreFocusOut: true });
  if (v === undefined) return undefined; // cancelled
  const t = v.trim();
  return t.length ? t : undefined;
}

// --- stage 1: segment ---------------------------------------------------------------------------

async function pickSegment(
  schema: Hl7Schema,
  opts: PickOpts,
): Promise<{ seg: string } | { manual: true } | undefined> {
  const items: vscode.QuickPickItem[] = [manualItem()];
  const scoped = opts.scope?.groups.length ? opts.scope.groups : undefined;
  if (scoped) {
    // P2: rank-not-remove — every schema segment is present, partitioned into visibly distinct groups.
    let group: string | undefined;
    for (const s of scoped) {
      if (s.group !== group) {
        items.push(separator(s.group));
        group = s.group;
      }
      items.push({ label: s.segment, description: s.description });
    }
  } else {
    items.push(separator("Segments"));
    for (const seg of segmentsOf(schema)) items.push({ label: seg });
  }
  const pick = await vscode.window.showQuickPick(items, {
    title: "HL7 segment",
    placeHolder: "Pick a segment (e.g. PID) — or “Enter path manually…” to type any path",
    ignoreFocusOut: true,
    matchOnDescription: true,
  });
  if (pick === undefined) return undefined;
  if (pick.label === MANUAL_LABEL) return { manual: true };
  return { seg: pick.label };
}

// --- stage 2: field -----------------------------------------------------------------------------

function fieldDescription(name: string | null, datatype: string | null, verified: boolean): string {
  const base = name ?? datatype ?? "";
  return verified ? base : base ? `${base}  ·  ${UNVERIFIED}` : UNVERIFIED;
}

async function pickField(
  schema: Hl7Schema,
  seg: string,
  opts: PickOpts,
): Promise<string | undefined> {
  const fields = fieldsOf(schema, seg);
  if (!fields.length) {
    // Unknown/empty segment (e.g. a Z-segment): drop straight to free-text for the whole path.
    return freeText(opts.seed || `${seg}-`, `Path in ${seg} (e.g. ${seg}-1)`);
  }
  const vseg = opts.verified?.[seg];
  const items: vscode.QuickPickItem[] = [manualItem(), separator(`${seg} fields`)];
  // P3: verified fields first, then unverified (still offered, badged) — rank, never remove.
  const ranked = [...fields].sort((a, b) => {
    const av = vseg ? (vseg.fields.includes(a.index) ? 0 : 1) : 0;
    const bv = vseg ? (vseg.fields.includes(b.index) ? 0 : 1) : 0;
    return av - bv || a.index - b.index;
  });
  for (const f of ranked) {
    const ok = vseg ? vseg.fields.includes(f.index) : true;
    items.push({ label: `${seg}-${f.index}`, description: fieldDescription(f.name, f.datatype, ok) });
  }
  const pick = await vscode.window.showQuickPick(items, {
    title: `HL7 field · ${seg}`,
    placeHolder: "Pick a field — or “Enter path manually…”",
    ignoreFocusOut: true,
    matchOnDescription: true,
  });
  if (pick === undefined) return undefined;
  if (pick.label === MANUAL_LABEL) return freeText(opts.seed || `${seg}-`, `Path in ${seg}`);
  const fieldIndex = Number.parseInt(pick.label.slice(seg.length + 1), 10);
  if (!componentsOf(schema, seg, fieldIndex).length) return pick.label; // no components -> whole field
  return pickComponent(schema, seg, fieldIndex, opts);
}

// --- stage 3: component -------------------------------------------------------------------------

async function pickComponent(
  schema: Hl7Schema,
  seg: string,
  fieldIndex: number,
  opts: PickOpts,
): Promise<string | undefined> {
  const whole = `${seg}-${fieldIndex}`;
  const comps = componentsOf(schema, seg, fieldIndex);
  const vseg = opts.verified?.[seg];
  const items: vscode.QuickPickItem[] = [
    manualItem(),
    { label: whole, description: "(whole field)" },
    separator(`${whole} components`),
  ];
  for (const c of comps) {
    const label = `${whole}.${c.index}`;
    const ok = vseg ? vseg.components.includes(`${fieldIndex}.${c.index}`) : true;
    items.push({ label, description: fieldDescription(c.name, c.datatype, ok) });
  }
  const pick = await vscode.window.showQuickPick(items, {
    title: `HL7 component · ${whole}`,
    placeHolder: "Pick a component, the whole field, or “Enter path manually…”",
    ignoreFocusOut: true,
    matchOnDescription: true,
  });
  if (pick === undefined) return undefined;
  if (pick.label === MANUAL_LABEL) return freeText(opts.seed || `${whole}.`, `Path in ${whole}`);
  return pick.label;
}

/**
 * Run the cascading picker and return the chosen HL7 path (e.g. `"PID-3.1"`), or `undefined` if the
 * user cancelled at any stage. `mode: "segment"` returns just a segment id. Free-text is always
 * reachable, so the picker never blocks a path.
 */
export async function pickHl7Path(schema: Hl7Schema, opts: PickOpts = {}): Promise<string | undefined> {
  const first = await pickSegment(schema, opts);
  if (first === undefined) return undefined;
  if ("manual" in first) {
    return freeText(opts.seed ?? "", opts.mode === "segment" ? "Segment id" : "HL7 path (e.g. PID-3.1)");
  }
  if ((opts.mode ?? "path") === "segment") return first.seg;
  return pickField(schema, first.seg, opts);
}
