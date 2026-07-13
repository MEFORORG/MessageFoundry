// Pure segment ranking for the HL7 field picker (ADR 0104 §2.3 P2). Given a handler's recognized message
// type (from `accepts=message_type_of(...)` or an inferred guard) + the sample's segments, partition the
// schema's segments into visibly distinct groups — in-scope first, then Z-segments and other sample
// segments unioned in, then "All segments". It RANKS, never removes: every schema segment is present, an
// "All segments" escape is always available, and a scope MISS reads differently from a Z-segment fallback.
// No vscode / I/O — unit-testable.
import type { Hl7Structures } from "./hl7schema";
import type { PickScope, SegItem } from "./hl7Picker";

const IN_TYPE = "In this message type";
const Z_IN_SAMPLE = "Z-segments (from the sample)";
const ALSO_IN_SAMPLE = "Also in the sample";
const ALL = "All segments";

/** The distinct 3-char segment ids that lead a line in a (synthetic, PHI-safe) sample message. */
export function sampleSegments(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split(/\r\n|\r|\n/)) {
    const m = /^([A-Z][A-Z0-9]{2})\|/.exec(line);
    if (m && !out.includes(m[1])) {
      out.push(m[1]);
    }
  }
  return out;
}

/** Structure ids for a handler's `accepts=` specs (or a single inferred type); `[]` if unresolvable
 *  (→ generic, unscoped picker). An explicit 3-component spec (`"ADT^A01^ADT_A05"`) uses its structure
 *  id directly; a 2-component spec resolves via the version-pinned trigger→structure map. */
export function resolveStructureIds(
  structures: Hl7Structures,
  acceptsTypes: string[] | undefined,
  inferredType: { code?: string; trigger?: string } | undefined,
): string[] {
  const ids = new Set<string>();
  const add = (code?: string, trigger?: string, explicit?: string): void => {
    if (explicit) {
      ids.add(explicit);
      return;
    }
    if (code && trigger) {
      const s = structures.triggerToStructure[`${code}^${trigger}`];
      if (s) {
        ids.add(s);
      }
    }
  };
  if (acceptsTypes?.length) {
    for (const spec of acceptsTypes) {
      const [code, trigger, structure] = spec.split("^");
      add(code, trigger, structure);
    }
  } else if (inferredType?.code) {
    add(inferredType.code, inferredType.trigger);
  }
  return [...ids];
}

/**
 * Rank the schema's segments for a handler's message type. Returns `undefined` (→ generic, unscoped) when
 * there is no structures artifact or the type is unresolvable. Otherwise every `allSegments` entry appears
 * exactly once (in-scope / sample-only / all-segments), the sample's Z-segments are unioned in, and a
 * scope miss is labelled `not in <STRUCTURE>` — distinct from the `Z-segment · site-custom` fallback.
 */
export function buildSegmentScope(
  allSegments: string[],
  structures: Hl7Structures | undefined,
  acceptsTypes: string[] | undefined,
  inferredType: { code?: string; trigger?: string } | undefined,
  sample: string[],
): PickScope | undefined {
  if (!structures) {
    return undefined;
  }
  const structureIds = resolveStructureIds(structures, acceptsTypes, inferredType);
  if (!structureIds.length) {
    return undefined; // unresolvable → the picker offers the generic segment list
  }
  const inScope = new Set<string>(
    structureIds.flatMap((s) => structures.structureSegments[s] ?? []),
  );
  const sampleSet = new Set(sample);
  const label = structureIds.join(", ");
  const groups: SegItem[] = [];
  // 1. In-scope standard segments — the ranked top.
  for (const seg of allSegments) {
    if (inScope.has(seg)) {
      groups.push({ segment: seg, group: IN_TYPE, description: "" });
    }
  }
  // 2. Z-segments from the sample (there is no Z source in the schema, so they are unioned in here).
  for (const seg of sample) {
    if (seg.startsWith("Z") && !inScope.has(seg)) {
      groups.push({ segment: seg, group: Z_IN_SAMPLE, description: "Z-segment · site-custom" });
    }
  }
  // 3. Standard segments present in the sample but not in the scoped structure.
  for (const seg of allSegments) {
    if (!inScope.has(seg) && !seg.startsWith("Z") && sampleSet.has(seg)) {
      groups.push({ segment: seg, group: ALSO_IN_SAMPLE, description: "in sample" });
    }
  }
  // 4. Everything else — a scope MISS, visibly distinct from a sanctioned Z/sample fallback.
  for (const seg of allSegments) {
    if (!inScope.has(seg) && !sampleSet.has(seg)) {
      groups.push({ segment: seg, group: ALL, description: `not in ${label}` });
    }
  }
  return { structureIds, groups };
}
