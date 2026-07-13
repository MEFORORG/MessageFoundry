// Shared HL7 v2 schema access for the code-view completion (completion.ts) and the Steps-view field
// picker (hl7Picker.ts). Single source for the bundled hl7schema.json shape + segment ordering + the
// segment/field/component enumeration primitives, so the two surfaces cannot drift. No per-keystroke
// Python — everything is answered from in-memory bundled data (ADR 0104 §2.3).
import * as fs from "node:fs";
import * as path from "node:path";

export interface Hl7Component {
  index: number;
  name: string | null;
  datatype: string | null;
}
export interface Hl7Field {
  index: number;
  name: string | null;
  datatype: string | null;
  components: Hl7Component[];
}
export interface Hl7Schema {
  version: string;
  segments: Record<string, { fields: Hl7Field[] }>;
}

/** The optional message-structure + round-trip-verified artifact (ide/media/hl7structures.json), added
 *  by ADR 0104 §2.3 P2/P3. Absent until that build lands — every consumer treats `undefined` as "no
 *  scope / nothing verified" and degrades to the generic, always-offered path list. */
export interface Hl7Structures {
  version: string;
  sentinel?: string; // the delimiter-free token the P3 round-trip gate wrote (documentation only)
  triggerToStructure: Record<string, string>; // "CODE^TRIGGER" -> structure id (e.g. "ADT^A08" -> "ADT_A01")
  structureSegments: Record<string, string[]>; // structure id -> ordered segment ids
  verified?: Record<string, { fields: number[]; components: string[] }>; // segment -> round-trip-proven paths
}

function loadJson<T>(extensionPath: string, file: string): T | undefined {
  try {
    return JSON.parse(fs.readFileSync(path.join(extensionPath, "media", file), "utf8")) as T;
  } catch {
    return undefined; // missing/corrupt bundle -> the caller degrades gracefully
  }
}

export function loadSchema(extensionPath: string): Hl7Schema | undefined {
  return loadJson<Hl7Schema>(extensionPath, "hl7schema.json");
}

/** P2/P3 artifact; `undefined` until the §2.3 P2 build generates it. */
export function loadStructures(extensionPath: string): Hl7Structures | undefined {
  return loadJson<Hl7Structures>(extensionPath, "hl7structures.json");
}

// Most-used HL7 segments float to the top of a segment list (the rest stay alphabetical).
export const COMMON_SEGMENTS = [
  "MSH", "PID", "PV1", "EVN", "OBR", "ORC", "OBX", "MSA",
  "NK1", "AL1", "DG1", "IN1", "GT1", "RXA", "RXR", "SPM", "SCH", "AIS",
];

export function segmentSortText(seg: string): string {
  const rank = COMMON_SEGMENTS.indexOf(seg);
  return rank >= 0 ? `0${String(rank).padStart(2, "0")}` : `1${seg}`;
}

// --- enumeration primitives (shared by completion.ts and hl7Picker.ts) ---------------------------

/** All segment ids in the schema, in COMMON_SEGMENTS-first then alphabetical order. */
export function segmentsOf(schema: Hl7Schema): string[] {
  return Object.keys(schema.segments).sort((a, b) =>
    segmentSortText(a).localeCompare(segmentSortText(b)),
  );
}

/** The fields of `seg` (empty if the segment is unknown). */
export function fieldsOf(schema: Hl7Schema, seg: string): Hl7Field[] {
  return schema.segments[seg]?.fields ?? [];
}

/** The components of `seg-fieldIndex` (empty if the field is unknown or has none). */
export function componentsOf(schema: Hl7Schema, seg: string, fieldIndex: number): Hl7Component[] {
  return fieldsOf(schema, seg).find((f) => f.index === fieldIndex)?.components ?? [];
}
