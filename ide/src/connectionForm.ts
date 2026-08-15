// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
// Schema-driven connection form model (ADR 0007) — PURE, like connectionMerge.ts: this module must
// never import vscode (`npm run test:unit` is plain-node mocha). It turns the ENGINE's
// `connection schema --json` plus one connection's `settings` table into the ordered, grouped field
// descriptors the webview renders.
//
// It replaces the editor's hand-written HINTS table (connectionEditor.ts — 6 transport:direction
// combos, key NAMES only) and its free-text key/value rows: the installed engine now declares which
// settings exist per transport, with type, default, help, direction, choices and secrecy, so the form
// renders whatever THAT engine supports instead of a stale TypeScript mirror. Two invariants make a
// schema-driven form safe to save over an existing connections.toml:
//
//  1. NOTHING ON THE RECORD IS EVER DROPPED. A settings key this engine's schema does not describe —
//     an older/newer engine, a hand-authored key, a leftover from the other direction — still gets a
//     descriptor (see UNKNOWN_GROUP / `known` / `offDirection`), so the save round-trips it instead
//     of silently deleting it. `connection upsert` is a FULL REPLACE of the table, so a key the form
//     fails to render is a key the form DELETES.
//  2. A DEFAULT IS A PLACEHOLDER, NEVER A VALUE. `value` is populated only from the record; the
//     schema default lands in `placeholder`/`defaultValue`, which are render-only. Saving an
//     untouched form therefore does not write the engine's entire default set into the file — absent
//     still means "whatever this engine defaults to", which is what keeps a config upgrade-safe.
//
// Ordering note: the field order inside a group is the schema's key order, which is the factory's
// signature order (JSON object key order survives JSON.parse). That is deliberate — the authors
// already ordered those parameters for humans.

/** The coarse type tag `connection schema --json` reports for a setting. */
export type ParamType = "str" | "int" | "float" | "bool" | "table" | "unknown";

export type Direction = "inbound" | "outbound";

/** The control the webview should render for a field. */
export type FieldControl = "text" | "number" | "checkbox" | "select" | "table";

/**
 * One setting as the engine describes it (schemaVersion 1). Every property is optional here even
 * though the engine always emits them: this type also has to survive a schema produced by a DIFFERENT
 * engine build than the one this extension was written against, and a missing property must degrade
 * (unknown type → a text control) rather than throw while drawing a form.
 */
export interface SchemaParam {
  type?: ParamType;
  choices?: unknown[] | null;
  /** The factory's default. Render-only — see invariant 2 above. */
  default?: unknown;
  /** No default at all in the factory, i.e. omitting it raises. */
  required?: boolean;
  /** The parameter's comment says "required" (e.g. mandatory only outbound). */
  requiredHint?: boolean;
  /** May be written as `{env = "KEY"}`. */
  env?: boolean;
  /** Credential-bearing (the engine's `_is_secret_setting`). */
  secret?: boolean;
  /** The direction it applies to; null/absent = both. */
  direction?: Direction | null;
  help?: string;
  /** A group heading. The engine emits it on the FIRST parameter of a block only. */
  section?: string;
}

export interface TransportSchema {
  doc?: string;
  params?: Record<string, SchemaParam>;
}

/** The whole `connection schema --json` document. */
export interface ConnectionSchema {
  schemaVersion: number;
  transports: Record<string, TransportSchema>;
  /** The per-direction connection-level key sets (NOT settings keys) — carried for completeness. */
  directionKeys?: Record<Direction, string[]>;
}

/** The emitted shape this module understands. The engine bumps it when a consumer must notice. */
export const SUPPORTED_SCHEMA_VERSION = 1;

/**
 * Whether this build can round-trip the fetched schema. The engine's contract is that the IDE
 * REFUSES a schema whose version it does not understand rather than rendering a form it cannot save
 * faithfully; the caller does the refusing, this is the predicate.
 */
export function isSupportedSchemaVersion(schema: ConnectionSchema | undefined): boolean {
  return schema?.schemaVersion === SUPPORTED_SCHEMA_VERSION;
}

/** Required-for-this-direction settings. First, never collapsed. */
export const ESSENTIAL_GROUP = "Essential";
/** Schema-described settings that belong to no section heading. */
export const OTHER_GROUP = "Other settings";
/** Keys the record carries that this engine's schema does not describe (invariant 1). */
export const UNKNOWN_GROUP = "On this record (not in this engine's schema)";

/**
 * One rendered field. `key` is the TOML settings key and doubles as the label: users author
 * connections.toml by hand too, and the engine's own errors name the raw key, so prettifying it into
 * "Max frame bytes" would just cost them the mapping.
 *
 * VALUE vs DEFAULT vs ENV — the three slots the renderer must keep apart:
 *  - `value`     the literal currently on the record, or undefined when the record does not set the
 *                key. NEVER populated from the schema default (invariant 2), and never populated for
 *                a secret (a credential is not displayed).
 *  - `placeholder` / `defaultValue`  the schema default, RENDER-ONLY: show it as a greyed hint (or
 *                as a checkbox's unset position), never as the control's value, and never post it.
 *  - `envKey` / `cast` / `envDefault`  set when the record holds the `{env = "KEY"}` inline table;
 *                the caller rebuilds `{env, cast?, default?}` from them. `cast`/`envDefault` exist so
 *                the two optional keys an env table may carry survive a save untouched.
 */
export interface FieldDescriptor {
  /** The settings key, exactly as it appears in connections.toml. */
  key: string;
  /** What to print above the control (the key, plus a marker where the control is not the value). */
  label: string;
  control: FieldControl;
  /** The schema's type tag, kept so `coerce` and the caller can round-trip the exact JSON type. */
  type: ParamType;
  help: string;
  /**
   * BLOCKING: the factory declares no default, so it raises without this. Only this flag may gate a
   * save.
   *
   * Deliberately NOT derived from the schema's `requiredHint`, which the engine uses for three
   * different things: direction-conditional (`mllp.host`, required outbound), value-conditional
   * (`mllp.tls_cert_file`, "required when tls") and sibling-conditional (`database.database`,
   * "required for dialect='sqlserver'; optional for 'generic'"). Treating the hint as blocking made
   * a plain non-TLS inbound MLLP listener unsavable -- the commonest connection in the product.
   */
  required: boolean;
  /**
   * The help text says "required" in some circumstance the schema cannot express. Worth a marker,
   * and worth hoisting into Essential, but it must NEVER block a save: only the engine can judge the
   * condition, and it already does so loudly at load.
   */
  conditionallyRequired: boolean;
  /** Credential-bearing: never render this value, never accept a literal (see `secretOnlyEnv`). */
  secret: boolean;
  /** The engine accepts `{env = "KEY"}` for this setting. */
  envAllowed: boolean;
  /**
   * The env-reference form is the ONLY form offered: there is no plaintext control at all, so the UI
   * collects an ENV KEY (`control` is "text" for that key) and the caller writes `{env: "KEY"}`.
   * True for every `secret` param — an inline credential in connections.toml is a plaintext secret in
   * a committed file, and the GUI must not be the thing that puts one there.
   */
  secretOnlyEnv: boolean;
  /** Allowed values for a "select", else null. */
  choices: unknown[] | null;
  /** The default, as display text for a hint. "" when the setting has no default. */
  placeholder: string;
  /** The default, raw (a checkbox needs its unset position). RENDER-ONLY — never post it. */
  defaultValue: unknown;
  /** The record's literal value, or undefined when the record does not set this key. */
  value: unknown;
  isEnvRef: boolean;
  /** The referenced environment key, when `isEnvRef`. */
  envKey?: string;
  /** The env table's named `cast` ("int"/"float"/"bool"/"str"), when it has one. */
  cast?: string;
  /** The env table's `default` fallback, when it has one — carried so a save preserves it. */
  envDefault?: unknown;
  /**
   * The record's raw value for a SECRET key that is stored as an inline literal rather than an
   * env reference. Not shown (it is a credential) and not editable, but handed back so the caller
   * can post it verbatim when the user does not replace it with an env key — deleting somebody's
   * working credential because the form refuses to display it would be its own outage.
   */
  preserveValue?: unknown;
  /** The title of the group this field was placed in. */
  group: string;
  /** False = the record carries this key but this engine's schema does not describe it. */
  known: boolean;
  /** True = the schema says this setting belongs to the OTHER direction, but the record sets it. */
  offDirection: boolean;
}

export interface FieldGroup {
  title: string;
  fields: FieldDescriptor[];
  collapsed: boolean;
  /** The full section heading when `title` is a shortened form of it (headings can be prose). */
  description?: string;
}

/**
 * The ordered, grouped fields for one connection's settings table.
 *
 * Grouping:
 *  1. ESSENTIAL_GROUP — `required`, or `requiredHint` for THIS direction (MLLP outbound: host+port).
 *     Never collapsed.
 *  2. one group per `section` heading in the schema (the TLS block, the DoS-guard block, …),
 *     collapsed. A heading is emitted on the first parameter of its block, so it carries forward to
 *     the parameters that follow it; that carry-forward is computed over the WHOLE parameter list
 *     before any filtering or hoisting, so a block keeps its heading even when its first parameter is
 *     pulled into Essential or hidden by direction.
 *  3. OTHER_GROUP — everything else the schema describes, collapsed.
 *  4. UNKNOWN_GROUP — LAST: keys present on the record that the schema does not describe. Not
 *     collapsed: an undescribed key is either a typo or an engine-version mismatch, and both want
 *     eyes on them. This group is the load-bearing half of invariant 1.
 *
 * Direction: a param for the other direction is hidden — UNLESS the record sets it, in which case it
 * is rendered (flagged `offDirection`) rather than dropped. Empty groups are omitted.
 */
export function buildForm(
  schema: ConnectionSchema | undefined,
  transport: string,
  direction: Direction,
  settings: Record<string, unknown> | undefined,
): FieldGroup[] {
  const record = asRecord(settings) ?? {};
  // An unknown transport (an engine that does not have it) yields no params — and therefore a form
  // that is entirely UNKNOWN_GROUP, which is the point: the record is still fully editable.
  const described = (asRecord(schema?.transports?.[transport]?.params) ?? {}) as Record<
    string,
    SchemaParam
  >;
  const { byKey, order } = assignSections(described);

  const buckets = new Map<string, FieldGroup>();
  const bucket = (key: string, title: string, collapsed: boolean, description?: string) => {
    const existing = buckets.get(key);
    if (existing) {
      return existing;
    }
    const created: FieldGroup = { title, fields: [], collapsed };
    if (description !== undefined) {
      created.description = description;
    }
    buckets.set(key, created);
    return created;
  };

  // Pre-create every bucket in FINAL order, then fill: Essential, the sections in schema order,
  // Other, Unknown. (Filling in parameter order would interleave "Other" among the sections.) A
  // section is keyed under a prefix so a heading that reads like one of the fixed group names can
  // never collide with it.
  bucket(ESSENTIAL_GROUP, ESSENTIAL_GROUP, false);
  for (const heading of order) {
    const { title, description } = groupHeading(heading);
    bucket(`section:${heading}`, title, true, description);
  }
  bucket(OTHER_GROUP, OTHER_GROUP, true);
  bucket(UNKNOWN_GROUP, UNKNOWN_GROUP, false);

  for (const [key, param] of Object.entries(described)) {
    const applies = param.direction == null || param.direction === direction;
    const present = has(record, key);
    if (!applies && !present) {
      continue; // not for this direction and not on the record — nothing to lose by hiding it
    }
    const essential = applies && (param.required === true || param.requiredHint === true);
    const heading = byKey.get(key);
    const bucketKey = essential
      ? ESSENTIAL_GROUP
      : heading !== undefined
        ? `section:${heading}`
        : OTHER_GROUP;
    const target = buckets.get(bucketKey) ?? bucket(OTHER_GROUP, OTHER_GROUP, true);
    target.fields.push(describe(key, param, record, target.title, applies));
  }

  const unknown = buckets.get(UNKNOWN_GROUP);
  for (const key of Object.keys(record)) {
    if (!has(described, key)) {
      unknown?.fields.push(describeUnknown(key, record[key]));
    }
  }

  return [...buckets.values()].filter((group) => group.fields.length > 0);
}

/**
 * One raw form control value → the typed value to post, or undefined when the key should be omitted
 * entirely. Omission is the point: connections.toml stays minimal and an absent optional key means
 * "this engine's default", which survives an engine upgrade that changes that default.
 *
 * - checkbox: a real boolean (`input.checked`) passes through; null/undefined/"" is "untouched" and
 *   yields undefined. An `<input type=checkbox>` has no "untouched" state to report -- it is always
 *   a boolean -- so a value the record did not carry AND that equals the schema default is omitted
 *   too (see the guard below). Without that, every save wrote an explicit `encrypt = true` for each
 *   default-true bool, which is exactly the bloat (and the upgrade-unsafety) invariant 2 forbids.
 * - number: `Number(text)`; text that is not a number is returned VERBATIM so the engine's validator
 *   rejects what the user actually typed instead of this function silently discarding it.
 * - select: the matching entry from `choices`, preserving its JSON type (a Literal may be an int).
 * - table: parsed as JSON; unparseable text is likewise returned verbatim to fail loud downstream.
 * - everything else: the trimmed string.
 *
 * A REQUIRED field left blank also yields undefined (the key is omitted, and the engine then raises
 * on the missing setting) — an empty string would be a wrong-typed value smuggled into the file,
 * which is the worse of the two failures. Blocking that save belongs to the caller, via `required`.
 *
 * Not used for the env-reference path: there the caller writes `{env: envKey[, cast][, default]}`
 * straight from the descriptor.
 */
export function coerce(
  descriptor: FieldDescriptor,
  raw: string | boolean | null | undefined,
): unknown {
  if (raw === undefined || raw === null) {
    return undefined;
  }
  // CHECKBOXES ONLY. Every other control can report "untouched" by being empty, and an empty value
  // already omits below -- so for those, a typed value equal to the default is a deliberate choice
  // and must be written. An <input type=checkbox> has no empty state: it always posts a boolean, so
  // without this guard every save wrote an explicit `encrypt = true` for each default-true flag,
  // the bloat (and upgrade-unsafety) invariant 2 forbids. Not applied when the record already
  // carried the key: a value the user authored stays explicit even if it equals the default.
  if (
    descriptor.control === "checkbox" &&
    descriptor.value === undefined &&
    !descriptor.isEnvRef &&
    descriptor.defaultValue !== undefined &&
    descriptor.defaultValue !== null &&
    raw === descriptor.defaultValue
  ) {
    return undefined;
  }
  if (descriptor.control === "checkbox") {
    if (typeof raw === "boolean") {
      return raw;
    }
    const flag = raw.trim().toLowerCase();
    if (flag === "") {
      return undefined;
    }
    return flag === "true" || flag === "1" || flag === "on" || flag === "yes";
  }
  const text = (typeof raw === "boolean" ? String(raw) : raw).trim();
  if (text === "") {
    return undefined;
  }
  if (descriptor.control === "number") {
    const parsed = Number(text);
    return Number.isFinite(parsed) ? parsed : text;
  }
  if (descriptor.control === "select") {
    const match = (descriptor.choices ?? []).find((choice) => String(choice) === text);
    return match === undefined ? text : match;
  }
  if (descriptor.control === "table") {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
  return text;
}

// ---- internals --------------------------------------------------------------------------------

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function has(record: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

/**
 * The section heading each parameter belongs to, carried forward from the parameter that declares it
 * (the engine emits a heading once, on the first parameter of the block), plus those headings in
 * schema order. Computed over every parameter — filtering and Essential-hoisting happen afterwards,
 * so they cannot orphan a block's heading.
 */
function assignSections(params: Record<string, SchemaParam>): {
  byKey: Map<string, string>;
  order: string[];
} {
  const byKey = new Map<string, string>();
  const order: string[] = [];
  let current: string | undefined;
  for (const [key, param] of Object.entries(params)) {
    const section = typeof param.section === "string" ? param.section.trim() : "";
    if (section !== "") {
      current = section;
      if (!order.includes(section)) {
        order.push(section);
      }
    }
    if (current !== undefined) {
      byKey.set(key, current);
    }
  }
  return { byKey, order };
}

const MAX_TITLE = 60;

/**
 * A group heading → a renderable `title` (+ the full text as `description` when shortened). The
 * headings are source comments: some are tidy (`Inbound DoS guards (…)`), some are decorated
 * (`--- TLS (WP-13b, ADR 0002) — per-connection MLLP-over-TLS ---`) and some are a paragraph that
 * carries a security instruction, which is exactly why the full text is preserved rather than cut.
 */
function groupHeading(raw: string): { title: string; description?: string } {
  const cleaned = raw
    .replace(/^[\s\-:]+/, "")
    .replace(/[\s\-:]+$/, "")
    .trim();
  const title = shorten(cleaned);
  return title === cleaned ? { title } : { title, description: cleaned };
}

function shorten(text: string): string {
  if (text.length <= MAX_TITLE) {
    return text;
  }
  // Cut at the first sentence / clause / parenthetical boundary that fits; keep the longest that
  // does, and never one that ends mid-parenthetical ("Inbound DoS guards (defaults mirror the …").
  const fitting = [". ", " — ", " (", "; "]
    .map((mark) => text.indexOf(mark))
    .filter((at) => at > 0)
    .map((at) => text.slice(0, at).trim())
    .filter((candidate) => candidate.length > 0 && candidate.length <= MAX_TITLE)
    .filter((candidate) => count(candidate, "(") === count(candidate, ")"));
  if (fitting.length > 0) {
    return fitting.reduce((best, candidate) => (candidate.length > best.length ? candidate : best));
  }
  const hard = text.slice(0, MAX_TITLE);
  const space = hard.lastIndexOf(" ");
  return `${(space > MAX_TITLE / 3 ? hard.slice(0, space) : hard).trim()}…`;
}

function count(text: string, character: string): number {
  return [...text].filter((each) => each === character).length;
}

/**
 * The record's `{env = "KEY"}` inline table, or undefined when the value is a plain literal. Mirrors
 * the engine's `parse_env_setting` exactly: an inline table is an env reference only when it carries
 * a non-empty string `env` AND no key outside {env, default, cast}. A REST `headers` map that happens
 * to contain an "env" header is therefore read as the literal table it is, not as a reference.
 */
const ENVREF_KEYS = new Set(["env", "default", "cast"]);

function envRefOf(
  value: unknown,
): { key: string; cast?: string; default?: unknown } | undefined {
  const table = asRecord(value);
  if (!table || typeof table.env !== "string" || table.env === "") {
    return undefined;
  }
  if (!Object.keys(table).every((key) => ENVREF_KEYS.has(key))) {
    return undefined;
  }
  const ref: { key: string; cast?: string; default?: unknown } = { key: table.env };
  if (typeof table.cast === "string") {
    ref.cast = table.cast;
  }
  if (has(table, "default")) {
    ref.default = table.default;
  }
  return ref;
}

function controlFor(type: ParamType, choices: unknown[] | null): FieldControl {
  if (choices) {
    return "select";
  }
  switch (type) {
    case "bool":
      return "checkbox";
    case "int":
    case "float":
      return "number";
    case "table":
      return "table";
    default:
      return "text";
  }
}

function placeholderFor(value: unknown): string {
  if (value === undefined || value === null) {
    return "";
  }
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function describe(
  key: string,
  param: SchemaParam,
  record: Record<string, unknown>,
  group: string,
  applies: boolean,
): FieldDescriptor {
  const present = has(record, key);
  const raw = present ? record[key] : undefined;
  const ref = envRefOf(raw);
  const secret = param.secret === true;
  const type = param.type ?? "unknown";
  // When the schema cannot classify a param, the value the record already holds is better evidence
  // than the "unknown" tag -- and trusting the tag loses data. `soap.body_secrets` types as unknown
  // but is authored as a table; giving it a text control rendered "[object Object]", and saving an
  // untouched form then replaced the real table with that string. Mirrors what describeUnknown()
  // already does for keys the schema does not mention at all. Never applied to a secret, whose
  // control is the env-key box regardless of the value's shape.
  const effectiveType: ParamType =
    type === "unknown" && present && !secret && ref === undefined ? inferType(raw) : type;
  const choices = Array.isArray(param.choices) && param.choices.length > 0 ? param.choices : null;
  const notes: string[] = [];
  if (!applies) {
    notes.push(
      `The schema marks this setting ${param.direction}-only, but this record sets it — shown so a ` +
        "save keeps it. Clear it deliberately if it does not belong here.",
    );
  }
  if (secret) {
    notes.push("Credential: reference an environment key; a literal is never stored here.");
  }
  const field: FieldDescriptor = {
    key,
    // A secret's control holds the ENV KEY, not the value; say so where the user is looking.
    label: secret ? `${key} (env key)` : key,
    // A secret is forced to the env-reference form, so its control is the text box for that key
    // whatever the declared type is (credential_password, for one, types as "unknown").
    control: secret ? "text" : controlFor(effectiveType, choices),
    type: effectiveType,
    help: [param.help ?? "", ...notes].filter((part) => part !== "").join(" "),
    // Only a genuinely defaultless param blocks a save; see FieldDescriptor.required.
    required: applies && param.required === true,
    conditionallyRequired: applies && param.requiredHint === true,
    secret,
    envAllowed: secret || param.env === true,
    secretOnlyEnv: secret,
    choices,
    placeholder: placeholderFor(param.default),
    defaultValue: param.default,
    // Only the record populates `value` (invariant 2) — and never for a secret (never displayed).
    value: ref === undefined && !secret ? raw : undefined,
    isEnvRef: ref !== undefined,
    group,
    known: true,
    offDirection: !applies,
  };
  if (ref !== undefined) {
    field.envKey = ref.key;
    if (ref.cast !== undefined) {
      field.cast = ref.cast;
    }
    if (has(ref, "default")) {
      field.envDefault = ref.default;
    }
  } else if (secret && present) {
    field.preserveValue = raw; // an inline credential already in the file: keep it, don't show it
  }
  return field;
}

/**
 * A key the record carries that the schema does not describe (invariant 1): an engine older or newer
 * than this extension, a hand-authored key, or a typo. Rendered as the old free-text row was —
 * type inferred from the value it already holds so the save round-trips the same JSON type.
 */
function describeUnknown(key: string, raw: unknown): FieldDescriptor {
  const ref = envRefOf(raw);
  const type = inferType(ref === undefined ? raw : "");
  const field: FieldDescriptor = {
    key,
    label: key,
    control: controlFor(type, null),
    type,
    help:
      "Not described by this engine's connection schema for this transport. It is kept and saved " +
      "unchanged — check the spelling, or whether it needs a different engine version.",
    required: false,
    // Nothing describes it, so nothing can claim it is required — blocking a save on a key this
    // engine cannot even explain would strand the user with no way to fix it.
    conditionallyRequired: false,
    secret: false,
    envAllowed: true,
    secretOnlyEnv: false,
    choices: null,
    placeholder: "",
    defaultValue: undefined,
    value: ref === undefined ? raw : undefined,
    isEnvRef: ref !== undefined,
    group: UNKNOWN_GROUP,
    known: false,
    offDirection: false,
  };
  if (ref !== undefined) {
    field.envKey = ref.key;
    if (ref.cast !== undefined) {
      field.cast = ref.cast;
    }
    if (has(ref, "default")) {
      field.envDefault = ref.default;
    }
  }
  return field;
}

function inferType(value: unknown): ParamType {
  if (typeof value === "boolean") {
    return "bool";
  }
  if (typeof value === "number") {
    return Number.isInteger(value) ? "int" : "float";
  }
  if (value !== null && typeof value === "object") {
    return "table";
  }
  return "str";
}
