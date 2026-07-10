// The Cookbook's static "solved problems" catalog (BACKLOG #104) — HL7 Router/Handler recipes as
// real, editable Python. Deliberately `vscode`-free/pure: this is the data cookbook.ts (the webview
// panel) renders and inserts via `editor.insertSnippet`, kept import-clean so the catalog itself is
// unit-testable under plain Node/Mocha with no Extension Host.
//
// STRICT BRIGHT LINE (BACKLOG #26 stays declined): a STATIC-snippet index only. Every recipe's `code`
// is a fixed string baked into this file — nothing here reads user input and generates code from it,
// there is no field-mapping form, no "customize this recipe" step, and nothing is persisted as a
// declarative artifact. A recipe may carry a handful of `${n:placeholder}` tabstops (identical
// convention to the bundled snippets file, snippets/messagefoundry.code-snippets) that the user then
// edits by hand in the editor, same as any other VS Code snippet.
//
// All example HL7 paths/values below are synthetic (no real names/IPs/MRNs) — CLAUDE.md §9.

export interface Recipe {
  id: string;
  title: string;
  category: string;
  summary: string;
  /** Extra search terms beyond title/summary/category (e.g. the HL7 fields/functions it touches). */
  tags: string[];
  /** Static, editable Python — inserted verbatim via `new vscode.SnippetString(code)`. */
  code: string;
}

export const RECIPES: Recipe[] = [
  {
    id: "route-by-message-type",
    title: "Route by message type",
    category: "Routing",
    summary: "Send ADT admits and ORU results to different Handlers; everything else is UNROUTED.",
    tags: ["router", "MSH-9", "message type", "trigger event"],
    code: [
      '@router("${1:adt_router}")',
      "def route(msg):",
      "\t# A Router sees EVERY inbound message — decide who (if anyone) handles it.",
      '\tif msg["MSH-9.1"] == "ADT" and msg["MSH-9.2"] in ("A01", "A04", "A08"):',
      '\t\treturn ["${2:admit_handler}"]',
      '\tif msg["MSH-9.1"] == "ORU":',
      '\t\treturn ["${3:results_handler}"]',
      "\treturn []  # anything else is routed nowhere -> logged UNROUTED",
    ].join("\n"),
  },
  {
    id: "filter-unwanted-event",
    title: "Filter out an unwanted event",
    category: "Filtering",
    summary: "Drop events a Handler doesn't care about — still counted and logged, never dropped silently.",
    tags: ["filter", "FILTERED", "MSH-9.2", "drop"],
    code: [
      '@handler("${1:admit_handler}")',
      "def handle(msg):",
      "\t# Only forward admit/transfer/discharge; everything else is FILTERED (logged, not delivered).",
      '\tif msg["MSH-9.2"] not in ("A01", "A02", "A03"):',
      "\t\treturn None  # FILTERED",
      '\treturn Send("${2:outbound_name}", msg)',
    ].join("\n"),
  },
  {
    id: "rearrange-segments",
    title: "Rearrange segments (move NTE ahead of OBX)",
    category: "Structure",
    summary: "Pull every NTE's text out and re-add it just before the first OBX, for a receiver that expects comment-then-result.",
    tags: ["segments", "reorder", "NTE", "OBX", "add_segment", "delete_segments"],
    code: [
      '@handler("${1:reorder_handler}")',
      "def handle(msg):",
      "\t# Pull every NTE's text out, delete them, then re-add just before the first OBX -- e.g. a",
      '\t# downstream system expects "comment before result", not HL7\'s "result then comment".',
      '\tnotes = [msg.field("NTE-3", occurrence=i) for i in range(1, msg.count_segments("NTE") + 1)]',
      '\tmsg.delete_segments("NTE")',
      '\tbefore = next((i - 1 for i, seg in enumerate(msg.segments(), start=1) if seg == "OBX"), None)',
      "\tfor note in reversed([n for n in notes if n]):",
      '\t\tmsg.add_segment(f"NTE|1|L|{note}", index=before)',
      '\treturn Send("${2:outbound_name}", msg)',
    ].join("\n"),
  },
  {
    id: "codeset-crosswalk",
    title: "Crosswalk a code via a code set",
    category: "Lookup",
    summary: "Translate a sender's local code to the receiver's, via a reload-safe code_set() table; leave it alone on a miss.",
    tags: ["code_set", "crosswalk", "translation table", "OBX-3"],
    code: [
      "# Module top level: captured once, reload-safe (config/reload re-executes this module).",
      'LAB_CODES = code_set("${1:lab_code_crosswalk}")',
      "",
      "",
      '@handler("${2:results_handler}")',
      "def handle(msg):",
      "\t# Translate the sending lab's local test code (OBX-3.1) to the receiving system's code",
      "\t# (OBX-3.2); leave the value untouched on a miss so nothing downstream silently loses data.",
      '\tmapped = LAB_CODES.get(msg["OBX-3.1"])',
      "\tif mapped is not None:",
      '\t\tmsg["OBX-3.2"] = mapped',
      '\treturn Send("${3:outbound_name}", msg)',
    ].join("\n"),
  },
  {
    id: "split-batch-by-obr",
    title: "Split a batch by OBR and send each order",
    category: "Fan-out",
    summary: "One ORU carrying several orders becomes one message per OBR, each sent (and able to fail) independently.",
    tags: ["split_by_obr", "batch", "OBR", "ItemSplit"],
    code: [
      '@handler("${1:orders_handler}")',
      "def handle(msg):",
      "\t# A batch ORU/ORM can carry several orders (OBR) under one MSH; split_by_obr() returns one",
      "\t# self-contained message per OBR (header + that order's OBX/NTE), sent independently so a",
      "\t# failure on one order never blocks the others.",
      '\treturn [Send("${2:outbound_name}", part) for part in split_by_obr(msg)]',
    ].join("\n"),
  },
  {
    id: "enrich-db-lookup",
    title: "Enrich a message via a live DB lookup",
    category: "Lookup",
    summary: "Fill in a field from a live, read-only database read (Handler-only; may differ on a re-run by design).",
    tags: ["db_lookup", "enrich", "PID-3", "live lookup"],
    code: [
      '@handler("${1:eligibility_handler}")',
      "def handle(msg):",
      "\t# Live, READ-ONLY lookup (Handler only, never a Router) -- gated by [egress].allowed_db.",
      "\t# May differ on a re-run; accepted by design (ADR 0010).",
      "\trows = db_lookup(",
      '\t\t"${2:CLARITY_RO}",',
      '\t\t"SELECT primary_care_provider FROM patient WHERE mrn = :mrn",',
      '\t\t{"mrn": msg["PID-3.1"]},',
      "\t)",
      "\tif rows:",
      '\t\tmsg["PV1-8"] = rows[0]["primary_care_provider"] or ""',
      '\treturn Send("${3:outbound_name}", msg)',
    ].join("\n"),
  },
  {
    id: "convert-timestamp",
    title: "Convert / re-timezone a timestamp",
    category: "Date/Time",
    summary: "Re-stamp an HL7 timestamp from the sender's zone to the receiver's with convert_hl7_timestamp().",
    tags: ["timestamp", "timezone", "OBR-7", "convert_hl7_timestamp"],
    code: [
      '@handler("${1:orders_handler}")',
      "def handle(msg):",
      "\t# Re-stamp OBR-7 (observation date/time) from the sender's zone to the receiving system's.",
      '\tmsg["OBR-7"] = convert_hl7_timestamp(msg["OBR-7"] or "", "${2:America/Chicago}")',
      '\treturn Send("${3:outbound_name}", msg)',
    ].join("\n"),
  },
  {
    id: "fan-out-multiple-outbounds",
    title: "Fan a message out to multiple outbounds",
    category: "Fan-out",
    summary: "Return several Sends from one Handler; each outbound drains independently, so a slow one never blocks its siblings.",
    tags: ["fan-out", "Send", "multiple destinations"],
    code: [
      '@handler("${1:fanout_handler}")',
      "def handle(msg):",
      "\t# One inbound ADT, several downstream systems -- return a list of Sends, one per destination.",
      "\t# Each outbound connection drains independently, so a slow/failing one never blocks the others.",
      "\treturn [",
      '\t\tSend("${2:OB_EHR_ADT}", msg),',
      '\t\tSend("${3:OB_BILLING_ADT}", msg),',
      '\t\tSend("${4:OB_REGISTRY_ADT}", msg),',
      "\t]",
    ].join("\n"),
  },
  {
    id: "default-blank-field",
    title: "Default a blank field",
    category: "Field",
    summary: "Stamp a default value when the sender leaves a required field blank, instead of forwarding it empty.",
    tags: ["default", "blank field", "PV1-3"],
    code: [
      '@handler("${1:admit_handler}")',
      "def handle(msg):",
      "\t# Stamp a default when the sender leaves a required field blank.",
      '\tif not msg["${2:PV1-3.1}"]:',
      '\t\tmsg["${2:PV1-3.1}"] = "${3:UNKNOWN}"',
      '\treturn Send("${4:outbound_name}", msg)',
    ].join("\n"),
  },
  {
    id: "add-identifier-repetition",
    title: "Add an identifier repetition (PID-3)",
    category: "Field",
    summary: "Append a second PID-3 identifier (e.g. a downstream MRN namespace) alongside the sender's, without overwriting it.",
    tags: ["add_repetition", "PID-3", "identifier", "MRN"],
    code: [
      '@handler("${1:mpi_handler}")',
      "def handle(msg):",
      "\t# Append a second PID-3 identifier (e.g. the receiving system's MRN namespace) alongside the",
      "\t# sender's, rather than overwriting it -- both survive as separate ~ repetitions.",
      '\tmsg.add_repetition("PID-3", "${2:1000042}^^^${3:ACME_MRN}^MR")',
      '\treturn Send("${4:outbound_name}", msg)',
    ].join("\n"),
  },
  {
    id: "patient-age-from-dob",
    title: "Compute patient age from DOB",
    category: "Date/Time",
    summary: "Use msg.age() (reads PID-7) to gate a feed by age, e.g. splitting off a pediatric registry.",
    tags: ["age", "PID-7", "DOB", "pediatric"],
    code: [
      '@handler("${1:registry_handler}")',
      "def handle(msg):",
      "\t# msg.age() reads PID-7 (DOB) and returns whole years as of today -- None if PID-7 is absent.",
      "\tyears = msg.age()",
      "\tif years is not None and years < ${2:18}:",
      "\t\treturn None  # FILTERED -- pediatric registry has its own separate feed",
      '\treturn Send("${3:outbound_name}", msg)',
    ].join("\n"),
  },
  {
    id: "drop-cancelled-order",
    title: "Drop a cancelled order from a multi-order batch",
    category: "Structure",
    summary: "Remove just the cancelled OBR order groups from a batch ORU, leaving sibling orders untouched.",
    tags: ["groups", "OBR-25", "cancelled", "SegmentGroup"],
    code: [
      '@handler("${1:results_handler}")',
      "def handle(msg):",
      "\t# A batch ORU can carry several orders (OBR); drop just the cancelled ones (OBR-25 result",
      "\t# status) without touching the rest. Walk groups() back-to-front: group.delete() re-indexes",
      "\t# LATER ordinals, so deleting in reverse never invalidates a group we haven't visited yet.",
      "\tfor group in reversed(msg.groups()):",
      '\t\tif group.field("OBR-25") == "${2:X}":',
      "\t\t\tgroup.delete()",
      '\treturn Send("${3:outbound_name}", msg)',
    ].join("\n"),
  },
];

/** The lower-cased blob a recipe is matched against for search — title/summary/category/tags. */
export function searchBlob(r: Recipe): string {
  return [r.title, r.summary, r.category, ...r.tags].join(" ").toLowerCase();
}
