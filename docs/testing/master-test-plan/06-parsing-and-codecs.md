[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 5. Parsing, Codecs, Validation & Message Data

**ID prefix:** `PARSE` · **Surface:** engine (pure library) + CLI + harness/IDE consumers
· **Primary risk:** a hostile-but-ordinary message *shape* (blank segment, `\X00\`) escapes the listener's catches and is **accepted-and-dropped with no disposition** — a count-and-log invariant break the current dual-backend parity oracle actively certifies as correct.

### 5.1 Scope & objectives

**In scope.** The pure, store-independent parsing/codec library and everything that derives a value from a payload *before* the ingress commit:

- **Two-tier HL7 v2.** Tolerant peek (`messagefoundry/parsing/peek.py:166-351`), the ADR 0054 low-allocation built-ins parser that is the **default** tolerant backend (`messagefoundry/parsing/_builtin_hl7.py`, 991 lines; `_backend.py:30 USE_BUILTIN = True`), the runtime fallback guard to python-hl7 (`peek.py:195-215`), and opt-in strict hl7apy validation (`messagefoundry/parsing/validate.py:44-95`).
- **Pre-parse resource caps and the ASVS 1.3.3 escape budget** (`peek.py:56-124`; `_builtin_hl7.py` `MAX_ESCAPE_REPEAT = 512`, `MAX_COUNTED_ESCAPE_OPENERS = 100_000`).
- **MSH-driven separators** (`_builtin_hl7.py:117-132 _extract_separators`) and the **independent** derivation in the viewer tree (`messagefoundry/parsing/tree.py:65-72`).
- **Escape/unescape codec** including the rich-text map and the `\Cxx\`/`\Mxx\` drop branch (`_builtin_hl7.py:_RICH_TEXT_MAP`, `unescape`), plus the BACKLOG #107 raw-separator escape hatch (`_builtin_hl7.unescape_separators`, `message.py encode_raw_separators`).
- **Message data model:** mutable `Message` (`messagefoundry/parsing/message.py`, 766 lines), `SegmentGroup` (`groups.py`), batch/per-OBR split (`split.py`), parse tree (`tree.py`), ingest-time `summarize()` (`summary.py:27-46`), Tier-3 cross-field consistency primitives (`consistency.py`).
- **Payload-agnostic ingress + `RawMessage`** (ADR 0004, `message.py:683-766`), hardened `RawMessage.xml()` (defusedxml, DTD/entities/external all forbidden), and the ADR 0028 `mfb64:v1:` base64 binary carriage (`binary.py:45,136,149`) with HL7 OBX-5 ED embed/extract.
- **Non-HL7 codecs:** X12 (`parsing/x12/`, 7 modules, ADR 0012) incl. the pyx12 strict guide validator; FHIR (`parsing/fhir/`, ADR 0022); DICOM + SR→HL7 (`parsing/dicom/`, ADR 0025); XML/SOAP + XSD + XML-DSig + WSDL 1.1 import (`parsing/xml/`, BACKLOG #31, ADR 0122); compression (`compression.py`, ADR 0123); content sniff (`sniff.py`).
- **Code sets** (ADR 0033, `messagefoundry/config/code_sets.py`, 609 lines) incl. the unmapped-value policy sidecar and the un-installed `UnmappedSink` seam.
- **HL7 metadata exports** (`hl7schema.py`, `hl7structures.py`) and the **13 synthetic generators** (`messagefoundry/generators/`).
- **Hostile/malformed input robustness**, HL7 version and message-type breadth, Z-segments, repeats, truncation, and **character-set fidelity** — accented Latin, CJK and combining marks through peek → `Peek.field` → escape/unescape → `Message.encode()` → `parse_tree`/`summarize()`, plus a declared `MSH-18` and the UTF-8 / latin-1 / cp1252 decode matrix. The **library and pre-ingress** half lives here; the **end-to-end** pass (store round-trip, CLI/console codepage, operator rendering) is owned by the **MIG** chapter (MIG-54 dialect corpus, MIG-67/MIG-68 non-cp1252 console + non-en-US locale).

**Explicitly NOT in scope here — owned elsewhere, cited not restated:**

| Area | Owner |
|---|---|
| The full six-dimension coverage-gap audit of HL7 parsing (rows `FCP:PARSE-1`..`FCP:PARSE-21`) | `docs/testing/FEATURE-COVERAGE-PLAN.md` §7 `[PARSE]`, lines 838-876 |
| RawMessage/`content_type` routing, `mfb64` carriage, OBX-5 ED, SEC-017 caps, ADR 0081 metadata bag (`FCP:INGEST-1`..`FCP:INGEST-8`) | `docs/testing/FEATURE-COVERAGE-PLAN.md` §8 `[INGEST]`, lines 878-901 |
| X12 (`FCP:X12-1`..`FCP:X12-19`) and DICOM (`FCP:DICOM-1`..`FCP:DICOM-26`) codec **plus transport** audits | `docs/testing/FEATURE-COVERAGE-PLAN.md` §4 and §3 |
| FHIR codec alongside the HTTP-family destinations | `docs/testing/FEATURE-COVERAGE-PLAN.md` §5 `[HTTPFHIR]` |
| Code-sets core + unmapped policy (`FCP:CFG-12`/`FCP:CFG-13`); synthetic generators (`FCP:CLI-12`) | `docs/testing/FEATURE-COVERAGE-PLAN.md` lines 1396-1397, 1437 |
| Windows Server 2025 host/service behaviour | `docs/testing/WIN2025-TEST-PLAN.md` — which **explicitly excludes** this area at line 71: *"Engine internals: staged pipeline, per-lane FIFO, store parity, HL7 parsing — CI-owned"* |
| Host-acceptance-level HL7/payload spot checks (`W25:E1`..`W25:E6`, run once, not per store backend) | `docs/testing/WIN2025-TEST-MATRIX.md` §E |
| The harness GUI itself — window, tabs, the console-rehomed view widgets (`harness/_console_widgets.py`, `_login.py`) and the `messagefoundry-harness` distribution | **TRAY** §13d, which states it takes ownership of the harness GUI because no other chapter did. This chapter drives one widget (`ParseTreeView`, PARSE-52) purely as a rendering oracle |
| End-to-end character-set behaviour: store round-trip, CLI/console codepage, non-en-US locale, operator rendering of a dialect corpus | **MIG** — MIG-54 (offline vendor-dialect corpus), MIG-67 (non-cp1252 console codepage), MIG-68 (non-en-US Windows locale cell) |
| Staged-pipeline stage handoff, FIFO, retry/dead-letter mechanics | `[STORE]`/pipeline chapters |
| Store-side encryption, retention, search of the persisted body | store/PHI chapters |

**Objectives.** (1) Close the two proven count-and-log breaks that live in derived-value code paths. (2) Give the ADR 0054 reimplementation a safety net that survives Phase 2. (3) Establish HL7 version breadth beyond 2.5.1. (4) Make codec-extra skips and viewer/router divergences observable rather than silent. (5) Pin non-ASCII fidelity (accented Latin, CJK, a declared `MSH-18`) through the parse/escape/re-encode path, handing the end-to-end pass to **MIG**.

### 5.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `tests/test_builtin_hl7_parity.py` (620 lines, 8 test fns, ~30 parametrized corpus units) | ADR 0054 AC-1..AC-5, AC-7 byte parity: 11 `Peek` properties + `routing()` + `segments()` + a 66-path probe battery + `Message.field`/`repetitions`/`encode`, plus a 12-op mutate→encode matrix, over samples + 12 synthetic + 4 adversarial bodies, under **both** backends via `_backend.backend(builtin=…)` |
| `tests/test_builtin_hl7_hardening.py` (703 lines, 39 tests) | DELTA-01 unescape repeat clamp, DELTA-02 no-raise, the full ASVS 1.3.3 aggregate expansion budget **including its own bounded scan cost**, PHI-free budget messages, an AST assertion that `unescape` declares no dotted key outside `_RICH_TEXT_MAP` |
| `tests/test_builtin_hl7_hardening.py:595-703` | **Closes `FCP:PARSE-14` outright:** fault-injected fallback built-ins→python-hl7 for both `Peek.parse` and `Message.parse`, the single WARNING record, `HL7PeekError`/`hl7.ParseException` re-raised with **no** fallback, the expansion-budget never falling back, and `test_fallback_log_is_phi_free_for_both_entry_points`. The "partial" rating in that row (`FEATURE-COVERAGE-PLAN.md:859`) is stale |
| `tests/test_builtin_hl7_hardening.py:513-565` | A working **pre-ACK ingress-disposition rig**: real `MessageStore` + `Registry` + `RegistryRunner._handle_inbound`, asserting `messages.status`/`error`, the `MSA\|AR` NAK, `COUNT(*) FROM queue == 0`, and an anti-vacuity at-budget twin that ACKs `AA` and lands `RECEIVED` |
| `tests/test_parsing.py` (253 lines, 24 tests) | `normalize` CR/LF + bytes + strict-errors, routing fields, the PHI-free `routing()` dict, path grammar, tolerance + no-MSH, strict validate + version mismatch, size/segment caps on both `Peek.parse` and `validate()`, and a 15-case hand-built adversarial corpus asserting `validate()` never raises (#89) |
| `tests/test_message.py` (35 tests) · `test_message_copy.py` · `test_message_export.py` · `test_message_type_of.py` · `test_hl7_core_features.py` (9) | read/set/encode, XFORM-1/2/3 escaping + CR/LF + field-separator injection guards, **one** CJK/non-latin-1 passthrough case (`test_message.py:156`, the single char `李`, asserted against python-hl7's `escape()` corrupting >U+00FF), custom separators, repetitions, segment occurrences, add/delete segment, copy-on-Send clone. Accented Latin is also covered at this level (`test_message.py:160-162`, `Müller^X` mixing a >U+00FF char with a delimiter that must be escaped) |
| `tests/test_parsing.py:32` · `tests/test_hl7_core_features.py:82-100` · `tests/test_hl7_raw_separators.py:42,133` · `tests/test_wiring_engine.py:106-111` · `tests/test_mllp_encoding_override.py:93` | **The non-ASCII net that does exist** — `normalize()` decoding latin-1 `Müller`; `Müller@Jürgen` + a `García!@#&X` write under a fully custom MSH-2 through `Message.field`/`set`; `Österreich^José^Müller` through the #107 raw-separator codec; a latin-1-declared body through `_handle_inbound` asserting the *persisted raw* is not mangled; and `test_reencode_preserves_non_ascii_names` on the outbound delimiter re-encode. **What it does not reach:** CJK beyond the single `李` above, combining marks / NFC-vs-NFD, and any non-ASCII through `Peek.field`/`routing()`, `summarize()` or `parse_tree()` leaves — see PARSE-61..PARSE-64 |
| `tests/test_groups.py` (18) · `test_message_split.py` (17) · `test_hl7_raw_separators.py` (22) | `SegmentGroup` edits incl. custom boundary; FHS/BHS batch + per-OBR split incl. custom separators; the #107 raw-separator codec + MLLP plumbing + loopback |
| `tests/test_binary_carriage.py` (18) · `test_nonhl7_ingress_size_cap.py` (15) · `test_payload_agnostic_ingress.py` (14) | `mfb64` round-trip incl. all-256 bytes + DICOM preamble, corrupt fail-loud, encrypted store, OBX-5 ED embed/extract, SEC-017 caps on both non-HL7 branches, `content_type` routing, `RawMessage.xml()` DOCTYPE/XXE/billion-laughs reject |
| `tests/test_x12_parsing.py` (40) · `test_x12_validate.py` (7) · `test_dicom_codec.py` (20) · `test_fhir_parsing.py` (12) · `test_fhir_resource.py` (12) · `test_xml_message.py` (11) · `test_xml_schema_signature.py` (4) · `test_xml_parser_consistency.py` · `test_wsdl_import.py` (14) · `test_compression.py` (23) | Per-codec functional, import-purity and PHI-safe-error coverage for every non-HL7 codec, incl. the X12 interchange splitter's unterminated-remainder and inter-interchange-noise cases and the ADR 0123 incremental bomb ceiling |
| `tests/test_asvs_phase0.py:214-240` | `parsing/sniff.py` content-vs-declared-type sniffing (HL7 / X12 / BOM / leading-noise) and the hoist-plus-re-export contract with `transports/file.py` — **the recon missed this; sniff.py is covered** |
| `tests/test_code_sets.py` (22) + `tests/test_code_sets_policy.py` (21) + `tests/test_run_context.py` | CSV/TOML load, duplicate-key fail-loud, reload swap, all four policy kinds, capture dedup + re-run idempotence + purity-without-scope, and two PHI-no-log assertions (values absent at INFO; DEBUG counts carry no values) |
| `tests/test_generators_types.py` · `test_generated_adt.py` · `test_generators_core.py` · `test_generate_cli.py` (7) | Every registered type × every trigger generates and passes the hl7apy gate at `generators/_core.py:495`; ADT 57-trigger routing-field check; determinism; unknown type/trigger error paths |
| `tests/test_parse_tree.py` (8) | Segment/field/component/subcomponent/repetition tree shape, MSH-1/MSH-2 literals, empty + no-MSH raise (default separators only) |
| `tests/test_summary.py` (3) · `tests/test_consistency.py` (17) · `tests/test_hl7schema.py` · `tests/test_hl7structures.py` | `summarize()` shape/omission, the Tier-3 consistency primitives, and the 2.5.1 schema/structure exports incl. the `verified_paths` readback gate |
| `tests/test_benchmark_parser.py` (235 lines, 6 tests) | Single-thread throughput **floor** (`rate > 200.0` msg/s), multi-thread determinism, cross-backend batch agreement, synthetic batch sanity. `FCP:PARSE-15` (`FEATURE-COVERAGE-PLAN.md:860`) says this file is "MISSING" — **that is stale**; the file exists |
| `.github/workflows/ci.yml:144-159` | The full-suite legs (ubuntu + windows-2022 + windows-2025) install `[dev,harness,fhir,dicom,x12,xml,webauthn]` against `constraints.lock`, so the `importorskip`-gated codec suites do run in CI |
| `.github/workflows/freethread-smoke.yml` | Weekly, non-blocking cp314t canary that provisions 3.14t, **asserts `sys._is_gil_enabled()` is False**, runs `tests/test_parsing.py` + `tests/test_wiring.py`, and has an anti-vacuous-pass verdict step |
| `harness/acceptance/matrix.py:276-369` (`W25:D5`/`W25:D6`/`W25:E1`-`W25:E6`) + `harness/compose.py:123-129` | Acceptance evidence-map rows; the harness Compose tab ships four manual presets (generated ADT^A01, no-MSH, bad-version, empty) |
| `samples/messages/hapi-hl7v2/` (7 files, 26 messages, HL7 2.1-2.5.1, MPL-2.0, incl. an `ERP^Z99` v2.3.1 Z-segment file) | A vendored, PHI-free, real-vendor multi-version corpus already exists in-repo — acquisition is not needed, wiring is (see PARSE-13) |

**Done — do not re-plan.** Escape-budget hardening (DELTA-01/DELTA-02 and the full ASVS 1.3.3 aggregate budget with its bounded scan) is complete and has a working pre-ACK disposition rig. The ADR 0054 **Phase-1 fallback guard** is fully closed, PHI-free log assertion included — `FCP:PARSE-14`'s "partial" and `FCP:PARSE-15`'s "bench file MISSING" are both stale ratings, not gaps. `mfb64` carriage is proven NUL-safe at rest on all three store backends. `RawMessage.xml()` XXE hardening, SEC-017 caps on both non-HL7 branches, `sniff.py`, the compression bomb ceiling, the #107 raw-separator codec, `SegmentGroup`, batch/OBR split, and the Tier-3 consistency primitives are all covered. Do not restage any of these.

### 5.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| Blank segment in any feed (i.e. any partner writing `\r\n\r\n`) | `Peek.field`, every routing property and `summarize()` raise a bare `IndexError` from `_builtin_hl7.raise_if_blank_segment_scan`. The reads at `wiring_runner.py:3721` (`peek.control_id`) and `:3732` (`summarize(peek)`) sit **outside every catch**, so it unwinds out of `_handle_inbound`; `transports/mllp.py` logs, emits `framing_error` and drops the TCP connection | Every message on that connection: 0 `messages` rows, 0 `queue` rows, no ACK/NAK. Direct count-and-log break **plus** a one-packet, infinitely repeatable per-connection DoS | **No — worse than no.** `tests/test_builtin_hl7_parity.py:183-189` (`adv:empty-fields`) *contains* a blank segment, and `_eq()` at `:74` compares exceptions **by type**, so both backends raising `IndexError` scores a PASS. `samples/messages/hapi-hl7v2/oml_o21.hl7` (26 interior blank lines) is in the globbed parity corpus and is certified this way | **P0** |
| `\X00\` in any summarized field | Unescapes to a real U+0000 **inside `summarize()`** — after the `FCP:INGEST-4` post-decode NUL guard (`wiring_runner.py:3523`), which inspects only the raw decoded text (the raw carries the 5-char escape, no NUL). The NUL rides `summary=summarize(peek)` into `enqueue_ingress` at `:3732`, a **pre-ACK** commit. Reproduced: `'MRN AB\x00CD · DOE, JANE'` | Postgres rejects a NUL at bind (`DataError`/SQLSTATE 22021) → the raise unwinds out of `_handle_inbound` exactly as the ADR 0028 `FCP:INGEST-4` amendment describes, dropping the connection with **no ERROR row**. SQLite/SQL Server truncate the summary → operator blind spot in list/search | No. `grep -r 'X00' tests/` returns nothing. The whole `FCP:INGEST-4` retrofit was built for this class and missed the derived-value path | **P0** |
| ADR 0054 Phase 2 drops python-hl7 (`pyproject.toml:48` still pins `hl7>=0.4.5`) | The dual-backend oracle structurally requires python-hl7 installed. On removal `test_builtin_hl7_parity.py` becomes vacuous or uncollectable | Every subsequent edit to a 991-line from-scratch reimplementation of python-hl7's tolerant semantics ships unguarded | No golden vectors exist. Already flagged as `FCP:PARSE-12` (row at `FEATURE-COVERAGE-PLAN.md:857`, recommendation at `:874`) | P1 |
| HL7 version breadth is 2.5.1-only | Generators are hl7apy `v2_5_1`-driven (`generators/_core.py:24,142,495`); `hl7schema.py:22` and `hl7structures.py:31` are pinned to `SUPPORTED_VERSION = "2.5.1"`; no test drives `validate()` over a 2.3/2.3.1/2.4/2.6/2.7 body | Real hospital feeds are dominated by 2.3/2.4. An hl7apy upgrade could start NAKing an entire production feed synchronously with no failing test | No | P1 |
| Z-segment tolerance under strict validation is unpinned | Verified today: appending `ZPD\|1\|custom^data` to a conformant ADT^A01 still yields `ok=True` — but nothing asserts it | If an hl7apy upgrade tightens this, **every** message on **every** strict inbound NAKs AE synchronously — total feed outage — and the suite stays green | No | P1 |
| Codec extras silently uninstall | 41 test files use `importorskip`; there is no skip-counting guard in `tests/conftest.py` or `pyproject.toml` `addopts` | ~100 DICOM/FHIR/X12/XML/WSDL tests vanish and the build is GREEN. `pyproject.toml:119-123` documents exactly this class of breakage (annotated-types 0.8.0 dropping `SLOTS`) already happening once | No — the existing plan flags it for `FCP:X12-6` only | P1 |
| `parse_tree()` has its own separator derivation | `tree.py:65-72` blind-slices `msh[4:8]` and takes `sub_sep = enc[3]`. **Verified divergence:** for a legal 3-character MSH-2 (`^~\`), the tree derives `sub_sep = '\|'` (the *field* separator) while `_extract_separators` correctly returns `'&'`. Leaves are also never unescaped, so the viewer shows `O\S\Brien` where `Peek.field` returns `O^Brien` | The operator's only structural view of what actually arrived renders wrong in **both** the web console and the harness Qt pane, while routing stays correct — nothing else signals it | No. `test_parse_tree.py` is 8 tests over one default-separator ADT | P1 |
| ADR 0054 AC-6 (≥6× multi-core, ~14× single-thread on cp314t) has no executable gate | `test_benchmark_parser.py:207-235` is `skipif`-not-freethreaded and asserts only `ratio > 1.0`; `freethread-smoke.yml` runs only `test_parsing.py` + `test_wiring.py`, so the measure never executes anywhere | The entire justification for reimplementing python-hl7 (ADR 0053/0052) is unverified on any automated surface; only the crude `> 200 msg/s` floor would catch an orders-of-magnitude fall | Partially — the floor exists, the scaling gate does not | P1 |
| WSDL multi-part message selection | `parsing/xml/wsdl.py:290` `_body_element_for_message` returns `parts[0].element` unconditionally, never reading the binding's `<soap:body parts=…>` selector. Disclosed at BACKLOG #69 | A WS-I-conformant multi-part `wsdl:message` makes validate-against-WSDL check the **wrong** element — a false PASS on a non-conformant body or a false FAIL on a valid one, silently either way | No test in `test_wsdl_import.py` covers it | P1 |
| No malformed/oversized corpus generator | `generators/_core.generate_message` emits only hl7apy-conformant bodies and raises on an unknown trigger; `messagefoundry generate` exposes only `--type/--triggers/--count/--out/--seed/--list/--json` (`__main__.py:349-362`) | The error/dead-letter path — the count-and-log invariant itself — is never exercised at load or repeatably. Both P0s above are exactly the shapes such a generator would emit. Blocks automating `W25:S4.8` (`WIN2025-TEST-PLAN.md:926,1044,1351`) | No — `W25:S4.8` bad input is GUI-injected manually | P1 |
| `ValidationResult.errors` unasserted PHI-redacted | `validate.py:91` appends `str(exc)` from hl7apy verbatim; `wiring_runner.py:3659` does pass it through `safe_text` before persisting, but nothing pins that the **library** result is safe for other callers (dry-run, IDE, harness) | A datatype/table conformance failure can carry the offending field VALUE into any surface that renders `result.errors` directly | Partly — the persisted path is scrubbed; the library return is not asserted | P2 |
| No property-based or coverage-guided fuzzing | `pyproject.toml` carries no hypothesis/atheris; both "fuzz" corpora (`test_parsing.py:228-244`, 15 cases; `test_builtin_hl7_hardening.py`) are hand-enumerated. `docs/quality-gates/HANDOFF-mutation-coverage.md:223` proposes mutmut over `parsing/` but is a handoff doc only | Hand-enumerated corpora find only shapes an author imagined — demonstrated by both P0s, each trivially reachable and each missed. Parsing is the largest attacker-influenced surface in the product | No | P2 |
| Evidence-map drift in the acceptance matrix | `harness/acceptance/matrix.py:336-341` maps `W25:E2` "Strict validation opt-in (hl7apy)" to `tests/test_hl7schema.py` — **verified 0 occurrences of `validate`**; `:349-355` maps `W25:E4` payload-agnostic ingress to `tests/test_message.py` — **verified 0 occurrences of `RawMessage`/`content_type`**; `:330` labels `W25:E1` "Tolerant peek (python-hl7) routing" though the built-ins parser is the default | The acceptance report claims automated coverage that does not exist for the single most safety-critical HL7 control. Auditors and the Windows acceptance run both consume this map | No readback gate on cited-file relevance | P2 |
| `MSH-18` (character set) is absent from code and docs | Zero hits for MSH-18 anywhere in `messagefoundry/` or `docs/`; decode uses only the connection's `encoding` setting (`wiring_runner.py:3489`, `peek.py:152`) | A partner declaring `MSH-18 = 8859/1` (the vendored `erp_z99_v231.hl7` does exactly this, verified in its MSH) is decoded as UTF-8 → `UnicodeDecodeError` → ERROR + AR NAK for the whole feed, with no documented rationale | No — neither built nor declined in writing | P2 |
| Non-ASCII fidelity is pinned only at the `Message` level, never on a derived value | Accented Latin and one CJK code point are asserted through `Message` read/write/encode (`test_message.py:156,160-162`), the custom-separator path (`test_hl7_core_features.py:82-100`) and the raw-separator codec (`test_hl7_raw_separators.py:42`). **Nothing** exercises non-ASCII through `Peek.field`/`routing()`, the `\Xhh\` hex branch, `parse_tree` leaves or `summarize()` — i.e. through any value the engine *derives* and persists; combining marks and NFC-vs-NFD are untouched at every level; and `normalize()` defaults to `errors="replace"` (`peek.py:152`), so a wrong-encoding decode silently yields U+FFFD instead of raising | An accented-name or CJK feed routes correctly but is delivered and displayed mangled — the raw is preserved, every derived value is not, and **no disposition records the substitution**, so it is a count-and-log-clean silent corruption. `MSH-18` (row above) is the declaration side of the same hole | Partly — `Message`-level only; no coverage of any derived value, of CJK breadth, or of normalisation forms | **P1** |
| No default `UnmappedSink` installed | `code_sets.py:255 _sink = None`; the only callers of `set_unmapped_sink` are tests (`test_code_sets_policy.py`, `test_run_context.py`) — **no production installer** | A one-line regression silently creates a new PHI-at-rest surface (unmapped keys are PHI per `docs/CODESETS.md`) with no encryption, audit or retention, and the existing PHI-no-log tests still pass | No test pins the default | P2 |
| Full generator corpus revalidation is unreachable | `MEFOR_FULL_CORPUS=1` (`tests/test_generated_adt.py:130-142`) appears in **no** workflow — verified by grep over `.github/workflows/` | An index-dependent generator defect (a data pool exhausting, a seeded field colliding at index > 1) escapes CI, and the corpus is the substrate for the parity suite, the harness and the load profiles | No | P2 |

### 5.4 Test matrix

**Row class (`Cls`).** **T** = *Test* — a falsifiable assertion with an observable pass criterion; **only T rows count toward the release gate.** **C** = *Characterisation* — produces a recorded measurement, finding or dated decision with no threshold yet; legitimate work that **cannot fail**, so it never gates a release, and it becomes a T row the day its threshold is recorded. **A** = *Assurance* — an external engagement (pen test, third-party review, DAST), blocking only for an off-loopback / production-exposure release.

**This chapter: 64 rows — 60 T, 4 C, 0 A.** Of the 60 T rows, **10 are P0** (PARSE-01..PARSE-10, the two proven count-and-log breaks), 20 are P1 and 30 are P2. Counting every row regardless of class: 10 P0, 22 P1, 32 P2. The four C rows are **PARSE-34** (a cp314t number in a weekly log), **PARSE-40** (a published surviving-mutant baseline), **PARSE-56** (a real-partner dialect capture whose divergences are filed, not failed) and **PARSE-58** (a real partner WSDL whose unsupported constructs are recorded as known limitations). No A rows: parsing is a pure library with no external-engagement surface — the pen-test/DAST rows live in the **SEC** chapter.

**Foreign IDs.** `FCP:` prefixes a `docs/testing/FEATURE-COVERAGE-PLAN.md` gap ID and `W25:` a WIN2025 test/matrix ID. A bare `PARSE-nn` always means a row in **this** table — note that `FCP:PARSE-12`/`14`/`15` and this plan's PARSE-12/14/15 are *different* rows.

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| PARSE-01 | Blank-segment body through the real ingress path: `RegistryRunner._handle_inbound` with `MSH…\rEVN…\r\rPID…\r` | Negative/Security | pytest | container-CI | SQLite | T | P0 | `_handle_inbound` returns without raising; exactly one `messages` row; `status` is a recorded disposition (`ERROR` if refused, `RECEIVED` if tolerated per the PARSE-OQ1 ruling); a wire ACK string is returned (`MSA\|AR` on refuse, `MSA\|AA` on tolerate); no `IndexError` escapes; `COUNT(*) FROM queue` matches the chosen disposition (0 on refuse, 1 on tolerate) |
| PARSE-02 | `Peek.field`/`routing()`/`message_code`/`control_id` contract on a blank-segment body | Negative/Security | pytest | container-CI | n/a | T | P0 | No call raises anything other than `HL7PeekError`; a bare `IndexError` from `_builtin_hl7.raise_if_blank_segment_scan` reaching the caller is a failure |
| PARSE-03 | `summarize()` on a blank-segment body | Negative/Security | pytest | container-CI | n/a | T | P0 | Returns a `str` (possibly empty) or raises `HL7PeekError`; never `IndexError` |
| PARSE-04 | Real-vendor blank-segment corpus driven through ingress: `samples/messages/hapi-hl7v2/oml_o21.hl7` (26 interior blank lines) and `batch_18_messages.txt` (17) | Negative/Security | pytest | container-CI | SQLite | T | P0 | Every message yields exactly one `messages` row with a recorded disposition and a returned ACK; total rows equals the number of messages fed; no unhandled exception |
| PARSE-05 | MLLP connection survives a blank-segment frame: send the frame twice over one socket | HA/Resilience | pytest | container-CI | SQLite | T | P0 | The second frame receives an ACK on the **same** socket; no `framing_error` counter increment attributable to the blank segment; the listener task is still alive afterwards |
| PARSE-06 | `_builtin_hl7.unescape('\X00\', seps)` unit | Negative/Security | pytest | container-CI | n/a | T | P0 | Documented and asserted: either the NUL is emitted (current behaviour, pinning it) **or** the sequence is dropped — the chosen contract is asserted with an absolute expected value, not left implicit |
| PARSE-07 | `summarize()` over a `PID-3.1` carrying `AB\X00\CD` | PHI | pytest | container-CI | n/a | T | P0 | `"\x00" not in summarize(peek)` — the derived summary is NUL-free regardless of what `unescape` emits |
| PARSE-08 | End-to-end pre-ACK: NUL-in-derived-summary body through `_handle_inbound` on SQLite | Negative/Security | pytest | container-CI | SQLite | T | P0 | One `messages` row; `messages.summary` read back contains no `\x00` and is not truncated at the escape position; an ACK is returned |
| PARSE-09 | Cross-backend twin of PARSE-08, mirroring `test_ingest4_nul_ingress_persists_error_row` | Cross-backend | pytest | container-CI | x2 (server DBs) | T | P0 | Postgres: no `asyncpg.DataError`/SQLSTATE 22021 escapes `_handle_inbound`, the connection is not dropped, the row round-trips. SQL Server: the persisted `summary` is not NVARCHAR-truncated at the NUL |
| PARSE-10 | Derived-value NUL twins beyond `summary`: `\X00\` in MSH-10 (→ `control_id`) and MSH-9 (→ `message_type`) | Negative/Security | pytest | container-CI | x3 (all three) | T | P0 | Every value passed to `enqueue_ingress` is NUL-free; no bind error on Postgres; one `messages` row per body |
| PARSE-11 | Anti-vacuity twin for PARSE-06..10: the same bodies with `\X41\` (a benign `A`) | Functional | pytest | container-CI | SQLite | T | P1 | Bodies ACK `AA`, land `RECEIVED`, and the summary contains the expected literal — proving the NUL assertions are not passing because the fixture is inert |
| PARSE-12 | Frozen golden-vector oracle: serialize the current parity matrix (corpus × probe paths × mutation ops, both backends) into a committed JSON file and assert against it | Compat | pytest | container-CI | n/a | T | P1 | A committed `tests/data/hl7_golden_vectors.json` exists; the built-ins backend reproduces every recorded value byte-for-byte with python-hl7 **uninstalled**; the generator is re-runnable and its output is byte-stable across two runs |
| PARSE-13 | Widen `_sample_corpus()` from `rglob('*.hl7')` to also take `*.txt`, splitting batch files on MSH boundaries as it already does | Compat | pytest | container-CI | n/a | T | P1 | All 26 vendored HAPI messages (7 files) appear as parity units; the parametrize id list is asserted to contain `adt_a01.txt`, `adt_a03.txt`, `omd_o03.txt`, `omd_o03_rep.txt` and ≥18 units from `batch_18_messages.txt` |
| PARSE-14 | Parity `_eq()` exception comparison tightened: an exception outside the documented contract set is a parity **failure**, not a match | Negative/Security | pytest | container-CI | n/a | T | P1 | `_eq()` treats a raised `IndexError` as a failure unless the corpus unit is on an explicit, commented divergence allow-list; the allow-list is empty or each entry names its ADR/BACKLOG justification |
| PARSE-15 | AC-4 subcomponent-depth probes under custom encoding characters; correct the inverted comment at `test_builtin_hl7_parity.py:454` | Functional | pytest | container-CI | n/a | T | P2 | `PID-3.1.1` and `PID-5.1.2` probe paths added with **absolute** expected values (not just cross-backend equality); the comment states `MSH-2[2]` = escape, `MSH-2[3]` = subcomponent, matching `_builtin_hl7.py:130-131` |
| PARSE-16 | Strict `validate()` version matrix over the vendored HAPI corpus (2.1, 2.3, 2.3.1, 2.4, 2.5, 2.5.1) | Compat | pytest | container-CI | n/a | T | P1 | For every version in the owner-declared supported set (PARSE-OQ4), `validate(body, expected_version=<v>)` returns a `ValidationResult` and never raises; each `(file, version) → ok` outcome is asserted against a recorded expectation, so an hl7apy upgrade that flips one reds the build |
| PARSE-17 | Z-segment tolerance under strict validation | Compat | pytest | container-CI | n/a | T | P1 | `validate(conformant_adt_a01 + "ZPD\|1\|custom^data\r")` returns `ok is True` with `errors == []` |
| PARSE-18 | Unknown non-Z three-character segment under strict validation | Compat | pytest | container-CI | n/a | T | P1 | The outcome (accept or reject) is asserted with an absolute expectation and a comment naming the intended contract |
| PARSE-19 | `validate(profile=…)` no-op contract | Functional | pytest | container-CI | n/a | T | P2 | Per the PARSE-OQ11 ruling, either: passing a profile object returns the identical `ValidationResult` as omitting it (asserted field-by-field), **or** it raises `NotImplementedError` |
| PARSE-20 | `ValidationResult.errors` PHI redaction at the library boundary | PHI | pytest | container-CI | n/a | T | P2 | A synthetic canary token (e.g. `ZZCANARYZZ`) placed in a field that trips a datatype/length rule appears **nowhere** in `result.errors`, and nowhere in the persisted `messages.error` after `_handle_inbound` |
| PARSE-21 | `parse_tree()` under custom encoding characters (`MSH#@$%^\|…`) | Functional | pytest | container-CI | n/a | T | P1 | Field/component/subcomponent split matches `_builtin_hl7._extract_separators` for the same body; asserted node-by-node on at least one 3-deep path |
| PARSE-22 | `parse_tree()` with a legal three-character MSH-2 (`^~\`) — the verified divergence | Functional | pytest | container-CI | n/a | T | P1 | `tree._separators(msh)[3]` equals `_builtin_hl7._extract_separators(msh)[3]` (`'&'`), not the field separator; a value `A^B&C` splits to subcomponents `B` and `C` in the tree, matching `Peek.field('PID-3.2.1')` |
| PARSE-23 | `parse_tree()` size/segment caps (its own `enforce_size_limits` call at `tree.py:54`) | Negative/Security | pytest | container-CI | n/a | T | P2 | A >16 MiB body and a >10 000-segment body each raise `HL7PeekError` from `parse_tree`, with the numeric-only message (no field value) |
| PARSE-24 | Escaped-vs-unescaped viewer contract, documented and asserted | Functional | pytest | container-CI | n/a | T | P1 | Per the PARSE-OQ10 ruling: for a `PID-5.1` of `O\S\Brien`, the tree leaf value and `Peek.field('PID-5.1')` are asserted to the chosen contract (identical after a tree-side unescape, or explicitly divergent with the divergence stated in `tree.py`'s docstring) |
| PARSE-25 | `parse_tree()` on a blank-segment body | Negative/Security | pytest | container-CI | n/a | T | P2 | Returns a node list with the blank line dropped (current `tree.py:57` behaviour) and raises nothing — pinned so the harness pane stays safe when PARSE-01's fix lands |
| PARSE-26 | Rich-text escape branches absolute oracle: `.br`, `.sp`, `.fi`, `.nf`, `.in`, `.ti`, `.sk`, `.ce`, each with and without a count | Functional | pytest | container-CI | n/a | T | P2 | Each of the eight branches has an absolute expected output string (not a cross-backend comparison), including `\.in0\` → `""` and `\.in513\` → `""` (over `MAX_ESCAPE_REPEAT`) |
| PARSE-27 | `\Cxx\` / `\Mxx\` charset-switch branches absolute oracle | Functional | pytest | container-CI | n/a | T | P2 | Both drop to empty string with the surrounding text intact, asserted absolutely |
| PARSE-28 | `\Xhh\` hex branch absolute oracle: odd-length hex, non-hex chars, multi-byte runs, `\X41 42\` | Functional | pytest | container-CI | n/a | T | P2 | Each case has an absolute expected value; a malformed run drops without raising |
| PARSE-29 | Harness/console client peek surfaces on a blank-segment body | Usability | pytest | dev-PC | n/a | T | P2 | With `QT_QPA_PLATFORM=offscreen`, `harness/compose.py::_peek`, `harness/mllp.py:74,264`, and `harness/file_transport.py:157` each degrade to their `?`/fallback value rather than propagating an exception |
| PARSE-30 | `MEFOR_REQUIRE_EXTRAS=1` no-silent-skip guard in `tests/conftest.py` | Compat | CI-leg | container-CI | n/a | T | P1 | On the ubuntu/windows-2022/windows-2025 full-suite legs, a session-finish hook fails the run if any test was skipped by an `importorskip` for `pydicom`/`pynetdicom`/`fhir.resources`/`fhirpathpy`/`pyx12`/`lxml`/`xmlschema`/`signxml`; a deliberate uninstall of one extra reds the leg |
| PARSE-31 | WSDL `<soap:body parts=…>` selector honoured | Functional | pytest | container-CI | n/a | T | P1 | A fixture with a two-part `wsdl:message` and a binding selecting the **second** part makes `validate_envelope` accept an envelope whose body child is part 2 and reject one whose body child is part 1 |
| PARSE-32 | WSDL rpc/encoded refusal stays loud | Negative/Security | pytest | container-CI | n/a | T | P2 | An rpc/encoded operation raises `WsdlError` naming the operation, with no element content in the message |
| PARSE-33 | ADR 0054 AC-6 authoritative scaling measure on the cp314t bench box | Performance | external | dev-PC (cp314t bench) | n/a | T | P1 | Recorded under `docs/benchmarks/`: multi-core ≥6× and single-thread ~14× vs the recorded python-hl7 baseline, with the environment stamp and `sys._is_gil_enabled() is False` in the same artefact |
| PARSE-34 | Add `tests/test_benchmark_parser.py` to the `freethread-smoke.yml` subset | Performance | CI-leg | container-CI | n/a | C | P1 | The weekly cp314t run's log contains the measured msg/s and the multi/single ratio; the anti-vacuous-pass verdict step counts the bench tests among those that "flew". **Characterisation:** the leg publishes a number, it does not assert a threshold — the AC-6 verdict is PARSE-33's. Becomes a T row if the PARSE-OQ5 ruling makes the ratio blocking here |
| PARSE-35 | Single-thread throughput baseline ratchet | Performance | pytest | container-CI | n/a | T | P2 | Replace the flat `rate > 200.0` with a recorded baseline in `docs/benchmarks/` and a tolerance band; a deliberate 3× slowdown injected into `_builtin_hl7.parse` reds the test |
| PARSE-36 | Malformed/oversized synthetic corpus generator | Negative/Security | harness | container-CI | n/a | T | P1 | A seeded, deterministic, PHI-free-by-construction hostile catalogue is emitted (blank segment, `\X00\`, no-MSH, truncated MSH, 3-char MSH-2, custom separators, wrong version, over-cap bytes, over-cap segments, over-budget escape composition, torn MLLP frame, non-UTF-8 bytes, unterminated escape); two runs with the same seed produce byte-identical output; no case contains a name/MRN outside the generator's synthetic pool |
| PARSE-37 | Every hostile case from PARSE-36 driven through `_handle_inbound` | Negative/Security | pytest | container-CI | x3 (all three) | T | P1 | For every case: exactly one `messages` row with a non-null `status` and (for HL7v2 inbounds) a returned ACK string; zero unhandled exceptions across the whole catalogue; the `queue` row count matches the disposition |
| PARSE-38 | Property-based round-trip invariant (hypothesis, pending PARSE-OQ7) | Negative/Security | pytest | container-CI | n/a | T | P2 | For generated HL7-shaped bodies, `Message.parse(b).encode() == b` whenever no mutation was applied; counterexamples are minimised and committed as regression cases |
| PARSE-39 | Property-based never-raise invariant | Negative/Security | pytest | container-CI | n/a | T | P2 | For arbitrary byte strings, `Peek.parse` raises only `HL7PeekError`; for anything that parses, `Peek.field` over a valid path raises only `HL7PeekError`; `validate()` never raises at all |
| PARSE-40 | Mutation coverage over `messagefoundry/parsing/` per `docs/quality-gates/HANDOFF-mutation-coverage.md:223` | Compat | CI-leg | container-CI | n/a | C | P2 | A non-blocking scheduled leg publishes a surviving-mutant count for `parsing/`; the count is recorded as the baseline and any increase is reported in the run summary |
| PARSE-41 | `MEFOR_FULL_CORPUS=1` full generator-corpus regeneration on a scheduled leg | Compat | CI-leg | container-CI | n/a | T | P2 | A weekly non-blocking workflow runs `tests/test_generated_adt.py` with `MEFOR_FULL_CORPUS=1`; all 2 850 ADT messages generate and pass the hl7apy gate; the run log states the message count so a collapsed corpus is visible |
| PARSE-42 | MSH-18 (character set) decision, encoded as a test | Compat | pytest | container-CI | n/a | T | P2 | Per the PARSE-OQ3 ruling: either a body declaring `MSH-18 = 8859/1` on a `utf-8` inbound decodes via MSH-18, or a test asserts the declined-by-design behaviour (decode by the connection's `encoding` only) and `docs/CONNECTIONS.md` states it. `samples/messages/hapi-hl7v2/erp_z99_v231.hl7` is the fixture |
| PARSE-43 | Non-UTF-8 feed disposition: cp1252/latin-1 bytes on a `utf-8` inbound | Negative/Security | pytest | container-CI | x3 (all three) | T | P2 | One `messages` row with `status=ERROR` and `error` starting `decode error (utf-8)`; an `MSA\|AR` NAK is returned; the preserved raw round-trips to the original bytes via the `mfb64` ERROR-path seam; no NUL reaches the store |
| PARSE-44 | UTF-8 BOM immediately before `MSH` | Negative/Security | pytest | container-CI | n/a | T | P2 | `Peek.parse` either strips the BOM and routes normally, or raises `HL7PeekError` ("does not start with an MSH segment") and the listener records `ERROR` + NAK — the chosen behaviour is asserted, never an unhandled exception |
| PARSE-45 | Truncated MSH shapes: `MSH` alone, `MSH\|`, `MSH\|^~`, `MSH\|^~\&` with no further fields | Negative/Security | pytest | container-CI | n/a | T | P1 | Each yields either a routable `Peek` or an `HL7PeekError`; `_extract_separators` never raises `IndexError`; each shape driven through `_handle_inbound` produces exactly one `messages` row |
| PARSE-46 | Segment-repeat and occurrence breadth on a real-vendor body: `omd_o03_rep.txt` | Functional | pytest | container-CI | n/a | T | P2 | Repeating segment occurrences resolve at the expected indices under both backends, with absolute expected values for at least two paths |
| PARSE-47 | Very long single field and very long single segment (under the byte cap, over typical assumptions) | Negative/Security | pytest | container-CI | SQLite | T | P2 | A 1 MiB single field parses, routes, and commits within the 16 MiB cap; no quadratic blow-up (the test completes inside the 60 s pytest timeout at `pyproject.toml:228`) |
| PARSE-48 | `code_sets._sink` default-None pin | PHI | pytest | container-CI | n/a | T | P2 | At import, `messagefoundry.config.code_sets._sink is None`; a `capturing()` scope with unmapped keys drains to nothing persisted; no production module calls `set_unmapped_sink` (asserted by an AST/grep scan over `messagefoundry/`) |
| PARSE-49 | Unmapped-key PHI-no-log at INFO+ under a real Router/Handler run | PHI | pytest | container-CI | SQLite | T | P2 | With `caplog` at INFO, no captured record contains the unmapped key value; DEBUG records carry counts only — extends the existing assertions to the runner-bracketed path, not just direct `capturing()` |
| PARSE-50 | Acceptance evidence-map repoint: `W25:E1` label, `W25:E2` → `tests/test_parsing.py` (`test_validate_*`), `W25:E4` → `tests/test_payload_agnostic_ingress.py` + `tests/test_binary_carriage.py` | Compat | pytest | container-CI | n/a | T | P2 | `harness/acceptance/matrix.py` rows `W25:E1`/`W25:E2`/`W25:E4` updated **and** the evidence-map readback gate extended: for each row, at least one cited file must contain a token from the feature's API (`validate`, `RawMessage`/`content_type`, `Peek`) — the gate fails on today's `test_hl7schema.py`/`test_message.py` pointers |
| PARSE-51 | Web console `/ui` parse-tree render of a custom-encoding-chars message and an escaped `\S\` leaf | Usability | manual | browser-matrix | SQLite | T | P2 | Hierarchy matches PARSE-21/PARSE-24's asserted contract on screen; no blank/undefined nodes; a Z-segment renders with its fields |
| PARSE-52 | Harness Qt parse-tree pane — `ParseTreeView` in the console-rehomed widget module (`harness/_console_widgets.py:159`, `parse_tree(raw)` at `:170`) with the same two bodies | Usability | manual | dev-PC | SQLite | T | P2 | Renders identically to the web console for the same body; a blank-segment body renders without an exception dialog. Rendering *correctness for this parse tree* is scoped here; the harness GUI itself (window, tabs, widget lifecycle, packaging) is owned by **TRAY** §13d — no harness-GUI work is scoped in this chapter beyond driving the pane |
| PARSE-53 | VS Code Test Bench UTF-8 byte/hex pane (ADR 0119) and HL7-aware before/after diff (ADR 0121) | Usability | ide-mocha | dev-PC | n/a | T | P2 | A CJK field and a `\X41\` escape each display the expected byte sequence; the diff highlights only the changed field path |
| PARSE-54 | VS Code code-set grid editor (ADR 0033) | Usability | ide-mocha | dev-PC | n/a | T | P2 | Create/edit/rename/delete round-trip to `codesets/<name>.csv`; read-only TOML mode blocks edits; a CLI validation error surfaces inline |
| PARSE-55 | HL7 field-path autocomplete driven by `hl7schema.json`/`hl7structures.json` | Usability | ide-mocha | dev-PC | n/a | T | P2 | `PID-5.` offers component names for 2.5.1; the picker badge states the pinned version |
| PARSE-56 | Real-partner HL7 dialect conformance against an anonymised production capture | Compat | external | dev-PC | SQLite | C | P1 | A capture produced through the ADR 0030 `tee anonymize-captures` path (never raw PHI) is replayed; every message yields a recorded disposition; any parse divergence is filed as a corpus addition |
| PARSE-57 | Real DICOM modality / PACS Structured Report round-trip through the SR→HL7 mapper | Compat | external | dev-PC | SQLite | T | P2 | A vendor SR (headers/SR only, no pixel data, PHI-free test patient) maps to a routable ORU with the expected OBX paths |
| PARSE-58 | Real partner-supplied WSDL: multi-part messages, `<xsd:import>` graphs, rpc/encoded refusal | Compat | external | dev-PC | n/a | C | P2 | Import either succeeds with correct operation/element resolution or raises `WsdlError` naming the unsupported construct; a multi-document import graph's current non-resolution is recorded as a known limitation |
| PARSE-59 | Harness Compose-tab hostile-input injection during a sustained load phase (`W25:S4.8`) | HA/Resilience | harness | W2025-box | x3 (all three) | T | P2 | With the PARSE-36 generator wired as a load-profile mix entry, hostile messages injected at ≥1 % of a sustained rate produce one `messages` row each, no listener restart, and no throughput cliff on the conformant traffic |
| PARSE-60 | Visual confirmation that a non-UTF-8 / MSH-18-declaring feed renders legibly (or fails legibly) in the operator console | Usability | manual | browser-matrix | SQLite | T | P2 | The ERROR row's message names the encoding; the raw view shows a byte-faithful representation, not mojibake presented as clean text |
| PARSE-61 | Character-set fidelity through the **tolerant peek** path: accented Latin (`Müller`, `José`, `Österreich`), CJK (`李四`, `東京`), a combining-mark pair (`e`+U+0301) and its NFC twin, each in PID-3.1, PID-5.1 and MSH-10 | Functional | pytest | container-CI | n/a | T | P1 | Under **both** backends (`_backend.backend(builtin=…)`), `Peek.field`, `Peek.routing()`, `Peek.control_id` and `Message.field` return each value with an **absolute** expected string; no U+FFFD appears in any return; the NFC and NFD forms each round-trip **unchanged** (the library applies no Unicode normalisation of its own) |
| PARSE-62 | Non-ASCII through the **escape codec and re-encode** path: `_builtin_hl7.escape`/`unescape`, `Message.encode()`, and `\Xhh\` runs whose bytes decode to a multi-byte UTF-8 character | Functional | pytest | container-CI | n/a | T | P1 | `Message.parse(b).encode() == b` byte-for-byte for every PARSE-61 value with no mutation applied; `escape()` leaves >U+00FF code points intact, pinning the divergence from python-hl7's `escape()` already recorded at `test_message.py:156`; a write that mixes a >U+00FF char with a live delimiter escapes only the delimiter (extends `test_message.py:160-162` to CJK); each multi-byte `\Xhh\` run has an absolute expected value consistent with PARSE-28's contract |
| PARSE-63 | Non-ASCII through every **derived value** the engine persists: `summarize()`, `parse_tree()` leaves, `control_id`, `message_type` | PHI | pytest | container-CI | n/a | T | P1 | For the PARSE-61 corpus: `summarize()` and each tree leaf carry the exact input code points — no U+FFFD, no mojibake, and no truncation that splits a code point or a combining sequence; any summary length cap is applied in code points, not bytes; the PHI-free `routing()` dict has the same key shape as its ASCII twin (anti-vacuity: the ASCII twin is asserted in the same test) |
| PARSE-64 | Declared `MSH-18` + the decode matrix driven through ingress: UTF-8 / latin-1 / cp1252 bytes × (MSH-18 declared, MSH-18 absent), using `samples/messages/hapi-hl7v2/erp_z99_v231.hl7` (declares `MSH-18 = 8859/1`, verified in its MSH) as the declared fixture | Cross-backend | pytest | container-CI | x3 (all three) | T | P1 | Every combination yields exactly one `messages` row with a recorded disposition and a returned ACK/NAK. A `normalize()` substitution (U+FFFD from the `errors="replace"` default, `peek.py:152`) is **never** allowed to land as a clean `RECEIVED`: it is either eliminated or recorded as an `ERROR`/warning disposition per the PARSE-OQ14 ruling. The preserved raw round-trips to the original bytes on SQLite, PostgreSQL and SQL Server. The MSH-18-honouring branch is asserted only once PARSE-OQ3 rules; the substitution-disposition half is unconditional. Store round-trip *display* and console codepage are **MIG**'s (MIG-67/MIG-68) |

### 5.5 Detailed scenarios

#### S-PARSE-A — Blank-segment ingress disposition (PARSE-01, PARSE-04, PARSE-05)

**Why narrative.** The fix is blocked on an owner ruling (PARSE-OQ1) because the current behaviour is a *deliberate* byte-parity replication of a python-hl7 defect (`_builtin_hl7.raise_if_blank_segment_scan`, whose docstring says so explicitly). Getting the test right means writing the assertion against the ruling, not against today's behaviour, and simultaneously breaking the parity oracle's certification of the defect.

**Preconditions.** Repo at the project root; `.venv` with `[dev]` installed; python-hl7 still installed (needed for PARSE-14's allow-list work).

**Steps.**
1. Reproduce first, so the test is written against a demonstrated failure:
   ```
   .venv/Scripts/python.exe -c "from messagefoundry.parsing.peek import Peek; p = Peek.parse(open('samples/messages/hapi-hl7v2/oml_o21.hl7', encoding='utf-8').read()); print(p.field('MSH-9'))"
   ```
   Observed today: `IndexError: string index out of range`.
2. Add the ingress test to `tests/test_builtin_hl7_hardening.py`, reusing the existing `store` fixture and `_hl7_registry()` helper at `tests/test_builtin_hl7_hardening.py:513-535` verbatim — that rig already opens a real `MessageStore`, builds a `Registry` with one MLLP inbound and a no-op Router, and asserts on `messages` + `queue`.
3. Feed the body as **bytes** through `runner._handle_inbound(reg.inbound["IB_HL7"], body)` — not through `Peek` directly. The whole point is that the failure is at `wiring_runner.py:3721` (`peek.control_id`) and `:3732` (`summarize(peek)`), outside every catch.
4. Add the real-vendor variant driving each message split out of `samples/messages/hapi-hl7v2/oml_o21.hl7` and `batch_18_messages.txt`.
5. Add the socket-level variant (PARSE-05): open one MLLP connection, send the blank-segment frame, read the reply, send a **conformant** frame on the same socket, read the reply.

**Observation point.** `SELECT status, error FROM messages` and `SELECT COUNT(*) FROM queue` on the test store; the returned ACK string; for PARSE-05, whether the second frame's reply arrives on the same socket.

**Expected result.** Under either ruling, `_handle_inbound` returns normally and the message is counted. Under "correctness wins": one `ERROR` row, `MSA|AR`, zero `queue` rows. Under "tolerate": one `RECEIVED` row, `MSA|AA`, one `queue` row. What is **not** acceptable under either: an `IndexError` escaping, zero `messages` rows, or a dropped socket.

**Cleanup/rollback.** `tmp_path` store is discarded by the fixture. If the ruling is "correctness wins", the same PR must add the divergence allow-list entry (PARSE-14) for `adv:empty-fields` and `oml_o21.hl7`, or the parity suite will red.

#### S-PARSE-B — `\X00\` NUL in a derived value, across store backends (PARSE-06..10)

**Why narrative.** The NUL never appears in the raw text, so the `FCP:INGEST-4` guard at `wiring_runner.py:3523` cannot see it; it materialises only inside `summarize()`. Proving the consequence requires Postgres — SQLite and SQL Server truncate silently and cannot demonstrate the bind failure.

**Preconditions.** A PostgreSQL service container and a SQL Server 2022/2025 container with ODBC Driver 18, reachable via whatever env vars `tests/test_postgres_store.py` and `tests/test_sqlserver_store.py` already use for their gates. PHI-free synthetic body only.

**Steps.**
1. Confirm the reproduction:
   ```
   .venv/Scripts/python.exe -c "from messagefoundry.parsing.peek import Peek; from messagefoundry.parsing.summary import summarize; b='MSH|^~\\\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\rPID|1||AB\\\\X00\\\\CD^^^H^MR||DOE^JANE\r'; s=summarize(Peek.parse(b)); print(repr(s), chr(0) in s)"
   ```
   Observed today: `'MRN AB\x00CD · DOE, JANE' True`.
2. Add the unit tests (PARSE-06, PARSE-07) to `tests/test_builtin_hl7_hardening.py`.
3. Add the SQLite end-to-end (PARSE-08) using the same `_handle_inbound` rig as S-PARSE-A.
4. Add the gated cross-backend twins (PARSE-09) to `tests/test_postgres_store.py` and `tests/test_sqlserver_store.py`, mirroring the shape and naming of the existing `test_ingest4_nul_ingress_persists_error_row`. Assert on the **exception type and SQLSTATE** (`asyncpg.DataError` / `22021`), never on a driver message string.
5. Add the MSH-10 / MSH-9 twins (PARSE-10) — `control_id` and `message_type` are the two other derived values passed to `enqueue_ingress`.
6. Add the `\X41\` anti-vacuity twin (PARSE-11) so a fixture that silently stops carrying an escape is caught.

**Observation point.** For Postgres: whether any exception escapes `_handle_inbound`, and `SELECT summary FROM messages`. For SQL Server: the persisted `summary` length vs the expected string length.

**Expected result.** No exception escapes on any backend; `summary` is NUL-free and not truncated; exactly one `messages` row per body.

**Cleanup/rollback.** Containers are per-run. If the chosen fix is to scrub at the derived-value boundary rather than in `unescape`, PARSE-06's assertion must record the *unchanged* `unescape` behaviour so the two layers do not silently disagree — the same "two callers on the same text must be incapable of disagreeing" property `peek.enforce_expansion_budget` was built around.

#### S-PARSE-C — Freezing golden vectors before ADR 0054 Phase 2 (PARSE-12)

**Why narrative.** Ordering is load-bearing: the vectors must be generated **while python-hl7 is still installed** and must then be validated with it **uninstalled**, otherwise the file merely records the built-ins' own output and proves nothing.

**Preconditions.** python-hl7 (`hl7>=0.4.5`, `pyproject.toml:48`) installed. The PARSE-13 corpus widening merged first, so the vectors cover all 26 vendored messages rather than 2 files' worth.

**Steps.**
1. Add a generator entry point (a `pytest` marker or a small script under `scripts/`) that walks the existing parity matrix — `_sample_corpus()` + `_synthetic_corpus()` + `_ADVERSARIAL`, × the 66-path probe battery × the 12-op mutate matrix — under `_backend.backend(builtin=False)` and writes `tests/data/hl7_golden_vectors.json`.
2. Record, per unit: the input label, the probe path, and either the string value or the exception **type name**. Record no message bodies beyond the corpus already committed in-repo (all PHI-free).
3. Run it twice and diff — byte-stability is a precondition of committing it.
4. In a scratch venv, `pip uninstall hl7`, then run the golden-vector assertion test. It must pass with the built-ins backend alone.
5. Commit the JSON plus the assertion test. Add a note to ADR 0054's Migration step 5 that Phase 2 is gated on it.

**Observation point.** The uninstalled-python-hl7 run's pass/fail, and the collected test count (a suite that collects zero tests without python-hl7 is the vacuous-pass shape `freethread-smoke.yml`'s verdict step was written to catch).

**Expected result.** Golden-vector test passes with python-hl7 absent; the live parity suite skips or is deselected cleanly rather than erroring at import.

**Cleanup/rollback.** Delete the scratch venv. Do not modify the real `.venv` or `pyproject.toml` in this scenario — the dependency drop is Phase 2's own PR.

#### S-PARSE-D — `parse_tree()` separator divergence (PARSE-21, PARSE-22, PARSE-24)

**Why narrative.** The divergence is easy to test wrongly: `tree.py` has an *independent* derivation (`tree.py:65-72`), so a test that only checks the standard `|^~\&` case passes on both the correct and the broken implementation. The failing case needs a legal-but-uncommon MSH-2.

**Preconditions.** None beyond `[dev]`.

**Steps.**
1. Confirm the divergence:
   ```
   .venv/Scripts/python.exe -c "from messagefoundry.parsing.tree import _separators; from messagefoundry.parsing import _builtin_hl7 as B; m='MSH|^~\\\\|APP|FAC|R|RF|20260101||ADT^A01|1|P|2.5.1'; print(_separators(m), B._extract_separators(m))"
   ```
   Observed today: `('|', '^', '~', '|')` vs `('|', '^', '~', '&', '\\')` — the tree's subcomponent separator **is** the field separator.
2. Add PARSE-22 to `tests/test_parse_tree.py`, asserting the tree derivation against `_builtin_hl7._extract_separators` for: the standard 4-char MSH-2, the 3-char MSH-2, and the 5-char custom set `#@$%^`.
3. Add PARSE-21: build a full `MSH#@$%^|…` body and assert node-by-node down to a subcomponent.
4. Add PARSE-24: assert the escaped-vs-unescaped leaf contract for `PID-5.1 = O\S\Brien`, and update `tree.py`'s module docstring to state it either way.

**Observation point.** The returned `TreeNode` tree, compared path-by-path with `Peek.field` over the same paths.

**Expected result.** After the fix, tree and parser agree on all five separators for all three MSH-2 lengths; the escaped-leaf contract is stated in the docstring and asserted.

**Cleanup/rollback.** Pure-library change, no state. If the fix is to reuse `_builtin_hl7._extract_separators` from `tree.py`, note that `tree.py` currently imports only from `peek.py` — importing `_builtin_hl7` directly is consistent with `peek.py`'s own import at `peek.py:29`.

#### S-PARSE-E — Malformed/oversized corpus generator (PARSE-36, PARSE-37, PARSE-59)

**Why narrative.** This is the shared dependency of three areas (this chapter, the load harness, and the count-and-log invariant tests) and it must be PHI-free *by construction*, not by review. It also must not use `messagefoundry generate`'s existing path: `generators/_core.generate_message` strict-validates every message it emits (`_core.py:495`) and raises on an unknown trigger, so it structurally cannot produce a bad message.

**Preconditions.** A ruling on ownership (PARSE-OQ6). The CLI surface today is `--type/--trigger/--count/--out/--seed/--list/--json` (`messagefoundry/__main__.py:349-362`) — there is no `--malformed` flag and no `--show-message` flag.

**Steps.**
1. Add `messagefoundry/generators/malformed.py` with a named, seeded catalogue. Every case is derived by *mutating* a synthetic conformant body from the existing generators, so no new patient-data pool is introduced.
2. Cases (minimum): blank segment; `\X00\` in PID-3.1, MSH-9 and MSH-10; no MSH; `MSH` alone; `MSH|`; 3-char MSH-2; 5-char custom MSH-2; wrong MSH-12 for a strict inbound; body over `DEFAULT_MAX_MESSAGE_BYTES`; >10 000 segments; escape composition just over the ASVS 1.3.3 budget; >`MAX_COUNTED_ESCAPE_OPENERS` counted openers; unterminated trailing escape; cp1252 bytes; UTF-8 BOM before MSH; torn MLLP frame (no trailing `\x1c\x0d`).
3. Expose it as a CLI mode (e.g. `messagefoundry generate --malformed`) that writes to `--out` like the conformant path.
4. **PHI discipline:** the generator's stdout is a full message body. Treat it exactly like `dryrun`/`generate` per CLAUDE.md §9 — never redirect it into a committed file, a ticket, or a CI log. The corpus directory stays git-ignored; the *catalogue definition* (the mutation recipes) is what gets committed.
5. Wire the catalogue into PARSE-37 as a pytest parametrize over `_handle_inbound`.
6. Wire it as a load-profile mix entry for PARSE-59 / `W25:S4.8`.

**Observation point.** For PARSE-37: `messages` row count == case count, every row has a non-null `status`, zero unhandled exceptions. For the generator itself: two identical seeded runs diff clean.

**Expected result.** Every hostile shape is counted and logged on all three store backends; the two P0 shapes are in the catalogue and pass only after their fixes land.

**Cleanup/rollback.** Delete the generated corpus directory. Confirm `.gitignore` covers it before the first run.

#### S-PARSE-F — No-silent-skip guard for codec extras (PARSE-30)

**Why narrative.** The failure this guards against is a *green* build, which is exactly the shape nobody investigates. It must be provable by deliberate breakage, not by inspection.

**Preconditions.** `tests/conftest.py` exists; `pyproject.toml:211-231` `[tool.pytest.ini_options]` currently sets `asyncio_mode`, `addopts = "--timeout=60 --timeout-method=thread"` and one marker — no skip accounting.

**Steps.**
1. Add a `pytest_sessionfinish` hook to `tests/conftest.py` that, when `os.environ.get("MEFOR_REQUIRE_EXTRAS") == "1"`, inspects the session's skip reports and fails the session if any skip reason names one of: `pydicom`, `pynetdicom`, `fhir.resources`, `fhirpathpy`, `pyx12`, `lxml`, `xmlschema`, `signxml`, `PySide6`.
2. Set `MEFOR_REQUIRE_EXTRAS=1` on the three full-suite legs in `.github/workflows/ci.yml` (the legs that already install `[dev,harness,fhir,dicom,x12,xml,webauthn]` at line 159). Do **not** set it on any leg that installs a narrower extra set, or that leg reds immediately.
3. Prove it: in a scratch venv, `pip uninstall pydicom`, run the suite with the env var set, and confirm the session fails naming the missing extra.
4. Prove the negative: run without the env var and confirm the same uninstalled state skips silently as today (local extra-less runs must stay usable).

**Observation point.** Session exit status and the failure message's named extra.

**Expected result.** A missing extra reds the CI leg with an actionable message; local runs are unaffected.

**Cleanup/rollback.** Discard the scratch venv. If a leg reds unexpectedly, the correct fix is to widen the leg's install list or narrow the guard's name list — never to remove the env var.

### 5.6 Automation disposition

**New pytest modules**
- `tests/test_hl7_hostile_shapes.py` — PARSE-01..05, PARSE-44, PARSE-45, PARSE-47, and the PARSE-37 catalogue drive. Owns the "every hostile shape gets a disposition" invariant end-to-end. Reuses the `store` fixture and `_hl7_registry()` from `tests/test_builtin_hl7_hardening.py:513-535`. **Effort: M.**
- `tests/test_hl7_golden_vectors.py` + `tests/data/hl7_golden_vectors.json` — PARSE-12. Must be collectable and passing with python-hl7 absent. **Effort: M.**
- `tests/test_hl7_version_matrix.py` — PARSE-16, PARSE-17, PARSE-18, PARSE-42. Parametrized over the vendored HAPI corpus × the declared supported version set. **Effort: M** (blocked on PARSE-OQ4).
- `tests/test_parsing_properties.py` — PARSE-38, PARSE-39. Gated behind a hypothesis dependency decision. **Effort: M** (blocked on PARSE-OQ7).
- `tests/test_hl7_charset_fidelity.py` — PARSE-61, PARSE-62, PARSE-63, and the SQLite half of PARSE-64. One shared corpus constant (accented Latin, CJK, NFC/NFD pair) parametrized across the peek, escape/re-encode and derived-value assertions, run under both parser backends. The cross-backend half of PARSE-64 extends `tests/test_postgres_store.py` + `tests/test_sqlserver_store.py` alongside PARSE-09. The end-to-end console/codepage pass is **not** here — it is MIG-67/MIG-68. **Effort: M.**

**Extends an existing module**
- `tests/test_builtin_hl7_hardening.py` — PARSE-06, PARSE-07, PARSE-08, PARSE-10, PARSE-11, PARSE-26, PARSE-27, PARSE-28. This file already owns the escape codec's absolute-value and pre-ACK-disposition assertions; keep them together. **Effort: S.**
- `tests/test_builtin_hl7_parity.py` — PARSE-13 (widen `_sample_corpus()` to `*.txt`), PARSE-14 (tighten `_eq()` + divergence allow-list), PARSE-15 (subcomponent probes + comment fix). **Effort: S.**
- `tests/test_parse_tree.py` — PARSE-21, PARSE-22, PARSE-23, PARSE-24, PARSE-25. **Effort: S.**
- `tests/test_parsing.py` — PARSE-19, PARSE-20, PARSE-43. **Effort: S.**
- `tests/test_postgres_store.py` + `tests/test_sqlserver_store.py` — PARSE-09 (gated cross-backend NUL twins) and the server-DB half of PARSE-64. **Effort: S.**
- `tests/test_wsdl_import.py` — PARSE-31, PARSE-32. **Effort: S.**
- `tests/test_code_sets_policy.py` — PARSE-48, PARSE-49. **Effort: S.**
- `tests/test_benchmark_parser.py` — PARSE-35 (baseline ratchet replacing the flat 200 msg/s floor). **Effort: S.**
- Harness Qt tests (`QT_QPA_PLATFORM=offscreen`) — PARSE-29. **Effort: S.**
- Acceptance evidence-map readback gate — PARSE-50. **Effort: S.**

**CI legs**
- Extend `.github/workflows/ci.yml` full-suite legs with `MEFOR_REQUIRE_EXTRAS=1` — PARSE-30. **Effort: S.**
- Extend `.github/workflows/freethread-smoke.yml`'s test subset with `tests/test_benchmark_parser.py` — PARSE-34. Keep it non-blocking and keep the verdict step's "did the canary fly" accounting honest. **Effort: S.**
- New weekly non-blocking workflow (or a second job in `freethread-smoke.yml`) running `MEFOR_FULL_CORPUS=1 pytest tests/test_generated_adt.py` — PARSE-41. **Effort: S.**
- New scheduled advisory leg for mutation coverage over `messagefoundry/parsing/` — PARSE-40, per `docs/quality-gates/HANDOFF-mutation-coverage.md`. **Effort: M** (blocked on PARSE-OQ7's dependency decision if mutmut needs locking).

**Harness / probe capability**
- `messagefoundry/generators/malformed.py` + a `generate` CLI mode — PARSE-36. Shared dependency of PARSE-37 and PARSE-59 and of the `W25:S4.8` load acceptance. **Effort: M.**
- Wire the malformed catalogue as a load-profile mix entry in `harness/config/load` — PARSE-59. **Effort: S.**

**Stays manual / external, and why**
- PARSE-51, PARSE-52, PARSE-60 — visual correctness of a rendered hierarchy and of mojibake-vs-legible-failure needs an eyeball; no assertion substitutes. PARSE-52 drives the harness pane only; the harness GUI itself is **TRAY** §13d's (that chapter states it takes ownership because no other did), so schedule PARSE-52 with the TRAY manual matrix rather than standing up a second harness session. PARSE-60's operator-console codepage twin belongs to **MIG** (MIG-67/MIG-68).
- PARSE-53, PARSE-54, PARSE-55 — VS Code webview/TypeScript surfaces; `ide-mocha` under headless VS Code, outside the Python suite.
- PARSE-33 — the authoritative AC-6 re-measure is operator-owned on the cp314t bench box named in ADR 0054's resolved-on-acceptance list; the CI leg (PARSE-34) produces a *number in a log*, not a verdict.
- PARSE-56, PARSE-57, PARSE-58 — a real partner's non-conformance profile, a real modality's SR, and a real partner WSDL cannot be synthesised. PARSE-56 requires an anonymised capture through the ADR 0030 `tee anonymize-captures` path; never a raw PHI capture.
- **Total rough effort:** S ≈ 11 buckets, M ≈ 8 buckets, L ≈ 0 (PARSE-33's bench work is measurement time, not build time).

### 5.7 Environment, data & prerequisites

**Already in place — wire, don't procure**
- `samples/messages/hapi-hl7v2/` — 7 files, 26 messages, HL7 2.1-2.5.1, MPL-2.0, PHI-free, in-repo. Includes `erp_z99_v231.hl7` (a v2.3.1 Z-segment message declaring `MSH-18 = 8859/1`), `oml_o21.hl7` (26 interior blank lines — the PARSE-04 fixture), and `batch_18_messages.txt` (18 messages, 2.1-2.4). Only the two `*.hl7` files are consumed by any test today.
- `samples/messages/adt_a01.hl7`, `adt_batch.hl7`, `x12_270_eligibility.edi`.
- The `[dev,harness,fhir,dicom,x12,xml,webauthn]` install on the three CI full-suite legs (`ci.yml:159`), pinned against `constraints.lock`.
- `.github/workflows/freethread-smoke.yml` — a working cp314t provisioning path with a GIL-disabled assertion and an anti-vacuous-pass verdict.
- The pre-ACK ingress rig at `tests/test_builtin_hl7_hardening.py:513-565`.

**Must be stood up**
- **PostgreSQL service container** — load-bearing for PARSE-09/PARSE-10: it is the only backend that *rejects* a NUL at bind (`DataError`/22021). SQLite and SQL Server truncate silently and cannot demonstrate the failure.
- **SQL Server 2022/2025 container + ODBC Driver 18** — the NVARCHAR-truncation twin for the same cases.
- **Free-threaded CPython 3.14t (cp314t)** — the bench box named in ADR 0054 for PARSE-33, plus the existing `actions/setup-python` freethreaded runner for PARSE-34.
- **python-hl7 (`hl7>=0.4.5`) present** — a hard prerequisite of the parity oracle and of *generating* the golden vectors (PARSE-12); the golden-vector *assertion* must then be validated with it absent.
- **PySide6 with `QT_QPA_PLATFORM=offscreen`** — PARSE-29, PARSE-52.
- **Node + headless VS Code (`@vscode/test-electron`)** — PARSE-53, PARSE-54, PARSE-55.
- **Windows Server 2025 box** — PARSE-59 only (the sustained-load injection); everything else in this chapter is CI-owned per `WIN2025-TEST-PLAN.md:71`.

**Data sets and commands**
- Conformant synthetic corpus: `python -m messagefoundry generate --type ADT --count 50 --out <git-ignored-dir> --seed <seed>`. Registered types today: 13 (ADT, ORU, ORM, DFT, SIU, OML, ORL, MDM, VXU, BAR, RDE, RAS, MFN); ADT covers 57 triggers across 25 structures. Corpus is git-ignored; ~2 850 ADT messages at `--count 50`. Disk: low hundreds of MB.
- Malformed corpus: **to be built** (PARSE-36). Not expressible today — `generators/_core.generate_message` strict-validates every output at `_core.py:495` and raises on an unknown trigger.
- Anonymised real-partner capture: produced only through the ADR 0030 `tee anonymize-captures` path. Never a raw PHI capture, never committed.

**Dependency decisions requiring a DEP-1 vet**
- `hypothesis` (PARSE-38, PARSE-39) and/or `mutmut` (PARSE-40). Both need `pyproject.toml` + `uv lock` + `uv export` per CLAUDE.md §7 — no ad-hoc install.

**PHI discipline reminders specific to this area**
- `dryrun`, `generate`, and the proposed `generate --malformed` all emit full message bodies to stdout. Never redirect their output into a committed file, a ticket, or a CI log.
- Every fixture in this chapter is synthetic. The `\X00\`, canary-token and NUL fixtures use invented MRNs and the generators' own synthetic name pool.
- PARSE-20's canary is a *marker token*, not a realistic name — its whole job is to be unmistakably absent.

### 5.8 Exit criteria

1. **Both P0s closed with tests.** PARSE-01..PARSE-11 all green. Specifically: zero `IndexError` can escape `_handle_inbound` for any body in the PARSE-36 catalogue, and no value passed to `enqueue_ingress` (`raw`, `control_id`, `message_type`, `summary`) contains U+0000 on any of the three store backends.
2. **Count-and-log is falsifiably proven for hostile shapes.** For every one of the ≥15 catalogue cases, on all three backends: exactly one `messages` row with a non-null `status`, and (for HL7v2 inbounds) a returned ACK string. Zero cases produce zero rows.
3. **The parity oracle no longer certifies a defect.** `_eq()` rejects out-of-contract exceptions; the divergence allow-list is either empty or every entry cites an ADR/BACKLOG justification; `_sample_corpus()` covers all 26 vendored HAPI messages.
4. **Golden vectors are committed and green with python-hl7 uninstalled**, and ADR 0054's Migration step 5 records that Phase 2 is gated on them.
5. **HL7 version breadth is declared and tested.** The owner-declared supported version set is written into `docs/HL7-VALIDATION.md`; `validate()` has a recorded pass/fail expectation for every `(vendored file × supported version)` pair; Z-segment tolerance is pinned by an explicit assertion.
6. **No silent extra skips.** `MEFOR_REQUIRE_EXTRAS=1` is set on all three full-suite legs and a deliberate `pip uninstall pydicom` reds the leg.
7. **Viewer and router agree, or the divergence is documented.** `tree._separators` matches `_builtin_hl7._extract_separators` for 3-, 4- and 5-character MSH-2; the escaped-vs-unescaped leaf contract is stated in `tree.py`'s docstring and asserted.
8. **The AC-6 number exists on two surfaces:** an operator-signed measurement under `docs/benchmarks/` from the cp314t bench box, and a per-run number in the weekly `freethread-smoke` log.
9. **The malformed corpus generator ships**, is seeded-deterministic, is wired into PARSE-37, and is available as a load-profile mix entry for `W25:S4.8`.
10. **Evidence-map drift is closed.** `harness/acceptance/matrix.py` rows `W25:E1`/`W25:E2`/`W25:E4` cite files that actually reference the feature's API, enforced by an extended readback gate.
11. **Every open question in §5.9 has a recorded ruling** (an ADR amendment, a BACKLOG entry, or a docs line) — including the ones whose answer is "declined by design", which today are simply absent.
12. **Zero P0 or P1 T rows in this matrix are left in `manual` or `external` disposition without a dated owner and a scheduled run.** (The four C rows — PARSE-34, PARSE-40, PARSE-56, PARSE-58 — are excluded: they produce a recorded number or finding and cannot gate the release.)
13. **Non-ASCII fidelity is pinned on the library side.** PARSE-61..PARSE-64 green: accented Latin, CJK and an NFC/NFD pair survive peek → `Peek.field`/`routing()` → escape/unescape → `Message.encode()` → `parse_tree`/`summarize()` with absolute expected values under both parser backends; no derived value carries U+FFFD; and a decode substitution can never land as a clean `RECEIVED`. The end-to-end pass (store round-trip, CLI/console codepage, operator rendering) is **MIG**'s exit criterion, not this chapter's — MIG-54, MIG-67, MIG-68.

### 5.9 Open questions

1. **Blank-segment: correctness or byte-parity?** `_builtin_hl7.raise_if_blank_segment_scan` deliberately replicates a python-hl7 defect. Fixing it (raise `HL7PeekError`, or skip blank segments) breaks the ADR 0054 AC-1/AC-2 parity contract for `adv:empty-fields` and `oml_o21.hl7`. **Blocks:** PARSE-01, PARSE-02, PARSE-03, PARSE-14, and the shape of the whole S-PARSE-A scenario. If correctness wins, does the parity suite get a documented divergence allow-list, and does the golden-vector file record the *new* behaviour?
2. **`\X00\` — where does the scrub live?** Options: make `unescape` drop the sequence (a parity divergence in the same family as #1); scrub at the `summarize()`/`control_id`/`message_type` boundary; or extend the `FCP:INGEST-4` guard to every derived value before `enqueue_ingress`. **Blocks:** the assertion in PARSE-06 and whether PARSE-10's twins are needed at all.
3. **MSH-18 (character set): honour it on decode, or declare it declined?** It is absent from both code and docs today; the per-connection `encoding` setting is the only lever (`wiring_runner.py:3489`). The vendored `erp_z99_v231.hl7` declares `MSH-18 = 8859/1` (verified in its MSH). **Blocks:** PARSE-42, PARSE-43's expectation, PARSE-60's pass criteria, and PARSE-64's MSH-18-honouring branch.
4. **Which HL7 versions are in support — 2.3? 2.3.1? 2.4? 2.6? 2.7?** Generator breadth, the `hl7schema.py`/`hl7structures.py` 2.5.1 pinning, and the strict-validate matrix all follow from this one answer. **Blocks:** PARSE-16, PARSE-18, and whether `SUPPORTED_VERSION` needs to become a set.
5. **Is AC-6 (≥6× multi-core, ~14× single-thread) a blocking gate or permanently operator-owned?** ADR 0054 says block-ship; the code is reported-not-gated (`test_benchmark_parser.py:235` asserts only `ratio > 1.0`). **Blocks:** whether PARSE-34 stays informational and whether PARSE-35's ratchet is advisory or blocking.
6. **Who owns the malformed/oversized corpus generator?** It is a shared dependency of this chapter (PARSE-36/37), the load harness (`W25:S4.8`), and the count-and-log invariant tests. **Blocks:** PARSE-36, PARSE-37, PARSE-59, and the automation of the Windows load acceptance.
7. **Is a property-based testing dependency (`hypothesis`) acceptable under DEP-1, or must adversarial corpora stay hand-enumerated?** Same question for `mutmut`. **Blocks:** PARSE-38, PARSE-39, PARSE-40.
8. **When does ADR 0054 Phase 2 (drop `hl7>=0.4.5`) land, and is freezing golden vectors a hard precondition of that PR?** **Blocks:** the scheduling of PARSE-12 and PARSE-13 relative to the dependency-removal PR.
9. **Does the code-set `UnmappedSink` persistence half get built?** If yes it creates a new PHI-at-rest surface needing encryption, audit and retention decisions, and the `_sink is None` pin (PARSE-48) becomes a pin on the *default*, not on the absence of the feature. **Blocks:** PARSE-48's framing.
10. **Should `parse_tree()` unescape leaf values so the operator's view matches the router's?** Today the viewer shows `O\S\Brien` where `Peek.field` returns `O^Brien`. Either answer is defensible; neither is written down or asserted. **Blocks:** PARSE-24, PARSE-51, PARSE-52.
11. **Does `validate(profile=…)` stay a silent no-op (`validate.py:56`), or raise `NotImplementedError` until conformance profiles exist?** A caller passing a profile today gets an `ok=True` that means nothing on a safety-critical strict feed. **Blocks:** PARSE-19.
12. **Is the WSDL `<soap:body parts=…>` multi-part defect (`wsdl.py:290`) in scope to fix, or accepted while WSDL import stays demand-gated?** It is disclosed at BACKLOG #69. **Blocks:** PARSE-31 — a test written now would encode the defect.
13. **Should the stale ratings and doc drift be corrected as part of this work?** Concretely: `FEATURE-COVERAGE-PLAN.md` `FCP:PARSE-14` (`:859`) says "partial" (closed by `test_builtin_hl7_hardening.py:595-703`) and `FCP:PARSE-15` (`:860`) says the bench file is "MISSING" (it exists, 235 lines); `docs/HL7-VALIDATION.md:10` still names python-hl7 as the Tier-1 engine though ADR 0054's built-ins parser is the default; ADR 0012 §5 still calls the X12 strict validator deferred though `parsing/x12/validate.py` ships; ADR 0033's header still reads "Proposed … ratified-on-build" though the code sets are built; and `docs/FEATURE-MAP.md` §3 omits ADR 0054, 0122, 0123, 0033, `parsing/xml/`, `consistency.py`, `split.py` and `sniff.py`. **Blocks:** nothing technically — but the acceptance report and this plan both cite those documents as authority.
14. **Is a silent U+FFFD substitution an acceptable ingress outcome?** `normalize()` defaults to `errors="replace"` (`peek.py:152`) precisely so the hot path keeps routing a slightly-off body — but a substitution is an unrecorded, irreversible corruption of every *derived* value while the raw stays byte-faithful, which is count-and-log-clean by construction. Options: keep `replace` and record a warning/`ERROR` disposition when the decoded text differs from a strict decode; switch the ingress decode to `errors="strict"` and let it NAK (PARSE-43's path); or declare it accepted-by-design in `docs/CONNECTIONS.md`. **Blocks:** PARSE-64's unconditional half and the framing of PARSE-43.
