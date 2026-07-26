# PLAN-12 · Wave 1 · #234 writer parity — derived write schema + list canonicalization

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)
> (authored with the plan, 2026-07-16). **This file is the maintainable source of truth for this session's status.**
> Shared rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `config-234-writer` |
| **Wave** | 1 |
| **Status** | ✅ **Complete** (2026-07-16 — both phases landed in this session's PR) |
| **Effort** | 2 (1.5–2 sittings, one worktree) |
| **Backlog items** | #234 (Phases 1 + 2 of 4) |
| **ADR** | No — enforces ADR 0007's existing "one file, two equal editors" contract; the merge-on-absent flip was evaluated and rejected (S10 records it) |
| **Store schema / 3-backend** | No (config layer only) |

## Items

| Item | Title | Status |
|---|---|---|
| #234 (P1) | Writer parity: derived write schema, type-driven emission, fail-loud unknown keys | ✅ built (this PR) |
| #234 (P2) | `connection list` schedule canonicalization + byte-idempotence + CLI end-to-end | ✅ built (this PR) |

## Owned files / seams

`messagefoundry/config/connections_edit.py` · `tests/test_connections_file.py` (parity guard + extended round-trips)
· `tests/test_connections_roundtrip.py` (new — parametrized per-key round-trips, maximal tables) ·
`tests/test_connections_cli.py` (end-to-end via `main()`, byte-idempotence) · `messagefoundry/__main__.py`
**expected UNCHANGED** (record the decision that `_print_json` stays bare — canonicalize at the list boundary).

## The work

**Phase 1 — writer parity (`connections_edit.py`):**

1. One canonical ordered write tuple: the existing 14 scalars keep their current relative order (minimizes diffs on
   files the current writer produced); new scalar keys appended grouped by feature with a why-comment; arrays
   (`source_ip_allowlist`) emitted with scalars (TOML requires key-values before sub-table headers); then sub-tables
   (`settings`, `retry`, `buildup`, `stall`, `batch`, `metadata`, `schedule` **last** — it nests windows as an array
   of inline tables).
2. **Parity guard**: import `_INBOUND_KEYS`/`_OUTBOUND_KEYS` from `connections_file` (intra-package) and assert
   set-equality — **the pytest parity test is the CI guard of record** (a module-level `assert` vanishes under
   `python -O`). Prove red→green by demonstrating a removed tuple key fails the test.
3. `_toml_value` gains a list branch (list-of-dicts → tomlkit array of inline tables, else plain array).
4. **Never emit `direction`** (explicit skip + comment referencing `connections_file.py` `_reject_unknown`).
5. `_validate_input` gains **fail-loud unknown-input-key rejection** (`WiringError` naming the keys, mirroring the
   loader's message shape) — validated against the **direction-appropriate** key set (a cross-direction key like
   `retry`-on-inbound must fail; a union check would pass it).
6. Sub-table emission on `is not None` (explicit-empty survives).
7. **Verdict-corrected arithmetic** (use these numbers everywhere, incl. tests and the eventual ledger flip): the
   read-schema union is **33 distinct keys** (25 inbound + 16 outbound, 8 shared; **41 per-direction slots**); the
   casualty list is **19 per-direction slots / 16 distinct keys INCLUDING inbound `metadata`**.
8. **New pin test: absent-key-deletes.** `test_upsert_replaces_in_place` does NOT lock full-replace semantics — a
   merge-on-absent writer passes it. Add the test that an upsert omitting a previously-present key deletes it.
9. Maximal-fixture constraint: the maximal inbound fixture keeps `content_type=hl7v2` (`stream_threshold_bytes` is
   HL7-specific) — or split fixtures.

**Phase 2 — `connection list` canonicalization + idempotence:**

1. `list_connections` (~:55-70) recursively canonicalizes `datetime.time`/`date`/`datetime` unwrapped from
   TOML-native values to ISO strings (HH:MM:SS; Pydantic re-parses them on load, `models.py:298-299`, so the string
   form is read-schema-legal when written back). Canonicalize **at the list boundary** — NOT via a `default=` on
   `_print_json` — so the IDE's `runJson`, the CLI, and direct-Python callers all see one canonical form.
2. Regression test **red-first**: `connection list` today crashes with an uncaught `TypeError` through
   `__main__.py:3231-3232` on a config whose `schedule` uses TOML-native times — for the WHOLE file.
3. TOML-native-time schedule round-trip: author `07:00` → list → upsert → reload → `Schedule` semantically equal
   (times rewritten as strings in the **touched** table is accepted — full-replace rewrites the touched table's
   style; ADR 0007's byte contract covers untouched tables). The reload-equality test **explicitly accepts**
   date/datetime→string type-narrowing from recursive canonicalization.
4. **Byte-idempotence** (new guarantee): a second identical upsert leaves the file byte-identical.
5. CLI end-to-end through `main()`: maximal both-direction config + hand-commented sibling table → `list --json` →
   `upsert --data` each → reload equality + sibling comments intact. ("Untouched-table byte-stability" is honestly
   described as **comment-substring survival**.)

## Dependencies

None — buildable now. Unblocks [w03-ide-234-merge-fix](w03-ide-234-merge-fix.md) (without the writer fix, the merged
post is re-stripped server-side; without Phase 2, the list feeding the merge crashes on schedule-bearing files).

## Notes & gotchas

- **Must-stay-green regression set:** `test_upsert_replaces_in_place` (`test_connections_cli.py:68`),
  `test_hand_comment_survives_gui_upsert` (:176-205), `test_gui_upsert_preserves_lifecycle_flags`
  (`test_connections_file.py:602-619`), and `test_upsert_preserves_simulate` — which lives in
  **`tests/test_outbound_simulate.py:219-240`**, not `test_connections_cli.py`.
- The root cause being closed is **schema drift between reader and writer** — the derived-schema parity test is the
  drift guard; a key added to the read schema and not the write tuple must **fail a test**, never silently delete
  data.
- `source_ip_allowlist` being silently dropped is a **security regression** vector — call it out in the PR.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy messagefoundry` (strict) → `QT_QPA_PLATFORM=offscreen pytest -q`.
- Red-first demonstrations recorded in the PR: (a) parity guard fails when a key is removed from the write tuple;
  (b) `connection list` crashes today on TOML-native schedule times.
- All 33 read-schema keys round-trip semantically; `direction` never appears in written TOML; second save
  byte-idempotent.
- PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; owner approves push/PR.

---
_Last reconciled: 2026-07-16 against `origin/main` @ `8e413919`. Master index:
[MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)._
