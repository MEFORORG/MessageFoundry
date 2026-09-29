# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Doc-vs-code drift guard for the ``docs/PHI.md`` at-rest inventory (ASVS 14.1.1 / 14.1.2 / 14.2.4).

For these three requirements the **shipped document IS the control**: 14.1.1 wants every piece of
sensitive data identified and classified into protection levels, 14.1.2 wants each level to carry a
documented set of protection requirements, and 14.2.4 scores whether the controls are implemented *as
documented*. A missing row is therefore the defect, not a cosmetic gap — so this guard enumerates the
truth **from the code at test time** and fails when the document under-reports it.

Four mechanical assertions, none of which reads a hand-copied list:

1. **Cipher-registry parity.** Every ``(table, column)`` pair the store cipher covers — derived from the
   literal ``cell_aad("<table>", "<column>", ...)`` call sites across ``messagefoundry/`` *plus* the
   literal pairs inside each backend's ``_CIPHER_COLUMNS`` / ``_encrypt_existing_rows`` /
   ``reencrypt_to_active`` (filtered to real table names taken from that module's own ``CREATE TABLE``
   statements, so AAD *column* tuples like ``("namespace", "key")`` are not mistaken for tables) — must
   appear as a ``table.column`` token in the §2 inventory.
2. **Protection-requirement parity (the 14.1.2 half).** Every such pair must *also* be named in §3, so a
   tier can never be inventoried without a documented requirement set.
3. **Retention parity (the 14.2.4 half).** Every such pair must *also* be named in §8 — either under a
   purge that acts on it, or in the honest "no retention today" list. This is what keeps
   ``messages.metadata`` and ``search_presets.criteria`` from silently drifting back out of the doc, and
   it fails loudly if a future change adds a purge for them without a doc row.
4. **Per-backend purge surface.** Every ``purge_*`` on the ``Store`` protocol, plus the maintenance
   surface the ``RetentionRunner`` calls, must be *defined on* each of the three backend classes (not
   inherited or stubbed) **and** documented in §8 with a cell for each backend. Paired with a negative
   token guard against the exact retired claims this sweep removed.

Further down, the claim-truth guards bind a claim to a code fact rather than to a token. One of them
is the backend-reach registry (BACKLOG #1186 slice B): every "all three backends" claim that cites a
store protocol or an open-time keyword must be true of the three backend classes.

A planted-omission self-test proves the assertions are not vacuous.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import re
import textwrap
import typing
from collections.abc import Callable
from pathlib import Path

import pytest

import messagefoundry.store.base as store_base
import messagefoundry.store.postgres as store_postgres
import messagefoundry.store.privilege as store_privilege
import messagefoundry.store.sqlserver as store_sqlserver
import messagefoundry.store.store as store_store
from messagefoundry.config.settings import ServiceSettings
from messagefoundry.store.base import Store
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore
from tests._ast_sites import (
    call_sites,
    code_strings,
    delete_keeping_a_mention,
    find_funcs,
    parse_source,
    source_calls,
    source_has_literal,
    source_uses,
)
from tests._cipher_registry import covered_pairs, string_pairs

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "PHI.md"
_PKG = _ROOT / "messagefoundry"
_BACKEND_MODULES = (
    _PKG / "store" / "store.py",
    _PKG / "store" / "sqlserver.py",
    _PKG / "store" / "postgres.py",
)
#: The functions whose literal ``(table, column)`` tuples enumerate the cipher registry.
_CIPHER_PASS_FUNCS = frozenset({"_encrypt_existing_rows", "reencrypt_to_active"})
#: Table names as declared by the backends' own DDL — used to reject AAD column tuples.
_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?#?([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE
)
#: The SET list of a ``purge_message_bodies`` UPDATE, read from the SQL literal up to its WHERE.
_PURGE_UPDATE_RE = re.compile(r"UPDATE messages SET (.+?)\s+WHERE\b", re.DOTALL)
#: Maintenance calls the RetentionRunner makes through the Store protocol, beyond ``purge_*``.
_BACKTICK_RE = re.compile(r"`([^`]+)`")
#: Maintenance calls…
_MAINTENANCE_SURFACE = ("strip_embedded_documents", "wal_checkpoint", "vacuum", "db_status")
#: Claims this sweep deleted, scanned across the whole operator-facing doc corpus (not just PHI.md —
#: two of them were live in CONFIGURATION.md / EARLY-ADOPTER-GUIDE.md while the single-file tripwire
#: was green). Each is RETENTION-scoped on purpose: a bare "SQLite-only" is a true and useful
#: statement about WAL checkpoint, VACUUM, group commit and the `.mfbak` snapshot, so matching it
#: alone would be a false positive across a dozen documents.
_RETIRED_CLAIMS = (
    "SQLite-only.** Retention",
    "Retention/maintenance runs on the SQLite backend",
    "targets the SQLite store",
    "at-rest retention is a DBA concern",
    "Retention is a DBA concern",
    "encrypts every PHI-bearing column",
    # ASVS 14.2.7 (#294): messages.metadata and search_presets.criteria BOTH gained a retention
    # window. These six statements were true when written and are now false. This registration is the
    # ONLY thing in the repo that can catch them coming back: the §8 token guard below is
    # presence-only, and both columns were already "documented" in §8 — by honest-gap rows asserting
    # exactly the opposite — so the suite stayed green while the docs said there was no purge.
    #
    # Each string is deliberately NARROWER than it looks. The bare "no purge on any backend" is NOT
    # listed, and the reason CHANGED without changing the answer. It used to collide with PHI.md's
    # legacy `outbox.payload` row, which was then still true. ASVS 14.2.7 retired that row — but the
    # same edit added a PAST-TENSE account of what the retirement fixed ("...kept full outbound PHI
    # bodies there that no purge on any backend reached"), which is a true statement about history and
    # would red on the short form just as the old row did. Re-verified by grep at retirement time; a
    # phrase whose collision merely MOVED is not a phrase that became safe to register.
    "nulled by no purge on any backend",
    "No retention purge nulls this column",
    "No retention purge on any backend",
    "the preset lives until its owner",
    "it persists until its owner deletes the preset",
    "keeping the metadata row",
    # ASVS 5.2.4 (#291): [store].uploads_dir blobs gained an age-based prune (UploadStore.prune_expired
    # + UploadRetentionRunner, default 30d) — so these "no retention path" claims are now false. The
    # backend-parity of the prune is enforced positively by test_uploads_dir_retention_is_documented;
    # these two dead phrases are the belt-and-suspenders tripwire. Verified unique: no still-true row
    # uses "no retention path" (the surviving gaps say "no purge"/"keep-forever").
    "no retention path at all",
    "no retention path exists at all",
    # ASVS 14.2.7 (this change): `reference.value` gains purge_reference_snapshots, and the legacy
    # SQL Server `outbox` table is migrated into `queue` and DROPped. The three statements below are
    # TRUE TODAY and become false in Commits 3 and 6 — they are registered HERE, first, so that
    # `test_retired_false_claims_do_not_reappear` goes RED against the UNEDITED docs and only turns
    # green once the edits actually land. Registering after the edit proves nothing: it would pass on
    # day one whether or not the guard works.
    #
    # A FOURTH candidate was DELIBERATELY STRUCK. The obvious string "no retention purge" collides
    # with a still-TRUE sentence:
    #     docs/security/ASVS-292-289-HANDOFF-2026-07-25.md:173
    #     "`pending_approvals.params` is unencrypted and has no retention purge on any backend."
    # `_retired_claim_hits()` globs docs/*.md PLUS docs/security/*.md — and docs/security/ is
    # GIT-IGNORED. So registering it reds on a developer's machine and passes in CI, where the file
    # does not exist. A guard that is strictly weaker in CI than on a laptop is not a guard.
    # Grep evidence recorded at registration time (docs/*.md | docs/security/*.md):
    #     "no retention purge"                    1 | 1   <- STRUCK, collides with a true statement
    #     "**No purge path at all**"              1 | 0
    #     "touched by no purge on any backend"    1 | 0
    #     "is purged by nothing on any backend"   1 | 0
    # Re-run that grep before adding any further string here.
    "**No purge path at all**",
    "touched by no purge on any backend",
    "is purged by nothing on any backend",
)
#: Filename markers identifying an ASVS **scoring / evidence** artifact. Those documents quote the
#: retired wording deliberately, as the record of what was found, so scanning them for it would be a
#: guaranteed false positive. Matched as a generic marker rather than by exact filename: a newly
#: dated artifact is covered without an edit, and this file carries no deployment identifier (the
#: publishable-subset leak gate scans ``tests/``).
_EVIDENCE_ARTIFACT_MARKERS = (
    "ASSESSMENT",
    "STATUS-",
    "RISK-ACCEPTANCE",
    "DISPOSITIONS",
    "MULTISESSION-PLAN",
    "RESCORE",
)
#: Settings names the rewritten §2/§3/§8 text depends on; a rename must red the doc, not rot it.
_CITED_SETTINGS = (
    ("store", "aad_bind"),
    ("store", "cipher_provider"),
    ("store", "key_provider"),
    ("store", "uploads_dir"),
    ("store", "uploads_retention_days"),
    ("security", "delete_message_bodies_after_days"),
    ("security", "allow_keeping_phi_indefinitely"),
    ("retention", "messages_days"),
    ("retention", "dead_letter_days"),
    ("retention", "state_max_age_days"),
    ("retention", "connection_event_retention_hours"),
    ("retention", "app_log_days"),
    ("retention", "search_preset_days"),
    ("retention", "audit_days"),
    ("retention", "max_pass_seconds"),
    ("retention", "max_db_mb"),
    ("retention", "wal_checkpoint_seconds"),
    ("retention", "vacuum_at"),
    ("backup", "config_only_on_server_db"),
    # #122 / ADR 0162 — the opt-in engine-managed application-log sink the inventory's app-log row
    # now names, and the fail-closed policy it names beside it.
    ("logging", "file"),
    ("logging", "on_write_failure"),
)


# The code probes below read engine source as CODE through tests._ast_sites' source_* helpers
# (BACKLOG #2056). A substring scan of the file read a comment or docstring naming a construct
# as the construct itself, so deleting the code left the probe green.
# test_the_code_probes_fail_when_the_code_is_gone deletes each one and keeps a mention.


# --- doc slicing ---------------------------------------------------------------------------------


def _doc_text() -> str:
    return _DOC.read_text(encoding="utf-8")


def _section(number: int, text: str | None = None) -> str:
    """Return the body of top-level section ``## <number>. …`` (up to the next ``## `` heading)."""
    body = _doc_text() if text is None else text
    start = re.search(rf"^## {number}\. .*$", body, re.MULTILINE)
    assert start is not None, f"docs/PHI.md has no '## {number}.' section"
    rest = body[start.end() :]
    nxt = re.search(r"^## ", rest, re.MULTILINE)
    return rest[: nxt.start()] if nxt else rest


# --- code-derived cipher registry ----------------------------------------------------------------


def _cipher_cells() -> set[str]:
    """The code-derived set of ``table.column`` tokens the doc must classify."""
    return {f"{t}.{c}" for t, c in covered_pairs()}


# --- assertions (reusable so the self-test can plant an omission) --------------------------------


def _assert_tokens_present(tokens: set[str], section_text: str, where: str) -> None:
    missing = sorted(t for t in tokens if t not in section_text)
    assert not missing, (
        f"docs/PHI.md {where} does not document these cipher-covered cells: {missing}. "
        "Completeness is the control here (ASVS 14.1.1/14.1.2/14.2.4) — add a row, do not narrow "
        "the guard."
    )


def _table_rows(section_text: str) -> str:
    """Only the markdown TABLE rows of a section.

    A whole-section substring test cannot distinguish "this tier has a row" from "some paragraph
    mentions it": ``shared_body.body`` and ``outbox.payload`` both also occur in §2's per-backend
    coverage prose, so deleting either INVENTORY ROW left the guard green (verified by planting).
    """
    return "\n".join(line for line in section_text.splitlines() if line.strip().startswith("|"))


#: §2 row keys whose §3 "Applies to:" spelling differs (a path glob vs the setting, a filename
#: extension vs the tier's name). Reviewed and explicit, so a NEW tier still forces a decision.
_LEVEL_KEY_ALIASES = {
    "[store].uploads_dir/*.blob": "[store].uploads_dir",
    "[backup].destination/mefor-backup-*.mfbak": ".mfbak",
    ".hl7": "File-connector spill dirs",
}


def _section_2_levels() -> dict[str, str]:
    """``{row key: protection level}`` parsed from §2's own Protection-level column.

    Bound to the table rather than to the cipher registry, so it also covers tiers the cipher walk
    cannot see (the ``attachment`` header, ``connection_event.peer_host``, the file tiers) — the
    class of omission that let a §2-classified tier ship with no requirement in its PL block. The key
    is the FIRST backticked token of the row's first cell, which is that row's identity.
    """
    rows: dict[str, str] = {}
    for line in _table_rows(_section(2)).splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 5 or set(cells[0]) <= set("-: "):
            continue
        level = next((part for part in cells if part.startswith("**PL-")), None)
        if level is None:
            continue
        tokens = _BACKTICK_RE.findall(cells[0])
        key = tokens[0] if tokens else cells[0]
        rows[_LEVEL_KEY_ALIASES.get(key, key)] = level.strip("*")
    return rows


def _assert_purge_surface_documented(names: list[str], section_text: str) -> None:
    missing = sorted(n for n in names if n not in section_text)
    assert not missing, (
        f"docs/PHI.md §8 does not document these store purge/maintenance operations: {missing}"
    )


# --- tests ---------------------------------------------------------------------------------------


def test_cipher_registry_is_enumerable_from_code() -> None:
    """Sanity: the enumeration finds the tiers we know ship, so a later refactor that silently
    empties it cannot make every other assertion vacuously pass."""
    cells = _cipher_cells()
    assert len(cells) >= 19, f"cipher-cell enumeration collapsed to {sorted(cells)}"
    for expected in (
        "messages.raw",
        "queue.payload",
        "attachment_chunk.ciphertext",
        "shared_body.body",
        "response.body",
        "state.value",
        "reference.value",
        "search_presets.criteria",
        "users.totp_secret",
        "connection_event.reason",
        "alert_instance.reason",
        # `outbox.payload` was here until the legacy SQL Server table was migrated into `queue` and
        # DROPped (ASVS 14.2.7). It is gone from the registry BECAUSE the cell no longer exists —
        # `test_per_backend_cipher_counts_are_derived_not_hand_written` is what proves that is a real
        # retirement and not a silently narrowed enumeration: it re-derives 18/17/17 from the code.
        "uploaded_file.body",
    ):
        assert expected in cells, f"{expected} vanished from the code-derived cipher registry"


def test_every_cipher_covered_cell_is_in_the_section_2_inventory() -> None:
    """ASVS 14.1.1 — all sensitive data identified and classified into protection levels.

    Scoped to the inventory TABLE, not the whole section: two cells (`shared_body.body`,
    `outbox.payload`) also occur in §2's per-backend-coverage prose, so a whole-section check could
    not see their rows being deleted.
    """
    _assert_tokens_present(
        _cipher_cells(), _table_rows(_section(2)), "§2 (data-at-rest inventory table)"
    )


def test_section_2_inventory_declares_protection_levels() -> None:
    """The inventory must classify, not merely list: every PL-* level is defined and used."""
    section = _section(2)
    for level in ("PL-1", "PL-2", "PL-3", "PL-4", "PL-5"):
        assert level in section, f"§2 no longer classifies rows into {level}"
    assert "Protection level" in section, "§2 lost its protection-level column"


def test_every_cipher_covered_cell_has_a_protection_requirement() -> None:
    """ASVS 14.1.2 — every protection level carries documented protection requirements."""
    section = _section(3)
    assert "Protection requirements per protection level" in section, (
        "§3 lost its per-protection-level requirements block (ASVS 14.1.2)"
    )
    _assert_tokens_present(_cipher_cells(), section, "§3 (protection requirements)")


def test_protection_requirements_state_cell_binding_and_the_third_cipher_tier() -> None:
    """The 14.1.2 residual names ``aad_bind`` explicitly; ``vault_transit`` is a distinct at-rest tier."""
    section = _section(3)
    for token in ("aad_bind", "mfenc:v2", "mfenc:v3", "vault_transit"):
        assert token in section, f"§3 no longer documents {token}"


def test_every_cipher_covered_cell_has_a_stated_retention_position() -> None:
    """ASVS 14.2.4 — controls implemented as documented, including "no retention today"."""
    section = _section(8)
    assert "no** retention today" in section or "no retention today" in section, (
        "§8 lost its honest 'tiers with no retention today' list"
    )
    _assert_tokens_present(_cipher_cells(), section, "§8 (retention & purge)")


def test_purge_surface_is_defined_on_every_backend_and_documented_per_backend() -> None:
    """The retention runner is backend-agnostic, so every backend must really implement the surface."""
    surface = sorted(n for n in dir(Store) if n.startswith("purge_")) + list(_MAINTENANCE_SURFACE)
    for cls in (MessageStore, SqlServerStore, PostgresStore):
        undefined = [n for n in surface if n not in cls.__dict__]
        assert not undefined, (
            f"{cls.__name__} does not define {undefined} itself — docs/PHI.md §8 claims the retention "
            "surface is implemented on every backend"
        )
    section = _section(8)
    _assert_purge_surface_documented(surface, section)
    for backend in ("SQLite", "SQL Server", "Postgres"):
        assert backend in section, f"§8's per-backend table lost the {backend} column"
    # The server backends' two documented no-ops must stay documented as no-ops, not silently promoted.
    for cls in (SqlServerStore, PostgresStore):
        for name in ("wal_checkpoint", "vacuum"):
            doc = (getattr(cls, name).__doc__ or "").lower()
            assert "no-op" in doc, f"{cls.__name__}.{name} no longer documents itself as a no-op"
    assert "no-op (DBA-owned)" in section, "§8 no longer marks the server-backend no-ops"


def _purge_blanked_columns(source: str) -> set[str]:
    """The ``messages`` columns ``purge_message_bodies`` in ``source`` blanks, read from its SQL.

    The literals the function runs, not its source lines: a comment or docstring quoting an UPDATE
    used to count as one, and the line scan also stopped at the first quote inside the SQL, so it
    never saw a column after ``raw=''`` (BACKLOG #2056).
    """
    return {
        column
        for func in find_funcs(parse_source(source), "purge_message_bodies")
        for sql in code_strings(func)
        for fragment in _PURGE_UPDATE_RE.findall(sql)
        for column in re.findall(r"([a-z_]+)\s*=", fragment)
    }


def test_purge_message_bodies_blanked_columns_are_documented() -> None:
    """Whatever each backend's ``UPDATE messages SET …`` actually blanks must appear in §8."""
    section = _section(8)
    for path in _BACKEND_MODULES:
        columns = _purge_blanked_columns(path.read_text(encoding="utf-8"))
        assert columns, (
            f"no 'UPDATE messages SET' in {path.name} — the extraction broke, not the doc"
        )
        for column in sorted(columns):
            token = f"messages.{column}"
            assert token in section, (
                f"{path.name}'s purge_message_bodies blanks {token} but docs/PHI.md §8 never names it"
            )


def _retired_claim_hits() -> list[str]:
    """``file:line`` for every retired claim found anywhere in the operator-facing doc corpus.

    Scoped to ONE file, this tripwire could not fail on the regression it is named for: two of the
    four claims were live in docs/CONFIGURATION.md and docs/EARLY-ADOPTER-GUIDE.md while the suite
    was green, telling an installer on the deployed SQL Server backend that the engine does not do
    retention. ASVS SCORING / evidence artifacts are excluded because they QUOTE the retired wording
    as historical evidence; they are matched by a generic filename marker rather than by name, both
    so a newly dated artifact is covered automatically and so this file never carries a deployment
    identifier (the publishable-subset leak gate scans `tests/`).
    """
    hits: list[str] = []
    corpus = sorted((_ROOT / "docs").glob("*.md")) + sorted(
        (_ROOT / "docs" / "security").glob("*.md")
    )
    for path in corpus:
        if any(marker in path.name.upper() for marker in _EVIDENCE_ARTIFACT_MARKERS):
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for claim in _RETIRED_CLAIMS:
                if claim in line:
                    hits.append(f"{path.relative_to(_ROOT).as_posix()}:{lineno}: {claim!r}")
    return hits


def test_retired_false_claims_do_not_reappear() -> None:
    """The tripwire against the exact regression this sweep fixed — across the whole doc corpus."""
    hits = _retired_claim_hits()
    assert not hits, (
        "retired/false retention claims are live in the operator-facing docs (the engine enforces "
        "retention on ALL THREE backends):\n" + "\n".join(hits)
    )


def test_retired_claim_scanner_detects_a_planted_regression() -> None:
    """Proves the corpus scanner can fail — the property the single-file version did not have."""
    victim = _ROOT / "docs" / "CONFIGURATION.md"
    original = victim.read_text(encoding="utf-8")
    assert not any("CONFIGURATION.md" in hit for hit in _retired_claim_hits()), (
        "fixture drifted: CONFIGURATION.md already carries a retired claim"
    )
    try:
        victim.write_text(
            original + "\n> **SQLite-only.** Retention planted regression, removed by the test.\n",
            encoding="utf-8",
        )
        hits = _retired_claim_hits()
        assert any("CONFIGURATION.md" in hit for hit in hits), (
            "the scanner did not see a retired claim planted in docs/CONFIGURATION.md — it is still "
            f"effectively single-file. Hits: {hits}"
        )
    finally:
        victim.write_text(original, encoding="utf-8")


def test_cited_settings_names_resolve() -> None:
    settings = ServiceSettings()
    for section_name, field in _CITED_SETTINGS:
        model = getattr(settings, section_name, None)
        assert model is not None, f"docs/PHI.md cites unknown settings section [{section_name}]"
        assert field in type(model).model_fields, (
            f"docs/PHI.md cites [{section_name}].{field}, which no longer exists"
        )


def test_documented_defaults_match_the_shipped_defaults() -> None:
    """A default flip must force the §3/§8 wording to be revisited, not rot silently."""
    settings = ServiceSettings()
    assert settings.store.aad_bind is True, "§3 says cell binding is ON by default"
    assert settings.store.cipher_provider == "aesgcm", (
        "§3 says the default cipher is in-process AES-GCM"
    )
    assert settings.security.delete_message_bodies_after_days == 30, (
        "§8 says [security].delete_message_bodies_after_days defaults to 30"
    )
    assert settings.security.allow_keeping_phi_indefinitely is False, (
        "§8 says the keep-forever opt-out is off by default"
    )
    assert settings.retention.messages_days == 0, (
        "§8 says the raw [retention] windows still default to 0"
    )
    assert settings.retention.max_pass_seconds == 0.0, "§8 says the pass cap defaults to off"
    assert settings.store.uploads_retention_days == 30, (
        "§8 says [store].uploads_dir blobs auto-prune after uploads_retention_days (default 30)"
    )


def test_guard_detects_a_planted_omission() -> None:
    """Prove the assertions are not vacuous: strip a row and they must raise."""
    cells = _cipher_cells()
    planted = {"connection_event.reason", "alert_instance.reason"}
    assert planted <= cells
    damaged = (
        _section(2).replace("connection_event.reason", "").replace("alert_instance.reason", "")
    )
    with pytest.raises(AssertionError):
        _assert_tokens_present(cells, damaged, "§2 (planted omission)")
    damaged_purge = _section(8).replace("purge_alert_instances", "")
    with pytest.raises(AssertionError):
        _assert_purge_surface_documented(["purge_alert_instances"], damaged_purge)


@pytest.mark.parametrize("victim", ["shared_body.body"])
def test_guard_detects_a_planted_full_row_deletion(victim: str) -> None:
    """The case the whole-section check passed: the token survives in §2's coverage PROSE, so
    deleting its inventory ROW was undetectable until the assertion was table-scoped.

    `outbox.payload` was the second parameter until ASVS 14.2.7 retired the legacy SQL Server table.
    It is dropped rather than kept because this case needs a victim that is BOTH in the code-derived
    cipher registry AND named in §2's prose; a retired cell is in neither, so keeping it would fail on
    the `assert victim in cells` precondition — a fixture failure, not a guard failure.
    """
    cells = _cipher_cells()
    assert victim in cells
    rows = _table_rows(_section(2))
    mutated = "\n".join(line for line in rows.splitlines() if victim not in line)
    assert mutated != rows, f"fixture drifted: no §2 row carries {victim}"
    with pytest.raises(AssertionError):
        _assert_tokens_present(cells, mutated, "§2 (planted row deletion)")
    # ...and confirm the whole-section form really was blind to it.
    prose_survives = "\n".join(
        line
        for line in _section(2).splitlines()
        if victim in line and not line.strip().startswith("|")
    )
    assert victim in prose_survives, (
        f"fixture drifted: {victim} no longer occurs in §2's prose, so the table-scoping rationale "
        "needs restating"
    )


def test_every_section_2_tier_has_a_requirement_in_its_protection_level_block() -> None:
    """Bound to §2's OWN Protection-level column, so it covers tiers the cipher walk cannot see.

    RULE (14.1.2): a tier classified into a protection level must appear in that level's
    "**Applies to:**" list. The cipher-keyed guard is structurally blind to a non-ciphered tier — which
    is how the ``attachment`` header shipped classified PL-4 with no access and no retention
    requirement anywhere.
    """
    section3 = _section(3)
    blocks: dict[str, str] = {}
    for level in ("PL-1", "PL-2", "PL-3", "PL-4", "PL-5"):
        match = re.search(rf"^#### {level} .*$", section3, re.MULTILINE)
        assert match is not None, f"§3 lost its {level} block"
        rest = section3[match.end() :]
        nxt = re.search(r"^#### PL-", rest, re.MULTILINE)
        blocks[level] = rest[: nxt.start()] if nxt else rest

    missing: list[str] = []
    for token, level in sorted(_section_2_levels().items()):
        # A row may state two levels ("PL-1 (SQLite) / PL-4 (server backends)"); accept either.
        levels = re.findall(r"PL-\d", level)
        if not any(token in blocks[name] for name in levels if name in blocks):
            missing.append(f"{token} (classified {level})")
    assert not missing, (
        "§2-classified tier(s) with no protection requirement in their PL block of §3 — an "
        f"inventoried tier whose requirements are simply absent (ASVS 14.1.2): {missing}"
    )


def test_section_2_level_parser_detects_a_planted_applies_to_deletion() -> None:
    """Proves the check above can fail on the exact omission it was written for."""
    levels = _section_2_levels()
    assert "attachment" in levels or any(t.startswith("attachment") for t in levels), (
        "fixture drifted: §2 no longer names the attachment header tier"
    )
    section3 = _section(3)
    match = re.search(r"^#### PL-4 .*$", section3, re.MULTILINE)
    assert match is not None
    rest = section3[match.end() :]
    nxt = re.search(r"^#### PL-", rest, re.MULTILINE)
    block = rest[: nxt.start()] if nxt else rest
    assert "message_attachment" in block, (
        "PL-4's Applies-to no longer names the attachment linkage tier — the §2 row classifies it "
        "PL-4, so its requirements belong there"
    )
    assert "message_attachment" not in block.replace("message_attachment", ""), (
        "sanity: removing the token from the block really does make it absent"
    )


# =================================================================================================
# ASVS 14.1.1 — the PL-5 substrate rows, and the per-backend counts
# =================================================================================================

#: The store backends ``open_store`` can build. Each needs a PL-5 *substrate* row in §2: the files the
#: application cipher provably cannot reach, and the cover that has to be bought elsewhere.
_PL5_SUBSTRATE = {
    "SQLite": ("-wal", "-shm"),
    "SQL Server": (".ldf", "tempdb", "#eligible"),
    "Postgres": ("pg_wal",),
}


def _pl5_rows(section: str) -> list[str]:
    """§2 rows whose Protection-level cell is PL-5."""
    return [
        line
        for line in section.splitlines()
        if line.strip().startswith("|") and "PL-5" in line and "Protection level" not in line
    ]


def test_every_backend_has_a_pl5_substrate_row_naming_its_files() -> None:
    """The BINDING item of 14.1.1, and it had no guard at all.

    RULE: each backend needs a §2 row for the substrate the app cipher cannot reach. The only PL-5
    assertion used to be "the literal token ``PL-5`` appears somewhere in §2" — which survives in the
    level legend, so deleting all three substrate rows left the whole suite green.
    """
    section = _section(2)
    rows = _pl5_rows(section)
    assert rows, "§2 has no PL-5 substrate rows at all"
    for backend, markers in _PL5_SUBSTRATE.items():
        owning = [r for r in rows if backend in r]
        assert owning, (
            f"§2 has no PL-5 substrate row for {backend}. Every backend's engine-unreachable files "
            "(WAL / transaction log / tempdb / cluster WAL) must be inventoried and their cover "
            "named — the application cipher provably cannot protect them (ASVS 14.1.1)."
        )
        joined = " ".join(owning)
        missing = [m for m in markers if m not in joined]
        assert not missing, f"the {backend} PL-5 row does not name {missing}"


def test_sql_server_pl5_row_is_pinned_to_the_code_that_makes_it_load_bearing() -> None:
    """The SQL Server substrate row is true only because the engine forces snapshot isolation.

    RULE: if the engine stops force-enabling RCSI / snapshot isolation, or stops materialising the
    ``#eligible`` temp table, the row's reasoning changes and the doc must be revisited.
    """
    source = (_PKG / "store" / "sqlserver.py").read_text(encoding="utf-8")
    for pragma in ("READ_COMMITTED_SNAPSHOT", "ALLOW_SNAPSHOT_ISOLATION"):
        assert source_has_literal(source, f"ALTER DATABASE CURRENT SET {pragma}"), (
            f"the store no longer force-enables {pragma}; §2's SQL Server PL-5 row says it does, and "
            "that is the reason tempdb's version store holds PHI row images."
        )
    assert source_has_literal(source, "CREATE TABLE #eligible"), (
        "purge_message_bodies no longer materialises #eligible in tempdb; update the SQL Server "
        "PL-5 row's tempdb-object list."
    )


def test_pl5_guard_detects_a_planted_row_deletion() -> None:
    """Proves the substrate guard can fail — the old ``"PL-5" in section`` check could not, because
    the token survives in the level legend even with every substrate row gone."""
    section = _section(2)
    rows = _pl5_rows(section)
    assert rows, "baseline: §2 has no PL-5 rows"
    mutated = "\n".join(line for line in section.splitlines() if line not in rows)
    assert "PL-5" in mutated, (
        "fixture drifted: with every PL-5 row deleted the token should STILL be present (that is the "
        "whole point) — the legend must still define the level"
    )
    assert not _pl5_rows(mutated), "the row extractor did not notice the planted deletion"


def _per_backend_cipher_counts() -> dict[str, int]:
    """``{backend label: (table, column) pair count}``, derived per module."""
    counts: dict[str, int] = {}
    labels = {"store.py": "SQLite", "sqlserver.py": "SQL Server", "postgres.py": "Postgres"}
    for path in _BACKEND_MODULES:
        src = path.read_text(encoding="utf-8")
        tables = {m.lower() for m in _CREATE_TABLE_RE.findall(src)}
        tree = ast.parse(src)
        pairs: set[tuple[str, str]] = set()
        for node in ast.walk(tree):
            interesting = isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and (
                node.name in _CIPHER_PASS_FUNCS
            )
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "_CIPHER_COLUMNS"
                for target in node.targets
            ):
                interesting = True
            if interesting:
                pairs |= {p for p in string_pairs(node) if p[0].lower() in tables}
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "cell_aad"
                and len(node.args) >= 2
                and all(isinstance(a, ast.Constant) for a in node.args[:2])
                and node.args[0].value.lower() in tables  # type: ignore[attr-defined]
            ):
                pairs.add((node.args[0].value, node.args[1].value))  # type: ignore[attr-defined]
        # The doc counts CELLS THAT CAN HOLD A ROW. `shared_body` is created by every backend's DDL
        # and declared cipher-covered, but the server backends never INSERT into it (the ADR 0100
        # body-dedup path is SQLite-only), so §2 states the count "minus shared_body.body". Asserted,
        # not assumed: if a server backend starts writing it, the count must move.
        if path.name != "store.py":
            writes_shared_body = "INSERT INTO shared_body" in src
            assert not writes_shared_body, (
                f"{path.name} now INSERTs into shared_body; §2's per-backend count carve-out "
                '("minus `shared_body.body`, never written there") is stale.'
            )
            pairs.discard(("shared_body", "body"))
        counts[labels[path.name]] = len(pairs)
    return counts


def test_per_backend_cipher_counts_are_derived_not_hand_written() -> None:
    """The three integers §2 and §3 both quote, pinned to the code.

    RULE: the completeness guard forces a new §2/§3/§8 row for any newly cipher-covered column while
    leaving these counts untouched — so the very next cipher cell would make both sections
    numerically false with CI green. That is the rot this closes.
    """
    counts = _per_backend_cipher_counts()
    assert set(counts) == {"SQLite", "SQL Server", "Postgres"}
    flat2 = " ".join(_section(2).split())
    sqlite_2 = re.search(r"covers \*\*(\d+)\*\* `\(table, column\)`", flat2)
    server_2 = re.search(r"\*\*SQL Server\*\* covers (\d+)", flat2)
    postgres_2 = re.search(r"\*\*Postgres\*\* covers (\d+)", flat2)
    assert sqlite_2 and server_2 and postgres_2, (
        "§2's per-backend cipher-coverage paragraph changed shape; re-derive the three counts."
    )
    stated2 = [int(m.group(1)) for m in (sqlite_2, server_2, postgres_2)]
    live = [counts["SQLite"], counts["SQL Server"], counts["Postgres"]]
    assert stated2 == live, f"§2 states {stated2} per-backend cipher pairs; the code has {live}"
    flat3 = " ".join(_section(3).split())
    quoted3 = re.search(
        r"(\d+) `\(table, column\)` pairs on SQLite, (\d+) on SQL Server, (\d+) on Postgres", flat3
    )
    assert quoted3, "§3 item 1 no longer quotes the three per-backend counts"
    stated3 = [int(quoted3.group(i)) for i in (1, 2, 3)]
    assert stated3 == live, (
        f"§3 states {stated3} per-backend cipher pairs; the code has {live}. A new cipher cell makes "
        "both §2 and §3 numerically false unless these move together."
    )


def test_plaintext_key_columns_are_inventoried() -> None:
    """``state`` / ``reference`` key columns are plaintext and may carry a raw identifier.

    RULE: 14.1.1 is "all sensitive data identified and classified". Only ``value`` is cipher-covered;
    the key columns are the composite PK and the AAD input, and the engine's own docs describe the
    store as patient-id correlation — so they need rows and a protection level, exactly as the far
    less sensitive plaintext ``messages.control_id`` already has.
    """
    section2 = _section(2)
    for token in ("state.namespace", "state.key", "reference.key"):
        assert token in section2, (
            f"§2 does not inventory the plaintext key column {token}. It is not cipher-covered (only "
            "`.value` is), and config/state.py describes the store as patient-id correlation."
        )
    source = (_PKG / "config" / "state.py").read_text(encoding="utf-8")
    assert "patient-id mapping" in source, (
        "config/state.py no longer describes the state store as patient-id correlation; re-derive "
        "whether the key columns still warrant an inventory row."
    )


# =================================================================================================
# ASVS 14.1.2 — the per-level protection requirements must cover every tier they list
# =================================================================================================


def test_pl1_encryption_rule_carves_out_the_backup_codec() -> None:
    """``.mfbak`` is listed as a PL-1 tier but is sealed by a DIFFERENT codec with a DIFFERENT AAD,
    and ``[backup].allow_unencrypted`` writes cleartext — none of which the blanket store-cipher
    sentence covered. The cipher-cell guard cannot see file-based tiers, so this is pinned by token.
    """
    section3 = _section(3)
    for token in ("backup_codec", ".mfbak.plain", "frame_counter"):
        assert token in section3, (
            f"§3's PL-1 encryption rule does not state {token!r}: `.mfbak` uses store/backup_codec.py "
            "(chunked AES-256-GCM, header_sha256+frame_counter+final_flag AAD, resolve_active_key — "
            "so vault_transit never applies), and allow_unencrypted writes a CLEARTEXT archive."
        )
    source = (_PKG / "pipeline" / "dr_backup.py").read_text(encoding="utf-8")
    assert source_calls(source, "resolve_active_key"), (
        "dr_backup no longer resolves the archive key directly; the doc's `.mfbak` seal sentence "
        "rests on that — re-derive it."
    )
    # ADR 0049 AC-13 put a SECOND cipher in this module: the full restore-verify opens the extracted
    # snapshot's CELLS through build_store_cipher, where cipher_provider does apply. The archive's own
    # seal still does not. This used to assert `build_store_cipher not in source`, which read as "one
    # cipher here" and would now be a false premise under §11's compensating-control rule — so it pins
    # the distinction instead: if the module builds the store cipher, §3 must say which governs which.
    if source_calls(source, "build_store_cipher"):
        assert "build_store_cipher" in section3, (
            "dr_backup builds the STORE cipher (the full restore-verify reads the snapshot's cells "
            "back through it), and §3's PL-1 rule does not name it. Left unstated, the `.mfbak` "
            "bullet's 'vault_transit never applies to a backup' reads as covering that read too, and "
            "it does not — under vault_transit the cell read runs in Transit."
        )
    assert source_has_literal(source, ".mfbak.plain"), (
        "the cleartext-archive path is gone; remove the carve-out from §3 in the same change."
    )


#: ``dr_backup`` functions that SEAL or UNSEAL the ``.mfbak`` archive itself. §3's carve-out
#: ("the archive's own seal is keyed by `resolve_active_key` and not `build_store_cipher`, so
#: `vault_transit` never applies") is a claim about THESE functions and no others.
#:
#: ``_restore_blocking`` (the `restore` subcommand, BACKLOG #1717) was added to this set rather than
#: waived, and the carve-out is re-derived for it rather than assumed. It unseals with ``match_key``,
#: which ``_select_decrypt_key`` picks by the archive header's ``key_id`` out of the set ``run_restore``
#: resolved with ``resolve_decrypt_keys`` — the ACTIVE key plus RETIRED ones, so an archive sealed
#: before a rotation still restores (ADR 0049 AC-5). Do not write ``_resolve_key`` here: that is
#: ``BackupRunner._resolve_key``, the SEAL side, and it wraps ``resolve_active_key`` alone. Either way
#: the material is RAW DEK BYTES and never a store cipher, which is the half §3's sentence turns on.
#: The part that had to
#: be CHECKED rather than asserted is the other half: whether restoring also reads the snapshot's cells
#: back, which is the operation that legitimately needs the store cipher. A full restore-verify does,
#: through ``_full_open_check``/``_decrypt_check`` — which is what those two are doing in
#: :data:`_SNAPSHOT_READ_FUNCS`. The restore path has no such companion. ``_restore_blocking`` stops
#: at the seal: its post-extract checks are
#: ``_integrity_check`` (``PRAGMA integrity_check``) and ``_count_tables`` (``SELECT COUNT(*)``), both
#: on a plain read-only ``sqlite3`` connection with no cipher, and it then PLACES the file. No cell is
#: decrypted on the restore path, so unlike a full restore-verify it needs no store cipher at all — and
#: under ``vault_transit`` a restore makes no Transit call. Limb (2) below is what holds that to
#: account: ``_restore_blocking`` is absent from :data:`_SNAPSHOT_READ_FUNCS`, so the day it acquires a
#: store cipher this test reds again rather than passing on this note.
#:
#: ``_verify_in_staging`` (BACKLOG #1721) is the verify's steps 2 to 4, split out of
#: ``_verify_archive_blocking`` so that caller can always discard the staging directory. It unseals
#: with the ``match_key`` its caller picked by the header's ``key_id`` out of ``keys``. At least two
#: callers supply ``keys``: ``run_restore_verify`` resolves them with ``resolve_decrypt_keys``, and
#: ``_do_backup`` passes the one key ``BackupRunner._resolve_key`` got from ``resolve_active_key``.
#: Either way they are RAW DEK BYTES, never a store cipher.
#: Its full-verify leg reads cells only through ``_full_open_check``, which is in
#: :data:`_SNAPSHOT_READ_FUNCS`, so the carve-out holds for it unchanged.
_MFBAK_CODEC_FUNCS = frozenset(
    {
        "_do_backup",
        "_resolve_key",
        "_build_archive_blocking",
        "_verify_archive_blocking",
        "_verify_in_staging",
        "_restore_blocking",
    }
)
#: ``dr_backup`` functions that read the EXTRACTED snapshot's own store cells during a full
#: restore-verify. Reading a store cell is what the store cipher is FOR, so these are where
#: ``build_store_cipher`` (and ``open_store``, which builds one internally) belong.
_SNAPSHOT_READ_FUNCS = frozenset({"_full_open_check", "_decrypt_check"})
#: Names that construct or obtain the STORE cipher. ``open_store`` is in the list because it calls
#: ``build_store_cipher`` itself — a file-wide token scan could not see that, which is half of why
#: it was the wrong instrument.
_STORE_CIPHER_CTORS = frozenset(
    {"build_store_cipher", "make_cipher", "build_transit_cipher", "open_store"}
)
#: The archive codec's own entry points (``store/backup_codec.py``), which take RAW DEK BYTES.
_ARCHIVE_CODEC_CALLS = frozenset({"encrypt_stream", "decrypt_stream"})


def _callee_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _dr_backup_tree() -> ast.Module:
    return ast.parse((_PKG / "pipeline" / "dr_backup.py").read_text(encoding="utf-8"))


def _named_func(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    found = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == name
    ]
    assert len(found) == 1, (
        f"pipeline/dr_backup.py declares {len(found)} functions named {name!r}; this guard names the "
        "backup's key paths by function, so a rename or a duplicate must be re-derived here, not "
        "silently skipped."
    )
    return found[0]


def _sites(calls: list[ast.Call]) -> list[str]:
    """Call nodes rendered for a failure message — the callee and the line it sits on."""
    return [f"{_callee_name(c)} at line {c.lineno}" for c in calls]


def _split_call_sites(
    tree: ast.Module, funcs: frozenset[str], names: frozenset[str]
) -> tuple[list[ast.Call], list[ast.Call]]:
    """``(inside, outside)`` — call sites of ``names``, split by whether they sit LEXICALLY in one of
    ``funcs``. No call is followed: a helper defined outside ``funcs`` and called from inside one
    lands in ``outside``, which errs toward reporting rather than toward a false green.

    Keyed on AST node identity (``ast`` nodes hash by identity), not on a line range, so a nested
    helper such as ``_full_open_check._open`` counts as INSIDE its enclosing function and nothing is
    double-counted.

    DELIBERATE DUPLICATION. ``tests/_ast_sites.py`` on the unlanded PR 1176 exports near-twins of
    this and the three helpers above. These stay private so this guard lands independently of a
    branch that is still conflicting. Whoever collapses them once both are on ``main`` must keep the
    LEXICAL bucketing: 1176's ``call_sites`` answers a different question, and a de-duplication that
    matches on the name alone would silently swap the semantics this test's verdict rests on.
    """
    inside_nodes = {
        sub
        for name in funcs
        for sub in ast.walk(_named_func(tree, name))
        if isinstance(sub, ast.Call)
    }
    inside: list[ast.Call] = []
    outside: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _callee_name(node) in names:
            (inside if node in inside_nodes else outside).append(node)
    return inside, outside


def test_the_mfbak_seal_never_reaches_for_the_store_cipher() -> None:
    """§3's `.mfbak` carve-out, pinned by CALL PATH rather than by a file-wide token.

    RULE: sealing a `.mfbak` under the store cipher would make §3's "`vault_transit` never applies
    to sealing or unsealing a `.mfbak`" false, and would put a per-value string cipher on a multi-GB
    stream. That is the thing forbidden, and this asserts it where it happens — the functions that
    write and read the archive.

    WHY A SEPARATE TEST FROM ``test_pl1_encryption_rule_carves_out_the_backup_codec`` ABOVE. That one
    asks whether §3 still NAMES the tokens the codec tier needs; this one asks whether the CODE stays
    inside the boundary §3 describes. Two failure modes, two reds, and the message tells you which:
    a sentence deleted from the document, versus a call that crossed the line. Measured on this
    branch: planting a ``build_store_cipher`` call in ``_build_archive_blocking`` reds THIS test and
    leaves that one green, and deleting §3's scoping sentence does the same — so neither subsumes the
    other in either direction.

    WHAT THIS DELIBERATELY DOES NOT ASSERT. That the bytes sealing the archive ARE the
    ``resolve_active_key`` DEK is proved by behaviour, not by syntax, in
    ``tests/test_backup_runner.py::test_archive_encrypted_under_store_dek`` — it runs the real
    ``BackupRunner`` and decrypts the produced ``.mfbak`` with the configured store DEK, so any other
    key fails there. An AST re-derivation of that chain was tried and removed: it pinned call SHAPE,
    so rewriting ``encrypt_stream(src, dst, key, ...)`` to pass ``key=key`` would have reddened it
    with a message reporting a key-material regression that had not happened.

    WHAT THE OLD INSTRUMENT COULD NOT DO. Before the AC-13 restore-verify landed, the assertion was
    ``"build_store_cipher" not in dr_backup.py`` — the whole file, by token — and it was wrong in
    both directions. It **under-fired**: ``_full_open_check`` has always called ``open_store``, which
    builds a store cipher internally, so the token scan could never have caught a seal that obtained
    its cipher that way, nor one that aliased the import. And it **over-fired**: a full restore-verify
    decrypts the extracted snapshot's own cells, which is a store read and legitimately needs the
    store cipher — a different operation from sealing the archive, in a different function, on a
    different key use. A file-wide token cannot tell those two apart, so it was replaced by a
    conditional documentation-sync check, which forbids nothing. This guard restores the prohibition
    at the resolution the claim is actually made: the permitted region is named and closed, and a
    seal that reaches for the store cipher by ANY of the four constructor names fails.

    SCOPE. ``_split_call_sites`` buckets LEXICALLY and follows no calls; its own docstring states the
    consequences. It is why this test says "in" rather than "reached".
    """
    # (0) The doc limb. Every sibling in this file pins the §3 prose before it pins the code, and a
    # code-only guard would stay green if the scoped sentence were deleted — pinning a claim the
    # document no longer makes, which is the defect this whole file exists to catch. The phrase is
    # matched against the FLATTENED section so a reflow of the bullet does not read as a deletion.
    section3 = _section(3)
    flat3 = " ".join(section3.split())
    assert "never applies to sealing or unsealing a `.mfbak`" in flat3, (
        "§3's PL-1 encryption rule no longer scopes `vault_transit` off the archive seal. The code "
        "assertions below pin only half of that claim; without the sentence they pin nothing a "
        "reader is told."
    )
    # `build_store_cipher` is deliberately NOT re-asserted here: the sibling test above already pins
    # it in §3 whenever dr_backup builds one, and limb (2) below pins that it does. Asserting it in
    # both places would give one deletion two reds pointing at one edit.
    assert "resolve_active_key" in section3, (
        "§3's PL-1 encryption rule no longer names `resolve_active_key`. The carve-out is SCOPED — "
        "the store cipher is OFF the archive seal and ON the full restore-verify's snapshot read — "
        "and the seal's own key source has to stay stated for that scoping to mean anything."
    )

    # (0b) The forbidden-constructor list is hand-named, so pin each name to a real symbol. Without
    # this a rename in store/ leaves an entry matching nothing and the arm below passes on a list of
    # dead strings — the same shape of defect as the token scan this test replaces. Resolved by
    # GETATTR rather than by scanning source text: this test's whole thesis is that a token scan
    # answers the wrong question, and it would be answering the wrong one here too — a decorated or
    # re-exported constructor has no literal `def name(` to find.
    from messagefoundry.store import base, crypto, crypto_transit

    _ctor_modules = (base, crypto, crypto_transit)
    unresolved = sorted(
        n
        for n in _STORE_CIPHER_CTORS
        if not any(callable(getattr(m, n, None)) for m in _ctor_modules)
    )
    assert not unresolved, (
        f"_STORE_CIPHER_CTORS names {unresolved}, which no longer resolve to a callable in "
        "messagefoundry.store.{base,crypto,crypto_transit}. Re-derive the store-cipher entry points "
        "(or the module that holds them); a stale name guards nothing."
    )

    tree = _dr_backup_tree()

    # (1) The archive codec is called ONLY from the seal/unseal region. A new sealing site added
    # elsewhere lands in `outside` and reds, rather than escaping a region named once and forgotten.
    codec_inside, codec_outside = _split_call_sites(tree, _MFBAK_CODEC_FUNCS, _ARCHIVE_CODEC_CALLS)
    assert {_callee_name(c) for c in codec_inside} == _ARCHIVE_CODEC_CALLS, (
        f"the instrument did not find both archive-codec entry points; it saw {_sites(codec_inside)}. "
        "A guard that cannot see the thing it guards proves nothing by passing."
    )
    assert not codec_outside, (
        f"pipeline/dr_backup.py seals or unseals a .mfbak outside the named codec region: "
        f"{_sites(codec_outside)}. Add the function to _MFBAK_CODEC_FUNCS and re-derive §3's "
        "carve-out for it."
    )

    # (2) The store cipher is constructed ONLY on the snapshot-read path. This is the prohibition the
    # old token scan was written for, now scoped to where it is true.
    cipher_inside, cipher_outside = _split_call_sites(
        tree, _SNAPSHOT_READ_FUNCS, _STORE_CIPHER_CTORS
    )
    assert cipher_inside, (
        "the instrument found no store-cipher construction anywhere in pipeline/dr_backup.py, so its "
        "'none outside the snapshot-read path' result is vacuous. Re-derive which functions open the "
        "extracted snapshot."
    )
    assert not cipher_outside, (
        f"pipeline/dr_backup.py builds the STORE cipher outside the snapshot-read path: "
        f"{_sites(cipher_outside)}. §3 says the `.mfbak` seal is keyed by resolve_active_key and NOT "
        "by build_store_cipher, so `cipher_provider = vault_transit` never applies to the archive — "
        "sealing with the store cipher makes that sentence false."
    )


#: A synthetic ``dr_backup`` in miniature for the self-test below: every function the guard names,
#: each call in the region the guard permits. The clean arm must produce two empty ``outside``
#: buckets, so each planted violation below is attributable to the one line it adds.
_SEAL_GUARD_FIXTURE = """
def _resolve_key():
    return resolve_active_key(settings)

def _do_backup():
    key = _resolve_key()
    return to_thread(self._build_archive_blocking, key=key)

def _build_archive_blocking(key):
    encrypt_stream(src, dst, key)

def _verify_archive_blocking(keys):
    return _verify_in_staging(staging, match_key=keys[0])

def _verify_in_staging(staging, match_key):
    decrypt_stream(src, dst, match_key)

def _restore_blocking(keys):
    decrypt_stream(src, dst, keys[0])

def _full_open_check(snap, settings):
    return open_store(settings)

def _decrypt_check(snap, settings):
    return build_store_cipher(settings)
"""


def _seal_guard_buckets(source: str) -> tuple[list[ast.Call], list[ast.Call]]:
    """``(codec_outside, cipher_outside)`` — the two buckets the guard above renders its verdict on."""
    tree = ast.parse(source)
    _, codec_outside = _split_call_sites(tree, _MFBAK_CODEC_FUNCS, _ARCHIVE_CODEC_CALLS)
    _, cipher_outside = _split_call_sites(tree, _SNAPSHOT_READ_FUNCS, _STORE_CIPHER_CTORS)
    return codec_outside, cipher_outside


def test_the_mfbak_seal_guard_reds_on_a_planted_violation() -> None:
    """The planted-violation self-test this file's claim-truth banner requires, for the seal guard.

    A guard that cannot fail is worse than none: it licenses the behaviour it appears to forbid. The
    vacuity limb inside the guard proves the instrument SEES the archive codec; it does not prove a
    misplaced call lands in ``outside``, which is what the verdict is actually read off. This plants
    one, against a synthetic module rather than by editing ``pipeline/dr_backup.py``, so the proof
    runs on every CI leg instead of once in the session that hand-mutated the engine.

    The two violations are mutated in OPPOSITE directions and asserted to red DISJOINTLY, by COUNT.
    Paired arms that both red prove only that something is wrong; requiring each arm to leave the
    other bucket EMPTY is what shows the two limbs discriminate rather than co-firing on any change.
    """
    clean_codec, clean_cipher = _seal_guard_buckets(_SEAL_GUARD_FIXTURE)
    assert not clean_codec and not clean_cipher, (
        f"the self-test fixture is not clean to begin with (codec {_sites(clean_codec)}, cipher "
        f"{_sites(clean_cipher)}), so neither planted violation below is attributable to its own line."
    )

    # (a) A seal that reaches for the store cipher: the prohibition the guard exists for.
    seal_reaches = _SEAL_GUARD_FIXTURE.replace(
        "    encrypt_stream(src, dst, key)",
        "    encrypt_stream(src, dst, build_store_cipher(settings))",
    )
    codec_a, cipher_a = _seal_guard_buckets(seal_reaches)
    assert len(cipher_a) == 1 and _callee_name(cipher_a[0]) == "build_store_cipher", (
        f"a store cipher built inside _build_archive_blocking did not land outside the snapshot-read "
        f"path; the guard would pass a seal keyed by the store cipher. Saw {_sites(cipher_a)}."
    )
    assert not codec_a, (
        f"the codec limb co-fired on a store-cipher violation ({_sites(codec_a)}); the two limbs do "
        "not discriminate, so neither red identifies its own cause."
    )

    # (b) A seal added outside the named region: the escape a region named once and forgotten allows.
    stray_seal = (
        _SEAL_GUARD_FIXTURE + "\ndef _sneaks_a_seal(key):\n    encrypt_stream(src, dst, key)\n"
    )
    codec_b, cipher_b = _seal_guard_buckets(stray_seal)
    assert len(codec_b) == 1 and _callee_name(codec_b[0]) == "encrypt_stream", (
        f"a .mfbak sealed from a function outside _MFBAK_CODEC_FUNCS did not land outside the codec "
        f"region; a new sealing site would escape the guard. Saw {_sites(codec_b)}."
    )
    assert not cipher_b, (
        f"the store-cipher limb co-fired on a stray-seal violation ({_sites(cipher_b)}); the two "
        "limbs do not discriminate, so neither red identifies its own cause."
    )


def test_pl1_retention_covers_every_tier_it_lists() -> None:
    """The PL-1 retention/destruction bullet used to cover 8 of the 10 tiers it enumerates."""
    section3 = _section(3)
    block = section3[section3.index("#### PL-1") : section3.index("#### PL-2")]
    retention = block[block.index("- **Retention / destruction.**") :]
    assert "retention_keep" in retention, (
        "the PL-1 retention bullet does not state `.mfbak`'s keep-N bound — a classified PHI-body "
        "tier with no stated retention position anywhere is the 14.1.2 defect."
    )
    assert "spill dirs have no engine-managed retention" in retention, (
        "the PL-1 retention bullet does not state that File-connector spill dirs have NO engine "
        "retention or destruction at all."
    )


def test_pl1_access_names_the_bulk_export_and_the_outbound_route() -> None:
    """The engine's largest PHI-body read surface was absent from the whole document."""
    section3 = _section(3)
    for token in ("/messages/export", "messages:export", "messages_export", "/outbound"):
        assert token in section3, (
            f"§3's PL-1 access rule does not name {token!r}. `GET /messages/export` streams many raw "
            "bodies behind a fresh step-up over BOTH messages:export and messages:view_raw, and the "
            "transformed payload has its own route — 14.1.2 scores the access requirement."
        )


def test_pl4_states_a_per_tier_retention_position() -> None:
    """PL-4 was the only level with no Applies-to list, and one tier's window stood for all."""
    section3 = _section(3)
    block = section3[section3.index("#### PL-4") : section3.index("#### PL-5")]
    assert "**Applies to:**" in block, "PL-4 has no Applies-to list"
    for tier in ("purge_expired_sessions", "processed_files", "state_max_age_days", "reference"):
        assert tier in block, (
            f"PL-4's retention statement does not cover {tier!r} — `[retention].audit_days` is "
            "reserved and not enforced, but the level's other tiers ARE purged, by other drivers."
        )


# =================================================================================================
# ASVS 14.2.4 — a documented control that the deployed backend does not have
# =================================================================================================


def test_owner_only_file_acl_is_always_qualified_to_the_sqlite_store() -> None:
    """The engine applies an owner-only ACL only where it CREATES the file.

    RULE (14.2.4 — "controls implemented as documented"): ``_secure_file`` exists on the SQLite store
    alone; on SQL Server / Postgres the engine creates no database file and never calls it. Every
    mention of the ACL must therefore carry a SQLite qualifier, including the HIPAA §164.312 mapping
    row — an unqualified claim in the scored posture is the defect itself.
    """
    sqlite_src = (_PKG / "store" / "store.py").read_text(encoding="utf-8")
    assert source_calls(sqlite_src, "_secure_file"), (
        "the SQLite store no longer applies an owner-only ACL"
    )
    for other in ("sqlserver.py", "postgres.py"):
        source = (_PKG / "store" / other).read_text(encoding="utf-8")
        # Absence over text on purpose: a mention can only over-fire, and a text scan also sees
        # an aliased import, which a name walk would not.
        assert "_secure_file" not in source, (
            f"{other} now applies a file ACL; the SQLite-only qualifiers in docs/PHI.md are stale."
        )
    text = _doc_text()
    lowered = text.lower()
    unqualified: list[str] = []
    for index, line in enumerate(text.splitlines()):
        if "owner-only" not in line.lower():
            continue
        # The qualifier may sit on the sentence's own line, on the two lines before it (a bolded
        # "[BUILT — SQLite only]" lead-in) or on the two after (a wrapped bullet).
        lines = text.splitlines()
        window = " ".join(lines[max(0, index - 2) : index + 3]).lower()
        if "sqlite" not in window and "server-db store" not in window:
            unqualified.append(line.strip()[:110])
    assert not unqualified, (
        "unqualified owner-only-file-ACL claim(s) in docs/PHI.md — the engine applies no ACL on a "
        f"server-DB store, which is the deployed posture: {unqualified}"
    )
    assert "sqlite" in lowered, "sanity: the document no longer mentions SQLite at all"


def test_presence_gated_security_desugar_is_documented_and_true() -> None:
    """``[security].delete_message_bodies_after_days``'s model default of 30 is INERT unless set.

    RULE: the §8 posture-gate bullet quoted the 30 as if it took effect. ``_desugar_security`` is
    presence-gated, so a config with no ``[security]`` block leaves ``[retention].messages_days`` at
    0 and the posture gate is what bounds a PHI instance. Asserted behaviourally, not by reading the
    two endpoint defaults independently.
    """
    settings = ServiceSettings()
    assert settings.security.delete_message_bodies_after_days == 30, (
        "the model default moved; update §8 and this pin together"
    )
    assert settings.retention.messages_days == 0, (
        "an unset [security] block now writes through onto [retention].messages_days; the "
        "presence-gating §8 documents is gone — update the doc in the same change."
    )
    section8 = _section(8)
    assert "presence-gated" in section8, (
        "§8 must state that the desugar is presence-gated, or a reader concludes the body window "
        "defaults to 30 days on a non-PHI instance. It does not."
    )


def _purge_table_cells(section: str) -> dict[str, dict[str, str]]:
    """``{operation: {backend: verdict}}`` parsed from §8's per-backend table."""
    out: dict[str, dict[str, str]] = {}
    header: list[str] | None = None
    for raw in section.splitlines():
        line = raw.strip()
        if not (line.startswith("|") and line.endswith("|")):
            continue
        cells = [c.strip() for c in line[1:-1].split("|")]
        if all(c and set(c) <= set("-: ") for c in cells):
            continue
        if header is None and any(c in {"SQLite", "SQL Server", "Postgres"} for c in cells):
            header = cells
            continue
        if header is None:
            continue
        name = next((n for n in _BACKTICK_RE.findall(cells[0])), None)
        if name is None:
            continue
        verdicts = {
            backend: cells[i]
            for i, backend in enumerate(header)
            if backend in {"SQLite", "SQL Server", "Postgres"} and i < len(cells)
        }
        if verdicts:
            out[name] = verdicts
    return out


#: §8 rows whose operation is NOT a Store method: the app-log sweep is filesystem work owned by the
#: RetentionRunner itself, identical on every backend. Reviewed and pinned below, so it cannot be
#: used as a hiding place for a store operation that quietly stopped being implemented.
_NON_STORE_OPERATIONS = frozenset({"app_log_days"})


def _method_shape(cls: type, name: str) -> str:
    """``"stub"`` (docstring only), ``"delegated"`` (raises DbaDelegatedError) or ``"enforced"``."""
    func = cls.__dict__.get(name)
    if func is None:
        return "absent"
    source = textwrap.dedent(inspect.getsource(func))
    tree = ast.parse(source).body[0]
    assert isinstance(tree, ast.FunctionDef | ast.AsyncFunctionDef)
    body = [
        n for n in tree.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))
    ]
    if not body:
        return "stub"
    if any(isinstance(n, ast.Raise) and "DbaDelegatedError" in ast.dump(n) for n in ast.walk(tree)):
        return "delegated"
    return "enforced"


def test_per_backend_purge_verdicts_are_bound_to_the_method_bodies() -> None:
    """§8's central claim — "every PHI purge is enforced by the engine on all three backends" — is
    now bound to behaviour, not to a substring.

    RULE: the guard used to assert only that a method NAME was in the class ``__dict__`` and that the
    three backend words appeared somewhere in §8. Gutting ``SqlServerStore.purge_state`` to ``pass``,
    or flipping a cell from "enforced" to "no-op (DBA-owned)", both passed unchanged.
    """
    backends = {
        "SQLite": MessageStore,
        "SQL Server": SqlServerStore,
        "Postgres": PostgresStore,
    }
    table = _purge_table_cells(_section(8))
    assert table, "§8's per-backend purge table could not be parsed"
    mismatches = _verdict_mismatches(table, backends)
    assert not mismatches, "docs/PHI.md §8's per-backend verdicts disagree with the code: " + str(
        mismatches
    )
    # The reviewed non-Store exemption must stay honest in both directions: genuinely absent from
    # every backend class, and genuinely present in the RetentionRunner.
    retention = (_PKG / "pipeline" / "retention.py").read_text(encoding="utf-8")
    for operation in sorted(_NON_STORE_OPERATIONS):
        for backend, cls in sorted(backends.items()):
            assert operation not in cls.__dict__, (
                f"{backend}.{operation} is now a Store method; drop it from _NON_STORE_OPERATIONS "
                "so its per-backend verdict is bound like every other row."
            )
        assert source_uses(retention, operation), (
            f"{operation} is exempted as RetentionRunner-owned but no longer appears in "
            "pipeline/retention.py — the §8 row describes nothing."
        )


def _verdict_mismatches(table: dict[str, dict[str, str]], backends: dict[str, type]) -> list[str]:
    """The comparison itself, factored out so the self-test can run it against a MUTATED table."""
    mismatches: list[str] = []
    for operation, verdicts in sorted(table.items()):
        if operation in _NON_STORE_OPERATIONS:
            continue
        for backend, cell in sorted(verdicts.items()):
            shape = _method_shape(backends[backend], operation)
            if shape == "absent":
                mismatches.append(f"{backend}.{operation}: not defined on the class at all")
                continue
            lowered = cell.lower()
            if "no-op" in lowered and shape != "stub":
                mismatches.append(
                    f"{backend}.{operation}: §8 says no-op, but the method body does real work"
                )
            elif "dba-delegated" in lowered and shape != "delegated":
                mismatches.append(
                    f"{backend}.{operation}: §8 says DBA-delegated, but it does not raise "
                    "DbaDelegatedError"
                )
            elif "enforced" in lowered and shape != "enforced":
                mismatches.append(
                    f"{backend}.{operation}: §8 says enforced, but the body is {shape} — a gutted "
                    "implementation next to an 'enforced' cell is exactly the 14.2.4 defect"
                )
    return mismatches


def test_purge_verdict_guard_detects_a_planted_cell_flip() -> None:
    """Proves the verdict binding can fail — by MUTATING the doc cell and re-running the comparison.

    The previous version only asserted ``_method_shape(SqlServerStore, "purge_state") != "stub"``,
    a check that cannot fail while the code is correct. This flips the real cell in an in-memory copy
    of the table and requires the comparison to report it.
    """
    backends = {
        "SQLite": MessageStore,
        "SQL Server": SqlServerStore,
        "Postgres": PostgresStore,
    }
    table = _purge_table_cells(_section(8))
    victim = "purge_state"
    assert victim in table and "enforced" in table[victim]["SQL Server"].lower(), (
        f"fixture drifted: {victim} is no longer an enforced SQL Server cell"
    )
    assert not _verdict_mismatches(table, backends), "the unmutated table must compare clean"
    mutated = {op: dict(cells) for op, cells in table.items()}
    mutated[victim]["SQL Server"] = "no-op (DBA-owned)"
    reported = _verdict_mismatches(mutated, backends)
    assert any(f"SQL Server.{victim}" in m for m in reported), (
        f"flipping the {victim} SQL Server cell to 'no-op (DBA-owned)' must be reported; the "
        f"comparison returned {reported}"
    )


# --- claim-truth guards: a token appearing is not the same as its claim being true ---------------
#
# The presence checks above assert a code-derived token appears SOMEWHERE in a section. That let four
# false statements ship green (secret_rotation_meta "SQLite only" once #1186 put it on all three
# backends; uploads "no retention path" once #291 shipped the prune) — the tokens were present in the
# very rows that lied. These checks bind the CLAIM to a code fact, so they fail on a real regression
# rather than merely confirming a name is spelled. Each ships a planted-violation self-test.

#: The three backend classes an "all three backends" claim is about, and the modules where the store
#: protocols a claim may cite are defined. A REGISTERED row citing a protocol outside these modules
#: reds as unknown; the section 2 scan below skips a token it cannot resolve.
_BACKENDS: tuple[type, ...] = (MessageStore, SqlServerStore, PostgresStore)
_PROTOCOL_MODULES = (store_base, store_store, store_sqlserver, store_postgres, store_privilege)
_SQLITE_ONLY_LIES = ("SQLite only", "SQLite-only", "server backends don't")
_ALL_THREE_RE = re.compile(r"all three", re.IGNORECASE)
#: A sentence boundary inside a prose paragraph: end punctuation (optionally closing a bold run),
#: space, then a capital, a bold or code marker, a bracket or a ``#``.
_SENTENCE_SPLIT_RE = re.compile(r"(?:(?<=[.!?])|(?<=[.!?]\*\*))\s+(?=[A-Z*`(\[#])")


# --- the backend-reach claim registry (BACKLOG #1186 slice B) -------------------------------------
#
# ONE ROW USED TO BE HAND-WRITTEN HERE, and its CODE side was hand-written too: a tuple of two
# secret_rotation_meta accessors, checked for presence on the three backend classes. The protocol
# that tuple stood for has THREE members, so the hand list was already short.
#
# Now each registry row names a CLAIM docs/PHI.md makes and the FEATURE it is about, and what makes
# the claim true is read from code, never typed here:
#
# * A store ``Protocol`` is on every backend when each backend class implements every member the
#   protocol declares (``typing.get_protocol_members``). A method must be defined in the class's
#   own body with a real body: a docstring-only stub or a DbaDelegatedError refusal does not count
#   (``_method_shape``). A data member counts when the class body or its ``__init__`` sets it.
# * An open-time keyword reaches every backend when ``_open_backend`` passes ``kw=kw`` on every call
#   to each backend's ``open``, that ``open`` passes ``kw=kw`` on every constructor call, and the
#   constructor stores it as ``self.kw`` or ``self._kw``. It does NOT check what ``open_store``
#   passes in (which may legitimately be ``None``), nor that any later code READS the attribute.
#
# The doc side is bound too. Each row's anchor is the claim's own words, so a claim reworded into a
# negation stops matching. A table-row claim is read from its Backends cell only. And every section
# 2 row whose Backends cell cites a feature must be registered, whether it says "all three" or
# "SQLite only", so a structured claim cannot land unbound in either direction. A PROSE claim added
# elsewhere is not discovered; that shape rests on review.
#
# HONEST BOUND. This binds WHERE a feature is delivered, and nothing else. What the GCM tag and the
# cell AAD protect, and what the audit MAC detects, are integrity claims it cannot express.


@dataclasses.dataclass(frozen=True)
class _ReachClaim:
    #: The claim's own words in docs/PHI.md. It must fall inside exactly one claim unit. For a prose
    #: claim it must itself say "all three"; a table row is located by its first cell.
    anchor: str
    #: A store Protocol name, or an open-time keyword. Resolved from code.
    feature: str


#: THE REGISTRY. A new "all three backends" claim is a new row here.
_REACH_CLAIMS = (
    _ReachClaim("| `secret_rotation_meta` (", "SecretRotationMetaStore"),
    _ReachClaim("Transit-backed audit MAC reaches **all three** backends", "audit_mac_fn"),
)


def _protocol_named(name: str) -> type | None:
    for module in _PROTOCOL_MODULES:
        obj = vars(module).get(name)
        if isinstance(obj, type) and obj.__module__ == module.__name__ and typing.is_protocol(obj):
            return obj
    return None


def _self_assignments(init_source: str) -> list[tuple[str, ast.expr | None]]:
    """``(attribute, value)`` for every ``self.<attribute> = <value>`` in ``init_source``."""
    found: list[tuple[str, ast.expr | None]] = []
    for node in ast.walk(parse_source(textwrap.dedent(init_source))):
        targets: list[ast.expr]
        value: ast.expr | None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        for target in targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                found.append((target.attr, value))
    return found


def _init_source(cls: type) -> str:
    return inspect.getsource(vars(cls)["__init__"])


def _implements(cls: type, member: str) -> bool:
    attr = vars(cls).get(member)
    if attr is None:
        return any(name == member for name, _v in _self_assignments(_init_source(cls)))
    if inspect.isfunction(attr):
        return _method_shape(cls, member) == "enforced"
    return True  # a property or a class-level data member defined in the class body


def _protocol_is_on_every_backend(protocol: type) -> bool:
    members = typing.get_protocol_members(protocol)
    return bool(members) and all(_implements(cls, m) for cls in _BACKENDS for m in members)


def _passes_through(call: ast.Call, keyword: str) -> bool:
    """Whether ``call`` passes ``keyword=keyword`` -- the name, not a literal such as ``None``."""
    return any(
        kw.arg == keyword and isinstance(kw.value, ast.Name) and kw.value.id == keyword
        for kw in call.keywords
    )


def _dispatch_calls(dispatch_source: str | None = None) -> dict[str, list[ast.Call]]:
    """``{backend class name: its open calls}`` in ``_open_backend``. ``dispatch_source`` stands in
    for the real source so a self-test can plant a dropped keyword."""
    source = (
        inspect.getsource(store_base._open_backend) if dispatch_source is None else dispatch_source
    )
    calls: dict[str, list[ast.Call]] = {}
    for call in call_sites(parse_source(textwrap.dedent(source)), "open"):
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
            calls.setdefault(call.func.value.id, []).append(call)
    expected = {cls.__name__ for cls in _BACKENDS}
    assert set(calls) == expected, f"_open_backend dispatch changed shape: {sorted(calls)}"
    return calls


def _open_passes_on(open_source: str, keyword: str) -> bool:
    """Whether every constructor call in a backend's ``open`` passes ``keyword=keyword``."""
    ctor_calls = call_sites(parse_source(textwrap.dedent(open_source)), "cls", bare_only=True)
    return bool(ctor_calls) and all(_passes_through(call, keyword) for call in ctor_calls)


def _init_keeps(init_source: str, keyword: str) -> bool:
    """Whether ``__init__`` stores the parameter as ``self.<keyword>`` or ``self._<keyword>``."""
    return any(
        name in {keyword, f"_{keyword}"} and isinstance(value, ast.Name) and value.id == keyword
        for name, value in _self_assignments(init_source)
    )


def _keyword_reaches_every_backend(keyword: str, dispatch_source: str | None = None) -> bool:
    for cls in _BACKENDS:
        calls = _dispatch_calls(dispatch_source)[cls.__name__]
        if not all(_passes_through(call, keyword) for call in calls):
            return False
        if not _open_passes_on(inspect.getsource(vars(cls)["open"].__func__), keyword):
            return False
        if not _init_keeps(_init_source(cls), keyword):
            return False
    return True


def _feature_kind(token: str) -> str | None:
    """``"protocol"``, ``"keyword"``, or ``None`` when ``token`` names neither. Resolve only."""
    if _protocol_named(token) is not None:
        return "protocol"
    dispatched = _dispatch_calls()
    if any(kw.arg == token for calls in dispatched.values() for c in calls for kw in c.keywords):
        return "keyword"
    return None


def _feature_reaches_every_backend(feature: str, dispatch_source: str | None = None) -> bool | None:
    """True or False from code, or None when ``feature`` names neither a protocol nor a keyword."""
    protocol = _protocol_named(feature)
    if protocol is not None:
        return _protocol_is_on_every_backend(protocol)
    if _feature_kind(feature) == "keyword":
        return _keyword_reaches_every_backend(feature, dispatch_source)
    return None


def _claim_units(text: str) -> list[str]:
    """Each table row, and each sentence of each prose paragraph, with whitespace folded."""
    units: list[str] = []
    paragraph: list[str] = []

    def flush() -> None:
        if paragraph:
            units.extend(_SENTENCE_SPLIT_RE.split(" ".join(" ".join(paragraph).split())))
            paragraph.clear()

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|"):
            flush()
            units.append(stripped)
        elif not stripped or re.match(r"(#+ |[-*] |\d+\. |```)", stripped):
            flush()
            if stripped:
                paragraph.append(stripped)
        else:
            paragraph.append(stripped)
    flush()
    return units


def _backends_cell(row: str) -> str:
    cells = [c.strip() for c in row.strip().strip("|").split("|")]
    return cells[1] if len(cells) > 1 else ""


def _doc_side_problems(text: str, claim: _ReachClaim) -> list[str]:
    """What is wrong with how the doc states ``claim`` (pure -- drives the self-test)."""
    matches = [unit for unit in _claim_units(text) if claim.anchor in unit]
    if len(matches) != 1:
        return [f"the anchor locates {len(matches)} claim units, not 1"]
    unit = matches[0]
    scope = _backends_cell(unit) if unit.startswith("|") else unit
    problems = []
    if not _ALL_THREE_RE.search(scope):
        problems.append("no longer says 'all three'")
    if claim.feature not in _BACKTICK_RE.findall(scope):
        problems.append(f"no longer cites `{claim.feature}`")
    lie = next((phrase for phrase in _SQLITE_ONLY_LIES if phrase in scope), None)
    if lie is not None:
        problems.append(f"calls it {lie!r}")
    return problems


def _unregistered_section_2_claims(section: str) -> list[str]:
    """Section 2 rows whose Backends cell cites a feature no registry row names. Either direction:
    a row saying "all three" and a row saying "SQLite only" both need a registry row."""
    registered = {claim.feature for claim in _REACH_CLAIMS}
    found = []
    for line in _table_rows(section).splitlines():
        for token in _BACKTICK_RE.findall(_backends_cell(line)):
            if token not in registered and _feature_kind(token) is not None:
                found.append(f"{token} in: {line[:120]}")
    return found


def test_every_registered_reach_claim_is_stated_in_the_doc() -> None:
    """The doc side: each registered claim is still in docs/PHI.md in its own words, still says
    'all three', still cites its feature, and does not call it SQLite-only."""
    text = _doc_text()
    prose_anchors_without_the_claim = [
        c.anchor
        for c in _REACH_CLAIMS
        if not c.anchor.startswith("|") and "all three" not in c.anchor
    ]
    assert prose_anchors_without_the_claim == []
    problems = {c.feature: p for c in _REACH_CLAIMS if (p := _doc_side_problems(text, c))}
    assert problems == {}, f"registered backend-reach claims drifted in docs/PHI.md: {problems}"


def test_every_registered_reach_claim_is_true_in_code() -> None:
    """ASVS 14.2.4 -- the audit MAC's delivery to every backend, and the secret_rotation_meta row it
    generalises. Each feature must resolve, and must reach all three. This binds where the MAC is
    DELIVERED, not what it protects: the integrity claims themselves stay unbound."""
    verdicts = {c.feature: _feature_reaches_every_backend(c.feature) for c in _REACH_CLAIMS}
    unknown = sorted(f for f, v in verdicts.items() if v is None)
    assert not unknown, f"registered features code does not define: {unknown}"
    false = sorted(f for f, v in verdicts.items() if v is False)
    assert not false, f"docs/PHI.md says all three backends, but code does not: {false}"


def test_every_section_2_backends_cell_feature_is_registered() -> None:
    """Completeness for the STRUCTURED claims. A section 2 row whose Backends cell cites a protocol or
    an open keyword must be a registry row, or its claim would ship unbound."""
    assert _unregistered_section_2_claims(_section(2)) == []


def test_secret_rotation_meta_row_is_not_documented_sqlite_only() -> None:
    """ASVS 13.3.4 -- ``secret_rotation_meta`` is on all three backends (#1186), so its section 2
    row must not call it SQLite-only. The row is now one registry row among others, and its protocol
    is read from code rather than a hand-typed accessor tuple.

    The name is kept because the ASVS record anchors on it."""
    claim = next(c for c in _REACH_CLAIMS if c.feature == "SecretRotationMetaStore")
    assert _feature_reaches_every_backend(claim.feature), "not on every backend -- re-cut this"
    assert _doc_side_problems(_doc_text(), claim) == []


def test_the_reach_check_discriminates_on_both_halves() -> None:
    """The instrument, checked before it is trusted. Each half must return False on a case built to
    be False, and True where it should, in the same run -- otherwise it cannot fail."""
    # Keyword half: a real SQLite-only open keyword, and a name that is no feature at all.
    assert _feature_reaches_every_backend("group_commit_window_ms") is False
    assert _feature_reaches_every_backend("no_such_feature") is None

    # Protocol half: a member only the SQLite backend defines; a data member every backend sets in
    # __init__; and a member SQL Server defines only as a docstring stub.
    class _SqliteOnly(typing.Protocol):
        def _migrate_outbox_to_queue(self) -> None: ...

    class _EveryBackendSetsPath(typing.Protocol):
        path: object

    class _StubOnSqlServer(typing.Protocol):
        def vacuum(self) -> None: ...

    assert "_migrate_outbox_to_queue" in vars(MessageStore), "the planted member moved; re-point"
    assert _method_shape(SqlServerStore, "vacuum") == "stub", "the stub moved; re-point"
    assert _protocol_is_on_every_backend(_SqliteOnly) is False
    assert _protocol_is_on_every_backend(_EveryBackendSetsPath) is True
    assert _protocol_is_on_every_backend(_StubOnSqlServer) is False


def test_backend_reach_registry_reds_on_a_planted_dropped_keyword() -> None:
    """Delete-and-watch-it-fail on the dispatch leg. Drop ``audit_mac_fn`` from ONE backend's
    ``open`` call in ``_open_backend``, or pass ``None`` instead: the audit-MAC claim must read False."""
    for plant in ("drop", "none"):
        # A private ast.parse, never parse_source: that tree is cached and shared, and mutating it
        # would plant the change in every later reader of the same source.
        tree = ast.parse(textwrap.dedent(inspect.getsource(store_base._open_backend)))
        calls = [c for c in call_sites(tree, "open") if _passes_through(c, "audit_mac_fn")]
        assert len(calls) == 3, "the forwarding calls moved; re-point this self-test"
        if plant == "drop":
            calls[0].keywords = [kw for kw in calls[0].keywords if kw.arg != "audit_mac_fn"]
        else:
            for kw in calls[0].keywords:
                if kw.arg == "audit_mac_fn":
                    kw.value = ast.Constant(value=None)
        assert _feature_reaches_every_backend("audit_mac_fn", ast.unparse(tree)) is False, plant
    assert _feature_reaches_every_backend("audit_mac_fn") is True


def test_the_constructor_and_init_legs_can_fail() -> None:
    """Delete-and-watch-it-fail on the other two legs, with planted sources."""
    ok_open = "def open(cls, s):\n    return cls(s, audit_mac_fn=audit_mac_fn)\n"
    assert _open_passes_on(ok_open, "audit_mac_fn")
    assert not _open_passes_on(ok_open.replace("=audit_mac_fn)", "=None)"), "audit_mac_fn")
    two_ctors = ok_open + "    return cls(s)\n"
    assert not _open_passes_on(two_ctors, "audit_mac_fn"), "one constructor call drops it"
    ok_init = "def __init__(self, audit_mac_fn):\n    self._audit_mac_fn = audit_mac_fn\n"
    assert _init_keeps(ok_init, "audit_mac_fn")
    assert not _init_keeps(ok_init.replace("self._audit_mac_fn", "self._unused"), "audit_mac_fn")
    assert not _init_keeps(ok_init.replace("= audit_mac_fn", "= None"), "audit_mac_fn")


def test_backend_reach_registry_self_test_on_planted_doc_text() -> None:
    """Non-vacuity on the doc side: a SQLite-only row is flagged, the corrected row is clean, a claim
    that lost its cite is flagged, a negated prose claim no longer matches, and an unregistered
    section 2 row is found in both directions."""
    row_claim = next(c for c in _REACH_CLAIMS if c.feature == "SecretRotationMetaStore")
    lie = "| `secret_rotation_meta` (x) | **SQLite only** (`SecretRotationMetaStore`) | a | b | c |"
    assert any("SQLite only" in p for p in _doc_side_problems(lie, row_claim))
    fixed = (
        "| `secret_rotation_meta` (x) | **All three backends** (`SecretRotationMetaStore`) | a |"
    )
    assert _doc_side_problems(fixed, row_claim) == []
    uncited = "| `secret_rotation_meta` (x) | **All three backends** | `SecretRotationMetaStore` |"
    assert _doc_side_problems(uncited, row_claim) == ["no longer cites `SecretRotationMetaStore`"]
    mac_claim = next(c for c in _REACH_CLAIMS if c.feature == "audit_mac_fn")
    negated = (
        "The Transit-backed audit MAC (`audit_mac_fn`) reaches SQLite but not all three backends."
    )
    assert _doc_side_problems(negated, mac_claim) == ["the anchor locates 0 claim units, not 1"]
    for backends in ("**all three** (`AuditStore`)", "**SQLite only** (`AuditStore`)"):
        row = f"| `audit_log` | {backends} | a |"
        assert _unregistered_section_2_claims(row) == [f"AuditStore in: {row[:120]}"]


#: Code markers proving uploads.py ships a real age-based prune (ASVS 5.2.4, #291).
_UPLOAD_PRUNE_MARKERS = ("prune_expired", "UploadRetentionRunner")


def _upload_prune_ships() -> bool:
    src = (_PKG / "uploads.py").read_text(encoding="utf-8")
    return all(source_uses(src, m) for m in _UPLOAD_PRUNE_MARKERS)


def _section_8_calls_uploads_a_no_retention_gap(section8: str) -> bool:
    """True if any §8 line names an uploaded_file tier AND denies it retention (pure — self-testable)."""
    for line in section8.splitlines():
        if "uploaded_file" in line and ("no retention" in line or "no purge" in line):
            return True
    return False


def test_uploads_dir_retention_is_documented_when_it_ships() -> None:
    """ASVS 5.2.4 — a shipped upload prune forces a POSITIVE retention statement in §8; the doc may not
    keep denying it. Fails today's-past behaviour where §8 called uploads a 'no retention' gap."""
    if not _upload_prune_ships():
        pytest.skip(
            "no UploadStore.prune_expired/UploadRetentionRunner — a 'no retention' row is allowed"
        )
    section8 = _section(8)
    assert "uploads_retention_days" in section8, (
        "uploads.py ships UploadStore.prune_expired + UploadRetentionRunner (ASVS 5.2.4, #291), but "
        "PHI.md §8 never names [store].uploads_retention_days — a real retention control is undocumented"
    )
    assert not _section_8_calls_uploads_a_no_retention_gap(section8), (
        "PHI.md §8 still lists an uploaded_file tier as a 'no retention'/'no purge' gap while the prune ships"
    )


def test_uploads_retention_guard_self_test() -> None:
    """Non-vacuity: the negative check must catch a re-introduced 'no retention' upload row."""
    planted = (
        "| `[store].uploads_dir` blobs (`uploaded_file.body`) | no retention path exists at all |"
    )
    assert _section_8_calls_uploads_a_no_retention_gap(planted)
    clean = "and uploaded_file pairs auto-prune after uploads_retention_days (default 30)."
    assert not _section_8_calls_uploads_a_no_retention_gap(clean)


#: Delete-and-watch-it-fail for every code probe above (BACKLOG #2056): ``(module, the code to
#: delete, what replaces it, the probe)``. Each case also appends a comment naming the deleted
#: construct, the mention the old substring scan read as the code.
_CODE_PROBE_DELETIONS: tuple[tuple[str, str, str, Callable[[str], bool]], ...] = (
    (
        "store/sqlserver.py",
        '"ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"',
        '"SELECT 1"',
        lambda src: source_has_literal(src, "ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT"),
    ),
    (
        "store/sqlserver.py",
        '"ALTER DATABASE CURRENT SET ALLOW_SNAPSHOT_ISOLATION ON"',
        '"SELECT 1"',
        lambda src: source_has_literal(src, "ALTER DATABASE CURRENT SET ALLOW_SNAPSHOT_ISOLATION"),
    ),
    (
        "store/sqlserver.py",
        '"CREATE TABLE #eligible (id NVARCHAR(64) PRIMARY KEY)"',
        '"SELECT 1"',
        lambda src: source_has_literal(src, "CREATE TABLE #eligible"),
    ),
    (
        "store/store.py",
        "SET metadata=NULL, raw='', summary=NULL, error=NULL ",
        "SET metadata=NULL, raw='' ",
        lambda src: "summary" in _purge_blanked_columns(src),
    ),
    (
        "store/store.py",
        "        _secure_file(path)\n",
        "        pass\n",
        lambda src: source_calls(src, "_secure_file"),
    ),
    (
        "pipeline/dr_backup.py",
        "resolve_active_key(self._store_settings)",
        "None",
        lambda src: source_calls(src, "resolve_active_key"),
    ),
    (
        "pipeline/dr_backup.py",
        "build_store_cipher(settings)",
        "None",
        lambda src: source_calls(src, "build_store_cipher"),
    ),
    (
        "pipeline/dr_backup.py",
        '_PLAINTEXT_EXT = ".mfbak.plain"',
        '_PLAINTEXT_EXT = ""',
        lambda src: source_has_literal(src, ".mfbak.plain"),
    ),
    (
        "pipeline/retention.py",
        "app_log_days",
        "other_days",
        lambda src: source_uses(src, "app_log_days"),
    ),
    ("uploads.py", "prune_expired", "prune_other", lambda src: source_uses(src, "prune_expired")),
)


@pytest.mark.parametrize(
    ("module", "code", "replacement", "probe"),
    _CODE_PROBE_DELETIONS,
    ids=[f"{m}:{c.strip()[:40]}" for m, c, _r, _p in _CODE_PROBE_DELETIONS],
)
def test_the_code_probes_fail_when_the_code_is_gone(
    module: str, code: str, replacement: str, probe: Callable[[str], bool]
) -> None:
    source = (_PKG / module).read_text(encoding="utf-8")
    assert probe(source), f"the probe does not see {code!r} in the real {module}"
    mutated = delete_keeping_a_mention(source, code, replacement)
    assert not probe(mutated), f"{module}: a comment naming {code.strip()!r} reads as the code"
