# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""`PHI_RETENTION_WINDOWS` and docs/PHI.md §2's Retention column must describe the SAME set.

ASVS 14.2.7 wants retention derived from a data classification. The serve gate's tier list is built
from :data:`PHI_RETENTION_WINDOWS`; this test is what makes that constant *derived* rather than
hand-typed, by asserting two-way equality against the column. Add a PHI tier to the doc without adding
it here, or here without the doc, and this reds.

**The parser is bounded STRUCTURALLY, and that is the whole difficulty.** §2 contains THREE contiguous
pipe blocks — a 2-column PL legend, the 7-column inventory, and a 4-column at-rest threat matrix. A
naive "every pipe row in §2" scan trips on the other two; and the natural repair (skip rows whose cell
count is wrong) DISARMS the cell-count check, so the drift test would then pass over a mangled table.
So the inventory is located by its own header and asserted UNIQUE, the cell-count check applies only
inside it, and there is a floor on the row count.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from messagefoundry.config.retention_classification import (
    MIN_PHI_RETENTION_WINDOWS,
    PHI_RETENTION_WINDOWS,
    auto_bounded_windows,
    warn_only_windows,
)
from messagefoundry.config.settings import (
    BackupSettings,
    LoggingSettings,
    RetentionSettings,
    SecuritySettings,
    StoreSettings,
)

_PHI_MD = pathlib.Path(__file__).resolve().parents[1] / "docs" / "PHI.md"

#: A backticked `[section].setting` — the machine-readable half of every bounded vocabulary form.
_SETTING = re.compile(r"`(\[[a-z_]+\]\.[a-z_]+)`")

#: The prose forms, which carry NO backticked setting. Listed so an unrecognised cell is an error
#: rather than being silently read as "no window".
_PROSE_FORMS = ("UNBOUNDED — honest gap", "n/a — not PHI", "keep-forever by design")


def _inventory_rows() -> list[list[str]]:
    """The §2 at-rest inventory as cell lists — located structurally, asserted unique."""
    lines = _PHI_MD.read_text(encoding="utf-8").splitlines()
    headers = [i for i, line in enumerate(lines) if line.startswith("| Location | Backends |")]
    assert len(headers) == 1, (
        f"expected exactly ONE §2 inventory header in docs/PHI.md, found {len(headers)} at lines "
        f"{[i + 1 for i in headers]}. Zero means the table was renamed and this guard is asserting "
        f"nothing; more than one means the scan would silently merge two tables."
    )
    start = headers[0]
    ncols = lines[start].count("|") - 1

    rows: list[list[str]] = []
    i = start + 2  # skip the header and its separator
    while i < len(lines) and lines[i].lstrip().startswith("|"):
        line = lines[i]
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        assert len(cells) == ncols, (
            f"docs/PHI.md:{i + 1} has {len(cells)} cells, header has {ncols}. Do NOT 'fix' this by "
            f"skipping mismatched rows — that disarms this check and lets a mangled table pass.\n"
            f"  {line[:120]}"
        )
        rows.append(cells)
        i += 1

    # Floor + liveness receipt. A parser that silently matched nothing would make every assertion
    # below pass vacuously, which is the exact failure mode this whole change set exists to remove.
    assert len(rows) >= 35, (
        f"only {len(rows)} inventory rows parsed from docs/PHI.md §2 (expected ~38). The table shape "
        f"changed or the scan is broken — either way the equality assertions below are worthless."
    )
    return rows


def _documented_settings() -> set[str]:
    """Every `[section].setting` named in the Retention column."""
    rows = _inventory_rows()
    documented: set[str] = set()
    for row in rows:
        cell = row[-1]  # Retention is the last column
        found = _SETTING.findall(cell)
        if found:
            documented.update(found)
            continue
        assert any(form in cell for form in _PROSE_FORMS), (
            f"unrecognised Retention cell {cell!r}. Every cell must be one of the eight vocabulary "
            f"forms — a bounded form naming a backticked `[section].setting`, or one of {_PROSE_FORMS}. "
            f"An unparsed cell would otherwise read as 'no window' and silently drop a PHI tier out of "
            f"the generated gate list."
        )
    return documented


def test_the_constant_and_the_doc_describe_the_same_windows() -> None:
    """Two-way equality. This is the control that makes the constant *derived*.

    Mutation: delete any entry from `PHI_RETENTION_WINDOWS` — reds on the doc-not-code side. Change a
    §2 cell to name a window that does not exist — reds on the code-not-doc side.
    """
    documented = _documented_settings()
    declared = {w.setting for w in PHI_RETENTION_WINDOWS}

    doc_not_code = documented - declared
    code_not_doc = declared - documented
    assert not doc_not_code, (
        f"docs/PHI.md §2 classifies these windows but PHI_RETENTION_WINDOWS does not carry them: "
        f"{sorted(doc_not_code)}. The serve gate is generated from the constant, so a tier documented "
        f"only in the doc is NOT checked at startup."
    )
    assert not code_not_doc, (
        f"PHI_RETENTION_WINDOWS carries these but docs/PHI.md §2 does not classify them: "
        f"{sorted(code_not_doc)}. Either the doc lost a row or the constant invented coverage."
    )


#: `[section]` -> the settings model that owns it. The classification spans FIVE sections, not just
#: `[retention]`, so a check against one model would have to exempt the rest — and an exemption list is
#: how a field name silently stops being verified.
_SECTION_MODELS = {
    "[retention]": RetentionSettings,
    "[store]": StoreSettings,
    "[backup]": BackupSettings,
    "[security]": SecuritySettings,
    "[logging]": LoggingSettings,
}


def test_every_declared_field_exists_on_its_own_settings_model() -> None:
    """Each window's `field` must exist on the model for ITS section — no exemptions.

    The first version of this test checked every window against `RetentionSettings` and exempted
    `[store]`/`[security]` by prefix. Adding `[backup].retention_keep` reded it, and the tempting fix
    was to widen the exemption — which would have stopped verifying three of the five sections. Routing
    each window to its own model instead makes the check STRONGER than before it failed.

    Mutation: rename any `field` — reds here, at import time, rather than in a serve path CI never runs.
    """
    unknown_section = [
        w.setting for w in PHI_RETENTION_WINDOWS if w.reads_from not in _SECTION_MODELS
    ]
    assert not unknown_section, (
        f"windows in a section with no model mapping: {unknown_section} — add it to _SECTION_MODELS "
        f"rather than exempting it, or the field name stops being checked"
    )
    missing = [
        f"{w.setting} -> {_SECTION_MODELS[w.reads_from].__name__}.{w.field}"
        for w in PHI_RETENTION_WINDOWS
        if w.field not in _SECTION_MODELS[w.reads_from].model_fields
    ]
    assert not missing, f"windows naming a field their own settings model does not have: {missing}"


def test_every_requires_setting_resolves() -> None:
    """A `requires_setting` naming a field that does not exist would make the gate skip forever.

    This is the `requires_setting` trap in its quiet form: the gate skips a window whose dependency is
    unmet, so a MISSPELLED dependency is indistinguishable from an unmet one — the window is simply
    never checked, and nothing reds. Resolve every pair against the real models.
    """
    models = {"logging": LoggingSettings, "backup": BackupSettings, "store": StoreSettings}
    for w in PHI_RETENTION_WINDOWS:
        if w.requires_setting is None:
            continue
        section, field = w.requires_setting
        assert section in models, f"{w.setting}: requires_setting names unknown section {section!r}"
        assert field in models[section].model_fields, (
            f"{w.setting}: requires_setting ({section}, {field}) does not resolve — the gate would "
            f"skip this window forever and report success"
        )


def test_the_floor_is_seven_not_six_and_is_enforced() -> None:
    """`if not TUPLE` is not a floor — a merge dropping five of seven leaves a non-empty tuple.

    Seven because `reference_snapshot_days` made the classification-derived list seven entries; any
    floor written as six was wrong the day the reference purge landed.

    Mutation: set MIN to 6 — reds, because the real length is checked against it AND against the
    documented reason for the value.
    """
    assert MIN_PHI_RETENTION_WINDOWS == 9, (
        "the floor changed. It is 9 — and that number was CORRECTED BY THIS TEST rather than counted: "
        "it was first written as 7, and the two-way equality above immediately reported "
        "[backup].retention_keep and [retention].connection_event_retention_hours as "
        "documented-but-absent. If the classification genuinely grew or shrank, update this assertion "
        "and say why in the same commit."
    )
    assert len(PHI_RETENTION_WINDOWS) >= MIN_PHI_RETENTION_WINDOWS, (
        f"PHI_RETENTION_WINDOWS has {len(PHI_RETENTION_WINDOWS)} entries, floor is "
        f"{MIN_PHI_RETENTION_WINDOWS} — a startup gate built from this would check fewer windows than "
        f"the classification defines while still reporting success."
    )


def test_the_auto_bound_and_warn_only_split_matches_the_owner_ruling() -> None:
    """The owner ruled which windows silently default and which only warn (2026-07-30).

    Auto-bounding a window whose timestamp moves only on a WRITE deletes live operational data —
    `state.set_at` is never refreshed by `state_get`, so a long-lived correlation map would vanish
    mid-stream. This asserts the split rather than trusting a comment.

    Mutation: give `state_max_age_days` an `auto_bound_days=30` — reds.
    """
    auto = {w.setting for w in auto_bounded_windows()}
    warn = {w.setting for w in warn_only_windows()}
    assert auto == {
        "[security].delete_message_bodies_after_days",
        "[retention].dead_letter_days",
        "[retention].reference_snapshot_days",
    }, f"auto-bound set drifted from the owner ruling: {sorted(auto)}"
    assert "[retention].state_max_age_days" in warn, (
        "state_max_age_days must NOT auto-bound — purge_state deletes by `set_at`, which a read never "
        "refreshes, so a Handler's correlation map would be deleted while still in use"
    )
    assert "[retention].search_preset_days" in warn, (
        "search_preset_days must NOT auto-bound — pipeline/retention.py forbids exactly that "
        "inheritance in prose, and no test anchors that comment"
    )
    assert not (auto & warn), "a window cannot be both auto-bound and warn-only"


@pytest.mark.parametrize("form", _PROSE_FORMS)
def test_each_prose_form_is_actually_used(form: str) -> None:
    """The vocabulary must not contain dead forms.

    A form nothing uses is either a classification nobody applied or a leftover — both mean the legend
    describes a scheme the table does not follow. `UNBOUNDED — honest gap` in particular MUST appear:
    this codebase has unbounded PHI tiers, and a classification with none is flattering, not complete.
    """
    cells = [row[-1] for row in _inventory_rows()]
    assert any(form in cell for cell in cells), (
        f"the vocabulary form {form!r} appears in no §2 Retention cell. If a classification genuinely "
        f"no longer applies, remove it from the legend in the same commit."
    )
