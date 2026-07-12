# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Transform steps for the ``IB_DEMO_ORU`` feed — the *transformer* half of the per-feed **Hybrid**
config layout (see docs/CONNECTIONS.md §"Decomposing by role").

This is a ``_``-prefixed **helper** module: the loader skips ``_*`` files as feeds but resolves them
as sibling imports (``config/wiring.py`` ``_SiblingHelperFinder``), so ``IB_DEMO_ORU_handler.py`` does
``from _demo_oru_transforms import apply_demo_oru_transforms``. Keeping the field-level steps out of the
Handler is the whole point of the split — a ported Corepoint child's many manipulations live here as
small, reviewable, unit-testable functions while the Handler stays a thin *filter → delegate → Send*.

The steps are **pure** (message in → message mutated in place → no external side effects, ADR 0001),
and each reads the ORIGINAL value it needs BEFORE any step overwrites that location
(snapshot-before-mutate) — the flat ``Message`` API has no separate ``%in``/``%out`` view, so a later
write would otherwise clobber a read source.
"""

from __future__ import annotations

from messagefoundry import Message, code_set


def apply_demo_oru_transforms(msg: Message) -> None:
    """Apply the feed's transform steps in order, mutating ``msg`` in place."""
    # Snapshot every %in value a later step overwrites, up front.
    orig_patient_class = msg["PV1-2"] or ""
    _stamp_sending_facility(msg)
    _tag_mrn_identifier(msg)
    _carry_then_clear_visit(msg, orig_patient_class)


def _stamp_sending_facility(msg: Message) -> None:
    # Translate MSH-4 (Sending Facility) through a managed mnemonic table
    # (codesets/facility_mnemonics.toml). On a miss the table returns None and we leave the original
    # value — the Corepoint translation-table "pass through unmapped" default. Looked up at call time
    # so `POST /config/reload` picks up an edited table without a code change.
    mnemonic = code_set("facility_mnemonics").get(msg["MSH-4"] or "")
    if mnemonic is not None:
        msg["MSH-4"] = mnemonic


def _tag_mrn_identifier(msg: Message) -> None:
    # Stamp the PID-3 identifier-type code as MRN (first PID-3 repetition, component 5).
    msg["PID-3.5"] = "MR"


def _carry_then_clear_visit(msg: Message, orig_patient_class: str) -> None:
    # Preserve the ORIGINAL Patient Class into PV1-18 (Patient Type), then blank PV1-19 (Visit Number).
    msg["PV1-18"] = orig_patient_class
    msg["PV1-19"] = ""
