# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tee-side HL7 anonymization adapter (ADR 0030 §1) — the standalone **non-parity seam**.

Does the *same thing* as ``messagefoundry/anon/hl7.py`` but through a tiny pure-stdlib splitter, so
the tee needs no ``python-hl7`` / ``messagefoundry`` import (the write-side companion to the existing
read-only ``tee/hl7_fields.py``). It shares the ``normalized_message`` / ``read_message_seps`` /
``scrub_message_site_codes`` / ``preserve_obx5_value`` helpers and the **same fail-closed contract** as
the engine adapter: a message with no parseable MSH / encoding characters is **refused**
(:class:`AnonError`, body-free) — never passed through un-anonymized, and an OBX-5 is preserved only
against the shared **allowlist** of value types, so an unrecognized or absent OBX-2 is redacted. The
golden-corpus + adversarial parity tests pin the two to the same output / same refusal on the
inputs they hold. The two do NOT agree on every input: ``docs/PHI.md`` section 9 names at least the
cases known to differ (a header not in capitals among them). A ``BHS`` or ``FHS`` rule now reaches
the same field on both sides, and both refuse a short later header line (BACKLOG #2998).

Never string-slices in the forbidden sense: it splits only on the message's *actual* field separator
(read from MSH) and replaces whole fields — surrogate values never contain a field separator.
"""

from __future__ import annotations

from .keying import Keyer
from .rules import (
    HEADER_SEGMENTS,
    AnonError,
    FieldRule,
    SurrogateKind,
    _refuse_unwritable_rules,
)
from .surrogates import (
    Seps,
    normalized_message,
    obx5_kind,
    preserve_obx5_value,
    read_message_seps,
    scrub_message_site_codes,
    surrogate_field_recorded,
)


def _segment_id(path: str) -> str:
    return path.split("-", 1)[0]


def _field_num(path: str) -> int:
    return int(path.split("-", 1)[1])


def anonymize_message(
    raw: str, keyer: Keyer, rules: tuple[FieldRule, ...], blanked: list[str] | None = None
) -> str:
    """De-identify one HL7 v2 message: apply ``rules`` field-by-field, then the site-code pass.

    Pure + deterministic for a given ``keyer``. Raises :class:`AnonError` (carrying no body) when the
    message has no parseable MSH / encoding characters — fail closed, matching the engine adapter.

    ``blanked``, when given, collects the address of every field the ``DATE`` kind scrubbed to empty
    (``surrogate_field_recorded``), as the engine adapter does.
    """
    _refuse_unwritable_rules(rules)
    text = normalized_message(raw, tuple(rule.path for rule in rules))
    parsed = read_message_seps(text)
    if parsed is None:
        raise AnonError("message has no parseable MSH / encoding characters — refusing to emit")
    seps, field_sep = parsed
    segments = [seg.split(field_sep) for seg in text.split("\r")]
    # The header may be spelled ``Msh``: the separators are read from it in any case and the
    # leak-check skips it in any case, so an MSH rule must reach it in any case too. Only the
    # header: a later line not in capitals is not an MSH line to the engine or to the leak-check.
    header = next((fields for fields in segments if fields[0].upper() == "MSH"), None)
    for rule in rules:
        seg_id = _segment_id(rule.path)
        # An MSH rule applies to EVERY MSH line, as on the engine side: the leak-check counts an
        # MSH-N rule's field as scrubbed, so it must be (BACKLOG #2265). Field 1 of a header
        # segment (MSH, BHS, FHS) is the field separator itself, so its field N sits one split
        # index lower than any other segment's field N. The engine's parser and the leak-check
        # number all three that way (BACKLOG #2998).
        is_msh = seg_id == "MSH"
        index = _field_num(rule.path) - (1 if seg_id in HEADER_SEGMENTS else 0)
        for fields in segments:
            if fields[0] != seg_id and not (is_msh and fields is header):
                continue
            if _skip_obx5(rule, fields, seps):
                continue
            if index < len(fields):
                fields[index] = surrogate_field_recorded(
                    rule.path, _kind_for(rule, fields), fields[index], keyer, seps, blanked
                )
    encoded = "\r".join(field_sep.join(fields) for fields in segments)
    return scrub_message_site_codes(encoded, keyer, rules)


def _skip_obx5(rule: FieldRule, fields: list[str], seps: Seps) -> bool:
    """True if this is the OBX-5 free-text rule and the shared allowlist says THIS OBX's value may be
    preserved — see :func:`preserve_obx5_value`. Only the way the two adapters reach OBX-2/OBX-5
    differs; the decision itself is shared."""
    if rule.path != "OBX-5" or rule.kind != SurrogateKind.FREETEXT:
        return False
    return preserve_obx5_value(
        fields[2] if len(fields) > 2 else None,
        fields[5] if len(fields) > 5 else None,
        seps,
    )


def _kind_for(rule: FieldRule, fields: list[str]) -> SurrogateKind:
    """The kind to apply: the rule's own, except that the OBX-5 free-text rule hands a date-typed
    value to the ``DATE`` kind -- see :func:`obx5_kind`, which is where that decision lives."""
    if rule.path != "OBX-5" or rule.kind != SurrogateKind.FREETEXT:
        return rule.kind
    return obx5_kind(fields[2] if len(fields) > 2 else None)
