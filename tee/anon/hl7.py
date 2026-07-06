# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tee-side HL7 anonymization adapter (ADR 0030 §1) — the standalone **non-parity seam**.

Does the *same thing* as ``messagefoundry/anon/hl7.py`` but through a tiny pure-stdlib splitter, so
the tee needs no ``python-hl7`` / ``messagefoundry`` import (the write-side companion to the existing
read-only ``tee/hl7_fields.py``). It shares the ``normalized_message`` / ``read_message_seps`` /
``scrub_message_site_codes`` helpers and the **same fail-closed contract** as the engine adapter: a
message with no parseable MSH / encoding characters is **refused** (:class:`AnonError`, body-free) —
never passed through un-anonymized. The golden-corpus + adversarial parity tests pin the two to the
same output / same refusal.

Never string-slices in the forbidden sense: it splits only on the message's *actual* field separator
(read from MSH) and replaces whole fields — surrogate values never contain a field separator.
"""

from __future__ import annotations

from .keying import Keyer
from .rules import AnonError, FieldRule, SurrogateKind
from .surrogates import (
    normalized_message,
    read_message_seps,
    scrub_message_site_codes,
    surrogate_field,
)

#: OBX-5 is free text only when OBX-2 names a textual value type (see the engine adapter).
_TEXTUAL_OBX_TYPES = frozenset({"TX", "FT", "ST", "CF"})


def _segment_id(path: str) -> str:
    return path.split("-", 1)[0]


def _field_num(path: str) -> int:
    return int(path.split("-", 1)[1])


def anonymize_message(raw: str, keyer: Keyer, rules: tuple[FieldRule, ...]) -> str:
    """De-identify one HL7 v2 message: apply ``rules`` field-by-field, then the site-code pass.

    Pure + deterministic for a given ``keyer``. Raises :class:`AnonError` (carrying no body) when the
    message has no parseable MSH / encoding characters — fail closed, matching the engine adapter.
    """
    text = normalized_message(raw)
    parsed = read_message_seps(text)
    if parsed is None:
        raise AnonError("message has no parseable MSH / encoding characters — refusing to emit")
    seps, field_sep = parsed
    segments = [seg.split(field_sep) for seg in text.split("\r")]
    for rule in rules:
        seg_id = _segment_id(rule.path)
        fnum = _field_num(rule.path)
        for fields in segments:
            if not fields or fields[0] != seg_id or seg_id == "MSH":
                continue  # rules never target MSH (its field numbering is offset by MSH-1)
            if _skip_obx5(rule, fields):
                continue
            if fnum < len(fields):
                fields[fnum] = surrogate_field(rule.kind, fields[fnum], keyer, seps)
    encoded = "\r".join(field_sep.join(fields) for fields in segments)
    return scrub_message_site_codes(encoded, keyer)


def _skip_obx5(rule: FieldRule, fields: list[str]) -> bool:
    """True if this is the OBX-5 free-text rule but THIS OBX's value type (OBX-2) is non-textual."""
    if rule.path != "OBX-5" or rule.kind is not SurrogateKind.FREETEXT:
        return False
    value_type = (fields[2] if len(fields) > 2 else "").upper()
    return value_type not in _TEXTUAL_OBX_TYPES
