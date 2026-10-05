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
golden-corpus + adversarial parity tests pin the two to the same output / same refusal.

Never string-slices in the forbidden sense: it splits only on the message's *actual* field separator
(read from MSH) and replaces whole fields — surrogate values never contain a field separator.
"""

from __future__ import annotations

from .keying import Keyer
from .rules import AnonError, FieldRule, SurrogateKind
from .surrogates import (
    Seps,
    normalized_message,
    preserve_obx5_value,
    read_message_seps,
    scrub_message_site_codes,
    surrogate_field,
)


def _segment_id(path: str) -> str:
    return path.split("-", 1)[0]


#: The first MSH field a rule may rewrite. MSH-1 and MSH-2 hold the message's own delimiters: with
#: either rewritten the output has no readable header, and the leak-check has no separators to walk
#: it with. MSH-0 is not a field at all.
_FIRST_REWRITABLE_MSH_FIELD = 3


def _refuse_delimiter_rules(rules: tuple[FieldRule, ...]) -> None:
    """Refuse a rule set that would rewrite MSH-0, MSH-1 or MSH-2 (a body-free :class:`AnonError`).

    The field NUMBER is compared, not the path text, so ``MSH-02`` is refused like ``MSH-2``. A
    ``KEEP`` rewrites nothing, so it is allowed. A path that is not a whole-field address, which
    ``load_rules`` refuses, is not this check's business and is left to the adapter as before.
    The same check runs in both adapters (BACKLOG #2265)."""
    rewrites = (r.path.partition("-") for r in rules if r.kind != SurrogateKind.KEEP)
    named = sorted(
        {
            int(number)
            for segment, _, number in rewrites
            if segment == "MSH" and number.isdecimal() and int(number) < _FIRST_REWRITABLE_MSH_FIELD
        }
    )
    if named:
        raise AnonError(
            f"a rule names {' and '.join(f'MSH-{n}' for n in named)}, which a rule cannot rewrite: "
            "MSH-1 and MSH-2 hold the message's delimiters; refusing to emit"
        )


def _field_num(path: str) -> int:
    return int(path.split("-", 1)[1])


def anonymize_message(raw: str, keyer: Keyer, rules: tuple[FieldRule, ...]) -> str:
    """De-identify one HL7 v2 message: apply ``rules`` field-by-field, then the site-code pass.

    Pure + deterministic for a given ``keyer``. Raises :class:`AnonError` (carrying no body) when the
    message has no parseable MSH / encoding characters — fail closed, matching the engine adapter.
    """
    _refuse_delimiter_rules(rules)
    text = normalized_message(raw)
    parsed = read_message_seps(text)
    if parsed is None:
        raise AnonError("message has no parseable MSH / encoding characters — refusing to emit")
    seps, field_sep = parsed
    segments = [seg.split(field_sep) for seg in text.split("\r")]
    for rule in rules:
        seg_id = _segment_id(rule.path)
        # An MSH rule applies to EVERY MSH line, as on the engine side: the leak-check counts an
        # MSH-N rule's field as scrubbed, so it must be (BACKLOG #2265). MSH-1 is the field
        # separator itself, so MSH-N sits one split index lower than any other segment's field N.
        is_msh = seg_id == "MSH"
        index = _field_num(rule.path) - (1 if is_msh else 0)
        for fields in segments:
            # The header may be spelled ``Msh``: the separators are read from it in any case, and
            # the leak-check skips it in any case, so an MSH rule must reach it in any case too.
            if (fields[0].upper() if is_msh else fields[0]) != seg_id:
                continue
            if _skip_obx5(rule, fields, seps):
                continue
            if index < len(fields):
                fields[index] = surrogate_field(rule.kind, fields[index], keyer, seps)
    encoded = "\r".join(field_sep.join(fields) for fields in segments)
    return scrub_message_site_codes(encoded, keyer)


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
