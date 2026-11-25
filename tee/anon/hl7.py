# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tee-side HL7 anonymization adapter (ADR 0030 §1) — the standalone **non-parity seam**.

Does the *same thing* as ``messagefoundry_toolkit/anon/hl7.py`` but through a tiny pure-stdlib splitter, so
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
(read from MSH) and replaces whole fields. Joined back, a field value holding the field
separator would add fields and renumber every later field for any reader of the output. What a
surrogate writes itself, such as the date fill's ``+``, the free-text redaction's ``[`` and ``]``
and a street's space, is judged first, against the field separator and the MSH-2 delimiters, the
same on both adapters, in the shared ``surrogates.surrogate_field_recorded`` (BACKLOG #5540).
:func:`_whole_field` then checks the whole field a rule wrote, sender text it kept included, for
the field separator, CR, LF, an MLLP frame byte or NUL, which the engine adapter's whole-field
``Message.set`` refuses too. CR, LF and the frame bytes never reach a field:
``normalized_message`` turns CR and LF into segment breaks and strips the frame bytes, so of the
five only NUL can reach :func:`_whole_field`. Under a rule other than a ``keep``,
``surrogate_field_recorded`` refuses an undeclared C0 byte in what the surrogate wrote first
(BACKLOG #5533 item 14), so there a NUL reaches :func:`_whole_field` only when the message
declares it. A ``keep`` rule passed straight to this adapter skips that shared C0 refusal, and
the kept value is written back, so an undeclared NUL in it reaches :func:`_whole_field`, which
refuses it. The shared site-code pass that runs after the rules writes no digit the message
declares as a separator.
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
    SurrogateSeparatorRefused,
    normalized_message,
    obx5_kind,
    preserve_obx5_value,
    read_message_seps,
    repeats_encoding_characters,
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

    Pure + deterministic for a given ``keyer``. Raises :class:`AnonError` (carrying no body) when it
    cannot safely anonymize the message — fail closed, matching the engine adapter. The causes
    include at least a message with no parseable MSH / encoding characters, a surrogate that
    would hold the field separator (see :func:`_whole_field`), and one that would hold a declared
    delimiter in a value it wrote itself (``surrogates._written``).

    ``blanked``, when given, collects the address of every field the ``DATE`` kind scrubbed to empty
    (``surrogate_field_recorded``), as the engine adapter does. Those addresses are added only once
    the message has been written, so a refused message adds none (BACKLOG #5540).
    """
    _refuse_unwritable_rules(rules)
    # A keep rewrites nothing, so it never makes a line reachable (BACKLOG #3001).
    text = normalized_message(
        raw, tuple(rule.path for rule in rules if rule.kind != SurrogateKind.KEEP)
    )
    parsed = read_message_seps(text)
    if parsed is None:
        if repeats_encoding_characters(text):
            raise AnonError("message MSH-2 repeats an encoding character — refusing to emit")
        raise AnonError("message has no parseable MSH / encoding characters — refusing to emit")
    seps, field_sep = parsed
    # None when the caller asked for no record, so the date check is not run for nothing.
    found: list[str] | None = [] if blanked is not None else None
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
                value = surrogate_field_recorded(
                    rule.path, _kind_for(rule, fields), fields[index], keyer, seps, found
                )
                fields[index] = _whole_field(rule.path, value, field_sep)
    encoded = "\r".join(field_sep.join(fields) for fields in segments)
    output = scrub_message_site_codes(encoded, keyer, rules)
    if blanked is not None and found:
        blanked.extend(found)
    return output


#: Beside the field separator, what the engine's whole-field ``Message.set`` refuses: CR, LF, then
#: its ``_STRUCTURE_REFUSED``, which the tee cannot import. A test pins the two refusing alike.
_REFUSED_IN_FIELD = ("\r", "\n", "\x0b", "\x1c", "\x00")


def _whole_field(path: str, value: str, field_sep: str) -> str:
    """``value``, unless it holds the field separator or a character in ``_REFUSED_IN_FIELD``; then a
    body-free :class:`SurrogateSeparatorRefused` naming the rule and the cause, never the value."""
    if field_sep in value:
        cause = "the message's field separator (MSH-1)"
    elif any(char in value for char in _REFUSED_IN_FIELD):
        cause = "a segment separator, an MLLP frame byte or NUL"
    else:
        return value
    raise SurrogateSeparatorRefused(path, cause)


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
