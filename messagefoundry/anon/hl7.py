# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Engine-side HL7 anonymization adapter (ADR 0030 §1/§3) — the **non-parity seam**.

Drives the rule map over a message using the engine's battle-tested mutable model
(:class:`messagefoundry.parsing.message.Message`). The standalone ``tee/anon/hl7.py`` does the *same
thing* through a pure stdlib splitter (it cannot import ``messagefoundry``); the two share the
``normalized_message`` / ``read_message_seps`` / ``scrub_message_site_codes`` / ``preserve_obx5_value``
helpers and a single **fail-closed contract**. The golden-corpus + adversarial parity tests pin the
two equal on the inputs they hold; the two do NOT agree on every input, and ``docs/PHI.md`` section 9
names at least the cases known to differ. The contract:

* normalize first (strip MLLP framing, drop empty segments, ``\\r`` line endings);
* a message with **no parseable MSH / encoding characters** is **refused** — :class:`AnonError`, a
  body-free error — never emitted un-anonymized (ADR 0030 §3 / CLAUDE.md §8: parse defensively, fail
  closed); and
* any malformed-structure error from the parser is caught and re-raised as a body-free
  :class:`AnonError` rather than crashing the caller or leaking the body in a traceback; and
* OBX-5 is preserved only against an **allowlist** of value types (``preserve_obx5_value``) — an
  unrecognized, absent or empty OBX-2 means the value is redacted, never passed through. A value
  under a date type keeps its year only (``obx5_kind``).

Never string-slices raw HL7: surrogation goes through ``Message.set``'s whole-field write, and the
site-code pass splits only on the message's actual separators.
"""

from __future__ import annotations

from messagefoundry.parsing.message import Message

from .keying import Keyer
from .rules import AnonError, FieldRule, SurrogateKind
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


#: The lowest field number a rule may rewrite: 1 in any segment, because field 0 is the segment
#: id, and 3 in MSH, because MSH-1 and MSH-2 hold the message's own delimiters. With either of
#: those rewritten the output has no readable header, and the leak-check has no separators to
#: walk it with.
_FIRST_REWRITABLE_FIELD = 1
_FIRST_REWRITABLE_MSH_FIELD = 3


def _refuse_unwritable_rules(rules: tuple[FieldRule, ...]) -> None:
    """Refuse a rule set that would rewrite a segment id, MSH-1 or MSH-2 (a body-free
    :class:`AnonError`).

    The field number is read with ``int()``, the way the adapters read it, so ``MSH-02`` and a
    path with a stray space or newline are refused like ``MSH-2``. A path whose number ``int()``
    cannot read is not a whole-field address, and it is not this check's to refuse.
    ``FieldRule`` refuses every path that is not a whole-field address when the rule is built,
    field 0 and ``MSH-02`` included (BACKLOG #2330). So for those spellings this check is a
    second line, and for ``MSH-1`` and ``MSH-2`` it is the only one. A ``KEEP`` rewrites
    nothing, so it is allowed. The same check runs in both adapters (BACKLOG #2265)."""
    named: set[str] = set()
    for rule in rules:
        if rule.kind == SurrogateKind.KEEP:
            continue
        segment, _, number = rule.path.partition("-")
        try:
            field = int(number)
        except ValueError:
            continue
        is_msh = segment.upper() == "MSH"
        if field < (_FIRST_REWRITABLE_MSH_FIELD if is_msh else _FIRST_REWRITABLE_FIELD):
            named.add(f"{segment}-{field}")
    if named:
        raise AnonError(
            f"a rule names {', '.join(sorted(named))}, which no rule can rewrite: field 0 is the "
            "segment id, and MSH-1 and MSH-2 hold the message's delimiters. Repair or remove a "
            "later MSH line that carries data there. Refusing to emit"
        )


def anonymize_message(
    raw: str, keyer: Keyer, rules: tuple[FieldRule, ...], blanked: list[str] | None = None
) -> str:
    """De-identify one HL7 v2 message: apply ``rules`` field-by-field, then the site-code pass.

    Pure + deterministic for a given ``keyer`` (same message + salt → same fixture). Raises
    :class:`AnonError` (carrying no body) when the message cannot be safely anonymized — fail closed.

    ``blanked``, when given, collects the address of every field the ``DATE`` kind scrubbed to empty
    (``surrogate_field_recorded``). It is the caller's list; nothing else is written to it.
    """
    _refuse_unwritable_rules(rules)
    text = normalized_message(raw, tuple(rule.path for rule in rules))
    parsed = read_message_seps(text)
    if parsed is None:
        raise AnonError("message has no parseable MSH / encoding characters — refusing to emit")
    seps, _field_sep = parsed
    try:
        msg = Message.parse(text)
        for rule in rules:
            seg_id = _segment_id(rule.path)
            for occ in range(1, msg.count_segments(seg_id) + 1):
                value = msg.field(rule.path, occurrence=occ)
                if value is None:  # field absent/empty — nothing to surrogate
                    continue
                if _skip_obx5(rule, msg, occ, value, seps):
                    continue
                kind = _kind_for(rule, msg, occ)
                scrubbed = surrogate_field_recorded(rule.path, kind, value, keyer, seps, blanked)
                msg.set(rule.path, scrubbed, occurrence=occ)
        encoded = msg.encode()
    except AnonError:
        raise  # already a body-free refusal with its own reason; do not relabel it "malformed"
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        # Convert any malformed-structure error into a body-free refusal — never crash the caller or
        # let a traceback carry the message. ValueError includes HL7PeekError, which Message.parse
        # raises for a body with no leading MSH and for a parser fault.
        raise AnonError("could not anonymize HL7 message (malformed structure)") from exc
    return scrub_message_site_codes(encoded, keyer, rules)


def _skip_obx5(rule: FieldRule, msg: Message, occurrence: int, value: str, seps: Seps) -> bool:
    """True if this is the OBX-5 free-text rule and the shared allowlist says THIS OBX's ``value`` may
    be preserved — see :func:`preserve_obx5_value`, which is where the decision lives."""
    if rule.path != "OBX-5" or rule.kind != SurrogateKind.FREETEXT:
        return False
    return preserve_obx5_value(msg.field("OBX-2", occurrence=occurrence), value, seps)


def _kind_for(rule: FieldRule, msg: Message, occurrence: int) -> SurrogateKind:
    """The kind to apply: the rule's own, except that the OBX-5 free-text rule hands a date-typed
    value to the ``DATE`` kind -- see :func:`obx5_kind`, which is where that decision lives."""
    if rule.path != "OBX-5" or rule.kind != SurrogateKind.FREETEXT:
        return rule.kind
    return obx5_kind(msg.field("OBX-2", occurrence=occurrence))
