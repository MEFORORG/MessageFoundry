# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Engine-side HL7 anonymization adapter (ADR 0030 §1/§3) — the **non-parity seam**.

Drives the rule map over a message using the engine's battle-tested mutable model
(:class:`messagefoundry.parsing.message.Message`). The standalone ``tee/anon/hl7.py`` does the *same
thing* through a pure stdlib splitter (it cannot import ``messagefoundry``); the two share the
``normalized_message`` / ``read_message_seps`` / ``scrub_message_site_codes`` / ``preserve_obx5_value``
helpers and a single **fail-closed contract** so they agree on every input (the golden-corpus +
adversarial parity tests pin them):

* normalize first (strip MLLP framing, drop empty segments, ``\\r`` line endings);
* a message with **no parseable MSH / encoding characters** is **refused** — :class:`AnonError`, a
  body-free error — never emitted un-anonymized (ADR 0030 §3 / CLAUDE.md §8: parse defensively, fail
  closed); and
* any malformed-structure error from python-hl7 is caught and re-raised as a body-free
  :class:`AnonError` rather than crashing the caller or leaking the body in a traceback; and
* OBX-5 is preserved only against an **allowlist** of value types (``preserve_obx5_value``) — an
  unrecognized, absent or empty OBX-2 means the value is redacted, never passed through.

Never string-slices raw HL7: surrogation goes through ``Message.set``'s whole-field write, and the
site-code pass splits only on the message's actual separators.
"""

from __future__ import annotations

from hl7.exceptions import HL7Exception

from messagefoundry.parsing.message import Message

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


def anonymize_message(raw: str, keyer: Keyer, rules: tuple[FieldRule, ...]) -> str:
    """De-identify one HL7 v2 message: apply ``rules`` field-by-field, then the site-code pass.

    Pure + deterministic for a given ``keyer`` (same message + salt → same fixture). Raises
    :class:`AnonError` (carrying no body) when the message cannot be safely anonymized — fail closed.
    """
    text = normalized_message(raw)
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
                msg.set(rule.path, surrogate_field(rule.kind, value, keyer, seps), occurrence=occ)
        encoded = msg.encode()
    except (HL7Exception, ValueError, KeyError, IndexError, TypeError) as exc:
        # Convert any malformed-structure error into a body-free refusal — never crash the caller or
        # let a traceback carry the message. (AnonError, a ValueError, would be re-wrapped harmlessly.)
        raise AnonError("could not anonymize HL7 message (malformed structure)") from exc
    return scrub_message_site_codes(encoded, keyer)


def _skip_obx5(rule: FieldRule, msg: Message, occurrence: int, value: str, seps: Seps) -> bool:
    """True if this is the OBX-5 free-text rule and the shared allowlist says THIS OBX's ``value`` may
    be preserved — see :func:`preserve_obx5_value`, which is where the decision lives."""
    if rule.path != "OBX-5" or rule.kind is not SurrogateKind.FREETEXT:
        return False
    return preserve_obx5_value(msg.field("OBX-2", occurrence=occurrence), value, seps)
