# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Hybrid correlation for the tee parity comparison (#14, decision D2).

Matches a MEFOR transformed output to the Corepoint output produced from the **same input message**, so
:mod:`tee.compare` can diff equivalent pairs. Pure and dependency-free (HL7 structure via
:mod:`tee.hl7_fields`); no I/O, no ``messagefoundry`` import.

Strategy (D2):
  1. **Primary — source MSH-10.** When the Corepoint copy preserves the source control id, match it to
     MEFOR's source control id (``messages.control_id`` from the engine API).
  2. **Fallback — content key.** When the control id was rewritten, match on a tolerant content key:
     patient id(s) (PID-3) + message type (MSH-9) + MSH-7 truncated to **whole seconds** (a tolerant
     matcher, not an equality key).
  3. **Fan-out + ambiguity.** One input can produce several outputs; destination — ``(MSH-5, MSH-6)``
     of the output — corroborates the match key. A key shared by a fan-out (or matched by several
     candidates) is **ambiguous**: it is claimed only when destination uniquely aligns, or when the key
     is an unambiguous 1:1 (single MEFOR output, single candidate — then a relabelled/blank destination
     is tolerated). When neither holds the output is **left unmatched** rather than guessed by input
     order — a conservative bias, so the tool never manufactures a false mismatch out of two
     genuinely-different (or differently-routed) outputs.
  4. **A40 patient merge (1->N).** An ``ADT^A40`` references two MRNs (PID-3 survivor + MRG-1 prior);
     the content key uses the **unordered union** of both so a merge output correlates regardless of
     which MRN each engine placed in PID-3 (the cross-MRN hazard). A control-id match whose patient
     ids positively disagree (disjoint, both present) is rejected — a recycled/colliding MSH-10 across
     distinct patients does not pair.

Unmatched outputs on either side are returned as ``method="unmatched"`` pairs (missing-on-a-side). The
verdict structure is PHI-safe; ``MeforOutput.payload`` / ``CorepointOutput.raw`` carry message bodies
(PHI), so callers gate any rendering of them (test-data-only).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field

from tee.hl7_fields import (
    Segment,
    Separators,
    parse,
    split_components,
    split_repetitions,
)

# Content-key components: (patient-id set, (message code, trigger event), MSH-7 whole seconds).
ContentKey = tuple[frozenset[str], tuple[str, str], str]


@dataclass(frozen=True)
class MeforOutput:
    """One MEFOR transformed outbound payload (from the engine's ``/messages/{id}/outbound``)."""

    message_id: str  # MEFOR message id — groups one input's fan-out
    source_control_id: str  # source MSH-10 (messages.control_id), the primary match key
    destination_name: str  # MEFOR destination name (for reporting/labelling)
    payload: str  # the transformed HL7 body


@dataclass(frozen=True)
class CorepointOutput:
    """One Corepoint output body captured from the ``corepoint_copy`` feed (tee ``RelayStore``)."""

    control_id: str | None  # MSH-10 of Corepoint's output (may be rewritten or absent)
    raw: str  # Corepoint's output HL7 body


@dataclass(frozen=True)
class CorrelatedPair:
    """One correlation outcome. ``method`` is how it matched (or ``"unmatched"`` for a missing side);
    exactly one of ``mefor``/``corepoint`` is ``None`` for an unmatched pair."""

    method: str  # "control_id" | "content_key" | "unmatched"
    mefor: MeforOutput | None
    corepoint: CorepointOutput | None
    source_control_id: str | None
    destination: tuple[str, str] | None  # (MSH-5, MSH-6) of the output


@dataclass(frozen=True)
class CorrelateConfig:
    """Tunable correlation policy. ``merge_triggers`` are the trigger events whose content key unions
    PID-3 with MRG-1 (default: the A40 patient merge). ``destination_aliases`` canonicalises an
    output's ``(MSH-5, MSH-6)`` destination before matching, so a receiver the two engines label
    differently (a migration reality) still aligns — map each engine-specific label to a shared
    canonical one (applied to both sides)."""

    merge_triggers: frozenset[str] = frozenset({"A40"})
    destination_aliases: Mapping[tuple[str, str], tuple[str, str]] = field(default_factory=dict)


@dataclass(frozen=True)
class _Fingerprint:
    control_id: str
    destination: tuple[str, str]
    content_key: ContentKey


@dataclass(frozen=True)
class _CpItem:
    output: CorepointOutput
    fp: _Fingerprint


def _first(segments: list[Segment], seg_id: str) -> Segment | None:
    for seg in segments:
        if seg.id.upper() == seg_id:
            return seg
    return None


def _whole_seconds(datetime_field: str) -> str:
    """MSH-7 (or any HL7 DTM) truncated to whole seconds: the leading digit run, capped at 14
    (``YYYYMMDDHHMMSS``) — fractional seconds and the timezone offset are dropped."""
    digits: list[str] = []
    for ch in datetime_field:
        if ch.isdigit():
            digits.append(ch)
        else:
            break
    return "".join(digits)[:14]


def _message_type(msh: Segment | None, seps: Separators) -> tuple[str, str]:
    if msh is None:
        return ("", "")
    comps = split_components(msh.field(9), seps)
    return (comps[0] if comps else "", comps[1] if len(comps) > 1 else "")


def _cx_ids(field_value: str, seps: Separators) -> set[str]:
    """The id values of a repeating CX field (PID-3 / MRG-1): the first component of each repetition."""
    ids: set[str] = set()
    if not field_value:
        return ids
    for rep in split_repetitions(field_value, seps):
        comps = split_components(rep, seps)
        if comps and comps[0]:
            ids.add(comps[0])
    return ids


def _patient_ids(
    segments: list[Segment], seps: Separators, trigger: str, cfg: CorrelateConfig
) -> frozenset[str]:
    ids: set[str] = set()
    pid = _first(segments, "PID")
    if pid is not None:
        ids |= _cx_ids(pid.field(3), seps)
    # A patient-merge trigger (A40) spans two MRNs (PID-3 survivor + MRG-1 prior); unioning both makes
    # the content key order-independent across the cross-MRN hazard.
    if trigger in cfg.merge_triggers:
        mrg = _first(segments, "MRG")
        if mrg is not None:
            ids |= _cx_ids(mrg.field(1), seps)
    return frozenset(ids)


def _fingerprint(body: str, cfg: CorrelateConfig) -> _Fingerprint:
    seps = Separators.from_message(body)
    segments = parse(body, seps)
    msh = _first(segments, "MSH")
    control_id = msh.field(10) if msh is not None else ""
    destination = (msh.field(5), msh.field(6)) if msh is not None else ("", "")
    destination = cfg.destination_aliases.get(destination, destination)
    msg_type = _message_type(msh, seps)
    whole_seconds = _whole_seconds(msh.field(7)) if msh is not None else ""
    patient_ids = _patient_ids(segments, seps, msg_type[1], cfg)
    return _Fingerprint(control_id, destination, (patient_ids, msg_type, whole_seconds))


def _meaningful(content_key: ContentKey) -> bool:
    """Whether a content key carries enough to match on (avoids two empty/unparseable bodies pairing)."""
    patient_ids, msg_type, _ = content_key
    return bool(patient_ids) or bool(msg_type[0])


def _patients_disjoint(a: _Fingerprint, b: _Fingerprint) -> bool:
    """True when both fingerprints carry patient ids and the sets do not overlap — a strong signal the
    two outputs are different patients (a recycled/colliding control id), so the match is rejected."""
    pa, pb = a.content_key[0], b.content_key[0]
    return bool(pa) and bool(pb) and pa.isdisjoint(pb)


def _assign(
    cps: list[_CpItem], candidates: list[int], destination: tuple[str, str], unique: bool
) -> int | None:
    """Choose at most one Corepoint candidate for a MEFOR output sharing a match key. Destination
    (``(MSH-5, MSH-6)``) corroborates the key: a uniquely destination-aligned candidate wins; failing
    that, an **unambiguous** 1:1 key (``unique`` and a single candidate) is accepted despite a
    relabelled/blank destination. Anything else is ambiguous — return ``None`` (leave unmatched) rather
    than guess by input order, so two genuinely-different or differently-routed outputs are never
    force-paired."""
    if not candidates:
        return None
    dest_matches = [i for i in candidates if cps[i].fp.destination == destination]
    if len(dest_matches) == 1:
        return dest_matches[0]
    if dest_matches:
        return None  # several candidates also share the destination — ambiguous
    if unique and len(candidates) == 1:
        return candidates[0]  # unambiguous 1:1; tolerate a relabelled/blank destination
    return None


def correlate(
    mefor_outputs: list[MeforOutput],
    corepoint_outputs: list[CorepointOutput],
    config: CorrelateConfig | None = None,
) -> list[CorrelatedPair]:
    """Correlate MEFOR outputs to Corepoint outputs (D2). Returns one :class:`CorrelatedPair` per MEFOR
    output (matched or missing-on-Corepoint) followed by one per unmatched Corepoint output
    (missing-on-MEFOR)."""
    cfg = config or CorrelateConfig()
    cps = [_CpItem(o, _fingerprint(o.raw, cfg)) for o in corepoint_outputs]
    mfps = [_fingerprint(mo.payload, cfg) for mo in mefor_outputs]
    used: set[int] = set()
    pairs: list[CorrelatedPair] = []
    pending: list[int] = []

    # A match key shared by more than one MEFOR output (a fan-out, or control-id reuse) is ambiguous —
    # a match on it alone is not trusted, so destination must agree (see :func:`_assign`).
    control_counts = Counter(mo.source_control_id for mo in mefor_outputs if mo.source_control_id)
    content_counts = Counter(mfp.content_key for mfp in mfps if _meaningful(mfp.content_key))

    # Pass 1 — primary key: source MSH-10 (run for ALL outputs before any content fallback, so a
    # preserved-control-id match is never stolen by a weaker content match).
    for idx, mo in enumerate(mefor_outputs):
        mfp = mfps[idx]
        if not mo.source_control_id:
            pending.append(idx)
            continue
        candidates = [
            i
            for i, item in enumerate(cps)
            if i not in used
            and item.fp.control_id == mo.source_control_id
            and not _patients_disjoint(mfp, item.fp)
        ]
        i = _assign(cps, candidates, mfp.destination, control_counts[mo.source_control_id] == 1)
        if i is not None:
            used.add(i)
            pairs.append(
                CorrelatedPair(
                    "control_id", mo, cps[i].output, mo.source_control_id, mfp.destination
                )
            )
        else:
            pending.append(idx)

    # Pass 2 — fallback: content key.
    for idx in pending:
        mo, mfp = mefor_outputs[idx], mfps[idx]
        if not _meaningful(mfp.content_key):
            pairs.append(
                CorrelatedPair("unmatched", mo, None, mo.source_control_id or None, mfp.destination)
            )
            continue
        candidates = [
            i
            for i, item in enumerate(cps)
            if i not in used and item.fp.content_key == mfp.content_key
        ]
        i = _assign(cps, candidates, mfp.destination, content_counts[mfp.content_key] == 1)
        if i is not None:
            used.add(i)
            pairs.append(
                CorrelatedPair(
                    "content_key", mo, cps[i].output, mo.source_control_id, mfp.destination
                )
            )
        else:
            pairs.append(
                CorrelatedPair("unmatched", mo, None, mo.source_control_id or None, mfp.destination)
            )

    # Leftover Corepoint outputs that no MEFOR output claimed — missing on the MEFOR side.
    for i, item in enumerate(cps):
        if i not in used:
            pairs.append(
                CorrelatedPair(
                    "unmatched", None, item.output, item.fp.control_id or None, item.fp.destination
                )
            )
    return pairs
