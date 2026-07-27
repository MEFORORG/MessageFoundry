# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The replay corpus — synthetic HL7 generated once, then replayed with a fresh control id per send.

The generators validate each message against the hl7apy reference tree (slow), so generation happens
**once, before the run** and never on the hot path. Each template is parsed into a
:class:`~messagefoundry.parsing.message.Message` at build time; per send the corpus stamps a unique
MSH-10 via the parsed model (``set`` → ``encode`` — never string slicing) and hands back the encoded
payload. A weighted :class:`Sampler` picks the message type per the active phase's mix.

Control ids are dense and monotonic (see :class:`~harness.load.ids.ControlIds`) so the correlator can
use an O(1) ring and the sink can reverse the id trivially.
"""

from __future__ import annotations

import bisect
import json
import random
from dataclasses import dataclass
from pathlib import Path

from harness.load.ids import ControlIds
from harness.load.profile import LoadProfile, LoadProfileError, TypeMix
from messagefoundry.generators import _core
from messagefoundry.generators import (
    all_types as _all_types,  # noqa: F401  (registers message types)
)
from messagefoundry.parsing.message import Message


@dataclass(frozen=True)
class Outgoing:
    """One message ready to send."""

    seq: int
    code: str  # message-type code (e.g. "ADT") — the sender routes to a target accepting it
    control_id: str
    payload: str


class Sampler:
    """Weighted picker over mix keys (``"ADT"`` or ``"ADT^A05"``) using one ``random`` draw."""

    __slots__ = ("_keys", "_cum", "_total")

    def __init__(self, mix: TypeMix) -> None:
        keys: list[str] = []
        cum: list[float] = []
        running = 0.0
        for key, weight in sorted(mix.weights.items()):
            if weight <= 0.0:
                continue
            running += weight
            keys.append(key)
            cum.append(running)
        if not keys:
            raise ValueError("mix has no positive-weight entries")
        self._keys = keys
        self._cum = cum
        self._total = running

    def pick(self, rng: random.Random) -> str:
        x = rng.random() * self._total
        return self._keys[bisect.bisect_right(self._cum, x)]


#: Sequence-space stride between concurrent SENDER PROCESSES (see ``seq_base``). Decimal, so a seq stays
#: legible inside the 12-digit control id: worker ``j`` owns ``[j*1e9, (j+1)*1e9)`` — 1e9 seqs each (a run
#: emits ~1e6 at the very most) and up to 999 workers before the 12-digit width is exhausted. FAIL LOUD in
#: ``ControlIds.format``'s caller rather than silently widen: a 13-digit id would not round-trip MSH-10.
SEQ_BASE_STRIDE: int = 1_000_000_000


class Corpus:
    """In-RAM pool of parsed templates, indexed for both ``CODE`` and ``CODE^TRIGGER`` mix keys.

    ``seq_base`` offsets this corpus's sequence space. It defaults to 0 — byte-identical to a single-sender
    run — and exists for the MULTI-PROCESS sender tier, where each worker builds its OWN ``Corpus`` in its
    OWN process. Left at 0 there, EVERY worker emits the identical stream ``0, 1, 2, …``, which:

    * stamps the SAME control id on K different messages (two workers' ``SC000000000005`` are different
      messages), and
    * PHASE-LOCKS any seq-derived routing decision — the shardcert's PARTITIONED selector picks the
      destination lane from the seq, so K lockstepped workers all target the SAME lane at the same instant:
      the sender tier walks the lanes K-deep in bursts instead of spreading K concurrent messages over K
      distinct lanes. The long-run per-lane load is unchanged (still R/L), but the per-lane arrival process
      becomes bursty, which aliases against the soak's ``in_pipeline`` sampler.

    Giving worker ``j`` ``seq_base = j * SEQ_BASE_STRIDE`` makes the K streams DISJOINT, so ids are unique
    across the tier and the instantaneous lane spread is uniform."""

    def __init__(
        self,
        ids: ControlIds,
        by_code_trigger: dict[tuple[str, str], list[Message]],
        seed: str,
        seq_base: int = 0,
    ) -> None:
        self._ids = ids
        self._by_ct = by_code_trigger
        self._by_code: dict[str, list[Message]] = {}
        for (code, _trigger), msgs in by_code_trigger.items():
            self._by_code.setdefault(code, []).extend(msgs)
        self._seq = seq_base
        self._cursor: dict[str, int] = {}
        self._rng = random.Random(seed)

    def sampler(self, mix: TypeMix) -> Sampler:
        return Sampler(mix)

    def _candidates(self, key: str) -> list[Message]:
        if "^" in key:
            code, trigger = key.split("^", 1)
            return self._by_ct.get((code, trigger), [])
        return self._by_code.get(key, [])

    def next(self, sampler: Sampler) -> Outgoing:
        """Pick a template per the sampler, stamp a unique MSH-10, and return the encoded message."""
        key = sampler.pick(self._rng)
        candidates = self._candidates(key)
        if not candidates:
            raise KeyError(f"corpus has no messages for mix key {key!r}")
        # Round-robin within a key so a small pool still varies content across sends.
        i = self._cursor.get(key, 0)
        self._cursor[key] = i + 1
        template = candidates[i % len(candidates)]
        seq = self._seq
        self._seq += 1
        control_id = self._ids.format(seq)
        # next() is synchronous (no await), so mutating the shared template + encoding is atomic w.r.t.
        # the event loop; encode() captures the payload string before the template is reused.
        template.set("MSH-10", control_id)
        return Outgoing(
            seq=seq, code=key.split("^", 1)[0], control_id=control_id, payload=template.encode()
        )


def _pairs_for_profile(profile: LoadProfile) -> set[tuple[str, str]]:
    """Every (code, trigger) the profile's mixes can emit — what the corpus must generate."""
    keys: set[str] = set(profile.default_mix.weights)
    for phase in profile.phases:
        if phase.mix is not None:
            keys |= set(phase.mix.weights)
    pairs: set[tuple[str, str]] = set()
    for key in keys:
        if "^" in key:
            code, trigger = key.split("^", 1)
            pairs.add((code, trigger))
        else:
            for trigger in _core.triggers_for(key):
                pairs.add((key, trigger))
    return pairs


def corpus_from_file(path: str | Path, ids: ControlIds) -> Corpus:
    """Build a replay :class:`Corpus` from a **committed, de-identified dataset** (ADR 0030 §6) —
    the JSONL the anonymizer / capture sink writes (``{"control_id", "raw", ...}`` per line, ``raw``
    being a whole HL7 message). Each message is parsed and indexed by ``(code, trigger)`` from its
    MSH-9, so the harness can replay a PHI-free corpus of **real-shaped** traffic instead of synthetic
    generation — the point of the anonymizer. ``next()``'s MSH-10 restamp applies unchanged.

    Raises :class:`~harness.load.profile.LoadProfileError` if the file is empty or a line is not a
    JSON record carrying a parseable ``raw`` message.
    """
    by_ct: dict[tuple[str, str], list[Message]] = {}
    text = Path(path).read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)["raw"]
            msg = Message.parse(raw)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LoadProfileError(f"{path}:{lineno}: not a valid dataset record: {exc}") from exc
        code = msg.field("MSH-9.1") or "UNK"
        trigger = msg.field("MSH-9.2") or ""
        by_ct.setdefault((code, trigger), []).append(msg)
    if not by_ct:
        raise LoadProfileError(f"dataset file {path} contained no messages")
    return Corpus(ids, by_ct, str(path))


def build_corpus(profile: LoadProfile, ids: ControlIds, seq_base: int = 0) -> Corpus:
    """Generate (validated, off the hot path) and parse the corpus a profile needs. Raises if a mix
    references a message type/trigger the generators don't know.

    ``seq_base`` (default 0 ⇒ unchanged) offsets the sequence space so CONCURRENT SENDER PROCESSES do not
    emit the same stream — see :class:`Corpus`."""
    pairs = _pairs_for_profile(profile)
    by_ct: dict[tuple[str, str], list[Message]] = {}
    for code, trigger in sorted(pairs):
        try:
            raws = [
                _core.generate_message(code, trigger, i, seed=profile.seed)
                for i in range(1, profile.corpus_count_per_trigger + 1)
            ]
        except (KeyError, ValueError) as exc:
            # Consistent error type with profile parsing — a mix naming an unknown trigger surfaces as
            # a LoadProfileError, not a bare ValueError from deep in the generators.
            raise LoadProfileError(f"cannot generate corpus for {code}^{trigger}: {exc}") from exc
        by_ct[(code, trigger)] = [Message.parse(raw) for raw in raws]
    return Corpus(ids, by_ct, profile.seed, seq_base)
