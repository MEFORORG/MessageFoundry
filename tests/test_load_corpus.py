# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The replay corpus: generate once, stamp a unique control id per send, sample by the mix.

Asserts unique/monotonic control ids that round-trip through MSH-10, that the sampler honors weights,
and that round-robin varies content within a type.
"""

from __future__ import annotations

import collections
import random

from messagefoundry.parsing import Peek, normalize

from harness.load.corpus import build_corpus
from harness.load.ids import ControlIds
from harness.load.profile import TypeMix, load_profile_text

_IDS = ControlIds(prefix="LX", width=12)

_PROFILE = """
[load]
name = "corpus-test"
corpus_count_per_trigger = 4
[[load.target]]
name = "hub"
[load.mix]
"ADT^A05" = 3.0
"ORU^R01" = 1.0
[[load.phase]]
name = "s"
kind = "sustained"
loop = "open"
rate_start = 10.0
duration_s = 1.0
"""


def _cid(raw: str) -> str:
    return Peek.parse(normalize(raw)).control_id or ""


def test_next_stamps_unique_monotonic_control_ids() -> None:
    profile = load_profile_text(_PROFILE)
    corpus = build_corpus(profile, _IDS)
    sampler = corpus.sampler(profile.default_mix)
    out = [corpus.next(sampler) for _ in range(20)]
    assert [o.seq for o in out] == list(range(20))  # dense + monotonic
    assert [o.control_id for o in out] == [_IDS.format(i) for i in range(20)]
    # The stamped control id is what actually lands in MSH-10 of the encoded payload.
    assert all(_cid(o.payload) == o.control_id for o in out)
    assert all(o.code in {"ADT", "ORU"} for o in out)


def test_sampler_honors_weights() -> None:
    profile = load_profile_text(_PROFILE)
    corpus = build_corpus(profile, _IDS)
    sampler = corpus.sampler(profile.default_mix)
    counts = collections.Counter(corpus.next(sampler).code for _ in range(4000))
    # ADT weight 3 vs ORU weight 1 → roughly 75/25; allow generous slack for randomness.
    assert 0.65 < counts["ADT"] / 4000 < 0.85


def test_round_robin_varies_content_within_a_type() -> None:
    profile = load_profile_text(_PROFILE)
    corpus = build_corpus(profile, _IDS)
    only_adt = corpus.sampler(TypeMix({"ADT^A05": 1.0}))
    payloads = {corpus.next(only_adt).payload for _ in range(4)}  # count_per_trigger == 4 distinct
    # MSH-10 differs per send, so strip it out: compare the rest of the message bodies.
    bodies = {p.replace(_cid(p), "") for p in payloads}
    assert len(bodies) >= 2  # not all identical — the pool is being cycled


def test_sampler_is_deterministic_for_a_seed() -> None:
    profile = load_profile_text(_PROFILE)
    a = build_corpus(profile, _IDS)
    b = build_corpus(profile, _IDS)
    sa, sb = a.sampler(profile.default_mix), b.sampler(profile.default_mix)
    seq_a = [a.next(sa).code for _ in range(50)]
    seq_b = [b.next(sb).code for _ in range(50)]
    assert seq_a == seq_b  # same seed → same type sequence


def test_sampler_pick_uses_supplied_rng() -> None:
    mix = TypeMix({"ADT": 1.0, "ORU": 1.0, "ORM": 1.0})
    from harness.load.corpus import Sampler

    s = Sampler(mix)
    picks = [s.pick(random.Random(7)) for _ in range(5)]
    assert all(p in {"ADT", "ORU", "ORM"} for p in picks)
