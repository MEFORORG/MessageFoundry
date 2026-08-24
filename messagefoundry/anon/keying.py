# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Deterministic, salt-keyed pseudonymization seed for the anonymizer (ADR 0030 §4).

The surrogate chosen for a real value must be two things at once:

* **stable within one dataset** — the same MRN must map to the same fake MRN across every
  message, so cross-message links survive (an A40 merge's ``MRG-1`` keyed identically to
  ``PID-3``, repeated demographics, encounter joins); and
* **re-identification-resistant** — you must not be able to run a surrogate back to the real
  value it replaced.

Both come from a single **secret, per-dataset salt** (ADR 0030 owner decision, 2026-06-20:
*pinned-per-dataset secret, env-supplied, never committed*). The seed for a ``(kind, value)``
pair is a **keyed BLAKE2b** under that salt, so a different salt yields entirely different
surrogates (no cross-dataset linkage) and the keyed hash is one-way. :class:`random.Random` is
seeded from that digest **only to pick** a surrogate from a fixed pool — it never provides the
irreversibility (the keyed hash does); a plain string-seeded PRNG would be trivially reversible.

This module is **pure stdlib** and is one of the byte-identical files vendored into ``tee/anon/``
(kept in lockstep by the parity test) — keep it free of any ``messagefoundry`` import.
"""

from __future__ import annotations

import hashlib
import math
import random
from collections import Counter

#: 128-bit seed — ample entropy to index any surrogate pool without collisions you'd notice.
_DIGEST_SIZE = 16

#: A salt shorter than this is almost certainly a placeholder/typo, not a real secret. The CLI
#: boundaries source it from the environment and should pass a high-entropy value; we refuse an
#: obviously-weak salt rather than emit guessable surrogates (fail closed, ADR 0030 §4).
MIN_SALT_LEN = 16

#: Floor on the salt's ESTIMATED entropy, in bits. Length alone is not strength: sixteen copies of
#: the letter "a" clears ``MIN_SALT_LEN`` and is guessable on the first try, so the length floor
#: could be passed by a salt with no secrecy at all.
MIN_SALT_ENTROPY_BITS = 32.0

#: Floor on the salt's estimated entropy PER CHARACTER, in bits. The total-bits floor above is
#: length-scaled, so **length alone would rescue a degenerate pattern**: ``"ab"`` repeated eight
#: times scores 16.00 bits and is refused, while the SAME two-symbol pattern repeated sixteen times
#: scores 32.00 and would pass. That is not a blind spot the estimator's docstring can wave at -- it
#: is the length floor defeating the entropy floor -- so the rate is checked separately from the
#: total and a string has to clear BOTH.
#:
#: 2.0 bits per character means an effective alphabet of four symbols. Measured against the shapes
#: that matter: ``"ab"`` repeated scores 1.00 and is refused at any length; ``"abc"`` repeated scores
#: about 1.58 and is refused; a random DECIMAL salt -- the narrowest alphabet a real generator would
#: produce -- scores about 3.32, and random hex about 3.9, so neither is touched. A single repeated
#: character scores 0.00 and was already refused by the total.
MIN_SALT_ENTROPY_BITS_PER_CHAR = 2.0

#: **WHY 32 BITS AND NOT THE 128 THE ADR NAMES.** ADR 0030 section 4 requires ``dataset_key`` to be
#: DRAWN from ``secrets.token_bytes``/``os.urandom`` with at least 128 bits of entropy. That is a
#: requirement on GENERATION and it is not the same measurement as this one. These floors grade a
#: string the engine did not generate, using a distribution estimate that is a LOWER BOUND and a
#: loose one: a genuine 128-bit secret rendered as sixteen decimal digits estimates about 40 bits
#: here, and rendered as base62 about 95 -- neither reaches 128, because the estimator cannot see
#: the entropy of the generator, only of the characters in front of it.
#:
#: So a floor set at the ADR's 128 would refuse real, conformant secrets, which is why it is not set
#: there. **The consequence must be read honestly: clearing these floors does NOT establish that a
#: salt meets ADR 0030, and no check on a supplied string could.** This is a screen against a
#: visibly degenerate salt, sitting underneath the ADR requirement rather than implementing it. The
#: control that actually delivers 128 bits is generating the salt with the tool the error message
#: names, and that stays where the ADR puts it.

#: Ceiling on the salt's UTF-8 length in BYTES, set by BLAKE2b's keyed mode
#: (``hashlib.blake2b.MAX_KEY_SIZE``, 64). Checked here at construction rather than left to
#: :meth:`Keyer.seed`, where it fired as a bare ``ValueError: maximum key length is 64 bytes`` on
#: the FIRST message instead of on the bad configuration -- an 86-byte ``secrets.token_urlsafe(64)``
#: built a Keyer without complaint and then failed mid-dataset. Bytes, not characters: a non-ASCII
#: salt can pass 64 bytes well under 64 characters.
MAX_SALT_BYTES = hashlib.blake2b.MAX_KEY_SIZE


def _estimated_entropy_bits(salt: str) -> float:
    """Shannon entropy of the salt's OBSERVED character distribution, scaled by its length.

    Why this estimator. It is the weakest assumption we can make about a string we did not
    generate: count the symbols, take ``-sum(p * log2(p))`` for the per-character entropy, and
    multiply by the length for a total in bits. It needs no dictionary, no alphabet table and no
    network, it grades continuously rather than by category, and -- unlike a bare count of distinct
    characters -- it sees SKEW. A salt of sixteen "a" characters plus seven distinct others has
    eight distinct characters and would clear a distinct-character floor of eight, while this
    estimator scores it at about 40 bits for twenty-three characters and grades it near the floor,
    which is the honest reading of a string that is five-sixths one symbol.

    WHAT IT CANNOT SEE, stated plainly because every distribution-based estimator shares the blind
    spot: it is ORDER-BLIND and DICTIONARY-BLIND. It scores every permutation of a string
    identically, so "abcdefghijklmnop" measures a full 64.00 bits at the length floor -- the
    arithmetic maximum for sixteen characters -- and passes, despite being one of the first strings
    any attacker would try. A repeated cycle such as "abcdabcdabcdabcd" measures exactly 32.00 bits
    and also passes. This check therefore catches a salt that is visibly DEGENERATE; it cannot
    certify that a salt is unpredictable, and nothing short of generating the salt ourselves could.
    The real defence stays where ADR 0030 section 4 puts it: an env-supplied secret from a random
    generator. This is the floor under that, not a substitute for it.

    Where the floor came from. Measured 2026-08-22 by sampling 200,000 random 16-character salts
    per alphabet and counting how many this estimator scores below 32 bits: base62 0, lowercase 0,
    lowercase hex 1, and decimal digits 57 -- the tightest realistic case, and a 16-digit salt
    carries only about 53 bits of real entropy to begin with. The zeros are trustworthy because the
    same run returned NON-ZERO at higher floors (at 40 bits the same four alphabets rejected 0, 2,
    306 and 11,066 of 200,000), so the instrument can fire. A 40-bit floor would refuse better than
    5 percent of genuinely random 16-digit salts, which is refusing real secrets; 32 bits does not.
    """
    if not salt:
        return 0.0
    n = len(salt)
    per_char = sum(-(c / n) * math.log2(c / n) for c in Counter(salt).values())
    return n * per_char


class Keyer:
    """Maps a ``(field-kind, real value)`` pair to a stable, salt-keyed PRNG — one per dataset.

    Construct **one** ``Keyer`` per dataset run from the secret salt; every surrogate function
    draws its choice from ``keyer.rng(kind, value)`` so equal inputs (same salt, kind, value)
    always yield the same surrogate, and a different salt yields a disjoint mapping.
    """

    __slots__ = ("_salt",)

    def __init__(self, salt: str) -> None:
        if len(salt) < MIN_SALT_LEN:
            raise ValueError(
                f"anonymizer salt must be a secret of at least {MIN_SALT_LEN} characters "
                "(ADR 0030 §4: pinned-per-dataset secret, env-supplied, never committed)"
            )
        encoded = salt.encode("utf-8")
        if len(encoded) > MAX_SALT_BYTES:
            raise ValueError(
                f"anonymizer salt must be at most {MAX_SALT_BYTES} bytes when UTF-8 encoded "
                f"(this one is {len(encoded)}); that is BLAKE2b's keyed-mode limit, and a salt at "
                "the ceiling already carries far more entropy than the surrogate pools can use. "
                "secrets.token_urlsafe(48) is the longest that fits."
            )
        # Length is a necessary floor, not a sufficient one -- see MIN_SALT_ENTROPY_BITS and
        # _estimated_entropy_bits for the measure and its limits. Neither the salt nor any part of
        # it appears in the message: it is a re-identification key, so an exception that quotes it
        # would leak it into a traceback, a log or a CI transcript.
        entropy = _estimated_entropy_bits(salt)
        if entropy < MIN_SALT_ENTROPY_BITS:
            raise ValueError(
                f"anonymizer salt is too predictable: about {entropy:.1f} bits of estimated "
                f"entropy against a floor of {MIN_SALT_ENTROPY_BITS:.0f}. Generate one with "
                "secrets.token_urlsafe(24) and supply it from the environment. The salt itself is "
                "withheld from this message on purpose. Note this floor is a SCREEN, not the ADR "
                "0030 section 4 requirement: that one is 128 bits AT GENERATION, which no check on "
                "a supplied string can confirm."
            )
        # Checked SEPARATELY from the total, because the total is length-scaled and length would
        # otherwise rescue a degenerate pattern -- "ab" repeated sixteen times reaches the 32-bit
        # total on 1.00 bits per character. Both floors bind; neither substitutes for the other.
        per_char = entropy / len(salt)
        if per_char < MIN_SALT_ENTROPY_BITS_PER_CHAR:
            raise ValueError(
                f"anonymizer salt repeats too few distinct characters: about {per_char:.2f} bits "
                f"per character against a floor of {MIN_SALT_ENTROPY_BITS_PER_CHAR:.1f}. Making it "
                "longer will NOT help -- a repeating pattern carries the same rate at any length. "
                "Generate one with secrets.token_urlsafe(24) and supply it from the environment. "
                "The salt itself is withheld from this message on purpose."
            )
        # Hold the salt as bytes only; it is PHI-equivalent (a re-identification key) and must
        # never be logged, persisted, or surfaced — so we keep no other reference to it.
        self._salt = encoded

    def seed(self, kind: str, value: str) -> int:
        """A 128-bit seed for ``(kind, value)``, keyed by the dataset salt (one-way)."""
        digest = hashlib.blake2b(
            f"{kind}\x00{value}".encode(), key=self._salt, digest_size=_DIGEST_SIZE
        ).digest()
        return int.from_bytes(digest, "big")

    def rng(self, kind: str, value: str) -> random.Random:
        """A deterministic :class:`random.Random` for ``(kind, value)`` — the surrogate picker."""
        return random.Random(self.seed(kind, value))
