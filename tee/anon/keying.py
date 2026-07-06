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
import random

#: 128-bit seed — ample entropy to index any surrogate pool without collisions you'd notice.
_DIGEST_SIZE = 16

#: A salt shorter than this is almost certainly a placeholder/typo, not a real secret. The CLI
#: boundaries source it from the environment and should pass a high-entropy value; we refuse an
#: obviously-weak salt rather than emit guessable surrogates (fail closed, ADR 0030 §4).
MIN_SALT_LEN = 16


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
        # Hold the salt as bytes only; it is PHI-equivalent (a re-identification key) and must
        # never be logged, persisted, or surfaced — so we keep no other reference to it.
        self._salt = salt.encode("utf-8")

    def seed(self, kind: str, value: str) -> int:
        """A 128-bit seed for ``(kind, value)``, keyed by the dataset salt (one-way)."""
        digest = hashlib.blake2b(
            f"{kind}\x00{value}".encode(), key=self._salt, digest_size=_DIGEST_SIZE
        ).digest()
        return int.from_bytes(digest, "big")

    def rng(self, kind: str, value: str) -> random.Random:
        """A deterministic :class:`random.Random` for ``(kind, value)`` — the surrogate picker."""
        return random.Random(self.seed(kind, value))
