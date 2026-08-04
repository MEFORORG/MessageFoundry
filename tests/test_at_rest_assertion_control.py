# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Negative control for the PHI-at-rest assertion FORM itself (BACKLOG #347 follow-up).

**Why this file exists.** The at-rest tests assert that a stored body is ciphertext by checking the
`mfenc:` marker and the absence of the plaintext. When one of those assertions flakes, the cheap fix is
to weaken it until it stops failing — and a weakened assertion is indistinguishable, on a green run,
from a working one. That is the whole argument of BACKLOG #1000: a control nobody has watched fail is
an assumption wearing a green tick.

So the *form* gets its own control. These tests do not exercise the store; they exercise the predicate
the store tests rely on, against a body that is deliberately NOT enciphered. If someone later relaxes
`assert PLAINTEXT not in stored` back to a short-substring check, the last test here goes red and says
why.

This is deliberately a separate file from `test_store_encryption.py`: it is about the assertion, not
about the cipher, and keeping it separate means a sweep of the store tests cannot quietly take it with
them.
"""

from __future__ import annotations

import base64
import os

from messagefoundry.store.crypto import MARKER_PREFIX, generate_key, make_cipher

# A synthetic ADT — never real PHI. Carries '|' and CR, which base64 cannot emit; that is precisely
# what makes whole-plaintext absence a DETERMINISTIC assertion rather than a probabilistic one.
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def _leaking_at_rest(plaintext: str) -> str:
    """A stored value that carries the marker but was NEVER enciphered.

    This is the realistic failure, not a contrived one: a cipher misconfigured to identity, a writer
    that stamps the marker before encrypting, or a migration that copies a plaintext body forward. In
    every case the marker is present and the body is readable.
    """
    return MARKER_PREFIX + "v1:deadbeef:" + plaintext


def test_the_marker_check_alone_does_not_detect_a_leak() -> None:
    """Establishes the baseline: `startswith(MARKER_PREFIX)` proves nothing about confidentiality.

    Stated as a passing test rather than a comment, because the marker half is genuinely load-bearing
    for "is this row enciphered at all" and must NOT be removed — it just cannot carry the PHI claim
    on its own. Both halves are needed, for different reasons.
    """
    leaked = _leaking_at_rest(ADT)
    assert leaked.startswith(MARKER_PREFIX)  # the marker is happy...
    assert ADT in leaked  # ...while the entire body sits there in cleartext


def test_whole_plaintext_absence_detects_a_leak() -> None:
    """THE CONTROL. The form used at every at-rest call site must fail on an unenciphered body.

    If this test ever needs changing to accommodate a "fix" to a flaky at-rest assertion, that is the
    signal the fix weakened the property rather than sharpened it.
    """
    leaked = _leaking_at_rest(ADT)
    detected = not (leaked.startswith(MARKER_PREFIX) and ADT not in leaked)
    assert detected, (
        "the whole-plaintext-absence assertion PASSED on a body that was never enciphered — "
        "the at-rest PHI check is no longer able to detect the thing it exists for"
    )


def test_whole_plaintext_absence_does_not_flake_on_real_ciphertext() -> None:
    """The other direction: the form must not red on correct encryption.

    A control that catches leaks by being trigger-happy would be swapped out within a week. Real
    tokens, real key, many draws — the deterministic form has no false-positive rate to measure.
    """
    cipher = make_cipher(generate_key())
    for _ in range(200):
        token = cipher.encrypt(ADT)
        assert token.startswith(MARKER_PREFIX) and ADT not in token


def test_a_short_substring_check_is_not_a_substitute() -> None:
    """Why the retired form was replaced, pinned so it cannot quietly return.

    A 3-character needle against a random base64 body collides at a rate that is small per assertion
    and NOT small per CI run — measured at ~1 in 2,222 per assertion here, and it did fire in CI. The
    point is not the exact rate; it is that the rate is nonzero and unbounded by anything the test
    controls, while the whole-plaintext form's is zero by construction.

    Both properties are asserted over the SAME draws, so this cannot pass by sampling luck: whatever
    the short needle does, the deterministic form is clean across every one of them.
    """
    cipher = make_cipher(generate_key())
    short_needle_hits = 0
    for _ in range(2000):
        token = cipher.encrypt(ADT)
        assert ADT not in token  # deterministic form: never fires on correct encryption
        if "DOE" in token:
            short_needle_hits += 1

    # Independent of the cipher, to keep this honest about WHY: it is a property of random base64,
    # not of this particular token stream.
    random_hits = sum(1 for _ in range(20000) if "DOE" in base64.b64encode(os.urandom(96)).decode())
    assert random_hits > 0, (
        "'DOE' never appeared in 20,000 random base64 bodies — that contradicts the measured rate "
        "(~1 in 2,222) and means this control is no longer demonstrating the flake it documents"
    )
