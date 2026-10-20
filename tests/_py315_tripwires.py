# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one marker for the TLS tripwires that fire by design on CPython 3.15.

Each marked test asserts a 3.14 fact about the ``ssl`` module: no ``set_ciphersuites``, no
``set_client_sigalgs``/``set_server_sigalgs``, no key-exchange group list. CPython 3.15 adds all three, so on 3.15 each one
fails on purpose and names the security record that must be re-derived. The advisory 3.15 canary
measured exactly that (run 39418750602). The re-derivation is still owed; this mark does not do it,
it only stops the canary reporting the same known finding every week.

On 3.14, the supported floor, the mark is inert and every test asserts as it did.

On 3.15 the mark is a tripwire of its own, and a coarse one:

* ``strict=True``: a marked test that PASSES there turns the canary red, because the fact it measures
  changed again.
* ``raises=AssertionError``: an exception that is not an ``AssertionError`` stays red, for example a
  ``TypeError`` or an ``ImportError``.
* WHAT IT DOES NOT DO. Any ``AssertionError`` in a marked test reads as the expected failure on 3.15,
  including one from a non-tripwire control in the same test, such as a handshake that should
  succeed. So on 3.15 these tests positively check nothing. Real 3.15 arms that assert the pin and
  the narrowing took belong to the re-derivation.

``test_the_py315_tripwire_mark_has_not_outlived_the_314_floor`` in ``tests/test_tls_policy.py`` goes
red when the floor leaves 3.14 or another workflow names 3.15, so the mark cannot become a permanent
expected failure on a leg that is not the canary.
"""

from __future__ import annotations

import sys

import pytest

PY315_TLS_TRIPWIRE = pytest.mark.xfail(
    sys.version_info >= (3, 15),
    strict=True,
    raises=AssertionError,
    reason=(
        "3.15 ssl adds set_ciphersuites, the sigalgs setters and a key-exchange group list: ASVS "
        "11.3.1/11.6.2/TLS 1.3 R4 re-derivation owed when the floor moves to 3.15 (#2478)"
    ),
)
