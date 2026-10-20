# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one marker for the TLS tripwires that fire by design on CPython 3.15.

Each marked test asserts a 3.14 fact about the ``ssl`` module: no ``set_ciphersuites``, no
``set_client_sigalgs``, no key-exchange group list. CPython 3.15 adds all three, so on 3.15 each one
fails on purpose and names the security record that must be re-derived. That re-derivation belongs
to the change that raises the floor to 3.15, not to the advisory canary that runs on 3.15 today.

The condition keeps 3.14 exactly as before: the mark is inert there and every test asserts as it did.
``strict=True`` makes the mark a tripwire of its own on 3.15. A marked test that PASSES there turns
the canary red, because the fact it measures changed again. ``raises=AssertionError`` keeps any other
exception red too: every marked test fires through an ``assert``, so a ``TypeError`` or an import
failure is a new break, not the tripwire.
"""

from __future__ import annotations

import sys

import pytest

PY315_TLS_TRIPWIRE = pytest.mark.xfail(
    sys.version_info >= (3, 15),
    strict=True,
    raises=AssertionError,
    reason=(
        "3.15 ssl adds set_ciphersuites, set_client_sigalgs and a key-exchange group list: ASVS "
        "11.3.1/11.6.2/TLS 1.3 R4 re-derivation owed when the floor moves to 3.15 (#2478)"
    ),
)
