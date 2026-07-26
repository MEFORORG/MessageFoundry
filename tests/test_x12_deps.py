# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The optional ``[x12]`` extra (``pyx12``) guard (ADR 0012, X12-6): a missing extra must fail as a
:class:`RuntimeError` (a deploy/config error), NEVER as the :class:`ValueError`-rooted data errors in
:mod:`messagefoundry.parsing.x12.errors`. If it were a ``ValueError``, a Handler's ``except ValueError``
(which routes malformed X12 to the dead-letter path) would silently swallow a "you forgot to install
the extra" error. Mirrors the DICOM-5 missing-``[dicom]``-extra test in ``tests/test_dicom_codec.py``."""

from __future__ import annotations

import sys

import pytest

pytest.importorskip(
    "pyx12", reason="the [x12]-guard test simulates pyx12's absence from a present one"
)

from messagefoundry.parsing.x12 import X12Error, X12ValidationError, validate  # noqa: E402
from messagefoundry.parsing.x12._deps import load_x12_validator  # noqa: E402


def test_missing_x12_extra_raises_runtimeerror_not_valueerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # None in sys.modules makes ``import pyx12.params`` raise ImportError — the no-extra path (the
    # module's importorskip means the real pyx12 is present here, so we simulate its absence). We null
    # the submodules too, since they may already be cached from an earlier test in the session.
    for name in ("pyx12", "pyx12.params", "pyx12.x12n_document"):
        monkeypatch.setitem(sys.modules, name, None)

    with pytest.raises(RuntimeError, match=r"messagefoundry\[x12\]"):
        load_x12_validator()

    # validate() funnels through load_x12_validator, so it surfaces the same RuntimeError — before any
    # walk — distinct from the ValueError-rooted X12ValidationError a *failed* validation would raise.
    with pytest.raises(RuntimeError) as excinfo:
        validate("ISA*00*...~")  # never reaches a parse; the guard fires first
    exc = excinfo.value
    assert not isinstance(exc, ValueError)  # a Handler's `except ValueError` won't catch it
    assert not isinstance(exc, X12Error)  # nor the X12 data-error hierarchy
    assert not isinstance(exc, X12ValidationError)
    assert "pip install 'messagefoundry[x12]'" in str(exc)

    # Belt-and-suspenders: prove the error escapes an `except ValueError` (the Handler dead-letter guard).
    escaped = False
    try:
        validate("ISA*00*...~")
    except ValueError:  # pragma: no cover - must NOT be taken (RuntimeError is not a ValueError)
        escaped = False
    except RuntimeError:
        escaped = True
    assert escaped
