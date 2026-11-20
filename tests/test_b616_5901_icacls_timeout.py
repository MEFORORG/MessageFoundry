# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The trust-anchor DACL read bounds its ``icacls`` run (vault BACKLOG #5901).

A stalled ``icacls`` run held every caller of :func:`dacl_is_owner_only` with no bound. The read
now passes a timeout, and running out answers ``None``, the undeterminable verdict. The bound
covers icacls only: the in-process reads :func:`evaluate_anchor` makes before it are not bounded
here, and ``_ICACLS_TIMEOUT_S``'s comment names what else stays open. ``subprocess.run`` is faked:
no real share or child is stalled.
"""

from __future__ import annotations

import logging
import os
import subprocess

import pytest

from messagefoundry.auth import trust_anchors as ta

pytestmark = pytest.mark.skipif(os.name != "nt", reason="the icacls DACL read is the nt path")

_PATH = r"C:\anchors\ca.pem"


def test_an_icacls_read_that_times_out_is_undeterminable(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    seen: list[object] = []

    def _run(argv: list[str], **kw: object) -> object:
        seen.append(kw.get("timeout"))
        # What subprocess.run raises once the timeout passes. Faked, so this proves the bound is
        # passed and how running out is answered, not that a real stalled child is reaped.
        raise subprocess.TimeoutExpired(argv, ta._ICACLS_TIMEOUT_S)

    monkeypatch.setattr(subprocess, "run", _run)  # the module object trust_anchors calls
    with caplog.at_level(logging.WARNING, logger=ta.log.name):
        assert ta.dacl_is_owner_only(_PATH) is None
    # Guard the guard: the fake must have run, with a finite timeout, or the None above proves
    # only that some other branch answered it.
    assert seen == [ta._ICACLS_TIMEOUT_S]
    assert isinstance(seen[0], float) and 0 < seen[0] < float("inf")
    assert any("within" in r.getMessage() and repr(_PATH) in r.getMessage() for r in caplog.records)


def test_an_icacls_read_passes_its_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    # Before the fix the call carried no timeout at all; a read that answers is unchanged.
    seen: list[object] = []

    class _R:
        returncode = 0
        stdout = f"{_PATH} DESKTOP-A\\svc:(F)\n\nSuccessfully processed 1 files; Failed processing 0 files\n"
        stderr = ""

    def _run(argv: list[str], **kw: object) -> _R:
        seen.append(kw.get("timeout"))
        return _R()

    monkeypatch.setattr(subprocess, "run", _run)
    assert ta.dacl_is_owner_only(_PATH) is True
    assert seen == [ta._ICACLS_TIMEOUT_S]
