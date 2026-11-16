# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The verifier redacts credentials out of the exception text it writes into a check's detail
(BACKLOG #5395).

A verify report is written to JSON and Markdown that an operator pastes into a ticket. Each arm below
used to interpolate the raw exception text, and a store driver or a config module can quote a DSN or
a ``password=`` / ``PWD=`` pair. Every secret here is synthetic, and each carries a hyphen and an
underscore so the unrelated long-base64 sweep cannot be what hides it.
"""

from __future__ import annotations

import socket
import ssl
from pathlib import Path

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.config.wiring import Registry, WiringError
from messagefoundry.store import base as store_base
from messagefoundry.verify import smoke
from messagefoundry.verify.model import CheckResult
from messagefoundry.verify.report import render_json, render_markdown

_PLANTED = "pw-V3rify_Det-81"
#: A driver error that quotes its connection in the three shapes a driver uses.
_LEAKY = (
    f"connection to postgresql://svc:{_PLANTED}@db.invalid:5432/mefor failed; "
    f"Server=db.invalid;UID=svc;PWD={_PLANTED}; password={_PLANTED}"
)


def _assert_hidden(result: CheckResult, prefix: str) -> None:
    assert result.detail.startswith(prefix), result.detail
    assert _PLANTED not in result.detail, result.detail
    # The rendered reports are what leave the box; check them too, not only the field.
    assert _PLANTED not in render_json([result])
    assert _PLANTED not in render_markdown([result])


def _raise(exc: BaseException) -> Registry:
    raise exc


@pytest.mark.parametrize("exc", [WiringError(_LEAKY), OSError(_LEAKY), RuntimeError(_LEAKY)])
def test_config_load_failure_detail_hides_the_credential(
    tmp_path: Path, exc: BaseException
) -> None:
    r = smoke.smoke_self(str(tmp_path), graph=lambda: _raise(exc))
    _assert_hidden(r, "config failed to load: ")


def test_a_wiring_error_keeps_its_text_whole_around_the_redaction(tmp_path: Path) -> None:
    """The engine's own wiring diagnostic is the fix an operator reads, so it is not cut to the
    200 characters ``safe_exc`` keeps, and gets no type prefix."""
    tail = "handler 'h' sends to unknown outbound 'ob_missing'"
    long_text = f"{_LEAKY}; " + "x" * 300 + f"; {tail}"
    r = smoke.smoke_self(str(tmp_path), graph=lambda: _raise(WiringError(long_text)))
    assert _PLANTED not in r.detail
    assert r.detail.endswith(tail), r.detail
    assert "WiringError" not in r.detail


@pytest.mark.parametrize(
    ("exc", "prefix"),
    [
        (ssl.SSLError(_LEAKY), "TLS handshake with the engine inbound at 127.0.0.1:1 failed: "),
        (OSError(_LEAKY), "could not reach the engine inbound at 127.0.0.1:1: "),
    ],
)
def test_live_smoke_connect_failure_detail_hides_the_credential(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException, prefix: str
) -> None:
    def refuse(*_a: object, **_k: object) -> socket.socket:
        raise exc

    monkeypatch.setattr(socket, "create_connection", refuse)
    r = smoke.smoke_live(host="127.0.0.1", port=1, message="MSH|^~\\&|A", timeout=1.0)
    _assert_hidden(r, prefix)


def _store_that_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StoreSettings:
    """A store whose open raises the leaky driver error, past the missing-file gate."""
    db = tmp_path / "verify.db"
    db.write_bytes(b"")

    async def leaky_open(*_a: object, **_k: object) -> object:
        raise RuntimeError(_LEAKY)

    monkeypatch.setattr(store_base, "open_store", leaky_open)
    return StoreSettings(path=str(db))


def test_store_open_failure_detail_hides_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = smoke.check_store_connectivity(_store_that_raises(tmp_path, monkeypatch))
    _assert_hidden(r, "sqlite store failed to open: ")


def test_store_disposition_poll_failure_detail_hides_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _store_that_raises(tmp_path, monkeypatch)
    r = smoke.check_smoke_disposition(settings, control_id="C1", baseline_id=None, timeout=1.0)
    _assert_hidden(r, "could not read the store disposition: ")


def test_control_safe_exc_alone_keeps_the_credential() -> None:
    """The positive control for every arm above: ``safe_exc`` by itself is a PHI pass and leaves
    this text's credentials in place, so the arms are hidden by the credential passes, not by it.
    If this goes red, ``safe_exc`` learned credentials and ``smoke._exc_detail``'s docstring is stale."""
    from messagefoundry.redaction import safe_exc

    assert _PLANTED in safe_exc(RuntimeError(_LEAKY))


def test_a_long_detail_is_bounded_after_the_credential_passes() -> None:
    """The length bound runs after the redactor, so a credential past ``safe_exc``'s usual cut is
    still read whole and the detail stays bounded."""
    padding = " ".join(["word"] * 60)
    detail = smoke._exc_detail(RuntimeError(f"{padding} password= {_PLANTED} {_LEAKY}"))
    assert _PLANTED not in detail
    assert len(detail) < 260, detail
