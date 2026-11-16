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
from messagefoundry.verify import checks, runner, smoke
from messagefoundry.verify.model import CheckResult, safe_exc_detail
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
    """The engine's own wiring diagnostic is the fix an operator reads, so it is not cut at all,
    and gets no type prefix."""
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
    this text's credentials in place, so the arms are hidden by the credential pass, not by it. If
    this goes red, ``safe_exc`` learned credentials and ``model.safe_exc_detail``'s docstring is
    stale."""
    from messagefoundry.redaction import safe_exc

    assert _PLANTED in safe_exc(RuntimeError(_LEAKY))


def test_a_long_detail_is_bounded_and_a_credential_near_the_bound_hidden() -> None:
    """The detail keeps ``safe_text``'s bound, and a credential sitting just inside it is hidden. No
    order control: ``safe_text`` cuts at whole tokens, so neither order was measured to print a
    value at the cut; the credential pass runs first for the label reason in the next test."""
    exc = RuntimeError(" ".join(["word"] * 37) + f" PWD={_PLANTED}" + " tail" * 80)
    detail = safe_exc_detail(exc)
    assert _PLANTED not in detail, detail
    assert "PWD=" in detail, detail
    assert len(detail) < 260, len(detail)


@pytest.mark.parametrize(
    "label", ["Login Password", "Access Token", "Client Secret", "Bind Password"]
)
def test_a_capitalized_two_word_label_keeps_its_value_hidden(label: str) -> None:
    """The PHI name pass reads ``Login Password`` as a name. Run first, it took the label away from
    the credential pass and the value printed; the credential pass runs first now."""
    from messagefoundry.redaction import safe_exc

    exc = RuntimeError(f"{label}={_PLANTED}")
    assert _PLANTED in safe_exc(exc)  # control: the PHI pass alone keeps it
    assert _PLANTED not in safe_exc_detail(exc)


@pytest.mark.parametrize(
    "exc",
    [
        ssl.SSLCertVerificationError("certificate verify failed"),
        PermissionError(13, "Permission denied", "/var/lib/messagefoundry/messagefoundry.db"),
    ],
)
def test_the_words_an_operator_needs_survive(exc: BaseException) -> None:
    """The class name and the path stay readable. The bundle's long-base64 sweep, tried first, blanked
    both, since a 24-character run is either."""
    detail = safe_exc_detail(exc)
    assert detail.startswith(type(exc).__name__), detail
    assert str(exc) in detail, detail


def test_a_label_and_its_value_on_different_lines_are_read_together() -> None:
    text = "\n".join(["line one", "password=", f"{_PLANTED} more"])
    detail = safe_exc_detail(RuntimeError(text))
    assert _PLANTED not in detail, detail


def test_a_dry_run_error_detail_hides_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``result.error`` quotes a Router/Handler's own ``raise``, which can quote a DSN."""
    from types import SimpleNamespace

    from messagefoundry.pipeline import dryrun

    reg = Registry()
    monkeypatch.setattr(reg, "validate", lambda: None)
    result = SimpleNamespace(
        inbound="IB_X",
        disposition=SimpleNamespace(value="ERROR"),
        handlers=[],
        deliveries=[],
        error=f"router/handler error: RuntimeError: {_LEAKY}",
    )
    monkeypatch.setattr(dryrun, "dry_run", lambda *_a, **_k: result)
    r = smoke.smoke_self(str(tmp_path), graph=lambda: reg)
    _assert_hidden(r, "inbound=IB_X")


def test_lockable_accounts_store_failure_detail_hides_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same store open as ``store.connect``, so the same driver text, in a sibling row."""
    from messagefoundry.config.settings import AuthSettings

    r = checks.check_lockable_accounts(_store_that_raises(tmp_path, monkeypatch), AuthSettings())
    _assert_hidden(r, "could not read the accounts: ")


def test_the_odbc_census_reason_hides_a_config_load_credential(tmp_path: Path) -> None:
    """The run's shared config load is quoted again in the ODBC hop census, a sibling row."""
    entries, reason = runner._buildable_entries(str(tmp_path), lambda: _raise(OSError(_LEAKY)))
    assert entries == []
    assert reason is not None and "did not load" in reason
    assert _PLANTED not in reason, reason


def test_the_odbc_census_failure_reason_hides_the_credential() -> None:
    def boom() -> checks.OdbcHops:
        raise RuntimeError(_LEAKY)

    hops = checks._census(boom, "host.odbc")
    assert hops.unknown is not None and _PLANTED not in hops.unknown, hops.unknown


def test_the_graph_read_failure_reason_hides_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> object:
        raise RuntimeError(_LEAKY)

    monkeypatch.setattr(runner, "_buildable_entries", boom)
    hops = runner._driver_hops(None, None, str(tmp_path), lambda: Registry())
    assert hops.unknown is not None and "graph read raised" in hops.unknown
    assert _PLANTED not in hops.unknown, hops.unknown
