# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3099, item 1: N listeners sharing one stale CRL log one warning, not N.

A held copy of a CRL is matched by its file, so every row naming the file judges the same copies.
Each row logged the scan's whole account of them: N listeners sharing one CRL file gave N warnings
per pass, each listing the same N holders. The pass now logs that account once per file, and the
one line names the other rows.

Only the log line is folded. Each row still raises its own ``crl_expiry`` alert with its own
``detail`` and ``shared_with`` (vault BACKLOG #2319), and the tests below pin that beside the count.

The instrument is the scan itself: real MLLP listener contexts built by ``_mllp_ssl_context``, the
rows ``certs_from_registry`` reads from a real ``Registry``, one ``run_once``, and the WARNING
records of ``messagefoundry.pipeline.cert_expiry`` that name the file.

Run against ``cert_expiry.py`` as it stood before the fix, four tests fail: the three-listener
count, the count on each of two passes, the two-file count, and the file replaced part way through
a pass. The other three pass before and after, as their comments say.

All material is synthetic and minted here. No PHI.
"""

from __future__ import annotations

import hashlib
import logging
import ssl
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from messagefoundry.config.settings import CertMonitorSettings
from messagefoundry.config.wiring import MLLP, InboundConnection, Registry
from messagefoundry.pipeline.cert_expiry import CertExpiryRunner, certs_from_registry
from messagefoundry.transports.mllp import _mllp_ssl_context
from tests.test_cert_expiry import _RecordingSink
from tests.test_crl_bundle_anchors import (  # noqa: F401 - clean_anchor_checks is a fixture
    _make_ca,
    clean_anchor_checks,
)
from tests.test_crl_held_copy_alert import _another_ca, _Ca, _mine

pytestmark = pytest.mark.usefixtures("clean_anchor_checks")

_HELD = "still holds a copy of"
_ALSO = "The same file also serves"


@pytest.fixture
def ca() -> _Ca:
    return _another_ca("mefor-3099-ca")


def _scan(
    registry: Registry, caplog: pytest.LogCaptureFixture, sink: _RecordingSink | None = None
) -> _RecordingSink:
    """One pass over the registry's rows, leaving only that pass's records in ``caplog``."""
    sink = sink or _RecordingSink()
    runner = CertExpiryRunner(
        lambda: certs_from_registry(registry, None),
        CertMonitorSettings(warn_days=30),
        alert_sink=sink,
    )
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.cert_expiry"):
        runner.run_once(now=time.time())
    return sink


@dataclass
class _Site:
    """N MLLP listeners that all name one CRL file, built on its first version."""

    registry: Registry
    crl: Path
    names: list[str]
    contexts: list[ssl.SSLContext]  # kept, so each listener's held copy stays alive

    def lines(self, caplog: pytest.LogCaptureFixture) -> list[str]:
        """The held-copy warnings in ``caplog`` that name this site's file."""
        messages = [r.getMessage() for r in caplog.records]
        return [m for m in messages if _HELD in m and str(self.crl) in m]


def _site(ca: _Ca, d: Path, count: int, *, prefix: str = "IB_SITE") -> _Site:
    """``count`` listeners sharing one CRL file that has since been replaced, so each holds the
    old copy: the stale state the monitor warns about."""
    d.mkdir(exist_ok=True)
    # A leaf and key for the listeners to present. The CA under test signs only the CRLs.
    identity = _make_ca(d, f"{prefix.lower()}-identity")
    ca_file = d / "client-ca.pem"
    ca_file.write_bytes(ca.pem)
    crl = d / "shared-crl.pem"
    crl.write_bytes(ca.crl(days=5.5, number=1))
    registry = Registry()
    names = [f"{prefix}{i}_ADT" for i in range(1, count + 1)]
    contexts: list[ssl.SSLContext] = []
    for port, name in enumerate(names, start=2575):
        spec = MLLP(
            port=port,
            tls=True,
            tls_cert_file=identity.leaf,
            tls_key_file=identity.leaf_key,
            tls_ca_file=str(ca_file),
            tls_ca_pin=hashlib.sha256(ca.pem).hexdigest(),
            tls_crl_file=str(crl),
        )
        registry.inbound[name] = InboundConnection(name=name, spec=spec, router="r")
        ctx = _mllp_ssl_context(spec.settings, server=True, name=name)
        assert ctx is not None and ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
        contexts.append(ctx)
    crl.write_bytes(ca.crl(days=90, number=2))  # the refresh no listener has taken yet
    return _Site(registry, crl, names, contexts)


def _holder(name: str) -> str:
    """How a listener's held copy is named: the setting its context loaded the CRL from."""
    return f"inbound connection '{name}' tls_crl_file"


def test_three_listeners_sharing_one_stale_crl_log_one_warning(
    ca: _Ca, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # THE DEFECT. Before the fix this pass logged three warnings, one per row, and each listed all
    # three holders: nine names where three say it.
    site = _site(ca, tmp_path, 3)

    _scan(site.registry, caplog)

    lines = site.lines(caplog)
    assert len(lines) == 1
    (line,) = lines
    assert "(3 load(s), from " in line
    for name in site.names:
        assert line.count(_holder(name)) == 1  # each listener holding the copy, once
    # The row the line is logged under leads; the line names the other two after it, once each.
    first, *others = site.names
    assert f"a copy of {first!r} CRL {site.crl} " in line
    assert line.endswith(f"{_ALSO} {', '.join(map(repr, others))}.")


def test_the_alerts_are_still_one_per_listener(
    ca: _Ca, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Only the log is folded. Vault BACKLOG #2319 reports a held copy under every row naming its
    # file, each with the other rows in shared_with and the holders in its detail. This passes
    # before and after the fix.
    site = _site(ca, tmp_path, 3)

    sink = _scan(site.registry, caplog)

    mine = _mine(sink, site.crl)
    assert [sink.crl_calls[i][0] for i in mine] == site.names
    assert [sink.crl_calls[i][3] for i in mine] == [5, 5, 5]  # the held copy's days, on each
    for i, name in zip(mine, site.names, strict=True):
        held_copy, detail, shared_with = sink.crl_notes[i]
        assert held_copy is True
        assert shared_with == tuple(n for n in site.names if n != name)
        assert detail.startswith("A reload is pending")
        assert all(_holder(n) in detail for n in site.names)


def test_control_one_listener_logs_one_warning_that_names_no_other_row(
    ca: _Ca, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # THE CONTROL. One listener, one row, one warning, before and after the fix: so the count
    # above comes from the sharing, and the fold does not swallow a file's only line.
    site = _site(ca, tmp_path, 1)

    sink = _scan(site.registry, caplog)

    lines = site.lines(caplog)
    assert len(lines) == 1
    assert "(1 load(s), from " in lines[0]
    assert lines[0].count(_holder(site.names[0])) == 1
    assert _ALSO not in lines[0]
    assert lines[0].endswith("logs why.")  # the line as it was, with nothing added
    assert len(_mine(sink, site.crl)) == 1


def test_each_pass_logs_the_warning_again(
    ca: _Ca, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The fold is per pass, not per process: while the listeners hold the old copy, every pass
    # still says so. Before the fix each pass logged three lines.
    site = _site(ca, tmp_path, 3)

    _scan(site.registry, caplog)
    first = site.lines(caplog)
    _scan(site.registry, caplog)
    second = site.lines(caplog)

    assert (len(first), len(second)) == (1, 1)


def test_two_stale_crl_files_log_one_warning_each(
    ca: _Ca, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The fold is per file. Two pairs of listeners on two files: one line for each file, naming
    # that file's own listeners and not the other's. Before the fix this was two lines per file.
    east = _site(ca, tmp_path / "east", 2, prefix="IB_EAST")
    west = _site(ca, tmp_path / "west", 2, prefix="IB_WEST")
    registry = Registry()
    registry.inbound.update(east.registry.inbound)
    registry.inbound.update(west.registry.inbound)

    _scan(registry, caplog)

    east_lines, west_lines = east.lines(caplog), west.lines(caplog)
    assert (len(east_lines), len(west_lines)) == (1, 1)
    assert east_lines[0].endswith(f"{_ALSO} 'IB_EAST2_ADT'.")
    assert west_lines[0].endswith(f"{_ALSO} 'IB_WEST2_ADT'.")
    assert "IB_WEST" not in east_lines[0] and "IB_EAST" not in west_lines[0]


class _ReplacingSink(_RecordingSink):
    """Makes the CRL file unparseable when the first row's alert arrives, so the rows after it
    read other bytes: a file replaced part way through a pass."""

    def __init__(self, crl: Path) -> None:
        super().__init__()
        self._crl = crl

    def crl_expiry(
        self,
        name: str,
        *,
        path: str,
        not_after: str,
        days_remaining: int,
        held_copy: bool = False,
        detail: str = "",
        shared_with: tuple[str, ...] = (),
    ) -> None:
        super().crl_expiry(
            name,
            path=path,
            not_after=not_after,
            days_remaining=days_remaining,
            held_copy=held_copy,
            detail=detail,
            shared_with=shared_with,
        )
        self._crl.write_bytes(b"not a CRL\n")


def test_a_file_replaced_part_way_through_a_pass_is_logged_again(
    ca: _Ca, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Each row reads the file itself. The first row finds a pending reload; the file then changes
    # and the second finds one it cannot parse. That is another account of the file, so the fold
    # must not swallow it: it is logged, once, and the third row's copy of it is folded. Before the
    # fix this pass logged three lines.
    site = _site(ca, tmp_path, 3)

    _scan(site.registry, caplog, _ReplacingSink(site.crl))

    lines = site.lines(caplog)
    assert len(lines) == 2
    assert "A reload is pending" in lines[0]
    assert "whose file cannot be parsed" in lines[1]
    assert f"a copy of {site.names[1]!r} CRL " in lines[1]


def test_a_failure_grouping_the_rows_folds_nothing(
    ca: _Ca, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The one line names the other rows from the grouping. With no grouping (BACKLOG #3176 keeps
    # the scan going past that failure) the pass cannot name them, so it folds nothing and each row
    # logs its own line, as before the fix. A quieter log must not cost a row its only mention.
    site = _site(ca, tmp_path, 3)

    def _broken(rows: object) -> dict[str, tuple[str, ...]]:
        raise RuntimeError("synthetic grouping failure")

    monkeypatch.setattr("messagefoundry.pipeline.cert_expiry._rows_by_crl_file", _broken)

    sink = _scan(site.registry, caplog)

    lines = site.lines(caplog)
    assert len(lines) == 3
    for line, name in zip(lines, site.names, strict=True):
        assert f"a copy of {name!r} CRL " in line
        assert _ALSO not in line
    assert len(_mine(sink, site.crl)) == 3
