# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2774: ``poll_seconds`` is refused at build unless it is a finite number above zero.

The File, RemoteFile and Database sources used it as the wait timeout between scans with a bare
``float(...)``, so zero or a negative value made every wait end at once and the scan loop spin, and
on the File source it also shrank the settle window to nothing. Each source now refuses zero, a
negative value, NaN, infinity and text that is not a number, naming the setting.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import DatabasePoll, Sftp
from messagefoundry.transports import build_source, remotefile
from messagefoundry.transports.base import poll_interval

_EGRESS = EgressSettings(deny_by_default=False)


def _file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: Any) -> Any:
    settings: dict[str, Any] = {"directory": str(tmp_path)}
    if value is not _ABSENT:
        settings["poll_seconds"] = value
    return build_source(Source(type=ConnectorType.FILE, settings=settings), egress=_EGRESS)


def _remote(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: Any) -> Any:
    monkeypatch.setattr(remotefile, "_make_client", lambda settings, **_: object())
    settings = dict(Sftp(host="sftp.example.com", remote_dir="/in").settings)
    settings.pop("poll_seconds")
    if value is not _ABSENT:
        settings["poll_seconds"] = value
    return build_source(Source(type=ConnectorType.REMOTEFILE, settings=settings), egress=_EGRESS)


def _database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: Any) -> Any:
    settings = dict(
        DatabasePoll(
            server="sql.example.com",
            database="MFDB",
            poll_statement="SELECT id, payload FROM mf_inbox WHERE status='NEW'",
            body_column="payload",
        ).settings
    )
    settings.pop("poll_seconds")
    if value is not _ABSENT:
        settings["poll_seconds"] = value
    return build_source(Source(type=ConnectorType.DATABASE, settings=settings), egress=_EGRESS)


_ABSENT = object()
_SOURCES: dict[str, tuple[Callable[..., Any], str, float]] = {
    "file": (_file, "poll_seconds", 1.0),
    "remotefile": (_remote, "_poll_seconds", 5.0),
    "database": (_database, "_poll_seconds", 5.0),
}


@pytest.mark.parametrize("source", list(_SOURCES))
@pytest.mark.parametrize(
    "value",
    [0, 0.0, -1, -0.5, math.nan, math.inf, "0", "nan", "soon"],
    ids=[
        "zero",
        "zero-float",
        "negative",
        "negative-float",
        "nan",
        "inf",
        "zero-text",
        "nan-text",
        "not-a-number",
    ],
)
def test_a_poll_interval_that_is_not_a_finite_positive_number_is_refused(
    source: str, value: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build, _, _ = _SOURCES[source]
    with pytest.raises(ValueError, match="poll_seconds="):
        build(tmp_path, monkeypatch, value)


@pytest.mark.parametrize("source", list(_SOURCES))
def test_a_positive_interval_and_the_default_are_accepted(
    source: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CONTROL: the refusal is not refusing everything, and text from an uncast env() still reads."""
    build, attr, default = _SOURCES[source]
    assert getattr(build(tmp_path, monkeypatch, _ABSENT), attr) == default
    assert getattr(build(tmp_path, monkeypatch, 0.01), attr) == 0.01
    assert getattr(build(tmp_path, monkeypatch, "2.5"), attr) == 2.5


def test_the_refusal_names_the_source_and_says_what_is_wanted() -> None:
    with pytest.raises(ValueError) as caught:
        poll_interval({"poll_seconds": 0}, default=1.0, transport="file source")
    assert str(caught.value) == (
        "file source poll_seconds=0 must be a finite number of seconds above zero"
    )
