# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A cap written as ``"0"`` must mean what the same cap written as ``0`` means (BACKLOG #1872).

A ``connections.toml`` ``env()`` reference without a ``cast`` hands a connector the environment's TEXT,
so an operator disabling a cap through the environment writes ``"0"``. The old idiom
``int(v) if v else None`` tested the RAW value, and a non-empty string is truthy, so ``"0"`` became a
live cap of zero: a listener that refused every connection, rejected every frame, or closed every
socket at once. Engine PR 1309 fixed that on the MLLP listener with ``_cap_setting``; this file pins
the same rule at every other site, one parametrized case per setting rather than one per module,
because the sites were individually wrong.

It also pins the second, separate defect in the family: nothing refused a negative value, so a
``receive_timeout`` of ``-1`` made every peer look idle the instant it connected. That is an absent
range check, not a coercion asymmetry, and it has its own tests below.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import Sftp
from messagefoundry.transports import build_source, mllp
from messagefoundry.transports.base import cap_setting, positive_cap, resolve_poll_ceiling
from messagefoundry.transports.dicom import DicomScpSource, DicomScuDestination
from messagefoundry.transports.file import FileSource
from messagefoundry.transports.http_listener import DEFAULT_MAX_HEADER_BYTES, HttpSource
from messagefoundry.transports.mllp import MLLPDestination, MLLPSource
from messagefoundry.transports.remotefile import RemoteFileSource
from messagefoundry.transports.tcp import TcpDestination, TcpSource
from messagefoundry.transports.x12 import X12Destination, X12Source

Build = Callable[[dict[str, Any]], Any]


def _src(ctype: ConnectorType, cls: type[Any], base: dict[str, Any]) -> Build:
    return lambda over: cls(Source(type=ctype, settings={**base, **over}))


def _dst(ctype: ConnectorType, cls: type[Any], base: dict[str, Any]) -> Build:
    return lambda over: cls(Destination(name="OB_TEST", type=ctype, settings={**base, **over}))


def _file(over: dict[str, Any]) -> FileSource:
    return FileSource(Source(type=ConnectorType.FILE, settings={"directory": "unused", **over}))


def _remote(over: dict[str, Any]) -> RemoteFileSource:
    settings = {**Sftp(host="sftp.example.com", remote_dir="/in").settings, **over}
    src = build_source(Source(type=ConnectorType.REMOTEFILE, settings=settings))
    assert isinstance(src, RemoteFileSource)
    return src


_LOOPBACK = {"host": "127.0.0.1", "port": 1}
_MLLP_IN = _src(ConnectorType.MLLP, MLLPSource, {"port": 0})
_MLLP_OUT = _dst(ConnectorType.MLLP, MLLPDestination, _LOOPBACK)
_TCP_IN = _src(ConnectorType.TCP, TcpSource, {"port": 0, "framing": "stx_etx"})
_TCP_OUT = _dst(ConnectorType.TCP, TcpDestination, {**_LOOPBACK, "framing": "stx_etx"})
_X12_IN = _src(ConnectorType.X12, X12Source, {"port": 0})
_X12_OUT = _dst(ConnectorType.X12, X12Destination, _LOOPBACK)
_HTTP_IN = _src(ConnectorType.HTTP, HttpSource, {"port": 0})
_SCP = _src(ConnectorType.DIMSE, DicomScpSource, {"ae_title": "MEFOR_SCP", "port": 0})
_SCU = _dst(ConnectorType.DIMSE, DicomScuDestination, {**_LOOPBACK, "ae_title": "MEFOR_SCU"})

#: (builder, settings key, attribute the connector reads it into). Every entry documents ``None``/``0``
#: as "disabled" and reads a disabled cap as ``None``.
_OFF_BY_ZERO = [
    # counts
    pytest.param(_TCP_IN, "max_connections", "max_connections", id="tcp-in-max_connections"),
    pytest.param(_X12_IN, "max_connections", "max_connections", id="x12-in-max_connections"),
    pytest.param(_HTTP_IN, "max_connections", "max_connections", id="http-in-max_connections"),
    # bytes
    pytest.param(_TCP_IN, "max_frame_bytes", "max_frame_bytes", id="tcp-in-max_frame_bytes"),
    pytest.param(_TCP_OUT, "max_frame_bytes", "max_frame_bytes", id="tcp-out-max_frame_bytes"),
    pytest.param(_MLLP_OUT, "max_frame_bytes", "max_frame_bytes", id="mllp-out-max_frame_bytes"),
    pytest.param(
        _X12_IN, "max_interchange_bytes", "max_interchange_bytes", id="x12-in-max_interchange"
    ),
    pytest.param(
        _X12_OUT, "max_interchange_bytes", "max_interchange_bytes", id="x12-out-max_interchange"
    ),
    pytest.param(_HTTP_IN, "max_body_bytes", "max_body_bytes", id="http-in-max_body_bytes"),
    pytest.param(_file, "max_file_bytes", "max_file_bytes", id="file-max_file_bytes"),
    pytest.param(
        _file, "max_decompressed_bytes", "max_decompressed_bytes", id="file-max_decompressed"
    ),
    pytest.param(_remote, "max_file_bytes", "_max_file_bytes", id="remote-max_file_bytes"),
    pytest.param(_SCU, "max_object_bytes", "_max_object_bytes", id="scu-max_object_bytes"),
    # seconds
    pytest.param(_TCP_IN, "receive_timeout", "receive_timeout", id="tcp-in-receive_timeout"),
    pytest.param(_X12_IN, "receive_timeout", "receive_timeout", id="x12-in-receive_timeout"),
    pytest.param(_HTTP_IN, "receive_timeout", "receive_timeout", id="http-in-receive_timeout"),
    pytest.param(_MLLP_OUT, "idle_timeout_seconds", "idle_timeout_seconds", id="mllp-out-idle"),
    pytest.param(_TCP_OUT, "idle_timeout_seconds", "idle_timeout_seconds", id="tcp-out-idle"),
    pytest.param(_X12_OUT, "idle_timeout_seconds", "idle_timeout_seconds", id="x12-out-idle"),
    pytest.param(
        _MLLP_OUT, "max_connection_age_seconds", "max_connection_age_seconds", id="mllp-out-age"
    ),
    pytest.param(
        _TCP_OUT, "max_connection_age_seconds", "max_connection_age_seconds", id="tcp-out-age"
    ),
    pytest.param(
        _X12_OUT, "max_connection_age_seconds", "max_connection_age_seconds", id="x12-out-age"
    ),
    # rates
    pytest.param(_MLLP_IN, "max_messages_per_second", "max_messages_per_second", id="mllp-rate"),
    pytest.param(_TCP_IN, "max_messages_per_second", "max_messages_per_second", id="tcp-rate"),
    pytest.param(_X12_IN, "max_messages_per_second", "max_messages_per_second", id="x12-rate"),
    pytest.param(_HTTP_IN, "max_messages_per_second", "max_messages_per_second", id="http-rate"),
    pytest.param(
        _SCP,
        "max_associations_per_second",
        "max_associations_per_second",
        id="scp-association-rate",
    ),
]


@pytest.mark.parametrize(("build", "key", "attr"), _OFF_BY_ZERO)
def test_a_string_zero_disables_the_cap_exactly_as_a_number_zero_does(
    build: Build, key: str, attr: str
) -> None:
    """``"0"``, ``0`` and ``None`` all read as disabled, and the empty string an unset env var yields.

    Red mutation: restore ``int(v) if v else None`` at any one site. Its ``"0"`` case becomes a live
    cap of zero and only that site's case reds, which is why this is parametrized per setting."""
    assert getattr(build({key: 0}), attr) is None
    assert getattr(build({key: "0"}), attr) is None, f"{key}='0' became a live cap of zero"
    assert getattr(build({key: None}), attr) is None
    assert getattr(build({key: ""}), attr) is None
    # The control: the same key really is read into that attribute when it is a live value.
    assert getattr(build({key: "7"}), attr) == 7


@pytest.mark.parametrize(("build", "key", "attr"), _OFF_BY_ZERO)
def test_a_negative_cap_is_refused_at_build(build: Build, key: str, attr: str) -> None:
    """A negative cap refuses all traffic, which nobody means. It is a build error, not a running
    connection that accepts nothing. ``attr`` is unused here; the table is shared on purpose."""
    del attr
    with pytest.raises(ValueError, match=key):
        build({key: -1})
    with pytest.raises(ValueError, match=key):
        build({key: "-1"})


def test_the_dicom_scp_object_cap_reads_a_string_zero_as_uncapped() -> None:
    """The SCP resolves an uncapped object size to the engine's ingress ceiling and keeps the
    configured value for its inflate bound. ``"0"`` used to reach the inflate bound as a live zero, so
    every deflated object would have been refused while the object cap itself looked uncapped."""
    zero, string_zero = _SCP({"max_object_bytes": 0}), _SCP({"max_object_bytes": "0"})
    assert string_zero._max_object_bytes == zero._max_object_bytes
    assert string_zero._max_inflated_bytes == zero._max_inflated_bytes
    assert zero._max_inflated_bytes > 0
    with pytest.raises(ValueError, match="max_object_bytes"):
        _SCP({"max_object_bytes": -1})


_BURSTS = [
    pytest.param(_MLLP_IN, "message_burst", "max_messages_per_second", id="mllp-burst"),
    pytest.param(_TCP_IN, "message_burst", "max_messages_per_second", id="tcp-burst"),
    pytest.param(_X12_IN, "message_burst", "max_messages_per_second", id="x12-burst"),
    pytest.param(_HTTP_IN, "message_burst", "max_messages_per_second", id="http-burst"),
    pytest.param(
        _SCP, "association_burst", "max_associations_per_second", id="scp-association-burst"
    ),
]


@pytest.mark.parametrize(("build", "key", "rate_key"), _BURSTS)
def test_a_string_zero_burst_defaults_to_the_rate_like_a_number_zero(
    build: Build, key: str, rate_key: str
) -> None:
    """A burst of ``0`` means "one second's worth", the rate. A string ``"0"`` used to become a burst
    of zero, which the pacer floors to one, so every burst past one message was paced.

    Red mutation: restore ``float(v or rate or 0.0)`` for the burst. The ``"0"`` case reads 0.0."""
    burst_attr = key
    zero = build({rate_key: 100, key: 0})
    string_zero = build({rate_key: 100, key: "0"})
    assert getattr(zero, burst_attr) == 100.0
    assert getattr(string_zero, burst_attr) == 100.0
    assert getattr(build({rate_key: 100, key: "7"}), burst_attr) == 7.0  # the control
    with pytest.raises(ValueError, match=key):
        build({rate_key: 100, key: -1})


# === max_header_bytes: a cap with no "off" =========================================================


def test_max_header_bytes_refuses_zero_in_either_spelling() -> None:
    """This one cap cannot be switched off. Before #1872 a TOML ``0`` silently became the 64 KiB
    default while a string ``"0"`` became a cap of zero that refused every request, so one number had
    two outcomes. Both now refuse loudly, because an operator who writes 0 means "no cap", which this
    listener does not offer. Unset, ``None`` and ``""`` still take the default."""
    for zero in (0, "0", 0.0):
        with pytest.raises(ValueError, match="max_header_bytes"):
            _HTTP_IN({"max_header_bytes": zero})
    for bad in (-1, "-1", 0.5):
        with pytest.raises(ValueError, match="max_header_bytes"):
            _HTTP_IN({"max_header_bytes": bad})
    assert _HTTP_IN({}).max_header_bytes == DEFAULT_MAX_HEADER_BYTES
    assert _HTTP_IN({"max_header_bytes": None}).max_header_bytes == DEFAULT_MAX_HEADER_BYTES
    assert _HTTP_IN({"max_header_bytes": ""}).max_header_bytes == DEFAULT_MAX_HEADER_BYTES
    assert _HTTP_IN({"max_header_bytes": "4096"}).max_header_bytes == 4096


# === the poll ceiling ==============================================================================


def test_the_poll_ceiling_reads_a_string_zero_as_unlimited_like_the_toml_zero() -> None:
    """``resolve_poll_ceiling`` raised on ``"0"`` while a TOML ``0`` meant unlimited. Both now mean
    unlimited, the direction the TOML spelling already took. Every poll source reads it here."""
    for off in (0, "0", None, "", 0.0):
        assert resolve_poll_ceiling(off, knob="poll_max_files", transport="file source") is None
    assert resolve_poll_ceiling("25", knob="poll_max_files", transport="file source") == 25
    for bad in (-1, "-1", 0.5):
        with pytest.raises(ValueError, match="positive number of items per poll"):
            resolve_poll_ceiling(bad, knob="poll_max_files", transport="file source")
    assert _file({"poll_max_files": "0"}).poll_max_files is None


# === a negative receive_timeout, on every listener =================================================

_LISTENERS = [
    pytest.param(_MLLP_IN, id="mllp"),
    pytest.param(_TCP_IN, id="tcp"),
    pytest.param(_X12_IN, id="x12"),
    pytest.param(_HTTP_IN, id="http"),
]


@pytest.mark.parametrize("build", _LISTENERS)
@pytest.mark.parametrize("bad", [-1, -0.5, "-1", math.nan])
def test_a_negative_or_nan_receive_timeout_is_refused_at_build(build: Build, bad: object) -> None:
    """A negative idle bound made every peer look idle the moment it connected, so the listener closed
    each one as an idle timeout. NaN is refused with it: every comparison with NaN is false, so it
    could not be recognised as off and would fire a bare ``wait_for`` at once.

    Red mutation: drop the MLLP listener's receive_timeout guard. Its ``-1`` case builds cleanly."""
    with pytest.raises(ValueError, match="receive_timeout"):
        build({"receive_timeout": bad})


@pytest.mark.parametrize("build", _LISTENERS)
def test_a_positive_receive_timeout_still_builds(build: Build) -> None:
    """The control for the refusal above: a guard that refused everything would pass it."""
    assert build({"receive_timeout": 0.25}).receive_timeout == 0.25
    assert build({"receive_timeout": "0"}).receive_timeout is None


@pytest.mark.parametrize(
    ("key", "attr"),
    [("max_connections", "max_connections"), ("max_frame_bytes", "max_frame_bytes")],
)
def test_the_mllp_listener_refuses_its_other_negative_caps(key: str, attr: str) -> None:
    """The MLLP listener's call sites are unchanged; its guard block now refuses a negative on the two
    caps that had none, so it matches the other three listeners."""
    with pytest.raises(ValueError, match=key):
        _MLLP_IN({key: -1})
    assert getattr(_MLLP_IN({key: "0"}), attr) is None


# === the shared helpers ============================================================================


def test_mllp_reads_the_shared_cap_helper_rather_than_a_copy() -> None:
    """Moving the helper must not leave MLLP on a private copy that can drift from the shared one."""
    # vars() because strict mypy does not treat an `import ... as _name` as an explicit re-export.
    assert vars(mllp)["_cap_setting"] is cap_setting


def test_positive_cap_refuses_what_is_left_after_zero_reads_as_off() -> None:
    assert positive_cap("0", int, knob="k", transport="t") is None
    assert positive_cap(" 0 ", float, knob="k", transport="t") is None
    assert positive_cap("3", int, knob="k", transport="t") == 3
    # 0.5 truncates to an int cap of zero, which refuses everything; NaN, "1e3" and text fail inside
    # int() itself, and must still name the setting.
    for bad in (-1, "-1", 0.5, math.nan, "1e3", "lots"):
        with pytest.raises(ValueError, match="t k="):
            positive_cap(bad, int, knob="k", transport="t")
    for bad_seconds in (-0.5, "-0.5", math.nan):
        with pytest.raises(ValueError, match="t k="):
            positive_cap(bad_seconds, float, knob="k", transport="t")
