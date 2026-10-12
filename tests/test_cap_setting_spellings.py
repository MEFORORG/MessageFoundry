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
from decimal import Decimal
from fractions import Fraction
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    _NAMED_CASTS,
    MLLP,
    ConnectionSpec,
    Database,
    DatabasePoll,
    Http,
    Sftp,
    Soap,
    env,
    resolve_env_settings,
)
from messagefoundry.transports import build_destination, build_source, database, mllp
from messagefoundry.transports.base import cap_setting, positive_cap, resolve_poll_ceiling
from messagefoundry.transports.database import DatabaseLookupExecutor
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
    src = build_source(
        Source(type=ConnectorType.REMOTEFILE, settings=settings),
        egress=EgressSettings(deny_by_default=False),
    )
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
    assert getattr(build({key: "0.0"}), attr) is None, f"{key}='0.0' is zero written as text"
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
    """The SCP resolves an uncapped object size to the engine's ingress ceiling, and its inflate bound
    to the codec's inflate ceiling. ``"0"`` used to reach the inflate bound as a live zero, so
    every deflated object would have been refused while the object cap itself looked uncapped."""
    zero, string_zero = _SCP({"max_object_bytes": 0}), _SCP({"max_object_bytes": "0"})
    assert string_zero._max_object_bytes == zero._max_object_bytes
    assert string_zero._max_inflated_bytes == zero._max_inflated_bytes
    assert zero._max_inflated_bytes > 0
    with pytest.raises(ValueError, match="max_object_bytes"):
        _SCP({"max_object_bytes": -1})


_RATE = "max_messages_per_second"
_BURSTS = [
    pytest.param(_MLLP_IN, "message_burst", _RATE, "MLLP source", id="mllp-burst"),
    pytest.param(_TCP_IN, "message_burst", _RATE, "TCP source", id="tcp-burst"),
    pytest.param(_X12_IN, "message_burst", _RATE, "X12 source", id="x12-burst"),
    pytest.param(_HTTP_IN, "message_burst", _RATE, "HTTP source", id="http-burst"),
    pytest.param(
        _SCP,
        "association_burst",
        "max_associations_per_second",
        "DICOM-SCP source",
        id="scp-association-burst",
    ),
]


@pytest.mark.parametrize(("build", "key", "rate_key", "transport"), _BURSTS)
def test_a_string_zero_burst_defaults_to_the_rate_like_a_number_zero(
    build: Build, key: str, rate_key: str, transport: str
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
    # The refusal names the connector too, so a listener that stops passing its own name shows up.
    with pytest.raises(ValueError, match=f"{transport} {key}="):
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


def test_max_decompressed_members_refuses_zero_in_either_spelling() -> None:
    """The File source's gzip member cap cannot be switched off either (BACKLOG #1129): the codec's
    ``max_members`` has no ``None``. Zero in any spelling refuses; unset, ``None`` and ``""`` take the
    default rather than meaning "off"."""
    for zero in (0, "0", 0.0):
        with pytest.raises(ValueError, match="max_decompressed_members"):
            _file({"max_decompressed_members": zero})
    default = _file({}).max_decompressed_members
    assert _file({"max_decompressed_members": None}).max_decompressed_members == default
    assert _file({"max_decompressed_members": ""}).max_decompressed_members == default
    assert _file({"max_decompressed_members": "4096"}).max_decompressed_members == 4096


# === the poll ceiling ==============================================================================


def test_the_poll_ceiling_reads_a_string_zero_as_unlimited_like_the_toml_zero() -> None:
    """``resolve_poll_ceiling`` raised on ``"0"`` while a TOML ``0`` meant unlimited. Both now mean
    unlimited, the direction the TOML spelling already took. Every poll source reads it here."""
    for off in (0, "0", None, "", 0.0):
        assert resolve_poll_ceiling(off, knob="poll_max_files", transport="file source") is None
    assert resolve_poll_ceiling("25", knob="poll_max_files", transport="file source") == 25
    for bad in (-1, "-1"):
        with pytest.raises(ValueError, match="positive number of items per poll"):
            resolve_poll_ceiling(bad, knob="poll_max_files", transport="file source")
    # A fraction is not a count at all, so it is refused before the range check (BACKLOG #3431).
    with pytest.raises(ValueError, match="poll_max_files=0.5 is not a valid int value"):
        resolve_poll_ceiling(0.5, knob="poll_max_files", transport="file source")
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

    Red mutation: read the MLLP listener's receive_timeout with ``_cap_setting`` instead of
    ``positive_cap``. Its ``-1`` case builds cleanly."""
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
    """The MLLP listener reads these two caps through ``positive_cap``, so a negative is refused as
    it is on the other three listeners."""
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
    # 0.5 is not a whole count (BACKLOG #3431), and NaN, inf, "1e3", text and a list are not counts
    # at all. Each refusal must still name the setting.
    for bad in (-1, "-1", 0.5, math.nan, "1e3", "lots", [1], math.inf):
        with pytest.raises(ValueError, match="t k="):
            positive_cap(bad, int, knob="k", transport="t")
    for bad_seconds in (-0.5, "-0.5", math.nan):
        with pytest.raises(ValueError, match="t k="):
            positive_cap(bad_seconds, float, knob="k", transport="t")


# === an integer cap is a whole count (BACKLOG #3431) ==============================================


def _database(over: dict[str, Any]) -> Any:
    settings = DatabasePoll(server="db.example", database="d", poll_statement="SELECT 1").settings
    return build_source(
        Source(type=ConnectorType.DATABASE, settings={**settings, **over}),
        egress=EgressSettings(deny_by_default=False),
    )


def _database_out(over: dict[str, Any]) -> Any:
    settings = Database(
        server="db.example", database="d", statement="INSERT INTO t (a) VALUES (:a)"
    )
    return build_destination(
        Destination(
            name="OB_DB", type=ConnectorType.DATABASE, settings={**settings.settings, **over}
        ),
        egress=EgressSettings(deny_by_default=False),
    )


def _lookup(over: dict[str, Any]) -> SimpleNamespace:
    executor = DatabaseLookupExecutor(
        {"clarity": {"server": "db.example", "database": "d", **over}},
        egress=EgressSettings(deny_by_default=False),
    )
    return SimpleNamespace(pool_max=executor._pool_max["clarity"])


def _soap(over: dict[str, Any]) -> Any:
    return build_destination(
        Destination(
            name="OB_SOAP",
            type=ConnectorType.SOAP,
            settings={**Soap(url="https://api.example.com/svc").settings, **over},
        ),
        egress=EgressSettings(deny_by_default=False),
    )


#: (builder, settings key, attribute) for every cap read as an ``int`` count with a range check on top:
#: ``positive_cap``, ``resolve_poll_ceiling``, the MLLP listener's ``max_connections_per_host``, and the
#: two caps with no off switch (``max_header_bytes``, ``max_decompressed_members``).
_INT_CAPS = [
    pytest.param(_MLLP_IN, "max_connections", "max_connections", id="mllp-in-max_connections"),
    pytest.param(
        _MLLP_IN, "max_connections_per_host", "max_connections_per_host", id="mllp-in-per_host"
    ),
    pytest.param(_MLLP_IN, "max_frame_bytes", "max_frame_bytes", id="mllp-in-max_frame_bytes"),
    pytest.param(_MLLP_IN, "max_inflight_frames", "max_inflight_frames", id="mllp-in-inflight"),
    pytest.param(_MLLP_OUT, "max_frame_bytes", "max_frame_bytes", id="mllp-out-max_frame_bytes"),
    pytest.param(_TCP_IN, "max_connections", "max_connections", id="tcp-in-max_connections"),
    pytest.param(
        _TCP_IN, "max_connections_per_host", "max_connections_per_host", id="tcp-in-per_host"
    ),
    pytest.param(_TCP_IN, "max_frame_bytes", "max_frame_bytes", id="tcp-in-max_frame_bytes"),
    pytest.param(_TCP_OUT, "max_frame_bytes", "max_frame_bytes", id="tcp-out-max_frame_bytes"),
    pytest.param(_X12_IN, "max_connections", "max_connections", id="x12-in-max_connections"),
    pytest.param(
        _X12_IN, "max_connections_per_host", "max_connections_per_host", id="x12-in-per_host"
    ),
    pytest.param(
        _X12_IN, "max_interchange_bytes", "max_interchange_bytes", id="x12-in-max_interchange"
    ),
    pytest.param(
        _X12_OUT, "max_interchange_bytes", "max_interchange_bytes", id="x12-out-max_interchange"
    ),
    pytest.param(_HTTP_IN, "max_connections", "max_connections", id="http-in-max_connections"),
    pytest.param(
        _HTTP_IN, "max_connections_per_host", "max_connections_per_host", id="http-in-per_host"
    ),
    pytest.param(_HTTP_IN, "max_body_bytes", "max_body_bytes", id="http-in-max_body_bytes"),
    pytest.param(_HTTP_IN, "max_header_bytes", "max_header_bytes", id="http-in-max_header_bytes"),
    pytest.param(_file, "max_file_bytes", "max_file_bytes", id="file-max_file_bytes"),
    pytest.param(
        _file, "max_decompressed_bytes", "max_decompressed_bytes", id="file-max_decompressed"
    ),
    pytest.param(
        _file, "max_decompressed_members", "max_decompressed_members", id="file-max_members"
    ),
    pytest.param(_file, "poll_max_files", "poll_max_files", id="file-poll_max_files"),
    pytest.param(_remote, "max_file_bytes", "_max_file_bytes", id="remote-max_file_bytes"),
    pytest.param(_remote, "poll_max_files", "_poll_max_files", id="remote-poll_max_files"),
    pytest.param(_database, "poll_max_rows", "_poll_max_rows", id="database-poll_max_rows"),
    pytest.param(_SCP, "max_object_bytes", "_max_object_bytes", id="scp-max_object_bytes"),
    pytest.param(_SCU, "max_object_bytes", "_max_object_bytes", id="scu-max_object_bytes"),
]

#: Integer settings read by ``count_setting`` alone. Each was a bare ``int()`` before #3431. None has a
#: range check, so a negative is not refused here; that is a separate question for each setting.
_COUNT_ONLY = [
    pytest.param(_SCP, "max_associations", "_max_associations", id="scp-max_associations"),
    pytest.param(_SCP, "max_pdu_size", "_max_pdu_size", id="scp-max_pdu_size"),
    pytest.param(_SCU, "max_pdu_size", "_max_pdu_size", id="scu-max_pdu_size"),
    pytest.param(_database_out, "pool_max", "_pool_max", id="database-out-pool_max"),
    pytest.param(
        _database_out, "capture_max_rows", "_capture_max_rows", id="database-out-capture_rows"
    ),
    pytest.param(
        _database_out, "capture_max_bytes", "_capture_max_bytes", id="database-out-capture_bytes"
    ),
    pytest.param(_database, "pool_max", "_pool_max", id="database-in-pool_max"),
    pytest.param(_lookup, "pool_max", "pool_max", id="database-lookup-pool_max"),
    pytest.param(
        _soap, "ws_timestamp_ttl_seconds", "ws_timestamp_ttl_seconds", id="soap-timestamp_ttl"
    ),
]

_NOT_A_COUNT = [True, False, 1.9, 2048.5, 0.5, Decimal("1.9"), Fraction(19, 10), math.inf, math.nan]


@pytest.mark.parametrize(("build", "key", "attr"), _INT_CAPS + _COUNT_ONLY)
@pytest.mark.parametrize("bad", _NOT_A_COUNT)
def test_an_integer_setting_refuses_a_bool_or_a_fraction(
    build: Build, key: str, attr: str, bad: object
) -> None:
    """``int()`` turns ``True`` into 1 and ``1.9`` into 1, so before #3431 either one built a live
    cap of one byte or one connection, a cap that refuses nearly everything. Each is a typo, so each
    is a build error that names the key. A ``Decimal`` or a ``Fraction`` is held to the same rule.

    Red mutation: let ``cap_setting`` read an ``int`` cap with ``int()`` again, or put a bare
    ``int()`` back on any ``_COUNT_ONLY`` site. That site's ``True``, ``1.9``, ``Decimal`` and
    ``Fraction`` cases build cleanly."""
    del attr
    with pytest.raises(ValueError, match=f"{key}=.* is not a valid int value"):
        build({key: bad})


@pytest.mark.parametrize(("build", "key", "attr"), _INT_CAPS)
def test_an_integer_cap_still_refuses_a_negative(build: Build, key: str, attr: str) -> None:
    """The range check on top of the count rule still runs on every ``_INT_CAPS`` site."""
    del attr
    with pytest.raises(ValueError, match=key):
        build({key: -1})


@pytest.mark.parametrize(("build", "key", "attr"), _INT_CAPS + _COUNT_ONLY)
def test_an_integer_setting_accepts_a_whole_number_and_padded_text(
    build: Build, key: str, attr: str
) -> None:
    """The control for the refusal above: a TOML ``2048.0`` is a whole count, and so is a whole
    ``Decimal``. An uncast ``env()`` reference hands over text such as ``" 7 "`` or ``"+5"``, which
    ``int()`` reads."""
    assert getattr(build({key: 2048.0}), attr) == 2048
    assert getattr(build({key: Decimal("4096")}), attr) == 4096
    assert getattr(build({key: " 7 "}), attr) == 7
    assert getattr(build({key: "+5"}), attr) == 5


async def test_the_reference_sync_pool_size_is_a_count(monkeypatch: pytest.MonkeyPatch) -> None:
    """A DATABASE reference source reads ``pool_max`` by the same rule, before any pool is made."""
    from messagefoundry.pipeline.reference_sync import _load_database_source

    made: list[object] = []

    async def _no_pool(*args: object, **kwargs: object) -> object:
        made.append(args)
        raise AssertionError("the pool size should have been refused before a pool was made")

    monkeypatch.setattr(database, "_make_pool", _no_pool)
    base = {"server": "db.example", "database": "d", "statement": "SELECT a", "key_column": "a"}
    for bad in (True, 1.9, Decimal("1.9"), Fraction(19, 10)):
        with pytest.raises(ValueError, match="reference source pool_max=.* is not a valid int"):
            await _load_database_source(
                {**base, "pool_max": bad}, EgressSettings(deny_by_default=False)
            )
    assert made == []


def _from_spec(spec: ConnectionSpec) -> Any:
    return build_source(
        Source(type=spec.type, settings=spec.settings),
        egress=EgressSettings(deny_by_default=False),
    )


def test_the_reachable_spellings_are_refused_end_to_end() -> None:
    """A ``connections.toml`` literal ``1.9`` or ``true`` on an integer key never reaches a connector:
    ``_check_setting_types`` refuses it at load. Two routes do reach one, and both are pinned here.

    A code-first factory call passes its keyword straight into the settings, and an ``env()``
    reference cast to ``float`` or ``bool`` hands the connector exactly that type. A config module
    is not type-checked, so the fraction is passed untyped, as one would arrive there."""
    fraction: Any = 1.9
    with pytest.raises(ValueError, match="max_frame_bytes"):
        _from_spec(MLLP(port=0, max_frame_bytes=fraction))
    with pytest.raises(ValueError, match="max_header_bytes"):
        _from_spec(Http(port=0, max_header_bytes=True))
    for cast, raw in ((float, "1.9"), (_NAMED_CASTS["bool"], "true"), (_NAMED_CASTS["bool"], "0")):
        settings = resolve_env_settings(
            {"port": 0, "max_connections": env("cap", cast=cast)}, {"cap": raw}
        )
        with pytest.raises(ValueError, match="max_connections"):
            _TCP_IN({**settings, "framing": "stx_etx"})


def test_the_bool_refusal_says_why() -> None:
    """The message tells the operator what is wrong, not only which key."""
    with pytest.raises(ValueError, match="a count is not a bool"):
        positive_cap(True, int, knob="k", transport="t")
    with pytest.raises(ValueError, match="whole number"):
        positive_cap(1.9, int, knob="k", transport="t")
    with pytest.raises(ValueError, match="whole number"):
        positive_cap(Decimal("1.9"), int, knob="k", transport="t")
    # A float cap is not a count, so a fraction is the whole point of it.
    assert positive_cap(1.9, float, knob="k", transport="t") == 1.9


_FLOAT_CAPS = [
    pytest.param(_MLLP_IN, "receive_timeout", id="mllp-in-receive_timeout"),
    pytest.param(_MLLP_IN, "max_frame_seconds", id="mllp-in-max_frame_seconds"),
    pytest.param(_MLLP_IN, "max_messages_per_second", id="mllp-rate"),
    pytest.param(_TCP_OUT, "idle_timeout_seconds", id="tcp-out-idle"),
    pytest.param(_SCP, "max_associations_per_second", id="scp-association-rate"),
]


@pytest.mark.parametrize(("build", "key"), _FLOAT_CAPS)
@pytest.mark.parametrize("bad", [True, False])
def test_a_float_cap_refuses_a_bool(build: Build, key: str, bad: bool) -> None:
    """``float(True)`` is 1.0, so a bool built a one-second timeout or a rate of one per second, and
    ``False`` read as "off". Neither is what a bool means here, so both are refused, naming the key.

    Red mutation: drop the bool refusal from ``cap_setting``'s float path. Every case builds."""
    with pytest.raises(ValueError, match=f"{key}={bad!r} is not a valid float value"):
        build({key: bad})
