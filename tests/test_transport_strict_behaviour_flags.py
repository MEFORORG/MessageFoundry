# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The transports read their default-off behaviour flags strictly (vault BACKLOG #3234): at least
``no_ack``, ``persistent``, ``capture_response``, ``verify_ack_control_id``, ``dynamic_headers``
and ``overwrite``, on the destinations that carry them.

The load and the runner's builds refuse a non-bool literal on a boolean setting. A connector
constructed directly from a ``Destination``, as tests and embedders do, passes neither, and reached
these reads, where ``bool("false")`` is True: a ``persistent="false"`` kept one connection open, a
``no_ack="false"`` stopped reading the ACK. Each read now goes through ``flag_from_settings``,
which refuses anything that is not a real ``bool`` with the ``require_flag`` message. A real
``bool`` and an absent key read as before: the controls. Synthetic settings only; nothing dials."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.transports.base import DestinationConnector
from messagefoundry.transports.fhir import FhirDestination
from messagefoundry.transports.file import FileDestination
from messagefoundry.transports.mllp import MLLPDestination
from messagefoundry.transports.remotefile import RemoteFileDestination
from messagefoundry.transports.rest import RestDestination
from messagefoundry.transports.soap import SoapDestination
from messagefoundry.transports.tcp import TcpDestination
from messagefoundry.transports.x12 import X12Destination

_NON_BOOLS: list[Any] = ["false", "true", 0, 1]

Build = Callable[[Path, dict[str, Any]], DestinationConnector]


def _mllp(tmp: Path, extra: dict[str, Any]) -> DestinationConnector:
    settings = {"host": "127.0.0.1", "port": 2575, **extra}
    return MLLPDestination(Destination(name="OB_MLLP", type=ConnectorType.MLLP, settings=settings))


def _tcp(tmp: Path, extra: dict[str, Any]) -> DestinationConnector:
    settings = {
        "host": "127.0.0.1",
        "port": 9100,
        "framing": "stx_etx",
        "expect_reply": True,
        **extra,
    }
    return TcpDestination(Destination(name="OB_TCP", type=ConnectorType.TCP, settings=settings))


def _x12(tmp: Path, extra: dict[str, Any]) -> DestinationConnector:
    settings = {"host": "127.0.0.1", "port": 9200, "expect_reply": True, **extra}
    return X12Destination(Destination(name="OB_X12", type=ConnectorType.X12, settings=settings))


def _rest(tmp: Path, extra: dict[str, Any]) -> DestinationConnector:
    settings = {"url": "https://127.0.0.1/api", **extra}
    return RestDestination(Destination(name="OB_REST", type=ConnectorType.REST, settings=settings))


def _fhir(tmp: Path, extra: dict[str, Any]) -> DestinationConnector:
    settings = {"url": "https://127.0.0.1/fhir", **extra}
    return FhirDestination(Destination(name="OB_FHIR", type=ConnectorType.FHIR, settings=settings))


def _soap(tmp: Path, extra: dict[str, Any]) -> DestinationConnector:
    settings = {"url": "https://127.0.0.1/ws", "soap_action": "urn:x", **extra}
    return SoapDestination(Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=settings))


def _file(tmp: Path, extra: dict[str, Any]) -> DestinationConnector:
    settings = {"directory": str(tmp / "out"), **extra}
    return FileDestination(Destination(name="OB_FILE", type=ConnectorType.FILE, settings=settings))


def _remotefile(tmp: Path, extra: dict[str, Any]) -> DestinationConnector:
    # The flag is read before any other setting, so a config the rest of the build would refuse
    # still names the flag first.
    return RemoteFileDestination(
        Destination(name="OB_SFTP", type=ConnectorType.REMOTEFILE, settings=dict(extra))
    )


_CASES: list[tuple[str, Build, str]] = [
    ("mllp", _mllp, "persistent"),
    ("mllp", _mllp, "no_ack"),
    ("mllp", _mllp, "capture_response"),
    ("mllp", _mllp, "verify_ack_control_id"),
    ("tcp", _tcp, "persistent"),
    ("tcp", _tcp, "capture_response"),
    ("x12", _x12, "persistent"),
    ("x12", _x12, "capture_response"),
    ("rest", _rest, "capture_response"),
    ("rest", _rest, "dynamic_headers"),
    ("fhir", _fhir, "capture_response"),
    ("fhir", _fhir, "dynamic_headers"),
    ("soap", _soap, "capture_response"),
    ("file", _file, "overwrite"),
    ("remotefile", _remotefile, "overwrite"),
]
_IDS = [f"{name}-{key}" for name, _, key in _CASES]


@pytest.mark.parametrize("value", _NON_BOOLS)
@pytest.mark.parametrize(("name", "build", "key"), _CASES, ids=_IDS)
def test_a_non_bool_behaviour_flag_is_refused(
    tmp_path: Path, name: str, build: Build, key: str, value: Any
) -> None:
    """Red before: ``bool(value)`` read each of these as a flag, a truthy string as on."""
    with pytest.raises(
        ValueError, match=f"{key} must be true or false, not {type(value).__name__}"
    ):
        build(tmp_path, {key: value})


_CONTROLS = [case for case in _CASES if case[0] != "remotefile"]


@pytest.mark.parametrize("value", [True, False, None])
@pytest.mark.parametrize(
    ("name", "build", "key"), _CONTROLS, ids=[f"{n}-{k}" for n, _, k in _CONTROLS]
)
def test_a_real_bool_behaviour_flag_still_builds(
    tmp_path: Path, name: str, build: Build, key: str, value: bool | None
) -> None:
    # The control: a real bool, or an explicit None, builds as before. The MLLP reply checks need
    # an ACK to read, so no_ack=True beside them is not built.
    build(tmp_path, {key: value})
