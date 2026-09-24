# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The per-connection ``tls_revocation_attested`` escape has an authoring surface, both directions.

Owner ruling 2026-09-24 on PR 1502 (ADR 0173 §1.5 item 4, "Attestation escape, both directions").
The field sat on ``Source`` and ``Destination`` with no ``inbound()``/``outbound()`` parameter and no
``connections.toml`` key, so an operator could not set it, and on the inbound side ``_source_config``
never populated it -- ``check_inbound_revocation``'s attested branch was unreachable in production.

Built the way ADR 0153's ``cleartext_accepted`` + ``cleartext_reason`` are: a TOP-LEVEL key on the
connection (not a transport setting), a required ``tls_revocation_attested_reason``, validated once in
the shared ``build_*_connection`` choke point, and audited where it suppresses a would-be refusal.

Every test here drives a real authoring surface -- a config module through ``load_config`` or a
``connections.toml`` through ``load_connections_file`` -- and then the runner's own model builder, so
"reaches the model" means what a running engine would see, not what a hand-built model says.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.tls_policy import HopPosture, RevocationHopGuard
from messagefoundry.config.wiring import Registry, WiringError, load_config
from messagefoundry.pipeline.wiring_runner import (
    _dest_config,
    _source_config,
    check_inbound_revocation,
)

_REASON = "partner PKI runs OCSP at the site edge (ticket SEC-114)"
_ENFORCING = HopPosture(enforcing=True)

# An mTLS MLLP listener (a CA is loaded, so client certificates are required) and a verifying https
# outbound. Paths are never opened: loading the graph and building the models reads settings only.
_MTLS_MLLP = (
    'MLLP(port=15099, tls=True, tls_cert_file="c.pem", tls_key_file="k.pem", tls_ca_file="ca.pem")'
)


def _code_first(tmp_path: Path, *, ib_kwargs: str = "", ob_kwargs: str = "") -> Registry:
    (tmp_path / "graph.py").write_text(
        f"""
from messagefoundry import MLLP, Rest, Send, handler, inbound, outbound, router

inbound("IB", {_MTLS_MLLP}, router="r"{ib_kwargs})
outbound("OB", Rest(url="https://collector.example.org/ingest"){ob_kwargs})


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB", msg)
""",
        encoding="utf-8",
    )
    return load_config(tmp_path)


_ATTEST = f', tls_revocation_attested=True, tls_revocation_attested_reason="{_REASON}"'


def _toml(tmp_path: Path, *, ib_extra: str = "", ob_extra: str = "") -> Registry:
    path = tmp_path / "connections.toml"
    path.write_text(
        f"""
[[inbound]]
name = "IB"
transport = "mllp"
router = "r"
{ib_extra}
[inbound.settings]
port = 15099
tls = true
tls_cert_file = "c.pem"
tls_key_file = "k.pem"
tls_ca_file = "ca.pem"

[[outbound]]
name = "OB"
transport = "rest"
{ob_extra}
[outbound.settings]
url = "https://collector.example.org/ingest"
""",
        encoding="utf-8",
    )
    reg = Registry()
    load_connections_file(path, reg)
    return reg


_TOML_ATTEST = f'tls_revocation_attested = true\ntls_revocation_attested_reason = "{_REASON}"\n'


# --- the flag reaches the model, through BOTH surfaces, in BOTH directions -------------------------


def test_code_first_outbound_attestation_reaches_the_destination(tmp_path: Path) -> None:
    dest = _dest_config(_code_first(tmp_path, ob_kwargs=_ATTEST).outbound["OB"], {})
    assert dest.tls_revocation_attested is True
    assert dest.tls_revocation_attested_reason == _REASON


def test_connections_toml_outbound_attestation_reaches_the_destination(tmp_path: Path) -> None:
    dest = _dest_config(_toml(tmp_path, ob_extra=_TOML_ATTEST).outbound["OB"], {})
    assert dest.tls_revocation_attested is True
    assert dest.tls_revocation_attested_reason == _REASON


def test_code_first_inbound_attestation_reaches_the_source(tmp_path: Path) -> None:
    src = _source_config(_code_first(tmp_path, ib_kwargs=_ATTEST).inbound["IB"], "127.0.0.1", {})
    assert src.tls_revocation_attested is True
    assert src.tls_revocation_attested_reason == _REASON


def test_connections_toml_inbound_attestation_reaches_the_source(tmp_path: Path) -> None:
    src = _source_config(_toml(tmp_path, ib_extra=_TOML_ATTEST).inbound["IB"], "127.0.0.1", {})
    assert src.tls_revocation_attested is True
    assert src.tls_revocation_attested_reason == _REASON


def test_an_undeclared_connection_carries_no_attestation(tmp_path: Path) -> None:
    # CONTROL for the four above: the same graph without the keys builds unattested models, so a
    # True there is the declaration arriving and not a default that was always True.
    reg = _code_first(tmp_path)
    assert _dest_config(reg.outbound["OB"], {}).tls_revocation_attested is False
    assert _source_config(reg.inbound["IB"], "127.0.0.1", {}).tls_revocation_attested is False


# --- the reason is required, on both surfaces --------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        (", tls_revocation_attested=True", "requires tls_revocation_attested_reason"),
        (f', tls_revocation_attested_reason="{_REASON}"', "without tls_revocation_attested=true"),
        (', tls_revocation_attested=True, tls_revocation_attested_reason="  "', "non-empty"),
    ],
)
@pytest.mark.parametrize("direction", ["ib_kwargs", "ob_kwargs"])
def test_code_first_pair_is_validated(
    tmp_path: Path, kwargs: str, match: str, direction: str
) -> None:
    with pytest.raises(WiringError, match=match):
        _code_first(tmp_path, **{direction: kwargs})


@pytest.mark.parametrize("direction", ["ib_extra", "ob_extra"])
def test_connections_toml_flag_without_reason_is_refused(tmp_path: Path, direction: str) -> None:
    with pytest.raises(WiringError, match="requires tls_revocation_attested_reason"):
        _toml(tmp_path, **{direction: "tls_revocation_attested = true\n"})


# --- the INBOUND attested branch is now reachable, and it is audited ----------------------------------


def test_an_authored_inbound_attestation_crosses_the_enforcing_refusal_and_is_audited(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    src = _source_config(_toml(tmp_path, ib_extra=_TOML_ATTEST).inbound["IB"], "127.0.0.1", {})
    with caplog.at_level(logging.WARNING):
        check_inbound_revocation(src, "IB", posture=_ENFORCING)  # no WiringError: the escape works
    audit = " ".join(r.getMessage() for r in caplog.records)
    assert "operator attestation" in audit
    assert "'IB'" in audit and _REASON in audit


def test_the_same_inbound_unattested_is_still_refused(tmp_path: Path) -> None:
    # CONTROL: the crossing above is the attestation's doing, not a gate that stopped firing.
    src = _source_config(_toml(tmp_path).inbound["IB"], "127.0.0.1", {})
    with pytest.raises(WiringError, match="no revocation"):
        check_inbound_revocation(src, "IB", posture=_ENFORCING)


def test_the_outbound_audit_line_carries_the_reason(caplog: pytest.LogCaptureFixture) -> None:
    guard = RevocationHopGuard.capture(
        host="collector.example.org",
        cell="REST destination",
        description="verified https egress",
        attested=True,
        attested_reason=_REASON,
        posture=_ENFORCING,
    )
    with caplog.at_level(logging.WARNING):
        guard.enforce_construction()
    audit = " ".join(r.getMessage() for r in caplog.records)
    assert "operator attestation" in audit and _REASON in audit
