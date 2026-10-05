# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The revocation-hop guard on outbound hops that verified a peer certificate and ran no guard
(vault BACKLOG #2193, ADR 0173).

ADR 0173's construction-time refusal already ran on the HTTP-family destinations, MLLP, EMAIL, the
SMART token hop and others. These hops verified a peer certificate too, and called neither
``refuse_unrevoked_verified_hop`` nor ``RevocationHopGuard.capture``: under an enforcing posture
they would have accepted a revoked certificate with no refusal, no warning and no audit record.

Each hop here gets the same three arms, because each arm alone proves too little:

* **refused** under an enforcing posture with no CRL. This is the control the other arms relax.
* **admitted** with a ``[tls].crl_file`` that reaches the hop's OWN context. It reads
  ``VERIFY_CRL_CHECK_LEAF`` off the context the connector will really dial with, so it fails if the
  guard runs before that context exists (vault BACKLOG #2188) or reads a look-alike beside it.
* **still refused** where the same CRL is configured but cannot reach the hop. A guard that keyed on
  the setting, and not on the context, would pass the first two arms and fail this one.

Nothing here dials: construction reads settings only. All certificates and CRLs are synthetic.
"""

from __future__ import annotations

import datetime
import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopPosture,
    InsecureHopRefused,
    TrustAnchorPolicy,
    active_hop_posture,
    build_smtp_tls_context,
    context_checks_revocation,
)
from messagefoundry.config.wiring import WiringError, load_config
from messagefoundry.transports import dicom as dicom_module
from messagefoundry.transports import direct as direct_module
from messagefoundry.transports import fhir as fhir_module
from messagefoundry.transports import remotefile as remotefile_module
from messagefoundry.transports.dicom import DicomScuDestination
from messagefoundry.transports.direct import DirectDestination
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.remotefile import RemoteFileDestination
from messagefoundry.transports.rest import (
    _NO_REDIRECT_OPENER,
    http_family_trust_anchor,
    opener_tls_context,
)
from tests.test_direct_transport import _mint_ca, _mint_leaf, _write_key, _write_pem
from tests.test_revocation_audit_names_connection import _build_check, _shipped

ENFORCING = HopPosture(enforcing=True)
NOT_ENFORCING = HopPosture(enforcing=False)

REMOTE = "10.0.0.5"  # non-loopback, never dialled: construction reads settings only
LOOPBACK = "127.0.0.1"
REASON = "partner PKI runs OCSP at the site edge"

_OPEN_EGRESS = EgressSettings(deny_by_default=False)


@pytest.fixture(autouse=True)
def _no_blanket_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test with the blanket attestation and the weakened-TLS escape unset, so neither
    can stand in for the hop's own facts."""
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)


@pytest.fixture(scope="module")
def bare_crl(tmp_path_factory: pytest.TempPathFactory) -> str:
    """A CRL with no CA beside it: the shape a hop on the system trust store loads. Synthetic."""
    now = datetime.datetime.now(datetime.UTC)
    day = datetime.timedelta(days=1)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-2193-ca")])
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - 2 * day)
        .next_update(now + 30 * day)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path_factory.mktemp("crl2193") / "crl_only.pem"
    path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return str(path)


def _crl_policy(crl: str) -> TrustAnchorPolicy:
    """The shipped default plus a CRL: ``system`` mode, no internal CA."""
    return TrustAnchorPolicy(crl_file=crl)


#: The logger every revocation refusal, warning and audit line is written to.
_GUARD_LOGGER = "messagefoundry.config.tls_policy"


class _GuardLog(logging.Handler):
    """The messages one or more named loggers emitted, collected ON those loggers."""

    def __init__(self, loggers: list[logging.Logger]) -> None:
        super().__init__(level=logging.WARNING)
        self.messages: list[str] = []
        self._loggers = loggers

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())

    def has(self, text: str) -> bool:
        return any(text in message for message in self.messages)

    @property
    def audit(self) -> str:
        """Every attested-crossing audit line, joined."""
        return " ".join(m for m in self.messages if "operator attestation" in m)

    def state(self) -> str:
        """What an assertion prints when an expected line is missing: the facts that decide
        whether a record reaches a logger's own handlers at all."""
        loggers = "; ".join(
            f"{lg.name}: level={lg.level} effective={lg.getEffectiveLevel()} "
            f"disabled={lg.disabled} filters={len(lg.filters)}"
            for lg in self._loggers
        )
        return (
            f"captured {len(self.messages)} message(s): {self.messages!r}. "
            f"logging.disable level={logging.root.manager.disable}. {loggers}"
        )


@contextmanager
def _guard_log(*names: str) -> Iterator[_GuardLog]:
    """Collect WARNING and above from the named loggers themselves, by default the guard's own.

    Not ``caplog``. ``caplog`` reads records at the ROOT logger, so it depends on every logger
    between the emitter and the root still propagating, on the root's level, and on pytest's
    capture handler still being on the root. This suite changes all three between tests on
    purpose (``tests/conftest.py`` quiets ``messagefoundry`` in each teardown window, and
    ``tests/_root_logging.py`` rewrites the root's handler list), and a test elsewhere on the same
    xdist worker can leave any of them changed. Read through ``caplog``, five arms of this file
    lost their records in 2 of 13 runs under xdist on 2026-10-04, and passed alone every time. Which
    of those three the lost records went through was NOT identified: eight further runs with a
    probe attached did not reproduce it. ``test_the_guard_capture_does_not_depend_on_the_root_logger``
    shows this capture holds under all of them.

    A handler on the emitting logger sees the record before any of that. The logger's own level
    is set, so a quieted parent cannot raise its effective level. ``logging.disable`` and the
    logger's ``disabled`` flag are cleared for the block, as ``caplog.at_level`` clears the first,
    because both drop a record before any handler runs. All of it is put back on exit.

    This does not loosen what is asserted. The same messages are read; only where they are
    collected moved."""
    loggers = [logging.getLogger(name) for name in (names or (_GUARD_LOGGER,))]
    sink = _GuardLog(loggers)
    saved = [(lg, lg.level, lg.disabled) for lg in loggers]
    disable_level = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    for lg in loggers:
        lg.setLevel(logging.WARNING)
        lg.disabled = False
        lg.addHandler(sink)
    try:
        yield sink
    finally:
        for lg, level, disabled in saved:
            lg.removeHandler(sink)
            lg.setLevel(level)
            lg.disabled = disabled
        logging.disable(disable_level)


def _without_the_policy[T](real: Callable[..., T]) -> Callable[..., T]:
    """A stand-in for a context or anchor builder that hands ``real`` no trust-anchor policy.

    Every other argument is forwarded as given, positional or keyword. The stand-in names none of
    them, so it keeps working when the real builder gains a parameter, and a new argument still
    reaches the real builder."""

    def stand_in(*args: Any, **kwargs: Any) -> T:
        kwargs["trust_anchor_policy"] = None
        return real(*args, **kwargs)

    return stand_in


def _dest(
    name: str,
    ctype: ConnectorType,
    settings: dict[str, object],
    *,
    attested: bool = False,
    policy: TrustAnchorPolicy | None = None,
) -> Destination:
    return Destination(
        name=name,
        type=ctype,
        settings=settings,
        tls_revocation_attested=attested,
        tls_revocation_attested_reason=REASON if attested else None,
        trust_anchor_policy=policy or TrustAnchorPolicy(),
    )


def test_the_guard_capture_does_not_depend_on_the_root_logger(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The capture every log arm below reads through, under the states that lose a record on its
    way to the root: the ``messagefoundry`` parent quieted as ``tests/conftest.py`` quiets it in a
    teardown window, and logging disabled process-wide. The guard's line is still collected.

    ``caplog`` is the CONTROL, and the only use of it in this file: in the same block it sees
    nothing, so the hostile state is real and the pass above is the capture's doing."""
    parent = logging.getLogger("messagefoundry")
    saved = (parent.propagate, parent.level, logging.root.manager.disable)
    parent.propagate = False
    parent.setLevel(logging.CRITICAL + 10)
    logging.disable(logging.CRITICAL)
    try:
        with active_hop_posture(NOT_ENFORCING), _guard_log() as log:
            DicomScuDestination(_scu(REMOTE))
        assert log.has("revocation"), log.state()
        assert not any("revocation" in r.getMessage() for r in caplog.records)
        # And the capture put back what it changed.
        assert logging.root.manager.disable == logging.CRITICAL
        assert logging.getLogger(_GUARD_LOGGER).level == logging.NOTSET
    finally:
        logging.disable(saved[2])
        parent.setLevel(saved[1])
        parent.propagate = saved[0]


# --- FhirLookupExecutor: the live read hop (transports/fhir.py) ------------------------------------


def _lookup(
    settings: dict[str, object], *, policy: TrustAnchorPolicy | None = None
) -> FhirLookupExecutor:
    return FhirLookupExecutor({"epic": settings}, egress=_OPEN_EGRESS, trust_anchor_policy=policy)


def test_a_fhir_lookup_read_hop_is_refused_when_it_checks_no_revocation() -> None:
    # THE CONTROL. Before #2193 this constructed: the read hop verified the server and ran no guard.
    with (
        active_hop_posture(ENFORCING),
        pytest.raises(InsecureHopRefused, match="revocation") as exc,
    ):
        _lookup({"url": f"https://{REMOTE}/fhir"})
    # The refusal names the lookup, in the lookup namespace, so an operator can find the declaration.
    assert "connection 'fhir_lookup:epic';" in str(exc.value)


def test_a_fhir_lookup_read_hop_is_admitted_when_a_crl_reaches_its_own_opener(
    bare_crl: str,
) -> None:
    with active_hop_posture(ENFORCING):
        executor = _lookup({"url": f"https://{REMOTE}/fhir"}, policy=_crl_policy(bare_crl))
    # The opener this lookup will really dial through, not the shared import-time one.
    opener = executor._opener["epic"]
    assert opener is not _NO_REDIRECT_OPENER
    assert context_checks_revocation(opener_tls_context(opener, connector="probe")) is True


def test_a_configured_crl_does_not_admit_a_fhir_lookup_it_cannot_reach(bare_crl: str) -> None:
    """A CRL on the policy is not a CRL on the hop. Of two lookups built by ONE executor with ONE
    policy, the loopback one resolves no CRL and crosses on the on-box rule, and the remote one
    crosses only because its own opener checks. Take the CRL away and the remote one is refused
    while the loopback one still builds, so the guard is deciding per lookup."""
    both: dict[str, dict[str, object]] = {
        "onbox": {"url": f"https://{LOOPBACK}:8443/fhir"},
        "epic": {"url": f"https://{REMOTE}/fhir"},
    }
    with active_hop_posture(ENFORCING):
        executor = FhirLookupExecutor(
            both, egress=_OPEN_EGRESS, trust_anchor_policy=_crl_policy(bare_crl)
        )
    assert executor._opener["onbox"] is _NO_REDIRECT_OPENER  # no CRL reached the on-box hop
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused, match="fhir_lookup:epic"):
        FhirLookupExecutor(both, egress=_OPEN_EGRESS)
    with active_hop_posture(ENFORCING):
        FhirLookupExecutor({"onbox": both["onbox"]}, egress=_OPEN_EGRESS)


def test_a_configured_crl_does_not_admit_a_fhir_lookup_whose_opener_lacks_it(
    bare_crl: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard reads the opener's context, never the setting. The policy carries a CRL and the
    opener the lookup ends up holding does not, so a REMOTE lookup must stay refused. A guard keyed
    on ``trust_anchor_policy.crl_file`` would admit it; the arm above cannot catch that, because its
    only CRL-less lookup is on loopback."""
    monkeypatch.setattr(
        fhir_module, "http_family_trust_anchor", _without_the_policy(http_family_trust_anchor)
    )
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused, match="revocation"):
        _lookup({"url": f"https://{REMOTE}/fhir"}, policy=_crl_policy(bare_crl))


def test_a_fhir_lookup_read_hop_crosses_on_its_own_attestation_and_is_audited() -> None:
    settings: dict[str, object] = {
        "url": f"https://{REMOTE}/fhir",
        "tls_revocation_attested": True,
        "tls_revocation_attested_reason": REASON,
    }
    with active_hop_posture(ENFORCING), _guard_log() as log:
        _lookup(settings)
    assert "connection 'fhir_lookup:epic';" in log.audit and REASON in log.audit, log.state()
    assert "FhirLookup 'epic' (verified TLS" in log.audit


def test_the_hop_attestation_does_not_cross_the_fhir_lookup_revocation_refusal() -> None:
    # `tls_hop_attested` answers a different question (is this cleartext hop secure). A guard that
    # read it here would cross on the wrong operator claim.
    settings: dict[str, object] = {
        "url": f"https://{REMOTE}/fhir",
        "tls_hop_attested": True,
        "tls_hop_attested_reason": REASON,
    }
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused, match="revocation"):
        _lookup(settings)


def test_a_fhir_lookup_read_hop_warns_but_builds_when_not_enforcing() -> None:
    with active_hop_posture(NOT_ENFORCING), _guard_log() as log:
        _lookup({"url": f"https://{REMOTE}/fhir"})
    assert log.has("revocation"), log.state()


def test_a_fhir_lookup_built_outside_the_gate_is_unchanged() -> None:
    # No posture stamped: a direct build or an embedding. The guard no-ops, as its siblings do.
    _lookup({"url": f"https://{REMOTE}/fhir"})


def test_a_fhir_lookup_that_verifies_nothing_is_the_verify_off_refusal_not_this_one() -> None:
    """Disjoint gates. A ``verify_tls=false`` lookup has no verified certificate whose revocation
    could matter, so the verify-off refusal owns it. Both raise the same type, so the MESSAGE is
    what tells them apart."""
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        _lookup({"url": f"https://{REMOTE}/fhir", "verify_tls": False})
    assert "disables TLS certificate verification" in str(exc.value)
    assert "revocation" not in str(exc.value)


def _lookup_config(tmp_path: Path, *, declared: bool) -> Path:
    attest = f', tls_revocation_attested=True, tls_revocation_attested_reason="{REASON}"'
    (tmp_path / "lookup.py").write_text(
        "from messagefoundry import FhirLookup\n"
        f'FhirLookup("epic", url="https://ehr.example.org/fhir"{attest if declared else ""})\n',
        encoding="utf-8",
    )
    return tmp_path


def test_the_check_gate_refuses_an_undeclared_fhir_lookup_and_admits_a_declared_one(
    tmp_path: Path,
) -> None:
    """End to end through the gate ``messagefoundry check``, dry-run and reload all reach, with the
    settings the runner really hands the executor. The typed declaration on ``FhirLookup()`` is the
    authoring surface, and the mirror is what carries it to the read hop."""
    undeclared = tmp_path / "undeclared"
    undeclared.mkdir()
    registry = load_config(_lookup_config(undeclared, declared=False), allow_empty=True)
    with pytest.raises(WiringError, match="FhirLookup 'epic'.*revocation"):
        _build_check(registry)
    declared = tmp_path / "declared"
    declared.mkdir()
    registry = load_config(_lookup_config(declared, declared=True), allow_empty=True)
    with _guard_log() as log:
        _build_check(registry)
    assert "connection 'fhir_lookup:epic';" in log.audit and REASON in log.audit, log.state()


# --- DICOM C-STORE SCU over TLS (transports/dicom.py) ----------------------------------------------


def _scu(
    host: str,
    *,
    tls: bool = True,
    attested: bool = False,
    policy: TrustAnchorPolicy | None = None,
) -> Destination:
    settings: dict[str, object] = {"ae_title": "MF_SCU", "host": host, "port": 11112}
    if tls:
        settings["tls"] = True
    return _dest("OB_PACS", ConnectorType.DIMSE, settings, attested=attested, policy=policy)


def test_a_dicom_tls_association_is_refused_when_it_checks_no_revocation() -> None:
    # THE CONTROL. Before #2193 this constructed: the SCU's only hop guard was the cleartext one.
    with (
        active_hop_posture(ENFORCING),
        pytest.raises(InsecureHopRefused, match="revocation") as exc,
    ):
        DicomScuDestination(_scu(REMOTE))
    assert "connection 'OB_PACS';" in str(exc.value)


def test_a_dicom_tls_association_is_admitted_when_a_crl_reaches_its_own_context(
    bare_crl: str,
) -> None:
    with active_hop_posture(ENFORCING):
        dest = DicomScuDestination(_scu(REMOTE, policy=_crl_policy(bare_crl)))
    # The context the association will really dial with.
    assert context_checks_revocation(dest._ssl) is True


def test_a_configured_crl_does_not_admit_a_dicom_association_whose_context_lacks_it(
    bare_crl: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard reads the context, never the setting. Here the policy carries a CRL and the context
    the SCU ends up holding does not, so the hop must stay refused. A guard keyed on
    ``trust_anchor_policy.crl_file`` would admit it."""
    monkeypatch.setattr(
        dicom_module, "_client_ssl_context", _without_the_policy(dicom_module._client_ssl_context)
    )
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused, match="revocation"):
        DicomScuDestination(_scu(REMOTE, policy=_crl_policy(bare_crl)))


def test_a_dicom_tls_association_crosses_on_its_attestation_and_is_audited() -> None:
    with active_hop_posture(ENFORCING), _guard_log() as log:
        DicomScuDestination(_scu(REMOTE, attested=True))
    shipped = _shipped(log.audit)
    assert "connection 'OB_PACS';" in shipped and REASON in shipped, log.state()
    # The cell label survives the log filters, which scrub two adjacent all-capital tokens.
    assert "DICOM C-STORE client (SCU) over TLS" in shipped


def test_a_dicom_tls_association_on_loopback_still_crosses(bare_crl: str) -> None:
    # On-box: not a network exposure, and no CRL is applied there even when one is configured.
    with active_hop_posture(ENFORCING):
        dest = DicomScuDestination(_scu(LOOPBACK, policy=_crl_policy(bare_crl)))
    assert context_checks_revocation(dest._ssl) is False


def test_a_dicom_tls_association_warns_but_builds_when_not_enforcing() -> None:
    with active_hop_posture(NOT_ENFORCING), _guard_log() as log:
        DicomScuDestination(_scu(REMOTE))
    assert log.has("revocation"), log.state()


def test_a_dicom_association_built_outside_the_gate_is_unchanged() -> None:
    DicomScuDestination(_scu(REMOTE))


def test_a_plaintext_dicom_association_is_the_cleartext_refusal_not_this_one() -> None:
    """Disjoint gates. With TLS off there is no verified certificate, so the cleartext guard owns
    the hop. Both raise the same type, so the MESSAGE is what tells them apart."""
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        DicomScuDestination(_scu(REMOTE, tls=False))
    assert "plaintext DIMSE" in str(exc.value)
    assert "revocation" not in str(exc.value)


# --- FTPS upload, the destination (transports/remotefile.py) ---------------------------------------


def _ftps(
    host: str,
    *,
    protocol: str = "ftps",
    tls_verify: bool = True,
    attested: bool = False,
    policy: TrustAnchorPolicy | None = None,
) -> Destination:
    settings: dict[str, object] = {"host": host, "remote_dir": "/in", "protocol": protocol}
    if not tls_verify:
        settings["tls_verify"] = False
    return _dest("OB_FTPS", ConnectorType.REMOTEFILE, settings, attested=attested, policy=policy)


def test_an_ftps_upload_is_refused_when_it_checks_no_revocation() -> None:
    # THE CONTROL. Before #2193 this constructed: the file's only hop guard was for anonymous ftp.
    with (
        active_hop_posture(ENFORCING),
        pytest.raises(InsecureHopRefused, match="revocation") as exc,
    ):
        RemoteFileDestination(_ftps(REMOTE))
    assert "connection 'OB_FTPS';" in str(exc.value)


def test_an_ftps_upload_is_admitted_when_a_crl_reaches_its_own_context(bare_crl: str) -> None:
    with active_hop_posture(ENFORCING):
        dest = RemoteFileDestination(_ftps(REMOTE, policy=_crl_policy(bare_crl)))
    assert context_checks_revocation(dest._client.tls_context) is True


def test_a_configured_crl_does_not_admit_an_ftps_upload_whose_context_lacks_it(
    bare_crl: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard reads the client's context, never the setting. The policy carries a CRL and the
    context the client ends up holding does not, so the hop must stay refused."""
    monkeypatch.setattr(
        remotefile_module,
        "_ftps_ssl_context",
        _without_the_policy(remotefile_module._ftps_ssl_context),
    )
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused, match="revocation"):
        RemoteFileDestination(_ftps(REMOTE, policy=_crl_policy(bare_crl)))


def test_an_ftps_upload_crosses_on_its_attestation_and_is_audited() -> None:
    with active_hop_posture(ENFORCING), _guard_log() as log:
        RemoteFileDestination(_ftps(REMOTE, attested=True))
    shipped = _shipped(log.audit)
    assert "connection 'OB_FTPS';" in shipped and REASON in shipped, log.state()
    assert "REMOTEFILE ftps destination" in shipped


def test_an_ftps_upload_on_loopback_still_crosses(bare_crl: str) -> None:
    with active_hop_posture(ENFORCING):
        dest = RemoteFileDestination(_ftps(LOOPBACK, policy=_crl_policy(bare_crl)))
    assert context_checks_revocation(dest._client.tls_context) is False


def test_an_ftps_upload_warns_but_builds_when_not_enforcing() -> None:
    with active_hop_posture(NOT_ENFORCING), _guard_log() as log:
        RemoteFileDestination(_ftps(REMOTE))
    assert log.has("revocation"), log.state()


def test_an_ftps_upload_built_outside_the_gate_is_unchanged() -> None:
    RemoteFileDestination(_ftps(REMOTE))


def test_an_ftps_upload_that_verifies_nothing_takes_no_revocation_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Disjoint gates. ``tls_verify=false`` has no verified certificate whose revocation could
    matter, so its own refusal owns it under an enforcing posture. Where the escape permits the hop,
    the guard is not taken at all: a non-enforcing posture WARNs on every guarded hop, and no such
    line appears here. The connector's own verify-off warning, read through the same capture, is
    what shows the capture was live when it saw no revocation line."""
    with active_hop_posture(ENFORCING), pytest.raises(ValueError, match="tls_verify=false") as exc:
        RemoteFileDestination(_ftps(REMOTE, tls_verify=False))
    assert "revocation" not in str(exc.value)
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with (
        active_hop_posture(NOT_ENFORCING),
        _guard_log(_GUARD_LOGGER, remotefile_module.logger.name) as log,
    ):
        RemoteFileDestination(_ftps(REMOTE, tls_verify=False))
    assert log.has("verification is DISABLED"), log.state()
    assert not log.has("revocation"), log.state()


def test_an_anonymous_plain_ftp_upload_is_the_cleartext_refusal_not_this_one() -> None:
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        RemoteFileDestination(_ftps(REMOTE, protocol="ftp"))
    assert "cleartext anonymous FTP" in str(exc.value)
    assert "revocation" not in str(exc.value)


# --- DIRECT: the SMTP authentication leg (transports/direct.py) ------------------------------------
#
# DIRECT's body is S/MIME-protected, and the shipped decision is that a DIRECT hop with NO SMTP
# credential takes no revocation guard. That decision is kept, and it has its own arm below. A hop
# that also sends a username and password is a credential hop like any other, and is guarded.


@pytest.fixture(scope="module")
def direct_material(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    """The S/MIME files DirectDestination loads before it reaches its TLS arms. Synthetic."""
    directory = tmp_path_factory.mktemp("direct2193")
    ca_key, ca_cert = _mint_ca()
    signer_key, signer_cert = _mint_leaf("Sender Direct", ca_key, ca_cert)
    _recipient_key, recipient_cert = _mint_leaf("recipient@hisp.example", ca_key, ca_cert)
    _write_pem(directory / "signer.crt", signer_cert)
    _write_key(directory / "signer.key", signer_key)
    _write_pem(directory / "recipient.crt", recipient_cert)
    _write_pem(directory / "ca.crt", ca_cert)
    return {
        "signing_cert": str(directory / "signer.crt"),
        "signing_key": str(directory / "signer.key"),
        "recipient_cert": str(directory / "recipient.crt"),
        "trust_anchor": str(directory / "ca.crt"),
    }


def _direct(
    material: dict[str, str],
    host: str,
    *,
    credential: bool = True,
    attested: bool = False,
    policy: TrustAnchorPolicy | None = None,
    **extra: object,
) -> Destination:
    settings: dict[str, object] = {
        "host": host,
        "sender": "sender@hisp.example",
        "recipients": ["recipient@hisp.example"],
        **material,
        **extra,
    }
    if credential:
        settings.update({"username": "svc", "password": "synthetic-not-a-secret"})
    return _dest("OB_DIRECT", ConnectorType.DIRECT, settings, attested=attested, policy=policy)


def test_a_credentialed_direct_hop_is_refused_when_it_checks_no_revocation(
    direct_material: dict[str, str],
) -> None:
    # THE CONTROL. Before #2193 this constructed: DIRECT took no revocation guard at all.
    with (
        active_hop_posture(ENFORCING),
        pytest.raises(InsecureHopRefused, match="revocation") as exc,
    ):
        DirectDestination(_direct(direct_material, REMOTE))
    assert "connection 'OB_DIRECT';" in str(exc.value)


def test_a_credentialed_direct_hop_is_admitted_when_a_crl_reaches_its_own_context(
    direct_material: dict[str, str], bare_crl: str
) -> None:
    with active_hop_posture(ENFORCING):
        dest = DirectDestination(_direct(direct_material, REMOTE, policy=_crl_policy(bare_crl)))
    # The context this destination hands to smtplib.
    assert context_checks_revocation(dest._tls_context) is True


def test_a_configured_crl_does_not_admit_a_direct_hop_whose_context_lacks_it(
    direct_material: dict[str, str], bare_crl: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard reads the context, never the setting. The policy carries a CRL and the context the
    destination ends up holding does not, so the hop must stay refused."""

    monkeypatch.setattr(
        direct_module, "build_smtp_tls_context", _without_the_policy(build_smtp_tls_context)
    )
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused, match="revocation"):
        DirectDestination(_direct(direct_material, REMOTE, policy=_crl_policy(bare_crl)))


def test_a_credentialed_direct_hop_crosses_on_its_attestation_and_is_audited(
    direct_material: dict[str, str],
) -> None:
    with active_hop_posture(ENFORCING), _guard_log() as log:
        DirectDestination(_direct(direct_material, REMOTE, attested=True))
    shipped = _shipped(log.audit)
    assert "connection 'OB_DIRECT';" in shipped and REASON in shipped, log.state()
    # The cell label survives the log filters, which scrub two adjacent all-capital tokens.
    assert "Direct destination (SMTP authentication over verified TLS)" in shipped


def test_a_direct_hop_with_no_credential_still_takes_no_revocation_guard(
    direct_material: dict[str, str],
) -> None:
    """The shipped S/MIME decision, kept for the case it argues. With no username the hop sends no
    credential, so it constructs under an enforcing posture with no CRL and no attestation. Under a
    non-enforcing posture every guarded hop WARNs, and no such line appears here, so the guard is
    not taken at all. A credentialed hop built inside the SAME capture then does warn, which shows
    the capture was live when it saw nothing."""
    with active_hop_posture(ENFORCING):
        DirectDestination(_direct(direct_material, REMOTE, credential=False))
    with active_hop_posture(NOT_ENFORCING), _guard_log() as log:
        DirectDestination(_direct(direct_material, REMOTE, credential=False))
        assert not log.has("revocation"), log.state()
        DirectDestination(_direct(direct_material, REMOTE))
        assert log.has("revocation"), log.state()


def test_a_credentialed_direct_hop_on_loopback_still_crosses(
    direct_material: dict[str, str],
) -> None:
    with active_hop_posture(ENFORCING):
        DirectDestination(_direct(direct_material, LOOPBACK))


def test_a_credentialed_direct_hop_warns_but_builds_when_not_enforcing(
    direct_material: dict[str, str],
) -> None:
    with active_hop_posture(NOT_ENFORCING), _guard_log() as log:
        DirectDestination(_direct(direct_material, REMOTE))
    assert log.has("revocation"), log.state()


def test_a_credentialed_direct_hop_built_outside_the_gate_is_unchanged(
    direct_material: dict[str, str],
) -> None:
    DirectDestination(_direct(direct_material, REMOTE))


def test_a_credentialed_direct_hop_that_verifies_nothing_keeps_its_own_refusal(
    direct_material: dict[str, str],
) -> None:
    """Disjoint gates. A credential over ``tls_verify=false`` is refused absolutely by the arm that
    owns it, before any context exists, so the revocation guard never decides that hop."""
    with active_hop_posture(ENFORCING), pytest.raises(ValueError, match="tls_verify=false") as exc:
        DirectDestination(_direct(direct_material, REMOTE, tls_verify=False))
    assert "revocation" not in str(exc.value)
