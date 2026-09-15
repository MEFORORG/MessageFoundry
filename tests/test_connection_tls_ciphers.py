# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0188 — the per-connection ``tls_ciphers`` opt-in on the MLLP and DICOM seams.

Four seams carry it: the MLLP listener, the MLLP destination, the DICOM SCP listener and the DICOM
SCU destination. Every test below runs against all four, because a setting wired into three of four
is the failure this shape invites and a spot check on one cannot see it.

**The hard boundary is the point of this file, not a side note.** The feature is opt-in and a
connection that leaves ``tls_ciphers`` unset must build the context it built before ADR 0188 existed
-- the interpreter's inherited suite list, **the six CBC-SHA2 suites included**. The allow-list
governs what an operator may CONFIGURE and never what an inherited default may contain (the ruling
recorded in ``harden_cipher_suites``), and retiring those six is gated on a peer census that does not
exist. So the unset path is proven three ways rather than asserted once:

* ``test_unset_leaves_the_inherited_suite_list_untouched`` compares each seam against a REFERENCE
  construction of the same context shape -- a bare ``ssl`` call that runs none of this code;
* ``test_unset_never_calls_set_ciphers`` watches the method itself and requires zero calls, with the
  opt-in arm as the positive control that the watcher is wired up at all;
* ``test_unset_still_offers_the_suites_the_allow_list_excludes`` names the six CBC-SHA2 suites and
  requires them still negotiable, which is the boundary stated in the sharpest form available.

The first two would both pass on a context nobody built, so each asserts a non-empty suite list
first. The third is the one that would go red if a future change applied the allow-list to the
inherited default, which is precisely the overshoot ADR 0188 forbids.
"""

from __future__ import annotations

import datetime
import ssl
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config import tls_policy
from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.tls_policy import (
    CONNECTION_TLS_CIPHERS_SETTING,
    apply_connection_tls_ciphers,
)
from messagefoundry.config.wiring import DICOM, MLLP, Registry
from messagefoundry.transports import dicom as dicom_transport
from messagefoundry.transports import mllp as mllp_transport

#: An operator string every property check and the approved allow-list accept, resolving to a set
#: STRICTLY NARROWER than the shipped default. Two suites rather than one so a test cannot pass by
#: accident on a single-element comparison.
NARROW = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"

#: The six the allow-list excludes and the inherited default still enables (ADR 0188, and the
#: retention decision recorded in ``harden_cipher_suites``). Named rather than derived: a derivation
#: that drifted with the code would report agreement with itself.
CBC_SHA2_SUITES = frozenset(
    {
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA256",
        "DHE-RSA-AES256-SHA256",
        "DHE-RSA-AES128-SHA256",
    }
)


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    """A self-signed EC cert + key PEM under ``tmp_path``; returns ``(cert_path, key_path)``."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _build(seam: str, tmp_path: Path, ciphers: str | None) -> ssl.SSLContext:
    """Build one seam's context exactly as its connector does, with ``tls_ciphers`` set or absent.

    ``None`` omits the KEY, not merely its value: a connector whose factory default lands ``None`` in
    the settings mapping and one that omits the key entirely must behave identically, and only the
    omitted form proves the ``settings.get(...)`` read is what makes unset a no-op.
    """
    cert, key = _self_signed(tmp_path)
    settings: dict[str, Any] = {"tls": True, "host": "localhost"}
    if seam.endswith("listener"):
        settings |= {"tls_cert_file": str(cert), "tls_key_file": str(key)}
    if ciphers is not None:
        settings[CONNECTION_TLS_CIPHERS_SETTING] = ciphers
    match seam:
        case "MLLP listener":
            ctx = mllp_transport._mllp_ssl_context(settings, server=True)
        case "MLLP destination":
            ctx = mllp_transport._mllp_ssl_context(settings, server=False)
        case "DICOM listener":
            ctx = dicom_transport._server_ssl_context(settings)
        case "DICOM destination":
            ctx = dicom_transport._client_ssl_context(settings)
        case _:  # pragma: no cover - a typo in a parametrisation, not a runtime path
            raise AssertionError(f"unknown seam {seam!r}")
    assert ctx is not None, f"{seam}: tls=true must build a context"
    return ctx


def _reference(seam: str) -> ssl.SSLContext:
    """The same context SHAPE, built by bare ``ssl`` with none of this module's code in the path.

    This is the control for the unset comparison. Comparing a seam against another seam would only
    show the four agreeing with each other, which they would do just as readily if all four were
    wrong together.
    """
    if seam.endswith("listener"):
        return ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    return ssl.create_default_context(ssl.Purpose.SERVER_AUTH)


SEAMS = ["MLLP listener", "MLLP destination", "DICOM listener", "DICOM destination"]


def _suites(ctx: ssl.SSLContext) -> set[str]:
    return {str(c.get("name", "?")) for c in ctx.get_ciphers()}


@pytest.fixture
def set_ciphers_calls(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Record every ``SSLContext.set_ciphers`` argument, and still perform the call.

    Patched on the CLASS, so it sees the call whoever makes it -- the seam, a helper it delegates to,
    or ``ssl`` itself. A spy on ``apply_connection_tls_ciphers`` would only prove that one function
    behaved, which is not the claim: the claim is that NOTHING narrows an unset context.
    """
    seen: list[str] = []
    real = ssl.SSLContext.set_ciphers

    def spy(self: ssl.SSLContext, value: str) -> None:
        seen.append(value)
        real(self, value)

    monkeypatch.setattr(ssl.SSLContext, "set_ciphers", spy)
    yield seen


# --- AC-1 / AC-2: the opt-in applies, on all four seams -----------------------------------------


@pytest.mark.parametrize("seam", SEAMS)
def test_opt_in_applies_the_operator_suite_list(seam: str, tmp_path: Path) -> None:
    """AC-1, AC-2. The context negotiates exactly what the operator string resolves to.

    Measured against the reference rather than against a hardcoded list, because what a string
    resolves to is an OpenSSL build fact. The TLS 1.3 suites are deliberately excluded from the
    comparison: ``set_ciphers`` does not govern them (they are configured by ``set_ciphersuites``),
    so requiring them to disappear would assert a false expectation of the API.
    """
    got = _suites(_build(seam, tmp_path, NARROW))
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    probe.set_ciphers(NARROW)
    expected = _suites(probe)
    tls13 = {"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"}
    assert got - tls13 == expected - tls13, f"{seam}: opt-in did not apply the operator suite list"
    assert got - tls13, f"{seam}: resolved to no TLS 1.2 suite at all — the comparison is vacuous"


@pytest.mark.parametrize("seam", SEAMS)
def test_opt_in_removes_the_suites_the_allow_list_excludes(seam: str, tmp_path: Path) -> None:
    """The direction of the change, stated as a difference. ``test_opt_in_applies...`` above pins the
    resulting SET; this pins that opting in NARROWS, which is the operator-visible claim ADR 0188
    makes and the one a reader checks the feature against."""
    unset, opted_in = _suites(_build(seam, tmp_path, None)), _suites(_build(seam, tmp_path, NARROW))
    assert opted_in < unset, f"{seam}: opting in did not narrow the suite list"
    assert not (opted_in & CBC_SHA2_SUITES), f"{seam}: CBC-SHA2 survived an AEAD-only opt-in"


# --- AC-3: the shared policy refuses the same strings here as at [api].tls_ciphers ---------------


@pytest.mark.parametrize("seam", SEAMS)
@pytest.mark.parametrize(
    ("spec", "why"),
    [
        ("AES256-SHA:@SECLEVEL=0", "static RSA key exchange — no forward secrecy"),
        ("ECDHE-RSA-AES256-SHA384", "sound but NOT on the AEAD-only approved list"),
        ("this-is-not-a-cipher-string", "unparseable by OpenSSL"),
    ],
)
def test_a_suite_the_shared_policy_refuses_is_refused_here(
    seam: str, spec: str, why: str, tmp_path: Path
) -> None:
    """AC-3. Refused at construction, naming the connector.

    The connector label is asserted, not just the raise: ``validate_tls_ciphers`` speaks about a
    generic ``tls_ciphers``, and an operator running several connections needs the error to say which
    one. A raise without the label would satisfy a looser test and leave that operator guessing.
    """
    with pytest.raises(ValueError, match=re_escape_seam(seam)) as excinfo:
        _build(seam, tmp_path, spec)
    assert "tls_ciphers" in str(excinfo.value), f"{seam}: refusal does not name the setting ({why})"


def re_escape_seam(seam: str) -> str:
    """``pytest.raises(match=...)`` takes a regex; a seam label is plain text with no metacharacters
    today, and escaping it keeps that true if one is ever added."""
    import re

    return re.escape(seam)


def test_the_refusal_is_the_shared_validator_and_not_a_second_copy(tmp_path: Path) -> None:
    """The reuse claim, checked rather than trusted. ADR 0188 says the seam runs
    ``validate_tls_ciphers`` ITSELF -- the same function ``[api].tls_ciphers`` runs -- so a future
    tightening of the allow-list reaches both surfaces at once. A seam carrying its own copy would
    pass every test above and silently drift from the API knob."""
    calls: list[str] = []
    real = tls_policy.validate_tls_ciphers

    def spy(value: str, *, require_approved_suites: bool = True) -> str:
        calls.append(value)
        return real(value, require_approved_suites=require_approved_suites)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    original = tls_policy.validate_tls_ciphers
    tls_policy.validate_tls_ciphers = spy  # type: ignore[assignment]
    try:
        apply_connection_tls_ciphers(ctx, {"tls_ciphers": NARROW}, connector="probe")
    finally:
        tls_policy.validate_tls_ciphers = original  # type: ignore[assignment]
    assert calls == [NARROW], "the seam did not run the shared validator on the operator string"


# --- AC-4 / AC-5 / AC-6: THE BOUNDARY. Unset must change nothing. --------------------------------


@pytest.mark.parametrize("seam", SEAMS)
def test_unset_leaves_the_inherited_suite_list_untouched(seam: str, tmp_path: Path) -> None:
    """AC-4, and the regression that protects ADR 0188's hard boundary.

    An unset connection must resolve the SAME suite list as a reference construction of that context
    shape. Sets, not lists: ``harden_kex_groups`` and the verify flags run on the seam and not on the
    reference, and neither is a suite-list change, but pinning ORDER here would couple this test to
    facts it is not making a claim about.
    """
    got, reference = _suites(_build(seam, tmp_path, None)), _suites(_reference(seam))
    assert got, f"{seam}: resolved to NO suites — the comparison is vacuous"
    assert got == reference, (
        f"{seam}: leaving tls_ciphers unset changed the negotiated suite list. "
        f"ADR 0188 is opt-in: only-here {sorted(got - reference)}, "
        f"only-in-reference {sorted(reference - got)}."
    )


@pytest.mark.parametrize("seam", SEAMS)
def test_unset_never_calls_set_ciphers(
    seam: str, tmp_path: Path, set_ciphers_calls: list[str]
) -> None:
    """AC-5. Not merely "the list came out the same" — the narrowing call is never made at all.

    A seam that called ``set_ciphers`` with a string resolving back to the default would pass AC-4
    and still be a behaviour change: it would freeze the suite list against a future interpreter
    whose default moved. This is the stronger statement, and the two are worth having separately.
    """
    _build(seam, tmp_path, None)
    assert set_ciphers_calls == [], f"{seam}: unset path called set_ciphers{set_ciphers_calls}"


def test_the_set_ciphers_watcher_can_see_a_call(
    tmp_path: Path, set_ciphers_calls: list[str]
) -> None:
    """POSITIVE CONTROL for the test above. A spy that never fires reports "no calls" identically
    whether the code is clean or the patch missed its target, and a class-level patch on a stdlib
    method is exactly the kind that silently misses. Here the opt-in arm must record a call."""
    _build("MLLP listener", tmp_path, NARROW)
    assert NARROW in set_ciphers_calls, "the set_ciphers watcher is not wired up — AC-5 is vacuous"


@pytest.mark.parametrize("seam", SEAMS)
def test_unset_still_offers_the_suites_the_allow_list_excludes(seam: str, tmp_path: Path) -> None:
    """AC-6, and the boundary in its sharpest form: the six CBC-SHA2 suites stay negotiable.

    This is the test that goes red if someone applies ``_APPROVED_TLS_SUITES`` to an inherited
    context -- the one overshoot ADR 0188 names and refuses. Retiring these six is an owner call
    gated on a peer census nobody has run; it is not a side effect of adding an operator knob.

    Skips rather than passes where the local OpenSSL enables none of them, because a build that
    offers no CBC-SHA2 suite to begin with cannot show one being retained.
    """
    present = _suites(_reference(seam)) & CBC_SHA2_SUITES
    if not present:  # pragma: no cover - build-dependent
        pytest.skip(f"this OpenSSL ({ssl.OPENSSL_VERSION}) enables no CBC-SHA2 suite by default")
    assert _suites(_build(seam, tmp_path, None)) >= present, (
        f"{seam}: leaving tls_ciphers unset RETIRED CBC-SHA2 suite(s) "
        f"{sorted(present - _suites(_build(seam, tmp_path, None)))}. ADR 0188 forbids this: the "
        f"allow-list governs what an operator may configure, never what a default may contain."
    )


# --- The order at the seam: narrow first, assert second ------------------------------------------


@pytest.mark.parametrize("seam", SEAMS)
def test_the_assertion_runs_on_the_post_set_ciphers_context(
    seam: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The assertion must see the list the connector will actually use.

    ADR 0188 first folded both steps into one helper to make this un-driftable; that shape hid the
    assertion from the 12.1.2 call-site guard, so the seams now carry two calls and the order is
    theirs to keep. This is what replaces the structural guarantee.

    Patched in EACH TRANSPORT's namespace, not in ``tls_policy``: the transports bind the name at
    import, so a patch on the definition module would record nothing and report a pass.
    """
    module = mllp_transport if seam.startswith("MLLP") else dicom_transport
    seen: list[set[str]] = []
    real = module.harden_cipher_suites

    def spy(ctx: ssl.SSLContext, *, connector: str) -> None:
        seen.append(_suites(ctx))
        real(ctx, connector=connector)

    monkeypatch.setattr(module, "harden_cipher_suites", spy)
    final = _suites(_build(seam, tmp_path, NARROW))
    assert seen, f"{seam}: harden_cipher_suites was never reached — the seam asserts nothing"
    assert seen[-1] == final, (
        f"{seam}: the assertion ran on a PRE-set_ciphers context. It must run last, on the suite "
        f"list the connector will negotiate."
    )


# --- Reachability from both authoring surfaces ---------------------------------------------------


def test_the_code_first_factories_carry_the_setting() -> None:
    """Surface one: ``MLLP()`` / ``DICOM()`` put the value in the settings mapping the context
    builders read, under the single name ``CONNECTION_TLS_CIPHERS_SETTING``. A factory that spelled
    the key differently would read as "the operator set nothing" and never fail."""
    for spec in (
        MLLP(port=2575, tls_ciphers=NARROW),
        DICOM(port=11112, ae_title="MEFOR", tls_ciphers=NARROW),
    ):
        assert spec.settings[CONNECTION_TLS_CIPHERS_SETTING] == NARROW
    for default in (MLLP(port=2575), DICOM(port=11112, ae_title="MEFOR")):
        assert default.settings[CONNECTION_TLS_CIPHERS_SETTING] is None, (
            "the factory default must be None — an unset connection reaches settings.get() as None"
        )


def test_tls_ciphers_reaches_the_mllp_connector_from_connections_toml(tmp_path: Path) -> None:
    """Surface two, for the half that has one. ``connections.toml`` desugars ``[settings]`` straight
    through the same factory ("the factory IS the schema"), so the parameter added to ``MLLP()``
    reaches the data surface with no second schema to keep in step -- which is the claim ADR 0188
    makes about its config surface, checked here rather than reasoned about.

    **DICOM has no TOML transport name**, so its half is factory-only. That is a pre-existing
    property of the DICOM connector and not something ADR 0188 changed;
    ``test_dicom_is_still_absent_from_the_toml_transport_table`` pins it so the gap cannot close
    silently and leave this file claiming a coverage it no longer has.
    """
    (tmp_path / "connections.toml").write_text(
        "[[inbound]]\n"
        'name = "IB_TEST_ADT"\n'
        'transport = "mllp"\n'
        'router = "r"\n'
        "strict = false\n"
        "[inbound.settings]\n"
        "port = 2575\n"
        "tls = true\n"
        f'tls_ciphers = "{NARROW}"\n',
        encoding="utf-8",
    )
    registry = Registry()
    load_connections_file(tmp_path / "connections.toml", registry)
    ((_name, connection),) = registry.inbound.items()
    assert connection.spec.settings[CONNECTION_TLS_CIPHERS_SETTING] == NARROW


def test_dicom_is_still_absent_from_the_toml_transport_table() -> None:
    """The negative half of the reachability claim above, pinned so it stays honest in both
    directions: if DICOM ever gains a ``connections.toml`` transport name, this goes red and the
    sibling test's docstring gets corrected instead of quietly becoming false."""
    from messagefoundry.config.connections_file import _TRANSPORTS

    assert "dicom" not in _TRANSPORTS and "dimse" not in _TRANSPORTS, (
        "DICOM is now authorable in connections.toml — extend the reachability test above to cover "
        "its tls_ciphers and correct ADR 0188's Consequences note."
    )
