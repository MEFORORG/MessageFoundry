# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5511: an inbound listener's ``tls_crl_file`` checks the whole client chain.

The MLLP listener's context builder, which the inbound HTTP listener shares, and the DICOM SCP's
both passed only the leaf flag, so with a two-tier PKI a client whose intermediate CA the root's
CRL revokes would complete the handshake. They now check the whole chain, as the API listener has
since #5627, and refuse at start a CRL file that leaves a loaded client CA without a CRL of its
own, since under the chain check every client under that CA would be refused.

The two-tier PKI and the in-memory handshake are the API suite's. All material is synthetic and
minted there. No PHI.
"""

from __future__ import annotations

import gc
import logging
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.pipeline import crl_reload
from messagefoundry.transports.dicom import _server_ssl_context
from messagefoundry.transports.mllp import _mllp_ssl_context
from tests import test_api_tls_client_trust as _api_suite
from tests.test_api_tls_client_trust import _client, _TwoTier
from tests.test_trust_anchor_byte_binding import _handshake

# Fixtures bound by name, so pytest applies them in this module too.
two_tier = _api_suite.two_tier
clean_anchor_checks = _api_suite.clean_anchor_checks
_fresh_registry = _api_suite._fresh_registry

#: What every CRL-signature line says once a build has loaded the file (vault BACKLOG #5896).
_LOADED = "This TLS context loaded the file and checks revocation with it"

_Builder = Callable[[dict[str, Any]], ssl.SSLContext | None]


def _mllp(s: dict[str, Any]) -> ssl.SSLContext | None:
    return _mllp_ssl_context(s, server=True, name="IB_PARTNER_ADT")


def _dicom(s: dict[str, Any]) -> ssl.SSLContext | None:
    return _server_ssl_context(s, name="IB_PARTNER_DICOM")


_LISTENERS = pytest.mark.parametrize("build", [_mllp, _dicom], ids=["mllp-and-http", "dicom-scp"])


def _listener(build: _Builder, pki: _TwoTier, crl: Path) -> ssl.SSLContext:
    ctx = build(
        {
            "tls": True,
            "tls_cert_file": str(pki.server_cert),
            "tls_key_file": str(pki.server_key),
            "tls_ca_file": str(pki.root_file),
            "tls_crl_file": str(crl),
        }
    )
    assert ctx is not None
    return ctx


@_LISTENERS
@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_revoked_intermediate_refuses_its_clients(build: _Builder, two_tier: _TwoTier) -> None:
    """Red before the fix: the leaf flag alone never read the root's CRL, so the client got in.
    The API suite's ``test_control_the_leaf_check_alone_admits_the_revoked_intermediates_client``
    is the control that this CRL file under the leaf flag admits it."""
    ctx = _listener(build, two_tier, two_tier.revokes_intermediate)
    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN == ssl.VERIFY_CRL_CHECK_CHAIN
    with pytest.raises(ssl.SSLError, match="revoked"):
        _handshake(_client(two_tier), ctx)


@_LISTENERS
@pytest.mark.usefixtures("clean_anchor_checks")
def test_the_chain_check_admits_a_client_whose_chain_nobody_revoked(
    build: _Builder, two_tier: _TwoTier
) -> None:
    """The control for the refusal above: the chain flag is not a CRL that refuses everyone."""
    _handshake(_client(two_tier), _listener(build, two_tier, two_tier.revokes_nothing))


@_LISTENERS
@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_loaded_client_ca_with_no_crl_of_its_own_refuses_the_build(
    build: _Builder, two_tier: _TwoTier, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A site that supplies only the issuing intermediate's CRL is refused at start, naming the
    root, rather than built to refuse every client at the handshake. The refusal is not preceded
    by the signature warning that says the context loaded the file. The control is the same CA file with
    the root's CRL added, which builds and admits the client."""
    crl = tmp_path / "inter-crl-only.pem"
    crl.write_bytes(two_tier.inter_crl_file.read_bytes())
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.config.tls_policy"),
        pytest.raises(
            ValueError,
            match=r"inbound connection 'IB_PARTNER_\w+' tls_crl_file .*'CN=Client Root'.* have no "
            "CRL of their own",
        ),
    ):
        _listener(build, two_tier, crl)
    assert _LOADED.lower() not in caplog.text.lower()
    # The control: the file that builds also holds the intermediate's CRL, which no loaded CA
    # signed, so the warning this test looks for is logged there and the instrument can differ.
    crl.write_bytes(two_tier.revokes_nothing.read_bytes())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.tls_policy"):
        ctx = _listener(build, two_tier, crl)
    assert _LOADED in caplog.text
    _handshake(_client(two_tier), ctx)


@_LISTENERS
@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_reload_refuses_a_file_that_leaves_a_loaded_client_ca_without_its_own_crl(
    build: _Builder, two_tier: _TwoTier, tmp_path: Path
) -> None:
    """The running-hop reload applies the start's own-CRL rule to these listeners too, since it
    keys on the chain flag the listener's context now carries. Replacing the file with the
    intermediate's CRL alone is a file to fix, and the hop keeps the copy it holds."""
    crl = tmp_path / "client-crl.pem"
    crl.write_bytes(two_tier.revokes_nothing.read_bytes())
    ctx = _listener(build, two_tier, crl)
    crl.write_bytes(two_tier.inter_crl_file.read_bytes())

    gc.collect()
    (outcome,) = [o for o in crl_reload.reload_replaced_crls() if Path(o.path) == crl.resolve()]

    assert outcome.refusal is not None and outcome.refusal.remedy == crl_reload.FIX
    assert "have no CRL of their own" in outcome.refusal.reason
    assert outcome.reloaded == 0
    _handshake(_client(two_tier), ctx)  # the copy it holds still admits the client
