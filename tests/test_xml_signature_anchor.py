# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""XML-DSig verify() must require an explicit trust anchor (DELTA-03).

Without an anchor, signxml would trust any signature whose embedded certificate chains to the host's
system CA store (origin-blind verification). The codec is opt-in (called by a code-first Handler), so
the fix is a secure-by-default guard: refuse the no-anchor call rather than verify origin-blind.

These assertions do not need the ``[xml]`` extra installed — the anchor guard fires before signxml is
loaded.
"""

from __future__ import annotations

import pytest

from messagefoundry.parsing.xml.signature import verify

# Any non-None value clears the anchor guard (it is never parsed as a certificate on this code path),
# so a plain sentinel is used instead of a certificate-shaped blob — the latter compiles into the
# .pyc and trips antivirus "embedded certificate" heuristics (Gen:Heur.PHS.1), a false positive.
_DUMMY_ANCHOR = b"unit-test-anchor-sentinel"


@pytest.mark.parametrize("kwargs", [{}, {"x509_cert": None, "ca_pem_file": None}])
def test_verify_without_anchor_is_refused(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="anchor"):
        verify(b"<root/>", **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [{"x509_cert": _DUMMY_ANCHOR}, {"ca_pem_file": _DUMMY_ANCHOR}],
)
def test_verify_with_an_anchor_gets_past_the_guard(kwargs: dict[str, object]) -> None:
    # Supplying either anchor must clear the no-anchor guard. The call then fails downstream (extra
    # absent -> RuntimeError, or extra present -> XmlError / crypto error on the dummy doc/cert) — but
    # never with the anchor-required ValueError.
    try:
        verify(b"<root/>", **kwargs)  # type: ignore[arg-type]
    except ValueError as exc:  # pragma: no cover - only asserts the guard did not misfire
        assert "anchor" not in str(exc).lower(), "anchor supplied but no-anchor guard still fired"
    except Exception:  # noqa: BLE001 - any non-anchor failure means the guard let the call through
        pass


# --- BACKLOG #1171 (ASVS 11.4.1): the accept-set passed to signxml ---------------------------------


def test_the_verifier_refuses_a_sub_254_bit_digest() -> None:
    """``verify()`` passed NO ``expect_config``, so signxml's own default chose what a partner could
    sign with -- and that default admits SHA-224 and SHA3-224.

    The V11 appendix disqualifies a sub-254-bit digest for any collision-resistance-requiring
    application, and a signature is one.
    """
    signxml = pytest.importorskip("signxml")
    from messagefoundry.parsing.xml.signature import _approved_signature_config

    cfg = _approved_signature_config(signxml)
    weak_digests = [d.name for d in cfg.digest_algorithms if "224" in d.name]
    weak_methods = [m.name for m in cfg.signature_methods if "224" in m.name]
    assert not weak_digests, f"a sub-254-bit digest is still accepted: {weak_digests}"
    assert not weak_methods, (
        f"a signature method over a weak digest is still accepted: {weak_methods}"
    )


def test_the_accept_set_is_narrowed_rather_than_emptied() -> None:
    """POSITIVE CONTROL: without it, returning an EMPTY accept-set would satisfy the test above.

    An empty set refuses every signature, which is a different defect wearing the same green. The
    common cases -- SHA-256 and SHA-512 -- must survive.
    """
    signxml = pytest.importorskip("signxml")
    from messagefoundry.parsing.xml.signature import _approved_signature_config

    cfg = _approved_signature_config(signxml)
    names = {d.name for d in cfg.digest_algorithms}
    assert {"SHA256", "SHA512"} <= names, (
        f"the approved digests were emptied, not narrowed: {names}"
    )
    assert cfg.signature_methods, "every signature method was removed"


def test_the_libraries_other_defaults_are_not_silently_rebuilt() -> None:
    """Derived by subtraction from signxml's default, so a hardening we never named is not reverted.

    A hand-built config would freeze today's answer to questions this code does not decide --
    ``require_x509`` being the one that matters most here.
    """
    signxml = pytest.importorskip("signxml")
    from messagefoundry.parsing.xml.signature import _approved_signature_config

    default = signxml.SignatureConfiguration()
    cfg = _approved_signature_config(signxml)
    assert cfg.require_x509 == default.require_x509
    assert cfg.expect_references == default.expect_references
    assert cfg.default_reference_c14n_method == default.default_reference_c14n_method
