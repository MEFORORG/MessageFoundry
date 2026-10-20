# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SHA-224 signature-scheme narrowing, in ONE copy every TLS client and server shares.

:func:`narrow_signature_algorithms`'s docstring is the one statement of what it does, of the owner
ruling of 2026-09-29 on ASVS 11.4.1 behind it, and of what it reaches. ``tls_policy`` re-exports
it under the same name, so ``tls_policy.narrow_signature_algorithms`` is this function.

Stdlib-only, so :mod:`messagefoundry.config.tls_policy`, :mod:`messagefoundry.apiclient.client`
(which may not import ``config/``, CLAUDE.md section 4) and :mod:`messagefoundry.tray.probe` (which
may import neither ``config/`` nor anything that pulls it in, ADR 0113 section 1) share it rather
than each keeping a copy that could drift (BACKLOG #3414). It must stay stdlib-only: the tray's
fresh-interpreter import probe in ``tests/test_dependency_boundaries.py`` goes red if it reaches
``config/``.
"""

from __future__ import annotations

import functools
import logging
import ssl

__all__ = ["NarrowerRefused", "narrow_signature_algorithms"]

logger = logging.getLogger(__name__)

#: The marker every SHA-224 TLS signature scheme carries in its OpenSSL name: ``rsa_pkcs1_sha224``,
#: ``ecdsa_sha224`` and ``dsa_sha224`` (codepoints 0x0301, 0x0303, 0x0302). Matched case-blind.
_SHA224_SIGALG_MARKER = "sha224"

#: The ML-DSA schemes OpenSSL 3.5 adds through a provider, in the order its stock offer lists them
#: (0x0905, 0x0906, 0x0904). ``ssl.get_sigalgs`` does not list provider schemes, so these are put
#: back by name, at the front, where the stock offer has them (Manager ruling on BACKLOG #1171).
_PROVIDER_MLDSA_SIGALGS = ("mldsa65", "mldsa87", "mldsa44")

#: Set once the "cannot narrow" warning has been logged, so a context built per send logs it once.
_SIGALGS_PIN_WARNED = False

#: Set once the "ML-DSA left out" warning has been logged, for the same reason.
_SIGALGS_MLDSA_WARNED = False


class NarrowerRefused(RuntimeError):
    """No list the build will take is left: the signature schemes here (BACKLOG #1171), or the
    TLS 1.3 suites in ``tls_policy.narrow_tls13_suites``, which raises this class too.

    A :class:`RuntimeError` and never an :class:`ssl.SSLError`, so a caller that reads an
    ``SSLError`` as "cannot load the certificate", as the tray's ``load_pin`` does, cannot report a
    build fault as a bad file. ``tls_policy`` turns it into a configuration refusal (BACKLOG #2484);
    the apiclient and the tray let it propagate, as they do for a refused suite list."""


@functools.cache
def _sigalgs_without_sha224() -> str | None:
    """OpenSSL's own signature-scheme catalogue minus the SHA-224 schemes, as a ``:`` list.

    ``None`` only when the catalogue cannot be read: ``ssl.get_sigalgs`` is absent before CPython
    3.15, and raises ``NotImplementedError`` on an OpenSSL older than 3.4. A catalogue holding
    nothing but SHA-224 gives ``""``, which the setter refuses, so that case fails closed rather
    than reading as "cannot list". Read once per process, because the linked OpenSSL does not
    change while the process runs."""
    get_sigalgs = getattr(ssl, "get_sigalgs", None)
    if get_sigalgs is None:
        return None
    try:
        catalogue = [str(name) for name in get_sigalgs()]
    except NotImplementedError:
        return None
    return ":".join(name for name in catalogue if _SHA224_SIGALG_MARKER not in name.lower())


def _sigalg_candidates(base: str) -> tuple[str, str, str]:
    """The lists to try, in order: ML-DSA with OpenSSL's ``?`` (ignore if unknown) prefix, ML-DSA
    plain for a build without that prefix, then ``base`` alone. If ``base`` already holds any
    ML-DSA name, a later OpenSSL lists them itself, so its own list and order are used as they are."""
    held = {name.lower() for name in base.split(":")}
    if held & set(_PROVIDER_MLDSA_SIGALGS):
        return base, base, base
    marked = ":".join(f"?{name}" for name in _PROVIDER_MLDSA_SIGALGS)
    return f"{marked}:{base}", ":".join([*_PROVIDER_MLDSA_SIGALGS, base]), base


def narrow_signature_algorithms(ctx: ssl.SSLContext) -> bool:
    """Take the SHA-224 signature schemes out of ``ctx``; return whether it did (BACKLOG #1171).

    **This docstring is the one statement of the owner ruling of 2026-09-29 on ASVS 11.4.1**; other
    sites point here. The ruling: build it now behind a feature check, so an engine on Python 3.15
    stops offering SHA-224 signature schemes at once, while 3.14 keeps today's behaviour. Raising the
    supported floor to 3.15 is filed separately and is not part of this.

    **One setter covers every direction, and it is ``set_server_sigalgs``.** CPython 3.15 maps it to
    ``SSL_CTX_set1_sigalgs_list`` and ``set_client_sigalgs`` to
    ``SSL_CTX_set1_client_sigalgs_list`` (read in CPython's ``Modules/_ssl.c``). OpenSSL uses the
    first list for the ClientHello a client sends, for the scheme a server picks to sign with, and
    for the CertificateRequest a server sends, unless the second list is set. The second is set
    nowhere here, so the one call also covers a listener that asks for a client certificate. It
    also bounds which scheme a client may sign its own certificate proof with,
    and which peer signature a client accepts (read in OpenSSL 3.5 ``ssl/t1_lib.c``,
    ``tls12_get_psigalgs``). No handshake has been run on 3.15 here, so that reading is unmeasured.

    **The list is OpenSSL's own catalogue minus SHA-224, with ML-DSA put back.** ``ssl.get_sigalgs``
    returns every scheme libssl has built in and can use, so nothing is hand-picked there. It omits
    the schemes a provider adds, which on OpenSSL 3.5 are the three ML-DSA schemes (0x0904 to
    0x0906), and the stock ClientHello offers those first. The ruling was no interop change, and the
    post-quantum roadmap (ADR 0019) needs ML-DSA kept, so :data:`_PROVIDER_MLDSA_SIGALGS` puts them
    back at the front by name. Three lists are tried in order:

    1. ML-DSA with OpenSSL's ``?`` prefix, which skips a name the build does not know;
    2. ML-DSA without it, for a build that does not accept the prefix;
    3. the catalogue minus SHA-224 alone. This drops ML-DSA and logs a warning once per process.

    ML-DSA alone never makes this fail closed. Only a refusal of the third list raises.

    Measured through the OpenSSL 3.5.7 command line (``-sigalgs``, which sets the same list through
    the same OpenSSL call; not a CPython 3.15 run): the first list took, and the ClientHello lost
    exactly 0x0301, 0x0302 and 0x0303. One order change
    remains on the wire, once the security level has removed SHA-1: ``rsa_pss_rsae_*`` comes before
    ``rsa_pss_pss_*``. The two apply to different key types, so no certificate can use both.

    SHA-1 schemes stay in the list, as they are in the default one. The OpenSSL security level
    filters them out of what is sent, and ``tls_policy.refuse_lowered_security_level`` holds that
    level.

    **``False`` means SHA-224 is still offered.** That is CPython 3.14, which has no setter, and a
    3.15 linked to an OpenSSL older than 3.4, whose catalogue cannot be read. The second case logs a
    warning once per process and keeps today's behaviour, as 3.14 does (accepted by the Manager on
    BACKLOG #1171). An OpenSSL that refuses the list without ML-DSA, or a catalogue with no scheme
    left once SHA-224 is removed, raises :class:`NarrowerRefused`, a :class:`RuntimeError`, as
    ``tls_policy.narrow_tls13_suites`` does, so the failure is never blamed on an operator's
    ``tls_ciphers``. ``tls_policy``'s wrappers turn that into ``EngineTlsListRefused``, as they do
    for the TLS 1.3 list (BACKLOG #2484).

    **Reach.** Every engine-built context that narrows its suites, through
    ``tls_policy.narrow_to_approved_suites`` or ``tls_policy.apply_operator_tls_ciphers``, the LDAPS
    hop included since BACKLOG #2494 (``tls_policy.assert_ldap3_tls_suites``). Since BACKLOG #3414
    the client contexts outside ``tls_policy`` that narrow their suites are reached too: at least the
    apiclient's (``_build_verify_context``, both trust branches) and the tray probe's
    (``_narrow_to_approved_suites``, both branches), which call this function directly.

    **At least one context is deliberately not reached: the startup TLS-floor probe's offers in**
    ``config/tls_probe._offer_context``. They verify no certificate (``CERT_NONE``), so the
    signature they would bound authenticates nothing; the legacy offers are TLS 1.0 and 1.1, which
    carry no ``signature_algorithms`` extension; and the third offer is a default-capability client
    by design, so it stays the interpreter's stock offer. The comment there records it.

    A ``truststore.SSLContext`` is narrowed through its inner context, as in
    ``tls_policy.narrow_tls13_suites`` and for the same reason."""
    target = getattr(ctx, "_ctx", ctx)
    if not hasattr(target, "set_server_sigalgs"):
        return False  # CPython 3.14: no setter, so the stock list stands
    names = _sigalgs_without_sha224()
    if names is None:
        global _SIGALGS_PIN_WARNED
        if not _SIGALGS_PIN_WARNED:
            _SIGALGS_PIN_WARNED = True
            logger.warning(
                "Could not take SHA-224 out of the TLS signature schemes: this interpreter cannot "
                "list OpenSSL's schemes (ssl.get_sigalgs is absent, or the linked OpenSSL %s is "
                "older than 3.4) (BACKLOG #1171). Logged once per process.",
                ssl.OPENSSL_VERSION,
            )
        return False
    if not names:
        raise NarrowerRefused(
            "OpenSSL's signature scheme catalogue has no scheme left once SHA-224 is removed, so "
            "there is no list to pin (BACKLOG #1171)"
        )
    marked, plain, base = _sigalg_candidates(names)
    if marked != base:  # there is ML-DSA to put back
        for candidate in (marked, plain):
            try:
                target.set_server_sigalgs(candidate)
            except ssl.SSLError:
                continue  # this build refused the ML-DSA names or the prefix; try the next list
            return True
    try:
        target.set_server_sigalgs(base)
    except ssl.SSLError as exc:
        raise NarrowerRefused(
            f"this OpenSSL build refused the engine's signature scheme list, OpenSSL's own "
            f"catalogue without SHA-224 (BACKLOG #1171): {exc}"
        ) from exc
    global _SIGALGS_MLDSA_WARNED
    if marked != base and not _SIGALGS_MLDSA_WARNED:
        # Only after the list without ML-DSA took, so the log never says SHA-224 is gone when the
        # refusal above says it is not.
        _SIGALGS_MLDSA_WARNED = True
        logger.warning(
            "This OpenSSL (%s) refused the TLS signature scheme list with ML-DSA in it, so "
            "SHA-224 is removed and ML-DSA is not offered either (BACKLOG #1171). Logged once "
            "per process.",
            ssl.OPENSSL_VERSION,
        )
    return True
