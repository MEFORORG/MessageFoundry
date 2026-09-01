# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""One TLS trust anchor for a whole harness run.

The engine always serves TLS (BACKLOG #1276 part A, owner ruling 2026-08-22) and mints a
self-signed placeholder when no operator certificate is configured. That left every harness driver
talking cleartext to a TLS socket.

**The harness supplies the certificate rather than chasing the one the engine mints.**
:func:`ensure_api_tls_material` returns operator-supplied material on its FIRST branch and never
mints over it, so handing each node ``[api].tls_cert_file`` makes the generated path unreachable for
harness engines. Two properties follow, and both are the reason this module exists:

* **No race.** The pair is on disk before any engine is spawned, so no client ever waits for a file
  to appear. Waiting was the alternative, and its timeout would surface as "nodes did not become
  healthy" -- indistinguishable from the very bug this fixes.
* **One anchor, not N.** Minting per node would mean threading a different CA through every
  multi-node ``EnginePoller`` URL list. Minting once collapses that to a single constant.

Non-prod only, and it never leaves this box: the pair lands in a per-process temp directory and
covers loopback names alone.
"""

from __future__ import annotations

import functools
import os
import ssl
import tempfile
import threading
from pathlib import Path

__all__ = ["harness_ssl_context", "harness_tls_material"]

# Loopback only, on purpose. Every engine this harness SPAWNS binds 127.0.0.1; an engine on another
# box (shardcert's two-box rig) mints its own cert that this process has never seen, so it is out of
# this module's scope rather than quietly covered by a SAN that would not match anyway.
_CN = "127.0.0.1"
_SANS = ["127.0.0.1", "localhost", "::1"]

#: Published into the environment after minting so a CHILD harness process (connscale-remote, spawned
#: by batchbox) inherits the SAME anchor. Without this the child would mint its own pair and fail to
#: verify engines the PARENT started -- a cross-process bug that no single-process test would show.
_ENV_CERT = "MEFOR_HARNESS_TLS_CERT_FILE"
_ENV_KEY = "MEFOR_HARNESS_TLS_KEY_FILE"

_LOCK = threading.Lock()
_MATERIAL: tuple[str, str] | None = None


def harness_tls_material() -> tuple[str, str]:
    """``(cert_path, key_path)`` for this process, minted once on first call.

    Feed these to a node as ``MEFOR_API_TLS_CERT_FILE`` / ``MEFOR_API_TLS_KEY_FILE``.
    """
    global _MATERIAL
    with _LOCK:
        if _MATERIAL is None:
            inherited = os.environ.get(_ENV_CERT), os.environ.get(_ENV_KEY)
            if all(inherited) and Path(inherited[0] or "").exists():
                # A parent harness process already minted for this run; reuse its anchor verbatim.
                _MATERIAL = (inherited[0] or "", inherited[1] or "")
                return _MATERIAL
            # Local import: pki pulls cryptography, which the harness should not require merely to
            # be imported (the load package is imported by report-only paths too).
            from messagefoundry import pki

            state = Path(tempfile.mkdtemp(prefix="mefor-harness-tls-"))
            cert_pem, key_pem = pki.make_self_signed(_CN, _SANS, 365)
            cert_path = state / "harness-api-cert.pem"
            key_path = state / "harness-api-key.pem"
            cert_path.write_bytes(cert_pem)
            key_path.write_bytes(key_pem)
            # Best-effort on Windows, where mode bits are advisory; the engine's own
            # _write_private_key applies the real DACL to material IT writes, and this pair is a
            # throwaway in a temp dir either way.
            key_path.chmod(0o600)
            _MATERIAL = (str(cert_path), str(key_path))
            os.environ.setdefault(_ENV_CERT, _MATERIAL[0])
            os.environ.setdefault(_ENV_KEY, _MATERIAL[1])
        return _MATERIAL


@functools.cache
def harness_ssl_context() -> ssl.SSLContext:
    """A client context whose ONLY trust anchor is :func:`harness_tls_material`'s certificate.

    Pinning rather than disabling verification: the harness minted this certificate itself, so
    verifying against it costs nothing and keeps the ad-hoc ``httpx`` probes and the shared
    ``EngineClient`` (which offers pinning and no way to switch verification off) on one posture.

    **Cached by decorator, never by a nullable module global.** The obvious lazy singleton --
    ``_CONTEXT: ssl.SSLContext | None = None`` plus an ``if _CONTEXT is None`` guard -- makes the
    literal ``None`` a value this function can return as far as any caller or any analyser can prove.
    Every call site feeds the result straight to ``httpx``'s ``verify=``, where a falsy value means
    *verification off*, so that shape puts a "may run without certificate validation" finding on all
    four httpx clients in the load harness (CodeQL ``py/request-without-cert-validation``, high). The
    runtime never actually returned ``None``; the point is that nothing made it provable, and an
    unprovable claim about TLS verification is the kind that rots silently. Returning
    ``ssl.create_default_context(...)`` directly mirrors ``apiclient.client._build_verify_context``,
    which has the same job and has never carried a nullable cache.

    Thread-safety is unchanged in the way that matters: the single ANCHOR is still serialised by
    :func:`harness_tls_material`'s lock. A race here can build two contexts over that one anchor,
    which are interchangeable -- nothing compares context identity.
    """
    cert_path, _ = harness_tls_material()
    return ssl.create_default_context(cafile=cert_path)
