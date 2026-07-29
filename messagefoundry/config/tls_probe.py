# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Startup TLS-floor probe against the declared front door (ASVS 12.1.1).

**This module is the cell.** Off-loopback the browser/API TLS is terminated at the operator's reverse
proxy, so the engine negotiates no browser-facing TLS and cannot enforce or inspect the minimum
version — that is the residual of record. `[api].proxy_tls_min_version` was the answer, and it is only
an **attestation**: the operator types ``1.2`` and nothing checks it. Making an unverified declaration
*mandatory* does not close the requirement; it just makes the unchecked claim compulsory.

A probe converts the declaration into a **measurement**. At startup the engine dials its own declared
``public_origin`` and asks the proxy three questions:

1. *Do you still speak TLS 1.0?* — offered with ``minimum_version == maximum_version == TLSv1`` and
   ``ALL:@SECLEVEL=0`` so the offer is genuinely made. A **successful handshake is the failure**: it
   proves the front door accepts a protocol NIST SP 800-52r2 withdrew.
2. *Do you still speak TLS 1.1?* — same shape.
3. *What do you actually choose?* — a **default-capability** client, asserting the negotiated version.
   This is deliberately a full offer rather than a 1.3-only probe: version selection is server-driven,
   so a full offer landing on 1.3 proves the proxy **prefers** it, whereas a 1.3-only handshake proves
   only that it *supports* it. Preference is the property 12.1.1 is about.

**The enum is asserted, never skipped.** ``ssl.TLSVersion.TLSv1``/``TLSv1_1`` are deprecated and will
eventually be removed. A probe that quietly skipped when the enum vanished would become a gate that
cannot fail — the exact ``harden_kex_groups`` failure mode this codebase already carries (it pins
nothing on 3.14.6 because ``set_groups`` does not exist, and returns silently). So the absence of the
enum is an **error**, not a skip: the check must be rebuilt, not silently retired.

**Certificate validation is deliberately OFF here** (``CERT_NONE``). The probe measures the *protocol
floor*, not the chain — an internal CA the engine does not trust would otherwise mask the answer, and
a self-signed proxy cert would read as "TLS 1.0 refused" when it was never asked. Chain validation for
real traffic is a different control (12.1.4 / ``harden_verify_flags``); this context is built here,
used for one handshake, and never returned to a caller.

**Operational cost, stated rather than buried.** On the posture where this refuses, a boot now depends
on the proxy being reachable. That is a real tension for an interface engine and it is deliberate: an
unreachable-means-warn rule is defeated by start ordering (start the engine first and the check never
runs), so warn-on-unreachable is not a gate at all. The blast radius is bounded to the posture the
requirement is about — a declared upstream terminator on a PHI instance under ``enforce`` — and every
other posture is byte-identical. A regression detected *later*, at runtime, must NOT kill the engine
and the hospital's feed with it; that path belongs to an AlertSink event.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

__all__ = [
    "LEGACY_TLS_VERSIONS",
    "TlsFloorProbe",
    "probe_tls_floor",
]

#: The withdrawn protocol versions the front door must refuse (NIST SP 800-52r2). Held as NAMES and
#: resolved through :func:`_legacy_version` so a runtime that has dropped the enum is an ERROR rather
#: than a silent skip.
LEGACY_TLS_VERSIONS = ("TLSv1", "TLSv1_1")

#: Seconds per handshake attempt. Three attempts, so the worst case adds ~3x this to startup. Short
#: enough that a wedged proxy fails fast, long enough for a loaded one to answer.
_PROBE_TIMEOUT_SECONDS = 5.0


class TlsProbeUnavailable(RuntimeError):
    """The probe cannot run as specified — e.g. the interpreter dropped a deprecated ``TLSVersion``.

    Raised rather than returning a "skip" result, deliberately: a security check that degrades to a
    no-op when its mechanism disappears reports success forever afterwards. Callers must treat this as
    a build/runtime defect to fix, never as a pass.
    """


def _legacy_version(name: str) -> ssl.TLSVersion:
    """The :class:`ssl.TLSVersion` member for ``name``, or raise :class:`TlsProbeUnavailable`."""
    member = getattr(ssl.TLSVersion, name, None)
    if not isinstance(member, ssl.TLSVersion):
        raise TlsProbeUnavailable(
            f"ssl.TLSVersion.{name} is not available on this interpreter, so the TLS-floor probe "
            f"cannot offer a {name} handshake. This check must be rebuilt against whatever the "
            f"runtime now exposes — do NOT let it degrade to a skip, which would make it a gate that "
            f"cannot fail (ASVS 12.1.1)."
        )
    return member


def _offer_context(version: ssl.TLSVersion | None) -> ssl.SSLContext:
    """A client context that offers exactly ``version`` (or the default capability when ``None``).

    ``check_hostname``/``verify_mode`` are off because this measures the PROTOCOL FLOOR: an untrusted
    internal CA would otherwise abort the handshake before the version was settled, and the probe
    would report "legacy refused" for a door it never actually knocked on. This context handles no
    application data and never leaves this module.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        ctx.minimum_version = version
        ctx.maximum_version = version
        # SECLEVEL=0 is required for the offer to be genuine: modern OpenSSL refuses to even send a
        # TLS 1.0 ClientHello at the default security level, so without this the probe would measure
        # OUR refusal to ask rather than THEIR refusal to answer — a false pass.
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


@dataclass(frozen=True, slots=True)
class TlsFloorProbe:
    """What the declared front door actually did when asked."""

    host: str
    port: int
    reachable: bool
    #: Withdrawn versions the front door ACCEPTED. Non-empty is a failure.
    legacy_accepted: tuple[str, ...]
    #: The version a default-capability client negotiated, or ``None`` if it could not connect.
    negotiated: str | None
    #: Transport-level detail when unreachable. Never contains a credential.
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True only when the door was reached, refused every withdrawn version, and chose TLS 1.3."""
        return self.reachable and not self.legacy_accepted and self.negotiated == "TLSv1.3"

    def describe(self) -> str:
        """A one-line operator-facing summary. PHI-free by construction — host, port, versions only."""
        if not self.reachable:
            return f"{self.host}:{self.port} unreachable ({self.error})"
        parts = [f"negotiated {self.negotiated}"]
        if self.legacy_accepted:
            parts.append(f"ACCEPTS withdrawn {', '.join(self.legacy_accepted)}")
        else:
            parts.append("refused TLS 1.0 and 1.1")
        return f"{self.host}:{self.port}: " + "; ".join(parts)


def _handshake(host: str, port: int, ctx: ssl.SSLContext) -> tuple[bool, str | None, str | None]:
    """``(completed, negotiated_version, error)`` for one handshake attempt."""
    try:
        with (
            socket.create_connection((host, port), timeout=_PROBE_TIMEOUT_SECONDS) as raw,
            ctx.wrap_socket(raw, server_hostname=host) as tls,
        ):
            return True, tls.version(), None
    except ssl.SSLError as exc:
        # A refused protocol/cipher is the EXPECTED outcome of the legacy probes — not an error.
        return False, None, str(exc)
    except (OSError, TimeoutError) as exc:
        return False, None, f"{type(exc).__name__}: {exc}"


def probe_tls_floor(origin: str) -> TlsFloorProbe:
    """Measure the TLS floor of ``origin`` (an ``https://host[:port]`` URL).

    Raises :class:`TlsProbeUnavailable` if the interpreter cannot express the legacy offers — see the
    module docstring on why that is an error rather than a skip. Never raises for a merely
    unreachable or badly-behaved front door: those are reported in the result so the CALLER decides
    the disposition, which keeps the policy in the serve gate and the measurement here.
    """
    parts = urlsplit(origin)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if not host:
        raise ValueError(f"cannot probe {origin!r}: no host")

    # Resolve BOTH enums up front so an unavailable one fails before any network call — the failure is
    # about this build, not about the operator's proxy, and should not look like a proxy problem.
    legacy = [(name, _legacy_version(name)) for name in LEGACY_TLS_VERSIONS]

    accepted: list[str] = []
    for name, version in legacy:
        completed, _negotiated, _err = _handshake(host, port, _offer_context(version))
        if completed:
            # The door answered a withdrawn protocol. THIS is the finding.
            accepted.append(name.replace("_", "."))

    completed, negotiated, error = _handshake(host, port, _offer_context(None))
    if not completed:
        return TlsFloorProbe(host, port, False, tuple(accepted), None, error)
    return TlsFloorProbe(host, port, True, tuple(accepted), negotiated, None)
