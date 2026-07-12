# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Kerberos/SPNEGO channel-binding (EPA) acceptor-enforcement spike (BACKLOG #98(a)).

**AD-independent prep — a diagnostic, not a shipped feature and NOT a test.** It lives under
``scripts/`` (outside ``testpaths = ["tests"]``) so a plain ``pytest`` run never collects it: on a
box with no AD/KDC there is nothing to run and nothing to skip. Run it by hand *inside the
domain-joined lab* per ``docs/security/KERBEROS-EPA-SPIKE-RUNBOOK.md``.

**The question it answers (ADR 0068 §9 open item).** Browser SSO ships with ``channel_bindings=None``
on the acceptor *always* (behind a TLS-terminating proxy, ``tls-server-end-point`` EPA is
structurally broken — the browser hashed the *proxy's* cert, not the engine's, so EPA must never be
silently enforced; see ``OFF-LOOPBACK-DEPLOYMENT.md``). The undecided part is: **when the acceptor is
built with** ``channel_bindings=None`` **but a client presents a channel-binding token (CBT), does the
provider ENFORCE it (reject) or IGNORE it (accept)?** GSSAPI acceptors traditionally ignore a client
CBT unless the acceptor itself supplies bindings; Windows SSPI may enforce under registry/EPA policy.

- If the decisive cell **(server=None, client=present)** ACCEPTS → the acceptor ignores client CBT →
  the WP-15 reverse-proxy posture is safe untouched, **no knob needed** for #98(b).
- If it REJECTS → SSPI is enforcing → an explicit CBT-off knob (or an opt-in
  ``tls-server-end-point`` binding for the in-process-TLS mode only) is warranted — #98(b).

**How it mirrors production.** The acceptor is constructed exactly as
``messagefoundry/auth/ldap.py`` builds it — ``spnego.server(service=<spn>, channel_bindings=<...>)``
then ``server.step(token)`` — the only addition being the ``channel_bindings`` argument this spike
varies. The client leg drives a real in-process SPNEGO exchange via ``spnego.client(...)``, so the
provider's *actual* enforcement behaviour is observed, not assumed.

Env vars (all required; the runbook sets them):

* ``MEFOR_SPIKE_SPN``      — the acceptor SPN, e.g. ``HTTP/engine.lab.example.com`` (matches
  ``[auth].kerberos_spn``). Passed verbatim as ``service=`` to the acceptor, mirroring ldap.py.
* ``MEFOR_SPIKE_HOSTNAME`` — the client-side target host (FQDN); used only if the SPN has no ``/``.
* ``MEFOR_SPIKE_USER``     — the test domain user for the client leg (``user`` or ``user@REALM``).
* ``MEFOR_SPIKE_PASS``     — that user's password (lab, disposable — never a prod credential).
* ``MEFOR_SPIKE_DOMAIN``   — the lab realm/domain, recorded in the report header for provenance.
* ``MEFOR_SPIKE_CERT_HASH_HEX`` (optional) — hex of a real server-cert hash to use as the
  ``tls-server-end-point`` application data; if unset a fixed synthetic hash is used (the enforce/
  ignore decision does not depend on the hash being a real cert digest).

Exit code: ``0`` if the exchange ran and a matrix was produced (spike succeeded — read the matrix for
the answer), ``2`` on a setup/precondition failure (missing env, no Kerberos-capable provider).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import for typing only; the runtime imports are lazy (mirrors ldap.py)
    from spnego import ContextProxy
    from spnego.channel_bindings import GssChannelBindings

# A fixed 32-byte stand-in for a SHA-256 tls-server-end-point cert hash (RFC 5929 §4.1). The
# ignore-vs-enforce decision turns on *whether* a CBT is present and whether the two sides agree —
# not on the bytes being a genuine cert digest — so a deterministic placeholder keeps the run
# reproducible. Override with MEFOR_SPIKE_CERT_HASH_HEX to bind a real certificate.
_HASH_A = bytes(range(32))
_HASH_B = bytes(range(32, 64))  # a distinct hash for the "mismatching client CBT" column

_ENV_VARS = (
    "MEFOR_SPIKE_SPN",
    "MEFOR_SPIKE_HOSTNAME",
    "MEFOR_SPIKE_USER",
    "MEFOR_SPIKE_PASS",
    "MEFOR_SPIKE_DOMAIN",
)


@dataclass(frozen=True)
class LabParams:
    """The domain-joined lab inputs, read from the environment."""

    spn: str
    hostname: str
    username: str
    password: str
    domain: str
    cert_hash: bytes

    @property
    def client_service(self) -> str:
        """Service class for the *client* target SPN (``HTTP`` from ``HTTP/host``)."""
        return self.spn.split("/", 1)[0] if "/" in self.spn else self.spn

    @property
    def client_hostname(self) -> str:
        """Host for the *client* target SPN — the ``/``-suffix of the SPN, else the env hostname."""
        return self.spn.split("/", 1)[1] if "/" in self.spn else self.hostname


@dataclass(frozen=True)
class CellResult:
    """Outcome of one exchange cell — richer than a bare accept/reject so the verdict can tell a
    *channel-binding* rejection apart from a broken exchange (KDC/SPN/creds), and can confirm the
    mech that actually resolved was Kerberos and not a silent NTLM fallback."""

    accepted: bool
    detail: str
    # The mech that actually negotiated for this exchange (``"kerberos"``/``"ntlm"``/…), read off the
    # contexts when observable; ``None`` if the handshake never got far enough to negotiate one.
    negotiated: str | None
    # True only when the rejection was specifically a channel-binding (EPA) rejection
    # (``BadBindingsError``) — not a generic ``SpnegoError``/KDC/SPN/credential failure.
    bad_bindings: bool


def _read_params() -> LabParams | None:
    """Read + validate the lab env vars. Returns ``None`` (with a diagnostic) if any is missing."""
    missing = [name for name in _ENV_VARS if not os.environ.get(name)]
    if missing:
        print("Kerberos EPA spike — PRECONDITION NOT MET (setup only, no exchange run)")
        print(f"  missing required env vars: {', '.join(missing)}")
        print(
            "  set them per docs/security/KERBEROS-EPA-SPIKE-RUNBOOK.md inside the lab, then re-run"
        )
        return None
    hash_hex = os.environ.get("MEFOR_SPIKE_CERT_HASH_HEX")
    if hash_hex:
        try:
            cert_hash = bytes.fromhex(hash_hex)
        except ValueError:
            print(f"MEFOR_SPIKE_CERT_HASH_HEX is not valid hex: {hash_hex!r}")
            return None
    else:
        cert_hash = _HASH_A
    return LabParams(
        spn=os.environ["MEFOR_SPIKE_SPN"],
        hostname=os.environ["MEFOR_SPIKE_HOSTNAME"],
        username=os.environ["MEFOR_SPIKE_USER"],
        password=os.environ["MEFOR_SPIKE_PASS"],
        domain=os.environ["MEFOR_SPIKE_DOMAIN"],
        cert_hash=cert_hash,
    )


def _kerberos_capable() -> bool:
    """Whether a **Kerberos-capable** SPNEGO provider is present — SSPI (Windows) or GSSAPI (Linux
    with krb5). Mirrors ``messagefoundry.auth.ldap._kerberos_capable`` so the spike gates on exactly
    what production requires; the pure-Python NTLM-only fallback cannot validate a Kerberos ticket."""
    import importlib

    try:
        for mod, cls in (("spnego._sspi", "SSPIProxy"), ("spnego._gss", "GSSAPIProxy")):
            try:
                proxy = getattr(importlib.import_module(mod), cls)
                if "kerberos" in proxy.available_protocols():
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return True


def _detect_provider() -> str:
    """Name the active SPNEGO provider — the answer to the spike differs by backend, so it is
    reported alongside the matrix. SSPI (Windows) and GSSAPI (Linux/krb5) are the Kerberos-capable
    ones; anything else is the pure-Python NTLM fallback that cannot validate a ticket."""
    import importlib

    for mod, cls, label in (
        ("spnego._sspi", "SSPIProxy", "SSPI (Windows native)"),
        ("spnego._gss", "GSSAPIProxy", "GSSAPI (Linux / krb5)"),
    ):
        try:
            proxy = getattr(importlib.import_module(mod), cls)
            if "kerberos" in proxy.available_protocols():
                return label
        except Exception:
            continue
    return "pure-Python NTLM fallback (NOT Kerberos-capable)"


def _bindings(cert_hash: bytes) -> GssChannelBindings:
    """A ``tls-server-end-point`` channel-binding structure (RFC 5929 §4.1): the application data is
    the literal ``tls-server-end-point:`` prefix followed by the raw cert hash."""
    from spnego.channel_bindings import GssChannelBindings

    return GssChannelBindings(application_data=b"tls-server-end-point:" + cert_hash)


def _negotiated_mech(*contexts: ContextProxy | None) -> str | None:
    """Best-effort read of the mech that actually negotiated (``kerberos``/``ntlm``/…). SPNEGO can
    fall back to NTLM silently even under the Kerberos-capable provider; the verdict must know which
    mech answered before attributing a result to Kerberos. Returns ``None`` if no context resolved
    one (e.g. the handshake failed before mech selection)."""
    for ctx in contexts:
        if ctx is None:
            continue
        proto = getattr(ctx, "negotiated_protocol", None)
        if proto:
            return str(proto)
    return None


def _run_exchange(
    params: LabParams,
    server_cb: GssChannelBindings | None,
    client_cb: GssChannelBindings | None,
) -> CellResult:
    """Drive one real in-process SPNEGO exchange and report a :class:`CellResult`.

    The acceptor is built exactly as ``auth/ldap.py`` does — ``spnego.server(service=<spn>, …)`` +
    ``server.step(token)`` — with only ``channel_bindings`` added. A rejected exchange raises
    ``SpnegoError``; the provider's *channel-binding* (EPA) rejection surfaces specifically as
    ``BadBindingsError`` and is flagged so the verdict never confuses it with an unrelated
    KDC/SPN/credential failure. Anything that completes the context is an accept.
    """
    import spnego
    from spnego.exceptions import BadBindingsError

    # Declared up front so the ``except`` handlers can still read the negotiated mech off whatever
    # context got constructed before the failure.
    client: ContextProxy | None = None
    server: ContextProxy | None = None
    try:
        client = spnego.client(
            username=params.username,
            password=params.password,
            hostname=params.client_hostname,
            service=params.client_service,
            channel_bindings=client_cb,
        )
        # Mirror ldap.py's acceptor construction verbatim, plus the varied channel_bindings.
        server = spnego.server(service=params.spn, channel_bindings=server_cb)

        token = client.step()
        # SPNEGO can be multi-leg; bound the ping-pong so a misbehaving provider can't spin forever.
        for _ in range(12):
            if token is None:
                break
            out = server.step(token)  # the decisive step — a CBT rejection raises here
            if server.complete and client.complete:
                return CellResult(
                    True, "context established", _negotiated_mech(server, client), False
                )
            if out is None:
                break
            token = client.step(out)
            if client.complete and server.complete:
                return CellResult(
                    True, "context established", _negotiated_mech(server, client), False
                )
        if server.complete and client.complete:
            return CellResult(True, "context established", _negotiated_mech(server, client), False)
        return CellResult(
            False,
            "handshake did not complete (no exception, context incomplete)",
            _negotiated_mech(server, client),
            False,
        )
    except BadBindingsError as exc:
        # The one rejection that actually means "the acceptor enforced the channel binding".
        return CellResult(
            False,
            f"rejected (channel-binding EPA): {type(exc).__name__}: {exc}",
            _negotiated_mech(server, client),
            True,
        )
    except spnego.exceptions.SpnegoError as exc:
        # A rejection, but NOT a channel-binding one (bad SPN/name, bad creds, clock skew, KDC
        # unreachable, …). It says nothing about EPA enforcement.
        return CellResult(
            False,
            f"rejected (NOT channel-binding): {type(exc).__name__}: {exc}",
            _negotiated_mech(server, client),
            False,
        )
    except (ValueError, OSError) as exc:
        # The pure-Python provider raises bare ValueErrors parsing a token; OSError covers a KDC/
        # credential I/O failure. Both are a failed exchange, not an enforcement signal.
        return CellResult(
            False, f"error: {type(exc).__name__}: {exc}", _negotiated_mech(server, client), False
        )


def _interpret(server_has_cb: bool, client_kind: str, accepted: bool) -> str:
    """One-line reading of a cell — what its accept/reject means for #98(a)/(b)."""
    if not server_has_cb:
        if client_kind == "none":
            return "baseline: neither side binds — must ACCEPT (sanity check)"
        # The decisive cells: acceptor bound to nothing, client presenting a CBT.
        if accepted:
            return "DECISIVE → acceptor IGNORES client CBT (proxy posture SAFE, no knob needed)"
        return "DECISIVE → acceptor ENFORCES client CBT (SSPI/EPA — #98(b) knob WARRANTED)"
    # Acceptor supplies bindings — the conventional EPA-on direction.
    if client_kind == "none":
        return "acceptor bound, client unbound → reject expected if EPA is honoured"
    if client_kind == "matching":
        return "both bound + agree → ACCEPT expected (EPA satisfied)"
    return "both bound + DISAGREE → reject expected (EPA mismatch caught)"


def main() -> int:
    params = _read_params()
    if params is None:
        return 2

    print("=" * 78)
    print("Kerberos / SPNEGO channel-binding (EPA) acceptor-enforcement spike — BACKLOG #98(a)")
    print("=" * 78)
    print(f"  domain     : {params.domain}")
    print(f"  acceptor SPN: {params.spn}  (passed verbatim as service= — mirrors auth/ldap.py)")
    print(f"  client user : {params.username}")
    print(
        f"  cert hash   : {'operator-supplied' if len(params.cert_hash) != 32 or params.cert_hash != _HASH_A else 'synthetic placeholder'} ({len(params.cert_hash)} bytes)"
    )

    provider = _detect_provider()
    print(f"  SPNEGO provider: {provider}")
    if not _kerberos_capable():
        print()
        print("PRECONDITION NOT MET: no Kerberos-capable provider (SSPI/GSSAPI). The pure-Python")
        print("NTLM fallback cannot validate a Kerberos ticket, so the spike cannot run here.")
        print("Run this on the domain-joined acceptor host per the runbook.")
        return 2

    server_none = None
    server_a = _bindings(params.cert_hash)
    client_matrix: list[tuple[str, GssChannelBindings | None]] = [
        ("none", None),
        ("matching", _bindings(params.cert_hash)),
        ("mismatching", _bindings(_HASH_B)),
    ]

    rows: list[tuple[str, str, CellResult, str]] = []
    for server_label, server_cb in (("None", server_none), ("tls-server-end-point", server_a)):
        for client_kind, client_cb in client_matrix:
            res = _run_exchange(params, server_cb, client_cb)
            interp = _interpret(server_cb is not None, client_kind, res.accepted)
            rows.append((server_label, client_kind, res, interp))

    print()
    print("ENFORCEMENT MATRIX")
    print("-" * 78)
    print(f"  {'server CBT':<22}{'client CBT':<14}{'result':<10}{'mech':<10}outcome")
    print("  " + "-" * 74)
    for server_label, client_kind, res, interp in rows:
        result = "ACCEPT" if res.accepted else "REJECT"
        mech = res.negotiated or "-"
        print(f"  {server_label:<22}{client_kind:<14}{result:<10}{mech:<10}{interp}")
        print(f"  {'':<22}{'':<14}{'':<10}{'':<10}({res.detail})")
    print("-" * 78)

    # Locate the baseline sanity cell (neither side binds) and the two decisive cells (server=None,
    # client presents a CBT). The verdict is gated on both so a broken exchange (KDC/SPN/creds/clock
    # skew) or a silent NTLM fallback can never masquerade as a Kerberos EPA-enforcement result.
    baseline = next(r[2] for r in rows if r[0] == "None" and r[1] == "none")
    decisive = [r[2] for r in rows if r[0] == "None" and r[1] != "none"]

    decisive_accepts = all(r.accepted for r in decisive)
    # ENFORCES requires the *channel-binding* rejection specifically, not any rejection.
    decisive_cb_rejects = all((not r.accepted) and r.bad_bindings for r in decisive)
    # Every cell the verdict rests on must have actually resolved over Kerberos, not NTLM.
    verdict_cells = [baseline, *decisive]
    mechs = {r.negotiated for r in verdict_cells}
    all_kerberos = mechs == {"kerberos"}
    baseline_ok = baseline.accepted

    print()
    print("VERDICT (BACKLOG #98(a)):")
    if not all_kerberos:
        # Any cell that did not negotiate Kerberos (fell back to NTLM, or never negotiated a mech)
        # makes this NOT a Kerberos answer — NTLM's channel-binding semantics differ, so a result
        # resolved over it would attribute the wrong mech's behaviour to Kerberos.
        observed = ", ".join(sorted(m or "none" for m in mechs))
        print(
            "  INCONCLUSIVE — the verdict cells did not all negotiate Kerberos (observed mech(s):"
        )
        print(
            f"    {observed}). SPNEGO may have fallen back to NTLM, or the handshake failed before"
        )
        print("    mech selection. NTLM channel-binding semantics differ from Kerberos, so no")
        print("    Kerberos EPA conclusion can be drawn. Fix the SPN/DNS/TGT so Kerberos resolves,")
        print("    then re-run (see runbook §5).")
    elif not baseline_ok:
        # The control leg failed its own "must ACCEPT" expectation → the rig itself is broken; any
        # rejection in the decisive cells is untrustworthy as an enforcement signal.
        print(
            "  INCONCLUSIVE — the baseline cell (server=None, client=none) did NOT accept, so the"
        )
        print("  exchange rig is broken (KDC/SPN/creds/clock skew). A rejection in the decisive")
        print(f"    cells cannot be read as EPA enforcement. Baseline detail: ({baseline.detail})")
        print("  Repair the baseline to ACCEPT, then re-run (see runbook §5).")
    elif decisive_accepts:
        print(
            f"  On {provider}, the acceptor built with channel_bindings=None IGNORES a client CBT."
        )
        print("  → The WP-15 reverse-proxy posture is safe as shipped; no CBT-off knob is needed.")
        print("  → #98(b) opt-in binding is OPTIONAL (in-process-TLS mode only), not required.")
    elif decisive_cb_rejects:
        print(
            f"  On {provider}, the acceptor built with channel_bindings=None ENFORCES a client CBT."
        )
        print("  → Confirmed via a channel-binding rejection (BadBindingsError) in every decisive")
        print("    cell, with the baseline accepting and Kerberos negotiated throughout.")
        print(
            "  → A deployment behind a TLS-terminating proxy would break (EPA structurally wrong)."
        )
        print("  → #98(b) is WARRANTED: an explicit CBT-off knob, and/or an opt-in")
        print("    tls-server-end-point binding for the in-process-TLS termination mode only.")
    else:
        print(
            "  Mixed / non-channel-binding result across the decisive cells — inspect the (detail)"
        )
        print(
            "  lines above. A rejection that is NOT a BadBindingsError (bad SPN/name, creds, clock"
        )
        print(
            "  skew, KDC unreachable) is not EPA enforcement; resolve it and re-run before drawing"
        )
        print("  a conclusion (see runbook §5).")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
