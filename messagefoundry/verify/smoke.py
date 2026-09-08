# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""End-to-end smoke + store connectivity — proves the deployment actually works on this box.

* ``self``  — route a synthetic HL7 through the box's *real* config via :func:`dry_run` (no store, no
  network, no side effects). Proves the config loads + routes + transforms cleanly on this host.
* ``live``  — MLLP-send a synthetic HL7 to the running engine's inbound and confirm an **AA ACK**.
  Proves the real listener accepts + acks. (Full disposition is then confirmed in the console — a
  MANUAL row — so the tool stays dependency-light and not brittle to API specifics.)
* store     — open the configured store backend and confirm it connects (no writes beyond the
  idempotent schema-ensure ``open_store`` already does).

Synthetic HL7 only — never real PHI. The smoke message is inlined below rather than generated, so
the verifier never imports ``messagefoundry.generators`` (BACKLOG #1192 / ASVS 15.2.3).
"""

from __future__ import annotations

import socket
import ssl
from typing import Final

from messagefoundry.config.settings import StoreSettings
from messagefoundry.config.tls_policy import (
    harden_cipher_suites,
    harden_kex_groups,
    harden_verify_flags,
)
from messagefoundry.verify.model import CheckResult, Status

#: The smoke message, segment by segment.
#:
#: **Why it is a literal.** The deployment verifier is the one tool an operator runs on a real box,
#: so anything it imports is functionality that install is required to carry. Generating the message
#: pulled the whole ``messagefoundry.generators`` package — development tooling — into the verifier's
#: runtime dependency set. Inlining removes that edge. Nothing else under ``messagefoundry/verify/``
#: touches the generators, and ``tests/test_verify.py`` pins that.
#:
#: **Where it came from.** ``generate_message("ADT", "A01", 0)`` from the engine's own ADT generator
#: at ``744a7a434``, verbatim, except that every person name was replaced with the ``ZZZTEST`` family
#: so an operator who finds this message in their own store reads it as a probe rather than a
#: patient. The edited form was re-checked through the generator's compliance gate and hl7apy strict
#: validation at 2.5.1 before being pasted here, and ``tests/test_verify.py`` re-runs that validation
#: on every test run — so the literal cannot rot into a non-conformant message unnoticed.
#:
#: Every value is fabricated: the demographics come from the generator's synthetic pools, the phone
#: sits in the reserved 555-01xx fictional range, and MSH-10 carries the tool's own ``MEFOR`` prefix.
#: No real PHI (CLAUDE.md section 9).
_SYNTHETIC_ADT_A01_SEGMENTS: Final[tuple[str, ...]] = (
    r"MSH|^~\&|ADT|MAINHOSP|PHARMACY|MAINHOSP|20260202114200||ADT^A01^ADT_A01"
    r"|MEFORADTA0100000|P|2.5.1",
    "EVN|A01|20260202114200||||20260202114200",
    "PID|1||6824181^^^HOSP^MR||ZZZTEST^SYNTHETIC^C||20081018|U|||"
    "26 HILLCREST AVE^^CLAYTON^MO^63105^USA||(834)555-0120|||||V2167387^^^HOSP^AN",
    "NK1|1|ZZZTEST^KINONE|CHD^Child^HL70063",
    "NK1|2|ZZZTEST^KINTWO|FND^Friend^HL70063",
    "PV1|1|R|MATERNITY^412^B^SOUTH||||1008^ZZZTEST^PROVONE|||URO|||||||1006^ZZZTEST^PROVTWO"
    "||V2167387^^^HOSP^VN|||||||||||||||||||||||||20260202114200",
    "PV2|||R07.9^Chest pain unspecified^I10",
    "DB1|1|PT",
    "DB1|2|PT",
    "OBX|1|NM|8302-2^Body height^LN||170|cm|||||F",
    "AL1|1|DA^Drug allergy^HL70127|SULFA^Sulfa drugs^L|MO",
)

#: ``\r``-delimited with a trailing ``\r``, the form the generator emits and an MLLP frame carries.
SYNTHETIC_ADT_A01: Final[str] = "\r".join(_SYNTHETIC_ADT_A01_SEGMENTS) + "\r"


def synthetic_message() -> str:
    """One conformant synthetic ADT^A01 (no PHI). See :data:`SYNTHETIC_ADT_A01`."""
    return SYNTHETIC_ADT_A01


def smoke_self(
    config_dir: str, *, inbound: str | None = None, snapshot_on_send: bool = False
) -> CheckResult:
    """Route a synthetic message through the box's config with no side effects (``dry_run``).

    ``snapshot_on_send`` (ADR 0104) selects the copy-on-Send posture the preview reproduces, matching
    the live engine's ``[pipeline].snapshot_on_send``. It keeps the library default ``False`` here so a
    caller that resolves no service settings previews the pre-ADR-0104 behaviour; the verify runner
    passes the resolved setting (``True`` on a default engine) so the smoke mirrors what actually ships
    — see :func:`messagefoundry.verify.runner.run_verify`."""
    from pathlib import Path

    if not Path(config_dir).is_dir():
        return CheckResult(
            "smoke.self",
            "Self smoke (dry-run routing)",
            Status.SKIP,
            f"no config dir at {config_dir!r} — pass --config <your config repo>",
        )
    from messagefoundry.config.wiring import WiringError, load_config
    from messagefoundry.pipeline.dryrun import dry_run

    try:
        reg = load_config(config_dir)
    except WiringError as exc:
        return CheckResult(
            "smoke.self",
            "Self smoke (dry-run routing)",
            Status.FAIL,
            f"config failed to load: {exc}",
        )
    msg = synthetic_message()  # a module constant since #1192 — cannot fail
    try:
        result = dry_run(reg, msg, inbound=inbound, snapshot_on_send=snapshot_on_send)
    except ValueError as exc:  # ambiguous/unknown inbound
        return CheckResult("smoke.self", "Self smoke (dry-run routing)", Status.SKIP, str(exc))
    except Exception as exc:
        return CheckResult(
            "smoke.self", "Self smoke (dry-run routing)", Status.ERROR, f"dry-run raised: {exc!r}"
        )

    summary = (
        f"inbound={result.inbound}, disposition={result.disposition.value}, "
        f"handlers={len(result.handlers)}, deliveries={len(result.deliveries)}"
    )
    if result.error:
        return CheckResult(
            "smoke.self", "Self smoke (dry-run routing)", Status.FAIL, f"{summary} — {result.error}"
        )
    return CheckResult("smoke.self", "Self smoke (dry-run routing)", Status.PASS, summary)


def _recv_mllp(sock: socket.socket, timeout: float) -> bytes:
    """Read an MLLP frame (until the FS+CR trailer) or whatever arrives before timeout."""
    sock.settimeout(timeout)
    buf = bytearray()
    try:
        while b"\x1c\x0d" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
    except TimeoutError:
        pass
    return bytes(buf)


def _ack_code(frame: bytes) -> str | None:
    """Extract MSA-1 (AA/AE/AR) from an MLLP-stripped ACK, reading the field separator from MSH."""
    body = frame.replace(b"\x0b", b"").replace(b"\x1c", b"").replace(b"\x0d", b"\r").strip()
    if not body.startswith(b"MSH") or len(body) < 4:
        return None
    sep = body[3:4]
    for segment in body.split(b"\r"):
        if segment.startswith(b"MSA"):
            fields = segment.split(sep)
            if len(fields) > 1:
                return fields[1].decode("ascii", "replace")
    return None


def live_smoke_ssl_context(*, ca_file: str | None = None) -> ssl.SSLContext:
    """The client TLS context for a live smoke against a ``tls = true`` MLLP inbound (BACKLOG #1178).

    Hardened the same way every other context the engine builds is: a TLS 1.2 floor, the approved
    key-exchange groups, the forward-secrecy assertion (ASVS 12.1.2) and strict RFC 5280 validation
    (ASVS 12.1.4). Inheriting the interpreter's defaults without asserting them is the residual the
    hardening helpers exist to close, and a verifier is not exempt from it.

    ``ca_file`` anchors the engine's certificate when it is not in the system trust store, which is
    the usual case: the engine mints a self-signed pair on first run (ADR 0172). There is
    deliberately **no** verify-off switch — a smoke that accepts any certificate proves the port
    answers, not that the hop is the engine, and this whole item is about not weakening a hop to
    make a test pass."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
    harden_cipher_suites(ctx, connector="verify live smoke")  # forward secrecy (ASVS 12.1.2)
    harden_verify_flags(ctx)  # strict RFC 5280 validation of the engine cert (ASVS 12.1.4)
    return ctx


def smoke_live(
    *,
    host: str,
    port: int,
    message: str,
    timeout: float = 10.0,
    ssl_context: ssl.SSLContext | None = None,
    server_hostname: str | None = None,
) -> CheckResult:
    """MLLP-send ``message`` to the running engine and confirm an AA ACK.

    ``ssl_context`` makes the smoke speak the protocol the target inbound speaks (BACKLOG #1178,
    ASVS 12.3.1). Without it this call writes a whole MLLP frame — a synthetic message body, but a
    body — onto a bare socket before it has any evidence the peer is a cleartext listener. ``None``
    keeps that plaintext path, which is correct for a plaintext inbound and only for one.

    The switch is the caller's to make and is never inferred: probing in the clear and retrying over
    TLS (or the reverse) is exactly the protocol fall-back 12.3.1 forbids, so a mismatch fails and
    says so instead."""
    frame = b"\x0b" + message.encode("utf-8") + b"\x1c\x0d"
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            # Handshake FIRST when TLS is asked for, so no application byte can precede it.
            # wrap_socket detaches `raw`, so the outer context manager's close is a no-op and the
            # descriptor is closed exactly once, by the inner one.
            sock = (
                raw
                if ssl_context is None
                else ssl_context.wrap_socket(raw, server_hostname=server_hostname or host)
            )
            with sock:
                sock.sendall(frame)
                reply = _recv_mllp(sock, timeout)
    except ssl.SSLError as exc:  # an OSError subclass, so it must be caught before the arm below
        return CheckResult(
            "smoke.live",
            "Live smoke (MLLP + ACK)",
            Status.FAIL,
            f"TLS handshake with the engine inbound at {host}:{port} failed: {exc}",
        )
    except OSError as exc:
        return CheckResult(
            "smoke.live",
            "Live smoke (MLLP + ACK)",
            Status.FAIL,
            f"could not reach the engine inbound at {host}:{port}: {exc}",
        )
    code = _ack_code(reply)
    if code == "AA":
        return CheckResult(
            "smoke.live",
            "Live smoke (MLLP + ACK)",
            Status.PASS,
            f"{host}:{port} returned an AA ACK (confirm disposition in the console)",
        )
    if code in ("AE", "AR"):
        return CheckResult(
            "smoke.live",
            "Live smoke (MLLP + ACK)",
            Status.FAIL,
            f"engine NAK'd the message: MSA-1={code}",
        )
    detail = f"no parseable ACK from {host}:{port} ({len(reply)} bytes received)"
    if not reply and ssl_context is None:
        # A TLS listener handed a cleartext MLLP frame fails the handshake and closes, so the
        # client sees an accepted connection and zero bytes — indistinguishable, from here, from a
        # plaintext listener that hung up. Name the possibility rather than act on it: switching
        # protocols on this evidence is the fall-back ASVS 12.3.1 forbids, and the operator knows
        # which one their inbound is.
        detail += (
            "; the listener accepted the connection and closed without a byte, which is also what "
            "a tls = true MLLP inbound does to a cleartext frame. If this inbound is TLS, the "
            "synthetic message has already crossed in the clear; re-run with --smoke-tls (and "
            "--smoke-tls-ca for a self-signed engine certificate). The smoke never retries over "
            "TLS on its own"
        )
    return CheckResult("smoke.live", "Live smoke (MLLP + ACK)", Status.FAIL, detail)


def check_store_connectivity(store: StoreSettings) -> CheckResult:
    """Open the configured store backend and confirm it connects, then close. No test-data writes."""
    import asyncio

    from messagefoundry.store.base import open_store

    async def _open_close() -> None:
        handle = await open_store(store)
        await handle.close()

    try:
        asyncio.run(_open_close())
    except Exception as exc:  # any driver/connection/auth failure
        return CheckResult(
            "store.connect",
            "Store connectivity",
            Status.FAIL,
            f"{store.backend.value} store failed to open: {exc}",
        )
    return CheckResult(
        "store.connect",
        "Store connectivity",
        Status.PASS,
        f"{store.backend.value} store opened and closed cleanly as the calling user "
        "(NOT proof the NSSM service account can connect — confirm the service-identity grants)",
    )


def newest_message_id(store: StoreSettings, control_id: str) -> str | None:
    """Id of the most-recent stored message with ``control_id`` (the pre-send baseline for the
    disposition check), or ``None``. Lets a re-used synthetic control id not match a prior run's
    message — the disposition poll waits for one NEWER than this baseline. Read-only."""
    import asyncio

    from messagefoundry.store.base import open_store

    async def _newest() -> str | None:
        handle = await open_store(store)
        try:
            rows = await handle.list_messages(control_id=control_id, limit=1)
            return str(rows[0]["id"]) if rows else None
        finally:
            await handle.close()

    return asyncio.run(_newest())


def _classify_disposition(status: str | None, *, control_id: str, timeout: float) -> CheckResult:
    """Map a polled message status to the ``smoke.disposition`` result (pure — unit-tested)."""
    from messagefoundry.store.store import MessageStatus

    rid, title = "smoke.disposition", "Live smoke disposition"
    if status is None:
        return CheckResult(
            rid,
            title,
            Status.FAIL,
            f"no NEW stored message with control id {control_id} within {timeout:.0f}s "
            "(is the engine running and pointed at this same store?)",
        )
    if status == MessageStatus.PROCESSED.value:
        return CheckResult(rid, title, Status.PASS, f"control id {control_id} reached PROCESSED")
    if status in {
        MessageStatus.ERROR.value,
        MessageStatus.FILTERED.value,
        MessageStatus.UNROUTED.value,
    }:
        return CheckResult(
            rid,
            title,
            Status.FAIL,
            f"control id {control_id} ended {status.upper()}, not PROCESSED — a post-ACK failure "
            "(dead-letter / handler / delivery; e.g. the service-identity db-grant trap)",
        )
    return CheckResult(
        rid,
        title,
        Status.FAIL,
        f"control id {control_id} still {status.upper()} after {timeout:.0f}s "
        "(did not reach a terminal disposition)",
    )


def check_smoke_disposition(
    store: StoreSettings, *, control_id: str, baseline_id: str | None, timeout: float = 15.0
) -> CheckResult:
    """Poll the store for the live-smoke message's FINAL disposition.

    ``smoke.live`` only proves the listener ACKed; this proves the message actually *processed* —
    catching a **post-ACK dead-letter** (a bad transform, a delivery failure, or the service-identity
    db-grant trap), which a headless/CI acceptance run would otherwise miss. Correlates by MSH-10
    control id, waiting for a message NEWER than ``baseline_id`` (so a re-used synthetic id can't match
    a prior run). Read-only; opens the store as the calling user.
    """
    import asyncio

    from messagefoundry.store.base import open_store
    from messagefoundry.store.store import MessageStatus

    terminal = {
        MessageStatus.PROCESSED.value,
        MessageStatus.ERROR.value,
        MessageStatus.FILTERED.value,
        MessageStatus.UNROUTED.value,
    }

    async def _poll() -> str | None:
        handle = await open_store(store)
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            last: str | None = None
            while True:
                rows = await handle.list_messages(control_id=control_id, limit=1)
                if rows and str(rows[0]["id"]) != baseline_id:
                    last = str(rows[0]["status"])
                    if last in terminal:
                        return last
                if loop.time() >= deadline:
                    return last
                await asyncio.sleep(0.25)
        finally:
            await handle.close()

    try:
        status = asyncio.run(_poll())
    except Exception as exc:  # any driver/connection failure — surface, never crash the verify run
        return CheckResult(
            "smoke.disposition",
            "Live smoke disposition",
            Status.ERROR,
            f"could not read the store disposition: {exc}",
        )
    return _classify_disposition(status, control_id=control_id, timeout=timeout)
