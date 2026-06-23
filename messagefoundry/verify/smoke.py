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

Synthetic HL7 only (the engine's own generators) — never real PHI.
"""

from __future__ import annotations

import importlib
import socket

from messagefoundry.config.settings import StoreSettings
from messagefoundry.verify.model import CheckResult, Status


def synthetic_message() -> str:
    """One conformant synthetic ADT^A01 (no PHI) from the engine's generators."""
    importlib.import_module("messagefoundry.generators.all_types")  # registers built-in types
    from messagefoundry.generators import _core

    return _core.generate_message("ADT", "A01", 0)


def smoke_self(config_dir: str, *, inbound: str | None = None) -> CheckResult:
    """Route a synthetic message through the box's config with no side effects (``dry_run``)."""
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
    try:
        msg = synthetic_message()
    except Exception as exc:  # generator failure is a tool/install problem
        return CheckResult(
            "smoke.self",
            "Self smoke (dry-run routing)",
            Status.ERROR,
            f"could not generate a synthetic message: {exc}",
        )
    try:
        result = dry_run(reg, msg, inbound=inbound)
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
    except socket.timeout:
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


def smoke_live(*, host: str, port: int, message: str, timeout: float = 10.0) -> CheckResult:
    """MLLP-send ``message`` to the running engine and confirm an AA ACK."""
    frame = b"\x0b" + message.encode("utf-8") + b"\x1c\x0d"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(frame)
            reply = _recv_mllp(sock, timeout)
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
    return CheckResult(
        "smoke.live",
        "Live smoke (MLLP + ACK)",
        Status.FAIL,
        f"no parseable ACK from {host}:{port} ({len(reply)} bytes received)",
    )


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
        f"{store.backend.value} store opened and closed cleanly",
    )
