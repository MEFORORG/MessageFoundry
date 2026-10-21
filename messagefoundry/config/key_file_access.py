# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""May the engine use a private-key file that a broad group can read? (ASVS 13.3.2, BACKLOG #3402)

One rule, :func:`key_file_problem`, and every caller applies it. ``serve`` and ``supervise`` call it
through their start gates for the store key file, the TLS key the engine minted, and an operator's
``[api].tls_key_file``. The registry preflight here calls it for each key file the graph names, and
``supervise`` calls it for the whole graph before it starts an engine shard. Under
``[security].enforcement = enforce`` a key file a broad group can read refuses; under ``warn`` it is
reported and the start or load goes on. What counts as broad is
:func:`messagefoundry.restricted_file.broad_access_problem`'s answer.

**Why the connector keys are judged as graph data.** A connection's key path can come from
``env()``, which resolves against this instance's environment values, and a ``/config/reload`` can
change both the graph and those values without a restart. So the start gates cannot see these
files. The engine awaits a registry preflight over each graph it is about to run, with the values
that load resolves: at the first load, on every real reload, and on a DR activation, which
re-applies the running graph. A refused reload or activation leaves the running graph in place. A
dry-run reload skips the preflight, and starts no connection. The file checks run in a worker
thread, so they never block the event loop.

**What the preflight judges.** A connection's TLS identity, as :func:`connection_key_files` reads
it. Which key settings that covers and which it leaves out, and when a key file is not judged, is
stated once, in ``docs/PHI.md`` section 2, *Key files*.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from collections.abc import Iterable

    from messagefoundry.config.wiring import InboundConnection, OutboundConnection, Registry

__all__ = [
    "KEY_FILE_REMEDY",
    "connection_key_file_problem",
    "connection_key_files",
    "key_file_problem",
    "make_connection_key_file_preflight",
]

#: Each (certificate setting, key setting, TLS-gated) a connector loads as its own TLS identity. A
#: pair is read only where its certificate is set. A TLS-gated pair is read only where the
#: connection loads a TLS identity, and there an unset key is read from the certificate. A SOAP
#: client certificate needs its key setting, so it never holds the key, and SOAP loads the pair
#: whenever both are set.
_IDENTITY_SETTINGS: Final[tuple[tuple[str, str, bool], ...]] = (
    ("tls_cert_file", "tls_key_file", True),
    ("client_cert_file", "client_key_file", False),
)

#: What marks a setting's value as PEM text rather than a path, as ``transports/signing.py`` reads it.
_PEM_MARKER: Final = "-----BEGIN"

#: The remedy for a key file an operator supplied.
KEY_FILE_REMEDY: Final = "Restrict it to the account the engine runs as"


#: Windows errors CPython raises as FileNotFoundError for a path it could not reach:
#: ERROR_BAD_NETPATH (53) and ERROR_BAD_NET_NAME (67).
_UNREACHABLE_WINERRORS: Final = frozenset({53, 67})


def _absent(path: str) -> bool:
    """Whether nothing is at ``path``. Only a missing name counts: a file whose status cannot be
    read is not absent, and :func:`broad_access_problem` reports it as a problem."""
    try:
        # The same call broad_access_problem makes: lstat on Windows, stat on POSIX, so a dangling
        # link is missing on POSIX, as the loader that follows it finds it.
        os.lstat(path) if sys.platform == "win32" else os.stat(path)
    except FileNotFoundError as exc:
        # Windows also reports a share or network path it cannot reach as FileNotFoundError. That
        # is a file nobody examined, not a missing one, so it goes to the access check, which
        # refuses what it cannot read rather than passing it.
        return getattr(exc, "winerror", None) not in _UNREACHABLE_WINERRORS
    except NotADirectoryError:
        return True
    except OSError:
        return False  # not a missing name: the access check that follows reports it
    return False


def key_file_problem(path: str, *, what: str, remedy: str, absent_ok: bool = False) -> str | None:
    """Why the engine may not use the key file at ``path``, or ``None`` when it may.

    A known broad group must not be able to read or change the file. ``what`` names the file for
    the operator and ``remedy`` says what to do about it; the reason never carries the file's
    contents. With ``absent_ok``, a missing file passes: the loader that opens it refuses it and
    says why, which is the fault the operator needs to hear about. It prints and logs nothing:
    each caller refuses under ``enforce`` and warns under ``warn``."""
    from messagefoundry.restricted_file import broad_access_problem

    if "\x00" in path:
        # No file can carry this name, and the stat calls below raise ValueError on it rather than
        # the OSError the access check reports. Refused as unexaminable, never passed as absent.
        return f"{what} is not restricted: its path could not be examined (a NUL in it). {remedy}"
    if absent_ok and _absent(path):
        return None
    problem = broad_access_problem(Path(path))
    if problem is None:
        return None
    return f"{what} is not restricted: {problem}. {remedy}"


def connection_key_files(
    registry: Registry, env_values: Mapping[str, Any]
) -> list[tuple[str, str]]:
    """``(label, path)`` for each private-key file a connection in ``registry`` names.

    ``env()`` references are resolved against ``env_values``. Every deployed inbound and outbound
    connection is read. One with ``deployed=False`` is not: the engine never builds it, and ADR 0111
    forbids resolving its ``env()`` values, so the reload that deploys it judges its key. A setting that does
    not resolve is skipped with its pair: the connection's own build refuses it and names the
    missing value. So is a value that is not a path, or that holds PEM text. A key whose certificate
    setting is unset is skipped too, because every loader loads an identity only from a certificate,
    so it would never open that key. A ``tls_key_file`` or
    ``tls_cert_file`` is judged only where the connection loads a TLS identity, and the certificate
    stands in for a key that resolves unset or blank, as the loader then reads the key from it. The
    label names the connection and the setting, never the path."""
    from messagefoundry.config.models import remote_file_protocol
    from messagefoundry.config.wiring import WiringError, resolve_env_settings

    unresolved = object()

    def resolved(settings: Mapping[str, Any], name: str) -> object:
        if name not in settings:
            return None
        try:
            return resolve_env_settings({name: settings[name]}, env_values)[name]
        except WiringError:
            return unresolved

    def as_path(value: object) -> str | None:
        # Every loader str()s the value, so a pathlib.Path names a file as text does.
        if isinstance(value, os.PathLike):
            value = os.fspath(value)
        if not isinstance(value, str) or not value or _PEM_MARKER in value:
            return None
        return value

    def loads_tls_identity(settings: Mapping[str, Any]) -> bool:
        # ``tls`` on MLLP, the HTTP listener and DICOM; the ``ftps`` protocol of a remote-file
        # connection, read through the transport's own normalisation.
        tls = resolved(settings, "tls")
        if tls is not unresolved and tls:
            return True
        protocol = resolved(settings, "protocol")
        return isinstance(protocol, str) and remote_file_protocol({"protocol": protocol}) == "ftps"

    found: list[tuple[str, str]] = []
    groups: tuple[tuple[str, Iterable[InboundConnection | OutboundConnection]], ...] = (
        ("inbound", registry.inbound.values()),
        ("outbound", registry.outbound.values()),
    )
    for direction, connections in groups:
        for conn in sorted(connections, key=lambda c: c.name):
            if not conn.deployed:
                continue  # ADR 0111: never built, and its env() values are never resolved
            settings = conn.spec.settings
            for cert_setting, key_setting, tls_identity in _IDENTITY_SETTINGS:
                if tls_identity and not loads_tls_identity(settings):
                    continue  # the loader opens neither file
                cert_path = as_path(resolved(settings, cert_setting))
                if cert_path is None:
                    continue  # every loader keys its identity on the certificate: no cert, no load
                key = resolved(settings, key_setting)
                if key is unresolved:
                    continue
                setting, value = key_setting, as_path(key)
                if value is None and not key and tls_identity:
                    # The key resolves unset or blank, so the loader reads it from the certificate.
                    setting, value = cert_setting, cert_path
                if value is not None:
                    found.append(
                        (f"{direction} connection {conn.name!r} setting {setting!r}", value)
                    )
    return found


def connection_key_file_problem(registry: Registry, env_values: Mapping[str, Any]) -> str | None:
    """Why the engine may not use the key files a graph's connections name, or ``None``.

    The decision behind :func:`make_connection_key_file_preflight` and the ``supervise`` pre-check,
    so both reach it in the same words. It reads each file's access list, so an async caller runs it
    in a worker thread. Each file is judged once by :func:`key_file_problem`, however many settings
    name it, and a missing one passes, because the connection's build refuses it. Every problem is
    named in one reason, so one start shows the operator every file to fix."""
    labels_by_path: dict[str, list[str]] = {}
    for label, path in connection_key_files(registry, env_values):
        labels_by_path.setdefault(path, []).append(label)
    reasons: list[str] = []
    for path, labels in labels_by_path.items():
        reason = key_file_problem(
            path,
            what=f"the private key file named by {' and '.join(labels)}",
            remedy=KEY_FILE_REMEDY,
            absent_ok=True,
        )
        if reason is not None:
            reasons.append(reason)
    return "; ".join(reasons) if reasons else None


def make_connection_key_file_preflight(
    *, enforcing: bool, log: logging.Logger
) -> Callable[[Registry, Mapping[str, Any]], Awaitable[None]]:
    """The engine registry preflight for the key files a graph's connections name.

    The engine awaits it with the graph and the ``env()`` values that load resolves: its own values
    at the first load and on a DR activation, and on a real reload the values that reload read and
    has not yet applied, so the check and the swap use one read. A dry-run reload skips it, which
    is acceptable because a dry run starts no connection. The file checks run in a worker thread,
    off the event loop. Under ``enforce`` a problem raises ``WiringError``: a first load fails the start, and a reload or a DR activation is refused with
    the running graph kept. Under ``warn`` it writes the reason to the logger AND to stderr, as the
    retention override guard does, and passes the graph.

    The engine runs it after the engine-shard filter, so an engine shard judges its own inbound
    connections and every outbound one. ``supervise`` judges the whole graph before it starts any."""

    async def preflight(registry: Registry, env_values: Mapping[str, Any]) -> None:
        problem = await asyncio.to_thread(connection_key_file_problem, registry, env_values)
        if problem is None:
            return
        if enforcing:
            from messagefoundry.config.wiring import WiringError

            raise WiringError(problem)
        log.warning("%s", problem)
        print(f"warning: {problem}.", file=sys.stderr)

    return preflight
