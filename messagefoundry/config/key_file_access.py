# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""May the engine use a private-key file that a broad group can read? (ASVS 13.3.2, BACKLOG #3402)

One rule, :func:`key_file_problem`, and every caller applies it. ``serve`` and ``supervise`` call it
through their start gates for the store key file, the TLS key the engine minted, and an operator's
``[api].tls_key_file``. The registry guard here calls it for each key file the graph names. Under
``[security].enforcement = enforce`` a key file a broad group can read refuses; under ``warn`` it is
reported and the start or load goes on. What counts as broad is
:func:`messagefoundry.restricted_file.broad_access_problem`'s answer.

**Why the connector keys are judged as graph data.** A connection's key path can come from
``env()``, which resolves against this instance's environment values, and a ``/config/reload`` can
change both the graph and those values without a restart. So the start gates cannot see these
files. A registry guard judges each graph the engine loads, at least at the first load and on every
reload. A refused reload leaves the running graph in place.

**What the guard judges, at least.** The TLS identity of a connection: ``tls_key_file`` (MLLP, the
HTTP listener, DICOM, and the FTPS key :mod:`messagefoundry.transports.remotefile` reads) and
``Soap(client_key_file=...)``. Where the key setting is unset, the private key is in the certificate
PEM, so the certificate file is judged instead, as the loaders read it. A value holding PEM text is
key material, not a path, and is never judged as one. Not judged, at least: a ``Database``
connection's ``odbc_params`` ``sslkey``, ``smart_private_key`` (on a connection or a ``FhirLookup``),
a signing key such as ``sign_private_key`` or ``Direct(signing_key=...)``, the syslog client PEM, and
``[auth].oidc_client_private_key``. ``Sftp(private_key=...)`` is key text, not a file. A DR
activation re-applies the running graph without the registry guard, so it does not judge these
files again.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable, Mapping
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
    "make_connection_key_file_guard",
]

#: Each (certificate setting, key setting, TLS-gated) a connector loads as its own TLS identity. A
#: TLS-gated pair is read only where the connection loads a TLS identity, and there an unset key is
#: read from the certificate. A SOAP client certificate needs its key setting, so it never holds the
#: key, and SOAP loads the pair whenever both are set.
_IDENTITY_SETTINGS: Final[tuple[tuple[str, str, bool], ...]] = (
    ("tls_cert_file", "tls_key_file", True),
    ("client_cert_file", "client_key_file", False),
)

#: What marks a setting's value as PEM text rather than a path, as ``transports/signing.py`` reads it.
_PEM_MARKER: Final = "-----BEGIN"

#: The remedy for a key file an operator supplied.
KEY_FILE_REMEDY: Final = "Restrict it to the account the engine runs as"


def _absent(path: str) -> bool:
    """Whether nothing is at ``path``. Only a missing name counts: a file whose status cannot be
    read is not absent, and :func:`broad_access_problem` reports it as a problem."""
    try:
        # The same call broad_access_problem makes: lstat on Windows, stat on POSIX, so a dangling
        # link is missing on POSIX, as the loader that follows it finds it.
        os.lstat(path) if sys.platform == "win32" else os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
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

    ``env()`` references are resolved against ``env_values``. Every inbound and outbound connection
    is read, deployed or not, so a key is judged before a deploy can load it. A setting that does
    not resolve is skipped with its pair: the connection's own build refuses it and names the
    missing value. So is a value that is not a path, or that holds PEM text. A ``tls_key_file`` or
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
            settings = conn.spec.settings
            for cert_setting, key_setting, tls_identity in _IDENTITY_SETTINGS:
                if tls_identity and not loads_tls_identity(settings):
                    continue  # the loader opens neither file
                key = resolved(settings, key_setting)
                if key is unresolved:
                    continue
                setting, value = key_setting, as_path(key)
                if value is None and not key and tls_identity:
                    # The key resolves unset or blank, so the loader reads it from the certificate.
                    cert = resolved(settings, cert_setting)
                    setting, value = cert_setting, None if cert is unresolved else as_path(cert)
                if value is not None:
                    found.append(
                        (f"{direction} connection {conn.name!r} setting {setting!r}", value)
                    )
    return found


def connection_key_file_problem(registry: Registry, env_values: Mapping[str, Any]) -> str | None:
    """Why the engine may not use the key files a graph's connections name, or ``None``.

    The decision behind :func:`make_connection_key_file_guard` and the ``supervise`` pre-check, so
    both reach it in the same words. Each file is judged by :func:`key_file_problem`, and a missing
    one passes, because the connection's build refuses it. Every problem is named in one reason, so
    one start shows the operator every file to fix."""
    reasons: list[str] = []
    for label, path in connection_key_files(registry, env_values):
        reason = key_file_problem(
            path,
            what=f"the private key file named by {label}",
            remedy=KEY_FILE_REMEDY,
            absent_ok=True,
        )
        if reason is not None:
            reasons.append(reason)
    return "; ".join(reasons) if reasons else None


def make_connection_key_file_guard(
    env_values: Callable[[], Mapping[str, Any]], *, enforcing: bool, log: logging.Logger
) -> Callable[[Registry], None]:
    """The engine registry guard for the key files a graph's connections name.

    ``env_values`` is the engine's own provider, read again for each graph, so a reload is judged
    against the values that reload resolves. Under ``enforce`` a problem raises ``WiringError``: a
    first load fails the start, and a ``/config/reload`` is refused with the running graph kept.
    Under ``warn`` the guard writes the reason to the logger AND to stderr, as the retention
    override guard does, and passes the graph. A failure to read the values raises the
    ``WiringError`` the provider raises.

    It runs only where the engine calls its registry guard, which is before the engine-shard
    filter, so each engine shard judges the whole graph and reaches the verdict its siblings do."""

    def guard(registry: Registry) -> None:
        problem = connection_key_file_problem(registry, env_values())
        if problem is None:
            return
        if enforcing:
            from messagefoundry.config.wiring import WiringError

            raise WiringError(problem)
        log.warning("%s", problem)
        print(f"warning: {problem}.", file=sys.stderr)

    return guard
