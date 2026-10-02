# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Remote-file driver: upload each payload over SFTP into the ``/inbox`` an engine REMOTEFILE inbound
polls.

A real SFTP client, dialing the ``host`` endpoint, not a write into the share's local directory: the
upload crosses the same wire the engine reads from. It verifies the share's host key against the pinned
``remotefile_known_hosts`` file (paramiko ``RejectPolicy``; an unknown key is refused, never added) and
authenticates with the password from ``MEFOR_VALUE_REMOTEFILE_HARNESS_PASSWORD``.

Each upload goes to a hidden ``.<name>.part`` temp first and is then renamed onto its final
``<uuid>.hl7`` name, so the engine's ``*.hl7`` poll never lists a half-written file. A failure is
reported in the :class:`Injection`, never raised, as every driver does.

paramiko (the ``[sftp]`` extra) is imported inside :meth:`RemoteFileDriver.inject`, so discovering this
module never needs it.
"""

from __future__ import annotations

import contextlib
import posixpath
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

from harness.drivers import Driver, Injection
from harness.endpoints import Endpoints
from harness.sinks._sftp_server import (
    INBOX,
    KNOWN_HOSTS_ENDPOINT,
    USERNAME,
    import_paramiko,
    share_password,
)

KIND = "remotefile"


class RemoteFileDriver(Driver):
    kind = KIND

    def __init__(
        self,
        host: str,
        port: int,
        *,
        known_hosts: str | Path,
        password: str | None = None,
        remote_dir: str = INBOX,
        suffix: str = ".hl7",
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.known_hosts = Path(known_hosts)
        self.password = password
        self.remote_dir = remote_dir
        self.suffix = suffix
        self.timeout = timeout

    def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
        try:
            paramiko = import_paramiko()
            password = share_password() if self.password is None else self.password
        except OSError as exc:
            return [Injection(error=str(exc)) for _ in payloads]
        faults = _faults(paramiko)
        client: Any = paramiko.SSHClient()
        try:
            client.load_host_keys(str(self.known_hosts))
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                hostname=self.host,
                port=self.port,
                username=USERNAME,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                channel_timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            sftp = client.open_sftp()
        except faults as exc:
            client.close()
            error = (
                f"SFTP connect to {self.host}:{self.port} failed: {str(exc) or type(exc).__name__}"
            )
            return [Injection(error=error) for _ in payloads]
        try:
            sftp.get_channel().settimeout(self.timeout)
            return [self._upload(faults, sftp, payload) for payload in payloads]
        finally:
            sftp.close()
            client.close()

    def _upload(
        self, faults: tuple[type[BaseException], ...], sftp: Any, payload: bytes
    ) -> Injection:
        name = f"{uuid4().hex}{self.suffix}"
        temp = posixpath.join(self.remote_dir, f".{name}.part")
        try:
            with sftp.open(temp, "wb") as fh:
                fh.write(payload)
            sftp.rename(temp, posixpath.join(self.remote_dir, name))
        except faults as exc:
            # Leave no partial temp behind, matching the File driver's drop_atomic.
            with contextlib.suppress(*faults):
                sftp.remove(temp)
            return Injection(error=f"SFTP upload failed: {str(exc) or type(exc).__name__}")
        return Injection()


def _faults(paramiko: Any) -> tuple[type[BaseException], ...]:
    """What a connect or an upload can raise that is a failed SEND, to report rather than raise:
    paramiko's SSH and SFTP errors (``SFTPError`` is not an ``SSHException``), an unreadable
    ``known_hosts`` line, and the socket's own errors."""
    return (
        paramiko.SSHException,
        paramiko.SFTPError,
        paramiko.hostkeys.InvalidHostKey,
        OSError,
        EOFError,
    )


def build(endpoints: Endpoints, key: str) -> Driver:
    return RemoteFileDriver(
        endpoints.host,
        endpoints.port(key),
        known_hosts=endpoints.value(KNOWN_HOSTS_ENDPOINT),
    )
