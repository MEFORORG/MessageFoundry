# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Remote-file sink: host the harness SFTP share and record each file an engine REMOTEFILE outbound
writes into its ``/outbox``.

The sink IS the share (:class:`~harness.sinks._sftp_server.SftpShare`), because the engine dials it:
started on enter, it binds 127.0.0.1 on the endpoint's port, pins its fresh host key into the
``remotefile_known_hosts`` file, and serves a temporary directory. The same share also holds the
``/inbox`` the engine's inbound polls, so a scenario keeps it up for its whole run even when it asserts
nothing about the outbound.

What arrived is read by the File sink's own scan over the outbox's local directory, so the rules match:
files present at start are ignored, dot-files (the engine's ``.<name>.<hex>.part`` upload temp) are
skipped, each read is capped, and every record carries ``relpath`` and ``inside``. A record also
carries ``remote_path``, the name the engine published under.
"""

from __future__ import annotations

from pathlib import Path

from harness.endpoints import Endpoints
from harness.sinks import LOOPBACK, Record, Sink
from harness.sinks._sftp_server import KNOWN_HOSTS_ENDPOINT, OUTBOX, SftpShare
from harness.sinks.file import FileSink

KIND = "remotefile"


class RemoteFileSink(Sink):
    kind = KIND

    def __init__(
        self,
        port: int = 0,
        *,
        known_hosts: str | Path,
        advertised_host: str = LOOPBACK,
        password: str | None = None,
    ) -> None:
        super().__init__()
        self._port = port
        self._known_hosts = known_hosts
        self._advertised_host = advertised_host
        self._password = password
        self.share: SftpShare | None = None
        self._outbox: FileSink | None = None
        self._final: list[Record] | None = None

    @property
    def port(self) -> int:
        return self.share.port if self.share is not None else self._port

    def start(self) -> None:
        self._final = None
        self.share = SftpShare(
            self._port,
            known_hosts=self._known_hosts,
            advertised_host=self._advertised_host,
            password=self._password,
        )
        self.share.start()
        try:
            self._outbox = FileSink(self.share.local(OUTBOX))
            self._outbox.start()
        except BaseException:
            self._outbox = None
            self.share.stop()  # a failed start runs no __exit__, so release the port here
            raise

    def stop(self) -> None:
        if self.share is None:
            return
        try:
            # Snapshot before the share deletes its directory, so a caller can still report what
            # came. The share is stopped whatever the scan does, so the port is never left bound.
            self._final = self.records()
        finally:
            self._outbox = None
            self.share.stop()

    def records(self) -> list[Record]:
        if self._outbox is None:
            return list(self._final or [])
        return [
            Record(
                r.payload,
                {**r.meta, "remote_path": f"{OUTBOX}/{r.meta.get('relpath', '')}"},
            )
            for r in self._outbox.records()
        ]


def build(endpoints: Endpoints, key: str) -> Sink:
    return RemoteFileSink(
        endpoints.port(key),
        known_hosts=endpoints.value(KNOWN_HOSTS_ENDPOINT),
        advertised_host=endpoints.host,
    )
