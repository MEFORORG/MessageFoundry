# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Harness REMOTEFILE graph: an SFTP inbound polling the harness share and an SFTP outbound writing
back to it.

Served on its own -- ``python -m messagefoundry serve --config harness/config/remotefile --env dev`` --
and NOT by ``serve --config harness/config``, which reads only top-level modules. It lives apart because
it cannot load without ``MEFOR_VALUE_REMOTEFILE_HARNESS_PASSWORD`` (the password has no default, so no
credential sits in source), and because its inbound polls a share that exists only while a remotefile
scenario runs. Start the engine with that variable set, then run ``python -m harness --scenario
remotefile_poll_in`` (or ``remotefile_write_out``) with the same variable: the scenario hosts the share
on ``harness_remotefile_sftp`` and pins its throwaway host key into ``harness_remotefile_known_hosts``.

Host-key verification stays ON; the rule about the insecure escape is stated once, in
``harness/sinks/_sftp_server.py``. With no share up, the inbound logs one failed poll per interval and
retries; nothing else is affected.

``/inbox`` and ``/outbox`` are the share's two directories (``harness/sinks/_sftp_server.py``). Every
ADT message the inbound reads is forwarded unchanged, so the outbound's file must equal the upload byte
for byte. Anything else is routed nowhere (UNROUTED). All data is synthetic.
"""

from messagefoundry import Send, Sftp, env, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy

# Each default here must equal its entry in harness/endpoints/remotefile.py (and harness_host's in
# harness/endpoints/coverage.py); a test holds them equal. Nothing here imports `harness`.
_SHARE = {
    "host": env("harness_host", default="127.0.0.1"),
    "port": env("harness_remotefile_sftp", default=2670, cast=int),
    "username": "harness",
    "password": env("remotefile_harness_password"),
    "known_hosts": env(
        "harness_remotefile_known_hosts", default="./harness_io/remotefile/known_hosts"
    ),
}

inbound(
    "IB_Harness_RemoteFile_Sftp",
    Sftp(**_SHARE, remote_dir="/inbox", pattern="*.hl7", poll_seconds=1.0),
    router="remotefile_router",
)

outbound(
    "OB_Harness_RemoteFile_Sftp",
    Sftp(**_SHARE, remote_dir="/outbox", filename="{MSH-10}.hl7"),
    retry=RetryPolicy(
        max_attempts=3, backoff_seconds=1.0, backoff_multiplier=2.0, max_backoff_seconds=5.0
    ),
)


@router("remotefile_router")
def route(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.1"] != "ADT":
        return []  # routed nowhere (logged UNROUTED), never silently dropped
    return ["remotefile_handler"]


@handler("remotefile_handler")
def handle(msg):  # type: ignore[no-untyped-def]
    return Send("OB_Harness_RemoteFile_Sftp", msg)
