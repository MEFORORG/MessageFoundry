# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``ha`` Postgres refuses a first start it would half-initialize, and its health check
waits for the real server (BACKLOG #8298 items 1 and 11).

Item 11: with ``./pg-tls`` empty, the image's entrypoint ran initdb, then its temporary server
failed on the missing certificate, leaving a data volume with no ``messagefoundry`` database
that every later start skipped initializing. The service's entrypoint now checks the files the
command names, the way Postgres reads them, before the image's entrypoint runs. The check is run
here under ``sh``, with ``id``, ``stat``, ``gosu`` and ``docker-entrypoint.sh`` stubbed.

Item 1: ``pg_isready`` with no host probes the Unix socket, which the image's temporary
initialization server answers on; the probe now goes over TCP and queries the database.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.test_compose_revocation_attestation import _compose_doc

_SH = shutil.which("sh")
_STUBS = {
    "id": '#!/bin/sh\n[ "$1 $2" = "-u postgres" ] && echo 999\n',
    "stat": '#!/bin/sh\ncase "$3" in %u) echo "$STUB_UID" ;; %a) echo "$STUB_MODE" ;; esac\n',
    "gosu": '#!/bin/sh\nshift\nexec "$@"\n',
    "docker-entrypoint.sh": '#!/bin/sh\necho "$*" > "$MARKER"\n',
}


def _postgres() -> dict[str, Any]:
    return dict(_compose_doc()["services"]["postgres"])


def _check_script() -> str:
    entry = [str(a) for a in _postgres().get("entrypoint") or []]
    assert entry[:2] == ["sh", "-c"] and len(entry) == 4, entry
    return entry[2]


def test_the_check_script_has_no_compose_interpolation() -> None:
    """Every ``$`` is doubled, so compose passes the script through unchanged."""
    assert "$" not in _check_script().replace("$$", "")


def _run(tmp: Path, *, files: dict[str, bytes], uid: str, mode: str) -> tuple[int, str, str]:
    assert _SH is not None
    tls = tmp / "tls"
    tls.mkdir()
    for name, body in files.items():
        (tls / name).write_bytes(body)
    bindir = tmp / "bin"
    bindir.mkdir()
    for name, body in _STUBS.items():
        stub = bindir / name
        stub.write_bytes(body.encode())
        stub.chmod(0o755)
    command = [
        str(a).replace("/etc/postgresql/tls", tls.as_posix()) for a in _postgres()["command"]
    ]
    marker = tmp / "entrypoint-ran"
    env = {
        **os.environ,
        "PATH": f"{bindir.as_posix()}{os.pathsep}{os.environ.get('PATH', '')}",
        "STUB_UID": uid,
        "STUB_MODE": mode,
        "MARKER": marker.as_posix(),
    }
    script = _check_script().replace("$$", "$")
    proc = subprocess.run(
        [_SH, "-c", script, "pg-tls-check", *command],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    ran = marker.read_text().strip() if marker.exists() else ""
    return proc.returncode, proc.stderr, ran


_BOTH = {"server.crt": b"cert", "server.key": b"key"}


@pytest.mark.skipif(_SH is None, reason="no sh on PATH")
@pytest.mark.parametrize(
    ("files", "uid", "mode", "why"),
    (
        ({}, "999", "600", "missing or empty"),
        ({"server.crt": b"cert"}, "999", "600", "server.key is missing or empty"),
        ({"server.crt": b"cert", "server.key": b""}, "999", "600", "missing or empty"),
        (_BOTH, "999", "640", "has mode 640"),
        (_BOTH, "0", "644", "has mode 644"),
        (_BOTH, "0", "777", "has mode 777"),
        (_BOTH, "1000", "600", "owned by uid 1000"),
    ),
)
def test_a_start_postgres_would_refuse_never_reaches_the_image_entrypoint(
    tmp_path: Path, files: dict[str, bytes], uid: str, mode: str, why: str
) -> None:
    code, err, ran = _run(tmp_path, files=files, uid=uid, mode=mode)
    assert code != 0 and not ran, (code, err, ran)
    assert why in err and "nothing was initialized" in err, err


@pytest.mark.skipif(_SH is None, reason="no sh on PATH")
@pytest.mark.parametrize(("uid", "mode"), (("999", "600"), ("999", "400"), ("0", "640")))
def test_a_key_postgres_accepts_hands_the_command_to_the_image_entrypoint(
    tmp_path: Path, uid: str, mode: str
) -> None:
    code, err, ran = _run(tmp_path, files=_BOTH, uid=uid, mode=mode)
    assert code == 0, err
    assert ran.split()[:3] == ["postgres", "-c", "ssl=on"], ran
    assert "ssl_key_file=" in ran, ran


def _health_refusal(test: list[str]) -> str | None:
    """Why the health check could pass before the real server serves the database, or None."""
    assert test[:1] == ["CMD-SHELL"], test
    steps = [shlex.split(part) for part in test[1].split("&&")]
    probes = {s[0]: s for s in steps if s}
    for tool in ("pg_isready", "psql"):
        argv = probes.get(tool)
        if argv is None:
            return f"no {tool} step"
        host = argv[argv.index("-h") + 1] if "-h" in argv else ""
        if host != "127.0.0.1":
            return f"{tool} probes host {host!r}, not TCP on 127.0.0.1"
        if "messagefoundry" not in argv:
            return f"{tool} does not name the messagefoundry database"
    if not any(a.startswith("-") and "c" in a for a in probes["psql"][1:]):
        return "psql runs no query"
    return None


def test_the_health_check_waits_for_the_real_server_and_its_database() -> None:
    assert _health_refusal(list(_postgres()["healthcheck"]["test"])) is None


@pytest.mark.parametrize(
    "test",
    (
        ["CMD-SHELL", "pg_isready -U mefor -d messagefoundry"],
        ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U mefor -d messagefoundry"],
        [
            "CMD-SHELL",
            "pg_isready -h 127.0.0.1 -d messagefoundry && psql -d messagefoundry -c 'select 1'",
        ],
    ),
)
def test_the_health_check_test_sees_a_socket_or_database_blind_probe(test: list[str]) -> None:
    assert _health_refusal(test) is not None
