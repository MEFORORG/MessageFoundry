# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""End-to-end smoke of a real engine: serve, MLLP send, ACK, final disposition through the API.

Unit tests can pass while the running engine is broken, so this starts one and drives it::

    python -m harness.e2e_smoke                       # samples/config, IB_Test_ADT on 2575
    python -m harness.e2e_smoke --config <dir> --mllp-port <port> --expect processed

Each run gets a fresh temp directory holding the store, the engine's working directory (so a
``File`` outbound's relative path lands there) and a throwaway loopback TLS pair. The API port is a
free one. The MLLP port is the inbound's own, from its config: ``--mllp-port``, 2575 for the
sample's ``IB_Test_ADT``. A port already taken fails the ``ports`` step rather than sending to
whatever holds it.

The steps, in order: ``ports``, ``provision``, ``serve``, ``ready``, ``mllp``, ``sign-in``,
``disposition``. Exit 0 when every step passes; otherwise exit 1 with ``FAIL <step>: <reason>``
on stderr. The engine is stopped and the temp directory deleted either way.

It signs in as the rig Administrator :mod:`harness.load.rigadmin` provisions with a password drawn
per run, which is never printed. The engine runs with the same per-gate relaxations the load
harness's nodes take (``harness.load.failover.Node``), because it serves a synthetic graph.

It prints step names, the control id and the disposition, never a message body (CLAUDE.md
section 9). On a ``serve`` or ``ready`` failure it prints the tail of the engine's own log.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from harness.load import rigadmin
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.parsing.peek import HL7PeekError, Peek, normalize
from messagefoundry.proctree import ADOPT_CREATIONFLAGS, resume_into_job, terminate_job
from messagefoundry.terminal_text import escape_for_terminal
from messagefoundry.verify.model import Status
from messagefoundry.verify.smoke import smoke_live

_REPO = Path(__file__).resolve().parents[1]
_DEFAULT_CONFIG = _REPO / "samples" / "config"
_DEFAULT_MESSAGE = _REPO / "samples" / "messages" / "adt_a01.hl7"
_DEFAULT_INBOUND = "IB_Test_ADT"
_DEFAULT_MLLP_PORT = 2575

#: The interpreter options the engine starts under, as CLAUDE.md section 7 runs ``serve``.
SERVE_PYTHON_OPTIONS = ("-P", "-X", "disable-remote-debug")

#: The terminal dispositions, by ``MessageStatus`` value. Polling stops at the first of these.
_TERMINAL = frozenset({"processed", "filtered", "unrouted", "error"})

_LOG_TAIL_BYTES = 4000


class StepFailed(Exception):
    """A step did not pass. ``step`` names it; the message says why."""

    def __init__(self, step: str, reason: str) -> None:
        super().__init__(reason)
        self.step = step


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _port_taken(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return True
    return False


def _serve_env(cert: Path, key: Path) -> dict[str, str]:
    """The engine's environment: this one, less the rig credential, plus the rig's relaxations."""
    env = {
        name: value
        for name, value in os.environ.items()
        if name not in (rigadmin.ADMIN_PASS_ENV, rigadmin.ADMIN_FACTOR_ENV)
    }
    env.update(rigadmin.SERVE_ENV)
    env.update(
        {
            "MEFOR_API_TLS_CERT_FILE": str(cert),
            "MEFOR_API_TLS_KEY_FILE": str(key),
            "MEFOR_SECURITY_ENFORCEMENT": "warn",
            "MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI": "true",
            "MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUND": "false",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    if sys.platform == "win32":
        # A checkout on Windows is writable to BUILTIN\Users, which the config-source check refuses;
        # honoured only beside the warn dial above (see harness.load.failover.Node).
        env["MEFOR_ALLOW_INSECURE_CONFIG_SOURCE"] = "1"
    return env


def _log_tail(log: Path) -> str:
    try:
        with log.open("rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            fh.seek(max(0, size - _LOG_TAIL_BYTES))
            data = fh.read()
    except OSError:
        return ""
    return escape_for_terminal(data.decode("utf-8", "replace")).replace("\\n", "\n")


def _wait_ready(
    client: EngineClient, proc: subprocess.Popen[bytes], mllp_port: int, deadline: float
) -> None:
    """Wait until the API answers ``/health`` and the inbound accepts a connection."""
    api_up = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise StepFailed("serve", f"the engine exited with code {proc.returncode}")
        if not api_up:
            with contextlib.suppress(ApiError, OSError):
                client.health()
                api_up = True
        if api_up:
            with contextlib.suppress(OSError):
                socket.create_connection(("127.0.0.1", mllp_port), timeout=1.0).close()
                return
        time.sleep(0.2)
    what = f"the inbound on port {mllp_port} never accepted" if api_up else "/health never answered"
    raise StepFailed("ready", what)


def _poll_disposition(
    client: EngineClient, *, inbound: str, control_id: str, deadline: float
) -> str | None:
    """The message's status once terminal, or the last status seen (``None`` if never stored)."""
    last: str | None = None
    while True:
        page = client.list_messages(channel_id=inbound, control_id=control_id, limit=1)
        if page.messages:
            last = page.messages[0].status.lower()
            if last in _TERMINAL:
                return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(0.25)


def run(
    *,
    config: Path,
    message_file: Path,
    inbound: str,
    mllp_port: int,
    expect: str,
    timeout: float,
) -> None:
    """Run every step. Returns on a pass; raises :class:`StepFailed` naming the step otherwise."""
    try:
        message = normalize(message_file.read_bytes())
        control_id = Peek.parse(message).control_id
    except (OSError, HL7PeekError) as exc:
        raise StepFailed("message", f"cannot read {message_file}: {type(exc).__name__}") from None
    if not control_id:
        raise StepFailed("message", f"{message_file} has no MSH-10 control id")
    if _port_taken(mllp_port):
        raise StepFailed("ports", f"MLLP port {mllp_port} is already in use on 127.0.0.1")
    api_port = _free_port()

    work = Path(tempfile.mkdtemp(prefix="mefor-e2e-smoke-"))
    proc: subprocess.Popen[bytes] | None = None
    job: int | None = None
    log_fh = None
    try:
        from messagefoundry import pki  # pulls cryptography; only a run needs it

        cert_pem, key_pem = pki.make_self_signed("127.0.0.1", ["127.0.0.1", "localhost"], 2)
        cert, key = work / "api-cert.pem", work / "api-key.pem"
        cert.write_bytes(cert_pem)
        key.write_bytes(key_pem)
        db = work / "store.db"
        env = _serve_env(cert, key)

        print(f"step provision: rig Administrator in {db.name}", flush=True)
        try:
            rigadmin.provision(env=env, cwd=work, db=str(db))
        except rigadmin.RigAdminError as exc:
            raise StepFailed("provision", str(exc)) from None

        argv = [
            sys.executable,
            *SERVE_PYTHON_OPTIONS,
            "-m",
            "messagefoundry",
            "serve",
            "--config",
            str(config),
            "--db",
            str(db),
            "--env",
            "dev",
            "--port",
            str(api_port),
            "--project-root",
            str(_REPO),
        ]
        print(f"step serve: API on {api_port}, inbound {inbound} on {mllp_port}", flush=True)
        log = work / "engine.log"
        log_fh = log.open("wb")
        proc = subprocess.Popen(  # noqa: S603 -- our own interpreter and fixed arguments
            argv,
            cwd=str(work),
            env=env,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            creationflags=ADOPT_CREATIONFLAGS,
        )
        try:
            # Windows: the engine starts suspended and joins a kill-on-close job, so it dies with
            # this process by any route. Elsewhere this is a no-op and the child already runs.
            job = resume_into_job(proc.pid, who="e2e smoke engine")
        except OSError:
            proc.kill()
            raise StepFailed("serve", "could not resume the engine process") from None

        client = EngineClient(f"https://127.0.0.1:{api_port}", cacert=str(cert), timeout=10.0)
        with client:
            try:
                _wait_ready(client, proc, mllp_port, time.monotonic() + timeout)
            except StepFailed as exc:
                raise StepFailed(
                    exc.step, f"{exc}\n--- engine log tail ---\n{_log_tail(log)}"
                ) from None
            print("step ready: API and inbound are up", flush=True)

            ack = smoke_live(host="127.0.0.1", port=mllp_port, message=message)
            if ack.status is not Status.PASS:
                raise StepFailed("mllp", ack.detail)
            print(f"step mllp: AA for control id {control_id}", flush=True)

            admin = rigadmin.rig_admin()
            try:
                client.login(admin.username, admin.password)
            except ApiError as exc:
                raise StepFailed("sign-in", f"the engine refused the rig sign-in: {exc}") from None
            print("step sign-in: rig Administrator", flush=True)

            try:
                status = _poll_disposition(
                    client,
                    inbound=inbound,
                    control_id=control_id,
                    deadline=time.monotonic() + timeout,
                )
            except ApiError as exc:
                raise StepFailed("disposition", f"GET /messages failed: {exc}") from None
            if status != expect:
                seen = "never stored" if status is None else status.upper()
                raise StepFailed(
                    "disposition",
                    f"control id {control_id} on {inbound}: {seen}, expected {expect.upper()}",
                )
            print(f"step disposition: {status.upper()}", flush=True)
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=15)
        if job is not None:
            terminate_job(job)
        if log_fh is not None:
            log_fh.close()
        _remove(work)


def _remove(path: Path) -> None:
    """Delete the temp dir. Windows may hold the store file briefly after the engine dies."""
    for _ in range(20):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.25)
    shutil.rmtree(path, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m harness.e2e_smoke", description=__doc__)
    parser.add_argument("--config", type=Path, default=_DEFAULT_CONFIG)
    parser.add_argument("--message", type=Path, default=_DEFAULT_MESSAGE)
    parser.add_argument("--inbound", default=_DEFAULT_INBOUND)
    parser.add_argument("--mllp-port", type=int, default=_DEFAULT_MLLP_PORT)
    parser.add_argument("--expect", default="processed", choices=sorted(_TERMINAL))
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds per waiting step")
    args = parser.parse_args(argv)
    started = time.monotonic()
    try:
        run(
            config=args.config.resolve(),
            message_file=args.message.resolve(),
            inbound=args.inbound,
            mllp_port=args.mllp_port,
            expect=args.expect,
            timeout=args.timeout,
        )
    except StepFailed as exc:
        print(f"FAIL {exc.step}: {exc}", file=sys.stderr, flush=True)
        return 1
    print(f"PASS e2e smoke in {time.monotonic() - started:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
