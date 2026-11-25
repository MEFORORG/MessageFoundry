# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""End-to-end smoke of a real engine: serve, MLLP send, ACK, final disposition through the API.

Unit tests can pass while the running engine is broken, so this starts one and drives it::

    python -m harness.e2e_smoke                       # samples/config, IB_Test_ADT on 2575
    python -m harness.e2e_smoke --config <dir> --mllp-port <port> --expect processed

Each run gets a fresh temp directory holding the store, the engine's working directory (so a
``File`` outbound's relative path lands there) and a throwaway loopback TLS pair. The API port is a
free one unless ``--api-port`` names it. The MLLP port is the inbound's own, from its config:
``--mllp-port``, 2575 for the sample's ``IB_Test_ADT``. A port already held fails the ``ports``
step, and the ``ready`` step waits for the API to report this engine's inbound running on that
port, so the message never goes to another process that holds it.

The steps, in order: ``message``, ``ports``, ``provision``, ``serve``, ``sign-in``, ``ready``,
``mllp``, ``disposition``. Exit 0 when every step passes; otherwise exit 1 with
``FAIL <step>: <reason>`` on stderr. The engine is stopped and the temp directory deleted on
either exit, and on SIGTERM; only a SIGKILL of this process skips that, and on Windows the engine
still dies with it (its kill-on-close job).

It signs in as the rig Administrator :mod:`harness.load.rigadmin` provisions with a password drawn
per run, which is never printed. The engine gets none of the caller's ``MEFOR_*`` settings, only
the per-gate relaxations ``harness.load.failover.EngineNode`` takes, because it serves a synthetic
graph.

It prints step names, the control id and the disposition, never a message body (CLAUDE.md
section 9). On a ``serve`` or ``ready`` failure it prints the tail of the engine's own log.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import FrameType

from harness.load import rigadmin
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.mllpcodec import (
    DEFAULT_MAX_FRAME_BYTES,
    FramePayloadError,
    MLLPDecoder,
    MLLPFrameError,
    frame_checked,
)
from messagefoundry.parsing.peek import HL7PeekError, Peek, normalize
from messagefoundry.proctree import (
    ADOPT_CREATIONFLAGS,
    ADOPT_NEW_SESSION,
    kill_process_group,
    resume_into_job,
    terminate_job,
)
from messagefoundry.terminal_text import escape_for_terminal
from messagefoundry.verify_leaf import port_state

_REPO = Path(__file__).resolve().parents[1]
_DEFAULT_CONFIG = _REPO / "samples" / "config"
_DEFAULT_MESSAGE = _REPO / "samples" / "messages" / "adt_a01.hl7"
_DEFAULT_INBOUND = "IB_Test_ADT"
_DEFAULT_MLLP_PORT = 2575

#: The interpreter options the engine starts under, as CLAUDE.md section 7 runs ``serve``.
SERVE_PYTHON_OPTIONS = ("-P", "-X", "disable-remote-debug")

#: The final dispositions, by ``MessageStatus`` value. Polling stops at the first of these.
#: ``error`` is reachable only after the ACK (a router or transform failure): a message the
#: listener refuses is NAKed, which fails the ``mllp`` step first.
_TERMINAL = frozenset({"processed", "filtered", "unrouted", "error", "not_deployed"})

#: Once a second: the engine paces PHI and monitoring reads per actor (120 a minute by default), and a faster poll
#: would turn a slow disposition into a 429.
_POLL_S = 1.0
_LOG_TAIL_BYTES = 4000


class StepFailed(Exception):
    """A step did not pass. ``step`` names it; the message says why."""

    def __init__(self, step: str, reason: str) -> None:
        super().__init__(reason)
        self.step = step


def _shown(text: str) -> str:
    """Untrusted text (a control id from the message file, an API value) made safe to print."""
    return escape_for_terminal(text, single_line=True)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _serve_env(cert: Path, key: Path) -> dict[str, str]:
    """The engine's environment: this one, less every ``MEFOR_*`` (a developer's own store backend
    or bind host must not redirect the smoke), plus the rig's relaxations."""
    env = {name: value for name, value in os.environ.items() if not name.startswith("MEFOR_")}
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
        # honoured only beside the warn dial above (see harness.load.failover.EngineNode).
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
    return escape_for_terminal(data.decode("utf-8", "replace").replace("\r\n", "\n"))


def _wait_api(client: EngineClient, proc: subprocess.Popen[bytes], deadline: float) -> None:
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise StepFailed("serve", f"the engine exited with code {proc.returncode}")
        with contextlib.suppress(ApiError):
            client.health()
            return
        time.sleep(0.2)
    raise StepFailed("serve", "/health never answered")


def _wait_inbound(
    client: EngineClient,
    proc: subprocess.Popen[bytes],
    *,
    inbound: str,
    mllp_port: int,
    deadline: float,
) -> None:
    """Wait until the API reports THIS engine's inbound running on ``mllp_port``.

    A bare connect would accept any process holding the port, and a failed inbound bind leaves the
    engine up (ADR 0031), so only the engine's own word that its listener runs is evidence."""
    seen = "no source row"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise StepFailed("ready", f"the engine exited with code {proc.returncode}")
        for row in client.connections():
            if row.role == "source" and row.channel_id == inbound:
                seen = f"status {row.status}, port {row.port}"
                if row.status == "running" and row.port == mllp_port:
                    return
                if row.status == "failed":
                    raise StepFailed("ready", f"inbound {inbound} failed to start")
        time.sleep(_POLL_S)  # GET /connections is paced per actor too
    raise StepFailed("ready", f"inbound {inbound} never ran on port {mllp_port} ({_shown(seen)})")


def _send(port: int, message: str, timeout: float) -> str | None:
    """MLLP-send ``message`` to the loopback inbound and return the ACK's MSA-1."""
    try:
        wire = frame_checked(message)
    except FramePayloadError as exc:
        raise StepFailed("mllp", f"not sent: {type(exc).__name__}") from None
    deadline = time.monotonic() + timeout
    decoder = MLLPDecoder(max_frame_bytes=DEFAULT_MAX_FRAME_BYTES)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.sendall(wire)
            while (left := deadline - time.monotonic()) > 0:
                sock.settimeout(left)
                chunk = sock.recv(4096)
                if not chunk:
                    break
                for ack in decoder.feed(chunk):
                    try:
                        return Peek.parse(ack).field("MSA-1")
                    except HL7PeekError:
                        return None
    except (OSError, MLLPFrameError) as exc:
        raise StepFailed("mllp", f"no ACK from port {port}: {type(exc).__name__}") from None
    raise StepFailed("mllp", f"no ACK from port {port} within {timeout:.0f}s")


def _poll_disposition(
    client: EngineClient, *, inbound: str, control_id: str, deadline: float
) -> str | None:
    """The message's status once final, or the last status seen (``None`` if never stored)."""
    last: str | None = None
    while True:
        page = client.list_messages(channel_id=inbound, control_id=control_id, limit=1)
        if page.messages:
            last = page.messages[0].status.lower()
            if last in _TERMINAL:
                return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(_POLL_S)


def _stop(proc: subprocess.Popen[bytes], job: int | None) -> None:
    """Stop the engine and everything it started. Never raises: it runs in a ``finally``."""
    if proc.poll() is None:
        # PermissionError: Windows refuses TerminateProcess on a root its job is already ending.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=15)
    if job is not None:
        terminate_job(job)
    if ADOPT_NEW_SESSION:
        # POSIX: whatever the engine started is in its own group, which outlives the leader.
        kill_process_group(proc.pid, started_as_leader=True)


def _start(
    argv: list[str], *, work: Path, env: dict[str, str], log: Path
) -> tuple[subprocess.Popen[bytes], int | None]:
    with log.open("wb") as log_fh:
        proc = subprocess.Popen(  # noqa: S603 -- our own interpreter and fixed arguments
            argv,
            cwd=str(work),
            env=env,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            creationflags=ADOPT_CREATIONFLAGS,
            start_new_session=ADOPT_NEW_SESSION,
        )
    try:
        # Windows: the engine starts suspended and joins a kill-on-close job, so it dies with
        # this process by any route. Elsewhere this is a no-op and the child already runs.
        return proc, resume_into_job(proc.pid, who="e2e smoke engine")
    except OSError:
        _stop(proc, None)
        raise StepFailed("serve", "could not resume the engine process") from None


def run(
    *,
    config: Path,
    message_file: Path,
    inbound: str,
    mllp_port: int,
    expect: str,
    timeout: float,
    api_port: int | None = None,
    project_root: Path = _REPO,
) -> None:
    """Run every step. Returns on a pass; raises :class:`StepFailed` naming the step otherwise."""
    try:
        message = normalize(message_file.read_bytes())
        control_id = Peek.parse(message).control_id
    except (OSError, HL7PeekError) as exc:
        raise StepFailed("message", f"cannot read {message_file}: {type(exc).__name__}") from None
    if not control_id:
        raise StepFailed("message", f"{message_file} has no MSH-10 control id")
    shown_id = _shown(control_id)
    state = port_state(mllp_port)
    if state != "free":
        raise StepFailed("ports", f"MLLP port {mllp_port} is {state}")
    if api_port is None:
        api_port = _free_port()

    work = Path(tempfile.mkdtemp(prefix="mefor-e2e-smoke-"))
    proc: subprocess.Popen[bytes] | None = None
    job: int | None = None
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
            created = rigadmin.provision(env=env, cwd=work, db=str(db))
        except rigadmin.RigAdminError as exc:
            raise StepFailed("provision", str(exc)) from None
        if not created:
            raise StepFailed("provision", "the fresh store already held an Administrator")

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
            str(project_root),
        ]
        print(f"step serve: API on {api_port}, inbound {inbound} on {mllp_port}", flush=True)
        log = work / "engine.log"
        proc, job = _start(argv, work=work, env=env, log=log)

        client = EngineClient(f"https://127.0.0.1:{api_port}", cacert=str(cert), timeout=10.0)
        with client:
            try:
                _wait_api(client, proc, time.monotonic() + timeout)
                try:
                    # rigadmin's sign-in, so a rig that supplies an authenticator key signs in too.
                    client.set_token(rigadmin.sign_in(client.base_url, cacert=str(cert)))
                except (rigadmin.RigAdminError, ApiError) as exc:
                    raise StepFailed(
                        "sign-in", f"the engine refused the rig sign-in: {exc}"
                    ) from None
                print("step sign-in: rig Administrator", flush=True)
                _wait_inbound(
                    client,
                    proc,
                    inbound=inbound,
                    mllp_port=mllp_port,
                    deadline=time.monotonic() + timeout,
                )
            except StepFailed as exc:
                if exc.step == "sign-in":
                    raise
                tail = _log_tail(log)
                raise StepFailed(exc.step, f"{exc}\n--- engine log tail ---\n{tail}") from None
            except ApiError as exc:
                raise StepFailed("ready", f"GET /connections failed: {exc}") from None
            print(f"step ready: inbound {inbound} running on {mllp_port}", flush=True)

            code = _send(mllp_port, message, timeout=10.0)
            if code != "AA":
                raise StepFailed("mllp", f"MSA-1 was {_shown(str(code))}, expected AA")
            print(f"step mllp: AA for control id {shown_id}", flush=True)

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
                seen = "never stored" if status is None else _shown(status.upper())
                raise StepFailed(
                    "disposition",
                    f"control id {shown_id} on {inbound}: {seen}, expected {expect.upper()}",
                )
            print(f"step disposition: {status.upper()}", flush=True)
    finally:
        if proc is not None:
            _stop(proc, job)
        _remove(work)


def _remove(path: Path) -> None:
    """Delete the temp dir. Windows may hold the store file briefly after the engine dies."""
    for _ in range(8):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.25)
    try:
        shutil.rmtree(path)
    except OSError as exc:
        # It holds a throwaway loopback key and a synthetic store; say so rather than pass quietly.
        print(
            f"WARNING could not delete {path} ({type(exc).__name__}); remove it by hand",
            file=sys.stderr,
            flush=True,
        )


def _exit_on_sigterm(signum: int, frame: FrameType | None) -> None:
    raise SystemExit(128 + signum)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m harness.e2e_smoke", description=__doc__)
    parser.add_argument("--config", type=Path, default=_DEFAULT_CONFIG)
    parser.add_argument("--message", type=Path, default=_DEFAULT_MESSAGE)
    parser.add_argument("--inbound", default=_DEFAULT_INBOUND)
    parser.add_argument("--mllp-port", type=int, default=_DEFAULT_MLLP_PORT)
    parser.add_argument("--api-port", type=int, default=None, help="default: a free port")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=_REPO,
        help="where environments/dev.toml is read (default: this repository)",
    )
    parser.add_argument("--expect", default="processed", choices=sorted(_TERMINAL))
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds per waiting step")
    args = parser.parse_args(argv)
    # A SIGTERM (a CI cancel, a subprocess timeout) unwinds through run()'s finally, so the engine
    # is stopped and the temp directory deleted.
    previous = signal.signal(signal.SIGTERM, _exit_on_sigterm)
    started = time.monotonic()
    try:
        run(
            config=args.config.resolve(),
            message_file=args.message.resolve(),
            inbound=args.inbound,
            mllp_port=args.mllp_port,
            expect=args.expect,
            timeout=args.timeout,
            api_port=args.api_port,
            project_root=args.project_root.resolve(),
        )
    except StepFailed as exc:
        print(f"FAIL {exc.step}: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(f"PASS e2e smoke in {time.monotonic() - started:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
