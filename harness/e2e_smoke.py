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
port, so the message does not go to another process that took it in between. An inbound whose port
comes from ``env()`` reports none, so for it ``ready`` rests on the name and status alone, and only
the ``ports`` step's earlier check says the port was this engine's to take.

The steps, in order: ``message``, ``ports``, ``checkout``, ``provision``, ``serve``, ``sign-in``,
``ready``, ``mllp``, ``disposition``. ``checkout`` asks the engine's interpreter, started as
``serve`` is, where it imports ``messagefoundry`` from, and fails unless that is the package this
script imports: the engine runs with ``-P`` from the temp directory, so it imports whatever the
environment installed, which can be another checkout. Exit 0 when every step passes; otherwise
exit 1 with ``FAIL <step>: <reason>`` on stderr, where an unforeseen error gives its type as the
reason's first word and an error while stopping the engine names the step ``teardown``. An
installed harness has no checkout around it, so it fails ``message`` unless ``--config``,
``--message`` and ``--project-root`` name real paths.

The engine is stopped and the temp directory deleted on either exit, and on SIGINT, SIGTERM,
SIGHUP (POSIX) or SIGBREAK (Windows), when :func:`main` runs the smoke. Such a signal during that
teardown, or while a started engine is being handed back, is held until that finishes, and then
ends the run. A SIGKILL of this process skips the teardown, and so does a caller's timeout that
sends one, such as ``subprocess.run(timeout=...)``. On Windows the
engine still dies with it (its kill-on-close job); on POSIX it does not: the engine leads its own
session, so it outlives this process and keeps its ports until stopped by hand, and the temp
directory stays. For the same reason a terminal hangup reaches the engine only through this
process's SIGHUP handler.

It signs in as the rig Administrator :mod:`harness.load.rigadmin` provisions with a password drawn
per run, which is never printed. The engine gets none of the caller's ``MEFOR_*`` settings, only
the ones :func:`_serve_env` names, which loosen checks because it serves a synthetic graph.

It prints step names, the control id and the disposition, never a message body (CLAUDE.md
section 9). On a ``serve`` or ``ready`` failure it prints the tail of the engine's own log.
"""

from __future__ import annotations

import argparse
import contextlib
import math
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from types import FrameType

import messagefoundry
from harness.load import rigadmin
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.childenv import CHILD_INTERPRETER_FLAGS, outside_engine_namespace
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
    GroupKill,
    kill_process_group,
    kill_reaped_leader_group,
    resume_into_job,
    terminate_job,
)
from messagefoundry.terminal_text import escape_for_terminal
from messagefoundry.verify_leaf import port_state

_REPO = Path(__file__).resolve().parents[1]
_DEFAULT_CONFIG = _REPO / "samples" / "config"
_DEFAULT_MESSAGE = _REPO / "samples" / "messages" / "adt_a01.hl7"
#: What ``serve --env dev`` reads under the default ``--project-root``.
_DEFAULT_ENVIRONMENTS = _REPO / "environments"
_DEFAULT_INBOUND = "IB_Test_ADT"
_DEFAULT_MLLP_PORT = 2575
_DEFAULT_MLLP_TIMEOUT = 10.0

#: The final dispositions, by ``MessageStatus`` value. Polling stops at the first of these.
#: ``error`` is reachable only after the ACK (a router or transform failure): a message the
#: listener refuses is NAKed, which fails the ``mllp`` step first.
_TERMINAL = frozenset({"processed", "filtered", "unrouted", "error", "not_deployed"})

#: Once a second: the engine paces reads per actor, by default 120 a minute for PHI reads and 600 for
#: monitoring reads, and a faster poll would turn a slow disposition into a 429.
_POLL_S = 1.0
_LOG_TAIL_BYTES = 4000

#: The signals :func:`main` turns into an orderly exit, so the run's teardown still runs.
_HANDLED_SIGNALS: tuple[signal.Signals, ...] = tuple(
    sig
    for sig in (
        signal.SIGINT,
        signal.SIGTERM,
        getattr(signal, "SIGHUP", None),
        getattr(signal, "SIGBREAK", None),
    )
    if sig is not None
)


def _raise_for(signum: int) -> None:
    if signum == signal.SIGINT:
        raise KeyboardInterrupt
    raise SystemExit(128 + signum)


class _SignalState:
    """The handler :func:`main` installs for :data:`_HANDLED_SIGNALS`.

    Outside :meth:`held` a signal ends the run at once, as ``KeyboardInterrupt`` for SIGINT and
    ``SystemExit(128 + n)`` for the others, which unwinds through the teardown. Inside it the
    first signal waits until the block is done and is acted on then, so a second Ctrl+C or a
    repeated SIGTERM cannot cut a teardown halfway, or lose a started engine before it is
    recorded. The flag is the only state the handler reads, so entering the block is one store,
    with no handler swap for a signal to land in. A signal in the instant before that store still
    acts at once."""

    def __init__(self) -> None:
        self.holding = False
        self.pending: int | None = None

    def handle(self, signum: int, frame: FrameType | None) -> None:
        if not self.holding:
            _raise_for(signum)
        if self.pending is None:
            self.pending = signum

    def release(self) -> None:
        """End the hold, then act on a signal that arrived during it."""
        self.holding = False
        if self.pending is not None:
            signum, self.pending = self.pending, None
            _raise_for(signum)

    @contextlib.contextmanager
    def held(self) -> Iterator[None]:
        """Hold signals for the block, then act on one that arrived, however the block exits."""
        self.holding = True
        try:
            yield
        finally:
            self.release()


_SIGNALS = _SignalState()


class _Progress:
    """The step :func:`run` is on, so :func:`main` can name it when something unforeseen escapes."""

    def __init__(self) -> None:
        self.step = "message"


_PROGRESS = _Progress()


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
    """The engine's environment: this one, less the engine's namespace (every ``MEFOR_*`` and the
    secrets outside it; a developer's own store backend or bind host must not redirect the smoke),
    plus :data:`harness.load.rigadmin.SERVE_ENV`, this run's TLS pair, and three per-gate
    relaxations (and, on Windows, the config-source escape) that
    :class:`harness.load.failover.EngineNode` also sets. Unlike that node it leaves the
    monitoring-read pace on, which the once-a-second poll stays under."""
    env = {k: v for k, v in os.environ.items() if outside_engine_namespace(k)}
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
            data = fh.read(_LOG_TAIL_BYTES)
    except OSError as exc:
        return f"(the engine log could not be read: {type(exc).__name__})"
    return escape_for_terminal(data.decode("utf-8", "replace").replace("\r\n", "\n"))


def _check_checkout(env: dict[str, str], work: Path) -> Path:
    """Fail unless the engine's interpreter imports the ``messagefoundry`` this script does, and
    return that package's directory."""
    probe = "import sys, messagefoundry; sys.stdout.write(messagefoundry.__file__ or '')"
    try:
        done = subprocess.run(  # noqa: S603 -- our own interpreter and a fixed probe
            [sys.executable, *CHILD_INTERPRETER_FLAGS, "-c", probe],
            cwd=str(work),
            env=env,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StepFailed("checkout", f"could not run the probe: {type(exc).__name__}") from None
    if done.returncode != 0 or not done.stdout:
        lines = done.stderr.decode("utf-8", "replace").strip().splitlines()
        why = f": {_shown(lines[-1])}" if lines else ""
        raise StepFailed("checkout", f"the engine's interpreter cannot import messagefoundry{why}")
    theirs = Path(done.stdout.decode("utf-8", "replace")).resolve().parent
    ours = Path(messagefoundry.__file__ or "").resolve().parent
    if theirs != ours:
        raise StepFailed(
            "checkout",
            f"the engine would import messagefoundry from {_shown(str(theirs))}, not "
            f"{_shown(str(ours))}; install this checkout into the interpreter "
            "(scripts/worktree/ensure-venv.ps1)",
        )
    return ours


def _wait_api(client: EngineClient, proc: subprocess.Popen[bytes], deadline: float) -> None:
    last = "no answer yet"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise StepFailed("serve", f"the engine exited with code {proc.returncode}")
        try:
            client.health()
            return
        except ApiError as exc:
            last = str(exc)
        time.sleep(0.2)
    raise StepFailed("serve", f"/health never answered (last: {_shown(last)})")


def _wait_inbound(
    client: EngineClient,
    proc: subprocess.Popen[bytes],
    *,
    inbound: str,
    mllp_port: int,
    deadline: float,
) -> int | None:
    """Wait until the API reports THIS engine's inbound running on ``mllp_port``, and return the
    port it reported. A running MLLP inbound that reports no port (one whose port comes from
    ``env()``) passes on its name, and returns ``None``. ``GET /connections`` reports a port for no
    other connector type, so any other inbound fails at once: the smoke sends MLLP.

    A bare connect would accept any process holding the port, and a failed inbound bind leaves the
    engine up (ADR 0031), so only the engine's own word that its listener runs is evidence. An
    inbound that failed, is not deployed, is DR-parked (``filtered``), runs on another port, or is
    absent from a graph that lists other inbounds will not change by waiting, so each fails at
    once with what the API said."""
    seen = "no source row"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise StepFailed("ready", f"the engine exited with code {proc.returncode}")
        try:
            rows = client.connections()
        except ApiError as exc:
            raise StepFailed("ready", f"GET /connections failed: {_shown(str(exc))}") from None
        sources = [row for row in rows if row.role == "source"]
        mine = [row for row in sources if row.channel_id == inbound]
        if sources and not mine:
            raise StepFailed("ready", f"inbound {_shown(inbound)} is not in the engine's graph")
        for row in mine:
            if row.method != "MLLP":
                raise StepFailed(
                    "ready", f"inbound {_shown(inbound)} is {_shown(row.method)}, not MLLP"
                )
            seen = f"status {row.status}, port {row.port}"
            if row.status == "running" and row.port in (mllp_port, None):
                return row.port
            if row.status in ("failed", "not_deployed", "filtered", "running"):
                raise StepFailed(
                    "ready", f"inbound {_shown(inbound)}: {_shown(seen)}, expected port {mllp_port}"
                )
        time.sleep(_POLL_S)  # GET /connections is paced per actor too
    raise StepFailed(
        "ready", f"inbound {_shown(inbound)} never ran on port {mllp_port} ({_shown(seen)})"
    )


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
                    raise StepFailed("mllp", f"port {port} closed the connection before an ACK")
                for ack in decoder.feed(chunk):
                    try:
                        return Peek.parse(ack).field("MSA-1")
                    except HL7PeekError as exc:
                        raise StepFailed(
                            "mllp",
                            f"the reply from port {port} did not parse: {type(exc).__name__}",
                        ) from None
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


def _stop(proc: subprocess.Popen[bytes], job: int | None, *, never_ran: bool = False) -> bool:
    """Stop the engine and everything it started. It is not meant to raise: it runs in a
    ``finally``, where :func:`run` reports an error it does raise as a ``WARNING`` when a step had
    already failed. ``never_ran`` is for a child that was never resumed, whose job already ended
    it, so no job holding it is no loss.

    On POSIX the engine's group outlives its leader. Once ``Popen`` has reaped the leader its pid
    may be reused, so the group is signalled through the reuse-safe
    :func:`~messagefoundry.proctree.kill_reaped_leader_group`; only a leader still unreaped, whose
    pid nothing else can hold, takes :func:`~messagefoundry.proctree.kill_process_group`.

    A refused or failed kill is not swallowed: an engine still running afterwards, or a Windows
    engine no kill-on-close job held, prints a ``WARNING`` line, and the return is ``False``."""
    clean = True
    if proc.poll() is None:
        # PermissionError: Windows refuses TerminateProcess on a root its job is already ending.
        # Suppressed only because the check below reports an engine that outlived the refusal.
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
        if proc.poll() is None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
    if proc.poll() is None:
        clean = False
        print(
            f"WARNING the engine (pid {proc.pid}) did not stop; stop it by hand",
            file=sys.stderr,
            flush=True,
        )
    elif sys.platform == "win32" and job is None and not never_ran:
        clean = False
        print(
            f"WARNING no kill-on-close job held the engine (pid {proc.pid}); a process it started"
            " may still run",
            file=sys.stderr,
            flush=True,
        )
    if ADOPT_NEW_SESSION:
        if proc.returncode is None:
            reached = kill_process_group(proc.pid, started_as_leader=True) is not GroupKill.NOT_SENT
        else:
            reached = kill_reaped_leader_group(proc.pid) is not None
        if not reached:
            clean = False
            print(
                f"WARNING the engine's process group {proc.pid} could not be signalled; a process"
                " it started may still run",
                file=sys.stderr,
                flush=True,
            )
    return clean


def _start(
    argv: list[str], *, work: Path, env: dict[str, str], log: Path
) -> tuple[subprocess.Popen[bytes], int | None]:
    try:
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
    except OSError as exc:
        raise StepFailed("serve", f"could not start the engine: {type(exc).__name__}") from None
    try:
        # Windows: the engine starts suspended and joins a kill-on-close job, so it dies with
        # this process by any route. Elsewhere this is a no-op and the child already runs.
        return proc, resume_into_job(proc.pid, who="e2e smoke engine")
    except OSError:
        _stop(proc, None, never_ran=True)
        raise StepFailed("serve", "could not resume the engine process") from None
    except BaseException:
        # Anything else, a Ctrl+C included, still leaves a suspended engine outside any job; stop
        # it before the error travels on, so no engine outlives the run.
        _stop(proc, None, never_ran=True)
        raise


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
    mllp_timeout: float = _DEFAULT_MLLP_TIMEOUT,
) -> None:
    """Run every step. Returns on a pass; raises :class:`StepFailed` naming the step otherwise."""
    _PROGRESS.step = "message"
    try:
        message = normalize(message_file.read_bytes())
        control_id = Peek.parse(message).control_id
    except (OSError, HL7PeekError) as exc:
        raise StepFailed(
            "message", f"cannot read {_shown(str(message_file))}: {type(exc).__name__}"
        ) from None
    if not control_id:
        raise StepFailed("message", f"{_shown(str(message_file))} has no MSH-10 control id")
    shown_id = _shown(control_id)
    shown_inbound = _shown(inbound)
    _PROGRESS.step = "ports"
    for what, port in (("MLLP", mllp_port), ("API", api_port)):
        if port is not None and (state := port_state(port)) != "free":
            raise StepFailed("ports", f"{what} port {port} is {state}")

    work = Path(tempfile.mkdtemp(prefix="mefor-e2e-smoke-"))
    proc: subprocess.Popen[bytes] | None = None
    job: int | None = None
    failing: BaseException | None = None
    try:
        cert, key = work / "api-cert.pem", work / "api-key.pem"
        db = work / "store.db"
        env = _serve_env(cert, key)
        _PROGRESS.step = "checkout"
        package = _check_checkout(env, work)
        print(f"step checkout: messagefoundry from {_shown(str(package))}", flush=True)

        _PROGRESS.step = "provision"
        from messagefoundry import pki  # pulls cryptography; only a run needs it

        cert_pem, key_pem = pki.make_self_signed("127.0.0.1", ["127.0.0.1", "localhost"], 2)
        cert.write_bytes(cert_pem)
        key.touch(mode=0o600)  # owner-only before the key is in it, as the engine's key gate wants
        key.write_bytes(key_pem)
        print(f"step provision: rig Administrator in {db.name}", flush=True)
        # The account is this run's own: a rig credential the caller's shell still carries
        # (MEFOR_RIG_ADMIN_*) must not reach a smoke whose engine gets none of its settings.
        admin = rigadmin.RigAdmin(rigadmin._DEFAULT_USERNAME, rigadmin._new_password())
        try:
            created = rigadmin.provision(env=env, cwd=work, db=str(db), admin=admin)
        except rigadmin.RigAdminError as exc:
            raise StepFailed("provision", _shown(str(exc))) from None
        if not created:
            raise StepFailed("provision", "the fresh store already held an Administrator")
        if api_port is None:
            api_port = _free_port()  # drawn last, so another process has least time to take it
            while api_port == mllp_port:  # free now, but the inbound is about to bind it
                api_port = _free_port()

        argv = [
            sys.executable,
            *CHILD_INTERPRETER_FLAGS,
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
        _PROGRESS.step = "serve"
        print(f"step serve: API on {api_port}, inbound {shown_inbound} on {mllp_port}", flush=True)
        log = work / "engine.log"
        with _SIGNALS.held():  # a signal here must not lose the engine before ``proc`` holds it
            proc, job = _start(argv, work=work, env=env, log=log)

        client = EngineClient(f"https://127.0.0.1:{api_port}", cacert=str(cert), timeout=10.0)
        with client:
            try:
                _wait_api(client, proc, time.monotonic() + timeout)
                _PROGRESS.step = "sign-in"
                try:
                    # rigadmin's sign-in, as the account provisioned above.
                    client.set_token(rigadmin.sign_in(client.base_url, admin, cacert=str(cert)))
                except (rigadmin.RigAdminError, ApiError) as exc:
                    raise StepFailed(
                        "sign-in", f"the rig sign-in failed: {_shown(str(exc))}"
                    ) from None
                print("step sign-in: rig Administrator", flush=True)
                _PROGRESS.step = "ready"
                reported = _wait_inbound(
                    client,
                    proc,
                    inbound=inbound,
                    mllp_port=mllp_port,
                    deadline=time.monotonic() + timeout,
                )
            except StepFailed as exc:
                if exc.step == "sign-in" and proc.poll() is None:
                    raise
                died = (
                    f"; the engine exited with code {proc.returncode}"
                    if exc.step == "sign-in"
                    else ""
                )
                tail = _log_tail(log)
                raise StepFailed(
                    exc.step, f"{exc}{died}\n--- engine log tail ---\n{tail}"
                ) from None
            where = f"on {mllp_port}" if reported is not None else "(port not reported)"
            print(f"step ready: inbound {shown_inbound} running {where}", flush=True)

            try:
                _PROGRESS.step = "mllp"
                code = _send(mllp_port, message, timeout=mllp_timeout)
                # CA is the enhanced-mode commit accept: an inbound with ack_mode="enhanced" says it.
                if code not in ("AA", "CA"):
                    raise StepFailed("mllp", f"MSA-1 was {_shown(str(code))}, expected AA or CA")
                print(f"step mllp: {code} for control id {shown_id}", flush=True)
                _PROGRESS.step = "disposition"

                try:
                    status = _poll_disposition(
                        client,
                        inbound=inbound,
                        control_id=control_id,
                        deadline=time.monotonic() + timeout,
                    )
                except ApiError as exc:
                    raise StepFailed(
                        "disposition", f"GET /messages failed: {_shown(str(exc))}"
                    ) from None
            except StepFailed as exc:
                if proc.poll() is None:
                    raise
                # The engine died on the message: that, not the socket or the API, is the cause.
                raise StepFailed(
                    exc.step,
                    f"{exc}; the engine exited with code {proc.returncode}\n"
                    f"--- engine log tail ---\n{_log_tail(log)}",
                ) from None
            if status != expect:
                seen = "never stored" if status is None else _shown(status.upper())
                raise StepFailed(
                    "disposition",
                    f"control id {shown_id} on {shown_inbound}: {seen}, expected {expect.upper()}",
                )
            print(f"step disposition: {status.upper()}", flush=True)
    except BaseException as exc:
        failing = exc
        raise
    finally:
        _SIGNALS.holding = True  # first, one store: a signal from here on waits for the teardown
        # A step's failure stays the run's failure: a teardown error then is only a WARNING. With
        # no failure in flight, the teardown's own error, or anything it left behind, ends the run
        # as ``teardown``.
        failed_step, _PROGRESS.step = _PROGRESS.step, "teardown"
        clean = True
        try:
            try:
                if proc is not None:
                    clean = _stop(proc, job)
            finally:
                try:
                    clean = _remove(work) and clean
                finally:
                    _SIGNALS.release()
            if not clean and failing is None:
                raise StepFailed(
                    "teardown",
                    "the run left the engine or its temp directory behind (WARNING above)",
                )
        except StepFailed:
            raise
        except Exception as exc:
            if failing is None:
                raise
            print(
                f"WARNING the teardown failed too: {type(exc).__name__}: {_shown(str(exc))}",
                file=sys.stderr,
                flush=True,
            )
        _PROGRESS.step = failed_step


def _remove(path: Path) -> bool:
    """Delete the temp dir, and say whether it is gone. Windows may hold the store file briefly
    after the engine dies."""
    for _ in range(8):
        try:
            shutil.rmtree(path)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            time.sleep(0.25)
    try:
        shutil.rmtree(path)
        return True
    except OSError as exc:
        # It holds a throwaway loopback key and a synthetic store; say so rather than pass quietly.
        print(
            f"WARNING could not delete {path} ({type(exc).__name__}); remove it by hand",
            file=sys.stderr,
            flush=True,
        )
        return False


def _positive_seconds(text: str) -> float:
    value = float(text)
    if not (value > 0 and math.isfinite(value)):
        raise argparse.ArgumentTypeError(f"must be a finite number of seconds above 0, not {text}")
    return value


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
    parser.add_argument(
        "--timeout", type=_positive_seconds, default=60.0, help="seconds per waiting step"
    )
    parser.add_argument(
        "--mllp-timeout",
        type=_positive_seconds,
        default=_DEFAULT_MLLP_TIMEOUT,
        help=f"seconds to wait for the ACK (default {_DEFAULT_MLLP_TIMEOUT:.0f})",
    )
    args = parser.parse_args(argv)
    # An installed harness has no checkout around it, so a default left in place names a path
    # under site-packages that does not exist. Say so, rather than fail later on a missing file.
    absent = [
        f"--{flag} ({_shown(str(needed))})"
        for flag, path, default, needed in (
            ("config", args.config, _DEFAULT_CONFIG, _DEFAULT_CONFIG),
            ("message", args.message, _DEFAULT_MESSAGE, _DEFAULT_MESSAGE),
            ("project-root", args.project_root, _REPO, _DEFAULT_ENVIRONMENTS),
        )
        if path == default and not needed.exists()
    ]
    if absent:
        print(
            f"FAIL message: not found for the default {', '.join(absent)}, so this harness has"
            " no checkout around it; pass --config, --message and --project-root, or run from a"
            " MessageFoundry checkout",
            file=sys.stderr,
            flush=True,
        )
        return 1
    # A Ctrl+C, a SIGTERM (a CI cancel, a POSIX caller's terminate()), a hangup or a Ctrl+Break
    # unwinds through run()'s finally, so the engine is stopped and the temp directory deleted. On
    # Windows terminate() is TerminateProcess, which no handler sees.
    previous: dict[signal.Signals, signal._HANDLER] = {}
    for sig in _HANDLED_SIGNALS:
        try:
            if signal.getsignal(sig) == signal.SIG_IGN:
                continue  # the caller ignores it on purpose, as nohup does SIGHUP
            previous[sig] = signal.signal(sig, _SIGNALS.handle)
        except ValueError:  # not the main thread, where no signal is delivered anyway
            break
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
            mllp_timeout=args.mllp_timeout,
        )
    except StepFailed as exc:
        print(f"FAIL {exc.step}: {exc}", file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        print("INTERRUPTED e2e smoke", file=sys.stderr, flush=True)
        return 128 + signal.SIGINT
    except Exception as exc:  # noqa: BLE001 -- the last word: every failure ends in a FAIL line
        print(
            f"FAIL {_PROGRESS.step}: {type(exc).__name__}: {_shown(str(exc))}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    finally:
        for sig, handler in previous.items():
            # None: a handler not installed from Python, which signal.signal cannot put back.
            signal.signal(sig, signal.SIG_DFL if handler is None else handler)
    print(f"PASS e2e smoke in {time.monotonic() - started:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
