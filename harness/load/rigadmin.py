# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The rig Administrator: how a CI leg or a load rig signs in to the engine it starts.

A *rig* is a workflow step or a harness runner that starts a real ``messagefoundry serve`` in order
to smoke it or measure it. Rigs sign in. The engine creates no account on its own, so a rig
provisions one Administrator in the store before the engine starts, signs in once it is up, and
reads the API with that session.

``provision-admin`` reads its password from a terminal and has no other input, on purpose. A rig has
no terminal. So :func:`provision` runs the shipped command in a child process with that one read
replaced by a value the rig holds. Settings, the at-rest gate, the store open, the password policy
and the account write are the shipped code path. ``scripts/service/measure-store-access.ps1`` does
the same on Windows; this is that recipe for every platform.

**This is test tooling.** It adds no flag, no environment switch and no password path to any shipped
command. The rig password is drawn per run and is never written to a file or printed. It is held in
memory, in this process's environment for a child harness process, and in the environment of the
one child that provisions.

Two things a rig's ``serve`` needs beside the account:

* ``MEFOR_SECURITY_REQUIRE_MFA=false`` (:data:`SERVE_ENV`). The shipped command enrols an
  authenticator app at the terminal, and offers no other way, so the rig account has none.
* Under ``[security].enforcement = enforce``, a way to send account-security notices
  (:data:`NOTIFY_ENV`). A start with sign-in on refuses without one. The account carries an address
  for the same reason.

**It imports nothing beside the standard library at module level**, and nothing from ``harness``.
So one file serves three callers: the harness runners import it, a workflow runs
``python -m harness.load.rigadmin``, and the container smoke mounts this file alone and runs it with
the image's interpreter.

The session is one per process, as the TLS anchor is (:mod:`harness.load.tlsmat`). Sessions live in
the store, so one sign-in covers every node that shares a store, however many nodes there are. That
matters because the engine caps the sessions one user may hold: a session per node would end the
first ones on a large fleet. A node on a different store refuses the session, and
:func:`renew_session` signs in again there. A drive split over more harness PROCESSES than that cap
(five by default) would end sessions in turn; no single-box rig is split that way.
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import io
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

__all__ = [
    "ADMIN_NAME_ENV",
    "ADMIN_PASS_ENV",
    "EXIT_EXISTS",
    "NOTIFY_ENV",
    "RIG_SESSION",
    "SERVE_ENV",
    "RigAdmin",
    "RigAdminError",
    "RigSession",
    "RigSignInRefused",
    "RigUnreachable",
    "provision",
    "renew_session",
    "rig_admin",
    "session_token",
    "sign_in",
]

#: The rig credential, when the caller supplies it. A workflow step draws the password in its own
#: shell and passes it here to both ``provision`` and the later sign-in. A harness process that finds
#: no password draws one and publishes it here, so a child harness process inherits the same
#: credential (the pattern :mod:`harness.load.tlsmat` uses for the certificate). An operator who keeps
#: one server store across runs exports both, since a store that already holds an Administrator
#: cannot be provisioned again.
#:
#: These two hold the NAMES of environment variables, and messages below print them. CodeQL's
#: clear-text-logging query labels a value by the name it is assigned to, so neither Python name
#: spells a word its heuristics match (at least "password", "secret", "token" and "account").
ADMIN_NAME_ENV = "MEFOR_RIG_ADMIN_USERNAME"
ADMIN_PASS_ENV = "MEFOR_RIG_ADMIN_PASSWORD"

_DEFAULT_USERNAME = "rig-operator"
#: ``.invalid`` never resolves (RFC 2606), so no notice for this account can leave the box.
_NOTIFY_ADDRESS = "rig-operator@example.invalid"

#: What a rig's ``serve`` carries so the rig account can use the API. ``provision`` sets it for the
#: provisioning child itself.
SERVE_ENV: Mapping[str, str] = {"MEFOR_SECURITY_REQUIRE_MFA": "false"}

#: What an ENFORCING rig's ``serve`` carries beside :data:`SERVE_ENV`: a configured channel for
#: account-security notices. The gate reads configuration only. Nothing listens on the port, so a
#: notice the engine tries to send is refused on loopback and logged.
NOTIFY_ENV: Mapping[str, str] = {
    "MEFOR_ALERTS_EMAIL_SMTP_HOST": "127.0.0.1",
    "MEFOR_ALERTS_EMAIL_SMTP_PORT": "2525",
    "MEFOR_ALERTS_EMAIL_FROM": _NOTIFY_ADDRESS,
    "MEFOR_ALERTS_EMAIL_TO": _NOTIFY_ADDRESS,
}

#: The part of ``provision-admin``'s refusal that means the store already has an enabled
#: Administrator. The VS Code extension keys on the same words (``ide/src/engineControlModel.ts``).
_ADMIN_EXISTS = "already has an enabled Administrator"

#: ``provision`` exit code for "the store already had an Administrator". Not a failure: the second
#: node of a shared store meets it on every run.
EXIT_EXISTS = 3

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_HTTP_TIMEOUT_S = 10.0
_PROVISION_TIMEOUT_S = 180.0


class RigAdminError(RuntimeError):
    """The rig could not provision its Administrator or sign in."""


class RigUnreachable(RigAdminError):
    """The engine did not answer: it is down, killed, or still starting."""


class RigSignInRefused(RigAdminError):
    """The engine answered and refused the rig credential."""


class RigSession:
    """Marker type for :data:`RIG_SESSION`."""

    def __repr__(self) -> str:
        return "RIG_SESSION"


#: Pass this where a bearer token goes to mean "sign in as this run's rig Administrator, when the
#: engine is up". ``EnginePoller`` takes it, because a poller is built before its engine starts.
RIG_SESSION = RigSession()


@dataclass(frozen=True)
class RigAdmin:
    """The rig's one account. ``password`` stays out of ``repr`` so a log line cannot carry it."""

    username: str
    password: str = field(repr=False)


def _new_password() -> str:
    # 48 hexadecimal characters. Every word on the engine's context deny-list, and this module's
    # username, holds a letter outside a-f, so the shipped password policy cannot refuse a draw for
    # one. A random alphanumeric draw spells one about once in 1,900 times, which is how a CI run
    # went red on 2026-09-30 (see measure-store-access.ps1).
    return secrets.token_hex(24)


class _HeldAdmin:
    """The one rig credential this process holds."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.admin: RigAdmin | None = None


_credential = _HeldAdmin()


def rig_admin() -> RigAdmin:
    """This process's rig credential: the one in the environment, or one drawn on first call."""
    with _credential.lock:
        if _credential.admin is None:
            username = os.environ.get(ADMIN_NAME_ENV) or _DEFAULT_USERNAME
            password = os.environ.get(ADMIN_PASS_ENV)
            if not password:
                password = _new_password()
                # A child harness process must sign in as the same account (see ADMIN_NAME_ENV).
                os.environ[ADMIN_PASS_ENV] = password
            _credential.admin = RigAdmin(username, password)
        return _credential.admin


# --- provisioning ------------------------------------------------------------


def provision(
    *,
    env: Mapping[str, str],
    cwd: str | Path | None = None,
    db: str | None = None,
    service_config: str | None = None,
    admin: RigAdmin | None = None,
) -> bool:
    """Provision the rig Administrator in the store ``env`` names, before ``serve`` starts.

    ``env`` and ``cwd`` are the ones the rig's ``serve`` runs under, so the child loads the same
    settings and opens the same store. Returns ``True`` when it created the account and ``False``
    when the store already had an enabled Administrator. Raises :class:`RigAdminError` on any other
    refusal, carrying the command's own words.

    The child is this file, run with ``-P`` so its directory is not put on ``sys.path``:
    ``harness/load`` holds modules named like standard-library ones.
    """
    admin = admin or rig_admin()
    child_env = {**env, ADMIN_NAME_ENV: admin.username, ADMIN_PASS_ENV: admin.password}
    argv = [sys.executable, "-P", str(Path(__file__).resolve()), "provision"]
    if db is not None:
        argv += ["--db", db]
    if service_config is not None:
        argv += ["--service-config", service_config]
    try:
        done = subprocess.run(
            argv,
            env=child_env,
            cwd=None if cwd is None else str(cwd),
            capture_output=True,
            text=True,
            timeout=_PROVISION_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise RigAdminError(
            f"provisioning the rig Administrator did not finish in {_PROVISION_TIMEOUT_S:.0f} s"
        ) from None
    if done.returncode == 0:
        return True
    if done.returncode == EXIT_EXISTS:
        return False
    detail = (done.stdout + done.stderr).strip()[-2000:]
    raise RigAdminError(
        f"could not provision the rig Administrator (exit {done.returncode}): {detail}"
    )


def _provision_here(db: str | None, service_config: str | None) -> int:
    """Run the shipped ``provision-admin`` in THIS process, with its terminal read replaced."""
    username = os.environ.get(ADMIN_NAME_ENV) or _DEFAULT_USERNAME
    # Popped, so the engine code below never finds the credential in its environment.
    held = os.environ.pop(ADMIN_PASS_ENV, None)
    if not held:
        print(
            f"error: {ADMIN_PASS_ENV} is not set. Draw a password for this run in the calling shell "
            "and pass it to this command and to the later sign-in.",
            file=sys.stderr,
        )
        return 2
    os.environ.update(SERVE_ENV)

    import messagefoundry.__main__ as cli

    def _held_password(prompt: str) -> str:
        return held

    # The ONE seam. Everything else provision-admin does is the shipped code path.
    cli._read_new_password = _held_password
    argv = ["provision-admin", "--username", username, "--email", _NOTIFY_ADDRESS]
    argv += ["--no-totp", "--json"]
    if db is not None:
        argv += ["--db", db]
    if service_config is not None:
        argv += ["--service-config", service_config]
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = cli.main(argv)
    if code == 0:
        print("provisioned the rig Administrator")
        return 0
    refusal = _json_error(captured.getvalue())
    if _ADMIN_EXISTS in refusal:
        print("the store already has an enabled Administrator; nothing provisioned")
        return EXIT_EXISTS
    # The command's refusals name settings and clauses, never the password it was given.
    print(refusal or captured.getvalue().strip(), file=sys.stderr)
    return code or 1


def _json_error(text: str) -> str:
    """The ``error`` string of the last JSON object ``provision-admin --json`` printed, or ``""``."""
    for line in reversed(text.strip().splitlines()):
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("error"), str):
            return str(payload["error"])
    return ""


# --- the API hop -------------------------------------------------------------


def _checked_base(base_url: str) -> str:
    """``base_url`` without a trailing slash, refused when a credential would cross it in clear."""
    parts = urlsplit(base_url)
    host = (parts.hostname or "").lower()
    if parts.scheme == "https" or (parts.scheme == "http" and host in _LOOPBACK_HOSTS):
        return base_url.rstrip("/")
    raise RigAdminError(
        "refusing to send a credential over cleartext to a host that is not loopback; "
        "reach the engine over https"
    )


def _context(cacert: str | None) -> ssl.SSLContext:
    # Verification is never switched off. With a PEM, that certificate is the only trust anchor,
    # which is how a client reaches an engine serving its own self-signed pair.
    return ssl.create_default_context(cafile=cacert)


def _call(
    method: str,
    url: str,
    *,
    cacert: str | None,
    body: Mapping[str, object] | None = None,
    bearer: str | None = None,
) -> tuple[int, bytes]:
    """One request. Returns ``(status, body)`` for any HTTP answer; raises when there is none."""
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if bearer:
        request.add_header("Authorization", f"Bearer {bearer}")
    try:
        # The context is passed on every call. A loopback http URL makes no handshake and ignores it.
        with urllib.request.urlopen(
            request, context=_context(cacert), timeout=_HTTP_TIMEOUT_S
        ) as reply:
            return int(reply.status), reply.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        # The reason only: an exception's text can carry the address, and callers log this.
        raise RigUnreachable(f"the engine did not answer ({type(exc).__name__})") from None


def sign_in(base_url: str, admin: RigAdmin | None = None, *, cacert: str | None = None) -> str:
    """Sign in as the rig Administrator and return the session's bearer token.

    Raises :class:`RigUnreachable` when the engine does not answer and :class:`RigSignInRefused`
    when it answers anything but a usable session.
    """
    admin = admin or rig_admin()
    base = _checked_base(base_url)
    status, raw = _call(
        "POST",
        f"{base}/auth/login",
        cacert=cacert,
        body={"username": admin.username, "password": admin.password},
    )
    if status != 200:
        raise RigSignInRefused(
            f"the engine refused the rig Administrator's sign-in (HTTP {status}). If this store "
            f"held an Administrator before this run, set {ADMIN_NAME_ENV} and {ADMIN_PASS_ENV} to that "
            "account, or use a fresh store."
        )
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        raise RigSignInRefused("the engine's sign-in answer was not a JSON object")
    if payload.get("mfa_required") or payload.get("must_change_password"):
        raise RigSignInRefused(
            "the engine signed the rig Administrator in but asks for a second factor or a "
            "password change first; the rig's serve needs MEFOR_SECURITY_REQUIRE_MFA=false"
        )
    held = payload.get("token")
    if not isinstance(held, str) or not held:
        raise RigSignInRefused("the engine answered the sign-in with no session")
    return held


class _HeldSession:
    """The one rig session this process holds, and the lock that serialises signing in."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.token: str | None = None


_held = _HeldSession()


def session_token(base_url: str, *, cacert: str | None = None) -> str:
    """This process's rig session, signing in at ``base_url`` on first use.

    No request is made once a session is held. A node that refuses the token (HTTP 401) is on a
    store this session is not in, or the session has expired: call :func:`renew_session`.
    """
    with _held.lock:
        if _held.token is None:
            _held.token = sign_in(base_url, cacert=cacert)
        return _held.token


def renew_session(base_url: str, stale: str | None, *, cacert: str | None = None) -> str:
    """Replace a session the engine at ``base_url`` refused, and return the one to use now.

    ``stale`` is the token that was refused. If another thread has already replaced it, that newer
    session is returned and no second sign-in is made. ``None`` always signs in: a caller that
    needs a credential proved just now, for a route that asks for one, passes it.
    """
    with _held.lock:
        if stale is None or _held.token is None or _held.token == stale:
            _held.token = sign_in(base_url, cacert=cacert)
        return _held.token


def _require_sign_in(base: str, path: str, *, cacert: str | None) -> None:
    """Refuse an engine that answers ``path`` with no session.

    A leg that signs in to an engine that would have answered anyway proves nothing about sign-in,
    so the command-line modes check this first.
    """
    status, _ = _call("GET", f"{base}{path}", cacert=cacert)
    if status != 401:
        raise RigAdminError(
            f"the engine answered {path} with HTTP {status} to a request that carried no session; "
            "a rig expects sign-in to be on"
        )


# --- command line ------------------------------------------------------------


def _cmd_provision(args: argparse.Namespace) -> int:
    return _provision_here(args.db, args.service_config)


def _cmd_run(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        print("error: give the command to run after --", file=sys.stderr)
        return 2
    base = _checked_base(args.engine)
    _require_sign_in(base, "/stats", cacert=args.cacert)
    held = sign_in(base, cacert=args.cacert)
    print(f"signed in as the rig Administrator; running {command[0]}", flush=True)
    # Resolved here, so a relative interpreter path works on Windows as it does on POSIX.
    command[0] = shutil.which(command[0]) or command[0]
    # The harness command line takes the session as --token, and the child is the only reader. The
    # child is given the session and not the password it came from.
    child_env = {name: value for name, value in os.environ.items() if name != ADMIN_PASS_ENV}
    try:
        return subprocess.call([*command, "--token", held], env=child_env)
    except OSError as exc:
        raise RigAdminError(f"could not start {command[0]}: {exc.strerror}") from None


def _cmd_get(args: argparse.Namespace) -> int:
    base = _checked_base(args.engine)
    path = args.path if args.path.startswith("/") else f"/{args.path}"
    if any(ch.isspace() for ch in path):
        raise RigAdminError("the API path holds whitespace; quote it, and check the shell kept it")
    _require_sign_in(base, path, cacert=args.cacert)
    held = sign_in(base, cacert=args.cacert)
    deadline = time.monotonic() + args.timeout
    while True:
        status, raw = _call("GET", f"{base}{path}", cacert=args.cacert, bearer=held)
        if status != 200:
            print(f"error: GET {path} answered HTTP {status}", file=sys.stderr)
            return 1
        if args.field is None:
            sys.stdout.write(raw.decode("utf-8", "replace"))
            return 0
        try:
            answer = json.loads(raw)
        except ValueError:
            answer = None
        value = answer.get(args.field) if isinstance(answer, dict) else None
        if not isinstance(value, int) or isinstance(value, bool):
            # Nothing on stdout: a caller that captures the count must never read a non-number.
            print(f"error: GET {path} carried no integer {args.field!r}", file=sys.stderr)
            return 1
        if value >= args.at_least or time.monotonic() >= deadline:
            print(value)
            return 0 if value >= args.at_least else 1
        time.sleep(args.interval)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rigadmin",
        description="Provision and sign in the Administrator a CI leg or load rig uses. "
        f"The password comes from {ADMIN_PASS_ENV}; it is never an argument.",
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    provision_cmd = sub.add_parser(
        "provision",
        help="create the rig Administrator in the store, before serve starts "
        f"(exit {EXIT_EXISTS}: the store already had one)",
    )
    provision_cmd.add_argument("--db", default=None, help="store path, as serve's --db")
    provision_cmd.add_argument("--service-config", default=None, help="service settings TOML")
    provision_cmd.set_defaults(handler=_cmd_provision)

    for name, text in (
        ("run", "sign in, then run a command with --token <session> appended"),
        ("get", "sign in, then GET one API path and print the answer"),
    ):
        cmd = sub.add_parser(name, help=text)
        cmd.add_argument("--engine", required=True, help="engine API base URL")
        cmd.add_argument("--cacert", default=None, help="PEM to pin as the only trust anchor")
        if name == "run":
            cmd.add_argument("command", nargs=argparse.REMAINDER, help="-- command [argument ...]")
            cmd.set_defaults(handler=_cmd_run)
        else:
            cmd.add_argument("path", help="API path, such as /messages?status=processed")
            cmd.add_argument("--field", default=None, help="print this integer field, not the body")
            cmd.add_argument(
                "--at-least",
                type=int,
                default=0,
                help="with --field: ask again until the field reaches this (exit 1 if it never does)",
            )
            cmd.add_argument("--timeout", type=float, default=30.0, help="seconds to keep asking")
            cmd.add_argument("--interval", type=float, default=0.5, help="seconds between asks")
            cmd.set_defaults(handler=_cmd_get)

    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except RigAdminError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Run by path, Python puts this file's directory first on sys.path. That directory holds modules
    # named like standard-library ones (profile), and this file needs none of them.
    _here = Path(__file__).resolve().parent
    sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != _here]
    raise SystemExit(main())
