# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CI and load rigs sign in (vault BACKLOG #2719, stage A): ``harness/load/rigadmin.py``.

A rig starts a real ``messagefoundry serve``. It used to start it with sign-in switched off. It now
provisions one Administrator, signs in, and reads the API with that session.

Three layers, cheapest first:

* the helper's own rules, with the engine and the network faked;
* the provisioning child against a real store, which is the shipped ``provision-admin`` with its
  terminal read replaced;
* one real ``serve`` behind :class:`~harness.load.failover.EngineNode`, to show the node refuses a
  request with no session and answers the rig's.

The workflow half is ``tests/test_ci_rig_legs_sign_in.py``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from harness.load import enginepoll, rigadmin
from harness.load.enginepoll import EnginePoller
from harness.load.failover import EngineNode
from harness.load.rigadmin import RIG_SESSION, RigAdmin
from harness.load.tlsmat import harness_ssl_context
from messagefoundry.apiclient import ApiError
from messagefoundry.auth.policy import CONTEXT_WORDS, PasswordPolicy

_ROOT = Path(__file__).resolve().parents[1]


def _env_for_a_sqlite_store(**extra: str) -> dict[str, str]:
    """This process's environment for a child that must use its OWN SQLite store: no store setting
    a server-database leg exports."""
    kept = {
        name: value for name, value in os.environ.items() if not name.startswith("MEFOR_STORE_")
    }
    return {**kept, **extra}


@pytest.fixture
def fresh_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give a test its own credential and session holders, and put the process's back after."""
    monkeypatch.setattr(rigadmin, "_credential", rigadmin._HeldAdmin())
    monkeypatch.setattr(rigadmin, "_held", rigadmin._HeldSession())
    # Set, then deleted: `rig_admin` publishes a drawn password into the environment itself, and
    # monkeypatch can only undo a variable it has seen.
    for name in (rigadmin.ADMIN_PASS_ENV, rigadmin.ADMIN_NAME_ENV):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


# --- the password ------------------------------------------------------------


def test_a_drawn_password_cannot_spell_a_deny_listed_word_or_the_username() -> None:
    """The draw is hexadecimal BECAUSE the shipped policy refuses a password that holds a context
    word or the account's own name, and an unscreened draw would hold one now and then. Checked
    against the engine's own list, so a word added there that hex can spell fails here."""
    hexdigits = set("0123456789abcdef")
    for word in (*CONTEXT_WORDS, rigadmin._DEFAULT_USERNAME):
        assert set(word.lower()) - hexdigits, f"{word!r} can be spelled in hexadecimal"
    policy = PasswordPolicy()
    for _ in range(25):
        drawn = rigadmin._new_password()
        assert set(drawn) <= hexdigits and len(drawn) == 48
        assert policy.violations(drawn, username=rigadmin._DEFAULT_USERNAME) == []
    # CONTROL: the same call refuses a draw that does hold a context word.
    assert policy.violations("0123456789abcdef-hl7-0123456789abcdef", username="rig-operator")


def test_the_credential_comes_from_the_environment_when_it_is_there(
    fresh_state: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(rigadmin.ADMIN_NAME_ENV, "bench-operator")
    monkeypatch.setenv(rigadmin.ADMIN_PASS_ENV, "f" * 48)
    assert rigadmin.rig_admin() == RigAdmin("bench-operator", "f" * 48)


def test_a_drawn_credential_is_published_for_a_child_process_and_drawn_once(
    fresh_state: None,
) -> None:
    first = rigadmin.rig_admin()
    assert first.username == rigadmin._DEFAULT_USERNAME
    # A child harness process (connscale-remote under batchbox) must sign in as the same account.
    assert os.environ[rigadmin.ADMIN_PASS_ENV] == first.password
    assert rigadmin.rig_admin() is first


def test_the_password_is_not_in_the_repr() -> None:
    admin = RigAdmin("rig-operator", "a1" * 24)
    assert "a1a1" not in repr(admin) and "rig-operator" in repr(admin)


# --- the hop -----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["https://engine.example.org:8765", "https://127.0.0.1:8765/", "http://127.0.0.1:8765"],
)
def test_a_credential_may_cross_https_or_loopback(url: str) -> None:
    assert rigadmin._checked_base(url) == url.rstrip("/")


@pytest.mark.parametrize("url", ["http://engine.example.org:8765", "http://10.0.0.5:8765", "x"])
def test_a_credential_is_refused_cleartext_to_another_host(url: str) -> None:
    with pytest.raises(rigadmin.RigAdminError, match="cleartext"):
        rigadmin._checked_base(url)


def _answers(monkeypatch: pytest.MonkeyPatch, *replies: tuple[int, object]) -> list[dict[str, Any]]:
    """Script ``rigadmin._call``: each call takes the next reply, and is recorded."""
    calls: list[dict[str, Any]] = []
    queue = list(replies)

    def fake(method: str, url: str, **kw: Any) -> tuple[int, bytes]:
        calls.append({"method": method, "url": url, **kw})
        status, body = queue.pop(0)
        return status, json.dumps(body).encode("utf-8")

    monkeypatch.setattr(rigadmin, "_call", fake)
    return calls


def test_sign_in_posts_the_credential_and_returns_the_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _answers(monkeypatch, (200, {"token": "session-1"}))
    admin = RigAdmin("rig-operator", "ab" * 24)
    assert rigadmin.sign_in("https://127.0.0.1:1/", admin, cacert="pin.pem") == "session-1"
    assert calls == [
        {
            "method": "POST",
            "url": "https://127.0.0.1:1/auth/login",
            "cacert": "pin.pem",
            "body": {"username": "rig-operator", "password": "ab" * 24},
        }
    ]


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (401, {"detail": "invalid credentials"}),
        (503, {"detail": "authentication is not enabled"}),
        (200, {"token": "t", "mfa_required": True}),
        (200, {"token": "t", "must_change_password": True}),
        (200, {"token": ""}),
        (200, ["not", "an", "object"]),
    ],
)
def test_an_answer_that_is_not_a_usable_session_is_a_refusal_and_never_carries_the_password(
    monkeypatch: pytest.MonkeyPatch, status: int, body: object
) -> None:
    _answers(monkeypatch, (status, body))
    admin = RigAdmin("rig-operator", "cd" * 24)
    with pytest.raises(rigadmin.RigSignInRefused) as refused:
        rigadmin.sign_in("https://127.0.0.1:1", admin)
    assert admin.password not in str(refused.value)


def test_an_engine_that_does_not_answer_is_unreachable_and_not_a_refusal() -> None:
    """A real socket with nothing behind it: the hop itself, with no fake. A caller that treats
    "unreachable" as "still starting" must not be handed a refusal, and the reverse."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(rigadmin.RigUnreachable) as unreachable:
        rigadmin.sign_in(f"http://127.0.0.1:{port}", RigAdmin("rig-operator", "ef" * 24))
    assert not isinstance(unreachable.value, rigadmin.RigSignInRefused)
    assert str(port) not in str(unreachable.value), "the address must stay out of the message"


# --- the one session per process ---------------------------------------------


def test_one_sign_in_serves_every_node_until_one_refuses_it(
    fresh_state: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed_in_at: list[str] = []

    def fake_sign_in(base_url: str, admin: object = None, *, cacert: str | None = None) -> str:
        signed_in_at.append(base_url)
        return f"session-{len(signed_in_at)}"

    monkeypatch.setattr(rigadmin, "sign_in", fake_sign_in)
    # Two nodes of one store: ONE sign-in, so the engine's per-user session cap sees one session.
    assert rigadmin.session_token("https://a") == "session-1"
    assert rigadmin.session_token("https://b") == "session-1"
    assert signed_in_at == ["https://a"]
    # Node b is on another store and refused it: sign in there.
    assert rigadmin.renew_session("https://b", "session-1") == "session-2"
    # A second thread that was refused the SAME stale session gets the replacement, no third sign-in.
    assert rigadmin.renew_session("https://b", "session-1") == "session-2"
    assert signed_in_at == ["https://a", "https://b"]
    # None forces one: a route that wants a credential proved just now.
    assert rigadmin.renew_session("https://b", None) == "session-3"
    assert rigadmin.session_token("https://a") == "session-3"


# --- provisioning: the caller's side -----------------------------------------


def _fake_child(monkeypatch: pytest.MonkeyPatch, returncode: int, text: str = "") -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        seen.update(argv=argv, **kw)
        return subprocess.CompletedProcess(argv, returncode, stdout=text, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return seen


def test_provision_hands_the_password_to_the_child_in_its_environment_and_never_on_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = _fake_child(monkeypatch, 0)
    admin = RigAdmin("rig-operator", "0f" * 24)
    env = {"MEFOR_STORE_PATH": "rig.db", "PATH": "/x"}
    assert rigadmin.provision(env=env, cwd=tmp_path, db="other.db", admin=admin) is True
    assert admin.password not in " ".join(seen["argv"])
    assert seen["env"] == {
        **env,
        rigadmin.ADMIN_NAME_ENV: "rig-operator",
        rigadmin.ADMIN_PASS_ENV: admin.password,
        "PYTHONIOENCODING": "utf-8",
    }
    # The child's output is pinned to UTF-8 on both ends, so a non-ASCII refusal cannot fail to decode.
    assert (seen["encoding"], seen["errors"]) == ("utf-8", "replace")
    assert seen["cwd"] == str(tmp_path)
    # -P keeps harness/load, which holds a module named `profile`, off the child's sys.path.
    assert seen["argv"][:2] == [sys.executable, "-P"]
    assert Path(seen["argv"][2]) == Path(rigadmin.__file__).resolve()
    assert seen["argv"][3:] == ["provision", "--db", "other.db"]
    assert env == {"MEFOR_STORE_PATH": "rig.db", "PATH": "/x"}, "the caller's env was changed"


def test_a_store_that_already_had_an_administrator_is_not_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_child(monkeypatch, rigadmin.EXIT_EXISTS)
    assert rigadmin.provision(env={}, admin=RigAdmin("rig-operator", "1e" * 24)) is False


def test_any_other_refusal_raises_with_the_commands_own_words(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_child(monkeypatch, 2, "no store key is set in this shell; refusing to provision")
    with pytest.raises(rigadmin.RigAdminError, match=r"exit 2.*no store key is set"):
        rigadmin.provision(env={}, admin=RigAdmin("rig-operator", "2d" * 24))


def test_the_json_error_reader_takes_the_last_error_object() -> None:
    assert rigadmin._json_error('noise\n{"error": "first"}\n{"error": "last"}\n') == "last"
    assert rigadmin._json_error('{"username": "rig-operator"}\n') == ""
    assert rigadmin._json_error("not json") == ""


# --- provisioning: the real command, in a child -------------------------------


def _store_key() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


@pytest.mark.timeout(240)
def test_the_child_provisions_through_the_shipped_command_and_then_finds_it_done(
    tmp_path: Path,
) -> None:
    """The real ``provision-admin``, at the shipped ``enforce`` posture, against a SQLite store in
    ``tmp_path``. Only its terminal read is replaced. Two runs: the first creates the account, the
    second finds it. Neither prints the password."""
    admin = RigAdmin("rig-operator", rigadmin._new_password())
    env = _env_for_a_sqlite_store(
        MEFOR_STORE_ENCRYPTION_KEY=_store_key(),
        **{rigadmin.ADMIN_NAME_ENV: admin.username, rigadmin.ADMIN_PASS_ENV: admin.password},
    )
    db = tmp_path / "rig.db"
    argv = [sys.executable, "-P", str(Path(rigadmin.__file__).resolve()), "provision"]
    argv += ["--db", str(db)]
    first = subprocess.run(argv, env=env, cwd=tmp_path, capture_output=True, text=True)
    assert first.returncode == 0, first.stdout + first.stderr
    assert db.exists(), "the store was not created"
    second = subprocess.run(argv, env=env, cwd=tmp_path, capture_output=True, text=True)
    assert second.returncode == rigadmin.EXIT_EXISTS, second.stdout + second.stderr
    for done in (first, second):
        assert admin.password not in done.stdout + done.stderr

    # CONTROL: with no password in its environment the child refuses, and creates no store.
    bare = {k: v for k, v in env.items() if k != rigadmin.ADMIN_PASS_ENV}
    other = tmp_path / "never.db"
    refused = subprocess.run(
        [*argv[:-1], str(other)], env=bare, cwd=tmp_path, capture_output=True, text=True
    )
    assert refused.returncode == 2 and rigadmin.ADMIN_PASS_ENV in refused.stderr
    assert not other.exists()


# --- the poller's client -----------------------------------------------------


class _FakeClient:
    """The slice of ``EngineClient`` that ``adopt_rig_session`` uses."""

    def __init__(self, accepts: set[str]) -> None:
        self.accepts = accepts
        self.token: str | None = None
        self.step_up: Any = None

    def set_token(self, token: str) -> None:
        if token not in self.accepts:
            raise ApiError("session refused", status=401)
        self.token = token

    def set_step_up_handler(self, handler: Any) -> None:
        self.step_up = handler


def test_a_client_refused_the_held_session_signs_in_again_at_its_own_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    renewed: list[tuple[str, str | None]] = []
    monkeypatch.setattr(rigadmin, "session_token", lambda url, cacert=None: "held")

    def renew(url: str, stale: str | None, cacert: str | None = None) -> str:
        renewed.append((url, stale))
        return "fresh"

    monkeypatch.setattr(rigadmin, "renew_session", renew)
    client = _FakeClient(accepts={"fresh"})
    enginepoll.adopt_rig_session(client, "https://b", None)  # type: ignore[arg-type]
    assert client.token == "fresh" and renewed == [("https://b", "held")]
    # The step-up handler signs in afresh (stale=None) and reports success to the client.
    assert client.step_up() is True and renewed[-1] == ("https://b", None)


def test_an_unreachable_engine_reads_as_an_api_error_and_a_refusal_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreachable(url: str, cacert: str | None = None) -> str:
        raise rigadmin.RigUnreachable("the engine did not answer (ConnectionRefusedError)")

    monkeypatch.setattr(rigadmin, "session_token", unreachable)
    with pytest.raises(ApiError):
        enginepoll.adopt_rig_session(_FakeClient(set()), "https://a", None)  # type: ignore[arg-type]

    def refused(url: str, cacert: str | None = None) -> str:
        raise rigadmin.RigSignInRefused("the engine refused the rig Administrator's sign-in")

    monkeypatch.setattr(rigadmin, "session_token", refused)
    with pytest.raises(rigadmin.RigSignInRefused):
        enginepoll.adopt_rig_session(_FakeClient(set()), "https://a", None)  # type: ignore[arg-type]


def test_a_drive_of_another_processs_engines_refuses_to_draw_its_own_credential(
    fresh_state: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A split drive signs in to engines another process provisioned. A password drawn in the drive
    could only be wrong, and each wrong try counts against the account. So it refuses first."""
    poller = EnginePoller("https://127.0.0.1:1", rigadmin.REMOTE_RIG_SESSION, origin=0.0)
    with pytest.raises(rigadmin.RigAdminError, match="another process started"):
        poller._open_sync()
    assert rigadmin.ADMIN_PASS_ENV not in os.environ, "it drew a credential anyway"
    # CONTROL: with the credential supplied the same check passes.
    monkeypatch.setenv(rigadmin.ADMIN_PASS_ENV, "ab" * 24)
    rigadmin.require_supplied_credential()
    assert rigadmin.RIG_SESSION.supplied is False and rigadmin.REMOTE_RIG_SESSION.supplied is True


# --- the command line's own failures -----------------------------------------


def test_a_rig_that_cannot_sign_in_exits_with_its_own_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``run`` returns its child's code, and the harness command line uses 0 to 3. So "the rig never
    signed in" has a code of its own, and a workflow can fail on that and nothing else."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    engine = f"http://127.0.0.1:{port}"
    assert rigadmin.EXIT_RIG_FAILED == 4
    assert rigadmin.main(["get", "--engine", engine, "/stats"]) == rigadmin.EXIT_RIG_FAILED
    code = rigadmin.main(["run", "--engine", engine, "--", sys.executable, "-c", "pass"])
    assert code == rigadmin.EXIT_RIG_FAILED
    assert "did not answer" in capsys.readouterr().err


# --- the workflow legs carry this module's settings ---------------------------


def _serving_step(workflow: str, job: str, needle: str) -> dict[str, Any]:
    from tests._workflow_contexts import jobs_of

    steps = [s for s in jobs_of(workflow)[job]["steps"] if needle in str(s.get("run") or "")]
    assert len(steps) == 1, f"{workflow} {job}: {len(steps)} step(s) hold {needle!r}"
    step: dict[str, Any] = steps[0]
    return step


def test_each_workflow_leg_carries_the_settings_this_module_names() -> None:
    """``SERVE_ENV`` and ``NOTIFY_ENV`` are written out by hand in seven workflow steps, in three
    syntaxes. This holds each copy to the module, so the port or the address cannot drift in one.

    An enforcing leg carries both. A leg at ``warn`` carries ``SERVE_ENV``: the notification gate
    only warns there."""
    pytest.importorskip("yaml")
    enforcing = {**rigadmin.SERVE_ENV, **rigadmin.NOTIFY_ENV}
    assert len(enforcing) == 5, "CONTROL FAILED: the module's settings changed shape"
    legs: list[tuple[str, str, dict[str, str]]] = [
        ("ci.yml", "load-test", enforcing),
        ("benchmark.yml", "baseline-sqlite", enforcing),
        ("ci.yml", "load-test-sqlserver", dict(rigadmin.SERVE_ENV)),
        ("benchmark.yml", "baseline-postgres", dict(rigadmin.SERVE_ENV)),
        ("benchmark.yml", "baseline-sqlserver", dict(rigadmin.SERVE_ENV)),
    ]
    for workflow, job, wanted in legs:
        env = _serving_step(workflow, job, "messagefoundry serve")["env"]
        got = {name: str(env.get(name)) for name in wanted}
        assert got == wanted, f"{workflow} {job}: {got}"
    # The container smoke passes them to `docker run`, the Windows smoke to NSSM.
    docker = str(_serving_step("ci.yml", "docker-smoke", "serve --config")["run"])
    service = str(_serving_step("ci.yml", "windows-service-smoke", "AppEnvironmentExtra")["run"])
    for name, value in enforcing.items():
        assert f"-e {name}={value} " in docker, f"docker-smoke: {name}"
        assert f'"{name}={value}" `' in service, f"windows-service-smoke: {name}"


# --- one real engine ---------------------------------------------------------

_CONFIG = """\
from messagefoundry import MLLP, inbound, router

inbound("IB_RIG_PROOF", MLLP(port={port}), router="rig_proof_router")


@router("rig_proof_router")
def route(msg):
    return []
"""


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _cli(*argv: str) -> tuple[int, str]:
    """Run the helper's command line in this process; returns ``(exit code, stdout)``."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = rigadmin.main(list(argv))
    return code, out.getvalue()


@pytest.mark.timeout(300)
async def test_a_rig_node_serves_with_sign_in_on_and_the_rig_reads_it_signed_in(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "IB_RIG_PROOF.py").write_text(_CONFIG.format(port=_free_port()), encoding="utf-8")
    base_env = _env_for_a_sqlite_store(MEFOR_STORE_PATH=str(tmp_path / "rig.db"))
    node = EngineNode("rig-proof", _free_port(), env=base_env, config_dir=str(config), cwd=tmp_path)
    assert rigadmin.ADMIN_PASS_ENV not in node._env
    assert node._env["MEFOR_SECURITY_REQUIRE_MFA"] == "false"

    await node.start()
    try:
        async with httpx.AsyncClient(timeout=4.0, verify=harness_ssl_context()) as client:
            deadline = time.monotonic() + 120.0
            while not await node.healthy(client):
                assert node.alive, f"the node exited during startup:\n{node.log_tail()}"
                assert time.monotonic() < deadline, f"never healthy:\n{node.log_tail()}"
                await asyncio.sleep(0.25)

            # THE POINT: no session, no answer. A node still serving with sign-in off answers 200.
            bare = await client.get(f"{node.url}/stats")
            assert bare.status_code == 401, bare.status_code
            # ...and the rig's own reads are answered.
            assert await node.stats(client) is not None
            assert await node.role(client) is not None

            # A node that refuses the held session is signed in to again, not read as down.
            good = rigadmin.session_token(node.url, cacert=node.cacert)
            rigadmin._held.token = "not-a-session"
            assert await node.stats(client) is not None
            assert rigadmin._held.token not in (good, "not-a-session")

        poller = EnginePoller(node.url, RIG_SESSION, origin=time.perf_counter())
        await poller.open()
        try:
            assert await poller.sample_once() is not None
            # A caller about to TIME a sensitive request proves the credential first: a new
            # session, taken by the client, that the engine answers.
            before = rigadmin._held.token
            await poller.prove_sign_in()
            assert rigadmin._held.token != before
            assert await poller.sample_once() is not None
        finally:
            await poller.close()
        # CONTROL: the same poller with no session reads nothing.
        unsigned = EnginePoller(node.url, None, origin=time.perf_counter())
        await unsigned.open()
        try:
            assert await unsigned.sample_once() is None
        finally:
            await unsigned.close()

        # The store has its Administrator now, so provisioning again finds it and changes nothing.
        await node.provision()

        # The command line a workflow step uses, against the same node.
        url, pin = node.url, node.cacert
        code, out = await asyncio.to_thread(_cli, "get", "--engine", url, "--cacert", pin, "/stats")
        assert code == 0 and "in_pipeline" in json.loads(out), out
        code, out = await asyncio.to_thread(
            _cli, "get", "--engine", url, "--cacert", pin, "--field", "in_pipeline", "/stats"
        )
        assert (code, out.strip()) == (0, "0")
        # `run` hands the session to its child as --token, and not the password it came from.
        child = (
            "import os, sys; "
            f"sys.exit(9 if {rigadmin.ADMIN_PASS_ENV!r} in os.environ else "
            "0 if sys.argv[-2] == '--token' and len(sys.argv[-1]) > 20 else 7)"
        )
        code, _ = await asyncio.to_thread(
            _cli, "run", "--engine", url, "--cacert", pin, "--", sys.executable, "-c", child
        )
        assert code == 0, code

        # A credential the store does not hold is refused, in words that carry no password.
        wrong = RigAdmin(rigadmin.rig_admin().username, "0" * 48)
        with pytest.raises(rigadmin.RigSignInRefused, match="HTTP 401"):
            await asyncio.to_thread(rigadmin.sign_in, url, wrong, cacert=pin)
    finally:
        await node.stop()
