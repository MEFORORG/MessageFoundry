"""REMOTEFILE transport connector (SFTP / FTP / FTPS): upload, poll, error mapping, security, egress.

The remote client is faked (``_make_client`` is monkeypatched, or the ``_SftpClient`` host-key policy
is exercised against a fake paramiko module), so nothing hits the network or SSH — exactly like the
DATABASE driver fake and the REST opener fake. paramiko need not be installed.
"""

from __future__ import annotations

import asyncio
import posixpath
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Ftp, Sftp, WiringError
from messagefoundry.pipeline.wiring_runner import check_egress_allowed, check_source_allowed
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports import remotefile
from messagefoundry.transports.remotefile import (
    RemoteFileDestination,
    RemoteFileSource,
    _RemoteClient,
    _RemoteError,
    _SftpClient,
)


# --- a fake remote client ----------------------------------------------------


class _FakeClient(_RemoteClient):
    """In-memory remote-file client. Records the operation order so a test can assert that a store
    happened before its rename (atomic publish)."""

    def __init__(
        self,
        files: dict[str, bytes] | None = None,
        *,
        sizes: dict[str, int] | None = None,
        store_exc: _RemoteError | None = None,
        rename_exc: _RemoteError | None = None,
        retrieve_exc: _RemoteError | None = None,
    ) -> None:
        self.files: dict[str, bytes] = dict(files or {})
        self._sizes = sizes or {}
        self.ops: list[tuple[str, str]] = []  # (op, path)
        self.dirs: list[str] = []
        self._store_exc = store_exc
        self._rename_exc = rename_exc
        self._retrieve_exc = retrieve_exc

    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        for path, data in self.files.items():
            if posixpath.dirname(path) == remote_dir:
                name = posixpath.basename(path)
                out.append((name, self._sizes.get(path, len(data))))
        return out

    def retrieve(self, path: str) -> bytes:
        self.ops.append(("retrieve", path))
        if self._retrieve_exc is not None:
            raise self._retrieve_exc
        return self.files[path]

    def store(self, path: str, data: bytes) -> None:
        self.ops.append(("store", path))
        if self._store_exc is not None:
            raise self._store_exc
        self.files[path] = data

    def rename(self, src: str, dst: str) -> None:
        self.ops.append(("rename", f"{src}->{dst}"))
        if self._rename_exc is not None:
            raise self._rename_exc
        self.files[dst] = self.files.pop(src)

    def remove(self, path: str) -> None:
        self.ops.append(("remove", path))
        self.files.pop(path, None)

    def ensure_dir(self, remote_dir: str) -> None:
        self.dirs.append(remote_dir)


def _install_client(monkeypatch: pytest.MonkeyPatch, client: _FakeClient) -> None:
    monkeypatch.setattr(remotefile, "_make_client", lambda settings: client)


def _dest(
    monkeypatch: pytest.MonkeyPatch, client: _FakeClient, **over: Any
) -> RemoteFileDestination:
    _install_client(monkeypatch, client)
    base: dict[str, Any] = dict(host="sftp.example.com", remote_dir="/in")
    base.update(over)
    d = build_destination(
        Destination(name="OB_REMOTE", type=ConnectorType.REMOTEFILE, settings=Sftp(**base).settings)
    )
    assert isinstance(d, RemoteFileDestination)
    return d


def _src(monkeypatch: pytest.MonkeyPatch, client: _FakeClient, **over: Any) -> RemoteFileSource:
    _install_client(monkeypatch, client)
    base: dict[str, Any] = dict(host="sftp.example.com", remote_dir="/in")
    base.update(over)
    s = build_source(Source(type=ConnectorType.REMOTEFILE, settings=Sftp(**base).settings))
    assert isinstance(s, RemoteFileSource)
    return s


class _RecordingHandler:
    def __init__(self, exc: Exception | None = None) -> None:
        self.bodies: list[bytes] = []
        self._exc = exc

    async def __call__(self, raw: bytes) -> str | None:
        self.bodies.append(raw)
        if self._exc is not None:
            raise self._exc
        return None


# === destination =============================================================


async def test_destination_uploads_store_then_rename(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    await dest.send("MSH|^~\\&|A|B")
    # The final file exists with the payload, and store happened BEFORE the rename (atomic publish).
    assert client.files["/in/msg.hl7"] == b"MSH|^~\\&|A|B"
    op_names = [op for op, _ in client.ops]
    assert op_names.index("store") < op_names.index("rename")
    # The stored path was a .part temp, renamed to the final name.
    store_path = next(p for op, p in client.ops if op == "store")
    assert store_path.endswith(".part") and "/in/" in store_path


async def test_destination_filename_templating(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    dest = _dest(monkeypatch, client, filename="{MSH-10}.hl7")
    await dest.send("MSH|^~\\&|A|B|C|D|20260613||ADT^A01|CTRL123|P|2.5")
    assert "/in/CTRL123.hl7" in client.files


async def test_destination_no_silent_clobber(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/msg.hl7": b"existing"})
    dest = _dest(monkeypatch, client, filename="msg.hl7", overwrite=False)
    await dest.send("new")
    assert client.files["/in/msg.hl7"] == b"existing"  # original untouched
    assert client.files["/in/msg-1.hl7"] == b"new"  # uniquified, not clobbered


async def test_destination_overwrite_replaces(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/msg.hl7": b"existing"})
    dest = _dest(monkeypatch, client, filename="msg.hl7", overwrite=True)
    await dest.send("new")
    assert client.files["/in/msg.hl7"] == b"new"


async def test_destination_transient_error_is_delivery_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(store_exc=_RemoteError("connection reset", permanent=False))
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(DeliveryError) as ei:
        await dest.send("x")
    assert not isinstance(ei.value, NegativeAckError)  # transient → retry


async def test_destination_permanent_error_is_negative_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(store_exc=_RemoteError("no such directory", permanent=True))
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("x")
    assert ei.value.permanent is True


async def test_destination_cleans_temp_on_failed_rename(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(rename_exc=_RemoteError("rename failed", permanent=False))
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(DeliveryError):
        await dest.send("x")
    assert any(op == "remove" for op, _ in client.ops)  # temp cleaned up
    assert not client.files  # nothing left behind


# === source ==================================================================


async def test_source_polls_retrieves_and_moves_to_processed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(files={"/in/a.hl7": b"AAA", "/in/b.hl7": b"BBB"})
    src = _src(monkeypatch, client)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"AAA", b"BBB"]  # both delivered, in sorted order
    # Moved to the processed dir (only after the handler returned), not left in /in.
    assert "/in/.processed/a.hl7" in client.files
    assert "/in/.processed/b.hl7" in client.files
    assert "/in/a.hl7" not in client.files


async def test_source_pattern_filters_non_matching(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/a.hl7": b"AAA", "/in/skip.txt": b"nope"})
    src = _src(monkeypatch, client, pattern="*.hl7")
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"AAA"]  # the .txt is ignored


async def test_source_after_read_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/a.hl7": b"AAA"})
    src = _src(monkeypatch, client, after_read="delete")
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"AAA"]
    assert "/in/a.hl7" not in client.files  # deleted, not moved
    assert not any(p.startswith("/in/.processed") for p in client.files)


async def test_source_handler_failure_leaves_file(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/a.hl7": b"AAA"})
    src = _src(monkeypatch, client)
    h = _RecordingHandler(exc=RuntimeError("store write failed"))
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"AAA"]  # handler attempted
    assert "/in/a.hl7" in client.files  # left in place → re-emits next poll (at-least-once)
    assert "/in/.processed/a.hl7" not in client.files


async def test_source_oversize_moves_to_error_without_retrieving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(files={"/in/big.hl7": b"x" * 10}, sizes={"/in/big.hl7": 10})
    src = _src(monkeypatch, client, max_file_bytes=5)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == []  # never delivered
    assert not any(op == "retrieve" for op, _ in client.ops)  # never retrieved
    assert "/in/.error/big.hl7" in client.files  # quarantined


async def test_source_retrieve_failure_leaves_file(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(
        files={"/in/a.hl7": b"AAA"}, retrieve_exc=_RemoteError("locked", permanent=False)
    )
    src = _src(monkeypatch, client)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == []  # nothing delivered
    assert "/in/a.hl7" in client.files  # left in place to retry


async def test_source_run_loop_survives_a_poll_error(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    src = _src(monkeypatch, client)
    calls: list[int] = []

    async def boom() -> None:
        calls.append(1)
        src._stop.set()
        raise RuntimeError("poll blew up")

    src._poll_once = boom  # type: ignore[method-assign]
    src._poll_seconds = 0.0
    await src._run()  # must NOT propagate — a bad poll never kills the poller
    assert calls == [1]


async def test_source_start_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    src = _src(monkeypatch, client)

    async def handler(raw: bytes) -> str | None:
        return None

    await src.start(handler)
    await src.stop()
    assert src._task is None


# --- source: leader-gating (Track B Step 4b) --------------------------------


def test_source_declares_polls_shared_resource() -> None:
    # A remote directory is a shared external resource — the runner reads this flag to leader-gate it.
    assert RemoteFileSource.polls_shared_resource is True


async def test_source_run_loop_skips_poll_when_gate_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A follower (leader_gate() -> False) must NOT list/download/move the remote dir: the loop ticks
    # but _poll_once is never reached, so the shared dir is untouched (no duplicate intake).
    client = _FakeClient(files={"/in/a.hl7": b"AAA"})
    src = _src(monkeypatch, client)
    src._leader_gate = lambda: False
    src._poll_seconds = 0.0

    async def spy() -> None:
        raise AssertionError("a follower must not poll the remote dir")

    src._poll_once = spy  # type: ignore[method-assign]
    runner = asyncio.create_task(src._run())
    await asyncio.sleep(0.02)
    src._stop.set()
    await runner
    assert client.ops == []  # never listed/retrieved/moved
    assert "/in/a.hl7" in client.files  # left in place


async def test_source_follower_real_poll_lists_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    # Higher-fidelity follower test (matches the FILE source's end-to-end check): let the REAL
    # _poll_once run under a False gate. The gate must short-circuit before list_dir/retrieve/move —
    # so the handler gets no body, the client records no retrieve/store/rename/remove ops, and the
    # remote file is left in place. A regression where _may_poll returns True would surface here.
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A|B"})
    src = _src(monkeypatch, client)
    h = _RecordingHandler()
    src._handler = h
    src._leader_gate = lambda: False
    src._poll_seconds = 0.0
    runner = asyncio.create_task(src._run())
    await asyncio.sleep(0.02)  # several ticks — each gated out before any remote op
    src._stop.set()
    await runner
    assert h.bodies == []  # never handed a body
    assert client.ops == []  # no retrieve / store / rename / remove
    assert "/in/a.hl7" in client.files  # left in place (not moved to .processed)


async def test_source_run_loop_polls_when_gate_true(monkeypatch: pytest.MonkeyPatch) -> None:
    # A leader (leader_gate() -> True) polls exactly as the un-gated default does.
    client = _FakeClient()
    src = _src(monkeypatch, client)
    src._leader_gate = lambda: True
    src._poll_seconds = 0.0
    calls: list[int] = []

    async def spy() -> None:
        calls.append(1)
        src._stop.set()

    src._poll_once = spy  # type: ignore[method-assign]
    await src._run()
    assert calls == [1]  # the gate was True → poll_once ran


def test_source_may_poll_logs_transition_once_then_resumes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    src = _src(monkeypatch, client)
    leader = {"on": False}
    src._leader_gate = lambda: leader["on"]
    assert src._may_poll() is False and src._skipping is True
    assert src._may_poll() is False and src._skipping is True  # no re-flip while still a follower
    leader["on"] = True
    assert src._may_poll() is True and src._skipping is False  # became leader → resume


# === security: cleartext-ftp credential guard ================================


def _ftp_dest(**over: Any) -> Destination:
    base: dict[str, Any] = dict(host="ftp.example.com", remote_dir="/in")
    base.update(over)
    return Destination(name="OB", type=ConnectorType.REMOTEFILE, settings=Ftp(**base).settings)


def test_plain_ftp_with_credentials_refused_without_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="CLEARTEXT"):
        build_destination(_ftp_dest(username="u", password="p"))


def test_plain_ftp_with_credentials_allowed_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    dest = build_destination(_ftp_dest(username="u", password="p"))
    assert isinstance(dest, RemoteFileDestination)  # builds (warns), not refused


def test_plain_ftp_without_credentials_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest = build_destination(_ftp_dest())  # anonymous — nothing to leak
    assert isinstance(dest, RemoteFileDestination)


def test_ftps_with_credentials_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest = build_destination(_ftp_dest(tls=True, username="u", password="p"))  # TLS → fine
    assert isinstance(dest, RemoteFileDestination)


def test_sftp_with_credentials_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.REMOTEFILE,
            settings=Sftp(host="h", remote_dir="/in", username="u", password="p").settings,
        )
    )
    assert isinstance(dest, RemoteFileDestination)  # SSH → credentials fine


# === security: SFTP host-key verification ====================================


class _FakePolicyError(Exception):
    pass


class _FakeSSHClient:
    """Minimal paramiko.SSHClient stand-in recording the missing-host-key policy chosen."""

    last_policy: Any = None

    def __init__(self) -> None:
        self.policy: Any = None

    def load_system_host_keys(self) -> None:
        pass

    def load_host_keys(self, path: str) -> None:
        pass

    def set_missing_host_key_policy(self, policy: Any) -> None:
        self.policy = policy
        type(self).last_policy = policy

    def connect(self, **kw: Any) -> None:
        if isinstance(self.policy, _RejectPolicy):
            # An unknown host key under RejectPolicy raises SSHException, as paramiko does.
            raise _SSHException("Server host key not found in known_hosts")

    def open_sftp(self) -> Any:
        raise AssertionError("connect should have raised before open_sftp under RejectPolicy")

    def close(self) -> None:
        pass


class _RejectPolicy:
    pass


class _AutoAddPolicy:
    pass


class _SSHException(Exception):
    pass


class _AuthException(Exception):
    pass


class _FakeParamiko:
    SSHClient = _FakeSSHClient
    RejectPolicy = _RejectPolicy
    AutoAddPolicy = _AutoAddPolicy
    SSHException = _SSHException
    AuthenticationException = _AuthException

    class RSAKey:
        @staticmethod
        def from_private_key(*a: Any, **k: Any) -> Any:
            return object()


def test_sftp_unknown_host_key_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    monkeypatch.setattr(remotefile, "_import_paramiko", lambda: _FakeParamiko)
    client = _SftpClient({"host": "h", "port": 22, "remote_dir": "/in"})
    assert client._accept_unknown is False
    with pytest.raises(_RemoteError) as ei:
        client.list_dir("/in")
    assert ei.value.permanent is True  # a rejected host key is a permanent security stop


def test_sftp_unknown_host_key_accepted_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    monkeypatch.setattr(remotefile, "_import_paramiko", lambda: _FakeParamiko)
    client = _SftpClient({"host": "h", "port": 22, "remote_dir": "/in"})
    assert client._accept_unknown is True  # AutoAddPolicy will be selected (logged loudly)


# === egress allowlist ([egress].allowed_remote) ==============================


def _remote_dest(host: str, port: int = 22) -> Destination:
    return Destination(
        name="OB",
        type=ConnectorType.REMOTEFILE,
        settings=Sftp(host=host, port=port, remote_dir="/in").settings,
    )


def test_egress_blocks_unlisted_host() -> None:
    with pytest.raises(WiringError):
        check_egress_allowed(
            _remote_dest("other.example.com"), EgressSettings(allowed_remote=["sftp.example.com"])
        )


def test_egress_permits_listed_host() -> None:
    check_egress_allowed(
        _remote_dest("sftp.example.com"), EgressSettings(allowed_remote=["sftp.example.com"])
    )


def test_egress_host_port_match() -> None:
    egress = EgressSettings(allowed_remote=["sftp.example.com:22"])
    check_egress_allowed(_remote_dest("sftp.example.com", 22), egress)  # ok
    with pytest.raises(WiringError):
        check_egress_allowed(_remote_dest("sftp.example.com", 23), egress)  # wrong port


def test_egress_unrestricted_when_empty() -> None:
    check_egress_allowed(_remote_dest("anywhere.example"), EgressSettings())


def _remote_src_cfg(host: str, port: int = 22) -> Source:
    return Source(
        type=ConnectorType.REMOTEFILE,
        settings=Sftp(host=host, port=port, remote_dir="/in").settings,
    )


def test_source_connect_blocks_unlisted_host() -> None:
    with pytest.raises(WiringError):
        check_source_allowed(
            _remote_src_cfg("other.example.com"),
            "IB_REMOTE",
            EgressSettings(allowed_remote=["sftp.example.com"]),
        )


def test_source_connect_permits_listed_host() -> None:
    check_source_allowed(
        _remote_src_cfg("sftp.example.com"),
        "IB_REMOTE",
        EgressSettings(allowed_remote=["sftp.example.com"]),
    )


def test_source_connect_unrestricted_when_empty() -> None:
    check_source_allowed(_remote_src_cfg("anywhere.example"), "IB_REMOTE", EgressSettings())


# === factory smoke ===========================================================


def test_sftp_factory_protocol_and_settings() -> None:
    spec = Sftp(host="h", remote_dir="/in", username="u")
    assert spec.type is ConnectorType.REMOTEFILE
    assert spec.settings["protocol"] == "sftp"
    assert spec.settings["port"] == 22
    assert spec.settings["host"] == "h"


def test_ftp_factory_plain_vs_tls() -> None:
    assert Ftp(host="h", remote_dir="/in").settings["protocol"] == "ftp"
    assert Ftp(host="h", remote_dir="/in", tls=True).settings["protocol"] == "ftps"
    assert Ftp(host="h", remote_dir="/in").settings["port"] == 21


@pytest.mark.parametrize("missing", ["host", "remote_dir"])
def test_requires_core_settings(missing: str) -> None:
    base: dict[str, Any] = dict(host="h", remote_dir="/in")
    base[missing] = ""
    with pytest.raises(ValueError):
        build_destination(
            Destination(name="OB", type=ConnectorType.REMOTEFILE, settings=Sftp(**base).settings)
        )
