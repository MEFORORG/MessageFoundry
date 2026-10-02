# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness REMOTEFILE (SFTP) family: the in-process share, its driver and sink, and the two
scenarios run against the REAL ``harness/config/remotefile`` graph (vault BACKLOG #2679).

The share is a real paramiko SSH server on loopback, so the engine's own SFTP client dials it, verifies
its pinned host key and authenticates. Each end-to-end test serves the subdirectory graph in-process
(``tests/_harness_engine.py``) with a throwaway password in the environment, and keeps
``MEFOR_ALLOW_INSECURE_TLS`` unset so host-key verification is on throughout.

Negative controls pair every pass: a wrong password and an unpinned host key are refused by the driver,
the ENGINE refuses an unpinned host key until the right one is pinned, a scenario expecting the wrong
disposition fails, and a changed or misplaced written file fails the byte check. A missing ``[sftp]``
extra is a SETUP error, never a pass.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from harness import drivers, sinks
from harness.__main__ import main
from harness.drivers.remotefile import RemoteFileDriver
from harness.endpoints import Endpoints
from harness.scenarios import SCENARIOS, run_scenario
from harness.scenarios.remotefile import RemoteFileScenario, verify_written
from harness.sinks import Record
from harness.sinks._sftp_server import (
    INBOX,
    OUTBOX,
    PASSWORD_ENV,
    USERNAME,
    RemoteFileSetupError,
    SftpShare,
    known_hosts_name,
)
from harness.sinks.remotefile import RemoteFileSink
from messagefoundry.apiclient import EngineClient
from tests._harness_engine import (
    HARNESS_CONFIG,
    ephemeral_overrides,
    free_port,
    serve_harness_config,
)

REMOTEFILE_GRAPH = HARNESS_CONFIG / "remotefile"
_SCENARIOS = sorted(n for n, s in SCENARIOS.items() if s.graph == "remotefile")


def _paramiko() -> Any:
    return pytest.importorskip(
        "paramiko",
        reason="the [sftp] extra is not installed, so the harness SFTP share cannot run here",
    )


@pytest.fixture
def password(monkeypatch: pytest.MonkeyPatch) -> str:
    """A throwaway password for the share and the graph, and host-key verification left ON."""
    value = uuid.uuid4().hex
    monkeypatch.setenv(PASSWORD_ENV, value)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    return value


@pytest.fixture
def served(tmp_path: Path, password: str) -> Iterator[tuple[str, Endpoints]]:
    """The real harness/config/remotefile graph, served on ephemeral endpoints. No share is up yet:
    the inbound starts by polling an unreachable server, which is the case it must survive."""
    _paramiko()
    with serve_harness_config(
        tmp_path, ephemeral_overrides(tmp_path), config_dir=REMOTEFILE_GRAPH
    ) as running:
        yield running


def _hl7(control_id: str) -> bytes:
    raw = "MSH|^~\\&|A|B|C|D|20260101000000||ADT^A04|" + control_id + "|P|2.5.1\rPID|1||X\r"
    return raw.encode()


def _other_key(paramiko: Any) -> Any:
    return paramiko.ECDSAKey.generate()


def _client(paramiko: Any, share: SftpShare, password: str) -> Any:
    """A stock paramiko SSH client on the share, verifying its pinned key."""
    ssh = paramiko.SSHClient()
    ssh.load_host_keys(str(share.known_hosts))
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    ssh.connect(
        "127.0.0.1",
        port=share.port,
        username=USERNAME,
        password=password,
        timeout=10,
        allow_agent=False,
        look_for_keys=False,
    )
    return ssh


# --- registration and coverage -----------------------------------------------------------------


def test_both_scenarios_are_registered_on_the_remotefile_graph() -> None:
    assert _SCENARIOS == ["remotefile_poll_in", "remotefile_write_out"]
    assert SCENARIOS["remotefile_poll_in"].covers == {("remotefile", "inbound")}
    assert SCENARIOS["remotefile_write_out"].covers == {
        ("remotefile", "inbound"),
        ("remotefile", "outbound"),
    }
    assert "remotefile" in drivers.registry() and "remotefile" in sinks.registry()


def test_coverage_reports_the_remotefile_rows(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--coverage"]) == 0
    lines = capsys.readouterr().out.splitlines()
    rows = {tuple(ln.split()[:2]): ln.split(None, 2)[2] for ln in lines if len(ln.split()) > 2}
    assert rows[("inbound", "remotefile")] == "remotefile_poll_in, remotefile_write_out"
    assert rows[("outbound", "remotefile")] == "remotefile_write_out"


def test_the_graph_holds_no_credential_and_keeps_verification_on() -> None:
    from messagefoundry.config.wiring import _UNSET, EnvRef, load_config

    registry = load_config(str(REMOTEFILE_GRAPH))
    specs = [registry.inbound["IB_Harness_RemoteFile_Sftp"].spec]
    specs.append(registry.outbound["OB_Harness_RemoteFile_Sftp"].spec)
    for spec in specs:
        secret = spec.settings["password"]
        assert isinstance(secret, EnvRef) and secret.key == "remotefile_harness_password"
        assert secret.default is _UNSET  # no default: the graph refuses to load without it
        assert isinstance(spec.settings["known_hosts"], EnvRef)
        assert spec.settings["private_key"] is None


def test_a_remotefile_scenario_refuses_a_foreign_sink() -> None:
    with pytest.raises(ValueError, match="IS the share"):
        RemoteFileScenario("x", "", "ADT", "A04", sink="file", sink_endpoint="remotefile_sftp")


# --- the share, the driver and the sink, without an engine ------------------------------------------


def test_the_driver_uploads_into_the_share_and_the_sink_records_the_outbox(
    tmp_path: Path, password: str
) -> None:
    paramiko = _paramiko()
    known_hosts = tmp_path / "kh" / "known_hosts"
    with RemoteFileSink(0, known_hosts=known_hosts) as sink:
        share = sink.share
        assert share is not None and share.root is not None
        root = share.root
        assert share.host == sinks.LOOPBACK
        keys = paramiko.HostKeys(str(known_hosts))
        assert keys.lookup(known_hosts_name("127.0.0.1", share.port)) is not None

        driver = RemoteFileDriver("127.0.0.1", share.port, known_hosts=known_hosts)
        out = driver.inject([_hl7("UP1"), _hl7("UP2")])
        assert [o.error for o in out] == ["", ""]
        inbox = share.local(INBOX)
        assert sorted(p.read_bytes() for p in inbox.iterdir()) == sorted([_hl7("UP1"), _hl7("UP2")])
        assert all(p.suffix == ".hl7" for p in inbox.iterdir())  # no .part temp left behind

        # What the engine's outbound does: a hidden temp, then a rename onto the final name.
        ssh = _client(paramiko, share, password)
        try:
            sftp = ssh.open_sftp()
            with sftp.open(f"{OUTBOX}/.OUT1.hl7.abc.part", "wb") as fh:
                fh.write(_hl7("OUT1"))
            assert sink.records() == []  # the temp is not a delivery
            sftp.rename(f"{OUTBOX}/.OUT1.hl7.abc.part", f"{OUTBOX}/OUT1.hl7")
            sftp.close()
        finally:
            ssh.close()
        records = sink.wait_for(lambda rs: bool(rs), 5.0)
    assert [r.payload for r in records] == [_hl7("OUT1")]
    assert records[0].meta["remote_path"] == "/outbox/OUT1.hl7"
    assert records[0].meta["inside"] == "true"
    assert sink.records() == records  # still readable after the share deleted its directory
    assert not root.exists()


def test_the_driver_is_refused_a_wrong_password_and_an_unpinned_key(
    tmp_path: Path, password: str
) -> None:
    """Negative controls for the round trip above, each against the same live share, with the
    correct driver as the control that the share itself still answers."""
    paramiko = _paramiko()
    known_hosts = tmp_path / "known_hosts"
    stranger = tmp_path / "stranger_known_hosts"
    nobody = tmp_path / "empty_known_hosts"
    nobody.write_text("", encoding="ascii")
    with RemoteFileSink(0, known_hosts=known_hosts) as sink:
        assert sink.share is not None
        port = sink.share.port
        wrong = RemoteFileDriver("127.0.0.1", port, known_hosts=known_hosts, password="not-it")
        (refused,) = wrong.inject([_hl7("W1")])
        assert "Authentication failed" in refused.error

        other = paramiko.HostKeys()
        key = _other_key(paramiko)
        other.add(known_hosts_name("127.0.0.1", port), key.get_name(), key)
        other.save(str(stranger))
        (mismatch,) = RemoteFileDriver("127.0.0.1", port, known_hosts=stranger).inject([_hl7("W2")])
        assert "does not match" in mismatch.error  # a key other than the pinned one
        (unknown,) = RemoteFileDriver("127.0.0.1", port, known_hosts=nobody).inject([_hl7("W5")])
        assert "not found in known_hosts" in unknown.error  # an unknown host is never added

        (ok,) = RemoteFileDriver("127.0.0.1", port, known_hosts=known_hosts).inject([_hl7("W3")])
        assert ok.error == ""
        assert [f.read_bytes() for f in sink.share.local(INBOX).iterdir()] == [_hl7("W3")]
    (gone,) = RemoteFileDriver("127.0.0.1", port, known_hosts=known_hosts).inject([_hl7("W4")])
    assert "unable to connect" in gone.error.lower()  # the share stopped: reported, not raised


def test_the_share_confines_every_path_and_refuses_to_replace_on_rename(
    tmp_path: Path, password: str
) -> None:
    paramiko = _paramiko()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.hl7").write_bytes(b"not for the share")
    with RemoteFileSink(0, known_hosts=tmp_path / "known_hosts") as sink:
        share = sink.share
        assert share is not None and share.root is not None
        root = share.root
        ssh = _client(paramiko, share, password)
        try:
            sftp = ssh.open_sftp()
            # `..` cannot climb out: it lands at the top of the served directory.
            with sftp.open("/../../escape.hl7", "wb") as fh:
                fh.write(b"x")
            assert (root / "escape.hl7").read_bytes() == b"x"
            assert not (root.parent / "escape.hl7").exists()
            # A symlink that resolves outside is refused, and a client cannot make one.
            if hasattr(os, "symlink") and sys.platform != "win32":
                os.symlink(outside, root / "link")
                with pytest.raises(PermissionError):
                    sftp.listdir("/link")
                with pytest.raises(OSError):
                    sftp.open("/link/secret.hl7", "rb")
            with pytest.raises(OSError):
                sftp.symlink("/", "/inbox/up")
            # RENAME never replaces (the engine's outbound relies on that); posix-rename does.
            for name, body in (("a", b"A"), ("b", b"B")):
                with sftp.open(f"/inbox/{name}", "wb") as fh:
                    fh.write(body)
            with pytest.raises(OSError):
                sftp.rename("/inbox/a", "/inbox/b")
            assert (root / "inbox" / "b").read_bytes() == b"B"
            sftp.posix_rename("/inbox/a", "/inbox/b")
            assert (root / "inbox" / "b").read_bytes() == b"A"
            sftp.close()
        finally:
            ssh.close()


def test_a_sink_binds_loopback_and_pins_the_host_the_engine_dials(
    tmp_path: Path, password: str
) -> None:
    _paramiko()
    known_hosts = tmp_path / "known_hosts"
    port = free_port()
    others = [
        "# an existing file is edited, not replaced",
        "|1|c2FsdA==|aGFzaA== ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY=",
        f"[localhost]:{port + 1} ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY=",
        f"[localhost]:{port} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== (stale, must go)",
    ]
    known_hosts.write_text("".join(f"{line}\n" for line in others), encoding="ascii")
    eps = Endpoints(
        {
            "host": "localhost",
            "remotefile_sftp": str(port),
            "remotefile_known_hosts": str(known_hosts),
        },
        environ={},
    )
    with sinks.build("remotefile", eps, "remotefile_sftp") as sink:
        assert isinstance(sink, RemoteFileSink) and sink.share is not None
        assert sink.share.host == sinks.LOOPBACK
        sink.share.pin_host_key()  # a second pin replaces the first, never piles up
        lines = known_hosts.read_text(encoding="ascii").splitlines()
        assert lines[:3] == others[:3]  # comments, markers and other hosts kept byte for byte
        (mine,) = lines[3:]
        assert mine.startswith(f"[localhost]:{port} ecdsa-sha2-nistp256 ")
        assert mine.split()[2] == sink.share.host_key.get_base64()


def test_a_pin_keeps_the_files_line_endings_and_permissions(tmp_path: Path, password: str) -> None:
    _paramiko()
    real = tmp_path / "real_known_hosts"
    real.write_bytes(b"# windows-edited\r\nother.example ssh-ed25519 AAAA\r\n")
    if sys.platform != "win32":
        real.chmod(0o644)
        link = tmp_path / "known_hosts"
        link.symlink_to(real)
    else:
        link = real
    with RemoteFileSink(0, known_hosts=link) as sink:
        assert sink.share is not None
        pinned = real.read_bytes()
    assert pinned.startswith(b"# windows-edited\r\nother.example ssh-ed25519 AAAA\r\n")
    assert pinned.endswith(b"\r\n") and pinned.count(b"\r\n") == 3
    assert f"[127.0.0.1]:{sink.port} ecdsa-sha2-nistp256 ".encode() in pinned
    if sys.platform != "win32":
        assert link.is_symlink()  # the target got the pin; the link was not replaced
        assert real.stat().st_mode & 0o777 == 0o644


# --- a missing extra or password is a reported SETUP error, never a pass ------------------------------


def test_a_missing_extra_is_a_setup_error(
    tmp_path: Path,
    password: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setitem(sys.modules, "paramiko", None)  # what an install without [sftp] looks like
    with pytest.raises(RemoteFileSetupError, match=r"\[sftp\] extra"):
        SftpShare(0, known_hosts=tmp_path / "known_hosts")
    (out,) = RemoteFileDriver("127.0.0.1", 1, known_hosts=tmp_path / "kh").inject([b"x"])
    assert "[sftp] extra" in out.error
    rc = main(
        [
            "--scenario",
            "remotefile_poll_in",
            "--engine",
            "http://127.0.0.1:9",
            "--endpoint",
            f"remotefile_known_hosts={tmp_path / 'known_hosts'}",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert err.startswith("SETUP remotefile_poll_in:") and "[sftp] extra" in err


def test_a_missing_password_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _paramiko()
    monkeypatch.delenv(PASSWORD_ENV, raising=False)
    with pytest.raises(RemoteFileSetupError, match=PASSWORD_ENV):
        SftpShare(0, known_hosts=tmp_path / "known_hosts")


# --- the scenarios against the real graph --------------------------------------------------------------


@pytest.mark.parametrize("name", _SCENARIOS)
def test_every_remotefile_scenario_passes_against_its_graph(
    served: tuple[str, Endpoints], name: str
) -> None:
    api_url, eps = served
    with EngineClient(api_url) as client:
        result = run_scenario(SCENARIOS[name], client, timeout=60.0, endpoints=eps)
    assert result.ok, result.detail


def test_a_remotefile_scenario_expecting_the_wrong_disposition_fails(
    served: tuple[str, Endpoints],
) -> None:
    """Negative control for the test above: the poll-in path can say no."""
    api_url, eps = served
    wrong = RemoteFileScenario("wrong", "", "ADT", "A04", count=1, expect="filtered")
    with EngineClient(api_url) as client:
        result = run_scenario(wrong, client, timeout=15.0, endpoints=eps)
    assert not result.ok
    assert "statuses seen: ['processed']" in result.detail


def test_the_engine_refuses_an_unpinned_host_key_until_the_right_one_is_pinned(
    served: tuple[str, Endpoints],
) -> None:
    """The ENGINE's verification, isolated from the driver's: the file is placed straight into the
    share's inbox, then the share is made an UNKNOWN host (no entry) and next a MISMATCHED one (a
    stranger's key), and nothing may be read either way. Pinning the share's own key again is the
    control that the same file then flows."""
    paramiko = _paramiko()
    api_url, eps = served
    probe = RemoteFileScenario("probe", "", "ADT", "A04", count=1)
    (payload,), (control_id,) = probe.payloads()
    with sinks.build("remotefile", eps, "remotefile_sftp") as sink, EngineClient(api_url) as client:
        assert isinstance(sink, RemoteFileSink) and sink.share is not None
        share = sink.share
        inbox = share.local(INBOX)
        share.unpin_host_key()
        (inbox / f"{control_id}.hl7").write_bytes(payload)
        for stranger in (None, _other_key(paramiko)):
            if stranger is not None:
                share.pin_host_key(stranger)
            # Tied to the engine actually trying, not to a clock: three more connections are three
            # more polls, and the settle gate needs two successful listings to read a file.
            seen = share.connections
            deadline = time.monotonic() + 30.0
            while share.connections < seen + 3 and time.monotonic() < deadline:
                time.sleep(0.1)
            assert share.connections >= seen + 3, "the engine stopped polling the share"
            assert client.list_messages(control_id=control_id, limit=1).messages == []
            assert (inbox / f"{control_id}.hl7").exists()  # not read, not moved

        share.pin_host_key()
        deadline = time.monotonic() + 30.0
        status = None
        while time.monotonic() < deadline and status != "processed":
            rows = client.list_messages(control_id=control_id, limit=1).messages
            status = rows[0].status if rows else None
            time.sleep(0.2)
        assert status == "processed"


# --- the byte check --------------------------------------------------------------------------------


def test_verify_written_catches_changed_bytes_and_a_misplaced_file() -> None:
    scenario = SCENARIOS["remotefile_write_out"]
    assert isinstance(scenario, RemoteFileScenario)
    sent = {"C1": _hl7("C1")}
    good = Record(_hl7("C1"), {"relpath": "C1.hl7", "inside": "true"})
    assert verify_written(scenario, [good], sent, "p").ok
    changed = Record(_hl7("C1") + b"X", {"relpath": "C1.hl7", "inside": "true"})
    result = verify_written(scenario, [changed], sent, "p")
    assert not result.ok and "differs from the upload" in result.detail
    nested = Record(_hl7("C1"), {"relpath": "sub/C1.hl7", "inside": "true"})
    assert not verify_written(scenario, [nested], sent, "p").ok
    escaped = Record(_hl7("C1"), {"relpath": "C1.hl7", "inside": "false"})
    assert not verify_written(scenario, [escaped], sent, "p").ok
