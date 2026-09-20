# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the wheel-only deployment verifier (`messagefoundry verify`).

These run in CI from the dev repo even though the tool ships in the wheel: they prove no host check
raises, the smoke/store paths behave, the report renders, and the CLI wires up + exits correctly.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.base import open_store
from messagefoundry.store.store import MessageStatus
from messagefoundry.verify import checks, smoke
from messagefoundry.verify.model import CheckResult, Status
from messagefoundry.verify.report import exit_code, render_console, render_json, render_markdown
from messagefoundry.verify.runner import ALL_SECTIONS, run_verify

# ---- host checks ------------------------------------------------------------------------------


def test_run_host_checks_never_errors(tmp_path: Path) -> None:
    results = checks.run_host_checks(ports={"MLLP": 2575}, writable_dir=tmp_path)
    assert results, "no host checks produced"
    for r in results:
        assert isinstance(r, CheckResult)
        assert isinstance(r.status, Status)
        assert r.detail
        assert r.status is not Status.ERROR, f"{r.id} errored: {r.detail}"


def test_python_runtime_passes() -> None:
    r = checks.check_python_runtime()
    assert r.status is Status.PASS
    assert "messagefoundry" in r.detail


def test_writable_dir_pass_and_fail(tmp_path: Path) -> None:
    ok = checks.check_writable_dir(tmp_path)
    assert ok.status is Status.MANUAL  # writable -> MANUAL (ACLs still need a human)
    # A path under a file can't be created -> FAIL, not a crash.
    afile = tmp_path / "afile"
    afile.write_text("x", encoding="utf-8")
    bad = checks.check_writable_dir(afile / "subdir")
    assert bad.status is Status.FAIL


def test_writable_dir_never_creates_the_dir_it_checks(tmp_path: Path) -> None:
    """#1708: the check used to ``mkdir(parents=True)`` first, so it could not fail for the reason
    its title names — and it runs before ``store.connect``, so the tree it made was the one the store
    then filled. An absent directory must FAIL and leave nothing behind."""
    missing = tmp_path / "no" / "such" / "tree"
    r = checks.check_writable_dir(missing)
    assert r.status is Status.FAIL
    assert str(missing) in r.detail
    assert not missing.exists()
    assert not (tmp_path / "no").exists()  # not even the first level


def test_writable_dir_leaves_no_probe_file_behind(tmp_path: Path) -> None:
    before = sorted(p.name for p in tmp_path.iterdir())
    assert checks.check_writable_dir(tmp_path).status is Status.MANUAL
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_listener_ports_is_manual_with_evidence() -> None:
    r = checks.check_listener_ports({"MLLP": 2575, "API": 8765})
    assert r.status is Status.MANUAL
    assert "MLLP" in r.evidence and "API" in r.evidence


def test_console_no_window_detects_flag() -> None:
    # On Windows both sc.exe spawners must carry a non-zero _NO_WINDOW and pass creationflags=;
    # elsewhere the flag does not exist, so the honest answer is SKIP (#1713).
    r = checks.check_console_no_window()
    assert r.id == "host.noflash"
    assert r.status is (Status.MANUAL if sys.platform == "win32" else Status.SKIP)


def test_console_no_window_covers_both_sc_spawners() -> None:
    """#1713: ``service_status`` carries its own ``_NO_WINDOW`` and the check never read it, so a
    regression in the stdlib-only leaf was invisible. Pin that both modules are inspected."""
    assert checks._NO_WINDOW_MODULES == (
        "messagefoundry.service",
        "messagefoundry.service_status",
    )
    for name in checks._NO_WINDOW_MODULES:
        src = Path(importlib.import_module(name).__file__ or "").read_text(encoding="utf-8")
        assert checks._spawns_without_creationflags(src) == []


def test_console_no_window_is_not_satisfied_by_a_comment() -> None:
    """The old check passed on the substring ``CREATE_NO_WINDOW`` appearing anywhere in the file,
    which the module's own explanatory comment satisfies on its own — so it stayed MANUAL through
    exactly the regression its FAIL text names. The AST walk must see the call site, not the prose."""
    regressed = (
        "import subprocess\n"
        "# CREATE_NO_WINDOW suppresses the console window.\n"
        "_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)\n"
        "def q(name):\n"
        "    return subprocess.run(['sc.exe', 'query', name], capture_output=True)\n"
    )
    assert "CREATE_NO_WINDOW" in regressed  # positive control: a grep would have passed this
    missing = checks._spawns_without_creationflags(regressed)
    assert missing and "subprocess.run" in missing[0]

    guarded = regressed.replace(
        "capture_output=True", "capture_output=True, creationflags=_NO_WINDOW"
    )
    assert checks._spawns_without_creationflags(guarded) == []


def test_host_console_row_is_gone(tmp_path: Path) -> None:
    """#1713: ``host.console`` reported PySide6 as "Console importable" and told a deploying operator
    to install a ``[console]`` extra that ``pyproject.toml`` has never had. The desktop console was
    retired and the operator console is served in-process at ``/ui``, so there is no host
    prerequisite left for it to check."""
    assert not hasattr(checks, "check_console_importable")
    results = checks.run_host_checks(ports={"MLLP": 2575}, writable_dir=tmp_path)
    assert "host.console" not in {r.id for r in results}


def test_no_flash_targets_stay_wheel_only() -> None:
    """Replaces the ``httpx_absent`` pair this diff deletes (#1713).

    Those blocked ``httpx`` to simulate a missing ``[console]`` extra, but nothing on the host path
    imports ``httpx``, so both were vacuous — and off Windows the check now returns SKIP before
    importing anything at all. Their comments also described a ``[console]`` extra that
    ``pyproject.toml`` has never had, which is half of what #1713 is about.

    What genuinely needs pinning is the property those tests were reaching for: the no-flash check
    imports its targets for real, so a third-party dep creeping into either would turn a host row
    into a SKIP on a minimal install."""
    for name in checks._NO_WINDOW_MODULES:
        tree = ast.parse(Path(importlib.import_module(name).__file__ or "").read_text("utf-8"))
        roots = {
            (node.module or "").split(".")[0]
            if isinstance(node, ast.ImportFrom)
            else node.names[0].name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import | ast.ImportFrom)
        }
        third_party = roots - set(sys.stdlib_module_names) - {"messagefoundry"}
        assert not third_party, (
            f"{name} grew a third-party import {third_party}; host checks must stay wheel-only"
        )


# ---- self smoke -------------------------------------------------------------------------------


def test_self_smoke_missing_config_skips() -> None:
    r = smoke.smoke_self("no/such/config/dir")
    assert r.status is Status.SKIP


def test_self_smoke_ambiguous_inbound_skips() -> None:
    # samples/config has several inbounds; with none chosen, the smoke skips and lists them.
    r = smoke.smoke_self("samples/config")
    assert r.status is Status.SKIP
    assert "inbound" in r.detail.lower()


def test_self_smoke_routes_synthetic_adt() -> None:
    # The happy path, and it has to PROVE delivery rather than merely find the word. `deliveries=`
    # also matches `deliveries=0`, so the original substring passed on the exact outcome BACKLOG
    # #1707 exists to fail -- an assertion that cannot go red is the same defect as the gate it
    # covers.
    r = smoke.smoke_self("samples/config", inbound="IB_ACME_ADT")
    assert r.status is Status.PASS, r.detail
    assert f"disposition={MessageStatus.RECEIVED.value}" in r.detail
    assert "deliveries=1" in r.detail


# ---- self smoke: PASS requires a DELIVERING outcome (BACKLOG #1707) ----------------------------
#
# `dry_run` sets `DryRunResult.error` for a parse failure, a strict-validation failure or a
# Router/Handler raise -- and for NOTHING else. UNROUTED and FILTERED carry `error=None`, so gating
# on the error alone answered "did dry_run return?" when the question is "would a message land?".


def _write_smoke_config(tmp_path: Path, *, route: str, handle: str) -> str:
    """A one-module config dir whose Router returns ``route`` and whose Handler returns ``handle``."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "IB_SMOKE.py").write_text(
        f"""\
# SPDX-License-Identifier: AGPL-3.0-or-later
from messagefoundry import MLLP, Send, handler, inbound, outbound, router

inbound("IB_SMOKE", MLLP(port=2601), router="r")
outbound("OB_SMOKE", MLLP(host="127.0.0.1", port=2602))


@router("r")
def route(msg):
    return {route}


@handler("h")
def handle(msg):
    return {handle}
""",
        encoding="utf-8",
    )
    return str(cfg)


# The two shapes a deploying site actually hits, and they go wrong at DIFFERENT stages. Unrouted:
# the Router matched nothing, so no Handler ever ran. Filtered: the Router DID select a handler and
# the transform DID run, so every stage reports having worked -- it is the delivery count that is
# zero, which is the whole question the check exists to answer.
@pytest.mark.parametrize(
    ("route", "handle", "disposition", "handlers", "reason"),
    [
        ("[]", 'Send("OB_SMOKE", msg)', MessageStatus.UNROUTED, 0, "no handler"),
        ('["h"]', "None", MessageStatus.FILTERED, 1, "no delivery"),
    ],
    ids=["unrouted", "filtered"],
)
def test_self_smoke_fails_without_a_delivery(
    tmp_path: Path,
    route: str,
    handle: str,
    disposition: MessageStatus,
    handlers: int,
    reason: str,
) -> None:
    """A run that delivers nowhere must not read green.

    It proves the config LOADS and proves nothing about routing, because nothing reached a
    destination. A deploying site would otherwise read a green acceptance report off a message the
    engine would have dropped.
    """
    cfg = _write_smoke_config(tmp_path, route=route, handle=handle)
    r = smoke.smoke_self(cfg, inbound="IB_SMOKE")
    assert r.status is Status.FAIL, r.detail
    assert f"disposition={disposition.value}" in r.detail
    assert f"handlers={handlers}" in r.detail
    # Kept even though the disposition implies it: this pins that the row REPORTS the count, which
    # is a property of the summary string rather than of `disposition_for`.
    assert "deliveries=0" in r.detail
    assert reason in r.detail  # the FAIL text names why, not just the verdict


def test_classify_self_smoke() -> None:
    """The classifier itself, including the arm that must not exist: a silent PASS.

    Mirrors ``test_classify_disposition`` for the live smoke -- the same vocabulary reaching the same
    verdict on the same synthetic message, so the two halves of ``verify`` cannot answer one question
    two ways.
    """
    ok = smoke._classify_self_smoke(MessageStatus.RECEIVED, "SUMMARY")
    assert ok.id == "smoke.self"
    assert ok.status is Status.PASS
    assert ok.detail == "SUMMARY"  # a delivering run adds nothing to the summary

    for bad in (MessageStatus.UNROUTED, MessageStatus.FILTERED):
        r = smoke._classify_self_smoke(bad, "SUMMARY")
        assert r.status is Status.FAIL, bad
        assert r.detail.startswith("SUMMARY ")
        # An operator gets a next step, not just a red row: the synthetic message is a fixed ADT^A01
        # from MAINHOSP, so a Router keyed on another feed declines it legitimately.
        assert "--inbound" in r.detail, bad

    # NOT_DEPLOYED has its own arm now (BACKLOG #1714, packet 14 P14-09). It used to reach the
    # fail-closed arm below, which got the VERDICT right and left the operator no next step -- and
    # `disposition_for` returns it for real, for a routed run whose every Send addressed a
    # present-but-not-deployed destination (BACKLOG #1690).
    nd = smoke._classify_self_smoke(MessageStatus.NOT_DEPLOYED, "SUMMARY")
    assert nd.status is Status.FAIL
    assert nd.detail.startswith("SUMMARY ")
    # A remedy, and specifically NOT the unrouted/filtered one: the Router and the Handler both did
    # their job, so re-pointing `--inbound` would send the operator after a feed that was fine.
    assert "--inbound" not in nd.detail
    # Both spellings are chosen to DISCRIMINATE. A bare `"deploy" in detail.lower()` would not:
    # the fail-closed arm this replaced said "NOT_DEPLOYED is not a delivering outcome", which
    # contains the word and none of the advice.
    assert "deploy the outbound" in nd.detail
    assert "present-but-not-deployed" in nd.detail

    # FILTERED must no longer claim the outcome above as one of its own meanings -- naming it in
    # both places is what made a decline indistinguishable from an author's filter.
    filtered = smoke._classify_self_smoke(MessageStatus.FILTERED, "SUMMARY")
    assert "present-but-not-deployed" not in filtered.detail

    # FAIL CLOSED. Each of these must fail NAMING itself rather than fall through to the PASS arm --
    # that fall-through is the defect, so the fix must not leave a door in. These are the members
    # `disposition_for` does not return, so this arm has no usable remedy to offer and gives none.
    for unknown in (MessageStatus.ERROR, MessageStatus.ROUTED):
        r = smoke._classify_self_smoke(unknown, "SUMMARY")
        assert r.status is Status.FAIL, unknown
        assert unknown.value.upper() in r.detail, unknown
        # ...and WITHOUT the unrouted/filtered remedy. "Re-point --inbound" is advice that flag
        # cannot act on for these, and a confident wrong next step costs more than none.
        assert "--inbound" not in r.detail, unknown


def test_synthetic_message_is_hl7() -> None:
    msg = smoke.synthetic_message()
    assert msg.startswith("MSH|")
    assert msg.endswith("\r")  # segment-terminated, as the generator emitted it and MLLP expects


def test_synthetic_message_strict_validates() -> None:
    """The inlined literal (#1192) is still a conformant 2.5.1 ADT^A01.

    Nothing regenerates the message any more, so something has to keep it honest. This pins
    CONFORMANCE rather than byte-equality with ``messagefoundry.generators``, deliberately: an
    equality test would go red the day the generators leave the engine distribution -- the end state
    this inlining exists to unblock -- and would churn on any unrelated generator edit while proving
    nothing extra, since a generator change does not make the existing literal non-conformant.
    Conformance is the property ``smoke_self`` and ``smoke_live`` actually depend on.
    """
    from messagefoundry.parsing.validate import validate

    result = validate(smoke.synthetic_message(), expected_version="2.5.1")
    assert result.ok, result.errors
    assert result.version == "2.5.1"


def test_synthetic_message_reads_as_a_probe_not_a_patient() -> None:
    """Synthetic only (CLAUDE.md section 9), and OBVIOUSLY so.

    ``smoke_live`` sends this message into a real engine, where it lands in the operator's own
    store. Every person name is the ZZZTEST family and MSH-10 carries the tool's own prefix, so an
    operator reading that row sees a probe rather than a patient.
    """
    from messagefoundry.parsing.message import Message

    msg = Message.parse(smoke.synthetic_message())
    assert msg.message_type == "ADT^A01^ADT_A01"
    control_id = msg.control_id
    assert control_id is not None and control_id.startswith("MEFOR"), control_id
    assert msg["PID-5.1"] == "ZZZTEST"
    for occurrence in range(1, msg.count_segments("NK1") + 1):
        assert msg.field("NK1-2.1", occurrence=occurrence) == "ZZZTEST"
    for occurrence in range(1, msg.count_segments("PV1") + 1):
        assert msg.field("PV1-7.2", occurrence=occurrence) == "ZZZTEST"
        assert msg.field("PV1-17.2", occurrence=occurrence) == "ZZZTEST"


# ---- the verifier must not carry the development generators (#1192 / ASVS 15.2.3) --------------

# Run in a FRESH interpreter: this pytest process has already imported the generators for other
# suites, so an in-process sys.modules read could never answer the question.
_GENERATORS_PROBE = """\
import sys

import messagefoundry.verify
from messagefoundry.verify import checks, federation, model, report, runner, smoke

smoke.synthetic_message()

found = sorted(m for m in sys.modules if m.startswith("messagefoundry.generators"))
print("AFTER_VERIFY=" + ",".join(found))

# Positive control. Without it an empty line above is indistinguishable from a probe that cannot
# see a generators import at all.
import messagefoundry.generators.all_types  # noqa: F401

found = sorted(m for m in sys.modules if m.startswith("messagefoundry.generators"))
print("AFTER_CONTROL=" + ",".join(found))
"""


def test_verify_does_not_import_the_generators() -> None:
    """``messagefoundry.verify`` must not pull ``messagefoundry.generators`` into its runtime.

    This is the guarantee the inlining buys. Without this test the import edge could come back on
    any later edit and nothing would report it.
    """
    repo_root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "-c", _GENERATORS_PROBE],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=repo_root,  # sys.path[0] for -c, so the probe reads THIS tree, not an editable install
    )
    assert proc.returncode == 0, proc.stderr
    lines = dict(
        line.split("=", 1) for line in proc.stdout.splitlines() if line.startswith("AFTER_")
    )
    assert lines["AFTER_VERIFY"] == "", (
        f"messagefoundry.verify imported the generators: {lines['AFTER_VERIFY']}"
    )
    assert "messagefoundry.generators.all_types" in lines["AFTER_CONTROL"], (
        "positive control failed -- the probe cannot detect a generators import at all, so its "
        "clean answer above means nothing"
    )


def _generator_imports(source: str) -> list[str]:
    """Every way ``source`` could reach ``messagefoundry.generators``, by symbol not by text.

    A plain substring scan cannot do this job: the prose in ``smoke.py`` names the package to
    explain why it is absent, and a scan would read that as the defect it documents. Walk the AST
    instead -- ``import``, ``from ... import``, and the string form an ``importlib.import_module``
    call takes.
    """
    hits: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            hits += [a.name for a in node.names if a.name.startswith("messagefoundry.generators")]
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and node.module.startswith("messagefoundry.generators")
        ):
            hits.append(node.module)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("messagefoundry.generators")
        ):
            hits.append(node.value)
    return hits


def test_no_verify_source_imports_the_generators() -> None:
    """Source-level companion to the import probe.

    The probe only sees imports that actually execute; a lazy ``from messagefoundry.generators
    import ...`` inside an un-taken branch, or a dotted path handed to ``importlib``, would slip
    past it.
    """
    verify_dir = Path(__file__).resolve().parents[1] / "messagefoundry" / "verify"
    sources = sorted(verify_dir.glob("*.py"))
    assert sources, f"no verify sources found under {verify_dir}"
    hits = {
        path.name: found
        for path in sources
        if (found := _generator_imports(path.read_text(encoding="utf-8")))
    }
    assert not hits, f"verify still imports the generators: {hits}"

    # Positive control on all three forms. Without it, the clean result above is indistinguishable
    # from a predicate that can never fire.
    control = (
        "import messagefoundry.generators.all_types\n"
        "from messagefoundry.generators import _core\n"
        'importlib.import_module("messagefoundry.generators.adt")\n'
    )
    assert len(_generator_imports(control)) == 3, _generator_imports(control)


# ---- self smoke: snapshot_on_send thread-through (#241 F3) -------------------------------------


def test_smoke_self_threads_snapshot_on_send(monkeypatch: pytest.MonkeyPatch) -> None:
    # smoke_self must pass its snapshot_on_send straight into dry_run (not silently drop to the
    # library default), so the self-smoke previews the engine's real copy-on-Send posture (ADR 0104).
    import messagefoundry.pipeline.dryrun as dryrun_mod
    from messagefoundry.pipeline.dryrun import DryRunResult

    real = dryrun_mod.dry_run
    seen: list[bool] = []

    def _spy(*args: object, **kwargs: object) -> DryRunResult:
        seen.append(bool(kwargs.get("snapshot_on_send")))
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(dryrun_mod, "dry_run", _spy)
    r = smoke.smoke_self("samples/config", inbound="IB_ACME_ADT", snapshot_on_send=True)
    assert r.status is Status.PASS, r.detail
    assert seen == [True]


def test_run_verify_self_smoke_threads_resolved_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    # run_verify must feed smoke_self the RESOLVED [pipeline].snapshot_on_send — True on a default
    # engine (PipelineSettings default), the configured value otherwise — and keep the dry_run library
    # default (False) when no service settings load (#241 F3, #230 CLI parity).
    from messagefoundry.config.settings import PipelineSettings, ServiceSettings
    from messagefoundry.verify import runner as runner_mod

    seen: list[bool] = []

    def _spy_smoke_self(
        config_dir: str, *, inbound: str | None = None, snapshot_on_send: bool = False
    ) -> CheckResult:
        seen.append(snapshot_on_send)
        return CheckResult("smoke.self", "spy", Status.PASS, "spy")

    monkeypatch.setattr(runner_mod, "smoke_self", _spy_smoke_self)

    # settings present, snapshot ON (the default-engine posture) -> threaded True.
    monkeypatch.setattr(runner_mod, "_load_settings", lambda _c: (ServiceSettings(), None))
    run_verify(sections=["smoke"], smoke_mode="self")
    assert seen[-1] is True

    # settings present, snapshot OFF -> threaded False (proves it's the resolved value, not a constant).
    monkeypatch.setattr(
        runner_mod,
        "_load_settings",
        lambda _c: (ServiceSettings(pipeline=PipelineSettings(snapshot_on_send=False)), None),
    )
    run_verify(sections=["smoke"], smoke_mode="self")
    assert seen[-1] is False

    # no service settings -> keep the dry_run library default (False), never the ON engine default.
    monkeypatch.setattr(runner_mod, "_load_settings", lambda _c: (None, "boom"))
    run_verify(sections=["smoke"], smoke_mode="self")
    assert seen[-1] is False


# ---- live smoke (ACK parsing + a fake MLLP server) --------------------------------------------


def test_ack_code_parses_msa() -> None:
    aa = b"MSH|^~\\&|R|R|S|S|20260101||ACK|1|P|2.5.1\rMSA|AA|1\r"
    assert smoke._ack_code(aa) == "AA"
    ae = b"MSH|^~\\&|R|R|S|S|20260101||ACK|1|P|2.5.1\rMSA|AE|1|bad\r"
    assert smoke._ack_code(ae) == "AE"
    assert smoke._ack_code(b"not hl7") is None


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _serve_one(ack: bytes) -> int:
    """Start a one-shot MLLP server that replies with `ack`; return its port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = int(srv.getsockname()[1])

    def handle() -> None:
        try:
            conn, _ = srv.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(b"\x0b" + ack + b"\x1c\x0d")
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


def test_live_smoke_passes_on_aa() -> None:
    port = _serve_one(b"MSH|^~\\&|R|R|S|S|20260101||ACK|1|P|2.5.1\rMSA|AA|1\r")
    r = smoke.smoke_live(
        host="127.0.0.1", port=port, message=smoke.synthetic_message(), timeout=5.0
    )
    assert r.status is Status.PASS, r.detail


def test_live_smoke_fails_on_nak() -> None:
    port = _serve_one(b"MSH|^~\\&|R|R|S|S|20260101||ACK|1|P|2.5.1\rMSA|AR|1\r")
    r = smoke.smoke_live(
        host="127.0.0.1", port=port, message=smoke.synthetic_message(), timeout=5.0
    )
    assert r.status is Status.FAIL
    assert "AR" in r.detail


def test_live_smoke_fails_when_unreachable() -> None:
    r = smoke.smoke_live(host="127.0.0.1", port=_free_port(), message="MSH|x", timeout=2.0)
    assert r.status is Status.FAIL


# ---- live smoke over TLS (BACKLOG #1178, ASVS 12.3.1) -------------------------------------------
#
# The defect these cover, measured before the fix: smoke_live wrote a whole MLLP frame onto a bare
# socket regardless of the target inbound's TLS posture, so `verify --smoke live` against a
# `tls = true` inbound put a synthetic message BODY on the wire in the clear and then failed with
# an unexplained "0 bytes received".


def _self_signed(tmp_path: Path) -> tuple[str, str]:
    """A throwaway cert/key for a loopback TLS listener, SAN=localhost so hostname checking is real."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now.replace(year=2040))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "smoke-cert.pem", tmp_path / "smoke-key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_file), str(key_file)


def _serve_one_tls(ack: bytes, cert: str, key: str) -> int:
    """A one-shot MLLP-over-TLS listener that replies with ``ack``; returns its port."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = int(srv.getsockname()[1])

    def handle() -> None:
        try:
            conn, _ = srv.accept()
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(65536)
                tls.sendall(b"\x0b" + ack + b"\x1c\x0d")
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


def _record_first_bytes() -> tuple[socket.socket, int, list[bytes]]:
    """A raw listener that records the first bytes of each connection. Yields (server, port, seen)."""
    seen: list[bytes] = []
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def handle() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(3.0)
                try:
                    seen.append(conn.recv(64))
                except OSError:
                    seen.append(b"")

    threading.Thread(target=handle, daemon=True).start()
    return srv, int(srv.getsockname()[1]), seen


def test_live_smoke_over_tls_passes_on_aa(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    port = _serve_one_tls(b"MSH|^~\\&|R|R|S|S|20260101||ACK|1|P|2.5.1\rMSA|AA|1\r", cert, key)
    r = smoke.smoke_live(
        host="127.0.0.1",
        port=port,
        message=smoke.synthetic_message(),
        timeout=5.0,
        ssl_context=smoke.live_smoke_ssl_context(ca_file=cert),
        server_hostname="localhost",
    )
    assert r.status is Status.PASS, r.detail


def test_live_smoke_over_tls_puts_no_plaintext_frame_on_the_wire(tmp_path: Path) -> None:
    """The whole point of #1178's smoke limb, with its own positive control in the same run.

    Both calls hit the SAME raw recorder, so the plaintext arm proves the recorder can see an MLLP
    frame at all — a TLS arm that observed nothing against a broken recorder would be reporting the
    instrument, not the fix.
    """
    srv, port, seen = _record_first_bytes()
    try:
        smoke.smoke_live(host="127.0.0.1", port=port, message="MSH|^~\\&|A", timeout=2.0)
        smoke.smoke_live(
            host="127.0.0.1",
            port=port,
            message="MSH|^~\\&|A",
            timeout=2.0,
            ssl_context=smoke.live_smoke_ssl_context(ca_file=_self_signed(tmp_path)[0]),
            server_hostname="localhost",
        )
    finally:
        srv.close()
    assert len(seen) == 2, f"the recorder saw {len(seen)} connection(s), expected 2"
    plaintext, over_tls = seen
    assert plaintext.startswith(b"\x0bMSH"), "positive control: the cleartext arm must be visible"
    assert over_tls[:2] == b"\x16\x03", f"expected a TLS ClientHello, saw {over_tls[:8]!r}"
    assert b"MSH" not in over_tls, "an application byte preceded or escaped the handshake"


def test_live_smoke_tls_handshake_failure_is_named_as_such(tmp_path: Path) -> None:
    """A cert problem must not read as an unreachable partner — that sends the operator to the
    firewall for what is a trust-anchor question."""
    cert, key = _self_signed(tmp_path)
    port = _serve_one_tls(b"MSH|x\rMSA|AA|1\r", cert, key)
    r = smoke.smoke_live(
        host="127.0.0.1",
        port=port,
        message="MSH|^~\\&|A",
        timeout=5.0,
        ssl_context=smoke.live_smoke_ssl_context(),  # system trust store: cannot anchor this cert
        server_hostname="localhost",
    )
    assert r.status is Status.FAIL
    assert "TLS handshake" in r.detail, r.detail


def test_plaintext_live_smoke_against_a_silent_listener_names_tls_as_a_cause() -> None:
    """Zero bytes back is what a TLS inbound does to a cleartext frame. Say so; never retry."""
    srv, port, _seen = _record_first_bytes()
    try:
        r = smoke.smoke_live(host="127.0.0.1", port=port, message="MSH|^~\\&|A", timeout=2.0)
    finally:
        srv.close()
    assert r.status is Status.FAIL
    assert "0 bytes received" in r.detail
    assert "--smoke-tls" in r.detail, r.detail
    assert "never retries" in r.detail, r.detail


def test_live_smoke_ssl_context_offers_no_verify_off_escape() -> None:
    ctx = smoke.live_smoke_ssl_context()
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_live_smoke_ssl_context_asserts_forward_secrecy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reaching the shared assertion is observable only when it can fire, so make it fire.

    Mirrors ``tests/test_tls_cipher_assertion_sites.py``: the shipped suite list is entirely
    forward-secret, so a correctly-wired call site and a missing one look identical without this.
    """
    from messagefoundry.config import tls_policy

    monkeypatch.setattr(tls_policy, "_is_forward_secret", lambda cipher: False)
    with pytest.raises(ValueError, match="verify live smoke"):
        smoke.live_smoke_ssl_context()


# ---- store connectivity -----------------------------------------------------------------------


def _seed_store(path: Path) -> StoreSettings:
    """A StoreSettings pointing at a real, already-created SQLite store.

    #1708 rewrote the two tests below to seed first. Their PASS assertion was always correct; the
    fixture was what was wrong — it handed the check a path with no database on it, and the check
    passed by making one, so the tests certified the defect.
    """
    settings = StoreSettings(path=str(path))
    asyncio.run(_seed_message(settings, control_id="SEED", status=MessageStatus.PROCESSED))
    assert path.is_file()  # the seed, not the check, is what created it
    return settings


def test_store_connectivity_sqlite(tmp_path: Path) -> None:
    settings = _seed_store(tmp_path / "verify.db")
    r = smoke.check_store_connectivity(settings)
    assert r.status is Status.PASS, r.detail


def test_store_connectivity_never_creates_the_store_it_reports_on(tmp_path: Path) -> None:
    """#1708: ``open_store``'s schema-ensure creates whatever path it is handed, so this check
    returned PASS against a database it had just made and left it behind. A mistyped ``[store].path``
    therefore could not fail for the reason the row's title names."""
    missing = tmp_path / "nothing-here.db"
    r = smoke.check_store_connectivity(StoreSettings(path=str(missing)))
    assert r.status is Status.FAIL
    assert str(missing) in r.detail
    assert not missing.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == []  # no -wal/-shm sidecars either


def test_disposition_helpers_never_create_the_store(tmp_path: Path) -> None:
    """The same defect in the two read-only ``--check-disposition`` helpers. Read-only *intent* is
    not enough: both only ever read, and both created a database to do it."""
    missing = tmp_path / "absent.db"
    settings = StoreSettings(path=str(missing))

    assert smoke.newest_message_id(settings, "CID") is None
    r = smoke.check_smoke_disposition(settings, control_id="CID", baseline_id=None, timeout=3)
    assert r.status is Status.FAIL and str(missing) in r.detail
    assert sorted(p.name for p in tmp_path.iterdir()) == []


def test_missing_sqlite_store_gate_is_scoped_to_sqlite_on_disk() -> None:
    """The gate fires only where a *file* would be created. ``:memory:`` writes none, and the server
    backends are out of its reach — see :func:`smoke.missing_sqlite_store` for what that leaves
    open on Postgres and SQL Server, which is a real limit rather than a clean bill."""
    assert smoke.missing_sqlite_store(StoreSettings(path=":memory:")) is None
    for backend in (StoreBackend.SQLSERVER, StoreBackend.POSTGRES):
        settings = StoreSettings(
            backend=backend,
            path="does-not-exist.db",
            server="db.example.invalid",
            database="mefor",
            username="mefor_svc",
        )
        assert smoke.missing_sqlite_store(settings) is None


def test_every_open_store_in_verify_goes_through_the_gate() -> None:
    """#1708's invariant, pinned structurally instead of asserted in a docstring.

    The three call sites are correct today and one PR away from being false again, with nothing to
    notice — which is the same failure shape #1713 fixes in this very change: a check that stays
    green through the regression it names. An AST walk, in the pattern
    :func:`test_verify_does_not_import_the_generators` already uses on this package."""
    verify_dir = Path(smoke.__file__).parent
    gated, ungated = [], []
    for source_file in sorted(verify_dir.glob("*.py")):
        tree = ast.parse(source_file.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            called = {
                sub.func.id
                for sub in ast.walk(node)
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
            }
            if "open_store" not in called:
                continue
            where = f"{source_file.name}::{node.name}"
            (gated if "missing_sqlite_store" in called else ungated).append(where)

    assert not ungated, (
        f"{ungated} call open_store without missing_sqlite_store first, so verify would create the "
        "SQLite store it reports on (#1708)"
    )
    # Positive control: an instrument that finds no open_store at all would pass vacuously.
    assert sorted(gated) == [
        "smoke.py::check_smoke_disposition",
        "smoke.py::check_store_connectivity",
        "smoke.py::newest_message_id",
    ]


# ---- report -----------------------------------------------------------------------------------


def test_report_render_and_exit_code() -> None:
    rows = [
        CheckResult("a", "alpha", Status.PASS, "ok"),
        CheckResult("b", "beta", Status.MANUAL, "later"),
        CheckResult("c", "gamma", Status.SKIP, "n/a"),
    ]
    assert exit_code(rows) == 0
    assert exit_code(rows + [CheckResult("d", "delta", Status.FAIL, "boom")]) == 1
    assert exit_code(rows + [CheckResult("e", "eps", Status.ERROR, "broke")]) == 1

    console = render_console(rows)
    assert "alpha" in console and "exit 0" in console
    md = render_markdown(rows)
    assert "| a | alpha |" in md
    import json

    parsed = json.loads(render_json(rows))
    assert parsed["exit_code"] == 0
    assert parsed["tally"]["PASS"] == 1
    assert {r["id"] for r in parsed["results"]} == {"a", "b", "c"}


# ---- runner + CLI -----------------------------------------------------------------------------


def test_run_verify_sections_and_manual() -> None:
    results = run_verify(sections=["host", "manual"], smoke_mode="none")
    ids = {r.id for r in results}
    assert any(i.startswith("host.") for i in ids)
    assert "manual.nssm" in ids
    assert not any(i.startswith("smoke.") for i in ids)  # smoke not selected
    assert all(r.status is not Status.ERROR for r in results)


def test_run_verify_manual_only() -> None:
    results = run_verify(sections=["manual"], smoke_mode="none")
    assert results and all(r.id.startswith("manual.") for r in results)


def test_cli_verify_runs_and_exits_zero() -> None:
    assert main(["verify", "--section", "host,manual", "--smoke", "none"]) == 0


def test_cli_verify_rejects_unknown_section(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify", "--section", "bogus", "--smoke", "none"]) == 2
    assert "unknown section" in capsys.readouterr().err


def test_all_sections_constant() -> None:
    assert set(ALL_SECTIONS) == {"host", "store", "smoke", "manual", "federation"}


# ---- disposition (--check-disposition) --------------------------------------------------------

_RAW_ADT = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|X|P|2.5.1\rEVN|A01|20260101\rPID|1||1^^^H^MR||DOE^J\r"
)


async def _seed_message(settings: StoreSettings, *, control_id: str, status: MessageStatus) -> str:
    handle = await open_store(settings)
    try:
        return await handle.record_received(
            channel_id="verify-test", raw=_RAW_ADT, status=status, control_id=control_id
        )
    finally:
        await handle.close()


def test_classify_disposition() -> None:
    ok = smoke._classify_disposition("processed", control_id="X", timeout=5)
    assert ok.status is Status.PASS and ok.id == "smoke.disposition"
    err = smoke._classify_disposition("error", control_id="X", timeout=5)
    assert err.status is Status.FAIL and "ERROR" in err.detail
    assert smoke._classify_disposition("unrouted", control_id="X", timeout=5).status is Status.FAIL
    assert smoke._classify_disposition("filtered", control_id="X", timeout=5).status is Status.FAIL
    inflight = smoke._classify_disposition("routed", control_id="X", timeout=5)
    assert (
        inflight.status is Status.FAIL and "ROUTED" in inflight.detail
    )  # still in flight at timeout
    none = smoke._classify_disposition(None, control_id="X", timeout=5)
    assert none.status is Status.FAIL and "no NEW stored message" in none.detail


def test_store_connectivity_detail_names_calling_user(tmp_path: Path) -> None:
    settings = _seed_store(tmp_path / "verify.db")
    r = smoke.check_store_connectivity(settings)
    assert r.status is Status.PASS
    assert "calling user" in r.detail and "service account" in r.detail


def test_check_smoke_disposition_processed(tmp_path: Path) -> None:
    settings = StoreSettings(path=str(tmp_path / "d.db"))
    asyncio.run(_seed_message(settings, control_id="CID-OK", status=MessageStatus.PROCESSED))
    r = smoke.check_smoke_disposition(settings, control_id="CID-OK", baseline_id=None, timeout=3)
    assert r.status is Status.PASS and r.id == "smoke.disposition"


def test_check_smoke_disposition_dead_letter_fails(tmp_path: Path) -> None:
    settings = StoreSettings(path=str(tmp_path / "d.db"))
    asyncio.run(_seed_message(settings, control_id="CID-BAD", status=MessageStatus.ERROR))
    r = smoke.check_smoke_disposition(settings, control_id="CID-BAD", baseline_id=None, timeout=3)
    assert r.status is Status.FAIL and "ERROR" in r.detail


def test_check_smoke_disposition_ignores_baseline(tmp_path: Path) -> None:
    # A pre-existing message with the same control id (the baseline) must NOT satisfy the check — only
    # a NEWER message counts, so a re-used synthetic id can't pass on a prior run's result.
    settings = StoreSettings(path=str(tmp_path / "d.db"))
    old = asyncio.run(_seed_message(settings, control_id="CID-DUP", status=MessageStatus.PROCESSED))
    r = smoke.check_smoke_disposition(settings, control_id="CID-DUP", baseline_id=old, timeout=1)
    assert r.status is Status.FAIL and "no NEW stored message" in r.detail


def test_run_verify_check_disposition_skips_without_settings() -> None:
    # check_disposition with no --service-config: the disposition row SKIPs (no store to poll).
    results = run_verify(
        sections=["smoke"], smoke_mode="live", mllp_port=59999, check_disposition=True
    )
    disp = [r for r in results if r.id == "smoke.disposition"]
    assert disp and disp[0].status is Status.SKIP


# ---- settings-load failures are reported, not disguised as "no settings" -----------------------


def test_absent_config_resolves_defaults_and_adds_no_row(tmp_path: Path) -> None:
    """A box with NO messagefoundry.toml is not an error: load_settings returns defaults. The run
    must therefore be byte-unchanged — no config.load row, no exit-code change."""
    from messagefoundry.verify.runner import _load_settings

    settings, error = _load_settings(None)
    assert settings is not None and error is None

    results = run_verify(sections=["store"], smoke_mode="none")
    assert not [r for r in results if r.id == "config.load"]


def test_a_config_that_exists_but_is_invalid_fails_with_the_reason(tmp_path: Path) -> None:
    """The defect this fixes: `settings is None` NEVER meant "absent" (absent yields defaults), yet
    every dependent row said "no service settings — pass --service-config", sending an operator to
    look for a file that is present and broken. It must FAIL, naming the cause."""
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        "[api]" + chr(10) + 'public_origin = "https://ops.example"' + chr(10),
        encoding="utf-8",
    )

    results = run_verify(sections=["store"], smoke_mode="none", service_config=str(cfg))
    load = [r for r in results if r.id == "config.load"]
    assert load and load[0].status is Status.FAIL
    assert "public_origin" in load[0].detail  # the actual cause, not a generic message
    assert exit_code(results) == 1  # a broken config must not pass an acceptance run

    store = [r for r in results if r.id == "store.connect"]
    assert store and store[0].status is Status.SKIP
    assert "config.load" in store[0].detail  # points at the row carrying the reason


def test_a_missing_explicit_config_path_fails_rather_than_skipping(tmp_path: Path) -> None:
    results = run_verify(
        sections=["store"], smoke_mode="none", service_config=str(tmp_path / "nope.toml")
    )
    load = [r for r in results if r.id == "config.load"]
    assert load and load[0].status is Status.FAIL
    assert exit_code(results) == 1


def test_settings_error_never_echoes_a_configured_value(tmp_path: Path) -> None:
    """A verify report is written to disk and pasted into tickets, so a pydantic ValidationError must
    contribute loc+msg only — never `input`, which for a password or DSN would be a credential."""
    secret = "SUPERSECRET-do-not-print-me"
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        "[api]" + chr(10) + 'port = "' + secret + '"' + chr(10),
        encoding="utf-8",
    )

    results = run_verify(sections=["store"], smoke_mode="none", service_config=str(cfg))
    rendered = render_json(results) + render_markdown(results) + render_console(results)
    assert secret not in rendered
    load = [r for r in results if r.id == "config.load"]
    assert load and "api.port" in load[0].detail  # the FIELD is named; the value is not
