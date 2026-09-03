# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0152 rungs 1 + 2 — the platform memory-encryption READ-OUT and the operator declaration.

Three things are on trial here and only one of them is behaviour.

**The behaviour:** a self-report read from the platform, surfaced report-only on
``GET /security/posture`` in the ADR 0120 shape; a ``[security].memory_encryption_operator_declared``
switch that is byte-identical when unset; and a contradiction between the two that warns rather than
refuses.

**The scoping.** An exposed PHI instance without the declaration WARNS — on every built-in
environment, at both ``[security].enforcement`` settings. It refuses only behind the opt-in
``[security].require_memory_encryption_declaration``. That is not a softening: this is a HOST property
that no operator can satisfy on Windows, ADR 0148 makes even ``dev`` derive PHI, and "exposed" includes
the loopback-behind-proxy topology the runbook recommends — so a default refusal would stop a service
that boots today from booting at all. The parametrized test below is the pin for that rule.

**The naming.** ASVS 11.7.1 asks for full memory encryption protecting data in use, and NOTHING in
this feature satisfies it — a local flag is emitted by the OS whose integrity the control exists to
protect against. So there are negative tests below whose whole job is to fail if this feature ever
grows a field, a rendered value, a runtime string or a docstring that could be pasted into a customer
questionnaire as though it did.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.api.models import SecurityPosture
from messagefoundry.config.memory_encryption import (
    GUEST_ATTESTABLE_MECHANISMS,
    GUEST_DEVICES,
    MEMORY_ENCRYPTION_FLAGS,
    READOUT_DISCLAIMER,
    MemoryEncryptionReadout,
    platform_memory_encryption_readout,
)
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecuritySettings,
    StoreSettings,
    load_settings,
    security_loosenings,
)


def _loosenings(sec: SecuritySettings) -> list[tuple[str, str]]:
    """``security_loosenings`` with the shipped [store]/[auth] defaults and an empty accepted set.

    The registry takes all four inputs as REQUIRED arguments deliberately (ADR 0148: one posture, and a
    deviation the registry cannot see is a second posture by the back door). The tests below are about
    the ``[security]`` switches specifically, so the other three are pinned at shipped values here."""
    return security_loosenings(
        sec, StoreSettings(), AuthSettings(), AlertsSettings(), (), (), (), None
    )


SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


def exposed_prod_phi(*security_lines: str) -> str:
    """An EXPOSED production-PHI service config that clears every gate ahead of the ADR 0152 one.

    Covers the Posture-B ladder (declared proxy + intra-service auth + attested TLS floor), bounded
    retention, deny-by-default egress and a configured alert sink. RFC 1918 addresses only.

    Extra ``[security]`` lines are spliced in BEFORE the first table header rather than appended: in
    TOML a trailing ``security.x = true`` after ``[alerts]`` lands in ``[alerts]``, loads clean, and
    silently does nothing — which would make a declared-start test pass for the wrong reason."""
    return (
        "security.local_access_only = false\n"
        'security.listen_address = "0.0.0.0"\n'
        "security.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n"
        # BACKLOG #1026: a PHI instance behind a declared terminator under `enforce` now REFUSES
        # without a public address -- the ASVS 12.1.1 probe dials it, and leaving it unset silently
        # disabled that check. Declared here with the rest of the pre-cleared ladder so these cases
        # keep testing the ADR 0152 readout rather than the new precondition, exactly as the
        # docstring above says the Posture-B declarations are pre-cleared.
        #
        # THE AUTHORED KEY IS `[security].web_console_public_address`. `[api].public_origin` is the
        # INTERNAL settings name and ADR 0118 retired the authored form, which is refused outright.
        # And note WHERE it goes: before the first table header, for the reason the docstring gives.
        'security.web_console_public_address = "https://mefor.example.org"\n'
        + "".join(security_lines)
        + '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n'
        'proxy_intra_service_auth = "network"\nproxy_tls_min_version = "1.2"\n'
        "[retention]\ndead_letter_days = 30\n"
        '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'
    )


class _PassingProbe:
    """Stand-in for TlsFloorProbe: the startup ladder reads only ``.ok`` and ``.describe()``."""

    ok = True

    def describe(self) -> str:
        return "stubbed probe (test)"


def _serve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str, *, env: str = "prod") -> int:
    """Run ``serve`` through the gate ladder with the app + uvicorn mocked (no socket opened)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    # The ASVS 12.1.1 TLS-floor probe makes real TLS handshakes against the declared public address,
    # which #1026 now requires in this posture -- so it runs in every case here and would return 2
    # with nothing listening, failing each test for a reason none of them is about. Stubbed to PASS
    # for the same reason `uvicorn.run` is: these are CONFIG-gate tests. The probe's own network
    # behaviour is covered by tests/test_tls_floor_probe.py, and stubbing it to FAIL would assert
    # the probe rather than the ladder.
    monkeypatch.setattr(
        "messagefoundry.config.tls_probe.probe_tls_floor", lambda origin: _PassingProbe()
    )
    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", env])


def _readout(
    monkeypatch: pytest.MonkeyPatch,
    *,
    capability: bool | None,
    active: bool | None,
    mechanism: str | None = None,
    source: str = "test",
) -> None:
    """Pin the platform read-out for the serve gate.

    Patching the defining module is enough and is deliberate: ``_serve`` imports the helper INSIDE
    the function (the CLI defers heavy imports), so the name is resolved per call and picks the patch
    up. ``api/app.py`` imports it at module scope, so a route test would have to patch there instead
    — there is no route test here, and pinning a name that does not exist would silently pass."""
    fake = MemoryEncryptionReadout(
        capability=capability, active=active, mechanism=mechanism, source=source
    )
    monkeypatch.setattr(
        "messagefoundry.config.memory_encryption.platform_memory_encryption_readout",
        lambda: fake,
    )


# --- rung 1: the read-out reports capability and activation as DIFFERENT facts -------------------


def test_readout_never_raises_and_names_its_source() -> None:
    report = platform_memory_encryption_readout()
    assert isinstance(report, MemoryEncryptionReadout)
    # "we looked and saw nothing" must be distinguishable from "we did not look".
    assert report.source


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows arm")
def test_windows_reports_unknown_not_false() -> None:
    """ADR 0152 makes the Windows in-guest attestation path a spike that has NOT landed. Reporting
    ``False`` there would be a measurement we never made; ``None`` is the honest answer."""
    report = platform_memory_encryption_readout()
    assert report.capability is None
    assert report.active is None
    assert report.mechanism is None
    assert report.source == "unsupported-platform:win32"
    # An undeterminable read-out contradicts NOTHING — and it must not say ``False`` either, which
    # would read as "measured and agrees" on the platform this engine primarily ships on.
    assert report.contradicts_declaration is None


def test_capability_and_activation_are_separate_fields() -> None:
    """A CPU flag says the silicon CAN; a guest device says this guest IS. Fusing them is the single
    most likely route to a false compliance claim, so the dataclass must keep them apart and must not
    offer any convenience property that collapses them into one boolean."""
    fields = set(MemoryEncryptionReadout.__dataclass_fields__)
    assert fields == {"capability", "active", "mechanism", "source"}

    # A capable-but-inactive host is representable and is NOT reported as protected.
    capable_only = MemoryEncryptionReadout(
        capability=True, active=False, mechanism="amd-sev-snp", source="test"
    )
    assert capable_only.capability is True
    assert capable_only.active is False
    assert capable_only.contradicts_declaration is True

    # None (undeterminable) is a third state and never collapses to False.
    unknown = MemoryEncryptionReadout(
        capability=None, active=None, mechanism=None, source="unsupported-platform:test"
    )
    assert unknown.contradicts_declaration is None


def test_contradiction_never_accuses_a_deployment_it_cannot_measure() -> None:
    """``contradicts_declaration`` is TRI-STATE and deliberately under-reports.

    "No guest device node" is only informative on a host that advertises a mechanism which WOULD
    have one. Publishing it as a flat accusation would name three legitimate deployment shapes as
    liars on the endpoint ADR 0152 designates as the evidence artifact:

    * an AMD SME / Intel TME host — memory-controller-wide encryption of all DRAM, the most literal
      reading of 11.7.1's "full memory encryption", and a mechanism with no guest-visible activation
      signal whatsoever, so it could ONLY ever be reported as contradicted;
    * a container or k8s deployment (both shipped modes) that does not ``--device``-map the node on
      an otherwise genuinely confidential host;
    * a host whose ``/proc/cpuinfo`` could not be read at all.
    """
    sme = MemoryEncryptionReadout(
        capability=True, active=False, mechanism="amd-sme", source="test:sme"
    )
    assert sme.contradicts_declaration is None

    unreadable_cpuinfo = MemoryEncryptionReadout(
        capability=None, active=False, mechanism=None, source="linux:guest-devices-only"
    )
    assert unreadable_cpuinfo.contradicts_declaration is None

    # The one shape where absence IS informative: a guest-attestable mechanism, no guest interface.
    for mechanism in sorted(GUEST_ATTESTABLE_MECHANISMS):
        missing = MemoryEncryptionReadout(
            capability=True, active=False, mechanism=mechanism, source="test"
        )
        assert missing.contradicts_declaration is True, mechanism

    # Present interface → corroborated by the self-report (which is still not evidence).
    present = MemoryEncryptionReadout(
        capability=True, active=True, mechanism="intel-tdx", source="test"
    )
    assert present.contradicts_declaration is False

    # Every guest-attestable mechanism must be one the device table can actually observe, or the
    # narrowing above would silence a case it was meant to keep.
    assert {mechanism for _, mechanism in GUEST_DEVICES} == GUEST_ATTESTABLE_MECHANISMS


def test_activation_is_never_inferred_from_a_cpu_flag() -> None:
    """The flag table and the device table are disjoint inputs. If a device path ever appears in the
    flag table (or vice versa) the two facts have been wired to the same source."""
    flags = {flag for flag, _ in MEMORY_ENCRYPTION_FLAGS}
    devices = {path for path, _ in GUEST_DEVICES}
    assert flags.isdisjoint(devices)
    assert all(path.startswith("/dev/") for path in devices)
    assert not any(flag.startswith("/") for flag in flags)


@pytest.mark.skipif(sys.platform != "linux", reason="the Linux /proc + /dev arm")
def test_linux_reads_cpuinfo_and_guest_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.config import memory_encryption as me

    # __wrapped__ is the UNCACHED function. platform_memory_encryption_readout is @cache'd (the
    # platform's answer is fixed at boot, and GET /security/posture must not re-read /proc/cpuinfo on
    # every console poll), so calling it here would either serve a stale answer or poison the cache
    # for the rest of the session.
    monkeypatch.setattr(me, "_read_cpuinfo_flags", lambda: frozenset({"fpu", "sev_snp"}))
    monkeypatch.setattr(me.Path, "is_char_device", lambda self: False)
    # Capability present, activation absent → capable but NOT active. Exactly the case a fused
    # boolean would get wrong.
    report = me.platform_memory_encryption_readout.__wrapped__()
    assert report.capability is True
    assert report.active is False
    assert report.mechanism == "amd-sev-snp"

    # No flags readable at all (a container masking /proc) → undeterminable capability, never False.
    monkeypatch.setattr(me, "_read_cpuinfo_flags", lambda: None)
    report = me.platform_memory_encryption_readout.__wrapped__()
    assert report.capability is None


def test_activation_requires_a_character_device_not_merely_a_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A guest attestation interface is a CHARACTER DEVICE. ``exists()`` is equally true of a
    zero-byte regular file, so anything able to write ``/dev`` — a bad container image, a bind-mount,
    an entrypoint script — could otherwise manufacture a positive activation read-out by touching a
    file. This is the only measurement in the feature an attacker could plant."""
    from messagefoundry.config import memory_encryption as me

    regular_file = tmp_path / "sev-guest"
    regular_file.write_bytes(b"")
    assert regular_file.exists() is True
    assert regular_file.is_char_device() is False

    monkeypatch.setattr(me, "GUEST_DEVICES", ((str(regular_file), "amd-sev-snp"),))
    monkeypatch.setattr(me, "_read_cpuinfo_flags", lambda: frozenset({"sev_snp"}))
    monkeypatch.setattr(me.sys, "platform", "linux")
    report = me.platform_memory_encryption_readout.__wrapped__()
    assert report.active is False


# --- rung 1: the posture surface ----------------------------------------------------------------


def test_posture_fields_default_to_undeterminable_and_undeclared() -> None:
    """Additive + report-only in the ADR 0120 shape: None = undeterminable, and every default is the
    'we know nothing / nobody claimed anything' position."""
    posture = SecurityPosture(
        backend="sqlite",
        encryption_enabled=True,
        key_source="env",
        require_encryption=False,
        allow_unencrypted_phi=False,
    )
    assert posture.memory_encryption_self_reported_capability is None
    assert posture.memory_encryption_self_reported_active is None
    assert posture.memory_encryption_self_reported_mechanism is None
    assert posture.memory_encryption_readout_source is None
    assert posture.memory_encryption_operator_declared is False
    # NOT False. "Nobody claimed anything" and "the platform corroborates the claim" must not render
    # alike — that fusion is what makes a `false` here quotable as corroboration.
    assert posture.memory_encryption_readout_contradicts_declaration is None


# --- rung 2: the setting ------------------------------------------------------------------------


def test_setting_defaults_false_and_is_byte_identical_when_unset(tmp_path: Path) -> None:
    """Every shipped default is unchanged, and the switch is not a loosening (it asserts a protection
    rather than giving one up), so an all-defaults instance names nothing new anywhere."""
    assert SecuritySettings().memory_encryption_operator_declared is False
    assert _loosenings(SecuritySettings()) == []
    assert _loosenings(SecuritySettings(memory_encryption_operator_declared=True)) == []

    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("", encoding="utf-8")
    assert (
        load_settings(config_path=cfg, environ={}).security.memory_encryption_operator_declared
        is False
    )

    # It is read DIRECTLY by the serve gate + the posture route, so it desugars into no internal
    # field — a passthrough entry would imply a functional section owns it.
    from messagefoundry.config.settings import _SECURITY_PASSTHROUGH

    assert not any(
        key == "memory_encryption_operator_declared" for key, _, _ in _SECURITY_PASSTHROUGH
    )


def test_setting_round_trips_from_toml(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("security.memory_encryption_operator_declared = true\n", encoding="utf-8")
    assert (
        load_settings(config_path=cfg, environ={}).security.memory_encryption_operator_declared
        is True
    )


# --- rung 2: the serve gate ---------------------------------------------------------------------


def test_stock_start_does_not_consult_or_gate_on_any_of_this(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """BYTE-IDENTITY, and the "consult" half is literal.

    A stock loopback start must not mention memory encryption at all — not a refusal, not a warning,
    not an info line — and it must not even TAKE the read-out. On Linux that read is a
    ``/proc/cpuinfo`` parse (hundreds of KB on a large host) plus two device stats, for an answer no
    branch on this path can consume."""
    calls: list[int] = []

    def _counting_readout() -> MemoryEncryptionReadout:
        calls.append(1)
        return MemoryEncryptionReadout(False, False, None, "test:negative")

    monkeypatch.setattr(
        "messagefoundry.config.memory_encryption.platform_memory_encryption_readout",
        _counting_readout,
    )
    rc = _serve(tmp_path, monkeypatch, "security.handles_real_patient_data = false\n", env="dev")
    assert rc == 0
    captured = capsys.readouterr()
    assert "memory" not in (captured.out + captured.err).lower()
    assert calls == []


def test_silent_on_a_loopback_phi_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Keyed on EXPOSURE as well as PHI: an unexposed PHI instance is not publishing its heap to
    anyone the control is about, and refusing it would break working deployments on upgrade."""
    _readout(monkeypatch, capability=False, active=False, source="test:negative")
    rc = _serve(
        tmp_path,
        monkeypatch,
        "security.delete_message_bodies_after_days = 30\n"
        "security.block_unlisted_outbound = true\n"
        "[retention]\ndead_letter_days = 30\n"
        '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n',
        env="prod",
    )
    assert rc == 0
    assert "11.7.1" not in capsys.readouterr().err


@pytest.mark.parametrize("env", ["prod", "staging", "dev"])
def test_no_existing_deployment_newly_refuses_it_only_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], env: str
) -> None:
    """THE SCOPING RULE, pinned for every built-in environment under the DEFAULT enforce dial.

    Nothing here may return 2. ADR 0148 makes dev/staging/prod all derive ``DataClass.PHI``, so a
    default refusal would stop an exposed dev or test instance that declared nothing at all — over a
    HOST property that is unsatisfiable on Windows, where the read-out is always null. That is a
    hard-stop of a deployment which boots today, which the ADR 0151 precedent forbids ("only fire on
    the opt-in, so it cannot break an existing deployment"). So: warn, always, and refuse only behind
    ``require_memory_encryption_declaration``."""
    _readout(monkeypatch, capability=False, active=False, source="test:negative")
    rc = _serve(tmp_path, monkeypatch, exposed_prod_phi(), env=env)
    assert rc == 0
    err = capsys.readouterr().err
    assert "warning:" in err and "11.7.1" in err
    assert "refusing" not in err
    assert "memory_encryption_operator_declared" in err
    # The warning must state WHAT it read, or an operator cannot tell a missing declaration from a
    # host that genuinely lacks the feature.
    assert "test:negative" in err


def test_the_recommended_loopback_behind_proxy_topology_still_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """OFF-LOOPBACK-DEPLOYMENT.md's own recommended topology — engine on loopback, proxy facing the
    network — counts as exposed because it declares ``tls_terminated_upstream``. The Posture-B gate
    deliberately downgrades ITS refusal to a warning in exactly this case; this gate must not be
    stricter than the one it is modelled on, or the published runbook config stops booting."""
    _readout(monkeypatch, capability=None, active=None, source="unsupported-platform:win32")
    rc = _serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n"
        # BACKLOG #1026 CHANGES THIS TOPOLOGY'S MINIMUM CONFIG, and that is a real consequence of the
        # ruling rather than a test detail. The 12.1.1 probe deliberately runs behind a declared proxy
        # ON LOOPBACK TOO -- "a reachable front door that speaks TLS 1.0 is a fact, on loopback or
        # not" -- so the precondition applies here as well, and the runbook's own config now needs a
        # public address. Flagged for docs/security/OFF-LOOPBACK-DEPLOYMENT.md; this test asserts the
        # topology STILL STARTS once declared, which is the property its docstring is defending.
        'security.web_console_public_address = "https://mefor.example.org"\n'
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n'
        'proxy_intra_service_auth = "network"\nproxy_tls_min_version = "1.2"\n'
        "[retention]\ndead_letter_days = 30\n"
        '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n',
        env="prod",
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "refusing" not in err
    assert "11.7.1" in err  # it is still SAID, just never fatal


def test_refusal_is_reachable_only_through_the_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The enforcement path an estate that HAS standardized on confidential hosts can turn on.
    Default-false, so it cannot break anything that exists; and the remedy it prints is its own
    switch, not the global [security].enforcement disarm (which would downgrade every higher-severity
    refusal in the ladder at once)."""
    _readout(monkeypatch, capability=False, active=False, source="test:negative")
    rc = _serve(
        tmp_path,
        monkeypatch,
        exposed_prod_phi("security.require_memory_encryption_declaration = true\n"),
        env="prod",
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "11.7.1" in err
    assert "require_memory_encryption_declaration" in err
    assert "enforcement=warn" not in err.replace(" ", "")


def test_the_opt_in_refusal_still_obeys_the_warn_dial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ADR 0148 refuse/warn dial applies ON TOP of the opt-in, as it does for every posture gate."""
    _readout(monkeypatch, capability=False, active=False, source="test:negative")
    rc = _serve(
        tmp_path,
        monkeypatch,
        exposed_prod_phi(
            'security.enforcement = "warn"\nsecurity.require_memory_encryption_declaration = true\n'
        ),
        env="staging",
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "warning:" in err and "11.7.1" in err


def test_exposed_prod_phi_is_silent_once_declared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _readout(monkeypatch, capability=None, active=None, source="unsupported-platform:test")
    rc = _serve(
        tmp_path,
        monkeypatch,
        exposed_prod_phi("security.memory_encryption_operator_declared = true\n"),
        env="prod",
    )
    assert rc == 0
    assert "11.7.1" not in capsys.readouterr().err


def test_a_positive_readout_does_not_discharge_the_declaration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The read-out softens the MESSAGE, never the gate.

    An earlier revision let a positive read-out substitute for the declaration on ergonomic grounds.
    That made the one signal ADR 0152 calls non-evidentiary the only input in this feature able to
    RELAX a control: a wrongly-positive read-out — or a device node someone planted — discharged the
    requirement with nobody declaring anything. Now nothing here refuses OR clears on a read-out, in
    either direction, which is the asymmetry the contradiction branch's warn-never-refuse rests on."""
    _readout(monkeypatch, capability=True, active=True, mechanism="amd-sev-snp", source="test:live")
    rc = _serve(
        tmp_path,
        monkeypatch,
        exposed_prod_phi("security.require_memory_encryption_declaration = true\n"),
        env="prod",
    )
    assert rc == 2
    err = capsys.readouterr().err
    # ...and the message says what it saw, rather than pretending the host reported nothing.
    assert "amd-sev-snp" in err


def test_exposed_synthetic_instance_is_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _readout(monkeypatch, capability=False, active=False, source="test:negative")
    rc = _serve(
        tmp_path,
        monkeypatch,
        exposed_prod_phi("security.handles_real_patient_data = false\n"),
        env="prod",
    )
    assert rc == 0
    assert "11.7.1" not in capsys.readouterr().err


# --- rung 2: the contradiction case -------------------------------------------------------------


def test_contradicted_declaration_warns_loudly_and_never_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """DECISION: warn, never refuse.

    The read-out is a self-report, not evidence, and it has known false negatives (a SEV-SNP guest
    whose sev-guest driver is not loaded; a container that does not map the node). Refusing here
    would let an untrusted, known-fallible signal halt a clinical interface engine — harm caused by
    exactly the input ADR 0152 already declared unreliable. Nothing in this feature refuses on a
    read-out in either direction.

    The warning must also NAME the benign causes: it fires on deployment shapes we ship (containers,
    Azure CVMs), so a message that offers only "your host is not what you think it is" would be
    wrong more often than right."""
    _readout(monkeypatch, capability=True, active=False, mechanism="amd-sev-snp", source="test:neg")
    rc = _serve(
        tmp_path,
        monkeypatch,
        exposed_prod_phi("security.memory_encryption_operator_declared = true\n"),
        env="prod",
    )
    assert rc == 0  # never a refusal
    err = capsys.readouterr().err
    assert "contradict" in err.lower()
    assert "amd-sev-snp" in err
    assert "container" in err.lower() and "driver" in err.lower()


def test_an_sme_host_is_never_accused_of_contradicting_its_operator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AMD SME / Intel TME encrypt all DRAM at the memory controller — arguably the most literal
    reading of 11.7.1 — and have NO guest-visible activation signal, so a device-node check can only
    ever come back empty on them. Publishing that as a contradiction would accuse the deployment
    closest to satisfying the requirement."""
    _readout(monkeypatch, capability=True, active=False, mechanism="amd-sme", source="test:sme")
    rc = _serve(
        tmp_path,
        monkeypatch,
        exposed_prod_phi("security.memory_encryption_operator_declared = true\n"),
        env="prod",
    )
    assert rc == 0
    assert "contradict" not in capsys.readouterr().err.lower()


def test_undeterminable_readout_is_not_a_contradiction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """ "we cannot tell" and "it is not there" are different answers. Treating the first as the second
    would manufacture a contradiction on Windows — the platform this engine primarily ships on."""
    _readout(monkeypatch, capability=None, active=None, source="unsupported-platform:win32")
    rc = _serve(
        tmp_path,
        monkeypatch,
        exposed_prod_phi("security.memory_encryption_operator_declared = true\n"),
        env="prod",
    )
    assert rc == 0
    assert "contradict" not in capsys.readouterr().err.lower()


def test_contradiction_is_silent_when_nobody_declared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A negative read-out on its own contradicts nothing — the contradiction branch is reachable
    only once the operator has opted in, which is why it costs no byte-identity."""
    _readout(monkeypatch, capability=True, active=False, source="test:neg")
    rc = _serve(tmp_path, monkeypatch, "security.handles_real_patient_data = false\n", env="dev")
    assert rc == 0
    assert "contradict" not in capsys.readouterr().err.lower()


# --- the negative test that matters -------------------------------------------------------------

#: Words that would turn a self-report into a compliance claim. A field or label matching any of
#: these is the failure mode ADR 0152 names explicitly: "a self-reported flag gets cited as
#: satisfying 11.7.1".
_COMPLIANCE_WORDS = re.compile(
    r"compliant|compliance|satisfie|satisfies|satisfied|certified|verified|asvs|11[._]7[._]1|"
    r"conformant|approved|guaranteed",
    re.IGNORECASE,
)


#: Every ``memory_encryption_*`` posture field must carry ONE of these hedges in its own name, so
#: the field is self-limiting when it is quoted alone: the value came from the host that 11.7.1
#: distrusts (``self_reported`` / ``readout``), or it is an operator's word (``operator_declared``),
#: or it is the disclaimer itself (``note``).
_REQUIRED_HEDGES = ("self_reported", "readout", "operator_declared", "note")


def test_no_field_can_be_read_as_11_7_1_satisfied() -> None:
    """NOTHING this feature exposes may be citable as satisfying ASVS 11.7.1.

    "attest" is BANNED from these names, not permitted. In confidential computing — the exact domain
    of 11.7.1 — attestation means a CPU-signed quote verified against the silicon vendor's root PKI,
    which is ADR 0152 rung 3 and is not built. The in-house convention that "attested" means
    "unverified, someone took responsibility" (MEFOR_TLS_REVOCATION_ATTESTED) is codebase-internal
    and does not travel with a JSON body leaving the building. An earlier revision of THIS test
    explicitly allowed ``attest`` in a field name — the one guard meant to catch the problem was
    blessing it."""
    added = [name for name in SecurityPosture.model_fields if name.startswith("memory_encryption")]
    assert added, "the read-out fields must exist for this test to mean anything"
    for name in added:
        assert not _COMPLIANCE_WORDS.search(name), f"{name} reads as a compliance claim"
        assert "attest" not in name, (
            f"{name} uses the confidential-computing term of art for a CPU-signed, PKI-verified "
            "quote — which this feature does not produce"
        )
        assert any(hedge in name for hedge in _REQUIRED_HEDGES), name

    # The [security] switch is subject to the same rule: it is the operator's word, and its name has
    # to say so wherever it is quoted.
    for name in SecuritySettings.model_fields:
        if name.startswith("memory_encryption"):
            assert "attest" not in name, name
            assert "operator_declared" in name, name

    # And no field anywhere on the posture DTO claims the requirement is met.
    for name in SecurityPosture.model_fields:
        assert not re.search(r"11[._]7[._]1|asvs", name, re.IGNORECASE), name


def test_the_evidence_artifact_carries_its_own_disclaimer() -> None:
    """ADR 0152 designates ``GET /security/posture`` the evidence artifact for this control, so the
    limits must ship IN THE RESPONSE. Field naming alone is not enough — the naming discipline was
    applied to the four measurements and the JSON still contained no self-limiting text, which on
    Windows (where every measurement is null) left an operator boolean as the only assertive value in
    the body. A disclaimer in a Python comment, a docstring, an ADR or the console HTML reaches
    nobody reading the JSON."""
    assert "11.7.1" in READOUT_DISCLAIMER
    assert "not satisfy" in READOUT_DISCLAIMER or "neither satisfies" in READOUT_DISCLAIMER
    # It must say what WOULD be evidence, or it is unactionable.
    assert "vendor" in READOUT_DISCLAIMER.lower() and "root" in READOUT_DISCLAIMER.lower()
    assert "not built" in READOUT_DISCLAIMER

    posture = SecurityPosture(
        backend="sqlite",
        encryption_enabled=True,
        key_source="env",
        require_encryption=False,
        allow_unencrypted_phi=False,
        memory_encryption_note=READOUT_DISCLAIMER,
    )
    assert posture.memory_encryption_note == READOUT_DISCLAIMER


def test_the_runtime_strings_carry_the_disclaimer_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The startup strings are what gets pasted into a ticket, so they must not read as a verdict
    derived from configuration ("we refuse to start without ASVS 11.7.1 in-use data protection —
    ours starts"). Both arms say what is actually missing (a DECLARATION), and both carry the same
    disclaimer sentence the posture body does."""
    _readout(monkeypatch, capability=False, active=False, source="test:negative")
    _serve(tmp_path, monkeypatch, exposed_prod_phi(), env="prod")
    warn = capsys.readouterr().err
    assert "no declaration of in-use data protection" in warn
    assert READOUT_DISCLAIMER in warn

    _readout(monkeypatch, capability=False, active=False, source="test:negative")
    rc = _serve(
        tmp_path,
        monkeypatch,
        exposed_prod_phi("security.require_memory_encryption_declaration = true\n"),
        env="prod",
    )
    assert rc == 2
    refusal = capsys.readouterr().err
    assert "no declaration of in-use data protection" in refusal
    assert READOUT_DISCLAIMER in refusal


def test_no_runtime_string_asserts_a_measurement_it_did_not_take(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """On Windows the host reports NOTHING, so "this host reports no active hardware memory
    encryption" would be a claim about a measurement that was never made — the same vacuity that
    makes a two-state contradiction flag misleading there."""
    _readout(monkeypatch, capability=None, active=None, source="unsupported-platform:win32")
    _serve(tmp_path, monkeypatch, exposed_prod_phi(), env="prod")
    err = capsys.readouterr().err
    assert "could not be read at all" in err
    assert "reports no active hardware memory encryption" not in err


def test_readout_docstrings_disclaim_rather_than_claim() -> None:
    """The docstring disclaimer is for the ENGINEER reading the module; the one that reaches an
    operator or an auditor ships in the response body (see the disclaimer tests above). Both are
    required — this pins the module-level half."""
    from messagefoundry.config import memory_encryption as me

    module_doc = me.__doc__ or ""
    class_doc = MemoryEncryptionReadout.__doc__ or ""
    assert "11.7.1" in module_doc
    assert "not evidence" in module_doc.lower() or "NOT evidence" in module_doc
    # It must say what WOULD be evidence, or the disclaimer is unactionable.
    assert "vendor" in module_doc.lower() and "root" in module_doc.lower()
    assert "does not satisfy ASVS 11.7.1" in class_doc


def test_console_labels_and_values_never_read_as_corroboration() -> None:
    """The RENDERED strings, not just the field names — the console is what gets screenshotted.

    The three states of the read-out-vs-declaration check must render distinctly. A bare "no" beside
    a "yes" declaration reads as CORROBORATED, and on Windows nothing is ever measured, so a
    two-state rendering would print that reassuring "no" on the primary deployment platform purely by
    vacuity."""
    from messagefoundry_webconsole.pages.monitoring import _contradiction, _memenc

    nothing_measured = _contradiction(None)
    agrees = _contradiction(False)
    contradicts = _contradiction(True)
    assert len({nothing_measured, agrees, contradicts}) == 3
    assert "nothing measured" in nothing_measured
    assert "contradicts" in contradicts.lower()
    for rendered in (nothing_measured, agrees, contradicts, _memenc(True), _memenc(None)):
        assert not _COMPLIANCE_WORDS.search(rendered), rendered
    # Every state of the measurement rows says where the value came from.
    assert "self-reported" in _memenc(True) and "self-reported" in _memenc(False)


def test_the_engine_never_reports_memory_encryption_as_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """There is deliberately no ``memory_encryption_enabled`` / ``_ok`` / ``_compliant`` anywhere: a
    boolean with a bare name is what gets screenshotted into an audit response."""
    banned = {
        "memory_encryption_enabled",
        "memory_encryption",
        "memory_encryption_ok",
        "memory_encryption_compliant",
        "memory_encryption_verified",
    }
    assert banned.isdisjoint(SecurityPosture.model_fields)
    assert banned.isdisjoint(SecuritySettings.model_fields)
