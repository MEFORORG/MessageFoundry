# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2903 (ADR 0216): ``serve`` probes each Vault token at start, and the gravest grants
refuse the start under ``[security].enforcement = enforce``.

The defect, in the conditional this repo requires (a not-deployed beta, zero instances): the Vault
probe ran only inside ``check-privileges``, so on a first deployment a Vault token holding the root
policy or key-export rights would start with no warning, no audit row and no refusal.

Every Vault answer here is MOCKED by the fake client the ``check-privileges`` tests already use, and
every token is a synthetic string that could not authenticate anywhere. No test opens a socket.

Pinned here: the two classes the owner ruling of 2026-10-04 names (the refusing class refuses, the
warning class only warns, and three ordinary setups are in the warning class); the one decision
function both ``serve`` and ``check-privileges`` call; the audited opt-out; and the lifespan seam,
end to end through the real probe, so a lifespan that stops calling it fails a test.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import (
    AiSettings,
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    EgressSettings,
    SecretRotationSettings,
    SecretsSettings,
    SecurityEnforcement,
    SecuritySettings,
    ServiceSettings,
    StorePrivilegeStatus,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.privilege_check import (
    VAULT_OVER_GRANT_OPT_OUT,
    HopPrivilege,
    HopState,
    VaultConsumer,
    serve_verdict,
    vault_hop,
    vault_hops,
    vault_preflight_outcome,
)
from messagefoundry.privilege_probes import VaultTokenReading, read_vault_token
from messagefoundry.store import keyprovider_vault
from messagefoundry.store.privilege import PreflightOutcome, StorePrivilegeReport
from messagefoundry.vault_preflight import VaultPrivilegeError, run_vault_privilege_preflight
from tests.test_vault_ldap_privilege_probes import (
    _KEK,
    _TOKEN,
    _VAULT_ADDR,
    Forbidden,
    _FakeVault,
    _least_caps,
    _reading,
)

_STORE = VaultConsumer("vault.store", "kek", "store key provider", "read and decrypt the KEK")
_KV_PATH = "secret/data/mefor/ad"
_KV = VaultConsumer("vault.secrets", "kv", "kv", "read the KV path", ("mefor/ad",))


def _hop(**kwargs: Any) -> Any:
    return vault_hop(_STORE, _reading(_FakeVault(**kwargs)))


# --- the two classes (closing step 2) ----------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "words"),
    [
        ({"policies": ("root",)}, "the token carries the root policy"),
        (
            {
                "caps": _least_caps()
                | {"sys/policies/acl/messagefoundry-check-privileges": ["create"]}
            },
            "sys/policies/acl/messagefoundry-check-privileges grants create",
        ),
        ({"caps": _least_caps() | {"auth/token/create": ["update"]}}, "auth/token/create grants"),
        # A token able to rewrite its own policy.
        ({"caps": _least_caps() | {"sys/policies/acl/mefor-store": ["update"]}}, "mefor-store"),
        ({"caps": _least_caps() | {f"transit/keys/{_KEK}/config": ["update"]}}, "/config grants"),
        ({"caps": _least_caps() | {f"transit/keys/{_KEK}/rotate": ["update"]}}, "/rotate grants"),
        (
            {"caps": _least_caps() | {f"transit/export/encryption-key/{_KEK}": ["read"]}},
            "export/encryption-key",
        ),
        ({"caps": _least_caps() | {f"transit/backup/{_KEK}": ["read"]}}, "/backup/"),
    ],
)
def test_the_gravest_grants_are_in_the_refusing_class(kwargs: dict[str, Any], words: str) -> None:
    hop = _hop(**kwargs)
    assert hop.state is HopState.OVER_GRANTED
    assert hop.refusing, "a gravest grant must be in the refusing class"
    assert any(words in r for r in hop.refusing)
    assert vault_preflight_outcome(hop, enforcing=True, over_grant_accepted=False) is (
        PreflightOutcome.REFUSE
    )


def test_an_extra_capability_on_a_path_the_engine_calls_only_warns() -> None:
    """The row's second ordinary setup: ``list`` beside ``read`` must not refuse a start."""
    caps = _least_caps() | {f"transit/keys/{_KEK}": ["list", "read"]}
    hop = _hop(caps=caps)
    assert hop.state is HopState.OVER_GRANTED
    assert hop.refusing == ()
    assert vault_preflight_outcome(hop, enforcing=True, over_grant_accepted=False) is (
        PreflightOutcome.WARN
    )


def test_a_policy_name_the_probe_cannot_judge_only_warns() -> None:
    """The row's third ordinary setup: a name the probe cannot tell from root means cannot judge."""
    hop = _hop(caps=_least_caps(), policies=("default", "r\u043eot"))  # a Cyrillic o
    assert hop.state is HopState.OVER_GRANTED
    assert hop.refusing == ()
    assert "cannot be told apart from root" in hop.detail
    assert vault_preflight_outcome(hop, enforcing=True, over_grant_accepted=False) is (
        PreflightOutcome.WARN
    )


def test_a_name_that_reads_as_root_only_once_stripped_only_warns() -> None:
    """A lookalike is a name the probe cannot tell from root by reading it, so it is reported as
    over-granted but is in the warning class, and the refusal never says the token holds root."""
    hop = _hop(caps=_least_caps(), policies=("default", "r\u200boot"))
    assert hop.state is HopState.OVER_GRANTED
    assert hop.refusing == ()
    assert "as far as reading it can tell" in hop.detail
    assert vault_preflight_outcome(hop, enforcing=True, over_grant_accepted=False) is (
        PreflightOutcome.WARN
    )


def test_the_json_read_out_names_the_refusing_reasons() -> None:
    assert _hop(policies=("root",)).as_dict()["refusing"] == ["the token carries the root policy"]
    assert _hop(caps=_least_caps()).as_dict()["refusing"] == []


def test_one_token_shared_by_two_hops_only_warns() -> None:
    """The row's first ordinary setup: one token serving two hops is over-granted, and warns."""
    caps = _least_caps() | {_KV_PATH: ["read"]}
    store = _reading(_FakeVault(caps=caps))
    secrets = read_vault_token(
        lambda: _TOKEN,
        lambda: _VAULT_ADDR,
        lambda a, t: _FakeVault(caps=caps),
        lambda: {_KV_PATH: frozenset({"read"})},
    )
    hops = vault_hops([_STORE, _KV], [store, secrets])
    assert [h.state for h in hops] == [HopState.OVER_GRANTED, HopState.OVER_GRANTED]
    assert [h.refusing for h in hops] == [(), ()]
    assert {
        vault_preflight_outcome(h, enforcing=True, over_grant_accepted=False) for h in hops
    } == {PreflightOutcome.WARN}


# --- the one decision (closing step 3) ---------------------------------------------------------


def test_the_decision_table() -> None:
    clean = _hop(caps=_least_caps())
    grave = _hop(policies=("root",))
    warning = _hop(caps=_least_caps() | {f"transit/keys/{_KEK}": ["list", "read"]})
    blind = _hop(lookup_error=ConnectionError("vault.invalid"))
    assert blind.state is HopState.UNOBSERVABLE

    def outcome(hop: Any, enforcing: bool, accepted: bool) -> PreflightOutcome:
        return vault_preflight_outcome(hop, enforcing=enforcing, over_grant_accepted=accepted)

    for enforcing in (True, False):
        for accepted in (True, False):
            assert outcome(clean, enforcing, accepted) is PreflightOutcome.CLEAN
            # The opt-out lifts the refusal only: the warning class and a blind probe still warn.
            assert outcome(warning, enforcing, accepted) is PreflightOutcome.WARN
            assert outcome(blind, enforcing, accepted) is PreflightOutcome.WARN
    assert outcome(grave, True, False) is PreflightOutcome.REFUSE
    assert outcome(grave, True, True) is PreflightOutcome.ACCEPTED
    # Under warn nothing refuses.
    assert outcome(grave, False, False) is PreflightOutcome.WARN
    assert outcome(grave, False, True) is PreflightOutcome.WARN


# --- the preflight -----------------------------------------------------------------------------


class _AuditStore:
    def __init__(self) -> None:
        self.audits: list[tuple[str, dict[str, Any]]] = []

    async def record_audit(self, action: str, *, actor: str | None, detail: str | None) -> None:
        self.audits.append((action, json.loads(detail or "{}")))


_VAULT_SETTINGS = ServiceSettings.model_validate({"store": {"key_provider": "vault"}})


def _probe(vault: _FakeVault) -> Any:
    calls: list[str] = []

    def probe(consumer: VaultConsumer) -> VaultTokenReading:
        calls.append(consumer.hop)
        return _reading(vault)

    probe.calls = calls  # type: ignore[attr-defined]
    return probe


async def test_a_root_token_refuses_start_under_enforce_and_says_how_to_accept_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _AuditStore()
    with (
        caplog.at_level(logging.WARNING),
        pytest.raises(VaultPrivilegeError, match="allow_over_granted_vault_token") as refused,
    ):
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            store,
            enforcing=True,
            over_grant_accepted=False,
            probe=_probe(_FakeVault(policies=("root",))),
        )
    assert "vault.store" in str(refused.value)
    assert _TOKEN not in str(refused.value) and _TOKEN not in caplog.text
    # The audit row is written BEFORE the refusal, so a refused start is durable.
    [(action, detail)] = store.audits
    assert action == "vault_privilege_preflight"
    assert detail["hop"] == "vault.store"
    assert detail["state"] == "over_granted"
    assert detail["refused"] is True
    assert detail["over_grant_accepted"] is False
    assert detail["refusing"] == ["the token carries the root policy"]
    assert _TOKEN not in json.dumps(store.audits)


async def test_the_opt_out_starts_a_root_token_and_records_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _AuditStore()
    with caplog.at_level(logging.WARNING):
        hops = await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            store,
            enforcing=True,
            over_grant_accepted=True,
            probe=_probe(_FakeVault(policies=("root",))),
        )
    assert [h.state for h in hops] == [HopState.OVER_GRANTED]
    assert "AUDIT:" in caplog.text and VAULT_OVER_GRANT_OPT_OUT in caplog.text
    [(_, detail)] = store.audits
    assert detail["refused"] is False
    assert detail["over_grant_accepted"] is True


async def test_a_warning_class_grant_warns_audits_and_starts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _AuditStore()
    caps = _least_caps() | {f"transit/keys/{_KEK}": ["list", "read"]}
    with caplog.at_level(logging.WARNING):
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            store,
            enforcing=True,
            over_grant_accepted=False,
            probe=_probe(_FakeVault(caps=caps)),
        )
    assert "vault privilege preflight" in caplog.text and "REFUSING" not in caplog.text
    [(_, detail)] = store.audits
    assert detail["state"] == "over_granted"
    assert detail["refused"] is False and detail["over_grant_accepted"] is False
    assert detail["refusing"] == []


async def test_an_unobservable_probe_warns_audits_and_starts() -> None:
    store = _AuditStore()
    await run_vault_privilege_preflight(
        _VAULT_SETTINGS,
        store,
        enforcing=True,
        over_grant_accepted=False,
        probe=_probe(_FakeVault(lookup_error=ConnectionError("vault.invalid"))),
    )
    [(_, detail)] = store.audits
    assert detail["state"] == "unobservable" and detail["refused"] is False


async def test_nothing_refuses_under_enforcement_warn() -> None:
    store = _AuditStore()
    await run_vault_privilege_preflight(
        _VAULT_SETTINGS,
        store,
        enforcing=False,
        over_grant_accepted=False,
        probe=_probe(_FakeVault(policies=("root",))),
    )
    assert store.audits[0][1]["refused"] is False


async def test_a_clean_token_writes_a_clean_row(caplog: pytest.LogCaptureFixture) -> None:
    store = _AuditStore()
    with caplog.at_level(logging.WARNING):
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            store,
            enforcing=True,
            over_grant_accepted=False,
            probe=_probe(_FakeVault(caps=_least_caps())),
        )
    assert caplog.records == []
    assert store.audits[0][1]["state"] == "clean"


async def test_no_vault_consumer_probes_nothing_and_writes_no_row() -> None:
    store = _AuditStore()
    probe = _probe(_FakeVault(policies=("root",)))
    hops = await run_vault_privilege_preflight(
        ServiceSettings(), store, enforcing=True, over_grant_accepted=False, probe=probe
    )
    assert hops == []
    assert probe.calls == []
    assert store.audits == []


def _raising(exc: BaseException) -> Any:
    def probe(consumer: VaultConsumer) -> VaultTokenReading:
        raise exc

    return probe


#: A probe failure the 2026-10-04 ruling lets only warn: a network failure, a timeout, a 403.
_EXCUSED = [
    pytest.param(ConnectionError(f"https://vault.invalid/ token={_TOKEN}"), id="network"),
    pytest.param(TimeoutError(f"timed out, token={_TOKEN}"), id="timeout"),
    pytest.param(Forbidden(f"permission denied, token={_TOKEN}"), id="403"),
]

#: Programming defects, such as an hvac rename or a signature drift leaves behind.
_DEFECTS = [
    pytest.param(TypeError(f"lookup_self() got an unexpected keyword, {_TOKEN}"), id="TypeError"),
    pytest.param(AttributeError(f"no attribute 'lookup_self', {_TOKEN}"), id="AttributeError"),
]


@pytest.mark.parametrize("error", _DEFECTS)
async def test_a_probe_that_raises_a_code_defect_refuses_start_under_enforce(
    error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    """The Lander's hold on PR 2650: a catch-all read any raise as unobservable, which only warns,
    so a TypeError after an hvac signature drift let an enforcing instance start on a token nobody
    judged. RED at dc852601f1: the preflight returned and nothing refused."""
    store = _AuditStore()
    with (
        caplog.at_level(logging.WARNING),
        pytest.raises(VaultPrivilegeError, match="not a network failure") as refused,
    ):
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS, store, enforcing=True, over_grant_accepted=False, probe=_raising(error)
        )
    name = type(error).__name__
    assert "vault.store" in str(refused.value)
    assert f"the probe raised {name}" in caplog.text
    [(_, detail)] = store.audits
    assert detail["refused"] is True and detail["unexcused"] == [name]
    assert _TOKEN not in str(refused.value) and _TOKEN not in caplog.text
    assert _TOKEN not in json.dumps(store.audits)


async def test_the_opt_out_does_not_accept_a_probe_that_raised_a_code_defect() -> None:
    """The opt-out accepts a grant that was seen; a token the probe never read is not one."""
    with pytest.raises(VaultPrivilegeError, match="does not accept this"):
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            _AuditStore(),
            enforcing=True,
            over_grant_accepted=True,
            probe=_raising(TypeError("synthetic")),
        )


@pytest.mark.parametrize("error", _DEFECTS)
async def test_a_code_defect_inside_the_real_probe_refuses_start_under_enforce(
    error: Exception,
) -> None:
    """The same defect where an hvac drift would really land: inside ``read_vault_token``, whose
    own catch records it as a problem and never raises. RED at dc852601f1: it read as unobservable
    and only warned."""
    store = _AuditStore()
    with pytest.raises(VaultPrivilegeError, match="vault.store"):
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            store,
            enforcing=True,
            over_grant_accepted=False,
            probe=_probe(_FakeVault(caps=_least_caps(), lookup_error=error)),
        )
    [(_, detail)] = store.audits
    assert detail["state"] == "unobservable" and detail["refused"] is True
    assert detail["unexcused"] == [type(error).__name__]


async def test_an_answer_missing_a_path_refuses_start_under_enforce() -> None:
    """A capabilities answer that names no capabilities for a path left that path unjudged, and is
    not a network, timeout or 403 failure, so it refuses as a code defect does."""
    vault = _FakeVault(caps=_least_caps())
    vault.unanswered.add(f"transit/keys/{_KEK}/config")
    store = _AuditStore()
    with pytest.raises(VaultPrivilegeError, match="not a network failure"):
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            store,
            enforcing=True,
            over_grant_accepted=False,
            probe=_probe(vault),
        )
    assert store.audits[0][1]["unexcused"] == ["an answer naming no capabilities for a path"]


@pytest.mark.parametrize("error", _EXCUSED)
async def test_a_network_timeout_or_403_failure_only_warns_under_enforce(
    error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    """The control for the two tests above: the failures the ruling excuses still only warn, both
    raised from the probe and caught inside it."""
    for probe in (_raising(error), _probe(_FakeVault(caps=_least_caps(), lookup_error=error))):
        store = _AuditStore()
        with caplog.at_level(logging.WARNING):
            [hop] = await run_vault_privilege_preflight(
                _VAULT_SETTINGS, store, enforcing=True, over_grant_accepted=False, probe=probe
            )
        assert hop.state is HopState.UNOBSERVABLE
        [(_, detail)] = store.audits
        assert detail["refused"] is False and detail["unexcused"] == []
    assert "REFUSING" not in caplog.text
    assert _TOKEN not in caplog.text


def test_the_real_library_classes_are_excused() -> None:
    """The fakes above stand in for these: requests' timeouts and connection errors are OSErrors,
    and hvac's 403 is ``Forbidden``. A change to either library that moves them fails here."""
    import socket

    from messagefoundry.privilege_probes import excused_failure
    from messagefoundry.transports.bounded_read import TruncatedResponseError

    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    requests = pytest.importorskip("requests")

    for error in (
        requests.ConnectionError("synthetic"),
        requests.ConnectTimeout("synthetic"),
        requests.ReadTimeout("synthetic"),
        requests.exceptions.ChunkedEncodingError("synthetic"),
        requests.exceptions.ProxyError("synthetic"),
        TruncatedResponseError("synthetic"),
        socket.gaierror("synthetic"),
        hvac_exceptions.Forbidden("synthetic"),
    ):
        assert excused_failure(error), type(error).__name__
    # Configuration and code, not the network: OSErrors among them are not excused for being one.
    for error in (
        requests.exceptions.InvalidHeader("synthetic"),
        requests.exceptions.InvalidURL("synthetic"),
        requests.exceptions.MissingSchema("synthetic"),
        requests.exceptions.SSLError("synthetic"),
        FileNotFoundError("synthetic"),
        hvac_exceptions.InternalServerError("synthetic"),
        TypeError("synthetic"),
        AttributeError("synthetic"),
    ):
        assert not excused_failure(error), type(error).__name__


def test_a_tls_failure_is_read_through_its_wrapper() -> None:
    """Review round two: requests reports a TLS failure on the proxy leg as a ProxyError, which is
    a ConnectionError, and a handshake the peer cut off as an SSLError. The wrapped ssl error, not
    the wrapper, says which: verification is configuration, a cut-off handshake is the network."""
    import ssl

    from messagefoundry.privilege_probes import excused_failure

    rex = pytest.importorskip("requests.exceptions")

    def wrapping(outer: BaseException, inner: BaseException) -> BaseException:
        outer.__cause__ = inner
        return outer

    verify = ssl.SSLCertVerificationError("synthetic")
    cut = ssl.SSLEOFError("synthetic")
    assert not excused_failure(wrapping(rex.ProxyError("synthetic"), verify))
    assert not excused_failure(wrapping(rex.SSLError("synthetic"), verify))
    # urllib3 keeps the cause in args, not __cause__.
    assert not excused_failure(rex.ProxyError(rex.SSLError(verify)))
    assert excused_failure(wrapping(rex.SSLError("synthetic"), cut))
    assert excused_failure(wrapping(rex.ProxyError("synthetic"), cut))
    assert excused_failure(rex.ProxyError("synthetic"))


def test_an_unexcused_failure_is_named_once_however_often_it_recurs() -> None:
    from messagefoundry.store.keyprovider import KeyProviderError

    def unset() -> str:
        raise KeyProviderError("synthetic: the variable is not set")

    def no_paths() -> dict[str, frozenset[str]]:
        raise KeyProviderError("synthetic: the key name is not set")

    reading = read_vault_token(unset, unset, lambda a, t: _FakeVault(), no_paths)
    assert reading.unexcused == ("KeyProviderError",)
    assert len(reading.problems) == 3


def _over_granted_and_unjudged(**kwargs: Any) -> Any:
    """A token whose lookup read and showed a grant, and whose capabilities read then failed with
    a code defect."""
    hop = _hop(caps_error=TypeError("synthetic"), **kwargs)
    assert hop.unexcused == ("TypeError",)
    return hop


@pytest.mark.parametrize("accepted", [True, False])
def test_serve_refuses_an_unexcused_failure_the_opt_out_cannot_lift(accepted: bool) -> None:
    hop = _over_granted_and_unjudged(policies=("root",))
    assert hop.state is HopState.OVER_GRANTED
    assert vault_preflight_outcome(hop, enforcing=True, over_grant_accepted=accepted) is (
        PreflightOutcome.REFUSE
    )
    assert vault_preflight_outcome(hop, enforcing=False, over_grant_accepted=accepted) is (
        PreflightOutcome.WARN
    )


@pytest.mark.parametrize(
    ("kwargs", "accepted", "starts"),
    [
        ({"policies": ("root",)}, True, True),
        ({"policies": ("root",)}, False, False),
        ({"caps": _least_caps()}, False, True),
    ],
)
def test_check_privileges_names_an_unexcused_failure_beside_its_verdict(
    kwargs: dict[str, Any], accepted: bool, starts: bool
) -> None:
    """Review rounds one and two: check-privileges judged a hop's grants and said nothing of the
    failure serve refuses on. It now judges the grants it saw and names the failure in a note,
    because its own run may meet a failure serve's does not, such as an unset key name."""
    hop = _over_granted_and_unjudged(**kwargs)
    settings = _VAULT_SETTINGS.model_copy(
        update={"security": SecuritySettings(allow_over_granted_vault_token=accepted)}
    )
    verdict = serve_verdict(_sqlite_report(), settings, [hop])
    assert verdict.startswith("would start" if starts else "would REFUSE to start"), verdict
    assert "a timeout or a 403 (vault.store: TypeError); serve refuses to start" in verdict


def test_an_unexcused_reading_with_no_problem_is_never_clean() -> None:
    """A reading naming an unexcused failure is never CLEAN, even one that lists no problem."""
    reading = VaultTokenReading(
        looked_up=True,
        required=dict(_reading(_FakeVault(caps=_least_caps())).required),
        capabilities={p: tuple(c) for p, c in _least_caps().items()},
        unexcused=("TypeError",),
    )
    hop = vault_hop(_STORE, reading)
    assert hop.state is HopState.UNOBSERVABLE
    assert vault_preflight_outcome(hop, enforcing=True, over_grant_accepted=False) is (
        PreflightOutcome.REFUSE
    )


async def test_an_accepted_grant_is_not_recorded_as_accepted_when_another_hop_refuses(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With one hop accepted and another refusing, nothing started, so no row and no AUDIT line
    may say the opt-out let a start through. The control is the same pair with the second hop
    clean, which records the acceptance."""
    from messagefoundry import vault_preflight

    monkeypatch.setattr(vault_preflight, "vault_consumers", lambda settings: [_STORE, _KV])

    def probe_with(second: BaseException | None) -> Any:
        def probe(consumer: VaultConsumer) -> VaultTokenReading:
            if consumer.hop == _STORE.hop:
                return _reading(_FakeVault(policies=("root",)))
            if second is not None:
                raise second
            return VaultTokenReading()

        return probe

    store = _AuditStore()
    with caplog.at_level(logging.WARNING), pytest.raises(VaultPrivilegeError):
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            store,
            enforcing=True,
            over_grant_accepted=True,
            probe=probe_with(TypeError("synthetic")),
        )
    assert "AUDIT:" not in caplog.text
    assert [d["over_grant_accepted"] for _, d in store.audits] == [False, False]

    control = _AuditStore()
    await run_vault_privilege_preflight(
        _VAULT_SETTINGS, control, enforcing=True, over_grant_accepted=True, probe=probe_with(None)
    )
    assert [d["over_grant_accepted"] for _, d in control.audits] == [True, False]


async def test_the_refusal_names_both_causes_of_one_hop() -> None:
    with pytest.raises(VaultPrivilegeError) as refused:
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            _AuditStore(),
            enforcing=True,
            over_grant_accepted=False,
            probe=_probe(_FakeVault(policies=("root",), caps_error=TypeError("synthetic"))),
        )
    assert "holds the root policy" in str(refused.value)
    assert "not a network failure" in str(refused.value)


@pytest.mark.parametrize("enforcing", [True, False])
async def test_a_probe_that_raises_never_escapes_the_preflight(enforcing: bool) -> None:
    """A raise from the probe (a token re-read that fails, an unrouted consumer kind) never escapes
    as itself: under warn nothing may refuse, and under enforce it refuses through the preflight's
    own error, after its audit row."""
    store = _AuditStore()
    probe = _raising(ValueError(f"synthetic failure quoting {_TOKEN}"))
    if enforcing:
        with pytest.raises(VaultPrivilegeError):
            await run_vault_privilege_preflight(
                _VAULT_SETTINGS, store, enforcing=True, over_grant_accepted=False, probe=probe
            )
    else:
        [hop] = await run_vault_privilege_preflight(
            _VAULT_SETTINGS, store, enforcing=False, over_grant_accepted=False, probe=probe
        )
        assert hop.state is HopState.UNOBSERVABLE
        assert "the probe raised ValueError" in hop.detail
    assert _TOKEN not in json.dumps(store.audits)
    assert store.audits[0][1]["refused"] is enforcing


async def test_a_code_defect_under_warn_warns_naming_its_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _AuditStore()
    with caplog.at_level(logging.WARNING):
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            store,
            enforcing=False,
            over_grant_accepted=False,
            probe=_raising(TypeError("synthetic")),
        )
    assert "the probe raised TypeError" in caplog.text and "REFUSING" not in caplog.text
    assert store.audits[0][1]["refused"] is False


async def test_an_audit_failure_never_masks_the_refusal() -> None:
    class _AuditFails:
        async def record_audit(self, action: str, *, actor: str | None, detail: str | None) -> None:
            raise RuntimeError("audit table unavailable")

    with pytest.raises(VaultPrivilegeError):
        await run_vault_privilege_preflight(
            _VAULT_SETTINGS,
            _AuditFails(),
            enforcing=True,
            over_grant_accepted=False,
            probe=_probe(_FakeVault(policies=("root",))),
        )


# --- check-privileges says what serve would do (closing step 5) --------------------------------


def _sqlite_report() -> StorePrivilegeReport:
    from messagefoundry.config.settings import StoreBackend

    return StorePrivilegeReport(
        backend=StoreBackend.SQLITE, status=StorePrivilegeStatus.NOT_APPLICABLE
    )


def test_serve_verdict_refuses_on_a_gravest_vault_grant() -> None:
    verdict = serve_verdict(_sqlite_report(), _VAULT_SETTINGS, [_hop(policies=("root",))])
    assert verdict.startswith("would REFUSE to start")
    assert "vault.store" in verdict and "allow_over_granted_vault_token" in verdict


def test_serve_verdict_keeps_an_accepted_store_over_grant_beside_a_vault_refusal() -> None:
    from messagefoundry.config.settings import StoreBackend

    over = StorePrivilegeReport(
        backend=StoreBackend.SQLSERVER,
        status=StorePrivilegeStatus.OBSERVED,
        principal=r"CORP\mefor-svc$",
        database="MessageFoundry",
        excess=("server role sysadmin",),
    )
    settings = _VAULT_SETTINGS.model_copy(
        update={"security": SecuritySettings(allow_over_granted_store_principal=True)}
    )
    verdict = serve_verdict(over, settings, [_hop(policies=("root",))])
    assert verdict.startswith("would REFUSE to start: a Vault token on vault.store")
    assert "allow_over_granted_store_principal" in verdict


def test_serve_verdict_names_an_accepted_vault_grant() -> None:
    settings = _VAULT_SETTINGS.model_copy(
        update={"security": SecuritySettings(allow_over_granted_vault_token=True)}
    )
    verdict = serve_verdict(_sqlite_report(), settings, [_hop(policies=("root",))])
    assert verdict.startswith("would start")
    assert "vault.store" in verdict and "accepted" in verdict


def test_serve_verdict_says_a_warning_class_grant_does_not_refuse() -> None:
    caps = _least_caps() | {f"transit/keys/{_KEK}": ["list", "read"]}
    verdict = serve_verdict(_sqlite_report(), _VAULT_SETTINGS, [_hop(caps=caps)])
    assert verdict.startswith("would start")
    assert "vault.store warns only" in verdict


def test_serve_verdict_never_calls_an_unread_vault_hop_a_warning() -> None:
    """A run without the token (a scheduled task) says nothing about the token serve will read."""
    blind = _hop(lookup_error=ConnectionError("vault.invalid"))
    verdict = serve_verdict(_sqlite_report(), _VAULT_SETTINGS, [blind])
    assert "vault.store could not be read here" in verdict
    assert "warns only" not in verdict


def test_serve_verdict_under_warn_refuses_nothing() -> None:
    settings = _VAULT_SETTINGS.model_copy(
        update={"security": SecuritySettings(enforcement=SecurityEnforcement.WARN)}
    )
    verdict = serve_verdict(_sqlite_report(), settings, [_hop(policies=("root",))])
    assert not verdict.startswith("would REFUSE")


# --- the opt-out is a loosening (closing step 3) -----------------------------------------------


def _loosenings(security: SecuritySettings) -> dict[str, str]:
    return dict(
        security_loosenings(
            security,
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            path_form_fhir_hops=(),
            ech_cleartext_sidecar_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            cert_monitor=CertMonitorSettings(),
            backup=BackupSettings(),
            secrets=SecretsSettings(),
            ai=AiSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
            service_env=None,
        )
    )


def test_the_opt_out_is_named_as_a_loosening() -> None:
    assert "allow_over_granted_vault_token" not in _loosenings(SecuritySettings())
    named = _loosenings(SecuritySettings(allow_over_granted_vault_token=True))
    assert "ADR 0216" in named["allow_over_granted_vault_token"]


# --- the lifespan seam (closing step 1), end to end through the real probe ---------------------


def _vault_env(monkeypatch: pytest.MonkeyPatch, vault: _FakeVault) -> None:
    for name in ("VAULT_TOKEN", "VAULT_ADDR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", _VAULT_ADDR)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", _KEK)
    monkeypatch.setattr(keyprovider_vault, "_build_client", lambda a, t, **_: vault)


def _managed_app(tmp_path: Path, security: SecuritySettings) -> Any:
    from messagefoundry.api.app import create_managed_app
    from messagefoundry.config.settings import AiSettings

    # The store itself is SQLite; only the resolved service settings name a Vault consumer, so the
    # store open makes no Vault call and the probe is the only thing that reaches the fake.
    security = security.model_copy(
        update={
            "allow_unencrypted_phi": True,
            "allow_unencrypted_phi_under_strict_enforcement": True,
        }
    )
    settings = _VAULT_SETTINGS.model_copy(update={"security": security})
    return create_managed_app(
        store_settings=StoreSettings(
            path=str(tmp_path / "vault-preflight.db"), allow_unencrypted_phi=True
        ),
        allow_no_auth=True,
        ai_settings=AiSettings(),
        security_settings=security,
        static_credential_settings=settings,
        egress_settings=EgressSettings(deny_by_default=False),
    )


def test_serve_refuses_to_start_on_a_root_vault_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The defect itself: before this change the lifespan never probed, and this started."""
    from starlette.testclient import TestClient

    vault = _FakeVault(policies=("root",))
    _vault_env(monkeypatch, vault)
    app = _managed_app(tmp_path, SecuritySettings())
    with pytest.raises(VaultPrivilegeError, match="vault.store"), TestClient(app):
        pass
    assert vault.asked, "the lifespan must probe the token through the engine's own client"


def test_serve_starts_on_a_least_privilege_vault_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the same wiring starts on a clean token, so the refusal above is the grant."""
    from starlette.testclient import TestClient

    vault = _FakeVault(caps=_least_caps())
    _vault_env(monkeypatch, vault)
    with TestClient(_managed_app(tmp_path, SecuritySettings())):
        pass
    assert vault.asked


def test_serve_starts_on_a_root_vault_token_with_the_opt_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from starlette.testclient import TestClient

    vault = _FakeVault(policies=("root",))
    _vault_env(monkeypatch, vault)
    with TestClient(_managed_app(tmp_path, SecuritySettings(allow_over_granted_vault_token=True))):
        pass
    assert vault.asked


# --- slice B: the alert, and the clean read that resolves it -----------------------------------


class _RecordingSink:
    """Records the two calls the preflight makes; stands in for any ``AlertSink``."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.cleared: list[str] = []

    def vault_privilege_warning(
        self, name: str, *, finding: str, refusing_count: int, detail: str
    ) -> None:
        self.events.append(
            {"name": name, "finding": finding, "refusing_count": refusing_count, "detail": detail}
        )

    def vault_privilege_clean(self, name: str) -> None:
        self.cleared.append(name)


class _RaisingSink(_RecordingSink):
    def vault_privilege_warning(
        self, name: str, *, finding: str, refusing_count: int, detail: str
    ) -> None:
        raise RuntimeError("sink down")


async def _run(vault: _FakeVault, sink: Any, *, enforcing: bool, accepted: bool = False) -> Any:
    return await run_vault_privilege_preflight(
        _VAULT_SETTINGS,
        _AuditStore(),
        enforcing=enforcing,
        over_grant_accepted=accepted,
        probe=_probe(vault),
        alert_sink=sink,
    )


async def test_a_grave_grant_under_warn_raises_the_alert() -> None:
    """The row's closing step 3, alert half. RED before slice B: the preflight took no sink."""
    sink = _RecordingSink()
    await _run(_FakeVault(policies=("root",)), sink, enforcing=False)
    [event] = sink.events
    assert event["name"] == "vault:store"
    assert event["finding"] == "over_granted"
    assert event["refusing_count"] == 1
    assert "the token carries the root policy" in event["detail"]
    assert sink.cleared == []
    assert _TOKEN not in json.dumps(sink.events)


async def test_a_warning_class_grant_alerts_with_no_refusing_grant() -> None:
    sink = _RecordingSink()
    caps = _least_caps() | {f"transit/keys/{_KEK}": ["list", "read"]}
    await _run(_FakeVault(caps=caps), sink, enforcing=True)
    assert [(e["finding"], e["refusing_count"]) for e in sink.events] == [("over_granted", 0)]


async def test_an_unobservable_probe_alerts_under_its_own_finding() -> None:
    sink = _RecordingSink()
    await _run(_FakeVault(lookup_error=ConnectionError("vault.invalid")), sink, enforcing=True)
    assert [e["finding"] for e in sink.events] == ["unobservable"]
    assert sink.cleared == []


async def test_a_clean_token_raises_the_inverse_and_no_alert() -> None:
    """The control for the three above: a least-privilege token pages nobody, and clears."""
    sink = _RecordingSink()
    await _run(_FakeVault(caps=_least_caps()), sink, enforcing=True)
    assert sink.events == []
    assert sink.cleared == ["vault:store"]


async def test_the_refusal_still_refuses_and_alerts_before_it_does() -> None:
    sink = _RecordingSink()
    with pytest.raises(VaultPrivilegeError):
        await _run(_FakeVault(policies=("root",)), sink, enforcing=True)
    assert [e["finding"] for e in sink.events] == ["over_granted"]


async def test_the_opt_out_quiets_no_alert() -> None:
    sink = _RecordingSink()
    await _run(_FakeVault(policies=("root",)), sink, enforcing=True, accepted=True)
    assert [e["refusing_count"] for e in sink.events] == [1]


async def test_a_failing_sink_never_masks_the_refusal(caplog: pytest.LogCaptureFixture) -> None:
    with (
        caplog.at_level(logging.ERROR, logger="messagefoundry.vault_preflight"),
        pytest.raises(VaultPrivilegeError),
    ):
        await _run(_FakeVault(policies=("root",)), _RaisingSink(), enforcing=True)
    assert any("alert sink raised" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    "state", [HopState.NOT_APPLICABLE, HopState.NOT_PROBED, HopState.NOT_CONFIGURED]
)
async def test_a_state_that_judged_nothing_raises_neither_alert(
    monkeypatch: pytest.MonkeyPatch, state: HopState
) -> None:
    """The preflight reads these as clean (vault_preflight_outcome), so a warning would page a
    finding nobody made, and a clean inverse would resolve one nobody re-read."""
    import messagefoundry.vault_preflight as vault_preflight

    raw = HopPrivilege("vault.store", state, "i", "m", "nothing judged")
    monkeypatch.setattr(vault_preflight, "vault_hops", lambda consumers, readings: [raw])
    sink = _RecordingSink()
    await _run(_FakeVault(caps=_least_caps()), sink, enforcing=True)
    assert sink.events == [] and sink.cleared == []


async def test_the_alert_detail_escapes_a_line_break_a_server_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hop's detail is kept as the server sent it; the alert's copy reaches a notifier body."""
    import messagefoundry.vault_preflight as vault_preflight

    raw = HopPrivilege("vault.store", HopState.OVER_GRANTED, "i", "m", "policy a\nALERT forged")
    monkeypatch.setattr(vault_preflight, "vault_hops", lambda consumers, readings: [raw])
    sink = _RecordingSink()
    await _run(_FakeVault(caps=_least_caps()), sink, enforcing=False)
    [event] = sink.events
    assert "\n" not in event["detail"] and "ALERT forged" in event["detail"]


def test_each_hop_is_its_own_subject() -> None:
    from messagefoundry.vault_preflight import vault_privilege_alert_subject

    store, secrets = (
        vault_hop(consumer, _reading(_FakeVault(caps=_least_caps()))) for consumer in (_STORE, _KV)
    )
    assert vault_privilege_alert_subject(store) == "vault:store"
    assert vault_privilege_alert_subject(secrets) == "vault:secrets"


def test_the_event_is_rule_targetable_and_its_inverse_resolves_it() -> None:
    """A name a sink emits but the rule validator refuses is silently un-routable."""
    from messagefoundry.config.settings import _ALERT_EVENT_TYPES, AlertRule
    from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, AlertRuleSet

    assert "vault_privilege_warning" in _ALERT_EVENT_TYPES
    decision = AlertRuleSet(
        [AlertRule(id="vault-rule", event_type="vault_privilege_warning")]
    ).decide({"type": "vault_privilege_warning", "connection": "vault:store"})
    # decide() never returns None: an unmatched event gets the default decision, with no rule id.
    assert decision.rule_id == "vault-rule"
    assert _AUTO_RESOLVE["vault_privilege_clean"] == "vault_privilege_warning"
    # The inverse is not a page, so a rule must not be able to target it.
    assert "vault_privilege_clean" not in _ALERT_EVENT_TYPES


def test_the_notifier_payload_carries_no_count_for_an_unread_token() -> None:
    from messagefoundry.pipeline.alert_sinks import NotifierAlertSink

    events: list[dict[str, Any]] = []

    class _Capture(NotifierAlertSink):
        def _emit(self, event: dict[str, Any]) -> None:
            events.append(event)

    sink = _Capture.__new__(_Capture)
    sink.vault_privilege_warning(
        "vault:store", finding="unobservable", refusing_count=0, detail="x"
    )
    sink.vault_privilege_warning(
        "vault:store", finding="over_granted", refusing_count=0, detail="y"
    )
    assert "refusing_count" not in events[0]
    assert events[1]["refusing_count"] == 0


def test_the_logging_sink_line_does_not_read_clean_for_an_unread_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sink's own logger is swapped for a recorder, as the store test does: caplog depends on
    logger state other tests in the same xdist worker may change."""
    import messagefoundry.pipeline.alerts as alerts_module
    from messagefoundry.pipeline.alerts import LoggingAlertSink

    lines: list[str] = []

    class _Recorder:
        def warning(self, msg: str, *args: object) -> None:
            lines.append(msg % args)

    monkeypatch.setattr(alerts_module, "log", _Recorder())
    sink = LoggingAlertSink()
    sink.vault_privilege_warning(
        "vault:store", finding="unobservable", refusing_count=0, detail="d"
    )
    sink.vault_privilege_warning(
        "vault:store", finding="over_granted", refusing_count=1, detail="d"
    )
    assert "ALERT vault_privilege_warning" in lines[0] and "not read" in lines[0]
    assert "0 grant" not in lines[0]
    assert "1 grant(s) in the refusing class" in lines[1]


async def test_a_later_clean_start_resolves_the_open_alert(tmp_path: Path) -> None:
    """End to end through the real notifier and a real store: a warn-mode start on a root token
    opens an alert instance, and the next start on a least-privilege token resolves it."""
    from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
    from messagefoundry.store.store import MessageStore
    from tests.test_alert_state import _drain

    store = await MessageStore.open(tmp_path / "alerts.db")
    try:
        sink = NotifierAlertSink([], store=store)
        await _run(_FakeVault(policies=("root",)), sink, enforcing=False)
        await _drain(sink)
        [open_] = await store.list_active_alert_instances(allowed_channels=None)
        assert (open_.event_type, open_.connection) == ("vault_privilege_warning", "vault:store")

        await _run(_FakeVault(caps=_least_caps()), sink, enforcing=False)
        await _drain(sink)
        assert list(await store.list_active_alert_instances(allowed_channels=None)) == []
    finally:
        await store.close()


def test_serve_hands_the_alert_sink_to_the_vault_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The alert is only as good as its wiring: through the lifespan, with no notifier configured,
    the logging sink gets the warning, and the refused start raised it first."""
    from starlette.testclient import TestClient

    from messagefoundry.pipeline.alerts import LoggingAlertSink

    raised: list[str] = []

    def record(self: object, name: str, **kw: Any) -> None:
        raised.append(f"{name} {kw['finding']}")

    monkeypatch.setattr(LoggingAlertSink, "vault_privilege_warning", record)
    _vault_env(monkeypatch, _FakeVault(policies=("root",)))
    app = _managed_app(tmp_path, SecuritySettings())
    with pytest.raises(VaultPrivilegeError), TestClient(app):
        pass
    assert raised == ["vault:store over_granted"]
