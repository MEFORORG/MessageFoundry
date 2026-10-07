# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The three hop-policy flags are read as strict bools by the factories and seams (vault BACKLOG #2232).

``tls_hop_attested``, ``tls_revocation_attested`` and ``cleartext_accepted`` were read with
``bool(...)``. ``bool("false")`` is ``True``, so the string ``"false"`` would have counted as the flag
SET. ``connections.toml`` already refused a non-bool (``connections_file._require_bool``), and the
code-first ``tls_hop_attested`` factories did too. Two gaps remained, both pinned here:

* a code-first ``FhirLookup(cleartext_accepted="false", cleartext_reason=...)`` loaded, and the
  runner mirrored the flag into the lookup's settings as ``True``, so the read hop would have
  crossed as an accepted cleartext hop; the same held for ``tls_revocation_attested``;
* every settings-driven seam read the mirrored key with ``bool(...)``, so a mapping written past the
  factories would have been honoured on a truthy string.

One strict reader, ``models.flag_from_settings``, now serves the seams that gate a hop, and the
shared flag-with-reason check refuses a non-bool flag at load, naming the key.

A strict reader AFTER ``env()`` resolves is not enough. A ``FhirLookup``, ``DatabaseLookup`` or
``DatabaseRef`` keeps its settings in a mutable dict, and ``env(..., cast=bool)`` written there after
the factory resolves ``"false"`` to a real ``True``. So ``wiring.refuse_unresolved_hop_flags`` refuses
any raw flag that is not ``None`` or a real bool, an ``EnvRef`` included, at every place a carrier is
read at load. The loosening report ``attested_secure_hops`` must not raise, so it fails toward
listing: any flag that is not ``None`` or ``False`` is listed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import (
    flag_from_settings,
    hop_attestation_from_settings,
    require_flag,
)
from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.tls_policy import MIRRORED_CONNECTION_SETTING
from messagefoundry.config.wiring import (
    MLLP,
    DatabaseLookupSpec,
    FhirLookupSpec,
    Ftp,
    Registry,
    Rest,
    WiringError,
    attested_secure_hops,
    build_inbound_connection,
    build_outbound_connection,
    env,
    load_config,
    refuse_unresolved_hop_flags,
)
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    _fhir_lookup_settings,
    build_check_registry,
)
from messagefoundry.transports.http_auth import (
    digest_handler_from_settings,
    oauth2_cc_provider_from_settings,
)
from messagefoundry.transports.remotefile import _anon_ftp_guard
from messagefoundry.transports.rest import HttpAuthError, cleartext_acceptance_from_settings
from messagefoundry.transports.smart import (
    SmartAuthError,
    revocation_attestation_from_settings,
    token_provider_from_settings,
)

REASON = "TLS terminates at the site's stunnel sidecar"
FLAGS = ("tls_hop_attested", "tls_revocation_attested", "cleartext_accepted")
# The flag and the reason key each one pairs with.
REASON_KEY = {
    "tls_hop_attested": "tls_hop_attested_reason",
    "tls_revocation_attested": "tls_revocation_attested_reason",
    "cleartext_accepted": "cleartext_reason",
}


# --- the reader itself ----------------------------------------------------------------------


@pytest.mark.parametrize("key", FLAGS)
def test_reader_refuses_the_string_false_naming_the_key(key: str) -> None:
    with pytest.raises(ValueError, match=rf"^{key} must be true or false, not str$"):
        flag_from_settings({key: "false"}, key)


@pytest.mark.parametrize("value", ["true", 1, 0, "", env("MEFOR_X")])
def test_reader_refuses_every_non_bool(value: object) -> None:
    with pytest.raises(ValueError, match="tls_hop_attested must be true or false"):
        flag_from_settings({"tls_hop_attested": value}, "tls_hop_attested")


@pytest.mark.parametrize("key", FLAGS)
def test_reader_absent_or_none_means_false_and_a_real_bool_passes(key: str) -> None:
    assert flag_from_settings({}, key) is False
    assert flag_from_settings({key: None}, key) is False
    assert flag_from_settings({key: False}, key) is False
    assert flag_from_settings({key: True}, key) is True


def test_require_flag_returns_a_real_bool_unchanged() -> None:
    assert require_flag(True, "k") is True
    assert require_flag(False, "k") is False


def test_hop_attestation_from_settings_refuses_the_string_false() -> None:
    # The DB lookup / reference-source reader, which has no typed model in front of it.
    with pytest.raises(ValueError, match="tls_hop_attested must be true or false"):
        hop_attestation_from_settings({"tls_hop_attested": "false", "tls_hop_attested_reason": "r"})


# --- the settings-driven seams --------------------------------------------------------------


def test_rest_cleartext_reader_refuses_the_string_false() -> None:
    with pytest.raises(ValueError, match="cleartext_accepted must be true or false"):
        cleartext_acceptance_from_settings({"cleartext_accepted": "false", "cleartext_reason": "r"})


def test_smart_revocation_reader_refuses_the_string_false() -> None:
    with pytest.raises(ValueError, match="tls_revocation_attested must be true or false"):
        revocation_attestation_from_settings(
            {"tls_revocation_attested": "false", "tls_revocation_attested_reason": "r"}
        )


def test_digest_seam_refuses_the_string_false_before_it_decides_the_hop() -> None:
    # Before the fix, bool("false") attested the cleartext digest hop and the handler was built.
    with pytest.raises(ValueError, match="tls_hop_attested must be true or false"):
        digest_handler_from_settings(
            {
                "http_auth": "digest",
                "http_auth_user": "u",
                "http_auth_password": "p",
                "tls_hop_attested": "false",
            },
            url="http://api.example.com/x",
        )


def test_anonymous_ftp_guard_refuses_the_string_false() -> None:
    settings = {
        "host": "ftp.example.com",
        "remote_dir": "/in",
        "protocol": "ftp",
        "tls_hop_attested": "false",
        "tls_hop_attested_reason": "r",
    }
    with pytest.raises(ValueError, match="tls_hop_attested must be true or false"):
        _anon_ftp_guard(settings, connection=None)


def test_anonymous_ftp_guard_still_honours_a_real_bool() -> None:
    settings: dict[str, Any] = {"host": "ftp.example.com", "remote_dir": "/in", "protocol": "ftp"}
    guard = _anon_ftp_guard(
        {**settings, "tls_hop_attested": True, "tls_hop_attested_reason": REASON}, connection=None
    )
    assert guard is not None and guard.attested is True
    unattested = _anon_ftp_guard(settings, connection=None)
    assert unattested is not None and unattested.attested is False


# --- the code-first factories ---------------------------------------------------------------


def _rest() -> Any:
    return Rest(url="https://api.example.com/x")


def _ftp() -> Any:
    return Ftp(host="ftp.example.com", remote_dir="/out")


@pytest.mark.parametrize("make_spec", [_rest, _ftp], ids=["Rest", "Ftp"])
@pytest.mark.parametrize("key", FLAGS)
def test_outbound_factory_refuses_the_string_false_naming_the_key(make_spec: Any, key: str) -> None:
    kwargs: dict[str, Any] = {key: "false", REASON_KEY[key]: REASON}
    with pytest.raises(
        WiringError, match=rf"outbound connection 'OB'.*{key} must be true or false"
    ):
        build_outbound_connection("OB", make_spec(), **kwargs)


def test_inbound_factory_refuses_a_string_revocation_attestation() -> None:
    with pytest.raises(
        WiringError, match=r"inbound connection 'IB'.*tls_revocation_attested must be true or false"
    ):
        build_inbound_connection(
            "IB",
            MLLP(port=2575),
            router="r",
            tls_revocation_attested="false",  # type: ignore[arg-type]
            tls_revocation_attested_reason=REASON,
        )


@pytest.mark.parametrize("key", FLAGS)
def test_outbound_factory_still_takes_a_real_bool(key: str) -> None:
    on_kwargs: dict[str, Any] = {key: True, REASON_KEY[key]: REASON}
    off_kwargs: dict[str, Any] = {key: False}
    on = build_outbound_connection("OB", _rest(), **on_kwargs)
    assert getattr(on, key) is True
    off = build_outbound_connection("OB", _rest(), **off_kwargs)
    assert getattr(off, key) is False
    absent = build_outbound_connection("OB", _rest())
    assert getattr(absent, key) is False


@pytest.mark.parametrize("key", ["cleartext_accepted", "tls_revocation_attested"])
def test_fhir_lookup_refuses_the_string_false_at_load(tmp_path: Path, key: str) -> None:
    # The hole the row named, measured before the fix: this loaded, and the runner mirrored the
    # flag into the lookup's settings as True.
    (tmp_path / "lookup.py").write_text(
        "from messagefoundry import FhirLookup\n"
        f'FhirLookup("epic", url="http://fhir.example.org/fhir", {key}="false", '
        f'{REASON_KEY[key]}="{REASON}")\n',
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match=rf"fhir lookup 'epic'.*{key} must be true or false"):
        load_config(tmp_path, allow_empty=True)


def test_fhir_lookup_still_takes_a_real_bool(tmp_path: Path) -> None:
    (tmp_path / "lookup.py").write_text(
        "from messagefoundry import FhirLookup\n"
        'FhirLookup("epic", url="http://fhir.example.org/fhir", cleartext_accepted=True, '
        f'cleartext_reason="{REASON}")\n',
        encoding="utf-8",
    )
    reg = load_config(tmp_path, allow_empty=True)
    assert reg.fhir_lookups["epic"].cleartext_accepted is True


# --- the seams a factory-level test cannot reach --------------------------------------------
# Each of these runs only on settings written past the factories, so the factory refusal above
# never reaches them. Each test fails if its read goes back to bool(...).


def test_oauth2_provider_refuses_the_string_false() -> None:
    settings = {
        "oauth2_token_url": "https://auth.example.com/token",
        "oauth2_client_id": "c",
        "oauth2_client_secret": "s",
        "tls_hop_attested": "false",
    }
    with pytest.raises(ValueError, match="tls_hop_attested must be true or false"):
        oauth2_cc_provider_from_settings(settings)


def test_smart_provider_refuses_the_string_false() -> None:
    settings = {
        "smart_token_url": "https://auth.example.com/token",
        "smart_client_id": "c",
        "smart_private_key": "not-read-before-the-flag",
        "tls_hop_attested": "false",
    }
    with pytest.raises(ValueError, match="tls_hop_attested must be true or false"):
        token_provider_from_settings(settings)


def test_digest_seam_keeps_its_error_contract() -> None:
    with pytest.raises(HttpAuthError, match="cleartext_accepted must be true or false"):
        digest_handler_from_settings(
            {
                "http_auth": "digest",
                "http_auth_user": "u",
                "http_auth_password": "p",
                "cleartext_accepted": "false",
            },
            url="http://api.example.com/x",
        )


def test_a_directly_built_fhir_lookup_spec_refuses_a_string_attestation() -> None:
    with pytest.raises(WiringError, match=r"fhir lookup 'LK'.*tls_hop_attested must be true or"):
        FhirLookupSpec("LK", {"tls_hop_attested": "false", "tls_hop_attested_reason": "r"})


def test_a_directly_built_fhir_lookup_spec_refuses_an_attestation_with_no_reason() -> None:
    with pytest.raises(WiringError, match="tls_hop_attested=true requires tls_hop_attested_reason"):
        FhirLookupSpec("LK", {"tls_hop_attested": True})
    spec = FhirLookupSpec("LK", {"tls_hop_attested": True, "tls_hop_attested_reason": REASON})
    assert spec.settings["tls_hop_attested"] is True


def test_the_lookup_settings_builder_refuses_a_string_written_after_the_factory(
    tmp_path: Path,
) -> None:
    (tmp_path / "lookup.py").write_text(
        "from messagefoundry import FhirLookup\n"
        'FhirLookup("epic", url="https://fhir.example.org/fhir")\n',
        encoding="utf-8",
    )
    spec = load_config(tmp_path, allow_empty=True).fhir_lookups["epic"]
    spec.settings["tls_hop_attested"] = "false"
    with pytest.raises(WiringError, match=r"fhir lookup 'epic'.*tls_hop_attested must be true or"):
        _fhir_lookup_settings(spec, {}, EgressSettings())


# --- a flag written into a settings carrier after its factory (review of PR 2075) -----------
# `env("att", cast=bool)` resolves the environment value "false" to True, because bool("false") is
# True. The strict reader then sees a real bool and honours it. So the raw flag is refused before
# env() resolves, at each place a carrier is read at load.

#: The environment value an operator writes to switch the flag OFF.
_ENV_OFF = {"att": "false"}

_CARRIER_MODULE = (
    "from messagefoundry import DatabaseLookup, DatabaseRef, FhirLookup, Reference\n"
    'FhirLookup("epic", url="https://fhir.example.org/fhir")\n'
    'DatabaseLookup("clar", server="db.example.org", database="d")\n'
    'Reference("codes", source=DatabaseRef(server="db.example.org", database="d", '
    'statement="SELECT code FROM t", key_column="code"))\n'
)

_CARRIERS = ("fhir lookup 'epic'", "database lookup 'clar'", "reference set 'codes'")


def _carriers(tmp_path: Path) -> Registry:
    (tmp_path / "carriers.py").write_text(_CARRIER_MODULE, encoding="utf-8")
    return load_config(tmp_path, allow_empty=True)


def _carrier_settings(reg: Registry, carrier: str) -> dict[str, Any]:
    if carrier == "fhir lookup 'epic'":
        return reg.fhir_lookups["epic"].settings
    if carrier == "database lookup 'clar'":
        return reg.lookups["clar"].settings
    return reg.references["codes"].source.settings


def _write_env_flag(settings: dict[str, Any], key: str) -> None:
    settings[key] = env("att", cast=bool)
    settings[REASON_KEY[key]] = REASON


@pytest.mark.parametrize("key", FLAGS)
@pytest.mark.parametrize("carrier", _CARRIERS)
def test_build_check_refuses_an_env_flag_written_after_the_factory(
    tmp_path: Path, carrier: str, key: str
) -> None:
    reg = _carriers(tmp_path)
    _write_env_flag(_carrier_settings(reg, carrier), key)
    with pytest.raises(WiringError, match=rf"{carrier}: {key} must be true or false, not EnvRef"):
        build_check_registry(
            reg,
            inbound_bind_host="127.0.0.1",
            env_values=_ENV_OFF,
            egress=EgressSettings(deny_by_default=False),
        )


def test_build_check_refuses_an_unresolvable_env_flag_on_a_reference_too(tmp_path: Path) -> None:
    # A reference source whose env() values do not resolve is left to its sync. The flag refusal
    # needs no value, so it must run before that skip.
    reg = _carriers(tmp_path)
    _write_env_flag(_carrier_settings(reg, "reference set 'codes'"), "tls_hop_attested")
    with pytest.raises(WiringError, match=r"reference set 'codes': tls_hop_attested must be"):
        build_check_registry(
            reg,
            inbound_bind_host="127.0.0.1",
            env_values={},
            egress=EgressSettings(deny_by_default=False),
        )


@pytest.mark.parametrize("key", FLAGS)
def test_the_lookup_settings_builder_refuses_an_env_flag(tmp_path: Path, key: str) -> None:
    # The one builder both FhirLookup executor paths use (live start/reload and build_check).
    spec = _carriers(tmp_path).fhir_lookups["epic"]
    _write_env_flag(spec.settings, key)
    with pytest.raises(WiringError, match=rf"fhir lookup 'epic': {key} must be true or false"):
        _fhir_lookup_settings(spec, _ENV_OFF, EgressSettings())


@pytest.mark.parametrize("key", FLAGS)
def test_the_live_db_lookup_executor_build_refuses_an_env_flag(tmp_path: Path, key: str) -> None:
    reg = _carriers(tmp_path)
    _write_env_flag(reg.lookups["clar"].settings, key)
    store: Any = object()  # never reached: the refusal comes before any executor exists
    runner = RegistryRunner(
        reg, store, env_values=_ENV_OFF, egress=EgressSettings(deny_by_default=False)
    )
    with pytest.raises(WiringError, match=rf"database lookup 'clar': {key} must be true or false"):
        runner._build_lookup_executor()


@pytest.mark.parametrize("key", FLAGS)
def test_the_reference_sync_refuses_an_env_flag(tmp_path: Path, key: str) -> None:
    spec = _carriers(tmp_path).references["codes"]
    _write_env_flag(spec.source.settings, key)
    store: Any = object()  # never reached: the refusal comes before the dial and the snapshot
    runner = ReferenceSyncRunner(
        store,
        lambda: [spec],
        ReferenceSettings(),
        env_values=_ENV_OFF,
        egress=EgressSettings(deny_by_default=False),
    )
    with pytest.raises(WiringError, match=rf"reference set 'codes': {key} must be true or false"):
        asyncio.run(runner._sync_one(spec))


def test_a_real_bool_or_none_written_after_the_factory_passes_the_raw_check(
    tmp_path: Path,
) -> None:
    # Control arm: the refusal keys on the type, so the same write with a real bool is not refused.
    settings = _carrier_settings(_carriers(tmp_path), "database lookup 'clar'")
    for value in (True, False, None):
        for key in FLAGS:
            settings[key] = value
        # The attestation pair is checked too, so a set flag carries its reason.
        settings["tls_hop_attested_reason"] = REASON if value else None
        refuse_unresolved_hop_flags(settings, "database lookup 'clar'")


# --- the report fails toward listing --------------------------------------------------------


def test_the_attested_report_lists_any_flag_that_is_not_none_or_false() -> None:
    reg = Registry()
    reg.add_fhir_lookup(
        FhirLookupSpec("ON", {"tls_hop_attested": True, "tls_hop_attested_reason": REASON})
    )
    as_string = FhirLookupSpec("STR", {})
    as_string.settings["tls_hop_attested"] = "false"  # past the spec; the load check refuses it
    reg.add_fhir_lookup(as_string)
    reg.add_lookup(
        DatabaseLookupSpec(
            "ENV", {"tls_hop_attested": env("att", cast=bool), "tls_hop_attested_reason": REASON}
        )
    )
    reg.add_lookup(DatabaseLookupSpec("OFF", {"tls_hop_attested": False}))
    reg.add_lookup(DatabaseLookupSpec("NONE", {"tls_hop_attested": None}))
    reg.add_fhir_lookup(FhirLookupSpec("ABSENT", {}))
    assert [name for name, _ in attested_secure_hops(reg)] == [
        "db_lookup:ENV",
        "fhir_lookup:ON",
        "fhir_lookup:STR",
    ]


# --- the spec and the builder check the reason by the factory's rule ------------------------


@pytest.mark.parametrize(
    ("reason", "refusal"),
    [
        ("ok\nWARNING forged", "must not contain control characters"),
        (5, "tls_hop_attested_reason must be a string, not int"),
    ],
    ids=["control-character", "not-a-string"],
)
def test_a_directly_built_fhir_lookup_spec_checks_the_reason_like_the_factory(
    reason: object, refusal: str
) -> None:
    with pytest.raises(WiringError, match=rf"fhir lookup 'LK': .*{refusal}"):
        FhirLookupSpec("LK", {"tls_hop_attested": True, "tls_hop_attested_reason": reason})


@pytest.mark.parametrize("carrier", ["database lookup 'clar'", "reference set 'codes'"])
def test_build_check_holds_a_db_carrier_reason_to_the_factory_rule(
    tmp_path: Path, carrier: str
) -> None:
    # The DB carriers' own reader str()s the reason, so a control character written after the
    # factory would reach `check` output and the posture report. The load check refuses it, as it
    # does on a FhirLookup.
    reg = _carriers(tmp_path)
    settings = _carrier_settings(reg, carrier)
    settings["tls_hop_attested"] = True
    settings["tls_hop_attested_reason"] = "ok\nWARNING forged"
    with pytest.raises(WiringError, match=rf"{carrier}: .*must not contain control characters"):
        build_check_registry(
            reg,
            inbound_bind_host="127.0.0.1",
            env_values={},
            egress=EgressSettings(deny_by_default=False),
        )


def test_the_lookup_settings_builder_refuses_a_flag_with_no_reason() -> None:
    # The pair, not the flag alone: a flag set after the spec was built, with no reason, would
    # otherwise attest the hop with nothing for the audit record to say.
    spec = FhirLookupSpec("LK", {"url": "https://fhir.example.org/fhir"})
    spec.settings["tls_hop_attested"] = True
    with pytest.raises(
        WiringError,
        match="fhir lookup 'LK': tls_hop_attested=true requires tls_hop_attested_reason",
    ):
        _fhir_lookup_settings(spec, {}, EgressSettings())


# --- each credential seam raises its own refusal type, naming the connection ----------------


def test_the_oauth2_seam_raises_http_auth_error_naming_the_connection() -> None:
    settings = {
        "oauth2_token_url": "https://auth.example.com/token",
        "oauth2_client_id": "c",
        "oauth2_client_secret": "s",
        "tls_hop_attested": "false",
        MIRRORED_CONNECTION_SETTING: "OB_X",
    }
    with pytest.raises(
        HttpAuthError, match=r"^connection 'OB_X'; tls_hop_attested must be true or false"
    ):
        oauth2_cc_provider_from_settings(settings)


def test_the_smart_seam_raises_smart_auth_error_naming_the_connection() -> None:
    settings = {
        "smart_token_url": "https://auth.example.com/token",
        "smart_client_id": "c",
        "smart_private_key": "not-read-before-the-flag",
        "tls_revocation_attested": "false",
        MIRRORED_CONNECTION_SETTING: "OB_X",
    }
    with pytest.raises(
        SmartAuthError, match=r"^connection 'OB_X'; tls_revocation_attested must be true or false"
    ):
        token_provider_from_settings(settings)


def test_the_digest_seam_names_the_connection() -> None:
    with pytest.raises(
        HttpAuthError, match=r"^connection 'OB_X'; tls_hop_attested must be true or false"
    ):
        digest_handler_from_settings(
            {
                "http_auth": "digest",
                "http_auth_user": "u",
                "http_auth_password": "p",
                "tls_hop_attested": "false",
                MIRRORED_CONNECTION_SETTING: "OB_X",
            },
            url="http://api.example.com/x",
        )
