# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The three hop-policy flags are read as strict bools on every path (vault BACKLOG #2232).

``tls_hop_attested``, ``tls_revocation_attested`` and ``cleartext_accepted`` were read with
``bool(...)``. ``bool("false")`` is ``True``, so the string ``"false"`` would have counted as the flag
SET. ``connections.toml`` already refused a non-bool (``connections_file._require_bool``), and the
code-first ``tls_hop_attested`` factories did too. Two gaps remained, both pinned here:

* a code-first ``FhirLookup(cleartext_accepted="false", cleartext_reason=...)`` loaded, and the
  runner mirrored the flag into the lookup's settings as ``True``, so the read hop would have
  crossed as an accepted cleartext hop; the same held for ``tls_revocation_attested``;
* every settings-driven seam read the mirrored key with ``bool(...)``, so a mapping written past the
  factories would have been honoured on a truthy string.

One strict reader, ``models.flag_from_settings``, now serves every seam, and the shared
flag-with-reason check refuses a non-bool flag at load, naming the key.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import (
    flag_from_settings,
    hop_attestation_from_settings,
    require_flag,
)
from messagefoundry.config.wiring import (
    MLLP,
    Ftp,
    Rest,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
    env,
    load_config,
)
from messagefoundry.transports.http_auth import digest_handler_from_settings
from messagefoundry.transports.remotefile import _anon_ftp_guard
from messagefoundry.transports.rest import cleartext_acceptance_from_settings
from messagefoundry.transports.smart import revocation_attestation_from_settings

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
