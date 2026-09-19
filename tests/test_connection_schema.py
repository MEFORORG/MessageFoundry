# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`connection schema --json` — the engine-derived connection catalogue the VS Code editor renders.

The editor used to enumerate transports and settings by hand in TypeScript: 9 of 11 transports, and
per-transport field hints for 6, against the ~200 keyword-only parameters the factories accept. A
setting added to the engine simply never appeared in the GUI, and nothing failed.

The anti-rot guarantee is `test_every_factory_parameter_is_emitted`: every keyword-only parameter of
every registered transport factory must reach the schema. Add a setting to `wiring.py` and it shows
up in the form; miss one and this test fails rather than the field quietly not existing."""

from __future__ import annotations

import copy
import inspect
import json
import re
import subprocess
import sys
from typing import Any

import pytest

from messagefoundry.config.connection_schema import SCHEMA_VERSION, build_schema
from messagefoundry.config.connections_file import _INBOUND_KEYS, _OUTBOUND_KEYS, _TRANSPORTS
from messagefoundry.config.wiring import _is_secret_setting


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return build_schema()


def test_schema_version_is_reported(schema: dict[str, Any]) -> None:
    assert schema["schemaVersion"] == SCHEMA_VERSION


def test_every_registered_transport_is_described(schema: dict[str, Any]) -> None:
    assert set(schema["transports"]) == set(_TRANSPORTS)


def test_every_factory_parameter_is_emitted(schema: dict[str, Any]) -> None:
    """THE anti-rot gate: a setting the engine accepts but the schema omits is invisible in the GUI."""
    for name, factory in _TRANSPORTS.items():
        expected = {
            param
            for param, spec in inspect.signature(factory).parameters.items()
            if spec.kind is inspect.Parameter.KEYWORD_ONLY
        }
        emitted = set(schema["transports"][name]["params"])
        assert emitted == expected, f"{name}: schema/factory drift {expected ^ emitted}"


def test_direction_key_sets_mirror_the_loader(schema: dict[str, Any]) -> None:
    assert set(schema["directionKeys"]["inbound"]) == set(_INBOUND_KEYS)
    assert set(schema["directionKeys"]["outbound"]) == set(_OUTBOUND_KEYS)


def test_secret_flag_matches_the_engine_predicate(schema: dict[str, Any]) -> None:
    """The GUI must never offer a plaintext value box for a credential, so this flag is load-bearing."""
    for transport in schema["transports"].values():
        for param, spec in transport["params"].items():
            assert spec["secret"] == _is_secret_setting(param), param


def test_known_credentials_are_flagged_secret(schema: dict[str, Any]) -> None:
    params = schema["transports"]
    assert params["soap"]["params"]["ws_password"]["secret"] is True
    assert params["sftp"]["params"]["private_key"]["secret"] is True
    assert params["mllp"]["params"]["tls_key_password"]["secret"] is True
    assert params["mllp"]["params"]["host"]["secret"] is False


def test_annotations_resolve_to_types_not_strings(schema: dict[str, Any]) -> None:
    """wiring.py uses `from __future__ import annotations`; without eval_str every type is unknown."""
    mllp = schema["transports"]["mllp"]["params"]
    assert mllp["port"]["type"] == "int"
    assert mllp["tls"]["type"] == "bool"
    assert mllp["host"]["type"] == "str"
    assert mllp["connect_timeout"]["type"] == "float"


def test_env_capability_is_detected(schema: dict[str, Any]) -> None:
    """`host` accepts env(); `tls` does not. The form only offers an env-ref control where legal."""
    mllp = schema["transports"]["mllp"]["params"]
    assert mllp["host"]["env"] is True
    assert mllp["port"]["env"] is True
    assert mllp["tls"]["env"] is False


def test_multiline_parameter_comment_is_captured(schema: dict[str, Any]) -> None:
    """`tls_key_password`'s declaration spans three lines with the comment on the LAST one.

    A first-physical-line scrape loses exactly these — which are disproportionately the TLS and
    credential parameters — so the span-based attribution is pinned here."""
    help_text = schema["transports"]["mllp"]["params"]["tls_key_password"]["help"]
    assert "passphrase" in help_text.lower()
    assert "env()" in help_text


def test_direction_markers_are_parsed(schema: dict[str, Any]) -> None:
    """`# OUTBOUND: ...` on a parameter means the form should only offer it in that direction."""
    mllp = schema["transports"]["mllp"]["params"]
    assert mllp["host"]["direction"] == "outbound"
    assert mllp["tls_verify"]["direction"] == "outbound"
    assert mllp["encoding"]["direction"] is None  # applies to both


def test_required_is_true_only_without_a_default(schema: dict[str, Any]) -> None:
    mllp = schema["transports"]["mllp"]["params"]
    assert mllp["port"]["required"] is True  # no default -> the factory raises without it
    assert mllp["host"]["required"] is False  # defaults to None (mandatory outbound via the hint)
    assert mllp["host"]["requiredHint"] is True


def test_defaults_are_json_safe(schema: dict[str, Any]) -> None:
    json.dumps(schema)  # raises TypeError if any default leaked a non-JSON object


#: A setting the GUI is drawing a field for cannot also be a setting nothing can populate: every
#: emitted parameter IS a keyword-only parameter of a registered factory, which
#: `test_every_factory_parameter_is_emitted` establishes as an equality. So these claims are
#: self-contradictory wherever they appear in emitted text, whatever their wording elsewhere.
_UNSETTABLE_CLAIM = re.compile(
    r"could not be reached|cannot be reached|no factory parameter", re.IGNORECASE
)
#: Narrower: true of a `codeFirstOnly` parameter, which connections.toml genuinely cannot express,
#: so it is only a contradiction for the rest.
_NO_TOML_CLAIM = re.compile(r"no connections\.toml key", re.IGNORECASE)

#: A reference into the maintainer-internal ledger, in either spelling used in `wiring.py` comments.
_LEDGER_REFERENCE = re.compile(r"(?:BACKLOG\s*)?#\s*\d{2,}", re.IGNORECASE)


def _unreachability_claims(schema: dict[str, Any]) -> list[str]:
    """Emitted strings telling the form that a setting it is rendering cannot be set."""
    found: list[str] = []
    for transport, described in sorted(schema["transports"].items()):
        for param, spec in sorted(described["params"].items()):
            patterns = [_UNSETTABLE_CLAIM]
            if not spec.get("codeFirstOnly"):
                patterns.append(_NO_TOML_CLAIM)
            for field in ("section", "help"):
                text = spec.get(field) or ""
                if any(pattern.search(text) for pattern in patterns):
                    found.append(f"{transport}.{param}.{field}")
    return found


def test_no_emitted_text_tells_the_form_a_rendered_setting_cannot_be_set(
    schema: dict[str, Any],
) -> None:
    """The form is not a hand-written mirror: a section heading IS a comment out of `wiring.py`.

    `_param_comments` promotes the own-line comment block preceding a parameter into that
    parameter's `section`, so a note an author wrote for the next maintainer is rendered to an
    operator as the heading above the input. MLLP's rate-pacing block was one: it kept explaining
    that the pacer existed and no factory parameter or `connections.toml` key could populate it,
    for the whole period after both keys became `MLLP()` parameters (BACKLOG #1249). A deploying
    operator would have been told the control could not be reached while looking at the box that
    reaches it.

    Unlike a phrase screen over prose, the contradiction here is structural: a parameter reaches
    the schema only by BEING a keyword-only parameter of a registered factory, so no emitted string
    about it may say it is unreachable. The `codeFirstOnly` carve-out is the one honest exception --
    those really cannot be written in `connections.toml`."""
    claims = _unreachability_claims(schema)
    assert not claims, (
        f"these emitted strings tell the connection form that a setting it renders cannot be set: "
        f"{claims}. Every emitted parameter is a live factory parameter, so the text is stale -- "
        "move the history into the factory's docstring, which the schema does not read past its "
        "first paragraph."
    )


def test_the_unreachability_check_fails_on_the_claim_it_was_cut_from(
    schema: dict[str, Any],
) -> None:
    """Proves the check above can fail, by replanting the retired MLLP sentence into the schema."""
    retired = (
        "INBOUND message-RATE pacing. The connector has read both keys since the pacer was built -- "
        "until now no factory parameter and no connections.toml key could populate them, so the "
        "setting existed and could not be reached."
    )
    planted = copy.deepcopy(schema)
    planted["transports"]["mllp"]["params"]["max_messages_per_second"]["section"] = retired
    assert _unreachability_claims(planted) == ["mllp.max_messages_per_second.section"], (
        "the check does not see the exact string this guard was written against -- it is not a guard"
    )
    assert _unreachability_claims(schema) == [], (
        "the check already fires on the shipped schema, so a green run above proves nothing"
    )


def test_the_mllp_pacing_section_carries_no_internal_ledger_number(
    schema: dict[str, Any],
) -> None:
    """The ledger is maintainer-internal; a `section` string is operator-facing in a GUI.

    MLLP's rate-pacing heading carried one, so it is pinned here along with the wording fix. SCOPE,
    stated plainly rather than implied: this pins the two MLLP pacing parameters ONLY. A census of
    the whole emitted schema on 2026-09-19 found 40 strings across 11 transports carrying a `#NNN`
    or `BACKLOG #NNN` reference -- the raw-TCP and HTTP pacing sections among them. Widening this
    assertion to the schema is a separate sweep with its own row, and pinning a COUNT here would go
    red for everyone the first time somebody legitimately edits an unrelated comment."""
    params = schema["transports"]["mllp"]["params"]
    for name in ("max_messages_per_second", "message_burst"):
        for field in ("section", "help"):
            text = params[name].get(field) or ""
            assert not _LEDGER_REFERENCE.search(text), (
                f"mllp.{name}.{field} puts an internal ledger reference in front of an operator: "
                f"{text!r}. The maintainer trail belongs in the factory docstring."
            )
    # The check must be able to see one: the same pattern over a planted string.
    assert _LEDGER_REFERENCE.search("INBOUND message-RATE pacing (BACKLOG #1249)."), (
        "the ledger pattern does not match the reference this guard was written against"
    )


def test_cli_emits_schema_without_a_config_dir(tmp_path: Any) -> None:
    """`connection schema` describes the ENGINE: it must not need (or read) a config directory.

    Run from an empty cwd with no --config, so a workspace whose modules do not import — or which
    would trip the Windows config-source trust check (ADR 0036) — can still draw the form."""
    proc = subprocess.run(
        [sys.executable, "-m", "messagefoundry", "connection", "schema", "--json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schemaVersion"] == SCHEMA_VERSION
    assert set(payload["transports"]) == set(_TRANSPORTS)
