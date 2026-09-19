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
#: `test_every_factory_parameter_is_emitted` establishes as an equality. That equality is what makes
#: the claim self-contradictory; DETECTION is still a phrase set, so it is kept wide and the words
#: this repository actually reaches for are all in it -- "unreachable" included, since the prose
#: explaining the defect uses that word and would otherwise sail past its own guard.
#:
#: "unreachable" is ANCHORED TO ITS SUBJECT rather than taken bare. Bare, it matched the FTP and
#: SFTP `validate_directory` help ("fail-fast at start on an unreachable remote dir"), where the
#: unreachable thing is a directory on a remote host and the sentence is entirely correct.
_SETTING_WORD = r"(?:setting|keys?|control|pacer|parameter)s?"
_UNSETTABLE_CLAIM = re.compile(
    r"could not be reached|cannot be reached"
    rf"|{_SETTING_WORD}[^.]{{0,60}}?\bunreachable|\bunreachable[^.]{{0,20}}?{_SETTING_WORD}"
    r"|no factory parameter|nothing can populate|no surface can set"
    rf"|{_SETTING_WORD} cannot be set|no way to set"
    r"|not settable|no way to (?:turn|switch) (?:this |it )?on",
    re.IGNORECASE,
)
#: Narrower: true of a `codeFirstOnly` parameter, which connections.toml genuinely cannot express,
#: so it is only a contradiction for the rest. `\bnot\b` and `\bcannot\b` are anchored: written as a
#: bare `not.{0,20}in connections\.toml` this matched INSIDE "cannot", "annotation" and "another",
#: so an ordinary true sentence ("read as a string, not an int, in connections.toml") would have
#: reddened the guard and its message would have told the author to delete correct prose.
_NO_TOML_CLAIM = re.compile(
    r"no connections\.toml key|\bcannot\b.{0,20}in connections\.toml", re.IGNORECASE
)

#: A reference into the maintainer-internal ledger. Both spellings: with the hash (`BACKLOG #1249`,
#: `#1249`) and without it (`BACKLOG 1249`). An earlier draft wrote the hash form as
#: `(?:BACKLOG\s*)?#\d+`, where the optional prefix matched nothing the bare `#\d+` did not.
_LEDGER_REFERENCE = re.compile(r"#\s*\d{2,}|\bBACKLOG\s+\d{2,}", re.IGNORECASE)


def _unreachability_claims(schema: dict[str, Any]) -> list[str]:
    """Emitted strings telling the form that a setting it is rendering cannot be set.

    `doc` is screened alongside `section` and `help` because it is emitted too: `_summary` puts the
    factory docstring's FIRST paragraph there and the IDE renders it. Leaving it out would have made
    this guard's own remedy -- move the history into the docstring -- a way to reintroduce the defect
    with every test still green.

    `doc` is screened with `_UNSETTABLE_CLAIM` ONLY. A transport-level docstring covers every one of
    that transport's parameters at once, so there is no single `codeFirstOnly` flag to grade the
    `connections.toml` claim against -- and for a transport that HAS a code-first-only setting (SOAP's
    `body_secrets`) the claim would be true. Screening it there would demand the deletion of a correct
    sentence."""
    found: list[str] = []
    for transport, described in sorted(schema["transports"].items()):
        if _UNSETTABLE_CLAIM.search(described.get("doc") or ""):
            found.append(f"{transport}.doc")
        for param, spec in sorted(described["params"].items()):
            patterns = [_UNSETTABLE_CLAIM]
            if not spec.get("codeFirstOnly"):
                patterns.append(_NO_TOML_CLAIM)
            for field in ("section", "help"):
                text = spec.get(field) or ""
                if any(pattern.search(text) for pattern in patterns):
                    found.append(f"{transport}.{param}.{field}")
    return found


#: The fields these guards read must actually carry text. A comment restructure can move a heading
#: onto a different parameter (open the block with an `inbound:` marker, say, and `_param_comments`
#: appends the line to the PREVIOUS parameter's help instead of starting a section), at which point
#: every check below reads "" and passes covering nothing.
_PACING_SECTION_TOKEN = "message-RATE pacing"


def _shipped_pacing_section(schema: dict[str, Any]) -> str:
    """The MLLP pacing heading as shipped, proven non-empty so a guard over it cannot go vacuous."""
    section = schema["transports"]["mllp"]["params"]["max_messages_per_second"].get("section") or ""
    assert _PACING_SECTION_TOKEN in section, (
        "the MLLP pacing block no longer opens a `section` on max_messages_per_second "
        f"(got {section!r}). Every guard below reads that field, so they are passing on an empty "
        "string rather than on a clean heading -- re-aim them before trusting a green run."
    )
    return section


def test_no_emitted_text_tells_the_form_a_rendered_setting_cannot_be_set(
    schema: dict[str, Any],
) -> None:
    """The form is not a hand-written mirror: a section heading IS a comment out of `wiring.py`.

    `_param_comments` promotes the own-line comment block preceding a parameter into that
    parameter's `section`, so a note an author wrote for the next maintainer is rendered to an
    operator as the heading above the input. MLLP's rate-pacing block was one, and what it said is
    stated once in `MLLP()`'s docstring under "Inbound message-rate pacing" (BACKLOG #1249) rather
    than copied here: a deploying operator would have been told the control could not be reached
    while looking at the box that reaches it.

    What is structural here is the JUSTIFICATION, not the detection, and the difference matters to
    anyone deciding how much this guard is worth: a parameter reaches the schema only by BEING a
    keyword-only parameter of a registered factory, so the claim is self-contradictory wherever it
    appears -- but what finds it is still a list of phrases, and a fresh way of saying the same wrong
    thing passes. The `codeFirstOnly` carve-out is the one honest exception to the
    `connections.toml` half; those really cannot be written there."""
    _shipped_pacing_section(schema)  # the fields below carry text, so a pass is not vacuous
    claims = _unreachability_claims(schema)
    assert not claims, (
        f"these emitted strings tell the connection form that a setting it renders cannot be set: "
        f"{claims}. Every emitted parameter is a live factory parameter, so the text is stale -- "
        "move the history into a factory docstring paragraph AFTER the first, which is the part "
        "`_summary` does not emit. The first paragraph IS emitted, as `doc`, and is screened here."
    )


def test_the_unreachability_check_fails_on_the_claim_it_was_cut_from(
    schema: dict[str, Any],
) -> None:
    """Proves the check above can fail, by replanting the retired MLLP sentence into the schema.

    Planted in each of the three emitted fields in turn, because they are reached by different code
    paths: `section` and `help` per parameter, `doc` per transport."""
    retired = (
        "INBOUND message-RATE pacing. The connector has read both keys since the pacer was built -- "
        "until now no factory parameter and no connections.toml key could populate them, so the "
        "setting existed and could not be reached."
    )
    for target, expected in (
        (("params", "max_messages_per_second", "section"), "mllp.max_messages_per_second.section"),
        (("params", "message_burst", "help"), "mllp.message_burst.help"),
        (("doc",), "mllp.doc"),
    ):
        planted = copy.deepcopy(schema)
        node: Any = planted["transports"]["mllp"]
        for step in target[:-1]:
            node = node[step]
        node[target[-1]] = retired
        assert _unreachability_claims(planted) == [expected], (
            f"planting the retired sentence in {expected} produced "
            f"{_unreachability_claims(planted)} -- this field is not screened, so a green run says "
            "nothing about it"
        )
    assert _unreachability_claims(schema) == [], (
        "the check already fires on the shipped schema, so a green run above proves nothing"
    )


def test_the_mllp_pacing_section_carries_no_internal_ledger_number(
    schema: dict[str, Any],
) -> None:
    """The ledger is maintainer-internal; a `section` string is operator-facing in a GUI.

    MLLP's rate-pacing heading carried one, so it is pinned here along with the wording fix. SCOPE,
    stated plainly rather than implied: this pins the MLLP pacing block ONLY.

    Censused 2026-09-19 with `_LEDGER_REFERENCE` as defined above -- the needle is named because the
    count is a fact about it: **39 emitted strings across 10 of the 11 registered transports** carry a
    ledger reference (only `timer` carries none), the raw-TCP and HTTP pacing sections among them. 40
    before the MLLP fix in this change. An earlier draft of this docstring said "40 across 11", which
    was wrong in both halves at once -- it kept the pre-fix string count and reported the count of
    REGISTERED transports as the count of AFFECTED ones. Recorded rather than quietly corrected,
    because a wrong measurement in a docstring is the exact defect this change exists to fix.

    Widening this assertion to the schema is a separate sweep with its own row, and pinning a COUNT
    here would go red for everyone the first time somebody legitimately edits an unrelated comment.

    Only fields that actually carry text are asserted over. `message_burst` has no `section` of its
    own -- the engine emits a heading once, on the parameter that OPENS the block -- so asserting
    over it would have been an assertion that could not fail."""
    params = schema["transports"]["mllp"]["params"]
    subjects = {
        "max_messages_per_second.section": _shipped_pacing_section(schema),
        "max_messages_per_second.help": params["max_messages_per_second"]["help"],
        "message_burst.help": params["message_burst"]["help"],
    }
    for where, text in subjects.items():
        assert text, f"mllp.{where} is empty, so the assertion below cannot fail -- re-aim it"
        assert not _LEDGER_REFERENCE.search(text), (
            f"mllp.{where} puts an internal ledger reference in front of an operator: {text!r}. "
            "The maintainer trail belongs in a factory docstring paragraph after the first."
        )


def test_the_ledger_pattern_reads_the_field_and_not_just_a_literal(
    schema: dict[str, Any],
) -> None:
    """Proves the ledger guard fires off the SCHEMA, not off a string typed into the test.

    The earlier control ran the pattern over a literal in this file, which established that the
    regex compiles and nothing else: it would have passed against an empty schema. This plants each
    spelling into each of the three fields the guard asserts over, and reads them back out of the
    schema. Covering only the `section` would have left the two `help` reads unproven -- the same
    reason the sibling plant test walks every field it screens."""
    fields = (
        ("max_messages_per_second", "section"),
        ("max_messages_per_second", "help"),
        ("message_burst", "help"),
    )
    for reference in ("(BACKLOG #1249)", "(#1249)", "(BACKLOG 1249)"):
        for param, field in fields:
            planted = copy.deepcopy(schema)
            planted["transports"]["mllp"]["params"][param][field] = (
                f"INBOUND message-RATE pacing {reference}. Defaults to OFF."
            )
            read_back = planted["transports"]["mllp"]["params"][param][field]
            assert _LEDGER_REFERENCE.search(read_back), (
                f"the ledger pattern does not see {reference!r} in mllp.{param}.{field}"
            )
    for param, field in fields:
        text = schema["transports"]["mllp"]["params"][param][field]
        assert not _LEDGER_REFERENCE.search(text), (
            f"the pattern fires on the shipped mllp.{param}.{field}, so a green run proves nothing"
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
