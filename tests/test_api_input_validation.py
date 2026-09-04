# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The operator API's input-validation rules (BACKLOG #1108, ASVS 2.1.1).

Three jobs, in order of what each protects:

1. **The rules do what they say.** Every constrained type accepts a legitimate value and refuses a
   structurally impossible one. Each rejection is paired with the acceptance that proves the check
   can still return the other answer -- a check that refuses everything is indistinguishable from a
   correct one until something legitimate arrives.
2. **The measurements the rules were drawn from stay true.** Four connection names shipped in this
   repository carry a hyphen; the connection-name rule was widened past the VS Code extension's
   grammar because of them. If one is renamed the rule may be narrowed, but nobody should discover
   that by accident.
3. **The document and the module cannot drift.** ``docs/API-INPUT-VALIDATION.md`` quotes every bound
   in prose. The drift check reads those numbers back out of the page and compares them to the
   module, and it carries its own control: doctored text must make it fail.

Synthetic only. No store, no network, no PHI.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from messagefoundry.api import validation as v
from messagefoundry.api.models import (
    DeadLetterReplayRequest,
    EditResendRequest,
    MessageExportRequest,
    MessageSearchRequest,
    ResendRequest,
)
from messagefoundry.auth.permissions import CUSTOM_ROLE_ID_PREFIX
from messagefoundry.parsing.peek import parse_path
from messagefoundry.uploads import _FILE_ID_RE

_REPO = Path(__file__).resolve().parents[1]
_DOC = _REPO / "docs" / "API-INPUT-VALIDATION.md"

_HEX32 = "0123456789abcdef" * 2
_HEX64 = _HEX32 * 2


def _accepts(alias: object, value: object) -> bool:
    """Whether the constrained alias accepts ``value``, decided by pydantic and nothing else."""

    class Probe(BaseModel):
        field: alias  # type: ignore[valid-type]

    try:
        Probe(field=value)
    except ValidationError:
        return False
    return True


# --- The pinned rules -----------------------------------------------------------------------------


def test_resource_id_is_thirty_two_lowercase_hex() -> None:
    assert v.RESOURCE_ID_PATTERN == r"^[0-9a-f]{32}$"
    assert _accepts(v.ResourceId, _HEX32)  # control: a real id is still accepted
    for bad in (
        _HEX32[:-1],  # one short
        _HEX32 + "0",  # one long
        _HEX32.upper(),  # wrong case
        "../../etc/passwd",
        _HEX32[:-2] + "..",
    ):
        assert not _accepts(v.ResourceId, bad), bad


def test_an_otherwise_valid_id_with_a_trailing_newline_is_refused() -> None:
    """Pydantic compiles ``pattern=`` with Rust's regex, where ``$`` is end-of-input.

    Python's ``re`` would let this through, which is why ``messagefoundry.uploads._FILE_ID_RE`` needs
    ``\\Z`` and this module does not. Both halves are asserted so neither can be "fixed" into the
    other's spelling without a red test.
    """
    assert _accepts(v.ResourceId, _HEX32)
    assert not _accepts(v.ResourceId, _HEX32 + "\n")
    assert _FILE_ID_RE.match(_HEX32) is not None
    assert _FILE_ID_RE.match(_HEX32 + "\n") is None
    assert r"\Z" not in v.RESOURCE_ID_PATTERN


def test_the_upload_file_id_rule_and_the_api_resource_id_rule_agree() -> None:
    """The API's id rule generalizes the one ``uploads.py`` already shipped; it must not narrow it."""
    for probe in (_HEX32, _HEX32.upper(), "not-an-id", ""):
        assert _accepts(v.ResourceId, probe) == (_FILE_ID_RE.match(probe) is not None), probe


def test_digest_id_is_sixty_four_lowercase_hex() -> None:
    assert v.DIGEST_ID_PATTERN == r"^[0-9a-f]{64}$"
    assert _accepts(v.DigestId, _HEX64)
    assert not _accepts(v.DigestId, _HEX32)
    assert not _accepts(v.DigestId, _HEX64.upper())


def test_custom_role_id_carries_the_prefix_the_auth_package_mints() -> None:
    assert v.CUSTOM_ROLE_ID_PATTERN == r"^custom:[0-9a-f]{32}$"
    assert CUSTOM_ROLE_ID_PREFIX == "custom:"
    assert _accepts(v.CustomRoleId, CUSTOM_ROLE_ID_PREFIX + _HEX32)
    assert not _accepts(v.CustomRoleId, _HEX32)  # a built-in role id is not a custom one
    assert not _accepts(v.CustomRoleId, "administrator")


# --- Connection names, and the measurement behind them --------------------------------------------

#: The connection names this repository ships that carry a hyphen. The VS Code extension's wizard
#: grammar (``ide/src/connectionWizardModel.ts``) rejects all four; the API rule admits them, and
#: that is the whole reason the two grammars differ.
HYPHENATED_SHIPPED_NAMES = (
    "FILE-OUT_ACME_ADT",
    "FILE-OUT_Coverage",
    "FILE-OUT_EXAMPLE_ADT",
    "FILE-OUT_Test_ADT",
)

#: The wizard's grammar, transcribed. Not imported -- it is TypeScript -- so it is pinned by the
#: assertion below that it rejects exactly the names the API rule accepts.
_IDE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def test_connection_name_admits_the_hyphenated_names_the_ide_grammar_rejects() -> None:
    assert v.CONNECTION_NAME_PATTERN == r"^[A-Za-z][A-Za-z0-9_-]{0,255}$"
    for name in HYPHENATED_SHIPPED_NAMES:
        assert _accepts(v.ConnectionName, name), name
        # The control: these names really are the disagreement, not an arbitrary set.
        assert _IDE_NAME_RE.match(name) is None, name
    # ...and the two rules still agree on an ordinary name, so the divergence is the hyphen alone.
    assert _accepts(v.ConnectionName, "IB_ACME_ADT")
    assert _IDE_NAME_RE.match("IB_ACME_ADT") is not None


def test_connection_name_refuses_what_would_carry_meaning_downstream() -> None:
    assert _accepts(v.ConnectionName, "OB_DEMO_ORU")
    for bad in (
        "",
        "../../etc/passwd",
        "IB/ACME",
        "IB\\ACME",
        "IB.ACME",
        "IB ACME",
        "IB'ACME",
        "IB%2FACME",
        "IB\nACME",
        "IB\x00ACME",
        "9_LEADING_DIGIT",
        "-LEADING_HYPHEN",
        "A" * 257,
    ):
        assert not _accepts(v.ConnectionName, bad), bad
    assert _accepts(v.ConnectionName, "A" * 256)  # the ceiling itself is legal


def test_the_shipped_connection_names_all_pass_the_rule() -> None:
    """A live sweep, so a newly-authored sample that breaks the rule reds here rather than in the API.

    The sweep's own control is the hyphenated set above: if the pattern that finds names stops
    matching anything, that assertion fails first and the empty sweep cannot read as a clean one.
    """
    found: set[str] = set()
    # ``[^"\n]`` so a match cannot run past the end of its line. Without it the pattern splices one
    # source line's opening quote to a later line's closing one and reports the text between them as
    # a connection name.
    factory = re.compile(r"\b(?:inbound|outbound)\(\s*\"([^\"\n]+)\"")
    for root in ("samples", "harness", "tests", "messagefoundry"):
        for py in (_REPO / root).rglob("*.py"):
            found.update(factory.findall(py.read_text(encoding="utf-8", errors="replace")))
    assert found >= set(HYPHENATED_SHIPPED_NAMES), "the sweep stopped finding known names"
    bad = sorted(n for n in found if not _accepts(v.ConnectionName, n))
    assert not bad, f"connection names that the API rule would refuse: {bad}"


# --- Time bounds ----------------------------------------------------------------------------------


def test_time_bounds_refuse_infinity_and_nan() -> None:
    """The gap this rule closes. A lower bound of zero does not exclude ``inf``."""
    assert v.EPOCH_SECONDS_MAX == 4_102_444_800.0
    assert _accepts(v.EpochSeconds, 1_700_000_000.0)  # control: a real timestamp still passes
    assert _accepts(v.EpochSeconds, 0.0)
    for bad in (float("inf"), float("-inf"), float("nan"), "inf", "nan", -1.0, 1e30):
        assert not _accepts(v.EpochSeconds, bad), bad


# --- Free text and vocabulary tokens ---------------------------------------------------------------


def test_free_text_refuses_control_characters_and_keeps_everything_else() -> None:
    assert v.SEARCH_TEXT_MAX == 512
    for good in ("SMITH", "O'Brien", "Zoë", "a b c", "^~\\&", "x" * 512):
        assert _accepts(v.SearchText, good), good
    for bad in ("SMITH\x00", "SMITH\nFORGED", "SMITH\rFORGED", "SMITH\tX", "", "x" * 513):
        assert not _accepts(v.SearchText, bad), bad


def test_vocabulary_tokens_match_the_engines_own_status_values() -> None:
    from messagefoundry.store.store import MessageStatus, OutboxStatus

    assert v.VOCABULARY_MEMBER_PATTERN == r"^[A-Za-z_]{1,64}$"
    for status in (*MessageStatus, *OutboxStatus):
        assert _accepts(v.StatusFilter, status.value), status
        assert _accepts(v.StatusFilter, status.value.upper()), status
    for bad in ("received;DROP", "received 1", "", "a" * 65):
        assert not _accepts(v.StatusFilter, bad), bad


def test_message_type_keeps_the_hl7_component_separator() -> None:
    """``ADT^A01`` must survive. A narrower alphabet rule here would be wrong, not stricter."""
    assert _accepts(v.MessageTypeFilter, "ADT^A01")
    assert _accepts(v.MessageTypeFilter, "ORU^R01^ORU_R01")
    assert not _accepts(v.MessageTypeFilter, "ADT^A01\n")


def test_email_rule_accepts_an_ordinary_address_and_refuses_the_obvious_breakage() -> None:
    for good in ("ops@example.org", "first.last+tag@sub.example.co.uk"):
        assert _accepts(v.EmailAddress, good), good
    for bad in (
        "ops",
        "ops@",
        "@example.org",
        "ops@example",
        "a b@example.org",
        "ops@ex\nample.org",
    ):
        assert not _accepts(v.EmailAddress, bad), bad


# --- The rules as the request models apply them ----------------------------------------------------


def test_search_request_applies_the_rules_to_its_own_fields() -> None:
    ok = MessageSearchRequest(content="SMITH", channel_id="IB_ACME_ADT", status="processed")
    assert ok.channel_id == "IB_ACME_ADT"
    with pytest.raises(ValidationError):
        MessageSearchRequest(channel_id="../../etc")
    with pytest.raises(ValidationError):
        MessageSearchRequest(content="SMITH\nFORGED")
    with pytest.raises(ValidationError):
        MessageSearchRequest(status="processed; DROP TABLE")


def test_resend_request_bounds_both_connection_names() -> None:
    ok = ResendRequest(to="OB_ACME_ADT", idempotency_key="k-1", source="OB_OTHER")
    assert ok.to == "OB_ACME_ADT"
    with pytest.raises(ValidationError):
        ResendRequest(to="OB/ACME", idempotency_key="k-1")
    with pytest.raises(ValidationError):
        ResendRequest(to="OB_ACME_ADT", idempotency_key="k\x001")


def test_edit_resend_keeps_the_message_body_unconstrained() -> None:
    """``raw`` is the data plane. It carries carriage returns by construction and must stay open."""
    body = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5\rPID|||123^^^MRN\r"
    ok = EditResendRequest(raw=body, idempotency_key="k-1")
    assert ok.raw == body
    with pytest.raises(ValidationError):
        EditResendRequest(raw=body, idempotency_key="k-1", to="OB ACME")


def test_dead_letter_replay_bounds_its_two_scopes() -> None:
    assert DeadLetterReplayRequest().channel_id is None  # the all-channels scope survives
    assert DeadLetterReplayRequest(channel_id="IB_ACME_ADT").channel_id == "IB_ACME_ADT"
    with pytest.raises(ValidationError):
        DeadLetterReplayRequest(destination_name="OB\x00ACME")


def test_export_ids_are_ids_and_the_list_is_bounded() -> None:
    assert MessageExportRequest(ids=[_HEX32]).ids == [_HEX32]
    assert v.MAX_EXPORT_IDS == 100_000
    with pytest.raises(ValidationError):
        MessageExportRequest(ids=["not-an-id"])
    with pytest.raises(ValidationError):
        MessageExportRequest(ids=[_HEX32] * (v.MAX_EXPORT_IDS + 1))


def test_role_and_permission_ids_admit_every_shipped_value() -> None:
    """The shape rule must be wider than the catalogs, which stay the auth package's to define."""
    from messagefoundry.auth.permissions import Permission, Role

    for role in Role:
        assert _accepts(v.RoleId, role.value), role
    assert _accepts(v.RoleId, CUSTOM_ROLE_ID_PREFIX + _HEX32)
    for perm in Permission:
        assert _accepts(v.PermissionId, perm.value), perm
    for bad in ("Administrator", "admin;DROP", "custom:short", "", "a" * 33):
        assert not _accepts(v.RoleId, bad), bad
    for bad in ("messages read", "messages", "MESSAGES:READ", "a:b:c"):
        assert not _accepts(v.PermissionId, bad), bad


def test_the_auth_models_carry_the_same_rules() -> None:
    from messagefoundry.api.auth_models import (
        AdGroupMap,
        AdGroupMapEntry,
        ChannelScope,
        CustomRoleRequest,
        RolesUpdateRequest,
    )

    assert ChannelScope(channels=["IB_A", "FILE-OUT_Test_ADT"]).channels is not None
    assert ChannelScope().channels is None  # the all-channels scope survives
    with pytest.raises(ValidationError):
        ChannelScope(channels=["IB_A", "../../etc"])
    assert RolesUpdateRequest(roles=["viewer"]).roles == ["viewer"]
    with pytest.raises(ValidationError):
        RolesUpdateRequest(roles=["viewer", "Bad Role"])
    assert CustomRoleRequest(display_name="X", permissions=["messages:read"]).permissions
    with pytest.raises(ValidationError):
        CustomRoleRequest(display_name="X", permissions=["messages read"])
    # The directory maps were the uncapped lists; a client no longer sizes the request.
    entry = AdGroupMapEntry(ad_group="g", role="viewer")
    assert AdGroupMap(entries=[entry]).entries == [entry]
    with pytest.raises(ValidationError):
        AdGroupMap(entries=[entry] * (v.MAX_MAP_ENTRIES + 1))


def test_the_field_path_rule_stays_where_it_already_lives() -> None:
    """No pattern is declared for ``field_path``; ``parse_path`` is its single authority."""
    assert "FIELD_PATH" not in dir(v)
    assert parse_path("PID-3") == ("PID", 3, None, None)
    with pytest.raises(Exception):  # noqa: B017 -- HL7PeekError, raised from parsing
        parse_path("PID-3; DROP")


# --- The page and the module cannot drift ----------------------------------------------------------


def _doc_claims() -> tuple[str, ...]:
    """The sentences the page must contain, each BUILT FROM the module constant it reports.

    Built rather than transcribed on purpose: a hard-coded expectation pins the test to a literal,
    which then agrees with a page that has drifted away from the code. Each claim also carries enough
    surrounding words to be falsifiable -- a bare ``32`` occurs in "32 lowercase hex" and would match
    a page that had dropped the event-kind ceiling entirely.
    """
    return (
        f"up to {int(v.EPOCH_SECONDS_MAX)}",
        f"up to {v.SEARCH_TEXT_MAX} characters",
        f"at most {v.MAX_EXPORT_IDS} ids",
        f"at most {v.MAX_EVENT_KINDS} event kinds",
        f"at most {v.MAX_MAP_ENTRIES} entries",
        CUSTOM_ROLE_ID_PREFIX,
    )


def _doc_drift(text: str) -> list[str]:
    """Which claims the page no longer makes. Empty means the page and the module agree."""
    flat = text.replace(",", "")
    return [claim for claim in _doc_claims() if claim not in flat]


def test_the_reference_page_states_the_bounds_the_module_enforces() -> None:
    assert _doc_drift(_DOC.read_text(encoding="utf-8")) == []


def test_the_drift_check_can_return_the_other_answer() -> None:
    """The control. A checker that passes on doctored text is measuring nothing."""
    doctored = _DOC.read_text(encoding="utf-8").replace("4102444800", "9999999999")
    assert _doc_drift(doctored) == [f"up to {int(v.EPOCH_SECONDS_MAX)}"]


def test_the_reference_page_is_linked_from_the_docs_index() -> None:
    index = (_REPO / "docs" / "README.md").read_text(encoding="utf-8")
    assert "API-INPUT-VALIDATION.md" in index
