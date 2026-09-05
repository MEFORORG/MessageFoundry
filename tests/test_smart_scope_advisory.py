# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The SMART scope over-grant advisory (#1159, ASVS 10.2.3).

Both scope settings travelled from operator config to the wire through one ``str(...)`` conversion and
nothing else, and ``messagefoundry check`` carried no scope rule at all. On a first deployment a site
would be free to request broader FHIR authority than the connection can spend, with nothing in the
engine or in ``check`` reporting it.

What is under test is the DISCRIMINATOR, not the plumbing: the check must compute a requirement from
the connection's declared shape and compare the request against it, never pattern-match a ``*``
character. So the suite pins both directions — that an over-broad NON-wildcard scope fires, and that a
wildcard scope whose letters a shape can actually spend stays quiet. A check that only rejected ``*``
would fail the first and pass the second, which is why both assertions are here.

Its silences carry the same weight as its findings. An advisory that fires on a valid clinical
configuration teaches operators to ignore it, so every deliberate silence in
``overbroad_smart_scopes`` has a test that would go red if the check started guessing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.transports.smart import smart_scope_letters

_TOML = """
[store]
backend = "sqlite"

[ai]
environment = "dev"

[security]
handles_real_patient_data = false
"""

#: Every shape the check has an opinion about, plus every shape it must stay quiet on, in one graph.
#: Synthetic hosts; the key is a placeholder because nothing here builds a connector — ``load_config``
#: runs the module body and the advisory reads the resulting graph.
_CONFIG_MODULE = """
from messagefoundry import FHIR, FhirLookup, MLLP, Rest, Send, handler, inbound, outbound, router
from messagefoundry.transports.smart import with_smart_backend

_TOKEN = "https://auth.example.invalid/token"
_KEY = "env-placeholder-signing-material"


def _smart(spec, scope):
    return with_smart_backend(
        spec, token_url=_TOKEN, client_id="cid", private_key=_KEY, scope=scope
    )


inbound("IB", MLLP(port=15099), router="r")

# FIRES. The shape the shipped worked examples carried until this item narrowed them: a create-only
# connection asking for read and search, while omitting the create letter it actually spends.
outbound(
    "OB_CREATE_WILDCARD",
    _smart(FHIR(url="https://fhir.example.invalid/fhir", interaction="create"), "system/*.rs"),
)
# FIRES, and it carries NO wildcard. This is the discriminator: a character match would miss it.
outbound(
    "OB_UPDATE_BROAD",
    _smart(
        FHIR(url="https://fhir.example.invalid/fhir", interaction="update"),
        "system/Patient.cruds",
    ),
)
# FIRES on the write letters a structurally GET-only read connection can never spend.
with_smart_backend(
    FhirLookup("lk_broad", url="https://fhir.example.invalid/fhir"),
    token_url=_TOKEN,
    client_id="cid",
    private_key=_KEY,
    scope="system/*.cruds",
)

# --- everything below must stay QUIET -----------------------------------------------------------

# The Bundle carries arbitrary methods over arbitrary types, so no letter set is determinate.
outbound(
    "OB_TXN",
    _smart(
        FHIR(url="https://fhir.example.invalid/fhir", interaction="transaction"),
        "system/*.cruds",
    ),
)
# A plain Rest() composed with SMART auth declares no interaction at all.
outbound(
    "OB_REST",
    _smart(Rest(url="https://rest.example.invalid/api"), "system/*.cruds"),
)
# A wildcard RESOURCE whose LETTERS a GET-only lookup can spend. The resource half is read from the
# outgoing body at delivery, so it is not derivable and is not a finding here.
with_smart_backend(
    FhirLookup("lk_exact", url="https://fhir.example.invalid/fhir"),
    token_url=_TOKEN,
    client_id="cid",
    private_key=_KEY,
    scope="system/*.rs",
)
# `if-none-exist` stays a POST and makes the server search on the client's behalf, so c+s is exact.
outbound(
    "OB_COND",
    _smart(
        FHIR(
            url="https://fhir.example.invalid/fhir",
            interaction="create",
            conditional="if-none-exist",
            conditional_query="identifier=sys|val",
        ),
        "system/Patient.cs",
    ),
)
# THE REGRESSION GUARD. `conditional` beats `interaction` in _resolve_request, so this legal shape --
# the DEFAULT interaction plus a conditional knob -- issues PUT and spends `u`. A table keyed on
# `interaction` alone computes `c` here and tells the operator to drop the one letter it uses.
outbound(
    "OB_COND_PUT",
    _smart(
        FHIR(
            url="https://fhir.example.invalid/fhir",
            conditional="conditional-update",
            conditional_query="identifier=sys|val",
        ),
        "system/Patient.us",
    ),
)
# `if-match` is a version-aware PUT whose ETag comes from the outgoing body -- no search, so `u` alone.
outbound(
    "OB_IF_MATCH",
    _smart(
        FHIR(url="https://fhir.example.invalid/fhir", conditional="if-match"),
        "system/Patient.u",
    ),
)
# A vocabulary this reader cannot parse is not evidence of over-breadth.
outbound(
    "OB_OPAQUE",
    _smart(FHIR(url="https://fhir.example.invalid/fhir", interaction="create"), "claims.write"),
)
# SMART auth is off, so nothing is requested.
outbound("OB_PLAIN", FHIR(url="https://fhir.example.invalid/fhir", interaction="create"))


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_CREATE_WILDCARD", msg)
"""

#: The same graph with every over-grant removed — the negative control. An absence claim ships with a
#: live positive control or the check is blind, and the pair IS the control: same code path, same
#: fixture shape, one green and one reporting.
_CLEAN_MODULE = """
from messagefoundry import FHIR, MLLP, Send, handler, inbound, outbound, router
from messagefoundry.transports.smart import with_smart_backend

inbound("IB", MLLP(port=15099), router="r")
outbound(
    "OB_CREATE",
    with_smart_backend(
        FHIR(url="https://fhir.example.invalid/fhir", interaction="create"),
        token_url="https://auth.example.invalid/token",
        client_id="cid",
        private_key="env-placeholder-signing-material",
        scope="system/Observation.c",
    ),
)


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_CREATE", msg)
"""


def _write_config(tmp_path: Path, *, clean: bool = False) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(_CLEAN_MODULE if clean else _CONFIG_MODULE, encoding="utf-8")
    (tmp_path / "messagefoundry.toml").write_text(_TOML, encoding="utf-8")
    return cfg


def _result(report: object, name: str):  # type: ignore[no-untyped-def]
    return next(r for r in report.results if r.name == name)  # type: ignore[attr-defined]


@pytest.fixture(scope="module")
def over_grant_detail(tmp_path_factory: pytest.TempPathFactory) -> str:
    """The `smart-scope` detail for the over-granting graph, from ONE `run_checks` pass.

    Module-scoped because `run_checks` re-imports and re-executes every config module on each call, and
    six assertions against six substrings of one string do not need six passes. The clean-config and
    unloadable-config cases keep their own runs -- they are different graphs, not different reads."""
    from messagefoundry.checks import run_checks

    cfg = _write_config(tmp_path_factory.mktemp("over"))
    r = _result(run_checks(cfg, run_lint=False), "smart-scope")
    assert r.ok and not r.required and not r.skipped
    return str(r.detail)


# --- the scope grammar --------------------------------------------------------------------------


def test_v2_letters_and_v1_words_read_to_the_same_alphabet() -> None:
    assert smart_scope_letters("system/Patient.cru") == frozenset("cru")
    assert smart_scope_letters("system/*.rs") == frozenset("rs")
    # SMART v1 words expand to the v2 letters they stand for, so a v1 string is graded the same way.
    assert smart_scope_letters("system/Patient.read") == frozenset("rs")
    assert smart_scope_letters("system/Patient.write") == frozenset("cud")
    assert smart_scope_letters("system/*.*") == frozenset("cruds")


def test_the_v2_search_parameter_constraint_is_tolerated() -> None:
    assert smart_scope_letters("system/Observation.rs?category=vital-signs") == frozenset("rs")


def test_non_fhir_tokens_are_skipped_rather_than_treated_as_over_breadth() -> None:
    scope = "openid fhirUser offline_access launch/patient system/Patient.c"
    assert smart_scope_letters(scope) == frozenset("c")


def test_an_unreadable_vocabulary_is_none_and_not_an_empty_set() -> None:
    # None means "this reader cannot grade the string"; frozenset() would mean "asks for nothing".
    # The caller stays quiet on None, so conflating the two would make it guess at a partner's
    # namespace — the exact reason the generic OAuth2 leg is out of scope.
    assert smart_scope_letters("claims.write") is None
    assert smart_scope_letters("") is None
    assert smart_scope_letters("system/Patient.readwrite") is None


# --- `messagefoundry check` ---------------------------------------------------------------------


def test_check_names_the_letters_a_create_only_connection_cannot_spend(
    over_grant_detail: str,
) -> None:
    assert "OB_CREATE_WILDCARD" in over_grant_detail
    assert "requests r/s which a interaction='create' connection cannot use" in over_grant_detail


def test_check_fires_on_an_over_broad_scope_carrying_no_wildcard(over_grant_detail: str) -> None:
    # The discriminator. A rule that merely rejected a `*` character would pass this config while
    # reading as a control, which is the no-op this check exists not to be.
    assert "OB_UPDATE_BROAD" in over_grant_detail
    assert (
        "requests c/d/r/s which a interaction='update' connection cannot use" in over_grant_detail
    )


def test_check_covers_the_read_side_lookup_connections(over_grant_detail: str) -> None:
    assert "fhir_lookup:lk_broad" in over_grant_detail
    assert "requests c/d/u which a GET-only lookup connection cannot use" in over_grant_detail


def test_check_stays_quiet_on_every_shape_that_does_not_determine_the_answer(
    over_grant_detail: str,
) -> None:
    # The other half of the discriminator: a wildcard alone is never the finding. `lk_exact` requests
    # `system/*.rs`, and a GET-only lookup can spend both letters, so it must not appear.
    #
    # OB_COND_PUT and OB_IF_MATCH are the regression guards for the allowance table being keyed the
    # way _resolve_request dispatches. Both declare the DEFAULT interaction ("create") plus a
    # conditional that makes the connection issue PUT, so both legitimately spend `u`. A table keyed
    # on `interaction` alone computes `c` for them and fires -- telling an operator to drop the one
    # letter their connection uses, on a shape the repo's own transport tests construct.
    for quiet in (
        "OB_TXN",
        "OB_REST",
        "lk_exact",
        "OB_COND",
        "OB_COND_PUT",
        "OB_IF_MATCH",
        "OB_OPAQUE",
        "OB_PLAIN",
    ):
        assert quiet not in over_grant_detail
    assert over_grant_detail.startswith("3 SMART connection(s)")


def test_check_stays_quiet_on_under_grant(over_grant_detail: str) -> None:
    # OB_CREATE_WILDCARD omits the `c` it needs. That is a correctness defect and it is not this
    # verb, and advising an operator to ADD a letter would advise requesting authority the
    # authorization server may never have registered.
    assert "missing" not in over_grant_detail.lower()


def test_check_says_none_explicitly_when_there_is_nothing_to_report(tmp_path: Path) -> None:
    # It states the clean case out loud rather than going quiet, so a passing line is never confused
    # with a check that did not run.
    from messagefoundry.checks import run_checks

    report = run_checks(_write_config(tmp_path, clean=True), run_lint=False)
    r = _result(report, "smart-scope")
    assert r.ok and not r.skipped
    assert "no SMART connection requests permission letters" in r.detail


def test_check_never_blocks_the_gate(tmp_path: Path) -> None:
    # A refusing gate was ruled out on the merits: a SMART authorization server registers scopes per
    # app and MAY grant a subset, so a wrong refusal would take a working clinical feed offline.
    from messagefoundry.checks import run_checks

    report = run_checks(_write_config(tmp_path), run_lint=False)
    r = _result(report, "smart-scope")
    assert r.required is False and r.ok is True and r.blocking is False
    # Ask the precise question: is `smart-scope` among the checks that fail the gate? `report.ok` would
    # ask a different one -- this fixture's placeholder signing key blocks `build-check`, so the report
    # is not ok for reasons that have nothing to do with scopes.
    assert "smart-scope" not in {x.name for x in report.results if x.blocking}


def test_check_skips_rather_than_reporting_clean_on_an_unloadable_config(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "broken.py").write_text("this is not python(", encoding="utf-8")
    r = _result(run_checks(cfg, run_lint=False), "smart-scope")
    assert r.skipped and "config did not load" in r.detail
