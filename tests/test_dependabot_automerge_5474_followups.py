# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5474 follow-up items on ``.github/workflows/dependabot-auto-merge.yml``.

Kept apart from ``test_dependabot_automerge_guardrails.py`` so that file's existing tests are not
rewritten here; the step-running harness is imported from it, not copied. Each test names the
ledger item it answers.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from tests import test_dependabot_automerge_guardrails as g

# --------------------------------------------------------------------------------------------------
# Item 3: the allow-set's name splitting
# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("names", "expected"),
    [
        # Controls: fetch-metadata's own `, ` join, and padding at either end, still pass.
        ("actions/checkout, github/codeql-action/init", "true"),
        (" actions/checkout ", "true"),
        ("actions/checkout,\tactions/setup-python", "true"),
        # THE REGRESSION ROWS, each `eligible=true` before the fix. `read` drops one trailing empty
        # field, so a trailing comma read as a list with no empty member.
        ("actions/checkout,", "false"),
        # Interior whitespace was stripped, rewriting the name into one the row admits.
        ("actions/ checkout", "false"),
        ("actions/check out", "false"),
        ("actions/checkout, github/codeql-action /init", "false"),
        # Neighbouring controls that already denied.
        (",actions/checkout", "false"),
        ("actions/checkout,,", "false"),
    ],
)
def test_allowset_denies_a_trailing_comma_and_whitespace_inside_a_name(
    names: str, expected: str, tmp_path: Path
) -> None:
    run = g._run_step_body(
        "allowset", {"DEP_NAMES": names, "DEP_ECOSYSTEM": "github_actions"}, tmp_path
    )
    assert run.rc == 0, f"the allowset body aborted (rc={run.rc}){g._diagnostic(run)}"
    assert run.outputs.get("eligible") == expected, f"{names!r}{g._diagnostic(run)}"


# --------------------------------------------------------------------------------------------------
# Item 4: the version-track pin, and the release-age gate through real jq with a curl journal
# --------------------------------------------------------------------------------------------------


def _unquoted(body: str) -> str:
    """The body with shell quotes removed, so `track="version"` reads as `track=version`."""
    return body.replace('"', "").replace("'", "")


def _version_routes(body: str) -> tuple[int, int]:
    """How many times the body assigns the version track, and emits its output, in any quoting."""
    flat = _unquoted(body)
    return (
        # A shell assignment takes no spaces round `=`, and `$track` is a read, not an assignment.
        len(re.findall(r"(?<![A-Za-z0-9_$])track=version\b", flat)),
        len(re.findall(r"security_track=false\b", flat)),
    )


def test_a_quoted_second_version_track_route_cannot_hide_from_the_pin() -> None:
    """The existing pin counts the literal ``track=version``, so a second arm spelled
    ``track="version"`` would sit beside it unread. This count reads through the quoting."""
    body = str(g._step("ghsa")["run"])
    assert _version_routes(body) == (1, 1), _version_routes(body)
    # The instrument check: each quoted second route must move the count.
    for planted in (
        'x) track="version" ;;',
        "x) track='version' ;;",
        'echo "security_track="false"" >> "$GITHUB_OUTPUT"',
    ):
        mutated = body.replace(
            "*security*) track=security ;;", f"{planted}\n*security*) track=security ;;"
        )
        assert mutated != body, "the mutation anchor is gone; re-read the ghsa body"
        assert _version_routes(mutated) != (1, 1), planted


def _journaling_curl(tmp_path: Path, stub_dir: Path, payload: str) -> Path:
    """Replace ``stub_dir``'s curl with one that records its argv OUTSIDE the stub directory."""
    journal = tmp_path / "curl5474.calls"
    record = "printf '%s\\n' \"$*\" >> '" + journal.as_posix() + "'\n"
    stub = stub_dir / "curl"
    stub.write_text(
        "#!/usr/bin/env bash\n" + record + f"cat <<'JSON'\n{payload}\nJSON\n",
        encoding="utf-8",
        newline="\n",
    )
    stub.chmod(0o755)
    return journal


def _calls(journal: Path) -> list[str]:
    return journal.read_text(encoding="utf-8").splitlines() if journal.exists() else []


_NAMELESS_AGE_ROWS = [
    ('[{"dependencyName":"requests","newVersion":"2.32.3"}]', "true"),
    ("[{}]", "false"),
    ('[{"dependencyName":"","newVersion":""}]', "false"),
    ('[{"newVersion":"2.32.3"}]', "false"),
    ('[{"dependencyName":"requests","newVersion":"2.32.3"},{}]', "false"),
]


def _assert_the_age_rows(deps_json: str, expected: str, tmp_path: Path, real_jq: bool) -> None:
    """The aged row must have been answered by the curl stub, and a nameless row denies before
    asking about itself: every recorded call names the one named dependency."""
    aged = g._iso(24 * 30)
    if real_jq:
        stub_dir = g._stub_dir(tmp_path, [], jq=False)
    else:
        # The jq stub prints these rows as real jq's `@tsv` would print this DEPS_JSON.
        rows = [(d.get("dependencyName"), d.get("newVersion")) for d in json.loads(deps_json)]
        stub_dir = g._stub_dir(tmp_path, rows, published=aged)
    journal = _journaling_curl(
        tmp_path, stub_dir, f'{{"urls":[{{"upload_time_iso_8601":"{aged}"}}]}}'
    )
    run = g._run_step_body(
        "age",
        {"SECURITY_TRACK": "true", "DEP_ECOSYSTEM": "uv", "DEPS_JSON": deps_json},
        tmp_path,
        path_prepend=stub_dir,
    )
    assert run.rc == 0, f"the age body aborted (rc={run.rc}){g._diagnostic(run)}"
    assert run.outputs.get("age_ok") == expected, f"{deps_json}{g._diagnostic(run)}"
    calls = _calls(journal)
    assert all("requests/2.32.3/json" in c for c in calls), f"a nameless row was asked: {calls}"
    if expected == "true":
        assert calls, f"the curl stub never answered the aged row{g._diagnostic(run)}"


@pytest.mark.parametrize(("deps_json", "expected"), _NAMELESS_AGE_ROWS)
def test_the_release_age_gate_asks_the_curl_stub_only_for_a_named_row(
    deps_json: str, expected: str, tmp_path: Path
) -> None:
    """The stubbed-jq rows, with the curl journal ``_stub_dir`` lacks."""
    _assert_the_age_rows(deps_json, expected, tmp_path, real_jq=False)


@pytest.mark.skipif(
    shutil.which("jq") is None,
    reason="needs bash + jq, the same runner matrix as the guardrail file's real-jq rows",
)
@pytest.mark.parametrize(("deps_json", "expected"), _NAMELESS_AGE_ROWS)
def test_the_real_jq_feeds_a_nameless_row_to_the_release_age_deny(
    deps_json: str, expected: str, tmp_path: Path
) -> None:
    """The guardrail file's real-jq nameless rows cover the ghsa step only; these are the age
    step's, through the REAL jq filter, with curl journaled."""
    _assert_the_age_rows(deps_json, expected, tmp_path, real_jq=True)


# --------------------------------------------------------------------------------------------------
# Item 11: the age and authors gates are the allow-set conjunct EXACTLY
# --------------------------------------------------------------------------------------------------

_ALLOWSET_GATE = "steps.allowset.outputs.eligible == 'true'"


def _is_exactly_the_allowset_gate(cond: object) -> bool:
    return " ".join(str(cond).split()) == _ALLOWSET_GATE


@pytest.mark.parametrize("step_id", ["age", "authors"])
def test_the_gated_steps_run_on_the_allow_set_conjunct_and_nothing_else(step_id: str) -> None:
    """A substring check passes ``... == 'true' || always()``; equality does not."""
    cond = g._step(step_id).get("if", "")
    assert _is_exactly_the_allowset_gate(cond), f"{step_id} if: {cond!r}"
    for loosened in (
        f"{_ALLOWSET_GATE} || always()",
        f"always() || {_ALLOWSET_GATE}",
        f"${{{{ {_ALLOWSET_GATE} || true }}}}",
        f"{_ALLOWSET_GATE} || steps.allowset.outputs.eligible == 'false'",
    ):
        assert _ALLOWSET_GATE in loosened  # the old substring check would have passed it
        assert not _is_exactly_the_allowset_gate(loosened), loosened


# --------------------------------------------------------------------------------------------------
# Item 16: an end-to-end run of the hold for an actions PR outside dependabot.yml's groups
# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("group", "arms"),
    [
        # The control: a named version group is the version track and arms.
        ("actions-deps", True),
        # THE HOLD: an ungrouped actions PR, or one in a group this workflow does not name.
        ("", False),
        ("actions-new", False),
    ],
)
def test_an_actions_pr_outside_the_groups_holds_end_to_end(
    group: str, arms: bool, tmp_path: Path
) -> None:
    """The allow-set, ghsa and age bodies run in order on one actions PR, each fed the previous
    steps' real outputs, and the shipped merge ``if`` decides on them."""
    for sub in ("a", "g", "s"):
        (tmp_path / sub).mkdir()
    eco = "github_actions"
    deps = '[{"dependencyName":"actions/checkout","prevVersion":"4.1.0","newVersion":"4.1.1"}]'
    allow = g._run_step_body(
        "allowset", {"DEP_NAMES": "actions/checkout", "DEP_ECOSYSTEM": eco}, tmp_path / "a"
    )
    assert allow.rc == 0 and allow.outputs.get("eligible") == "true", g._diagnostic(allow)
    ghsa = g._run_step_body(
        "ghsa",
        {"DEP_GROUP": group, "DEP_ECOSYSTEM": eco, "DEPS_JSON": deps, "GH_TOKEN": "stub"},
        tmp_path / "g",
    )
    assert ghsa.rc == 0, g._diagnostic(ghsa)
    # The age step's own `if` is the allow-set conjunct, which passed above, so it runs.
    age = g._run_step_body(
        "age",
        {
            "SECURITY_TRACK": ghsa.outputs.get("security_track", ""),
            "DEP_ECOSYSTEM": eco,
            "DEPS_JSON": deps,
        },
        tmp_path / "s",
    )
    assert age.rc == 0, g._diagnostic(age)
    context = {
        "steps.allowset.outputs.eligible": allow.outputs.get("eligible", ""),
        "steps.authors.outputs.sole_author": "true",
        "steps.ghsa.outputs.security_track": ghsa.outputs.get("security_track", ""),
        "steps.ghsa.outputs.advisory_ok": ghsa.outputs.get("advisory_ok", ""),
        "steps.age.outputs.age_ok": age.outputs.get("age_ok", ""),
        "steps.meta.outputs.update-type": "version-update:semver-patch",
        "steps.meta.outputs.dependency-type": "direct:production",
    }
    verdict = g._evaluate_expression(str(g._merge_step().get("if", "")), context)
    assert verdict is arms, f"group={group!r} {context}"


# --------------------------------------------------------------------------------------------------
# Item 21: the actions groups cover every action
# --------------------------------------------------------------------------------------------------


def _unrestricted_star(group: dict) -> bool:
    """A group that admits every dependency: ``*`` and no narrowing key."""
    narrowing = {"exclude-patterns", "dependency-type", "update-types"}
    return "*" in (group.get("patterns") or []) and not (narrowing & group.keys())


def test_the_actions_groups_cover_every_action() -> None:
    """The workflow header says every github-actions update lands in ``actions-deps`` or
    ``actions-security``, so the unknown-group hold is reached only by a PR Dependabot opens outside
    them. That rests on both groups matching ``*`` unrestricted; this pins it."""
    actions = [
        u for u in g._load_dependabot()["updates"] if u["package-ecosystem"] == "github-actions"
    ]
    assert len(actions) == 1, actions
    groups = actions[0].get("groups") or {}
    version = [
        n for n, v in groups.items() if v.get("applies-to", "version-updates") == "version-updates"
    ]
    security = [n for n, v in groups.items() if v.get("applies-to") == "security-updates"]
    assert version == ["actions-deps"] and security == ["actions-security"], groups
    for name in version + security:
        assert _unrestricted_star(groups[name]), (name, groups[name])
    # The instrument check: a narrowed group is told apart.
    assert not _unrestricted_star({"patterns": ["actions/*"]})
    assert not _unrestricted_star({"patterns": ["*"], "exclude-patterns": ["pypa/*"]})
    assert not _unrestricted_star({"patterns": ["*"], "update-types": ["patch"]})
