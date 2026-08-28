# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every keyword handed to a settings model must be a real field of it (BACKLOG #1327).

**The defect.** ``_Section`` carries ``extra="ignore"``, so a settings model ACCEPTS an unknown keyword
and silently drops it. Deleting a setting therefore leaves every call site that still passes it green --
and the call site most likely to pass it is the test NAMED after the setting, which then establishes
nothing while continuing to report success.

Measured on the shipped models: ``_Section(this_setting_does_not_exist=123)`` is accepted, ``hasattr`` is
False, and the control ``Schedule(bogus_kwarg=1)`` raises ``ValidationError``.

*** WHY THIS IS A TEST-TIME CHECK AND NOT ``extra="forbid"`` ON THE MODELS. ***

The item proposes setting ``extra="forbid"`` as ``AlertRule`` does. **That is refused here, and the
reason is measured rather than argued.** ``pydantic``'s ``extra_forbidden`` error ECHOES THE OFFENDING
VALUE:

    Extra inputs are not permitted [type=extra_forbidden, input_value='<the value>', input_type=str]

``config/settings.py`` records that the CLI prints that exception verbatim to a log file, so a mistyped
SECRET key would be written to disk in cleartext. The same comment records two further disqualifiers:
``_env_overrides`` scrapes every ``MEFOR_<section>_<key>`` into its section dict and a dozen documented
variables are read straight from ``os.environ`` by their consuming module, so a Vault-backed store
configured exactly as the shipped docs instruct would fail to start; and ``security show`` validates
``SecuritySettings`` directly, so a forbidding model would deny an operator the view they use to repair
the typo.

``AlertRule`` proves ``forbid`` works on a surface with no env scraping and no secret-bearing keys. That
is a different claim from the one the item makes, so it does not carry.

**This check has none of those costs.** It changes no runtime behaviour, never constructs a model from
untrusted input, and emits no value -- only a field NAME it already knew.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from pydantic import BaseModel

from messagefoundry.config import settings as settings_mod

_ROOT = Path(__file__).resolve().parents[1]


def _settings_models() -> dict[str, set[str]]:
    """Model name -> its declared field names, for every pydantic model in config.settings."""
    out: dict[str, set[str]] = {}
    for name, obj in vars(settings_mod).items():
        if inspect.isclass(obj) and issubclass(obj, BaseModel) and obj is not BaseModel:
            out[name] = set(obj.model_fields)
    return out


class _Offence:
    __slots__ = ("path", "line", "model", "keyword")

    def __init__(self, path: str, line: int, model: str, keyword: str) -> None:
        self.path, self.line, self.model, self.keyword = path, line, model, keyword

    def __repr__(self) -> str:  # shown verbatim in the failure, so make it actionable
        return f"{self.path}:{self.line} {self.model}(... {self.keyword}=...) is not a field"


def _scan_source(
    source: str, label: str, models: dict[str, set[str]]
) -> tuple[list[_Offence], int]:
    """Offences, and the number of calls skipped because a ``**splat`` makes them unreadable.

    THE SKIP COUNT IS RETURNED RATHER THAN SWALLOWED. A checker that silently ignores what it cannot
    read reports a clean sweep over a population it never examined, which is the shape this whole item
    is about.
    """
    offences: list[_Offence] = []
    unreadable = 0
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return offences, unreadable

    # A CALL INSIDE `with pytest.raises(...)` IS A NEGATIVE CONTROL, NOT A DEFECT, AND MUST NOT BE
    # FLAGGED. The item names the live instance: tests/test_alert_rules.py deliberately constructs
    # AlertRule with an unknown keyword to prove that model FORBIDS extras. Flagging it would make this
    # check refuse the very test that proves the fix works elsewhere in the codebase -- and a checker
    # that fires on a deliberate control is one somebody disables, which costs more than it catches.
    exempt: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        raises = any(
            isinstance(item.context_expr, ast.Call)
            and isinstance(item.context_expr.func, ast.Attribute)
            and item.context_expr.func.attr == "raises"
            for item in node.items
        )
        if raises:
            for inner in node.body:
                for sub in ast.walk(inner):
                    if isinstance(sub, ast.Call):
                        exempt.add(id(sub))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and id(node) in exempt:
            continue
        if not isinstance(node, ast.Call):
            continue
        # Both shapes: `Model(...)` and `mod.Model(...)`. The item records that a scan seeing only the
        # first "would not have found their own bug".
        func = node.func
        if isinstance(func, ast.Name):
            model_name = func.id
        elif isinstance(func, ast.Attribute):
            model_name = func.attr
        else:
            continue
        fields = models.get(model_name)
        if fields is None:
            continue
        if any(kw.arg is None for kw in node.keywords):
            unreadable += 1
            continue
        for kw in node.keywords:
            if kw.arg is not None and kw.arg not in fields:
                offences.append(_Offence(label, node.lineno, model_name, kw.arg))
    return offences, unreadable


def _sweep() -> tuple[list[_Offence], int, int]:
    models = _settings_models()
    offences: list[_Offence] = []
    unreadable = 0
    examined = 0
    for base in ("messagefoundry", "tests"):
        for path in sorted((_ROOT / base).rglob("*.py")):
            examined += 1
            found, skipped = _scan_source(
                path.read_text(encoding="utf-8", errors="replace"),
                str(path.relative_to(_ROOT)).replace("\\", "/"),
                models,
            )
            offences.extend(found)
            unreadable += skipped
    return offences, unreadable, examined


def test_the_checker_FINDS_a_planted_bad_keyword() -> None:
    """THE POSITIVE CONTROL, AND THE SWEEP BELOW IS WORTHLESS WITHOUT IT.

    A sweep that returns zero is indistinguishable from a sweep that cannot see anything -- a checker
    whose model lookup silently missed would report a clean repository forever. This plants the exact
    defect and requires the checker to report it.
    """
    models = _settings_models()
    assert "ApiSettings" in models, "the fixture model vanished; re-point this control"
    bad = "ApiSettings(host='127.0.0.1', this_field_was_deleted=True)\n"
    offences, _ = _scan_source(bad, "<planted>", models)
    assert len(offences) == 1, f"the checker did not see a planted bad keyword: {offences}"
    assert offences[0].keyword == "this_field_was_deleted"


def test_the_checker_does_NOT_flag_a_real_field() -> None:
    """The other polarity. Without this, a checker that flags EVERY keyword also passes the control
    above while making the sweep useless -- and the two failures look identical from the outside."""
    models = _settings_models()
    real = next(iter(models["ApiSettings"]))
    offences, _ = _scan_source(f"ApiSettings({real}=1)\n", "<planted>", models)
    assert offences == [], f"a real field was flagged: {offences}"


def test_the_checker_reads_the_ATTRIBUTE_call_shape_too() -> None:
    """``mod.Model(...)``, not just ``Model(...)``. The item records that a scan seeing only the bare
    name "would not have found their own bug"."""
    models = _settings_models()
    offences, _ = _scan_source("settings.ApiSettings(nope_not_a_field=1)\n", "<planted>", models)
    assert len(offences) == 1, f"the attribute call shape was not read: {offences}"


def test_a_deliberate_pytest_raises_CONTROL_is_not_flagged() -> None:
    """The live false positive this checker had on its first run, now pinned.

    tests/test_alert_rules.py constructs AlertRule with an unknown keyword ON PURPOSE, inside
    pytest.raises, to prove that model forbids extras. A checker that flags it would refuse the very
    test proving the fix works -- and a checker that fires on a deliberate control gets disabled.
    """
    models = _settings_models()
    src = """with pytest.raises(ValidationError):
    AlertRule(extra_field='x')
"""
    offences, _ = _scan_source(src, "<planted>", models)
    assert offences == [], f"a deliberate negative control was flagged: {offences}"


def test_the_exemption_does_NOT_swallow_the_same_call_OUTSIDE_the_block() -> None:
    """THE OTHER HALF, and without it the exemption above is indistinguishable from one that swallows
    everything. Same model, same keyword, no pytest.raises -- it must still be reported."""
    models = _settings_models()
    offences, _ = _scan_source(
        """AlertRule(extra_field='x')
""",
        "<planted>",
        models,
    )
    assert len(offences) == 1, f"the exemption is too broad: {offences}"
    assert offences[0].keyword == "extra_field"


def test_a_NON_raises_with_block_is_not_exempt() -> None:
    """THE ARM A MUTATION ROUND ADDED, because the pair above could not see the mutant.

    Broadening the exemption from ``pytest.raises`` to EVERY ``with`` block survived the whole file:
    the sibling test that checks a call outside the block has no ``with`` statement at all, so nothing
    is exempted in it either way and it passes under both. Only a bad call inside a DIFFERENT kind of
    ``with`` separates them.
    """
    models = _settings_models()
    src = """with open("f") as fh:
    AlertRule(extra_field='x')
"""
    offences, _ = _scan_source(src, "<planted>", models)
    assert len(offences) == 1, (
        f"a non-raises with-block was treated as a negative control: {offences}"
    )


def test_no_call_site_passes_a_keyword_that_is_not_a_settings_FIELD() -> None:
    """THE SWEEP. A keyword that is not a field is silently dropped at runtime, so nothing else reports
    it -- not the constructor, not the type checker, and not the test named after the setting."""
    offences, unreadable, examined = _sweep()
    assert not offences, (
        f"{len(offences)} call site(s) pass a keyword no settings model declares.\n"
        + "\n".join(f"  {o!r}" for o in offences)
        + "\n  These are accepted and DROPPED at runtime, so the call reports success either way."
    )
    # Scope, printed rather than implied: a bare pass here covers only what the sweep could read.
    assert examined > 100, f"the sweep examined only {examined} files; it is not reaching the tree"


def test_the_sweep_REPORTS_what_it_could_not_read() -> None:
    """A ``**splat`` cannot be resolved statically, so those calls are counted and excluded rather than
    assumed clean. The count is asserted to be small: if it grows, the sweep's coverage is quietly
    shrinking and the clean result above means less than it appears to."""
    _, unreadable, _ = _sweep()
    assert unreadable < 40, (
        f"{unreadable} settings-model calls use a **splat and cannot be checked statically. "
        "The sweep's clean result does not cover them, and at this count it covers noticeably less "
        "than it did when this bound was set."
    )


@pytest.mark.parametrize("model_name", ["AlertRule", "Schedule"])
def test_the_models_that_already_FORBID_extras_keep_doing_so(model_name: str) -> None:
    """Per-model ``forbid`` is fine where it is already correct, and this pins the three that have it so
    a future sweep does not 'harmonise' them down to ignore. It is the blanket change to the other
    thirty-four that this item's proposal gets wrong, not forbid itself."""
    model = getattr(settings_mod, model_name)
    assert model.model_config.get("extra") == "forbid", (
        f"{model_name} no longer forbids extras; if that was deliberate, this row should say why"
    )
