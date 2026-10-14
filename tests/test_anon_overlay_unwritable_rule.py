# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An overlay rule on ``MSH-1`` or ``MSH-2`` is refused when the overlay loads (BACKLOG #2997).

No rule can rewrite those two fields: they hold the message's delimiters. The refusal used to
run only inside the per-message call, so such an overlay loaded cleanly and then every message
failed. The tee counted the failures and dropped the reason. ``load_rules`` now refuses it once
and names the field.

Field 0 was already refused at load, by the ``FieldRule`` path check (BACKLOG #2330). That case
is the control here, not a fix. The tee command's side of this is one case in
``tests/test_anon_b193_2267.py``.

Every value here is synthetic.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

import messagefoundry.anon.hl7 as engine_hl7
import messagefoundry.anon.rules as engine_rules
import tee.anon.hl7 as tee_hl7
import tee.anon.rules as tee_rules
from messagefoundry.anon import anonymize as engine_anonymize
from tee.anon import anonymize as tee_anonymize

_BOTH = pytest.mark.parametrize("rules_module", (engine_rules, tee_rules), ids=("engine", "tee"))
_SALT = "b254-2997-salt-0123456789abcdef"
_MSG = "\r".join(
    (
        r"MSH|^~\&|APP|FAC|RCV|RFAC|20260101120000||ADT^A01|M1|P|2.5.1",
        "PID|1||1^^^H^MR||X^Y",
    )
)


def _overlay(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "anon.toml"
    path.write_text(body, encoding="utf-8")
    return path


@_BOTH
@pytest.mark.parametrize(
    ("body", "named"),
    [
        ('[hl7]\ndrop = ["MSH-2"]\n', "MSH-2"),
        ('[hl7]\ndrop = ["MSH-1"]\n', "MSH-1"),
        ('[hl7.fields]\n"MSH-2" = "id"\n', "MSH-2"),
        ('[hl7.fields]\n"MSH-1" = "freetext"\n"MSH-2" = "drop"\n', "MSH-1, MSH-2"),
        # A drop is applied after a keep, so the final rule on the path is the drop.
        ('[hl7]\nkeep = ["MSH-2"]\ndrop = ["MSH-2"]\n', "MSH-2"),
    ],
    ids=["drop-msh-2", "drop-msh-1", "fields-msh-2", "both", "keep-then-drop"],
)
def test_an_overlay_rule_on_a_delimiter_field_is_refused_at_load(
    rules_module: ModuleType, body: str, named: str, tmp_path: Path
) -> None:
    overlay = _overlay(tmp_path, body)

    with pytest.raises(rules_module.RuleError) as exc:
        rules_module.load_rules(overlay)

    message = str(exc.value)
    assert f"sets a rule on {named}, which no rule can rewrite" in message
    assert str(overlay) in message


@_BOTH
@pytest.mark.parametrize(
    ("body", "path", "kind"),
    [
        ('[hl7]\nkeep = ["MSH-2"]\n', "MSH-2", "keep"),
        ('[hl7]\nkeep = ["MSH-1", "MSH-2"]\n', "MSH-1", "keep"),
        ('[hl7.fields]\n"MSH-2" = "keep"\n', "MSH-2", "keep"),
        # The check reads the final rule set: this keep replaces the rule the table set.
        ('[hl7.fields]\n"MSH-2" = "id"\n\n[hl7]\nkeep = ["MSH-2"]\n', "MSH-2", "keep"),
        # MSH-3 is the lowest MSH field a rule may rewrite.
        ('[hl7]\ndrop = ["MSH-3"]\n', "MSH-3", "drop"),
    ],
    ids=["keep-msh-2", "keep-both", "fields-keep", "keep-over-fields", "drop-msh-3"],
)
def test_a_keep_on_a_delimiter_field_still_loads(
    rules_module: ModuleType, body: str, path: str, kind: str, tmp_path: Path
) -> None:
    """The control: these loaded before the fix and must load after it."""
    rules = rules_module.load_rules(_overlay(tmp_path, body))

    assert {rule.path: rule.kind.value for rule in rules}[path] == kind


@_BOTH
def test_field_zero_was_already_refused_at_load_by_the_path_check(
    rules_module: ModuleType, tmp_path: Path
) -> None:
    """The control for the scope: this refusal is older, and it is a different message."""
    with pytest.raises(rules_module.RuleError, match="not a whole-field HL7 address"):
        rules_module.load_rules(_overlay(tmp_path, '[hl7]\ndrop = ["PID-0"]\n'))


@pytest.mark.parametrize(
    ("rules_module", "anonymize"),
    [(engine_rules, engine_anonymize), (tee_rules, tee_anonymize)],
    ids=("engine", "tee"),
)
def test_a_rule_set_built_in_code_still_meets_the_per_message_refusal(
    rules_module: ModuleType, anonymize: Callable[..., str]
) -> None:
    """A caller who passes ``rules=`` never calls ``load_rules``. The per-message check is what
    refuses that rule set, and it stays an ``AnonError``: the tee's loop counts that type."""
    rules = (*rules_module.DEFAULT_RULES, rules_module.FieldRule("MSH-2", "drop"))

    with pytest.raises(rules_module.AnonError, match="a rule names MSH-2,") as exc:
        anonymize(_MSG, salt=_SALT, rules=rules)

    assert not isinstance(exc.value, rules_module.RuleError)
    assert "PID|" in anonymize(_MSG, salt=_SALT, rules=rules_module.DEFAULT_RULES)


@pytest.mark.parametrize(
    ("hl7_module", "rules_module"),
    [(engine_hl7, engine_rules), (tee_hl7, tee_rules)],
    ids=("engine", "tee"),
)
def test_each_adapter_uses_the_one_copy_in_rules(
    hl7_module: ModuleType, rules_module: ModuleType
) -> None:
    assert hl7_module._refuse_unwritable_rules is rules_module._refuse_unwritable_rules
