# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The anonymizer token file and the site prefix it loads (vault BACKLOG #3609).

#3609: a token file saved with a byte-order mark, whose first line is ``[site_prefix]``, loaded no
site prefix: the mark stayed on the header line. The publish guard drops the mark, so it still
called the token tables live. Both ``surrogates.py`` copies now drop it the way the guard does, on
every source route. The same row holds a smaller finding: ``kept_defaults`` listed a path that a
rule set built in code both keeps and rewrites, which the anonymizer rewrites.

Every token file here lives under ``tmp_path`` and holds a made-up two-digit prefix. Synthetic HL7
only.
"""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

import pytest

from tests.test_anon_b193_2344 import _IMPORT_ROOT
from tests.test_anon_b254_2995 import _BOTH, _TOKEN_PARTS, _stand_in
from tests.test_anon_b254_2995 import no_token_variable as no_token_variable  # autouse

_BOM = chr(0xFEFF)
_TOKENS = "[site_prefix]\n77\n"
_SALT = "b455-salt-0123456789abcdef"


# --- #3609: a byte-order mark no longer hides a first-line header -----------------------------------


@_BOTH
@pytest.mark.parametrize("route", ["one-path", "variable-file", "variable-inline"])
@pytest.mark.parametrize("bom", [True, False], ids=["with-mark", "control-no-mark"])
def test_a_marked_token_source_loads_its_prefix(
    module: ModuleType, route: str, bom: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each route a token text takes. Red on the unfixed code with the mark only."""
    text = (_BOM if bom else "") + _TOKENS
    if route == "one-path":
        module_file = _stand_in(tmp_path, monkeypatch, module)
        token_file = module_file.parents[_IMPORT_ROOT].joinpath(*_TOKEN_PARTS)
        token_file.parent.mkdir(parents=True)
        token_file.write_bytes(text.encode("utf-8"))
    elif route == "variable-file":
        token_file = tmp_path / "tokens.txt"
        token_file.write_bytes(text.encode("utf-8"))
        monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", str(token_file))
    else:
        monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", text)
    module.reload_site_prefixes()
    assert module._SITE_PREFIXES == ("77",)
    # Where the mark mattered: a whole component that is a site code left unchanged.
    scrubbed = module.scrub_site_codes("WARD^771234^A", module.Keyer(_SALT), module.Seps())
    assert "771234" not in scrubbed


# --- #3609 finding 4: a keep and a rewrite on one path ----------------------------------------------


@pytest.mark.parametrize("package", ["messagefoundry.anon", "tee.anon"], ids=["engine", "tee"])
def test_a_kept_path_that_a_rule_also_rewrites_is_not_listed_as_kept(package: str) -> None:
    """Only a rule set built in code can hold both. The anonymizer drops the keep and runs the
    rewrite, so the field is not left as captured. The retarget list still names it."""
    anon = pytest.importorskip(package)
    rules = (
        anon.FieldRule("PID-5", anon.SurrogateKind.KEEP),
        anon.FieldRule("PID-5", anon.SurrogateKind.MRN),
    )
    assert anon.kept_defaults(rules) == ()
    assert [(d.path, n.kind) for d, n in anon.retargeted_defaults(rules)] == [
        ("PID-5", anon.SurrogateKind.MRN)
    ]
    # The control: a keep alone is still listed.
    assert [r.path for r in anon.kept_defaults(rules[:1])] == ["PID-5"]
