# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The anonymizer token file and the site prefix it loads (vault BACKLOG #3609, #3516).

#3609: a token file saved with a byte-order mark, whose first line is ``[site_prefix]``, loaded no
site prefix: the mark stayed on the header line. The publish guard drops the mark, so it still
called the token tables live. Both ``surrogates.py`` copies now drop it the way the guard does, on
every source route. The same row holds a smaller finding: ``kept_defaults`` listed a path that a
rule set built in code both keeps and rewrites, which the anonymizer rewrites.

#3516: when no site prefix loaded, ``python -m tee anonymize-captures`` said nothing about it. It
now prints a warning, whatever the cause.

Every token file here lives under ``tmp_path`` and holds a made-up two-digit prefix. Synthetic HL7
only.
"""

from __future__ import annotations

import pathlib
from pathlib import Path
from types import ModuleType

import pytest

from tee.__main__ import main as tee_main
from tee.anon import surrogates as tee_surrogates
from tests.test_anon_b193_2344 import _IMPORT_ROOT
from tests.test_anon_b254_2995 import _BOTH, _TOKEN_PARTS, _plant, _stand_in
from tests.test_anon_b254_2995 import no_token_variable as no_token_variable  # autouse
from tests.test_anon_b254_3004 import _seed

_BOM = chr(0xFEFF)
_TOKENS = "[site_prefix]\n77\n"
_SALT = "b455-salt-0123456789abcdef"
_MESSAGE = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"
_WARNING = "warning: no site prefix loaded"


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


@_BOTH
def test_a_prefix_of_non_ascii_digits_does_not_load(
    module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fullwidth ``77`` passes ``isdigit`` and no site code holds it, so loaded it would match
    nothing while reading as loaded. The guard takes ASCII digits only; so does this loader."""
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", "[site_prefix]\n" + chr(0xFF17) * 2 + "\n77\n")
    module.reload_site_prefixes()
    assert module._SITE_PREFIXES == ("77",)


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


# --- #3516: the tee says when no site prefix loaded -------------------------------------------------


def _tee_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> str:
    """One in-process ``anonymize-captures`` run over one synthetic capture; its stderr."""
    # The in-process run must not reconfigure logging for the whole pytest session.
    monkeypatch.setattr("tee.__main__._configure_logging", lambda level: None)
    monkeypatch.setenv("MEFOR_ANON_SALT", _SALT)
    db = str(tmp_path / "tee.db")
    _seed(db, (_MESSAGE,))
    capsys.readouterr()
    tee_main(["anonymize-captures", "--db", db, "--out", str(tmp_path / "ds.jsonl")])
    return capsys.readouterr().err


@pytest.mark.parametrize("unreadable", [False, True], ids=["no-file", "unreadable-file"])
def test_the_tee_warns_when_the_one_path_gives_no_prefix(
    unreadable: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``no-file`` is the absent-file case the row names. Red on the unfixed code: nothing was
    printed. ``unreadable-file`` plants a file whose read raises, as a permission refusal would."""
    module_file = _stand_in(tmp_path, monkeypatch, tee_surrogates)
    if unreadable:
        _plant(module_file.parents[_IMPORT_ROOT], "77")

        def refuse(self: Path, *args: object, **kwargs: object) -> str:
            raise PermissionError(13, "synthetic refusal", str(self))

        with monkeypatch.context() as patch:
            patch.setattr(pathlib.Path, "read_text", refuse)
            tee_surrogates.reload_site_prefixes()
    else:
        tee_surrogates.reload_site_prefixes()
    assert not tee_surrogates.site_prefixes_loaded()
    assert _tee_stderr(tmp_path, monkeypatch, capsys).count(_WARNING) == 1


@pytest.mark.parametrize(
    "value",
    [
        # A value that names no existing file is taken as the content, which holds no prefix.
        str(Path("no-such-folder") / "tokens.txt"),
        "",
        "[names]\nZZNAME\n[site_prefix]\n777\n",
    ],
    ids=["names-no-file", "empty", "no-two-digit-entry"],
)
def test_the_tee_warns_when_the_variable_gives_no_prefix(
    value: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", value)
    tee_surrogates.reload_site_prefixes()
    assert not tee_surrogates.site_prefixes_loaded()
    assert _tee_stderr(tmp_path, monkeypatch, capsys).count(_WARNING) == 1


def test_the_tee_does_not_warn_when_a_prefix_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: the same run with a prefix loaded prints no such line."""
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", _TOKENS)
    tee_surrogates.reload_site_prefixes()
    assert tee_surrogates.site_prefixes_loaded()
    err = _tee_stderr(tmp_path, monkeypatch, capsys)
    assert _WARNING not in err
    assert "wrote 1 de-identified message(s)" in err
