# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A token file that is not UTF-8 stops ``reload_site_prefixes`` (BACKLOG #3493, #3516).

Its docstring said "Never raises". #3516 kept the stop on a decode error on purpose, so the
docstring now says so; these tests pin the behaviour it states, in both copies of the module.
The token bytes are made up and name nothing real.
"""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from tee.anon import surrogates as tee_surrogates

COPIES = [
    pytest.param(engine_surrogates, id="toolkit"),
    pytest.param(tee_surrogates, id="tee"),
]


@pytest.mark.parametrize("module", COPIES)
def test_a_token_file_that_is_not_utf8_raises(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tokens = tmp_path / "tokens.txt"
    tokens.write_bytes(b"[site_prefix]\n97\n\xff\n")
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", str(tokens))
    try:
        with pytest.raises(UnicodeDecodeError):
            module.reload_site_prefixes()
    finally:
        monkeypatch.undo()
        module.reload_site_prefixes()


@pytest.mark.parametrize("module", COPIES)
def test_control_the_same_file_in_utf8_loads_its_prefix(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tokens = tmp_path / "tokens.txt"
    tokens.write_bytes(b"[site_prefix]\n97\n")
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", str(tokens))
    try:
        module.reload_site_prefixes()
        assert module.site_prefixes_loaded()
    finally:
        monkeypatch.undo()
        module.reload_site_prefixes()
