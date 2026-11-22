# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Some records about the key-file check say no more than the check does (vault BACKLOG #5657 step 14).

Each test pins a sentence a record was corrected to beside the behaviour it describes, read from a
pure decision function, so a change to either shows here. The records pinned are ``docs/PHI.md``
section 2, *Key files*, ADR 0214's amendments, ``docs/CONFIGURATION.md``'s secrets directory
section, the ``docker/k8s`` manifests and the ``key_file_problem`` docstring. Text is compared with
its line breaks folded to spaces.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

from messagefoundry.auth.anchor_path import WinTrust
from messagefoundry.config.key_file_access import key_file_problem
from messagefoundry.restricted_file import (
    _posix_holder_problem,
    _posix_own_problem,
    _windows_engine_owner_problem,
)

_REPO = Path(__file__).resolve().parent.parent
_ADR_0214 = (
    "docs/adr/0214-a-secrets-directory-and-one-accessor-for-the-engine-s-secret-class-settings.md"
)
_ENGINE_UID = 10001
_SHARED_SERVICES = ("S-1-5-19", "S-1-5-20")  # LOCAL SERVICE, NETWORK SERVICE


def _text(relative: str) -> str:
    return re.sub(r"\s+", " ", (_REPO / relative).read_text(encoding="utf-8"))


@pytest.mark.parametrize("manifest", ["docker/k8s/statefulset.yaml", "docker/k8s/ha-postgres.yaml"])
def test_the_manifests_say_a_key_whose_own_name_is_a_link_is_refused(manifest: str) -> None:
    # A link above the key that only root or the engine can change passes the link walk, so "a TLS
    # key reached through a link" said more than the check does. A link at the key's own name is
    # refused whoever owns it, which is what a Secret volume serves.
    text = _text(manifest)
    assert "refuses a TLS key reached through a link" not in text
    assert "refuses a TLS key whose own name is a link, or one a group may read" in text
    assert _posix_own_problem(mode=stat.S_IFLNK | 0o777, uid=0, euid=_ENGINE_UID) is not None


def test_phi_says_a_root_owned_directory_passes_on_posix() -> None:
    # "a directory that another account owns" read as refusing a root-owned one, which passes.
    text = _text("docs/PHI.md")
    assert (
        "one held in a directory that such an account owns or that a group or other may write "
        "without the sticky bit"
    ) in text
    assert "one held in a directory that another account owns" not in text
    directory = stat.S_IFDIR | 0o755
    assert _posix_holder_problem(parent_mode=directory, parent_uid=0, euid=_ENGINE_UID) is None
    assert _posix_holder_problem(parent_mode=directory, parent_uid=4242, euid=_ENGINE_UID)


@pytest.mark.parametrize("shared", _SHARED_SERVICES)
def test_phi_says_a_shared_service_owner_of_the_minted_key_is_accepted(shared: str) -> None:
    # The record once said only that such an owner "does not show the engine made it", which read
    # as a refusal. The check accepts it.
    text = _text("docs/PHI.md")
    assert "a key that account owns is accepted" in text
    assert _windows_engine_owner_problem(shared, shared) is None
    # Stated once: the bullet on the folders above no longer repeats the minted-key owner rule.
    assert text.count("must be owned by the engine's own account, SYSTEM or Administrators") == 1


@pytest.mark.parametrize("shared", _SHARED_SERVICES)
def test_phi_says_the_link_rule_does_not_trust_a_shared_service_engine(shared: str) -> None:
    text = _text("docs/PHI.md")
    assert (
        "TrustedInstaller and the engine's own account, unless that is LOCAL SERVICE or NETWORK "
        "SERVICE"
    ) in text
    trust = WinTrust(shared, lambda _sid: False)
    assert trust.owner(shared) is False
    assert WinTrust("S-1-5-21-1-2-3-1001", lambda _sid: False).owner("S-1-5-21-1-2-3-1001")


def test_the_posix_owner_rule_names_root_as_allowed() -> None:
    assert _posix_own_problem(mode=stat.S_IFREG | 0o600, uid=0, euid=_ENGINE_UID) is None
    assert _posix_own_problem(mode=stat.S_IFREG | 0o600, uid=4242, euid=_ENGINE_UID)
    doc = re.sub(r"\s+", " ", key_file_problem.__doc__ or "")
    assert "a file owned by an account other than the engine's own or root" in doc
    assert "On POSIX the same check also refuses a directory or file another account owns" not in (
        _text(_ADR_0214)
    )
    assert "an account other than the engine's own or root owns" in _text("docs/CONFIGURATION.md")
