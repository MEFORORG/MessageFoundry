# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The records about the key-file check say no more than the check does (vault BACKLOG #5657 step 14).

Each test pins a corrected sentence in a record beside the behaviour it describes, read from the
pure decision functions in :mod:`messagefoundry.restricted_file`, so the two move together. The
records are ``docs/PHI.md`` section 2, *Key files*, the two ``changelog.d`` fragments, ADR 0214's
amendments, ``docs/CONFIGURATION.md``'s secrets directory section, the ``docker/k8s`` manifests
and the ``key_file_problem`` docstring. Text is compared with its line breaks folded to spaces.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

from messagefoundry.config.key_file_access import key_file_problem
from messagefoundry.restricted_file import (
    _HOLDER_REPLACE_MASK,
    DELETE_ACCESS,
    _posix_holder_problem,
    _posix_own_problem,
    _windows_engine_owner_problem,
)

_REPO = Path(__file__).resolve().parent.parent
_ENGINE_UID = 10001
_LOCAL_SERVICE = "S-1-5-19"
_NETWORK_SERVICE = "S-1-5-20"


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
    assert (
        _posix_holder_problem(parent_mode=stat.S_IFDIR | 0o755, parent_uid=0, euid=_ENGINE_UID)
        is None
    )
    assert (
        _posix_holder_problem(parent_mode=stat.S_IFDIR | 0o755, parent_uid=4242, euid=_ENGINE_UID)
        is not None
    )


@pytest.mark.parametrize("shared", [_LOCAL_SERVICE, _NETWORK_SERVICE])
def test_phi_says_a_shared_service_owner_of_the_minted_key_is_accepted(shared: str) -> None:
    # The record once said only that such an owner "does not show the engine made it", which read
    # as a refusal. The check accepts it.
    text = _text("docs/PHI.md")
    assert "a key that account owns is accepted" in text
    assert _windows_engine_owner_problem(shared, shared) is None
    # Stated once: the bullet on the folders above no longer repeats the minted-key owner rule.
    assert text.count("must be owned by the engine's own account, SYSTEM or Administrators") == 1


def test_the_records_say_delete_on_the_holder_is_not_counted() -> None:
    assert DELETE_ACCESS & _HOLDER_REPLACE_MASK == 0
    adr = _text(
        "docs/adr/0214-a-secrets-directory-and-one-accessor-for-the-engine-s-secret-class-settings.md"
    )
    assert "a broad group's `DELETE` on the holder is still not counted" in adr


def test_the_5636_fragment_does_not_claim_every_connection_key_file() -> None:
    # connection_key_files reads a connection's key only where it loads an identity from it.
    text = _text("changelog.d/5636-posix-key-file-owner-link-directory.security.md")
    assert "each connection's key file" not in text
    assert "the connection key files that `serve` and `supervise` judge" in text


@pytest.mark.parametrize(
    "fragment",
    [
        "changelog.d/5636-posix-key-file-owner-link-directory.security.md",
        "changelog.d/5657-key-file-owner-holder-and-folders-above.security.md",
    ],
)
def test_the_fragments_say_warn_mode_warns(fragment: str) -> None:
    assert 'Under `[security].enforcement = "warn"`' in _text(fragment)


def test_the_5657_fragment_names_the_refusals_it_ships() -> None:
    text = _text("changelog.d/5657-key-file-owner-holder-and-folders-above.security.md")
    assert "a key file whose own owner is such a group or cannot be read" in text
    assert "a TLS key the engine minted that is not owned by the engine's own account" in text
    assert "a junction or link on the path that an account it does not trust could change" in text


def test_the_posix_owner_rule_names_root_as_allowed() -> None:
    assert _posix_own_problem(mode=stat.S_IFREG | 0o600, uid=0, euid=_ENGINE_UID) is None
    doc = re.sub(r"\s+", " ", key_file_problem.__doc__ or "")
    assert "a file owned by an account other than the engine's own or root" in doc
    adr = _text(
        "docs/adr/0214-a-secrets-directory-and-one-accessor-for-the-engine-s-secret-class-settings.md"
    )
    assert "a directory or file owned by an account other than the engine's own or root" in adr
    assert "an account other than the engine's own or root owns" in _text("docs/CONFIGURATION.md")
