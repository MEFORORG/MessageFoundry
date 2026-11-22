# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Some records about the key-file check say no more than the check does (vault BACKLOG #5657 step 14).

Most tests pin a sentence a record was corrected to beside the behaviour it describes, read from a
pure decision function, so a change to either shows here. The records read are ``docs/PHI.md``
section 2, *Key files*, ``docs/CONFIGURATION.md``'s secrets directory section, the ``docker/k8s``
manifests and the ``key_file_problem`` docstring; for ADR 0214's amendments only the removed
wording's absence is checked. Text is compared with its line breaks folded to spaces.
"""

from __future__ import annotations

import functools
import inspect
import re
import stat
import sys
from pathlib import Path

import pytest

from messagefoundry.auth.anchor_path import (
    _SHARED_SERVICE_SIDS,
    ACCESS_ALLOWED_ACE_TYPE,
    DIRECTORY,
    LINK,
    SYSTEM_SID,
    WinSecurity,
    WinTrust,
)
from messagefoundry.config.key_file_access import key_file_problem
from messagefoundry.restricted_file import (
    _posix_holder_problem,
    _posix_own_problem,
    _windows_engine_owner_problem,
    _windows_link_problem,
)

_REPO = Path(__file__).resolve().parent.parent
_ADR_0214 = (
    "docs/adr/0214-a-secrets-directory-and-one-accessor-for-the-engine-s-secret-class-settings.md"
)
_ENGINE_UID = 10001
_SHARED_SERVICES = sorted(_SHARED_SERVICE_SIDS)  # LOCAL SERVICE, NETWORK SERVICE


@functools.cache
def _text(relative: str) -> str:
    return re.sub(r"\s+", " ", (_REPO / relative).read_text(encoding="utf-8"))


@pytest.mark.parametrize("manifest", ["docker/k8s/statefulset.yaml", "docker/k8s/ha-postgres.yaml"])
def test_the_manifests_say_a_key_whose_own_name_is_a_link_is_refused(manifest: str) -> None:
    # A link above the key that only root or the engine can change passes the link walk, so "a TLS
    # key reached through a link" said more than the check does. A link at the key's own name is
    # refused whoever owns it, which is what a Secret volume serves.
    text = _text(manifest)
    assert "refuses a TLS key reached through a link" not in text
    assert "refuses at least a TLS key whose own name is a link, or one a group" in text
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
    assert trust.grantee(shared) is False
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


# --- the refusal and remedy text, for an engine that runs as a shared service account -------------

_SHARED_TEXT = "a LOCAL SERVICE or NETWORK SERVICE engine's own not counting"


def _joined(source: str) -> str:
    """``source`` with adjacent string literals joined and whitespace folded to single spaces."""
    return re.sub(r"\s+", " ", re.sub(r'"\s+"', "", source))


@pytest.mark.parametrize("shared", _SHARED_SERVICES)
def test_a_link_refusal_does_not_say_the_engine_account_is_another(shared: str) -> None:
    # The link rule never trusts a shared service account, the engine's own included, so a refusal
    # that said "an account other than the engine's own" named the engine's account as another.
    system = WinSecurity(SYSTEM_SID, ((ACCESS_ALLOWED_ACE_TYPE, 0, 0x001F01FF, SYSTEM_SID),))
    owned = WinSecurity(shared, ((ACCESS_ALLOWED_ACE_TYPE, 0, 0x001F01FF, SYSTEM_SID),))

    def read(path: str, _kind: str) -> WinSecurity:
        return owned if path == "C:\\linked" else system

    chain = [("C:\\", DIRECTORY), ("C:\\linked", LINK)]
    problem = _windows_link_problem(chain, read, WinTrust(shared, lambda _sid: False))
    assert problem is not None
    assert "other than the engine's own" not in problem
    assert "does not trust" in problem and "even when the engine runs as one" in problem


def test_the_remedies_do_not_say_another_account_for_a_shared_service_engine() -> None:
    import messagefoundry.__main__ as cli
    from messagefoundry import engine_secrets, secrets_dpapi
    from messagefoundry.config.key_file_access import KEY_FILE_REMEDY

    texts = {
        "KEY_FILE_REMEDY": KEY_FILE_REMEDY,
        "engine_secrets._REMEDY": engine_secrets._REMEDY,
        # Both run only where DPAPI is, so their text is read from the source.
        "load_protected_key": _joined(inspect.getsource(secrets_dpapi.load_protected_key)),
        "_store_key_file_gate": _joined(inspect.getsource(cli._store_key_file_gate)),
    }
    for name, text in texts.items():
        assert "that another account can change" not in text, name
        assert _SHARED_TEXT in text, name


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_the_generated_key_remedy_names_the_trusted_accounts(
    monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    import messagefoundry.__main__ as cli

    monkeypatch.setattr(cli, "_engine_account_name", lambda: "mefor")
    monkeypatch.setattr(sys, "platform", platform)
    remedy = cli._generated_tls_key_remedy(Path("/srv/mefor"))
    assert "another account can change" not in remedy
    if platform == "win32":
        assert _SHARED_TEXT in remedy
    else:
        assert "an account other than root or the engine's own" in remedy
    # Step 11 (g): the delete-and-mint advice names the key's own owner refusal, which a refusal
    # about the directory's owner ("the directory that holds it is owned by") does not match.
    assert "names who owns it" not in remedy
    assert '"is not restricted: it is owned by"' in remedy
