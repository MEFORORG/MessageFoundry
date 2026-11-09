# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What this process observed of its store key's custody, and the loosenings that follows from it
(vault BACKLOG #3411, key custody slice S3).

A leaf: the standard library only, so ``config.settings.security_loosenings`` can read it without
importing the store package. :mod:`messagefoundry.store.custody_host` records an observation each
time it opens a host blob under the ``host`` key provider. A process that has opened none, such as
``messagefoundry security show`` run from a shell, holds none, and the observed entries are then not
named: no observation is not a clean result, and that caller says what it reports.

The observation is a fact about this process (the account it runs as, the blob it read), which is
why it is held per process rather than passed down every call that renders the loosenings.

Never holds key material: two plain facts and a refusal text that names an account by SID.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "HOST_KEY_PROVIDER",
    "KeyCustodyPosture",
    "key_custody_loosenings",
    "observed_key_custody",
    "record_key_custody",
]

#: The ``[store].key_provider`` that holds the master key in a host blob.
HOST_KEY_PROVIDER = "host"


@dataclass(frozen=True, slots=True)
class KeyCustodyPosture:
    """What one open of a host blob found.

    ``recovery_key_proved`` is whether the blob records that the recovery key came back from
    outside and opened the recovery wrap (the key custody draft, rule 4). ``non_local_account`` is
    why the account the engine runs as is not local to this host, when it is not and
    ``[security].enforcement`` let it through; ``None`` when it is local, or on a POSIX host."""

    recovery_key_proved: bool
    non_local_account: str | None = None


_lock = threading.Lock()
_observed: KeyCustodyPosture | None = None


def record_key_custody(posture: KeyCustodyPosture | None) -> None:
    """Record what the latest open of a host blob in this process found. ``None`` forgets it."""
    global _observed
    with _lock:
        _observed = posture


def observed_key_custody() -> KeyCustodyPosture | None:
    """What the latest open of a host blob in this process found, or ``None`` when it opened none."""
    with _lock:
        return _observed


def key_custody_loosenings(
    *, key_provider: str, cipher_provider: str, observed: KeyCustodyPosture | None
) -> list[tuple[str, str]]:
    """The ``(name, plain-language risk)`` entries for the store key's custody. One place for the
    wording.

    ``store_id_not_pinned`` is read from the settings: under the ``vault`` key provider or the
    ``vault_transit`` cipher no host blob holds the store id, so nothing checks at open that the key
    belongs to this store (the key custody design leaves those providers as they are until its slice
    S7). The other two are read from ``observed``, and only under the ``host`` key provider."""
    out: list[tuple[str, str]] = []
    if key_provider == "vault" or cipher_provider == "vault_transit":
        out.append(
            (
                "store_id_not_pinned",
                "the store key comes from Vault, not from a host blob, so no store id is pinned: "
                "nothing checks at open that the key belongs to this store and not to a copy or "
                "another store under the same Vault key",
            )
        )
    if key_provider != HOST_KEY_PROVIDER or observed is None:
        return out
    if not observed.recovery_key_proved:
        out.append(
            (
                "recovery_key_unproved",
                "the store's recovery key has never been entered back and shown to open the "
                "store's key, so nobody has shown that the copy kept off this host is right. If "
                "this host is lost, a wrong copy loses the data for good",
            )
        )
    if observed.non_local_account is not None:
        out.append(
            (
                "key_custody_non_local_account",
                f"the store key is held for an account that is not local to this host: "
                f"{observed.non_local_account}. [security].enforcement = enforce refuses it",
            )
        )
    return out
