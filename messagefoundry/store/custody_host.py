# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``host`` key provider: key custody wired into the engine (vault BACKLOG #3411, slice S3
part B3b; the key custody ADR draft, rules 1 to 4, 3b and 13).

* **Mint** (:func:`mint_host_custody`). The command that creates the store mints the master key,
  the store id and the recovery key (:mod:`messagefoundry.store.custody`). The recovery key is shown
  once to the person at the terminal, who enters it back; nothing is written until that entry has
  opened the recovery wrap, so every blob written here records its recovery key as proved.
* **Where the blob goes.** A fixed name in the custody directory (:func:`custody_directory`): the
  directory ``MEFOR_SECRETS_DIRECTORY`` names, or else a SQLite store's own data directory.
  :data:`HOST_FILE_NAME` is the host blob in the engine account's own scope, written by an account
  minting for itself; :data:`HANDOFF_FILE_NAME` is the machine-scope handoff an administrator writes
  for the service account (Windows only). A second mint over either is ``FileExistsError``.
* **First start** (:func:`load_host_custody`). A start that finds only the handoff converts it: the
  service re-wraps the key in its own user scope, writes the host file, checks that it opens, and
  deletes the handoff through the handle it read it with. A start that finds both applies the crash
  rule: the handoff is deleted when it names the host file's store id, and the start refuses when it
  names another.
* **The store id pin.** Every open under this provider holds the store to the blob's store ids
  (:class:`~messagefoundry.store.store.StorePin`): a new store's genesis record is written with
  the current id, and an existing store's must name one the blob names.
* **Precedence.** A host blob is never read beside another store key source, and a host blob or a
  handoff in the custody directory refuses every other key provider (rules 2 and 13).
* **The account.** SYSTEM, LOCAL SERVICE and NETWORK SERVICE are refused always, and on Linux root
  and nobody (the custody primitives refuse them). An account that is not local to this host, at
  least a domain user or a group managed service account, is refused under ``enforce`` and named as
  a loosening outside it.

**Not wired here (slice B3c), each failing closed:** ``serve`` does not mint (a store under this
provider with no host blob refuses, naming ``provision-admin``); the installer does not pass
``--service-account``; there is no no-terminal probe beyond the terminal check; and an offline
command run by an account that cannot open the host blob refuses rather than asking for the
recovery key. Nothing here writes the keyring table.

**No key material reaches a log, an exception message, argv or the environment.** This module
logs nothing at all. The recovery key's text goes only to the terminal callable the caller passes,
which writes the console device, and an entry read back is dropped once it is parsed.
"""

from __future__ import annotations

import base64
import os
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple, Protocol

from messagefoundry.custody_posture import (
    HOST_KEY_PROVIDER,
    KeyCustodyPosture,
    record_key_custody,
)
from messagefoundry.engine_secrets import (
    CUSTODY_FILE_NAMES,
    KEY_CLASS_NAMES,
    SECRETS_DIRECTORY_VARIABLE,
)
from messagefoundry.store.keyprovider import KeyProviderError

if TYPE_CHECKING:
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store.base import Store
    from messagefoundry.store.custody import HostBlob, MasterKey, StoreId
    from messagefoundry.store.store import StorePin

__all__ = [
    "HANDOFF_FILE_NAME",
    "HOST_FILE_NAME",
    "HOST_PROVIDER",
    "HostCustodyMissing",
    "HostCustodyRefused",
    "MintedCustody",
    "RecoveryKeyTerminal",
    "KEYED_OPEN_TABLES",
    "SCHEMA_BOOKKEEPING_TABLES",
    "custody_directory",
    "foreign_custody_refusal",
    "host_store_key",
    "load_host_custody",
    "mint_host_custody",
    "store_holds_data",
    "store_pin",
]

HOST_PROVIDER = HOST_KEY_PROVIDER  # the one spelling, in the custody_posture leaf
#: The host blob, in the engine account's own scope, and the machine-scope handoff an administrator
#: writes for the service's first start (Windows). Named once, in ``engine_secrets``.
HOST_FILE_NAME, HANDOFF_FILE_NAME = CUSTODY_FILE_NAMES
#: How many times the recovery key may be entered back before the mint stops, writing nothing.
RECOVERY_KEY_ATTEMPTS = 3
#: Pushes the key off the screen, then clears the screen and, where the terminal honours it, its
#: scrollback. The blank lines do it where escape sequences are not honoured (a console with no
#: virtual terminal processing prints them as text instead).
_CLEAR_SCREEN = "\n" * 100 + "\x1b[2J\x1b[3J\x1b[H"
#: The HKDF label the store's data key is derived from the master key under, until slice S4 puts the
#: master key over wrapped data keys (draft rule 6). The master key itself never seals data.
_HOST_STORE_KEY_INFO = b"mefor/host-store-key/v1"


class HostCustodyRefused(KeyProviderError):
    """The ``host`` key provider could not provide the store key. A
    :class:`~messagefoundry.store.keyprovider.KeyProviderError`, so every command that already
    reports an unresolved store key as "could not start" reports this the same way. The message
    names files, settings and accounts, never key material."""


class MintedCustody(NamedTuple):
    """What a mint made: the blob, the file it was written to, and the recovery wrap, which is not
    secret and is kept in the new store's genesis record."""

    blob: HostBlob
    path: Path
    recovery_wrap: bytes


class HostCustodyMissing(HostCustodyRefused):
    """Neither a host blob nor a handoff is in the custody directory: no store key was minted here."""


class RecoveryKeyTerminal(Protocol):
    """The terminal the recovery key is shown on and entered back at. ``show`` writes to the
    console device itself, never to stdout, stderr or a log; ``read`` returns one entry, read
    without echo and never written anywhere else. Either raises ``OSError`` when the console is
    gone."""

    def show(self, text: str) -> None: ...

    def read(self) -> str: ...


# --- where the blob lives -------------------------------------------------------------------------


def custody_directory(
    settings: StoreSettings, *, environ: Mapping[str, str] | None = None
) -> Path | None:
    """The directory the host blob and the handoff live in, or ``None`` when there is none.

    The directory ``MEFOR_SECRETS_DIRECTORY`` names when it is set (an absolute path, or
    :class:`HostCustodyRefused`); otherwise a SQLite store's data directory, the one that holds the
    database file. A server store, or an in-memory one, has no data directory."""
    from messagefoundry.config.settings import StoreBackend

    environ = os.environ if environ is None else environ
    raw = environ.get(SECRETS_DIRECTORY_VARIABLE, "").strip()
    if raw:
        path = Path(raw)
        if not path.is_absolute():
            raise HostCustodyRefused(f"{SECRETS_DIRECTORY_VARIABLE} must be an absolute path")
        return path
    if settings.backend is StoreBackend.SQLITE and settings.path != ":memory:":
        return Path(settings.path).resolve().parent
    return None


def _custody_paths(directory: Path) -> tuple[Path, Path]:
    return directory / HOST_FILE_NAME, directory / HANDOFF_FILE_NAME


def _key_sources_beside(settings: StoreSettings, environ: Mapping[str, str]) -> list[str]:
    """Every other store key source that is set: the settings' own and the key-class variables."""
    named = []
    if settings.encryption_key:
        named.append("MEFOR_STORE_ENCRYPTION_KEY")
    if settings.encryption_key_file:
        named.append("[store].encryption_key_file")
    if settings.encryption_keys_retired.strip():
        named.append("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED")
    for name in KEY_CLASS_NAMES:
        if environ.get(name) and name not in named:
            named.append(name)
    return named


def _precedence_refusal(settings: StoreSettings, environ: Mapping[str, str]) -> str | None:
    """Why the ``host`` provider must not run with these settings (draft rules 2 and 13)."""
    beside = _key_sources_beside(settings, environ)
    if beside:
        return (
            f"[store].key_provider = 'host' reads the store key from its host blob only, and "
            f"{', '.join(beside)} is set beside it. Remove it: a second key source would sit "
            "readable and could be taken for the store's key"
        )
    if settings.cipher_provider != "aesgcm":
        return (
            f"[store].key_provider = 'host' supplies the in-process cipher, and "
            f"[store].cipher_provider is {settings.cipher_provider!r}. Use 'aesgcm'"
        )
    return None


def foreign_custody_refusal(
    settings: StoreSettings, *, environ: Mapping[str, str] | None = None
) -> str | None:
    """Why a store under any key provider but ``host`` must not open, or ``None``: a host blob or a
    handoff sits in its custody directory, so the store's key would be taken from somewhere other
    than the blob minted for it. An unusable directory setting is left for the reader of that
    setting to refuse."""
    environ = os.environ if environ is None else environ
    try:
        directory = custody_directory(settings, environ=environ)
    except HostCustodyRefused:
        return None
    if directory is None:
        return None
    found = [p.name for p in _custody_paths(directory) if os.path.lexists(p)]
    if not found:
        return None
    return (
        f"{' and '.join(found)} is in {directory}, but [store].key_provider is "
        f"{settings.key_provider!r}, and a store with a host blob takes its key from that blob "
        f"only. {keep_the_key_step()}"
    )


# --- the account ----------------------------------------------------------------------------------


def _engine_sid() -> str | None:
    """The SID of the account this process runs as. Windows only."""
    from messagefoundry.config.wiring import _win32_config_source_probes

    return _win32_config_source_probes().self_sid


def non_local_account_reading(
    *, enforcing: bool, sid_of: Callable[[], str | None] | None = None
) -> str | None:
    """Why this process's account is not local to this host, or ``None`` when it is (or off
    Windows). Under ``enforcing`` that is a refusal (:class:`HostCustodyRefused`); outside it the
    reason is returned for the caller to name as a loosening. SYSTEM and the shared service accounts
    are refused first, whatever the setting, as the custody files refuse them. ``sid_of`` stands in
    for the account read in a test."""
    if sys.platform != "win32" and sid_of is None:
        return None
    from messagefoundry.restricted_file import (
        custody_engine_problem,
        custody_non_local_account_problem,
        local_account_domain_sid,
    )

    sid = (sid_of or _engine_sid)()
    # SYSTEM and the shared service accounts first, refused whatever the setting, so they are
    # never named as a domain account.
    if (shared := custody_engine_problem(sid)) is not None:
        raise HostCustodyRefused(f"the store key is not held for this account: {shared}")
    assert sid is not None  # custody_engine_problem refuses an unread account
    problem = custody_non_local_account_problem(sid, local_account_domain_sid())
    if problem is not None and enforcing:
        raise HostCustodyRefused(
            f"the store key is not held for this account: {problem}. "
            "[security].enforcement = enforce refuses it"
        )
    return problem


# --- the key the store opens with, and its pin ----------------------------------------------------


def host_store_key(blob: HostBlob) -> str:
    """The base64 store key the in-process cipher opens with: HKDF-SHA256 over the master key under
    its own label, so the master key itself seals nothing (draft rule 6). Never log the result."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HOST_STORE_KEY_INFO)
    return base64.b64encode(hkdf.derive(blob.master_key.material())).decode("ascii")


def store_pin(blob: HostBlob, recovery_wrap: bytes = b"") -> StorePin:
    """The store ids ``blob`` holds a store to: its current id, and every earlier one, with the
    recovery wrap a new store's genesis record keeps when the blob was just minted."""
    from messagefoundry.store.store import StorePin

    current = blob.store_id.value
    accepted = frozenset({current, *(s.value for s in blob.earlier_store_ids)})
    return StorePin(current, accepted, recovery_wrap)


# --- reading, converting and settling at open -----------------------------------------------------


def _refused(what: str, exc: BaseException) -> HostCustodyRefused:
    """A refusal naming ``what`` and the reason ``exc`` gives. Every error this module wraps comes
    from the custody primitives, the DPAPI calls or the file system, whose texts carry no key."""
    return HostCustodyRefused(f"{what}: {exc}")


def _custody_errors() -> tuple[type[BaseException], ...]:
    from messagefoundry.secrets_dpapi import DpapiError, DpapiUnavailable
    from messagefoundry.store.custody import CustodyError

    # OSError covers RestrictedFileError and a refused file system call.
    return (CustodyError, DpapiError, DpapiUnavailable, OSError)


def _settle_left_handoff(handoff: Path, blob: HostBlob) -> None:
    """The crash rule (draft rule 3 step 3): a handoff found beside a host file that opens is
    deleted when it names the host file's store id, through the handle that read it, and refused
    when it names another."""
    from messagefoundry.store.custody import CustodyError, HandoffLeftBehind, consume_handoff_file

    def same_store(left: HostBlob) -> None:
        # The store id, and the key: a handoff that names this store under another key is not a
        # copy of what the host file holds.
        if left.store_id != blob.store_id or left.master_key != blob.master_key:
            raise CustodyError(
                f"it names store id {left.store_id.hex()} and the host file names "
                f"{blob.store_id.hex()}, or it holds another key, so it is not this store's. "
                f"{keep_the_key_step()}"
            )

    try:
        consume_handoff_file(handoff, same_store)
    except FileNotFoundError:
        return  # another start settled it first
    except HandoffLeftBehind as exc:
        raise _refused(f"the handoff {handoff} beside the host file", exc) from exc
    except _custody_errors() as exc:
        raise _refused(f"the handoff {handoff} beside the host file was refused", exc) from exc


class _ConversionLeftHostFile(Exception):  # noqa: N818 -- a carrier, caught one frame up
    """A conversion refused, and the host file it wrote could not be removed. Its text keeps the
    read-back's own reason and names the file to remove; it carries no key material."""


def _convert_handoff(host: Path, handoff: Path) -> HostBlob:
    """The service's first start (draft rule 3 step 2): re-wrap the handoff's key in this account's
    own scope as the host file, check that the host file opens to the same blob, then delete the
    handoff through the handle that read it. A conversion that fails leaves the handoff, and the
    start refuses (step 3)."""
    from messagefoundry.store.custody import (
        CustodyError,
        consume_handoff_file,
        read_host_file,
        write_host_file,
    )

    def remove_written() -> str | None:
        """Remove the host file this conversion wrote; why it could not be, or ``None``."""
        try:
            host.unlink()
        except FileNotFoundError:
            return None
        except OSError as exc:
            return exc.strerror or type(exc).__name__
        return None

    def convert(blob: HostBlob) -> None:
        write_host_file(host, blob)
        # A host file that does not read back as the handoff's blob, or does not read back at all,
        # is removed, so the next start finds the handoff alone and converts again, rather than
        # refuse on this file or take it for a copy the crash rule may keep. A removal that fails
        # never replaces the reason the read-back gave.
        reason: str | None = None
        try:
            same = read_host_file(host) == blob
        except Exception as exc:
            left = remove_written()
            if left is None:
                raise
            reason = f"{exc}"
        except BaseException:
            remove_written()
            raise
        else:
            if same:
                return
            left = remove_written()
            reason = "the host file written does not open to the handoff's key"
            if left is None:
                raise CustodyError(reason)
        raise _ConversionLeftHostFile(
            f"{reason}; and the host file it wrote could not be removed ({left}): remove {host} "
            "by hand, and the next start converts the handoff again"
        )

    return consume_handoff_file(handoff, convert)


def _read_host(host: Path) -> HostBlob | None:
    """The host blob at ``host``, or ``None`` when there is no file; every refusal wrapped."""
    from messagefoundry.store.custody import read_host_file

    try:
        return read_host_file(host)
    except FileNotFoundError:
        return None
    except _custody_errors() as exc:
        raise _refused(f"the host file {host} was refused", exc) from exc


def _read_or_convert(host: Path, handoff: Path, *, convert: bool) -> HostBlob:
    from messagefoundry.store.custody import HandoffLeftBehind

    blob = _read_host(host)
    if blob is not None:
        # A read that may not convert leaves a handoff beside the host file as it is.
        if convert and os.path.lexists(handoff):
            _settle_left_handoff(handoff, blob)
        return blob
    if not os.path.lexists(handoff):
        # An engine shard may have converted it between the two looks.
        blob = _read_host(host)
        if blob is not None:
            return blob
        raise HostCustodyMissing(
            f"no host blob ({host}) and no handoff ({handoff}): no store key was minted for this "
            "store here. Run `messagefoundry provision-admin`, which mints it with the store"
        )
    if not convert:
        raise HostCustodyRefused(
            f"the handoff {handoff} has not been converted yet: start the service once, as its "
            "own account, and it converts the handoff into its host blob"
        )
    try:
        return _convert_handoff(host, handoff)
    except FileNotFoundError:
        pass  # another start (an engine shard) converted it between the two reads
    except HandoffLeftBehind as exc:
        raise _refused("the handoff was converted, but", exc) from exc
    except _ConversionLeftHostFile as exc:
        raise _refused(
            f"the handoff {handoff} could not be converted, and the start refuses rather than "
            "run from it",
            exc,
        ) from exc
    except _custody_errors() as exc:
        # An engine shard converting it at the same moment holds it, or has it pending delete;
        # the host file it leaves is read below. With none there, the start refuses.
        if not os.path.lexists(host):
            raise _refused(
                f"the handoff {handoff} could not be converted, and the start refuses rather than "
                "run from it",
                exc,
            ) from exc
    blob = _read_host(host)
    if blob is None:
        raise HostCustodyMissing(f"the handoff {handoff} went away and left no host file")
    return blob


def check_host_custody_settings(
    settings: StoreSettings, *, environ: Mapping[str, str] | None = None
) -> tuple[Path, Path]:
    """The host blob's and the handoff's paths, once the settings pass: no other store key source
    beside the blob, the ``aesgcm`` cipher, and a custody directory. Raises
    :class:`HostCustodyRefused` otherwise. A blob a minting command passes in is held to the same
    settings a read is."""
    environ = os.environ if environ is None else environ
    refusal = _precedence_refusal(settings, environ)
    if refusal is not None:
        raise HostCustodyRefused(refusal)
    directory = custody_directory(settings, environ=environ)
    if directory is None:
        raise HostCustodyRefused(
            "[store].key_provider = 'host' needs a directory for the host blob: set "
            f"{SECRETS_DIRECTORY_VARIABLE}, since this store has no data directory of its own"
        )
    return _custody_paths(directory)


def load_host_custody(
    settings: StoreSettings,
    *,
    enforcing: bool,
    convert: bool = True,
    observe: bool = False,
    environ: Mapping[str, str] | None = None,
) -> HostBlob:
    """The host blob a store under the ``host`` key provider opens with.

    Refuses, with :class:`HostCustodyRefused`: what :func:`check_host_custody_settings` refuses, an
    account the custody rules refuse (and one not local to this host under ``enforcing``), a host
    file or handoff the custody reads refuse, and a handoff the crash rule refuses.
    :class:`HostCustodyMissing` when neither file is there. ``convert`` lets a handoff be
    converted; a read-only open passes ``False``. ``observe`` records what was found as this
    process's custody observation; only a store open passes it, so a key read for another purpose
    (a backup, the upload cipher) never overwrites what the open found."""
    host, handoff = check_host_custody_settings(settings, environ=environ)
    if not (os.path.lexists(host) or os.path.lexists(handoff)):
        # Before the account is judged: no key is here for any account, and a command that mints
        # one for another account (provision-admin --service-account) must learn that first.
        raise HostCustodyMissing(
            f"no host blob ({host}) and no handoff ({handoff}): no store key was minted for this "
            "store here. Run `messagefoundry provision-admin`, which mints it with the store"
        )
    account = non_local_account_reading(enforcing=enforcing)
    blob = _read_or_convert(host, handoff, convert=convert)
    if observe:
        record_key_custody(
            KeyCustodyPosture(
                recovery_key_proved=blob.recovery_proved_at is not None, non_local_account=account
            )
        )
    return blob


#: The table whose row a server schema build writes before anything uses the store, so a row in
#: it is not data: ``schema_meta`` (the schema hash). ``global_session_epoch``'s seed row is
#: handled by the census itself (``SCHEMA_SEED_FILTERS``), which reads it as held only once a
#: revoke-all has raised the epoch. Names compare exactly, as the catalog stores them.
SCHEMA_BOOKKEEPING_TABLES: Final = frozenset({"schema_meta"})
#: The tables a keyed open commits before it starts the audit chain: the store salt, the AES-GCM
#: invocation counter and the keyed-surface markers. None holds a row of operator data. While
#: the chain is empty they are what a mint that failed before its genesis record left, so they do
#: not count; once ``audit_log`` holds a row they count like every other table.
KEYED_OPEN_TABLES: Final = frozenset({"store_salt", "cipher_meta", "keyed_surface"})
#: Tables every backend's schema has. A catalog read that does not list all of them did not see
#: the store's schema (no ``schema_meta`` resolved, or a permission hid them), so it proves
#: nothing about what the store holds.
_STORE_CORE_TABLES: Final = frozenset({"messages", "message_events", "audit_log", "users"})


async def store_holds_data(store: Store) -> bool:
    """Whether an opened store holds anything a mint must not take over. A server database with
    an empty audit chain may still be a store that ran keyless, so an empty chain alone does not
    make it absent (vault BACKLOG #3411).

    Counted: every table :meth:`Store.table_occupancy` lists, read from the database's own
    catalog, so a table this build does not name still counts. Excluded: only
    :data:`SCHEMA_BOOKKEEPING_TABLES`, and :data:`KEYED_OPEN_TABLES` while ``audit_log`` is
    empty. Any row in any other table holds data. Names compare exactly. Fails closed: a census
    that does not list every table in :data:`_STORE_CORE_TABLES` holds data, and a census that
    cannot be read, or cannot be shown complete, raises rather than reading as empty. What the
    census cannot see is stated once, on :meth:`Store.table_occupancy`. Counts only, so a probe
    opened under a throwaway key decrypts nothing."""
    occupancy = await store.table_occupancy()
    if not _STORE_CORE_TABLES.issubset(occupancy):
        return True
    held = {name for name, rows in occupancy.items() if rows}
    excluded = SCHEMA_BOOKKEEPING_TABLES | (
        KEYED_OPEN_TABLES if not occupancy["audit_log"] else set()
    )
    return bool(held - excluded)


# --- the mint -------------------------------------------------------------------------------------


def keep_the_key_step() -> str:
    """The one way on for every path that meets a key file or store it cannot tie to this store
    (PR 2804 fifth hold): it leaves everything that exists in place and creates only new things,
    a custody directory and a store location of this store's own. Names no path and no key."""
    # The variable is named here as a literal, not through SECRETS_DIRECTORY_VARIABLE: this text
    # reaches stderr, and CodeQL's name heuristic reads that constant as a secret (alert 315).
    return (
        "The engine cannot tell whose key an existing host blob or handoff in this store's custody "
        "directory holds, so it leaves that file in place, and the store too. To provision this "
        "store, give it a custody directory and a store location of its own: set "
        "MEFOR_SECRETS_DIRECTORY to a new, empty directory, here and in this store's own service "
        "environment, never in one another store's service also reads, since that store would "
        "then look for its key there; and point [store] at a new SQLite path or, on a server "
        "backend, a new database. Then run the command again. Nothing left in place is carried "
        "over to the new store"
    )


def mint_target(
    settings: StoreSettings,
    *,
    service_account: str | None,
    enforcing: bool,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """The file a mint would write, checked before anything is minted or shown.

    Refuses as :func:`load_host_custody` does for the settings and, when minting for this account
    (``service_account`` of ``None``), for the account. ``FileExistsError`` when a host blob or a
    handoff is already there: a second mint over a store's key is never made. A handoff is Windows
    only; a POSIX host mints as the service user itself."""
    host, handoff = check_host_custody_settings(settings, environ=environ)
    for path in (host, handoff):
        if os.path.lexists(path):
            raise FileExistsError(
                f"{path} already exists, so a store key was already minted here; a second mint "
                f"is never made over it. {keep_the_key_step()}"
            )
    if service_account is None:
        # What the write refuses for this account, asked now: the shared and non-local accounts
        # (and on Linux root and nobody).
        from messagefoundry.store.custody import CustodyError, check_host_writable

        non_local_account_reading(enforcing=enforcing)
        try:
            check_host_writable()
        except CustodyError as exc:
            raise _refused("no store key was minted", exc) from exc
        return host
    if sys.platform != "win32":
        raise HostCustodyRefused(
            "--service-account writes a Windows handoff; on this host run provision-admin as the "
            "service user itself, and it writes that account's host file"
        )
    from messagefoundry.store.custody import check_handoff_writable

    try:
        check_handoff_writable(service_account, enforcing=enforcing)
    except _custody_errors() as exc:
        raise _refused("no store key was minted", exc) from exc
    return handoff


def _prove_recovery_key(
    terminal: RecoveryKeyTerminal, wrapped: bytes, *, master_key: MasterKey, store_id: StoreId
) -> bool:
    """Read the recovery key back until an entry opens ``wrapped`` to ``master_key``, at most
    :data:`RECOVERY_KEY_ATTEMPTS` times. Each entry is dropped once it is parsed."""
    from messagefoundry.store.custody import CustodyError, RecoveryKey, unwrap_master_key

    for attempt in range(1, RECOVERY_KEY_ATTEMPTS + 1):
        terminal.show("Enter the recovery key back: ")
        entry = terminal.read()
        problem: str | None = None
        try:
            parsed = RecoveryKey.parse(entry)
        except CustodyError as exc:
            problem = str(exc)
        del entry
        if problem is None:
            try:
                opened = unwrap_master_key(wrapped, parsed, store_id)
            except CustodyError:
                problem = "that is a recovery key, but not the one shown above"
            else:
                if opened == master_key:
                    return True
                problem = "that entry did not open the store key"
        if attempt < RECOVERY_KEY_ATTEMPTS:
            terminal.show(f"{problem}. Try again.\n")
    return False


def mint_host_custody(
    settings: StoreSettings,
    *,
    service_account: str | None,
    enforcing: bool,
    terminal: RecoveryKeyTerminal,
    environ: Mapping[str, str] | None = None,
    now: Callable[[], float] = time.time,
) -> MintedCustody:
    """Mint a store's key custody, prove the recovery key, and write the blob (draft rules 1, 3, 4).

    Mints the master key, the store id and the recovery key; shows the recovery key once on
    ``terminal``, waits for the person to say it is copied, clears the screen, and reads it back
    until an entry opens the recovery wrap to the master key. Only then is anything written: the
    host blob in this account's own scope when ``service_account`` is ``None``, else the
    machine-scope handoff for that account. Returns the blob, which records the proof, the file
    written and the recovery wrap. The caller creates the store with the blob and the wrap, so its
    genesis record carries the blob's store id and keeps the wrap (``open_store(custody=...,
    recovery_wrap=...)``).

    Raises what :func:`mint_target` raises before anything is minted; :class:`HostCustodyRefused`
    when the entries run out, writing nothing, or when a write is refused; ``FileExistsError`` when
    the file appeared since the check; and ``OSError`` when the terminal goes away."""
    from messagefoundry.store.custody import (
        HostBlob,
        MasterKey,
        RecoveryKey,
        StoreId,
        wrap_master_key,
        write_handoff_file,
        write_host_file,
    )

    target = mint_target(
        settings,
        service_account=service_account,
        enforcing=enforcing,
        environ=environ,
    )
    master_key, store_id, recovery_key = MasterKey.mint(), StoreId.mint(), RecoveryKey.mint()
    wrapped = wrap_master_key(master_key, recovery_key, store_id)
    terminal.show(
        "\nThis store's RECOVERY KEY is shown once, now. It is what moves the store to another "
        "host, and the only way back in if this host is lost: with neither, the data is gone for "
        "good. Copy it somewhere off this host, then clear this terminal's scrollback.\n\n  "
        + recovery_key.text()
        + "\n\n"
    )
    del recovery_key
    # The entry must come from the copy kept, not from the screen: the key is cleared first.
    terminal.show("Press Enter once the recovery key is copied off this host. ")
    terminal.read()
    terminal.show(_CLEAR_SCREEN)
    proved = _prove_recovery_key(terminal, wrapped, master_key=master_key, store_id=store_id)
    terminal.show(_CLEAR_SCREEN)
    if not proved:
        raise HostCustodyRefused(
            f"the recovery key was not entered back in {RECOVERY_KEY_ATTEMPTS} tries, so it is not "
            "shown to be kept; nothing was written. Run the command again: it mints a new one"
        )
    blob = HostBlob(master_key, store_id, (), int(now()))
    try:
        if service_account is None:
            write_host_file(target, blob)
        else:
            write_handoff_file(target, blob, service_account=service_account, enforcing=enforcing)
    except FileExistsError:
        raise
    except _custody_errors() as exc:
        raise _refused(f"the store key was not written to {target}", exc) from exc
    return MintedCustody(blob, target, wrapped)
