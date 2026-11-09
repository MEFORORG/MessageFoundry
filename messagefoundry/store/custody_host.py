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
logs at least a custody directory it could not check before a mint, and, through the store's held
log lines, the class name of an error a refusal at open replaced; never an error's text. The
recovery key's text goes only to the terminal callable the caller passes,
which writes the console device, and an entry read back is dropped once it is parsed.
"""

from __future__ import annotations

import base64
import logging
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
    reports an unresolved store key as "could not start" reports it as one. The message names
    files, settings, accounts and the remedy, never key material.

    What follows holds for each refusal :func:`load_host_custody` raises, and not for every
    instance: at least the mint's (:func:`_refused`) quote the error they replace and chain it.
    ``open_store`` raises one as it is. A seam that resolves the key without that open, at least
    :func:`~messagefoundry.store.base.resolve_active_key`, ``resolve_decrypt_keys`` and
    ``build_store_cipher``, replaces it with a new ``KeyProviderError`` (BACKLOG #4882) that keeps
    its text, since it is recorded as built by the engine (:func:`_recorded_as`). That text reads
    nothing from an error it replaced, and the refusal keeps no cause and no context."""


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
            raise _recorded_as(
                HostCustodyRefused, f"{SECRETS_DIRECTORY_VARIABLE} must be an absolute path"
            )
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
        f"{settings.key_provider!r}. A store with a host blob takes its key from that blob only: "
        "if it holds this store's key, keep a copy of each key setting's value first, somewhere "
        "as protected as where it is now, since it may be the only copy of a store key, and then "
        "set [store].key_provider = 'host' and remove every other store key setting, with "
        "[store].cipher_provider = 'aesgcm', which that provider needs. The engine cannot tell "
        "whether the blob holds this store's key, so it "
        f"leaves the file in place. {keep_the_key_step(settings, new_store=False)}"
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
        raise _recorded_as(
            HostCustodyRefused, f"the store key is not held for this account: {shared}"
        )
    assert sid is not None  # custody_engine_problem refuses an unread account
    problem = custody_non_local_account_problem(sid, local_account_domain_sid())
    if problem is not None and enforcing:
        raise _recorded_as(
            HostCustodyRefused,
            f"the store key is not held for this account: {problem}. "
            "[security].enforcement = enforce refuses it",
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
    """A refusal naming ``what`` and the reason ``exc`` gives, for the mint. Every error this module
    wraps comes from the custody primitives, the DPAPI calls or the file system, whose texts carry
    no key. A read at open is refused by :func:`_read_refusal` instead, which reads no text."""
    return HostCustodyRefused(f"{what}: {exc}")


def _recorded_as[E: Exception](kind: type[E], text: str) -> E:
    """A new ``kind`` with ``text``, recorded as built by the engine, so a seam that replaces it
    (:func:`~messagefoundry.store.base.resolve_active_key` and its siblings, BACKLOG #4882) keeps
    ``text``, read from the record and never from the instance."""
    from messagefoundry.store.base import _recorded

    refusal = kind(text)
    _recorded(refusal, text)
    return refusal


def _read_reason(exc: BaseException) -> str:
    """Why a custody read or conversion refused, for a refusal at open: the text this module
    recorded for an error it built itself (:func:`_recorded_as`), or else a fixed text chosen by
    ``exc``'s class as read with ``type``. No text is read from ``exc``, so an OS, DPAPI or custody
    primitive text never reaches the refusal (BACKLOG #4882). A replaced error's class is logged by
    name alone, once the caller has left its handler (:func:`load_host_custody`)."""
    from messagefoundry.secrets_dpapi import DpapiError, DpapiUnavailable
    from messagefoundry.store.base import _log_unjudged, _recorded_text
    from messagefoundry.store.custody import CustodyError

    if (recorded := _recorded_text(exc)) is not None:
        return recorded
    kind = type(exc)
    _log_unjudged("a host custody error was replaced", kind)
    if issubclass(kind, DpapiUnavailable):
        return (
            "DPAPI, which a handoff and a Windows host file need, is not available on this host; "
            "a POSIX host uses no handoff"
        )
    if issubclass(kind, DpapiError):
        return (
            "a DPAPI call refused it; a host file opens only for the account that wrote it, and "
            "a handoff only on the machine it was written on"
        )
    if issubclass(kind, CustodyError):
        return (
            "a custody check refused it; those checks read at least the engine's account, the "
            "file's owner and access list, the file system it is on, and its contents"
        )
    if issubclass(kind, OSError):
        return "the file system refused it"
    return "it failed"


def _read_refusal(what: str, exc: BaseException) -> HostCustodyRefused:
    """A refusal of a read at open naming ``what``, which holds the paths and any remedy, then
    :func:`_read_reason`. :func:`load_host_custody` raises it with no chain."""
    return _recorded_as(HostCustodyRefused, f"{what}: {_read_reason(exc)}")


def custody_refusal_at_open(exc: BaseException) -> HostCustodyRefused:
    """The refusal ``open_store`` raises in place of an error on its custody path that the engine
    did not build, at least one from the custody directory's resolve, the minted blob's checks and
    key, or the observation, which the custody reads do not wrap: :func:`_read_refusal`'s fixed
    text, reading nothing from ``exc``. The caller raises it with no chain and then flushes the
    replaced class's log line (BACKLOG #4882)."""
    return _read_refusal(
        "the store's key custody could not be read or checked at the open: check "
        f"[store].key_provider, the custody directory ({SECRETS_DIRECTORY_VARIABLE}, or else a "
        "SQLite store's data directory) and the host file and handoff in it",
        exc,
    )


def _custody_errors() -> tuple[type[BaseException], ...]:
    from messagefoundry.secrets_dpapi import DpapiError, DpapiUnavailable
    from messagefoundry.store.custody import CustodyError

    # OSError covers RestrictedFileError and a refused file system call.
    return (CustodyError, DpapiError, DpapiUnavailable, OSError)


def _settle_left_handoff(handoff: Path, blob: HostBlob) -> HostCustodyRefused | None:
    """The crash rule (draft rule 3 step 3): a handoff found beside a host file that opens is
    deleted when it names the host file's store id, through the handle that read it, and refused
    when it names another. Returns the refusal, or ``None`` when the handoff is settled or another
    start settled it first; the caller raises it once it has dropped the blob (BACKLOG #4882)."""
    from messagefoundry.store.custody import CustodyError, HandoffLeftBehind, consume_handoff_file

    def same_store(left: HostBlob) -> None:
        # The store id, and the key: a handoff that names this store under another key is not a
        # copy of what the host file holds.
        if left.store_id != blob.store_id or left.master_key != blob.master_key:
            raise _recorded_as(
                CustodyError,
                f"it names store id {left.store_id.hex()} and the host file names "
                f"{blob.store_id.hex()}, or it holds another key, so it is not this store's. "
                "It may be another store's only key, so keep the file: move it out of "
                f"{handoff.parent} to a path outside that directory that does not exist yet, on "
                "the same volume and in a directory readable by no one but administrators, so it "
                "keeps its own access list, then run the command again",
            )

    try:
        consume_handoff_file(handoff, same_store)
    except FileNotFoundError:
        return None  # another start settled it first
    except HandoffLeftBehind:
        return _left_behind("the handoff beside the host file was settled", handoff)
    except _custody_errors() as exc:
        return _read_refusal(f"the handoff {handoff} beside the host file was refused", exc)
    return None


class _ConversionLeftHostFile(Exception):  # noqa: N818 -- a carrier, caught one frame up
    """A conversion refused, and the host file it wrote could not be removed. Its recorded text
    keeps the read-back's reason, as :func:`_read_reason` gives it, and names the file to remove;
    it carries no key material."""


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

    def remove_written() -> bool:
        """Remove the host file this conversion wrote; whether it is gone."""
        from messagefoundry.store.base import _log_unjudged

        try:
            host.unlink(missing_ok=True)
        except OSError as exc:
            _log_unjudged("the host file a conversion wrote could not be removed", type(exc))
            return False
        return True

    def convert(blob: HostBlob) -> None:
        write_host_file(host, blob)
        # A host file that does not read back as the handoff's blob, or does not read back at all,
        # is removed, so the next start finds the handoff alone and converts again, rather than
        # refuse on this file or take it for a copy the crash rule may keep. A removal that fails
        # never replaces the reason the read-back gave.
        try:
            same = read_host_file(host) == blob
        except Exception as exc:
            if remove_written():
                raise
            reason = _read_reason(exc)
        except BaseException:
            remove_written()
            raise
        else:
            if same:
                return
            reason = "the host file written does not open to the handoff's key"
            if remove_written():
                raise _recorded_as(CustodyError, reason)
        raise _recorded_as(
            _ConversionLeftHostFile,
            f"{reason}; and the host file it wrote could not be removed: remove {host} by hand, "
            "and the next start converts the handoff again",
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
        refusal = _read_refusal(f"the host file {host} was refused", exc)
    try:
        raise refusal  # outside the handler, so it has no context (BACKLOG #4882)
    finally:
        del refusal  # no cycle through this frame


def _read_or_convert(host: Path, handoff: Path, *, convert: bool) -> HostBlob:
    from messagefoundry.store.custody import HandoffLeftBehind

    blob = _read_host(host)
    if blob is not None:
        # A read that may not convert leaves a handoff beside the host file as it is.
        if convert and os.path.lexists(handoff):
            left = _settle_left_handoff(handoff, blob)
            if left is not None:
                # The master key is dropped from this frame, which the refusal's traceback keeps,
                # and the refusal from it, so the refusal never holds the key and leaves no
                # cycle. The frame that judged the handoff has returned, so the traceback does not
                # hold it either.
                del blob
                try:
                    raise left  # outside any handler, so it has no context (BACKLOG #4882)
                finally:
                    del left
        return blob
    if not os.path.lexists(handoff):
        # An engine shard may have converted it between the two looks.
        blob = _read_host(host)
        if blob is not None:
            return blob
        raise _missing(host, handoff)
    if not convert:
        raise _recorded_as(
            HostCustodyRefused,
            f"the handoff {handoff} has not been converted yet: start the service once, as its "
            "own account, and it converts the handoff into its host blob",
        )
    unconverted = (
        f"the handoff {handoff} could not be converted, and the start refuses rather than run "
        "from it"
    )
    refusal: HostCustodyRefused | None = None
    try:
        return _convert_handoff(host, handoff)
    except FileNotFoundError:
        pass  # another start (an engine shard) converted it between the two reads
    except HandoffLeftBehind:
        refusal = _left_behind(f"the handoff was converted into the host file {host}", handoff)
    except _ConversionLeftHostFile as exc:
        refusal = _read_refusal(unconverted, exc)
    except _custody_errors() as exc:
        # An engine shard converting it at the same moment holds it, or has it pending delete;
        # the host file it leaves is read below. With none there, the start refuses.
        if not os.path.lexists(host):
            refusal = _read_refusal(unconverted, exc)
        else:
            from messagefoundry.store.base import _log_unjudged

            _log_unjudged("a handoff conversion failed beside a host file", type(exc))
    if refusal is not None:
        try:
            raise refusal  # outside the handler, so it has no context (BACKLOG #4882)
        finally:
            del refusal  # no cycle through this frame
    blob = _read_host(host)
    if blob is None:
        raise _recorded_as(
            HostCustodyMissing, f"the handoff {handoff} went away and left no host file"
        )
    return blob


def _left_behind(done: str, handoff: Path) -> HostCustodyRefused:
    """``done``, and ``handoff`` was not shown deleted (:class:`HandoffLeftBehind`), whose own
    text, which may quote an OS reason, is not read."""
    return _recorded_as(
        HostCustodyRefused,
        f"{done}, but the handoff {handoff} could not be shown deleted: its delete was refused, or "
        "another handle still holds it and its name goes when that closes. Check that "
        f"{handoff} is gone, and delete the handoff if it is not; keep the host file",
    )


def _missing(host: Path, handoff: Path) -> HostCustodyMissing:
    """Neither ``host`` nor ``handoff`` is there."""
    return _recorded_as(
        HostCustodyMissing,
        f"no host blob ({host}) and no handoff ({handoff}): no store key was minted for this "
        "store here. Run `messagefoundry provision-admin`, which mints it with the store",
    )


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
        raise _recorded_as(HostCustodyRefused, refusal)
    directory = custody_directory(settings, environ=environ)
    if directory is None:
        raise _recorded_as(
            HostCustodyRefused,
            "[store].key_provider = 'host' needs a directory for the host blob: set "
            f"{SECRETS_DIRECTORY_VARIABLE}, since this store has no data directory of its own",
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
    (a backup, the upload cipher) never overwrites what the open found.

    Each refusal's text is fixed: it names the paths and settings, and the remedy where there is
    one, and reads no text from an error it replaced (BACKLOG #4882). An ``Exception`` from the
    account read, the file reads or the conversion that this module did not build is replaced by
    one too, its class logged by name alone. One that replaces an error is raised outside the
    handler, so it has no cause and no context, and each is recorded as built by the engine, so a
    seam that replaces it keeps that text."""
    from messagefoundry.store.base import _flush_unjudged, _recorded_text

    host, handoff = check_host_custody_settings(settings, environ=environ)
    if not (os.path.lexists(host) or os.path.lexists(handoff)):
        # Before the account is judged: no key is here for any account, and a command that mints
        # one for another account (provision-admin --service-account) must learn that first.
        raise _missing(host, handoff)
    try:
        try:
            stage = f"the engine's account could not be judged for the host custody of {host}"
            account = non_local_account_reading(enforcing=enforcing)
            stage = f"the host custody read of {host} and {handoff} failed"
            blob = _read_or_convert(host, handoff, convert=convert)
        except Exception as exc:
            if _recorded_text(exc) is not None:
                raise  # one this module built, already with no chain
            caught = exc
        else:
            if observe:
                record_key_custody(
                    KeyCustodyPosture(
                        recovery_key_proved=blob.recovery_proved_at is not None,
                        non_local_account=account,
                    )
                )
            return blob
        # Built and raised outside the handler, so neither the refusal nor anything its build
        # raises has the caught error as its context.
        try:
            refusal = _read_refusal(stage, caught)
        finally:
            del caught
        try:
            raise refusal
        finally:
            del refusal  # no cycle through this frame
    finally:
        _flush_unjudged()  # the replaced classes, logged once no handler is running


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


def keep_the_key_step(
    settings: StoreSettings, *, new_store: bool, service_account: str | None = None
) -> str:
    """A fallback way on, after a caller's own remedy, at least for the paths that meet a key file
    or store they cannot tie to this store (PR 2804 fifth and sixth holds). It advises changing no
    existing file, key, blob or store: it asks for a new custody directory, and with ``new_store`` a
    new store location, which changes the settings that name them. Names no path and no key."""
    from messagefoundry.config.settings import SchemaManagement, StoreBackend

    server = settings.backend is not StoreBackend.SQLITE
    # The variable is named here as a literal, not through SECRETS_DIRECTORY_VARIABLE: this text
    # can reach stderr, and CodeQL's name heuristic reads that constant as a secret (alert 315).
    text = (
        "To go on without it, give this store a custody directory of its own: a new directory, "
        "restricted and writable by the service as a secrets directory must be, which the engine "
        "checks at start, named by MEFOR_SECRETS_DIRECTORY here and in this store's own service "
        "environment, never in one that another store's service also reads, since that store "
        "would then look for its key there. Copy into it every secret file the current secrets "
        f"directory holds other than {HOST_FILE_NAME} and {HANDOFF_FILE_NAME}, if one is set, "
        "since the service reads its other secrets from there too"
    )
    if new_store:
        text += ". Point [store] at a store location of its own: " + (
            "a new database" if server else "a new SQLite path"
        )
        if server and settings.resolved_schema_management() is SchemaManagement.EXTERNAL:
            text += (
                ", whose schema a DDL-capable login provisions first ([store].schema_management "
                "= 'external'; DEPLOY-SERVER-DB.md section 2)"
            )
    host = settings.key_provider == HOST_PROVIDER
    if host:
        text += (
            ". Then run `messagefoundry provision-admin` again to mint this store's key in the new "
            "custody directory, with every argument it was given"
        )
        if service_account is not None:
            text += f', --service-account "{service_account}" among them'
        # --db overrides [store].path, for serve as for provision-admin, so the old --db would
        # point a new SQLite store's re-run and its service back at the old store. At least two
        # shipped service paths always pass one: install-service.ps1 writes serve --db <DbPath>, and
        # supervise passes its --db, default messagefoundry.db, to its one SQLite engine shard. So
        # --db must name the new path in both (PR 2804 eighth hold). Absolute, since provision-admin
        # resolves a relative --db against its working directory and serve under --project-root.
        # A reinstall that omits -DbPath writes the default path back, so -DbPath goes on every
        # later reinstall too. install-service.ps1 refuses -EngineWheel over a root that exists and
        # refuses its companions without it, so a reinstall over the root it built leaves out all
        # of them. `messagefoundry service install` has no -DbPath to pass (_install_params), so it
        # must not reinstall this service (PR 2804 ninth hold).
        # A server store is named by [store].server/database, which --db does not set.
        if new_store and server:
            text += (
                ", once [store] names that new database, here and for the service (--db sets only "
                "[store].path, which does not name a server store)"
            )
        elif new_store:
            text += (
                ", but with --db, which overrides [store].path, naming that new SQLite path by its "
                "absolute path, here and wherever the service passes --db, at least -DbPath when "
                "the service is reinstalled with install-service.ps1 on Windows, now and on every "
                "later reinstall, repeating its other install parameters but leaving out "
                "-EngineWheel and each parameter that goes only with it, at least "
                "-EngineWheelSha256, -RequirementsLock, -RequirementsLockSha256 and -BasePython, "
                "as for any re-run over the install root it built (`messagefoundry service "
                "install` cannot pass -DbPath, so never reinstall with it), and supervise --db, "
                "which supervise "
                "passes to its engine shard as messagefoundry.db, under --project-root if one is "
                "given, when its own command line leaves it out"
            )
        if service_account is None and sys.platform == "win32":
            text += (
                "; to mint it for the service's account rather than your own, add "
                "--service-account with that account"
            )
    else:
        text += ". Then run the command again"
    if new_store:
        text += ". The new store starts empty: nothing in the one left in place is carried over"
    if host:
        text += (
            ". The recovery key shown when an existing key file was minted goes with that file, "
            "not with a key minted after it"
        )
    return text


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
    only; a POSIX host mints as the service user itself. Last, :class:`HostCustodyRefused` for at
    least a custody directory that is missing, that this account cannot add a file to, or that is
    on a file system the write refuses (PR 2804 eleventh and twelfth holds)."""
    host, handoff = check_host_custody_settings(settings, environ=environ)
    for path in (host, handoff):
        if os.path.lexists(path):
            raise FileExistsError(
                f"{path} already exists, so a store key was already minted here; a second mint "
                "is never made over it. The engine cannot tell whose key it holds, so it leaves "
                "it in place. "
                f"{keep_the_key_step(settings, new_store=False, service_account=service_account)}"
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
        target = host
    else:
        if sys.platform != "win32":
            raise HostCustodyRefused(
                "--service-account writes a Windows handoff; on this host run provision-admin as "
                "the service user itself, and it writes that account's host file"
            )
        from messagefoundry.store.custody import check_handoff_writable

        try:
            check_handoff_writable(service_account, enforcing=enforcing)
        except _custody_errors() as exc:
            raise _refused("no store key was minted", exc) from exc
        target = handoff
    environ = os.environ if environ is None else environ
    _refuse_an_unusable_directory(
        target.parent,
        service_account=service_account,
        named=bool(environ.get(SECRETS_DIRECTORY_VARIABLE, "").strip()),
    )
    return target


def _refuse_an_unusable_directory(
    directory: Path, *, service_account: str | None, named: bool
) -> None:
    """Refuse, before any recovery key is shown, a custody directory the key file's write would
    refuse only after the ceremony, at least: one that is missing or not a directory, one this account
    cannot add a file to (PR 2804 twelfth hold, item 4), and one whose volume fails
    :func:`~messagefoundry.restricted_file.write_restricted_file`'s local-volume rule, asked through
    that rule's own check (PR 2804 eleventh hold). ``named`` is whether ``MEFOR_SECRETS_DIRECTORY``
    names the directory, rather than a SQLite store's own data directory, so each refusal names
    the setting that moves it."""
    from messagefoundry.restricted_file import can_add_a_file, key_directory_volume_problem

    none_shown = "so no store key was minted and no recovery key was shown"
    if sys.platform not in ("linux", "win32"):
        raise HostCustodyRefused(
            f"the host key provider mints a store key on Linux and Windows only, {none_shown}"
        )
    writers = "this account" + (
        "" if service_account is None else f' and the service account "{service_account}"'
    )
    secrets_directory = "restricted as a secrets directory must be and writable by " + writers

    def move_on(to: str) -> str:
        # The variable is named as a literal: this text reaches stderr (keep_the_key_step says
        # why).
        variable = (
            "set MEFOR_SECRETS_DIRECTORY, here and in the service's own environment, to "
            f"{to}, and copy into it every other secret file the current secrets directory "
            "holds, if one is set, since the service reads its other secrets from there too"
        )
        if named:
            return variable
        return (
            f"point --db at a SQLite path in {to}, by its absolute path, here and wherever the "
            "service passes --db, since the store key sits beside the store file, or "
            f"{variable}"
        )

    if not directory.is_dir():
        if os.path.lexists(directory):
            raise HostCustodyRefused(
                f"the custody directory {directory} is not a directory this account can read, "
                f"{none_shown}. To go on, {move_on('a directory ' + secrets_directory)}, and run "
                "the command again"
            )
        # A directory behind a parent this account cannot search reads as absent here too.
        raise HostCustodyRefused(
            f"the custody directory {directory} is missing, or a directory above it is one this "
            f"account cannot search, {none_shown}. Create it, {secrets_directory}, or let this "
            "account search the directories above it, and run the command again"
        )
    can_add = can_add_a_file(directory)
    if can_add is None:
        # Not answered, so the write is left to answer it, and the log keeps that this was asked.
        logging.getLogger(__name__).warning(
            "whether this account can add a file to the custody directory %s could not be "
            "checked before the recovery key is shown; the key file's write checks it",
            directory,
        )
    if can_add is False:
        raise HostCustodyRefused(
            f"this account cannot add a file to the custody directory {directory}, {none_shown}. "
            f"Let this account add files there, or {move_on('a directory ' + secrets_directory)}, "
            "and run the command again"
        )
    try:
        volume = key_directory_volume_problem(directory)
    except OSError as exc:
        raise HostCustodyRefused(
            f"the file system of the custody directory {directory} could not be checked, since "
            f"this account could not open the directory ({exc.strerror or type(exc).__name__}), "
            f"{none_shown}. Let this account open it, or "
            f"{move_on('a directory ' + secrets_directory)}, and run the command again"
        ) from exc
    if volume is not None:
        raise HostCustodyRefused(
            f"the custody directory {directory} cannot hold a store key: {volume}. No store key "
            "was minted and no recovery key was shown. To go on, "
            f"{move_on('a directory on a local file system, ' + secrets_directory)}, and run the "
            "command again"
        )


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
