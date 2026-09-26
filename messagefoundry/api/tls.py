# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""In-process API / WebSocket TLS context (WP-13a, ADR 0002).

Builds the ``ssl.SSLContext`` uvicorn terminates the engine API + ``/ws/stats`` WebSocket with, from the
``[api]`` ``tls_*`` settings. Pure stdlib ``ssl`` — no FastAPI/uvicorn import — so it is unit-testable in
isolation. The ``tls_min_version`` floor (NIST SP 800-52r2: 1.2+) is enforced via
``SSLContext.minimum_version``; an encrypted key's passphrase comes from ``MEFOR_API_TLS_KEY_PASSWORD``.
"""

from __future__ import annotations

import errno
import logging
import os
import ssl
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from messagefoundry.api_tls_source import GENERATED_CERT_NAME, ApiTlsSource, api_tls_source
from messagefoundry.auth.trust_anchors import api_client_anchor_spec, verified_anchor_cadata
from messagefoundry.config.settings import ApiSettings
from messagefoundry.config.tls_policy import (
    harden_cipher_suites,
    harden_crl_check,
    harden_kex_groups,
    harden_verify_flags,
    narrow_to_approved_suites,
)

__all__ = [
    "ApiTlsPlan",
    "ApiTlsSource",
    "api_tls_source",
    "build_api_ssl_context",
    "ensure_api_tls_material",
    "generated_state_dir",
    "plan_api_tls_material",
    "plaintext_upstream_hop_unacknowledged",
]

log = logging.getLogger(__name__)

# Map the validated tls_min_version floor to the SSLContext minimum (TLS < 1.2 is never allowed).
_MIN_VERSION = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}


def build_api_ssl_context(api: ApiSettings, *, enforcing: bool = True) -> ssl.SSLContext:
    """Build the server ``SSLContext`` for the API listener from ``[api].tls_*``.

    Requires ``api.tls_cert_file`` (the caller checks ``api.tls_enabled`` first). The private key may be
    embedded in the cert PEM (``tls_key_file`` optional). mTLS is **opt-in**: when ``tls_client_ca_file``
    is set, a client cert is **required** and verified against it (console mutual auth); otherwise no
    client auth (the default).

    #285 (ASVS 6.7.1): when ``tls_client_ca_file`` is set, the client-CA trust anchor is preflighted at
    this construction point — an optional SHA-256 pin (``[api].tls_client_ca_pin``) mismatch refuses
    always, and a group/world-writable DACL refuses when ``enforcing`` (``[security].enforcement``).
    The context loads the bytes that preflight read, never the file a second time (BACKLOG #1142)."""
    if not api.tls_cert_file:
        raise ValueError("build_api_ssl_context requires [api].tls_cert_file")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _MIN_VERSION[api.tls_min_version]
    # An encrypted key with no passphrase must fail deterministically, not fall back to OpenSSL's blocking
    # TTY prompt (no TTY under a service account / in a container). The empty-bytes callback is never
    # invoked for an unencrypted key (prior behavior preserved) and raises ssl.SSLError otherwise.
    pw_arg = api.tls_key_password if api.tls_key_password is not None else (lambda: b"")
    ctx.load_cert_chain(
        certfile=api.tls_cert_file,
        keyfile=api.tls_key_file,
        password=pw_arg,
    )
    if api.tls_ciphers:
        ctx.set_ciphers(api.tls_ciphers)
    else:
        # Unset is no longer "whatever the interpreter enables": the approved AEAD names are the
        # default on every context the engine builds (BACKLOG #300, the ADR 0188 amendment).
        narrow_to_approved_suites(ctx)
    harden_kex_groups(ctx)  # pin approved ECDHE groups where the runtime supports it (ASVS 11.6.2)
    harden_cipher_suites(ctx, connector="API/UI listener")  # assert forward secrecy (ASVS 12.1.2)
    harden_verify_flags(ctx)  # strict RFC 5280 cert validation (ASVS 12.1.4)
    client_ca = api_client_anchor_spec(api)
    if client_ca is not None:
        # #285: pin + owner-only-DACL + path preflight. BACKLOG #1142, slice 2: load the bytes that
        # preflight read, as cadata=. cafile= would open the file a second time, and a swap between
        # the two reads would admit a forged client certificate past a pin that matched.
        ctx.load_verify_locations(cadata=verified_anchor_cadata(client_ca, enforcing=enforcing))
        ctx.verify_mode = ssl.CERT_REQUIRED
        # Opt-in revocation (#1005). NOTE THE POSITION: harden_verify_flags runs ABOVE, before the
        # CA is loaded, and this must NOT sit beside it. The CRL goes into the trust store, so
        # loading it before the CA yields a context with the check flag set and zero CRLs -- which
        # refuses EVERY client rather than skipping the check.
        if api.tls_client_crl_file:
            harden_crl_check(ctx, api.tls_client_crl_file)
    return ctx


#: Filenames for the first-run generated pair, written beside the store database (BACKLOG #1276).
#: **Why there, and the alternative rejected.** That directory is already the engine's own writable
#: state (the database and its WAL live there), it is already operator-controlled via ``--db`` /
#: ``[store].path``, and it is NOT operator-authored configuration -- which is what keeps the engine
#: out of the business of editing an operator's TOML. The rejected alternative was a new
#: ``[api].tls_generated_dir`` setting: a knob for a question with one sensible answer.
_GENERATED_CERT_NAME = GENERATED_CERT_NAME
_GENERATED_KEY_NAME = "api-generated-key.pem"
#: The first-run mint's lock, beside the pair. It holds no data and is never deleted: the OS lock on
#: it is the whole mechanism (see :func:`_generated_pair_lock`), so the file is only a handle.
_GENERATED_LOCK_NAME = "api-generated.lock"
#: How long a starting engine waits for ANOTHER process's mint before it gives up. A mint is one
#: P-256 key and two small writes, so this is far past any real mint; it bounds only a hung holder.
_MINT_LOCK_TIMEOUT_S = 60.0
_MINT_LOCK_POLL_S = 0.05


def _generated_pair(state_dir: Path) -> tuple[Path, Path]:
    """The ``(cert, key)`` paths of the first-run generated pair. The only place they are spelled."""
    return state_dir / _GENERATED_CERT_NAME, state_dir / _GENERATED_KEY_NAME


def generated_state_dir(store_path: str) -> Path:
    """Where the engine keeps its own writable state: the directory holding the store database.

    Named here rather than spelled at each call site, because it is the rule a CLIENT must not have
    to know -- and it was already written twice (the serve path and the ``cert inventory`` reporter)
    before it had a name.
    """
    return Path(store_path).resolve().parent


# ApiTlsSource and api_tls_source live in messagefoundry.api_tls_source, the stdlib leaf the
# tray shares, and are re-exported from here.


def plaintext_upstream_hop_unacknowledged(api: ApiSettings) -> bool:
    """True when ``serve`` refuses to start on BACKLOG #1179: the engine serves the proxy-to-engine
    hop in plaintext (``api_tls_source`` is ``upstream``) and no operator has acknowledged it.

    One predicate for both callers, ``serve`` and the ``upstream-hop-ack`` leg of
    ``messagefoundry check``, so the refusal and the gate agree by construction.
    """
    source = api_tls_source(
        cert_file=api.tls_cert_file, tls_terminated_upstream=api.tls_terminated_upstream
    )
    return source == "upstream" and not api.plaintext_upstream_hop_acknowledged


@dataclass(frozen=True)
class ApiTlsPlan:
    """What the API bind **will** serve with, decided without reading or writing a single file.

    This is the branch order of :func:`ensure_api_tls_material` lifted out so a caller that must not
    mint can still answer the two questions a CLIENT has: *which scheme does this engine speak*, and
    *which certificate will it present*. Both were previously derivable only by re-implementing the
    predicate, and each re-implementation got it wrong in its own way -- keying the scheme on
    ``[api].tls_cert_file`` alone reads the SHIPPED DEFAULT as cleartext (BACKLOG #1126), and a
    client with no idea where the generated pair lands cannot trust it at all (BACKLOG #1695).

    **The ordering is declared once**, in :func:`messagefoundry.api_tls_source.api_tls_source`,
    a stdlib leaf. The tray reads it from there over a raw service-TOML dict, because by ADR 0113
    it may not import this module, which pulls pydantic and the settings package in.
    """

    source: ApiTlsSource
    #: The certificate the bind will present, **whether or not it exists yet** -- for ``generated``
    #: this is the path the engine mints to on its first run. ``None`` only for ``upstream``.
    cert_file: str | None
    key_file: str | None

    @property
    def scheme(self) -> Literal["http", "https"]:
        """The scheme the engine's OWN bind serves.

        ``http`` only for a DECLARED upstream terminator, which is not a weaker posture: the proxy
        holds the protected hop and the engine speaks plaintext behind it. A client that hardcodes
        https breaks exactly that topology, which is why this is reported rather than assumed.
        """
        return "http" if self.source == "upstream" else "https"

    def material(self) -> tuple[str, str | None] | None:
        """The pair in :func:`ensure_api_tls_material`'s shape, or ``None`` for an upstream proxy."""
        return None if self.cert_file is None else (self.cert_file, self.key_file)


def plan_api_tls_material(api: ApiSettings, *, state_dir: Path) -> ApiTlsPlan:
    """Decide the API bind's TLS posture **without touching the disk** -- see :class:`ApiTlsPlan`.

    Pure: it neither mints, reads, nor stats anything, so it is safe on a read-only path (the
    ``cert inventory`` reporter) and safe to call before the engine has ever run.
    :func:`ensure_api_tls_material` consumes it, so the engine's own material is decided once.
    """
    source = api_tls_source(
        cert_file=api.tls_cert_file, tls_terminated_upstream=api.tls_terminated_upstream
    )
    if source == "operator":
        # Pass tls_key_file through UNCHANGED, None included -- see ensure_api_tls_material.
        return ApiTlsPlan(source, api.tls_cert_file, api.tls_key_file)
    if source == "upstream":
        return ApiTlsPlan(source, None, None)
    cert_path, key_path = _generated_pair(state_dir)
    return ApiTlsPlan(source, str(cert_path), str(key_path))


def _discard_half_minted_pair(cert_path: Path, key_path: Path) -> None:
    """Remove a lone half of a previously generated pair, so the mint that follows can re-run.

    Called only under :func:`_generated_pair_lock`, once the reuse branch has established that BOTH
    files are not present, so at most one of these exists. The lock is what makes "a lone half" mean
    DEBRIS: without it, a lone key could be another process's mint in progress (BACKLOG #1276).

    A half-pair is unusable -- reuse needs both -- and the key half is also a TRAP: the mint falls
    through, :func:`_write_private_key`'s ``O_EXCL`` refuses the surviving key,
    and the engine fails to start. On EVERY start, permanently, naming no file to delete. ADR 0172
    makes the generated pair the default first-run path, so that is a fresh deployment that never
    comes up rather than an edge case.

    **This is the durable half of the fix, and the ``try/finally`` around the mint is not.** That
    guard unwinds an EXCEPTION. It does not run on a SIGKILL, a power loss, or an OOM kill, and each
    of those leaves exactly the same half-pair. Recovery therefore cannot hang off the failure; it
    has to sit on the path that runs next, which is this one. Attaching it here also makes the
    recovery indifferent to how the half-pair arose, which is the property that matters, since the
    causes are not enumerable.

    **Deleting a private key is safe here and only here.** An operator-supplied ``tls_cert_file``
    returned far above, so operator material never reaches this function; these are the engine's own
    fixed generated names under its own state dir, and a lone one is engine-written debris by
    construction. It is still logged at warning, because a deleted key must never be silent.
    """
    for orphan in (cert_path, key_path):
        if not orphan.exists():
            continue
        log.warning(
            "discarding a half-minted TLS pair: %s exists without its counterpart, so it is "
            "unusable and would refuse every later start. Re-minting both.",
            orphan,
        )
        _unlink_generated(orphan)


#: Windows ERROR_SHARING_VIOLATION: another process holds the file open without delete sharing.
_WINERROR_SHARING_VIOLATION = 32
_UNLINK_RETRY_S = 2.0


def _unlink_generated(path: Path) -> None:
    """Delete one generated file, riding out a brief Windows sharing violation.

    On Windows a file another process holds open cannot be deleted, and a certificate is exactly the
    file other processes open: the tray pins it, and backup or antivirus may scan it. That hold is
    momentary, so a refusal is retried for :data:`_UNLINK_RETRY_S` before it propagates. Any other
    error, and every error off Windows, propagates at once.
    """
    deadline = time.monotonic() + _UNLINK_RETRY_S
    while True:
        try:
            path.unlink()
            return
        except PermissionError as exc:
            shared = getattr(exc, "winerror", None) == _WINERROR_SHARING_VIOLATION
            if not shared or time.monotonic() >= deadline:
                raise
        time.sleep(_MINT_LOCK_POLL_S)


def _why_generated_pair_is_unusable(cert_path: Path, key_path: Path) -> str | None:
    """``None`` when the two files load as ONE serving pair, else the TLS layer's reason why not.

    The predicate is the serving path's own: ``load_cert_chain`` is what uvicorn calls, and it
    refuses a certificate whose public key is not the key's (``KEY_VALUES_MISMATCH``), a truncated
    PEM, and an empty file. Checking presence alone is what let a mismatched pair be reused on every
    start while every start failed to serve it (BACKLOG #1276).

    **Only a CONTENT refusal is reported.** ``ssl.SSLError`` means the bytes are wrong. Any other
    ``OSError`` -- a denied read, a sharing violation -- says nothing about the bytes, so it
    propagates: a key the engine merely failed to READ must never be treated as one it may delete.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        # The empty-bytes password callback: fail deterministically rather than prompt on a TTY,
        # as build_api_ssl_context does. The engine never writes an encrypted generated key.
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path, password=lambda: b"")
    except ssl.SSLError as exc:
        return str(exc)
    return None


def _discard_unusable_pair(cert_path: Path, key_path: Path, reason: str) -> None:
    """Remove a complete but unusable generated pair, so the mint that follows can replace it.

    Reached only under :func:`_generated_pair_lock`, with both files present and
    :func:`_why_generated_pair_is_unusable` naming a content refusal. **This is not a rotation.** A
    pair that loads is never replaced; this one cannot serve, and reusing it failed every start
    until someone deleted it by hand. The mismatched shape is exactly what two processes minting into one
    state dir used to leave (BACKLOG #1276), and a disk fault can leave the others.

    Logged at WARNING, per ADR 0172 decision 6: replacing a key on disk is never silent. The reason
    is the TLS layer's error text, which names the refusal and carries no key material.
    """
    log.warning(
        "discarding an unusable generated TLS pair at %s and %s: they do not load as one serving "
        "pair (%s). Re-minting both.",
        cert_path,
        key_path,
        reason,
    )
    # Cert first. Should the key's unlink still fail, a lone key is left, which the next start
    # discards as a half-pair, so no ordering leaves anything a later start cannot recover.
    _unlink_generated(cert_path)
    _unlink_generated(key_path)


def _try_lock(fd: int) -> bool:
    """Take an exclusive OS lock on ``fd`` without blocking. ``False`` when another handle holds it.

    An OS lock rather than an ``O_EXCL`` lock FILE, because the kernel releases it when its holder
    dies. A lock file left by a SIGKILL or a power loss would block every later start, which is the
    same unrecoverable shape the half-pair discard exists to prevent. Both forms conflict between
    separate opens of the file, within one process as well as across processes.
    """
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            # Measured on Windows: a held range refuses with EACCES. EDEADLOCK is the CRT's other
            # documented contention code. Anything else is a real fault and propagates.
            if exc.errno in (errno.EACCES, errno.EDEADLOCK):
                return False
            raise
        return True
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _unlock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def _generated_pair_lock(state_dir: Path) -> Iterator[None]:
    """Hold the ONE-WRITER lock for the generated pair in ``state_dir``, waiting a bounded time.

    **Why the pair needs one.** ``serve --shards`` starts N engine processes that all derive the
    same state dir, so on a first run they all find no pair at once. Unserialised, one process won the
    key's ``O_EXCL`` create and every other died with ``FileExistsError``; worse, a process arriving
    between another's key and cert writes read a lone key as debris, deleted it, and minted its own,
    and the first then overwrote that cert, leaving a mismatched pair that failed every later start.
    Under this lock exactly one process mints, and every other waits, then reuses that pair.

    **One shared pair for all shards** is what this keeps, and it is correct: the minted identity is
    ``[api].host`` and shards differ only by port. The lock does not choose it over one pair per
    shard; it removes the crash and the corruption from the answer the shared state dir already
    gave.

    Raises ``TimeoutError`` naming the lock file when a holder outlives
    :data:`_MINT_LOCK_TIMEOUT_S`, rather than waiting forever on a hung process.
    """
    lock_path = state_dir / _GENERATED_LOCK_NAME
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        deadline = time.monotonic() + _MINT_LOCK_TIMEOUT_S
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"{lock_path} has been held for over {_MINT_LOCK_TIMEOUT_S:g}s by another "
                    "start minting the API TLS pair; if no other engine start is running, the "
                    "holder is hung -- stop it and start again"
                )
            time.sleep(_MINT_LOCK_POLL_S)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)


#: BUILTIN\Users, by SID so the grant does not depend on the host's display language.
_LOCAL_USERS_SID = "*S-1-5-32-545"


def _let_local_users_read_cert(cert_path: Path) -> None:
    """Grant local users READ on the minted CERTIFICATE, so a local client can pin it. Never the key.

    ``scripts/service/install-service.ps1`` locks the data directory to SYSTEM, Administrators and
    the service account, and the pair is minted there. The tray runs as the logged-on user with a
    filtered token, so without this it cannot read the file it has to pin, and it reads a running
    engine as down. The certificate is public: every client that connects receives it in the TLS
    handshake, so letting local users read it discloses nothing. The key stays owner-only
    (:func:`_write_private_key`).

    Windows only, because the tray is. Best-effort, like ``store._secure_file``: a failed grant is
    logged and never stops the engine. The grant is ADDITIVE and names only this file; the
    directory's ACL is untouched. It runs through ``store._grant_read``, the existing ``icacls``
    site, so this module spawns no process of its own.
    """
    from messagefoundry.store.store import _grant_read

    _grant_read(cert_path, _LOCAL_USERS_SID)


def ensure_api_tls_material(api: ApiSettings, *, state_dir: Path) -> tuple[str, str | None] | None:
    """Return the ``(cert_path, key_path)`` the API should serve with, minting on first run.

    **``key_path`` is ``None`` when the operator embedded the key in the cert PEM.** That is a
    supported configuration (``[api].tls_key_file`` is optional -- see :class:`ApiSettings` and
    :func:`build_api_ssl_context`), and the ``None`` must survive all the way to
    ``ssl.load_cert_chain(keyfile=...)``, which reads a combined PEM only when keyfile is ``None``.
    Substituting ``""`` for it raises ``OSError: [Errno 22] Invalid argument`` instead, so an
    operator with a combined PEM could not start the engine at all. A minted pair is always two
    files, so that branch returns a real path.

    **The engine always serves TLS (owner ruling 2026-08-22, superseding ADR 0143's cleartext
    loopback premise).** An operator-supplied ``[api].tls_cert_file`` always wins -- this is a
    fallback BENEATH it, never a replacement -- so a site that configures its own chain sees no
    behaviour change and this function is not even consulted.

    **Returns ``None`` when a reverse proxy terminates TLS upstream.** Which of the three postures
    applies is :func:`plan_api_tls_material`'s decision, not this function's -- this one adds only
    the minting, so a read-only caller can ask the same question without writing a key.

    **Mint-once, then reuse.** The pair is written with :func:`_write_private_key`'s ``O_EXCL`` +
    ``0o600`` + Windows-DACL sequence, which REFUSES to overwrite. So a second start finds the
    files and loads them; it does not re-mint, and it cannot clobber a key. The certificate, and
    only the certificate, is then made readable by local users so the tray can pin it
    (:func:`_let_local_users_read_cert`).

    **ONE WRITER (BACKLOG #1276).** Every ``serve --shards`` shard shares this state dir, so any
    discard and the mint run under :func:`_generated_pair_lock`, after the reuse check is repeated
    there. A process that loses the race waits, then reuses the winner's pair; it neither crashes
    nor deletes a key another process is still writing. A pair that already loads is reused before
    the lock is taken (:func:`_loads_without_the_lock`).

    **REUSE MEANS THE PAIR LOADS, not that two files exist.** A pair that fails
    :func:`_why_generated_pair_is_unusable` (a cert that is not the key's, a truncated file) is
    discarded with a WARNING and re-minted -- see :func:`_discard_unusable_pair`. A pair that loads
    is never replaced here, so this is recovery, not rotation.

    **A HALF-PAIR IS THE OTHER EXCEPTION, and it re-mints rather than refusing** -- see
    :func:`_discard_half_minted_pair`. Reuse needs BOTH files, so one alone is unusable AND a trap:
    the O_EXCL refusal above would fire on the survivor at every later start, permanently.

    **The generated certificate is a PLACEHOLDER TO BE REPLACED, not an endorsed production
    terminator.** It is self-signed, so it carries no chain of trust: strictly better than
    cleartext, strictly worse than an operator-supplied chain. A browser reaching the console gets
    a trust interstitial until it is imported (``docs/TRAY.md`` documents that import).

    **NOT HANDLED HERE, and it is filed rather than forgotten:** nothing re-mints an EXPIRED
    generated pair. ``build_api_ssl_context`` performs no expiry check, so on day 366 the engine
    would serve an expired certificate every client rejects. The rotation shape is an open decision
    on #1276; until it lands, ``CertExpiryRunner`` alarms on this path like any other served cert.
    That holds because ``serve`` hands the monitor the path this function RETURNS, not
    ``[api].tls_cert_file``, which is empty exactly when a pair was minted -- so passing the config
    value left the generated certificate unwatched. ``tests/test_api_tls.py`` pins the wiring. The
    alarm fires from ``[cert_monitor].warn_days`` out (0 turns the monitor off), and it re-mints
    nothing: the reuse branch below returns an expired pair unchanged on every later start.
    """
    # The branch order lives in plan_api_tls_material, so the read-only reporter and the minting
    # path cannot disagree about which certificate the bind presents. Two of the three branches
    # need no disk at all: an operator's material is passed through UNCHANGED (tls_key_file's None
    # included -- see the key_path note above), and a DECLARED UPSTREAM TERMINATOR IS NOT AN
    # UNPROTECTED HOP, so minting there would break the proxy's own plaintext hop rather than
    # harden anything. "Always serves TLS" means the engine never leaves a hop unprotected, NOT
    # that it terminates TLS in every topology.
    plan = plan_api_tls_material(api, state_dir=state_dir)
    if plan.source != "generated":
        return plan.material()

    cert_path, key_path = _generated_pair(state_dir)
    if _loads_without_the_lock(cert_path, key_path):
        return str(cert_path), str(key_path)
    state_dir.mkdir(parents=True, exist_ok=True)
    with _generated_pair_lock(state_dir):
        # Re-decided UNDER the lock: a process that waited here finds the pair the holder just
        # minted, and reuses it. Only here may a failed check lead to a discard.
        if cert_path.exists() and key_path.exists():
            reason = _why_generated_pair_is_unusable(cert_path, key_path)
            if reason is None:
                return str(cert_path), str(key_path)
            _discard_unusable_pair(cert_path, key_path, reason)
        else:
            _discard_half_minted_pair(cert_path, key_path)
        _mint_generated_pair(api, cert_path, key_path)
    return str(cert_path), str(key_path)


def _loads_without_the_lock(cert_path: Path, key_path: Path) -> bool:
    """True when the pair already loads, read WITHOUT the lock. Every other answer is ``False``.

    Safe because a pair that loads is never replaced, so seeing one is final. A read that races a
    mint in progress sees a partial or vanishing file and answers ``False``, and the caller then
    decides again under the lock. So nothing here raises and nothing here deletes. The point of
    reading first is that the common start -- a pair minted long ago -- needs no write access to the
    state dir and no OS lock support, which is what it needed before the lock existed.
    """
    try:
        return (
            cert_path.exists()
            and key_path.exists()
            and _why_generated_pair_is_unusable(cert_path, key_path) is None
        )
    except OSError:
        return False


def _mint_generated_pair(api: ApiSettings, cert_path: Path, key_path: Path) -> None:
    """Mint the pair into two ABSENT paths. Call only under :func:`_generated_pair_lock`."""
    from messagefoundry import pki
    from messagefoundry.__main__ import _write_private_key

    # 365 days, inheriting the `cert self-signed` CLI default rather than inventing a second
    # lifetime for the same primitive.
    cert_pem, key_pem = pki.make_self_signed(api.host, [], 365)
    _write_private_key(key_path, key_pem)
    paired = False
    try:
        cert_path.write_bytes(cert_pem)
        paired = True
    finally:
        # THE MINT IS ALL-OR-NOTHING. An orphaned key.pem is not merely untidy: the reuse branch
        # above needs BOTH files, so a next start finds cert_path missing, falls through, re-mints,
        # and dies on _write_private_key's O_EXCL refusal. That repeats on every start until an
        # operator deletes a file nothing told them about, so a half-written pair would brick the
        # engine rather than degrade it. `finally`, not `except`, so no failure mode is missed.
        if not paired:
            key_path.unlink(missing_ok=True)
    _let_local_users_read_cert(cert_path)
    log.warning(
        "no [api].tls_cert_file configured — minted a SELF-SIGNED certificate for %s at %s. It has "
        "no chain of trust and is a PLACEHOLDER: browsers will show a trust interstitial until it "
        "is imported, and it should be replaced with an operator-supplied chain.",
        api.host,
        cert_path,
    )
