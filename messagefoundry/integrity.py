# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Startup self-attestation of the installed engine wheel — a runtime tamper tripwire.

ADR 0041 (D3). ADR 0036 guards the **config dir** (an unauthorized writer can't drop a ``.py`` that
the loader executes); nothing checked that the installed ``messagefoundry`` **site-packages** still
match the attested wheel. An admin with venv-write + restart rights could edit engine code in place
(neuter ``field_authz`` redaction, the off-box audit tee, …) and it would run with **no audit row at
all**. This module closes that gap: at startup it hashes every **loaded** first-party
``messagefoundry`` module file against the wheel's ``*.dist-info/RECORD`` baseline (a zero-new-artifact
manifest already shipped in the wheel) and, on drift, records a hash-chained ``startup_integrity``
audit row and fires the :class:`~messagefoundry.pipeline.alerts.AlertSink`.

It also attests a short, explicit list of shipped security **data** assets (:data:`_ATTESTED_ASSETS`,
BACKLOG #1432) — files that are not ``.py`` but that a control's behaviour depends on. Editing engine
code is not the only way to neuter a control in place: emptying the bundled common-password corpus
turns breach screening into a no-op with no ``.py`` touched at all.

It attests the **web console** too, when this process has loaded it (BACKLOG #1802). The console is a
separate, separately versioned wheel (``messagefoundry-webconsole``) mounted in-process, so its bytes
run with the engine's own privileges while the engine's ``RECORD`` never lists them. It gets its own
arm, :func:`attest_console`, run against the console distribution's own ``RECORD`` under the same
classifier and the same posture below. A console this process never imported is not attested: its
bytes never ran here, and importing it to look would run them. ADR 0041 AC-15 and its 2026-09-25
amendment are the record of what the arm covers and why.

Posture (ADR 0017 amendment, 2026-06-27):

- **Default = alert-only.** Drift records + alerts but the engine still starts. A legitimate, reviewed
  in-place security hotfix (e.g. the documented vendored-patch contingency for the dormant
  ``python-hl7``/``hl7apy`` parsers) would itself trip a ``RECORD`` mismatch, so fail-closed-by-default
  would brick a legitimate patch at the worst moment.
- **Opt-in ``[integrity].fail_closed_on_drift``** raises :class:`IntegrityError` before listeners bind
  — refuse to run unattested engine bytes.
- **No-op only on an install that DECLARES itself editable** (``pip install -e .`` — a
  ``direct_url.json`` with ``dir_info.editable``, or an ``__editable__``/``.pth`` finder row in
  ``RECORD``). A dev co-development checkout is **never** bricked or alerted. Under
  ``fail_closed_on_drift`` that no-op also logs a WARNING naming the reason: the opt-in asked for
  hard enforcement that this install cannot give, and the branch used to return silently, so a
  first deployment in that shape would start with its tripwire disarmed and nothing to read.
- **Attested-nothing is not clean** (BACKLOG #1679). An absent, empty or package-row-less ``RECORD``,
  an unresolvable install root, and a package imported from *outside* the install root all leave
  ``checked == 0``: no file was compared, so the pass proves nothing in either direction. That posture
  logs at WARNING, records the ``startup_integrity`` audit row, fires the AlertSink, and — under
  ``fail_closed_on_drift`` — refuses to start. Before #1679 all of those returned a silent clean no-op,
  so a site that opted into hard enforcement would start anyway with its tripwire disarmed, and the
  INFO line would say clean.

**What it detects is an INCONSISTENT edit, not a consistent one.** The baseline ships beside the code it
attests, inside the same install the stated adversary can write, so an edit that also re-seals ``RECORD``
passes clean. Widening the refusal above closes the shapes where the baseline is *gone*; it does not
make the baseline trustworthy, and **no in-process anchor can**: this module attests itself, so any
anchor it consumes is read by code the same venv-write actor already owns. The residual is accepted and
the reasoning is in ADR 0041 D3, *"The baseline's trust domain"* — read it there rather than re-deriving
it here.

Pure + offline: it hashes file *bytes* and reads packaging metadata only — no subprocess, no network,
no config import. The on-disk hashing is blocking, so the async entry point runs it off the event loop
(``asyncio.to_thread``), exactly like ``load_config`` / the config fingerprint.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from messagefoundry.pipeline.alerts import AlertSink
    from messagefoundry.store.base import Store

__all__ = [
    "IntegrityError",
    "AttestationResult",
    "DriftEntry",
    "UnattestedReason",
    "attest_console",
    "attest_engine",
    "run_startup_attestation",
]

log = logging.getLogger(__name__)

#: The installed distribution whose wheel ``RECORD`` is the integrity baseline.
_DIST_NAME = "messagefoundry"

#: Only first-party engine *source* is attested by the module walk. A ``.pyc`` is a build artifact,
#: not reviewed bytes, and ``RECORD`` lists ``.py`` (not the compiled cache), so attesting ``.py`` is
#: the right anchor. It also stays the right *probe* in :func:`_record_has_package_rows`: the question
#: there is "does RECORD carry package source at all", and a data file cannot answer that.
_ATTESTED_SUFFIX = ".py"

#: Shipped **data** files that a control's behaviour depends on, package-relative to
#: ``messagefoundry/`` (BACKLOG #1432).
#:
#: Attesting ``.py`` alone left a gap the module walk cannot see: an admin with venv-write plus
#: restart rights could truncate ``auth/data/common_passwords.txt`` to zero bytes, and
#: :func:`~messagefoundry.auth.policy._common_passwords` returned an empty set, so
#: ``PasswordPolicy.violations`` stopped emitting "not be a common or breached password" and breach
#: screening became a silent no-op. No engine ``.py`` changed, so attestation reported clean. Same
#: shape for ``security/semgrep/handler-security.yml``: emptying the rules file makes the operator's
#: opt-in CI leg pass everything.
#:
#: **That consequence is now contained, and this entry is still load-bearing** (BACKLOG #1438). The
#: loader raises rather than returning an empty set, so the truncation above is refused rather than
#: silently accepted. What the guard cannot see is a corpus **substituted rather than emptied** -- a
#: well-formed replacement of ordinary size, minus the one password the attacker intends to use --
#: because it grades the parsed result and that result looks entirely healthy. Only a hash catches
#: that one. The two are complementary in both directions: a wheel BUILT with a truncated corpus
#: matches its own ``RECORD`` and drifts from nothing, and there the loader's guard is the only
#: signal.
#:
#: Version skew is impossible by construction: this list and the ``RECORD`` it is compared against
#: ship in the *same* wheel, so a declared asset always has a baseline row.
#:
#: **DO NOT RECORD A DIGEST HERE.** This module holds *paths*; every expected hash is sourced from the
#: installed distribution's own ``RECORD``, so the baseline travels with the install and a wheel's
#: content and its digests are produced by one build. That is the whole reason a checkout's line
#: endings cannot make this cry tamper on a clean host, and it is why none of these assets needs a
#: ``.gitattributes`` byte pin *for attestation* (they may well want one for reproducible builds --
#: a different question). Pin a hash in source and you invert it: a repo-recorded digest is
#: platform-independent while an unpinned working tree is not, so the pin becomes load-bearing and its
#: absence becomes a false tamper alarm against a clean install. Five sessions re-derived this in one
#: day; ``test_line_endings_alone_never_report_tampering`` and its after-install control pin it.
#:
#: **The near-neighbour is not a counter-example, and it is what a future editor will find first.**
#: ``common_passwords.NOTICE`` records a sha256 of the corpus. That is a *provenance* record -- it
#: names the bytes that were built and shipped, nothing compares against it at runtime, and it is
#: explicit that it holds only under a ``.gitattributes`` pin. A **baseline** is the other kind: it is
#: compared, at startup, against a file on an operator's disk, and it must therefore come from the
#: same install as that file. Recording provenance beside the data is right; carrying that habit into
#: this module is the mistake.
#:
#: **An explicit list rather than every RECORD row under the package**, which is the stronger design
#: and the one actually weighed. It would make a forgotten asset impossible rather than guarded; it
#: was declined because attestation scope would then follow whatever packaging ships, and the day a
#: wheel carries a file an operator is *expected* to edit in place that is a standing false positive
#: on a channel an operator will mute. **Not a self-registering registry either** (the
#: ``transports/base.py`` pattern): that one is read after config load with every transport imported,
#: while this runs before most of the engine is, so the attested set would vary with import order.
#: BACKLOG #1432 carries both arguments, what the list leaves unattested, and what this does not buy.
#: Add an entry when a new shipped data file gates a security decision.
_ATTESTED_ASSETS: tuple[str, ...] = (
    "auth/data/common_passwords.txt",
    "security/semgrep/handler-security.yml",
)

#: The web console's distribution and import package (BACKLOG #1802). The console is a SEPARATE wheel
#: mounted in-process (ADR 0065), and the engine wheel does not contain it, so nothing keyed on
#: :data:`_DIST_NAME` ever reached its bytes. It gets its own arm rather than a widened ``_DIST_NAME``:
#: that name is also the engine's package prefix, and each site that reads it must keep meaning the
#: engine alone.
_CONSOLE_DIST_NAME = "messagefoundry-webconsole"
_CONSOLE_PACKAGE = "messagefoundry_webconsole"

#: The console arm attests EVERY file in the loaded package (bytecode caches aside), not only ``.py``.
#: Its static ``.js``/``.css`` run inside an operator's signed-in browser session, so editing one in
#: place tampers with the console with no ``.py`` touched. A native module or a sourceless ``.pyc``
#: planted beside a ``.py`` is imported in its place, so a suffix filter would hash the untouched
#: ``.py`` and report clean. Walking everything makes any file with no ``RECORD`` row ``missing`` drift.
#: The engine declined a whole-package scope because a wheel might one day ship a file an operator edits
#: in place (BACKLOG #1432); the console ships none. It is not an explicit list like
#: :data:`_ATTESTED_ASSETS` either: that list would ship in the ENGINE wheel and be compared against the
#: CONSOLE's ``RECORD``, and the two are versioned apart, so it would go stale.
#:
#: ``__pycache__`` is skipped because ``RECORD`` carries no hash for compiled caches. That leaves a
#: residual shared with the engine arm: a crafted cache whose header matches its ``.py`` is imported
#: without either arm looking at it.
_BYTECODE_CACHE_DIR = "__pycache__"


#: Why an attestation pass compared **nothing** (``checked == 0``). Only ``declared_editable`` is a
#: sanctioned no-op — a dev checkout that has no baseline by design (ADR 0041 AC-12). Every other value
#: is an install whose tripwire is disarmed, which a fail-closed site refuses to start on (BACKLOG
#: #1679). A ``Literal`` rather than a bare ``str`` so a typo in one of the six construction sites is a
#: type error instead of a reason nobody can match on.
UnattestedReason = Literal[
    "declared_editable",
    "not_an_installed_distribution",
    "record_absent_or_empty",
    "record_has_no_package_rows",
    "install_root_unresolvable",
    "no_attested_file_under_install_root",
]


class IntegrityError(RuntimeError):
    """Startup attestation could not vouch for the loaded engine bytes, or for the loaded web console's
    (BACKLOG #1802), AND ``[integrity].fail_closed_on_drift`` is set — the engine must refuse to start
    rather than run unattested bytes (raised before any listener binds).

    Two causes, not one (BACKLOG #1679): attestation found **drift**, or it verified **nothing** (no
    baseline, a stripped baseline, or a package loaded from outside the install root). The message names
    which, and names every arm that failed, the engine's first."""


@dataclass(frozen=True)
class DriftEntry:
    """One attested file (an engine module or a declared security asset) that does not match its
    ``RECORD`` baseline.

    ``reason`` is ``"hash_mismatch"`` (on-disk bytes differ from the recorded sha256) or ``"missing"``
    (the file has no ``RECORD`` entry at all — e.g. a module added in place after install — or it
    could not be read, which is how a *deleted* declared asset surfaces).
    No file content is carried — only the relpath + reason (no PHI, nothing sensitive).
    """

    path: str
    reason: str


@dataclass(frozen=True)
class AttestationResult:
    """Outcome of one attestation pass. ``editable``/``no_record`` are the classifier's verdicts on the
    install; ``checked`` counts the files actually compared (for the engine, loaded modules + declared
    security assets; for the web console, its loaded files); ``drift`` is the (possibly empty) list of
    mismatches.

    ``unattested_reason`` is the field a caller must read alongside ``drift`` (BACKLOG #1679): an empty
    ``drift`` list on its own cannot tell **attested clean** from **attested nothing**, and the second
    shape is what a competent in-place edit leaves behind."""

    attested: bool  # True only when a real RECORD baseline was compared against
    editable: bool
    no_record: bool
    checked: int
    drift: list[DriftEntry] = field(default_factory=list)
    #: Why this pass compared nothing; ``None`` when it compared at least one file. The single source of
    #: truth for :attr:`attested_nothing`'s cause and for :attr:`declared_editable`.
    unattested_reason: UnattestedReason | None = None

    @property
    def attested_nothing(self) -> bool:
        """Whether the pass compared **no** file against a baseline row.

        Independent of ``drift``: a pass can compare nothing and still report planted files as
        ``missing`` drift, so a caller acting on both must handle drift first — which
        :func:`run_startup_attestation` does."""
        return self.checked == 0

    @property
    def declared_editable(self) -> bool:
        """Whether the install **declares** itself editable (a PEP 610 ``direct_url.json`` or an
        ``__editable__``/``.pth`` finder row) — the one attested-nothing shape a fail-closed site still
        accepts, because bricking a dev checkout is the cost ADR 0041 AC-12 declined to pay.

        An editable verdict *inferred* only from a package-row-less ``RECORD`` is deliberately NOT this
        (BACKLOG #1679): that shape is indistinguishable from a baseline an adversary stripped, so it is
        treated as unattested rather than as a declaration."""
        return self.unattested_reason == "declared_editable"

    @property
    def ok(self) -> bool:
        """Whether the engine bytes were **verified** clean: at least one file was compared against its
        ``RECORD`` baseline and none drifted.

        A pass that compared nothing is **not** ``ok`` — it is :attr:`attested_nothing`, which proves
        nothing in either direction. This used to be ``not self.drift``, which reported every no-op
        shape as clean and gave a caller no way to tell the two apart (BACKLOG #1679)."""
        return self.checked > 0 and not self.drift

    def audit_detail(self) -> dict[str, object]:
        """A PHI-free JSON-able summary for the ``startup_integrity`` audit detail / alert payload."""
        detail: dict[str, object] = {
            "attested": self.attested,
            "checked": self.checked,
            "drift_count": len(self.drift),
        }
        if self.editable:
            detail["editable"] = True
        if self.no_record:
            detail["no_record"] = True
        if self.unattested_reason is not None:
            # Names WHICH shape left `checked == 0`, so an operator reading the audit row can tell a dev
            # checkout from a stripped baseline without re-deriving it from the other flags.
            detail["unattested_reason"] = self.unattested_reason
        if self.drift:
            # Bound the listed paths so a wholesale mismatch can't bloat the audit row; the count is
            # authoritative. Sorted for a stable, diffable detail.
            paths = sorted(d.path for d in self.drift)
            detail["drift"] = paths[:50]
            detail["drift_reasons"] = sorted({d.reason for d in self.drift})
        return detail


def _decode_record_hash(token: str) -> bytes | None:
    """Decode a RECORD ``hash`` token ``"sha256=<b64url-nopad>"`` to raw digest bytes.

    Returns ``None`` for an empty token (RECORD permits a blank hash, e.g. the ``RECORD`` file itself)
    or any non-sha256 / unparseable algorithm, so such an entry is simply not attested."""
    token = token.strip()
    if not token:
        return None
    algo, _, b64 = token.partition("=")
    if algo != "sha256" or not b64:
        return None
    # RECORD uses urlsafe base64 WITHOUT padding; restore the padding before decoding.
    pad = "=" * (-len(b64) % 4)
    try:
        return base64.urlsafe_b64decode(b64 + pad)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None


def _parse_record(record_text: str) -> dict[str, bytes]:
    """Map ``posix-relpath -> sha256-digest`` for every sha256 RECORD row, keyed by the relpath as
    written. RECORD rows are ``path,hash,size``; ``path`` may itself be quoted/contain commas, so the
    hash + size are split from the **right**. A row without a usable sha256 is skipped."""
    out: dict[str, bytes] = {}
    for raw in record_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # rsplit from the right: path,<sha256=...>,<size>. A path with an embedded comma stays intact.
        parts = line.rsplit(",", 2)
        if len(parts) != 3:
            continue
        path, hash_token, _size = parts
        digest = _decode_record_hash(hash_token)
        if digest is not None:
            out[path.strip().replace("\\", "/")] = digest
    return out


def _declares_editable(dist: metadata.Distribution, record: dict[str, bytes]) -> bool:
    """Whether the installed distribution **declares** itself editable (``pip install -e .``), via
    either marker pip writes (any one is conclusive):

    1. ``direct_url.json`` with ``dir_info.editable == true`` (PEP 660 / PEP 610).
    2. A RECORD entry naming an editable finder / path hook — ``__editable__.*`` or a ``*.pth``.

    A third signal used to live here — "RECORD lists no first-party package source" — and it is now
    :func:`_record_has_package_rows` instead (BACKLOG #1679). It is an *inference*, not a declaration:
    it cannot tell an editable install from a wheel install whose baseline was stripped, so reading it
    as a declaration let the stripped shape disarm the tripwire and report clean.
    """
    try:
        raw = dist.read_text("direct_url.json")
    except (OSError, KeyError):
        raw = None
    if raw:
        try:
            info = json.loads(raw)
            if bool(info.get("dir_info", {}).get("editable", False)):
                return True
        except (json.JSONDecodeError, AttributeError):
            pass
    for relpath in record:
        name = relpath.rsplit("/", 1)[-1]
        if name.startswith("__editable__") or name.endswith(".pth") or "_editable_impl" in name:
            return True
    return False


def _record_has_package_rows(record: dict[str, bytes], package: str) -> bool:
    """Whether RECORD carries first-party ``<package>/*.py`` rows — i.e. whether there is any
    baseline to attest the package source against.

    A wheel install records the package source. An editable install records none of it, and neither does
    a RECORD an adversary stripped: the two states are identical here, which is why the answer alone can
    never license a no-op (BACKLOG #1679)."""
    return any(rel.startswith(f"{package}/") and rel.endswith(_ATTESTED_SUFFIX) for rel in record)


def _loaded_module_files() -> list[Path]:
    """The on-disk ``.py`` files of the loaded first-party ``messagefoundry`` package, sorted.

    Sourced from ``messagefoundry.__path__`` so it attests exactly the bytes Python imported this
    process from this install (the integrity question is "do the loaded files match the wheel"). A
    ``.pyc`` cache, vendored ``tee/``, and any non-``.py`` are excluded.
    """
    import messagefoundry

    files: set[Path] = set()
    for root in messagefoundry.__path__:
        base = Path(root)
        for path in base.rglob(f"*{_ATTESTED_SUFFIX}"):
            if path.is_file():
                files.add(path.resolve())
    return sorted(files)


def _attested_asset_files() -> list[Path]:
    """The on-disk paths of the shipped security **data** assets in :data:`_ATTESTED_ASSETS`.

    Resolved under ``messagefoundry.__path__``, the same anchor the module walk uses, so both halves
    attest the install this process actually imported from.

    **A path is returned whether or not it exists.** Deleting a declared asset is tampering too, and a
    caller that filtered on existence would report clean for it; the attestation loop turns the
    unreadable file into ``missing`` drift.
    """
    import messagefoundry

    return list(
        dict.fromkeys(
            (Path(root) / rel).resolve()
            for root in messagefoundry.__path__
            for rel in _ATTESTED_ASSETS
        )
    )


def _console_loaded_files() -> list[Path] | None:
    """The on-disk files of the LOADED web console package, sorted, or ``None`` when this process has
    not imported it (BACKLOG #1802).

    Keyed on ``sys.modules`` rather than on the distribution being installed. The console's payload
    runs at import, so a console never imported has run nothing here, and finding it by importing it
    would run it -- the reason ``serve`` checks its provenance BEFORE importing it (BACKLOG #1193).
    ``create_app(serve_ui=True)`` imports it before the lifespan runs attestation, so a console that
    serves is a console that is attested.

    Sourced from the module's ``__path__`` like :func:`_loaded_module_files`, so it attests the files
    this process imported, and every file planted beside them is walked too (see
    :data:`_BYTECODE_CACHE_DIR` for the one directory skipped). A module with no ``__path__`` (a single
    file shadowing the package name) contributes its own ``__file__``; one with neither contributes
    nothing, which leaves the pass comparing nothing -- attested-nothing, not clean.

    **Directories are resolved, the file name is not.** A file swapped for a symlink therefore keeps its
    place under the install root, and hashing it reads the bytes the symlink points at, which is what
    an import would run. Resolving the file itself would move it outside the root, where the comparison
    skips it. ``Path.walk`` does not follow a symlinked directory; it reports it as a file, which has no
    ``RECORD`` row and so is drift.
    """
    module = sys.modules.get(_CONSOLE_PACKAGE)
    if module is None:
        return None
    files: set[Path] = set()
    search = getattr(module, "__path__", None)
    if search is None:
        origin = getattr(module, "__file__", None)
        if origin:
            path = Path(origin)
            files.add(path.parent.resolve() / path.name)
        return sorted(files)
    for root in search:
        for dirpath, dirnames, filenames in Path(root).walk():
            dirnames[:] = [name for name in dirnames if name != _BYTECODE_CACHE_DIR]
            directory = dirpath.resolve()
            files.update(directory / name for name in filenames)
    return sorted(files)


def _record_relpath(file: Path, install_root: Path) -> str | None:
    """The RECORD-relative posix path for ``file`` (relative to the site-packages install root), or
    ``None`` when the file is not under the install root (a defensive guard — a loaded module from an
    unexpected location is treated as unattestable, not silently matched)."""
    try:
        return file.relative_to(install_root).as_posix()
    except ValueError:
        return None


def _install_root(dist: metadata.Distribution) -> Path | None:
    """The site-packages root the RECORD relpaths are anchored to (the parent of the ``*.dist-info``
    dir). ``dist.locate_file('')`` resolves it across importlib backends; fall back to the dist-info
    parent."""
    try:
        located = dist.locate_file("")
        if located is not None:
            return Path(str(located)).resolve()
    except (AttributeError, OSError):
        pass
    path = getattr(dist, "_path", None)  # e.g. .../site-packages/messagefoundry-X.dist-info
    if path is not None:
        return Path(str(path)).parent.resolve()
    return None


def _nothing_attested(
    reason: UnattestedReason, *, no_record: bool = False, editable: bool = False
) -> AttestationResult:
    """One attested-nothing result (``checked == 0``, no drift), carrying the reason.

    Every early exit of :func:`_attest_distribution`, which both arms share, goes through here so the
    invariant a caller depends on -- ``checked == 0`` always names why -- cannot be broken by a new exit
    that forgets to set it."""
    return AttestationResult(
        attested=False, editable=editable, no_record=no_record, checked=0, unattested_reason=reason
    )


def attest_engine() -> AttestationResult:
    """Hash every loaded first-party ``messagefoundry`` module file, plus the shipped security data
    assets in :data:`_ATTESTED_ASSETS`, against the installed wheel's ``*.dist-info/RECORD`` baseline.
    Pure + offline + synchronous (blocking file reads) — callers on the event loop must wrap it in
    ``asyncio.to_thread``.

    Never raises for a missing/editable install; it returns a result whose ``unattested_reason`` names
    what stopped it from comparing anything, and :func:`run_startup_attestation` decides what that
    costs. A true I/O failure reading an attested file marks that file as drift (``missing``) rather
    than crashing startup.
    """
    return _attest_distribution(
        _DIST_NAME, _DIST_NAME, lambda: [*_loaded_module_files(), *_attested_asset_files()]
    )


def attest_console() -> AttestationResult | None:
    """Attest the loaded web console against the ``messagefoundry-webconsole`` wheel's own ``RECORD``
    (BACKLOG #1802), or return ``None`` when this process has not loaded the console.

    ``None`` covers both an install without the optional console and a JSON-only engine
    (``serve_ui`` off) that has it but never imported it: see :func:`_console_loaded_files` for why
    neither is looked into. A loaded console goes through the engine's classifier unchanged, so a
    console that declares itself editable is the same sanctioned no-op (ADR 0041 AC-12), and every
    other pass that compares nothing is attested-nothing (AC-13), which
    :func:`run_startup_attestation` treats exactly as it treats the engine's. Same blocking-I/O
    contract as :func:`attest_engine`.

    Unlike the engine arm it also reads every console row in ``RECORD``, so a DELETED console file is
    ``missing`` drift. The engine arm cannot do that without a list that could go stale; the console's
    own ``RECORD`` ships in the same wheel as its files, so it can.
    """
    files = _console_loaded_files()
    if files is None:
        log.debug(
            "integrity: %s is not loaded in this process; nothing to attest", _CONSOLE_PACKAGE
        )
        return None
    return _attest_distribution(
        _CONSOLE_DIST_NAME, _CONSOLE_PACKAGE, lambda: files, every_record_row=True
    )


def _attest_distribution(
    dist_name: str,
    package: str,
    attested_files: Callable[[], list[Path]],
    *,
    every_record_row: bool = False,
) -> AttestationResult:
    """Compare ``attested_files()`` against the ``RECORD`` of installed distribution ``dist_name``,
    whose source sits under the top-level ``package`` directory. The one classifier both arms share,
    so the engine and the console cannot drift apart on what counts as attested.

    ``attested_files`` is called only once a usable baseline is known to exist. ``every_record_row``
    additionally reports each hashed ``RECORD`` row under ``package/`` that no attested file matched as
    ``missing`` drift -- a deleted file. It applies only when at least one file was compared, so a
    package loaded from outside the install root stays attested-nothing rather than turning into a
    list of every file it did not load.
    """
    try:
        dist = metadata.distribution(dist_name)
    except metadata.PackageNotFoundError:
        # Run from a source tree without an installed dist (e.g. `python -m messagefoundry` in the
        # repo): no baseline exists, so nothing can be compared.
        log.debug("integrity: %s is not an installed distribution; nothing to attest", dist_name)
        return _nothing_attested("not_an_installed_distribution", no_record=True)

    try:
        record_text = dist.read_text("RECORD")
    except (OSError, KeyError):
        record_text = None
    if not record_text:
        log.debug("integrity: no %s RECORD baseline; nothing to attest", dist_name)
        return _nothing_attested("record_absent_or_empty", no_record=True)

    record = _parse_record(record_text)
    if _declares_editable(dist, record):
        log.debug(
            "integrity: %s declares an editable install; attestation is a no-op (dev never bricked)",
            dist_name,
        )
        return _nothing_attested("declared_editable", editable=True)
    if not _record_has_package_rows(record, package):
        # A RECORD with no package source rows on an install that does NOT declare itself editable.
        # `editable=False`: this is exactly the shape a stripped baseline produces, so classifying it as
        # a dev install is the defect BACKLOG #1679 closed, not a verdict worth keeping.
        log.debug("integrity: RECORD carries no %s package rows; nothing to attest", package)
        return _nothing_attested("record_has_no_package_rows")

    install_root = _install_root(dist)
    if install_root is None:
        log.debug("integrity: could not resolve the %s install root; nothing to attest", dist_name)
        return _nothing_attested("install_root_unresolvable")

    drift: list[DriftEntry] = []
    checked = 0
    seen: set[str] = set()
    for file in attested_files():
        rel = _record_relpath(file, install_root)
        if rel is None:
            continue  # loaded from outside the install root — not attestable against this RECORD
        seen.add(rel)
        expected = record.get(rel)
        if expected is None:
            # A loaded file with no RECORD row — an in-place-added file (a planted backdoor module is
            # exactly this) is drift, not a silent pass. A declared engine asset lands here only if it
            # was dropped from the wheel it is compared against, which is itself worth an alert.
            drift.append(DriftEntry(path=rel, reason="missing"))
            continue
        checked += 1
        try:
            actual = hashlib.sha256(file.read_bytes()).digest()
        except OSError:
            drift.append(DriftEntry(path=rel, reason="missing"))
            continue
        if actual != expected:
            drift.append(DriftEntry(path=rel, reason="hash_mismatch"))
    if every_record_row and checked:
        prefix = f"{package}/"
        cache = f"/{_BYTECODE_CACHE_DIR}/"
        drift.extend(
            DriftEntry(path=rel, reason="missing")
            for rel in sorted(record)
            if rel.startswith(prefix) and cache not in rel and rel not in seen
        )
    return AttestationResult(
        attested=True,
        editable=False,
        no_record=False,
        checked=checked,
        drift=drift,
        # A real baseline was read and still nothing was compared: every loaded file resolved outside
        # the install root (a shadowed `messagefoundry/` the working directory wins with — #1677 from
        # this control's side). `attested=True` with `checked == 0` is not clean, it is blind.
        unattested_reason=None if checked else "no_attested_file_under_install_root",
    )


#: AlertSink subject for a drift finding — the tripwire fired.
_DRIFT_ALERT_LABEL = "engine-integrity"

#: AlertSink subject for the attested-nothing posture — the tripwire could not run. A **distinct**
#: subject from the drift label so the two resolve as separate durable alert instances (ADR 0044): they
#: want different triage, and sharing a subject would let one overwrite the other's state.
_UNATTESTED_ALERT_LABEL = "engine-unattested"


async def _record_and_alert(
    store: Store,
    alert_sink: AlertSink,
    *,
    detail: dict[str, object],
    label: str,
    reason: str,
    drift_count: int,
) -> None:
    """Write the hash-chained ``startup_integrity`` audit row (it survives a host compromise via the
    off-box tee) and fire the dedicated ``integrity_drift`` channel (#54, PHI-free: a label + reason +
    count) so the off-box notifier pages, routable independently of a stalled delivery lane.

    Both are best-effort: a failure is logged and never masks the signal — the caller still refuses to
    start under fail-closed."""
    try:
        await store.record_audit("startup_integrity", actor=None, detail=json.dumps(detail))
    except Exception:  # noqa: BLE001 — audit is best-effort; never mask the integrity signal
        log.exception("startup integrity: failed to record the startup_integrity audit row")
    try:
        alert_sink.integrity_drift(label, reason=reason, drift_count=drift_count)
    except Exception:  # noqa: BLE001 — alerting is best-effort and must never break startup
        log.exception("startup integrity: AlertSink failed")


@dataclass(frozen=True)
class _Arm:
    """How one attested distribution names itself in the log, the alert and the refusal.

    The engine arm's values reproduce, word for word, the text this module emitted before the console
    arm existed (BACKLOG #1802), and ``distribution=None`` leaves its audit detail byte-identical.
    ``tests/test_startup_attestation.py`` pins both."""

    noun: str  # "... 3 {noun} file(s) ...": which code drifted
    wheel: str  # "the installed {wheel} RECORD": whose baseline it was compared against
    install: str  # "{install} DECLARES itself editable": whose editable marker disarmed the opt-in
    drift_label: str  # AlertSink subject for drift
    unattested_label: str  # AlertSink subject for attested-nothing
    distribution: str | None  # added to the audit detail; None keeps the engine's detail unchanged


_ENGINE_ARM = _Arm(
    noun="engine",
    wheel="wheel",
    install="this install",
    drift_label=_DRIFT_ALERT_LABEL,
    unattested_label=_UNATTESTED_ALERT_LABEL,
    distribution=None,
)

#: Distinct alert subjects again (ADR 0044): a drifted console and a drifted engine are separate
#: durable alert instances, so resolving one never clears the other.
_CONSOLE_ARM = _Arm(
    noun="web console",
    wheel=f"{_CONSOLE_DIST_NAME} wheel",
    install=f"the {_CONSOLE_DIST_NAME} install",
    drift_label="webconsole-integrity",
    unattested_label="webconsole-unattested",
    distribution=_CONSOLE_DIST_NAME,
)


async def _act_on(
    result: AttestationResult,
    arm: _Arm,
    store: Store,
    alert_sink: AlertSink,
    *,
    fail_closed_on_drift: bool,
) -> str | None:
    """Log, record and alert for one arm's result, and return the refusal message when this result
    must stop the engine starting (``None`` when it must not). The caller raises, so every arm records
    and alerts before anything refuses. The branch rules are :func:`run_startup_attestation`'s."""

    def detail() -> dict[str, object]:
        out = result.audit_detail()
        if arm.distribution is not None:
            out["distribution"] = arm.distribution
        out["fail_closed"] = fail_closed_on_drift
        return out

    if result.drift:
        drift_count = len(result.drift)
        log.error(
            "startup integrity DRIFT: %d %s file(s) do not match the installed %s RECORD "
            "(fail_closed=%s) — possible in-place %s tampering",
            drift_count,
            arm.noun,
            arm.wheel,
            fail_closed_on_drift,
            arm.noun,
        )
        await _record_and_alert(
            store,
            alert_sink,
            detail=detail(),
            label=arm.drift_label,
            reason=f"{drift_count} {arm.noun} file(s) drifted from the installed {arm.wheel} RECORD",
            drift_count=drift_count,
        )
        if fail_closed_on_drift:
            return (
                f"{arm.noun} integrity attestation failed: {drift_count} attested file(s) do not "
                f"match the installed {arm.wheel} RECORD "
                "([integrity].fail_closed_on_drift=true; refusing to start)"
            )
        return None

    if result.declared_editable:
        # AC-12: the install declares itself editable, so it has no baseline BY DESIGN. Never refused,
        # never audited, never alerted — the one attested-nothing shape a fail-closed site accepts.
        if fail_closed_on_drift:
            # AC-14 (BACKLOG #1679 act 5). A MISCONFIGURATION control, not a tamper control: the
            # operator asked for hard enforcement and this install cannot give it, so say so. Before
            # this line the branch returned with no log, no row and no alert, so a first deployment
            # that opted into fail-closed on an editable install WOULD start with its tripwire
            # disarmed and nothing in the boot log to read. It closes no hole — an adversary with
            # venv-write plants `direct_url.json` or rewrites this check in the same single write.
            # Keyed on the OPT-IN, not on editability: warning on every dev run is how a warning
            # stops being read, and AC-12 exists so a dev checkout is never nagged or bricked.
            log.warning(
                "startup integrity: [integrity].fail_closed_on_drift is set, but %s "
                "DECLARES itself editable (%s), so attestation compared no file and the tripwire "
                "is DISARMED — the hard enforcement you opted into is NOT in effect. Install the "
                "non-editable wheel to get it. This reports a misconfiguration, not a tamper: an "
                "actor who can write the venv can plant the editable marker itself.",
                arm.install,
                result.unattested_reason,
            )
        return None

    if result.attested_nothing:
        reason = result.unattested_reason or "unknown"
        log.warning(
            "startup integrity: attestation verified NOTHING (%s) — no %s file was compared "
            "against a RECORD baseline (fail_closed=%s), so an in-place edit would go undetected",
            reason,
            arm.noun,
            fail_closed_on_drift,
        )
        await _record_and_alert(
            store,
            alert_sink,
            detail=detail(),
            label=arm.unattested_label,
            # drift_count=0 is the honest count: nothing drifted, because nothing was compared. The
            # reason string is what carries the meaning on this channel.
            reason=f"startup attestation compared no {arm.noun} file against a baseline ({reason})",
            drift_count=0,
        )
        if fail_closed_on_drift:
            return (
                f"{arm.noun} integrity attestation verified nothing ({reason}): no {arm.noun} file "
                f"was compared against the installed {arm.wheel} RECORD "
                "([integrity].fail_closed_on_drift=true; refusing to start on an unattested install)"
            )
        return None

    log.info("startup integrity: %d %s file(s) attested clean", result.checked, arm.noun)
    return None


async def run_startup_attestation(
    store: Store,
    alert_sink: AlertSink,
    *,
    fail_closed_on_drift: bool,
) -> AttestationResult:
    """Run :func:`attest_engine` and :func:`attest_console` off the event loop and act on what each
    found (ADR 0041 D3). Each arm is judged on its own, by the same rules:

    - **verified clean** (``checked > 0``, no drift): an INFO line, nothing recorded, nothing alerted;
    - **declared editable**: nothing recorded, nothing alerted, never refused — a dev checkout has no
      baseline by design and is never bricked (AC-12). Under ``fail_closed_on_drift`` it additionally
      logs a WARNING naming the reason, because the opt-in cannot be honoured on this install and the
      branch used to return with no signal at all (AC-14). That line reports a **misconfiguration**,
      not a tamper;
    - **drift**: an ERROR line, a hash-chained ``startup_integrity`` audit row, and
      :meth:`AlertSink.integrity_drift`;
    - **attested nothing** (``checked == 0`` on an install that declares no editable marker — an absent,
      empty or stripped ``RECORD``, an unresolvable install root, a shadowed package): a WARNING, the
      same audit row, and the same alert channel under a distinct subject. The tripwire is disarmed in
      this shape; before BACKLOG #1679 it was reported as clean;
    - either of the last two **and** ``fail_closed_on_drift``: after recording + alerting, raise
      :class:`IntegrityError` so the caller refuses to start before any listener binds.

    ``fail_closed_on_drift=false`` (the default) keeps every signal above and starts anyway. The audit
    row and the alert are in **addition** to the refusal, never instead of it, so an operator who has not
    opted into hard enforcement still sees that attestation proved nothing.

    **The console arm** (BACKLOG #1802) runs only when this process has loaded the console, and only
    after the engine's result is logged, recorded and alerted, so nothing the console arm does can cost
    the engine's evidence. Both arms record and alert before either refuses, and a refusal names every
    arm that failed, the engine's first. The engine's text, subjects and audit detail are unchanged. The
    return value is the ENGINE's result, as it always was.

    A console with no distribution of its own, loaded beside an engine that DECLARES itself editable,
    takes the engine's AC-12 exemption: that is a dev checkout that installed only the engine. It costs
    nothing the engine's exemption did not already concede, because a declared-editable engine attests
    nothing either.

    Wire it into the engine/serve startup *before* listeners bind.
    """
    import asyncio

    result = await asyncio.to_thread(attest_engine)
    refusals = [
        await _act_on(
            result, _ENGINE_ARM, store, alert_sink, fail_closed_on_drift=fail_closed_on_drift
        )
    ]

    console = await asyncio.to_thread(attest_console)
    if console is not None:
        if (
            result.declared_editable
            and console.unattested_reason == "not_an_installed_distribution"
        ):
            console = _nothing_attested("declared_editable", editable=True)
        refusals.append(
            await _act_on(
                console, _CONSOLE_ARM, store, alert_sink, fail_closed_on_drift=fail_closed_on_drift
            )
        )

    failed = [refusal for refusal in refusals if refusal is not None]
    if failed:
        raise IntegrityError("; ".join(failed))
    return result
