# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared pytest fixtures.

Holds teardown-window logging guards. A background-component logger (the asyncio loop, the aiosqlite
worker, the engine/store/pipeline, the tee relay, uvicorn) can emit a record AFTER pytest has begun
tearing per-test capture down, raising 'I/O operation on closed file' inside logging.Handler.emit. The
fixtures below drop such a late emit at its source and make any straggler fail fast-and-silent.

The related mid-test asyncio<->aiosqlite cross-loop concern is handled in pyproject.toml — not here —
by running tests AND their async fixtures on one shared session loop (asyncio_default_test_loop_scope +
asyncio_default_fixture_loop_scope = "session"), which removes the per-test event-loop churn.
"""

from __future__ import annotations

import atexit
import functools
import inspect
import logging
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests import _tooling_manifest as tooling_manifest
from tests._extras_probe import report_header_lines, write_incomplete_run_summary
from tests._root_logging import root_logging_restored

if TYPE_CHECKING:
    from messagefoundry.config.wiring import _WinConfigSourceProbes

# ---------------------------------------------------------------------------------------------------
# Per-PROCESS test slot.
#
# A few tests reach machine-GLOBAL resources, so two pytest runs at once trample each other. That used to
# be an edge case; now that every session works in its own worktree, concurrent runs are the NORMAL case.
# Both of these were reproduced, not theorised:
#
#   * tests/test_multishard_smoke.py::_free_window scanned for a free port window from a FIXED floor of
#     20000. Probing alone is a TOCTOU race -- each process probes, each sees the window free, each takes
#     it. Measured: three concurrent processes ALL chose base=20000, and FOUR concurrent runs of that
#     suite produced THREE failures with WinError 10048 (address already in use). With this slot, the
#     same four runs all pass.
#   * tests/test_console_shards.py used a QSettings org of "MEFOR-Test", whose comment claimed it was
#     "in-memory" and touched "no disk". It is not: it writes %APPDATA%\MEFOR-Test\ShardTest.ini, and the
#     fixture .clear()s it -- so a sibling run's settings vanish mid-test.
#
# The colliding actor is the pytest PROCESS, not the worktree (two runs in one checkout collide just as
# hard, and you running the suite while an agent runs it is routine), so the slot is keyed on the process.
# Claiming is an exclusive-create: atomic, and free of the read-modify-write race a shared counter file
# would reintroduce.
#
# It never fails a run. If every slot is taken it falls back to the shared defaults -- the old behaviour,
# no worse.
# ---------------------------------------------------------------------------------------------------

_MAX_SLOTS = 32
_PORTS_PER_SLOT = 1000


def _pid_alive(pid: int) -> bool:
    if sys.platform != "win32":  # pragma: no cover - the CI Linux legs
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    out = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True, check=False
    ).stdout
    return str(pid) in out


def _slot_root() -> Path | None:
    """Machine-global, shared by every worktree of this repo -- the same scope as the collisions."""
    common = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if not common:
        return None
    root = Path(common) / "mefor-coord" / "test-slots"
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return root


def _claim_test_slot() -> int:
    root = _slot_root()
    if root is None:
        return 0
    # Two passes: the first claims, the second retries slots the first pass reaped from dead owners.
    for _ in (0, 1):
        for n in range(_MAX_SLOTS):
            lock = root / f"{n}.lock"
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:  # a crashed run must not hold a slot forever
                    owner = int(lock.read_text().strip() or "0")
                    if owner and not _pid_alive(owner):
                        lock.unlink(missing_ok=True)
                except (OSError, ValueError):
                    pass
                continue
            except OSError:
                return 0
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            atexit.register(lock.unlink, missing_ok=True)
            return n
    return 0  # saturated: fall back to the shared defaults rather than failing the run


# PUBLISHING THE SLOT: `setdefault` IS WRONG INSIDE AN XDIST WORKER, and silently so.
#
# Under pytest-xdist the CONTROLLER parses config and loads the initial conftests BEFORE it spawns any
# worker -- pyproject's `testpaths` makes `tests` an initial arg, so THIS module runs in the controller
# first. It claims a slot and publishes it into its own environ. execnet then spawns the workers with
# no env override, so every worker INHERITS those values and `setdefault` is a no-op in all of them:
# N workers all reading one port base, which is precisely the collision the slot machinery above exists
# to prevent. Nothing would report it -- the workers would simply race for the same ports.
#
# So a worker must claim its OWN slot and OVERWRITE. `PYTEST_XDIST_WORKER` is set by xdist in the
# worker process only ("gw0", "gw1", ...) and is absent in the controller and in any serial run, which
# makes it the exact discriminator. On a serial run this reduces to the original `setdefault`
# behaviour, so an outer harness can still pin the slot by exporting these before invoking pytest.
_IN_XDIST_WORKER = "PYTEST_XDIST_WORKER" in os.environ


def _publish_slot_var(name: str, value: str) -> None:
    if _IN_XDIST_WORKER:
        os.environ[name] = value
    else:
        os.environ.setdefault(name, value)


_SLOT = _claim_test_slot()
_publish_slot_var("MEFOR_TEST_SLOT", str(_SLOT))
_publish_slot_var("MEFOR_TEST_PORT_BASE", str(20000 + _PORTS_PER_SLOT * _SLOT))
_publish_slot_var("MEFOR_TEST_QSETTINGS_ORG", f"MEFOR-Test-{_SLOT}")


@pytest.fixture(scope="session", autouse=True)
def _force_aad_bind_when_requested() -> Iterator[None]:
    """ASVS 11.3.3 correctness net (cell-bound at-rest AAD, ADR 0019).

    When ``MEFOR_TEST_FORCE_AAD_BIND=1`` is set, force EVERY ``AesGcmCipher`` into the cell-bound
    ``mfenc:v2`` writer (``write_v2=True``) at its single construction chokepoint. Re-running the store
    round-trip suites under this flag turns every real write→read path into an AAD round-trip, so a
    mismatched encrypt/decrypt cell (a half-threaded ``cell_aad``) surfaces as a ``CipherError`` — the
    decisive check that no cell was missed.

    The flag is OFF by default and stays meaningful even though ``[store].aad_bind`` now DEFAULTS TRUE
    (ADR 0148 GIVEN 1). It is not a duplicate of that default: it patches ``AesGcmCipher.__init__``, so
    it forces ``write_v2`` on ciphers built with an EXPLICIT ``write_v2=False`` — including the ones
    ``test_store_encryption.py`` constructs directly to pin the v1 format. The settings default governs
    what ``open_store`` builds; this flag governs every cipher in the process, which is what makes the
    sweep exhaustive rather than merely representative."""
    if os.environ.get("MEFOR_TEST_FORCE_AAD_BIND") != "1":
        yield
        return
    from messagefoundry.store import crypto

    orig_init = crypto.AesGcmCipher.__init__

    def _forced_init(self, active_key, retired_keys=(), *, write_v2=False, allow_unmarked=False):
        # allow_unmarked passes through untouched (BACKLOG #1169): this flag forces the writer, not
        # the unmarked-value policy, and dropping it would turn every opt-out test into a TypeError.
        orig_init(self, active_key, retired_keys, write_v2=True, allow_unmarked=allow_unmarked)

    crypto.AesGcmCipher.__init__ = _forced_init  # type: ignore[method-assign]
    try:
        yield
    finally:
        crypto.AesGcmCipher.__init__ = orig_init  # type: ignore[method-assign]


#: The one account in the clean read below: it owns every path and it is the engine's own user.
_SUITE_SID = "S-1-5-21-1-2-3-1001"


def _clean_config_source_probes() -> _WinConfigSourceProbes:
    """Windows config-source readers that report every path clean: owned by the engine's own
    account, with an access list that grants nobody write."""
    from messagefoundry.config.wiring import _WinConfigSourceProbes, _WinPathSecurity

    clean = _WinPathSecurity(owner_sid=_SUITE_SID, aces=())
    return _WinConfigSourceProbes(
        self_sid=_SUITE_SID, read_path=lambda _path: clean, owner_in_admins=lambda _sid: False
    )


@pytest.fixture(scope="session", autouse=True)
def _read_the_checkout_as_a_clean_config_source() -> Iterator[Callable[[Path], None] | None]:
    """The suite loads sample/harness configs from the repo checkout, which is intentionally
    user-writable — and on the Windows CI runner the default workspace ACL grants ``BUILTIN\\Users``
    write, so the SEC-003 config-source trust guard would fail-closed on every config load.

    So on win32 only, the config-source gate's OWN call (``_assert_safe_config_source_windows``) runs
    the real check over readers that report a clean owner and access list. The check still runs and
    still decides. A test of the gate asks for the real call back with
    ``real_config_source_readers``, which this fixture yields (``None`` off win32). Scoped to win32
    because a POSIX checkout is not group/world-writable, so the Linux leg runs the real check in
    every test. The anchor-path fixture below is scoped the same way.

    **Only the gate's call is replaced, never ``_win32_config_source_probes`` itself.** Those readers
    are shared: ``messagefoundry.restricted_file`` reads a new file's access list back through them.
    This fixture first replaced the readers for the whole session, and every restricted create on
    Windows then compared the list it asked for with the stand-in's and refused.

    This used to set ``MEFOR_ALLOW_INSECURE_CONFIG_SOURCE`` for the whole session. Vault BACKLOG #2599
    clamped that escape: it is honoured only with ``MEFOR_SECURITY_ENFORCEMENT=warn`` beside it, and
    setting the dial for a whole session would move every default-posture test to ``warn``.

    A child process does not inherit this stand-in and runs the real check. A child that loads from
    ``tmp_path`` passes it: pytest makes that directory with mode ``0o700``, which on Windows is an
    access list of SYSTEM, Administrators and the owner alone, whatever ``%TEMP%`` grants (measured
    2026-10-01, Python 3.14). A child that loads from the checkout needs both variables in its own
    environment, as ``harness.load.failover.EngineNode`` sets them.

    The web console suite's conftest installs the same kind of stand-in, and one ``pytest`` run can
    load both. So the real call is found with ``inspect.unwrap``, and each stand-in records what
    it replaced, or this fixture would capture the other suite's stand-in as "real"."""
    if sys.platform != "win32":
        yield None
        return
    import messagefoundry.config.wiring as wiring

    real = inspect.unwrap(wiring._assert_safe_config_source_windows)
    # A stand-in that forgot to record what it replaced would be captured here as "real", and the
    # tests of the real access list would then pass without reading one.
    if Path(real.__code__.co_filename) != Path(wiring.__file__):
        raise RuntimeError(
            "the Windows config-source check found here is not the engine's own: a stand-in was "
            "installed without functools.wraps over the call it replaced"
        )
    probes = _clean_config_source_probes()

    @functools.wraps(real)
    def check_over_clean_readers(directory: Path) -> None:
        wiring._enforce_windows_config_source(directory, probes)

    patch = pytest.MonkeyPatch()
    patch.setattr(wiring, "_assert_safe_config_source_windows", check_over_clean_readers)
    try:
        yield real
    finally:
        patch.undo()


@pytest.fixture
def real_config_source_readers(
    monkeypatch: pytest.MonkeyPatch,
    _read_the_checkout_as_a_clean_config_source: Callable[[Path], None] | None,
) -> None:
    """Put the gate's real Windows call back for one test, so it reads through
    ``_win32_config_source_probes``: the real access list, or the readers a test hands it. A no-op
    off win32, where the session fixture above installs nothing."""
    if _read_the_checkout_as_a_clean_config_source is not None:
        monkeypatch.setattr(
            "messagefoundry.config.wiring._assert_safe_config_source_windows",
            _read_the_checkout_as_a_clean_config_source,
        )


#: The env gates that put a session against a live server-DB container. CI sets one of them together
#: with ``MEFOR_ALLOW_INSECURE_TLS`` because the container serves a self-signed certificate.
_SERVER_DB_GATES = ("MEFOR_TEST_SQLSERVER", "MEFOR_TEST_POSTGRES")


@pytest.fixture(scope="session", autouse=True)
def _warn_posture_for_the_server_db_legs() -> Iterator[None]:
    """Stamp a NON-enforcing hop posture for a session run against a live server-DB container.

    Vault BACKLOG #2354 made a weakened-TLS check with no posture fail closed: ``MEFOR_ALLOW_INSECURE_TLS``
    is honoured only where a ``[security].enforcement = warn`` posture is known. The CI store legs
    connect to a container with a self-signed certificate (``trust_server_certificate=true``) and
    open stores directly, with no ``serve`` to derive a posture. This is the explicit posture those
    legs need, stated once here rather than at every call site. It is session-scoped so a
    module-scoped store fixture sees it too, and it fires only when BOTH the escape and a server-DB
    gate are set, so an ordinary local run keeps the fail-closed default. A test that passes its own
    posture, or opens its own ``active_hop_posture`` scope, still wins. Subprocess children do not
    inherit a contextvar, so each child source passes the posture itself."""
    from messagefoundry.config.settings import insecure_tls_allowed
    from messagefoundry.config.tls_policy import HopPosture, active_hop_posture

    if not (insecure_tls_allowed() and any(os.environ.get(g) for g in _SERVER_DB_GATES)):
        yield
        return
    with active_hop_posture(HopPosture(enforcing=False)):
        yield


@pytest.fixture
def escape_at_warn(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """``MEFOR_ALLOW_INSECURE_TLS`` set on a known ``[security].enforcement = warn`` posture, the only
    shape in which the escape is honoured since vault BACKLOG #2354. For a test of what the escape
    PERMITS: the escape alone, with no posture, is now refused."""
    from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
    from messagefoundry.config.tls_policy import HopPosture, active_hop_posture

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with active_hop_posture(HopPosture(enforcing=False)):
        yield


@pytest.fixture(scope="session", autouse=True)
def _pass_the_anchor_path_check_on_windows() -> Iterator[None]:
    """The trust-anchor path check (BACKLOG #1142, directory arm) reads every directory from the volume
    root down, and on Windows ``tmp_path`` sits under the user's temp directory. That directory's DACL
    is the host's, not the test's. Measured on a Windows 11 dev host, 2026-09-24: ``%TEMP%`` grants a
    local group and an AppContainer capability SID rights that include DELETE, so every ``tmp_path``
    anchor refuses at ``enforce``, and every test that builds a TLS context from one fails.

    So on win32 only, the name ``trust_anchors`` calls answers ``True``. The check itself is not
    stubbed: ``tests/test_anchor_path.py`` calls ``anchor_path.anchor_path_verdict`` directly, and
    its preflight receipts put the real function back. POSIX ``tmp_path`` is a trusted chain (a sticky
    ``/tmp`` holding the runner's own directory), so the Linux leg runs the real check in every
    anchor test. The config-source readers above are scoped to win32 the same way."""
    if sys.platform != "win32":
        yield
        return
    from messagefoundry.auth import trust_anchors
    from messagefoundry.auth.anchor_path import PathVerdict

    patch = pytest.MonkeyPatch()
    patch.setattr(trust_anchors, "anchor_path_verdict", lambda _p: PathVerdict(True, (), "windows"))
    try:
        yield
    finally:
        patch.undo()


# Minimal source-logger set: every background-component child reaches one of these by propagation, so
# quiescing these five drops a late teardown-window emit at its source. Chosen from the suite's actual
# late emitters:
#   - "asyncio": the loop itself. asyncio routes loop-teardown faults ("Task was destroyed but it is
#     pending", unhandled callback exceptions via loop.call_exception_handler) through
#     logging.getLogger("asyncio") FROM THE LOOP THREAD during the exact teardown window #17 lives in —
#     the most on-mechanism late emitter, and reachable by NO other parent below (it does not propagate
#     through them).
#   - "aiosqlite": fixed name in aiosqlite/core.py — THE lost-wakeup emitter (worker-thread emits).
#   - "messagefoundry": engine/store/pipeline/transports all use getLogger(__name__); this parent
#     covers every child (incl. messagefoundry.audit) by propagation.
#   - "tee.relay": fixed name in tee/relay.py — the relay behind the historically-flaky test_tee_relay.
#   - "uvicorn": covers uvicorn / uvicorn.error / uvicorn.access (the server-side emits).
# Deliberately excluded (evidence-backed, not oversight): starlette registers no dedicated app logger;
# the harness monitor uses print()/Qt, not stdlib logging — neither is a teardown-window background
# emitter. (python-hl7's getLogger(__file__)-named loggers were listed here; the dependency is retired.)
_QUIESCE_TARGETS: tuple[str, ...] = (
    "asyncio",
    "aiosqlite",
    "messagefoundry",
    "tee.relay",
    "uvicorn",
)

# A sentinel level safely above CRITICAL so any late record is below the bar and dropped at the source.
_ABOVE_CRITICAL = logging.CRITICAL + 10


class _Baseline:
    """Snapshot of one target logger's natural (caplog-capturing) configuration.

    Captured once per session BEFORE any quiescing, so setup can restore each test body to the exact
    state caplog-asserting tests expect (e.g. messagefoundry.audit.propagate is True;
    uvicorn.error.handlers == []). We record the raw ``logger.level`` int (NOTSET is ``0``) so restore
    re-applies NOTSET vs an explicit level faithfully.
    """

    __slots__ = ("level", "propagate")

    def __init__(self, logger: logging.Logger) -> None:
        self.level: int = logger.level
        self.propagate: bool = logger.propagate


@pytest.fixture(scope="session", autouse=True)
def _quiesce_baseline() -> Iterator[dict[str, _Baseline]]:
    """Snapshot each target logger's natural config ONCE, before any per-test quiescing runs.

    Session-scoped so the baseline is the loggers' real configured state — not a state already
    perturbed by an earlier test's teardown quiesce. The per-test finalizer restores to this baseline
    at setup (pre-yield) so every test body captures exactly as it would without #17 in play.

    On session teardown it restores the baseline once more, so the final test's teardown-quiesce does
    not leave the targets mutated at process exit (state symmetry; harmless either way as the pytest
    process exits immediately and production loads a fresh interpreter).
    """
    baseline = {name: _Baseline(logging.getLogger(name)) for name in _QUIESCE_TARGETS}
    yield baseline
    _restore_baseline(baseline)


# A sentinel handler so a quiesced logger always has a terminal sink during teardown even if it does
# not propagate — a record that somehow clears the level still lands in a NullHandler (never a closing
# capture stream). We tag instances so setup can remove exactly the ones we added, leaving any
# application-installed handlers alone.
class _QuiesceNullHandler(logging.NullHandler):
    pass


@pytest.fixture(autouse=True)
def _quiesce_background_loggers_at_teardown(
    _quiesce_baseline: dict[str, _Baseline],
) -> Iterator[None]:
    """PRIMARY guard for the teardown-LOGGING race: quiesce background-component loggers in the per-test
    TEARDOWN window. (The mid-test cross-loop concern is handled by the shared session loop in pyproject.)

    This function-scoped autouse fixture is the version-robust hook point (GROUND A): its post-yield
    body runs inside ``LoggingPlugin``'s teardown ``catching_logs`` window — i.e. WHILE pytest's
    capture handlers are attached and BEFORE the capture streams finish closing — without depending on
    fragile relative hookwrapper ordering. It pairs setup-restore with teardown-quiesce atomically, so
    quiescing is ALWAYS undone before the next test body.

    SETUP (pre-yield): restore each target logger to its session baseline — propagate, level, and
    removal of any sentinel NullHandler we added. This guarantees the upcoming test body (and its
    ``caplog.at_level(...)`` assertions) captures normally, because the record must still propagate to
    the root capture handler during the body.

    TEARDOWN (post-yield): quiesce each target — propagate=False, level above CRITICAL, and a sentinel
    NullHandler if absent. A late emit from a background thread is then dropped at the SOURCE logger and
    never reaches a root capture handler on a closing stream, closing the dangerous
    teardown -> next-setup gap that #17 lives in. We do NOT touch pytest's own root handlers (GROUND A
    notes detaching is optional and secondary; several test_logging.py tests assert exact root-handler
    composition), so source-logger quiescing alone carries the fix.
    """
    # SETUP: restore the caplog-capturing baseline before the test body runs.
    _restore_baseline(_quiesce_baseline)
    try:
        yield
    finally:
        # TEARDOWN: drop late emits at the source for the rest of the teardown/next-setup window.
        _quiesce_targets()


@pytest.fixture
def bounded_warn_only_retention(monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #1967: an enforcing start refuses a warn-only retention tier with neither a window nor
    its acknowledgement. OPT-IN, never autouse, so a test module names the gate it stands down
    (tests/_phi_gate_provisions.py argues why): a module whose serve fixtures test other gates takes
    it with ``pytestmark = pytest.mark.usefixtures("bounded_warn_only_retention")``."""
    from tests._phi_gate_provisions import setenv_retention_windows

    setenv_retention_windows(monkeypatch)


@pytest.fixture(scope="session")
def _syslog_ca_and_crl_bundle(tmp_path_factory: pytest.TempPathFactory) -> str:
    """One synthetic CA+CRL PEM per session, for :func:`verified_log_forwarding`."""
    from tests._phi_gate_provisions import make_syslog_ca_and_crl

    return make_syslog_ca_and_crl(tmp_path_factory.mktemp("syslog-ca"))


@pytest.fixture
def verified_log_forwarding(
    monkeypatch: pytest.MonkeyPatch, _syslog_ca_and_crl_bundle: str
) -> None:
    """BACKLOG #1966: an enforcing PHI start refuses without off-box forwarding configured as
    verified TLS to a non-loopback collector. OPT-IN, never autouse, for the same reason as
    :func:`bounded_warn_only_retention`: a serve-provisioning module names it in its ``pytestmark``."""
    from tests._phi_gate_provisions import setenv_verified_log_forwarding

    setenv_verified_log_forwarding(monkeypatch, _syslog_ca_and_crl_bundle)


def _restore_baseline(baseline: dict[str, _Baseline]) -> None:
    """Return every target logger to its natural, caplog-capturing baseline (pre-yield)."""
    for name, snap in baseline.items():
        logger = logging.getLogger(name)
        logger.propagate = snap.propagate
        logger.setLevel(snap.level)
        # Drop only the sentinel handlers we added during a prior teardown; leave app handlers intact.
        for handler in [h for h in logger.handlers if isinstance(h, _QuiesceNullHandler)]:
            logger.removeHandler(handler)


def _quiesce_targets() -> None:
    """Drop late emits at the source logger during the teardown window (post-yield)."""
    for name in _QUIESCE_TARGETS:
        logger = logging.getLogger(name)
        logger.propagate = False
        logger.setLevel(_ABOVE_CRITICAL)
        if not any(isinstance(h, _QuiesceNullHandler) for h in logger.handlers):
            logger.addHandler(_QuiesceNullHandler())


@pytest.fixture(autouse=True)
def _restore_process_logging() -> Iterator[None]:
    """Put the root logger and the process-wide log write guard back after every test.

    ``configure_logging`` and ``configure_stderr_logging`` (reached through ``main(...)`` and direct
    calls) empty the root logger's handlers. They then add a handler bound to whatever ``sys.stdout``
    or ``sys.stderr`` was at that moment, which is that test's capture stream. They also set the root
    level and publish a write guard. None of it was undone.

    The measured failure, 2026-09-29: a later test on the same worker logged to the closed stream.
    The write guard then rolled the sink onto the new test's stdout. Its own warning and the record
    landed in that test's captured output. ``tests/test_forwarding_gate.py`` followed by the
    ``audit-verify``/``audit-anchor`` stdout tests in ``tests/test_store_schema.py`` fails on
    ``origin/main`` without this, and passes with it.

    BACKLOG #2093 widened the restore to filters, because a leaked ``RedactionFilter`` rewrites the
    record ``caplog`` later reads. ``tests/_root_logging.py`` is the one place that says what is
    restored, why, and what is not covered.

    A module fixture with this same name REPLACES this one for that module. Do not add one.
    """
    with root_logging_restored():
        yield


@pytest.fixture(scope="session", autouse=True)
def _tolerate_logging_on_closed_capture_streams() -> Iterator[None]:
    """SECONDARY backstop for the #17 teardown race — fast-and-silent, not the primary fix.

    Even with source-logger quiescing in place (the primary fix above), a record can in principle reach
    a closed capture stream during the brief teardown window. ``logging.Handler.emit`` then raises
    ``ValueError: I/O operation on closed file`` and routes it to ``Handler.handleError``, which — while
    ``logging.raiseExceptions`` is the default ``True`` — writes a traceback to ``sys.stderr``.
    Background threads can make that error-handling path flood output and wedge the event-loop thread
    *inside the synchronous* ``emit`` (it holds the handler lock) until the per-test ``--timeout`` fires.

    Setting ``logging.raiseExceptions = False`` makes ``handleError`` a no-op, so any straggler fails
    fast and silently instead of flooding / deadlocking. It is the stdlib's documented production-mode
    switch, scoped to the test session only (production keeps the default). This was shipped on its own
    first and did NOT clear the hang (flaked again on PR #396) — hence it is retained only as a
    secondary backstop beneath the teardown-ordering finalizer; the ``pytest-timeout`` watchdog (#375)
    remains the final guard.
    """
    prior_raise = logging.raiseExceptions
    logging.raiseExceptions = False
    try:
        yield
    finally:
        logging.raiseExceptions = prior_raise


# ---------------------------------------------------------------------------------------------------
# LOUD OMISSION: an incomplete run must SAY SO (BACKLOG #1230 — the loud-omission half only, per the
# owner's 2026-08-12 scope ruling; the venv is deliberately NOT changed here).
#
# WHAT PROMPTED IT, IN THE PAST TENSE BECAUSE IT IS FIXED. `scripts/worktree/new.ps1` USED TO build a
# lane venv from `.[dev,harness]` while CI installed five more extras and the web console package on
# top. Every module gated on that gap removed ITSELF at collection time via a module-level
# `pytest.importorskip`, so those tests never became test items at all: a large block of coverage
# collapsed into a short skip tally and the run still printed as green.
#
# THAT PARTICULAR GAP IS CLOSED (BACKLOG #1335). `new.ps1` now installs CI's full extras list plus
# `-e packaging/messagefoundry-webconsole`, and `tests/test_worktree_venv_extras_parity.py` compares
# the installer's line against `ci.yml`'s and goes red when they drift. Cite that test, not a line
# number: this comment used to name `new.ps1:232` and `ci.yml:273`, and both had moved by the time
# anyone read them. A stale line citation is worse than no citation, because following it lands
# somewhere plausible and so reads as verified.
#
# THE HOOKS BELOW ARE NOT THEREBY REDUNDANT. Parity covers ONE way to reach an incomplete run: the
# installer's. A venv built by hand, an installer skipped, a subset installed on purpose, or an extra
# CI gains before a lane is rebuilt all land in the same place, and none of them is a drift between
# two files that the parity test can see.
#
# THE DEFECT IS THE SILENCE, NOT THE ABSENCE. Skipping an uninstalled optional extra is correct and
# intended. Rendering an incomplete run as a complete one is not — "the full suite is green" is the
# sentence the next session bases its own scope on, and a run earns it only when the venv under it
# really did install everything.
#
# Deliberately NOT a pinned test count. A hard-coded figure would be right the day it was written and
# silently wrong after, and a stale number in a measurement surface is worse than none: re-running
# reproduces it, so it reads as verified. What prints is what is re-derived every run — which extras
# are absent, and the command that installs them.
#
# This never fails a run and never skips anything itself. It only makes an already-incomplete run
# legible, so the omission has to be read rather than inferred from a skip count.
#
# SCOPE, STATED RATHER THAN IMPLIED. These hooks live in tests/conftest.py, so they load for any run
# that collects tests/ — which includes every full-suite run, the only kind that can earn the phrase
# above. A run scoped ENTIRELY to the other testpath (packaging/messagefoundry-webconsole/tests)
# does not load this file and prints no banner. Measured both ways, with a control to rule out the
# hooks simply being inert: webconsole-only collected 365 tests silently; the same flags over a
# tests/ path printed the banner. That gap is left rather than fixed with a repo-root conftest.py,
# which would change collection globally and is outside this item's ruled scope — a deliberately
# scoped run already reads as partial; a full-suite run is the one that must not.
# ---------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------
# NO TEST MAY LEAVE ALLOCATION RECORDS IN THE CHECKOUT.
#
# The allocator (scripts/coord/alloc.ps1) and the fixtures that MIMIC it write their claims under
# <git-common-dir>/mefor-coord/alloc/<kind>/<number>.json. That path is inside .git, so a correct write
# is invisible to `git status` and cannot ride into a commit. A `mefor-coord/` directory at the WORK
# TREE root is therefore never legitimate -- it means something built that path from an empty or
# relative base and it landed in the process cwd instead.
#
# MEASURED 2026-09-18, and the reason this guard exists rather than a comment. tests/test_ledger_check.py
# built the path from `git rev-parse --git-common-dir` read through a helper that returns only stdout
# with check=False. Every git call in that run returned empty, so the base was "", Path("") / "mefor-
# coord" is RELATIVE, and five claim records landed at a worktree root. The records name the defect
# themselves: every field the helper DERIVED from git was "" while every field the caller PASSED was
# intact. Nothing reported a problem, because the write succeeded -- it just succeeded somewhere else.
#
# The guard is function-scoped so the failure names the test that did it. It compares against a
# pre-test snapshot, so a directory left behind by an earlier run fails ONE test rather than cascading
# through the suite; and it removes what leaked, so the next test's snapshot is clean again and the
# guard stays armed for the rest of the run. The evidence is not lost by that removal -- the failure
# message carries the file list, which is the part that identifies the writer.
#
# Both roots are checked because they can differ: the leak lands in the pytest process's cwd, which is
# usually the checkout root but is not required to be.
# ---------------------------------------------------------------------------------------------------

_CHECKOUT_ROOT = Path(__file__).resolve().parents[1]


def _coord_leak_roots() -> list[Path]:
    """The work-tree directories a stray allocation record can land in, de-duplicated."""
    roots: list[Path] = []
    for base in (_CHECKOUT_ROOT, Path.cwd().resolve()):
        candidate = base / "mefor-coord"
        if candidate not in roots:
            roots.append(candidate)
    return roots


@pytest.fixture(autouse=True)
def _no_allocation_records_in_the_checkout() -> Iterator[None]:
    """Fail the test that writes a mefor-coord/ tree into the work tree instead of its own temp repo."""
    before = {root: root.exists() for root in _coord_leak_roots()}
    yield

    leaked: list[str] = []
    for root, existed in before.items():
        if existed or not root.exists():
            continue
        leaked.extend(
            sorted(str(f) for f in root.rglob("*") if f.is_file()) or [f"{root} (no files)"]
        )
        shutil.rmtree(root, ignore_errors=True)

    if leaked:
        detail = "\n  ".join(leaked)
        pytest.fail(
            "this test wrote allocation records into the checkout instead of its own temp tree.\n"
            "A correct write goes under <git-common-dir>/mefor-coord/, which is inside .git.\n"
            "A relative or empty base lands it in the process cwd, where `git add -A` can commit it.\n"
            f"Leaked (now removed):\n  {detail}"
        )


def pytest_report_header() -> list[str]:
    return report_header_lines()


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    write_incomplete_run_summary(terminalreporter)


# ---------------------------------------------------------------------------------------------------
# THE TOOLING PARTITION -- marks the repo-harness tier so ci.yml can run it as its own path-gated job.
#
# The tier is 17 percent of the suite's tests and 66 percent of its TIME (measured 2026-08-16: 94
# files, 2,145s of 3,249s), because each test spawns real pwsh/git children. Its subject is the
# development harness, not the engine, so an engine-only PR cannot change its result -- yet it sets
# the `--dist loadfile` floor for every engine leg. `-m 'not tooling'` takes it off that path.
#
# MEMBERSHIP IS A MANIFEST, NOT A PATTERN, AND NOT A DIRECTORY. Three regex classifiers were tried
# and each got a different obvious case wrong (one would have moved `test_dependency_boundaries` --
# the one-way import rule -- off the engine legs). Relocating the files into tests/tooling/ was then
# tried and reverted: they are coupled to their location in at least five ways, two of which only
# surfaced by running the suite. Both failure modes are the same one CLAUDE.md section 11 records for
# the backlog glyph parser -- a classifier that agrees with the corpus by luck. So the list is
# written down, and tests/test_tooling_partition.py pins it against the tree.
#
# A MISSING OR UNREADABLE MANIFEST RAISES. It must not degrade to "mark nothing": that spelling keeps
# `-m 'not tooling'` correct-but-slow while making `-m tooling` collect ZERO, so the entire harness
# tier would stop running and its job would go green having tested nothing. Loud beats silent in the
# direction that loses coverage.
#
# Scoped to files sitting DIRECTLY in tests/. The other testpath
# (packaging/messagefoundry-webconsole/tests) is a separate suite with its own pytest config; keying
# on the basename alone would let a same-named file there inherit a mark meant for this directory.
#
# THE PYTHON PARSER IS tests/_tooling_manifest.py (BACKLOG #1434). This hook used to carry its own
# copy, one of three that nothing pinned against each other. ci.yml reads the file too, in shell;
# that module's docstring says how the two are kept from disagreeing.
# ---------------------------------------------------------------------------------------------------

_TESTS_DIR = Path(__file__).resolve().parent


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    # `tests` resolves through sys.path, and an editable install from ANOTHER worktree can put that
    # checkout first. Its manifest would then mark this tree's tests with no error, so refuse.
    if tooling_manifest.MANIFEST.parent != _TESTS_DIR:
        raise RuntimeError(
            f"the tooling manifest resolved to {tooling_manifest.MANIFEST}, outside {_TESTS_DIR}: "
            "`tests` was imported from another checkout, so its list would mark this one's tests"
        )
    names = frozenset(tooling_manifest.names())  # raises if absent or malformed -- see above
    for item in items:
        path = getattr(item, "path", None)
        if path is not None and path.parent == _TESTS_DIR and path.name in names:
            item.add_marker(pytest.mark.tooling)


@pytest.fixture(autouse=True)
def _provision_admin_enrols_a_synthetic_authenticator() -> Iterator[None]:
    """``provision-admin`` enrols TOTP at the terminal (ADR 0197 Amendment A, N-A), which reads a
    code from a real terminal. Every test that drives the command about something else gets a
    synthetic, VALID enrolment here, so it keeps testing what it was written for. The tests of the
    enrolment itself replace this stub in their own body.

    ITS OWN ``MonkeyPatch``, NOT THE ``monkeypatch`` FIXTURE. An autouse fixture that requests
    ``monkeypatch`` instantiates it before every other fixture of the test, so it is torn down AFTER
    them. A test that stubs an attribute a fixture's teardown uses (``tests/test_api.py`` swaps the
    engine's registry runner, relying on the undo running before ``engine.stop()``) then fails in
    teardown. A private instance leaves the shared fixture's order exactly as it was."""
    import messagefoundry.__main__ as cli
    from tests._admin_account import provision_totp

    def _stub(*, username: str, skew_steps: int) -> tuple[str, str, float]:
        kw = provision_totp()
        return kw["totp_secret"], kw["totp_code"], kw["totp_code_read_at"]

    # The real prompt, for the tests that drive it: ``cli._enrol_totp_at_terminal.__wrapped__``.
    _stub.__wrapped__ = cli._enrol_totp_at_terminal  # type: ignore[attr-defined]

    # The recovery codes go to the console DEVICE (CodeQL alert 228), which pytest cannot capture: on
    # a developer's machine the real one would print them onto the screen running the suite. Dropped
    # here; the tests of the enrolment record what reaches it in their own body.
    def _drop(text: str) -> None:
        return None

    _drop.__wrapped__ = cli._show_on_terminal  # type: ignore[attr-defined]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(cli, "_enrol_totp_at_terminal", _stub)
        patch.setattr(cli, "_show_on_terminal", _drop)
        yield
