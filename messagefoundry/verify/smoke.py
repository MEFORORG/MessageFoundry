# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""End-to-end smoke + store connectivity — proves the deployment actually works on this box.

* ``self``  — route a synthetic HL7 through the box's *real* config via :func:`dry_run` (no store, no
  network, no side effects). Proves the config loads + routes + transforms cleanly on this host. It
  PASSES only on a **delivering** outcome: a run that routes or transforms the message into nothing
  fails, naming the disposition (BACKLOG #1707) — see :func:`_classify_self_smoke`.
* ``live``  — MLLP-send a synthetic HL7 to the running engine's inbound and confirm an **AA ACK**.
  Proves the real listener accepts + acks. (Full disposition is then confirmed in the console — a
  MANUAL row — so the tool stays dependency-light and not brittle to API specifics.)
* store     — open the *existing* configured store backend and confirm it connects. For SQLite it
  refuses to create the database file first (BACKLOG #1708): ``open_store``'s schema-ensure created
  whatever path it was handed until BACKLOG #1780, so the check used to PASS against a store it had
  just made and leave the database behind — meaning it could not fail for the reason its title names.

Synthetic HL7 only — never real PHI. The smoke message is inlined below rather than generated, so
the verifier never imports ``messagefoundry.generators`` (BACKLOG #1192 / ASVS 15.2.3).
"""

from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import TYPE_CHECKING, Final

from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.config.tls_policy import (
    harden_cipher_suites,
    harden_kex_groups,
    harden_verify_flags,
)
from messagefoundry.verify.model import CheckResult, Status

if TYPE_CHECKING:
    # Annotation only. A runtime import here would pull ``store.store`` (and so ``aiosqlite``) into
    # every ``messagefoundry verify`` run, including ``--section host``, which never opens a store —
    # this package keeps its module-level surface thin on purpose and defers store imports into the
    # functions that need them.
    from messagefoundry.store.store import MessageStatus

#: The smoke message, segment by segment.
#:
#: **Why it is a literal.** The deployment verifier is the one tool an operator runs on a real box,
#: so anything it imports is functionality that install is required to carry. Generating the message
#: pulled the whole ``messagefoundry.generators`` package — development tooling — into the verifier's
#: runtime dependency set. Inlining removes that edge. Nothing else under ``messagefoundry/verify/``
#: touches the generators, and ``tests/test_verify.py`` pins that.
#:
#: **Where it came from.** ``generate_message("ADT", "A01", 0)`` from the engine's own ADT generator
#: at ``744a7a434``, verbatim, except that every person name was replaced with the ``ZZZTEST`` family
#: so an operator who finds this message in their own store reads it as a probe rather than a
#: patient. The edited form was re-checked through the generator's compliance gate and hl7apy strict
#: validation at 2.5.1 before being pasted here, and ``tests/test_verify.py`` re-runs that validation
#: on every test run — so the literal cannot rot into a non-conformant message unnoticed.
#:
#: Every value is fabricated: the demographics come from the generator's synthetic pools, the phone
#: sits in the reserved 555-01xx fictional range, and MSH-10 carries the tool's own ``MEFOR`` prefix.
#: No real PHI (CLAUDE.md section 9).
_SYNTHETIC_ADT_A01_SEGMENTS: Final[tuple[str, ...]] = (
    r"MSH|^~\&|ADT|MAINHOSP|PHARMACY|MAINHOSP|20260202114200||ADT^A01^ADT_A01"
    r"|MEFORADTA0100000|P|2.5.1",
    "EVN|A01|20260202114200||||20260202114200",
    "PID|1||6824181^^^HOSP^MR||ZZZTEST^SYNTHETIC^C||20081018|U|||"
    "26 HILLCREST AVE^^CLAYTON^MO^63105^USA||(834)555-0120|||||V2167387^^^HOSP^AN",
    "NK1|1|ZZZTEST^KINONE|CHD^Child^HL70063",
    "NK1|2|ZZZTEST^KINTWO|FND^Friend^HL70063",
    "PV1|1|R|MATERNITY^412^B^SOUTH||||1008^ZZZTEST^PROVONE|||URO|||||||1006^ZZZTEST^PROVTWO"
    "||V2167387^^^HOSP^VN|||||||||||||||||||||||||20260202114200",
    "PV2|||R07.9^Chest pain unspecified^I10",
    "DB1|1|PT",
    "DB1|2|PT",
    "OBX|1|NM|8302-2^Body height^LN||170|cm|||||F",
    "AL1|1|DA^Drug allergy^HL70127|SULFA^Sulfa drugs^L|MO",
)

#: ``\r``-delimited with a trailing ``\r``, the form the generator emits and an MLLP frame carries.
SYNTHETIC_ADT_A01: Final[str] = "\r".join(_SYNTHETIC_ADT_A01_SEGMENTS) + "\r"


def synthetic_message() -> str:
    """One conformant synthetic ADT^A01 (no PHI). See :data:`SYNTHETIC_ADT_A01`."""
    return SYNTHETIC_ADT_A01


def _classify_self_smoke(disposition: MessageStatus, summary: str) -> CheckResult:
    """Map a **dry-run** disposition to the ``smoke.self`` result (pure — unit-tested).

    The self smoke exists to answer *would a message reach a destination on this box*. Until BACKLOG
    #1707 it answered *did* ``dry_run`` *return*: ``Status.PASS`` was unconditional on everything but
    ``DryRunResult.error``, so a synthetic message the config routed nowhere (``UNROUTED``) or
    transformed into nothing (``FILTERED``) wrote its disposition into the summary and still reported
    the deployment green. Zero deliveries is **blind** here, not clean — the opposite of a scanner,
    where finding nothing is the good answer.

    The verdict matches the one :func:`_classify_disposition` reaches for the **live** smoke on the
    **same** synthetic message (``runner._run_live_smoke`` sends :func:`synthetic_message`).
    Softening one side would leave two divergent answers to one question about one config, which is
    worse than either answer alone. It is deliberately **not** that function: ``RECEIVED`` means
    different things on the two paths — :func:`~messagefoundry.pipeline.dryrun.disposition_for`
    explains the split — so sharing the code would teach one classifier two meanings of one member.
    """
    from messagefoundry.store.store import MessageStatus as Disposition

    rid, title = "smoke.self", "Self smoke (dry-run routing)"
    if disposition is Disposition.RECEIVED:
        return CheckResult(rid, title, Status.PASS, summary)  # the preview's delivering outcome
    if disposition is Disposition.NOT_DEPLOYED:
        # Its own arm and its own remedy, which is the whole point of the member (BACKLOG #1690
        # split it out of FILTERED so this gate could stop reading a decline as an author's filter).
        # The Router and the Handler both did their job here, so the two remedies below are both
        # wrong for it: re-pointing ``--inbound`` finds a different feed for a feed that was fine,
        # and looking at the filter finds a filter that did not fire.
        return CheckResult(
            rid,
            title,
            Status.FAIL,
            f"{summary} — a handler ran and produced a Send, but every destination it addressed is "
            "present-but-not-deployed, so nothing would be delivered; deploy the outbound "
            "connection(s) the Handler sends to, or send to one that is already deployed",
        )
    if disposition is Disposition.UNROUTED:
        reason = "the Router selected no handler, so nothing would be delivered"
    elif disposition is Disposition.FILTERED:
        # No longer "or every destination is present-but-not-deployed": that outcome is
        # ``NOT_DEPLOYED`` above, and naming it here too is what made the two indistinguishable.
        reason = "handlers ran but produced no delivery — a filter returned nothing"
    else:
        # Fail closed, and deliberately WITHOUT the remedy below. This arm exists for a member added
        # after this function: ``disposition_for`` returns exactly RECEIVED, UNROUTED, FILTERED and
        # NOT_DEPLOYED, and all four are handled above. Re-pointing ``--inbound`` is not something
        # that flag could act on for an unforeseen member, and a confident wrong remedy, at the one
        # moment an operator is reading this row, is worse than none.
        #
        # This comment used to claim ``disposition_for`` could not reach any member here. That
        # stopped being true when #1690 added NOT_DEPLOYED, and the arm silently became the handler
        # for a live outcome it was never written for -- correct verdict, no usable next step.
        return CheckResult(
            rid,
            title,
            Status.FAIL,
            f"{summary} — {disposition.value.upper()} is not a delivering outcome",
        )
    return CheckResult(
        rid,
        title,
        Status.FAIL,
        # The operator half, and it belongs to these two dispositions rather than to the verdict: the
        # verdict says no delivery, this says which of the two reasons is theirs. The synthetic
        # message is fixed (:data:`SYNTHETIC_ADT_A01`), so a site whose Router keys on its own sending
        # facility declines it legitimately and needs a pointer, not a shrug.
        f"{summary} — {reason}; this run proves the config LOADS, not that it routes. The synthetic "
        "message is an ADT^A01 from MAINHOSP, so a Router keyed on a different feed declines it: "
        "point --inbound at a connection that takes one, or fix the Router/Handler",
    )


def smoke_self(
    config_dir: str, *, inbound: str | None = None, snapshot_on_send: bool = False
) -> CheckResult:
    """Route a synthetic message through the box's config with no side effects (``dry_run``).

    PASSES only on a delivering outcome; :func:`_classify_self_smoke` carries what fails and why.

    ``snapshot_on_send`` (ADR 0104) selects the copy-on-Send posture the preview reproduces, matching
    the live engine's ``[pipeline].snapshot_on_send``. It keeps the library default ``False`` here so a
    caller that resolves no service settings previews the pre-ADR-0104 behaviour; the verify runner
    passes the resolved setting (``True`` on a default engine) so the smoke mirrors what actually ships
    — see :func:`messagefoundry.verify.runner.run_verify`."""
    from pathlib import Path

    # One source for the pair, as the classifiers below already do. The id is the grouping and
    # exit-code key `verify/report.py` reads, so spelling it per-return made a retitle a six-edit
    # change that splits the row in two if one is missed.
    rid, title = "smoke.self", "Self smoke (dry-run routing)"
    if not Path(config_dir).is_dir():
        return CheckResult(
            rid,
            title,
            Status.SKIP,
            f"no config dir at {config_dir!r} — pass --config <your config repo>",
        )
    from messagefoundry.config.wiring import WiringError, load_config
    from messagefoundry.pipeline.dryrun import (
        AmbiguousInboundError,
        NoInboundError,
        UnknownInboundError,
        dry_run,
    )
    from messagefoundry.redaction import safe_error, safe_exc

    try:
        reg = load_config(config_dir)
    except WiringError as exc:
        return CheckResult(rid, title, Status.FAIL, f"config failed to load: {exc}")
    msg = synthetic_message()  # a module constant since #1192 — cannot fail
    try:
        result = dry_run(reg, msg, inbound=inbound, snapshot_on_send=snapshot_on_send)
    except AmbiguousInboundError as exc:
        # The only selection failure that SKIPs: nothing is wrong, the operator has a choice to make.
        # An unknown `--inbound` name or a config with no inbound is a defect, so it FAILs below.
        # `_classify_self_smoke` tells an operator to re-point `--inbound`, so a typo in that remedy
        # must not read green (BACKLOG #1707). The detail names the flag, or the operator is told to
        # choose with no word on how.
        return CheckResult(rid, title, Status.SKIP, f"{exc}; pass --inbound <name> to pick one")
    except (UnknownInboundError, NoInboundError) as exc:
        # Connection names and operator input only, never message content, so nothing to redact.
        return CheckResult(rid, title, Status.FAIL, str(exc))
    except Exception as exc:
        # Raised while the message was in flight, so its text can quote the message (BACKLOG #1779).
        return CheckResult(rid, title, Status.ERROR, f"dry-run raised: {safe_exc(exc)}")

    summary = (
        f"inbound={result.inbound}, disposition={result.disposition.value}, "
        f"handlers={len(result.handlers)}, deliveries={len(result.deliveries)}"
    )
    if result.error:
        # `verify --report-md`/`--report-json` write this detail to a file that gets pasted into
        # tickets, and the error quotes a Router/Handler's own `raise` (BACKLOG #1779). No `show_phi`
        # opt-in, on purpose, for the reason the `check` gate refuses one: both write their output
        # somewhere it is kept and passed on, so an opt-in would put PHI there on request.
        return CheckResult(rid, title, Status.FAIL, f"{summary} — {safe_error(result.error)}")
    # Gate on what the run PRODUCED, never on "the call returned" (BACKLOG #1707). A postcondition
    # over the disposition the pipeline already computed cannot drift out of step with the pipeline;
    # re-deriving "did it deliver" here from the counts would be a second classifier to keep in sync.
    return _classify_self_smoke(result.disposition, summary)


def _recv_mllp(sock: socket.socket, timeout: float) -> bytes:
    """Read an MLLP frame (until the FS+CR trailer) or whatever arrives before timeout."""
    sock.settimeout(timeout)
    buf = bytearray()
    try:
        while b"\x1c\x0d" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
    except TimeoutError:
        pass
    return bytes(buf)


def _ack_code(frame: bytes) -> str | None:
    """Extract MSA-1 (AA/AE/AR) from an MLLP-stripped ACK, reading the field separator from MSH."""
    body = frame.replace(b"\x0b", b"").replace(b"\x1c", b"").replace(b"\x0d", b"\r").strip()
    if not body.startswith(b"MSH") or len(body) < 4:
        return None
    sep = body[3:4]
    for segment in body.split(b"\r"):
        if segment.startswith(b"MSA"):
            fields = segment.split(sep)
            if len(fields) > 1:
                return fields[1].decode("ascii", "replace")
    return None


def live_smoke_ssl_context(*, ca_file: str | None = None) -> ssl.SSLContext:
    """The client TLS context for a live smoke against a ``tls = true`` MLLP inbound (BACKLOG #1178).

    Hardened the same way every other context the engine builds is: a TLS 1.2 floor, the approved
    key-exchange groups, the forward-secrecy assertion (ASVS 12.1.2) and strict RFC 5280 validation
    (ASVS 12.1.4). Inheriting the interpreter's defaults without asserting them is the residual the
    hardening helpers exist to close, and a verifier is not exempt from it.

    ``ca_file`` anchors the engine's certificate when it is not in the system trust store, which is
    the usual case: the engine mints a self-signed pair on first run (ADR 0172). There is
    deliberately **no** verify-off switch — a smoke that accepts any certificate proves the port
    answers, not that the hop is the engine, and this whole item is about not weakening a hop to
    make a test pass."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
    harden_cipher_suites(ctx, connector="verify live smoke")  # forward secrecy (ASVS 12.1.2)
    harden_verify_flags(ctx)  # strict RFC 5280 validation of the engine cert (ASVS 12.1.4)
    return ctx


def smoke_live(
    *,
    host: str,
    port: int,
    message: str,
    timeout: float = 10.0,
    ssl_context: ssl.SSLContext | None = None,
    server_hostname: str | None = None,
) -> CheckResult:
    """MLLP-send ``message`` to the running engine and confirm an AA ACK.

    ``ssl_context`` makes the smoke speak the protocol the target inbound speaks (BACKLOG #1178,
    ASVS 12.3.1). Without it this call writes a whole MLLP frame — a synthetic message body, but a
    body — onto a bare socket before it has any evidence the peer is a cleartext listener. ``None``
    keeps that plaintext path, which is correct for a plaintext inbound and only for one.

    The switch is the caller's to make and is never inferred: probing in the clear and retrying over
    TLS (or the reverse) is exactly the protocol fall-back 12.3.1 forbids, so a mismatch fails and
    says so instead."""
    frame = b"\x0b" + message.encode("utf-8") + b"\x1c\x0d"
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            # Handshake FIRST when TLS is asked for, so no application byte can precede it.
            # wrap_socket detaches `raw`, so the outer context manager's close is a no-op and the
            # descriptor is closed exactly once, by the inner one.
            sock = (
                raw
                if ssl_context is None
                else ssl_context.wrap_socket(raw, server_hostname=server_hostname or host)
            )
            with sock:
                sock.sendall(frame)
                reply = _recv_mllp(sock, timeout)
    except ssl.SSLError as exc:  # an OSError subclass, so it must be caught before the arm below
        return CheckResult(
            "smoke.live",
            "Live smoke (MLLP + ACK)",
            Status.FAIL,
            f"TLS handshake with the engine inbound at {host}:{port} failed: {exc}",
        )
    except OSError as exc:
        return CheckResult(
            "smoke.live",
            "Live smoke (MLLP + ACK)",
            Status.FAIL,
            f"could not reach the engine inbound at {host}:{port}: {exc}",
        )
    code = _ack_code(reply)
    if code == "AA":
        return CheckResult(
            "smoke.live",
            "Live smoke (MLLP + ACK)",
            Status.PASS,
            f"{host}:{port} returned an AA ACK (confirm disposition in the console)",
        )
    if code in ("AE", "AR"):
        return CheckResult(
            "smoke.live",
            "Live smoke (MLLP + ACK)",
            Status.FAIL,
            f"engine NAK'd the message: MSA-1={code}",
        )
    detail = f"no parseable ACK from {host}:{port} ({len(reply)} bytes received)"
    if not reply and ssl_context is None:
        # A TLS listener handed a cleartext MLLP frame fails the handshake and closes, so the
        # client sees an accepted connection and zero bytes — indistinguishable, from here, from a
        # plaintext listener that hung up. Name the possibility rather than act on it: switching
        # protocols on this evidence is the fall-back ASVS 12.3.1 forbids, and the operator knows
        # which one their inbound is.
        detail += (
            "; the listener accepted the connection and closed without a byte, which is also what "
            "a tls = true MLLP inbound does to a cleartext frame. If this inbound is TLS, the "
            "synthetic message has already crossed in the clear; re-run with --smoke-tls (and "
            "--smoke-tls-ca for a self-signed engine certificate). The smoke never retries over "
            "TLS on its own"
        )
    return CheckResult("smoke.live", "Live smoke (MLLP + ACK)", Status.FAIL, detail)


def missing_sqlite_store(store: StoreSettings) -> Path | None:
    """The configured SQLite path when it is absent, else ``None`` (nothing for this gate to stop).

    Every ``open_store`` call in the verifier goes through this first (BACKLOG #1708). Before
    BACKLOG #1780 an ungated call made the store it was about to report on: SQLite's connect creates
    an absent file and ``open_store`` ensured the schema into it. Read-only intent was not enough —
    ``newest_message_id`` and ``check_smoke_disposition`` only ever read, and both created a database
    to do it. ``open_store`` now refuses an absent SQLite file by default (``StoreNotFoundError``).
    This gate still runs first, so the verifier reports its own FAIL without importing the store
    stack. The two differ at the edges: this one uses ``is_file()``, the seam counts only
    ``FileNotFoundError`` as absent.

    ``:memory:`` creates nothing on disk and so is outside what this gate exists to stop.

    **Scoped to SQLite, and that is a real limit rather than a proof the others are safe.** What the
    server backends do not do is ``CREATE DATABASE``, so a wrong database *name* fails at connect.
    They do build the whole schema into a database that *does* exist: ``open_store`` runs the same
    ensure-and-migrate on all three. So a Postgres store pointed at ``postgres``, or at a sibling
    application's database, is still populated by a PASSing check — the same defect one level up
    from the file. Closing that needs a per-backend schema-presence probe, which is not this gate;
    ``docs/testing/VERIFY.md`` carries the operator-facing warning meanwhile.
    """
    if store.backend is not StoreBackend.SQLITE or store.path == ":memory:":
        return None
    path = Path(store.path)
    try:
        return None if path.is_file() else path
    except OSError:  # e.g. a permission error stat-ing an ancestor — let the open report it
        return None


def check_store_connectivity(store: StoreSettings) -> CheckResult:
    """Open the *existing* configured store backend, confirm it connects, then close.

    For SQLite the file must already be there. Before BACKLOG #1780 ``open_store`` ensured the schema
    into whatever SQLite's connect created, so without this gate the check created the database it
    then reported PASS against (BACKLOG #1708) — a mistyped ``[store].path`` passed, and an operator
    running ``verify`` elevated on a fresh box left an administrator-owned store at the configured
    path before the service started under another identity.

    The gate covers SQLite only, and :func:`missing_sqlite_store` says what that leaves open on the
    server backends.
    """
    import asyncio

    rid, title = "store.connect", "Store connectivity"
    absent = missing_sqlite_store(store)
    if absent is not None:
        return CheckResult(
            rid,
            title,
            Status.FAIL,
            f"no SQLite store at {absent} — run `messagefoundry serve` once to create it, "
            "or check [store].path (verify does not create it for you)",
            evidence=str(absent),
        )

    # Below the gate on purpose: store.base pulls store.store and aiosqlite, the edge this module's
    # TYPE_CHECKING block exists to defer. The FAIL above needs one stat, not the store stack.
    from messagefoundry.store.base import open_store

    async def _open_close() -> None:
        handle = await open_store(store)
        await handle.close()

    try:
        asyncio.run(_open_close())
    except Exception as exc:  # any driver/connection/auth failure
        return CheckResult(
            rid,
            title,
            Status.FAIL,
            f"{store.backend.value} store failed to open: {exc}",
        )
    return CheckResult(
        rid,
        title,
        Status.PASS,
        f"{store.backend.value} store opened and closed cleanly as the calling user "
        "(NOT proof the NSSM service account can connect — confirm the service-identity grants)",
    )


def newest_message_id(store: StoreSettings, control_id: str) -> str | None:
    """Id of the most-recent stored message with ``control_id`` (the pre-send baseline for the
    disposition check), or ``None``. Lets a re-used synthetic control id not match a prior run's
    message — the disposition poll waits for one NEWER than this baseline. Read-only.

    An absent SQLite store holds no prior message, so it yields ``None`` without opening — and so
    without creating — one (BACKLOG #1708; see :func:`missing_sqlite_store`)."""
    import asyncio

    if missing_sqlite_store(store) is not None:
        return None

    from messagefoundry.store.base import (
        open_store,
    )  # below the gate — see check_store_connectivity

    async def _newest() -> str | None:
        handle = await open_store(store)
        try:
            rows = await handle.list_messages(control_id=control_id, limit=1)
            return str(rows[0]["id"]) if rows else None
        finally:
            await handle.close()

    return asyncio.run(_newest())


def _classify_disposition(status: str | None, *, control_id: str, timeout: float) -> CheckResult:
    """Map a polled message status to the ``smoke.disposition`` result (pure — unit-tested)."""
    from messagefoundry.store.store import MessageStatus

    rid, title = "smoke.disposition", "Live smoke disposition"
    if status is None:
        return CheckResult(
            rid,
            title,
            Status.FAIL,
            f"no NEW stored message with control id {control_id} within {timeout:.0f}s "
            "(is the engine running and pointed at this same store?)",
        )
    if status == MessageStatus.PROCESSED.value:
        return CheckResult(rid, title, Status.PASS, f"control id {control_id} reached PROCESSED")
    if status in {
        MessageStatus.ERROR.value,
        MessageStatus.FILTERED.value,
        MessageStatus.UNROUTED.value,
    }:
        return CheckResult(
            rid,
            title,
            Status.FAIL,
            f"control id {control_id} ended {status.upper()}, not PROCESSED — a post-ACK failure "
            "(dead-letter / handler / delivery; e.g. the service-identity db-grant trap)",
        )
    return CheckResult(
        rid,
        title,
        Status.FAIL,
        f"control id {control_id} still {status.upper()} after {timeout:.0f}s "
        "(did not reach a terminal disposition)",
    )


def check_smoke_disposition(
    store: StoreSettings, *, control_id: str, baseline_id: str | None, timeout: float = 15.0
) -> CheckResult:
    """Poll the store for the live-smoke message's FINAL disposition.

    ``smoke.live`` only proves the listener ACKed; this proves the message actually *processed* —
    catching a **post-ACK dead-letter** (a bad transform, a delivery failure, or the service-identity
    db-grant trap), which a headless/CI acceptance run would otherwise miss. Correlates by MSH-10
    control id, waiting for a message NEWER than ``baseline_id`` (so a re-used synthetic id can't match
    a prior run). Read-only; opens the store as the calling user, and refuses to create an absent
    SQLite one to do it (BACKLOG #1708).
    """
    import asyncio

    rid, title = "smoke.disposition", "Live smoke disposition"
    absent = missing_sqlite_store(store)
    if absent is not None:
        return CheckResult(
            rid,
            title,
            Status.FAIL,
            f"no SQLite store at {absent} — is the engine running and pointed at this same store? "
            "(check [store].path; verify does not create it for you)",
            evidence=str(absent),
        )

    # Below the gate — see check_store_connectivity.
    from messagefoundry.store.base import open_store
    from messagefoundry.store.store import MessageStatus

    terminal = {
        MessageStatus.PROCESSED.value,
        MessageStatus.ERROR.value,
        MessageStatus.FILTERED.value,
        MessageStatus.UNROUTED.value,
    }

    async def _poll() -> str | None:
        handle = await open_store(store)
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            last: str | None = None
            while True:
                rows = await handle.list_messages(control_id=control_id, limit=1)
                if rows and str(rows[0]["id"]) != baseline_id:
                    last = str(rows[0]["status"])
                    if last in terminal:
                        return last
                if loop.time() >= deadline:
                    return last
                await asyncio.sleep(0.25)
        finally:
            await handle.close()

    try:
        status = asyncio.run(_poll())
    except Exception as exc:  # any driver/connection failure — surface, never crash the verify run
        return CheckResult(rid, title, Status.ERROR, f"could not read the store disposition: {exc}")
    return _classify_disposition(status, control_id=control_id, timeout=timeout)
