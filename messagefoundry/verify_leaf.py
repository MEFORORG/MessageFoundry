# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The half of the deployment verifier a client may import: the listener-port probe and the detail
scrub.

**Why this module exists (BACKLOG #5389, #5395).** The acceptance harness (``harness/acceptance``)
reports the same port bindability and quotes the same kind of untrusted exception text as
``messagefoundry verify``. Importing either from :mod:`messagefoundry.verify` loads that package's
runner, and with it ``messagefoundry.transports`` and ``messagefoundry.config``, which a client may
not import (CLAUDE.md section 4). So both live here, beside the other client-importable leaves such
as :mod:`messagefoundry.mllpcodec`. This module imports only the standard library at load, and at
call time only :mod:`messagefoundry.redaction` and :mod:`messagefoundry.secretscrub`;
``tests/test_b532r_verify_harness_a5.py`` pins, in a fresh interpreter, that the harness probes
load none of ``messagefoundry.transports``, ``config``, ``verify``, ``pipeline`` and ``store``,
through the A5 probe and through an error arm that runs the scrub. They do load ``redaction`` and
``secretscrub``, which the scrub needs. :mod:`messagefoundry.verify.model` re-exports the public
scrub names its own import lines list. The private names, at least ``_PLACEHOLDER``, live only
here, and ``verify.model._PLACEHOLDER`` does not exist. The public port probe :func:`port_state` is
defined here, and :mod:`messagefoundry.verify.checks` binds it by import under the same name, so a
test that patches this module's ``port_state`` does not reach the checks;
``verify.checks._port_state`` does not exist.
"""

from __future__ import annotations

import errno
import logging
import re
import socket
import sys
from collections import Counter
from typing import Final

_log = logging.getLogger(__name__)


#: The bound for an arm that quotes a store driver, a socket or the TLS stack rather than a
#: Router/Handler. Those arms printed the whole text before BACKLOG #5395, and the engine's own
#: refusals there, such as the store's Vault revocation remedy, run past ``safe_text``'s 200; the
#: arms that can quote a message (config load, a WiringError included, and dry run, BACKLOG #1779)
#: keep 200.
DRIVER_DETAIL_LIMIT: Final = 2000


#: The placeholder both passes write here: the PHI pass's own, and ``scrub_credentials`` is told to use
#: it. Square brackets rather than ``secretscrub``'s ``<redacted>``, so a sink that renders a pasted
#: detail as HTML cannot read it as a tag and show ``PWD=`` as an empty password.
_PLACEHOLDER: Final = "[redacted]"


def safe_detail_text(text: str, *, limit: int | None = None) -> str:
    """``text`` for a :class:`CheckResult` detail: bounded, then both orders of the PHI and
    credential passes, hiding every fragment either order hid a copy of, then the length bound
    (BACKLOG #5395).

    A verify report is written to JSON and Markdown that an operator pastes into a ticket, so it
    leaves the box. The text a check quotes is a driver's, a config module's or the OS's: a store
    driver can quote its DSN or a ``password=`` / ``PWD=`` pair, and a config module can raise
    anything. :func:`~messagefoundry.redaction.safe_text` is a PHI pass, and on such a text it left
    the DSN password and the ``PWD=`` and ``password=`` values in place
    (``tests/test_verify_detail_redaction.py``). So the text also takes
    :func:`~messagefoundry.secretscrub.scrub_credentials`, the write-time credential vocabulary the
    log filter and wiring's own diagnostics use.

    NEITHER ORDER OF THE TWO PASSES HIDES WHAT THE OTHER DOES, so both run, and a fragment either
    order hid a copy of is hidden in the result. Credentials first: the credential pass read
    ``tk-1,mrn:`` in ``token=tk-1,mrn: MRN7712345`` as the token's value, the PHI pass then found no
    ``mrn:`` label, and the MRN printed. PHI first: the PHI pass takes a label the credential pass
    needs, at least a capitalized pair read as a name (``Login Password=``, ``Svc\\nPassword:``) and an HL7 field run that holds the label
    (``a|b^password= <value>``), and the value printed. The primary result is PHI first, then the
    credential pass over the WHOLE of it, which can only hide more than the PHI pass did; not split at
    the placeholders, which cut ``postgresql://19800505:<pw>@`` in two once the PHI pass had replaced
    the user. Then every whitespace-separated word of that result holding a fragment, a run of word
    characters between placeholders, that either result hid a copy of is replaced whole, at every
    occurrence (:func:`_printed_by_both`), with the residuals that function names. That errs toward
    hiding: a label the other order spelled differently goes with its value.

    The input is cut to :func:`~messagefoundry.redaction.clamp_untrusted`'s window before any pass
    reads it, and its note is kept past the length bound. That note is the only unscanned note the
    detail carries: what the length bound then holds back was scanned, and is counted
    as ``(+N chars)``.

    Not the support bundle's ``redact_log_line``: its long-base64 sweep blanked any 24-character run,
    which is an exception class name such as ``SSLCertVerificationError`` and the segments of a POSIX
    path, the words an operator needs here. This is best-effort, with at least the residuals
    ``secretscrub`` and :mod:`messagefoundry.redaction` state, and the PHI pass can blank a
    capitalized two-word phrase such as ``Program Files``."""
    from messagefoundry.redaction import _DEFAULT_LIMIT, _held_back, clamp_untrusted, redact
    from messagefoundry.secretscrub import scrub_credentials

    bounded = clamp_untrusted(text)
    # clamp_untrusted ends a cut text with "\n" and its note. The note says what no pass read, so it
    # must outlive the length bound below, which would otherwise drop it with the tail.
    head, note = bounded.rsplit("\n", 1) if bounded is not text else (bounded, "")
    phi_first = scrub_credentials(redact(head), placeholder=_PLACEHOLDER)
    credentials_first = redact(scrub_credentials(head, placeholder=_PLACEHOLDER))
    cleaned = _printed_by_both(phi_first, credentials_first, head)
    # Not safe_text: every character of ``cleaned`` was scanned above, but its placeholders can push
    # it past safe_text's work window, whose note would then call scanned characters unscanned. So
    # the PHI pass once more over the whole of it, which the placeholders at most multiply from a
    # bounded head, then safe_text's length bound alone.
    shown = _held_back(redact(cleaned).strip(), _DEFAULT_LIMIT if limit is None else limit)
    return f"{shown} {note}" if note else shown


_WORD_RUN: Final = re.compile(r"\w+")


def _fragments(word: str) -> list[str]:
    """The pieces of ``word`` between placeholders, each cut into its runs of word characters, so a
    value glued to punctuation (``Kv9x7Qz3.``, ``(Kv9x7Qz3)``) is the same fragment as the bare value.
    A piece holding no word character is kept whole."""
    return [
        run
        for piece in word.split(_PLACEHOLDER)
        if piece
        for run in (_WORD_RUN.findall(piece) or [piece])
    ]


def _printed_by_both(primary: str, other: str, source: str) -> str:
    """``primary`` with each word replaced by the placeholder where it holds a fragment that either
    order hid a copy of: printed fewer times by ``primary`` or by ``other`` than ``source`` holds
    it, or printed more often by ``primary`` than by ``other``. Linear: one split of each text and
    counter lookups.

    NOT A SET, AND NOT COUNTS BETWEEN THE ORDERS ALONE (BACKLOG #5395). Against a set of the other
    order's words, a password equal to another word the line prints survived: in ``user svcadmin
    ... Login Password: svcadmin`` the credentials-first order hid the second ``svcadmin`` and
    printed the first, so the word was "printed by both" and both printed. Comparing how often each
    order printed a fragment still kept one each order printed at a different place (BACKLOG #5395
    added item 2): in ``Login Password: Kv9x7Qz3 then token=tk-1,mrn: Kv9x7Qz3`` the PHI-first
    order printed the password and hid the copy after ``mrn:``, the credentials-first order did the
    reverse, and the counts were equal. Placing each fragment back on the source by walking it was
    misled by a placeholder that hid several words (code review of this change). So the test is
    against the source: a fragment either order printed fewer times than the source holds it was
    hidden somewhere by a pass, and it is hidden at EVERY occurrence, wherever it stood. That errs
    toward hiding: the user name goes with the password it equals, and a word the PHI pass took
    from a name goes everywhere it appears. A fragment is a run of word characters
    (:func:`_fragments`), so in ``Login Password: Kv9x7Qz3 retry with Kv9x7Qz3.`` the value glued to
    the full stop counts with the bare one and goes too, and a whole word goes when any run in it
    does.

    Best-effort. Residuals, at least these: a value glued to a word character is a different run,
    so ``xKv9x7Qz3y`` elsewhere on the line prints; and a pass that rewrote a value into a fragment
    the source does not hold is caught only by the count between the orders."""
    in_source = Counter(run for word in source.split() for run in _fragments(word))
    printed = Counter(run for word in other.split() for run in _fragments(word))
    shown = Counter(run for word in primary.split() for run in _fragments(word))
    hidden = {
        run for run, n in shown.items() if n > printed[run] or min(n, printed[run]) < in_source[run]
    }
    return re.sub(
        r"\S+",
        lambda m: _PLACEHOLDER if any(p in hidden for p in _fragments(m[0])) else m[0],
        primary,
    )


def safe_exc_detail(exc: BaseException, *, limit: int | None = None) -> str:
    """``exc`` for a :class:`CheckResult` detail: its type, then its text through
    :func:`safe_detail_text`. A ``UnicodeError`` takes :func:`~messagefoundry.redaction.safe_exc`
    whole, which builds the text from its attributes and quotes no character of the message; an
    exception holding one renders as ``codec_safe_str``'s fixed note. ``limit`` as
    :func:`safe_detail_text`, on both branches."""
    from messagefoundry.redaction import codec_safe_str, safe_exc

    if isinstance(exc, UnicodeError):
        return safe_exc(exc) if limit is None else safe_exc(exc, limit=limit)
    message = safe_detail_text(codec_safe_str(exc), limit=limit)
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__


def safe_exc_text(exc: BaseException, *, before: str = "") -> str:
    """``before`` then ``exc``'s text, through :func:`safe_detail_text` together and bounded at
    :data:`DRIVER_DETAIL_LIMIT`, for an arm that quotes an exception with no type name, such as the
    engine's own refusals (BACKLOG #5395 added item 1). Those quote paths, hosts, and an IdP's or a
    secret provider's text, which can carry a credential. ``before`` is scanned with the exception
    because an arm's own words can quote the same path."""
    from messagefoundry.redaction import codec_safe_str

    return safe_detail_text(before + codec_safe_str(exc), limit=DRIVER_DETAIL_LIMIT)


# Errors that mean IPv6 is not enabled here, not that the port is held. The engine's MLLP listener
# skips a family on the same two bind errors (transports/mllp.py, _FAMILY_NOT_ENABLED).
_FAMILY_NOT_ENABLED = frozenset({errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT})


def _not_probed(exc: OSError) -> str:
    """The ``could not be probed`` state, its OS text through :func:`safe_detail_text` as every
    exception this module quotes into a report is."""
    from messagefoundry.redaction import codec_safe_str

    reason = safe_detail_text(exc.strerror or codec_safe_str(exc), limit=DRIVER_DETAIL_LIMIT)
    return f"could not be probed ({reason})"


def port_state(port: object) -> str:
    """Report whether a listener could take ``port``: ``free``, ``in use/bound``, ``in use/bound or
    reserved`` (Windows), ``not bindable by this user``, ``could not be probed``, or ``invalid
    port``.

    The probe binds the IPv4 wildcard and the IPv6 wildcard (BACKLOG #5389). A wildcard bind
    conflicts with a listener on any address of its family, so a loopback, one-interface or
    all-interface listener reads as held, which is conservative for an engine bound to one address.
    The IPv6 probe is dual-stack (``IPV6_V6ONLY`` off) because on Windows a dual-stack listener on
    ``::`` lets an IPv4 bind and an IPv6-only bind succeed beside it, exclusive or not; only a
    dual-stack bind sees it. Only IPv6 is skipped when its family is not enabled; IPv4 always has
    to bind for the port to read free.

    On Windows the probe sets ``SO_EXCLUSIVEADDRUSE``, never ``SO_REUSEADDR``: there,
    ``SO_REUSEADDR`` lets a bind share a port another socket holds, which read a held port as free.
    On Linux ``SO_REUSEADDR`` only reuses a TIME_WAIT port, as the engine's own listener does, and a
    listening socket still refuses it. Elsewhere (BSD, macOS) it lets a wildcard bind succeed beside
    a listener on one address, so the probe sets neither, and a TIME_WAIT port may read held there.

    Of the bind errors that are not a permission refusal, only ``EADDRINUSE`` reads as in use. Any
    other, at least an IPv4 family error, is ``could not be probed``, so a probe that failed for
    another reason does not read as a held port (BACKLOG #5389). A permission refusal keeps its own
    two states above. The harness A5 probe calls this function too, so the two cannot drift apart.

    The answer is for the account running verify, which may not be the service account. A free
    result says nothing about an external firewall.
    """
    # bool is an int subclass, and True would otherwise probe port 1.
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return "invalid port (must be an integer from 1 to 65535)"
    # The wildcard is bound and closed, never listened on, so nothing is exposed.
    for family, wildcard in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):  # nosec B104
        ipv6 = family == socket.AF_INET6
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            if ipv6 and exc.errno in _FAMILY_NOT_ENABLED:
                _log.debug("port probe skipped IPv6, its family is not enabled: %s", exc)
                continue
            # Out of descriptors, or a sandbox denying socket(): nothing was probed, so not free.
            return _not_probed(exc)
        try:
            if sys.platform == "win32":
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            elif sys.platform.startswith("linux"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if ipv6:
                # Only a host with no dual-stack sockets refuses this, and no dual-stack listener can
                # exist there: the IPv4 probe covers IPv4, and an IPv6-only bind sees IPv6 listeners.
                try:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except OSError as exc:
                    _log.debug("port probe kept the IPv6 socket's default IPV6_V6ONLY: %s", exc)
            s.bind((wildcard, port))
        except PermissionError:
            if sys.platform == "win32":
                # WSAEACCES: another socket holds the port exclusively, or the OS reserves it.
                return "in use/bound or reserved"
            # POSIX checks privilege before conflict, so this cannot tell held from free.
            return "not bindable by this user (privileged port; it may also be in use)"
        except OSError as exc:
            if ipv6 and exc.errno in _FAMILY_NOT_ENABLED:
                _log.debug("port probe skipped IPv6, its family is not enabled: %s", exc)
                continue
            if exc.errno == errno.EADDRINUSE:  # WSAEADDRINUSE on Windows, where the two are equal
                return "in use/bound"
            return _not_probed(exc)
        finally:
            s.close()
    return "free"
