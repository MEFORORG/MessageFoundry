# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``[alerts]`` webhook URL checks that need no posture, stated once (vault BACKLOG #3533 item 14).

:func:`refuse_unbuildable_webhook_url` is called by at least the ``AlertsSettings`` load check,
``notifier_from_settings`` before it reads the SMTP password, ``WebhookTransport``'s build and its
every POST, so settings load and the build refuse the same URLs on these checks. The revocation
guard, which reads the posture, stays in ``pipeline/alert_sinks.py``.

Imports no ``transports`` module: that package's ``__init__`` registers every connector, and
settings load would pay for it.
"""

from __future__ import annotations

from collections.abc import Sequence

from messagefoundry.controlchars import has_control_char, has_lone_surrogate
from messagefoundry.urlscreen import (
    MAX_OUTBOUND_URL_LEN,
    UNCACHED_URLSPLIT,
    refuse_url_credentials,
)

__all__ = [
    "alert_host_allowed",
    "refuse_unbuildable_webhook_url",
]

#: What is stripped from each end before the checks: the ASCII whitespace ``str.strip()`` removes.
#: ``urlsplit`` strips C0 controls and space from the front only, and drops every tab, CR and LF;
#: urllib's dial strips what ``str.strip()`` strips from both ends, which also takes non-ASCII
#: whitespace. A value that still has whitespace at either end after this strip is refused, since
#: urlsplit would keep it in the host it judges while the dial removed it.
_STRIPPED_BY_BOTH = "".join(c for c in map(chr, range(0x21)) if c.isspace())

_SETTING = "[alerts].webhook_url"


def alert_host_allowed(host: str, allowed_hosts: Sequence[str]) -> bool:
    """Whether the ``[alerts]`` egress allowlist ``allowed_hosts`` admits ``host``.

    The one test the build and every send of the webhook and the SMTP relay apply, and the one the
    serve gate's security-channel check reads (BACKLOG #5088), so no two of them can disagree on
    which host is listed. Hosts compare without case.

    An empty allowlist admits every host: that is the settings' documented ``[]`` = any, and an
    environment value that splits to no host, such as ``""`` or ``","``, yields it too. A non-empty
    one admits only a host it lists, and an empty host is never listed, so ``[""]``, which names no
    host, refuses every one rather than matching a URL with no host."""
    if not allowed_hosts:
        return True
    candidate = host.lower()
    return bool(candidate) and candidate in (h.lower() for h in allowed_hosts)


def _refuse_hostless_or_off_allowlist(url: str, allowed_hosts: Sequence[str]) -> None:
    """Refuse a webhook URL that names no host, or whose host ``[alerts].webhook_allowed_hosts``
    does not admit. Private: ``url`` must already have passed ``refuse_url_credentials``, whose
    screen keeps urlsplit's own netloc-quoting ``ValueError`` from being raised here.

    Names the host, never the URL: the path carries the webhook's token (BACKLOG #1793)."""
    host = UNCACHED_URLSPLIT(url).hostname or ""  # urlsplit lower-cases the host
    if not host:
        # Whatever the allowlist: the build's revocation guard refuses a hostless URL in every
        # posture too, so this keeps settings load from passing one the build refuses.
        raise ValueError(f"{_SETTING} names no host")
    if not alert_host_allowed(host, allowed_hosts):
        raise ValueError(f"{_SETTING} host {host!r} is not in [alerts].webhook_allowed_hosts")


def refuse_unbuildable_webhook_url(url: str, allowed_hosts: Sequence[str]) -> str:
    """Refuse a webhook URL on the checks that read no secret, no posture and log nothing, and
    return the value it judged: ``url`` with :data:`_STRIPPED_BY_BOTH` stripped from each end. A
    caller that dials the URL dials that value, so no later reader sees other whitespace.

    No refusal here prints the URL (BACKLOG #1793): a Slack or Teams hook carries its secret in the
    PATH, and a userinfo URL carries a password. The userinfo screen runs before any check that
    names a part of the URL, and it raises outside urlsplit's own handler, whose text quotes the
    netloc. At least these are refused, in this order:

    * whitespace left at either end, and a control character or lone surrogate inside the value,
      after :data:`_STRIPPED_BY_BOTH` is
      stripped from each end (``urlsplit`` drops a tab, CR or LF, so the scheme it read need not
      be the one urllib dials);
    * a credential in the URL, or a URL that does not parse (``refuse_url_credentials``);
    * any scheme but https. A plaintext http target is refused with no escape, in every posture
      (vault BACKLOG #3533 item 5, ASVS 12.2.1): the URL can carry the hop's credential as a path
      token;
    * a URL that names no host, and a host off a non-empty ``webhook_allowed_hosts`` (BACKLOG
      #5088), after the scheme, so an http URL is never sent to fix an entry it cannot use;
    * a URL over the outbound length bound (ASVS 4.2.5). Construction-only is enough: the URL is
      operator config and the sole header is a fixed ``Content-Type``.
    """
    candidate = url.strip(_STRIPPED_BY_BOTH)
    if candidate != candidate.strip():
        raise ValueError(
            f"{_SETTING} starts or ends with a non-ASCII space; the value is not repeated here, "
            "since its path can carry the webhook's token"
        )
    if has_control_char(candidate) or has_lone_surrogate(candidate):
        raise ValueError(
            f"{_SETTING} holds a control character or an unpaired surrogate; the value is not "
            "repeated here, since its path can carry the webhook's token"
        )
    refuse_url_credentials(candidate, _SETTING, use="the path token the webhook service issues")
    scheme = UNCACHED_URLSPLIT(candidate).scheme  # urlsplit lower-cases the scheme
    if scheme == "http":
        raise ValueError(
            f"{_SETTING} over cleartext http would send the URL, and any path token in it, in "
            "clear; refused, with no escape, in every posture — use https"
        )
    if scheme != "https":
        # The scheme is not named: in a value with no "//", such as "svc:PW@host/x", it is text
        # the operator may not have meant as one.
        raise ValueError(f"{_SETTING} must be https")
    _refuse_hostless_or_off_allowlist(candidate, allowed_hosts)
    if len(candidate) > MAX_OUTBOUND_URL_LEN:
        raise ValueError(
            f"{_SETTING} is {len(candidate)} chars, over the {MAX_OUTBOUND_URL_LEN}-char limit"
        )
    return candidate
