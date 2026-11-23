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

import urllib.parse
from collections.abc import Sequence

from messagefoundry.urlscreen import (
    MAX_OUTBOUND_URL_LEN,
    UNCACHED_URLSPLIT,
    refuse_url_credentials,
    unsendable_request_target,
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

    The one comparison the build and every send of the webhook and the SMTP relay apply, and the
    one the serve gate's security-channel check reads (BACKLOG #5088). Hosts compare without case.
    The webhook's callers percent-decode the host and each entry before they call it; the SMTP
    relay's and the serve gate's do not, so an entry holding a '%' can name a different host in
    ``webhook_allowed_hosts`` than in ``smtp_allowed_hosts``.

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

    The host is judged as urllib dials it: percent-decoded, as ``urllib.request.Request`` decodes
    it before ``http.client`` validates it. A decoded host ``http.client`` could not send (a
    space, a control character or a non-ASCII character, written as ``%20``, ``%0d%0a`` or
    ``%7f`` say), or one holding ``/``, ``?`` or a backslash, is refused without naming it, and
    the allowlist judges the decoded host, so
    ``hooks%2Eexample`` is judged as the ``hooks.example`` it dials. Each allowlist entry is
    decoded the same way before the comparison.

    Names the host, never the URL: the path carries the webhook's token (BACKLOG #1793)."""
    # urlsplit lower-cases the host; the decoded form is lower-cased again for an encoded capital.
    host = urllib.parse.unquote(UNCACHED_URLSPLIT(url).hostname or "").lower()
    if not host:
        # Whatever the allowlist: the build's revocation guard refuses a hostless URL in every
        # posture too, so this keeps settings load from passing one the build refuses.
        raise ValueError(f"{_SETTING} names no host")
    # '/', '?' and a backslash too: no host holds one, and a decoded one means part of the path, the
    # token perhaps, was written into the authority, where the allowlist refusal and the
    # revocation guard's text would name it.
    if unsendable_request_target(host) or any(ch in host for ch in "/?\\"):
        raise ValueError(
            f"{_SETTING} has a space, control character, non-ASCII character, '#', '/', '?' or "
            "'\\' in its host, written as is or percent-encoded, which no host holds once urllib "
            "decodes it; the value is not repeated here, since its path can carry the webhook's "
            "token"
        )
    # Each entry is decoded too, so an entry written as the URL spells the host, such as an IPv6
    # zone's "%25", names the host urllib dials, as it did before the host was decoded.
    if not alert_host_allowed(host, [urllib.parse.unquote(h) for h in allowed_hosts]):
        raise ValueError(f"{_SETTING} host {host!r} is not in [alerts].webhook_allowed_hosts")


def refuse_unbuildable_webhook_url(url: str, allowed_hosts: Sequence[str]) -> str:
    """Refuse a webhook URL on the checks that read no secret, no posture and log nothing, and
    return the value it judged: ``url`` with :data:`_STRIPPED_BY_BOTH` stripped from each end. A
    caller that dials the URL dials that value, so the end whitespace stripped here reaches no
    later reader.

    No refusal here prints the URL (BACKLOG #1793): a Slack or Teams hook carries its secret in the
    PATH, and a userinfo URL carries a password. The userinfo screen runs before any check that
    names a part of the URL, and it raises outside urlsplit's own handler, whose text quotes the
    netloc. At least these are refused, in this order:

    * whitespace left at either end after :data:`_STRIPPED_BY_BOTH` is stripped, and a URL
      ``http.client`` could not send (``unsendable_request_target``, judged as sent): a space, a
      control character or a non-ASCII character inside it. ``http.client`` raises ``InvalidURL``
      quoting the path for the first two, and that text would reach the log at every POST;
      ``urlsplit`` also drops a tab, CR or LF, so the scheme it read need not be the one dialled;
    * a credential in the URL, or a URL that does not parse (``refuse_url_credentials``);
    * any scheme but https. A plaintext http target is refused with no escape, in every posture
      (vault BACKLOG #3533 item 5, ASVS 12.2.1): the URL can carry the hop's credential as a path
      token;
    * a URL that names no host, and a host off a non-empty ``webhook_allowed_hosts`` (BACKLOG
      #5088), after the scheme, so an http URL is never sent to fix an entry it cannot use;
    * a URL over the outbound length bound (ASVS 4.2.5). The URL is operator config and the
      sole header is a fixed ``Content-Type``, so nothing longer is added before the wire.
    """
    candidate = url.strip(_STRIPPED_BY_BOTH)
    if candidate != candidate.strip():
        raise ValueError(
            f"{_SETTING} starts or ends with a non-ASCII space; the value is not repeated here, "
            "since its path can carry the webhook's token"
        )
    if unsendable_request_target(candidate, sent_as_is=True):
        raise ValueError(
            f"{_SETTING} holds a space, a control character or a non-ASCII character, which "
            "http.client cannot send; the value is not repeated here, since its path can carry "
            "the webhook's token. Percent-encode the character, or write the host in punycode"
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
