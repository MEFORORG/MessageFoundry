# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline uploaded-logs /ui routes (BACKLOG #125/#126, ADR 0134).

Upload / list / browse / resend / delete over the engine's uploaded-logs CoreHandlers (seam v7). The
console never touches the filesystem or the store directly — it calls the audited JSON handlers by
reference and re-asserts the equivalent permission/step-up via ``require_ui*``. The browse GET (which
decrypts PHI) is step-up-gated + registered as an UNLOCK action (like content search); delete is a
step-up, body-less, auto-retryable POST behind a confirm step; upload is a step-up'd same-origin
multipart POST whose re-auth continuation is the UNLOCK form page at ``/ui/uploaded-logs/upload-form``
(BACKLOG #1739). Resend is a step-up POST behind a body-less confirm step, its message index and target
inbound carried in the query so the confirm URL is a valid re-auth continuation (BACKLOG #1227). The
confirm GET is step-up-gated too (BACKLOG #1822); both map a stale window back to that URL.

THE UPLOAD SENTENCE USED TO ARGUE THE OPPOSITE CONCLUSION, and it is quoted and answered here rather
than simply deleted, because it is the argument anyone re-opening this question will reach for again.
It read: upload takes "no step-up — a body-carrying POST can't survive the re-auth redirect, and
browsing PHI is the gated surface". The first premise is TRUE and the conclusion does not follow from
it, which is why a deletion would leave the next reader to re-derive it. Losing the body across
the redirect is the DESIGNED behaviour of the L0c unlock primitive, not a defect it must route around:
``POST /ui/users`` loses a typed PASSWORD exactly this way and is step-up-gated regardless — the
operator lands back on ``/ui/users/new`` inside a fresh window and retypes it. Here they re-pick the
file. The second premise is wrong on its own terms: upload WRITES PHI at rest, so gating the read
surface does not cover it. Its JSON twin ``POST /uploads`` has been ``require_step_up`` throughout,
and that is the parity this closes.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import (
    UploadedFileInfo,
    UploadedMessageSearchRequest,
    UploadResendRequest,
)
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.service import STEP_UP_ACTION_UPLOAD_RESEND

from .. import pages
from .._auth import (
    assert_same_origin,
    register_ui_action,
    require_ui,
    require_ui_step_up,
    require_ui_step_up_action,
)
from ..pages._common import _seg
from ._common import _form_pairs, for_echo, posted_needle

# The browse GET decrypts PHI (step-up), so register it as an UNLOCK form — a stale step-up 303s to
# /ui/reauth and GET-redirects back to the browse page. The PHI-shaped filter now travels in the POST
# body of .../filter (BACKLOG #1184) and so cannot cross the redirect at all. The delete POST is
# body-less + step-up, so it may be auto-retried after re-auth. NONE of the three body-carrying POSTs
# here — filter, upload, resend — is registered; each instead maps its ``reauth_next`` to a GET page
# that IS registered: filter to the browse GET it was carved out of, upload to the form below, resend
# to the confirm page below. That is the same shape messages' edit-resend uses. The re-auth for the
# confirm page mints the upload-resend grant (vault BACKLOG #2625), which the resend POST spends.
register_ui_action(
    r"^/ui/uploaded-logs/file/[^/?#]+$",
    Permission.FILES_BROWSE,
    auto_retry=False,
    unlock=True,
    label="View an uploaded file",
)
register_ui_action(
    r"^/ui/uploaded-logs/file/[^/?#]+/delete$",
    Permission.FILES_DELETE,
    label="Delete an uploaded file",
)
# The resend confirm page (BACKLOG #1227). QUERY-TOLERANT ON PURPOSE — see ``_auth.is_unlock_action``
# for what that trailing group widens and what still bounds it. It has to be:
# ``reauth_next`` puts ``?index=N&to=NAME`` into ``next``, and ``lookup_ui_action`` /
# ``is_unlock_action`` fullmatch the RAW value, so a path-only pattern matches nothing and dead-ends
# the whole flow at /ui with both parameters silently gone. ``auto_retry=False`` because it is a GET;
# ``unlock=True`` so re-auth 303-GET-redirects back here with the parameters intact.
# KEEP THE OPTIONAL GROUP rather than pinning ``\?index=\d+&to=...``: this form also fullmatches the
# bare route TEMPLATE, which is what keeps the R1 coverage guard in test_webui_monitoring.py able to see this
# entry. A stricter pattern would not match the template and would make that guard silently vacuous
# here — green, and covering nothing.
register_ui_action(
    r"^/ui/uploaded-logs/file/[^/?#]+/resend-confirm(\?[^#]*)?$",
    Permission.FILES_BROWSE,
    auto_retry=False,
    unlock=True,
    action=STEP_UP_ACTION_UPLOAD_RESEND,
    label="Open the uploaded-message resend confirmation",
)
# The upload FORM page (BACKLOG #1739), the unlock continuation for the body-carrying upload POST.
#
# WHY THE FORM SITS ON ITS OWN PATH RATHER THAN ON THE POST'S. It was the GET half of
# ``/ui/uploaded-logs/upload``, and registering that path here reds
# ``test_write_action_method_matches_its_continuation`` — an unlock entry is 303-GET-redirected to,
# so one that also served POST would be an open-POST gadget. Something had to move.
#
# THIS SPLITS THE OPPOSITE WAY FROM EVERY EARLIER SPLIT OF AN EXISTING PAIR, so the divergence is
# deliberate rather than an oversight. At least two went the other way — ``/ui/messages/search`` kept
# the form and gave the POST ``/ui/messages/search/run`` (routes/search.py), and the browse GET below
# kept its path while its criteria POST became ``.../filter`` (BACKLOG #1184). Both moved the POST.
#
# Here the POST is the half pinned from OUTSIDE this package: ``api/app.py``'s ``_UPLOAD_BODY_PATHS``
# matches ``scope["path"]`` against an EXACT frozenset to lift the 1 MiB request-body cap, so
# moving the POST means an engine-package edit or large uploads start failing at the cap. That is the
# whole of the reason. (The doc-drift tests naming this path are substring checks and would have
# tolerated either spelling — do not cite them as a constraint; the frozenset is the only hard pin.)
register_ui_action(
    r"^/ui/uploaded-logs/upload-form$",
    Permission.FILES_UPLOAD,
    auto_retry=False,
    unlock=True,
    label="Open the file upload form",
)

_log = logging.getLogger(__name__)

#: Where a REFUSED mutation lands: the uploaded-logs LIST page, never the detail page the POST came
#: from. Two properties make it the only correct target, and both are load-bearing.
#:
#: 1. The detail GET is step-up-gated AND registered as an unlock action above, so once the step-up
#:    window goes stale it 303s to /ui/reauth — which deliberately does NOT carry the query string
#:    back (the browse filter is a GET query that can hold PHI-shaped search terms). A flag aimed at
#:    the detail page is therefore DROPPED in exactly that window, landing the operator on a plain
#:    detail page: byte-identical to what a SUCCESSFUL resend produces. The list route is a plain
#:    ``require_ui(FILES_BROWSE)`` — no step-up, and no registered action — so the flag survives.
#: 2. Success never goes here. A resend's success 303s to the detail page and a delete's success 303s
#:    to the bare list URL, so neither can be confused with a flagged failure.
#:
#: A browse the store cipher refuses lands here too (BACKLOG #1169). It is a read, not a mutation, and
#: it cannot land on the detail page for a simpler reason: that page is the refused resource, so it
#: would answer 423 again even inside a fresh step-up window.
_FAILED_TARGET = "/ui/uploaded-logs"

#: The outcome codes the LIST page accepts (console convention: ``?e=<code>``, allow-listed and mapped
#: to fixed text, exactly as the login page does). Each is a BOOLEAN FLAG naming one cause, nothing
#: more. Every cause below is caller-influenced — the target inbound name and the message index come
#: from the resend form body, the file id from the path, and ``exc.detail`` quotes them back — so
#: reflecting any of it into the query string would put attacker-supplied text in the URL, the referrer
#: chain, every proxy log, and finally the rendered HTML. A fixed code cannot carry a payload.
RESEND_FAILED_CODE = "resend_failed"
RESEND_DENIED_CODE = "resend_denied"
RESEND_STOPPED_CODE = "resend_stopped"
RESEND_REFUSED_CODE = "resend_refused"
RESEND_LOCKED_CODE = "resend_locked"
DELETE_FAILED_CODE = "delete_failed"
DELETE_LOCKED_CODE = "delete_locked"
BROWSE_LOCKED_CODE = "browse_locked"
RESEND_DAMAGED_CODE = "resend_damaged"
DELETE_DAMAGED_CODE = "delete_damaged"
BROWSE_DAMAGED_CODE = "browse_damaged"
RESEND_ACCESS_CODE = "resend_access_refused"
DELETE_ACCESS_CODE = "delete_access_refused"
DELETE_INCOMPLETE_CODE = "delete_incomplete"
BROWSE_ACCESS_CODE = "browse_access_refused"
BROWSE_HOP_REFUSED_CODE = "browse_hop_refused"
BROWSE_THROTTLED_CODE = "browse_throttled"
UPLOADS_UNAVAILABLE_CODE = "uploads_unavailable"
KEY_SERVICE_BUSY_CODE = "key_service_busy"
STORAGE_UNREACHABLE_CODE = "storage_unreachable"
DELETE_UNCONFIRMED_CODE = "delete_unconfirmed"

#: The status the engine answers when the store cipher refuses an uploaded file (BACKLOG #1169).
_LOCKED_STATUS = status.HTTP_423_LOCKED
#: The status every uploaded-logs handler answers when no uploads store is configured. Browse runs
#: its PHI-read hop and pacing checks before the store check, so it can answer 403 or 429 first.
_UNAVAILABLE_STATUS = status.HTTP_503_SERVICE_UNAVAILABLE

#: The fixed text each code maps to. The 404 one names the three causes the operator can act on WITHOUT
#: distinguishing an owner denial (ASVS 8.2.2) from an absent file — the engine answers 404 for both
#: deliberately, so this one sentence has to cover both and must not split them.
RESEND_FAILED_NOTICE = (
    "That resend did not run — nothing was injected. The file, the message number or the target "
    "inbound connection was not found. Check them and try again."
)
RESEND_DENIED_NOTICE = (
    "That resend did not run — nothing was injected. You are not authorized to inject into that "
    "inbound connection."
)
RESEND_STOPPED_NOTICE = (
    "That resend did not run — nothing was injected. The target inbound connection is registered but "
    "not running. Start it, then try again."
)
RESEND_REFUSED_NOTICE = (
    "That resend did not run — nothing was injected. The target inbound connection would refuse "
    "that message from a sender. For example, it may be larger than the connection accepts, or not "
    "match the connection's declared content type."
)
DELETE_FAILED_NOTICE = (
    "That delete did not run — nothing was removed. The file was not found. It may already be gone."
)

#: The cause and the fix behind every 423 (BACKLOG #1169, owner ruling 2026-09-23). The fix is
#: CONDITIONAL, as the engine's own 423 text is. The engine gives the same answer for a file under a
#: key that is no longer configured, which ``rotate-key`` does not fix, and for a plaintext file
#: planted behind a sealed sidecar, which ``rotate-key`` would seal for good. So the notice names the
#: common case and its fix without claiming either is the only one. The store's opt-out for unmarked
#: values would also let the file through; it is a loosening, so no notice here may point at it.
#: A damaged file's 423 (BACKLOG #5388) gets the notices below it instead, because no key and no
#: rotate-key repairs it, and a keyless store has no key to name at all. So does the 423 of a file
#: the filesystem refused the engine (BACKLOG #5388 added item 2), which no key concerns either.
_LOCKED_CAUSE = (
    "The engine cannot read the file under the store's encryption key, so it refuses it. A file "
    "stored as plaintext before the key was turned on stays refused until an administrator seals "
    "it. They seal it by running 'messagefoundry rotate-key' with the engine stopped."
)
_BROWSE_LEAD = "That file could not be opened."
_RESEND_LEAD = "That resend did not run — nothing was injected."
_DELETE_LEAD = "That delete did not run — nothing was removed."
BROWSE_LOCKED_NOTICE = f"{_BROWSE_LEAD} {_LOCKED_CAUSE}"
RESEND_LOCKED_NOTICE = f"{_RESEND_LEAD} {_LOCKED_CAUSE}"
DELETE_LOCKED_NOTICE = f"{_DELETE_LEAD} {_LOCKED_CAUSE}"

#: Why a damaged file is refused, with no command named, since none repairs it. It promises
#: no removal, as the engine's text does not: some damaged files are refused by the delete too.
_DAMAGED_CAUSE = (
    "The engine found the file damaged, so it does not read or serve it. No encryption key and no "
    "command repairs it."
)
#: The engine's 423 does not say which damage it found, and some damaged files are ones
#: ``rotate-key`` reports as possibly holding a value under the prior key: a sidecar larger than a
#: sidecar can be, not UTF-8, or plaintext too long to seal (BACKLOG #5387). So every damaged notice
#: takes that command's stance, that the prior key stays until such a sidecar is fixed or
#: deliberately removed. It names no command, since no damaged notice does.
_PRIOR_KEY = (
    "Where the store has had an encryption key, at least a damaged file whose record of its "
    "details is larger than the engine reads, is not UTF-8 text, or is plaintext too long to seal "
    "may still hold a value under a prior key. An administrator should not retire a prior key "
    "until each such file is fixed, for example by restoring it from a backup, or is deliberately "
    "removed."
)
_MAY_DELETE = "The file may be deleted, but the engine may refuse that too."
BROWSE_DAMAGED_NOTICE = f"{_BROWSE_LEAD} {_DAMAGED_CAUSE} {_PRIOR_KEY} {_MAY_DELETE}"
RESEND_DAMAGED_NOTICE = f"{_RESEND_LEAD} {_DAMAGED_CAUSE} {_PRIOR_KEY} {_MAY_DELETE}"
#: A refused delete is not answered with advice to delete. The retention prune removes only some
#: damaged files, by their age on disk, so the notice promises no removal: at least a sidecar that
#: is a link or not a regular file is skipped by the prune, and a body that is a directory is one
#: its unlink refuses (BACKLOG #5388 added item 1 follow-up; docs/PHI.md section 3).
DELETE_DAMAGED_NOTICE = (
    f"{_DELETE_LEAD} {_DAMAGED_CAUSE} {_PRIOR_KEY} Deleting the file again is refused the same way. "
    "Where uploaded-file retention is on, the engine removes some damaged files once they are "
    "old enough on disk, but not every one. At least a file that is a link or is not a regular "
    "file, or whose body is a folder, stays until an administrator removes it on the server."
)

#: Why a file the filesystem refused the engine is refused (BACKLOG #5388 added item 2): at least a
#: permission or ACL the engine lacks, and on Windows a file another program holds open. The file
#: is not known to be damaged, so no notice here invites a delete, and none names a key.
_DENIED_CAUSE = (
    "The engine was refused access to the file on the server, for example by the file's "
    "permissions or because another program holds it open. The file is not known to be damaged."
)
_TRY_AGAIN = "Once an administrator fixes that on the server, try again."
BROWSE_ACCESS_NOTICE = f"{_BROWSE_LEAD} {_DENIED_CAUSE} {_TRY_AGAIN}"
RESEND_ACCESS_NOTICE = f"{_RESEND_LEAD} {_DENIED_CAUSE} {_TRY_AGAIN}"
DELETE_ACCESS_NOTICE = f"{_DELETE_LEAD} {_DENIED_CAUSE} {_TRY_AGAIN}"

#: 409 on a delete is one the engine could not finish (BACKLOG #5388 added item 3): the file was in
#: use on the server, with nothing removed, or its content went and its record stayed, so it is
#: still listed. One text serves both, so it claims neither, and it invites the retry that
#: finishes either.
DELETE_INCOMPLETE_NOTICE = (
    "That delete did not finish. The file was in use on the server, or part of it could not be "
    "removed, so some of it may already be gone and it may still be listed. Try deleting it "
    "again. If that keeps failing, an administrator should check the file on the server."
)

#: Three more engine answers the routes used to let escape as JSON (BACKLOG #1169, PR 1506
#: follow-up A). Each is this module's own text. The engine's detail for each names config keys and
#: posture internals, and none of it is reflected here, for the same reason as every notice above.
#:
#: 403 on a browse is the PHI-read hop guard (``enforce_phi_read_hop``). The owner check answers 404,
#: never 403, so this notice cannot disclose that someone else's file exists.
BROWSE_HOP_REFUSED_NOTICE = (
    "That file could not be opened. The engine does not send patient data over this connection, "
    "because the connection to the engine is not proven secure. An administrator must secure the "
    "engine's API with TLS, or declare the proxy that handles TLS in front of it."
)
#: 429 on a browse is the PHI-read limiter. It has a per-user budget and an optional global one, and
#: both are counted over a sliding window whose length a site configures. So the notice blames no
#: one and names no exact wait. The Retry-After header is not quoted either: it is engine text, and
#: the redirect drops it anyway.
BROWSE_THROTTLED_NOTICE = (
    "That file could not be opened. The engine limits how often patient data can be read, and "
    "that limit has been reached for now. Wait a while, then try again."
)
#: 503 is the engine's answer on every uploaded-logs handler when no uploads directory is set. The
#: list page answers it too, and renders this notice itself, so the code needs no banner entry. The
#: text claims no refused action, because the list page shows it to an operator who tried none.
UPLOADS_UNAVAILABLE_NOTICE = (
    "Uploaded logs are not available on this engine. No uploaded file can be opened, resent or "
    "removed until an administrator sets an uploads directory in the engine's store settings."
)

#: 503 WITH ``Retry-After`` is the engine's other 503 on a by-id route and on an upload: the store
#: cipher's key service gave no verdict on the file, so nothing was read, stored or removed
#: (BACKLOG #3734). The no-store 503 above carries no ``Retry-After``, which is how the two are told
#: apart. One text serves browse, resend and delete, so it names no single action.
KEY_SERVICE_BUSY_NOTICE = (
    "That request did not complete, and nothing was opened, injected or removed. The service that "
    "holds the store's encryption key could not complete it. Try again in a moment. If it keeps "
    "happening, an administrator should check that service."
)

#: 503 with ``Retry-After`` and ``storage_unreachable`` set: the uploads directory, or the share it
#: is on, could not be reached, so nothing was opened, injected or removed (BACKLOG #5388 added item
#: 3). One text serves browse, resend and delete, so it names no single action.
STORAGE_UNREACHABLE_NOTICE = (
    "That request did not complete, and nothing was opened, injected or removed. The engine could "
    "not reach the storage that holds uploaded files. Try again in a moment. If it keeps "
    "happening, an administrator should check the uploads folder on the server."
)

#: 503 with ``outcome_unconfirmed`` set: a delete met the storage going away at the body's unlink,
#: so whether the content was removed is not known (BACKLOG #5388 added item 3). It claims
#: neither a removal nor its absence.
DELETE_UNCONFIRMED_NOTICE = (
    "That delete could not be confirmed. The engine lost the storage that holds uploaded files "
    "while it was deleting, so the file's content may or may not be gone. Try the delete again "
    "once the storage is back. If it keeps happening, an administrator should check the uploads "
    "folder on the server."
)

#: The allow-list itself: an EXACT-match lookup from code to fixed module text. ``e`` is compared, never
#: rendered — an unrecognized value maps to no banner at all rather than being echoed.
_LIST_NOTICES: dict[str, str] = {
    RESEND_FAILED_CODE: RESEND_FAILED_NOTICE,
    RESEND_DENIED_CODE: RESEND_DENIED_NOTICE,
    RESEND_STOPPED_CODE: RESEND_STOPPED_NOTICE,
    RESEND_REFUSED_CODE: RESEND_REFUSED_NOTICE,
    RESEND_LOCKED_CODE: RESEND_LOCKED_NOTICE,
    DELETE_FAILED_CODE: DELETE_FAILED_NOTICE,
    DELETE_LOCKED_CODE: DELETE_LOCKED_NOTICE,
    BROWSE_LOCKED_CODE: BROWSE_LOCKED_NOTICE,
    RESEND_DAMAGED_CODE: RESEND_DAMAGED_NOTICE,
    DELETE_DAMAGED_CODE: DELETE_DAMAGED_NOTICE,
    BROWSE_DAMAGED_CODE: BROWSE_DAMAGED_NOTICE,
    RESEND_ACCESS_CODE: RESEND_ACCESS_NOTICE,
    DELETE_ACCESS_CODE: DELETE_ACCESS_NOTICE,
    DELETE_INCOMPLETE_CODE: DELETE_INCOMPLETE_NOTICE,
    BROWSE_ACCESS_CODE: BROWSE_ACCESS_NOTICE,
    BROWSE_HOP_REFUSED_CODE: BROWSE_HOP_REFUSED_NOTICE,
    BROWSE_THROTTLED_CODE: BROWSE_THROTTLED_NOTICE,
    KEY_SERVICE_BUSY_CODE: KEY_SERVICE_BUSY_NOTICE,
    STORAGE_UNREACHABLE_CODE: STORAGE_UNREACHABLE_NOTICE,
    DELETE_UNCONFIRMED_CODE: DELETE_UNCONFIRMED_NOTICE,
    # UPLOADS_UNAVAILABLE_CODE is deliberately absent. With no uploads store the list page answers
    # 503 and renders UPLOADS_UNAVAILABLE_NOTICE without reading ``e``. A listing that loads proves
    # the store is back, so a banner saying it is missing would be false there.
}

#: Which code each refused-resend status becomes. The engine distinguishes a denied TARGET channel
#: (403) from a registered-but-stopped inbound (409) from a not-found file/inbound/index (404), and
#: each is separately actionable — collapsing them would tell the operator something untrue for two of
#: the three. Later causes joined the same way: the target's own ingress guards, and a file the store
#: cipher refuses. Anything outside this map is not a refusal this route knows how to explain, so it is
#: re-raised rather than reported as one of these.
_RESEND_CODES: dict[int, str] = {
    403: RESEND_DENIED_CODE,
    404: RESEND_FAILED_CODE,
    409: RESEND_STOPPED_CODE,
    # BACKLOG #1911: the target inbound's ingress guards refused the message itself.
    413: RESEND_REFUSED_CODE,
    415: RESEND_REFUSED_CODE,
    422: RESEND_REFUSED_CODE,
    # BACKLOG #1169: the store cipher refused the uploaded file itself.
    _LOCKED_STATUS: RESEND_LOCKED_CODE,
    # BACKLOG #1169, PR 1506 follow-up A: no uploads store is configured.
    _UNAVAILABLE_STATUS: UPLOADS_UNAVAILABLE_CODE,
}

#: The same for a refused delete. 404 covers an absent file and an owner denial alike (ASVS 8.2.2).
#: A refused sidecar's 423 reaches only a files:access_any holder: the engine answers everyone else
#: 404 for a file whose sidecar it refuses, because the owner cannot be read. A damaged body's 423
#: (BACKLOG #5388) can reach the file's owner too, since its sound sidecar names that owner.
_DELETE_CODES: dict[int, str] = {
    404: DELETE_FAILED_CODE,
    _LOCKED_STATUS: DELETE_LOCKED_CODE,
    _UNAVAILABLE_STATUS: UPLOADS_UNAVAILABLE_CODE,
    status.HTTP_409_CONFLICT: DELETE_INCOMPLETE_CODE,
}

#: The same for a browse the engine refused. 404 is NOT here: an absent file, a traversal id and an
#: owner denial all 303 to the BARE list, with no code and no log line, exactly as before, so the
#: answer stays indistinguishable (ASVS 8.2.2). Anything else outside this map re-raises.
_BROWSE_CODES: dict[int, str] = {
    _LOCKED_STATUS: BROWSE_LOCKED_CODE,
    status.HTTP_403_FORBIDDEN: BROWSE_HOP_REFUSED_CODE,
    status.HTTP_429_TOO_MANY_REQUESTS: BROWSE_THROTTLED_CODE,
    _UNAVAILABLE_STATUS: UPLOADS_UNAVAILABLE_CODE,
}

#: A file id is minted as ``secrets.token_hex(16)``. The path segment reaching these routes is
#: CALLER-SUPPLIED and percent-decoded, so it can carry CR/LF and forge a log line; the engine rejects
#: a malformed id but only after this module has already decided to log. So a value that is not the
#: minted shape is logged as a fixed placeholder instead. This is a log-injection guard, not a second
#: copy of the path-traversal rule — that one stays in ``UploadStore._paths``.
_MINTED_FILE_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")


#: The engine's 423 carries which refusal it is as ``upload_refusal`` on the exception, never in
#: the response: ``"locked"``, ``"damaged"`` or ``"denied"`` (``_UploadRefused`` in
#: ``messagefoundry/api/app.py``). It is a typed signal, read in place of the detail text, so a
#: reworded detail cannot send a damaged or access-refused file to the store-key notice. A test pins
#: these values to what the engine raises. A refusal that carries none keeps its locked code.
_REFUSAL_ATTR = "upload_refusal"
#: The code a locked refusal becomes for each other kind the engine names.
_KIND_CODES: dict[str, dict[str, str]] = {
    # BACKLOG #5388 added item 1: a damaged file, which no key or rotate-key repairs.
    "damaged": {
        BROWSE_LOCKED_CODE: BROWSE_DAMAGED_CODE,
        RESEND_LOCKED_CODE: RESEND_DAMAGED_CODE,
        DELETE_LOCKED_CODE: DELETE_DAMAGED_CODE,
    },
    # BACKLOG #5388 added item 2: a file the filesystem refused the engine, which is not damaged.
    "denied": {
        BROWSE_LOCKED_CODE: BROWSE_ACCESS_CODE,
        RESEND_LOCKED_CODE: RESEND_ACCESS_CODE,
        DELETE_LOCKED_CODE: DELETE_ACCESS_CODE,
    },
}


def _refusal_code(exc: HTTPException, codes: dict[int, str]) -> str | None:
    """The allow-listed code for an engine refusal, or ``None`` for one ``codes`` does not map.

    A 423 that the engine names damaged maps to that operation's damaged code (BACKLOG #5388 added
    item 1), so its notice offers no key or rotate-key remedy, and one it names access-refused maps
    to the access code (BACKLOG #5388 added item 2), so its notice does not invite a delete. The
    kind is read from ``upload_refusal`` (:data:`_REFUSAL_ATTR`), never from the detail text.

    A 503 that carries ``Retry-After`` is a key-service outage (BACKLOG #3734), whatever ``codes``
    maps 503 to, because there an uploads store IS configured. It is told apart by its header, not
    by a type as the flag route's 503 is (BACKLOG #3811), so that this console needs no new seam
    import; the cost is that a later 503 with ``Retry-After`` from these handlers would read as an
    outage too. At least today, the handlers raise no other."""
    if exc.status_code == _UNAVAILABLE_STATUS and "Retry-After" in (exc.headers or {}):
        # BACKLOG #5388 added item 3: the engine marks a storage it could not reach, a typed
        # signal like ``upload_refusal``, so its notice does not blame the key service.
        if getattr(exc, "outcome_unconfirmed", False) is True:
            return DELETE_UNCONFIRMED_CODE
        if getattr(exc, "storage_unreachable", False) is True:
            return STORAGE_UNREACHABLE_CODE
        return KEY_SERVICE_BUSY_CODE
    code = codes.get(exc.status_code)
    kind = getattr(exc, _REFUSAL_ATTR, None)
    if code is None or not isinstance(kind, str):
        return code
    return _KIND_CODES.get(kind, {}).get(code, code)


def _log_file_id(file_id: str) -> str:
    return file_id if _MINTED_FILE_ID_RE.match(file_id) else "malformed"


def _resend_confirm_next(r: Request) -> str:
    """The re-auth continuation for BOTH resend routes: the confirm page, carrying the query.

    The query is the operator's selection (``index`` and ``to``). The default continuation is the
    bare path, which would come back from re-auth as a 422 with the selection gone. The POST and the
    confirm GET carry the same two parameters, so one mapping serves both. ``_seg`` re-encodes the
    decoded id, as the messages twin does, so a ``?`` or ``#`` in it cannot split the URL."""
    return f"/ui/uploaded-logs/file/{_seg(r.path_params['file_id'])}/resend-confirm?{r.url.query}"


def _refused(code: str) -> RedirectResponse:
    """The 303 a refused mutation answers with: :data:`_FAILED_TARGET` carrying one allow-listed code."""
    return RedirectResponse(f"{_FAILED_TARGET}?e={code}", status_code=303)


def _refused_by_engine(op: str, file_id: str, status_code: int, code: str) -> RedirectResponse:
    """Record an engine refusal server-side, then answer with :func:`_refused`.

    The refusal is logged so it survives whatever the browser does with the redirect. The line
    carries the file id (shape-checked) and the status only. The inbound name, the index and
    ``exc.detail`` are caller-supplied or engine text, and putting those in a log is log injection."""
    _log.warning(
        "uploaded-log %s refused: file_id=%s status=%d", op, _log_file_id(file_id), status_code
    )
    return _refused(code)


#: Page size the confirm pages walk the listing in. They need ONE file's metadata, not a page, so
#: they scan every page rather than the first — see :func:`_visible_file`. The engine's own ceiling.
_SCAN_PAGE = 500


def register(app: FastAPI, deps: UiDeps) -> None:
    core = deps.core

    async def _visible_file(
        request: Request, *, engine: Any, identity: Identity, file_id: str
    ) -> Any:
        """One visible file's metadata by id, or ``None`` — walked across the PAGED listing.

        The confirm pages read metadata through the listing rather than by id on purpose: the listing
        is owner-scoped, so a file the caller may not see is simply absent and the page 303s instead
        of disclosing that it exists. BACKLOG #1152 paged that listing, which silently broke the
        shape — a first-page-only scan would have redirected an operator away from their OWN file the
        moment they had more than a page of uploads, and reported it as "not found".

        Called with every parameter spelled out. These handlers are invoked BY REFERENCE across the
        seam, never over HTTP, so a FastAPI ``Query(...)`` default left unfilled arrives as a Query
        OBJECT rather than an int — which is exactly how this broke first: the object reached a list
        slice and raised TypeError inside the route.
        """
        offset = 0
        while True:
            data = await core.list_uploaded_files(
                request, engine=engine, identity=identity, limit=_SCAN_PAGE, offset=offset
            )
            match = next((f for f in data.files if f.file_id == file_id), None)
            if match is not None:
                return match
            offset += _SCAN_PAGE
            if offset >= data.total or not data.files:
                return None

    async def _confirm_target(
        request: Request, *, op: str, engine: Any, identity: Identity, file_id: str
    ) -> UploadedFileInfo | Response:
        """The file a confirm page names, or the redirect that page answers instead.

        An invisible file gets the BARE list, exactly as before, so the page discloses nothing to a
        non-owner. A missing uploads store gets its notice (PR 1506 follow-up A), because the
        listing handler raises 503 there and it would otherwise escape as JSON."""
        try:
            match = await _visible_file(request, engine=engine, identity=identity, file_id=file_id)
        except HTTPException as exc:
            if exc.status_code != _UNAVAILABLE_STATUS:
                raise
            return _refused_by_engine(op, file_id, exc.status_code, UPLOADS_UNAVAILABLE_CODE)
        if match is None:
            return RedirectResponse("/ui/uploaded-logs", status_code=303)
        info: UploadedFileInfo = match
        return info

    @app.get("/ui/uploaded-logs", response_class=HTMLResponse)
    async def ui_uploaded_logs(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.FILES_BROWSE)),
        e: str | None = Query(None, max_length=32),
        # BACKLOG #1152: the listing is paged. Declared with the SAME bounds as the JSON route, so a
        # hand-typed /ui query answers 422 here rather than reaching the handler with a value the
        # engine would clamp differently -- the console must not be the looser of the two doors.
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> HTMLResponse:
        try:
            data = await core.list_uploaded_files(
                request, engine=engine, identity=identity, limit=limit, offset=offset
            )
        except HTTPException as exc:
            # Every refusal on the other routes lands HERE, so this page answering the engine's
            # JSON would undo all of them. 503 is the one status the listing handler raises. The
            # page keeps the 503 so the status still says what the body says.
            if exc.status_code != _UNAVAILABLE_STATUS:
                raise
            return HTMLResponse(
                pages.uploaded_logs_unavailable(UPLOADS_UNAVAILABLE_NOTICE),
                status_code=_UNAVAILABLE_STATUS,
            )
        # The refused-mutation banner. An EXACT-key lookup in the allow-list, so the rendered string is
        # always one this module wrote — `e` itself is never rendered, echoed, or passed on, and an
        # unrecognized value yields no banner rather than reflected text.
        return HTMLResponse(pages.uploaded_logs(data, error=_LIST_NOTICES.get(e or "", "")))

    @app.get("/ui/uploaded-logs/upload-form", response_class=HTMLResponse)
    async def ui_uploaded_logs_upload_form(
        _identity: Identity = Depends(require_ui_step_up(Permission.FILES_UPLOAD)),
    ) -> HTMLResponse:
        # Renders an empty file input and no stored state, which is what makes it a safe unlock
        # continuation for the POST below: nothing of the operator's crosses the redirect.
        return HTMLResponse(pages.uploaded_logs_upload())

    @app.post("/ui/uploaded-logs/upload")
    async def ui_uploaded_logs_upload(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.FILES_UPLOAD,
                reauth_next=lambda _r: "/ui/uploaded-logs/upload-form",
            )
        ),
    ) -> Response:
        # Same-origin CSRF defense-in-depth on top of the SameSite cookie, plus the step-up its JSON
        # twin POST /uploads carries (BACKLOG #1739; the body-loss rationale is in the module
        # docstring). ``require_ui_step_up``, NOT the per-action variant: POST /uploads is plain
        # ``require_step_up``, so the shared session window is the parity, and binding a single-use
        # grant here would make the console the STRICTER door for a reason nothing states.
        assert_same_origin(request)
        try:
            await core.upload_file(request, engine=engine, identity=identity)
        except HTTPException as exc:
            return HTMLResponse(
                pages.uploaded_logs_upload(error=str(exc.detail)), status_code=exc.status_code
            )
        return RedirectResponse("/ui/uploaded-logs", status_code=303)

    async def _render_browse(
        file_id: str,
        request: Request,
        engine: Any,
        identity: Identity,
        *,
        content: str | None,
        field_path: str | None,
        field_value: str | None,
        message_type: str | None,
        control_id: str | None,
        limit: int,
        error: str = "",
        notice: str = "",
        refused: frozenset[str] = frozenset(),
        status_code: int = 200,
    ) -> Response:
        """Render one uploaded file's browse page for a given filter — shared by the GET page render
        and by the POST that filters on a needle (BACKLOG #1184)."""
        # No outcome banner here: this page is step-up-gated, so a flag aimed at it is dropped whenever
        # the window is stale (see :data:`_FAILED_TARGET`). Every refused mutation reports on the list.
        # A resend also needs messages:edit (vault BACKLOG #2625), so a role without it is not
        # offered a form whose confirm page would refuse it.
        can_resend = identity.has(Permission.MESSAGES_EDIT)
        # for_echo on every echoed criterion: a refused one may carry a control character, and the
        # page must not hand that byte back out (BACKLOG #6700).
        shared = dict(  # noqa: C408
            content=for_echo(content),
            field_path=for_echo(field_path),
            field_value=for_echo(field_value),
            message_type=for_echo(message_type),
            control_id=for_echo(control_id),
            notice=notice,
        )

        async def _browse(c: str | None, fp: str | None, fv: str | None) -> Any:
            return await core.browse_uploaded_file(
                request,
                file_id=file_id,
                engine=engine,
                identity=identity,
                content=c,
                field_path=fp,
                field_value=fv,
                target="both",
                # A filter the POST arm's model refused is echoed for correction, not applied
                # (BACKLOG #6700). The GET arm checks no alphabet, so `refused` is empty there.
                message_type=None if "message_type" in refused else message_type,
                control_id=None if "control_id" in refused else control_id,
                limit=limit,
                offset=0,
            )

        def _unreachable(exc: HTTPException) -> Response | None:
            """The answer for a browse the engine refused outright, or ``None`` for any other
            refusal. One table for both the first try and the retry below, so a status added here
            cannot be missed on the bad-criteria path, which is how the 404 retry bug arose."""
            if exc.status_code == 404:  # bad/absent id (incl. path-traversal): back to the list
                return RedirectResponse("/ui/uploaded-logs", status_code=303)
            code = _refusal_code(exc, _BROWSE_CODES)
            if code is None:
                return None
            return _refused_by_engine("browse", file_id, exc.status_code, code)

        # `error` means the criteria never validated, so there is nothing to search ON. Browse
        # metadata-only, but keep the typed values in `shared` so the form is not silently
        # blanked -- the same shape the HTTPException 400 arm below already uses.
        try:
            result = await _browse(
                *((None, None, None) if error else (content, field_path, field_value))
            )
        except HTTPException as exc:
            if (answer := _unreachable(exc)) is not None:
                return answer
            if exc.status_code == 400:  # bad content criteria → re-render metadata-only + the error
                # The engine parses the criteria BEFORE it authorizes the file, so this arm is reached
                # without the file ever having been reachable. The retry drops the criteria and so runs
                # far enough to 404 — on a denied owner check (ASVS 8.2.2) or an absent/traversal id —
                # or to 423 on a refused file, and either must take the SAME answer as above rather
                # than escaping this except block as raw JSON in the HTML plane.
                try:
                    result = await _browse(None, None, None)
                except HTTPException as retry_exc:
                    if (answer := _unreachable(retry_exc)) is not None:
                        return answer
                    raise
                return HTMLResponse(
                    pages.uploaded_log_detail(
                        result,
                        # for_echo on the DETAIL too, as on the search page: it is engine text
                        # built from the values the caller sent.
                        error=for_echo(str(exc.detail)),
                        can_resend=can_resend,
                        **shared,
                    ),
                    status_code=400,
                )
            raise
        return HTMLResponse(
            pages.uploaded_log_detail(result, error=error, can_resend=can_resend, **shared),
            status_code=status_code,
        )

    @app.get("/ui/uploaded-logs/file/{file_id}", response_class=HTMLResponse)
    async def ui_uploaded_log_browse(
        file_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.FILES_BROWSE)),
        field_path: str | None = Query(None, max_length=32),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        limit: int = Query(200, ge=1, le=500),
    ) -> Response:
        """The file's message list, filtered by the criteria that are safe on a URL (BACKLOG #1184).

        ``content`` and ``field_value`` are gone from this signature for the reason the content-search
        page states: a GET form writes the typed term into the address bar, browser history and every
        access log on the way. The filter form now POSTs to ``.../filter``, so a link still carrying
        ``?content=`` lists the whole file rather than filtering — the term is ignored, not honoured."""
        return await _render_browse(
            file_id,
            request,
            engine,
            identity,
            content=None,
            field_path=field_path,
            field_value=None,
            message_type=message_type,
            control_id=control_id,
            limit=limit,
        )

    @app.post("/ui/uploaded-logs/file/{file_id}/filter", response_class=HTMLResponse)
    async def ui_uploaded_log_filter(
        file_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.FILES_BROWSE,
                reauth_next=lambda r: r.url.path.removesuffix("/filter"),
            )
        ),
    ) -> Response:
        """Filter the browse listing on criteria carried in the request BODY (BACKLOG #1184).

        A path of its own because the browse page is a registered ``unlock`` action, which the console
        refuses to serve as a POST; ``reauth_next`` sends a stale-step-up bounce back to that page, the
        documented continuation for a body-carrying POST."""
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        needle = posted_needle(form)
        try:
            # The engine's own body model for this route, so a posted form is bounded exactly as the
            # JSON API bounds it — no second, drifting copy of the field lengths.
            criteria = UploadedMessageSearchRequest(
                content=needle.content,
                field_path=needle.field_path,
                field_value=needle.field_value,
                message_type=form.get("message_type") or None,
                control_id=form.get("control_id") or None,
                limit=200,  # the form carries no page-size control; same default the GET declares
                offset=0,
            )
        except ValidationError as exc:  # pydantic: a criterion breaks its bound or its alphabet
            # REFUSE, do not answer with the whole file. Returning 200 with every criterion dropped
            # and the inputs blanked reads to an operator as "your filter matched everything", which
            # is the opposite of what happened -- and it silently discarded their valid criteria too.
            # The sibling POST /ui/messages/search/run answers 400 with a banner, and the GET this
            # replaced answered 422; this arm was the only one that swallowed it (BACKLOG #1184).
            return await _render_browse(
                file_id,
                request,
                engine,
                identity,
                # The values the run would have used, so a leftover dropped above is not put back
                # without its marker (BACKLOG #6700). _render_browse echoes them through for_echo.
                content=needle.content,
                field_path=needle.field_path,
                field_value=needle.field_value,
                message_type=form.get("message_type") or None,
                control_id=form.get("control_id") or None,
                limit=200,
                error="a filter criterion is not a value that field accepts",
                notice=needle.notice,
                refused=frozenset(str(e["loc"][0]) for e in exc.errors() if e["loc"]),
                status_code=400,
            )
        return await _render_browse(
            file_id,
            request,
            engine,
            identity,
            content=criteria.content,
            field_path=criteria.field_path,
            field_value=criteria.field_value,
            message_type=criteria.message_type,
            control_id=criteria.control_id,
            limit=criteria.limit,
            notice=needle.notice,
        )

    @app.post("/ui/uploaded-logs/file/{file_id}/resend")
    async def ui_uploaded_log_resend(
        file_id: str,
        request: Request,
        index: int = Query(..., ge=0),
        to: str = Query(..., min_length=1, max_length=256),
        engine: Any = Depends(deps.get_engine),
        # Vault BACKLOG #2625: the JSON gate's two permissions and its action-bound proof. A resend
        # injects a message, so `files:browse` alone, a read, no longer reaches it.
        identity: Identity = Depends(
            require_ui_step_up_action(
                STEP_UP_ACTION_UPLOAD_RESEND,
                Permission.FILES_BROWSE,
                Permission.MESSAGES_EDIT,
                reauth_next=_resend_confirm_next,
            )
        ),
    ) -> Response:
        # BACKLOG #1227. The old premise here was "the browse page it posts from is already
        # step-up-gated, so the operator is fresh" — and NOTHING enforced that arrival path, so a form
        # left open past the window still posted. The freshness is now re-asserted ON THIS ROUTE,
        # because the console calls the engine handler BY REFERENCE across the CoreHandlers seam and
        # the engine's own ``require_step_up`` Depends never runs for a /ui caller.
        #
        # The two parameters ride the QUERY, not the body, so this POST is body-less and therefore
        # auto-retryable across the re-auth redirect — the same property that lets delete work. That
        # is the OPPOSITE choice from connection_writes.py's purge, which deliberately drops its
        # query: losing ``index``/``to`` here strands an operator mid-task, and neither value is
        # destructive or PHI-shaped. ``to`` is a connection name, i.e. a structural locator, which the
        # engine already writes to the audit store by name on every resend.
        #
        # The Query params carry the LENGTH bounds; the model carries the connection-name RULE
        # (BACKLOG #1108), which the query declaration deliberately does not repeat -- a second copy
        # would be a second definition. So the model can still refuse a value the query accepted, and
        # a `to` that could not name a connection is refused HERE, before the engine sees it.
        assert_same_origin(request)
        try:
            body = UploadResendRequest(index=index, to=to)
        except ValidationError:
            # Same shape as an engine refusal below, and for the same reason: answering with the
            # SUCCESS response would tell the operator a message was injected when none was. The
            # rejected value is caller-supplied, so it travels nowhere -- not into the URL, the HTML
            # or the log.
            _log.warning(
                "uploaded-log resend refused: file_id=%s reason=malformed_target",
                _log_file_id(file_id),
            )
            return _refused(RESEND_FAILED_CODE)
        try:
            await core.resend_uploaded_message(
                request, file_id=file_id, body=body, engine=engine, identity=identity
            )
        except HTTPException as exc:
            # A refused resend must not answer with the SUCCESS response, which is a bare 303 to the
            # detail page. Failing with the byte-identical answer to succeeding tells the operator a
            # message was injected when none was. So a refusal goes to :data:`_FAILED_TARGET` carrying
            # one allow-listed code, and the code is all that travels: `exc.detail` quotes the caller's
            # own inbound name and index back, and reflecting that into the URL or the HTML is an XSS
            # sink fed by the form body. Every status in :data:`_RESEND_CODES` is handled rather than
            # re-raised because an escaping HTTPException renders as application/json inside the
            # HTML console, with that same caller-supplied name quoted in it.
            code = _refusal_code(exc, _RESEND_CODES)
            if code is None:
                raise
            # And the refusal is recorded SERVER-SIDE; see :func:`_refused_by_engine`.
            return _refused_by_engine("resend", file_id, exc.status_code, code)
        return RedirectResponse(f"/ui/uploaded-logs/file/{file_id}", status_code=303)

    @app.get("/ui/uploaded-logs/file/{file_id}/resend-confirm", response_class=HTMLResponse)
    async def ui_uploaded_log_resend_confirm(
        file_id: str,
        request: Request,
        index: int = Query(..., ge=0),
        to: str = Query(..., min_length=1, max_length=256),
        engine: Any = Depends(deps.get_engine),
        # `messages:edit` as well as the POST, so a role that cannot resend is told so here rather
        # than after it confirms (vault BACKLOG #2625). The bound proof HELD, not spent (owner ruling
        # 2026-10-13, #3241 R2): a page opened inside the window but with no proof would cost the
        # operator a confirm and then a re-auth at the POST. The POST spends it.
        identity: Identity = Depends(
            require_ui_step_up_action(
                STEP_UP_ACTION_UPLOAD_RESEND,
                Permission.FILES_BROWSE,
                Permission.MESSAGES_EDIT,
                reauth_next=_resend_confirm_next,
                spend=False,
            )
        ),
    ) -> Response:
        # The confirm step for resend (BACKLOG #1227). STEP-UP-GATED since BACKLOG #1822, matching
        # the JSON browse route that carries the same permission. It used to be plain require_ui on
        # the claim that a gate on the re-auth continuation loops. It does not: /ui/reauth refreshes
        # the window BEFORE it redirects back, so the gated page renders, as the upload form's does.
        # The one real difference from that form is the query, which is why ``reauth_next`` is set.
        #
        # It exists so the POST can be body-less. The selection lives in THIS page's own URL rather
        # than in server-side state, which is why the shape beats stashing the message body across
        # re-auth: nothing is stored, so no message body gains a new lifetime or a new deletion
        # question (CLAUDE.md section 9).
        #
        # Metadata read via list, exactly as delete-confirm does — a bad or absent id 404s at the
        # browse handler, and this route must not disclose one file's existence to a non-owner.
        match = await _confirm_target(
            request, op="resend-confirm", engine=engine, identity=identity, file_id=file_id
        )
        if isinstance(match, Response):
            return match
        return HTMLResponse(pages.uploaded_log_resend_confirm(file_id, match.filename, index, to))

    @app.get("/ui/uploaded-logs/file/{file_id}/delete-confirm", response_class=HTMLResponse)
    async def ui_uploaded_log_delete_confirm(
        file_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.FILES_DELETE)),
    ) -> Response:
        # The confirm step (BACKLOG #126). Show the filename so the operator confirms the right file; a
        # bad/absent id (path-traversal) 404s at the browse handler, so read metadata via list here.
        match = await _confirm_target(
            request, op="delete-confirm", engine=engine, identity=identity, file_id=file_id
        )
        if isinstance(match, Response):
            return match
        return HTMLResponse(pages.uploaded_log_delete_confirm(file_id, match.filename))

    @app.post("/ui/uploaded-logs/file/{file_id}/delete")
    async def ui_uploaded_log_delete(
        file_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.FILES_DELETE)),
    ) -> Response:
        assert_same_origin(request)
        try:
            await core.delete_uploaded_file(
                request, file_id=file_id, engine=engine, identity=identity
            )
        except HTTPException as exc:
            # Same shape as the resend refusal one function up: the success is a bare 303 to the list,
            # so answering a REFUSED delete with that same 303 tells the operator the file was deleted
            # when it was not — including on an ASVS 8.2.2 owner denial, which the engine answers 404
            # so it stays indistinguishable from an absent file. The flag is what separates the two,
            # and the WARNING carries the record server-side (file_id shape-checked + status only).
            code = _refusal_code(exc, _DELETE_CODES)
            if code is None:
                raise
            return _refused_by_engine("delete", file_id, exc.status_code, code)
        return RedirectResponse("/ui/uploaded-logs", status_code=303)
