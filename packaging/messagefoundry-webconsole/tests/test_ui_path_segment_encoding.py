# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection names cannot escape a /ui path segment (ASVS 1.2.2, BACKLOG #1107 clause 2).

The apiclient half of this item shipped with `_seg` and is pinned by `tests/test_apiclient.py`. The
console half was left: `safe=""` appeared ZERO times in `messagefoundry_webconsole/`, the two sites
that encoded a path segment used `quote`'s DEFAULT `safe="/"`, and the dead-letter replay forms
interpolated a channel id and a destination name with no encoding at all.

`quote`'s default is the whole defect: measured, `quote("IB/ACME")` returns it UNCHANGED, because the
one character it leaves alone is the one a path segment turns on.

**All 54 interpolation sites were then partitioned by reading each value's PRODUCER**, not its
interpolation line. That is the only way to answer this: "every interpolated id is a `uuid4().hex`"
is true of most sites and FALSE for connection names, because `Registry._add` checks only for a
duplicate, so a name is unconstrained free text.

The partition found the id sites genuinely safe, but NOT for the reason usually given. They are safe
because every one is read back from the store after a lookup that 404s on a miss -- so a crafted path
param never reaches a render. **`ui_role_update` is the single exception on the whole surface**, and
the last two tests cover it: a `ValidationError` short-circuits before that lookup runs.

**A blanket sweep of the remaining sites would be WRONG**, which is why one test exists only to stop
it: `_auth`'s reauth `next` is CORRECTLY `safe="/"` because it carries a whole path inside a query
parameter. It is also safe for a DIFFERENT reason than its own comment implies -- adversarial review
showed attacker-influenceable bytes do reach it, and the `quote()` at the site is what holds. Remove
that call on a "server-generated anyway" argument and it opens.

**CORRECTION, BACKLOG #1107, measured on a real uvicorn server.** This file used to say a slash-
bearing name "silently becomes two segments and addresses a different route" and imply `_seg` stops
that. It does not, and no assertion here ever tested it: every assertion below reads the RENDERED
HTML, which is a question about the link, not about the route the browser then reaches. ASGI defines
`scope["path"]` as the DECODED path and Starlette routes on it, so the `%2F` `_seg` emits is a
separator again before matching. `_seg` genuinely holds `?` and `#`; the `/` limb is decided by the
route table's shape. `test_a_percent_encoded_slash_does_not_survive_to_the_routing_layer` pins the measurement.

The console has SIX same-method route pairs where an absorbing sibling exists, pinned as a set by
`test_the_console_absorb_a_segment_route_pairs_are_the_six_that_were_read`. Five carry an
engine-minted id read back from a lookup, so nothing crafted reaches them. **One carries free text:**
`POST /ui/dead-letters/{channel_id}/replay` against
`POST /ui/dead-letters/{channel_id}/{destination_name}/replay` -- the very pair the dead-letter test
below was written to protect. Both carry the same permission and step-up gate, so this is a
correctness defect and not an escalation: on a first deployment, an operator replaying dead letters
for a connection whose name contains a `/` would reach the destination-scoped handler with the name
split across its two parameters. Narrowing what a connection name may contain would close it, and
BACKLOG #1107 disqualifies that by name as a separate owner question -- so the finding is recorded
here rather than bought.
"""

from __future__ import annotations

import pathlib
import re

from messagefoundry.api.models import DeadLetterList, DeadLetterRow
from messagefoundry_webconsole.pages._common import _seg


def test_seg_encodes_the_separator_that_the_default_leaves_alone() -> None:
    """The unit fact the rest rests on, with a benign name as the negative control."""
    from urllib.parse import quote

    assert quote("IB/ACME") == "IB/ACME", (
        "the premise of this whole file just changed: quote's default no longer leaves '/' alone"
    )
    assert _seg("IB/ACME") == "IB%2FACME"
    assert _seg("a?b") == "a%3Fb"
    assert _seg("a#b") == "a%23b"
    # NEGATIVE CONTROL: a guard that mangled everything would satisfy the assertions above.
    assert _seg("IB_ACME_ADT") == "IB_ACME_ADT"


def _dead_letters(channel: str, destination: str) -> DeadLetterList:
    row = DeadLetterRow(
        outbox_id="o1",
        message_id="m1",
        channel_id=channel,
        destination_name=destination,
        attempts=1,
        last_error=None,
        failed_at=0.0,
        control_id=None,
        message_type=None,
        received_at=0.0,
    )
    return DeadLetterList(total=1, limit=50, offset=0, dead_letters=[row])


def test_the_dead_letter_replay_forms_encode_a_name_carrying_a_slash() -> None:
    """RENDERS the real page rather than reading the f-string, so the assertion is about output.

    These two forms were the unencoded pair: before this fix a connection named ``IB/ACME`` produced
    ``/ui/dead-letters/IB/ACME/replay`` in the markup.

    SCOPE, corrected under BACKLOG #1107: this asserts on the LINK, which is the only thing it ever
    measured. It is NOT evidence about which route the POST reaches, because the server decodes
    ``%2F`` before routing -- see the module docstring and
    ``test_a_percent_encoded_slash_does_not_survive_to_the_routing_layer``.
    """
    from messagefoundry_webconsole.pages.messages import dead_letters

    html = str(dead_letters(_dead_letters("IB/ACME", "OB/PARTNER")))

    assert "/ui/dead-letters/IB%2FACME/replay" in html
    assert "/ui/dead-letters/IB%2FACME/OB%2FPARTNER/replay" in html
    assert "/ui/dead-letters/IB/ACME/" not in html, (
        "the name escaped its path segment; the action addresses a different route"
    )


def test_a_benign_connection_name_still_renders_readably() -> None:
    """NEGATIVE CONTROL for the render path: encoding must not disfigure ordinary names."""
    from messagefoundry_webconsole.pages.messages import dead_letters

    html = str(dead_letters(_dead_letters("IB_ACME_ADT", "OB_PARTNER_ADT")))
    assert "/ui/dead-letters/IB_ACME_ADT/replay" in html
    assert "%5F" not in html, "an unreserved character was percent-encoded"


def test_every_connection_name_route_interpolates_through_seg() -> None:
    """GUARD THE GUARD: a new site on these routes reds this rather than slipping in unencoded.

    Scans the page builders for f-string path literals on the three routes that carry a connection
    name, and requires each interpolation to go through ``_seg``. Mutation: revert any one site to a
    bare ``quote(...)`` or a raw ``{name}``. Red: that literal is listed in the failure.
    """
    pages = pathlib.Path(__file__).resolve().parents[3] / "messagefoundry_webconsole" / "pages"
    literals: list[str] = []
    for path in sorted(pages.glob("*.py")):
        for lit in re.findall(
            r'f"(/ui/(?:connection|connections|dead-letters)/[^"]*)"',
            path.read_text(encoding="utf-8"),
        ):
            if "{" in lit:
                literals.append(f"{path.name}: {lit}")
    assert literals, "found NO connection-name path literals -- the scan is broken, not the code"
    unencoded = [lit for lit in literals if "_seg(" not in lit]
    assert not unencoded, f"connection-name path segments not routed through _seg: {unencoded}"


def test_the_reauth_next_parameter_is_left_alone() -> None:
    """The site a blanket path-segment sweep would BREAK, pinned so the sweep cannot happen quietly.

    ``_auth``'s reauth ``next`` carries a whole PATH inside a query parameter, so ``safe="/"`` is
    correct there. Encoding it as one segment would turn every re-auth redirect into a broken link.
    """
    auth = pathlib.Path(__file__).resolve().parents[3] / "messagefoundry_webconsole" / "_auth.py"
    source = auth.read_text(encoding="utf-8")
    assert 'quote(next_path if next_path is not None else request.url.path, safe="/")' in source, (
        "the reauth 'next' encoding changed; if a path-segment builder was applied here it is wrong "
        "-- that value is a path carried in a query parameter"
    )


def test_a_rejected_custom_role_submit_cannot_escape_its_path_segment() -> None:
    """THE ONE SITE ON THIS SURFACE WHERE THE 404 LOOKUP IS BYPASSED.

    Every other id rendered by the console is read back from the store, so a request path param that
    matched nothing 404s before anything renders. ``ui_role_update`` is the exception: a
    ``ValidationError`` from ``CustomRoleRequest`` short-circuits BEFORE ``update_custom_role`` runs,
    and the 400 branch then rebuilds the page from ``CustomRoleInfo(id=role_id, ...)`` using the RAW
    path param. ``CustomRoleInfo.id`` is a bare ``id: str`` with no ``Field`` constraint.

    So an operator who submits an invalid form to a crafted role path gets that path reflected into
    the update and delete form actions. Encoded, it stays one segment.
    """
    from messagefoundry.api.auth_models import CustomRoleInfo
    from messagefoundry_webconsole.pages.admin import role_form_page

    role = CustomRoleInfo(id="custom:abc/evil", display_name="x", description=None, permissions=[])
    html = str(role_form_page(["messages:read"], role=role, error="invalid input"))

    assert "/ui/roles/custom/custom%3Aabc%2Fevil/update" in html
    assert "/ui/roles/custom/custom%3Aabc%2Fevil/delete" in html
    assert "/ui/roles/custom/custom:abc/evil/" not in html, (
        "the reflected role id escaped its path segment; the form now posts to a different route"
    )


def test_a_real_custom_role_id_still_addresses_its_own_route() -> None:
    """NEGATIVE CONTROL. A genuine id is ``custom:`` + uuid4().hex, so the colon IS encoded -- that is
    harmless (FastAPI decodes the path param back) but it must still be ONE segment, and the benign
    case must not be mangled beyond that."""
    from messagefoundry.api.auth_models import CustomRoleInfo
    from messagefoundry_webconsole.pages.admin import role_form_page

    role = CustomRoleInfo(
        id="custom:0123456789abcdef", display_name="ops", description=None, permissions=[]
    )
    html = str(role_form_page(["messages:read"], role=role))
    assert "/ui/roles/custom/custom%3A0123456789abcdef/update" in html
    assert "%2F" not in html, "a legitimate id contains no slash, so none should be encoded"


def test_the_roles_list_link_encodes_its_path_segment() -> None:
    """The one bare path-segment site left inside the partition this file established (#1107).

    ``roles_page`` interpolated ``role.id`` raw while ``role_form_page`` routed the SAME value
    through ``_seg`` twice, so one file disagreed with itself about one value's context. The reason
    recorded for leaving it -- role ids are ``custom:`` + ``uuid4().hex``, so nothing hostile
    arrives -- is the trusted-identifier argument BACKLOG #1107 names as its live trap, and it is
    not the reason the sibling sites are encoded.
    """
    from messagefoundry.api.auth_models import RoleInfo
    from messagefoundry_webconsole.pages.admin import roles_page

    hostile = RoleInfo(
        id="custom:abc/evil", display_name="x", description=None, permissions=[], builtin=False
    )
    html = str(roles_page([hostile]))
    assert "/ui/roles/custom%3Aabc%2Fevil/edit" in html
    assert 'href="/ui/roles/custom:abc/evil/edit"' not in html, (
        "the role id escaped its path segment in the rendered link"
    )


def test_a_builtin_role_renders_no_edit_link_at_all() -> None:
    """NEGATIVE CONTROL for the test above: a page that linked every row would satisfy it too.

    Built-in roles are not editable, so they must render as plain text and never as a link.
    """
    from messagefoundry.api.auth_models import RoleInfo
    from messagefoundry_webconsole.pages.admin import roles_page

    builtin = RoleInfo(
        id="operator", display_name="Operator", description=None, permissions=[], builtin=True
    )
    html = str(roles_page([builtin]))
    assert "/ui/roles/operator/edit" not in html
    assert "Operator" in html


def test_a_percent_encoded_slash_does_not_survive_to_the_routing_layer() -> None:
    """THE CORRECTION THIS FILE OWED (BACKLOG #1107). ``_seg`` does not contain ``/`` at the router.

    Every other assertion in this file reads rendered HTML, which answers "what does the link say",
    not "which handler receives the POST". Those are different sentences, and only the first was
    ever tested. This asks the second, by driving a REAL uvicorn server: TestClient is not the wire,
    and a check reading ``httpx.URL.path`` rather than the raw request line would decode the ``%2F``
    itself and agree with broken code.

    ASGI defines ``scope["path"]`` as the DECODED path and Starlette matches routes against it, so a
    ``%2F`` is a separator again before any route is chosen. The two templates below are the
    console's own same-method dead-letter replay pair, copied verbatim.

    POSITIVE CONTROL in the same run: ``?`` and ``#`` DO stay inside the segment. So this is a
    finding about one metacharacter, not a claim that the encoding does nothing.
    """
    import socket
    import threading
    from urllib.parse import quote

    import httpx
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()

    @app.post("/ui/dead-letters/{channel_id}/replay")
    def channel_scoped(channel_id: str) -> dict[str, str]:
        return {"route": "channel", "channel_id": channel_id}

    @app.post("/ui/dead-letters/{channel_id}/{destination_name}/replay")
    def destination_scoped(channel_id: str, destination_name: str) -> dict[str, str]:
        return {"route": "destination", "channel_id": channel_id, "dest": destination_name}

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        waiter = threading.Event()
        while not server.started:
            waiter.wait(0.05)
        with httpx.Client(base_url=f"http://127.0.0.1:{port}") as client:
            seg = quote("IB/ACME", safe="")
            assert seg == "IB%2FACME", "the encoder changed; the rest of this test is about %2F"
            slashed = client.post(f"/ui/dead-letters/{seg}/replay")
            question = client.post(f"/ui/dead-letters/{quote('IB?ACME', safe='')}/replay")
            hashed = client.post(f"/ui/dead-letters/{quote('IB#ACME', safe='')}/replay")
            benign = client.post("/ui/dead-letters/IB_ACME_ADT/replay")
    finally:
        server.should_exit = True
        thread.join(timeout=10)

    assert slashed.json() == {"route": "destination", "channel_id": "IB", "dest": "ACME"}, (
        "GOOD NEWS IF THIS FAILS: a %2F now survives to the routing layer, so _seg contains '/' "
        "after all. Re-read the module docstring, this test and both _seg docstrings -- all three "
        "are written around the measurement that it does not."
    )
    assert question.json() == {"route": "channel", "channel_id": "IB?ACME"}
    assert hashed.json() == {"route": "channel", "channel_id": "IB#ACME"}
    assert benign.json() == {"route": "channel", "channel_id": "IB_ACME_ADT"}


def test_the_console_absorb_a_segment_route_pairs_are_the_six_that_were_read() -> None:
    """GUARD THE FINDING ABOVE. The ``/`` limb is held by the ROUTE TABLE, so pin the route table.

    A pair is at risk when one template is another's with an extra segment spliced into a parameter
    position AND the methods match -- then a decoded ``/`` in that parameter lands on the sibling.
    There are SIX, and they are NOT equally interesting, which is why this asserts the set and not a
    count. Five carry a ``message_id`` or a ``file_id``: engine-minted, and read back from a lookup
    that 404s on a miss, so no crafted value reaches them -- the same provenance argument the rest of
    this file rests those sites on. **The dead-letter pair is the one where an UNCONSTRAINED value
    meets an absorbing sibling**, because a connection name is free text.

    A new pair is not automatically a defect. It is a site somebody has to read, and nothing else in
    the tree would report it.
    """
    import re

    routes_dir = (
        pathlib.Path(__file__).resolve().parents[3] / "messagefoundry_webconsole" / "routes"
    )
    declared: set[tuple[str, str]] = set()
    for path in sorted(routes_dir.glob("*.py")):
        for method, template in re.findall(
            r'@app\.(get|post|put|delete|patch)\(\s*"(/ui[^"]*)"',
            path.read_text(encoding="utf-8"),
        ):
            declared.add((method.upper(), template))
    assert declared, "the route scan found NOTHING -- a broken instrument, not a clean tree"

    param = re.compile(r"\{[^}]+\}")
    pairs: set[tuple[str, str, str]] = set()
    for method, short in declared:
        segs = short.strip("/").split("/")
        for i, seg in enumerate(segs):
            if not param.fullmatch(seg):
                continue
            for other_method, long in declared:
                if other_method != method:
                    continue
                longs = long.strip("/").split("/")
                if (
                    len(longs) == len(segs) + 1
                    and longs[:i] == segs[:i]
                    and longs[i + 2 :] == segs[i + 1 :]
                ):
                    pairs.add((method, short, long))

    assert pairs == {
        ("GET", "/ui/messages/{message_id}", "/ui/messages/search/layered"),
        ("GET", "/ui/messages/{message_id}", "/ui/messages/{message_id}/edit"),
        ("GET", "/ui/messages/{message_id}", "/ui/messages/{message_id}/parse-tree"),
        (
            "GET",
            "/ui/uploaded-logs/file/{file_id}",
            "/ui/uploaded-logs/file/{file_id}/delete-confirm",
        ),
        (
            "GET",
            "/ui/uploaded-logs/file/{file_id}",
            "/ui/uploaded-logs/file/{file_id}/resend-confirm",
        ),
        (
            "POST",
            "/ui/dead-letters/{channel_id}/replay",
            "/ui/dead-letters/{channel_id}/{destination_name}/replay",
        ),
    }, f"the console's absorb-a-segment route pairs changed: {sorted(pairs)}"
