# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5526 item 3: the cleartext-credential refusal reads an ``Authorization`` header in every
spelling ``http_auth.is_authorization_header_name`` reads, not only in another letter case.

``http.client`` sends a name ending in a NUL or starting with a DEL as written, and a peer may read
it as the plain name, so such a header carries the credential over plain http too. Synthetic
values only.
"""

from __future__ import annotations

import pytest

from messagefoundry.transports.rest import refuse_cleartext_credentials

_OFF_BOX = "http://partner.example.org/api"


@pytest.mark.parametrize(
    "name",
    ["Authorization", "authorization ", "Authorization\x00", "\x7fAuthorization"],
    ids=["plain", "trailing-space", "trailing-nul", "leading-del"],
)
def test_an_authorization_header_in_any_spelling_is_refused_off_box(name: str) -> None:
    with pytest.raises(ValueError, match="Authorization header"):
        refuse_cleartext_credentials(
            "http", {name: "Bearer synthetic"}, _OFF_BOX, credentials=[], connection="OB_X"
        )


@pytest.mark.parametrize("name", ["X-Authorization", "Proxy-Authorization", "X-Site"])
def test_another_header_alone_is_not_counted(name: str) -> None:
    """The control: a name that is not ``Authorization`` adds no credential here."""
    refuse_cleartext_credentials("http", {name: "1"}, _OFF_BOX, credentials=[], connection="OB_X")
