# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The base class for every model the API parses out of a request body (ASVS 2.2.1, BACKLOG #1109).

Pydantic's default is ``extra="ignore"``, so before this module every API request body accepted an
unknown or misspelled key, dropped it, and reported success. On a first deployment that is a silent
wrong answer rather than a refusal: ``PUT /users/{id}/channel-scope`` sent ``{"chanels": [...]}``
leaves the optional ``channels`` at ``None``, and ``None`` means *all channels*. The operator asked
for a narrow scope, the engine granted a wide one, and nothing anywhere reported a problem.

**The posture is request-scoped on purpose, and the split must not be tidied away.** The engine's
response models keep ``extra="ignore"`` because the same classes are the client's *reader*:
:mod:`messagefoundry.apiclient.client` validates engine responses into them, and the web console
ships as a separately-versioned wheel. A response model that forbade unknown keys would make an
older client raise on a newer engine that grew a field -- turning an additive server change into a
hard client failure. Requests come from outside and must be refused when they are wrong; responses
come from a trusted engine and must be read tolerantly. Two directions, two rules, one reason.

**Five shapes are used in BOTH directions**, so they carry the request rule and pay the reader cost:
``AdGroupMap``, ``AdGroupMapEntry``, ``AdGroupScopeEntry``, ``AdGroupScopeMap`` and ``ChannelScope``
are the bodies of the AD-group and per-channel RBAC writes *and* the payloads of the matching reads.
They are strict because a dropped key on those routes is an RBAC mis-grant, which is the worst case
this class exists to stop. The cost is stated so it is not discovered later: **adding a field to one
of those five is a client-visible wire change, and the release that adds it must ship the client
bump with it.** ``tests/test_api_request_models_forbid_extra.py`` pins that set, so growing it is a
decision somebody makes on purpose.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

__all__ = ["RequestModel"]


class RequestModel(BaseModel):
    """A request body: unknown keys are refused (HTTP 422), never silently dropped."""

    model_config = ConfigDict(extra="forbid")
