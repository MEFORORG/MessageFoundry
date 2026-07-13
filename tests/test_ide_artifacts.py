# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The committed IDE data artifacts must stay in sync with the code that generates them.

A stale bundle ships wrong field-picker scope/badges silently (the IDE ships only the JSON, never runs
the generator), so — like ``requirements.lock`` — CI recomputes and compares. To fix a failure, regenerate:

    python -m messagefoundry hl7structures --json > ide/media/hl7structures.json
    python -m messagefoundry hl7schema     --json > ide/media/hl7schema.json
"""

from __future__ import annotations

import json
from pathlib import Path

from messagefoundry.hl7schema import hl7_schema
from messagefoundry.hl7structures import to_json

_MEDIA = Path(__file__).resolve().parents[1] / "ide" / "media"


def _committed(name: str) -> object:
    return json.loads((_MEDIA / name).read_text(encoding="utf-8"))


def test_hl7structures_artifact_in_sync() -> None:
    assert _committed("hl7structures.json") == to_json(), (
        "ide/media/hl7structures.json is stale — regenerate: "
        "python -m messagefoundry hl7structures --json > ide/media/hl7structures.json"
    )


def test_hl7schema_artifact_in_sync() -> None:
    assert _committed("hl7schema.json") == hl7_schema(), (
        "ide/media/hl7schema.json is stale — regenerate: "
        "python -m messagefoundry hl7schema --json > ide/media/hl7schema.json"
    )
