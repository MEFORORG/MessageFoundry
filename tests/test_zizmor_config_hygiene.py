# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every zizmor suppression must name a workflow that still exists.

``.github/zizmor.yml`` was asserted by nothing, so its ``release-sync-check.yml`` entry survived that
workflow's deletion (59fbc938, 2026-07-26) and sat there reading as coverage. zizmor's ignore entries
are BASE filenames (``filename.yml[:line[:column]]``) resolved against the scan target, and
zizmor.yml's job runs ``zizmor .github/workflows`` — so the ignore namespace is exactly that
directory's contents, and an entry naming anything else can never match.

A dead entry is worse than noise: this file's header calls every entry "a REVIEWED, justified
non-finding", so a name that cannot match reads as a reviewed risk that is actually unexamined.
"""

from __future__ import annotations

from tests._workflow_contexts import ROOT, WORKFLOWS

_CONFIG = ROOT / ".github" / "zizmor.yml"


def test_every_zizmor_ignore_names_a_live_workflow() -> None:
    import yaml

    assert _CONFIG.is_file(), f"{_CONFIG} is missing — this guard cannot pass vacuously"
    config = yaml.safe_load(_CONFIG.read_text(encoding="utf-8")) or {}
    scanned: list[str] = []
    for audit, body in (config.get("rules") or {}).items():
        for entry in (body or {}).get("ignore") or []:
            basename = str(entry).split(":", 1)[0]
            scanned.append(f"{audit} -> {entry}")
            assert (WORKFLOWS / basename).is_file(), (
                f"{audit}.ignore names {basename}, which is not in .github/workflows/ — the "
                "workflow was deleted or renamed and its suppression must go with it"
            )
    # Print what was covered: a gate that silently scanned nothing looks identical to a passing one.
    print(f"scanned {len(scanned)} zizmor ignore entries: {scanned}")
    assert scanned, (
        "parsed zero ignore entries — the config shape changed and this guard went blind"
    )
