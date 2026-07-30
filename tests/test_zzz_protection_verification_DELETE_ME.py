# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""THROWAWAY — proves the 2026-07-29 branch-protection change actually BLOCKS a red PR.

Delete this file and close its PR. It exists for one CI run. A protection change that returns HTTP
200 and blocks nothing is indistinguishable from one that works, so the only way to know is to make a
required context fail on purpose and watch the merge be refused.
"""

from __future__ import annotations


def test_deliberate_failure_to_prove_required_checks_block_a_merge() -> None:
    raise AssertionError("deliberate: verifying branch protection blocks a red PR")
