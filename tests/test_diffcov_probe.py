"""TEMPORARY — companion to messagefoundry/_diffcov_probe.py. DELETE BEFORE MERGE.

Covers `probe_covered` and pointedly not `probe_uncovered`, so the diff-coverage job has a real diff
with a mix of covered and uncovered changed lines to annotate.
"""

from messagefoundry._diffcov_probe import probe_covered


def test_probe_covered_doubles() -> None:
    assert probe_covered(21) == 42
    assert probe_covered(0) == 0
    assert probe_covered(-3) == -6
