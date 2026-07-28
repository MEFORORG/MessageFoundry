"""TEMPORARY diff-coverage probe — DELETE BEFORE MERGE. Not part of the engine.

Exists for one reason: four merged PRs surfaced the advisory quality gates, and the headline claim of
that work — that diff-cover emits INLINE `::notice` annotations on the Files changed tab — has never
been observed on a real diff, because none of those PRs touched `messagefoundry/` and `--cov` only
measures this package. The mechanism is proven locally and the CI path provably executes, but "it
reports correctly that there was nothing to report" is not the same as "it renders".

This module supplies real changed lines under coverage: `probe_covered` is exercised by
tests/test_diffcov_probe.py, `probe_uncovered` deliberately is not. A correct run annotates only the
latter — which proves both that the surface renders AND that it is scoped to genuinely uncovered
changed lines rather than to the whole diff.

Delete this file and its test once the annotation has been observed.
"""


def probe_covered(value: int) -> int:
    """Exercised by the probe test, so these lines must NOT be annotated."""
    doubled = value * 2
    return doubled


def probe_uncovered(value: int) -> str:
    """Deliberately unexercised. Every line below should come back as a `Missing Coverage` notice,
    coalesced into as few ranges as diff-cover can manage."""
    if value > 100:
        label = "large"
    elif value > 10:
        label = "medium"
    else:
        label = "small"
    suffix = "!" if value < 0 else ""
    return f"{label}{suffix}"
