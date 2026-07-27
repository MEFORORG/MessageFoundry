"""Report the cyclomatic-complexity (ruff C901) findings a pull request actually CAUSED.

Raw C901 cannot be surfaced on a diff, and measuring it is what proves that: every C901 finding
anchors on a SINGLE line -- the function-name token of its `def` -- so on this tree all 122
findings are single-line regions. GitHub renders a finding inline only when its lines are inside
the diff, which makes the raw signal wrong in both directions: a PR that adds 150 lines of
branching INSIDE an existing function touches no `def` line and produces nothing, while a PR that
reflows a signature or adds a type hint fires an annotation for debt it did not cause.

So compare instead. This reads two ruff JSON runs -- the merge base and HEAD -- keys findings on
(repo-relative file, function name), and reports only functions this PR INTRODUCED over the
threshold or whose complexity it INCREASED. Typical output is 0-3 entries, every one attributable
to the PR under review, which also keeps the count far below any annotation ceiling.

Output is GitHub workflow-command annotations on stdout (no token, no permission grant, identical
behaviour on fork PRs) plus a markdown table for the run summary. Decreases are reported in the
summary only, so an improvement is visible without spending an annotation on it.

Usage:
    python3 scripts/quality/c901_delta.py --base c901-base.json --head c901-head.json \
        --repo-root . --summary-file "$GITHUB_STEP_SUMMARY"
"""

import argparse
import json
import os
import re
import sys
from typing import NamedTuple

# ruff has NO machine-readable field for the measured complexity -- the number exists only inside the
# human-readable message, e.g. "`_serve` is too complex (95 > 10)". Parsing it is therefore load-bearing,
# and a ruff wording change MUST fail loudly rather than silently classifying every finding as absent
# (which would render this script a no-op that still reports success). See _parse_message.
_MESSAGE_RE = re.compile(
    r"^`(?P<name>[^`]+)` is too complex \((?P<actual>\d+) > (?P<threshold>\d+)\)$"
)

# Default annotation ceiling. GitHub's per-step annotation cap is undocumented (the commonly cited
# ~10 traces to a 2020 reviewdog issue citing a now-dead thread) and surplus annotations are dropped
# silently, with no error. The delta keeps real output at 0-3, so this only ever bounds a pathological
# run -- and the markdown summary is always complete regardless of what the cap drops.
_DEFAULT_MAX_ANNOTATIONS = 20


class Key(NamedTuple):
    """Identity of a complex function: repo-relative path plus the bare function name.

    Ruff's message carries only the bare name, not a qualified path, so two same-named methods in
    different classes in one file collapse to one key. Measured on this tree today: 122 findings ->
    122 unique keys, zero collisions. A collision takes the MAX complexity (see _parse_findings),
    which makes the delta conservative -- it can under-report an increase, never invent one.
    """

    path: str
    function: str


class Finding(NamedTuple):
    complexity: int
    threshold: int
    line: int


def _normalise_path(filename: str, repo_root: str, scan_root: str) -> str:
    """Return `filename` as a repo-relative POSIX path.

    Ruff emits ABSOLUTE paths, and they may be Windows-style even when this script runs elsewhere
    (a fixture captured on a developer machine, or a test), so os.path.relpath cannot be trusted to
    cross that boundary -- normalise separators and strip textually instead.

    The base run comes from a SECOND checkout of the merge base (`base-tree/`), so its absolute
    paths differ from HEAD's by more than the root. Stripping only the repo root would yield
    `base-tree/messagefoundry/a.py` against HEAD's `messagefoundry/a.py`, giving every function two
    non-matching keys -- every one would report as new AND removed, i.e. the exact 122-annotation
    flood this script exists to prevent. So: strip the repo root, and if what remains is not already
    anchored at the scanned package, cut at the last occurrence of it.
    """
    normalised = filename.replace("\\", "/")
    root = repo_root.replace("\\", "/").rstrip("/")
    anchor = f"{scan_root}/"

    # Windows paths are case-insensitive; comparing casefolded avoids a C:/ vs c:/ miss.
    if root and normalised.casefold().startswith(f"{root.casefold()}/"):
        stripped = normalised[len(root) + 1 :]
        if stripped.startswith(anchor):
            return stripped

    # Either a different checkout root, or an intervening directory (the base tree). Cut at the LAST
    # occurrence of the scanned package so a nested copy resolves to the inner one.
    index = normalised.rfind(f"/{anchor}")
    if index != -1:
        return normalised[index + 1 :]

    # Already relative, or a shape we cannot anchor. Return it normalised rather than guessing.
    return normalised.lstrip("./")


def _parse_message(message: str, filename: str) -> tuple[str, int, int]:
    """Extract (function, complexity, threshold) from ruff's C901 message text.

    Raises ValueError on an unrecognised message. This is deliberate and tested: reporting zero
    findings is indistinguishable from a clean PR, so a ruff format change must surface as a loud
    traceback in the job log rather than as a silently empty -- and permanently green -- report.
    """
    match = _MESSAGE_RE.match(message)
    if match is None:
        raise ValueError(
            f"unrecognised ruff C901 message {message!r} (from {filename!r}). "
            "Ruff's message format has probably changed; update _MESSAGE_RE in "
            "scripts/quality/c901_delta.py and its test before trusting this report."
        )
    return match["name"], int(match["actual"]), int(match["threshold"])


def _parse_findings(path: str, repo_root: str, scan_root: str) -> dict[Key, Finding]:
    """Load one ruff JSON run into a {Key: Finding} map."""
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)

    findings: dict[Key, Finding] = {}
    for entry in raw:
        if entry.get("code") != "C901":
            continue
        filename = entry["filename"]
        function, complexity, threshold = _parse_message(entry["message"], filename)
        key = Key(_normalise_path(filename, repo_root, scan_root), function)
        line = int(entry["location"]["row"])

        previous = findings.get(key)
        if previous is None or complexity > previous.complexity:
            findings[key] = Finding(complexity=complexity, threshold=threshold, line=line)
    return findings


class Change(NamedTuple):
    key: Key
    before: int | None  # None => the function is new over the threshold
    after: int
    threshold: int
    line: int


def classify(
    base: dict[Key, Finding], head: dict[Key, Finding]
) -> tuple[list[Change], list[Change], list[Change]]:
    """Split into (new, increased, decreased). Unchanged findings are dropped entirely."""
    new: list[Change] = []
    increased: list[Change] = []
    decreased: list[Change] = []

    for key, finding in sorted(head.items()):
        previous = base.get(key)
        if previous is None:
            new.append(Change(key, None, finding.complexity, finding.threshold, finding.line))
        elif finding.complexity > previous.complexity:
            increased.append(
                Change(
                    key, previous.complexity, finding.complexity, finding.threshold, finding.line
                )
            )
        elif finding.complexity < previous.complexity:
            decreased.append(
                Change(
                    key, previous.complexity, finding.complexity, finding.threshold, finding.line
                )
            )
    return new, increased, decreased


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def _annotation(change: Change) -> str:
    if change.before is None:
        title = "New function over the complexity threshold"
        detail = (
            f"`{change.key.function}` is new at complexity {change.after} "
            f"(mccabe threshold {change.threshold})"
        )
    else:
        title = "Complexity increased"
        detail = (
            f"`{change.key.function}` complexity {change.before} -> {change.after} "
            f"(mccabe threshold {change.threshold})"
        )
    return (
        f"::warning file={_escape_property(change.key.path)},"
        f"line={change.line},endLine={change.line},"
        f"title={_escape_property(title)}::{_escape_data(detail)}"
    )


def _markdown(new: list[Change], increased: list[Change], decreased: list[Change]) -> str:
    lines = ["## Cyclomatic complexity (C901) — changed by this PR", ""]

    if not new and not increased:
        lines.append("No function was introduced over the threshold or made more complex. ✅")
    else:
        lines += ["| Function | File | Complexity | Threshold |", "| --- | --- | --- | --- |"]
        for change in new + increased:
            before = "new" if change.before is None else str(change.before)
            lines.append(
                f"| `{change.key.function}` | `{change.key.path}`:{change.line} "
                f"| {before} → **{change.after}** | {change.threshold} |"
            )

    if decreased:
        lines += ["", "### Improved (summary only, not annotated)", ""]
        lines += ["| Function | File | Complexity |", "| --- | --- | --- |"]
        for change in decreased:
            lines.append(
                f"| `{change.key.function}` | `{change.key.path}`:{change.line} "
                f"| {change.before} → **{change.after}** |"
            )

    lines += [
        "",
        "<sub>Advisory only — never gates a merge. Pre-existing complexity is deliberately not "
        "reported: only what this PR changed appears here.</sub>",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="ruff C901 JSON from the merge base")
    parser.add_argument("--head", required=True, help="ruff C901 JSON from HEAD")
    parser.add_argument("--repo-root", default=".", help="checkout root, for relative paths")
    parser.add_argument("--scan-root", default="messagefoundry", help="scanned package name")
    parser.add_argument("--max-annotations", type=int, default=_DEFAULT_MAX_ANNOTATIONS)
    parser.add_argument(
        "--summary-file", default=None, help="append markdown here (GITHUB_STEP_SUMMARY)"
    )
    args = parser.parse_args(argv)

    repo_root = os.path.abspath(args.repo_root)
    base = _parse_findings(args.base, repo_root, args.scan_root)
    head = _parse_findings(args.head, repo_root, args.scan_root)
    new, increased, decreased = classify(base, head)

    annotated = new + increased
    for change in annotated[: args.max_annotations]:
        print(_annotation(change))
    if len(annotated) > args.max_annotations:
        dropped = len(annotated) - args.max_annotations
        print(
            f"::notice title=Complexity delta truncated::{dropped} further change(s) in the summary"
        )

    markdown = _markdown(new, increased, decreased)
    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as handle:
            handle.write(markdown)
    else:
        sys.stderr.write(markdown)

    # Always 0. This is an advisory reporter; a non-zero exit here would be a merge-blocking signal
    # in disguise. Genuine breakage (an unparseable ruff message) raises instead, which is visible
    # in the log without reddening the job.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
