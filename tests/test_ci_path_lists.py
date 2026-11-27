# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``changes`` job's path lists read the paths its inline arms read (BACKLOG #5472).

ci.yml sits at GitHub's workflow file size limit (tests/test_ci_engine_suite_shards.py holds it
under 512,000 bytes), and its five path arms -- ``serverdb``, ``docker``, ``packaging``, ``ide`` and
``tooling`` -- were written inline as one ``grep -qE '^(...)'`` each, several thousand bytes of
it. They moved to ``.github/ci-paths/<arm>.txt``, owner-approved in chat (the batch 20002 brief
dates the approval 2026-11-27), one ERE per line, which the step reads with ``grep -qEf`` through
its ``paths_match`` function.

THE MOVE MUST NOT CHANGE A DECISION. ``_INLINE_AT_60EB058`` below is each inline regex exactly as
ci.yml held it at commit 60eb058c1b3, the head the move started from, and the equivalence test runs
it and the list through REAL ``grep``, path for path, over every tracked file, every string literal
in the gate tests, and near-misses built from both. Python's ``re`` is a different engine from
grep's ERE, so a Python-only comparison would prove the two Python readings agree, not that the
step decides as before; the Python reading is compared too, because every other gate test uses it.

The only paths allowed to differ are ``_ADMITTED_SINCE_THE_PIN``: what the move itself added. An
edit to ci.yml ran every arm, because ci.yml was where the arms lived; each list now admits its own
file, so an edit to a list still runs the arm it governs. The tooling list admits tests/_ci_paths.py,
the reader its tests share.

THIS IS A PIN, AND IT REDS ON A DELIBERATE EDIT. A later change that widens an arm adds its paths
to ``_ADMITTED_SINCE_THE_PIN`` and says why in the commit; ``_INLINE_AT_60EB058`` and
``_SOURCE_SHA`` stay as they are, because they record where the move started. A change that narrows
an arm, or adds one, is the point at which this pin has done its job: retire the equivalence tests
rather than invent an inline arm that never existed. The gate tests beside this file pin what each
arm must admit; this file pins only that the move did not change it.

``paths_match`` itself is run under bash for the shapes a list can fail in: missing, empty, a line
that matches the empty line (a blank line, ``^x|``, ``^.*``, which ``grep -f`` reads as
match-everything), a CR, a pattern grep refuses. Each fails the step. The inline form had no such
failure: a missing list read as "no match", and the arm went false.
"""

from __future__ import annotations

import ast
import functools
import os
import re
import subprocess
from pathlib import Path

import pytest

from tests._bash_resolver import probe_env, require_bash
from tests._ci_paths import CI_PATHS, PATHS_MATCH, arm_list_name, ci_path_list, joined
from tests._workflow_contexts import changes_arm_pattern, jobs_of

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_SOURCE_SHA = "60eb058c1b35625a8bce6e9d112d0e8b01f06827"

#: Each arm's inline regex, exactly as ci.yml held it at _SOURCE_SHA (see the module docstring).
_INLINE_AT_60EB058: dict[str, str] = {
    "serverdb": (
        r"^(messagefoundry/store/|messagefoundry/__init__|messagefoundry/__main__|"
        r"messagefoundry/pki|messagefoundry/api/(__init__|app|approvals|security|models)|"
        r"messagefoundry/auth/(__init__|service|tokens|trust_anchors|anchor_path|"
        r"audit_visibility|identity|ldap|passwords|permissions|totp)|"
        r"messagefoundry/parsing/(__init__|binary|message|peek|x12/)|"
        r"messagefoundry/pipeline/(__init__|alerts|cluster|config_convergence|dr|leader_tasks|"
        r"phase_timing|reference_sync|retention|sharding|stage_dispatcher|wiring_runner|"
        r"alert_sinks|engine|ingress_guards|refused_body|security_signals)|"
        r"messagefoundry/connection_(events|names)|messagefoundry/sqlserver_roles|"
        r"messagefoundry/(logging_setup|redaction|integrity|security/__init__|"
        r"apiclient/__init__|logging_guard|mllpcodec|proctree|remotedebug|serviceenv|"
        r"startupcode|terminal_text)|messagefoundry_toolkit/(__init__|generators/)|"
        r"messagefoundry/odbc_(call_gate|env|dsn)|messagefoundry/content_type|"
        r"messagefoundry/uploads|messagefoundry/config/(__init__|models|response|settings|"
        r"wiring|fingerprint|snapshot|tls_policy)|messagefoundry/transports/(__init__|base|"
        r"database|dicomweb|fhir|http_auth|mllp|rest|soap|tcp|x12|admission|dicom|receipt)|"
        r"tests/test_(sqlserver|postgres|cluster|database_connector|database_source|pooled|"
        r"stage_dispatcher|batch_claim|claim_fifo|inline_fast_path|seq_only_fifo|fifo_index|"
        r"per_lane_wake|response_capture|reingress|x12_rte|shard_recovery|shard_cert|adr0071|"
        r"adr0075|adr0114|adr0157|dr_server_seed_gate|dr7_server_config_only_backup|"
        r"backup_runner_server_db|connscale|load_failover|load_runner|store_privilege|"
        r"store_pin_connect_refusal|uploads_shard_quota|embedded_document_pruning|alert_sinks|"
        r"alert_state|auth_hardening|b2614_revoke_all|b5091_global_session_epoch|"
        r"config_fingerprint|custom_roles|processed_files_ledger|"
        r"reload_dir_only_moves_on_apply|security_signals|start_config_change_alert|"
        r"startup_attestation)|tests/(_[^/]*|conftest)\.py$|harness/(load/|config/|"
        r"_spreadsheet|bounded_file|frame_cap)|tests/audit_chain_cases\.py|"
        r"tests/test_store_cipher_sweep_parity\.py|"
        r"tests/test_transit_bound_attestation_server_backends\.py|ci/python-version|"
        r"scripts/ci/(db-tls-cert|retry-native-crash)\.sh|\.github/workflows/ci\.yml)"
    ),
    "docker": (
        r"^(docker/|\.dockerignore|ci/locks/release-tools\.lock|pyproject\.toml|"
        r"requirements\.lock|(README\.md|LICENSE|NOTICE)$|messagefoundry/(__init__|__main__|"
        r"serviceenv|terminal_text|api/(__init__|app|models|tls)|auth/(trust_anchors|"
        r"anchor_path|passwords)|pki|config/(anchor|retention_classification|settings|"
        r"tls_policy|wiring)|transports/egress|logging_setup|startupcode|remotedebug)\.py$|"
        r"messagefoundry/_vendor/defusedxml/LICENSE$|harness/load/rigadmin\.py$|"
        r"scripts/ci/make_syslog_ca_crl\.py$|tests/_phi_gate_provisions\.py$|"
        r"\.github/workflows/ci\.yml)"
    ),
    "packaging": (
        r"^(pyproject\.toml|packaging/|scripts/release/|ci/python-version|"
        r"ci/locks/release-tools\.lock$|((README|CHANGELOG)\.md|LICENSE|NOTICE|hatch\.toml|"
        r"\.gitignore|messagefoundry/_vendor/defusedxml/LICENSE)$|\.github/workflows/(ci|"
        r"release)\.yml)"
    ),
    "ide": (r"^(ide/|\.github/workflows/ci\.yml)"),
    "tooling": (
        r"^(scripts/|\.github/|docs/|\.claude/|CLAUDE\.md|LICENSE|ide/|ci/npm-tools/|"
        r"ci/python-version|(ci|docker|security)/locks/|pyproject\.toml|hatch\.toml|"
        r"packaging/[^/]+/(pyproject|hatch)\.toml|\.gitignore|\.gitattributes|"
        r"\.gitleaks\.toml|\.semgrep/|\.codex/|\.pre-commit-config\.yaml|constraints\.lock|"
        r"requirements\.lock|tests/(conftest\.py|_tooling_manifest\.py|tooling_manifest\.txt|"
        r"test_tooling_partition\.py))"
    ),
}

#: A substring each arm's pattern holds, for ``changes_arm_pattern``'s wrong-arm check.
_SANITY = {
    "serverdb": "tests/test_(",
    "docker": "dockerignore",
    "packaging": "scripts/release/",
    "ide": "ide/",
    "tooling": "tooling_manifest",
}

#: The gate tests whose string literals join the corpus: whatever path a gate test asserts on, the
#: move must decide the same way.
_GATE_TESTS = (
    "test_ci_docker_gate.py",
    "test_ci_docs_only_detector.py",
    "test_ci_merge_group_gate.py",
    "test_ci_packaging_gate.py",
    "test_ci_tooling_gate.py",
    "test_serverdb_ci_coverage.py",
    "test_store_privilege_preflight.py",
)

#: Hand-written near-misses: an anchor, an escape or a `$` that went missing would admit one.
_NEAR_MISSES = (
    "",
    "LICENSE.txt",
    "LICENSEx",
    "xLICENSE",
    "NOTICE.md",
    "README.mdx",
    "docs/README.md",
    "CHANGELOG.md.bak",
    "pyproject_toml",
    "pyprojectXtoml",
    "requirements_lock",
    "constraints_lock",
    "hatchXtoml",
    ".github/workflows/ci_yml",
    ".github/workflows/cixyml",
    ".github/workflows/ci.yml.bak",
    ".github/workflows/release.yml",
    ".github/workflows/releaseXyml",
    ".github/ci-paths/serverdb.txt",
    ".github/ci-paths/new.txt",
    "x.github/workflows/ci.yml",
    "sub/docker/Dockerfile",
    "dockerfile",
    "Xdockerignore",
    "ide",
    "ide.md",
    "idex/package.json",
    "packaging",
    "packaging/x/pyproject.toml",
    "packaging/x/y/pyproject.toml",
    "messagefoundry/store",
    "messagefoundry/storex.py",
    "messagefoundry/api/app.pyc",
    "messagefoundry/api/app.py.orig",
    "messagefoundry/api/appXpy",
    "messagefoundry/_vendor/defusedxml/LICENSE.txt",
    "tests/_x.py",
    "tests/_x/y.py",
    "tests/_x.pyc",
    "tests/conftest.pyc",
    "tests/conftestXpy",
    "tests/test_sqlserver_x.py",
    "tests/test_sqlserverx.py",
    "tests/x/test_sqlserver.py",
    "harness/load",
    "harness/loadx/y.py",
    "ci/python-version.bak",
    "ci/locks/release-tools.lock.bak",
    "ci/locks/release-toolsXlock",
    "scripts",
    "scriptsx/y.py",
    "CLAUDE.mdx",
    "sub/CLAUDE.md",
)


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
        ["git", *args], cwd=str(_ROOT), capture_output=True, timeout=120, check=False
    )


def _literals(path: Path) -> set[str]:
    """Every string constant in a test module that could be a path: no whitespace, short."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and 0 < len(node.value) <= 200
        and not re.search(r"\s", node.value)
    }


def _mutations(path: str) -> list[str]:
    """Near-misses of a real path: each breaks one thing a pattern relies on."""
    return [
        "x" + path,  # a lost `^`
        "a/" + path,  # a lost `^`, at a directory boundary
        path + "x",  # a lost `$`
        path.replace(".", "X"),  # a lost `\.` escape
        path[1:],  # a lost leading character, such as the `.` of `.github/`
        path.upper(),  # case
    ]


@functools.cache
def _corpus() -> tuple[str, ...]:
    tracked = _git("ls-files", "-z")
    assert tracked.returncode == 0, tracked.stderr.decode("utf-8", "replace")
    paths = {p for p in tracked.stdout.decode("utf-8").split("\0") if p}
    assert len(paths) > 1000, f"git ls-files listed only {len(paths)} paths; the corpus is wrong"
    main = _git("ls-tree", "-r", "-z", "--name-only", "origin/main")
    if main.returncode == 0:
        paths |= {p for p in main.stdout.decode("utf-8").split("\0") if p}
    for name in _GATE_TESTS:
        paths |= _literals(_ROOT / "tests" / name)
    paths |= set(_NEAR_MISSES)
    for path in list(paths):
        paths.update(_mutations(path))
    # A path grep cannot hold on one line is not a path a diff can name.
    return tuple(sorted(p for p in paths if "\n" not in p and "\r" not in p))


@pytest.fixture(scope="module")
def bash(tmp_path_factory: pytest.TempPathFactory) -> str:
    return require_bash(tmp_path_factory.mktemp("resolve-bash"))


@pytest.fixture(scope="module")
def corpus_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("corpus") / "paths.txt"
    path.write_bytes(("\n".join(_corpus()) + "\n").encode("utf-8"))
    return path


def _grep(
    bash: str, corpus: Path, *, inline: str | None = None, listed: Path | None = None
) -> list[str]:
    """The corpus lines grep selects, under the same bash the step would use: ``grep -E -e INLINE``
    as the inline arm ran, or ``grep -Ef LIST`` as ``paths_match`` runs.

    The inline regex goes through the environment, not argv: on Windows the command line bash
    parses its argv from eats backslashes, and a ``\\.`` that arrives as ``.`` admits ``ci_yml``.
    Measured: passed as an argument, the docker arm's comparison differed on 46 paths, every one of
    them an escaped dot read as any character.
    """
    assert (inline is None) != (listed is None)
    env = probe_env(Path(bash), dict(os.environ))
    env["MF_INLINE"] = inline or ""
    script = 'grep -E -e "$MF_INLINE" "$1"' if inline is not None else 'grep -Ef "$2" "$1"'
    proc = subprocess.run(  # noqa: S603  # nosec B603 - resolved interpreter, fixed argv
        [
            bash,
            "-c",
            script + '; rc=$?; [ "$rc" -le 1 ] || exit "$rc"',
            "grep",
            corpus.as_posix(),
            listed.as_posix() if listed is not None else "",
        ],
        env=env,
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return proc.stdout.decode("utf-8").splitlines()


# --------------------------------------------------------------------------------------------------
# THE EQUIVALENCE, through real grep.
# --------------------------------------------------------------------------------------------------


#: What each list admits that its inline arm did not: what the move itself added (module
#: docstring), as the path that must be newly admitted and the shape every newly admitted path must
#: have. Each list admits its own file, as every arm admitted ci.yml, where it used to live. The
#: tooling list's new line is unanchored at the end like its siblings, so `_ci_paths.pyx` rides too.
_ADMITTED_SINCE_THE_PIN: dict[str, tuple[str, str]] = {
    "serverdb": (".github/ci-paths/serverdb.txt", r"^\.github/ci-paths/serverdb\.txt$"),
    "docker": (".github/ci-paths/docker.txt", r"^\.github/ci-paths/docker\.txt$"),
    "packaging": (".github/ci-paths/packaging.txt", r"^\.github/ci-paths/packaging\.txt$"),
    "ide": (".github/ci-paths/ide.txt", r"^\.github/ci-paths/ide\.txt$"),
    "tooling": ("tests/_ci_paths.py", r"^tests/_ci_paths\.py"),
}


def _added_as_expected(arm: str, added: set[str]) -> bool:
    must, shape = _ADMITTED_SINCE_THE_PIN[arm]
    return must in added and all(re.search(shape, path) for path in added)


@pytest.mark.parametrize("arm", sorted(_INLINE_AT_60EB058))
def test_each_list_admits_exactly_what_its_inline_regex_admitted(
    arm: str, bash: str, corpus_file: Path
) -> None:
    old = set(_grep(bash, corpus_file, inline=_INLINE_AT_60EB058[arm]))
    new = set(_grep(bash, corpus_file, listed=CI_PATHS / f"{arm}.txt"))
    assert old, f"the {arm} inline regex admits nothing in the corpus; the corpus is wrong"
    assert not old - new, (
        f"the {arm} list no longer admits {len(old - new)} path(s) ci.yml's inline arm at "
        f"{_SOURCE_SHA[:11]} admitted: {sorted(old - new)[:20]}"
    )
    assert _added_as_expected(arm, new - old), (
        f"the {arm} list admits {sorted(new - old)[:20]} beyond the inline arm; the move added only "
        f"{_ADMITTED_SINCE_THE_PIN[arm]}"
    )


@pytest.mark.parametrize("arm", sorted(_INLINE_AT_60EB058))
def test_the_python_reading_agrees_with_the_inline_regex(arm: str) -> None:
    """Every other gate test reads the list through ``changes_arm_pattern`` and Python's ``re``."""
    old = re.compile(_INLINE_AT_60EB058[arm])
    new = re.compile(changes_arm_pattern(arm, _SANITY[arm]))
    differ = {p for p in _corpus() if bool(old.search(p)) != bool(new.search(p))}
    assert all(new.search(p) for p in differ), f"the {arm} Python reading lost: {differ}"
    assert _added_as_expected(arm, differ), f"the {arm} Python reading differs on: {differ}"


@pytest.mark.parametrize("arm", sorted(_INLINE_AT_60EB058))
@pytest.mark.parametrize("damage", ["drop the first line", "unanchor the first line"])
def test_the_comparison_reds_on_a_damaged_list(
    arm: str, damage: str, bash: str, corpus_file: Path, tmp_path: Path
) -> None:
    """NEGATIVE CONTROL: a comparison that cannot fail proves nothing. Damage a copy of each list
    the two ways a hand edit most plausibly does, and the comparison must see it."""
    lines = ci_path_list(arm)
    if damage == "drop the first line":
        lines = lines[1:]
    else:
        lines = [lines[0].removeprefix("^"), *lines[1:]]
    damaged = tmp_path / f"{arm}.txt"
    damaged.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    old = set(_grep(bash, corpus_file, inline=_INLINE_AT_60EB058[arm]))
    new = set(_grep(bash, corpus_file, listed=damaged))
    assert old - new or not _added_as_expected(arm, new - old), (
        f"{damage} in the {arm} list went unseen; the equivalence test is blind to it"
    )


def test_the_pinned_regexes_are_the_ones_ci_yml_held(tmp_path: Path) -> None:
    """Provenance of the pin: read each inline arm out of ci.yml at the source commit, the way the
    pre-move reader did, and compare. That commit leaves the history once the branch squash-merges,
    so this skips where it is gone; it ran, and passed, on the branch that made the move."""
    if _git("cat-file", "-e", f"{_SOURCE_SHA}^{{commit}}").returncode != 0:
        pytest.skip(f"{_SOURCE_SHA[:11]} is not in this clone's history")
    shown = _git("show", f"{_SOURCE_SHA}:.github/workflows/ci.yml")
    assert shown.returncode == 0, shown.stderr.decode("utf-8", "replace")
    text = shown.stdout.decode("utf-8")
    for arm, sanity in _SANITY.items():
        emit = text.rfind(f'echo "{arm}=true" >> "$GITHUB_OUTPUT"')
        found = list(re.finditer(r"grep -qE '([^']*)'", text[:emit]))
        assert found, arm
        assert sanity in found[-1].group(1), arm
        assert found[-1].group(1) == _INLINE_AT_60EB058[arm], f"the {arm} pin is not ci.yml's"


# --------------------------------------------------------------------------------------------------
# THE WIRING: each output reads its own list, and every list is read.
# --------------------------------------------------------------------------------------------------


def _step_run() -> str:
    steps = jobs_of("ci.yml")["changes"]["steps"]
    found = [str(s["run"]) for s in steps if s.get("id") == "f"]
    assert len(found) == 1, "the changes job lost its `id: f` step"
    return found[0]


#: An inline path arm: a grep of the changed paths whose -flags include E and whose pattern is a
#: quoted literal starting `^`, in either quote. The code classifier's `grep -qE "$alwayscode"`
#: is a variable, and the manifest arm's `grep -vE '^...'` reads the manifest, not the paths.
_INLINE_ARM = re.compile(
    r"""echo\s+"\$changed"\s*\|\s*grep\s+-[A-Za-z]*E[A-Za-z]*\s+(?:-e\s+)?['"]\^"""
)


def _code_lines(script: str) -> str:
    return "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))


def test_each_output_is_decided_by_its_own_list() -> None:
    text = _CI.read_text(encoding="utf-8")
    for arm in _INLINE_AT_60EB058:
        assert arm_list_name(text, arm) == arm, f"`{arm}` is decided by another arm's list"


def test_every_list_is_read_by_one_arm_and_no_inline_arm_is_left() -> None:
    code = _code_lines(_step_run())
    named = [m.group(1) for m in PATHS_MATCH.finditer(code)]
    on_disk = sorted(p.stem for p in CI_PATHS.glob("*.txt"))
    assert sorted(named) == on_disk, f"arms {sorted(named)} against lists {on_disk}"
    assert set(_INLINE_AT_60EB058) <= set(named), "a pinned arm no longer reads its list"
    assert not _INLINE_ARM.search(code), "an inline path arm is back in the changes step"


@pytest.mark.parametrize(
    ("line", "inline"),
    [
        ("if echo \"$changed\" | grep -qE '^(docs/)'; then", True),
        ("if echo \"$changed\" | grep -Eq '^docs/'; then", True),
        ('if echo "$changed" | grep -qE "^(docs/)"; then', True),
        ("if echo \"$changed\" | grep -E -e '^docs/' >/dev/null; then", True),
        ('elif echo "$changed" | grep -qE "$alwayscode"; then', False),
        ("grep -qxFf <(grep -vE '^[[:space:]]*(#|$)' tests/tooling_manifest.txt)", False),
        ("if paths_match docs; then", False),
    ],
)
def test_the_inline_arm_detector_on_planted_lines(line: str, inline: bool) -> None:
    """NEGATIVE CONTROL for the guard above: it must see each inline shape, and not the arms that
    are not inline. At least these shapes; a pattern spelt through a variable is not seen."""
    assert bool(_INLINE_ARM.search(line)) is inline


def test_each_list_is_well_formed() -> None:
    """What ``ci_path_list`` and the step both refuse, plus: every line anchored, no line twice."""
    for arm in _INLINE_AT_60EB058:
        lines = ci_path_list(arm)
        unanchored = [line for line in lines if not line.startswith("^")]
        assert not unanchored, f"{arm} list lines without `^`: {unanchored}"
        assert len(set(lines)) == len(lines), f"the {arm} list repeats a line"


@pytest.mark.parametrize(
    ("content", "why"),
    [
        (b"^a(\n^b)\n", "two lines grep refuses that join into one valid regex"),
        (b"^docs/|\n", "a trailing `|`, which matches every path"),
        (b"^.*\n", "a line that matches every path"),
        (b"^docs/\n\n", "a blank line"),
        (b"^docs/\r\n", "a CR"),
        (b"", "an empty list"),
    ],
)
def test_the_python_reader_refuses_what_the_step_refuses(
    tmp_path: Path, content: bytes, why: str
) -> None:
    (tmp_path / "probe.txt").write_bytes(content)
    with pytest.raises(AssertionError):
        ci_path_list("probe", tmp_path)
    assert why


def test_the_python_reader_joins_lines_so_one_cannot_reach_into_the_next() -> None:
    """A ``|`` in one line must not widen the line beside it once joined."""
    pattern = re.compile(joined(["^a/(x|y)", "^b/"]))
    assert pattern.search("a/x") and pattern.search("b/c")
    assert not pattern.search("y") and not pattern.search("c/b/")


# --------------------------------------------------------------------------------------------------
# THE FAIL-CLOSED READER: `paths_match`, run under bash.
# --------------------------------------------------------------------------------------------------


def _paths_match_function() -> str:
    lines = _step_run().splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.strip() == "paths_match() {"), None)
    assert start is not None, "the changes step lost its paths_match function"
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = next((i for i in range(start + 1, len(lines)) if lines[i] == " " * indent + "}"), None)
    assert end is not None, "paths_match has no closing brace at its own indent"
    return "\n".join(lines[start : end + 1]) + "\n"


def _run_paths_match(
    bash: str, tmp_path: Path, content: bytes | None, changed: str, *, body: str | None = None
) -> subprocess.CompletedProcess[str]:
    lists = tmp_path / ".github" / "ci-paths"
    lists.mkdir(parents=True, exist_ok=True)
    if content is not None:
        (lists / "probe.txt").write_bytes(content)
    script = tmp_path / "probe.sh"
    script.write_text(
        (_paths_match_function() if body is None else "")
        + 'changed="$CHANGED"\n'
        + (body or "if paths_match probe; then echo MATCH; else echo NOMATCH; fi\n"),
        encoding="utf-8",
        newline="\n",
    )
    env = probe_env(Path(bash), dict(os.environ))
    env["CHANGED"] = changed
    proc = subprocess.run(  # noqa: S603  # nosec B603 - resolved interpreter, fixed argv
        # `bash -e`, which is what Actions runs a step with no declared shell under.
        [bash, "-e", str(script)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        timeout=60,
        check=False,
    )
    return subprocess.CompletedProcess(
        proc.args,
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


@pytest.mark.parametrize(
    ("changed", "expected"),
    [
        ("docs/a.md\nsrc/b.py", "MATCH"),
        ("src/b.py", "NOMATCH"),
        ("", "NOMATCH"),
        ("xdocs/a.md", "NOMATCH"),
    ],
)
def test_a_good_list_matches_as_grep_does(
    bash: str, tmp_path: Path, changed: str, expected: str
) -> None:
    proc = _run_paths_match(bash, tmp_path, b"^docs/\n^README\\.md$\n", changed)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == expected, proc.stdout


@pytest.mark.parametrize(
    ("content", "why"),
    [
        (None, "a missing list"),
        (b"", "an empty list"),
        (b"^docs/\n\n^src/\n", "a blank line, which grep -f reads as match-everything"),
        (b"^docs/\r\n^src/\r\n", "a CR, which grep -f would carry into every pattern"),
        (b"^docs/(\n", "a pattern grep refuses"),
        (b"^docs/|\n^src/\n", "a trailing `|`, which matches the empty line, so every path"),
        (b"^.*\n", "a line that matches every path"),
    ],
)
def test_a_bad_list_fails_the_step(
    bash: str, tmp_path: Path, content: bytes | None, why: str
) -> None:
    proc = _run_paths_match(bash, tmp_path, content, "docs/a.md\nsrc/b.py")
    assert proc.returncode == 1, f"{why} did not fail the step: rc {proc.returncode} {proc.stdout}"
    assert "MATCH" not in proc.stdout, f"{why} reached a decision: {proc.stdout}"
    assert "::error::" in proc.stdout, f"{why} failed without saying why: {proc.stdout}"


def test_the_unguarded_shape_reads_a_missing_list_as_no_match(bash: str, tmp_path: Path) -> None:
    """CONTROL for the test above: the same condition without ``paths_match``'s checks, which is
    what a bare ``grep -qEf`` in an ``if`` would be, exits 0 and decides NOMATCH on a list that is
    not there. That silent false is what the function exists to refuse."""
    proc = _run_paths_match(
        bash,
        tmp_path,
        None,
        "docs/a.md",
        body=(
            'if echo "$changed" | grep -qEf .github/ci-paths/probe.txt; then echo MATCH; '
            "else echo NOMATCH; fi\n"
        ),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "NOMATCH", proc.stdout
