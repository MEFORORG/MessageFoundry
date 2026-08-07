# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the ADR 0144 ``handler-security`` advisory lint (``_check_handler_security``).

The check is a stdlib-``ast`` scan over the config-dir Router/Handler modules with four rule
families (phi-to-log, unsafe-db-lookup, ambient-authority, impure-transform). It is **advisory**
(never blocks) and a documented compensating control for ASVS 15.2.5 / 15.2.4. Snippets are only
``ast.parse``-d, never imported/executed, so undefined names (``handler``/``Send``/``db_lookup``)
are fine.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.checks import (
    CheckResult,
    _check_handler_security,
    _shipped_dep_import_roots,
)

# (name, rule_id, expect_flagged, snippet) — the calibrated matrix from the ADR 0144 spec. Each rule
# has at least one positive (should flag) and one negative (must not flag) case.
CASES: list[tuple[str, str, bool, str]] = [
    (
        "phi_pos_log_info_bare_msg",
        "phi-to-log",
        True,
        """
        import logging
        log = logging.getLogger(__name__)

        @handler("h")
        def h(msg):
            log.info("got %s", msg)
            return Send("OB", msg)
        """,
    ),
    (
        "phi_pos_print_raw",
        "phi-to-log",
        True,
        """
        @handler("h")
        def h(msg):
            print(f"body={msg.raw}")
            return Send("OB", msg)
        """,
    ),
    (
        "phi_neg_fstring_to_send_not_log",
        "phi-to-log",
        False,
        """
        from html import escape

        @handler("h")
        def h(msg):
            body = f"<m>{escape(msg.encode())}</m>"
            return Send("OB", body)
        """,
    ),
    (
        "phi_neg_debug_and_constant",
        "phi-to-log",
        False,
        """
        import logging
        log = logging.getLogger(__name__)

        @handler("h")
        def h(msg):
            log.info("handler started")
            log.debug(msg)
            return Send("OB", msg)
        """,
    ),
    (
        "db_pos_fstring_statement",
        "unsafe-db-lookup",
        True,
        """
        @handler("h")
        def h(msg):
            rows = db_lookup("MPI", f"select * from p where mrn = '{msg['PID-3.1']}'")
            return Send("OB", msg)
        """,
    ),
    (
        "fhir_pos_flat_query_fstring",
        "unsafe-db-lookup",
        True,
        """
        @handler("h")
        def h(msg):
            res = fhir_lookup("epic", f"Patient?identifier=MRN|{msg['PID-3.1']}")
            return Send("OB", msg)
        """,
    ),
    (
        "db_neg_literal_stmt_params",
        "unsafe-db-lookup",
        False,
        """
        @handler("h")
        def h(msg):
            rows = db_lookup("MPI", "select npi from provider where mrn = :mrn", {"mrn": msg["PID-3.1"]})
            return Send("OB", msg)
        """,
    ),
    (
        "fhir_neg_structured_params",
        "unsafe-db-lookup",
        False,
        """
        @handler("h")
        def h(msg):
            res = fhir_lookup("epic", "Patient", {"identifier": f"MRN|{msg['PID-3.1']}"})
            return Send("OB", msg)
        """,
    ),
    (
        "amb_pos_subprocess",
        "ambient-authority",
        True,
        """
        import subprocess

        @handler("h")
        def h(msg):
            subprocess.run(["logger", msg.encode()])
            return Send("OB", msg)
        """,
    ),
    (
        "amb_pos_open_write",
        "ambient-authority",
        True,
        """
        @handler("h")
        def h(msg):
            open("/tmp/out.hl7", "w").write(msg.encode())
            return Send("OB", msg)
        """,
    ),
    (
        # __import__ intentionally omitted (it is a genuine ambient-authority hit; the spec's
        # calibration flagged that keeping it here would make this negative case flag).
        "amb_neg_pure_stdlib_and_reads",
        "ambient-authority",
        False,
        """
        import hashlib

        @handler("h")
        def h(msg):
            digest = hashlib.sha256(msg.raw_bytes).hexdigest()
            row = db_lookup("MPI", "select 1", {"id": msg["PID-3.1"]})
            return Send("OB", msg)
        """,
    ),
    (
        "impure_pos_time_time_in_handler",
        "impure-transform",
        True,
        """
        import time

        @handler("h")
        def h(msg):
            stamp = time.time()
            return Send("OB", msg)
        """,
    ),
    (
        "impure_pos_uuid4_in_handler",
        "impure-transform",
        True,
        """
        import uuid

        @handler("h")
        def h(msg):
            cid = uuid.uuid4().hex
            return Send("OB", msg)
        """,
    ),
    (
        "impure_neg_strftime_gmtime_in_handler",
        "impure-transform",
        False,
        """
        import time

        @handler("h")
        def h(msg):
            ts = time.strftime("%Y%m%d", time.gmtime(0))
            return Send("OB", msg)
        """,
    ),
    (
        "impure_neg_time_time_in_undecorated_helper",
        "impure-transform",
        False,
        """
        import time

        def build(pdf, ingest_time=None):
            return time.strftime("%Y%m%d%H%M%S", time.gmtime(ingest_time if ingest_time is not None else time.time()))
        """,
    ),
    # --- review-driven additions ---------------------------------------------------------------
    # @router is scanned by the decorated-scope rules too (not just @handler).
    (
        "router_pos_phi_to_log",
        "phi-to-log",
        True,
        """
        @router("r")
        def r(msg):
            print(msg.raw)
            return "h"
        """,
    ),
    (
        "router_pos_impure",
        "impure-transform",
        True,
        """
        import time

        @router("r")
        def r(msg):
            stamp = time.time()
            return "h"
        """,
    ),
    (
        "router_neg_clean",
        "phi-to-log",
        False,
        """
        @router("r")
        def r(msg):
            return "h" if msg else "drop"
        """,
    ),
    # unsafe-db-lookup: dotted-call form and keyword statement=/query= form.
    (
        "db_pos_dotted_call",
        "unsafe-db-lookup",
        True,
        """
        @handler("h")
        def h(msg):
            mf.db_lookup("MPI", f"select {msg['PID-3.1']}")
            return Send("OB", msg)
        """,
    ),
    (
        "db_pos_keyword_statement",
        "unsafe-db-lookup",
        True,
        """
        @handler("h")
        def h(msg):
            db_lookup("MPI", statement=f"select {msg['PID-3.1']}")
            return Send("OB", msg)
        """,
    ),
    (
        "fhir_pos_keyword_query",
        "unsafe-db-lookup",
        True,
        """
        @handler("h")
        def h(msg):
            fhir_lookup("epic", query=f"Patient?x={msg['PID-3.1']}")
            return Send("OB", msg)
        """,
    ),
    # whole-file rules fire in an UNDECORATED helper / at module level, not only in a @handler body.
    (
        "amb_pos_undecorated_helper",
        "ambient-authority",
        True,
        """
        import subprocess

        def _helper(cmd):
            subprocess.run(cmd)
        """,
    ),
    (
        "db_pos_undecorated_helper",
        "unsafe-db-lookup",
        True,
        """
        def _enrich(msg):
            return db_lookup("MPI", f"select {msg['PID-3.1']}")
        """,
    ),
    # phi-to-log discriminates on the message symbol: an INFO log of a non-message local is clean.
    (
        "phi_neg_non_message_local",
        "phi-to-log",
        False,
        """
        import logging
        log = logging.getLogger(__name__)

        @handler("h")
        def h(msg):
            n = 5
            log.info("count=%s", n)
            return []
        """,
    ),
    # MUST-FIX: an attribute-level call on a NON-logger receiver (FHIR/ACK builder, warnings) is not a
    # log sink, even when it references the message.
    (
        "phi_neg_builder_error_receiver",
        "phi-to-log",
        False,
        """
        @handler("h")
        def h(msg):
            outcome = OperationOutcome.construct()
            outcome.error(f"Patient {msg['PID-3.1']} not found")
            return Send("OB", outcome.json())
        """,
    ),
    (
        "phi_neg_warnings_warn",
        "phi-to-log",
        False,
        """
        import warnings

        @handler("h")
        def h(msg):
            warnings.warn(f"no OBX in {msg.control_id}")
            return Send("OB", msg)
        """,
    ),
    (
        "phi_pos_fatal_and_extra",
        "phi-to-log",
        True,
        """
        import logging
        log = logging.getLogger(__name__)

        @handler("h")
        def h(msg):
            log.info("processed", extra={"mrn": msg["PID-3.1"]})
            log.fatal(msg.raw)
            return Send("OB", msg)
        """,
    ),
    # ambient-authority: pathlib mutators + attribute .open("w"), shutil, socket egress vs read-only.
    (
        "amb_pos_pathlib_unlink",
        "ambient-authority",
        True,
        """
        from pathlib import Path

        @handler("h")
        def h(msg):
            Path("/tmp/scratch.hl7").unlink()
            return Send("OB", msg)
        """,
    ),
    (
        "amb_pos_pathlib_open_write",
        "ambient-authority",
        True,
        """
        from pathlib import Path

        @handler("h")
        def h(msg):
            Path("/tmp/out.hl7").open("w")
            return Send("OB", msg)
        """,
    ),
    (
        "amb_pos_shutil_copy",
        "ambient-authority",
        True,
        """
        import shutil

        @handler("h")
        def h(msg):
            shutil.copy("/tmp/a", "/tmp/b")
            return Send("OB", msg)
        """,
    ),
    (
        "amb_pos_socket_connect",
        "ambient-authority",
        True,
        """
        import socket

        @handler("h")
        def h(msg):
            socket.create_connection(("host", 1))
            return Send("OB", msg)
        """,
    ),
    (
        "amb_neg_socket_readonly_hostname",
        "ambient-authority",
        False,
        """
        import socket

        @handler("h")
        def h(msg):
            msg.set("MSH-3", socket.gethostname())
            return Send("OB", msg)
        """,
    ),
    # unsafe-db-lookup constant-folds a pure-literal concat (no injected value) but still nudges on a
    # trusted-identifier concat (the documented advisory FP).
    (
        "db_neg_constant_only_concat",
        "unsafe-db-lookup",
        False,
        """
        @handler("h")
        def h(msg):
            db_lookup("db", "select a " + "from b")
            return Send("OB", msg)
        """,
    ),
    (
        "db_pos_identifier_concat_documented_fp",
        "unsafe-db-lookup",
        True,
        """
        TABLE = "provider_v2"

        @handler("h")
        def h(msg):
            db_lookup("clarity", "select npi from " + TABLE + " where mrn = :mrn", {"mrn": msg["PID-3.1"]})
            return Send("OB", msg)
        """,
    ),
    # impure-transform is gated on a real imported module — a local shadowing `secrets` is clean.
    (
        "impure_neg_secrets_local_shadow",
        "impure-transform",
        False,
        """
        @handler("h")
        def h(msg):
            secrets = load_partner_config(msg)
            token = secrets.get("token")
            return Send("OB", msg)
        """,
    ),
    (
        "impure_pos_secrets_imported",
        "impure-transform",
        True,
        """
        import secrets

        @handler("h")
        def h(msg):
            tok = secrets.token_hex()
            return Send("OB", msg)
        """,
    ),
    (
        "impure_pos_time_localtime_noarg",
        "impure-transform",
        True,
        """
        import time

        @handler("h")
        def h(msg):
            now = time.localtime()
            return Send("OB", msg)
        """,
    ),
    # scope leak fix: a wall-clock default arg is import-time, not per-message impurity — not flagged.
    (
        "impure_neg_default_arg_is_import_time",
        "impure-transform",
        False,
        """
        import time

        @handler("h")
        def h(msg, _t=time.time()):
            return Send("OB", msg)
        """,
    ),
    # --- Increment 2: unvetted-import (supply-chain / slopsquat) ---------------------------------
    (
        "unvetted_pos_third_party",
        "unvetted-import",
        True,
        """
        import reqwest

        @handler("h")
        def h(msg):
            return Send("OB", msg)
        """,
    ),
    (
        "unvetted_neg_stdlib",
        "unvetted-import",
        False,
        """
        import json
        import hashlib
        from html import escape

        @handler("h")
        def h(msg):
            return Send("OB", msg)
        """,
    ),
    (
        "unvetted_neg_first_party",
        "unvetted-import",
        False,
        """
        from messagefoundry import Send, handler

        @handler("h")
        def h(msg):
            return Send("OB", msg)
        """,
    ),
    (
        "unvetted_neg_shipped_dep",
        "unvetted-import",
        False,
        """
        import hl7

        @handler("h")
        def h(msg):
            return Send("OB", msg)
        """,
    ),
    (
        "unvetted_pos_from_import",
        "unvetted-import",
        True,
        """
        from reqwest import get

        @handler("h")
        def h(msg):
            return Send("OB", msg)
        """,
    ),
    (
        "unvetted_pos_dotted",
        "unvetted-import",
        True,
        """
        import reqwest.client

        @handler("h")
        def h(msg):
            return Send("OB", msg)
        """,
    ),
    (
        "unvetted_neg_type_checking_guarded",
        "unvetted-import",
        False,
        """
        from __future__ import annotations
        from typing import TYPE_CHECKING

        if TYPE_CHECKING:
            import pandas

        @handler("h")
        def h(msg):
            return Send("OB", msg)
        """,
    ),
    # --- BACKLOG #337: constant getattr indirection is spliced in _dotted_call_name -------------
    # A constant getattr(mod, "name") indirection now resolves (getattr(os, "system") -> os.system),
    # so it is flagged like the bare dotted call; a dynamic getattr(os, name) stays unresolved.
    (
        "amb_pos_getattr_os_system",
        "ambient-authority",
        True,
        """
        import os

        @handler("h")
        def h(msg):
            getattr(os, "system")("id")
            return Send("OB", msg)
        """,
    ),
    (
        "amb_neg_getattr_dynamic_attr",
        "ambient-authority",
        False,
        """
        import os

        @handler("h")
        def h(msg):
            name = msg["PID-3.1"]
            getattr(os, name)("x")
            return Send("OB", msg)
        """,
    ),
    # The splice feeds impure-transform too (shared _dotted_call_name), still import-gated on `time`.
    (
        "impure_pos_getattr_time_time",
        "impure-transform",
        True,
        """
        import time

        @handler("h")
        def h(msg):
            stamp = getattr(time, "time")()
            return Send("OB", msg)
        """,
    ),
    # --- BACKLOG #337: phi-to-log widened to undecorated `_*` transform helpers -----------------
    # The decompose-by-role convention steers PHI handling into undecorated helpers, so phi-to-log
    # must reach them; it still keys on the first positional parameter as the message symbol.
    (
        "phi_pos_undecorated_helper_logs_msg",
        "phi-to-log",
        True,
        """
        import logging
        log = logging.getLogger(__name__)

        def apply(msg):
            log.info("transforming %s", msg.raw)
        """,
    ),
]


def _run(tmp_path: Path, snippet: str) -> CheckResult:
    (tmp_path / "feed.py").write_text(textwrap.dedent(snippet), encoding="utf-8")
    return _check_handler_security(tmp_path)


@pytest.mark.parametrize(
    ("name", "rule_id", "expect_flagged", "snippet"), CASES, ids=[c[0] for c in CASES]
)
def test_handler_security_matrix(
    tmp_path: Path, name: str, rule_id: str, expect_flagged: bool, snippet: str
) -> None:
    result = _run(tmp_path, snippet)
    if expect_flagged:
        assert not result.skipped, f"{name}: expected a finding, got skipped ({result.detail!r})"
        # tag is `[rule]` or `[rule:detail]` (unvetted-import carries the module), so match the prefix.
        assert f"[{rule_id}" in result.detail, (
            f"{name}: expected a {rule_id} finding in {result.detail!r}"
        )
    else:
        # A negative case must produce no finding at all → the check skips with 'no findings'.
        assert result.skipped, f"{name}: expected no finding, got {result.detail!r}"


def test_advisory_is_never_blocking(tmp_path: Path) -> None:
    # Even a flagged file is advisory: required=False and blocking=False, ok=True with findings —
    # exactly like _check_raise_fstring, so the gate's "0 iff no required check failed" is preserved.
    result = _run(
        tmp_path,
        """
        import subprocess

        @handler("h")
        def h(msg):
            subprocess.run(["x"])
            return Send("OB", msg)
        """,
    )
    assert not result.skipped
    assert result.required is False
    assert result.blocking is False
    assert result.ok is True


def test_broken_module_is_skipped_not_crashed(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    result = _check_handler_security(tmp_path)  # a SyntaxError file is validate's job
    assert result.skipped


def test_not_a_config_dir(tmp_path: Path) -> None:
    single = tmp_path / "x.py"
    single.write_text("x = 1\n", encoding="utf-8")
    result = _check_handler_security(single)  # a file, not a dir
    assert result.skipped
    assert "not a config dir" in result.detail


def test_multiple_findings_are_all_reported(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        """
        import subprocess

        @handler("h")
        def h(msg):
            print(msg.raw)
            rows = db_lookup("db", f"select {msg['PID-3.1']}")
            subprocess.run(["x"])
            return Send("OB", msg)
        """,
    )
    assert not result.skipped
    assert "[phi-to-log]" in result.detail
    assert "[unsafe-db-lookup]" in result.detail
    assert "[ambient-authority]" in result.detail


def test_handler_with_no_positional_param_does_not_crash(tmp_path: Path) -> None:
    # A decorated function with no positional param (msg_sym is None) must not IndexError — that would
    # turn an advisory (never-block) check into a hard crash of the whole commit/CI gate.
    result = _run(
        tmp_path,
        """
        @handler("h")
        def h():
            print("start")
            return []
        """,
    )
    assert result.skipped


def test_nested_decorated_function_is_counted_once(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        """
        import time

        @router("r")
        def r(msg):
            @handler("h")
            def inner(m):
                return time.time()
            return "h"
        """,
    )
    # The inner time.time() is scanned under `inner` exactly once (no outer/inner double-count).
    assert result.detail.count("[impure-transform]") == 1


# One representative snippet per distinct deny-list code path, so a typo/deletion in a rule set is
# caught — for a security deny-list, completeness is the value.
DENYLIST_COVERAGE: list[tuple[str, str, str]] = [
    ("ambient-authority", "eval_bare", 'def f():\n    return eval("1")\n'),
    ("ambient-authority", "exec_bare", 'def f():\n    exec("x=1")\n'),
    ("ambient-authority", "dunder_import", 'def f():\n    __import__("os")\n'),
    ("ambient-authority", "os_system", 'import os\n\ndef f():\n    os.system("id")\n'),
    ("ambient-authority", "os_execv", 'import os\n\ndef f():\n    os.execv("/bin/sh", [])\n'),
    (
        "ambient-authority",
        "os_posix_spawn",
        'import os\n\ndef f():\n    os.posix_spawn("/bin/sh", [], {})\n',
    ),
    (
        "ambient-authority",
        "urllib_request",
        'import urllib.request\n\ndef f():\n    urllib.request.urlopen("http://x")\n',
    ),
    (
        "ambient-authority",
        "http_client",
        'import http.client\n\ndef f():\n    http.client.HTTPConnection("x")\n',
    ),
    (
        "ambient-authority",
        "importlib",
        'import importlib\n\ndef f():\n    importlib.import_module("os")\n',
    ),
    ("ambient-authority", "pickle", 'import pickle\n\ndef f():\n    pickle.loads(b"")\n'),
    (
        "impure-transform",
        "random",
        'import random\n\n@handler("h")\ndef h(msg):\n    random.random()\n    return []\n',
    ),
    (
        "impure-transform",
        "uuid1",
        'import uuid\n\n@handler("h")\ndef h(msg):\n    uuid.uuid1()\n    return []\n',
    ),
    (
        "impure-transform",
        "datetime_now",
        '@handler("h")\ndef h(msg):\n    datetime.now()\n    return []\n',
    ),
    (
        "impure-transform",
        "os_urandom",
        'import os\n\n@handler("h")\ndef h(msg):\n    os.urandom(8)\n    return []\n',
    ),
]


@pytest.mark.parametrize(
    ("rule_id", "name", "snippet"), DENYLIST_COVERAGE, ids=[c[1] for c in DENYLIST_COVERAGE]
)
def test_denylist_member_flags(tmp_path: Path, rule_id: str, name: str, snippet: str) -> None:
    (tmp_path / "feed.py").write_text(snippet, encoding="utf-8")
    result = _check_handler_security(tmp_path)
    assert not result.skipped, f"{name}: expected a {rule_id} finding"
    assert f"[{rule_id}]" in result.detail, f"{name}: {result.detail!r}"


def test_sibling_config_module_import_is_vetted(tmp_path: Path) -> None:
    # `from _sibling import x` where _sibling.py is a config-dir module is first-party, not third-party.
    (tmp_path / "_sibling.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "feed.py").write_text(
        'from _sibling import VALUE\n\n@handler("h")\ndef h(msg):\n    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    result = _check_handler_security(tmp_path)
    assert result.skipped, result.detail


def test_shipped_dependency_roots_are_install_independent() -> None:
    # Guards the importlib.metadata mapping AND install-independence: a declared installed core dep
    # (hl7) maps to its real import name, and a declared-but-uninstalled optional-extra dep (pydicom,
    # under [dicom]) is vetted via a dist-name guess — so a lazy `import pydicom` is not a false
    # positive regardless of which extras are installed on the box running `check`.
    roots = _shipped_dep_import_roots()
    assert "hl7" in roots
    assert "pydicom" in roots


def test_lazy_shipped_extra_import_is_not_flagged_in_strict_mode(tmp_path: Path) -> None:
    # The MUST-FIX repro: a code-first DICOM Handler lazily imports pydicom (ADR 0025). It must not be
    # flagged/blocked even under --strict-handler-security, regardless of whether [dicom] is installed.
    (tmp_path / "feed.py").write_text(
        "from messagefoundry import Send, handler\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        "    import pydicom\n"
        '    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    assert _check_handler_security(tmp_path, strict=True).skipped


def test_block_mode_makes_a_finding_blocking(tmp_path: Path) -> None:
    (tmp_path / "feed.py").write_text(
        'import subprocess\n\n@handler("h")\ndef h(msg):\n    subprocess.run(["x"])\n    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    advisory = _check_handler_security(tmp_path)  # default: never blocks
    strict = _check_handler_security(tmp_path, strict=True)  # --strict-handler-security
    assert advisory.required is False and advisory.blocking is False
    assert strict.required is True and strict.ok is False and strict.blocking is True


def test_block_mode_on_clean_config_passes(tmp_path: Path) -> None:
    (tmp_path / "feed.py").write_text(
        'from messagefoundry import Send, handler\n\n@handler("h")\ndef h(msg):\n    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    result = _check_handler_security(tmp_path, strict=True)
    assert result.skipped and result.blocking is False  # no findings -> passes even in strict mode


def test_block_mode_through_run_checks(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    (tmp_path / "feed.py").write_text(
        "from messagefoundry import Send, handler\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        "    import pandas\n"  # operator-added, unvetted
        '    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    assert run_checks(tmp_path, run_lint=False).ok is True  # advisory never blocks the gate
    assert run_checks(tmp_path, run_lint=False, strict_handler_security=True).ok is False


def test_cli_strict_handler_security_exit_code(tmp_path: Path) -> None:
    import subprocess
    import sys

    (tmp_path / "feed.py").write_text(
        "from messagefoundry import Send, handler\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        "    import pandas\n"
        '    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    base = [sys.executable, "-m", "messagefoundry", "check", "--config", str(tmp_path), "--no-lint"]
    advisory = subprocess.run(base, capture_output=True, text=True)
    strict = subprocess.run([*base, "--strict-handler-security"], capture_output=True, text=True)
    assert advisory.returncode == 0, advisory.stdout + advisory.stderr
    assert strict.returncode == 1, strict.stdout + strict.stderr


# --- Increment 3: operator allowlist (--handler-security-allow) --------------------------------
_PANDAS_BODY_IMPORT = (
    "from messagefoundry import Send, handler\n\n"
    '@handler("h")\n'
    "def h(msg):\n"
    "    import pandas\n"  # operator-added, unvetted
    '    return Send("OB", msg)\n'
)


def test_unvetted_import_allow_vets_root(tmp_path: Path) -> None:
    (tmp_path / "feed.py").write_text(_PANDAS_BODY_IMPORT, encoding="utf-8")
    assert _check_handler_security(tmp_path, strict=True).blocking is True
    allowed = _check_handler_security(tmp_path, strict=True, allow=frozenset({"pandas"}))
    assert allowed.skipped and allowed.blocking is False


def test_allow_threads_through_run_checks(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    (tmp_path / "feed.py").write_text(_PANDAS_BODY_IMPORT, encoding="utf-8")
    assert run_checks(tmp_path, run_lint=False, strict_handler_security=True).ok is False
    assert (
        run_checks(
            tmp_path,
            run_lint=False,
            strict_handler_security=True,
            handler_security_allow=frozenset({"pandas"}),
        ).ok
        is True
    )


def test_allow_only_affects_named_root(tmp_path: Path) -> None:
    # ast-parse only (module-top imports never execute), so pandas/numpy need not be installed.
    (tmp_path / "feed.py").write_text(
        "from messagefoundry import Send, handler\nimport pandas\nimport numpy\n\n"
        '@handler("h")\ndef h(msg):\n    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    result = _check_handler_security(tmp_path, strict=True, allow=frozenset({"pandas"}))
    assert result.blocking is True  # numpy (un-allowed) still flags
    assert "numpy" in result.detail and "pandas" not in result.detail


def test_allow_does_not_suppress_other_rules(tmp_path: Path) -> None:
    (tmp_path / "feed.py").write_text(
        "from messagefoundry import Send, handler\nimport pandas\nimport subprocess\n\n"
        '@handler("h")\ndef h(msg):\n    subprocess.run(["x"])\n    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    result = _check_handler_security(tmp_path, strict=True, allow=frozenset({"pandas"}))
    assert result.blocking is True  # allow scopes to unvetted-import; ambient-authority survives
    assert "[ambient-authority]" in result.detail


def test_cli_handler_security_allow_exit_code(tmp_path: Path) -> None:
    import subprocess
    import sys

    (tmp_path / "feed.py").write_text(_PANDAS_BODY_IMPORT, encoding="utf-8")
    base = [
        sys.executable,
        "-m",
        "messagefoundry",
        "check",
        "--config",
        str(tmp_path),
        "--no-lint",
        "--strict-handler-security",
    ]
    blocked = subprocess.run(base, capture_output=True, text=True)
    allowed = subprocess.run(
        [*base, "--handler-security-allow", "pandas"], capture_output=True, text=True
    )
    assert blocked.returncode == 1, blocked.stdout + blocked.stderr
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr


# --- Increment 3 review fixes -----------------------------------------------------------------
def test_phi_to_log_exempts_non_phi_msh_accessor(tmp_path: Path) -> None:
    # msg.control_id / msg.message_type are HL7 MSH envelope metadata (non-PHI) — logging them is the
    # recommended safe pattern and must not flag.
    (tmp_path / "feed.py").write_text(
        "import logging\nfrom messagefoundry import Send, handler\n"
        "log = logging.getLogger(__name__)\n\n"
        '@handler("h")\ndef h(msg):\n'
        '    log.info("processed %s", msg.control_id)\n'
        '    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    assert _check_handler_security(tmp_path).skipped


def test_phi_to_log_flags_generic_log_method(tmp_path: Path) -> None:
    # log.log(level, body) is a full-body INFO+ sink like log.info.
    (tmp_path / "feed.py").write_text(
        "import logging\nfrom messagefoundry import Send, handler\n"
        "log = logging.getLogger(__name__)\n\n"
        '@handler("h")\ndef h(msg):\n    log.log(logging.INFO, msg.raw)\n    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    result = _check_handler_security(tmp_path)
    assert not result.skipped and "[phi-to-log]" in result.detail


def test_allow_root_still_flags_its_ambient_use(tmp_path: Path) -> None:
    # allow vets the IMPORT (unvetted-import) but the whole-file ambient-authority scan still flags
    # httpx.get() — allow scopes to unvetted-import only (the documented invariant).
    (tmp_path / "feed.py").write_text(
        "from messagefoundry import Send, handler\nimport httpx\n\n"
        '@handler("h")\ndef h(msg):\n    httpx.get("https://x")\n    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    result = _check_handler_security(tmp_path, strict=True, allow=frozenset({"httpx"}))
    assert result.blocking is True
    assert "[ambient-authority]" in result.detail
    assert "unvetted-import:httpx" not in result.detail


# --- BACKLOG #337: widening phi-to-log must NOT widen impure-transform, and must still discriminate.
def test_widened_phi_to_log_does_not_widen_impure_transform(tmp_path: Path) -> None:
    # The exact shipped `_pdf_mdm_transforms.py` ingest-time wall-clock fallback, in an UNDECORATED
    # helper. phi-to-log now reaches undecorated helpers (#337), but impure-transform stays
    # decorated-scope, so this timestamp fallback must not be flagged — it has no PHI log sink and the
    # impure rule must not widen (the trade ADR 0144 records; widening it would red the samples gate).
    (tmp_path / "_pdf_mdm.py").write_text(
        "import time\n\n"
        "def build(pdf, ingest_time=None):\n"
        "    return time.strftime(\n"
        '        "%Y%m%d%H%M%S",\n'
        "        time.gmtime(ingest_time if ingest_time is not None else time.time()),\n"
        "    )\n",
        encoding="utf-8",
    )
    assert _check_handler_security(tmp_path).skipped


def test_phi_to_log_undecorated_helper_non_message_local_is_clean(tmp_path: Path) -> None:
    # The widened phi-to-log still keys on the message symbol (first positional param): an undecorated
    # helper that logs a NON-message local (count) must not flag — proving the rule discriminates and
    # is not "any INFO+ log call in any function".
    (tmp_path / "_helper.py").write_text(
        "import logging\n"
        "log = logging.getLogger(__name__)\n\n"
        "def build(msg):\n"
        "    count = 5\n"
        '    log.info("c=%s", count)\n',
        encoding="utf-8",
    )
    assert _check_handler_security(tmp_path).skipped


def test_real_samples_config_is_clean() -> None:
    # False-positive calibration: the real shipped Router/Handler samples must not trip the lint.
    samples = Path(__file__).resolve().parents[1] / "samples" / "config"
    result = _check_handler_security(samples)
    assert result.skipped, f"handler-security tripped on real samples: {result.detail!r}"
