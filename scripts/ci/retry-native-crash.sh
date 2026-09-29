#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# Re-run a command ONLY when it dies from a native crash (segfault / abort), never on a
# normal non-zero exit.
#
# WHY THIS EXISTS: pyodbc 5.3.0 intermittently SEGFAULTS in its C parameter-binding path
# (GetParameterInfo -> SQLDescribeParam -> PrepareAndBind) when run under Python 3.14
# against the SQL Server 2025 service container. This is an UPSTREAM interpreter-level
# crash, not our code:
#   * mkleehammer/pyodbc#1459 tracks the same py3.14 MSSQL param/TVP-binding segfault; the
#     attempted fix (PR #1452) did not resolve it and it is still open.
#   * 5.3.0 is the NEWEST pyodbc AND the first release to support py3.14, so there is
#     nothing to upgrade to, and no pre-5.3.0 pyodbc has py3.14 wheels to pin back to.
#   * The SQL Server 2022 leg passes on identical pyodbc — 2025's SQLDescribeParam response
#     is what happens to trip the latent binding bug — so it is container/version-specific.
# A segfault kills the interpreter, so pytest-rerunfailures (an in-process rerun) cannot
# recover it; the whole step must re-run at the PROCESS level, which is what this wrapper
# does.
#
# WHY THIS IS SAFE (does not mask real regressions): we retry ONLY on the native-crash exit
# codes below. A genuine test failure exits 1 and is re-raised immediately, never retried.
# CORRECTED 2026-09-28 (BACKLOG #2049): this paragraph said our own Python cannot cause a native
# segfault. It can. The store's cancel path, pure Python, closed ODBC handles under a running
# statement, and the driver then crashed. So a retried crash CAN be a regression of ours; the
# section below on crash classes says how that class is kept visible. Each retry emits a visible
# ::warning:: (grep CI logs for "NATIVE CRASH" to track the flake frequency against #1459).
#
# REMOVING THIS WRAPPER IS NOT A BLANKET DELETION -- READ THE CALLER SET FIRST (BACKLOG #1260).
# #1459 covers the DATABASE legs. It says nothing about any other caller, and this note previously
# named one call site ("the throughput-invariant step") when ci.yml had TEN.
#
# THE DISCRIMINATOR IS IN THE WORKFLOW, NOT IN A MEMORY: any caller setting
# RETRY_NATIVE_CRASH_CAUSE="" has declared that ITS crash cause is NOT established as the pyodbc
# class. A fix to #1459 therefore does not license removing the wrapper from that leg -- doing so
# would silently strip its crash handling on the strength of an upstream fix that does not address
# it. Today the engine test suite is such a caller.
#
# SO: when #1459 ships and pyproject's pyodbc floor moves, remove the wrapper from the pyodbc
# callers, and decide each opted-out caller SEPARATELY on its own evidence.
# `tests/test_ci_retry_native_crash.py` fails if an opted-out caller exists and this note stops
# saying so, because the whole defect is a future reader deleting one line in good faith.
#
# THE ATTRIBUTION IS PER-CALLER, AND THAT IS THE POINT (BACKLOG #1260). The pyodbc class above is
# ESTABLISHED for the database legs and is NOT established anywhere else. A wrapper that names it
# unconditionally would print a cause it has not measured onto every leg it is ever added to -- a
# true observation (a native crash happened) carrying an invented mechanism, which is the harder
# error to catch because the part a reader checks is true. So callers where the class is NOT known
# set RETRY_NATIVE_CRASH_CAUSE="" and the message says so in words.
#
# THE DATABASE LEGS HAVE MORE THAN ONE CRASH CLASS, AND THIS WRAPPER CANNOT TELL THEM APART
# (BACKLOG #2049). The default attribution used to name #1459 alone. A second class is known: the
# SQL Server store's cancel path freed ODBC handles while the cancelled statement still ran, and the
# statement then read its result metadata from freed memory (SQLDescribeColW, SQLColAttributeW), not
# from the parameter-binding path #1459 is about. Naming only #1459 filed that crash under an upstream
# bug. Both are exit 139 and nothing the wrapper sees separates them, so the default clause names
# both and says so; the faulthandler dump is where a reader tells them apart.
# tests/test_sqlserver_store.py also runs a cancel scenario in a child process, so a crash of that
# class fails its own test as an assertion (exit 1), which this wrapper never retries.
#
# Usage: scripts/ci/retry-native-crash.sh <cmd> [args...]
# Env:   RETRY_NATIVE_CRASH_ATTEMPTS (default 3)
#        RETRY_NATIVE_CRASH_CAUSE    attribution clause; default names the two classes known on the
#                                    database legs. Set to "" on any leg where neither is proven.
set -uo pipefail

attempts="${RETRY_NATIVE_CRASH_ATTEMPTS:-3}"

# The default serves the nine database-leg call sites, so only a caller where neither class is
# established has to opt out. It names both known classes and does not pick one.
default_cause=" -- a database-leg crash class: the pyodbc py3.14 parameter-binding segfault (mkleehammer/pyodbc#1459) or a handle freed under a running statement on the store cancel path (BACKLOG #2049); this wrapper cannot tell them apart, read the faulthandler dump"
cause="${RETRY_NATIVE_CRASH_CAUSE-$default_cause}"
if [ -z "$cause" ]; then
  # DELIBERATELY NAMES NO CLASS, NOT EVEN TO WARN AGAINST ONE. An earlier draft said "do not
  # assume the pyodbc class" and its own test caught it: that puts the token in the annotation,
  # so a log grep for pyodbc matches the ONE leg where the class is explicitly not established.
  cause=" -- CAUSE NOT ESTABLISHED for this leg; do not infer the database-leg crash class"
fi

# A process killed by signal N exits with 128+N. 139 = 128+SIGSEGV(11) (the observed
# segfault); 134 = 128+SIGABRT(6) (the param/TVP path can abort() with a core dump instead).
is_native_crash() {
  [ "$1" -eq 139 ] || [ "$1" -eq 134 ]
}

rc=0
for n in $(seq 1 "$attempts"); do
  "$@"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    exit 0
  fi
  if ! is_native_crash "$rc"; then
    echo "::error::Command failed with exit ${rc} (not a native crash) — not retrying."
    exit "$rc"
  fi
  if [ "$n" -lt "$attempts" ]; then
      echo "::warning::NATIVE CRASH (exit ${rc}) on attempt ${n}/${attempts}${cause}; retrying."
  fi
done

echo "::error::NATIVE CRASH persisted: still crashing after ${attempts} attempts (exit ${rc})${cause}."
exit "$rc"
