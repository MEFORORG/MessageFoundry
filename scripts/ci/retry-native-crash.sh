#!/usr/bin/env bash
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
# Our own Python cannot cause a native segfault — a real logic regression surfaces as a
# pytest assertion (exit 1), so this wrapper can never hide one. Each retry emits a visible
# ::warning:: (grep CI logs for "Native crash" to track the flake frequency against #1459).
#
# REMOVE THIS WRAPPER once #1459 ships a fix and pyproject's pyodbc floor moves to the fixed
# release (the throughput-invariant step in .github/workflows/ci.yml calls this).
#
# Usage: scripts/ci/retry-native-crash.sh <cmd> [args...]
# Env:   RETRY_NATIVE_CRASH_ATTEMPTS (default 3)
set -uo pipefail

attempts="${RETRY_NATIVE_CRASH_ATTEMPTS:-3}"

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
    echo "::warning::Native crash (exit ${rc}) on attempt ${n}/${attempts} — likely the pyodbc py3.14 parameter-binding segfault (mkleehammer/pyodbc#1459); retrying."
  fi
done

echo "::error::Command still crashing after ${attempts} attempts (exit ${rc}); see mkleehammer/pyodbc#1459."
exit "$rc"
