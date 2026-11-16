#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#
# Claim-path benchmark driver (vault BACKLOG #4915 step 1), run by benchmark.yml's claim-path profile
# inside a server-store job, after that job has started its database container and served TLS from it.
#
#   bash scripts/bench/claim_path.sh <postgres|sqlserver>
#
# Environment: CLAIM_PATH_BEFORE and CLAIM_PATH_AFTER, two full 40-character commit SHAs;
# CLAIM_PATH_ROUNDS, default 2; the job's MEFOR_STORE_* connection settings. The script sets
# MEFOR_STORE_ENCRYPTION_KEY itself, to a key it mints for the run.
#
# Each commit is extracted with git archive into its own directory, stamped with its SHA, and installed
# editable into its own venv against its own constraints.lock, so each side runs on the dependencies
# it shipped with (the before commit still needed python-hl7, which the branch no longer installs).
# Each gets its own database, so neither commit's schema is applied over the other's. The rounds
# alternate the order (before then after, then after then before), and the count must be even so
# each order runs equally often. Reports are metrics only and go to out/claimpath/, and the
# before/after table, with each side's discarded claims, goes to the job summary.
set -euo pipefail

backend="${1:?usage: claim_path.sh <postgres|sqlserver>}"
case "$backend" in postgres|sqlserver) ;; *) echo "::error::unknown backend: $backend"; exit 1 ;; esac
rounds="${CLAIM_PATH_ROUNDS:-2}"
if [[ ! "$rounds" =~ ^[1-9][0-9]?$ ]] || (( rounds % 2 )); then
  echo "::error::CLAIM_PATH_ROUNDS must be an even number from 2 to 98, not $rounds"
  exit 1
fi
extra="$backend"
[[ "$backend" == sqlserver ]] || extra=postgres
out="out/claimpath"
mkdir -p "$out"

declare -A sha root db py
sha[before]="${CLAIM_PATH_BEFORE:-}"
sha[after]="${CLAIM_PATH_AFTER:-}"
for label in before after; do
  if [[ ! "${sha[$label]}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "::error::the $label commit must be a full 40-character lowercase SHA"
    exit 1
  fi
  git fetch --no-tags --depth=1 origin "${sha[$label]}"
  root[$label]="$RUNNER_TEMP/claimpath-$label"
  rm -rf "${root[$label]}"
  mkdir -p "${root[$label]}"
  git archive "${sha[$label]}" | tar -x -C "${root[$label]}"
  echo "${sha[$label]}" > "${root[$label]}/CLAIM_PATH_COMMIT"
  python -m venv "${root[$label]}/.venv"
  py[$label]="${root[$label]}/.venv/bin/python"
  "${py[$label]}" -m pip install --quiet --upgrade pip
  "${py[$label]}" -m pip install --quiet --constraint "${root[$label]}/constraints.lock" -e "${root[$label]}[$extra]"
done

if [[ "$backend" == postgres ]]; then
  db[before]=mf_claim_before
  db[after]=mf_claim_after
  python -I - "${db[before]}" "${db[after]}" <<'PY'
import asyncio
import os
import sys

import asyncpg


async def main(names: list[str]) -> None:
    conn = await asyncpg.connect(
        host=os.environ["MEFOR_STORE_SERVER"],
        port=int(os.environ["MEFOR_STORE_PORT"]),
        user=os.environ["MEFOR_STORE_USERNAME"],
        password=os.environ["MEFOR_STORE_PASSWORD"],
        database="postgres",
    )
    try:
        for name in names:
            if not await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", name):
                # The names are this script's two constants, never input.
                await conn.execute(f"CREATE DATABASE {name}")
    finally:
        await conn.close()


asyncio.run(main(sys.argv[1:]))
PY
else
  db[before]=MfClaimBefore
  db[after]=MfClaimAfter
  for label in before after; do
    /opt/mssql-tools18/bin/sqlcmd -b -S localhost -U "$MEFOR_STORE_USERNAME" -P "$MEFOR_STORE_PASSWORD" -C \
      -Q "IF DB_ID('${db[$label]}') IS NULL CREATE DATABASE ${db[$label]}; ALTER DATABASE ${db[$label]} SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE; ALTER DATABASE ${db[$label]} SET ALLOW_SNAPSHOT_ISOLATION ON;"
  done
fi

# measure opens the store through open_store, which refuses to start a keyless audit chain, and in
# the job each bench database is new (a fresh service container), so its chain is empty. Mint a
# throwaway AES-256 store key at runtime, never a committed literal, once for the whole run so every
# round reopens the same keyed chain. Both sides run keyed, and each report records it. A server that
# kept the bench databases from an earlier run holds a chain keyed under that run's key, so drop
# them before a rerun there. Assigned before export: `export VAR="$(...)"` returns export's status and
# hides a failed mint.
store_key="$(python -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())')"
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then echo "::add-mask::$store_key"; fi
export MEFOR_STORE_ENCRYPTION_KEY="$store_key"

for round in $(seq 1 "$rounds"); do
  if (( round % 2 )); then order=(before after); else order=(after before); fi
  for label in "${order[@]}"; do
    MEFOR_STORE_DATABASE="${db[$label]}" "${py[$label]}" -I -X disable-remote-debug scripts/bench/claim_path.py measure \
      --code-root "${root[$label]}" --backend "$backend" --label "$label" --commit "${sha[$label]}" \
      --round "$round" --out "$out/$backend-$label-r$round.json"
  done
done

# The table reaches the job summary even when compare refuses a scenario, so the refusal is readable
# there; compare's exit status is still the step's.
status=0
python -I scripts/bench/claim_path.py compare "$out"/"$backend"-*.json > "$out/summary-$backend.md" || status=$?
cat "$out/summary-$backend.md"
cat "$out/summary-$backend.md" >> "$GITHUB_STEP_SUMMARY"
exit "$status"
