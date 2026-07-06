<#
.SYNOPSIS
    Run the gated Postgres store test suite against a local PostgreSQL.

.DESCRIPTION
    Sets the MEFOR_* connection environment the gated tests need (tests/test_postgres_store.py
    skips unless MEFOR_TEST_POSTGRES is set) and runs them through the project venv.

    Assumes a PostgreSQL is reachable at the given host/port with the given database already
    created (see the install checklist / docs). This is a loopback, no-TLS DEV convenience: it
    sets MEFOR_ALLOW_INSECURE_TLS=1 so the store's weakened-TLS guard permits the plaintext
    local connection. Do NOT use these settings against a real/remote server.

.EXAMPLE
    scripts\dev\postgres.ps1
    # run just the Postgres store suite with the default local connection (postgres/mefor @ 127.0.0.1:5432/messagefoundry)

.EXAMPLE
    scripts\dev\postgres.ps1 -Password s3cret -Full
    # custom password; run the WHOLE pytest suite (with Postgres as the active store backend)
#>
[CmdletBinding()]
param(
    [string]$DbServer = "127.0.0.1",
    [int]$Port = 5432,
    [string]$Database = "messagefoundry",
    [string]$Username = "postgres",
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
        Justification = 'Dev/test helper only: a non-secret loopback Postgres dev password fed into MEFOR_STORE_PASSWORD for the gated suite. A real secret comes from env in production; SecureString here would just defeat the convenience.')]
    [string]$Password = "mefor",
    [switch]$Full  # run the entire pytest suite, not only tests/test_postgres_store.py
)

$ErrorActionPreference = "Stop"

# repo root = parent of scripts\ = parent of this script's dir (scripts\dev)
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$py = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    throw "venv python not found at $py - create the .venv and 'uv pip install asyncpg' (or 'uv sync --extra postgres') first"
}

$env:MEFOR_TEST_POSTGRES = "1"
$env:MEFOR_STORE_BACKEND = "postgres"
$env:MEFOR_STORE_SERVER = $DbServer
$env:MEFOR_STORE_PORT = "$Port"
$env:MEFOR_STORE_DATABASE = $Database
$env:MEFOR_STORE_USERNAME = $Username
$env:MEFOR_STORE_PASSWORD = $Password
$env:MEFOR_STORE_ENCRYPT = "false"        # local loopback: no TLS...
$env:MEFOR_ALLOW_INSECURE_TLS = "1"       # ...so the weakened-TLS guard permits it (dev/test only)

Write-Host "Running Postgres store tests against $Username@${DbServer}:$Port/$Database ..." -ForegroundColor Cyan
if ($Full) {
    & $py -m pytest -q
}
else {
    & $py -m pytest -q "tests/test_postgres_store.py"
}
exit $LASTEXITCODE
