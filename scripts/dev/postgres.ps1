# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Run the gated Postgres store test suite against a local PostgreSQL.

.DESCRIPTION
    Sets the MEFOR_* connection environment the gated tests need (tests/test_postgres_store.py
    skips unless MEFOR_TEST_POSTGRES is set) and runs them through the project venv.

    Assumes a PostgreSQL is reachable at the given host/port with the given database already
    created (see the install checklist / docs). The PostgreSQL must serve TLS: the store refuses
    encrypt=false at every posture, and MEFOR_ALLOW_INSECURE_TLS does not lift that (owner ruling
    2026-11-14, vault BACKLOG #3533 item 2). Pass -RootCert with the CA (or self-signed
    certificate) the server's certificate chains to, or trust it machine-wide.
    scripts\ci\db-tls-cert.sh makes a throwaway localhost certificate.

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
    [string]$RootCert = "",  # [store].ssl_root_cert: a CA bundle the server's certificate chains to
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
$env:MEFOR_STORE_SCHEMA_MANAGEMENT = "auto"   # #305: the test suites build their own schema
$env:MEFOR_STORE_SERVER = $DbServer
$env:MEFOR_STORE_PORT = "$Port"
$env:MEFOR_STORE_DATABASE = $Database
$env:MEFOR_STORE_USERNAME = $Username
$env:MEFOR_STORE_PASSWORD = $Password
# Verified TLS: set both keys, so a weakened value left in this shell is not inherited, since
# nothing permits a weakened store hop.
$env:MEFOR_STORE_ENCRYPT = "true"
$env:MEFOR_STORE_TRUST_SERVER_CERTIFICATE = "false"
if ($RootCert) { $env:MEFOR_STORE_SSL_ROOT_CERT = $RootCert }

Write-Host "Running Postgres store tests against $Username@${DbServer}:$Port/$Database ..." -ForegroundColor Cyan
if ($Full) {
    & $py -m pytest -q
}
else {
    & $py -m pytest -q "tests/test_postgres_store.py"
}
exit $LASTEXITCODE
