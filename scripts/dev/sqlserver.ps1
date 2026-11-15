# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Run the gated SQL Server store test suite against a local SQL Server.

.DESCRIPTION
    Sets the MEFOR_* connection environment the gated tests need
    (tests/test_sqlserver_store.py skips unless MEFOR_TEST_SQLSERVER is set) and runs
    them through the project venv.

    Requires: a local SQL Server reachable at the given host/port with the given
    database created; the 'sqlserver' extra installed ('uv pip install aioodbc'); and
    the Microsoft ODBC Driver 18 for SQL Server installed at the OS level (a separate
    component from the database engine - winget 'Microsoft.msodbcsql.18' or the MS
    download page).

    No local SQL Server? scripts\dev\sqlserver-docker.ps1 stands one up in Docker
    (SQL Server Evaluation edition) and creates the MessageFoundry database, ready for
    this script. The ODBC Driver 18 + aioodbc above still install on the host.

    NOTE: the SQL Server backend is a production server-DB backend. The full staged
    ingress->routed->outbound pipeline plus ADR-0013 response capture are implemented and
    CI-verified against a real SQL Server (2022 and 2025) by the gated service-container
    job - on par with the Postgres suite.

    The store refuses trust_server_certificate=true and encrypt=false at every posture, and
    MEFOR_ALLOW_INSECURE_TLS does not lift that (owner ruling 2026-11-14, vault BACKLOG #3533
    item 2). Pass -RootCert with the server's own certificate to pin it (Encrypt=strict, SQL
    Server 2022 or later), or trust the server's certificate machine-wide.

.EXAMPLE
    scripts\dev\sqlserver.ps1 -Password 'Your_sa_password'
    # run just the SQL Server store suite against sa@127.0.0.1:1433/MessageFoundry

.EXAMPLE
    $env:MEFOR_STORE_PASSWORD = 'Your_sa_password'; scripts\dev\sqlserver.ps1 -Full
    # password from env; run the WHOLE pytest suite with SQL Server as the active backend
#>
[CmdletBinding()]
param(
    [string]$DbServer = "127.0.0.1",
    [int]$Port = 1433,
    [string]$Database = "MessageFoundry",
    [string]$Username = "sa",
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
        Justification = 'Dev/test helper only: the local SQL Server sa password fed into MEFOR_STORE_PASSWORD for the gated suite. A real secret comes from env in production; SecureString here would just defeat the convenience.')]
    [string]$Password = $env:MEFOR_STORE_PASSWORD,
    [string]$RootCert = "",  # [store].ssl_root_cert: the server's own certificate, pinned
    [switch]$Full  # run the entire pytest suite, not only tests/test_sqlserver_store.py
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Password)) {
    throw "No SQL Server password. Pass -Password '<sa password>' or set the MEFOR_STORE_PASSWORD env var first."
}

# repo root = parent of scripts\ = parent of this script's dir (scripts\dev)
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$py = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    throw "venv python not found at $py - create the .venv and 'uv pip install aioodbc' (the sqlserver extra) first"
}

$env:MEFOR_TEST_SQLSERVER = "1"
$env:MEFOR_STORE_BACKEND = "sqlserver"
$env:MEFOR_STORE_SCHEMA_MANAGEMENT = "auto"   # #305: the test suites build their own schema
$env:MEFOR_STORE_SERVER = $DbServer
$env:MEFOR_STORE_PORT = "$Port"
$env:MEFOR_STORE_DATABASE = $Database
$env:MEFOR_STORE_AUTH = "sql"
$env:MEFOR_STORE_USERNAME = $Username
$env:MEFOR_STORE_PASSWORD = $Password
# Verified TLS: set both keys, so a weakened value left in this shell is not inherited, since
# nothing permits a weakened store hop. Clear a pin left from an earlier run when -RootCert is empty.
$env:MEFOR_STORE_ENCRYPT = "true"
$env:MEFOR_STORE_TRUST_SERVER_CERTIFICATE = "false"
if ($RootCert) { $env:MEFOR_STORE_SSL_ROOT_CERT = $RootCert } else { Remove-Item Env:MEFOR_STORE_SSL_ROOT_CERT -ErrorAction SilentlyContinue }

Write-Host "Running SQL Server store tests against $Username@${DbServer}:$Port/$Database ..." -ForegroundColor Cyan
if ($Full) {
    & $py -m pytest -q
}
else {
    & $py -m pytest -q "tests/test_sqlserver_store.py"
}
exit $LASTEXITCODE
