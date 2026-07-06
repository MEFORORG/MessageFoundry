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

    NOTE: the SQL Server backend is EXPERIMENTAL. The parity tests (enqueue / claim /
    deliver / auth) run, but the staged ingress->routed->outbound pipeline is not yet
    implemented on this backend (BACKLOG #1), so there are no staged-pipeline tests
    here yet - unlike the Postgres suite.

    Loopback DEV convenience: sets trust_server_certificate=true + MEFOR_ALLOW_INSECURE_TLS=1
    so the store's weakened-TLS guard permits the local self-signed connection. Do NOT
    use these settings against a real/remote server.

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
$env:MEFOR_STORE_SERVER = $DbServer
$env:MEFOR_STORE_PORT = "$Port"
$env:MEFOR_STORE_DATABASE = $Database
$env:MEFOR_STORE_AUTH = "sql"
$env:MEFOR_STORE_USERNAME = $Username
$env:MEFOR_STORE_PASSWORD = $Password
$env:MEFOR_STORE_TRUST_SERVER_CERTIFICATE = "true"   # local self-signed cert...
$env:MEFOR_ALLOW_INSECURE_TLS = "1"                  # ...so the weakened-TLS guard permits it (dev/test only)

Write-Host "Running SQL Server store tests against $Username@${DbServer}:$Port/$Database ..." -ForegroundColor Cyan
if ($Full) {
    & $py -m pytest -q
}
else {
    & $py -m pytest -q "tests/test_sqlserver_store.py"
}
exit $LASTEXITCODE
