<#
.SYNOPSIS
    Stand up (or tear down) a local SQL Server Evaluation edition in Docker for the
    gated SQL Server store suite.

.DESCRIPTION
    Brings up a SQL Server container (default image: 2022; pass -Image for 2025 — see the
    EXAMPLES). Evaluation edition is the image default; MSSQL_PID=Evaluation makes it explicit.
    Waits for it to accept connections, then creates the MessageFoundry database. Idempotent:
    re-running starts an existing stopped container and only creates the database if it is missing.

    This stands up exactly what scripts\dev\sqlserver.ps1 expects: sa @ 127.0.0.1:1433
    with the MessageFoundry database. After it succeeds, run:
        scripts\dev\sqlserver.ps1 -Password '<the same password>'

    The default SA password matches the one CI uses for its SQL Server service container
    (and the gitleaks allowlist), so there is one canonical dev/test password.

    Runs under Windows PowerShell 5.1 and PowerShell 7: every docker/sqlcmd call goes
    through Invoke-Docker, which relaxes $ErrorActionPreference so a native command's
    stderr on an EXPECTED failure (e.g. the not-ready-yet probes in the readiness loop)
    is not promoted to a terminating error on 5.1 - the exit code is the sole signal.

    HOST PREREQUISITES (NOT provided by the container - the Python store connects via
    aioodbc/pyodbc on the host):
      * Microsoft ODBC Driver 18 for SQL Server  (winget install Microsoft.msodbcsql.18)
      * the 'sqlserver' extra in the venv          (uv pip install aioodbc)

    DEV ONLY: the paired test helper bypasses the weakened-TLS guard for this loopback,
    self-signed instance. Never point these settings at a real/remote server.

.EXAMPLE
    scripts\dev\sqlserver-docker.ps1
    # bring up the container with the default dev password and create the database

.EXAMPLE
    scripts\dev\sqlserver-docker.ps1 -Password '<your-sa-password>'
    # bring it up with a chosen sa password (use -Down -PurgeData first if a data volume
    # already exists - SQL Server honors the SA password only on the volume's first init)

.EXAMPLE
    scripts\dev\sqlserver-docker.ps1 -Image mcr.microsoft.com/mssql/server:2025-latest `
        -ContainerName mefor-mssql-2025 -Volume mefor-mssql-2025-data -Port 1434
    # run SQL Server 2025 (17.x) alongside the default 2022 container (distinct name/volume/port so
    # both coexist), then point the suite at it: scripts\dev\sqlserver.ps1 -Password '<pw>' -Port 1434
    # NB: SQL Server 2025 requires an AVX-capable CPU.

.EXAMPLE
    scripts\dev\sqlserver-docker.ps1 -Down -PurgeData
    # stop + remove the container AND delete its data volume
#>
[CmdletBinding()]
param(
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
        Justification = 'Dev/test helper only: the local SQL Server sa password for a loopback container. A real secret comes from env in production; SecureString here would just defeat the convenience.')]
    [string]$Password = $(if ($env:MEFOR_STORE_PASSWORD) { $env:MEFOR_STORE_PASSWORD } else { 'Str0ng_P@ssw0rd!' }),
    [int]$Port = 1433,
    [string]$Database = "MessageFoundry",
    [string]$ContainerName = "mefor-mssql",
    [string]$Volume = "mefor-mssql-data",
    [string]$Image = "mcr.microsoft.com/mssql/server:2022-latest",
    [switch]$Down,        # stop + remove the container, then exit
    [switch]$PurgeData    # with -Down, also remove the data volume
)

$ErrorActionPreference = "Stop"

# sqlcmd lives at this path in both the 2022 and 2025 images; Driver 18 requires -C to trust the self-signed cert.
$sqlcmd = "/opt/mssql-tools18/bin/sqlcmd"

# Captured stdout+stderr of the last Invoke-Docker call, for diagnostics on failure.
$script:NativeOutput = ""

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "docker not found on PATH. Install Docker Desktop and ensure it is running."
}

# Run `docker <args>` without letting its stderr abort us. Under $ErrorActionPreference='Stop',
# Windows PowerShell 5.1 promotes a native command's stderr write to a TERMINATING error, which
# would kill the readiness loop on its (expected) not-ready-yet probes. Relax the preference for
# the call, capture all output for diagnostics, and return the exit code as the only signal.
function Invoke-Docker {
    param([Parameter(Mandatory)][string[]]$DockerArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $script:NativeOutput = (& docker @DockerArgs 2>&1 | Out-String).Trim()
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prev
    }
}

function Test-ContainerExists {
    Invoke-Docker @("ps", "-a", "--filter", "name=^/$ContainerName$", "--format", "{{.Names}}") | Out-Null
    return [bool]$script:NativeOutput
}

function Test-ContainerRunning {
    Invoke-Docker @("ps", "--filter", "name=^/$ContainerName$", "--format", "{{.Names}}") | Out-Null
    return [bool]$script:NativeOutput
}

# --- teardown ---------------------------------------------------------------
if ($Down) {
    if (Test-ContainerExists) {
        Write-Host "Removing container '$ContainerName' ..." -ForegroundColor Cyan
        if ((Invoke-Docker @("rm", "-f", $ContainerName)) -ne 0) {
            throw "docker rm failed:`n$script:NativeOutput"
        }
    }
    else {
        Write-Host "No container '$ContainerName' to remove." -ForegroundColor DarkGray
    }
    if ($PurgeData) {
        Write-Host "Removing data volume '$Volume' ..." -ForegroundColor Cyan
        # Tolerate an already-absent volume: a missing volume exits non-zero ("no such volume"),
        # which is the benign case this teardown is meant to swallow - not an error.
        if ((Invoke-Docker @("volume", "rm", $Volume)) -ne 0) {
            Write-Host "  (volume '$Volume' was not present)" -ForegroundColor DarkGray
        }
    }
    exit 0
}

# --- bring up ---------------------------------------------------------------
if (Test-ContainerExists) {
    if (Test-ContainerRunning) {
        Write-Host "Container '$ContainerName' already running." -ForegroundColor DarkGray
    }
    else {
        Write-Host "Starting existing container '$ContainerName' ..." -ForegroundColor Cyan
        if ((Invoke-Docker @("start", $ContainerName)) -ne 0) {
            throw "docker start failed:`n$script:NativeOutput"
        }
    }
}
else {
    Write-Host "Creating SQL Server container '$ContainerName' from $Image ..." -ForegroundColor Cyan
    $runArgs = @(
        "run",
        "-e", "ACCEPT_EULA=Y",
        "-e", "MSSQL_SA_PASSWORD=$Password",
        "-e", "MSSQL_PID=Evaluation",
        "-p", "${Port}:1433",
        "--name", $ContainerName,
        "--restart", "unless-stopped",
        "-v", "${Volume}:/var/opt/mssql",
        "-d", $Image
    )
    if ((Invoke-Docker $runArgs) -ne 0) {
        throw "docker run failed (is port $Port already in use, or is the Docker daemon down?):`n$script:NativeOutput"
    }
}

# --- wait for readiness -----------------------------------------------------
Write-Host "Waiting for SQL Server to accept connections ..." -ForegroundColor Cyan
$deadline = 90  # seconds
$ready = $false
$probe = @("exec", $ContainerName, $sqlcmd, "-S", "localhost", "-U", "sa", "-P", $Password, "-C", "-Q", "SELECT 1")
for ($i = 0; $i -lt $deadline; $i++) {
    if ((Invoke-Docker $probe) -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) {
    throw ("SQL Server did not become ready within $deadline s.`n" +
        "  - Check 'docker logs $ContainerName'.`n" +
        "  - If you changed -Password since the volume '$Volume' was first created, the original`n" +
        "    SA password persists (SQL Server honors MSSQL_SA_PASSWORD only on first init).`n" +
        "    Re-run with -Down -PurgeData to reset the volume, then bring it up again.`n" +
        "Last docker output:`n$script:NativeOutput")
}

# --- create the database (idempotent) --------------------------------------
Write-Host "Ensuring database '$Database' exists ..." -ForegroundColor Cyan
$create = @("exec", $ContainerName, $sqlcmd, "-S", "localhost", "-U", "sa", "-P", $Password, "-C",
    "-Q", "IF DB_ID('$Database') IS NULL CREATE DATABASE [$Database];")
if ((Invoke-Docker $create) -ne 0) {
    throw "Failed to create/verify database '$Database':`n$script:NativeOutput"
}

# --- next steps -------------------------------------------------------------
$hint = "    scripts\dev\sqlserver.ps1 -Password '$Password'"
if ($Port -ne 1433) { $hint += " -Port $Port" }
if ($Database -ne "MessageFoundry") { $hint += " -Database '$Database'" }

Write-Host ""
Write-Host "SQL Server is up: sa@127.0.0.1:$Port/$Database" -ForegroundColor Green
Write-Host "Run the gated store suite with:" -ForegroundColor Green
Write-Host $hint -ForegroundColor Green
