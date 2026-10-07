# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#
# Spike S-3 (ADR 0208): build the UNSIGNED per-user Windows installer for the Electron app.
#
#   pwsh -NoProfile -File theia-spike\scripts\build-installer.ps1
#
# What it does, in order:
#   1. Downloads the official Windows embeddable Python from python.org (one pinned URL) into a
#      cache, and refuses it unless its SHA-256 matches the pinned value. A cached copy is checked too.
#   2. Builds a wheel of this repository's messagefoundry, with no dependencies.
#   3. Installs the engine's base runtime dependencies into the embedded runtime, hash-checked. The
#      list comes from uv.lock (the source requirements.lock is exported from) without extras, and
#      every pin is checked against requirements.lock, so the two cannot drift apart silently.
#   4. Stages the Steps webview assets and a copy of samples/config, and writes runtime-pin.json.
#   5. Builds the Theia Electron app and packages it with electron-builder (NSIS, perMachine false).
#
# Prerequisites: npm install in theia-spike/, the repo .venv (scripts\worktree\ensure-venv.ps1), and uv.
# Outputs (all git-ignored): electron-app\build\ and electron-app\dist\. Nothing is signed.
#Requires -Version 7
[CmdletBinding()]
param(
    # Re-stage the payload but skip the Theia build, when only the Python side changed.
    [switch]$SkipTheiaBuild
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The ONLY Python source. Same minor as requires-python (>=3.14); 3.14.8 was the latest 3.14 release
# on 2026-10-07. The hash is the sha256_sum python.org publishes for this file in its release API
# (https://www.python.org/api/v2/downloads/release_file/?release=1126), and was re-computed locally.
$PythonVersion = '3.14.8'
$PythonUrl = 'https://www.python.org/ftp/python/3.14.8/python-3.14.8-embed-amd64.zip'
$PythonSha256 = 'a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310'

$spike = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repo = (Resolve-Path (Join-Path $spike '..')).Path
$app = Join-Path $spike 'electron-app'
$build = Join-Path $app 'build'
$cache = Join-Path $build 'cache'
$payload = Join-Path $build 'payload'
$runtime = Join-Path $payload 'python'
$sitePackages = Join-Path $runtime 'Lib\site-packages'
$hostPython = Join-Path $repo '.venv\Scripts\python.exe'

function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe exited $LASTEXITCODE" }
}

if (-not (Test-Path -LiteralPath $hostPython -PathType Leaf)) {
    throw "No repo virtual environment at $hostPython. Run scripts\worktree\ensure-venv.ps1 first."
}
# pip runs in the host venv but installs into the embedded runtime, so the two must agree on the
# binary-wheel tag: CPython 3.14, GIL build, 64-bit x86. A 3.15, 3.14t or ARM64 venv would put
# wheels into the bundle that the embedded interpreter cannot load.
$hostTag = & $hostPython -c "import sys, sysconfig, platform; print(sys.implementation.name, '%d.%d' % sys.version_info[:2], bool(sysconfig.get_config_var('Py_GIL_DISABLED')), platform.machine())"
if ($hostTag -ne 'cpython 3.14 False AMD64') {
    throw "The host venv must be CPython 3.14 (GIL build) on AMD64 to match the bundled runtime; it reports '$hostTag'."
}

# --- 1. The embeddable Python, from python.org only, hash-checked every run ------------------------
New-Item -ItemType Directory -Force -Path $cache | Out-Null
$zip = Join-Path $cache ([System.IO.Path]::GetFileName(([uri]$PythonUrl).AbsolutePath))
if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) {
    Write-Host "Downloading $PythonUrl"
    $partial = "$zip.partial"
    Invoke-WebRequest -Uri $PythonUrl -OutFile $partial -UseBasicParsing
    Move-Item -LiteralPath $partial -Destination $zip -Force
}
$actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $PythonSha256) {
    Remove-Item -LiteralPath $zip -Force
    throw "SHA-256 mismatch for $zip`: expected $PythonSha256, got $actual. The file was deleted."
}
Write-Host "Python $PythonVersion embeddable verified: $actual"

if (Test-Path -LiteralPath $payload) { Remove-Item -LiteralPath $payload -Recurse -Force }
New-Item -ItemType Directory -Force -Path $runtime, $sitePackages | Out-Null
Expand-Archive -LiteralPath $zip -DestinationPath $runtime

# The ._pth file fixes sys.path exactly: the stdlib zip, the runtime folder, and site-packages.
# `import site` stays off, so no .pth file in site-packages can add a path either.
$pth = Get-ChildItem -LiteralPath $runtime -Filter 'python3*._pth' | Select-Object -First 1
if (-not $pth) { throw "No python3*._pth in the embeddable package; the layout has changed." }
$stdlibZip = [System.IO.Path]::ChangeExtension($pth.Name, '.zip')
Set-Content -LiteralPath $pth.FullName -Encoding ascii -Value @($stdlibZip, '.', 'Lib\site-packages')

# --- 2. The engine wheel, built from this checkout ----------------------------------------------
# pip builds in an isolated environment and fetches the build backend (hatchling) from PyPI without a
# hash check. The wheel's own SHA-256 goes into runtime-pin.json so the output is at least recorded.
# A release build would pin the backend too.
$wheelDir = Join-Path $build 'wheel'
if (Test-Path -LiteralPath $wheelDir) { Remove-Item -LiteralPath $wheelDir -Recurse -Force }
Invoke-Native $hostPython @('-m', 'pip', 'wheel', $repo, '--no-deps', '--wheel-dir', $wheelDir, '--quiet')
$wheel = Get-ChildItem -LiteralPath $wheelDir -Filter 'messagefoundry-*.whl' | Select-Object -First 1
if (-not $wheel) { throw "pip wheel produced no messagefoundry wheel in $wheelDir" }
Write-Host "Engine wheel: $($wheel.Name)"

# --- 3. Base runtime dependencies, hash-checked, cross-checked against requirements.lock ---------
$baseReqs = Join-Path $build 'runtime-requirements.txt'
Push-Location $repo
try {
    Invoke-Native 'uv' @('export', '--frozen', '--no-emit-project', '--no-dev', '--format', 'requirements.txt', '--output-file', $baseReqs, '--quiet')
} finally { Pop-Location }
$lock = Get-Content -LiteralPath (Join-Path $repo 'requirements.lock') -Raw
$pins = Select-String -LiteralPath $baseReqs -Pattern '^([A-Za-z0-9._-]+)==([^\s;\\]+)' | ForEach-Object { $_.Matches[0].Value }
foreach ($pin in $pins) {
    if ($lock -notmatch ('(?m)^' + [regex]::Escape($pin) + '(\s|;|\\|$)')) {
        throw "$pin is not pinned in requirements.lock; re-lock before building."
    }
}
Write-Host "$(@($pins).Count) runtime pins match requirements.lock"

# The host venv runs pip, targeting the embedded runtime's site-packages. Both are CPython 3.14 on
# win_amd64, so the same binary wheels apply; --only-binary keeps any build step off this path.
Invoke-Native $hostPython @('-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', '--no-deps',
    '--require-hashes', '--only-binary=:all:', '--target', $sitePackages, '-r', $baseReqs)
Invoke-Native $hostPython @('-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', '--no-deps',
    '--target', $sitePackages, $wheel.FullName)
# pip writes console-script launchers into bin\ that point at the HOST interpreter. Nothing in the
# app runs them, and a launcher naming a build-machine path does not belong in an installer.
$launchers = Join-Path $sitePackages 'bin'
if (Test-Path -LiteralPath $launchers) { Remove-Item -LiteralPath $launchers -Recurse -Force }

# --- 4. Assets, samples, and the pin file ------------------------------------------------------
$assets = Join-Path $payload 'mfassets'
New-Item -ItemType Directory -Force -Path (Join-Path $assets 'ide\media'), (Join-Path $assets 'ide\src') | Out-Null
Copy-Item -LiteralPath (Join-Path $repo 'ide\media\stepsWebview.js') -Destination (Join-Path $assets 'ide\media')
Copy-Item -LiteralPath (Join-Path $repo 'ide\src\stepsView.ts') -Destination (Join-Path $assets 'ide\src')
New-Item -ItemType Directory -Force -Path (Join-Path $payload 'samples') | Out-Null
Copy-Item -LiteralPath (Join-Path $repo 'samples\config') -Destination (Join-Path $payload 'samples\config') -Recurse
Get-ChildItem -LiteralPath (Join-Path $payload 'samples') -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force

$init = Get-Content -LiteralPath (Join-Path $repo 'messagefoundry\__init__.py') -Raw
if ($init -notmatch '(?m)^__version__\s*=\s*"([^"]+)"') { throw 'Could not read __version__ from messagefoundry/__init__.py' }
$engineVersion = $Matches[1]
[ordered]@{
    minimumEngineVersion = $engineVersion
    pythonVersion        = $PythonVersion
    pythonUrl            = $PythonUrl
    pythonSha256         = $PythonSha256
    engineWheel          = $wheel.Name
    engineWheelSha256    = (Get-FileHash -LiteralPath $wheel.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $app 'runtime-pin.json') -Encoding utf8

# The bundled runtime must run the engine the way the Steps backend does: -I, no PATH, no cwd.
$embedded = Join-Path $runtime 'python.exe'
$reported = & $embedded -I -c 'import messagefoundry,sys; sys.stdout.write(messagefoundry.__version__)'
if ($LASTEXITCODE -ne 0 -or $reported -ne $engineVersion) {
    throw "The bundled runtime reports messagefoundry '$reported', expected $engineVersion"
}
$schema = '' | & $embedded -I -X utf8 -m messagefoundry lens schema --json
if ($LASTEXITCODE -ne 0) { throw 'The bundled runtime could not run `messagefoundry lens schema`.' }
Write-Host "Bundled runtime runs messagefoundry $engineVersion; lens schema returned $($schema.Length) characters"

# --- 5. Theia build and the installer -----------------------------------------------------------
Push-Location $spike
try {
    if (-not $SkipTheiaBuild) {
        Invoke-Native 'npm' @('run', 'build', '--workspace', '@messagefoundry/theia-steps-spike')
        Invoke-Native 'npm' @('run', 'build', '--workspace', 'messagefoundry-theia-spike-electron-app')
    }
    Invoke-Native 'npm' @('run', 'package', '--workspace', 'messagefoundry-theia-spike-electron-app')
} finally { Pop-Location }

$installer = Get-ChildItem -LiteralPath (Join-Path $app 'dist') -Filter '*-unsigned-setup.exe' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $installer) { throw 'electron-builder produced no installer in electron-app\dist' }
$hash = (Get-FileHash -LiteralPath $installer.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$unpacked = Join-Path $app 'dist\win-unpacked'
$unpackedBytes = (Get-ChildItem -LiteralPath $unpacked -Recurse -File | Measure-Object -Property Length -Sum).Sum
Write-Host ''
Write-Host "Installer : $($installer.FullName)"
Write-Host ("Size      : {0:N0} bytes ({1:N1} MiB)" -f $installer.Length, ($installer.Length / 1MB))
Write-Host ("Installed : {0:N0} bytes ({1:N1} MiB) unpacked" -f $unpackedBytes, ($unpackedBytes / 1MB))
Write-Host "SHA-256   : $hash"
Write-Host 'Signed    : no (on purpose; spike S-3 measures the unsigned response)'
