# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# Spike S-1: start the browser app on 127.0.0.1 with samples/config as the workspace.
# The backend runs only the interpreter named here (no PATH fallback); see steps-lens-service-impl.ts.
param(
    [string]$Workspace,
    [int]$Port = 3030
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Workspace) { $Workspace = Join-Path $repo 'samples\config' }
$env:MF_SPIKE_PYTHON = Join-Path $repo '.venv\Scripts\python.exe'
$env:MF_SPIKE_REPO = $repo
Set-Location (Join-Path $repo 'theia-spike\browser-app')
npx theia start $Workspace --hostname 127.0.0.1 --port $Port
