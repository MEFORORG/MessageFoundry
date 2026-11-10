# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# The hvtest payload entry for the DPAPI reboot spike (vault BACKLOG #3411). The hvtest runner runs
# this inside REVTEST01 as its local administrator; dpapi_reboot_spike.ps1 beside it holds the
# breaker, the rig and the judge, and its header says what this route can and cannot measure.
# From MEFORDEV01, with a copy of this folder as the payload (results land inside it):
#   pwsh -NoProfile -File <vault>\scripts\testing\hvtest\Invoke-HvTest.ps1 -Vm REVTEST01 -Checkpoint post-move-mefor-lab-2026-10-17 -Payload <copy of this folder>
& (Join-Path $PSScriptRoot 'dpapi_reboot_spike.ps1') -Mode Payload -OutDir $env:HVTEST_RESULTS
exit $LASTEXITCODE
