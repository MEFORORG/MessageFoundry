# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#
# Regression test for BACKLOG #5974: a caller that connects and closes before the helper's accept runs must not
# stop the helper, and the same pipe instance must then accept the next caller.
#
# PipeServer.Accept explains the failure. This script makes it happen on purpose rather than by racing the
# binary for it: it compiles the helper's own sources
# with Add-Type, so no SDK and no administrator token are needed, and drives PipeServer.Accept on a pipe of
# its own, under a name no helper uses. The net-helper workflow runs it on Windows.
#
# Usage: pwsh -NoProfile -File net-helper/tests/accept-dropped-caller.ps1

$ErrorActionPreference = 'Stop'

$sources = Get-ChildItem -LiteralPath (Split-Path -Parent $PSScriptRoot) -Filter *.cs | ForEach-Object FullName
$assembly = (Add-Type -Path $sources -PassThru)[0].Assembly
$server = $assembly.GetType('MessageFoundry.NetHelper.PipeServer', $true)
$accept = $server.GetMethod('Accept', [System.Reflection.BindingFlags]'NonPublic, Static')
if (-not $accept) { throw 'PipeServer.Accept was not found' }

$name = 'mefor-net-helper-test-' + [guid]::NewGuid().ToString('N')
$pipe = [System.IO.Pipes.NamedPipeServerStream]::new($name, [System.IO.Pipes.PipeDirection]::InOut, 1,
    [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]'Asynchronous, FirstPipeInstance')
try {
    $early = [System.IO.Pipes.NamedPipeClientStream]::new('.', $name, [System.IO.Pipes.PipeDirection]::InOut)
    $early.Connect(5000)
    $early.Dispose()

    # Before the fix this call threw "The pipe is being closed."
    $first = $accept.Invoke($null, @($pipe))
    if ($first -ne $false) { throw "the accept after an early close returned '$first', not False" }

    # Without a disconnect the instance stays closing and every later accept fails the same way.
    $next = [System.IO.Pipes.NamedPipeClientStream]::new('.', $name, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $connecting = $next.ConnectAsync(5000)
        $second = $accept.Invoke($null, @($pipe))
        if ($second -ne $true -or -not $pipe.IsConnected) {
            throw "the next caller was not accepted: Accept returned '$second', IsConnected is $($pipe.IsConnected)"
        }
        if (-not $connecting.Wait(5000)) { throw 'the next caller did not finish connecting' }
    } finally {
        $next.Dispose()
    }
} finally {
    $pipe.Dispose()
}

Write-Host 'an early close was logged and dropped, and the same instance accepted the next caller'
