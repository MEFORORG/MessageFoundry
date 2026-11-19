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

# This script drives Accept, not Run, which serves a fixed pipe name forever. So it pins, as text, that Run
# reaches WaitForConnection only through Accept and goes back to accepting when Accept returns false.
$text = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'PipeServer.cs')
if ($text -notmatch 'if \(!Accept\(pipe\)\)\s*\{\s*continue;\s*\}') { throw 'PipeServer.Run no longer continues when Accept returns false' }
if (([regex]::Matches($text, 'WaitForConnection\(')).Count -ne 1) { throw 'WaitForConnection is called outside PipeServer.Accept' }

# Log writes to Console.Out, so capture it to check the drop is logged.
$logged = [System.IO.StringWriter]::new()
$stdout = [Console]::Out

$name = 'mefor-net-helper-test-' + [guid]::NewGuid().ToString('N')
$pipe = [System.IO.Pipes.NamedPipeServerStream]::new($name, [System.IO.Pipes.PipeDirection]::InOut, 1,
    [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]'Asynchronous, FirstPipeInstance')
try {
    $early = [System.IO.Pipes.NamedPipeClientStream]::new('.', $name, [System.IO.Pipes.PipeDirection]::InOut)
    $early.Connect(5000)
    $early.Dispose()

    # Without the fix, the WaitForConnection here threw "The pipe is being closed."
    [Console]::SetOut($logged)
    try { $first = $accept.Invoke($null, @($pipe)) } finally { [Console]::SetOut($stdout) }
    if ($first -ne $false) { throw "the accept after an early close returned '$first', not False" }
    if ($logged.ToString() -notmatch 'WARN outcome=dropped reason="caller closed before it was accepted') {
        throw "the early close was not logged: '$logged'"
    }

    # Without a disconnect the instance stays closing and every later accept fails the same way.
    $next = [System.IO.Pipes.NamedPipeClientStream]::new('.', $name, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        # Accept runs on the thread pool so that a regression fails here, bounded, instead of blocking forever.
        $accepting = [System.Threading.Tasks.Task]::Run([Func[bool]][Delegate]::CreateDelegate([Func[bool]], $pipe, $accept))
        $connecting = $next.ConnectAsync(5000)
        if (-not $accepting.Wait(10000)) { throw 'the next caller was not accepted within 10 seconds' }
        if ($accepting.Result -ne $true -or -not $pipe.IsConnected) {
            throw "the next caller was not accepted: Accept returned '$($accepting.Result)', IsConnected is $($pipe.IsConnected)"
        }
        if (-not $connecting.Wait(5000)) { throw 'the next caller did not finish connecting' }
    } finally {
        $next.Dispose()
    }
} finally {
    $pipe.Dispose()
}

Write-Host 'an early close was logged and dropped, and the same instance accepted the next caller'
