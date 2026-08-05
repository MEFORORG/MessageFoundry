<#
.SYNOPSIS
    The worktree -> mailbox key function. ONE definition, dot-sourced by everything that needs it.

.DESCRIPTION
    Dot-source this; it defines a function and does nothing on its own.

        . "$PSScriptRoot\mail-key.ps1"
        $key = ConvertTo-BoxKey -Path $cwd

    ONE COPY ON PURPOSE, for the same reason session-registry.ps1 states for the liveness fence. The
    sender (scripts/coord/mail.ps1) and the drain (scripts/hooks/mail-drain.ps1) must compute the SAME
    key from the same path or mail is written to a box nobody reads -- and that failure is silent on
    both ends: the sender sees a queued message, the recipient sees an empty inbox, and nothing
    anywhere reports a mismatch. Two copies of this function would drift, and the copy that drifts is
    the one nobody is testing.

    NORMALISATION IS NOT COSMETIC. Three measured facts make it load-bearing:
      - VS Code records a LOWERCASE drive letter for the workspace path; the Desktop app records an
        uppercase one. The same physical worktree therefore arrives spelled two ways, and a
        case-sensitive key splits it into two boxes that never see each other's mail.
      - A path may or may not carry a trailing separator depending on who produced it.
      - Forward and back slashes both occur, because some producers are git and some are Windows.

    INJECTIVITY IS THE POINT OF THE HASH. A readable slug alone is not enough: two different worktree
    paths can sanitise to the same slug, and the failure mode is one worktree silently reading
    another's mail. The hash is computed over the NORMALISED path and is what carries injectivity. The
    slug exists only so a human can tell boxes apart in a directory listing.
#>

function ConvertTo-BoxKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $norm = $Path.Trim().TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\'

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($norm)) }
    finally { $sha.Dispose() }
    $short = -join ($bytes[0..3] | ForEach-Object { $_.ToString('x2') })

    $slug = (Split-Path $norm -Leaf) -replace '[^a-zA-Z0-9._-]', '-'
    if ($slug.Length -gt 40) { $slug = $slug.Substring(0, 40) }
    if (-not $slug) { $slug = 'root' }

    return "$slug-$short"
}
