# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
  Does a blob protected with USER-scope DPAPI by a service running as a virtual service account
  (NT SERVICE\<name>) still open after the machine reboots, and after that account's profile is
  unloaded and loaded again? A lab spike: it measures and builds nothing (vault BACKLOG #3411, the
  reboot arm the key-custody draft's spike question 3 names, which engine PR 2462's hosted-runner
  spike left out of scope).

.DESCRIPTION
  LAB ONLY: the test VM REVTEST01 under the Hyper-V host MEFORHV01. Synthetic data only: the only
  value it protects is 32 random bytes it draws itself, and no report holds them, only their SHA-256.

  THE INSTRUMENT. A throwaway service, MeforDpapiReboot, compiled in the guest from the C# below by
  the .NET Framework compiler that ships with Windows, so the VM needs nothing installed. It is
  registered the way scripts/service/install-service.ps1 registers the engine where that matters to
  DPAPI: run as its own virtual account NT SERVICE\MeforDpapiReboot (no password), SID type
  restricted, the one privilege SeChangeNotifyPrivilege, start type Automatic. It is NOT NSSM and
  NOT Python: it calls CryptProtectData with CRYPTPROTECT_UI_FORBIDDEN and no entropy, which is what
  messagefoundry.secrets_dpapi.dpapi_protect(machine_scope=False) passes, and CryptUnprotectData
  with CRYPTPROTECT_UI_FORBIDDEN, as dpapi_unprotect does.

  Before each start the rig names the arm that start answers in work\arm.txt, and the start writes
  one report, report-<arm>.txt, of key=value lines, so a start that writes nothing cannot shift a
  later report onto the wrong arm. The first start
  draws the value and protects it twice, in user scope (the question) and in machine scope (a
  control). Every start then unprotects both and compares with the value, and runs two negative
  controls: a user-scope blob protected by the administrator who installed the service (it must be
  refused, or user scope is not bound to the account), and a copy of its own blob with one byte
  flipped (it must be refused, or the unprotect checks nothing). A machine-scope blob that opens
  shows DPAPI and the file read worked in that process, so a user-scope refusal beside it is a real
  NO and not a broken instrument.

  THE ARMS:
    A1  first start: protect in user scope, unprotect in the same process
    A2  a service restart (the arm PR 2462 already measured on hosted runners)
    A3  a start after the account's profile was seen unloaded (Win32_UserProfile.Loaded)
    A4  after a reboot: the start the SCM makes at boot (start type Automatic)
    A5  after a reboot: a demand start
  The reboot is proven from the reports themselves: A4's boot time (its clock minus its uptime) must
  be at least 60 seconds after A3's. The verdict line is SURVIVES only if A4 and A5 both open the
  user-scope blob with every control held, DOES NOT SURVIVE if either is refused with the controls
  held, and INCONCLUSIVE otherwise.

  THREE MODES.
    -Mode Host     On MEFORHV01, elevated, by the owner. Refuses unless REVTEST01 is Off, reverts it
                   to -Checkpoint, checks its adapters are on the Private switch MEFOR-Lab or on none,
                   starts it, and drives every arm over PowerShell Direct, the reboot included. It
                   prompts once for the VM's local administrator (the hvtest VM credential). At the
                   end, pass or fail, it turns the VM off and reverts it to -Checkpoint again.
    -Mode Payload  Inside the VM, through the hvtest harness (entry.ps1 beside this file). Runs A1 to
                   A3. hvtest cannot reboot a VM inside a run (one PowerShell Direct session per run,
                   and every run starts by reverting the checkpoint), so A4 and A5 read NOT RUN.
    -Mode Guest    One step inside the VM. Host mode calls it over PowerShell Direct; run it by hand
                   only to clean up: -Mode Guest -Step Uninstall.

  CIRCUIT BREAKERS (CLAUDE.md section 5). Host mode checks [Environment]::MachineName is MEFORHV01.
  Guest and Payload modes run inside a VM whose guest computer name is the template image's, not
  REVTEST01, so they read the Hyper-V data-exchange values the host writes into every guest
  (HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters) and refuse unless VirtualMachineName is
  REVTEST01 and PhysicalHostName is MEFORHV01. A guest without those values is refused.

  WHAT IT CHANGES. In the guest: the service, C:\mefor-dpapi-reboot, and the virtual account's
  profile, all removed by -Step Uninstall; the VM is reverted afterwards in any case. On the host:
  REVTEST01's state (reverted to the checkpoint, started, turned off, reverted again) and one output
  folder. Nothing else: no switch, no other VM, no account, no firewall rule.

  OWNER COMMAND (MEFORHV01, PowerShell 7 started with Run as administrator, while no hvtest run is
  in flight; `ssh hvtest list` from MEFORDEV01 shows REVTEST01 Off). <SHA> is the full commit SHA
  of this file's commit, which the report that ships it names:

    if ([Environment]::MachineName -ne 'MEFORHV01') { Write-Host "STOP     this must run on MEFORHV01, but this is $([Environment]::MachineName); nothing ran" } else { $d = Join-Path $env:TEMP ('dpapi-reboot-' + [guid]::NewGuid().ToString('N')); $null = New-Item -ItemType Directory -Path $d; $repo = Join-Path $HOME 'mfsrc'; git -C $repo fetch origin b452-3411-dpapi-reboot-spike; $f = Join-Path $d 'dpapi_reboot_spike.ps1'; git -C $repo show '<SHA>:scripts/research/dpapi-reboot-spike/dpapi_reboot_spike.ps1' > $f; if ((Get-Item -LiteralPath $f).Length -lt 1000) { Write-Host 'STOP     the script did not arrive; nothing ran' } else { pwsh -NoProfile -ExecutionPolicy Bypass -File $f -Mode Host -OutDir (Join-Path $d 'out') } }

  It prints the DPAPI-REBOOT lines at the end and leaves them, the transcript and the raw reports
  in the out folder it names.

  RESULTS, 2026-11-04 06:03-06:09 UTC, -Mode Payload of this file's committed code, run from
  MEFORDEV01 through hvtest (Invoke-HvTest.ps1 at vault f71a97426) on REVTEST01 at
  post-move-mefor-lab-2026-10-17; hvtest "end: pass, exit 0: entry exit 0", every stage ok. The
  guest reported: guest=REVTEST01 os=Microsoft Windows Server 2022 Datacenter build=20348, caller
  REVTEST01\Administrator, pwsh 7.6.7. Raw lines (pid, utc and uptime lines left out):
    registration=ObjectName NT SERVICE\MeforDpapiReboot, ServiceSidType 3 (restricted), RequiredPrivileges SeChangeNotifyPrivilege, Start 2 (auto)
    report-A1 masterkey=NO FOLDER C:\Windows\ServiceProfiles\MeforDpapiReboot\AppData\Roaming\Microsoft\Protect\S-1-5-80-4122042409-3321711707-2963677527-2474584594-1716172443
    report-A1 action=protect protect_user=OK protect_machine=OK user_unprotect=OK match
    report-A2 masterkey_count=2 (Preferred, 48b58aa9-..., both written 06:03:50 by A1's protect)
    profile-A3 loaded_before_start=True profile=C:\Windows\ServiceProfiles\MeforDpapiReboot (after 300 s stopped)
    Uninstall: profile=kept, still loaded: C:\Windows\ServiceProfiles\MeforDpapiReboot
    DPAPI-REBOOT A1 first start, protect and unprotect in user scope: YES (user_unprotect OK match; controls HELD: foreign FAIL win32=-2146893813, tampered FAIL win32=13, machine OK match)
    DPAPI-REBOOT A2 after a service restart: YES (user_unprotect OK match; controls HELD: foreign FAIL win32=-2146893813, tampered FAIL win32=13, machine OK match)
    DPAPI-REBOOT A3 after the profile was unloaded: INCONCLUSIVE (the profile was not seen unloaded before the start; controls HELD: foreign FAIL win32=-2146893813, tampered FAIL win32=13, machine OK match)
    DPAPI-REBOOT A4 after a reboot, the SCM start at boot: NOT RUN (this route cannot reboot the VM inside a run)
    DPAPI-REBOOT A5 after a reboot, a demand start: NOT RUN (this route cannot reboot the VM inside a run)
    DPAPI-REBOOT VERDICT: NOT RUN
  An earlier draft of this file gave the same five lines at 05:46-05:51 UTC.
  What that shows. User-scope DPAPI works under the restricted virtual account, the blob is bound to
  it (the administrator's blob is refused; -2146893813 is 0x8009000B, NTE_BAD_KEY_STATE), and it
  survives a restart. The virtual account's profile is under C:\Windows\ServiceProfiles, and it
  stayed loaded for the 300 s A3 waited with the service stopped, so on this build no profile reload
  without a reboot was observed; the reboot (A4) is the first profile reload this can observe. The
  reboot arm is the owner command above, -Mode Host, and no session has run it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][ValidateSet('Host', 'Payload', 'Guest')][string]$Mode,
    [Parameter(Position = 1)]
    [ValidateSet('Install', 'Start', 'ProfileReload', 'Reboot', 'BootReport', 'Report', 'Uninstall')]
    [string]$Step,
    # Start, ProfileReload and Reboot: the arm the next service start answers (A1 to A5).
    [Parameter(Position = 2)][ValidatePattern('^(A[1-5])?$')][string]$Arm = '',
    [ValidateSet('REVTEST01')][string]$VMName = 'REVTEST01',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')][string]$Checkpoint = 'post-move-mefor-lab-2026-10-17',
    [string]$OutDir,
    [ValidatePattern('^[A-Za-z0-9._-]{1,20}$')][string]$VmUser = 'Administrator'
)

if ($Mode -eq 'Host') {
    if ([Environment]::MachineName -ne 'MEFORHV01') { & { $ErrorActionPreference = 'Stop'; throw "STOP     this must run on MEFORHV01, but this is $([Environment]::MachineName); nothing ran" } }
} else {
    # Not MachineName: inside the VM that is the template's computer name. The host writes these.
    $kvp = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters' -ErrorAction SilentlyContinue
    $vmSeen = ''; $hostSeen = ''
    if ($kvp) { $vmSeen = [string]$kvp.VirtualMachineName; $hostSeen = [string]$kvp.PhysicalHostName }
    if ($vmSeen -ne 'REVTEST01' -or $hostSeen -ne 'MEFORHV01') { & { $ErrorActionPreference = 'Stop'; throw "STOP     this must run inside the Hyper-V VM REVTEST01 on MEFORHV01, but this machine ($([Environment]::MachineName)) reports VM '$vmSeen' on host '$hostSeen'; nothing ran" } }
}

$ErrorActionPreference = 'Stop'

$ServiceName = 'MeforDpapiReboot'
$Account = "NT SERVICE\$ServiceName"
$Root = 'C:\mefor-dpapi-reboot'
$Bin = Join-Path $Root 'bin'
$Work = Join-Path $Root 'work'
$Exe = Join-Path $Bin "$ServiceName.exe"

# C# 5: the compiler is the .NET Framework 4 csc.exe that ships with Windows.
$CSharp = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;

public static class Dpapi
{
    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB { public int cbData; public IntPtr pbData; }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(ref DATA_BLOB pDataIn, string szDataDescr,
        IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, IntPtr ppszDataDescr,
        IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public const int UiForbidden = 0x1;
    public const int LocalMachine = 0x4;

    public static byte[] Protect(byte[] data, int flags, out int error) { return Call(true, data, flags, out error); }
    public static byte[] Unprotect(byte[] blob, out int error) { return Call(false, blob, UiForbidden, out error); }

    private static byte[] Call(bool protect, byte[] input, int flags, out int error)
    {
        DATA_BLOB inBlob = new DATA_BLOB();
        DATA_BLOB outBlob = new DATA_BLOB();
        GCHandle pin = GCHandle.Alloc(input, GCHandleType.Pinned);
        try
        {
            inBlob.cbData = input.Length;
            inBlob.pbData = pin.AddrOfPinnedObject();
            bool ok = protect
                ? CryptProtectData(ref inBlob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, flags, ref outBlob)
                : CryptUnprotectData(ref inBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, flags, ref outBlob);
            if (!ok) { error = Marshal.GetLastWin32Error(); return null; }
            error = 0;
            byte[] result = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
            return result;
        }
        finally
        {
            pin.Free();
            if (outBlob.pbData != IntPtr.Zero) { LocalFree(outBlob.pbData); }
        }
    }
}

public static class Spike
{
    [DllImport("kernel32.dll")]
    private static extern ulong GetTickCount64();

    private static string Sha256Hex(byte[] data)
    {
        using (SHA256 h = SHA256.Create())
        {
            StringBuilder s = new StringBuilder();
            foreach (byte b in h.ComputeHash(data)) { s.Append(b.ToString("x2")); }
            return s.ToString();
        }
    }

    private static bool Same(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length) { return false; }
        for (int i = 0; i < a.Length; i++) { if (a[i] != b[i]) { return false; } }
        return true;
    }

    private static string Open(byte[] blob, byte[] expected)
    {
        if (blob == null) { return "ABSENT"; }
        int error;
        byte[] got = Dpapi.Unprotect(blob, out error);
        if (got == null) { return "FAIL win32=" + error; }
        if (expected == null) { return "OPENED"; }
        return Same(got, expected) ? "OK match" : "OK mismatch";
    }

    private static byte[] ReadOrNull(string path) { return File.Exists(path) ? File.ReadAllBytes(path) : null; }

    private static byte[] Draw()
    {
        byte[] value = new byte[32];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) { rng.GetBytes(value); }
        return value;
    }

    private static void Commit(string dir, string stem, List<string> lines)
    {
        string tmp = Path.Combine(dir, stem + ".tmp");
        File.WriteAllLines(tmp, lines.ToArray(), new UTF8Encoding(false));
        File.Move(tmp, Path.Combine(dir, stem + ".txt"));
    }

    public static void Run(string dir)
    {
        // The rig names the arm this start answers in arm.txt before it starts the service, so a
        // start that writes nothing cannot shift a later report onto the wrong arm.
        string armPath = Path.Combine(dir, "arm.txt");
        string arm = File.Exists(armPath) ? File.ReadAllText(armPath).Trim() : "";
        if (arm.Length == 0) { arm = "unnamed-" + DateTime.UtcNow.Ticks; }
        List<string> lines = new List<string>();
        lines.Add("arm=" + arm);
        DateTime now = DateTime.UtcNow;
        ulong uptime = GetTickCount64();
        lines.Add("utc=" + now.ToString("o"));
        lines.Add("uptime_ms=" + uptime);
        lines.Add("boot_utc=" + now.AddMilliseconds(-(double)uptime).ToString("o"));
        WindowsIdentity me = WindowsIdentity.GetCurrent();
        string sid = me.User.Value;
        lines.Add("identity=" + me.Name);
        lines.Add("sid=" + sid);
        lines.Add("pid=" + Process.GetCurrentProcess().Id);
        lines.Add("userprofile=" + Environment.GetEnvironmentVariable("USERPROFILE"));
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        lines.Add("appdata=" + appData);
        string keys = Path.Combine(Path.Combine(Path.Combine(appData, "Microsoft"), "Protect"), sid);
        try
        {
            if (!Directory.Exists(keys)) { lines.Add("masterkey=NO FOLDER " + keys); }
            else
            {
                // A fresh virtual account holds one or two; the newest five and the count are enough
                // to see whether a reboot made a new one.
                FileInfo[] files = new DirectoryInfo(keys).GetFiles();
                Array.Sort(files, delegate(FileInfo a, FileInfo b) { return b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc); });
                lines.Add("masterkey_count=" + files.Length);
                for (int i = 0; i < files.Length && i < 5; i++)
                {
                    lines.Add("masterkey=" + files[i].Name + " bytes=" + files[i].Length + " written=" + files[i].LastWriteTimeUtc.ToString("o"));
                }
            }
        }
        catch (UnauthorizedAccessException e) { lines.Add("masterkey=UNREADABLE " + e.Message); }

        string plainPath = Path.Combine(dir, "plain.bin");
        string userPath = Path.Combine(dir, "user.blob");
        string machinePath = Path.Combine(dir, "machine.blob");
        if (!File.Exists(plainPath))
        {
            lines.Add("action=protect");
            byte[] fresh = Draw();
            int error;
            byte[] user = Dpapi.Protect(fresh, Dpapi.UiForbidden, out error);
            lines.Add("protect_user=" + (user == null ? "FAIL win32=" + error : "OK"));
            byte[] machine = Dpapi.Protect(fresh, Dpapi.UiForbidden | Dpapi.LocalMachine, out error);
            lines.Add("protect_machine=" + (machine == null ? "FAIL win32=" + error : "OK"));
            if (user != null) { File.WriteAllBytes(userPath, user); }
            if (machine != null) { File.WriteAllBytes(machinePath, machine); }
            File.WriteAllBytes(plainPath, fresh);
        }
        else { lines.Add("action=unprotect"); }

        byte[] plain = File.ReadAllBytes(plainPath);
        lines.Add("plain_sha256=" + Sha256Hex(plain));
        byte[] userBlob = ReadOrNull(userPath);
        lines.Add("user_unprotect=" + Open(userBlob, plain));
        lines.Add("machine_unprotect=" + Open(ReadOrNull(machinePath), plain));
        lines.Add("control_foreign=" + Open(ReadOrNull(Path.Combine(dir, "foreign.blob")), null));
        if (userBlob == null) { lines.Add("control_tampered=ABSENT"); }
        else
        {
            byte[] tampered = (byte[])userBlob.Clone();
            tampered[tampered.Length / 2] ^= 0xFF;
            lines.Add("control_tampered=" + Open(tampered, null));
        }
        Commit(dir, "report-" + arm, lines);
    }

    public static int ProtectForeign(string dir)
    {
        int error;
        byte[] blob = Dpapi.Protect(Draw(), Dpapi.UiForbidden, out error);
        if (blob == null) { Console.WriteLine("foreign_protect=FAIL win32=" + error); return 1; }
        File.WriteAllBytes(Path.Combine(dir, "foreign.blob"), blob);
        Console.WriteLine("foreign_protect=OK by " + WindowsIdentity.GetCurrent().Name);
        return 0;
    }

    public static void Crash(string dir, Exception e)
    {
        File.WriteAllText(Path.Combine(dir, "crash-" + DateTime.UtcNow.Ticks + ".txt"), e.ToString());
    }
}

public sealed class SpikeService : ServiceBase
{
    private readonly string dir;

    public SpikeService(string dir)
    {
        this.dir = dir;
        ServiceName = "MeforDpapiReboot";
        CanStop = true;
        AutoLog = false;
    }

    protected override void OnStart(string[] args)
    {
        Thread worker = new Thread(Work);
        worker.IsBackground = true;
        worker.Start();
    }

    private void Work()
    {
        // Broad on purpose: whatever fails must land in a file the rig prints, since a service has
        // no console. It is recorded, not swallowed.
        try { Spike.Run(dir); }
        catch (Exception e) { Spike.Crash(dir, e); }
    }
}

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--protect-foreign") { return Spike.ProtectForeign(args[1]); }
        if (args.Length != 1)
        {
            Console.Error.WriteLine("usage: MeforDpapiReboot.exe <work dir> | --protect-foreign <work dir>");
            return 2;
        }
        ServiceBase.Run(new SpikeService(args[0]));
        return 0;
    }
}
'@

# --- guest steps --------------------------------------------------------------------------------

function Invoke-Native {
    param([Parameter(Mandatory)][string]$File, [string[]]$Arguments)
    # Continue, so Windows PowerShell 5.1 does not turn a native stderr line into a terminating error
    # before the exit code is read. Cleared first, so a command that never ran cannot pass on an
    # earlier command's 0 (install-service.ps1 Stop-ServiceAndConfirm says why).
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = $null
    $out = (& $File @Arguments 2>&1 | Out-String).Trim()
    $exit = $LASTEXITCODE
    if ($null -eq $exit -or $exit -ne 0) { throw "$File $($Arguments -join ' ') exited '$exit': $out" }
    $out
}

function Get-ServiceSid {
    ([Security.Principal.NTAccount]$Account).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Get-SpikeProfile([string]$Sid) {
    Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$Sid'"
}

function Set-NextArm([string]$Name) {
    if (-not $Name) { throw "this step needs -Arm" }
    Set-Content -LiteralPath (Join-Path $Work 'arm.txt') -Value $Name -Encoding ASCII
}

function Stop-Spike {
    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
    }
}

function Show-File([string]$Path) {
    "===== $(Split-Path -Leaf $Path) ====="
    Get-Content -LiteralPath $Path
}

function Show-ScmEvents {
    # SilentlyContinue: Get-WinEvent raises "No events were found" when there are none, which is a
    # reading, not a fault.
    $since = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $since } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*$ServiceName*" -or $_.Message -like '*DPAPI reboot spike*' })
    "scm_events_since_boot=$($events.Count)"
    foreach ($e in $events) { "scm_event id=$($e.Id) time=$($e.TimeCreated.ToUniversalTime().ToString('o')) $(($e.Message -replace '\s+', ' ').Trim())" }
}

function Complete-Report([string]$Name, [int]$Seconds) {
    # Waits for the arm's report, then stops the service, which stays running once it has written.
    $path = Join-Path $Work "report-$Name.txt"
    $deadline = (Get-Date).AddSeconds($Seconds)
    while (-not (Test-Path -LiteralPath $path) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
    Stop-Spike
    if (-not (Test-Path -LiteralPath $path)) {
        "report-$Name=NONE"
        Show-ScmEvents
        foreach ($f in @(Get-ChildItem -LiteralPath $Work -Filter 'crash-*.txt' -File)) { Show-File $f.FullName }
        return
    }
    Show-File $path
}

function Step-Install {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw "service $ServiceName already exists; run -Mode Guest -Step Uninstall first" }
    if (Test-Path -LiteralPath $Root) { throw "$Root already exists; run -Mode Guest -Step Uninstall first" }
    $os = Get-CimInstance Win32_OperatingSystem
    "guest=$([Environment]::MachineName) os=$($os.Caption) version=$($os.Version) build=$($os.BuildNumber)"
    "caller=$([Security.Principal.WindowsIdentity]::GetCurrent().Name) powershell=$($PSVersionTable.PSVersion)"
    $null = New-Item -ItemType Directory -Path $Root
    # Administrators and SYSTEM only, owned by Administrators, before anything is run from it (the
    # hvtest payload contract; install-service.ps1 Set-AdminOnlyAcl does the same).
    $null = Invoke-Native 'icacls.exe' @($Root, '/setowner', '*S-1-5-32-544')
    $null = Invoke-Native 'icacls.exe' @($Root, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    $null = New-Item -ItemType Directory -Path $Bin
    $null = New-Item -ItemType Directory -Path $Work
    $source = Join-Path $Bin "$ServiceName.cs"
    [IO.File]::WriteAllText($source, $CSharp, (New-Object Text.UTF8Encoding($false)))
    $csc = Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc)) { throw "no C# compiler at $csc" }
    $null = Invoke-Native $csc @('/nologo', '/target:exe', '/platform:x64', "/out:$Exe", '/reference:System.ServiceProcess.dll', $source)
    "compiled=$Exe sha256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $Exe).Hash)"
    # No path holds a space, so the image path needs no quotes.
    $null = Invoke-Native 'sc.exe' @('create', $ServiceName, 'binPath=', "$Exe $Work", 'start=', 'demand', 'DisplayName=', 'MessageFoundry DPAPI reboot spike')
    # No password= argument, so the SCM gets a NULL password, which a virtual account requires.
    $null = Invoke-Native 'sc.exe' @('config', $ServiceName, 'obj=', $Account)
    $null = Invoke-Native 'sc.exe' @('sidtype', $ServiceName, 'restricted')
    # The installer's own list: install-service.ps1 $ServicePrivileges.
    $null = Invoke-Native 'sc.exe' @('privs', $ServiceName, 'SeChangeNotifyPrivilege')
    $null = Invoke-Native 'sc.exe' @('config', $ServiceName, 'start=', 'auto')
    # Read back from the SCM's own key, so a registration that drifted stops here, not in a verdict.
    $reg = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $privs = @($reg.RequiredPrivileges) -join ','
    if ($reg.ObjectName -ne $Account -or $reg.ServiceSidType -ne 3 -or $privs -ne 'SeChangeNotifyPrivilege' -or $reg.Start -ne 2) {
        throw "the registration read back as ObjectName '$($reg.ObjectName)', ServiceSidType '$($reg.ServiceSidType)', RequiredPrivileges '$privs', Start '$($reg.Start)'"
    }
    $sid = Get-ServiceSid
    # The grant is to the service SID, which is on a restricted service's restricting list, so it
    # counts for a write.
    $null = Invoke-Native 'icacls.exe' @($Work, '/grant', "*${sid}:(OI)(CI)M")
    $null = Invoke-Native 'icacls.exe' @($Bin, '/grant', "*${sid}:(OI)(CI)RX")
    # Not Invoke-Native: a failure here costs one control, which the judge then reads as absent.
    $foreign = (& $Exe --protect-foreign $Work 2>&1 | Out-String).Trim()
    "$foreign exit=$LASTEXITCODE"
    "install=OK service=$ServiceName account=$Account sid=$sid"
    "registration=ObjectName $($reg.ObjectName), ServiceSidType 3 (restricted), RequiredPrivileges $privs, Start 2 (auto)"
}

function Step-Start {
    Set-NextArm $Arm
    try { Start-Service -Name $ServiceName }
    catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        # A service that will not start is itself a reading (a logon or profile failure, say), so
        # the run goes on to record it rather than stop.
        "start=FAILED $Arm $($_.Exception.Message) $($_.Exception.InnerException.Message)"
        Show-ScmEvents
        return
    }
    Complete-Report $Arm 120
}

function Step-ProfileReload {
    $sid = Get-ServiceSid
    $deadline = (Get-Date).AddSeconds(300)
    $p = Get-SpikeProfile $sid
    while ($p -and $p.Loaded -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 5; $p = Get-SpikeProfile $sid }
    $state = 'loaded_before_start=NO PROFILE'
    if ($p) { $state = "loaded_before_start=$($p.Loaded) profile=$($p.LocalPath)" }
    # Kept beside the reports, so the judge reads what this step saw, wherever the judge runs.
    Set-Content -LiteralPath (Join-Path $Work "profile-$Arm.txt") -Value $state -Encoding ASCII
    "profile-$Arm $state"
    Step-Start
}

function Step-Reboot {
    # The start the SCM makes at boot answers this arm.
    Set-NextArm $Arm
    "reboot=requested for $Arm, last_boot_before=$((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o'))"
    $null = Invoke-Native 'shutdown.exe' @('/r', '/t', '15', '/d', 'p:0:0', '/c', 'MessageFoundry DPAPI reboot spike')
}

function Step-BootReport {
    "last_boot=$((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o'))"
    $svc = Get-Service -Name $ServiceName
    "service_after_boot=$($svc.Status) start_type=$($svc.StartType)"
    $name = (Get-Content -LiteralPath (Join-Path $Work 'arm.txt') -Raw).Trim()
    Complete-Report $name 300
    Show-ScmEvents
}

function Step-Report {
    foreach ($f in @(Get-ChildItem -LiteralPath $Work -Filter '*.txt' -File | Sort-Object Name)) { Show-File $f.FullName }
}

function Step-Uninstall {
    $sid = $null
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        $sid = Get-ServiceSid
        Stop-Spike
        $null = Invoke-Native 'sc.exe' @('delete', $ServiceName)
        'service=deleted'
    } else { 'service=absent' }
    if (Test-Path -LiteralPath $Root) { Remove-Item -LiteralPath $Root -Recurse -Force; "folder=removed $Root" } else { 'folder=absent' }
    if ($sid) {
        $p = Get-SpikeProfile $sid
        if (-not $p) { 'profile=absent' }
        elseif ($p.Loaded) { "profile=kept, still loaded: $($p.LocalPath)" }
        else { Remove-CimInstance -InputObject $p; "profile=removed $($p.LocalPath)" }
    }
}

function Invoke-GuestStep([string]$Name) {
    switch ($Name) {
        'Install' { Step-Install }
        'Start' { Step-Start }
        'ProfileReload' { Step-ProfileReload }
        'Reboot' { Step-Reboot }
        'BootReport' { Step-BootReport }
        'Report' { Step-Report }
        'Uninstall' { Step-Uninstall }
        default { throw "-Mode Guest needs -Step" }
    }
}

# The arms both routes run before any reboot, as (step, arm) pairs.
$PreRebootSteps = @(@('Install', ''), @('Start', 'A1'), @('Start', 'A2'), @('ProfileReload', 'A3'))

# --- the judge ----------------------------------------------------------------------------------

function Read-Report([string]$Dir, [string]$Name) {
    $path = Join-Path $Dir "report-$Name.txt"
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $r = @{}
    foreach ($line in Get-Content -LiteralPath $path) {
        $i = $line.IndexOf('=')
        if ($i -lt 1) { continue }
        $k = $line.Substring(0, $i); $v = $line.Substring($i + 1)
        if ($r.ContainsKey($k)) { $r[$k] = "$($r[$k]); $v" } else { $r[$k] = $v }
    }
    $r
}

function Get-Verdict($Report, [string]$Action, [string]$Extra) {
    # Returns @(verdict, why). $Extra is a precondition the arm needs, already judged: '' when it holds.
    if (-not $Report) { return @('INCONCLUSIVE', 'no report') }
    if ($Report['identity'] -ne $Account -or -not ([string]$Report['sid']).StartsWith('S-1-5-80-')) {
        return @('INCONCLUSIVE', "ran as $($Report['identity']) $($Report['sid']), not the virtual account")
    }
    if ($Report['action'] -ne $Action) { return @('INCONCLUSIVE', "action $($Report['action']), not $Action") }
    if ($Action -eq 'protect' -and $Report['protect_user'] -ne 'OK') { return @('NO', "protect_user $($Report['protect_user'])") }
    $controls = "foreign $($Report['control_foreign']), tampered $($Report['control_tampered']), machine $($Report['machine_unprotect'])"
    $held = ([string]$Report['control_foreign']).StartsWith('FAIL') -and ([string]$Report['control_tampered']).StartsWith('FAIL') -and
        $Report['machine_unprotect'] -eq 'OK match'
    if (-not $held) { return @('INCONCLUSIVE', "a control FAILED: $controls") }
    if ($Extra) { return @('INCONCLUSIVE', "$Extra; controls HELD: $controls") }
    $user = [string]$Report['user_unprotect']
    if ($user -eq 'OK match') { return @('YES', "user_unprotect $user; controls HELD: $controls") }
    if ($user.StartsWith('FAIL') -or $user -eq 'OK mismatch') { return @('NO', "user_unprotect $user; controls HELD: $controls") }
    @('INCONCLUSIVE', "user_unprotect $user; controls HELD: $controls")
}

function Get-BootGap($Earlier, $Later) {
    # Seconds between the boots two reports ran in, each its own clock less its own uptime.
    ([DateTime]::Parse($Later['boot_utc']).ToUniversalTime() - [DateTime]::Parse($Earlier['boot_utc']).ToUniversalTime()).TotalSeconds
}

function Invoke-Judge([string]$Dir, [bool]$Rebooted) {
    # Returns @{ Lines; Verdicts }, Verdicts keyed A1 to A5.
    $r = @{}
    foreach ($a in 'A1', 'A2', 'A3', 'A4', 'A5') { $r[$a] = Read-Report $Dir $a }
    $v = @{}
    $v['A1'] = Get-Verdict $r['A1'] 'protect' ''
    $v['A2'] = Get-Verdict $r['A2'] 'unprotect' ''
    $extra = 'the profile was not seen unloaded before the start'
    $pf = Join-Path $Dir 'profile-A3.txt'
    if ((Test-Path -LiteralPath $pf) -and ((Get-Content -LiteralPath $pf -Raw) -match 'loaded_before_start=False')) { $extra = '' }
    $v['A3'] = Get-Verdict $r['A3'] 'unprotect' $extra
    if ($Rebooted) {
        $extra = 'no reboot shown: report-A3 or report-A4 is missing'
        if ($r['A3'] -and $r['A4']) {
            $gap = Get-BootGap $r['A3'] $r['A4']
            if ($gap -ge 60) { $extra = '' } else { $extra = "boot times differ by $([int]$gap) s, under 60" }
        }
        $v['A4'] = Get-Verdict $r['A4'] 'unprotect' $extra
        $extra = 'report-A5 is not from the boot report-A4 is from'
        if ($r['A4'] -and $r['A5'] -and [Math]::Abs((Get-BootGap $r['A4'] $r['A5'])) -lt 60) { $extra = '' }
        $v['A5'] = Get-Verdict $r['A5'] 'unprotect' $extra
    } else {
        $notRun = @('NOT RUN', 'this route cannot reboot the VM inside a run')
        $v['A4'] = $notRun
        $v['A5'] = $notRun
    }
    $names = @{
        A1 = 'A1 first start, protect and unprotect in user scope'
        A2 = 'A2 after a service restart'
        A3 = 'A3 after the profile was unloaded'
        A4 = 'A4 after a reboot, the SCM start at boot'
        A5 = 'A5 after a reboot, a demand start'
    }
    $lines = @(foreach ($a in 'A1', 'A2', 'A3', 'A4', 'A5') { "DPAPI-REBOOT $($names[$a]): $($v[$a][0]) ($($v[$a][1]))" })
    $overall = 'NOT RUN'
    if ($Rebooted) {
        if ($v['A4'][0] -eq 'YES' -and $v['A5'][0] -eq 'YES') { $overall = 'SURVIVES' }
        elseif ($v['A4'][0] -eq 'NO' -or $v['A5'][0] -eq 'NO') { $overall = 'DOES NOT SURVIVE' }
        else { $overall = 'INCONCLUSIVE' }
    }
    @{ Lines = $lines + "DPAPI-REBOOT VERDICT: $overall"; Verdicts = $v }
}

# --- payload mode (hvtest) ----------------------------------------------------------------------

function Invoke-PayloadStep([string]$Log, [string]$Name, [string]$ArmName) {
    "----- guest step $Name $ArmName -----" | Add-Content -LiteralPath $Log -Encoding ASCII
    $script:Arm = $ArmName
    Invoke-GuestStep $Name | ForEach-Object { [string]$_ } | Add-Content -LiteralPath $Log -Encoding ASCII
}

function Invoke-Payload {
    # Returns the exit code: 0 when A1 and A2 are YES and A3 is not NO. A3 reads INCONCLUSIVE when
    # the profile never unloads, which the 2026-11-04 run showed is this build's behaviour, not a
    # fault of the run.
    if (-not $OutDir) { throw '-Mode Payload needs -OutDir (entry.ps1 passes HVTEST_RESULTS)' }
    $null = New-Item -ItemType Directory -Force -Path $OutDir
    $log = Join-Path $OutDir 'dpapi-reboot-spike.txt'
    $exit = 1
    try {
        foreach ($s in $PreRebootSteps) { Invoke-PayloadStep $log $s[0] $s[1] }
        Copy-Item -Path (Join-Path $Work '*.txt') -Destination $OutDir
        $judged = Invoke-Judge $Work $false
        $judged.Lines | Add-Content -LiteralPath $log -Encoding ASCII
        $judged.Lines | Write-Host
        $vs = $judged.Verdicts
        if ($vs['A1'][0] -eq 'YES' -and $vs['A2'][0] -eq 'YES' -and $vs['A3'][0] -ne 'NO') { $exit = 0 }
    } finally {
        Invoke-PayloadStep $log 'Uninstall' ''
    }
    $exit
}

# --- host mode (MEFORHV01) ----------------------------------------------------------------------

function Write-Log([string]$Line) {
    Write-Host $Line
    Add-Content -LiteralPath $script:HostLog -Value $Line -Encoding ASCII
}

function Invoke-Guest($Session, [string]$GuestStep, [string]$ArmName = '') {
    Write-Log "----- guest step $GuestStep $ArmName -----"
    $out = Invoke-Command -Session $Session -FilePath $PSCommandPath -ArgumentList 'Guest', $GuestStep, $ArmName
    foreach ($line in @($out)) { Write-Log ([string]$line) }
}

function Get-GuestBoot($Session) {
    Invoke-Command -Session $Session -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime() }
}

function Wait-GuestSession($Credential, [Nullable[DateTime]]$BootAfter, [int]$Seconds) {
    # Each failed attempt is logged with its type. While a guest boots the failure types vary (the
    # VM bus not up, the credential service not up, a session that drops), so no one type is caught.
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $s = $null
        try {
            $s = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
            if ($null -eq $BootAfter) { return $s }
            $boot = Get-GuestBoot $s
            if ($boot -gt $BootAfter.Value.AddSeconds(30)) { Write-Log "guest back, last boot $($boot.ToString('o'))"; return $s }
            Remove-PSSession $s
        } catch {
            Write-Log "waiting for the guest: $($_.Exception.GetType().FullName): $($_.Exception.Message)"
            if ($s) { Remove-PSSession $s -ErrorAction SilentlyContinue }
        }
        Start-Sleep -Seconds 10
    }
    throw "STOP     no PowerShell Direct session to $VMName within $Seconds s"
}

function Invoke-HostRun {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'STOP     run this from PowerShell started with Run as administrator; nothing ran' }
    Import-Module Hyper-V
    if (-not $OutDir) { throw 'STOP     -Mode Host needs -OutDir; nothing ran' }
    $vm = Get-VM -Name $VMName
    if ($vm.State -ne 'Off') { throw "STOP     $VMName is $($vm.State), not Off; an hvtest run may hold it. Wait until 'ssh hvtest list' shows it Off; nothing ran" }
    $snap = Get-VMSnapshot -VMName $VMName -Name $Checkpoint
    $lab = Get-VMSwitch -Name 'MEFOR-Lab'
    if ([string]$lab.SwitchType -ne 'Private') { throw "STOP     MEFOR-Lab is $($lab.SwitchType), not Private; nothing ran" }
    $null = New-Item -ItemType Directory -Force -Path $OutDir
    $script:HostLog = Join-Path $OutDir 'dpapi-reboot-spike-host.txt'
    $cred = Get-Credential -UserName $VmUser -Message "Local administrator of the test VM $VMName (the hvtest VM credential)"
    $session = $null
    # After the prompt, so the transcript never holds it. It catches what the log does not: an
    # error that ends the run.
    $null = Start-Transcript -LiteralPath (Join-Path $OutDir 'transcript.txt')
    try {
        Write-Log "host=$([Environment]::MachineName) vm=$VMName checkpoint=$Checkpoint utc=$((Get-Date).ToUniversalTime().ToString('o'))"
        Restore-VMSnapshot -VMSnapshot $snap -Confirm:$false
        foreach ($nic in @(Get-VMNetworkAdapter -VMName $VMName)) {
            if ($nic.SwitchName -and $nic.SwitchName -ne 'MEFOR-Lab') { throw "STOP     $VMName has an adapter on '$($nic.SwitchName)', not MEFOR-Lab; not started" }
        }
        Start-VM -Name $VMName
        $session = Wait-GuestSession $cred $null 600
        foreach ($s in $PreRebootSteps) { Invoke-Guest $session $s[0] $s[1] }
        $bootBefore = Get-GuestBoot $session
        Invoke-Guest $session 'Reboot' 'A4'
        Remove-PSSession $session
        $session = $null
        $session = Wait-GuestSession $cred $bootBefore 900
        Invoke-Guest $session 'BootReport'
        Invoke-Guest $session 'Start' 'A5'
        $reports = Join-Path $OutDir 'reports'
        $null = New-Item -ItemType Directory -Force -Path $reports
        Copy-Item -FromSession $session -Path 'C:\mefor-dpapi-reboot\work\*.txt' -Destination $reports
        Invoke-Guest $session 'Uninstall'
        foreach ($line in (Invoke-Judge $reports $true).Lines) { Write-Log $line }
    } finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        Stop-VM -Name $VMName -TurnOff -Force -ErrorAction Continue
        Restore-VMSnapshot -VMSnapshot $snap -Confirm:$false -ErrorAction Continue
        Write-Log "$VMName turned off and reverted to $Checkpoint; output in $OutDir"
        $null = Stop-Transcript
    }
}

switch ($Mode) {
    'Host' { Invoke-HostRun }
    # The exit code is the hvtest entry's pass or fail; entry.ps1 passes it on.
    'Payload' { exit (Invoke-Payload) }
    'Guest' { Invoke-GuestStep $Step }
}
