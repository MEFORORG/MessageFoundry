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
  LAB ONLY: the test VM REVTEST01 under the Hyper-V host MEFORHV01. Synthetic data only: what it
  protects is random bytes it draws itself, at least the service's 32-byte value and the
  administrator's 32-byte control value (foreign.blob), and no report holds either, only the
  SHA-256 of the service's value.

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
  refused with NTE_BAD_KEY_STATE, or the service is not held to its own account's keys), and a copy
  of its own blob with one byte flipped (it must be refused, or the unprotect checks nothing). After
  A1 the administrator also tries the service's own user-scope blob (crosscheck.txt), which must be
  refused, or the blob is not bound to the service account at all. A machine-scope blob that opens
  shows DPAPI and the file read worked in that process, so a user-scope refusal beside it is a real
  NO and not a broken instrument.

  THE ARMS:
    A1  first start: protect in user scope, unprotect in the same process
    A2  a service restart (the arm PR 2462 already measured on hosted runners)
    A3  a start after the account's profile was seen unloaded (Win32_UserProfile.Loaded)
    A4  after a reboot: the start the SCM makes at boot (start type Automatic)
    A5  after a reboot: a demand start
  The reboot is proven from the reports themselves, for A4 and for A5 each against A3, and A5 must
  be from A4's boot when A4 reported. Either signal shows a reboot: Windows' boot counter
  (PrefetchParameters BootId) changed, or the tick count went down (it resets only at a boot) while
  the boot time (clock minus uptime) moved later. With no counter in a report, a tick count that
  went down shows one alone, and so does a boot time 60 seconds or more later. The judge prints every report's raw counter, tick count and
  boot time on its boots line.

  Each arm reads YES, NO, INVALID or INCONCLUSIVE. INVALID is a report showing a broken instrument:
  a user-scope blob refused as damaged (win32=13), a value that opened but did not match, or a
  plain_sha256 that is not A1's; a YES needs that match. A3 still reads its result when the profile
  was not seen unloaded, so a refusal there shows; only a YES is held back to INCONCLUSIVE. The
  verdict line reads INVALID when any arm is INVALID or any of A1 to A3 is NO, whatever A4 and A5
  say; INCONCLUSIVE when A1 to A3 do not all open the blob (A3 counted where the unload was not
  seen; the payload's exit code is the same test); else SURVIVES when A4 and A5 both open the
  user-scope blob with every control held; SURVIVES, BUT NOT AT THE BOOT-TIME START when A5 opens it
  and A4 is refused; DOES NOT SURVIVE when A5 is refused with the controls held and A4 did not open
  it; INCONCLUSIVE, A4 OPENED AND A5 DID NOT for that contradiction; and INCONCLUSIVE otherwise, A5
  opening with A4 missing included.

  THREE MODES.
    -Mode Host     On MEFORHV01, elevated, by the owner. Refuses unless REVTEST01 is Off, reverts it
                   to -Checkpoint, checks its adapters are on the Private switch MEFOR-Lab or on none,
                   starts it, and drives every arm over PowerShell Direct, the reboot included. It
                   prompts once for the VM's local administrator (the hvtest VM credential). At the
                   end, pass or fail, it turns the VM off and reverts it to -Checkpoint again, and
                   reads back that it is off; where either step fails it prints a STOP line naming
                   the VM's state, which the owner then turns off and reverts by hand.
    -Mode Payload  Inside the VM, through the hvtest harness (entry.ps1 beside this file). Runs A1 to
                   A3. hvtest cannot reboot a VM inside a run (one PowerShell Direct session per run,
                   and every run starts by reverting the checkpoint), so A4 and A5 read NOT RUN.
    -Mode Guest    One step inside the VM. Host mode calls it over PowerShell Direct; run it by hand
                   only to clean up: -Mode Guest -Step Uninstall.

  CIRCUIT BREAKERS (CLAUDE.md section 5). Host mode checks [Environment]::MachineName is MEFORHV01.
  Guest and Payload modes check [Environment]::MachineName is REVTEST01, the guest computer name the
  2026-11-04 runs read. That name alone is weak: hvtest's templates keep the image's computer name
  (vault docs/testing/HVTEST.md, "Templates keep the image's computer name"), so another VM may
  carry it. So they also read the Hyper-V data-exchange values the host writes into the guest
  (HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters) and refuse unless VirtualMachineName is
  REVTEST01 and PhysicalHostName is MEFORHV01. A guest without those values is refused.

  WHAT IT CHANGES, at least. In the guest: the service and its virtual account, C:\mefor-dpapi-reboot,
  the account's profile under C:\Windows\ServiceProfiles (which -Step Uninstall removes only once it
  is unloaded, and the 2026-11-04 runs never saw it unloaded), System event log entries and the
  shutdown tracker. Every run reverts the VM afterwards, which discards all of that. On the host:
  REVTEST01's state (reverted to the checkpoint, started, turned off, reverted again), hvtest's lock
  file for REVTEST01, held for the run so hvtest reports the VM busy, the TEMP folder the owner
  command makes, and its output folder. It creates no switch, no VM and no host account, and changes
  no firewall rule.

  OWNER COMMAND (MEFORHV01, PowerShell 7 started with Run as administrator). <SHA> is the full
  commit SHA of a commit holding this file, which the report that ships it names; it is fetched by
  SHA, so it still works after the branch is merged and deleted:

    if ([Environment]::MachineName -ne 'MEFORHV01') { Write-Host "STOP     this must run on MEFORHV01, but this is $([Environment]::MachineName); nothing ran" } else { $d = Join-Path $env:TEMP ('dpapi-reboot-' + [guid]::NewGuid().ToString('N')); $null = New-Item -ItemType Directory -Path $d; $repo = Join-Path $HOME 'mfsrc'; git -C $repo fetch origin '<SHA>'; $f = Join-Path $d 'dpapi_reboot_spike.ps1'; git -C $repo show '<SHA>:scripts/research/dpapi-reboot-spike/dpapi_reboot_spike.ps1' > $f; if ((Get-Item -LiteralPath $f).Length -lt 1000) { Write-Host 'STOP     the script did not arrive; nothing ran' } else { pwsh -NoProfile -ExecutionPolicy Bypass -File $f -Mode Host -OutDir (Join-Path $d 'out') } }

  It prints the DPAPI-REBOOT lines at the end and leaves them, the transcript and the raw reports
  in the out folder it names.

  RESULTS. The code that ran is commit cde90392a04760c5a0170ad35a23b2dea760eea8; the commit that
  adds this block changes nothing below this header. -Mode Payload, run from MEFORDEV01 through
  hvtest (Invoke-HvTest.ps1 at vault f71a97426) on REVTEST01 at post-move-mefor-lab-2026-10-17,
  results stamp 20261104T073536Z; hvtest printed "end: pass, exit 0: entry exit 0", every stage ok.
  Verbatim lines from the VM's dpapi-reboot-spike.txt, a selection, unedited but for one master
  key's file name, given as <guid>:
    guest=REVTEST01 os=Microsoft Windows Server 2022 Datacenter version=10.0.20348 build=20348
    caller=REVTEST01\Administrator powershell=7.6.7
    registration=ObjectName NT SERVICE\MeforDpapiReboot, ServiceSidType 3 (restricted), RequiredPrivileges SeChangeNotifyPrivilege, Start 2 (auto)
    boot_id=5
    masterkey=NO FOLDER C:\Windows\ServiceProfiles\MeforDpapiReboot\AppData\Roaming\Microsoft\Protect\S-1-5-80-4122042409-3321711707-2963677527-2474584594-1716172443
    masterkey_count=2
    masterkey=<guid> bytes=468 written=2026-11-04T07:36:01.3489345Z
    profile-A3 loaded_before_start=True profile=C:\Windows\ServiceProfiles\MeforDpapiReboot
    profile=kept, still loaded: C:\Windows\ServiceProfiles\MeforDpapiReboot
    DPAPI-REBOOT crosscheck, the administrator opens the service's user-scope blob: admin_open=FAIL win32=-2146893813 by REVTEST01\Administrator exit=0
    DPAPI-REBOOT A1 first start, protect and unprotect in user scope: YES (user_unprotect OK match; controls HELD: foreign FAIL win32=-2146893813, tampered FAIL win32=13, machine OK match)
    DPAPI-REBOOT A2 after a service restart: YES (user_unprotect OK match; controls HELD: foreign FAIL win32=-2146893813, tampered FAIL win32=13, machine OK match)
    DPAPI-REBOOT A3 after the profile was unloaded: INCONCLUSIVE (the profile was not seen unloaded before the start)
    DPAPI-REBOOT A4 after a reboot, the SCM start at boot: NOT RUN (this route cannot reboot the VM inside a run)
    DPAPI-REBOOT A5 after a reboot, a demand start: NOT RUN (this route cannot reboot the VM inside a run)
    DPAPI-REBOOT VERDICT: NOT RUN
  Notes, not raw lines. boot_id=5 was the same in A1, A2 and A3. The first masterkey line is A1's,
  before its protect; the next two are A2's, and A3's read the same. profile-A3 was read after A3's
  step waited 300 s with the service stopped. Three runs of earlier drafts of this file (05:46,
  06:03 and 06:58 UTC) gave the same A1 to A5 answers.
  What that shows. User-scope DPAPI works under the restricted virtual account, and the blob is
  bound to it both ways: the service cannot open the administrator's blob, nor the administrator
  the service's (-2146893813 is 0x8009000B, NTE_BAD_KEY_STATE). It survives a restart. The virtual
  account's profile is under C:\Windows\ServiceProfiles and stayed loaded for those 300 s, so on
  this build no profile reload without a reboot was observed; the reboot (A4) is the first profile
  reload this can observe. The reboot arm is the owner command above, -Mode Host, and no session
  has run it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][ValidateSet('Host', 'Payload', 'Guest')][string]$Mode,
    [Parameter(Position = 1)]
    [ValidateSet('Install', 'Start', 'CrossCheck', 'ProfileReload', 'Reboot', 'BootReport', 'Report', 'Uninstall')]
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
    if ([Environment]::MachineName -ne 'REVTEST01') { & { $ErrorActionPreference = 'Stop'; throw "STOP     this must run inside the VM REVTEST01, but this is $([Environment]::MachineName); nothing ran" } }
    # The computer name can repeat across VMs made from one template; the host writes these.
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
        // Windows counts boots here; it names a boot without reading a clock.
        object bootId = Microsoft.Win32.Registry.GetValue(
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
            "BootId", null);
        lines.Add("boot_id=" + (bootId == null ? "" : bootId.ToString()));
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
        catch (IOException e) { lines.Add("masterkey=UNREADABLE " + e.Message); }

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

    public static int TryOpen(string path)
    {
        // Run as the administrator, against the service's own user-scope blob.
        Console.WriteLine("admin_open=" + Open(ReadOrNull(path), null) + " by " + WindowsIdentity.GetCurrent().Name);
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
        if (args.Length == 2 && args[0] == "--try-open") { return Spike.TryOpen(args[1]); }
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

function Invoke-Tolerant {
    param([Parameter(Mandatory)][string]$File, [string[]]$Arguments)
    # For a call whose failure costs one control, not the run: its output and exit code become a
    # reading. Continue for the reason Invoke-Native gives.
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = $null
    $out = (& $File @Arguments 2>&1 | Out-String).Trim()
    "$out exit=$LASTEXITCODE"
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
    # A failure here costs one control, which the judge then reads as absent.
    Invoke-Tolerant $Exe @('--protect-foreign', $Work)
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

function Step-CrossCheck {
    # The administrator tries the service's own user-scope blob; the judge needs it refused.
    $line = Invoke-Tolerant $Exe @('--try-open', (Join-Path $Work 'user.blob'))
    Set-Content -LiteralPath (Join-Path $Work 'crosscheck.txt') -Value $line -Encoding ASCII
    "crosscheck $line"
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
        'CrossCheck' { Step-CrossCheck }
        'ProfileReload' { Step-ProfileReload }
        'Reboot' { Step-Reboot }
        'BootReport' { Step-BootReport }
        'Report' { Step-Report }
        'Uninstall' { Step-Uninstall }
        default { throw "-Mode Guest needs -Step" }
    }
}

# The arms both routes run before any reboot, as (step, arm) pairs.
$PreRebootSteps = @(@('Install', ''), @('Start', 'A1'), @('CrossCheck', ''), @('Start', 'A2'), @('ProfileReload', 'A3'))

# --- the judge ----------------------------------------------------------------------------------

# CryptUnprotectData's refusal of another account's user-scope blob, as the 2026-11-04 runs read it.
$NteBadKeyState = 'FAIL win32=-2146893813'

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

function Get-Verdict($Report, [string]$Action, [string]$Extra, [string]$Plain) {
    # Returns @(verdict, why): YES, NO, INVALID (the report shows a broken instrument) or
    # INCONCLUSIVE. $Extra is a precondition of any answer, already judged: '' when it holds.
    # $Plain is report-A1's plain_sha256, which every unprotect start must carry ('' when A1
    # gives none).
    if (-not $Report) { return @('INCONCLUSIVE', 'no report') }
    if ($Report['identity'] -ne $Account -or -not ([string]$Report['sid']).StartsWith('S-1-5-80-')) {
        return @('INCONCLUSIVE', "ran as $($Report['identity']) $($Report['sid']), not the virtual account")
    }
    if ($Report['action'] -ne $Action) { return @('INCONCLUSIVE', "action $($Report['action']), not $Action") }
    if ($Action -eq 'protect' -and $Report['protect_user'] -ne 'OK') {
        # Before $Extra: a failed protect leaves no blob, so the crosscheck $Extra carries reads
        # ABSENT because of it, and would hide the cause. Only a NO when machine scope worked in
        # the same process; else DPAPI itself did not run.
        if ($Report['protect_machine'] -eq 'OK') { return @('NO', "protect_user $($Report['protect_user']); protect_machine OK") }
        return @('INCONCLUSIVE', "protect_user $($Report['protect_user']), protect_machine $($Report['protect_machine'])")
    }
    # The INVALID readings come before $Extra: a broken instrument shows whatever else failed.
    if ($Action -eq 'unprotect' -and $Plain -and $Report['plain_sha256'] -ne $Plain) {
        return @('INVALID', "plain_sha256 $($Report['plain_sha256']) is not report-A1's $Plain")
    }
    $user = [string]$Report['user_unprotect']
    # ERROR_INVALID_DATA is what the tampered control gets: a damaged blob, not a lost key.
    if ($user -eq 'FAIL win32=13' -or $user -eq 'OK mismatch') { return @('INVALID', "user_unprotect $user, a damaged blob or value") }
    if ($Extra) { return @('INCONCLUSIVE', $Extra) }
    if ($Action -eq 'unprotect' -and -not $Plain) { return @('INCONCLUSIVE', 'report-A1 gives no plain_sha256 to compare') }
    $controls = "foreign $($Report['control_foreign']), tampered $($Report['control_tampered']), machine $($Report['machine_unprotect'])"
    $held = $Report['control_foreign'] -eq $NteBadKeyState -and ([string]$Report['control_tampered']).StartsWith('FAIL') -and
        $Report['machine_unprotect'] -eq 'OK match'
    if (-not $held) { return @('INCONCLUSIVE', "a control FAILED: $controls") }
    if ($user -eq 'OK match') { return @('YES', "user_unprotect $user; controls HELD: $controls") }
    if ($user.StartsWith('FAIL')) { return @('NO', "user_unprotect $user; controls HELD: $controls") }
    @('INCONCLUSIVE', "user_unprotect $user; controls HELD: $controls")
}

function Get-BootReading($Report) {
    # @(boot_id or '', uptime as UInt64 or $null, boot time as UTC DateTime or $null). A field that
    # does not parse is $null, never 0, so a damaged report cannot pass for a fresh boot.
    $uptime = [UInt64]0
    $up = $null
    if ([UInt64]::TryParse([string]$Report['uptime_ms'], [ref]$uptime)) { $up = $uptime }
    $parsed = [DateTime]::MinValue
    $boot = $null
    if ([DateTime]::TryParse([string]$Report['boot_utc'], [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed)) { $boot = $parsed }
    @([string]$Report['boot_id'], $up, $boot)
}

function Get-BootRelation($Earlier, $Later) {
    # 'rebooted', 'same' or 'unknown', for two reports in time order. Either of two signals shows a
    # reboot: Windows' boot counter changed, or the tick count went down while the boot time (clock
    # minus uptime) moved later. A counter that did not move cannot overrule the second, since
    # nothing here shows every build moves it at every boot. With no counter, a tick count that went
    # down shows a reboot whatever the clock says (a clock read early at boot can put the boot time
    # back); else a boot time 60 s or more LATER shows one, and boot times within 60 s show the same
    # boot. Those last rest on the guest clock. Signals that disagree read 'unknown', a boot time
    # that moved back beside a tick count that went up included.
    $e = Get-BootReading $Earlier
    $l = Get-BootReading $Later
    $idKnown = [bool]($e[0] -and $l[0])
    $tickKnown = $null -ne $e[1] -and $null -ne $l[1]
    $bootKnown = $null -ne $e[2] -and $null -ne $l[2]
    $tickDown = $tickKnown -and $l[1] -lt $e[1]
    if ($idKnown -and $e[0] -ne $l[0]) { return 'rebooted' }
    if ($tickDown -and $bootKnown -and $l[2] -gt $e[2]) { return 'rebooted' }
    if ($idKnown) { if ($tickDown) { return 'unknown' } else { return 'same' } }
    if (-not $tickKnown -or -not $bootKnown) { return 'unknown' }
    if ($tickDown) { return 'rebooted' }
    $gap = ($l[2] - $e[2]).TotalSeconds
    if ($gap -ge 60) { return 'rebooted' }
    if ($gap -le -60) { return 'unknown' }
    'same'
}

function Invoke-Judge([string]$Dir, [bool]$Rebooted) {
    # Returns @{ Lines; Verdicts; PrePass }, Verdicts keyed A1 to A5. PrePass is the pre-reboot
    # arms' pass: A1 to A3 open the blob, A3 counted even where the unload was not seen.
    $arms = 'A1', 'A2', 'A3', 'A4', 'A5'
    $r = @{}
    foreach ($a in $arms) { $r[$a] = Read-Report $Dir $a }
    # A global control: the administrator must be refused the service's user-scope blob, by the
    # key refusal, not by a data error that a damaged blob would also give.
    $cross = ''
    $cf = Join-Path $Dir 'crosscheck.txt'
    if (Test-Path -LiteralPath $cf) { $cross = ([string](Get-Content -LiteralPath $cf -Raw)).Trim() }
    $crossProblem = ''
    if (-not $cross.StartsWith("admin_open=$NteBadKeyState ")) { $crossProblem = "crosscheck FAILED: '$cross'" }
    # Every later start must still hold A1's value; a different one means plain.bin changed.
    $plain = ''
    if ($r['A1']) { $plain = [string]$r['A1']['plain_sha256'] }
    $v = @{}
    $v['A1'] = Get-Verdict $r['A1'] 'protect' $crossProblem $plain
    $v['A2'] = Get-Verdict $r['A2'] 'unprotect' $crossProblem $plain
    $v['A3'] = Get-Verdict $r['A3'] 'unprotect' $crossProblem $plain
    # The pre-reboot arms pass when A1 to A3 open the blob. Read before the hold-back below, so an
    # A3 that opened passes even where the unload was not seen.
    $prePass = $v['A1'][0] -eq 'YES' -and $v['A2'][0] -eq 'YES' -and $v['A3'][0] -eq 'YES'
    # Without a seen unload A3 was one more restart: its result is read, but a YES answers nothing.
    $pf = Join-Path $Dir 'profile-A3.txt'
    $unloaded = (Test-Path -LiteralPath $pf) -and ([string](Get-Content -LiteralPath $pf -Raw) -match 'loaded_before_start=False')
    if (-not $unloaded -and $v['A3'][0] -eq 'YES') { $v['A3'] = @('INCONCLUSIVE', "the profile was not seen unloaded before the start; $($v['A3'][1])") }
    if ($Rebooted) {
        # Each relation once, as 'missing' where a report is.
        $rel = @{}
        foreach ($pair in @('A3', 'A4'), @('A3', 'A5'), @('A4', 'A5')) {
            $key = "$($pair[0])-$($pair[1])"
            if ($r[$pair[0]] -and $r[$pair[1]]) { $rel[$key] = Get-BootRelation $r[$pair[0]] $r[$pair[1]] } else { $rel[$key] = 'missing' }
        }
        # A reboot report-A4 shows is report-A5's too when both are from one boot, even where
        # report-A5's own tick count is past report-A3's.
        if ($rel['A3-A5'] -ne 'rebooted' -and $rel['A3-A4'] -eq 'rebooted' -and $rel['A4-A5'] -eq 'same') { $rel['A3-A5'] = 'rebooted' }
        foreach ($a in 'A4', 'A5') {
            $extra = ''
            $since = $rel["A3-$a"]
            if ($since -eq 'missing') { $extra = 'no reboot shown: a report is missing' }
            elseif ($since -ne 'rebooted') { $extra = "no reboot shown between report-A3 and report-${a}: $since" }
            # A5 narrows against A4 only when both are from one boot.
            elseif ($a -eq 'A5' -and $r['A4'] -and $rel['A4-A5'] -ne 'same') { $extra = "report-A5 is not shown to be from the boot report-A4 is from: $($rel['A4-A5'])" }
            if ($crossProblem) { $extra = $crossProblem }
            $v[$a] = Get-Verdict $r[$a] 'unprotect' $extra $plain
        }
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
    $lines = @("DPAPI-REBOOT crosscheck, the administrator opens the service's user-scope blob: $cross")
    # The raw readings the reboot is judged from, so a reader can check the judge's call.
    $boots = @(foreach ($a in $arms) {
            if ($r[$a]) { "$a boot_id=$($r[$a]['boot_id']) uptime_ms=$($r[$a]['uptime_ms']) boot_utc=$($r[$a]['boot_utc'])" } else { "$a no report" }
        }) -join '; '
    $lines += "DPAPI-REBOOT boots: $boots"
    $lines += @(foreach ($a in $arms) { "DPAPI-REBOOT $($names[$a]): $($v[$a][0]) ($($v[$a][1]))" })
    # A NO before the reboot, or an INVALID anywhere, is the instrument or the setup failing, and
    # no reboot arm beside it answers the question.
    $broken = @(foreach ($a in $arms) {
            if ($v[$a][0] -eq 'INVALID' -or ($v[$a][0] -eq 'NO' -and $a -in 'A1', 'A2', 'A3')) { "$a $($v[$a][0])" }
        })
    $overall = 'NOT RUN'
    if ($broken.Count) { $overall = "INVALID ($($broken -join ', '): the instrument or the setup failed)" }
    elseif ($Rebooted -and -not $prePass) {
        $overall = 'INCONCLUSIVE (A1 to A3 did not all open the blob, so the instrument is not shown working before the reboot)'
    } elseif ($Rebooted) {
        # A5 is the survival question: a demand start, once boot is over. A4 can only narrow it,
        # and an A4 that opened beside an A5 that did not contradicts it.
        $a4 = $v['A4'][0]; $a5 = $v['A5'][0]
        if ($a5 -eq 'YES' -and $a4 -eq 'YES') { $overall = 'SURVIVES' }
        elseif ($a5 -eq 'YES' -and $a4 -eq 'NO') { $overall = 'SURVIVES, BUT NOT AT THE BOOT-TIME START' }
        elseif ($a5 -eq 'NO' -and $a4 -ne 'YES') { $overall = 'DOES NOT SURVIVE' }
        elseif ($a5 -eq 'NO') { $overall = 'INCONCLUSIVE, A4 OPENED AND A5 DID NOT' }
        else { $overall = 'INCONCLUSIVE' }
    }
    @{ Lines = $lines + "DPAPI-REBOOT VERDICT: $overall"; Verdicts = $v; PrePass = $prePass }
}

# --- payload mode (hvtest) ----------------------------------------------------------------------

function Invoke-PayloadStep([string]$Log, [string]$Name, [string]$ArmName) {
    "----- guest step $Name $ArmName -----" | Add-Content -LiteralPath $Log -Encoding ASCII
    $script:Arm = $ArmName
    Invoke-GuestStep $Name | ForEach-Object { [string]$_ } | Add-Content -LiteralPath $Log -Encoding ASCII
}

function Invoke-Payload {
    # Returns the exit code: 0 when the judge's PrePass holds. A3 may read INCONCLUSIVE when its
    # start opened the blob but the profile was never seen unloaded, which the 2026-11-04 runs
    # showed is this build's behaviour, not a fault of the run.
    if (-not $OutDir) { throw '-Mode Payload needs -OutDir (entry.ps1 passes HVTEST_RESULTS)' }
    $null = New-Item -ItemType Directory -Force -Path $OutDir
    $log = Join-Path $OutDir 'dpapi-reboot-spike.txt'
    $exit = 1
    try {
        foreach ($s in $PreRebootSteps) { Invoke-PayloadStep $log $s[0] $s[1] }
        $judged = Invoke-Judge $Work $false
        $judged.Lines | Add-Content -LiteralPath $log -Encoding ASCII
        $judged.Lines | Write-Host
        if ($judged.PrePass) { $exit = 0 }
    } finally {
        # Out before the uninstall deletes them, on a failed step too, so the judge can be re-run.
        # Continue: a failed copy is reported, and must not skip the uninstall.
        if (Test-Path -LiteralPath $Work) { Copy-Item -Path (Join-Path $Work '*.txt') -Destination $OutDir -ErrorAction Continue }
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
    # Streamed, so the lines a step printed before it threw still reach the log.
    Write-Log "----- guest step $GuestStep $ArmName -----"
    Invoke-Command -Session $Session -FilePath $PSCommandPath -ArgumentList 'Guest', $GuestStep, $ArmName |
        ForEach-Object { Write-Log ([string]$_) }
}

function Get-GuestUptimeMs($Session) {
    # The guest's tick count, which only a boot resets. The guest side is Windows PowerShell 5.1,
    # whose .NET has no Environment.TickCount64.
    Invoke-Command -Session $Session -ScriptBlock {
        if (-not ('MeforSpike.Tick' -as [type])) {
            Add-Type -Namespace MeforSpike -Name Tick -MemberDefinition '[DllImport("kernel32.dll")] public static extern ulong GetTickCount64();'
        }
        [MeforSpike.Tick]::GetTickCount64()
    }
}

function Wait-GuestSession($Credential, $AskedAt, [int]$Seconds) {
    # $AskedAt is the host's time just before the reboot was asked, or $null for no reboot. The
    # guest is back from that reboot once its uptime is less than the time since: a guest that never
    # rebooted has been up longer than that. It reads no guest clock, which a reboot may set wrong.
    # Each failed attempt is logged with its type. While a guest boots the failure types vary (the
    # VM bus not up, the credential service not up, a session that drops), so no one type is caught;
    # a refused credential is the exception, and stops the wait at once.
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $s = $null
        $beat = [string](Get-VM -Name $VMName).Heartbeat
        if ($beat -notlike 'Ok*') { Write-Log "waiting for the guest: heartbeat $beat"; Start-Sleep -Seconds 10; continue }
        try {
            $s = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
            if ($null -eq $AskedAt) { return $s }
            $up = [double](Get-GuestUptimeMs $s)
            $since = ((Get-Date) - $AskedAt).TotalMilliseconds
            if ($up -lt $since) { Write-Log "guest back: uptime_ms=$up, $([long]$since) ms since the reboot was asked"; return $s }
            Write-Log "waiting for the guest: still the boot before, uptime_ms=$up, $([long]$since) ms since the reboot was asked"
            Remove-PSSession $s
        } catch {
            if ($s) { Remove-PSSession $s -ErrorAction SilentlyContinue }
            # The patterns hvtest's own runner stops on; it only tries once the heartbeat is Ok.
            if ($_.Exception.Message -match '(?i)credential is invalid|user name or password|logon failure') { throw "STOP     the VM credential was refused: $($_.Exception.Message)" }
            Write-Log "waiting for the guest: $($_.Exception.GetType().FullName): $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 10
    }
    throw "STOP     no PowerShell Direct session to $VMName within $Seconds s"
}

function Enter-HvTestLock([string]$Path = (Join-Path 'C:\ProgramData\hvtest\lock' ($VMName.ToLowerInvariant() + '.lock'))) {
    # hvtest's own per-VM lock (HvTestRunner.ps1 Enter-VmLock): the open handle with no sharing is
    # the lock, so while this run holds it an hvtest run on the VM reports busy, and this run cannot
    # start while one is in flight.
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $Path))) { throw "STOP     no hvtest lock folder at $(Split-Path -Parent $Path); nothing ran" }
    try {
        New-Object System.IO.FileStream ($Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    } catch [System.Management.Automation.MethodInvocationException] {
        # hvtest's test: only a sharing or a lock violation is another run holding the file. Any
        # other failure is a host fault, and calling it busy would send the owner to wait on nothing.
        $base = $_.Exception.GetBaseException()
        if ($base.HResult -eq -2147024864 -or $base.HResult -eq -2147024863) {
            throw "STOP     $VMName is busy: an hvtest run holds $Path ($($base.Message)); nothing ran"
        }
        throw ("STOP     cannot open hvtest's lock file {0}: {1} HRESULT 0x{2:X8}: {3}; nothing ran" -f $Path, $base.GetType().FullName, $base.HResult, $base.Message)
    }
}

function Invoke-HostRun {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'STOP     run this from PowerShell started with Run as administrator; nothing ran' }
    Import-Module Hyper-V
    if (-not $OutDir) { throw 'STOP     -Mode Host needs -OutDir; nothing ran' }
    $cred = Get-Credential -UserName $VmUser -Message "Local administrator of the test VM $VMName (the hvtest VM credential)"
    if (-not $cred) { throw 'STOP     no credential was entered; nothing ran' }
    # Every check after the prompt, which can sit for any length of time, and under the lock.
    $lock = Enter-HvTestLock
    try {
        $vm = @(Get-VM -Name $VMName)
        if ($vm.Count -ne 1) { throw "STOP     $($vm.Count) VMs are named $VMName, not 1; nothing ran" }
        if ($vm[0].State -ne 'Off') { throw "STOP     $VMName is $($vm[0].State), not Off; nothing ran" }
        $snap = @(Get-VMSnapshot -VMName $VMName -Name $Checkpoint)
        if ($snap.Count -ne 1) { throw "STOP     $VMName has $($snap.Count) checkpoints named $Checkpoint, not 1; nothing ran" }
        $snap = $snap[0]
        $lab = @(Get-VMSwitch -Name 'MEFOR-Lab')
        if ($lab.Count -ne 1 -or [string]$lab[0].SwitchType -ne 'Private') { throw "STOP     MEFOR-Lab is not one Private switch; nothing ran" }
        $null = New-Item -ItemType Directory -Force -Path $OutDir
        $script:HostLog = Join-Path $OutDir 'dpapi-reboot-spike-host.txt'
        $reports = Join-Path $OutDir 'reports'
        # The judge reads whatever is in it, so an earlier run's reports would pass for this run's.
        if ((Test-Path -LiteralPath $reports) -and @(Get-ChildItem -LiteralPath $reports -Force).Count) { throw "STOP     $reports already holds files from another run; pass a new -OutDir; nothing ran" }
        $null = New-Item -ItemType Directory -Force -Path $reports
        Invoke-Rig $cred $snap $reports
    } finally {
        $lock.Dispose()
    }
}

function Get-VMStateText {
    try { [string](Get-VM -Name $VMName -ErrorAction Stop).State }
    catch { "unreadable ($($_.Exception.Message))" }
}

function Stop-AndRevert($Snap) {
    # Returns '' once the VM is off and reverted, else the STOP line naming the state the owner must
    # put right by hand. Each step runs whatever the one before did, and the off state is read back.
    # The catches are broad on purpose: this is the cleanup, every failure lands in the STOP line,
    # and none may skip the revert or the judge after it.
    $problems = @()
    try { Stop-VM -Name $VMName -TurnOff -Force -ErrorAction Stop }
    catch { $problems += "Stop-VM failed: $($_.Exception.Message)" }
    $state = Get-VMStateText
    if ($state -ne 'Off') { $problems += "after Stop-VM it was $state, not Off" }
    try { Restore-VMSnapshot -VMSnapshot $Snap -Confirm:$false -ErrorAction Stop }
    catch { $problems += "Restore-VMSnapshot failed: $($_.Exception.Message)" }
    # The next run refuses a VM that is not Off, so a revert that leaves it Saved needs a hand too.
    $state = Get-VMStateText
    if ($state -ne 'Off') { $problems += "after the revert it was $state, not Off" }
    if (-not $problems.Count) { return '' }
    "STOP     $VMName was not turned off and reverted ($($problems -join '; ')); it is $(Get-VMStateText) now; turn it off and revert it to $Checkpoint by hand before anything else uses it"
}

function Invoke-Rig($Credential, $Snap, [string]$Reports) {
    $session = $null
    # After the prompt, so the transcript never holds it.
    $null = Start-Transcript -LiteralPath (Join-Path $OutDir 'transcript.txt')
    try {
        Write-Log "host=$([Environment]::MachineName) vm=$VMName checkpoint=$Checkpoint utc=$((Get-Date).ToUniversalTime().ToString('o'))"
        Restore-VMSnapshot -VMSnapshot $Snap -Confirm:$false
        foreach ($nic in @(Get-VMNetworkAdapter -VMName $VMName)) {
            if ($nic.SwitchName -and $nic.SwitchName -ne 'MEFOR-Lab') { throw "STOP     $VMName has an adapter on '$($nic.SwitchName)', not MEFOR-Lab; not started" }
        }
        Start-VM -Name $VMName
        $session = Wait-GuestSession $Credential $null 600
        foreach ($s in $PreRebootSteps) { Invoke-Guest $session $s[0] $s[1] }
        # Out before the reboot, so a guest that never comes back still leaves A1 to A3 to judge.
        Copy-Item -FromSession $session -Path (Join-Path $Work '*.txt') -Destination $Reports
        $askedAt = Get-Date
        Invoke-Guest $session 'Reboot' 'A4'
        Remove-PSSession $session
        $session = $null
        $session = Wait-GuestSession $Credential $askedAt 900
        Invoke-Guest $session 'BootReport'
        Invoke-Guest $session 'Start' 'A5'
    } catch {
        # Logged here: the transcript stops in finally, before a rethrown error reaches the console.
        Write-Log "FAILED: $($_.Exception.GetType().FullName): $($_.Exception.Message)"
        throw
    } finally {
        # The readings come out before the revert destroys them, on success and failure alike.
        if ($session) {
            try {
                Copy-Item -FromSession $session -Path (Join-Path $Work '*.txt') -Destination $Reports -ErrorAction Stop
                Invoke-Guest $session 'Uninstall'
            } catch {
                Write-Log "could not copy the reports or uninstall: $($_.Exception.Message)"
            }
            Remove-PSSession $session -ErrorAction SilentlyContinue
        } else {
            Write-Log 'no guest session at the end, so the judge reads only the reports copied before the reboot, if any'
        }
        $endStop = Stop-AndRevert $Snap
        if ($endStop) { Write-Log $endStop } else { Write-Log "$VMName turned off and reverted to $Checkpoint; output in $OutDir" }
        # After the revert, so a judge that throws on a damaged report cannot leave the VM running.
        try { foreach ($line in (Invoke-Judge $Reports $true).Lines) { Write-Log $line } }
        catch { Write-Log "the judge failed: $($_.Exception.GetType().FullName): $($_.Exception.Message)" }
        # Again last, so the verdict lines cannot push it off the owner's screen.
        if ($endStop) { Write-Log $endStop }
        $null = Stop-Transcript
    }
}

switch ($Mode) {
    'Host' { Invoke-HostRun }
    # The exit code is the hvtest entry's pass or fail; entry.ps1 passes it on.
    'Payload' { exit (Invoke-Payload) }
    'Guest' { Invoke-GuestStep $Step }
}
