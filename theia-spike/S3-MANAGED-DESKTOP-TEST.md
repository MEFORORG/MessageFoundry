# Spike S-3: managed-desktop test runbook

> **This is a stand-in, not proof for any real site.** The lab is one owner's dev/test box. A pass
> here says the spike build installed and ran under one App Control policy on one Windows 11 Pro
> machine. It says nothing about any hospital's image, policy set or signing chain. Use synthetic
> data only: the bundled `samples/config` and generated messages. No real HL7, no PHI.

Spike S-3 asks one question from the design spec (`docs/design/theia-analyst-editor.md`, section 17):
does the analyst build install and run on a managed Windows image without administrator rights? It
records installer size and memory use too.

The build under test is the **unsigned** per-user installer that `theia-spike/scripts/build-installer.ps1`
makes. It is unsigned on purpose, because SmartScreen's and App Control's response to it is part of
what this test measures. Section 13 of the spec says the real installers will be Authenticode-signed.

Everything below is PowerShell 7. Each step names the machine it runs on.

## What the spike build can and cannot show

The build is spike S-1's browser app moved into Electron, plus a bundled Python runtime and engine.
Know its limits before you start, so a missing feature is not logged as a failure.

| Feature | In this build? | Note |
|---|---|---|
| Install per-user, no elevation | Yes | NSIS, `perMachine: false`, installs under `%LOCALAPPDATA%\Programs` |
| Open a handler in Steps, edit a typed field, save | Yes | Runs the bundled Python with `-I -m messagefoundry lens ...` |
| Python resolution | Yes | Administrator setting, then the bundled runtime. Never `PATH` |
| Engine minimum version check | Yes | Refuses an engine below the version recorded at build time |
| **Test** (dry run) | **No** | Outside spike S-1. The button is there and does nothing |
| **Sign-in to the engine** | **No** | FR-5 is not built. Step 6 signs in through the web console instead |

So the spec's pass condition, *"installs and runs Test without administrator rights"*, cannot be
fully met by this build. This runbook measures the install and the edit-and-save path. Record Test
as **not available in the spike build**, not as a failure.

## The lab, as this runbook uses it

From `Z:\MEFOR-LAB-SERVER-ORIENTATION.md` (2026-10-07). Re-check it before you start.

| Machine | Address | Role in this test |
|---|---|---|
| MEFORHV01 | 192.168.4.40 | Hyper-V host. Checkpoints, PowerShell Direct. **Cannot resolve lab DNS** |
| DC01 | 192.168.7.200 | Domain controller for `lab.mefor.internal` (NetBIOS `MEFORLAB`). OU, user, group, GPO |
| CLIENT01 | 192.168.7.207 | The existing Windows 11 Pro test client (build 26200). The analyst desktop |
| APP01 | 192.168.7.205 | Runs a **separate** test engine instance on its own port |
| MEFORAG | 192.168.7.211 | SQL Server AG listener. The test engine's store connects here, **never** to SQL01 or SQL02 |
| Z: | `\\192.168.4.21\Shared` | Carries the installer from the owner's workstation to the lab |

Rules that bind this runbook:

- **Never write or echo a credential.** Every step that needs one prompts with `Get-Credential`.
  Do not paste a password into this file, a transcript or a ticket.
- **Checkpoints are a set.** Reverting one domain member alone restores an old machine-account
  password and breaks trust. So the GPO, OU, user and group are rolled back **by undoing them**
  (step 9). CLIENT01 is reverted only to the checkpoint taken just before the test (step 2).
- **The host cannot resolve lab names.** Use IP addresses, or `-Server 192.168.7.200`.
- **Node and npm are not on the host.** Build the installer on the owner's workstation.

## Step 0. Build the installer and copy it to Z: (owner's workstation)

1. In a checkout of branch `claude/theia-spike-s3-installer`, set up the Python environment:

   ```powershell
   pwsh -NoProfile -File scripts\worktree\ensure-venv.ps1
   ```

2. Install the Theia dependencies:

   ```powershell
   Set-Location theia-spike; npm install; Set-Location ..
   ```

3. Build. The script downloads Python only from python.org and refuses it unless the SHA-256 matches.

   ```powershell
   pwsh -NoProfile -File theia-spike\scripts\build-installer.ps1
   ```

4. Note the `Size` and `SHA-256` lines it prints.
5. Copy the installer to the share:

   ```powershell
   $dest = 'Z:\theia-spike-s3'
   New-Item -ItemType Directory -Force -Path $dest | Out-Null
   Copy-Item theia-spike\electron-app\dist\MessageFoundry-Steps-Spike-*-unsigned-setup.exe $dest
   Get-FileHash "$dest\MessageFoundry-Steps-Spike-*-unsigned-setup.exe" -Algorithm SHA256
   ```

6. Check that the hash matches step 4.

## Step 1. Record the starting state (MEFORHV01)

1. Confirm the lab is up:

   ```powershell
   Get-VM DC01, APP01, CLIENT01 | Format-Table Name, State, Uptime
   ```

2. Confirm DC01's clock, since Kerberos allows 5 minutes of skew:

   ```powershell
   $lab = Get-Credential -Message 'Lab domain admin (MEFORLAB\...)'
   Invoke-Command -VMName DC01 -Credential $lab { hostname; w32tm /query /status }
   ```

3. Record where CLIENT01's computer object lives now. Step 9 moves it back here.

   ```powershell
   Invoke-Command -VMName DC01 -Credential $lab { (Get-ADComputer CLIENT01).DistinguishedName }
   ```

4. Write that DN into the results table (section "Results").

## Step 2. Checkpoint CLIENT01 just before the test (MEFORHV01)

Take this checkpoint now, not earlier. A checkpoint from long ago can hold an old machine-account
password.

```powershell
$cp = "pre-S3-$(Get-Date -Format yyyyMMdd-HHmm)"
Checkpoint-VM -Name CLIENT01 -SnapshotName $cp
Get-VMSnapshot -VMName CLIENT01 | Format-Table Name, CreationTime
$cp
```

Record the checkpoint name. Do not checkpoint or revert any other VM for this test.

## Step 3. Create the OU, user, group and GPO (DC01, from MEFORHV01)

App Control for Business is the policy here. **CLIENT01 is Windows 11 Pro, and Pro does not enforce
AppLocker rules.** AppLocker would need Enterprise or Education. Do not substitute it.

1. Back up all GPOs first, so you can compare later. The test GPO is new, so rollback is removal.

   ```powershell
   Invoke-Command -VMName DC01 -Credential $lab {
       $dir = "C:\GPO-Backup\pre-S3-$(Get-Date -Format yyyyMMdd-HHmm)"
       New-Item -ItemType Directory -Force -Path $dir | Out-Null
       Backup-GPO -All -Path $dir | Out-Null
       $dir
   }
   ```

2. Create the OU, the group and the user. The password prompt runs on the host and is passed as a
   SecureString. Nothing is echoed.

   ```powershell
   $analystPw = Read-Host -AsSecureString -Prompt 'New password for analyst1'
   Invoke-Command -VMName DC01 -Credential $lab -ArgumentList $analystPw {
       param($pw)
       $domain = (Get-ADDomain).DistinguishedName
       New-ADOrganizationalUnit -Name 'MF-S3-Test' -Path $domain -ProtectedFromAccidentalDeletion $false
       $ou = "OU=MF-S3-Test,$domain"
       New-ADGroup -Name 'MF-Analysts' -GroupScope Global -GroupCategory Security -Path $ou
       New-ADUser -Name 'analyst1' -SamAccountName 'analyst1' -UserPrincipalName 'analyst1@lab.mefor.internal' `
           -Path $ou -AccountPassword $pw -Enabled $true -ChangePasswordAtLogon $false
       Add-ADGroupMember -Identity 'MF-Analysts' -Members 'analyst1'
       Get-ADGroup 'MF-Analysts' | Select-Object DistinguishedName
   }
   ```

3. Record the group's full DN. The engine's group map takes a full DN only (step 5).
4. Build the App Control policy from Windows' own example. Start in **audit** mode. Audit logs what
   enforcement would block, without blocking.

   ```powershell
   Invoke-Command -VMName DC01 -Credential $lab {
       $work = 'C:\MF-S3'
       New-Item -ItemType Directory -Force -Path $work | Out-Null
       Copy-Item "$env:windir\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml" "$work\MF-S3-AppControl.xml" -Force
       ConvertFrom-CIPolicy -XmlFilePath "$work\MF-S3-AppControl.xml" -BinaryFilePath "$work\SiPolicy.p7b"
       New-SmbShare -Name 'MF-S3$' -Path $work -ReadAccess 'Domain Computers' -ErrorAction SilentlyContinue
   }
   ```

5. Create the GPO and link it **only** to the new OU. It sets two things: App Control and
   SmartScreen. Step 7.16 adds the spike's Python administrator setting later.

   ```powershell
   Invoke-Command -VMName DC01 -Credential $lab {
       $domain = (Get-ADDomain).DistinguishedName
       $gpo = New-GPO -Name 'MF-S3-Managed-Desktop' -Comment 'Spike S-3 test only. Remove after the test.'
       # Deploy App Control for Business (Device Guard policy). Applies at the next restart.
       Set-GPRegistryValue -Name $gpo.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' `
           -ValueName 'DeployConfigCIPolicy' -Type DWord -Value 1
       Set-GPRegistryValue -Name $gpo.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' `
           -ValueName 'ConfigCIPolicyFilePath' -Type String -Value '\\192.168.7.200\MF-S3$\SiPolicy.p7b'
       # SmartScreen on, set to warn (the user can still choose to run).
       Set-GPRegistryValue -Name $gpo.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' `
           -ValueName 'EnableSmartScreen' -Type DWord -Value 1
       Set-GPRegistryValue -Name $gpo.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' `
           -ValueName 'ShellSmartScreenLevel' -Type String -Value 'Warn'
       New-GPLink -Name $gpo.DisplayName -Target "OU=MF-S3-Test,$domain" -LinkEnabled Yes
       Get-GPInheritance -Target "OU=MF-S3-Test,$domain"
   }
   ```

6. Check the GPO's settings in the Group Policy Management console. The App Control setting shows
   under Computer Configuration, Administrative Templates, System, Device Guard. If the console names
   it differently on this server, record what it says.

**No local admin.** `analyst1` is a plain domain user, and a domain user is not in CLIENT01's local
Administrators group unless someone adds it. Step 4 checks this rather than enforcing it with a
Restricted Groups policy. Add one only if the check shows otherwise.

## Step 4. Put CLIENT01 under the policy (DC01 and CLIENT01)

CLIENT01 is already joined to `lab.mefor.internal`. Do **not** re-join it.

1. Check the edition and build (CLIENT01, as the lab admin, through PowerShell Direct from the host):

   ```powershell
   Invoke-Command -VMName CLIENT01 -Credential $lab {
       Get-ComputerInfo -Property WindowsProductName, WindowsEditionId, OsBuildNumber
       (Get-CimInstance Win32_ComputerSystem).Domain
   }
   ```

   Expect edition `Professional` and build `26200`. Record what it says.
2. Move the computer object into the test OU (from the host):

   ```powershell
   Invoke-Command -VMName DC01 -Credential $lab {
       $domain = (Get-ADDomain).DistinguishedName
       Get-ADComputer CLIENT01 | Move-ADObject -TargetPath "OU=MF-S3-Test,$domain"
       (Get-ADComputer CLIENT01).DistinguishedName
   }
   ```

3. Apply the policy and restart CLIENT01, because App Control loads at boot:

   ```powershell
   Invoke-Command -VMName CLIENT01 -Credential $lab { gpupdate /force }
   Restart-VM -Name CLIENT01 -Force -Wait -For Heartbeat
   ```

4. Check that the GPO applied and the policy is active:

   ```powershell
   Invoke-Command -VMName CLIENT01 -Credential $lab {
       gpresult /r /scope computer | Select-String 'MF-S3'
       Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
           Select-Object CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus
   }
   ```

   In audit mode, expect status `1` (audit). Record the values.
5. Check `analyst1` is not a local admin. Sign in to CLIENT01 as `MEFORLAB\analyst1` through
   VMConnect, open PowerShell 7 or Windows PowerShell, and run:

   ```powershell
   whoami /groups | Select-String 'BUILTIN\\Administrators'
   ```

   Expect no output. If the line appears, stop: the test would not mean anything.

## Step 5. Start a separate test engine on APP01 (APP01)

This is a **new, separate engine instance** on APP01, on its own port, with its own database. It
does not join the APP01/APP02 cluster and does not touch the cluster's store. Leave the cluster's
engine service running and untouched.

> If you would rather use the existing cluster engine instead, say so in the results. Then skip
> this step, and in step 6 map `MF-Analysts` on that engine and remove the mapping afterwards.

The config keys below are from `docs/CONFIGURATION.md` and `docs/SECURITY.md`. Do not invent others.

1. Create a dedicated test database through the listener, with its own SQL login. The database is
   **not** added to the availability group. If the AG fails over during the test, the database will
   not be reachable through the listener; record that and fail it back rather than adding it.

   ```powershell
   $sqlAdmin = Get-Credential -Message 'SQL admin for MEFORAG (192.168.7.211)'
   $storeCred = Get-Credential -UserName 'mf_s3_test' -Message 'New SQL login for the S-3 test store'
   $pw = $storeCred.GetNetworkCredential().Password.Replace("'", "''")
   Invoke-Sqlcmd -ServerInstance '192.168.7.211' -Credential $sqlAdmin -TrustServerCertificate -Query @"
   CREATE DATABASE MF_S3_TEST;
   CREATE LOGIN mf_s3_test WITH PASSWORD = '$pw', CHECK_POLICY = ON;
   "@
   Invoke-Sqlcmd -ServerInstance '192.168.7.211' -Database MF_S3_TEST -Credential $sqlAdmin -TrustServerCertificate -Query @"
   CREATE USER mf_s3_test FOR LOGIN mf_s3_test;
   ALTER ROLE db_datareader ADD MEMBER mf_s3_test;
   ALTER ROLE db_datawriter ADD MEMBER mf_s3_test;
   "@
   Remove-Variable pw
   ```

   `Invoke-Sqlcmd` needs the `SqlServer` module. If it is missing, run the same two batches in SSMS.
   `docs/DEPLOY-SERVER-DB.md` lists the exact grants the runtime login needs; follow it if the
   engine's privilege probe reports a missing one.
2. Make an instance folder and start from the cluster engine's own working config, so every startup
   gate it already satisfies stays satisfied. Find that config first:

   ```powershell
   Get-CimInstance Win32_Service | Where-Object PathName -match 'nssm|messagefoundry' |
       Select-Object Name, State, PathName
   ```

   Then copy its `messagefoundry.toml` to `C:\srv\mefor\s3-test\messagefoundry.toml`.
3. Edit only these keys in the copy:

   | Section and key | Value | Why |
   |---|---|---|
   | `[store].backend` | `"sqlserver"` | Unchanged if already so |
   | `[store].server` | `"192.168.7.211"` | The AG listener, never a node |
   | `[store].database` | `"MF_S3_TEST"` | The dedicated test database |
   | `[store].auth`, `[store].username` | `"sql"`, `"mf_s3_test"` | Password comes from `MEFOR_STORE_PASSWORD` |
   | `[api].port` | `8790` | Any free port that is not the cluster engine's |
   | `[cluster].enabled` | `false` | A lone test instance. Delete any `[cluster.vip]` block |
   | `[security].local_access_only` | `false` | CLIENT01 must reach it |
   | `[security].listen_address` | `"192.168.7.205"` | APP01's address |
   | `[security].web_console_public_address` | `"https://192.168.7.205:8790"` | The origin the browser uses |
   | `[auth].ad_enabled` | `true` | Directory lookups |
   | `[auth].ad_server` | `"ldaps://192.168.7.200:636"` | If the DC's LDAPS certificate names only `dc01.lab.mefor.internal`, use that name; APP01 resolves lab DNS |
   | `[auth].ad_domain` | `"lab.mefor.internal"` | |
   | `[auth].ad_user_search_base` | `"DC=lab,DC=mefor,DC=internal"` | |
   | `[auth].ad_group_search_base` | `"DC=lab,DC=mefor,DC=internal"` | |
   | `[auth].ad_bind_dn` | the DN of a lab lookup account | Password comes from `MEFOR_AUTH_AD_BIND_PASSWORD` |
   | `[auth].ad_tls_ca_cert_file` | the DC01 AD CS root, exported as PEM | Verifies LDAPS without turning verification off |
   | `[auth].kerberos_enabled` | `true` | Windows sign-in. The directory **password** sign-in is retired (BACKLOG #1137) |
   | `[auth].kerberos_spn` | `"HTTP/app01.lab.mefor.internal"` | Must be registered to the account the test engine runs as |

   If `[api].tls_cert_file` is not set, an off-box bind is refused unless you also relax
   `[security].require_encryption_for_remote`. Prefer issuing APP01 a certificate from DC01's AD CS.
4. Set the secrets for this console only. Nothing is written to disk.

   ```powershell
   Set-Location C:\srv\mefor\s3-test
   $env:MEFOR_STORE_PASSWORD = $storeCred.GetNetworkCredential().Password
   $bind = Get-Credential -Message 'LDAP lookup account for the S-3 engine'
   $env:MEFOR_AUTH_AD_BIND_PASSWORD = $bind.GetNetworkCredential().Password
   $env:MEFOR_STORE_ENCRYPTION_KEY = (messagefoundry gen-key)
   ```

   The encryption key exists only in this console. The test database is thrown away in step 9, so
   losing the key loses nothing.
5. Create the schema. `docs/DEPLOY-SERVER-DB.md` says `serve` refuses to start until this has run,
   and it needs a DDL-capable principal:

   ```powershell
   messagefoundry store provision-schema --service-config C:\srv\mefor\s3-test\messagefoundry.toml
   ```

6. Run the engine in the foreground, with the repository's `samples/config`:

   ```powershell
   messagefoundry serve --service-config C:\srv\mefor\s3-test\messagefoundry.toml `
       --config <repo>\samples\config --env dev --port 8790
   ```

7. If `serve` exits 2, read the message. It names the gate and the key. Fix that key only.

## Step 6. Map MF-Analysts to a role (APP01, web console)

**The Analyst role does not exist yet.** ADR 0208 proposes it; `messagefoundry/auth/permissions.py`
has six built-in roles: administrator, operator, deployment, coding, viewer, auditor.

**Viewer stands in.** The proposed Analyst role would hold `code:steps`, which no engine route
checks, plus probably `monitoring:read`. Viewer holds `monitoring:read` and `messages:read`. Coding is
the wrong stand-in because it carries `code:edit`, the very permission an analyst must not have.

1. Open `https://192.168.7.205:8790/ui` as an engine Administrator.
2. Map the full DN from step 3 to `viewer`, for example
   `CN=MF-Analysts,OU=MF-S3-Test,DC=lab,DC=mefor,DC=internal`. A short name like `MF-Analysts`
   is refused (`docs/SECURITY.md`, *AD-group to role mapping*).

## Step 7. The analyst's run (CLIENT01, as MEFORLAB\analyst1)

Sign in to CLIENT01 through VMConnect as `MEFORLAB\analyst1`. Take a screenshot at every prompt,
block and error, and name it with the step number, such as `7-3-smartscreen.png`.

1. Copy the installer from the share. A copy from a UNC path carries no Mark of the Web, so
   SmartScreen does not check it. Make a second copy that looks like an internet download:

   ```powershell
   $dl = Join-Path $env:USERPROFILE 'Downloads'
   Copy-Item '\\192.168.4.21\Shared\theia-spike-s3\MessageFoundry-Steps-Spike-*-unsigned-setup.exe' $dl
   $setup = Get-ChildItem $dl -Filter 'MessageFoundry-Steps-Spike-*-unsigned-setup.exe' | Select-Object -First 1
   $web = Join-Path $dl ('web-' + $setup.Name)
   Copy-Item $setup.FullName $web
   Set-Content -LiteralPath $web -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3"
   Get-FileHash $setup.FullName -Algorithm SHA256
   ```

2. Check the hash matches step 0.
3. Double-click the `web-` copy in File Explorer. Record SmartScreen's response. If it warns, choose
   **More info**, then **Run anyway**, and record whether a non-admin is allowed to.
4. If the `web-` copy could not run, run the plain copy instead and record the difference.
5. Record any UAC prompt. **A UAC prompt here is a failure:** the installer is per-user.
6. When it finishes, check where it went:

   ```powershell
   Get-ChildItem "$env:LOCALAPPDATA\Programs" | Where-Object Name -like 'MessageFoundry*'
   ```

7. Start **MessageFoundry Steps Spike** from the Start menu. Record the time to the first window.
8. The app opens a copy of the samples in `Documents\MessageFoundry Steps Spike\config`. In the
   Explorer, double-click `IB_ACME_ADT.py`. Expect the Steps view with two rows.
9. In the **Send** row, change **to** from `OB_ACME_ADT` to `OB_ACME_ADT_S3`, press Enter, then
   press Ctrl+S. Expect the tab's dirty dot to clear.
10. Check the file on disk changed:

    ```powershell
    Select-String -Path "$env:USERPROFILE\Documents\MessageFoundry Steps Spike\config\IB_ACME_ADT.py" -Pattern 'OB_ACME_ADT_S3'
    ```

11. Record memory with the app open:

    ```powershell
    $dir = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Programs') -Directory |
        Where-Object Name -like 'MessageFoundry*' | Select-Object -First 1 -ExpandProperty FullName
    $p = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like "$dir\*" }
    '{0} processes, {1:N0} MiB' -f @($p).Count, (($p | Measure-Object WorkingSetSize -Sum).Sum / 1MB)
    ```

12. Click **Test**. Expect nothing to happen; record it as *not in the spike build*.
13. Sign in to the engine from Edge at `https://192.168.7.205:8790/ui` with Windows sign-in. This is
    the stand-in for FR-5. Record whether the session shows the Viewer role.
14. Save the launcher log, which says which interpreter ran and why:

    ```powershell
    Get-Content "$env:APPDATA\MessageFoundry Steps Spike\logs\launcher.log"
    ```

15. Read the App Control audit events. Event 3076 is "would have been blocked" in audit mode:

    ```powershell
    $since = (Get-Date).AddHours(-2)
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3076, 3077, 3089; StartTime = $since } |
        Select-Object TimeCreated, Id, Message | Format-List | Out-File "$env:USERPROFILE\Desktop\s3-codeintegrity-audit.txt"
    ```

    Reading that log may need an admin. If `analyst1` cannot, read it from the host through
    PowerShell Direct as the lab admin.

16. Show that the administrator setting wins. Do this in audit mode, because in enforced mode the
    unsigned app may never start. Close the app, then from the host add the setting:

    ```powershell
    Invoke-Command -VMName DC01 -Credential $lab {
        Set-GPRegistryValue -Name 'MF-S3-Managed-Desktop' -Key 'HKLM\SOFTWARE\Policies\MessageFoundry\StepsSpike' `
            -ValueName 'PythonPath' -Type String -Value 'C:\does-not-exist\python.exe'
    }
    Invoke-Command -VMName CLIENT01 -Credential $lab { gpupdate /force }
    ```

    Start the app as `analyst1`. Expect an error box naming the setting, and no fallback to the
    bundled runtime. The launcher log says `REFUSED`. Then remove the value:

    ```powershell
    Invoke-Command -VMName DC01 -Credential $lab {
        Remove-GPRegistryValue -Name 'MF-S3-Managed-Desktop' -Key 'HKLM\SOFTWARE\Policies\MessageFoundry\StepsSpike' -ValueName 'PythonPath'
    }
    Invoke-Command -VMName CLIENT01 -Credential $lab { gpupdate /force }
    ```

    The setting is in HKLM, which `analyst1` cannot write. The install folder is a different matter:
    a per-user install is writable by the user, and this spike sets no Electron fuses. So the spike
    does not stop a determined user from swapping the interpreter. App Control is what would.
    Record whether App Control blocks a changed file in step 8.

## Step 8. Repeat with App Control enforced (DC01, then CLIENT01)

Audit mode says what would be blocked. Enforced mode shows it.

1. Rebuild the binary policy without the audit option (rule option 3), on DC01:

   ```powershell
   Invoke-Command -VMName DC01 -Credential $lab {
       $work = 'C:\MF-S3'
       Set-RuleOption -FilePath "$work\MF-S3-AppControl.xml" -Option 3 -Delete
       ConvertFrom-CIPolicy -XmlFilePath "$work\MF-S3-AppControl.xml" -BinaryFilePath "$work\SiPolicy.p7b"
   }
   ```

2. On CLIENT01, uninstall the app as `analyst1` (Settings, Apps, or the uninstaller in the install
   folder). Then `gpupdate /force` and restart CLIENT01 from the host.
3. Repeat step 7, items 3 to 15. Expect the unsigned `MessageFoundry Steps Spike.exe` to be blocked.
   Record exactly what the user sees and the event IDs (3077 is an enforced block).
4. **PowerShell changes under enforcement.** The DefaultWindows policy is likely to block `pwsh.exe`,
   which is not a Windows component, and to put Windows PowerShell in Constrained Language Mode. Run
   the step 7 commands in Windows PowerShell (`powershell.exe`) on CLIENT01, and record any that
   fail. Where a command cannot run as `analyst1`, run it from the host through PowerShell Direct.

## Step 9. Roll back

Undo in this order. Do not revert DC01, APP01 or the SQL nodes to any checkpoint.

1. CLIENT01: uninstall the app as `analyst1` if it is still installed.
2. DC01: move CLIENT01 back to the DN recorded in step 1, then remove the GPO, its link, the share,
   the user, the group and the OU:

   ```powershell
   $originalOu = '<the parent of the DN from step 1, e.g. CN=Computers,DC=lab,DC=mefor,DC=internal>'
   Invoke-Command -VMName DC01 -Credential $lab -ArgumentList $originalOu {
       param($target)
       Get-ADComputer CLIENT01 | Move-ADObject -TargetPath $target
       Remove-GPO -Name 'MF-S3-Managed-Desktop'
       Remove-SmbShare -Name 'MF-S3$' -Force
       Remove-ADUser -Identity analyst1 -Confirm:$false
       Remove-ADGroup -Identity 'MF-Analysts' -Confirm:$false
       $domain = (Get-ADDomain).DistinguishedName
       Remove-ADOrganizationalUnit -Identity "OU=MF-S3-Test,$domain" -Confirm:$false
   }
   ```

3. CLIENT01: **removing the GPO does not remove the App Control policy.** The policy file stays in
   `C:\Windows\System32\CodeIntegrity` and keeps enforcing. The clean fix is to revert CLIENT01 to
   the checkpoint from step 2, which was taken minutes before the test:

   ```powershell
   Restore-VMSnapshot -VMName CLIENT01 -Name '<the step 2 checkpoint name>' -Confirm:$false
   Start-VM CLIENT01
   ```

   Then confirm trust: `Invoke-Command -VMName CLIENT01 -Credential $lab { Test-ComputerSecureChannel }`
   should print `True`. If it prints `False`, repair it with
   `Test-ComputerSecureChannel -Repair -Credential (Get-Credential)` rather than reverting anything else.
4. APP01: stop the test engine (Ctrl+C), clear the console's secrets, and remove the instance folder:

   ```powershell
   Remove-Item Env:MEFOR_STORE_PASSWORD, Env:MEFOR_AUTH_AD_BIND_PASSWORD, Env:MEFOR_STORE_ENCRYPTION_KEY
   ```

5. Drop the test database and login through the listener:

   ```powershell
   Invoke-Sqlcmd -ServerInstance '192.168.7.211' -Credential $sqlAdmin -TrustServerCertificate -Query @"
   ALTER DATABASE MF_S3_TEST SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
   DROP DATABASE MF_S3_TEST;
   DROP LOGIN mf_s3_test;
   "@
   ```

6. If you used the cluster engine instead of a test instance, remove the `MF-Analysts` mapping.
7. Delete the `pre-S3-...` checkpoint once CLIENT01 is healthy, so it does not join the lab's
   checkpoint set: `Remove-VMSnapshot -VMName CLIENT01 -Name '<name>'`.

## Results

Fill this in. Write "not run" rather than leaving a cell empty.

| # | Check | Audit mode | Enforced mode |
|---|---|---|---|
| R1 | CLIENT01 edition, build (step 4.1) | | |
| R2 | CLIENT01 original DN (step 1.3) | | |
| R3 | Installer file name, size, SHA-256 matches build | | |
| R4 | SmartScreen response to the `web-` copy | | |
| R5 | Could a non-admin choose **Run anyway**? | | |
| R6 | Any UAC prompt during install (a prompt is a fail) | | |
| R7 | Install folder | | |
| R8 | App Control response to the installer | | |
| R9 | App Control response to `MessageFoundry Steps Spike.exe` | | |
| R10 | App Control response to the bundled `python.exe` and its `.pyd` files | | |
| R11 | Time from start to first window | | |
| R12 | Steps view rendered `IB_ACME_ADT.py` (2 rows) | | |
| R13 | Edit and save changed the file on disk | | |
| R14 | Memory: processes and total working set | | |
| R15 | Test button | not in spike build | not in spike build |
| R16 | Web console Windows sign-in, role shown | | |
| R17 | Launcher log: interpreter and source | | |
| R18 | Administrator setting refusal (step 7.16) | | not run |
| R19 | CodeIntegrity event IDs seen | | |
| R20 | Rollback done, `Test-ComputerSecureChannel` result | | |

**Pass**, for this stand-in, means R6 shows no prompt, and R12 and R13 succeed in audit mode. The
enforced-mode column is expected to show blocks for an unsigned build; record them. They are the
evidence for the signing requirement in section 13, not a failure of the spike.

## What to send back

Put these in one folder on `Z:\theia-spike-s3\results-<date>\`:

1. The filled results table.
2. Every screenshot, named by step.
3. `launcher.log` from both runs.
4. `s3-codeintegrity-audit.txt` from both runs.
5. The `serve` startup lines from APP01, with any credential or key removed. Check before copying.
6. A short note of anything this runbook got wrong, so the next run does not repeat it.

Do not send message bodies, database files or anything from `--show-phi`.
