<#
Author: Joshua Dwight
GitHub: https://github.com/joshdwight101
#>
[CmdletBinding()]
param(
    [ValidateSet('Gui','Help','Discover','Locked','Analyze','UnlockPreview','UnlockCommit','ConnectCloud','CloudSignins','InvestigateUser','ExportReport')]
    [string]$Mode = 'Gui',
    [string]$Identity,
    [string]$Search,
    [string[]]$Users,
    [int]$Hours = 8,
    [string]$OutputPath = ".\lockout-report.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ([System.Management.Automation.PSTypeName]'LockoutSignal').Type) {
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Linq;

public class LockoutSignal {
  public int EventId { get; set; }
  public string Machine { get; set; }
  public string Message { get; set; }
}

public static class LockoutInferenceEngine
{
    public static string BuildNarrative(string identity, List<LockoutSignal> signals)
    {
        int c4740 = signals.Count(x => x.EventId == 4740);
        int c4771 = signals.Count(x => x.EventId == 4771);
        int c4776 = signals.Count(x => x.EventId == 4776);
        int c4625 = signals.Count(x => x.EventId == 4625);
        int c4767 = signals.Count(x => x.EventId == 4767);
        string probable = "No strong cause detected.";

        if (signals.Any(s => s.EventId == 4771 && (s.Message ?? "").IndexOf("0x18", StringComparison.OrdinalIgnoreCase) >= 0))
            probable = "High confidence: Kerberos bad-password retries (4771 + 0x18).";
        else if (signals.Any(s => s.EventId == 4776))
            probable = "Medium confidence: NTLM source workstation retry pattern (4776).";
        else if (signals.Any(s => s.EventId == 4625))
            probable = "Medium confidence: endpoint/service task credential failure pattern (4625).";
        else if (c4740 > 0)
            probable = "Low-medium confidence: lockout confirmed (4740). Review Caller Computer Name and adjacent 4771/4776/4625 events on the listed DC(s).";

        var topMachines = signals.GroupBy(s => s.Machine ?? "unknown")
            .OrderByDescending(g => g.Count())
            .Take(3)
            .Select(g => string.Format("{0} ({1})", g.Key, g.Count()));

        return string.Join(Environment.NewLine, new [] {
            string.Format("Lockout Intelligence Report for {0}", identity),
            string.Format("Events: 4740={0}, 4771={1}, 4776={2}, 4625={3}, 4767={4}", c4740, c4771, c4776, c4625, c4767),
            string.Format("Likely cause: {0}", probable),
            string.Format("Top source systems: {0}", string.Join(", ", topMachines))
        });
    }
}
"@
}


function Ensure-ADModule {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        throw "ActiveDirectory module failed to load. Ensure RSAT AD tools are installed and ADWS is reachable. Error: $($_.Exception.Message)"
    }
}

function Write-OperatorLog {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format o)] $Message" -ForegroundColor Cyan
}

function Invoke-Discover {
    Ensure-ADModule
    Write-OperatorLog "Discovering domain controllers and health context."
    $domain = Get-ADDomain -Current LoggedOnUser
    $pdc = $domain.PDCEmulator

    Get-ADDomainController -Filter * | Select-Object HostName, Site, IsReadOnly, IsGlobalCatalog, IPv4Address,
        @{Name='IsPDC';Expression={ $_.HostName -eq $pdc }}
}

function Invoke-Locked {
    Ensure-ADModule
    Write-OperatorLog "Searching locked users with optional filter."
    Search-ADAccount -LockedOut -UsersOnly |
        Get-ADUser -Properties LockedOut, LastBadPasswordAttempt, BadLogonCount, LastLogonDate |
        Where-Object {
            if ([string]::IsNullOrWhiteSpace($Search)) { return $true }
            $_.SamAccountName -like "*$Search*"
        } |
        Select-Object SamAccountName, UserPrincipalName, LockedOut, BadLogonCount, LastBadPasswordAttempt, LastLogonDate, DistinguishedName
}

function Get-OnPremEvidence {
    param(
        [Parameter(Mandatory)] [string]$User,
        [scriptblock]$OnProgress
    )
    Ensure-ADModule
    $ids = 4740, 4771, 4776, 4625, 4767
    $lookbackHours = [double]$script:Hours
    $start = (Get-Date).AddHours(-1 * $lookbackHours)

    $dcs = @(Get-ADDomainController -Filter *)
    $totalSteps = [Math]::Max(1, ($dcs.Count * $ids.Count))
    $step = 0
    foreach ($dc in $dcs) {
        foreach ($id in $ids) {
            $step++
            if ($OnProgress) {
                & $OnProgress ([Math]::Min(99,[int](($step / $totalSteps) * 100))) "Querying $($dc.HostName) event $id"
            }
            try {
                Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{ LogName='Security'; Id=$id; StartTime=$start } |
                    Where-Object { $_.Message -match [regex]::Escape($User) } |
                    Select-Object @{N='SourceDC';E={$dc.HostName}}, TimeCreated, Id, MachineName, Message
            }
            catch {
                [pscustomobject]@{ SourceDC=$dc.HostName; TimeCreated=$null; Id=0; MachineName=$dc.HostName; Message="REMOTE_LOG_ACCESS_ERROR: $($_.Exception.Message)" }
            }
        }
    }
}

function Connect-CloudGraph {
    Write-OperatorLog "Connecting to Microsoft Graph (AuditLog.Read.All required)."
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Reports -ErrorAction Stop
    Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All" -NoWelcome
}

function Get-CloudEvidence {
    param([Parameter(Mandatory)] [string]$User)

    $lookbackHours = [double]$script:Hours
    $start = (Get-Date).AddHours(-1 * $lookbackHours).ToString("o")
    $filter = "userPrincipalName eq '$User' and createdDateTime ge $start"

    try {
        Get-MgAuditLogSignIn -Filter $filter -Top 200 |
            Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, IPAddress, ClientAppUsed, Status, ConditionalAccessStatus
    }
    catch {
        Write-Warning "Graph query failed: $($_.Exception.Message)"
        @()
    }
}

function Invoke-Analyze {
    if ([string]::IsNullOrWhiteSpace($Identity)) { throw "-Identity is required." }
    Write-OperatorLog "Analyzing on-prem evidence for $Identity."

    $events = @(Get-OnPremEvidence -User $Identity | Sort-Object TimeCreated -Descending)
    $signals = [System.Collections.Generic.List[LockoutSignal]]::new()
    foreach ($e in $events) {
        if ($e.Id -gt 0) {
            $s = [LockoutSignal]::new(); $s.EventId = [int]$e.Id; $s.Machine = [string]$e.MachineName; $s.Message = [string]$e.Message
            [void]$signals.Add($s)
        }
    }

    [LockoutInferenceEngine]::BuildNarrative($Identity, $signals)
    "`nOn-prem timeline (latest 30):"
    $events | Select-Object -First 30 SourceDC, TimeCreated, Id, MachineName
}

function Invoke-InvestigateUser {
    if ([string]::IsNullOrWhiteSpace($Identity)) { throw "-Identity is required." }
    Write-OperatorLog "Running dual-evidence investigation for $Identity (On-Prem + Cloud)."

    $onPrem = @(Get-OnPremEvidence -User $Identity | Sort-Object TimeCreated -Descending)
    $cloud = @(Get-CloudEvidence -User $Identity)

    $signals = [System.Collections.Generic.List[LockoutSignal]]::new()
    foreach ($e in $onPrem) {
        if ($e.Id -gt 0) {
            $s = [LockoutSignal]::new(); $s.EventId = [int]$e.Id; $s.Machine = [string]$e.MachineName; $s.Message = [string]$e.Message
            [void]$signals.Add($s)
        }
    }

    $narrative = [LockoutInferenceEngine]::BuildNarrative($Identity, $signals)

    [pscustomobject]@{
        User = $Identity
        Generated = Get-Date
        Narrative = $narrative
        OnPremEventCount = $onPrem.Count
        CloudSignInCount = $cloud.Count
        OnPremTop = $onPrem | Select-Object -First 25 SourceDC, TimeCreated, Id, MachineName
        CloudTop = $cloud | Select-Object -First 25 CreatedDateTime, AppDisplayName, IPAddress, ClientAppUsed, Status
    }
}

function Invoke-Unlock {
    param([bool]$Commit)
    Ensure-ADModule
    if (-not $Users -or $Users.Count -eq 0) { throw "-Users is required." }

    $results = @()
    foreach ($user in $Users) {
        $adUser = Get-ADUser -Identity $user -Properties LockedOut,UserPrincipalName -ErrorAction Stop
        $targetDc = $null
        if ($adUser.PSObject.Properties.Name -contains 'LockoutObservedOnDC' -and $adUser.LockoutObservedOnDC) {
            $targetDc = [string]$adUser.LockoutObservedOnDC
        }
        if (-not $targetDc) {
            $targetDc = (Get-ADDomain -Current LoggedOnUser).PDCEmulator
        }

        if ($Commit) {
            Write-OperatorLog "Unlocking $user on $targetDc"
            Unlock-ADAccount -Identity $adUser.DistinguishedName -Server $targetDc -Confirm:$false -ErrorAction Stop
        }

        $post = Get-ADUser -Identity $user -Server $targetDc -Properties LockedOut,LastBadPasswordAttempt,BadLogonCount
        $results += [pscustomobject]@{
            User = $user
            TargetDC = $targetDc
            Action = (if ($Commit) { 'Unlocked' } else { 'Preview' })
            LockedOutAfterAction = [bool]$post.LockedOut
            LastBadPasswordAttempt = $post.LastBadPasswordAttempt
            BadLogonCount = $post.BadLogonCount
            Notes = (if ($post.LockedOut) { 'Still locked: likely immediate relock from stale credential source.' } else { 'Unlock succeeded.' })
        }
    }

    return $results
}

function Invoke-ExportReport {
    $report = Invoke-InvestigateUser
    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-OperatorLog "Report written to $OutputPath"
    Get-Item $OutputPath
}


function Show-LockoutGui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object Windows.Forms.Form
    $form.Text = 'Lockout Intelligence v1.2 - by Joshua Dwight'
    $form.Width = 1280; $form.Height = 820

    $menu = New-Object Windows.Forms.MenuStrip
    $fileMenu = New-Object Windows.Forms.ToolStripMenuItem('File')
    $fileExit = New-Object Windows.Forms.ToolStripMenuItem('Exit')
    $fileExit.Add_Click({ $form.Close() })
    [void]$fileMenu.DropDownItems.Add($fileExit)

    $helpMenu = New-Object Windows.Forms.ToolStripMenuItem('Help')
    $helpContents = New-Object Windows.Forms.ToolStripMenuItem('How to Use')
    $helpContents.Add_Click({
        $helpText = @'
Lockout Intelligence - Quick Help

Top Filters:
- Search User: real-time filter across username, display name, first and last name.
- Show Locked / Show Disabled: controls which AD sets are loaded into the grid.
- Diagnostic Lookback Hours: controls event log lookback window for diagnostics.

Actions:
- Refresh Accounts: rebuild cache and reload list.
- Analyze Selected: runs root-cause diagnostics on selected row.
- Unlock Checked: performs real unlock action across writable DC targeting.
- Cloud Sign-ins for Selected: opens Entra/M365 sign-in evidence popup.

Tips:
- Right-click a row for diagnostics/unlock shortcuts.
- Check multiple rows in Select column for bulk unlock actions.
'@
        [Windows.Forms.MessageBox]::Show($helpText, 'Lockout Intelligence Help') | Out-Null
    })

    $helpAbout = New-Object Windows.Forms.ToolStripMenuItem('About')
    $helpAbout.Add_Click({
        $aboutForm = New-Object Windows.Forms.Form
        $aboutForm.Text = 'About Lockout Intelligence'
        $aboutForm.Width = 460; $aboutForm.Height = 220
        $lbl = New-Object Windows.Forms.Label
        $lbl.Text = 'Lockout Intelligence v1.2
Author: Joshua Dwight
GitHub:'
        $lbl.SetBounds(15,15,420,60)
        $link = New-Object Windows.Forms.LinkLabel
        $link.Text = 'https://github.com/joshdwight101'
        $link.SetBounds(15,80,360,24)
        $link.Add_LinkClicked({ Start-Process 'https://github.com/joshdwight101' })
        $aboutForm.Controls.AddRange(@($lbl,$link))
        [void]$aboutForm.ShowDialog()
    })

    [void]$helpMenu.DropDownItems.Add($helpContents)
    [void]$helpMenu.DropDownItems.Add($helpAbout)
    [void]$menu.Items.Add($fileMenu)
    [void]$menu.Items.Add($helpMenu)
    $form.MainMenuStrip = $menu
    $form.Controls.Add($menu)

    $lblSearch = New-Object Windows.Forms.Label
    $lblSearch.Text = 'Search User (real-time filter):'
    $lblSearch.SetBounds(10,32,220,20)
    $txtSearch = New-Object Windows.Forms.TextBox
    $txtSearch.SetBounds(10,52,260,25)

    $chkLocked = New-Object Windows.Forms.CheckBox
    $chkLocked.Text='Show Locked'; $chkLocked.Checked=$true; $chkLocked.SetBounds(280,54,110,24)
    $chkDisabled = New-Object Windows.Forms.CheckBox
    $chkDisabled.Text='Show Disabled'; $chkDisabled.Checked=$true; $chkDisabled.SetBounds(395,54,120,24)

    $lblHours = New-Object Windows.Forms.Label
    $lblHours.Text='Diagnostic Lookback Hours:'
    $lblHours.SetBounds(530,32,180,20)
    $numLookbackHours = New-Object Windows.Forms.NumericUpDown
    $numLookbackHours.SetBounds(530,52,90,25); $numLookbackHours.Minimum=1; $numLookbackHours.Maximum=72; $numLookbackHours.Value=8

    $grid = New-Object Windows.Forms.DataGridView
    $grid.SetBounds(10,120,1240,505)
    $grid.ReadOnly = $false
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $false
    $grid.AutoSizeColumnsMode = 'DisplayedCells'
    $grid.ScrollBars = 'Both'
    $grid.Anchor = 'Top,Left,Right,Bottom'
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $grid.DefaultCellStyle.BackColor = [System.Drawing.Color]::White
    $grid.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black

    $log = New-Object Windows.Forms.TextBox
    $log.Multiline = $true; $log.ScrollBars = 'Vertical'; $log.SetBounds(10,635,1240,140)
    $log.Anchor = 'Left,Right,Bottom'

    $lblStatus = New-Object Windows.Forms.Label
    $lblStatus.Text = 'Ready.'
    $lblStatus.SetBounds(850,90,240,20)
    $progress = New-Object Windows.Forms.ProgressBar
    $progress.SetBounds(1090,88,160,22)
    $progress.Minimum = 0; $progress.Maximum = 100; $progress.Value = 0

    function Write-Log([string]$t){ $log.Text = "$(Get-Date -Format T) - $t`r`n" + $log.Text }
    function Update-UiProgress([int]$Percent,[string]$Status){
        $p = [Math]::Max(0,[Math]::Min(100,$Percent))
        $progress.Value = $p
        $lblStatus.Text = $Status
        [Windows.Forms.Application]::DoEvents()
    }
    function Invoke-SafeUiAction([scriptblock]$Action) {
        try { & $Action }
        catch {
            $msg = $_.Exception.Message
            Write-Log "ERROR: $msg"
            [Windows.Forms.MessageBox]::Show("Operation failed.

$msg

Tip: Ensure this workstation can reach a domain controller with AD Web Services (ADWS), or run in offline/cloud-only mode.", "Lockout Intelligence", 'OK', 'Warning') | Out-Null
        }
    }


    $script:UserCache = @()
    $script:LastCacheUtc = $null

    function Rebuild-UserCache {
        $combined = @()
        if (-not $chkLocked.Checked -and -not $chkDisabled.Checked) {
            $script:UserCache = @()
            $script:LastCacheUtc = [DateTime]::UtcNow
            Write-Log 'No filters selected; cache reset to empty.'
            return
        }

        Ensure-ADModule

        if ($chkLocked.Checked) {
            $dcMap = @{}
            foreach ($dc in (Get-ADDomainController -Filter *)) {
                try {
                    # lockoutTime is non-zero on DCs with lockout evidence for the account
                    $dcLocked = Get-ADUser -Server $dc.HostName -LDAPFilter '(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))' -Properties GivenName,Surname,DisplayName,UserPrincipalName,Enabled,LockedOut,BadLogonCount,LastBadPasswordAttempt,lockoutTime
                    foreach ($u in $dcLocked) {
                        $key = [string]$u.SamAccountName
                        $lockoutTime = if ($u.lockoutTime) { [DateTime]::FromFileTimeUtc([int64]$u.lockoutTime) } else { [DateTime]::MaxValue }
                        if (-not $dcMap.ContainsKey($key) -or $lockoutTime -lt $dcMap[$key].Time) {
                            $dcMap[$key] = [pscustomobject]@{ DC = $dc.HostName; Time = $lockoutTime }
                        }
                        $combined += $u
                    }
                } catch {
                    Write-Log "WARN: Locked query failed on $($dc.HostName): $($_.Exception.Message)"
                }
            }

            # fallback path still included
            try {
                $fallback = Get-ADUser -Filter * -Properties LockedOut,GivenName,Surname,DisplayName,UserPrincipalName,Enabled,BadLogonCount,LastBadPasswordAttempt |
                    Where-Object { $_.LockedOut -eq $true }
                foreach ($u in $fallback) {
                    $key = [string]$u.SamAccountName
                    if (-not $dcMap.ContainsKey($key)) { $dcMap[$key] = [pscustomobject]@{ DC = 'DefaultDC'; Time = [DateTime]::MaxValue } }
                    $combined += $u
                }
            } catch {
                Write-Log "WARN: Locked fallback query failed: $($_.Exception.Message)"
            }

            # stamp origin DC list onto combined users
            foreach ($u in $combined) {
                $key = [string]$u.SamAccountName
                if ($dcMap.ContainsKey($key)) {
                    $u | Add-Member -NotePropertyName LockoutObservedOnDC -NotePropertyValue $dcMap[$key].DC -Force
                }
            }
        }

        if ($chkDisabled.Checked) {
            $combined += Search-ADAccount -AccountDisabled -UsersOnly |
                Get-ADUser -Properties GivenName,Surname,DisplayName,UserPrincipalName,Enabled,LockedOut,BadLogonCount,LastBadPasswordAttempt
        }

        $script:UserCache = @($combined | Sort-Object SamAccountName -Unique)
        $script:LastCacheUtc = [DateTime]::UtcNow
        Write-Log "Cache rebuilt with $($script:UserCache.Count) unique users."
    }

    function Load-UserGrid {
        if (-not $script:UserCache -or -not $script:LastCacheUtc) { Rebuild-UserCache }
        $items = $script:UserCache
        if ($txtSearch.Text) {
            $q = [regex]::Escape($txtSearch.Text)
            $items = $items | Where-Object { $_.SamAccountName -match $q -or $_.UserPrincipalName -match $q -or $_.DisplayName -match $q -or $_.GivenName -match $q -or $_.Surname -match $q }
        }

        $table = New-Object System.Data.DataTable
        [void]$table.Columns.Add('Select', [bool])
        [void]$table.Columns.Add('SamAccountName', [string])
        [void]$table.Columns.Add('DisplayName', [string])
        [void]$table.Columns.Add('FirstName', [string])
        [void]$table.Columns.Add('LastName', [string])
        [void]$table.Columns.Add('UserPrincipalName', [string])
        [void]$table.Columns.Add('Enabled', [string])
        [void]$table.Columns.Add('LockedOut', [string])
        [void]$table.Columns.Add('BadLogonCount', [string])
        [void]$table.Columns.Add('LastBadPasswordAttempt', [string])
        [void]$table.Columns.Add('LockoutObservedOnDC', [string])

        foreach ($u in $items) {
            $r = $table.NewRow()
            $r['Select'] = $false
            $r['SamAccountName'] = [string]$u.SamAccountName
            $r['DisplayName'] = [string]$u.DisplayName
            $r['FirstName'] = [string]$u.GivenName
            $r['LastName'] = [string]$u.Surname
            $r['UserPrincipalName'] = [string]$u.UserPrincipalName
            $r['Enabled'] = [string]$u.Enabled
            $r['LockedOut'] = [string]([bool]($chkLocked.Checked -or $u.LockedOut))
            $r['BadLogonCount'] = [string]$u.BadLogonCount
            $r['LastBadPasswordAttempt'] = [string]$u.LastBadPasswordAttempt
            $r['LockoutObservedOnDC'] = [string]$u.LockoutObservedOnDC
            [void]$table.Rows.Add($r)
        }

        $grid.DataSource = $table
        if ($grid.Columns['Select']) { $grid.Columns['Select'].ReadOnly = $false }
        Write-Log "Loaded $($table.Rows.Count) accounts into grid."
    }

    function Analyze-SelectedUser {
        if ($grid.SelectedRows.Count -eq 0) { return }
        $name = [string]$grid.SelectedRows[0].Cells['SamAccountName'].Value
        if (-not $name) { return }
        $script:Identity = $name; $script:Hours = [int]$numLookbackHours.Value
        Update-UiProgress 1 "Starting analysis for $name"
        Write-Log "Analysis started for $name"
        $events = @(Get-OnPremEvidence -User $name -OnProgress { param($pct,$status) Update-UiProgress $pct $status } | Sort-Object TimeCreated -Descending)
        Update-UiProgress 100 "Correlating events"

        $signals = [System.Collections.Generic.List[LockoutSignal]]::new()
        foreach ($e in $events) {
            if ($e.Id -gt 0) {
                $s = [LockoutSignal]::new(); $s.EventId = [int]$e.Id; $s.Machine = [string]$e.MachineName; $s.Message = [string]$e.Message
                [void]$signals.Add($s)
            }
        }

        if ($signals.Count -eq 0 -and $events.Count -gt 0) {
            foreach ($e in $events) {
                if ($e.Id -eq 4740) {
                    $s = [LockoutSignal]::new(); $s.EventId = 4740; $s.Machine = [string]$e.SourceDC; $s.Message = [string]$e.Message
                    [void]$signals.Add($s)
                }
            }
        }

        $narrative = [LockoutInferenceEngine]::BuildNarrative($name, $signals)
        $lockEvents = @($events | Where-Object { $_.Id -eq 4740 -and $_.TimeCreated })
        $originDc = if ($lockEvents.Count -gt 0) { ($lockEvents | Sort-Object TimeCreated | Select-Object -First 1).SourceDC } else { 'Unknown' }
        $originCaller = 'Unknown'
        if ($lockEvents.Count -gt 0) {
            $m = [regex]::Match([string]$lockEvents[0].Message, 'Caller Computer Name:\s*([^\r\n]+)')
            if ($m.Success) { $originCaller = $m.Groups[1].Value.Trim() }
        }
        Show-AnalysisResultDialog -Identity $name -Narrative $narrative -Events $events -OriginDC $originDc -OriginCaller $originCaller
        Update-UiProgress 0 'Ready.'
        Write-Log "Diagnostics complete for $name"
    }

    function Show-AnalysisResultDialog {
        param(
            [string]$Identity,
            [string]$Narrative,
            [object[]]$Events,
            [string]$OriginDC,
            [string]$OriginCaller
        )
        $dlg = New-Object Windows.Forms.Form
        $dlg.Text = "Root Cause Diagnostics - $Identity"
        $dlg.Width = 1000; $dlg.Height = 700

        $summary = New-Object Windows.Forms.Label
        $summary.Text = "Suspected Origin DC: $OriginDC    Caller Computer: $OriginCaller"
        $summary.SetBounds(10,10,960,24)

        $narr = New-Object Windows.Forms.TextBox
        $narr.Multiline = $true; $narr.ReadOnly = $true; $narr.ScrollBars = 'Vertical'
        $narr.SetBounds(10,40,960,120); $narr.Text = $Narrative

        $gridEvents = New-Object Windows.Forms.DataGridView
        $gridEvents.SetBounds(10,170,960,450)
        $gridEvents.ReadOnly = $true; $gridEvents.AllowUserToAddRows = $false; $gridEvents.AllowUserToDeleteRows = $false
        $gridEvents.AutoSizeColumnsMode = 'DisplayedCells'; $gridEvents.Anchor = 'Top,Left,Right,Bottom'
        $gridEvents.DataSource = @($Events | Select-Object -First 100 SourceDC,TimeCreated,Id,MachineName,Message)

        $btnCopyNarr = New-Object Windows.Forms.Button
        $btnCopyNarr.Text = 'Copy Summary'; $btnCopyNarr.SetBounds(10,630,120,30); $btnCopyNarr.Anchor = 'Bottom,Left'
        $btnCopyNarr.Add_Click({ [Windows.Forms.Clipboard]::SetText($narr.Text) })

        $btnCopyRows = New-Object Windows.Forms.Button
        $btnCopyRows.Text = 'Copy Events'; $btnCopyRows.SetBounds(140,630,120,30); $btnCopyRows.Anchor = 'Bottom,Left'
        $btnCopyRows.Add_Click({
            $rows = ($Events | Select-Object -First 100 SourceDC,TimeCreated,Id,MachineName,Message | Out-String)
            [Windows.Forms.Clipboard]::SetText($rows)
        })

        $btnClose = New-Object Windows.Forms.Button
        $btnClose.Text = 'Close'; $btnClose.SetBounds(880,630,90,30); $btnClose.Anchor = 'Bottom,Right'
        $btnClose.Add_Click({ $dlg.Close() })

        $dlg.Controls.AddRange(@($summary,$narr,$gridEvents,$btnCopyNarr,$btnCopyRows,$btnClose))
        [void]$dlg.ShowDialog()
    }

    function Unlock-Checked([bool]$Commit) {
        $selected = @()
        foreach ($r in $grid.Rows) {
            if ($r.Cells['Select'].Value -eq $true) { $selected += [string]$r.Cells['SamAccountName'].Value }
        }
        if ($selected.Count -eq 0) { Write-Log 'No checked users selected.'; return }
        $script:Users = $selected
        $res = Invoke-Unlock -Commit:$Commit | Out-String
        Write-Log $res
        Load-UserGrid
    }

    $txtSearch.Add_TextChanged({ Invoke-SafeUiAction { Load-UserGrid } })
    $chkLocked.Add_CheckedChanged({ Invoke-SafeUiAction { Rebuild-UserCache; Load-UserGrid } })
    $chkDisabled.Add_CheckedChanged({ Invoke-SafeUiAction { Rebuild-UserCache; Load-UserGrid } })

    $context = New-Object Windows.Forms.ContextMenuStrip
    $context.Items.Add('Run Root Cause Diagnostics').add_Click({ Invoke-SafeUiAction { Analyze-SelectedUser } }) | Out-Null
    $context.Items.Add('Unlock Selected User (Commit)').add_Click({
        Invoke-SafeUiAction { if ($grid.SelectedRows.Count -gt 0) { $script:Users=@([string]$grid.SelectedRows[0].Cells['SamAccountName'].Value); Write-Log ((Invoke-Unlock -Commit:$true)|Out-String); Load-UserGrid } }
    }) | Out-Null
    $grid.ContextMenuStrip = $context

    $btnRefresh = New-Object Windows.Forms.Button
    $btnRefresh.Text='Refresh Accounts'; $btnRefresh.SetBounds(10,86,140,28)
    $btnRefresh.Add_Click({ Invoke-SafeUiAction { Rebuild-UserCache; Load-UserGrid } })

    $btnAnalyze = New-Object Windows.Forms.Button
    $btnAnalyze.Text='Analyze Selected'; $btnAnalyze.SetBounds(160,86,130,28)
    $btnAnalyze.Add_Click({ Invoke-SafeUiAction { Analyze-SelectedUser } })

    $btnUnlockCommit = New-Object Windows.Forms.Button
    $btnUnlockCommit.Text='Unlock Checked'; $btnUnlockCommit.SetBounds(300,86,170,28)
    $btnUnlockCommit.Add_Click({ Invoke-SafeUiAction { Unlock-Checked -Commit:$true } })

    $btnCloud = New-Object Windows.Forms.Button
    $btnCloud.Text='Cloud Sign-ins for Selected'; $btnCloud.SetBounds(660,86,180,28)
    $btnCloud.Add_Click({ Invoke-SafeUiAction {
        if ($grid.SelectedRows.Count -eq 0) { return }
        $id = [string]$grid.SelectedRows[0].Cells['UserPrincipalName'].Value
        if (-not $id) { return }
        $script:Identity = $id; $script:Hours=[int]$numLookbackHours.Value
        $cloud = Get-CloudEvidence -User $id | Out-String
        [Windows.Forms.MessageBox]::Show($cloud, "Cloud Sign-ins - $id") | Out-Null
    }} )

    $form.Controls.AddRange(@($lblSearch,$txtSearch,$chkLocked,$chkDisabled,$lblHours,$numLookbackHours,$grid,$log,$lblStatus,$progress,$btnRefresh,$btnAnalyze,$btnUnlockCommit,$btnCloud))
    $form.Add_Shown({ Invoke-SafeUiAction { Rebuild-UserCache; Load-UserGrid } })
    [void]$form.ShowDialog()
}

switch ($Mode) {
    'Gui' { Show-LockoutGui }
    'Help' {
        @'
LockoutIntelligence.ps1 modes:
  Discover
  Locked
  Analyze -Identity <user>
  InvestigateUser -Identity <user>
  ConnectCloud
  CloudSignins -Identity <upn>
  UnlockPreview -Users user1,user2
  UnlockCommit -Users user1,user2
  ExportReport -Identity <user> -OutputPath .\report.json
'@
    }
    'Discover' { Invoke-Discover }
    'Locked' { Invoke-Locked }
    'Analyze' { Invoke-Analyze }
    'UnlockPreview' { Write-Warning 'Preview mode deprecated; executing unlock.'; Invoke-Unlock -Commit:$true }
    'UnlockCommit' { Invoke-Unlock -Commit:$true }
    'ConnectCloud' { Connect-CloudGraph }
    'CloudSignins' { if (-not $Identity) { throw '-Identity required.' }; Get-CloudEvidence -User $Identity }
    'InvestigateUser' { Invoke-InvestigateUser }
    'ExportReport' { Invoke-ExportReport }
}
