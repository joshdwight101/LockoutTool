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
    Ensure-ADModule
    param([Parameter(Mandatory)] [string]$User)
    $ids = 4740, 4771, 4776, 4625, 4767
    $start = (Get-Date).AddHours(-1 * $Hours)

    foreach ($dc in Get-ADDomainController -Filter *) {
        foreach ($id in $ids) {
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

    $start = (Get-Date).AddHours(-1 * $Hours).ToString("o")
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
    Ensure-ADModule
    param([bool]$Commit)
    if (-not $Users -or $Users.Count -eq 0) { throw "-Users is required." }

    $accounts = $Users | ForEach-Object { Get-ADUser -Identity $_ -ErrorAction Stop }
    if ($Commit) {
        Write-OperatorLog "Committing unlock for $($Users -join ', ')."
        $accounts | Unlock-ADAccount -Confirm:$false
    } else {
        Write-OperatorLog "Previewing unlock for $($Users -join ', ')."
        $accounts | Unlock-ADAccount -WhatIf
    }

    $modeLabel = if ($Commit) { 'Commit' } else { 'Preview' }
    [pscustomobject]@{ Timestamp=Get-Date; Mode=$modeLabel; Users=($Users -join ',') }
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
    $form.Text = 'Lockout Intelligence - PowerShell GUI | Author: Joshua Dwight (@joshdwight101)'
    $form.Width = 1280; $form.Height = 820

    $lblSearch = New-Object Windows.Forms.Label
    $lblSearch.Text = 'Search User (real-time filter):'
    $lblSearch.SetBounds(10,8,220,20)
    $txtSearch = New-Object Windows.Forms.TextBox
    $txtSearch.SetBounds(10,28,260,25)

    $chkLocked = New-Object Windows.Forms.CheckBox
    $chkLocked.Text='Show Locked'; $chkLocked.Checked=$true; $chkLocked.SetBounds(280,30,110,24)
    $chkDisabled = New-Object Windows.Forms.CheckBox
    $chkDisabled.Text='Show Disabled'; $chkDisabled.Checked=$true; $chkDisabled.SetBounds(395,30,120,24)

    $lblHours = New-Object Windows.Forms.Label
    $lblHours.Text='Diagnostic Lookback Hours:'
    $lblHours.SetBounds(530,8,180,20)
    $hours = New-Object Windows.Forms.NumericUpDown
    $hours.SetBounds(530,28,90,25); $hours.Minimum=1; $hours.Maximum=72; $hours.Value=8

    $grid = New-Object Windows.Forms.DataGridView
    $grid.SetBounds(10,95,1240,530)
    $grid.ReadOnly = $false
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $false
    $grid.AutoSizeColumnsMode = 'Fill'
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $grid.DefaultCellStyle.BackColor = [System.Drawing.Color]::White
    $grid.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black

    $log = New-Object Windows.Forms.TextBox
    $log.Multiline = $true; $log.ScrollBars = 'Vertical'; $log.SetBounds(10,635,1240,140)

    function Write-Log([string]$t){ $log.Text = "$(Get-Date -Format T) - $t`r`n" + $log.Text }
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


    function Load-UserGrid {
        Ensure-ADModule
        $items = @()
        if ($chkLocked.Checked) {
            $items += Search-ADAccount -LockedOut -UsersOnly | Get-ADUser -Properties Enabled,LockedOut,LastBadPasswordAttempt,BadLogonCount
        }
        if ($chkDisabled.Checked) {
            $items += Search-ADAccount -AccountDisabled -UsersOnly | Get-ADUser -Properties Enabled,LockedOut,LastBadPasswordAttempt,BadLogonCount
        }

        $items = $items | Sort-Object SamAccountName -Unique
        if ($txtSearch.Text) {
            $q = [regex]::Escape($txtSearch.Text)
            $items = $items | Where-Object { $_.SamAccountName -match $q -or $_.UserPrincipalName -match $q -or $_.DisplayName -match $q }
        }

        $table = New-Object System.Data.DataTable
        [void]$table.Columns.Add('Select', [bool])
        [void]$table.Columns.Add('SamAccountName', [string])
        [void]$table.Columns.Add('DisplayName', [string])
        [void]$table.Columns.Add('UserPrincipalName', [string])
        [void]$table.Columns.Add('Enabled', [string])
        [void]$table.Columns.Add('LockedOut', [string])
        [void]$table.Columns.Add('BadLogonCount', [string])
        [void]$table.Columns.Add('LastBadPasswordAttempt', [string])

        foreach ($u in $items) {
            $r = $table.NewRow()
            $r['Select'] = $false
            $r['SamAccountName'] = [string]$u.SamAccountName
            $r['DisplayName'] = [string]$u.DisplayName
            $r['UserPrincipalName'] = [string]$u.UserPrincipalName
            $r['Enabled'] = [string]$u.Enabled
            $r['LockedOut'] = [string]$u.LockedOut
            $r['BadLogonCount'] = [string]$u.BadLogonCount
            $r['LastBadPasswordAttempt'] = [string]$u.LastBadPasswordAttempt
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
        $script:Identity = $name; $script:Hours = [int]$hours.Value
        $result = Invoke-Analyze | Out-String
        Write-Log "Diagnostics complete for $name"
        [Windows.Forms.MessageBox]::Show($result, "Root Cause Diagnostics - $name") | Out-Null
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
    $chkLocked.Add_CheckedChanged({ Invoke-SafeUiAction { Load-UserGrid } })
    $chkDisabled.Add_CheckedChanged({ Invoke-SafeUiAction { Load-UserGrid } })

    $context = New-Object Windows.Forms.ContextMenuStrip
    $context.Items.Add('Run Root Cause Diagnostics').add_Click({ Invoke-SafeUiAction { Analyze-SelectedUser } }) | Out-Null
    $context.Items.Add('Unlock Selected User (Preview)').add_Click({
        Invoke-SafeUiAction { if ($grid.SelectedRows.Count -gt 0) { $script:Users=@([string]$grid.SelectedRows[0].Cells['SamAccountName'].Value); Write-Log ((Invoke-Unlock -Commit:$false)|Out-String) } }
    }) | Out-Null
    $context.Items.Add('Unlock Selected User (Commit)').add_Click({
        Invoke-SafeUiAction { if ($grid.SelectedRows.Count -gt 0) { $script:Users=@([string]$grid.SelectedRows[0].Cells['SamAccountName'].Value); Write-Log ((Invoke-Unlock -Commit:$true)|Out-String); Load-UserGrid } }
    }) | Out-Null
    $grid.ContextMenuStrip = $context

    $btnRefresh = New-Object Windows.Forms.Button
    $btnRefresh.Text='Refresh Accounts'; $btnRefresh.SetBounds(10,60,140,28)
    $btnRefresh.Add_Click({ Invoke-SafeUiAction { Load-UserGrid } })

    $btnAnalyze = New-Object Windows.Forms.Button
    $btnAnalyze.Text='Analyze Selected'; $btnAnalyze.SetBounds(160,60,130,28)
    $btnAnalyze.Add_Click({ Invoke-SafeUiAction { Analyze-SelectedUser } })

    $btnUnlockPreview = New-Object Windows.Forms.Button
    $btnUnlockPreview.Text='Unlock Checked (Preview)'; $btnUnlockPreview.SetBounds(300,60,170,28)
    $btnUnlockPreview.Add_Click({ Invoke-SafeUiAction { Unlock-Checked -Commit:$false } })

    $btnUnlockCommit = New-Object Windows.Forms.Button
    $btnUnlockCommit.Text='Unlock Checked (Commit)'; $btnUnlockCommit.SetBounds(480,60,170,28)
    $btnUnlockCommit.Add_Click({ Invoke-SafeUiAction { Unlock-Checked -Commit:$true } })

    $btnCloud = New-Object Windows.Forms.Button
    $btnCloud.Text='Cloud Sign-ins for Selected'; $btnCloud.SetBounds(660,60,180,28)
    $btnCloud.Add_Click({ Invoke-SafeUiAction {
        if ($grid.SelectedRows.Count -eq 0) { return }
        $id = [string]$grid.SelectedRows[0].Cells['UserPrincipalName'].Value
        if (-not $id) { return }
        $script:Identity = $id; $script:Hours=[int]$hours.Value
        $cloud = Get-CloudEvidence -User $id | Out-String
        [Windows.Forms.MessageBox]::Show($cloud, "Cloud Sign-ins - $id") | Out-Null
    }} )

    $form.Controls.AddRange(@($lblSearch,$txtSearch,$chkLocked,$chkDisabled,$lblHours,$hours,$grid,$log,$btnRefresh,$btnAnalyze,$btnUnlockPreview,$btnUnlockCommit,$btnCloud))
    $form.Add_Shown({ Invoke-SafeUiAction { Load-UserGrid } })
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
    'UnlockPreview' { Invoke-Unlock -Commit:$false }
    'UnlockCommit' { Invoke-Unlock -Commit:$true }
    'ConnectCloud' { Connect-CloudGraph }
    'CloudSignins' { if (-not $Identity) { throw '-Identity required.' }; Get-CloudEvidence -User $Identity }
    'InvestigateUser' { Invoke-InvestigateUser }
    'ExportReport' { Invoke-ExportReport }
}
