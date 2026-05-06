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
    $form.Text = 'Lockout Intelligence - PowerShell GUI'
    $form.Width = 1200; $form.Height = 760

    $lblIdentity = New-Object Windows.Forms.Label
    $lblIdentity.Text = 'Identity (sAMAccountName or UPN)'
    $lblIdentity.SetBounds(10,8,240,18)

    $identity = New-Object Windows.Forms.TextBox
    $identity.SetBounds(10,26,300,25)

    $lblUsers = New-Object Windows.Forms.Label
    $lblUsers.Text = 'Bulk Unlock Users (comma separated)'
    $lblUsers.SetBounds(320,8,240,18)

    $users = New-Object Windows.Forms.TextBox
    $users.SetBounds(320,26,220,25)

    $lblHours = New-Object Windows.Forms.Label
    $lblHours.Text = 'Lookback Hours'
    $lblHours.SetBounds(550,8,120,18)

    $hours = New-Object Windows.Forms.NumericUpDown
    $hours.SetBounds(550,26,90,25); $hours.Minimum=1; $hours.Maximum=72; $hours.Value=8

    $grid = New-Object Windows.Forms.DataGridView
    $grid.SetBounds(10,90,1160,500)
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $false

    $log = New-Object Windows.Forms.TextBox
    $log.Multiline = $true; $log.ScrollBars = 'Vertical'; $log.SetBounds(10,600,1160,110)

    function Set-GridData($data) {
        if (-not $data) { $grid.DataSource = $null; return }
        if ($data -is [string]) { $log.Text = $data; return }
        $grid.DataSource = @($data)
    }

    function Set-Log($txt) {
        $log.Text = ($txt | Out-String)
    }

    $context = New-Object Windows.Forms.ContextMenuStrip
    $miAnalyze = $context.Items.Add('Analyze Selected User')
    $miPreview = $context.Items.Add('Unlock Preview Selected User')
    $miCommit = $context.Items.Add('Unlock Commit Selected User')
    $miCopy = $context.Items.Add('Copy Selected Cell')

    $miAnalyze.add_Click({
        if ($grid.SelectedRows.Count -eq 0) { return }
        $row = $grid.SelectedRows[0]
        $name = [string]$row.Cells['SamAccountName'].Value
        if (-not $name) { $name = [string]$row.Cells[0].Value }
        $script:Identity = $name; $identity.Text = $name; $script:Hours = [int]$hours.Value
        Set-Log (Invoke-Analyze)
    })

    $miPreview.add_Click({
        if ($grid.SelectedRows.Count -eq 0) { return }
        $row = $grid.SelectedRows[0]
        $name = [string]$row.Cells['SamAccountName'].Value
        if (-not $name) { $name = [string]$row.Cells[0].Value }
        $script:Users = @($name)
        Set-Log (Invoke-Unlock -Commit:$false)
    })

    $miCommit.add_Click({
        if ($grid.SelectedRows.Count -eq 0) { return }
        $row = $grid.SelectedRows[0]
        $name = [string]$row.Cells['SamAccountName'].Value
        if (-not $name) { $name = [string]$row.Cells[0].Value }
        $script:Users = @($name)
        Set-Log (Invoke-Unlock -Commit:$true)
    })

    $miCopy.add_Click({
        if ($grid.SelectedCells.Count -gt 0) { [Windows.Forms.Clipboard]::SetText([string]$grid.SelectedCells[0].Value) }
    })

    $grid.ContextMenuStrip = $context

    $btnDiscover = New-Object Windows.Forms.Button
    $btnDiscover.Text='Discover'; $btnDiscover.SetBounds(10,56,90,28)
    $btnDiscover.Add_Click({ Set-GridData (Invoke-Discover) })

    $btnLocked = New-Object Windows.Forms.Button
    $btnLocked.Text='Locked'; $btnLocked.SetBounds(110,56,90,28)
    $btnLocked.Add_Click({ $script:Search=''; Set-GridData (Invoke-Locked) })

    $btnAnalyze = New-Object Windows.Forms.Button
    $btnAnalyze.Text='Analyze'; $btnAnalyze.SetBounds(210,56,90,28)
    $btnAnalyze.Add_Click({ $script:Identity=$identity.Text; $script:Hours=[int]$hours.Value; Set-Log (Invoke-Analyze) })

    $btnCloud = New-Object Windows.Forms.Button
    $btnCloud.Text='Cloud'; $btnCloud.SetBounds(310,56,90,28)
    $btnCloud.Add_Click({ $script:Identity=$identity.Text; $script:Hours=[int]$hours.Value; Set-GridData (Get-CloudEvidence -User $identity.Text) })

    $btnPreview = New-Object Windows.Forms.Button
    $btnPreview.Text='Unlock Preview'; $btnPreview.SetBounds(410,56,110,28)
    $btnPreview.Add_Click({ $script:Users=$users.Text.Split(','); Set-Log (Invoke-Unlock -Commit:$false) })

    $btnCommit = New-Object Windows.Forms.Button
    $btnCommit.Text='Unlock Commit'; $btnCommit.SetBounds(530,56,110,28)
    $btnCommit.Add_Click({ $script:Users=$users.Text.Split(','); Set-Log (Invoke-Unlock -Commit:$true) })

    $form.Controls.AddRange(@($lblIdentity,$identity,$lblUsers,$users,$lblHours,$hours,$grid,$log,$btnDiscover,$btnLocked,$btnAnalyze,$btnCloud,$btnPreview,$btnCommit))
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
