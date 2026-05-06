[CmdletBinding()]
param(
    [ValidateSet('Discover','Locked','Analyze','UnlockPreview','UnlockCommit','ConnectCloud','CloudSignins','InvestigateUser','ExportReport')]
    [string]$Mode = 'InvestigateUser',
    [string]$Identity,
    [string]$Search,
    [string[]]$Users,
    [int]$Hours = 8,
    [string]$OutputPath = ".\lockout-report.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Linq;

public class LockoutSignal {
  public int EventId { get; set; }
  public string Machine { get; set; } = "";
  public string Message { get; set; } = "";
}

public static class LockoutInferenceEngine
{
    public static string BuildNarrative(string identity, List<LockoutSignal> signals)
    {
        int Count(int id) => signals.Count(x => x.EventId == id);
        var probable = "No strong cause detected.";

        if (signals.Any(s => s.EventId == 4771 && s.Message.IndexOf("0x18", StringComparison.OrdinalIgnoreCase) >= 0))
            probable = "High confidence: Kerberos bad-password retries (4771 + 0x18).";
        else if (signals.Any(s => s.EventId == 4776))
            probable = "Medium confidence: NTLM source workstation retry pattern (4776).";
        else if (signals.Any(s => s.EventId == 4625))
            probable = "Medium confidence: endpoint/service task credential failure pattern (4625).";

        var topMachines = signals.GroupBy(s => s.Machine)
            .OrderByDescending(g => g.Count())
            .Take(3)
            .Select(g => $"{g.Key} ({g.Count()})");

        return string.Join(Environment.NewLine, new [] {
            $"Lockout Intelligence Report for {identity}",
            $"Events: 4740={Count(4740)}, 4771={Count(4771)}, 4776={Count(4776)}, 4625={Count(4625)}, 4767={Count(4767)}",
            $"Likely cause: {probable}",
            $"Top source systems: {string.Join(", ", topMachines)}"
        });
    }
}
"@

function Write-OperatorLog {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format o)] $Message" -ForegroundColor Cyan
}

function Invoke-Discover {
    Write-OperatorLog "Discovering domain controllers and health context."
    $domain = Get-ADDomain -Current LoggedOnUser
    $pdc = $domain.PDCEmulator

    Get-ADDomainController -Filter * | Select-Object HostName, Site, IsReadOnly, IsGlobalCatalog, IPv4Address,
        @{Name='IsPDC';Expression={ $_.HostName -eq $pdc }}
}

function Invoke-Locked {
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

    [pscustomobject]@{ Timestamp=Get-Date; Mode=($Commit ? 'Commit':'Preview'); Users=$Users -join ',' }
}

function Invoke-ExportReport {
    $report = Invoke-InvestigateUser
    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-OperatorLog "Report written to $OutputPath"
    Get-Item $OutputPath
}

switch ($Mode) {
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
