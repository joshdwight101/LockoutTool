[CmdletBinding()]
param(
    [ValidateSet('Discover','Locked','Analyze','UnlockPreview','UnlockCommit')]
    [string]$Mode = 'Locked',
    [string]$Identity,
    [string]$Search,
    [string[]]$Users
)

Import-Module ActiveDirectory -ErrorAction Stop

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Linq;

public static class LockoutInferenceEngine
{
    public static string BuildNarrative(string identity, List<int> eventIds, List<string> messages)
    {
        var lines = new List<string>();
        lines.Add($"Lockout Intelligence Report for {identity}");
        lines.Add($"Evidence records: {eventIds.Count}");

        int Count(int id) => eventIds.Count(x => x == id);
        lines.Add($"Event 4740: {Count(4740)}");
        lines.Add($"Event 4771: {Count(4771)}");
        lines.Add($"Event 4776: {Count(4776)}");
        lines.Add($"Event 4625: {Count(4625)}");
        lines.Add($"Event 4767: {Count(4767)}");

        var probable = "No strong cause detected.";
        if (messages.Any(m => m.IndexOf("0x18", StringComparison.OrdinalIgnoreCase) >= 0))
            probable = "Likely Kerberos bad-password retries (0x18 evidence).";
        else if (eventIds.Any(x => x == 4776))
            probable = "Likely NTLM validation retries (4776 evidence).";
        else if (eventIds.Any(x => x == 4625))
            probable = "Likely endpoint/service/process logon failures (4625 evidence).";

        lines.Add($"Probable cause: {probable}");
        return string.Join(Environment.NewLine, lines);
    }
}
"@

function Invoke-Discover {
    Get-ADDomainController -Filter * |
        Select-Object HostName, Site, IsReadOnly, IsGlobalCatalog, IPv4Address
}

function Invoke-Locked {
    Search-ADAccount -LockedOut -UsersOnly |
        Select-Object SamAccountName, UserPrincipalName, LastBadPasswordAttempt, DistinguishedName |
        Where-Object {
            if ([string]::IsNullOrWhiteSpace($Search)) { return $true }
            $_.SamAccountName -like "*$Search*"
        }
}

function Get-LockoutEvidence {
    param([Parameter(Mandatory)] [string]$User)

    $ids = 4740, 4771, 4776, 4625, 4767
    $start = (Get-Date).AddHours(-8)

    $events = foreach ($dc in Get-ADDomainController -Filter *) {
        foreach ($id in $ids) {
            Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{
                LogName = 'Security'
                Id = $id
                StartTime = $start
            } -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -match [regex]::Escape($User) } |
                Select-Object TimeCreated, Id, MachineName, Message
        }
    }

    $events | Sort-Object TimeCreated -Descending
}

function Invoke-Analyze {
    if ([string]::IsNullOrWhiteSpace($Identity)) { throw "-Identity is required for Analyze mode." }

    $events = @(Get-LockoutEvidence -User $Identity)
    $ids = [System.Collections.Generic.List[int]]::new()
    $messages = [System.Collections.Generic.List[string]]::new()

    foreach ($e in $events) {
        [void]$ids.Add([int]$e.Id)
        [void]$messages.Add([string]$e.Message)
    }

    [LockoutInferenceEngine]::BuildNarrative($Identity, $ids, $messages)
    "`nTimeline (latest 25):"
    $events | Select-Object -First 25 TimeCreated, Id, MachineName
}

function Invoke-Unlock {
    param([bool]$Commit)
    if (-not $Users -or $Users.Count -eq 0) { throw "-Users is required." }

    $accounts = $Users | ForEach-Object { Get-ADUser -Identity $_ -ErrorAction Stop }
    if ($Commit) {
        $accounts | Unlock-ADAccount -Confirm:$false
        "Unlock commit complete for $($Users.Count) user(s)."
    }
    else {
        $accounts | Unlock-ADAccount -WhatIf
        "Unlock preview complete for $($Users.Count) user(s)."
    }
}

switch ($Mode) {
    'Discover' { Invoke-Discover }
    'Locked' { Invoke-Locked }
    'Analyze' { Invoke-Analyze }
    'UnlockPreview' { Invoke-Unlock -Commit:$false }
    'UnlockCommit' { Invoke-Unlock -Commit:$true }
}
