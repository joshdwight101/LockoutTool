[CmdletBinding()]
param(
    [ValidateSet('DiscoverDCs','SearchLocked','Correlate','UnlockPreview','UnlockCommit')]
    [string]$Mode = 'SearchLocked',
    [string]$Identity,
    [string[]]$Users
)

Import-Module ActiveDirectory -ErrorAction Stop

function Get-DomainControllerHealth {
    Get-ADDomainController -Filter * | ForEach-Object {
        [pscustomobject]@{
            HostName = $_.HostName
            Site = $_.Site
            IPv4Address = $_.IPv4Address
            IsReadOnly = $_.IsReadOnly
            IsGlobalCatalog = $_.IsGlobalCatalog
        }
    }
}

function Get-LockedUsers {
    Search-ADAccount -LockedOut -UsersOnly |
        Select-Object SamAccountName, UserPrincipalName, LastLogonDate, DistinguishedName
}

function Get-LockoutEvidence {
    param([Parameter(Mandatory)] [string]$User)

    $ids = 4740, 4771, 4776, 4625, 4767
    $start = (Get-Date).AddHours(-8)

    Get-ADDomainController -Filter * | ForEach-Object {
        $dc = $_.HostName
        foreach ($id in $ids) {
            Get-WinEvent -ComputerName $dc -FilterHashtable @{
                LogName = 'Security'
                Id = $id
                StartTime = $start
            } -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -match [regex]::Escape($User) } |
                Select-Object TimeCreated, Id, MachineName, Message
        }
    } | Sort-Object TimeCreated -Descending
}

switch ($Mode) {
    'DiscoverDCs' { Get-DomainControllerHealth }
    'SearchLocked' { Get-LockedUsers }
    'Correlate' { Get-LockoutEvidence -User $Identity }
    'UnlockPreview' {
        $Users | ForEach-Object { Get-ADUser -Identity $_ } | Unlock-ADAccount -WhatIf
    }
    'UnlockCommit' {
        $Users | ForEach-Object { Get-ADUser -Identity $_ } | Unlock-ADAccount -Confirm
    }
}
