# LockoutTool

Domain Controller and Office365 User Lockout Intelligence Tool.

## Implemented deliverables

This repository now includes two working implementations:

1. **Hybrid PowerShell + C#** (`src/LockoutHybrid`)  
   * C# host with an embedded PowerShell runspace.
   * Uses AD cmdlets (`Get-ADDomainController`, `Search-ADAccount`, `Unlock-ADAccount`) through in-process PowerShell.
   * Implements safe bulk unlock preview (`-WhatIf`) as default unlock behavior.

2. **Pure C# implementation** (`src/LockoutPureCSharp`)  
   * Uses only .NET APIs for domain discovery, lockout status checks, event-log retrieval, and unlock operations.
   * Uses `Domain.GetCurrentDomain()`, `PrincipalSearcher` / `UserPrincipal`, and `EventLogReader`.

A companion PowerShell workflow script is also included:

* `scripts/LockoutIntelligence.ps1`

## Hybrid app usage

```bash
dotnet run --project src/LockoutHybrid -- list-dcs
dotnet run --project src/LockoutHybrid -- search-locked
dotnet run --project src/LockoutHybrid -- unlock user1 user2
```

## Pure C# app usage

```bash
dotnet run --project src/LockoutPureCSharp -- list-dcs
dotnet run --project src/LockoutPureCSharp -- search-locked
dotnet run --project src/LockoutPureCSharp -- events alice
# performs real unlock for specified users
dotnet run --project src/LockoutPureCSharp -- unlock user1 user2
```

## PowerShell script usage

```powershell
# Discover domain controllers
./scripts/LockoutIntelligence.ps1 -Mode DiscoverDCs

# Find locked users
./scripts/LockoutIntelligence.ps1 -Mode SearchLocked

# Correlate lockout events (4740/4771/4776/4625/4767)
./scripts/LockoutIntelligence.ps1 -Mode Correlate -Identity alice

# Preview bulk unlock
./scripts/LockoutIntelligence.ps1 -Mode UnlockPreview -Users alice,bob
```

## Notes

* Both implementations are designed for **Windows domain-admin runtime environments** with the required RSAT/AD module and audit/log access.
* The hybrid version is optimized for compatibility with existing operational PowerShell playbooks.
* The pure C# version is optimized for a future desktop UX where all logic can remain in managed code.
