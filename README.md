# LockoutTool - Hybrid Lockout Intelligence Console

This repository provides exactly two apps for the same Lockout Intelligence platform:

1. **PowerShell GUI app (with embedded C# intelligence):** `scripts/LockoutIntelligence.ps1`
2. **C# GUI app:** `src/LockoutHybrid`

Both are designed as investigation consoles (not just unlock helpers) with:
- Multi-DC discovery
- Locked account search/filter
- Event-correlation intelligence (4740/4771/4776/4625/4767)
- Bulk unlock preview + commit
- Hybrid identity evidence path (on-prem + Microsoft 365/Entra sign-ins)
- Exportable investigation report

## PowerShell + C# Hybrid Tool

### GUI and modes
- `Discover`
- `Locked`
- `Analyze`
- `InvestigateUser`
- `ConnectCloud`
- `CloudSignins`
- `UnlockPreview`
- `UnlockCommit`
- `ExportReport`

### Examples
```powershell
# launch full PowerShell GUI (default)
./scripts/LockoutIntelligence.ps1

# discover domain controllers
./scripts/LockoutIntelligence.ps1 -Mode Discover

# list locked users with filter
./scripts/LockoutIntelligence.ps1 -Mode Locked -Search alice

# analyze on-prem lockout evidence for one user
./scripts/LockoutIntelligence.ps1 -Mode Analyze -Identity alice

# connect graph once per session
./scripts/LockoutIntelligence.ps1 -Mode ConnectCloud

# full dual-evidence investigation (on-prem + cloud)
./scripts/LockoutIntelligence.ps1 -Mode InvestigateUser -Identity alice@contoso.com -Hours 12

# export investigation package to JSON
./scripts/LockoutIntelligence.ps1 -Mode ExportReport -Identity alice@contoso.com -OutputPath .\alice-lockout-report.json

# bulk unlock safety preview first, then commit
./scripts/LockoutIntelligence.ps1 -Mode UnlockPreview -Users alice,bob
./scripts/LockoutIntelligence.ps1 -Mode UnlockCommit -Users alice,bob
```

## C# app variant

```bash
# launch full C# GUI
dotnet run --project src/LockoutHybrid
```

## Required prerequisites

### On-prem AD
- Windows host joined to domain.
- RSAT Active Directory module installed.
- Security log access to relevant domain controllers.
- Firewall/RPC rules for remote event log queries.

### Cloud / Microsoft 365
- Microsoft Graph PowerShell modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Reports`
- Graph delegated permissions at minimum:
  - `AuditLog.Read.All`
  - `Directory.Read.All`

## Troubleshooting common errors

- **`Import-Module ActiveDirectory` fails**: install RSAT AD tools and run in elevated PowerShell.
- **Remote event log access errors**: verify DC firewall rules for Remote Event Log Management and RPC.
- **`Get-MgAuditLogSignIn` permission errors**: consent required Graph scopes and reconnect via `ConnectCloud` mode.
- **No cloud results**: use UPN format for `-Identity` (for example `alice@contoso.com`).
