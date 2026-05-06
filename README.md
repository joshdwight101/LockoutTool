# LockoutTool

A single **Lockout Intelligence** application delivered in two implementations with matching capabilities:

1. **Hybrid PowerShell + C# tool** (PowerShell-first app with embedded C# inference engine): `scripts/LockoutIntelligence.ps1`
2. **Pure C# tool** (managed-only implementation): `src/LockoutPureCSharp`

Both variants support:
- Domain controller discovery
- Locked-account search + filter
- Root-cause lockout intelligence from Security logs (4740/4771/4776/4625/4767)
- Bulk unlock preview and bulk unlock commit

## PowerShell + C# Hybrid tool

The script is a complete operations tool and compiles embedded C# (`Add-Type`) for inference logic.

```powershell
# Discover domain controllers
./scripts/LockoutIntelligence.ps1 -Mode Discover

# Search locked users (filter by partial account)
./scripts/LockoutIntelligence.ps1 -Mode Locked -Search ali

# Analyze one user with root-cause narrative + timeline
./scripts/LockoutIntelligence.ps1 -Mode Analyze -Identity alice

# Bulk unlock preview
./scripts/LockoutIntelligence.ps1 -Mode UnlockPreview -Users alice,bob

# Bulk unlock commit
./scripts/LockoutIntelligence.ps1 -Mode UnlockCommit -Users alice,bob
```

## Pure C# tool

```bash
dotnet run --project src/LockoutPureCSharp -- list-dcs
dotnet run --project src/LockoutPureCSharp -- search-locked
dotnet run --project src/LockoutPureCSharp -- events alice
dotnet run --project src/LockoutPureCSharp -- unlock user1 user2
```

## Optional C# host for AD PowerShell runspace

A C# host for in-process PowerShell (`src/LockoutHybrid`) is included for teams that want the same workflows from a .NET executable and can be extended to a desktop UI shell.

## Runtime notes

- Windows domain environment required.
- ActiveDirectory module required for hybrid PowerShell operations.
- Appropriate rights and event-log RPC/firewall access are required for remote DC evidence collection.
