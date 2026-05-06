# Changelog

## [1.2.0] - 2026-05-06
### Added
- Per-user `LockoutObservedOnDC` aggregation from multi-DC lockout queries.
- Improved locked-user retrieval using per-DC LDAP lockout queries (`lockoutTime>=1`) with fallback.

### Changed
- Title bars and About dialog updated to `v1.2`.

## [1.1.0] - 2026-05-06
### Added
- Resizable/anchored grid behavior with horizontal scrolling.
- About dialog with clickable GitHub hyperlink.
- Lockout source DC column (`LockoutObservedOnDC`) in account view.
- Fallback locked-user query path for environments where `Search-ADAccount -LockedOut` misses users.
- Version tracking document for ongoing release notes.

### Changed
- App title updated to `Lockout Intelligence v1.1 - by Joshua Dwight`.
- Locked account cache builder now aggregates per-DC lockout observations and stores source DC metadata.

## [1.0.0] - 2026-05-06
### Added
- Initial PowerShell GUI lockout investigation tool.
- Initial C# WinForms companion app.
- AD + cloud sign-in investigation and unlock workflows.
