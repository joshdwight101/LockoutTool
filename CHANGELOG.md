# Changelog

## [1.2.2] - 2026-05-06
### Fixed
- Improved LockedOut column behavior in locked-user views to better reflect lockout-focused filtering.
- Added in-analysis progress updates and UI status/progress indicators to reduce non-responding perception during diagnostics.
- Added copy-friendly diagnostics dialog with a dedicated Copy Report action.
- Added additional fallback narrative guidance when only lockout confirmation events (4740) are available.

## [1.2.1] - 2026-05-06
### Fixed
- Resolved analyze/diagnostics runtime failure caused by NumericUpDown shadowing the `$Hours` value.
- Updated lockout source mapping so `LockoutObservedOnDC` reports the earliest observed lockout DC per user instead of listing all DCs.
- Hardened lookback-hour calculations in on-prem and cloud evidence collection by coercing to numeric values.

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
