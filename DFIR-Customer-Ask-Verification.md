# DFIR Customer Ask — KQL Verification Tracker

**Repository:** [Cyberlorians/KQL](https://github.com/Cyberlorians/KQL)  
**Tenant context:** DIB Security Commercial  
**Sentinel workspace:** `DIBSecCom` (`7e9298ab-22e6-4a82-a53e-c5ed7faee977`)  
**Validation date:** 2026-10-13  
**Validation method:** Microsoft Sentinel Data Exploration MCP against the live workspace

## Live rerun log — 2026-10-13

All twelve saved artifacts in `C:\tools\kqlDFIR\validated\` were rerun individually against the live workspace. All twelve completed successfully. The exact timeline artifact also completed successfully and returned zero rows because it still contains the placeholder `user@dibsecurity.onmicrosoft.com` rather than a confirmed investigation UPN.

The live counts are time-sensitive. The second run returned: `OfficeActivity` 2,001 rows; `DeviceEvents` 145,748 rows; `SigninLogs` 465 rows; `IdentityLogonEvents` 59 rows; `AuditLogs` 11,865 rows; `IdentityDirectoryEvents` 173 rows; `IdentityInfo` 558 rows; and `SecurityEvent` 0 rows for the tested network-share event IDs.

## KQL Search grounding

KQL Search was opened in the shared browser and searched for `Teams calls`. It returned the community query **Threat Hunting Microsoft Teams Calls By TLD**, using `CallActivityEvents`, with a GitHub source link. This supports the schema distinction that Teams call telemetry may be in `CallActivityEvents` rather than `OfficeActivity`; it does not validate DIBSecCom data. A broader search combining multiple terms returned no result, so KQL Search is treated as supplemental grounding only, never as tenant evidence.

## Verification standard

A query is marked **Executed** only after it ran successfully against the live workspace. A query is marked **Data confirmed** only when the requested evidence returned matching records. A successful query with zero results is not treated as proof that the data source is unsupported.

## Customer ask tracker

| # | Use case | Query/table | Status | Live evidence |
|---:|---|---|---|---|
| 1 | Email investigations — external communications, attachments, subject lines, sender/recipients | `OfficeActivity` | **Partial** | 2,001 rows; sender/recipient evidence 2,001; external-sharing heuristic 1,496; attachment and subject/item evidence 0 |
| 2 | Teams calls and meetings — join/leave, duration, shared activity, camera/mute | `OfficeActivity` | **Executed; data not confirmed** | Query succeeded; all four evidence counters returned 0 |
| 3 | SharePoint — sites/pages, file activity, sharing | `OfficeActivity` | **Data confirmed** | Site/page evidence 8; file activity 6; sharing evidence 1,968 |
| 4 | OneDrive — user activity, sync, file activity | `OfficeActivity` | **Partial** | 5 OneDrive-matching rows; user activity 5; file activity 4; sync evidence 0 |
| 5 | Device logon events | `DeviceEvents` | **Data confirmed** | 16 logon-action matches; account evidence 139,751; session evidence 1,497 |
| 6 | User logon events | `SigninLogs`, `IdentityLogonEvents` | **Data confirmed** | `SigninLogs` 463; `IdentityLogonEvents` 59 |
| 7 | User device activity — USB, hardware, file origin, DLP, process, scripts, registry, scheduled tasks, tampering | `DeviceEvents` | **Partial** | USB 5,940; hardware 477; process 125,326; registry 9; other requested heuristics returned 0 |
| 8 | Web activity — sites visited and browsers used | `DeviceEvents` | **Partial** | URL/site evidence 1,243; browser-action heuristic 0 |
| 9 | Network-share activity — access, create, modify, delete | `SecurityEvent` | **Executed; data not confirmed** | Tested Event IDs 5140/5142/5143/5144/5145 returned 0 rows |
| 10 | User activity event timeline | `OfficeActivity` + `DeviceEvents` | **Executed; requires target** | Normalized union succeeded; placeholder UPN returned no rows |
| 11 | User identity and access context | `AuditLogs`, `IdentityDirectoryEvents`, `IdentityInfo` | **Data confirmed** | `AuditLogs` 11,865; `IdentityDirectoryEvents` 173; `IdentityInfo` 558 |
| 12 | File metadata — filename, extension, hash, size | `DeviceEvents`, `OfficeActivity` | **Data confirmed** | Endpoint filenames 11,204; extensions 11,154; hashes 10,359; sizes 36,045; OfficeActivity filenames 6; extensions 1 |

## Repository grounding

This tracker is grounded in the following repositories:

- [Cyberlorians/KQL](https://github.com/Cyberlorians/KQL) — organization-specific Entra, Defender, Defender for Identity, Windows `SecurityEvent`, logon, network-share, removable-media, file/object-access, and identity queries.
- [reprise99/Sentinel-Queries](https://github.com/reprise99/Sentinel-Queries) — Sentinel fundamentals, Office 365 activity/file monitoring, Entra sign-in/audit patterns, and Sentinel versus Advanced Hunting differences.
- [ep3p/Sentinel_KQL](https://github.com/ep3p/Sentinel_KQL) — broader Sentinel query patterns and reusable functions.

## Next validation work

1. Identify the exact Office 365 audit operation names and connector coverage for Teams meeting telemetry.
2. Confirm whether Exchange attachment metadata is available through `OfficeActivity`, `EmailEvents`, `EmailAttachmentInfo`, or Purview exports.
3. Confirm OneDrive sync operation names and retention.
4. Confirm Defender action names for DLP, scripts, scheduled tasks, and tampering instead of relying on broad heuristics.
5. Confirm Windows Security audit collection for Event IDs 5140–5145 and removable-media events.
6. Replace the timeline placeholder with an actual investigation UPN and rerun it.
7. Add one production-ready KQL file per completed customer sub-ask after the evidence and schema are confirmed.

## Important limitation

These results describe the current workspace schema and the tested 30-day window. Zero results may indicate missing connectors, retention limits, audit-policy settings, action-name differences, or simply no activity in the window. They require follow-up before a production detection or analytic rule is declared complete.
