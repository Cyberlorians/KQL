# Collaboration data sources and validation

Queries are on the [DFIR Customer Investigations](DFIR-Customer-Investigations.md) page. This guide covers where each product's data comes from and what was validated in the tenant (2026-10-14).

## Data sources

| Product | Query | Data source | Where it runs |
|---|---|---|---|
| Microsoft Teams | Join/Leave times, Meeting Duration, SharedActivities | Defender XDR `CallActivityEvents` | Defender XDR Advanced Hunting only. The table is not available in Sentinel / Log Analytics and has no Sentinel connector. |
| SharePoint | Site/Page accessed/created/modified, Files uploaded/downloaded | Sentinel `OfficeActivity` | Sentinel / Log Analytics workspace logs |
| OneDrive | User File activity, Sync activity | Sentinel `OfficeActivity` | Sentinel / Log Analytics workspace logs |

SharePoint and OneDrive require the Microsoft 365 (Office 365) Sentinel connector with the SharePoint feed enabled, and Microsoft Purview Audit turned on. OneDrive personal-site records can arrive under either the `OneDrive` or `SharePoint` workload; the queries classify them by workload and by personal-site URL. Teams audit collection in this connector is not used.

## Parameters

Edit the `let` values at the top of each query. All nonempty values are combined with AND; empty values are ignored.

| Parameter | Queries | Meaning |
|---|---|---|
| `StartTime`, `EndTime` | All | Event time window. Default `ago(30d)` to `now()`. |
| `TargetUser` | All | Teams: exact UPN (case-insensitive). SharePoint/OneDrive: exact `UserId` (case-insensitive), or a substring of raw `Actor` when that field is populated. |
| `TargetCallId` | Teams | Exact `CallId`. |
| `TargetOperation` | SharePoint files, OneDrive | Exact operation from the query's allowlist. |
| `TargetSite` | SharePoint, OneDrive | Case-insensitive substring of `Site_Url` or `OfficeObjectId`. |
| `TargetFileName` | SharePoint, OneDrive | Exact source or destination file name (case-insensitive). |
| `MaxRows` | Teams | Row cap, at most 1000. SharePoint and OneDrive queries return the latest 1000 rows. |

A capped result can omit evidence. Narrow the time window rather than treating a capped result as complete.

## Validation in the tenant

Each query was run against live tenant data after real actions were performed, then checked against an independent query of the raw table. Every filter was tested alone and combined, with non-matching controls, case variants, window edges and empty windows.

| Product | Query | Live evidence used | Result |
|---|---|---|---|
| Teams | Join/Leave times | Real Teams call, JoinCall/LeaveCall | Validated |
| Teams | Meeting Duration | Real Teams call, first join to last leave per user | Validated |
| Teams | SharedActivities | StartShare/StopShare events | Validated for screen sharing |
| SharePoint | Site/Page accessed/created/modified | Created, published, viewed and modified an `.aspx` page | Validated |
| SharePoint | Files uploaded/downloaded | Browser upload/download of unique test files | Validated |
| OneDrive | User File activity | Upload, download, copy, rename, recycle of unique test files | Validated |
| OneDrive | Sync activity | Signed-in OneDrive.exe client: 4 `FileSyncUploadedFull` records | Validated for upload |

## Known limits

- **Camera and mute/unmute are not recorded.** `CallActivityEvents` has only `JoinCall`, `LeaveCall`, `StartShare` and `StopShare`, so SharedActivities cannot report camera or mute state.
- **Teams data is not in Sentinel.** Each join or leave can appear twice with different `ActivityId` values.
- **Sync download and partial operations were not observed.** `FileSyncDownloadedFull`, `FileSyncUploadedPartial` and `FileSyncDownloadedPartial` are in the allowlist but returned no rows in the tenant. Partial operations are legacy Groove.exe evidence.
- A generic upload (browser or Graph) is not sync evidence. Only the four `FileSync*` operations count.
- Operation labels do not prove transfer success or file contents. Inspect `ResultStatus` and the raw row.
- Audit generation and ingestion are delayed. Empty results can mean the event has not arrived yet.
- Records with no site or object URL cannot be classified as personal or non-personal by URL.
