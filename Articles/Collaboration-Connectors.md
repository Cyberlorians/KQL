# Email and collaboration data sources and validation

Queries are on the [DFIR Customer Investigations](DFIR-Customer-Investigations.md) page. This guide covers where each product's data comes from and what was validated in the tenant (2026-10-14).

## Data sources

| Product | Query | Data source | Where it runs |
|---|---|---|---|
| Email (Microsoft Defender for Office 365) | [External communications](../Microsoft%20Defender%20for%20Office%20365/External-communications.kql), [Specific attachment filenames and hashes](../Microsoft%20Defender%20for%20Office%20365/Specific-attachment-filenames-and-hashes.kql), [Specific Subject lines](../Microsoft%20Defender%20for%20Office%20365/Specific-Subject-lines.kql), [Specific sender and recipients](../Microsoft%20Defender%20for%20Office%20365/Specific-sender-and-recipients.kql) | `EmailEvents`, `EmailAttachmentInfo` | Sentinel (Defender XDR connector, `TimeGenerated`) or Defender XDR Advanced Hunting (replace `TimeGenerated` with `Timestamp`). |
| Microsoft Teams | [Join/Leave times](../Microsoft%20Teams/Join-Leave-times.kql), [Meeting Duration](../Microsoft%20Teams/Meeting-Duration.kql), [SharedActivities](../Microsoft%20Teams/SharedActivities.kql) | Defender XDR `CallActivityEvents` | Defender XDR Advanced Hunting only. The table is not available in Sentinel / Log Analytics and has no Sentinel connector. |
| SharePoint | [Site/Page accessed/created/modified](../SharePoint/Site-Page-accessed-created-modified.kql), [Files uploaded/downloaded](../SharePoint/Files-uploaded-downloaded-from-a-SharePoint-site.kql) | Sentinel `OfficeActivity` | Sentinel / Log Analytics workspace logs |
| OneDrive | [User File activity](../OneDrive/User-File-activity.kql), [Sync activity](../OneDrive/Sync-activity.kql) | Sentinel `OfficeActivity` | Sentinel / Log Analytics workspace logs |

SharePoint and OneDrive require the Microsoft 365 (Office 365) Sentinel connector with the SharePoint feed enabled, and Microsoft Purview Audit turned on. OneDrive personal-site records can arrive under either the `OneDrive` or `SharePoint` workload; the queries classify them by workload and by personal-site URL. Teams audit collection in this connector is not used.

## Parameters

Edit the `let` values at the top of each query. Every query returns all rows by default; fill a list only to narrow the result. All nonempty values are combined with AND; empty values are ignored. Each `let` has an `// Example:` comment next to it.

| Parameter | Queries | Meaning |
|---|---|---|
| `StartTime`, `EndTime` | All | Event time window. Default `ago(30d)` to `now()`. |
| `TargetUsers` | Email (external communications, subject lines, attachments), Teams | Array of addresses or UPNs (case-insensitive exact match). Email: visible sender, envelope sender or recipient (attachments: sender or recipient). Teams: the user in `ActivityInitiatorUpn` / `OriginatorUpn`. |
| `TargetDirections` | Email (external communications) | `["Inbound"]`, `["Outbound"]`; empty = both. |
| `TargetSenders`, `TargetRecipients` | Email (sender and recipients) | Arrays of addresses; senders match the visible or envelope sender. |
| `TargetSubjects` | Email (subject lines) | Array of words or phrases; whole-word match, case-insensitive. |
| `TargetFileNames`, `TargetSHA256` | Email (attachments) | Filename words (whole-word, case-insensitive) and SHA-256 hashes. |
| `TargetUsers` | SharePoint | Array of addresses; matches `UserId` (case-insensitive exact) or the raw `Actor`. |
| `TargetOperations`, `TargetSites`, `TargetFileNames` | SharePoint files | Arrays: `FileUploaded` / `FileDownloaded` (empty = both); site or object URL words (whole-word, case-insensitive); exact file names. |
| `TargetSites`, `TargetFileNames` | SharePoint site/page | Arrays: site or object URL words (whole-word, case-insensitive); exact page names. |
| `TargetUser` | OneDrive | Exact `UserId` (case-insensitive), or a substring of raw `Actor` when that field is populated. |
| `TargetCallIds`, `TargetActivityTypes` | Teams | Arrays of exact `CallId` values and `ActivityType` values (`JoinCall`, `LeaveCall`, `StartShare`, `StopShare`). |
| `TargetOperation` | OneDrive | Exact operation from the query's allowlist. |
| `TargetSite`, `TargetFileName` | OneDrive | Case-insensitive substring of `Site_Url` or `OfficeObjectId`; exact source or destination file name. |
| Row cap | All | Email, Teams, SharePoint and OneDrive queries return the latest 1000 rows. |

A capped result can omit evidence. Narrow the time window rather than treating a capped result as complete.

## Validation in the tenant

Each query was run against live tenant data after real actions were performed, then checked against an independent query of the raw table. Every filter was tested alone and combined, with non-matching controls, case variants, window edges and empty windows.

| Product | Query | Live evidence used | Result |
|---|---|---|---|
| Email | [External communications](../Microsoft%20Defender%20for%20Office%20365/External-communications.kql) | Live `EmailEvents`; row counts matched an independent raw-table count (default, user, direction) | Validated |
| Email | [Specific sender and recipients](../Microsoft%20Defender%20for%20Office%20365/Specific-sender-and-recipients.kql) | Live `EmailEvents`; default, sender and recipient filters | Validated |
| Email | [Specific Subject lines](../Microsoft%20Defender%20for%20Office%20365/Specific-Subject-lines.kql) | Live `EmailEvents`; default, subject and subject + user filters | Validated |
| Email | [Specific attachment filenames and hashes](../Microsoft%20Defender%20for%20Office%20365/Specific-attachment-filenames-and-hashes.kql) | Live `EmailAttachmentInfo`; default, filename, SHA-256, user and non-matching filters | Validated |
| Teams | [Join/Leave times](../Microsoft%20Teams/Join-Leave-times.kql) | Real Teams call, JoinCall/LeaveCall | Validated |
| Teams | [Meeting Duration](../Microsoft%20Teams/Meeting-Duration.kql) | Real Teams call, first join to last leave per user | Validated |
| Teams | [SharedActivities](../Microsoft%20Teams/SharedActivities.kql) | StartShare/StopShare events | Validated for screen sharing |
| SharePoint | [Site/Page accessed/created/modified](../SharePoint/Site-Page-accessed-created-modified.kql) | Created, published, viewed and modified an `.aspx` page | Validated |
| SharePoint | [Files uploaded/downloaded](../SharePoint/Files-uploaded-downloaded-from-a-SharePoint-site.kql) | Browser upload/download of unique test files | Validated |
| OneDrive | [User File activity](../OneDrive/User-File-activity.kql) | Upload, download, copy, rename, recycle of unique test files | Validated |
| OneDrive | [Sync activity](../OneDrive/Sync-activity.kql) | Signed-in OneDrive.exe client: 4 `FileSyncUploadedFull` records | Validated for upload |

## Known limits

- **Camera and mute/unmute are not recorded.** `CallActivityEvents` has only `JoinCall`, `LeaveCall`, `StartShare` and `StopShare`, so SharedActivities cannot report camera or mute state.
- **Teams data is not in Sentinel.** Each join or leave can appear twice with different `ActivityId` values.
- **Sync download and partial operations were not observed.** `FileSyncDownloadedFull`, `FileSyncUploadedPartial` and `FileSyncDownloadedPartial` are in the allowlist but returned no rows in the tenant. Partial operations are legacy Groove.exe evidence.
- A generic upload (browser or Graph) is not sync evidence. Only the four `FileSync*` operations count.
- Operation labels do not prove transfer success or file contents. Inspect `ResultStatus` and the raw row.
- Audit generation and ingestion are delayed. Empty results can mean the event has not arrived yet.
- Records with no site or object URL cannot be classified as personal or non-personal by URL.
