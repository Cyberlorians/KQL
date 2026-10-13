# Collaboration audit connectors and reproducible validation

**Status: DRAFTS — live execution confirmed; positive seeded coverage validation pending (2026-10-13).** All seven exact saved queries executed successfully against live Sentinel `OfficeActivity`. OneDrive User File activity returned 2 records; the other six returned zero. Execution PASS is not positive coverage PASS, and an empty result is NOT proof that an action did not occur. All other uncompleted tests below remain PENDING.

Queries are on the [DFIR Customer Investigations](DFIR-Customer-Investigations.md) page. This guide documents collection and validation, not a second query catalog with embedded KQL.

## Customer hierarchy

- **Microsoft Teams — Calls and Meeting activities**
  - **Join/Leave times** — [Microsoft Teams/Join-Leave-times.kql](../Microsoft%20Teams/Join-Leave-times.kql)
  - **Meeting Duration** — [Microsoft Teams/Meeting-Duration.kql](../Microsoft%20Teams/Meeting-Duration.kql)
  - **SharedActivities: was camera or screen shared, mute/unmute etc** — [Microsoft Teams/SharedActivities.kql](../Microsoft%20Teams/SharedActivities.kql)
- **SharePoint Activity**
  - **Site/Page accessed/created/modified** — [SharePoint/Site-Page-accessed-created-modified.kql](../SharePoint/Site-Page-accessed-created-modified.kql)
  - **Files uploaded/downloaded from a SharePoint site** — [SharePoint/Files-uploaded-downloaded-from-a-SharePoint-site.kql](../SharePoint/Files-uploaded-downloaded-from-a-SharePoint-site.kql)
- **OneDrive**
  - **User File activity** — [OneDrive/User-File-activity.kql](../OneDrive/User-File-activity.kql)
  - **Sync activity** — [OneDrive/Sync-activity.kql](../OneDrive/Sync-activity.kql)

## Observed live execution — 2026-10-13

Aggregate results from the previous seven-query runs; no tenant identifiers or private evidence are included. These counts confirm execution only, not independently correlated seeded coverage.

| Product | Saved query | Returned records | Execution | Positive seeded coverage |
|---|---|---:|---|---|
| Microsoft Teams | Join/Leave times | 0 | PASS | PENDING |
| Microsoft Teams | Meeting Duration | 0 | PASS | PENDING |
| Microsoft Teams | SharedActivities | 0 | PASS | PENDING |
| SharePoint | Site/Page accessed/created/modified | 0 | PASS | PENDING |
| SharePoint | Files uploaded/downloaded from a SharePoint site | 0 | PASS | PENDING |
| OneDrive | Sync activity | 0 | PASS | PENDING |
| OneDrive | User File activity | 2 | PASS | PENDING |

## Generic setup

1. Choose the intended Microsoft Sentinel / Log Analytics workspace. Use an authorized administrator for connector setup and least-privilege workspace query access for investigators. Do not embed access tokens, credentials, tenant identifiers, or real participant/file evidence in published queries or reports.
2. Confirm Microsoft Purview Audit is enabled for the organization, the test accounts/workloads are eligible for the required audit events, and retention covers the intended investigation. Licensing, audit configuration, and operation availability can affect coverage. Purview search permission is separate from Sentinel query permission.
3. In Sentinel Content hub, install/update the Microsoft 365 solution as applicable. Configure its **Microsoft 365** (historically Office 365) audit connector and enable **Teams** and **SharePoint** audit collection using the connector's currently documented authorization requirements. OneDrive personal-site audit records can arrive under the SharePoint feed/workload; do not require a separate OneDrive workload label to recognize them. Follow the current connector documentation if its UI or prerequisites differ.
4. Check connector health, authorized organization, enabled feeds, and ingestion errors. Confirm that events arrive in **OfficeActivity**, not merely in Purview Audit or another table. Enabling a connector is not proof that every historical record is backfilled.
5. Inspect the actual schema using `OfficeActivity | getschema`. These drafts use the supplied live schema: `TimeGenerated`; datetime `JoinTime`/`LeaveTime`; dynamic `Attendees`, `ArtifactsShared`, `Members`, `ExtraProperties`, `OperationProperties`; string `MeetingDetailId`, `ChatThreadId`, `Event_Data`; and `OfficeId`, `SourceRecordId`, `OfficeObjectId`, `Site_Url`, `SourceFileName`, `DestinationFileName`, `SourceRelativeUrl`, `DestinationRelativeUrl`, `ListItemUniqueId`, `Actor`, `UserId`, `ClientIP`, `ActorIpAddress`, `ResultStatus`, `OfficeWorkload`, `Operation`. `OrganizationId` is optional and read with `column_ifexists`. Resolve schema differences explicitly rather than silently dropping missing evidence columns.
6. Execute the exact saved query in workspace Logs using KQL mode and a portal time range that includes the query's UTC bounds. These are **Sentinel OfficeActivity-only** queries using `TimeGenerated`; there is no Defender XDR timestamp substitution or alternative data source.
7. Allow for audit generation, source availability, connector collection, and ingestion delays. **No latency SLA is asserted.** Track action UTC time, first source observation, first workspace observation, query window, and connector health privately. Retry within a justified investigation window; do not fabricate evidence or claim a missing event is a successful negative test.

## Parameter contract

All nonempty pivots are combined with **AND**. Alternatives within one pivot are **OR**; there is no unrestricted OR between distinct customer filters. Empty strings disable the corresponding pivot.

| Parameter | Applicable queries | Meaning |
|---|---|---|
| `StartTime`, `EndTime` | All | Inclusive UTC `TimeGenerated` window; defaults `ago(30d)` and `now()`. This is audit-event time filtering, not join-time filtering. |
| `TargetUser` | All | Case-insensitive exact `UserId` OR case-insensitive textual substring in raw `Actor`; Teams also searches raw `Attendees`/`Members`. A dynamic-payload match is a discovery pivot, not proof of an exact participant identity/role. Inspect the untouched raw payload. |
| `TargetOperation` | All | Case-insensitive exact operation, additionally constrained by the query's allowlist. |
| `TargetRecordId` | All | Case-insensitive exact `SourceRecordId` OR `OfficeId`. |
| `TargetMeetingId`, `TargetChatThreadId` | Teams | Case-insensitive exact meeting/thread identifiers. |
| `TargetArtifact` | SharedActivities | Case-insensitive substring in raw `ArtifactsShared`; not a camera, mute, or screen-sharing semantic filter. |
| `TargetSite` | SharePoint / OneDrive | Case-insensitive substring in `Site_Url` OR `OfficeObjectId`. Use a sufficiently specific full site URL to avoid prefix collisions. |
| `TargetFileName` | SharePoint / OneDrive | Case-insensitive exact source OR destination name; both are retained. Site-only events may have neither. |
| `TargetObjectId` | SharePoint / OneDrive | Case-insensitive exact `OfficeObjectId` OR `ListItemUniqueId`. |
| `MaxRows` | All | Positive integer literal; default 1000, hard upper bound 1000. Descending `TimeGenerated`; ties have no guaranteed order. |

Validate `StartTime <= EndTime` and `1 <= MaxRows <= 1000` before running. A cap can truncate evidence: narrow the time window or partition the investigation; do not treat a capped result as complete coverage.

## Evidence semantics and limitations

- Each query returns evidence records, not user/meeting/site aggregates. `summarize arg_max` is used only to select the latest duplicate evidence row, never to build sessions or aggregate counts/durations.
- Deduplication uses optional `OrganizationId` plus the first available `SourceRecordId` / `OfficeId`, namespaced by ID type, and a meaningful evidence fingerprint. Different raw evidence under the same ID is retained, including different users, participant arrays, join/leave times, artifacts, and other payloads. Missing IDs use a hash of `TimeGenerated` plus meaningful evidence fields. Same ID and same evidence with a later audit timestamp retains the latest row; missing-ID records with different audit times remain distinct. Identical anonymous payloads/times cannot be distinguished without upstream identifiers. Dynamic serialization/key-order differences may conservatively retain duplicates.
- Raw dynamic values are returned without parsing, replacing, flattening, or `mv-expand`. `Event_Data` is retained as its original string. Text conversions are used only for matching/fingerprints; they do not replace the returned evidence.
- Teams is limited to `MeetingDetail`, `MeetingParticipantDetail`, `CallParticipantDetail` with workload `MicrosoftTeams`. **AppDeleted is never meeting evidence.** Actual record types may have null join/leave fields. Meeting Duration returns a nullable interval only when both timestamps exist and `LeaveTime >= JoinTime`. A zero interval is valid when timestamps are equal. Participant intervals, reconnects, and call intervals are not an overall meeting duration.
- **Camera on/off and mute/unmute are unsupported by these queries.** The SharedActivities query preserves raw artifacts, but neither artifact presence nor absence establishes screen-sharing state/duration. Verify any artifact interpretation against the source record and current documented semantics before drawing a conclusion; no unsupported derived state is emitted.
- SharePoint queries require workload `SharePoint` and exclude personal locations identified in **either** `Site_Url` or `OfficeObjectId` by `-my.sharepoint.com` host text or `/personal/` path text, case-insensitively. OneDrive queries accept workload `OneDrive` **or** SharePoint with those personal-location indicators. This intentionally handles SharePoint-labeled OneDrive evidence. Records with both location fields missing cannot be conclusively classified by URL; inspect them, and do not assert universal classification coverage. The fallback assumes standard commercial personal-site URL conventions; unusual hosts/paths need explicit review.
- Page **file** operations require an `.aspx` source/destination filename, relative URL, or object URL (optional query/fragment suffix accepted). Explicit `PageViewed`/`PageViewedExtended` events are page access; explicit site operations are separately labeled. An uploaded/copied page is not proof of first-ever creation: updates/overwrites can also upload a page. No created timestamp is manufactured. The allowlist does not claim every page/site operation is available or covered.
- SharePoint file transfer scope is **only FileUploaded/FileDownloaded**, not sync. OneDrive file activity uses its explicit non-sync file-operation allowlist. Sync uses only `FileSyncUploadedFull`, `FileSyncDownloadedFull`, `FileSyncUploadedPartial`, `FileSyncDownloadedPartial`. A generic upload (including Microsoft Graph upload) does not establish sync. Labels do not prove transfer success or convergence; inspect `ResultStatus` and raw evidence, without assuming blank status means success.

## Reproducible test procedure

Current operation/schema references (documentation is not live execution proof):
- [Microsoft Purview audit activities](https://learn.microsoft.com/en-us/purview/audit-log-activities): file/page, site administration, synchronization, and Teams operation semantics.
- [OfficeActivity table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity).
- [Microsoft 365 Sentinel audit connector](https://learn.microsoft.com/en-us/azure/sentinel/connect-office-365).

Site administration scope is `SiteCollectionCreated` for creation and `SiteRenamed`, `SiteCollectionQuotaModified`, `WebThemeApplied` for modifications. Site access is evidenced through page-access rows retaining site/object URLs; no undocumented `SiteViewed` operation is manufactured. The legacy partial sync operations are deprecated with Groove.exe and are retained for historical evidence only; they are not expected acceptance criteria for a modern OneDrive.exe sync test.

Use only approved test users, meetings, sites, and harmless unique test files/pages. Keep an action ledger outside the public repository: test identifier, UTC action time, test account, exact resource IDs/URLs/names, expected source operation, submitted parameter values, returned raw evidence, and first observed time. Do not publish meeting participants, tenant IDs, tokens, or production file details.

For each positive test, first locate the raw OfficeActivity record in a bounded window, then run the **exact saved query** with each relevant pivot independently and with all applicable pivots combined. Capture the submitted query and raw result privately. Change the expected identity/name to a known nonmatching value for the negative control. Record **PASS**, **FAIL**, or **PENDING / not observed**, with evidence; distinguish source unavailability from a filter bug. Never make a count alone the acceptance criterion.

| Test | Reproduction / control | Required observation or assertion | Status (2026-10-13) |
|---|---|---|---|
| Schema and execution | Inspect schema; run each of the seven exact saved queries in the chosen workspace. | All seven compiled and executed without semantic/runtime errors against the live schema. Empty results do not validate retained-field completeness or positive coverage. | Execution PASS (7/7); positive coverage and raw-field validation PENDING |
| Real Teams join/leave | Have two authorized users **actually join** a Teams meeting; leave, then have one rejoin and leave. Separately place/join/end a call if call scope must be demonstrated. Record UTC times and meeting/thread IDs. Merely creating a calendar meeting is not this test. | Supported Teams operations with actual raw participant/join/leave evidence; separate participants and reconnect intervals remain separate where supplied. No guarantee that every source operation will appear. | PENDING |
| Duration positive | Locate a row with both join/leave timestamps and leave after join. Use its record and meeting IDs. | `Duration` equals that row's leave minus join; seconds agree; no group min/max or summed participant intervals. | PENDING |
| Duration null / invalid / equal | In a separate test editor, substitute a schema-compatible synthetic `datatable` for the OfficeActivity source containing missing join, missing leave, reverse interval, and equal timestamps. Keep the query's filters/transforms unchanged and clearly label the output synthetic. | Missing/reverse intervals have null duration/seconds and explanatory status; equal timestamps yield zero. Synthetic controls do NOT validate live telemetry. | PENDING |
| Not a meeting | Synthetic or real `MicrosoftTeams` / `AppDeleted` record within the window, with otherwise populated fields. | Excluded from all three Teams outputs. Calendar creation without real participation is not evidence of join/leave. | PENDING |
| Shared activity raw evidence | In the real test meeting, share a harmless window/screen and stop; toggle camera and mute/unmute if approved. Record observer notes separately. | Inspect raw `ArtifactsShared`, `ExtraProperties`, `OperationProperties`, `Event_Data`; retain null/empty fields. No derived camera/mute/screen state, no claim toggles are comprehensively audited. Use observed artifact text for a pivot test only if present. | PENDING; camera/mute inference unsupported |
| SharePoint page/site | On an approved **non-personal** site, create/publish an `.aspx` page, view it, then modify/publish it. An authorized administrator may separately create/change a disposable site. Upload/modify a `.txt` document as a negative page control. | Page file events have `.aspx` evidence; ordinary document file modifications are excluded; site events use their separate labels. Page upload/copy is not independently proof of first creation. | PENDING |
| SharePoint transfers | Browser-upload a uniquely named harmless file to a non-personal site, then explicitly download it. | `FileUploaded`/`FileDownloaded` rows for the correct user/site/file/object; matching raw status and IDs. Sync-only operations excluded. | PENDING |
| OneDrive file activity | Browser-upload/download/rename a harmless unique personal OneDrive file. Include a record where workload is `SharePoint` and only **one** of `OfficeObjectId`/`Site_Url` reveals the personal location. | Included in OneDrive file output and excluded from both SharePoint queries; source/destination names remain raw. Test the other URL field independently. | PENDING |
| OneDrive real sync | Sign an approved account into **OneDrive.exe**. Create/modify a harmless file in its local personal OneDrive folder for upload; make a remote change and explicitly hydrate/download it on the client for download. Confirm client configuration and record action times. | Actual allowlisted `FileSync*` records with matching resource/user, if audited. Graph/browser upload alone cannot PASS this test; client UI success alone cannot PASS audit-query coverage. | PENDING |
| Workload / URL classification | Separate synthetic cases: SharePoint normal site; SharePoint with personal object URL only; personal site URL only; mixed-case indicators; OneDrive workload without URLs; unrelated workload with personal-looking URL. | Normal site stays SharePoint; personal SharePoint stays OneDrive; explicit OneDrive is included; unrelated workload excluded. Missing URLs under SharePoint remain classification-limited, not proven non-personal. | PENDING |
| Pivots and AND controls | For each live positive, run user, operation, meeting/thread or site/file/object, record ID, artifact (when applicable) individually; repeat with changed case; combine valid filters, then replace exactly one with a nonmatch. | Known positive returned by applicable independent/compound pivots; compound single-negative excluded. Raw Actor/participant substring matching limitations documented. | PENDING |
| Dedup and tenant boundary | Separate synthetic source: repeat same ID+payload at two audit times; reuse ID across two organizations; reuse ID for two users/intervals/artifacts; omit IDs with different meaningful payloads or audit times. Include an optional-OrganizationId-absent schema variant. | Latest identical ID+payload row retained; organizations/participants/intervals/artifacts preserved separately; missing IDs do not collapse different evidence; optional tenant column causes no compile failure. | PENDING |
| Empty window and cap | Use a known empty bounded window; separately use a synthetic source with more than 1000 distinct allowed records and `MaxRows=1000`, then `MaxRows=10`, then a value greater than 1000. | Empty window returns no fabricated rows; results are descending and capped at 1000 / 10 / 1000 respectively. Ties are not a deterministic ordering claim. | PENDING |

### Synthetic fixture contract

Build fixtures in an unsaved/private test editor, never inside the production query files. Supply all required columns with the supplied schema types, including nullable datetime join/leave fields and untouched dynamic payloads. Use fictitious actors/resource names and generic organization strings, not real tenant identifiers. Use supported workloads/operations and timestamps within the configured window unless testing exclusion. Replace only the `OfficeActivity` table reference with the fixture; keep the rest of the exact query unchanged. Keep fixture results clearly labeled **synthetic logic tests**, separate from **live execution and source coverage**.

### Completion gate

Every exact saved query has executed successfully; these artifacts still remain drafts until required positive actions are independently correlated to raw source records and applicable negative/pivot/dedup/duration/cap controls are recorded. Unsupported camera/mute claims never become PASS just because meeting rows exist. If a required operation is not observed, retain PENDING and document the source/connector limitation rather than substituting calendar events, generic uploads, fabricated intervals, or unrelated operations.