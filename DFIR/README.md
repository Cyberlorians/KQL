# DFIR Investigations

Customer landing page for saved investigation queries, organized by product. Open the linked KQL file and set its parameters before running; query bodies are not duplicated here.

**Validation status — 2026-10-13:** Email queries have been live-executed with bounded positive validation; this is not universal or 100% telemetry, mailbox, or filter coverage. All seven collaboration queries executed successfully against Sentinel `OfficeActivity`; positive seeded coverage validation remains pending. OneDrive User File activity returned **2** records; the other six returned **0**. Counts alone do not prove coverage or absence of activity.

See the [collaboration connector and validation guide](Collaboration-Connectors.md) for collection prerequisites, observed execution counts, limitations, and pending tests.

## Microsoft Defender for Office 365

Observed email communications and attachment metadata. Canonical files use `TimeGenerated` for Sentinel/Log Analytics. Without Sentinel, replace every `TimeGenerated` with `Timestamp` in Defender XDR Advanced Hunting. Required raw tables, ingestion, retention, permissions, row/detail caps, and optional-field availability bound coverage; these queries do not supply complete mailbox contents, body/MIME, complete To/Cc/Bcc, read state, or attachment binaries.

- [External communications](Microsoft%20Defender%20for%20Office%20365/External-communications.kql)
- [Specific attachment filenames and hashes](Microsoft%20Defender%20for%20Office%20365/Specific-attachment-filenames-and-hashes.kql)
- [Specific Subject lines](Microsoft%20Defender%20for%20Office%20365/Specific-Subject-lines.kql)
- [Specific sender and recipients](Microsoft%20Defender%20for%20Office%20365/Specific-sender-and-recipients.kql)

See [product guidance and noncanonical historical references](Microsoft%20Defender%20for%20Office%20365/README.md).

## Microsoft Teams

Sentinel `OfficeActivity` only. Live execution confirmed for all three queries; each returned zero records. Positive seeded validation remains pending. Join/leave and duration describe recorded evidence intervals, not reconstructed overall meeting sessions. Camera/mute inference is unsupported; raw artifacts do not establish screen-sharing state or duration.

- [Join/Leave times](Microsoft%20Teams/Join-Leave-times.kql)
- [Meeting Duration](Microsoft%20Teams/Meeting-Duration.kql)
- [SharedActivities: was camera or screen shared, mute/unmute etc](Microsoft%20Teams/SharedActivities.kql)

## SharePoint

Sentinel `OfficeActivity` only. Both queries executed successfully and returned zero records; positive seeded page/site and transfer validation remains pending. Explicit operation allowlists do not establish exhaustive auditing or first-ever page creation.

- [Site/Page accessed/created/modified](SharePoint/Site-Page-accessed-created-modified.kql)
- [Files uploaded/downloaded from a SharePoint site](SharePoint/Files-uploaded-downloaded-from-a-SharePoint-site.kql)

## OneDrive

Sentinel `OfficeActivity` only, including SharePoint-labeled personal-site records recognized by the query's URL rules. Both queries executed successfully: User File activity returned 2 records, Sync activity returned zero. Positive seeded coverage validation remains pending; generic upload is not proof of OneDrive client sync.

- [User File activity](OneDrive/User-File-activity.kql)
- [Sync activity](OneDrive/Sync-activity.kql)