# DFIR Customer Ask — KQL Verification Tracker

**Repository:** [Cyberlorians/KQL](https://github.com/Cyberlorians/KQL)  
**Tenant context:** DIB Security Commercial  
**Sentinel workspace:** `DIBSecCom` (`7e9298ab-22e6-4a82-a53e-c5ed7faee977`)  
**Validation date:** 2026-10-13  
**Validation method:** Microsoft Sentinel Data Exploration MCP for legacy baseline probes; authenticated Defender XDR Advanced Hunting for the full email investigation

## Email Investigations

Expand the parent, then the investigation you need. Each child contains a complete Microsoft Defender Advanced Hunting query and expandable recorded proof. **Copy:** hover over a KQL code block and use GitHub's native copy icon in its upper-right corner. Repository Markdown does not support custom JavaScript copy buttons.

<details>
<summary><strong>Email Investigations</strong></summary>

**Platform:** Microsoft Defender XDR Advanced Hunting (`Timestamp`). Default window: last 30 days. Set the investigation parameters before running. These queries investigate observed email telemetry, not complete mailbox contents.

<details>
<summary><strong>External communications</strong></summary>

Filter a specific user or direction, or leave the parameters empty for all external communications. Direction comes from `EmailDirection`, not guessed domain ownership.

```kql
// External communications — observed inbound/outbound messages.
let StartTime = ago(30d);
let EndTime = now();
let TargetUser = "";          // Exact visible sender, envelope sender, or recipient.
let Direction = "";           // Inbound or Outbound; empty = both.
let MaxRows = 1000;
let ExternalMessages = materialize(
	EmailEvents
	| where Timestamp between (StartTime .. EndTime)
	| where EmailDirection in~ ("Inbound", "Outbound")
	| where isempty(Direction) or EmailDirection =~ Direction
	| where isempty(TargetUser) or SenderFromAddress =~ TargetUser
		or SenderMailFromAddress =~ TargetUser or RecipientEmailAddress =~ TargetUser
	| summarize FirstObserved=min(Timestamp), LastObserved=max(Timestamp),
		ObservedEventCount=count(), arg_max(Timestamp, *)
		by NetworkMessageId, RecipientEmailAddress
);
ExternalMessages
| project Timestamp, FirstObserved, LastObserved, ObservedEventCount,
	NetworkMessageId, InternetMessageId, EmailDirection,
	SenderFromAddress, SenderMailFromAddress, SenderFromDomain,
	SenderIPv4, SenderIPv6, RecipientEmailAddress, Subject,
	DeliveryAction, DeliveryLocation, AuthenticationDetails,
	ThreatTypes, ThreatNames, AttachmentCount, UrlCount
| top MaxRows by Timestamp desc
```

<details>
<summary>Proof — external communications</summary>

| Recorded live result | Count |
|---|---:|
| Inbound message-recipient records | 630 |
| Outbound message-recipient records | 0 |
| Internal message-recipient records (full investigation) | 0 |

**Positive evidence:** actual inbound `EmailEvents` direction and detailed message-recipient results, not OfficeActivity external-sharing heuristics. **Unverified:** outbound and internal examples were absent in the window. The full investigation and source probes were executed on 2026-10-13; this focused child query is a newly presented derivative and has not been independently rerun.

</details>
</details>

<details>
<summary><strong>Specific attachment filenames and hashes</strong></summary>

Set an exact SHA-256 hash, a filename substring, or both. When both are set, the **same attachment record** must match both. Empty parameters show all observed attachment metadata. Sender/recipient correlation uses message ID plus normalized recipient.

```kql
// Attachment pivot — matching attachment metadata correlated to its email recipient.
let StartTime = ago(30d);
let EndTime = now();
let AttachmentNameContains = "";  // Case-insensitive filename substring.
let AttachmentSHA256 = "";        // Exact SHA-256, case-insensitive.
let TargetRecipient = "";         // Exact recipient; empty = all.
let MaxRows = 1000;
let MatchingAttachments = materialize(
	EmailAttachmentInfo
	| where Timestamp between (StartTime .. EndTime)
	| where isempty(AttachmentNameContains) or FileName contains AttachmentNameContains
	| where isempty(AttachmentSHA256) or SHA256 =~ AttachmentSHA256
	| where isempty(TargetRecipient) or RecipientEmailAddress =~ TargetRecipient
	| extend RecipientKey=tolower(RecipientEmailAddress)
	| summarize AttachmentRecords=count(), MatchingAttachments=make_set(
		bag_pack("FileName", FileName, "SHA256", SHA256, "FileSize", FileSize,
			"FileType", FileType, "ThreatTypes", ThreatTypes,
			"ThreatNames", ThreatNames, "Timestamp", Timestamp), 500)
		by NetworkMessageId, RecipientKey
);
let Messages = EmailEvents
	| where Timestamp between (StartTime .. EndTime)
	| where NetworkMessageId in (MatchingAttachments | project NetworkMessageId)
	| where isempty(TargetRecipient) or RecipientEmailAddress =~ TargetRecipient
	| summarize FirstObserved=min(Timestamp), LastObserved=max(Timestamp),
		arg_max(Timestamp, *) by NetworkMessageId, RecipientEmailAddress
	| extend RecipientKey=tolower(RecipientEmailAddress);
MatchingAttachments
| join kind=leftouter Messages on NetworkMessageId, RecipientKey
| project NetworkMessageId, RecipientKey, RecipientEmailAddress,
	Timestamp, FirstObserved, LastObserved, InternetMessageId,
	SenderFromAddress, SenderMailFromAddress, Subject, EmailDirection,
	DeliveryAction, DeliveryLocation, AttachmentRecords, MatchingAttachments,
	MessageEvidence=iff(isnotempty(RecipientEmailAddress),
		"Message correlated", "Attachment observed; email missing in scope")
| top MaxRows by Timestamp desc
```

<details>
<summary>Proof — attachment filenames and hashes</summary>

| Recorded live result | Count |
|---|---:|
| Raw attachment records | 8 |
| Records with filenames | 8 |
| Records with SHA-256 | 8 |
| Records with positive file size | 8 |
| Declared-attachment messages / correlated messages | 8 / 8 |
| Declared-attachment messages missing metadata | 0 |
| Compound real-message filename/hash positive pivot | 1 matching message |
| Nonmatching attachment-hash pivot | 0 matching messages |

**Positive evidence:** the executed full investigation correlated all eight attachment-bearing messages, and a compound test matched a real filename/hash pair together with recipient/message/subject/direction parameters. **Limit:** metadata only, no binary retrieval; SHA1 not assumed. Dynamic detail arrays are capped at 500 per group. These are recorded results from the full investigation/source probes; this focused child query has not been independently rerun.

</details>
</details>

<details>
<summary><strong>Specific Subject lines</strong></summary>

Set `SubjectText` to the requested subject. Choose exact case-insensitive matching or substring matching. An empty value leaves the subject filter broad.

```kql
// Subject pivot — actual email Subject field.
let StartTime = ago(30d);
let EndTime = now();
let SubjectText = "";
let ExactSubject = false;       // true = exact; false = substring.
let TargetRecipient = "";       // Exact recipient; empty = all.
let MaxRows = 1000;
let SubjectMessages = materialize(
	EmailEvents
	| where Timestamp between (StartTime .. EndTime)
	| where isempty(SubjectText)
		or (ExactSubject and Subject =~ SubjectText)
		or (not(ExactSubject) and Subject contains SubjectText)
	| where isempty(TargetRecipient) or RecipientEmailAddress =~ TargetRecipient
	| summarize FirstObserved=min(Timestamp), LastObserved=max(Timestamp),
		ObservedEventCount=count(), arg_max(Timestamp, *)
		by NetworkMessageId, RecipientEmailAddress
);
SubjectMessages
| project Timestamp, FirstObserved, LastObserved, ObservedEventCount,
	NetworkMessageId, InternetMessageId, Subject,
	SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
	EmailDirection, DeliveryAction, DeliveryLocation,
	ThreatTypes, ThreatNames, AttachmentCount, UrlCount
| top MaxRows by Timestamp desc
```

<details>
<summary>Proof — subject lines</summary>

| Recorded live result | Count |
|---|---:|
| Message-recipient records with actual `Subject` | 630 / 630 |
| Compound real-message subject substring pivot | 1 matching message |

**Positive evidence:** actual email subjects are populated and the full investigation's compound subject-substring filter returned the selected real message. **Unverified:** the new exact-subject branch and this focused child query have not been independently rerun. Tenant subject values are deliberately not published.

</details>
</details>

<details>
<summary><strong>Specific sender and recipients</strong></summary>

Set `SenderAddress`, `RecipientAddress`, or both. If both are set, both must match the same message-recipient row. Choose visible From, envelope MAIL FROM, or either sender field.

```kql
// Sender/recipient pivot — distinct visible and envelope sender fields.
let StartTime = ago(30d);
let EndTime = now();
let SenderAddress = "";         // Exact sender; empty = all.
let RecipientAddress = "";      // Exact recipient; empty = all.
let SenderField = "Either";     // From, Envelope, or Either (case-sensitive).
let MaxRows = 1000;
let CommunicationPairs = materialize(
	EmailEvents
	| where Timestamp between (StartTime .. EndTime)
	| where isempty(SenderAddress)
		or (SenderField in ("From", "Either") and SenderFromAddress =~ SenderAddress)
		or (SenderField in ("Envelope", "Either") and SenderMailFromAddress =~ SenderAddress)
	| where isempty(RecipientAddress) or RecipientEmailAddress =~ RecipientAddress
	| summarize FirstObserved=min(Timestamp), LastObserved=max(Timestamp),
		ObservedEventCount=count(), arg_max(Timestamp, *)
		by NetworkMessageId, RecipientEmailAddress
);
CommunicationPairs
| project Timestamp, FirstObserved, LastObserved, ObservedEventCount,
	NetworkMessageId, InternetMessageId, SenderFromAddress,
	SenderMailFromAddress, SenderFromDomain, RecipientEmailAddress,
	Subject, EmailDirection, DeliveryAction, DeliveryLocation,
	AuthenticationDetails, AttachmentCount, UrlCount
| top MaxRows by Timestamp desc
```

<details>
<summary>Proof — sender and recipients</summary>

| Recorded live result | Count |
|---|---:|
| Records with visible sender | 630 / 630 |
| Records with envelope sender | 630 / 630 |
| Records with recipient | 630 / 630 |
| Compound exact-recipient/message pivot | 1 matching message |

**Positive evidence:** populated visible/envelope sender and recipient fields on actual message-recipient rows; recipient-side filtering in the full investigation returned a known message. **Unverified:** independently filtered sender branches, the new two-parameter pair filter, and this focused child query have not been rerun. These rows are not complete To/Cc/Bcc headers or evidence of reading.

</details>
</details>

Full combined query: [Email-Investigation.kql](DFIR/Email-Investigation.kql). Additional executed-test context and limitations: [Email-Verification.md](DFIR/Email-Verification.md). All four focused queries cap displayed rows at `MaxRows`; their absence of results does not establish absence of activity outside retention or ingestion coverage.

</details>

## Email-first investigation — current status

The new [full let-based email investigation](DFIR/Email-Investigation.kql) was executed in Defender, including corrected Timeline mode (630 records), Evidence mode, a compound real-message positive pivot, and a nonmatching attachment-hash test. See the [email subrequirement evidence and limitations](DFIR/Email-Verification.md). Inbound subjects, visible/envelope senders, recipients, and all 8 attachment-bearing messages have positive live evidence. Outbound/internal mail have no matching examples in the tested window and remain unverified. This does **not** establish 100% email coverage.

The earlier OfficeActivity email counts were audit-field heuristics, **not proof of sender/recipient pairs, email direction, or subjects**. They are superseded by the direct Defender evidence below.

## Live rerun log — 2026-10-13

All twelve saved artifacts in `C:\tools\kqlDFIR\validated\` were rerun individually against the live workspace. All twelve completed successfully. The exact timeline artifact also completed successfully and returned zero rows because it still contains the placeholder `user@dibsecurity.onmicrosoft.com` rather than a confirmed investigation UPN.

The live counts are time-sensitive. The second run returned: `OfficeActivity` 2,001 rows; `DeviceEvents` 145,748 rows; `SigninLogs` 465 rows; `IdentityLogonEvents` 59 rows; `AuditLogs` 11,865 rows; `IdentityDirectoryEvents` 173 rows; `IdentityInfo` 558 rows; and `SecurityEvent` 0 rows overall in the tested window (also no matching network-share event IDs).

## KQL Search grounding

KQL Search was opened in the shared browser and searched for `Teams calls`. It returned the community query **Threat Hunting Microsoft Teams Calls By TLD**, using `CallActivityEvents`, with a GitHub source link. This supports the schema distinction that Teams call telemetry may be in `CallActivityEvents` rather than `OfficeActivity`; it does not validate DIBSecCom data. A broader search combining multiple terms returned no result, so KQL Search is treated as supplemental grounding only, never as tenant evidence.

## Verification standard

A query is marked **Executed** only after successful live execution on the stated surface. **Positive evidence** applies only to the specific fields, correlations, and cases actually inspected. **Baseline only** means source counts/heuristics were observed, not that a complete customer ask was validated. All non-email entries below are legacy baseline probes pending full DFIR queries and subrequirement tests. A successful query with zero results is not proof that a source is unsupported. No entire customer ask is declared 100% verified here.

## Customer ask tracker

| # | Use case | Query/table | Status | Live evidence |
|---:|---|---|---|---|
| 1 | Email investigations — external communications, attachments, subject lines, sender/recipients | [Email investigation](DFIR/Email-Investigation.kql): `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `EmailPostDeliveryEvents` | **Partial; full query executed** | 630 message-recipient rows with subjects and visible/envelope sender/recipient fields; inbound 630; all 8 declared attachment messages correlated; outbound/internal 0. [Detailed evidence](DFIR/Email-Verification.md) |
| 2 | Teams calls and meetings — join/leave, duration, shared activity, camera/mute | `OfficeActivity` | **Executed; data not confirmed** | Query succeeded; all four evidence counters returned 0 |
| 3 | SharePoint — sites/pages, file activity, sharing | `OfficeActivity` | **Baseline only** | Site/page field presence 8; file field presence 6; sharing-like field heuristic 1,968; operation semantics not verified |
| 4 | OneDrive — user activity, sync, file activity | `OfficeActivity` | **Partial** | 5 OneDrive-matching rows; user activity 5; file activity 4; sync evidence 0 |
| 5 | Device logon events | `DeviceEvents` | **Baseline only** | 16 logon-action heuristic matches; account field presence 139,750; session field presence 1,498 |
| 6 | User logon events | `SigninLogs`, `IdentityLogonEvents` | **Baseline only** | `SigninLogs` 465; `IdentityLogonEvents` 59; full investigation pending |
| 7 | User device activity — USB, hardware, file origin, DLP, process, scripts, registry, scheduled tasks, tampering | `DeviceEvents` | **Partial** | USB 5,939; hardware 477; process 125,327; registry 9; other requested heuristics returned 0 |
| 8 | Web activity — sites visited and browsers used | `DeviceEvents` | **Partial** | URL/site evidence 1,243; browser-action heuristic 0 |
| 9 | Network-share activity — access, create, modify, delete | `SecurityEvent` | **Executed; data not confirmed** | Tested Event IDs 5140/5142/5143/5144/5145 returned 0 rows |
| 10 | User activity event timeline | `OfficeActivity` + `DeviceEvents` | **Executed; requires target** | Normalized union succeeded; placeholder UPN returned no rows |
| 11 | User identity and access context | `AuditLogs`, `IdentityDirectoryEvents`, `IdentityInfo` | **Baseline only** | `AuditLogs` 11,865; `IdentityDirectoryEvents` 173; `IdentityInfo` 558; identity correlation pending |
| 12 | File metadata — filename, extension, hash, size | `DeviceEvents`, `OfficeActivity` | **Baseline only** | Endpoint filename field presence 11,206; extension heuristic 11,156; hash field presence 10,361; size field presence 36,045; OfficeActivity filenames 6; extensions 1; same-file correlation not proven |

## Repository grounding

This tracker is grounded in the following repositories:

- [Cyberlorians/KQL](https://github.com/Cyberlorians/KQL) — organization-specific Entra, Defender, Defender for Identity, Windows `SecurityEvent`, logon, network-share, removable-media, file/object-access, and identity queries.
- [reprise99/Sentinel-Queries](https://github.com/reprise99/Sentinel-Queries) — Sentinel fundamentals, Office 365 activity/file monitoring, Entra sign-in/audit patterns, and Sentinel versus Advanced Hunting differences.
- [ep3p/Sentinel_KQL](https://github.com/ep3p/Sentinel_KQL) — broader Sentinel query patterns and reusable functions.

## Next validation work

1. Identify the exact Office 365 audit operation names and connector coverage for Teams meeting telemetry.
2. Complete the [remaining email verification gates](DFIR/Email-Verification.md#remaining-verification-gates), especially known outbound/internal examples. Defender attachment metadata and message-recipient correlation now have positive live evidence.
3. Confirm OneDrive sync operation names and retention.
4. Confirm Defender action names for DLP, scripts, scheduled tasks, and tampering instead of relying on broad heuristics.
5. Confirm Windows Security audit collection for Event IDs 5140–5145 and removable-media events.
6. Replace the timeline placeholder with an actual investigation UPN and rerun it.
7. Add one production-ready KQL file per completed customer sub-ask after the evidence and schema are confirmed.

## Important limitation

These results describe the current workspace schema and the tested 30-day window. Zero results may indicate missing connectors, retention limits, audit-policy settings, action-name differences, or simply no activity in the window. They require follow-up before a production detection or analytic rule is declared complete.
