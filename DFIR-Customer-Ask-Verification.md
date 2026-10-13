# DFIR KQL — Email

**Updated: 2026-10-13 · Email category only**

Expand a child below for its full KQL. Each code block has GitHub's **Copy code to clipboard** button. Expand **Proof** inside each child for recorded tenant results and validation limitations.

**Platform:** Microsoft Defender XDR Advanced Hunting (`Timestamp`). Default window: last 30 days. Set the investigation parameters before running. These queries investigate observed email telemetry, not complete mailbox contents.

<details open>
<summary><strong>Email Investigations</strong></summary>

> <details>
> <summary><strong>External communications</strong></summary>
>
> Filter a specific user or direction, or leave the parameters empty for all external communications. Direction comes from `EmailDirection`, not guessed domain ownership.
>
> ```kql
> // External communications — observed inbound/outbound messages.
> let StartTime = ago(30d);
> let EndTime = now();
> let TargetUser = "";          // Exact visible sender, envelope sender, or recipient.
> let Direction = "";           // Inbound or Outbound; empty = both.
> let MaxRows = 1000;
> let ExternalMessages = materialize(
> 	EmailEvents
> 	| where Timestamp between (StartTime .. EndTime)
> 	| where EmailDirection in~ ("Inbound", "Outbound")
> 	| where isempty(Direction) or EmailDirection =~ Direction
> 	| where isempty(TargetUser) or SenderFromAddress =~ TargetUser
> 		or SenderMailFromAddress =~ TargetUser or RecipientEmailAddress =~ TargetUser
> 	| summarize FirstObserved=min(Timestamp), LastObserved=max(Timestamp),
> 		ObservedEventCount=count(), arg_max(Timestamp, *)
> 		by NetworkMessageId, RecipientEmailAddress
> );
> ExternalMessages
> | project Timestamp, FirstObserved, LastObserved, ObservedEventCount,
> 	NetworkMessageId, InternetMessageId, EmailDirection,
> 	SenderFromAddress, SenderMailFromAddress, SenderFromDomain,
> 	SenderIPv4, SenderIPv6, RecipientEmailAddress, Subject,
> 	DeliveryAction, DeliveryLocation, AuthenticationDetails,
> 	ThreatTypes, ThreatNames, AttachmentCount, UrlCount
> | top MaxRows by Timestamp desc
> ```
>
> <details>
> <summary>Proof — external communications</summary>
>
> | Recorded live result | Count |
> |---|---:|
> | Inbound message-recipient records | 630 |
> | Outbound message-recipient records | 0 |
> | Internal message-recipient records (full investigation) | 0 |
>
> **Positive evidence:** actual inbound `EmailEvents` direction and detailed message-recipient results, not OfficeActivity external-sharing heuristics. **Unverified:** outbound and internal examples were absent in the window. The full investigation and source probes were executed on 2026-10-13; this focused child query is a newly presented derivative and has not been independently rerun.
>
> </details>
> </details>

> <details>
> <summary><strong>Specific attachment filenames and hashes</strong></summary>
>
> Set an exact SHA-256 hash, a filename substring, or both. When both are set, the **same attachment record** must match both. Empty parameters show all observed attachment metadata. Sender/recipient correlation uses message ID plus normalized recipient.
>
> ```kql
> // Attachment pivot — matching attachment metadata correlated to its email recipient.
> let StartTime = ago(30d);
> let EndTime = now();
> let AttachmentNameContains = "";  // Case-insensitive filename substring.
> let AttachmentSHA256 = "";        // Exact SHA-256, case-insensitive.
> let TargetRecipient = "";         // Exact recipient; empty = all.
> let MaxRows = 1000;
> let MatchingAttachments = materialize(
> 	EmailAttachmentInfo
> 	| where Timestamp between (StartTime .. EndTime)
> 	| where isempty(AttachmentNameContains) or FileName contains AttachmentNameContains
> 	| where isempty(AttachmentSHA256) or SHA256 =~ AttachmentSHA256
> 	| where isempty(TargetRecipient) or RecipientEmailAddress =~ TargetRecipient
> 	| extend RecipientKey=tolower(RecipientEmailAddress)
> 	| summarize AttachmentRecords=count(), MatchingAttachments=make_set(
> 		bag_pack("FileName", FileName, "SHA256", SHA256, "FileSize", FileSize,
> 			"FileType", FileType, "ThreatTypes", ThreatTypes,
> 			"ThreatNames", ThreatNames, "Timestamp", Timestamp), 500)
> 		by NetworkMessageId, RecipientKey
> );
> let Messages = EmailEvents
> 	| where Timestamp between (StartTime .. EndTime)
> 	| where NetworkMessageId in (MatchingAttachments | project NetworkMessageId)
> 	| where isempty(TargetRecipient) or RecipientEmailAddress =~ TargetRecipient
> 	| summarize FirstObserved=min(Timestamp), LastObserved=max(Timestamp),
> 		arg_max(Timestamp, *) by NetworkMessageId, RecipientEmailAddress
> 	| extend RecipientKey=tolower(RecipientEmailAddress);
> MatchingAttachments
> | join kind=leftouter Messages on NetworkMessageId, RecipientKey
> | project NetworkMessageId, RecipientKey, RecipientEmailAddress,
> 	Timestamp, FirstObserved, LastObserved, InternetMessageId,
> 	SenderFromAddress, SenderMailFromAddress, Subject, EmailDirection,
> 	DeliveryAction, DeliveryLocation, AttachmentRecords, MatchingAttachments,
> 	MessageEvidence=iff(isnotempty(RecipientEmailAddress),
> 		"Message correlated", "Attachment observed; email missing in scope")
> | top MaxRows by Timestamp desc
> ```
>
> <details>
> <summary>Proof — attachment filenames and hashes</summary>
>
> | Recorded live result | Count |
> |---|---:|
> | Raw attachment records | 8 |
> | Records with filenames | 8 |
> | Records with SHA-256 | 8 |
> | Records with positive file size | 8 |
> | Declared-attachment messages / correlated messages | 8 / 8 |
> | Declared-attachment messages missing metadata | 0 |
> | Compound real-message filename/hash positive pivot | 1 matching message |
> | Nonmatching attachment-hash pivot | 0 matching messages |
>
> **Positive evidence:** the executed full investigation correlated all eight attachment-bearing messages, and a compound test matched a real filename/hash pair together with recipient/message/subject/direction parameters. **Limit:** metadata only, no binary retrieval; SHA1 not assumed. Dynamic detail arrays are capped at 500 per group. These are recorded results from the full investigation/source probes; this focused child query has not been independently rerun.
>
> </details>
> </details>

> <details>
> <summary><strong>Specific Subject lines</strong></summary>
>
> Set `SubjectText` to the requested subject. Choose exact case-insensitive matching or substring matching. An empty value leaves the subject filter broad.
>
> ```kql
> // Subject pivot — actual email Subject field.
> let StartTime = ago(30d);
> let EndTime = now();
> let SubjectText = "";
> let ExactSubject = false;       // true = exact; false = substring.
> let TargetRecipient = "";       // Exact recipient; empty = all.
> let MaxRows = 1000;
> let SubjectMessages = materialize(
> 	EmailEvents
> 	| where Timestamp between (StartTime .. EndTime)
> 	| where isempty(SubjectText)
> 		or (ExactSubject and Subject =~ SubjectText)
> 		or (not(ExactSubject) and Subject contains SubjectText)
> 	| where isempty(TargetRecipient) or RecipientEmailAddress =~ TargetRecipient
> 	| summarize FirstObserved=min(Timestamp), LastObserved=max(Timestamp),
> 		ObservedEventCount=count(), arg_max(Timestamp, *)
> 		by NetworkMessageId, RecipientEmailAddress
> );
> SubjectMessages
> | project Timestamp, FirstObserved, LastObserved, ObservedEventCount,
> 	NetworkMessageId, InternetMessageId, Subject,
> 	SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
> 	EmailDirection, DeliveryAction, DeliveryLocation,
> 	ThreatTypes, ThreatNames, AttachmentCount, UrlCount
> | top MaxRows by Timestamp desc
> ```
>
> <details>
> <summary>Proof — subject lines</summary>
>
> | Recorded live result | Count |
> |---|---:|
> | Message-recipient records with actual `Subject` | 630 / 630 |
> | Compound real-message subject substring pivot | 1 matching message |
>
> **Positive evidence:** actual email subjects are populated and the full investigation's compound subject-substring filter returned the selected real message. **Unverified:** the new exact-subject branch and this focused child query have not been independently rerun. Tenant subject values are deliberately not published.
>
> </details>
> </details>

> <details>
> <summary><strong>Specific sender and recipients</strong></summary>
>
> Set `SenderAddress`, `RecipientAddress`, or both. If both are set, both must match the same message-recipient row. Choose visible From, envelope MAIL FROM, or either sender field.
>
> ```kql
> // Sender/recipient pivot — distinct visible and envelope sender fields.
> let StartTime = ago(30d);
> let EndTime = now();
> let SenderAddress = "";         // Exact sender; empty = all.
> let RecipientAddress = "";      // Exact recipient; empty = all.
> let SenderField = "Either";     // From, Envelope, or Either (case-sensitive).
> let MaxRows = 1000;
> let CommunicationPairs = materialize(
> 	EmailEvents
> 	| where Timestamp between (StartTime .. EndTime)
> 	| where isempty(SenderAddress)
> 		or (SenderField in ("From", "Either") and SenderFromAddress =~ SenderAddress)
> 		or (SenderField in ("Envelope", "Either") and SenderMailFromAddress =~ SenderAddress)
> 	| where isempty(RecipientAddress) or RecipientEmailAddress =~ RecipientAddress
> 	| summarize FirstObserved=min(Timestamp), LastObserved=max(Timestamp),
> 		ObservedEventCount=count(), arg_max(Timestamp, *)
> 		by NetworkMessageId, RecipientEmailAddress
> );
> CommunicationPairs
> | project Timestamp, FirstObserved, LastObserved, ObservedEventCount,
> 	NetworkMessageId, InternetMessageId, SenderFromAddress,
> 	SenderMailFromAddress, SenderFromDomain, RecipientEmailAddress,
> 	Subject, EmailDirection, DeliveryAction, DeliveryLocation,
> 	AuthenticationDetails, AttachmentCount, UrlCount
> | top MaxRows by Timestamp desc
> ```
>
> <details>
> <summary>Proof — sender and recipients</summary>
>
> | Recorded live result | Count |
> |---|---:|
> | Records with visible sender | 630 / 630 |
> | Records with envelope sender | 630 / 630 |
> | Records with recipient | 630 / 630 |
> | Compound exact-recipient/message pivot | 1 matching message |
>
> **Positive evidence:** populated visible/envelope sender and recipient fields on actual message-recipient rows; recipient-side filtering in the full investigation returned a known message. **Unverified:** independently filtered sender branches, the new two-parameter pair filter, and this focused child query have not been rerun. These rows are not complete To/Cc/Bcc headers or evidence of reading.
>
> </details>
> </details>

</details>

Full combined query: [Email-Investigation.kql](DFIR/Email-Investigation.kql). Additional executed-test context and limitations: [Email-Verification.md](DFIR/Email-Verification.md). All four focused queries cap displayed rows at `MaxRows`; their absence of results does not establish absence of activity outside retention or ingestion coverage.

<!-- Email-only report. Additional categories intentionally omitted. -->

