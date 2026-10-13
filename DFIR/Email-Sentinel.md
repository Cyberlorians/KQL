# DFIR KQL - Email - Microsoft Sentinel

**Updated: 2026-10-13 - Email category only**

Expand a child below for its full KQL. Each code block has GitHub's **Copy code to clipboard** button.

**Platform:** Microsoft Sentinel / Log Analytics (`TimeGenerated`). Default window: last 30 days. Set the investigation parameters before running. These queries investigate observed email telemetry, not complete mailbox contents.

**Prerequisite:** Ingest the raw Microsoft Defender for Office 365 events into the Sentinel workspace: `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, and `EmailPostDeliveryEvents`. Configure the Microsoft Defender XDR connector's raw-event collection for these tables; alerts/incidents alone are insufficient. Table availability, retention, permissions, and ingestion latency determine the usable scope. These versions use `TimeGenerated` throughout, including attachment and post-delivery bag keys; all other investigation logic is preserved.

**Time column:** Use `TimeGenerated` in Sentinel/Log Analytics and `Timestamp` in XDR Advanced Hunting. Both represent the recorded event time in these email tables; `TimeGenerated` is not the ingestion time. These pages already use the correct column for each platform.

**Platform choices:** [Microsoft Defender XDR](Email-XDR.md) | [Microsoft Sentinel / Log Analytics](Email-Sentinel.md) | [Platform selector](../DFIR-Customer-Ask-Verification.md).

<details open>
<summary><strong>Email Investigations</strong></summary>

> <details>
> <summary><strong>External communications</strong></summary>
>
> Filter a specific user or direction, or leave the parameters empty for all external communications. Direction comes from `EmailDirection`, not guessed domain ownership.
>
> Query file: [Sentinel/Email-External-Communications.kql](Sentinel/Email-External-Communications.kql).
>
> ```kql
> // Platform: Microsoft Sentinel / Log Analytics (TimeGenerated).
> // External communications — observed inbound/outbound messages.
> let StartTime = ago(30d);
> let EndTime = now();
> let TargetUser = "";          // Exact visible sender, envelope sender, or recipient.
> let Direction = "";           // Inbound or Outbound; empty = both.
> let MaxRows = 1000;
> let ExternalMessages = materialize(
> 	EmailEvents
> 	| where TimeGenerated between (StartTime .. EndTime)
> 	| where EmailDirection in~ ("Inbound", "Outbound")
> 	| where isempty(Direction) or EmailDirection =~ Direction
> 	| where isempty(TargetUser) or SenderFromAddress =~ TargetUser
> 		or SenderMailFromAddress =~ TargetUser or RecipientEmailAddress =~ TargetUser
> 	| summarize FirstObserved=min(TimeGenerated), LastObserved=max(TimeGenerated),
> 		ObservedEventCount=count(), arg_max(TimeGenerated, *)
> 		by NetworkMessageId, RecipientEmailAddress
> );
> ExternalMessages
> | project TimeGenerated, FirstObserved, LastObserved, ObservedEventCount,
> 	NetworkMessageId, InternetMessageId, EmailDirection,
> 	SenderFromAddress, SenderMailFromAddress, SenderFromDomain,
> 	SenderIPv4, SenderIPv6, RecipientEmailAddress, Subject,
> 	DeliveryAction, DeliveryLocation, AuthenticationDetails,
> 	ThreatTypes, ThreatNames, AttachmentCount, UrlCount
> | top MaxRows by TimeGenerated desc
> ```
> </details>

> <details>
> <summary><strong>Specific attachment filenames and hashes</strong></summary>
>
> Set an exact SHA-256 hash, a filename substring, or both. When both are set, the **same attachment record** must match both. Empty parameters show all observed attachment metadata. Sender/recipient correlation uses message ID plus normalized recipient.
>
> Query file: [Sentinel/Email-Attachment-Pivot.kql](Sentinel/Email-Attachment-Pivot.kql).
>
> ```kql
> // Platform: Microsoft Sentinel / Log Analytics (TimeGenerated).
> // Attachment pivot — matching attachment metadata correlated to its email recipient.
> let StartTime = ago(30d);
> let EndTime = now();
> let AttachmentNameContains = "";  // Case-insensitive filename substring.
> let AttachmentSHA256 = "";        // Exact SHA-256, case-insensitive.
> let TargetRecipient = "";         // Exact recipient; empty = all.
> let MaxRows = 1000;
> let MatchingAttachments = materialize(
> 	EmailAttachmentInfo
> 	| where TimeGenerated between (StartTime .. EndTime)
> 	| where isempty(AttachmentNameContains) or FileName contains AttachmentNameContains
> 	| where isempty(AttachmentSHA256) or SHA256 =~ AttachmentSHA256
> 	| where isempty(TargetRecipient) or RecipientEmailAddress =~ TargetRecipient
> 	| extend RecipientKey=tolower(RecipientEmailAddress)
> 	| summarize AttachmentRecords=count(), MatchingAttachments=make_set(
> 		bag_pack("FileName", FileName, "SHA256", SHA256, "FileSize", FileSize,
> 			"FileType", FileType, "ThreatTypes", ThreatTypes,
> 			"ThreatNames", ThreatNames, "TimeGenerated", TimeGenerated), 500)
> 		by NetworkMessageId, RecipientKey
> );
> let Messages = EmailEvents
> 	| where TimeGenerated between (StartTime .. EndTime)
> 	| where NetworkMessageId in (MatchingAttachments | project NetworkMessageId)
> 	| where isempty(TargetRecipient) or RecipientEmailAddress =~ TargetRecipient
> 	| summarize FirstObserved=min(TimeGenerated), LastObserved=max(TimeGenerated),
> 		arg_max(TimeGenerated, *) by NetworkMessageId, RecipientEmailAddress
> 	| extend RecipientKey=tolower(RecipientEmailAddress);
> MatchingAttachments
> | join kind=leftouter Messages on NetworkMessageId, RecipientKey
> | project NetworkMessageId, RecipientKey, RecipientEmailAddress,
> 	TimeGenerated, FirstObserved, LastObserved, InternetMessageId,
> 	SenderFromAddress, SenderMailFromAddress, Subject, EmailDirection,
> 	DeliveryAction, DeliveryLocation, AttachmentRecords, MatchingAttachments,
> 	MessageEvidence=iff(isnotempty(RecipientEmailAddress),
> 		"Message correlated", "Attachment observed; email missing in scope")
> | top MaxRows by TimeGenerated desc
> ```
> </details>

> <details>
> <summary><strong>Specific Subject lines</strong></summary>
>
> Set `SubjectText` to the requested subject. Choose exact case-insensitive matching or substring matching. An empty value leaves the subject filter broad.
>
> Query file: [Sentinel/Email-Subject-Pivot.kql](Sentinel/Email-Subject-Pivot.kql).
>
> ```kql
> // Platform: Microsoft Sentinel / Log Analytics (TimeGenerated).
> // Subject pivot — actual email Subject field.
> let StartTime = ago(30d);
> let EndTime = now();
> let SubjectText = "";
> let ExactSubject = false;       // true = exact; false = substring.
> let TargetRecipient = "";       // Exact recipient; empty = all.
> let MaxRows = 1000;
> let SubjectMessages = materialize(
> 	EmailEvents
> 	| where TimeGenerated between (StartTime .. EndTime)
> 	| where isempty(SubjectText)
> 		or (ExactSubject and Subject =~ SubjectText)
> 		or (not(ExactSubject) and Subject contains SubjectText)
> 	| where isempty(TargetRecipient) or RecipientEmailAddress =~ TargetRecipient
> 	| summarize FirstObserved=min(TimeGenerated), LastObserved=max(TimeGenerated),
> 		ObservedEventCount=count(), arg_max(TimeGenerated, *)
> 		by NetworkMessageId, RecipientEmailAddress
> );
> SubjectMessages
> | project TimeGenerated, FirstObserved, LastObserved, ObservedEventCount,
> 	NetworkMessageId, InternetMessageId, Subject,
> 	SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
> 	EmailDirection, DeliveryAction, DeliveryLocation,
> 	ThreatTypes, ThreatNames, AttachmentCount, UrlCount
> | top MaxRows by TimeGenerated desc
> ```
> </details>

> <details>
> <summary><strong>Specific sender and recipients</strong></summary>
>
> Set `SenderAddress`, `RecipientAddress`, or both. If both are set, both must match the same message-recipient row. Choose visible From, envelope MAIL FROM, or either sender field.
>
> Query file: [Sentinel/Email-Sender-Recipient-Pivot.kql](Sentinel/Email-Sender-Recipient-Pivot.kql).
>
> ```kql
> // Platform: Microsoft Sentinel / Log Analytics (TimeGenerated).
> // Sender/recipient pivot — distinct visible and envelope sender fields.
> let StartTime = ago(30d);
> let EndTime = now();
> let SenderAddress = "";         // Exact sender; empty = all.
> let RecipientAddress = "";      // Exact recipient; empty = all.
> let SenderField = "Either";     // From, Envelope, or Either (case-sensitive).
> let MaxRows = 1000;
> let CommunicationPairs = materialize(
> 	EmailEvents
> 	| where TimeGenerated between (StartTime .. EndTime)
> 	| where isempty(SenderAddress)
> 		or (SenderField in ("From", "Either") and SenderFromAddress =~ SenderAddress)
> 		or (SenderField in ("Envelope", "Either") and SenderMailFromAddress =~ SenderAddress)
> 	| where isempty(RecipientAddress) or RecipientEmailAddress =~ RecipientAddress
> 	| summarize FirstObserved=min(TimeGenerated), LastObserved=max(TimeGenerated),
> 		ObservedEventCount=count(), arg_max(TimeGenerated, *)
> 		by NetworkMessageId, RecipientEmailAddress
> );
> CommunicationPairs
> | project TimeGenerated, FirstObserved, LastObserved, ObservedEventCount,
> 	NetworkMessageId, InternetMessageId, SenderFromAddress,
> 	SenderMailFromAddress, SenderFromDomain, RecipientEmailAddress,
> 	Subject, EmailDirection, DeliveryAction, DeliveryLocation,
> 	AuthenticationDetails, AttachmentCount, UrlCount
> | top MaxRows by TimeGenerated desc
> ```
> </details>

</details>

<!-- Email-only page. Additional categories intentionally omitted. -->