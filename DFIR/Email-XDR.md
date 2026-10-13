# DFIR KQL - Email - Microsoft Defender XDR

**Updated: 2026-10-13 - Email category only**

Expand a child below for its full KQL. Each code block has GitHub's **Copy code to clipboard** button.

**Platform:** Microsoft Defender XDR Advanced Hunting (`Timestamp`). Default window: last 30 days. Set the investigation parameters before running. These queries investigate observed email telemetry, not complete mailbox contents.

**Time column:** Use `Timestamp` in XDR Advanced Hunting and `TimeGenerated` in Sentinel/Log Analytics. Both represent the recorded event time in these email tables; `TimeGenerated` is not the ingestion time. These pages already use the correct column for each platform.

**Platform choices:** [Microsoft Defender XDR](Email-XDR.md) | [Microsoft Sentinel / Log Analytics](Email-Sentinel.md) | [Platform selector](../DFIR-Customer-Ask-Verification.md).

<details open>
<summary><strong>Email Investigations</strong></summary>

> <details>
> <summary><strong>External communications</strong></summary>
>
> Filter a specific user or direction, or leave the parameters empty for all external communications. Direction comes from `EmailDirection`, not guessed domain ownership.
>
> Query file: [XDR/Email-External-Communications.kql](XDR/Email-External-Communications.kql).
>
> ```kql
> // Platform: Microsoft Defender XDR Advanced Hunting (Timestamp).
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
> </details>

> <details>
> <summary><strong>Specific attachment filenames and hashes</strong></summary>
>
> Set an exact SHA-256 hash, a filename substring, or both. When both are set, the **same attachment record** must match both. Empty parameters show all observed attachment metadata. Sender/recipient correlation uses message ID plus normalized recipient.
>
> Query file: [XDR/Email-Attachment-Pivot.kql](XDR/Email-Attachment-Pivot.kql).
>
> ```kql
> // Platform: Microsoft Defender XDR Advanced Hunting (Timestamp).
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
> </details>

> <details>
> <summary><strong>Specific Subject lines</strong></summary>
>
> Set `SubjectText` to the requested subject. Choose exact case-insensitive matching or substring matching. An empty value leaves the subject filter broad.
>
> Query file: [XDR/Email-Subject-Pivot.kql](XDR/Email-Subject-Pivot.kql).
>
> ```kql
> // Platform: Microsoft Defender XDR Advanced Hunting (Timestamp).
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
> </details>

> <details>
> <summary><strong>Specific sender and recipients</strong></summary>
>
> Set `SenderAddress`, `RecipientAddress`, or both. If both are set, both must match the same message-recipient row. Choose visible From, envelope MAIL FROM, or either sender field.
>
> Query file: [XDR/Email-Sender-Recipient-Pivot.kql](XDR/Email-Sender-Recipient-Pivot.kql).
>
> ```kql
> // Platform: Microsoft Defender XDR Advanced Hunting (Timestamp).
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
> </details>

</details>

<!-- Email-only page. Additional categories intentionally omitted. -->