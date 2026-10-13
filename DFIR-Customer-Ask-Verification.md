# Email Investigations

Expand a customer request to copy its full KQL. Set the parameters before running; default window: last 30 days.

Without Sentinel, replace every TimeGenerated with Timestamp in Defender XDR Advanced Hunting.

Requires raw email telemetry; results are observed events, not complete mailbox contents.

<details open>
<summary><strong>Email</strong></summary>

> <details>
> <summary><strong>External communications</strong></summary>
>
> Query file: [DFIR/Email/External-communications.kql](DFIR/Email/External-communications.kql).
>
> ```kql
> // External communications
> // Without Sentinel, replace every TimeGenerated with Timestamp in Defender XDR Advanced Hunting.
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
> Query file: [DFIR/Email/Specific-attachment-filenames-and-hashes.kql](DFIR/Email/Specific-attachment-filenames-and-hashes.kql).
>
> ```kql
> // Specific attachment filenames and hashes
> // Without Sentinel, replace every TimeGenerated with Timestamp in Defender XDR Advanced Hunting.
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
> Query file: [DFIR/Email/Specific-Subject-lines.kql](DFIR/Email/Specific-Subject-lines.kql).
>
> ```kql
> // Specific Subject lines
> // Without Sentinel, replace every TimeGenerated with Timestamp in Defender XDR Advanced Hunting.
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
> Query file: [DFIR/Email/Specific-sender-and-recipients.kql](DFIR/Email/Specific-sender-and-recipients.kql).
>
> ```kql
> // Specific sender and recipients
> // Without Sentinel, replace every TimeGenerated with Timestamp in Defender XDR Advanced Hunting.
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

