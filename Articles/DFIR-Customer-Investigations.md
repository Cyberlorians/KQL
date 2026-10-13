# DFIR Customer Investigations

Expand a customer request to copy its full KQL. Set the parameters before running; default window: last 30 days. Each query is also saved as a `.kql` file under its product folder.

Email queries use `TimeGenerated`; without Sentinel, replace every `TimeGenerated` with `Timestamp` in Defender XDR Advanced Hunting. Teams, SharePoint, and OneDrive queries read the Sentinel `OfficeActivity` table (Microsoft 365 connector with Teams and SharePoint enabled) and are execution-tested; positive coverage validation is pending. See [Collaboration connectors and validation](Collaboration-Connectors.md).

Results are observed events, not complete mailbox or file contents.

<details open>
<summary><strong>Email</strong></summary>

> <details>
> <summary><strong>External communications</strong></summary>
>
> Query file: [Microsoft Defender for Office 365/External-communications.kql](../Microsoft%20Defender%20for%20Office%20365/External-communications.kql).
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
> Query file: [Microsoft Defender for Office 365/Specific-attachment-filenames-and-hashes.kql](../Microsoft%20Defender%20for%20Office%20365/Specific-attachment-filenames-and-hashes.kql).
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
> Query file: [Microsoft Defender for Office 365/Specific-Subject-lines.kql](../Microsoft%20Defender%20for%20Office%20365/Specific-Subject-lines.kql).
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
> Query file: [Microsoft Defender for Office 365/Specific-sender-and-recipients.kql](../Microsoft%20Defender%20for%20Office%20365/Specific-sender-and-recipients.kql).
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

<details>
<summary><strong>Teams Calls and Meeting activities</strong></summary>

> <details>
> <summary><strong>Join/Leave times</strong></summary>
>
> Query file: [Microsoft Teams/Join-Leave-times.kql](../Microsoft%20Teams/Join-Leave-times.kql).
>
> ```kql
> // Teams Calls and Meeting activities > Join/Leave times
> // DRAFT: live execution confirmed; positive coverage validation pending. Sentinel OfficeActivity only.
> // Evidence rows, not reconstructed sessions. Only the three explicit meeting/call operations qualify.
> let StartTime = ago(30d);
> let EndTime = now();
> let TargetUser = "";          // Exact UserId OR case-insensitive substring in raw Actor/Attendees/Members.
> let TargetOperation = "";     // Exact operation; empty = all allowed operations.
> let TargetMeetingId = "";     // Exact MeetingDetailId.
> let TargetChatThreadId = "";  // Exact ChatThreadId.
> let TargetRecordId = "";      // Exact SourceRecordId or OfficeId.
> let MaxRows = 1000;
> OfficeActivity
> | where TimeGenerated between (StartTime .. EndTime)
> | where OfficeWorkload =~ "MicrosoftTeams"
> | where Operation in~ ("MeetingDetail", "MeetingParticipantDetail", "CallParticipantDetail")
> | where isempty(TargetOperation) or Operation =~ TargetOperation
> | where isempty(TargetUser) or UserId =~ TargetUser or tostring(Actor) contains TargetUser
>     or tostring(Attendees) contains TargetUser or tostring(Members) contains TargetUser
> | where isempty(TargetMeetingId) or MeetingDetailId =~ TargetMeetingId
> | where isempty(TargetChatThreadId) or ChatThreadId =~ TargetChatThreadId
> | where isempty(TargetRecordId) or tostring(SourceRecordId) =~ TargetRecordId or tostring(OfficeId) =~ TargetRecordId
> | extend OrganizationId = tostring(column_ifexists("OrganizationId", ""))
> // Include participant and raw evidence in the key: a shared record ID must not merge different participants/times.
> | extend EvidenceFingerprint = hash_sha256(tostring(pack_array(
>     OfficeWorkload, Operation, UserId, Actor, JoinTime, LeaveTime, Attendees, Members,
>     ArtifactsShared, MeetingDetailId, ChatThreadId, ExtraProperties, OperationProperties,
>     Event_Data, OfficeObjectId, Site_Url, SourceFileName, DestinationFileName,
>     SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId, ClientIP, ActorIpAddress, ResultStatus)))
> | extend RecordIdentity = case(isnotempty(tostring(SourceRecordId)), strcat("SourceRecordId:", tostring(SourceRecordId)),
>     isnotempty(tostring(OfficeId)), strcat("OfficeId:", tostring(OfficeId)),
>     strcat("Fallback:", hash_sha256(tostring(pack_array(TimeGenerated, EvidenceFingerprint)))))
> | extend EvidenceRecordKey = hash_sha256(tostring(pack_array(OrganizationId, RecordIdentity, EvidenceFingerprint)))
> | summarize arg_max(TimeGenerated, *) by EvidenceRecordKey
> | project TimeGenerated, OrganizationId, OfficeWorkload, Operation, UserId, Actor,
>     JoinTime, LeaveTime, MeetingDetailId, ChatThreadId, Attendees, Members, ArtifactsShared,
>     ExtraProperties, OperationProperties, Event_Data, SourceRecordId, OfficeId, OfficeObjectId,
>     Site_Url, SourceFileName, DestinationFileName, SourceRelativeUrl, DestinationRelativeUrl,
>     ListItemUniqueId, ClientIP, ActorIpAddress, ResultStatus, EvidenceRecordKey
> | top min_of(MaxRows, 1000) by TimeGenerated desc
> ```
> </details>

> <details>
> <summary><strong>Meeting Duration</strong></summary>
>
> Query file: [Microsoft Teams/Meeting-Duration.kql](../Microsoft%20Teams/Meeting-Duration.kql).
>
> ```kql
> // Teams Calls and Meeting activities > Meeting Duration
> // DRAFT: live execution confirmed; positive coverage validation pending. Sentinel OfficeActivity only.
> // Duration is the interval on this evidence row, NOT a reconstructed overall meeting duration.
> // No min/max timestamp reconstruction, zero substitution, or summation across participants.
> let StartTime = ago(30d);
> let EndTime = now();
> let TargetUser = "";          // Exact UserId OR case-insensitive substring in raw Actor/Attendees/Members.
> let TargetOperation = "";     // Exact operation; empty = all allowed operations.
> let TargetMeetingId = "";     // Exact MeetingDetailId.
> let TargetChatThreadId = "";  // Exact ChatThreadId.
> let TargetRecordId = "";      // Exact SourceRecordId or OfficeId.
> let MaxRows = 1000;
> OfficeActivity
> | where TimeGenerated between (StartTime .. EndTime)
> | where OfficeWorkload =~ "MicrosoftTeams"
> | where Operation in~ ("MeetingDetail", "MeetingParticipantDetail", "CallParticipantDetail")
> | where isempty(TargetOperation) or Operation =~ TargetOperation
> | where isempty(TargetUser) or UserId =~ TargetUser or tostring(Actor) contains TargetUser
>     or tostring(Attendees) contains TargetUser or tostring(Members) contains TargetUser
> | where isempty(TargetMeetingId) or MeetingDetailId =~ TargetMeetingId
> | where isempty(TargetChatThreadId) or ChatThreadId =~ TargetChatThreadId
> | where isempty(TargetRecordId) or tostring(SourceRecordId) =~ TargetRecordId or tostring(OfficeId) =~ TargetRecordId
> | extend OrganizationId = tostring(column_ifexists("OrganizationId", ""))
> | extend EvidenceFingerprint = hash_sha256(tostring(pack_array(
>     OfficeWorkload, Operation, UserId, Actor, JoinTime, LeaveTime, Attendees, Members,
>     ArtifactsShared, MeetingDetailId, ChatThreadId, ExtraProperties, OperationProperties,
>     Event_Data, OfficeObjectId, Site_Url, SourceFileName, DestinationFileName,
>     SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId, ClientIP, ActorIpAddress, ResultStatus)))
> | extend RecordIdentity = case(isnotempty(tostring(SourceRecordId)), strcat("SourceRecordId:", tostring(SourceRecordId)),
>     isnotempty(tostring(OfficeId)), strcat("OfficeId:", tostring(OfficeId)),
>     strcat("Fallback:", hash_sha256(tostring(pack_array(TimeGenerated, EvidenceFingerprint)))))
> // Participant discriminator prevents a reused record ID from collapsing distinct join/leave evidence.
> | extend EvidenceRecordKey = hash_sha256(tostring(pack_array(OrganizationId, RecordIdentity, EvidenceFingerprint)))
> | summarize arg_max(TimeGenerated, *) by EvidenceRecordKey
> | extend HasValidInterval = isnotnull(JoinTime) and isnotnull(LeaveTime) and LeaveTime >= JoinTime
> | extend Duration = iff(HasValidInterval, LeaveTime - JoinTime, timespan(null)),
>     DurationSeconds = iff(HasValidInterval, (LeaveTime - JoinTime) / 1s, real(null)),
>     DurationStatus = case(isnull(JoinTime) or isnull(LeaveTime), "Missing join or leave time",
>         LeaveTime < JoinTime, "Invalid: leave precedes join", "Valid recorded interval")
> | project TimeGenerated, OrganizationId, OfficeWorkload, Operation, UserId, Actor,
>     JoinTime, LeaveTime, Duration, DurationSeconds, DurationStatus, HasValidInterval,
>     MeetingDetailId, ChatThreadId, Attendees, Members, ArtifactsShared,
>     ExtraProperties, OperationProperties, Event_Data, SourceRecordId, OfficeId, OfficeObjectId,
>     Site_Url, SourceFileName, DestinationFileName, SourceRelativeUrl, DestinationRelativeUrl,
>     ListItemUniqueId, ClientIP, ActorIpAddress, ResultStatus, EvidenceRecordKey
> | top min_of(MaxRows, 1000) by TimeGenerated desc
> ```
> </details>

> <details>
> <summary><strong>SharedActivities: was camera or screen shared, mute/unmute etc</strong></summary>
>
> Query file: [Microsoft Teams/SharedActivities.kql](../Microsoft%20Teams/SharedActivities.kql).
>
> ```kql
> // Teams Calls and Meeting activities > SharedActivities: was camera or screen shared, mute/unmute etc
> // DRAFT: live execution confirmed; positive coverage validation pending. Sentinel OfficeActivity only.
> // Preserve ArtifactsShared and other raw payloads; do not infer camera on/off, mute/unmute,
> // or screen-sharing state/duration from their presence, absence, or an unverified artifact value.
> // These telemetry claims are unsupported here. Empty artifacts do NOT mean nothing was shared.
> let StartTime = ago(30d);
> let EndTime = now();
> let TargetUser = "";          // Exact UserId OR case-insensitive substring in raw Actor/Attendees/Members.
> let TargetOperation = "";     // Exact operation; empty = all allowed operations.
> let TargetMeetingId = "";     // Exact MeetingDetailId.
> let TargetChatThreadId = "";  // Exact ChatThreadId.
> let TargetArtifact = "";      // Case-insensitive substring in raw ArtifactsShared; not a semantic state filter.
> let TargetRecordId = "";      // Exact SourceRecordId or OfficeId.
> let MaxRows = 1000;
> OfficeActivity
> | where TimeGenerated between (StartTime .. EndTime)
> | where OfficeWorkload =~ "MicrosoftTeams"
> | where Operation in~ ("MeetingDetail", "MeetingParticipantDetail", "CallParticipantDetail")
> | where isempty(TargetOperation) or Operation =~ TargetOperation
> | where isempty(TargetUser) or UserId =~ TargetUser or tostring(Actor) contains TargetUser
>     or tostring(Attendees) contains TargetUser or tostring(Members) contains TargetUser
> | where isempty(TargetMeetingId) or MeetingDetailId =~ TargetMeetingId
> | where isempty(TargetChatThreadId) or ChatThreadId =~ TargetChatThreadId
> | where isempty(TargetArtifact) or tostring(ArtifactsShared) contains TargetArtifact
> | where isempty(TargetRecordId) or tostring(SourceRecordId) =~ TargetRecordId or tostring(OfficeId) =~ TargetRecordId
> | extend OrganizationId = tostring(column_ifexists("OrganizationId", ""))
> | extend EvidenceFingerprint = hash_sha256(tostring(pack_array(
>     OfficeWorkload, Operation, UserId, Actor, JoinTime, LeaveTime, Attendees, Members,
>     ArtifactsShared, MeetingDetailId, ChatThreadId, ExtraProperties, OperationProperties,
>     Event_Data, OfficeObjectId, Site_Url, SourceFileName, DestinationFileName,
>     SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId, ClientIP, ActorIpAddress, ResultStatus)))
> | extend RecordIdentity = case(isnotempty(tostring(SourceRecordId)), strcat("SourceRecordId:", tostring(SourceRecordId)),
>     isnotempty(tostring(OfficeId)), strcat("OfficeId:", tostring(OfficeId)),
>     strcat("Fallback:", hash_sha256(tostring(pack_array(TimeGenerated, EvidenceFingerprint)))))
> | extend EvidenceRecordKey = hash_sha256(tostring(pack_array(OrganizationId, RecordIdentity, EvidenceFingerprint)))
> | summarize arg_max(TimeGenerated, *) by EvidenceRecordKey
> | project TimeGenerated, OrganizationId, OfficeWorkload, Operation, UserId, Actor,
>     JoinTime, LeaveTime, MeetingDetailId, ChatThreadId, ArtifactsShared, Attendees, Members,
>     ExtraProperties, OperationProperties, Event_Data, SourceRecordId, OfficeId, OfficeObjectId,
>     Site_Url, SourceFileName, DestinationFileName, SourceRelativeUrl, DestinationRelativeUrl,
>     ListItemUniqueId, ClientIP, ActorIpAddress, ResultStatus, EvidenceRecordKey
> | top min_of(MaxRows, 1000) by TimeGenerated desc
> ```
> </details>

</details>

<details>
<summary><strong>SharePoint Activity</strong></summary>

> <details>
> <summary><strong>Site/Page accessed/created/modified</strong></summary>
>
> Query file: [SharePoint/Site-Page-accessed-created-modified.kql](../SharePoint/Site-Page-accessed-created-modified.kql).
>
> ```kql
> // SharePoint Activity > Site/Page accessed/created/modified
> // DRAFT: live execution confirmed; positive coverage validation pending. Sentinel OfficeActivity only.
> // Page creation/modification/access via FILE operations is restricted to .aspx paths.
> // Explicit page/site operations remain separately labeled; no document modification is called a page edit.
> // This is an explicit operation allowlist, not a claim of exhaustive site/page auditing.
> // Site access is evidenced by the page-access row's site/object URL, not an invented SiteViewed event.
> let StartTime = ago(30d);
> let EndTime = now();
> let TargetUser = "";          // Exact UserId OR case-insensitive substring in raw Actor.
> let TargetOperation = "";     // Exact operation.
> let TargetSite = "";          // Case-insensitive substring in Site_Url or OfficeObjectId.
> let TargetFileName = "";      // Exact SourceFileName or DestinationFileName (site-only events may have neither).
> let TargetObjectId = "";      // Exact OfficeObjectId or ListItemUniqueId.
> let TargetRecordId = "";      // Exact SourceRecordId or OfficeId.
> let MaxRows = 1000;
> OfficeActivity
> | where TimeGenerated between (StartTime .. EndTime)
> | where OfficeWorkload =~ "SharePoint"
> // Personal host OR personal object/site path is excluded even when the workload is SharePoint.
> | extend IsPersonalLocation = Site_Url contains "-my.sharepoint.com" or OfficeObjectId contains "-my.sharepoint.com"
>     or Site_Url contains "/personal/" or OfficeObjectId contains "/personal/"
> | where not(IsPersonalLocation)
> | extend IsAspxPath = SourceFileName matches regex @"(?i)\.aspx(?:[?#].*)?$"
>     or DestinationFileName matches regex @"(?i)\.aspx(?:[?#].*)?$"
>     or OfficeObjectId matches regex @"(?i)\.aspx(?:[?#].*)?$"
>     or SourceRelativeUrl matches regex @"(?i)\.aspx(?:[?#].*)?$"
>     or DestinationRelativeUrl matches regex @"(?i)\.aspx(?:[?#].*)?$"
> | extend ActivityKind = case(
>     Operation =~ "SiteCollectionCreated", "Site created",
>     Operation in~ ("SiteRenamed", "SiteCollectionQuotaModified", "WebThemeApplied"), "Site modified",
>     Operation in~ ("PageViewed", "PageViewedExtended"), "Page accessed",
>     IsAspxPath and Operation in~ ("FileAccessed", "FileAccessedExtended", "FilePreviewed"), "Page accessed (file audit)",
>     IsAspxPath and Operation in~ ("FileUploaded", "FileCopied"), "Page uploaded/copied (file audit)",
>     IsAspxPath and Operation in~ ("FileModified", "FileModifiedExtended", "FileRenamed", "FileMoved"), "Page modified (file audit)",
>     "")
> | where isnotempty(ActivityKind)
> | where isempty(TargetOperation) or Operation =~ TargetOperation
> | where isempty(TargetUser) or UserId =~ TargetUser or tostring(Actor) contains TargetUser
> | where isempty(TargetSite) or Site_Url contains TargetSite or OfficeObjectId contains TargetSite
> | where isempty(TargetFileName) or SourceFileName =~ TargetFileName or DestinationFileName =~ TargetFileName
> | where isempty(TargetObjectId) or OfficeObjectId =~ TargetObjectId or tostring(ListItemUniqueId) =~ TargetObjectId
> | where isempty(TargetRecordId) or tostring(SourceRecordId) =~ TargetRecordId or tostring(OfficeId) =~ TargetRecordId
> | extend OrganizationId = tostring(column_ifexists("OrganizationId", ""))
> | extend EvidenceFingerprint = hash_sha256(tostring(pack_array(
>     OfficeWorkload, Operation, UserId, Actor, OfficeObjectId, Site_Url, SourceFileName,
>     DestinationFileName, SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId,
>     ClientIP, ActorIpAddress, ResultStatus, ExtraProperties, OperationProperties, Event_Data,
>     JoinTime, LeaveTime, Attendees, Members, ArtifactsShared, MeetingDetailId, ChatThreadId)))
> | extend RecordIdentity = case(isnotempty(tostring(SourceRecordId)), strcat("SourceRecordId:", tostring(SourceRecordId)),
>     isnotempty(tostring(OfficeId)), strcat("OfficeId:", tostring(OfficeId)),
>     strcat("Fallback:", hash_sha256(tostring(pack_array(TimeGenerated, EvidenceFingerprint)))))
> | extend EvidenceRecordKey = hash_sha256(tostring(pack_array(OrganizationId, RecordIdentity, EvidenceFingerprint)))
> | summarize arg_max(TimeGenerated, *) by EvidenceRecordKey
> | project TimeGenerated, OrganizationId, OfficeWorkload, Operation, ActivityKind, IsAspxPath,
>     UserId, Actor, Site_Url, OfficeObjectId, SourceFileName, DestinationFileName,
>     SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId, SourceRecordId, OfficeId,
>     ClientIP, ActorIpAddress, ResultStatus, ExtraProperties, OperationProperties, Event_Data,
>     JoinTime, LeaveTime, Attendees, Members, ArtifactsShared, MeetingDetailId, ChatThreadId, EvidenceRecordKey
> | top min_of(MaxRows, 1000) by TimeGenerated desc
> ```
> </details>

> <details>
> <summary><strong>Files uploaded/downloaded from a SharePoint site</strong></summary>
>
> Query file: [SharePoint/Files-uploaded-downloaded-from-a-SharePoint-site.kql](../SharePoint/Files-uploaded-downloaded-from-a-SharePoint-site.kql).
>
> ```kql
> // SharePoint Activity > Files uploaded/downloaded from a SharePoint site
> // DRAFT: live execution confirmed; positive coverage validation pending. Sentinel OfficeActivity only.
> // Only FileUploaded/FileDownloaded: sync-full/partial operations are deliberately NOT included.
> // Operation is audit evidence, not proof of completion, file bytes, or file content.
> let StartTime = ago(30d);
> let EndTime = now();
> let TargetUser = "";          // Exact UserId OR case-insensitive substring in raw Actor.
> let TargetOperation = "";     // Exact FileUploaded or FileDownloaded.
> let TargetSite = "";          // Case-insensitive substring in Site_Url or OfficeObjectId.
> let TargetFileName = "";      // Exact SourceFileName or DestinationFileName.
> let TargetObjectId = "";      // Exact OfficeObjectId or ListItemUniqueId.
> let TargetRecordId = "";      // Exact SourceRecordId or OfficeId.
> let MaxRows = 1000;
> OfficeActivity
> | where TimeGenerated between (StartTime .. EndTime)
> | where OfficeWorkload =~ "SharePoint"
> | extend IsPersonalLocation = Site_Url contains "-my.sharepoint.com" or OfficeObjectId contains "-my.sharepoint.com"
>     or Site_Url contains "/personal/" or OfficeObjectId contains "/personal/"
> | where not(IsPersonalLocation)
> | where Operation in~ ("FileUploaded", "FileDownloaded")
> | where isempty(TargetOperation) or Operation =~ TargetOperation
> | where isempty(TargetUser) or UserId =~ TargetUser or tostring(Actor) contains TargetUser
> | where isempty(TargetSite) or Site_Url contains TargetSite or OfficeObjectId contains TargetSite
> | where isempty(TargetFileName) or SourceFileName =~ TargetFileName or DestinationFileName =~ TargetFileName
> | where isempty(TargetObjectId) or OfficeObjectId =~ TargetObjectId or tostring(ListItemUniqueId) =~ TargetObjectId
> | where isempty(TargetRecordId) or tostring(SourceRecordId) =~ TargetRecordId or tostring(OfficeId) =~ TargetRecordId
> | extend OrganizationId = tostring(column_ifexists("OrganizationId", ""))
> | extend EvidenceFingerprint = hash_sha256(tostring(pack_array(
>     OfficeWorkload, Operation, UserId, Actor, OfficeObjectId, Site_Url, SourceFileName,
>     DestinationFileName, SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId,
>     ClientIP, ActorIpAddress, ResultStatus, ExtraProperties, OperationProperties, Event_Data,
>     JoinTime, LeaveTime, Attendees, Members, ArtifactsShared, MeetingDetailId, ChatThreadId)))
> | extend RecordIdentity = case(isnotempty(tostring(SourceRecordId)), strcat("SourceRecordId:", tostring(SourceRecordId)),
>     isnotempty(tostring(OfficeId)), strcat("OfficeId:", tostring(OfficeId)),
>     strcat("Fallback:", hash_sha256(tostring(pack_array(TimeGenerated, EvidenceFingerprint)))))
> | extend EvidenceRecordKey = hash_sha256(tostring(pack_array(OrganizationId, RecordIdentity, EvidenceFingerprint)))
> | summarize arg_max(TimeGenerated, *) by EvidenceRecordKey
> | project TimeGenerated, OrganizationId, OfficeWorkload, Operation, UserId, Actor,
>     Site_Url, OfficeObjectId, SourceFileName, DestinationFileName,
>     SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId, SourceRecordId, OfficeId,
>     ClientIP, ActorIpAddress, ResultStatus, ExtraProperties, OperationProperties, Event_Data,
>     JoinTime, LeaveTime, Attendees, Members, ArtifactsShared, MeetingDetailId, ChatThreadId, EvidenceRecordKey
> | top min_of(MaxRows, 1000) by TimeGenerated desc
> ```
> </details>

</details>

<details>
<summary><strong>OneDrive</strong></summary>

> <details>
> <summary><strong>User File activity</strong></summary>
>
> Query file: [OneDrive/User-File-activity.kql](../OneDrive/User-File-activity.kql).
>
> ```kql
> // OneDrive > User File activity
> // DRAFT: live execution confirmed; positive coverage validation pending. Sentinel OfficeActivity only.
> // Explicit non-sync file operations; this allowlist is not exhaustive and does not reveal file contents.
> // SharePoint-labeled personal OneDrive records qualify by OfficeObjectId/Site_Url fallback.
> let StartTime = ago(30d);
> let EndTime = now();
> let TargetUser = "";          // Exact UserId OR case-insensitive substring in raw Actor.
> let TargetOperation = "";     // Exact operation from the allowlist below.
> let TargetSite = "";          // Case-insensitive substring in Site_Url or OfficeObjectId.
> let TargetFileName = "";      // Exact SourceFileName or DestinationFileName.
> let TargetObjectId = "";      // Exact OfficeObjectId or ListItemUniqueId.
> let TargetRecordId = "";      // Exact SourceRecordId or OfficeId.
> let MaxRows = 1000;
> OfficeActivity
> | where TimeGenerated between (StartTime .. EndTime)
> | extend IsPersonalLocation = Site_Url contains "-my.sharepoint.com" or OfficeObjectId contains "-my.sharepoint.com"
>     or Site_Url contains "/personal/" or OfficeObjectId contains "/personal/"
> | where OfficeWorkload =~ "OneDrive" or (OfficeWorkload =~ "SharePoint" and IsPersonalLocation)
> | where Operation in~ ("FileAccessed", "FileAccessedExtended", "FilePreviewed", "FileUploaded", "FileDownloaded",
>     "FileModified", "FileModifiedExtended", "FileCopied", "FileMoved", "FileRenamed", "FileDeleted",
>     "FileRecycled", "FileRestored", "FileCheckedIn", "FileCheckedOut", "FileCheckOutDiscarded", "FileVersionDeleted")
> | where isempty(TargetOperation) or Operation =~ TargetOperation
> | where isempty(TargetUser) or UserId =~ TargetUser or tostring(Actor) contains TargetUser
> | where isempty(TargetSite) or Site_Url contains TargetSite or OfficeObjectId contains TargetSite
> | where isempty(TargetFileName) or SourceFileName =~ TargetFileName or DestinationFileName =~ TargetFileName
> | where isempty(TargetObjectId) or OfficeObjectId =~ TargetObjectId or tostring(ListItemUniqueId) =~ TargetObjectId
> | where isempty(TargetRecordId) or tostring(SourceRecordId) =~ TargetRecordId or tostring(OfficeId) =~ TargetRecordId
> | extend OrganizationId = tostring(column_ifexists("OrganizationId", ""))
> | extend EvidenceFingerprint = hash_sha256(tostring(pack_array(
>     OfficeWorkload, Operation, UserId, Actor, OfficeObjectId, Site_Url, SourceFileName,
>     DestinationFileName, SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId,
>     ClientIP, ActorIpAddress, ResultStatus, ExtraProperties, OperationProperties, Event_Data,
>     JoinTime, LeaveTime, Attendees, Members, ArtifactsShared, MeetingDetailId, ChatThreadId)))
> | extend RecordIdentity = case(isnotempty(tostring(SourceRecordId)), strcat("SourceRecordId:", tostring(SourceRecordId)),
>     isnotempty(tostring(OfficeId)), strcat("OfficeId:", tostring(OfficeId)),
>     strcat("Fallback:", hash_sha256(tostring(pack_array(TimeGenerated, EvidenceFingerprint)))))
> | extend EvidenceRecordKey = hash_sha256(tostring(pack_array(OrganizationId, RecordIdentity, EvidenceFingerprint)))
> | summarize arg_max(TimeGenerated, *) by EvidenceRecordKey
> | project TimeGenerated, OrganizationId, OfficeWorkload, Operation, IsPersonalLocation, UserId, Actor,
>     Site_Url, OfficeObjectId, SourceFileName, DestinationFileName,
>     SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId, SourceRecordId, OfficeId,
>     ClientIP, ActorIpAddress, ResultStatus, ExtraProperties, OperationProperties, Event_Data,
>     JoinTime, LeaveTime, Attendees, Members, ArtifactsShared, MeetingDetailId, ChatThreadId, EvidenceRecordKey
> | top min_of(MaxRows, 1000) by TimeGenerated desc
> ```
> </details>

> <details>
> <summary><strong>Sync activity</strong></summary>
>
> Query file: [OneDrive/Sync-activity.kql](../OneDrive/Sync-activity.kql).
>
> ```kql
> // OneDrive > Sync activity
> // DRAFT: live execution confirmed; positive coverage validation pending. Sentinel OfficeActivity only.
> // Only explicit full/partial sync upload/download operations; generic FileUploaded is NOT sync evidence.
> // Partial operations are deprecated legacy Groove.exe evidence, retained for historical investigations.
> // A reproducible sync test requires the signed-in OneDrive.exe client, not a Graph upload.
> // Operation labels do not prove full client convergence or disclose file contents.
> let StartTime = ago(30d);
> let EndTime = now();
> let TargetUser = "";          // Exact UserId OR case-insensitive substring in raw Actor.
> let TargetOperation = "";     // Exact full/partial sync operation from the allowlist below.
> let TargetSite = "";          // Case-insensitive substring in Site_Url or OfficeObjectId.
> let TargetFileName = "";      // Exact SourceFileName or DestinationFileName.
> let TargetObjectId = "";      // Exact OfficeObjectId or ListItemUniqueId.
> let TargetRecordId = "";      // Exact SourceRecordId or OfficeId.
> let MaxRows = 1000;
> OfficeActivity
> | where TimeGenerated between (StartTime .. EndTime)
> | extend IsPersonalLocation = Site_Url contains "-my.sharepoint.com" or OfficeObjectId contains "-my.sharepoint.com"
>     or Site_Url contains "/personal/" or OfficeObjectId contains "/personal/"
> | where OfficeWorkload =~ "OneDrive" or (OfficeWorkload =~ "SharePoint" and IsPersonalLocation)
> | where Operation in~ ("FileSyncUploadedFull", "FileSyncDownloadedFull", "FileSyncUploadedPartial", "FileSyncDownloadedPartial")
> | where isempty(TargetOperation) or Operation =~ TargetOperation
> | where isempty(TargetUser) or UserId =~ TargetUser or tostring(Actor) contains TargetUser
> | where isempty(TargetSite) or Site_Url contains TargetSite or OfficeObjectId contains TargetSite
> | where isempty(TargetFileName) or SourceFileName =~ TargetFileName or DestinationFileName =~ TargetFileName
> | where isempty(TargetObjectId) or OfficeObjectId =~ TargetObjectId or tostring(ListItemUniqueId) =~ TargetObjectId
> | where isempty(TargetRecordId) or tostring(SourceRecordId) =~ TargetRecordId or tostring(OfficeId) =~ TargetRecordId
> | extend OrganizationId = tostring(column_ifexists("OrganizationId", ""))
> | extend EvidenceFingerprint = hash_sha256(tostring(pack_array(
>     OfficeWorkload, Operation, UserId, Actor, OfficeObjectId, Site_Url, SourceFileName,
>     DestinationFileName, SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId,
>     ClientIP, ActorIpAddress, ResultStatus, ExtraProperties, OperationProperties, Event_Data,
>     JoinTime, LeaveTime, Attendees, Members, ArtifactsShared, MeetingDetailId, ChatThreadId)))
> | extend RecordIdentity = case(isnotempty(tostring(SourceRecordId)), strcat("SourceRecordId:", tostring(SourceRecordId)),
>     isnotempty(tostring(OfficeId)), strcat("OfficeId:", tostring(OfficeId)),
>     strcat("Fallback:", hash_sha256(tostring(pack_array(TimeGenerated, EvidenceFingerprint)))))
> | extend EvidenceRecordKey = hash_sha256(tostring(pack_array(OrganizationId, RecordIdentity, EvidenceFingerprint)))
> | summarize arg_max(TimeGenerated, *) by EvidenceRecordKey
> | project TimeGenerated, OrganizationId, OfficeWorkload, Operation, IsPersonalLocation, UserId, Actor,
>     Site_Url, OfficeObjectId, SourceFileName, DestinationFileName,
>     SourceRelativeUrl, DestinationRelativeUrl, ListItemUniqueId, SourceRecordId, OfficeId,
>     ClientIP, ActorIpAddress, ResultStatus, ExtraProperties, OperationProperties, Event_Data,
>     JoinTime, LeaveTime, Attendees, Members, ArtifactsShared, MeetingDetailId, ChatThreadId, EvidenceRecordKey
> | top min_of(MaxRows, 1000) by TimeGenerated desc
> ```
> </details>

</details>
