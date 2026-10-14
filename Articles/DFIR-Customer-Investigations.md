# DFIR Customer Investigations

Expand a customer request to copy its full KQL. Set the parameters before running; default window: last 30 days. Each query is also saved as a `.kql` file under its product folder.

These queries are written for the unified Defender portal (Microsoft Sentinel and Defender XDR together) and we recommend running them there. Email queries use `TimeGenerated`, SharePoint and OneDrive queries read the Sentinel `OfficeActivity` table (Microsoft 365 connector with SharePoint enabled), and Teams call and meeting queries read the Defender XDR `CallActivityEvents` table. If you are not unified, the table or timestamp column may differ, for example replace `TimeGenerated` with `Timestamp` in Defender XDR only, so adjust the query or, better, unify Sentinel and Defender XDR. A green check mark means the query was tested against live tenant data. See [Collaboration connectors and validation](Collaboration-Connectors.md).

Results are observed events, not complete mailbox or file contents.

<details open>
<summary><strong>Email</strong></summary>

> <details>
> <summary>✅ <strong>External communications</strong></summary>
>
> Query file: [Microsoft Defender for Office 365/External-communications.kql](../Microsoft%20Defender%20for%20Office%20365/External-communications.kql).
>
> ```kql
> // External communications
> // Objective: Lists email sent to or received from outside the organization (Inbound and Outbound) with the sender,
> // recipient, subject, delivery and threat details. Internal-only mail is excluded by design.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all users, both directions).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"] (matches visible sender, envelope sender, or recipient)
> let TargetDirections = dynamic([]);     // Example: ["Outbound"] (Inbound or Outbound; empty = both)
> //
> // ----- Part 1: Filter external email -----
> //
> EmailEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where EmailDirection in~ ("Inbound", "Outbound")
> | where (array_length(TargetDirections) == 0 or EmailDirection in~ (TargetDirections))
> | where (array_length(TargetUsers) == 0 or SenderFromAddress in~ (TargetUsers)
>     or SenderMailFromAddress in~ (TargetUsers) or RecipientEmailAddress in~ (TargetUsers))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, EmailDirection, SenderFromAddress, SenderMailFromAddress,
>     RecipientEmailAddress, Subject, SenderFromDomain, SenderIPv4, SenderIPv6,
>     DeliveryAction, DeliveryLocation, AuthenticationDetails,
>     ThreatTypes, ThreatNames, AttachmentCount, UrlCount,
>     NetworkMessageId, InternetMessageId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Specific attachment filenames and hashes</strong></summary>
>
> Query file: [Microsoft Defender for Office 365/Specific-attachment-filenames-and-hashes.kql](../Microsoft%20Defender%20for%20Office%20365/Specific-attachment-filenames-and-hashes.kql).
>
> ```kql
> // Specific attachment filenames and hashes
> // Objective: Finds email attachments by filename or SHA-256, showing the sender, recipient, FileName, SHA256,
> // FileSize, FileType and threat details for each attachment.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (every attachment, all users).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetFileNames = dynamic([]);      // Example: ["invoice.pdf", "payroll"] (case-insensitive whole-word match on the filename, not partial words)
> let TargetSHA256 = dynamic([]);         // Example: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"] (matches sender or recipient)
> //
> // ----- Part 1: Filter attachments -----
> //
> EmailAttachmentInfo
> | where TimeGenerated between (StartTime .. EndTime)
> | where (array_length(TargetFileNames) == 0 or FileName has_any (TargetFileNames))
> | where (array_length(TargetSHA256) == 0 or SHA256 in~ (TargetSHA256))
> | where (array_length(TargetUsers) == 0 or SenderFromAddress in~ (TargetUsers)
>     or RecipientEmailAddress in~ (TargetUsers))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, SenderFromAddress, RecipientEmailAddress,
>     FileName, SHA256, FileSize, FileType, ThreatTypes, ThreatNames,
>     NetworkMessageId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Specific Subject lines</strong></summary>
>
> Query file: [Microsoft Defender for Office 365/Specific-Subject-lines.kql](../Microsoft%20Defender%20for%20Office%20365/Specific-Subject-lines.kql).
>
> ```kql
> // Specific Subject lines
> // Objective: Finds email by subject line, showing the subject, sender, recipient, direction,
> // delivery result, threat details and attachment/URL counts.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (every subject, all users).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetSubjects = dynamic([]);       // Example: ["Invoice", "Password reset"] (case-insensitive whole-word/phrase match, not partial words)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"] (matches visible sender, envelope sender, or recipient)
> //
> // ----- Part 1: Filter by subject and user -----
> //
> EmailEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where (array_length(TargetSubjects) == 0 or Subject has_any (TargetSubjects))
> | where (array_length(TargetUsers) == 0 or SenderFromAddress in~ (TargetUsers)
>     or SenderMailFromAddress in~ (TargetUsers) or RecipientEmailAddress in~ (TargetUsers))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
>     Subject, EmailDirection, DeliveryAction, DeliveryLocation,
>     ThreatTypes, ThreatNames, AttachmentCount, UrlCount,
>     NetworkMessageId, InternetMessageId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Specific sender and recipients</strong></summary>
>
> Query file: [Microsoft Defender for Office 365/Specific-sender-and-recipients.kql](../Microsoft%20Defender%20for%20Office%20365/Specific-sender-and-recipients.kql).
>
> ```kql
> // Specific sender and recipients
> // Objective: Shows who emailed whom: visible (From) and envelope (MailFrom) sender, recipient, subject,
> // direction (Inbound, Outbound or Intra-org), delivery result and attachment/URL counts.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all senders, all recipients).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetSenders = dynamic([]);        // Example: ["sender@contoso.com", "sender2@fabrikam.com"] (matches visible sender or envelope sender)
> let TargetRecipients = dynamic([]);     // Example: ["user@contoso.com", "user2@contoso.com"]
> //
> // ----- Part 1: Filter sender and recipient -----
> //
> EmailEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where (array_length(TargetSenders) == 0 or SenderFromAddress in~ (TargetSenders)
>     or SenderMailFromAddress in~ (TargetSenders))
> | where (array_length(TargetRecipients) == 0 or RecipientEmailAddress in~ (TargetRecipients))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, EmailDirection, SenderFromAddress, SenderMailFromAddress,
>     RecipientEmailAddress, Subject, SenderFromDomain,
>     DeliveryAction, DeliveryLocation, AuthenticationDetails,
>     AttachmentCount, UrlCount, NetworkMessageId, InternetMessageId
> | top 1000 by TimeGenerated desc
> ```
> </details>

</details>

<details>
<summary><strong>Teams Calls and Meeting activities</strong></summary>

> Defender XDR Advanced Hunting only. The `CallActivityEvents` table is not available in Microsoft Sentinel.

> <details>
> <summary>✅ <strong>Join/Leave times</strong></summary>
>
> Query file: [Microsoft Teams/Join-Leave-times.kql](../Microsoft%20Teams/Join-Leave-times.kql).
>
> ```kql
> // Teams Calls and Meeting activities > Join/Leave times
> // Written for the unified Defender portal. CallActivityEvents is an XDR table and is not available in Sentinel / Log Analytics alone.
> // One row per call activity event (JoinCall, LeaveCall and any other ActivityType); set TargetActivityTypes to ["JoinCall", "LeaveCall"] for join/leave only.
> // A join or leave can be reported more than once (different ActivityId).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all users, all calls, all activity types).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"]
> let TargetCallIds = dynamic([]);        // Example: ["11111111-2222-3333-4444-555555555555"] (CallId from a previous result)
> let TargetActivityTypes = dynamic([]);  // Example: ["JoinCall", "LeaveCall"] (empty = every ActivityType, including StartShare / StopShare)
> //
> // ----- Part 1: Filter Call Activity -----
> //
> CallActivityEvents
> | where ActivityTimestamp between (StartTime .. EndTime)
> | where (array_length(TargetUsers) == 0 or ActivityInitiatorUpn in~ (TargetUsers))
> | where (array_length(TargetCallIds) == 0 or CallId in~ (TargetCallIds))
> | where (array_length(TargetActivityTypes) == 0 or ActivityType in~ (TargetActivityTypes))
> | project ActivityTimestamp, ActivityType, ActivityInitiatorUpn, ActivityInitiatorDisplayName, ActivityInitiatorId,
>     OriginatorUpn, OriginatorUserDisplayName, CallSchedulingType, CallId, ThreadId, CallJoinUrl, ActivityId
> | top 1000 by ActivityTimestamp desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Meeting Duration</strong></summary>
>
> Query file: [Microsoft Teams/Meeting-Duration.kql](../Microsoft%20Teams/Meeting-Duration.kql).
>
> ```kql
> // Teams Calls and Meeting activities > Meeting Duration
> // Written for the unified Defender portal. CallActivityEvents is an XDR table and is not available in Sentinel / Log Analytics alone.
> // One row per user per CallId: first JoinCall to last LeaveCall. Rejoins inside one call are included in the span.
> // If the join or leave falls outside the time window, or is not recorded, Duration is empty and DurationStatus says why.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all users, all calls).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"]
> let TargetCallIds = dynamic([]);        // Example: ["11111111-2222-3333-4444-555555555555"] (CallId from a previous result)
> let TargetActivityTypes = dynamic([]);  // Example: ["JoinCall", "LeaveCall"] (duration is calculated from JoinCall and LeaveCall rows)
> //
> // ----- Part 1: Filter Call Activity, then calculate duration per user per call -----
> //
> CallActivityEvents
> | where ActivityTimestamp between (StartTime .. EndTime)
> | where (array_length(TargetUsers) == 0 or ActivityInitiatorUpn in~ (TargetUsers))
> | where (array_length(TargetCallIds) == 0 or CallId in~ (TargetCallIds))
> | where (array_length(TargetActivityTypes) == 0 or ActivityType in~ (TargetActivityTypes))
> | summarize FirstJoin=minif(ActivityTimestamp, ActivityType == "JoinCall"),
>     LastLeave=maxif(ActivityTimestamp, ActivityType == "LeaveCall"),
>     JoinRows=countif(ActivityType == "JoinCall"), LeaveRows=countif(ActivityType == "LeaveCall"),
>     ThreadId=take_any(ThreadId), CallSchedulingType=take_any(CallSchedulingType),
>     ActivityInitiatorDisplayName=take_any(ActivityInitiatorDisplayName), ActivityInitiatorId=take_any(ActivityInitiatorId),
>     OriginatorUpn=take_any(OriginatorUpn), OriginatorUserDisplayName=take_any(OriginatorUserDisplayName)
>     by CallId, ActivityInitiatorUpn
> | extend Valid = isnotnull(FirstJoin) and isnotnull(LastLeave) and LastLeave >= FirstJoin
> | extend Duration = iff(Valid, LastLeave - FirstJoin, timespan(null)),
>     DurationSeconds = iff(Valid, (LastLeave - FirstJoin) / 1s, real(null)),
>     DurationStatus = case(JoinRows == 0, "Missing join", LeaveRows == 0, "Missing leave",
>         LastLeave < FirstJoin, "Invalid: leave precedes join", "First join to last leave")
> | project CallId, ThreadId, CallSchedulingType, ActivityInitiatorUpn, ActivityInitiatorDisplayName, ActivityInitiatorId,
>     OriginatorUpn, OriginatorUserDisplayName, FirstJoin, LastLeave,
>     Duration, DurationSeconds, DurationStatus, JoinRows, LeaveRows
> | top 1000 by FirstJoin desc
> ```
> </details>

> <details>
> <summary>✅ <strong>SharedActivities: was camera or screen shared, mute/unmute etc</strong></summary>
>
> Query file: [Microsoft Teams/SharedActivities.kql](../Microsoft%20Teams/SharedActivities.kql).
>
> ```kql
> // Teams Calls and Meeting activities > SharedActivities: was camera or screen shared, mute/unmute etc
> // Written for the unified Defender portal. CallActivityEvents is an XDR table and is not available in Sentinel / Log Analytics alone.
> // Returns every ActivityType by default; set TargetActivityTypes to ["StartShare", "StopShare"] to see screen sharing only.
> // Camera on/off and mute/unmute have not been observed as ActivityTypes in this tenant's data.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all users, all calls, all activity types).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"]
> let TargetCallIds = dynamic([]);        // Example: ["11111111-2222-3333-4444-555555555555"] (CallId from a previous result)
> let TargetActivityTypes = dynamic([]);  // Example: ["StartShare", "StopShare"] (empty = every ActivityType, so any camera/mute type would show here)
> //
> // ----- Part 1: Filter Call Activity -----
> //
> CallActivityEvents
> | where ActivityTimestamp between (StartTime .. EndTime)
> | where (array_length(TargetUsers) == 0 or ActivityInitiatorUpn in~ (TargetUsers))
> | where (array_length(TargetCallIds) == 0 or CallId in~ (TargetCallIds))
> | where (array_length(TargetActivityTypes) == 0 or ActivityType in~ (TargetActivityTypes))
> | project ActivityTimestamp, ActivityType, ActivityInitiatorUpn, ActivityInitiatorDisplayName, ActivityInitiatorId,
>     OriginatorUpn, OriginatorUserDisplayName, CallSchedulingType, CallId, ThreadId, CallJoinUrl, ActivityId
> | top 1000 by ActivityTimestamp desc
> ```
> </details>

</details>

<details>
<summary><strong>SharePoint Activity</strong></summary>

> <details>
> <summary>✅ <strong>Site/Page accessed/created/modified</strong></summary>
>
> Query file: [SharePoint/Site-Page-accessed-created-modified.kql](../SharePoint/Site-Page-accessed-created-modified.kql).
>
> ```kql
> // SharePoint Activity > Site/Page accessed/created/modified
> // Objective: Shows who accessed, created or modified a SharePoint site or page (personal OneDrive sites are excluded),
> // with the user, operation, site, page name and client IP for each event.
> // Written for the unified Defender portal (Sentinel + XDR); OfficeActivity is a Sentinel table.
> // Page activity from FILE operations is limited to .aspx paths; explicit page/site operations are labeled separately.
> // This is an explicit operation allowlist, not a claim of exhaustive site/page auditing.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all users, all sites, all pages).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"] (matches UserId, or the raw Actor)
> let TargetSites = dynamic([]);          // Example: ["contoso.sharepoint.com/sites/HR"] (case-insensitive whole-word match on the site or object URL)
> let TargetFileNames = dynamic([]);      // Example: ["Home.aspx"] (exact page or file name, source or destination; site-only events have none)
> //
> // ----- Part 1: Filter SharePoint site and page activity -----
> //
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
> | where (array_length(TargetUsers) == 0 or UserId in~ (TargetUsers) or tostring(Actor) has_any (TargetUsers))
> | where (array_length(TargetSites) == 0 or Site_Url has_any (TargetSites) or OfficeObjectId has_any (TargetSites))
> | where (array_length(TargetFileNames) == 0 or SourceFileName in~ (TargetFileNames) or DestinationFileName in~ (TargetFileNames))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserId, Operation, ActivityKind, Site_Url,
>     SourceFileName, DestinationFileName, OfficeObjectId,
>     SourceRelativeUrl, DestinationRelativeUrl, ClientIP, ActorIpAddress, ResultStatus,
>     IsAspxPath, ListItemUniqueId, SourceRecordId, OfficeId, Actor,
>     ExtraProperties, OperationProperties, Event_Data
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Files uploaded/downloaded from a SharePoint site</strong></summary>
>
> Query file: [SharePoint/Files-uploaded-downloaded-from-a-SharePoint-site.kql](../SharePoint/Files-uploaded-downloaded-from-a-SharePoint-site.kql).
>
> ```kql
> // SharePoint Activity > Files uploaded/downloaded from a SharePoint site
> // Objective: Shows who uploaded or downloaded files on SharePoint sites (personal OneDrive sites are excluded),
> // with the user, operation, site, file name and client IP for each event.
> // Written for the unified Defender portal (Sentinel + XDR); OfficeActivity is a Sentinel table.
> // Only FileUploaded and FileDownloaded: sync operations are deliberately NOT included.
> // An operation is audit evidence, not proof of completion, file bytes, or file content.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all users, all sites, all files, both operations).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"] (matches UserId, or the raw Actor)
> let TargetOperations = dynamic([]);     // Example: ["FileDownloaded"] (FileUploaded or FileDownloaded; empty = both)
> let TargetSites = dynamic([]);          // Example: ["contoso.sharepoint.com/sites/HR"] (case-insensitive whole-word match on the site or object URL)
> let TargetFileNames = dynamic([]);      // Example: ["Q3-payroll.xlsx"] (exact file name, source or destination)
> //
> // ----- Part 1: Filter SharePoint file uploads and downloads -----
> //
> OfficeActivity
> | where TimeGenerated between (StartTime .. EndTime)
> | where OfficeWorkload =~ "SharePoint"
> | extend IsPersonalLocation = Site_Url contains "-my.sharepoint.com" or OfficeObjectId contains "-my.sharepoint.com"
>     or Site_Url contains "/personal/" or OfficeObjectId contains "/personal/"
> | where not(IsPersonalLocation)
> | where Operation in~ ("FileUploaded", "FileDownloaded")
> | where (array_length(TargetOperations) == 0 or Operation in~ (TargetOperations))
> | where (array_length(TargetUsers) == 0 or UserId in~ (TargetUsers) or tostring(Actor) has_any (TargetUsers))
> | where (array_length(TargetSites) == 0 or Site_Url has_any (TargetSites) or OfficeObjectId has_any (TargetSites))
> | where (array_length(TargetFileNames) == 0 or SourceFileName in~ (TargetFileNames) or DestinationFileName in~ (TargetFileNames))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserId, Operation, Site_Url,
>     SourceFileName, DestinationFileName, OfficeObjectId,
>     SourceRelativeUrl, DestinationRelativeUrl, ClientIP, ActorIpAddress, ResultStatus,
>     ListItemUniqueId, SourceRecordId, OfficeId, Actor,
>     ExtraProperties, OperationProperties, Event_Data
> | top 1000 by TimeGenerated desc
> ```
> </details>

</details>

<details>
<summary><strong>OneDrive</strong></summary>

> <details>
> <summary>✅ <strong>User File activity</strong></summary>
>
> Query file: [OneDrive/User-File-activity.kql](../OneDrive/User-File-activity.kql).
>
> ```kql
> // OneDrive > User File activity
> // Objective: Shows what each user did to files in OneDrive (opened, uploaded, downloaded, modified, copied, moved,
> // renamed, deleted, restored), with the user, operation, file and client IP for each event.
> // Explicit non-sync file operations; this allowlist is not exhaustive and does not reveal file contents.
> // Written for the unified Defender portal (Sentinel + XDR); OfficeActivity is a Sentinel table.
> // SharePoint-labeled personal OneDrive records qualify by OfficeObjectId/Site_Url fallback.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all users, all operations, all files).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"] (matches UserId, or the raw Actor)
> let TargetOperations = dynamic([]);     // Example: ["FileDownloaded", "FileDeleted"] (any operation from the allowlist below; empty = all)
> let TargetSites = dynamic([]);          // Example: ["contoso-my.sharepoint.com/personal/user_contoso_com"] (case-insensitive whole-word match on the site or object URL)
> let TargetFileNames = dynamic([]);      // Example: ["Budget.xlsx"] (exact file name, source or destination)
> //
> // ----- Part 1: Filter OneDrive file activity -----
> //
> OfficeActivity
> | where TimeGenerated between (StartTime .. EndTime)
> | extend IsPersonalLocation = Site_Url contains "-my.sharepoint.com" or OfficeObjectId contains "-my.sharepoint.com"
>     or Site_Url contains "/personal/" or OfficeObjectId contains "/personal/"
> | where OfficeWorkload =~ "OneDrive" or (OfficeWorkload =~ "SharePoint" and IsPersonalLocation)
> | where Operation in~ ("FileAccessed", "FileAccessedExtended", "FilePreviewed", "FileUploaded", "FileDownloaded",
>     "FileModified", "FileModifiedExtended", "FileCopied", "FileMoved", "FileRenamed", "FileDeleted",
>     "FileRecycled", "FileRestored", "FileCheckedIn", "FileCheckedOut", "FileCheckOutDiscarded", "FileVersionDeleted")
> | where (array_length(TargetOperations) == 0 or Operation in~ (TargetOperations))
> | where (array_length(TargetUsers) == 0 or UserId in~ (TargetUsers) or tostring(Actor) has_any (TargetUsers))
> | where (array_length(TargetSites) == 0 or Site_Url has_any (TargetSites) or OfficeObjectId has_any (TargetSites))
> | where (array_length(TargetFileNames) == 0 or SourceFileName in~ (TargetFileNames) or DestinationFileName in~ (TargetFileNames))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserId, Operation, OfficeWorkload, Site_Url,
>     SourceFileName, DestinationFileName, OfficeObjectId,
>     SourceRelativeUrl, DestinationRelativeUrl, ClientIP, ActorIpAddress, ResultStatus,
>     IsPersonalLocation, ListItemUniqueId, SourceRecordId, OfficeId, Actor,
>     ExtraProperties, OperationProperties, Event_Data
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Sync activity</strong></summary>
>
> Query file: [OneDrive/Sync-activity.kql](../OneDrive/Sync-activity.kql).
>
> ```kql
> // OneDrive > Sync activity
> // Objective: Shows files the OneDrive sync client uploaded or downloaded, with the user, operation, file and client IP
> // for each event. Only explicit full/partial sync operations; generic FileUploaded is NOT sync evidence.
> // Written for the unified Defender portal (Sentinel + XDR); OfficeActivity is a Sentinel table.
> // Tested live with the signed-in OneDrive.exe client (FileSyncUploadedFull); download and partial operations were not observed in the tenant.
> // Partial operations are deprecated legacy Groove.exe evidence, retained for historical investigations.
> // Operation labels do not prove full client convergence or disclose file contents.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all users, all sync operations, all files).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"] (matches UserId, or the raw Actor)
> let TargetOperations = dynamic([]);     // Example: ["FileSyncUploadedFull"] (FileSyncUploadedFull, FileSyncDownloadedFull, FileSyncUploadedPartial, FileSyncDownloadedPartial; empty = all)
> let TargetSites = dynamic([]);          // Example: ["contoso-my.sharepoint.com/personal/user_contoso_com"] (case-insensitive whole-word match on the site or object URL)
> let TargetFileNames = dynamic([]);      // Example: ["Budget.xlsx"] (exact file name, source or destination)
> //
> // ----- Part 1: Filter OneDrive sync activity -----
> //
> OfficeActivity
> | where TimeGenerated between (StartTime .. EndTime)
> | extend IsPersonalLocation = Site_Url contains "-my.sharepoint.com" or OfficeObjectId contains "-my.sharepoint.com"
>     or Site_Url contains "/personal/" or OfficeObjectId contains "/personal/"
> | where OfficeWorkload =~ "OneDrive" or (OfficeWorkload =~ "SharePoint" and IsPersonalLocation)
> | where Operation in~ ("FileSyncUploadedFull", "FileSyncDownloadedFull", "FileSyncUploadedPartial", "FileSyncDownloadedPartial")
> | where (array_length(TargetOperations) == 0 or Operation in~ (TargetOperations))
> | where (array_length(TargetUsers) == 0 or UserId in~ (TargetUsers) or tostring(Actor) has_any (TargetUsers))
> | where (array_length(TargetSites) == 0 or Site_Url has_any (TargetSites) or OfficeObjectId has_any (TargetSites))
> | where (array_length(TargetFileNames) == 0 or SourceFileName in~ (TargetFileNames) or DestinationFileName in~ (TargetFileNames))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserId, Operation, OfficeWorkload, Site_Url,
>     SourceFileName, DestinationFileName, OfficeObjectId,
>     SourceRelativeUrl, DestinationRelativeUrl, ClientIP, ActorIpAddress, ResultStatus,
>     IsPersonalLocation, ListItemUniqueId, SourceRecordId, OfficeId, Actor,
>     ExtraProperties, OperationProperties, Event_Data
> | top 1000 by TimeGenerated desc
> ```
> </details>

</details>
