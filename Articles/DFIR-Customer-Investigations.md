# DFIR Customer Investigations

Expand a customer request to copy its full KQL. Set the parameters before running; default window: last 30 days. Each query is also saved as a `.kql` file under its product folder.

These queries are written for the unified Defender portal (Microsoft Sentinel and Defender XDR together) and we recommend running them there. Email queries use `TimeGenerated`, SharePoint and OneDrive queries read the Sentinel `OfficeActivity` table (Microsoft 365 connector with SharePoint enabled), Teams call and meeting queries read the Defender XDR `CallActivityEvents` table, and User Logon Events queries read `SigninLogs` and `AADNonInteractiveUserSignInLogs` (Entra), `DeviceLogonEvents` (Defender for Endpoint) and `IdentityLogonEvents` (Defender for Identity). If you are not unified, the table or timestamp column may differ, for example replace `TimeGenerated` with `Timestamp` in Defender XDR only, so adjust the query or, better, unify Sentinel and Defender XDR. A green check mark means the query was tested against live tenant data. See [Collaboration connectors and validation](Collaboration-Connectors.md).

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

<details>
<summary><strong>Device Logon Events</strong></summary>

> <details>
> <summary>✅ <strong>Endpoint (device) logons</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-logon-events.kql](../Microsoft%20Defender%20for%20Endpoint/Device-logon-events.kql).
>
> ```kql
> // Device Logon Events
> // Objective: Shows who logged on (or tried to log on) to which device, with the account, logon type, remote device and IP,
> // protocol and failure reason, plus the process that initiated the logon. Raw events; failures and successes are both returned.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceLogonEvents (Microsoft Defender for Endpoint). LogonSuccessAggregatedReport rows are MDE's own roll-ups of repeated logons.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all logon types, successes and failures).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let TargetLogonTypes = dynamic([]);     // Example: ["RemoteInteractive", "Interactive"] (Interactive, RemoteInteractive, Network, Batch, Service, Local, Unknown)
> let TargetActionTypes = dynamic([]);    // Example: ["LogonFailed"] (LogonSuccess, LogonFailed, LogonAttempted, LogonSuccessAggregatedReport)
> //
> // ----- Part 1: Filter device logon activity -----
> //
> DeviceLogonEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where (array_length(TargetUsers) == 0 or AccountName in~ (TargetUsers)
>     or strcat(AccountDomain, "\\", AccountName) in~ (TargetUsers) or AccountSid in~ (TargetUsers))
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetLogonTypes) == 0 or LogonType in~ (TargetLogonTypes))
> | where (array_length(TargetActionTypes) == 0 or ActionType in~ (TargetActionTypes))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, AccountDomain, AccountName, ActionType, LogonType, DeviceName,
>     RemoteDeviceName, RemoteIP, RemotePort, Protocol, FailureReason, IsLocalAdmin,
>     AccountSid, LogonId, InitiatingProcessFileName, InitiatingProcessCommandLine,
>     InitiatingProcessAccountName, InitiatingProcessAccountDomain, DeviceId, ReportId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Device logon summary</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-logon-summary.kql](../Microsoft%20Defender%20for%20Endpoint/Device-logon-summary.kql).
>
> ```kql
> // Device Logon Summary
> // Objective: Summarizes device logons per account, device, and logon type: successful, failed, and local-admin logons, the remote IPs they came from, and first and last seen.
> // Use it to see who normally logs on to which device and to spot unusual accounts, logon types, or sources.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceLogonEvents (Microsoft Defender for Endpoint). Other logon events are MDE roll-ups (LogonSuccessAggregatedReport) and attempts (LogonAttempted).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all logon types).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let TargetLogonTypes = dynamic([]);     // Example: ["RemoteInteractive", "Interactive"] (Interactive, RemoteInteractive, Network, Batch, Service, Local, Unknown)
> //
> // ----- Part 1: Filter device logon activity -----
> //
> DeviceLogonEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where (array_length(TargetUsers) == 0 or AccountName in~ (TargetUsers)
>     or strcat(AccountDomain, "\\", AccountName) in~ (TargetUsers) or AccountSid in~ (TargetUsers))
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetLogonTypes) == 0 or LogonType in~ (TargetLogonTypes))
> //
> // ----- Part 2: Summarize per account, device, and logon type -----
> //
> | summarize SuccessfulLogons = countif(ActionType == "LogonSuccess"), FailedLogons = countif(ActionType == "LogonFailed"),
>     OtherLogonEvents = countif(ActionType !in ("LogonSuccess", "LogonFailed")), LocalAdminLogons = countif(IsLocalAdmin == true),
>     RemoteIPCount = dcountif(RemoteIP, isnotempty(RemoteIP)), RemoteIPs = make_set_if(RemoteIP, isnotempty(RemoteIP), 10),
>     FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
>     by AccountDomain, AccountName, DeviceName, LogonType
> | top 1000 by LastSeen desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Device failed logons and brute force</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-failed-logons.kql](../Microsoft%20Defender%20for%20Endpoint/Device-failed-logons.kql).
>
> ```kql
> // Device Failed Logons and Brute Force
> // Objective: Shows failed device logons grouped by source IP and device, with the number of failures, the accounts tried, the logon types and failure reasons,
> // and whether a successful logon from the same source followed a failure. Surfaces brute force, password spray, and failed remote (RDP) logons.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceLogonEvents (Microsoft Defender for Endpoint).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all logon types, any number of failures).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let TargetLogonTypes = dynamic([]);     // Example: ["RemoteInteractive", "Network"] (Interactive, RemoteInteractive, Network, Batch, Service, Local, Unknown)
> let MinFailedLogons = 1;                // Example: 10 (only return sources with at least this many failed logons)
> //
> // ----- Part 1: Filter failed and successful logons -----
> //
> DeviceLogonEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where ActionType in ("LogonFailed", "LogonSuccess")
> | where (array_length(TargetUsers) == 0 or AccountName in~ (TargetUsers)
>     or strcat(AccountDomain, "\\", AccountName) in~ (TargetUsers) or AccountSid in~ (TargetUsers))
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetLogonTypes) == 0 or LogonType in~ (TargetLogonTypes))
> //
> // ----- Part 2: Summarize per source IP and device -----
> //
> | extend Account = strcat(AccountDomain, "\\", AccountName)
> | summarize FailedLogons = countif(ActionType == "LogonFailed"), SuccessfulLogons = countif(ActionType == "LogonSuccess"),
>     FailedAccountCount = dcountif(Account, ActionType == "LogonFailed"), FailedAccounts = make_set_if(Account, ActionType == "LogonFailed", 10),
>     LogonTypes = make_set_if(LogonType, ActionType == "LogonFailed"), FailureReasons = make_set_if(FailureReason, ActionType == "LogonFailed" and isnotempty(FailureReason)),
>     FirstFailure = minif(TimeGenerated, ActionType == "LogonFailed"), LastFailure = maxif(TimeGenerated, ActionType == "LogonFailed"),
>     LastSuccess = maxif(TimeGenerated, ActionType == "LogonSuccess")
>     by RemoteIP, DeviceName
> | where FailedLogons >= MinFailedLogons and FailedLogons > 0
> | extend SuccessAfterFailure = iff(isnull(LastSuccess), false, LastSuccess > FirstFailure)
> | sort by FailedLogons desc, LastFailure desc
> | take 1000
> ```
> </details>

> <details>
> <summary>✅ <strong>Remote logons from public IP addresses</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-remote-logons-from-public-IPs.kql](../Microsoft%20Defender%20for%20Endpoint/Device-remote-logons-from-public-IPs.kql).
>
> ```kql
> // Device Logons from Public IP Addresses
> // Objective: Shows device logons (successes and failures) where the remote address is a public IP, with the account, device, logon type, and protocol.
> // Use it to find internet-exposed RDP or SMB, and logons from addresses outside your network.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceLogonEvents (Microsoft Defender for Endpoint).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all public IPs, successes and failures).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let TargetRemoteIPs = dynamic([]);      // Example: ["203.0.113.10"] (exact remote IP address)
> //
> // ----- Part 1: Filter logons from public IP addresses -----
> //
> DeviceLogonEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where RemoteIPType == "Public"
> | where (array_length(TargetUsers) == 0 or AccountName in~ (TargetUsers)
>     or strcat(AccountDomain, "\\", AccountName) in~ (TargetUsers) or AccountSid in~ (TargetUsers))
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetRemoteIPs) == 0 or RemoteIP in (TargetRemoteIPs))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, AccountDomain, AccountName, DeviceName, ActionType, LogonType,
>     RemoteIP, RemoteIPType, RemoteDeviceName, RemotePort, Protocol, FailureReason, IsLocalAdmin,
>     AccountSid, LogonId, InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Local account and local admin logons</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-local-account-and-admin-logons.kql](../Microsoft%20Defender%20for%20Endpoint/Device-local-account-and-admin-logons.kql).
>
> ```kql
> // Device Local Account and Local Admin Logons
> // Objective: Shows device logons by local (non-domain) accounts, by accounts that are local administrators on the device, and by the built-in Administrator (RID 500) account outside a local logon.
> // Use it to find local accounts bypassing domain policy, local admin use, and lateral movement with local credentials. Each row says why it matched.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceLogonEvents (Microsoft Defender for Endpoint).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all logon types, successes and failures).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let TargetLogonTypes = dynamic([]);     // Example: ["Network", "RemoteInteractive"] (Interactive, RemoteInteractive, Network, Batch, Service, Local, Unknown)
> //
> // ----- Part 1: Filter device logon activity -----
> //
> DeviceLogonEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where (array_length(TargetUsers) == 0 or AccountName in~ (TargetUsers)
>     or strcat(AccountDomain, "\\", AccountName) in~ (TargetUsers) or AccountSid in~ (TargetUsers))
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetLogonTypes) == 0 or LogonType in~ (TargetLogonTypes))
> //
> // ----- Part 2: Flag local accounts, local admins, and built-in Administrator logons -----
> //
> | extend LocalAccount = tolower(AccountDomain) == tolower(DeviceName), LocalAdmin = IsLocalAdmin == true,
>     BuiltInAdministratorNotLocal = AccountSid endswith "-500" and coalesce(tobool(todynamic(AdditionalFields).IsLocalLogon), false) == false
> | where LocalAccount or LocalAdmin or BuiltInAdministratorNotLocal
> | extend Reason = array_strcat(array_concat(
>     iff(LocalAccount, dynamic(["Local account"]), dynamic([])),
>     iff(LocalAdmin, dynamic(["Local administrator"]), dynamic([])),
>     iff(BuiltInAdministratorNotLocal, dynamic(["Built-in Administrator (RID 500) not a local logon"]), dynamic([]))), "; ")
> //
> // ----- Part 3: Output -----
> //
> | project TimeGenerated, AccountDomain, AccountName, DeviceName, Reason, ActionType, LogonType, IsLocalAdmin,
>     RemoteDeviceName, RemoteIP, RemoteIPType, RemotePort, Protocol, FailureReason,
>     AccountSid, LogonId, InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Last interactive logon per device</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-last-logon-per-device.kql](../Microsoft%20Defender%20for%20Endpoint/Device-last-logon-per-device.kql).
>
> ```kql
> // Device Last Interactive Logon
> // Objective: Shows the most recent successful interactive or remote desktop logon on each device, with the account, whether it is a local admin, and where an RDP logon came from.
> // Use it to answer "who was last logged on to this device" during an investigation.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceLogonEvents (Microsoft Defender for Endpoint).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> //
> // ----- Part 1: Filter successful interactive logons -----
> //
> DeviceLogonEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where ActionType == "LogonSuccess" and LogonType in ("Interactive", "RemoteInteractive")
> | where (array_length(TargetUsers) == 0 or AccountName in~ (TargetUsers)
>     or strcat(AccountDomain, "\\", AccountName) in~ (TargetUsers) or AccountSid in~ (TargetUsers))
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> //
> // ----- Part 2: Keep the latest logon per device -----
> //
> | summarize arg_max(TimeGenerated, *) by DeviceId
> | project TimeGenerated, DeviceName, AccountDomain, AccountName, LogonType, IsLocalAdmin,
>     RemoteDeviceName, RemoteIP, RemotePort, Protocol, AccountSid, LogonId,
>     InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Windows account logons and logoffs</strong></summary>
>
> Query file: [Windows/SecurityEvent/Windows-logon-and-logoff-events.kql](../Windows/SecurityEvent/Windows-logon-and-logoff-events.kql).
>
> ```kql
> // Windows Account Logons and Logoffs
> // Objective: Shows who logged on, failed to log on, or logged off a Windows computer, with the account, logon type, source IP and workstation,
> // authentication package, failure reason, and (for explicit-credential logons) the account whose credentials were used. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: SecurityEvent (Windows Security log, collected by the Windows Security Events connector / Azure Monitor Agent).
> // Event IDs: 4624 logon, 4625 failed logon, 4634 logoff, 4647 user-initiated logoff, 4648 logon using explicit credentials.
> // Audit policy: Logon/Logoff > Audit Logon (Success, Failure), Audit Logoff (Success), Audit Other Logon/Logoff Events (Success).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all computers, all five event IDs, all logon types).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetComputers = dynamic([]);      // Example: ["dc01", "pc01"] (case-insensitive whole-word match on the computer name)
> let TargetEventIDs = dynamic([]);       // Example: [4625] (4624, 4625, 4634, 4647, 4648; empty = all five)
> let TargetLogonTypes = dynamic([]);     // Example: [2, 10] (2 Interactive, 3 Network, 4 Batch, 5 Service, 7 Unlock, 8 NetworkCleartext, 9 NewCredentials, 10 RemoteInteractive, 11 CachedInteractive). Events without a logon type (4647, 4648) are hidden when this is set.
> let ExcludeMachineAccounts = false;     // Set to true to hide computer accounts (names ending in $)
> //
> // ----- Part 1: Filter Windows logon and logoff events -----
> //
> SecurityEvent
> | where TimeGenerated between (StartTime .. EndTime)
> | where EventID in (4624, 4625, 4634, 4647, 4648)
> | where (array_length(TargetEventIDs) == 0 or EventID in (TargetEventIDs))
> | where (array_length(TargetComputers) == 0 or Computer has_any (TargetComputers))
> | where (array_length(TargetLogonTypes) == 0 or LogonType in (TargetLogonTypes))
> // For 4648 the account that ran the process is the Subject; for every other event the account is the Target.
> | extend UserName = iff(EventID == 4648, SubjectUserName, TargetUserName),
>     UserDomain = iff(EventID == 4648, SubjectDomainName, TargetDomainName),
>     UserSid = iff(EventID == 4648, SubjectUserSid, TargetUserSid)
> | where (array_length(TargetUsers) == 0 or UserName in~ (TargetUsers)
>     or strcat(UserDomain, "\\", UserName) in~ (TargetUsers) or UserSid in~ (TargetUsers))
> | where ExcludeMachineAccounts == false or UserName !endswith "$"
> //
> // ----- Part 2: Output -----
> //
> | extend Event = case(
>         EventID == 4624, "Logon",
>         EventID == 4625, "Failed logon",
>         EventID == 4634, "Logoff",
>         EventID == 4647, "User-initiated logoff",
>         "Logon with explicit credentials"),
>     FailureReasonText = iff(EventID != 4625, "", case(
>         tolower(SubStatus) == "0xc0000064", "User name does not exist",
>         tolower(SubStatus) == "0xc000006a", "Wrong password",
>         tolower(SubStatus) == "0xc000006d", "Bad user name or authentication information",
>         tolower(SubStatus) == "0xc000006e", "Account restriction",
>         tolower(SubStatus) == "0xc000006f", "Logon outside allowed hours",
>         tolower(SubStatus) == "0xc0000070", "Workstation restriction",
>         tolower(SubStatus) == "0xc0000071", "Password expired",
>         tolower(SubStatus) == "0xc0000072", "Account disabled",
>         tolower(SubStatus) == "0xc000015b", "Logon type not granted",
>         tolower(SubStatus) == "0xc0000193", "Account expired",
>         tolower(SubStatus) == "0xc0000224", "Password must change at next logon",
>         tolower(SubStatus) == "0xc0000234", "Account locked out",
>         strcat("Status ", Status, " / SubStatus ", SubStatus))),
>     CredentialsUsedFor = iff(EventID == 4648, strcat(TargetDomainName, "\\", TargetUserName), "")
> | project TimeGenerated, UserName, UserDomain, EventID, Event, LogonTypeName, Computer, IpAddress, WorkstationName,
>     AuthenticationPackageName, LogonProcessName, FailureReasonText, Status, SubStatus, CredentialsUsedFor,
>     TargetServerName, ProcessName, TargetLogonId, SubjectLogonId, UserSid
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Windows privileged logons</strong></summary>
>
> Query file: [Windows/SecurityEvent/Windows-privileged-logons.kql](../Windows/SecurityEvent/Windows-privileged-logons.kql).
>
> ```kql
> // Windows Privileged Logons
> // Objective: Shows logons where special privileges were assigned to the new session (administrator-level logons), with the account, the privileges
> // granted, the computer, and how the session logged on (logon type, source IP, workstation, authentication package). Raw events, one row per privileged logon.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: SecurityEvent (Windows Security log). 4672 special privileges assigned to new logon, matched to the 4624 logon by computer and logon ID.
> // Audit policy: Logon/Logoff > Audit Special Logon (Success) and Audit Logon (Success).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all computers, all privileges).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetComputers = dynamic([]);      // Example: ["dc01", "pc01"] (case-insensitive whole-word match on the computer name)
> let TargetPrivileges = dynamic([]);     // Example: ["SeDebugPrivilege", "SeTcbPrivilege"] (rows that were granted any of these privileges)
> let ExcludeSystemAndMachineAccounts = false;  // Set to true to hide computer accounts and built-in service sessions (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM, UMFD)
> //
> // ----- Part 1: Find privileged logons (4672) -----
> //
> let PrivilegedLogons = SecurityEvent
>     | where TimeGenerated between (StartTime .. EndTime)
>     | where EventID == 4672
>     | where (array_length(TargetComputers) == 0 or Computer has_any (TargetComputers))
>     | where (array_length(TargetUsers) == 0 or SubjectUserName in~ (TargetUsers)
>         or strcat(SubjectDomainName, "\\", SubjectUserName) in~ (TargetUsers) or SubjectUserSid in~ (TargetUsers))
>     | where (array_length(TargetPrivileges) == 0 or PrivilegeList has_any (TargetPrivileges))
>     | where ExcludeSystemAndMachineAccounts == false
>         or not(SubjectUserName endswith "$" or SubjectDomainName in~ ("NT AUTHORITY", "Window Manager", "Font Driver Host"))
>     | project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, SubjectUserSid, SubjectLogonId, PrivilegeList
>     | top 1000 by TimeGenerated desc
>     | serialize
>     | extend RowId = row_number();
> //
> // ----- Part 2: Add how each session logged on (the latest 4624 with the same computer and logon ID, at or just before the 4672) -----
> // The 4672 is often written a fraction of a second before its 4624, so a 1 second tolerance is allowed. Reused logon IDs (for example 0x3e7 SYSTEM) match the most recent logon only.
> //
> let LogonDetails = PrivilegedLogons
>     | project RowId, Computer, SubjectLogonId, PrivilegeTime = TimeGenerated
>     | join kind=inner (
>         SecurityEvent
>         | where TimeGenerated between ((StartTime - 1h) .. (EndTime + 1m))
>         | where EventID == 4624
>         | project Computer, TargetLogonId, LogonTime = TimeGenerated, LogonTypeName, IpAddress, WorkstationName, AuthenticationPackageName, LogonProcessName
>     ) on Computer, $left.SubjectLogonId == $right.TargetLogonId
>     | where LogonTime <= PrivilegeTime + 1s
>     | summarize arg_max(LogonTime, LogonTypeName, IpAddress, WorkstationName, AuthenticationPackageName, LogonProcessName) by RowId;
> //
> // ----- Part 3: Output -----
> //
> PrivilegedLogons
> | join kind=leftouter LogonDetails on RowId
> | project TimeGenerated, UserName = SubjectUserName, UserDomain = SubjectDomainName, Computer, LogonTypeName, IpAddress, WorkstationName,
>     AuthenticationPackageName, LogonProcessName, Privileges = replace_regex(PrivilegeList, @"\s+", ", "),
>     SubjectLogonId, UserSid = SubjectUserSid
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Windows user-initiated logoffs</strong></summary>
>
> Query file: [Windows/SecurityEvent/Windows-user-initiated-logoff.kql](../Windows/SecurityEvent/Windows-user-initiated-logoff.kql).
>
> ```kql
> // Windows User-Initiated Logoffs (Event 4647)
> // Objective: Shows users who actively signed out (clicked Sign out / ran logoff) of a Windows computer. A disconnected RDP session does not generate this event. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: SecurityEvent (Windows Security log, collected by the Windows Security Events connector / Azure Monitor Agent).
> // Audit policy: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Logon/Logoff > Audit Logoff (Success).
> // Derived from the M-21-31 EL0 tracked query (EventID 4647).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results.
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetComputers = dynamic([]);      // Example: ["dc01", "pc01"] (case-insensitive whole-word match on the computer name)
> let ExcludeMachineAccounts = true;      // Set to false to include computer accounts (names ending in $)
> //
> // ----- Part 1: Filter user-initiated logoff events -----
> //
> SecurityEvent
> | where TimeGenerated between (StartTime .. EndTime)
> | where EventID == 4647
> | where (array_length(TargetComputers) == 0 or Computer has_any (TargetComputers))
> | where (array_length(TargetUsers) == 0 or TargetUserName in~ (TargetUsers)
>     or strcat(TargetDomainName, "\\", TargetUserName) in~ (TargetUsers) or TargetUserSid in~ (TargetUsers))
> | where ExcludeMachineAccounts == false or TargetUserName !endswith "$"
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserName = TargetUserName, UserDomain = TargetDomainName, EventID, Computer,
>     LogonId = TargetLogonId, UserSid = TargetUserSid, Activity
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary><strong>Windows explicit credential logons (Run as)</strong></summary>
>
> Query file: [Windows/SecurityEvent/Windows-explicit-credential-logons.kql](../Windows/SecurityEvent/Windows-explicit-credential-logons.kql).
>
> ```kql
> // Windows Explicit Credential Logons / Run As (Event 4648)
> // Objective: Shows logons attempted with explicit credentials (Run as, mapped drives with alternate credentials, scheduled tasks, lateral movement tooling), including which account ran the process, whose credentials were used, the target server, and the process. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: SecurityEvent (Windows Security log, collected by the Windows Security Events connector / Azure Monitor Agent).
> // Audit policy: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Logon/Logoff > Audit Logon (Success).
> // Derived from the M-21-31 EL0 tracked query (EventID 4648).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results.
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["xadmin", "CONTOSO\\xadmin"] (matches either the account that ran the process or the account whose credentials were used)
> let TargetComputers = dynamic([]);      // Example: ["dc01", "pc01"] (case-insensitive whole-word match on the computer name)
> let ExcludeMachineAccounts = true;      // Set to false to include computer accounts (names ending in $)
> //
> // ----- Part 1: Filter explicit credential logon events -----
> // SubjectUserName = account that ran the process. TargetUserName = account whose credentials were supplied.
> //
> SecurityEvent
> | where TimeGenerated between (StartTime .. EndTime)
> | where EventID == 4648
> | where (array_length(TargetComputers) == 0 or Computer has_any (TargetComputers))
> | where (array_length(TargetUsers) == 0 or SubjectUserName in~ (TargetUsers) or TargetUserName in~ (TargetUsers)
>     or strcat(SubjectDomainName, "\\", SubjectUserName) in~ (TargetUsers)
>     or strcat(TargetDomainName, "\\", TargetUserName) in~ (TargetUsers))
> | where ExcludeMachineAccounts == false or (SubjectUserName !endswith "$" and TargetUserName !endswith "$")
> //
> // ----- Part 2: Output -----
> // IsCrossUserActivity = true when the credentials used belong to a different account than the one that ran the process.
> //
> | extend IsCrossUserActivity = tolower(SubjectUserName) != tolower(TargetUserName)
> | project TimeGenerated, UserName = SubjectUserName, UserDomain = SubjectDomainName, EventID, Computer,
>     CredentialsUsedFor = strcat(TargetDomainName, "\\", TargetUserName), IsCrossUserActivity,
>     TargetServerName, ProcessName, IpAddress, SubjectLogonId, SubjectUserSid, Activity
> | top 1000 by TimeGenerated desc
> ```
> </details>

</details>

<details>
<summary><strong>User Logon Events</strong></summary>

> <details>
> <summary>✅ <strong>Entra sign-ins</strong></summary>
>
> Query file: [Entra/User-logon-events.kql](../Entra/User-logon-events.kql).
>
> ```kql
> // User Logon Events > Microsoft Entra sign-ins
> // Objective: Shows every Microsoft Entra ID sign-in by a user (interactive and, optionally, non-interactive), with the user,
> // outcome, application, resource, IP address, location, client and conditional access result. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). Sources: SigninLogs and AADNonInteractiveUserSignInLogs (Sentinel tables).
> // Non-interactive sign-ins are token refreshes and background sign-ins and are far more numerous than interactive ones.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all users, all IP addresses, successes and failures).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let IncludeNonInteractive = true;       // Example: false (interactive sign-ins only)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "user2@contoso.com"] (matches the user principal name)
> let TargetIPAddresses = dynamic([]);    // Example: ["203.0.113.10"] (exact client IP address)
> let TargetOutcomes = dynamic([]);       // Example: ["Failure"] (Success or Failure; empty = both)
> //
> // ----- Part 1: Filter Entra sign-ins -----
> //
> union
>     (SigninLogs
>         | extend SignInType = "Interactive", DeviceDetailText = tostring(DeviceDetail)),
>     (AADNonInteractiveUserSignInLogs
>         | where IncludeNonInteractive
>         | extend SignInType = "Non-interactive", DeviceDetailText = tostring(DeviceDetail))
> | where TimeGenerated between (StartTime .. EndTime)
> | extend Outcome = iff(ResultType == "0", "Success", "Failure")
> | where (array_length(TargetUsers) == 0 or UserPrincipalName in~ (TargetUsers))
> | where (array_length(TargetIPAddresses) == 0 or IPAddress in (TargetIPAddresses))
> | where (array_length(TargetOutcomes) == 0 or Outcome in~ (TargetOutcomes))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserPrincipalName, UserDisplayName, UserType, SignInType, Outcome, ResultType, ResultDescription,
>     AppDisplayName, ResourceDisplayName, IPAddress, Location, ClientAppUsed, UserAgent,
>     AuthenticationRequirement, ConditionalAccessStatus, DeviceDetail = DeviceDetailText,
>     UserId, CorrelationId, Id
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Entra risky users and sign-ins</strong></summary>
>
> Query file: [Entra/User-risk-events.kql](../Entra/User-risk-events.kql).
>
> ```kql
> // Entra User Risk Events and Risky Sign-ins
> // Objective: Shows risky Microsoft Entra ID activity for users: Identity Protection risk detections (for example unfamiliar sign-in properties,
> // anonymous IP, leaked credentials) and sign-ins that Entra flagged as risky, with the user, risk type, risk level, state, IP address,
> // location and application, plus the user's current risk state. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). Sources: AADUserRiskEvents, SigninLogs and AADRiskyUsers (Sentinel tables).
> // Risk data requires Microsoft Entra ID P2 (Identity Protection). Without it, sign-in risk levels show as "hidden" and no rows are returned.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all users, all risk types, levels and states).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com"] (matches the user principal name)
> let TargetRiskTypes = dynamic([]);      // Example: ["unfamiliarFeatures", "anonymizedIPAddress", "leakedCredentials"]
> let TargetRiskLevels = dynamic([]);     // Example: ["high", "medium"] (low, medium, high)
> let TargetRiskStates = dynamic([]);     // Example: ["atRisk", "confirmedCompromised"] (atRisk, confirmedCompromised, remediated, dismissed, confirmedSafe)
> //
> // ----- Part 1: Risk detections (AADUserRiskEvents) with the matching sign-in -----
> //
> let SignInDetails = SigninLogs
>     | where TimeGenerated between ((StartTime - 1d) .. (EndTime + 1d))
>     | summarize arg_max(TimeGenerated, AppDisplayName, ResultType, ClientAppUsed) by CorrelationId;
> let Detections = AADUserRiskEvents
>     | where TimeGenerated between (StartTime .. EndTime)
>     | join kind=leftouter SignInDetails on CorrelationId
>     | project TimeGenerated, LogType = "Risk detection", UserPrincipalName, UserId, RiskEventType, RiskLevel, RiskState, RiskDetail,
>         DetectionTimingType, IPAddress = IpAddress,
>         Location = iff(isempty(tostring(Location.countryOrRegion)), "", strcat(tostring(Location.city), ", ", tostring(Location.state), ", ", tostring(Location.countryOrRegion))),
>         AppDisplayName, ResultType, ClientAppUsed,
>         DetectionSource = Source, CorrelationId;
> //
> // ----- Part 2: Sign-ins that Entra flagged as risky (SigninLogs) -----
> //
> let RiskySignIns = SigninLogs
>     | where TimeGenerated between (StartTime .. EndTime)
>     | where RiskLevelDuringSignIn in~ ("low", "medium", "high") or RiskLevelAggregated in~ ("low", "medium", "high")
>     | project TimeGenerated, LogType = "Risky sign-in", UserPrincipalName, UserId,
>         RiskEventType = replace_regex(tostring(RiskEventTypes_V2), @'[\[\]"]', ""), RiskLevel = iff(RiskLevelDuringSignIn in~ ("low", "medium", "high"), RiskLevelDuringSignIn, RiskLevelAggregated),
>         RiskState, RiskDetail, DetectionTimingType = "", IPAddress, Location, AppDisplayName, ResultType, ClientAppUsed,
>         DetectionSource = "SigninLogs", CorrelationId;
> //
> // ----- Part 3: Add the user's current risk state, filter, and output -----
> //
> let CurrentUserRisk = AADRiskyUsers
>     | summarize arg_max(TimeGenerated, UserRiskState = RiskState, UserRiskLevel = RiskLevel) by UserId = Id
>     | project UserId, UserRiskState, UserRiskLevel;
> union Detections, RiskySignIns
> | where (array_length(TargetUsers) == 0 or UserPrincipalName in~ (TargetUsers))
> | where (array_length(TargetRiskTypes) == 0 or RiskEventType has_any (TargetRiskTypes))
> | where (array_length(TargetRiskLevels) == 0 or RiskLevel in~ (TargetRiskLevels))
> | where (array_length(TargetRiskStates) == 0 or RiskState in~ (TargetRiskStates))
> | join kind=leftouter CurrentUserRisk on UserId
> | project TimeGenerated, UserPrincipalName, LogType, RiskEventType, RiskLevel, RiskState, RiskDetail, DetectionTimingType,
>     IPAddress, Location, AppDisplayName, ResultType, ClientAppUsed, UserRiskState, UserRiskLevel, DetectionSource, UserId, CorrelationId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Entra application and managed identity sign-ins</strong></summary>
>
> Query file: [Entra/Workload-identity-sign-ins.kql](../Entra/Workload-identity-sign-ins.kql).
>
> ```kql
> // Entra Application and Managed Identity Sign-ins
> // Objective: Shows every sign-in by a service principal (application) or managed identity in Microsoft Entra ID, with the identity, the app,
> // the resource it signed in to, outcome, source IP and location, and the credential type used (secret, certificate, federated). Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). Sources: AADServicePrincipalSignInLogs and AADManagedIdentitySignInLogs (Sentinel tables).
> // These are non-human sign-ins and are far more numerous than user sign-ins.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all identities, all apps, successes and failures).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetIdentities = dynamic([]);     // Example: ["MyAutomationApp", "vm-prod-01"] (service principal or managed identity display name)
> let TargetAppIds = dynamic([]);         // Example: ["00000000-0000-0000-0000-000000000000"]
> let TargetResults = dynamic([]);        // Example: ["700027", "7000222"] (result codes; "0" is success; empty = all)
> let TargetIdentityTypes = dynamic([]);  // Example: ["Managed identity"] (Service principal, Managed identity; empty = both)
> //
> // ----- Part 1: Combine service principal and managed identity sign-ins -----
> //
> union
>     (AADServicePrincipalSignInLogs
>         | where TimeGenerated between (StartTime .. EndTime)
>         | extend IdentityType = "Service principal"),
>     (AADManagedIdentitySignInLogs
>         | where TimeGenerated between (StartTime .. EndTime)
>         | extend IdentityType = "Managed identity")
> | where (array_length(TargetIdentityTypes) == 0 or IdentityType in~ (TargetIdentityTypes))
> | where (array_length(TargetIdentities) == 0 or ServicePrincipalName in~ (TargetIdentities))
> | where (array_length(TargetAppIds) == 0 or AppId in~ (TargetAppIds))
> | where (array_length(TargetResults) == 0 or ResultType in (TargetResults))
> //
> // ----- Part 2: Output -----
> //
> | extend Outcome = iff(ResultType == "0", "Success", "Failure")
> | project TimeGenerated, ServicePrincipalName, IdentityType, Outcome, ResultType, ResultDescription, AppId, ServicePrincipalId,
>     ResourceDisplayName, IPAddress, Location, ClientCredentialType, FederatedCredentialId, ConditionalAccessStatus,
>     UserAgent, CorrelationId, Id
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Active Directory and identity logons</strong></summary>
>
> Query file: [Microsoft Defender for Identity/Identity-logon-events.kql](../Microsoft%20Defender%20for%20Identity/Identity-logon-events.kql).
>
> ```kql
> // User Logon Events > Active Directory and identity logons
> // Objective: Shows user logons and failed logons seen by Microsoft Defender for Identity, which covers on-premises Active Directory
> // (Kerberos, NTLM, RDP) and logons to cloud applications, with the user, logon type, protocol, source device, destination and IP.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: IdentityLogonEvents. Raw events; failures and successes are both returned.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, successes and failures).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["user@contoso.com", "jdoe"] (matches the UPN or the account name)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "dc01"] (case-insensitive whole-word match on the source or destination device name)
> let TargetActionTypes = dynamic([]);    // Example: ["LogonFailed"] (LogonSuccess or LogonFailed; empty = both)
> //
> // ----- Part 1: Filter identity logons -----
> //
> IdentityLogonEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where (array_length(TargetUsers) == 0 or AccountUpn in~ (TargetUsers) or AccountName in~ (TargetUsers))
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices) or DestinationDeviceName has_any (TargetDevices))
> | where (array_length(TargetActionTypes) == 0 or ActionType in~ (TargetActionTypes))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, AccountUpn, AccountName, AccountDomain, ActionType, LogonType, Protocol, FailureReason,
>     Application, DeviceName, DestinationDeviceName, IPAddress, Port, DestinationIPAddress, DestinationPort,
>     Location, ISP, AccountSid, AccountObjectId, ReportId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Windows Kerberos and NTLM authentication</strong></summary>
>
> Query file: [Windows/SecurityEvent/Windows-kerberos-and-ntlm-authentication-events.kql](../Windows/SecurityEvent/Windows-kerberos-and-ntlm-authentication-events.kql).
>
> ```kql
> // Windows Kerberos and NTLM Authentication
> // Objective: Shows credential validation by domain controllers: Kerberos ticket requests (successful and failed pre-authentication) and NTLM
> // validations, with the account, the source IP or workstation, the service requested, and a readable result. Surfaces password spray and brute force.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: SecurityEvent (Windows Security log on domain controllers).
> // Event IDs: 4768 Kerberos TGT requested, 4771 Kerberos pre-authentication failed, 4776 NTLM credential validation.
> // Audit policy: Account Logon > Audit Kerberos Authentication Service (Success, Failure) and Audit Credential Validation (Success, Failure).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all domain controllers, all three event IDs, successes and failures).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "jdoe@contoso.com", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetComputers = dynamic([]);      // Example: ["dc01"] (the domain controller that handled the request; case-insensitive whole-word match)
> let TargetEventIDs = dynamic([]);       // Example: [4771, 4776] (4768, 4771, 4776; empty = all three)
> let TargetStatusCodes = dynamic([]);    // Example: ["0x18", "0xc000006a"] (Kerberos or NTLM status codes; empty = all, success included)
> let ExcludeMachineAccounts = false;     // Set to true to hide computer accounts (names ending in $)
> //
> // ----- Part 1: Filter Kerberos and NTLM events -----
> //
> SecurityEvent
> | where TimeGenerated between (StartTime .. EndTime)
> | where EventID in (4768, 4771, 4776)
> | where (array_length(TargetEventIDs) == 0 or EventID in (TargetEventIDs))
> | where (array_length(TargetComputers) == 0 or Computer has_any (TargetComputers))
> | where (array_length(TargetStatusCodes) == 0 or Status in~ (TargetStatusCodes))
> | where (array_length(TargetUsers) == 0 or TargetUserName in~ (TargetUsers)
>     or strcat(TargetDomainName, "\\", TargetUserName) in~ (TargetUsers) or TargetSid in~ (TargetUsers))
> | where ExcludeMachineAccounts == false or TargetUserName !endswith "$"
> //
> // ----- Part 2: Output -----
> //
> | extend Protocol = iff(EventID == 4776, "NTLM", "Kerberos"),
>     Event = case(
>         EventID == 4768, "Kerberos TGT requested",
>         EventID == 4771, "Kerberos pre-authentication failed",
>         "NTLM credential validation"),
>     SourceIP = replace_string(IpAddress, "::ffff:", ""),
>     ResultText = case(
>         tolower(Status) == "0x0", "Success",
>         tolower(Status) == "0x6", "Kerberos: client not found in database (unknown user)",
>         tolower(Status) == "0x7", "Kerberos: server not found in database",
>         tolower(Status) == "0xc", "Kerberos: logon time or workstation restriction",
>         tolower(Status) == "0x12", "Kerberos: account disabled, expired, locked out, or logon hours restricted",
>         tolower(Status) == "0x17", "Kerberos: password expired",
>         tolower(Status) == "0x18", "Kerberos: pre-authentication failed (wrong password)",
>         tolower(Status) == "0x25", "Kerberos: clock skew too great",
>         tolower(Status) == "0xc0000064", "NTLM: user name does not exist",
>         tolower(Status) == "0xc000006a", "NTLM: wrong password",
>         tolower(Status) == "0xc000006f", "NTLM: logon outside allowed hours",
>         tolower(Status) == "0xc0000070", "NTLM: workstation restriction",
>         tolower(Status) == "0xc0000071", "NTLM: password expired",
>         tolower(Status) == "0xc0000072", "NTLM: account disabled",
>         tolower(Status) == "0xc0000234", "NTLM: account locked out",
>         strcat("Status ", Status))
> | project TimeGenerated, UserName = TargetUserName, UserDomain = TargetDomainName, EventID, Event, Protocol, ResultText, Status,
>     Computer, SourceIP, SourceWorkstation = Workstation, ServiceName, UserSid = TargetSid
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Windows Kerberos certificate (PKINIT) authentication</strong></summary>
>
> Query file: [Windows/SecurityEvent/Windows-kerberos-certificate-authentication.kql](../Windows/SecurityEvent/Windows-kerberos-certificate-authentication.kql).
>
> ```kql
> // Windows Kerberos Certificate (PKINIT) Authentication
> // Objective: Shows Kerberos ticket requests that were made with a certificate (smart card, PIV/CAC, or other PKINIT logons) on domain controllers, with the
> // account, the certificate issuer, serial number and thumbprint, the source IP, and a readable result. Use it to see who authenticates with a certificate and which certificate.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: SecurityEvent (Windows Security log on domain controllers).
> // Event ID: 4768 Kerberos TGT requested. Only requests that carry certificate details are returned; password logons have empty certificate fields and are not shown.
> // Audit policy: Account Logon > Audit Kerberos Authentication Service (Success, Failure).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all domain controllers, all certificates, successes and failures).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "jdoe@contoso.com", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetComputers = dynamic([]);      // Example: ["dc01"] (the domain controller that handled the request; case-insensitive whole-word match)
> let TargetCertIssuers = dynamic([]);    // Example: ["Contoso Issuing CA"] (case-insensitive whole-word match on the issuer name)
> let TargetCertThumbprints = dynamic([]); // Example: ["A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"]
> let TargetStatusCodes = dynamic([]);    // Example: ["0x0", "0x10"] (Kerberos status codes; empty = all, success included)
> let ExcludeMachineAccounts = false;     // Set to true to hide computer accounts (names ending in $)
> //
> // ----- Part 1: Filter 4768 events and read the certificate fields -----
> //
> SecurityEvent
> | where TimeGenerated between (StartTime .. EndTime)
> | where EventID == 4768
> | where (array_length(TargetComputers) == 0 or Computer has_any (TargetComputers))
> | where (array_length(TargetStatusCodes) == 0 or Status in~ (TargetStatusCodes))
> | where (array_length(TargetUsers) == 0 or TargetUserName in~ (TargetUsers)
>     or strcat(TargetDomainName, "\\", TargetUserName) in~ (TargetUsers) or TargetSid in~ (TargetUsers))
> | where ExcludeMachineAccounts == false or TargetUserName !endswith "$"
> | extend CertIssuer = extract(@'Name="CertIssuerName">([^<]+)<', 1, EventData),
>     CertSerialNumber = extract(@'Name="CertSerialNumber">([^<]+)<', 1, EventData),
>     CertThumbprint = extract(@'Name="CertThumbprint">([^<]+)<', 1, EventData),
>     PreAuthType = extract(@'Name="PreAuthType">([^<]+)<', 1, EventData)
> | where isnotempty(CertIssuer) or isnotempty(CertSerialNumber) or isnotempty(CertThumbprint)
> | where (array_length(TargetCertIssuers) == 0 or CertIssuer has_any (TargetCertIssuers))
> | where (array_length(TargetCertThumbprints) == 0 or CertThumbprint in~ (TargetCertThumbprints))
> //
> // ----- Part 2: Output -----
> //
> | extend SourceIP = replace_string(IpAddress, "::ffff:", ""),
>     ResultText = case(
>         tolower(Status) == "0x0", "Success",
>         tolower(Status) == "0x6", "Kerberos: client not found in database (unknown user)",
>         tolower(Status) == "0x10", "Kerberos: no support for this pre-authentication type (certificate not accepted or not found)",
>         tolower(Status) == "0x12", "Kerberos: account disabled, expired, locked out, or logon hours restricted",
>         tolower(Status) == "0x18", "Kerberos: pre-authentication failed",
>         tolower(Status) == "0x25", "Kerberos: clock skew too great",
>         strcat("Status ", Status))
> | project TimeGenerated, UserName = TargetUserName, UserDomain = TargetDomainName, ResultText, Status, Computer, SourceIP,
>     CertIssuer, CertSerialNumber, CertThumbprint, PreAuthType, ServiceName, UserSid = TargetSid
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary><strong>Windows Kerberos pre-authentication failures</strong></summary>
>
> Query file: [Windows/SecurityEvent/Windows-kerberos-preauthentication-failures.kql](../Windows/SecurityEvent/Windows-kerberos-preauthentication-failures.kql).
>
> ```kql
> // Windows Kerberos Pre-Authentication Failures (Event 4771)
> // Objective: Shows failed Kerberos pre-authentication attempts at the domain controller (wrong password, expired or disabled account, unknown user). Useful for Kerberos password spray and brute force. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: SecurityEvent from domain controllers (Windows Security log, collected by the Windows Security Events connector / Azure Monitor Agent).
> // Audit policy (domain controllers): Advanced Audit Policy Configuration > Account Logon > Audit Kerberos Authentication Service (Failure).
> // Derived from the M-21-31 EL0 tracked query (EventID 4771).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results.
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetComputers = dynamic([]);      // Example: ["dc01"] (case-insensitive whole-word match on the domain controller name)
> let TargetStatusCodes = dynamic([]);    // Example: ["0x18"] (0x6 unknown user, 0x12 disabled/locked, 0x17 password expired, 0x18 bad password)
> let ExcludeMachineAccounts = true;      // Set to false to include computer accounts (names ending in $)
> //
> // ----- Part 1: Filter Kerberos pre-authentication failures -----
> //
> SecurityEvent
> | where TimeGenerated between (StartTime .. EndTime)
> | where EventID == 4771
> | where (array_length(TargetComputers) == 0 or Computer has_any (TargetComputers))
> | where (array_length(TargetStatusCodes) == 0 or Status in~ (TargetStatusCodes))
> | where (array_length(TargetUsers) == 0 or TargetUserName in~ (TargetUsers)
>     or strcat(TargetDomainName, "\\", TargetUserName) in~ (TargetUsers) or TargetSid in~ (TargetUsers))
> | where ExcludeMachineAccounts == false or TargetUserName !endswith "$"
> //
> // ----- Part 2: Output -----
> //
> | extend SourceIP = replace_string(IpAddress, "::ffff:", ""),
>     FailureReason = case(
>         tolower(Status) == "0x6", "Client not found in Kerberos database (unknown user)",
>         tolower(Status) == "0x7", "Server not found in Kerberos database",
>         tolower(Status) == "0xc", "KDC policy rejected request (logon time or workstation restriction)",
>         tolower(Status) == "0xe", "Unsupported encryption type",
>         tolower(Status) == "0x10", "No support for PADATA type (likely smart card certificate issue)",
>         tolower(Status) == "0x12", "Account disabled, expired, locked out, or logon hours restricted",
>         tolower(Status) == "0x17", "Password expired",
>         tolower(Status) == "0x18", "Pre-authentication failed (bad password)",
>         tolower(Status) == "0x25", "Clock skew too great",
>         strcat("Status ", Status)),
>     IsHighPriorityFailure = tolower(Status) in ("0x6", "0x12", "0x18")
> | project TimeGenerated, UserName = TargetUserName, UserDomain = TargetDomainName, EventID, Computer, SourceIP,
>     FailureReason, Status, IsHighPriorityFailure, ServiceName, UserSid = TargetSid, Activity
> | top 1000 by TimeGenerated desc
> ```
> </details>

</details>

<details>
<summary><strong>User Device Activity</strong></summary>

> <details>
> <summary>✅ <strong>USB and removable media</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-USB-and-removable-media.kql](../Microsoft Defender for Endpoint/Device-USB-and-removable-media.kql).
>
> ```kql
> // Device USB and Removable Media Activity
> // Objective: Shows USB drives and plug-and-play devices connected to, mounted on, or removed from a device, and the user signed in or running the process that triggered the event.
> // Use it to see who plugged in removable media, which drive (name, serial number, drive letter) and when. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceEvents (Microsoft Defender for Endpoint). ActionTypes: UsbDriveMounted, UsbDriveUnmounted, UsbDriveDriveLetterChanged, PnpDeviceConnected, PnpDeviceAllowed, PnpDeviceBlocked.
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all USB and plug-and-play events).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches the account name, DOMAIN\name, or SID that initiated the event)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let TargetActionTypes = dynamic([]);    // Example: ["UsbDriveMounted"] (empty = all six ActionTypes listed above)
> //
> // ----- Part 1: Filter USB and removable media events -----
> //
> DeviceEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where ActionType in ("UsbDriveMounted", "UsbDriveUnmounted", "UsbDriveDriveLetterChanged", "PnpDeviceConnected", "PnpDeviceAllowed", "PnpDeviceBlocked")
> | where (array_length(TargetActionTypes) == 0 or ActionType in~ (TargetActionTypes))
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetUsers) == 0 or InitiatingProcessAccountName in~ (TargetUsers)
>     or strcat(InitiatingProcessAccountDomain, "\\", InitiatingProcessAccountName) in~ (TargetUsers)
>     or InitiatingProcessAccountSid in~ (TargetUsers))
> //
> // ----- Part 2: Output -----
> //
> | extend Details = todynamic(AdditionalFields)
> | project TimeGenerated, UserName = InitiatingProcessAccountName, UserDomain = InitiatingProcessAccountDomain, DeviceName, ActionType,
>     DriveLetter = tostring(coalesce(Details.DriveLetter, Details.DriveLetters)), DriveName = tostring(coalesce(Details.ProductName, Details.DeviceDescription, Details.ClassName)),
>     SerialNumber = tostring(coalesce(Details.SerialNumber, Details.DeviceId)), Manufacturer = tostring(Details.Manufacturer),
>     InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields, UserSid = InitiatingProcessAccountSid, DeviceId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>PowerShell commands</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-PowerShell-commands.kql](../Microsoft Defender for Endpoint/Device-PowerShell-commands.kql).
>
> ```kql
> // Device PowerShell Commands
> // Objective: Shows PowerShell commands run on a device, with the user, device, the command text, and the process that launched it.
> // Use it to see what a user ran in PowerShell, and to hunt for encoded, download, or credential-access commands with the keyword filter. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceEvents, ActionType PowerShellCommand (Microsoft Defender for Endpoint).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all commands).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches the account name, DOMAIN\name, or SID that ran the command)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let CommandKeywords = dynamic([]);      // Example: ["Invoke-WebRequest", "-enc", "DownloadString"] (shows commands containing any of these words)
> //
> // ----- Part 1: Filter PowerShell commands -----
> //
> DeviceEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where ActionType == "PowerShellCommand"
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetUsers) == 0 or InitiatingProcessAccountName in~ (TargetUsers)
>     or strcat(InitiatingProcessAccountDomain, "\\", InitiatingProcessAccountName) in~ (TargetUsers)
>     or InitiatingProcessAccountSid in~ (TargetUsers))
> | extend Command = tostring(todynamic(AdditionalFields).Command)
> | where (array_length(CommandKeywords) == 0 or Command has_any (CommandKeywords))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserName = InitiatingProcessAccountName, UserDomain = InitiatingProcessAccountDomain, DeviceName, Command,
>     InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FileName, ProcessCommandLine,
>     UserSid = InitiatingProcessAccountSid, DeviceId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Scheduled task activity</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-scheduled-task-activity.kql](../Microsoft Defender for Endpoint/Device-scheduled-task-activity.kql).
>
> ```kql
> // Device Scheduled Task Activity
> // Objective: Shows scheduled tasks created, updated, deleted, enabled, disabled, or run on a device, with the task name, the user, and the process that made the change.
> // Use it to find persistence and to see which user scheduled what. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceEvents, ActionTypes beginning with ScheduledTask (Microsoft Defender for Endpoint).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all task actions).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches the account name, DOMAIN\name, or SID that made the change)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let TargetActionTypes = dynamic([]);    // Example: ["ScheduledTaskCreated", "ScheduledTaskDeleted"] (empty = all scheduled task actions)
> let TargetTaskNames = dynamic([]);      // Example: ["Updater", "\\Microsoft\\Windows"] (shows tasks whose name contains any of these)
> //
> // ----- Part 1: Filter scheduled task events -----
> //
> DeviceEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where ActionType startswith "ScheduledTask"
> | where (array_length(TargetActionTypes) == 0 or ActionType in~ (TargetActionTypes))
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetUsers) == 0 or InitiatingProcessAccountName in~ (TargetUsers)
>     or strcat(InitiatingProcessAccountDomain, "\\", InitiatingProcessAccountName) in~ (TargetUsers)
>     or InitiatingProcessAccountSid in~ (TargetUsers))
> | extend Details = todynamic(AdditionalFields)
> | extend TaskName = tostring(Details.TaskName)
> | where (array_length(TargetTaskNames) == 0 or TaskName has_any (TargetTaskNames))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserName = InitiatingProcessAccountName, UserDomain = InitiatingProcessAccountDomain, DeviceName, ActionType, TaskName,
>     InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields, UserSid = InitiatingProcessAccountSid, DeviceId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Process execution by user</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-process-execution.kql](../Microsoft Defender for Endpoint/Device-process-execution.kql).
>
> ```kql
> // Device Process Execution by User
> // Objective: Shows the processes a user started on a device, with the command line, the parent process, and the file hash.
> // Use it to answer "what did this user run on this machine". Raw events (ProcessCreated only; aggregated reports are excluded).
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceProcessEvents (Microsoft Defender for Endpoint).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all processes).
> //
> let StartTime = ago(7d);                // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches account name, DOMAIN\name, or SID)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let TargetProcessNames = dynamic([]);   // Example: ["powershell.exe", "cmd.exe"] (exact file name of the process that started)
> let CommandLineKeywords = dynamic([]);  // Example: ["-enc", "whoami", "net user"] (shows command lines containing any of these)
> //
> // ----- Part 1: Filter process creation events -----
> //
> DeviceProcessEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where ActionType == "ProcessCreated"
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetUsers) == 0 or AccountName in~ (TargetUsers)
>     or strcat(AccountDomain, "\\", AccountName) in~ (TargetUsers) or AccountSid in~ (TargetUsers))
> | where (array_length(TargetProcessNames) == 0 or FileName in~ (TargetProcessNames))
> | where (array_length(CommandLineKeywords) == 0 or ProcessCommandLine has_any (CommandLineKeywords))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserName = AccountName, UserDomain = AccountDomain, DeviceName, FileName, ProcessCommandLine, FolderPath,
>     InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ProcessIntegrityLevel, SHA256,
>     UserSid = AccountSid, DeviceId
> | top 1000 by TimeGenerated desc
> ```
> </details>

</details>

<details>
<summary><strong>Web Activity</strong></summary>

> <details>
> <summary>✅ <strong>Web connections by user and device</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-web-connections.kql](../Microsoft Defender for Endpoint/Device-web-connections.kql).
>
> ```kql
> // Device Web Connections
> // Objective: Shows the websites and web addresses that devices connected to, with the user, device, destination URL, IP, port, and the program that made the connection.
> // Use it to see what sites a user reached, and to hunt for a specific site, domain, or program with the filters. Includes connections that succeeded, failed, or were requested. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceNetworkEvents, events that have a RemoteUrl (Microsoft Defender for Endpoint).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all sites, all programs).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches the account name, DOMAIN\name, or SID of the program that made the connection)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let UrlKeywords = dynamic([]);          // Example: ["dropbox.com", "pastebin", "mega.nz"] (shows connections to any URL containing these words)
> let TargetPrograms = dynamic([]);       // Example: ["chrome.exe", "msedge.exe", "powershell.exe"] (the program that made the connection)
> //
> // ----- Part 1: Filter web connections -----
> //
> DeviceNetworkEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where isnotempty(RemoteUrl)
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetUsers) == 0 or InitiatingProcessAccountName in~ (TargetUsers)
>     or strcat(InitiatingProcessAccountDomain, "\\", InitiatingProcessAccountName) in~ (TargetUsers)
>     or InitiatingProcessAccountSid in~ (TargetUsers))
> | where (array_length(UrlKeywords) == 0 or RemoteUrl has_any (UrlKeywords))
> | where (array_length(TargetPrograms) == 0 or InitiatingProcessFileName in~ (TargetPrograms))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserName = InitiatingProcessAccountName, UserDomain = InitiatingProcessAccountDomain, DeviceName, RemoteUrl,
>     RemoteIP, RemotePort, Protocol, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, LocalIP,
>     UserSid = InitiatingProcessAccountSid, DeviceId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Browser opened URLs</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-browser-opened-URLs.kql](../Microsoft Defender for Endpoint/Device-browser-opened-URLs.kql).
>
> ```kql
> // Device Browser Opened URLs
> // Objective: Shows links and files that were opened in a web browser on a device, with the user, device, the address or shortcut opened, and the program that opened it.
> // Use it to see what a user or program launched into a browser, and to hunt for a specific site or program with the filters. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceEvents, ActionType BrowserLaunchedToOpenUrl (Microsoft Defender for Endpoint).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all accounts, all devices, all addresses, all programs).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "CONTOSO\\jdoe", "S-1-5-21-..."] (matches the account name, DOMAIN\name, or SID that opened the link)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let UrlKeywords = dynamic([]);          // Example: ["dropbox.com", "login", "docusign"] (shows opened addresses containing any of these words)
> let TargetPrograms = dynamic([]);       // Example: ["outlook.exe", "winword.exe", "powershell.exe"] (the program that opened the browser)
> //
> // ----- Part 1: Filter browser launches -----
> //
> DeviceEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where ActionType == "BrowserLaunchedToOpenUrl"
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetUsers) == 0 or InitiatingProcessAccountName in~ (TargetUsers)
>     or strcat(InitiatingProcessAccountDomain, "\\", InitiatingProcessAccountName) in~ (TargetUsers)
>     or InitiatingProcessAccountSid in~ (TargetUsers))
> | where (array_length(UrlKeywords) == 0 or RemoteUrl has_any (UrlKeywords))
> | where (array_length(TargetPrograms) == 0 or InitiatingProcessFileName in~ (TargetPrograms))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, UserName = InitiatingProcessAccountName, UserDomain = InitiatingProcessAccountDomain, DeviceName, RemoteUrl,
>     InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
>     UserSid = InitiatingProcessAccountSid, DeviceId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>DNS lookups</strong></summary>
>
> Query file: [Microsoft Defender for Endpoint/Device-DNS-lookups.kql](../Microsoft Defender for Endpoint/Device-DNS-lookups.kql).
>
> ```kql
> // Device DNS Lookups
> // Objective: Shows the domain names that devices looked up, with the device, the domain, the answers returned, and the program that asked.
> // Use it to see which domains a device resolved, and to hunt for a specific domain or program with the filters. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: DeviceEvents, ActionType DnsQueryResponse (Microsoft Defender for Endpoint).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all devices, all domains, all programs).
> //
> let StartTime = ago(30d);               // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetUsers = dynamic([]);          // Example: ["jdoe", "NT AUTHORITY\\network service", "S-1-5-20"] (matches the account name, DOMAIN\name, or SID of the program that asked)
> let TargetDevices = dynamic([]);        // Example: ["pc01", "server02"] (case-insensitive whole-word match on the device name)
> let DomainKeywords = dynamic([]);       // Example: ["pastebin.com", "ngrok", "duckdns.org"] (shows lookups of any domain containing these words)
> let TargetPrograms = dynamic([]);       // Example: ["svchost.exe", "chrome.exe", "powershell.exe"] (the program that asked for the lookup)
> //
> // ----- Part 1: Filter DNS lookups -----
> //
> DeviceEvents
> | where TimeGenerated between (StartTime .. EndTime)
> | where ActionType == "DnsQueryResponse"
> | where (array_length(TargetDevices) == 0 or DeviceName has_any (TargetDevices))
> | where (array_length(TargetUsers) == 0 or InitiatingProcessAccountName in~ (TargetUsers)
>     or strcat(InitiatingProcessAccountDomain, "\\", InitiatingProcessAccountName) in~ (TargetUsers)
>     or InitiatingProcessAccountSid in~ (TargetUsers))
> | extend DnsQueryString = tostring(todynamic(AdditionalFields).DnsQueryString)
> | where (array_length(DomainKeywords) == 0 or DnsQueryString has_any (DomainKeywords))
> | where (array_length(TargetPrograms) == 0 or InitiatingProcessFileName in~ (TargetPrograms))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, DeviceName, DnsQueryString, DnsQueryResult = todynamic(AdditionalFields).DnsQueryResult,
>     ClientProcessName = tostring(todynamic(AdditionalFields).ClientProcessName),
>     UserName = InitiatingProcessAccountName, UserDomain = InitiatingProcessAccountDomain,
>     InitiatingProcessFileName, InitiatingProcessCommandLine, UserSid = InitiatingProcessAccountSid, DeviceId
> | top 1000 by TimeGenerated desc
> ```
> </details>

> <details>
> <summary>✅ <strong>Domain controller DNS server queries</strong></summary>
>
> Query file: [Windows/DNS/Windows-DNS-server-queries.kql](../Windows/DNS/Windows-DNS-server-queries.kql).
>
> ```kql
> // Domain Controller DNS Server Queries
> // Objective: Shows the DNS requests and responses handled by a Windows DNS server (the domain controller), with who asked, the domain looked up, the record type, the answer, and the result.
> // Use it to see which domains clients resolved through the domain controller, and to hunt for a specific client, domain, record type, or failed lookup with the filters. Also shows dynamic DNS updates. Raw events.
> // Written for the unified Defender portal (Sentinel + XDR). If you are not unified, replace every TimeGenerated with Timestamp.
> // Source: ASimDnsActivityLogs, from the Windows DNS Events via AMA connector (Microsoft Sentinel).
> //
> // ----- Part 0: Analyst-Driven Targeting (Optional) -----
> // Leave these empty to return all results (all clients, all DNS servers, all domains, all record types).
> //
> let StartTime = ago(1d);                // Example: datetime(2026-10-14T00:00:00Z)
> let EndTime = now();                    // Example: datetime(2026-10-14T23:59:59Z)
> let TargetClientIPs = dynamic([]);      // Example: ["10.1.1.25", "10.1.1.4"] (the IP address that sent the DNS request)
> let TargetDnsServers = dynamic([]);     // Example: ["adds01", "dc02"] (case-insensitive whole-word match on the DNS server / domain controller name)
> let DomainKeywords = dynamic([]);       // Example: ["pastebin.com", "ngrok", "duckdns.org"] (whole-word match: "microsoftonline.com" finds login.microsoftonline.com, "microsoft" does not)
> let RecordTypes = dynamic([]);          // Example: ["A", "AAAA", "TXT", "MX", "SRV"] (the DNS record type that was requested)
> let EventTypes = dynamic([]);           // Example: ["Query"] or ["Update"] (Query = lookups, Update = dynamic DNS record changes)
> let EventResults = dynamic([]);         // Example: ["Success"] or ["Failure"] (the result of the response; requests have no result)
> //
> // ----- Part 1: Filter DNS server events -----
> //
> ASimDnsActivityLogs
> | where TimeGenerated between (StartTime .. EndTime)
> | where (array_length(TargetDnsServers) == 0 or DvcHostname has_any (TargetDnsServers))
> | where (array_length(TargetClientIPs) == 0 or SrcIpAddr in (TargetClientIPs))
> | where (array_length(DomainKeywords) == 0 or DnsQuery has_any (DomainKeywords))
> | where (array_length(RecordTypes) == 0 or DnsQueryTypeName in~ (RecordTypes))
> | where (array_length(EventTypes) == 0 or EventType in~ (EventTypes))
> | where (array_length(EventResults) == 0 or EventResult in~ (EventResults))
> //
> // ----- Part 2: Output -----
> //
> | project TimeGenerated, DvcHostname, SrcIpAddr, SrcPortNumber, DstIpAddr, DnsQuery, DnsQueryTypeName, EventType, EventSubType, EventResult,
>     DnsResponseName, DnsResponseCode, DnsFlags, EventOriginalType, AdditionalFields, EventProduct, EventVendor
> | top 1000 by TimeGenerated desc
> ```
> </details>

</details>

<details>
<summary><strong>User Network Share Activity</strong></summary>

No queries added yet.

</details>

<details>
<summary><strong>User Activity Event Timeline</strong></summary>

No queries added yet.

</details>

<details>
<summary><strong>User Identity</strong></summary>

No queries added yet.

</details>

<details>
<summary><strong>File Metadata Tracking</strong></summary>

No queries added yet.

</details>
