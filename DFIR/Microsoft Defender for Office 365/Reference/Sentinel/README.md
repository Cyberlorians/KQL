# DFIR KQL - Email - Microsoft Sentinel

**Historical / advanced reference — noncanonical.** Earlier platform-specific guidance is retained here, with full query bodies in the linked files rather than duplicated Markdown. Start at [DFIR Investigations](../../../README.md) and use the [canonical MDO queries](../../README.md); this is not a competing customer entry point or platform selector.

**Updated: 2026-10-13 - Email category only**

**Platform:** Microsoft Sentinel / Log Analytics (`TimeGenerated`). Default window: last 30 days. Set the investigation parameters before running. These queries investigate observed email telemetry, not complete mailbox contents.

**Prerequisite:** Ingest the raw Microsoft Defender for Office 365 events into the Sentinel workspace: `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, and `EmailPostDeliveryEvents`. Configure the Microsoft Defender XDR connector's raw-event collection for these tables; alerts/incidents alone are insufficient. Table availability, retention, permissions, and ingestion latency determine the usable scope. These versions use `TimeGenerated` throughout, including attachment and post-delivery bag keys; all other investigation logic is preserved.

**Time column:** Use `TimeGenerated` in Sentinel/Log Analytics and `Timestamp` in XDR Advanced Hunting. Both represent the recorded event time in these email tables; `TimeGenerated` is not the ingestion time. The linked reference files already use the correct column for this platform.

## Retained email pivots

### External communications

Filter a specific user or direction, or leave the parameters empty for all external communications. Direction comes from `EmailDirection`, not guessed domain ownership.

Query file: [Email-External-Communications.kql](Email-External-Communications.kql).

### Specific attachment filenames and hashes

Set an exact SHA-256 hash, a filename substring, or both. When both are set, the **same attachment record** must match both. Empty parameters show all observed attachment metadata. Sender/recipient correlation uses message ID plus normalized recipient.

Query file: [Email-Attachment-Pivot.kql](Email-Attachment-Pivot.kql).

### Specific Subject lines

Set `SubjectText` to the requested subject. Choose exact case-insensitive matching or substring matching. An empty value leaves the subject filter broad.

Query file: [Email-Subject-Pivot.kql](Email-Subject-Pivot.kql).

### Specific sender and recipients

Set `SenderAddress`, `RecipientAddress`, or both. If both are set, both must match the same message-recipient row. Choose visible From, envelope MAIL FROM, or either sender field.

Query file: [Email-Sender-Recipient-Pivot.kql](Email-Sender-Recipient-Pivot.kql).

## Advanced reference artifacts

- [Combined email investigation](Email-Investigation.kql)
- [Aggregate metadata checks](Email-KQL-Checks.kql)