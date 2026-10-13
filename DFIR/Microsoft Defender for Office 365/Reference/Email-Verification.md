# Email DFIR — live validation and coverage

**Historical initial verification snapshot — noncanonical.** The prose and evidence below describe the earlier bounded runs, not the latest email validation status. Later validation does not retroactively change this report. Start at [DFIR Investigations](../../README.md) and use the [canonical MDO queries](../README.md).

## Artifact and execution surface

- Investigation: [XDR/Email-Investigation.kql](XDR/Email-Investigation.kql).
- Executed in authenticated Microsoft Defender XDR Advanced Hunting in DIB Security Commercial on **2026-10-13**. Uses `Timestamp`; do not paste unchanged into a Sentinel schema that uses `TimeGenerated`.
- Baseline Evidence window: **2026-09-13 15:34:03 UTC through 2026-10-13 15:34:03 UTC**. Subsequent timeline and filter runs used rolling `ago(30d)` / `now()` windows a few minutes later.
- Status: **implemented and live-executed; positive evidence for the observed inbound scope, not 100% coverage of all email communications**.
- Public evidence is aggregate only. No tenant message subjects, recipient addresses, message identifiers, or attachment hashes are published here.

## Customer subrequirements

| Requirement | Live evidence | Qualification |
|---|---|---|
| Subject lines | 630 / 630 message-recipient results have `Subject` | Actual `EmailEvents` field, not an audit-item heuristic |
| Sender and recipients | 630 / 630 have visible sender, envelope sender, and recipient | Visible and envelope sender are separate fields; each row represents one observed recipient, not a complete To/Cc/Bcc list |
| External communications | 630 inbound; 0 outbound | Classification uses recorded `EmailDirection`. Outbound matching evidence remains unverified |
| Internal communications | 0 `Intra-org` results | Query supports the recorded value; no positive internal-mail example in this window |
| Attachment metadata | 8 raw records; all 8 have filename, SHA256, and positive size | Metadata only, not attachment binary retrieval; `FileType` and threat fields are projected but their completeness is not asserted |
| Attachment correlation | 8 declared-attachment messages, 8 correlated messages, 0 missing-metadata messages | Joins on `NetworkMessageId` plus normalized recipient; enrichment is aggregated before joining |
| Messages without attachments | Baseline includes 630 total and only 8 with declared attachments: 622 attachment-free rows | `leftouter` enrichment retains these; counts agree with the direct email baseline |
| URL metadata enrichment | 2,813 raw URL records; 630 correlated message-recipient results | URL metadata is message-level; a URL record does not prove a click |
| Post-delivery enrichment | 2 raw events; 1 correlated message-recipient result | Recipient-specific action metadata, not proof of reading; not all raw events necessarily belong to in-scope messages |
| Email URL clicks (supplemental) | 0 `UrlClickEvents` rows with `Workload == "Email"` | Not positively verified and not included in the main investigation query |

## Executed validation cases

1. **Direct source probes:** `EmailEvents` returned 630 inbound rows with actual subjects, visible senders, and recipients; `EmailAttachmentInfo` returned 8 filenames/hashes/positive sizes. URL, post-delivery, and Email-workload click counts were independently queried.
2. **Full investigation, Evidence mode:** 630 message-recipient rows; all 630 contain sender, envelope sender, recipient, and subject; inbound 630, outbound 0, internal 0; declared attachments 8, correlated attachment messages 8, missing attachment metadata 0; URL-correlated messages 630; post-delivery-correlated messages 1.
3. **Exact saved default, Timeline mode:** final corrected artifact returned **630 items** at approximately **15:36 UTC**, with timestamped message-level fields and enrichment. Fixed an output-mode issue where summarizing an empty branch previously emitted an extra zero summary row. The corrected run has no extra row.
4. **Compound positive pivot:** at approximately **15:39 UTC**, selected one real attachment joined to an actual email/recipient and derived parameter values inside KQL. Set `TargetUser` to its recipient, `TargetNetworkMessageId`, `SubjectContains`, `Direction`, `ExternalOnly=true`, `AttachmentSHA256`, and `AttachmentNameContains` simultaneously. Evidence mode returned **1 message**, **1 declared attachment message**, **1 correlated attachment message**, **0 missing metadata**, and **1 URL-correlated message**. This validates the compound matching path, not every parameter in isolation or the sender-side user branch.
5. **Negative attachment pivot:** a nonmatching SHA256 parameter returned zero message/evidence counters without a query error.

Successful execution establishes the tested schema and query path, not completeness of tenant ingestion. No seeded messages or mailbox changes were made.

## Design and use

The sectioned `let` query separates parameters, message scope, attachment metadata, URLs, post-delivery actions, enrichment, and evidence. Start with a narrow time interval and set a confirmed user or message identifier. Empty parameters leave the scope broad. `TargetUser` matches exact visible sender, envelope sender, or recipient case-insensitively; subject and filename are case-insensitive substring filters. If both attachment filters are supplied, **the same attachment record must satisfy both**.

The output grain is `NetworkMessageId` / `RecipientEmailAddress`, retaining latest observed state plus first/last timestamps and observed event count. One-to-many sources are aggregated before joins; URLs are not recipient-specific. Repeated raw source records may contribute to record counters. `MaxRows=1000` caps Timeline output only; Evidence mode counts the full scoped result. Dynamic sets are capped at **500 entries per group**; counts can exceed the displayed detail arrays. Confirm row/detail caps before treating a result as a complete export.

Use `OutputMode="Evidence"` for aggregate validation and `OutputMode="Timeline"` for detailed investigation. Mode names are case-sensitive. Fixed UTC start/end parameters are recommended for reproducible incident evidence. Enrichment uses the same time window as messages; actions outside that interval are intentionally excluded.

## Grounding

The artifact is an original implementation informed by these inspected patterns and official schemas; community examples are not proof of tenant data:

- [Cyberlorians MDO table inventory and let-based style](https://github.com/Cyberlorians/KQL/blob/main/MDOSizing.kql).
- [reprise99 inbound email/attachment correlation](https://github.com/reprise99/Sentinel-Queries/blob/main/Office%20365/EmailEvents-MacroReceivedbyEmail.kql).
- [ep3p email pivots and enrichment](https://github.com/ep3p/Sentinel_KQL/blob/main/Temporary/Check%20email.kql).
- [KQL Search discovery](https://www.kqlsearch.com/?search=EmailAttachmentInfo), including [unexpected attachment type investigation](https://github.com/jkerai1/KQL-Queries/blob/main/Office%20365/Unexpected%20Attachment%20Types%20in%20Emails.kql).
- Official [EmailEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table) and [EmailAttachmentInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table).

## Remaining verification gates

- Obtain authorized, known outbound and internal message examples in retention and rerun the corresponding pivots; absence in this window is not proof of unsupported telemetry.
- Independently test sender-side user filtering and any additional requested parameters/edge cases before claiming exhaustive filter validation.
- Confirm To/Cc/Bcc, email body/MIME, mailbox read state, attachment binaries, or full mailbox history through appropriate mailbox/audit/export sources if requested. This query does **not** supply them.
- SHA1 is not assumed. SHA256 is the hash with positive live evidence.
- Licensing, ingestion, retention, permissions, limits, and source coverage constrain results. External classification reflects MDO direction rather than independent proof of domain ownership.

**Email remains partially verified overall. Other customer asks remain separate, pending full investigative implementation and subrequirement validation.**