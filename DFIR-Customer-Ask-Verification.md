# DFIR Customer Ask — KQL Verification Tracker

**Repository:** [Cyberlorians/KQL](https://github.com/Cyberlorians/KQL)  
**Tenant context:** DIB Security Commercial  
**Sentinel workspace:** `DIBSecCom` (`7e9298ab-22e6-4a82-a53e-c5ed7faee977`)  
**Validation date:** 2026-10-13  
**Validation method:** Microsoft Sentinel Data Exploration MCP for legacy baseline probes; authenticated Defender XDR Advanced Hunting for the full email investigation

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
