# DFIR KQL - Email platform selector

**Updated: 2026-10-13 - Email category only**

Choose the platform where the query will run. Each full page preserves the four displayed child queries, parameter explanations, and links to its KQL metadata checks and combined investigation query. Default window: last 30 days. These queries investigate observed email telemetry, not complete mailbox contents.

<details open>
<summary><strong>Email Investigations</strong></summary>

> <details>
> <summary><strong>Microsoft Defender XDR Advanced Hunting</strong></summary>
>
> Uses `Timestamp`. Open the [full XDR email page](DFIR/Email-XDR.md) for external communications, attachment filename/hash pivots, subject pivots, and sender/recipient pivots.
>
> [KQL metadata checks](DFIR/XDR/Email-KQL-Checks.kql) | [Combined investigation query (XDR canonical)](DFIR/Email-Investigation.kql).
> </details>

> <details>
> <summary><strong>Microsoft Sentinel / Log Analytics</strong></summary>
>
> Uses `TimeGenerated` throughout, including dynamic bag keys. Open the [full Sentinel email page](DFIR/Email-Sentinel.md) for the same four child categories and parameters.
>
> **Prerequisite:** Ingest raw Microsoft Defender for Office 365 events into the workspace: `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, and `EmailPostDeliveryEvents`. Enable the corresponding raw-event tables in the Microsoft Defender XDR connector; alerts/incidents alone do not supply these records. Availability, retention, permissions, and ingestion latency constrain the investigation scope.
>
> [KQL metadata checks](DFIR/Sentinel/Email-KQL-Checks.kql) | [Combined investigation query](DFIR/Sentinel/Email-Investigation.kql).
> </details>

</details>

Aggregate checks do not replace the four investigation pivots. No observed rows mean `PENDING`, not a demonstrated ingestion failure; missing tables are schema errors.

<!-- Email-only platform selector. Additional categories intentionally omitted. -->

