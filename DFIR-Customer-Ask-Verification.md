# DFIR KQL - Email platform selector

**Updated: 2026-10-13 - Email category only**

Choose the platform where the query will run. Each page includes four full investigation queries and a combined query. Default window: last 30 days.

**Time column:** XDR Advanced Hunting uses `Timestamp`; Sentinel/Log Analytics uses `TimeGenerated`. Both represent the recorded event time in these email tables, not ingestion time. Choose the matching platform version below.

<details open>
<summary><strong>Email Investigations</strong></summary>

> <details>
> <summary><strong>Microsoft Defender XDR Advanced Hunting</strong></summary>
>
> Uses `Timestamp`. Open the [full XDR email page](DFIR/Email-XDR.md) for external communications, attachment filename/hash pivots, subject pivots, and sender/recipient pivots.
>
> [Combined investigation query](DFIR/Email-Investigation.kql).
> </details>

> <details>
> <summary><strong>Microsoft Sentinel / Log Analytics</strong></summary>
>
> Uses `TimeGenerated`. Open the [full Sentinel email page](DFIR/Email-Sentinel.md) for the same four child categories and parameters.
>
> **Requires:** Raw `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, and `EmailPostDeliveryEvents` tables from the Defender XDR connector. Alerts/incidents alone are insufficient.
>
> [Combined investigation query](DFIR/Sentinel/Email-Investigation.kql).
> </details>

</details>

<!-- Email-only platform selector. Additional categories intentionally omitted. -->

