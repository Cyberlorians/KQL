# Microsoft Defender for Office 365

Use the [DFIR Investigations landing page](../README.md) for the customer investigation index.

## Canonical email queries

- [External communications](External-communications.kql)
- [Specific attachment filenames and hashes](Specific-attachment-filenames-and-hashes.kql)
- [Specific Subject lines](Specific-Subject-lines.kql)
- [Specific sender and recipients](Specific-sender-and-recipients.kql)

Set the saved query's parameters and UTC window before execution. These files use `TimeGenerated` in Sentinel/Log Analytics; without Sentinel, replace every occurrence with `Timestamp` for Defender XDR Advanced Hunting. Sentinel requires raw MDO event collection through the Defender XDR connector, not alerts/incidents alone. The relevant raw sources are `EmailEvents` and `EmailAttachmentInfo`; advanced enrichment additionally uses `EmailUrlInfo` and `EmailPostDeliveryEvents`.

**Status — 2026-10-13:** Live execution and bounded positive email validation confirmed, not universal 100% coverage. Ingestion, licensing, retention, permissions, caps, and optional-field availability constrain evidence. These queries do not retrieve complete mailbox contents, body/MIME, full To/Cc/Bcc, read state, or attachment binaries.

<details>
<summary>Historical / advanced References — noncanonical</summary>

These retained artifacts preserve earlier platform-specific guidance and historical evidence. They are not competing customer entry points or a platform selector; use the four canonical files above.

- [XDR historical guidance and advanced artifacts](Reference/XDR/README.md)
- [Sentinel historical guidance and advanced artifacts](Reference/Sentinel/README.md)
- [Historical initial email verification report](Reference/Email-Verification.md) — an earlier bounded snapshot, not the latest validation status.

</details>