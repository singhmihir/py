# stories

One folder per JIRA story (SNOWUSEMTP). Each holds the final ServiceNow scripts, the
PDI build / fixture / test / export drivers, and notes. `_update_sets/` holds the
platform-native export of every update set delivered so far (`index.json` lists
name, scope and update count).

| Folder | Story | Deliverable |
|---|---|---|
| `trident-1420` | SNOWUSEMTP-1420 Trident closure governance (CRG approvals) | single lifecycle business rule, `TridentClosureUtil`, fix script; sets V2.0 → V2.3 |
| `p317-vulnerability-summary` | SNOWUSEMTP.26.P3.17 weekly Vulnerability Summary per app owner | `VulnSummaryDigestUtil`, event, mail script, notification, weekly job; set V1.1 |
| `1625-cdp-remediation-task-payload` | SNOWUSEMTP-1625 Kafka payload for remediation tasks (CDP) | `RemediationTaskPayloadBuilder`, `CdpRemediationTaskPayloadBuilder`; set V1.0 |

Older sets in `_update_sets/` (SNOWUSEMTP-581, -670, -1003, exception deferral limits,
Trident closure governance V1/V2, CRG resolve-requires-attachment) were delivered in
earlier sessions; their scripts are inside the XML payloads.
