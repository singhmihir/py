# SNOWUSEMTP-1625 — Kafka payload for remediation tasks (CDP)

Global-scope update set V1.0 (2 script includes):

- `RemediationTaskPayloadBuilder.js` — the fellow developer's background script
  (`generateRemediationTaskSCRIPT.txt`) as a class: `buildPayload(record, activity)` returns the
  JSON string (envelope + `rem_tasks[0].remediation_task`) for one remediation task, empty string
  after a single `gs.error` on invalid input.
- `CdpRemediationTaskPayloadBuilder.js` — extends the first; body driven by the mapping sheet
  "Outbound to CDP (RemTask)" (`remtask_mapping.json`): 78 common keys plus table-specific keys
  for `sn_vul_vulnerability`, `sn_vul_app_vulnerability`, `sn_vul_container_vulnerability`,
  `sn_vulc_result_group`, rendered by dictionary type, plus `change_requests` (association
  tables) and `exception_requests` (approved/expired exception approvals).

Drivers: `build_1625.py`, `test_1625.py` (42 checks incl. negatives and a 50-record run),
`export_1625.py`.
