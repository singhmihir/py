# SNOWUSEMTP-1625 — Kafka payload for remediation tasks (CDP)

Global-scope update set V1.3 (2 script includes + 10 system properties):

- `RemediationTaskPayloadBuilder.js` — the fellow developer's background script
  (`generateRemediationTaskSCRIPT.txt`) as a class: `buildPayload(record, activity)` returns the
  JSON string (envelope + `rem_tasks[0].remediation_task`) for one remediation task, empty string
  after a single `gs.error` on invalid input.
- `CdpRemediationTaskPayloadBuilder.js` — extends the first; body driven by the mapping sheet
  "Outbound to CDP (RemTask)" (`remtask_mapping.json`): 78 common keys plus table-specific keys
  for `sn_vul_vulnerability`, `sn_vul_app_vulnerability`, `sn_vul_container_vulnerability`,
  `sn_vulc_result_group`, rendered by dictionary type, plus `change_requests` (association
  tables) and `exception_requests` (approved/expired exception approvals).

Field lists live in system properties, so field customisation needs no code change:
`usem.remtask.payload.fields` (first builder), `usem.cdp.remtask.fields.common`,
`usem.cdp.remtask.fields.<table>` (a table is supported while its property exists) and
`usem.cdp.remtask.changes.<table>` (`<association table>.<link field>`). Entries are comma
separated field names, `json_name=field` where the payload key differs. Values are generated
from the sheet into `properties.json` and created by `build_props_1625.py`.

Rendering branches inline on the dictionary internal type (dates formatted, journals latest entry, key-like types as display values, the rest stored values), errors use one format
(`<builder>: payload not built for <table> <sys_id> - <reason>`), and `element_activity`
comes from `current.operation()` in a business rule (never-updated -> INSERT, else UPDATE
outside one).

Drivers: `build_1625.py`, `build_props_1625.py`, `test_1625.py` (51 checks incl. negatives,
a business-rule probe and property changes at run time), `export_1625.py`.
