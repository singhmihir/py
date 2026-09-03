# SNOWUSEMTP-1625 — Kafka payload for remediation tasks (CDP)

Global-scope update set V2.0: one script include, `RemediationTaskPayloadBuilder`, plus four
system properties. `buildPayload(record)` returns the JSON string (envelope +
`rem_tasks[0].remediation_task`) for one remediation task record, or an empty string after a
single error in the format `RemediationTaskPayloadBuilder: payload not built for <table>
<sys_id> - <reason>`.

- Fields per table come from `usem.cdp.remtask.fields.<table>` — comma separated
  `servicenow_field=json_field` pairs holding the CDP-required rows of the sheet
  "Outbound to CDP (RemTask)" (40 common + the table's own). Generated into `properties.json`
  from `remtask_mapping.json`. A table is supported only while its property exists.
- A field is sent as `""` when it does not exist on the table or is empty; otherwise it is
  rendered by dictionary type (dates `MM-dd-yyyy HH:mm:ss` / `MM-dd-yyyy`, journals latest
  entry, references / choices / lists / booleans / durations as display values, the rest raw).
- `change_requests` (per-table association tables) and `exception_requests` (approved or
  expired exception approvals) are derived; the sheet marks both required without a field.
- `element_activity` is `current.operation()` inside a business rule; outside one, `INSERT`
  for a never-updated record and `UPDATE` otherwise.

Drivers: `build_1625.py` (set, deletions of the superseded script include and properties,
properties, script include), `test_1625.py` (43 checks: field-by-field rendering for all four
tables, missing/empty fields, property parsing, errors, activity in insert/update rules, 50
record run), `export_1625.py`. `generateRemediationTaskSCRIPT.txt` is the original background
script this replaced.
