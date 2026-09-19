# SNOWUSEMTP-1625 — Kafka payload for remediation tasks (CDP)

Global-scope update set V2.2: one script include, `RemediationTaskPayloadBuilder`, plus four
system properties. `buildPayload(record)` returns the JSON string (envelope +
`rem_tasks[0].remediation_task`) for one remediation task record, or an empty string after a
single error in the format `RemediationTaskPayloadBuilder: payload not built for <table>
<sys_id> - <reason>`.

- Fields per table come from `usem.cdp.remtask.fields.<table>` — one
  `servicenow_field=json_field,` pair per line (comma terminated) holding the CDP-required rows of the sheet
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


## V2.4 - line-format properties, client copy
V2.3 moved the `usem.cdp.remtask.fields.<table>` properties to JSON objects; V2.4 returns them to the
original `servicenow_field=json_field,` line format (same pairs, same order, same output) with the
original parser. `test_1625.py`: run twice.

`client/` holds the copy deployed on the client instance (`BOA_SI_USEM_RemediationTaskPayloadBuilder`,
scope `x_boar_bofa_usem_1`, property prefix `x_boar_bofa_usem_1.usem.cdp.remtask.fields.`) with the
operation parameter passed through to the envelope, one `.txt` file per property value, the import-ready
record XML (`Remediation Task Payload Builder - Script Include.xml`) and the stand-in scope build/test
drivers (`test_client.py`: the client copy against the reference builder on the four fixture records
plus the line-format parsing cases).
