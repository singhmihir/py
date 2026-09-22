# SNOWUSEMTP-1625 — Kafka payload for remediation tasks (CDP)

Global-scope update set (current `SNOWUSEMTP-1625_MS_Remediation Task CDP Payload_V2.6`): one script include, `RemediationTaskPayloadBuilder`, plus four
system properties. `buildPayload(record)` returns the JSON string (envelope +
`rem_tasks[0].remediation_task`) for one remediation task record, or an empty string after a
single error in the format `RemediationTaskPayloadBuilder: payload not built for <table>
<sys_id> - <reason>`.

- Fields per table come from `usem.cdp.remtask.fields.<table>` — one
  `servicenow_field=json_field,` pair per line (comma terminated) holding the CDP-required rows of the sheet
  "Outbound to CDP (RemTask)" (40 common + the table's own). Generated into `properties.json`
  from `remtask_mapping.json`. A table is supported only while its property exists.
- A field is sent as `""` when it does not exist on the table or is empty; otherwise it is
  rendered by dictionary type (see V2.6 for the rules).
- `change_requests` (per-table association tables: each change once, cancelled changes and links whose
  change is gone left out, change number order) and `exception_requests` (approved or expired exception
  approvals of the record) are derived; the sheet marks both required without a field.
- `element_activity` is `current.operation()` inside a business rule; outside one, `INSERT`
  for a never-updated record and `UPDATE` otherwise.

Drivers: `build_1625.py` (set, deletions of the superseded script include and properties,
properties, script include), `fixtures_1625.py`, `test_1625.py` and `client/test_client.py` (see V2.6),
`export_1625.py` (native export, upload with the platform's preview, archive). `generateRemediationTaskSCRIPT.txt` is the original background
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

## V2.6 - bugs found in the Kafka review, fixed in both copies
Measured on the PDI and fixed in the reference builder and the client copy alike:
- **Comments were "" on almost every payload.** A journal field is empty on a loaded record (`nil()` is
  true unless the save itself adds an entry), so the old code sent the comments only on the save that
  added one, and then with its header line (local time and author). The latest entry is now read from the
  journal on every save and sent without its header.
- **Counts carried the user's thousands separator** (`reassignment_count` "1,250"): an integer is sent as
  stored unless it has choices, in which case its label is sent.
- **`cr_count` was sent as HTML** (`[code]<a href="/nav_to.do?...">1</a>[/code]`, the platform's display
  markup): markup of that form is sent as its visible text ("1").
- **`change_requests` repeated a change linked twice** and could carry an empty entry for a link whose
  change is gone; each change is now taken once and a gone change left out; the reference builder now
  also leaves out cancelled changes, as the client copy already did.
- **The client copy failed on the client's call path in two ways that the reference never shows**: in a
  scoped application `GlideElementDescriptor.getChoice()` does not exist, and a record handed over from
  inside a function of a global script refuses `getED()` (`StatefulElementDescriptor ... not allowed in
  scope`). Choices are now told by `isChoiceTable()` and field types read from a record of the table the
  builder opens itself; a document id whose table field is empty (null on one path, an object without
  record methods on the other) gives `""`.
- **The property parser accepted malformed lines** silently: a line with more than one `=`, without a
  field name, with `=` but no payload name, a payload name used twice, or `change_requests` /
  `exception_requests` as a payload name, and a property holding only separators, are now refused with
  one error naming the line.
- The client copy's description now names its property with the scope prefix; the samples carry no
  working user.

`fixtures_1625.py` builds, on each of the four tables, a task with no change, one with one change and one
with several changes linked out of number order (the open change twice, a closed one, a cancelled one, one
of the child class `change_request_imac`, and a link whose change is gone), exception approvals approved,
expired and requested plus one for another record, two comments a minute apart, a four-digit count and a
change count held as display markup. `test_1625.py` (304 checks) works every expected value out through
the REST API apart from the builder (dictionary type, stored and display value, latest journal row,
change and exception records) for the twelve fixture tasks, the four sample records and the five latest
tasks per table (1683 mapped values), checks literals on the fixtures, every property refusal with its
exact log line, the business rule context (a save adding no comment, a save adding one, inserts) and the
configuration. `client/test_client.py` (122 checks) compares the client copy, called from inside a
function of a global script, with the reference on the same 36 records and checks its own refusals.
Both run twice, all passing.
