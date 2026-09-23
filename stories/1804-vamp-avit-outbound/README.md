# SNOWUSEMTP-1804 — VAMP outbound payload for application vulnerable items

One rule, two script includes and two properties: an after insert/update business rule on
`sn_vul_app_vulnerable_item` builds the payload and sends it to the Kafka topic
`sn_usem_verification_outbound`. The payload is ours (agreed with the client: we build it and VAMP
validates it) and follows the sheet "SN to VAMP" of `SN to VAMP Mapping.xlsx`: the **JSON structure**
of column H names each section and the **JSON field name** of column I names each field. The
ServiceNow field behind every row is resolved on the instance by the field-check script, never
assumed.

## Payload

```
{envelope, findings: [{tpe: {...}, remediation_task: [{...}, ...], finding: {...}, ptreq: {...}}]}
```

- Sections in sheet order, keyed by column H (a space becomes an underscore, as the CDP remediation
  task payload does: *Remediation Task* is `remediation_task`), fields in sheet order keyed by
  column I, every value a string.
- **One property carries the whole structure**, as the CDP payloads do: one
  `servicenow_field=json_field` pair per line in `usem.vamp.fields.sn_vul_app_vulnerable_item`, the
  ServiceNow field on the left (the item's own plain, another section's as `<table>.<field>`) and the
  payload name on the right as `<column H>.<column I>`. The sections of the payload are the structures
  in the order the property introduces them, so nothing else has to be configured.
- **`remediation_task` is a list**: one entry per remediation task linked to the item through
  `sn_vul_app_m2m_vul_group_item`, in task number order, `[]` when the item has none. An item with
  several tasks carries all of them.
- Envelope as CDP: topic `sn_usem_verification_outbound`, namespace `com.bofa.usem`, versions 1.0.0,
  UUID event id, UTC timestamp, `element_count` the number of findings, `element_activity` from
  `record.operation()`.
- Values, as the sheet's types ask: references and document ids as the display value of their record
  (`""` when that record is gone, never its sys_id), lists and domains as displayed, dates and
  date/times `MM-dd-yyyy[ HH:mm:ss]`, integers and strings as stored, a journal field as its latest entry
  without the date and author line the platform puts above it; a field the instance does not have, an
  empty field or a section without a record is `""`.

## Versions
V1.0 to V1.6 keyed the sections by ServiceNow table name and sent one remediation task.
V2.0: sections named by the sheet's JSON structure and carried in the one field
property, as for the CDP payloads; the remediation tasks sent as a list; the vulnerability entry read
in its own class; error handling, payload validation and comments on every function; built in a PDI
mirror of the client integration application, so the update set carries the client names and imports
as it is.
**V2.1**: field types read in a way a scoped application may use whoever calls it (a record
handed over from inside a function of a global script refused `getED()` in the scope:
`StatefulElementDescriptor ... not allowed in scope`, measured on the PDI); a reference or document id
whose record is gone guarded on every path; document ids, lists, domains, due dates and journals rendered; payload
names trimmed and checked around the dot, the field on the left checked (`<field>` or
`<table>.<field>`, a table with a path from the item); the producer names the item as
`<table> <sys_id>` in its errors and sends nothing without a saved record; and the 19 records V1.0 to V1.6
delivered under other sys_ids are deleted (see *Earlier sys_ids*).
**V2.2** accepts only the INSERT and UPDATE the rule fires on. **V2.3** (current) again names the configured
fields the instance lacks in a second info message, after the payload.

### The two bugs fixed in V2.0
- **Only one remediation task was sent.** `_remediationTask()` read the group item table, ordered by
  creation date and took the first row. The item the client showed carries two tasks, so one was
  dropped. The walk now collects every linked task (skipping a link whose task is gone), and the
  section is a list.
- **Fields of the vulnerability entry were lost.** `sn_vul_app_vul_entry` extends `sn_vul_entry` and
  the item's `vulnerability` field references the base table, so `getRefRecord()` hands out a record
  of the base table and a field of the extended class (the sheet's `u_vuln_sub_cat_id`) reads as
  empty. Every related record is now re-opened in the class its `sys_class_name` names
  (`_inOwnClass`), which is proved on the developer instance with a sub category id that exists on
  the extended table only.

## Records
- `BOFA_BR_AVIT_VampOutbound.js` — after insert/update on `sn_vul_app_vulnerable_item`, order 100, no
  condition: processor → producer, one try/catch; a payload the processor refused is not sent.
- `BOFASIVampOutboundProcessor.js` — `buildPayload(record)` returns the JSON text and shows it with
  `gs.addInfoMessage` on the item; a second message names any configured field the instance does not have. `_payloadMap()` reads the one property and yields the sections with their table, their shape
  and their fields. The paths from the item to the other sections live in `initialize()`:
  `vulnerability` for the entry, `assessment_request` for the pen test request and the group item
  table for the remediation tasks; a path with `list` makes its section a list and a task linked more
  than once is taken once.
- `BOFASIKafkaProducerVamp.js` — `sendPayload(payload, record)`: topic sys_id from
  `x_boar_bofa_usem_1.usem.vamp.kafka.topic_sys_id` (spaces around the value ignored), key
  `<table>.<sys_id>`, `sn_ih_kafka.ProducerV2().send(...)` asynchronous, no headers, no schema; the
  response shown with `gs.addInfoMessage`; nothing sent without an existing record.
- `VAMP Field Check - Background Script.js` — generated from the workbook by `extract_mapping.py`.
  Read only, global scope. For every sheet row it looks for the field behind the JSON field name:
  same name, then the sheet's label, then the `u_` variant; checks the type and prints the two
  property values to use. `resolve_1804.py` runs it and writes `field_resolution.json`,
  `field_check_output.txt` and `properties.json`.

## Error handling, validation and comments
Every function carries a JSDoc header. The rule and the two public methods are the only try/catch
blocks besides the helpers that name a record for the log and the producer's JSON parse guard; the private methods throw and the entry point logs one `gs.error` in the form
`<class>: <what failed> for <table> <sys_id> - <reason>` (`no record` as the key when no record was
given). The processor refuses a record that was never fetched or does not exist, a property that is
not configured or holds nothing, a line with more than one "=", without a field name, with a field
that is not `<field>` or `<table>.<field>`, of a table with no path from the item (a dot-walk such as
`cmdb_ci.name` included), without a payload name or with a payload name that is not
`<structure>.<field>` (one dot, both parts present; spaces around them ignored), a section that would
take fields from two tables, and the same payload name twice in a section.
`_validatePayload` then checks the finished message before it is returned: the envelope constants, a
UUID event id, a UTC timestamp, an activity of INSERT or UPDATE, `element_count` equal to the
number of findings, every configured section present (a list where the sheet is one to many), every
configured field present as a string, and nothing else in the message; all problems are named in one
error. A refused build returns `''`, so the rule never calls the producer. The producer refuses an
empty topic property or one that is not a sys_id, a missing or unsaved record, and a payload that is empty, not
JSON, without envelope or findings, without a finding, or whose `element_count` does not match.

## Earlier sys_ids
V1.0 to V1.6 were built in the PDI's stand-in scope and delivered as record XML under the stand-in's
sys_ids (V1.0 with ten properties, later ones with fewer); V2.0 was built in the mirror application under
new ones. An instance that loaded a V1 file and then V2.0 holds two rules and two copies of each script
include (same API names), and the V2.0 properties of the same names were refused there (property names
are unique), leaving the V1 values - the old two-property format, which V2.0 cannot read - in place.
V2.1 keeps the V2.0 sys_ids and deletes the 19 earlier ones (`prior_records.json`, every sys_id of an
earlier record XML that V2.1 does not use): the update set carries a DELETE for each, recorded before the
current records so that on commit an earlier property goes before the current one of the same name is
written; the record XML lists them first as `action="DELETE"` elements (Import XML deletes such a record
and ignores a sys_id it does not hold, measured on the PDI). On an instance without the earlier records
the deletions do nothing; the platform's preview shows no problem for them. Where the earlier topic or
field property was edited on the instance after its import, the preview reports a newer local update
for its deletion; accepting the remote update is the intended result.

## Tests (`test_1804.py`, 158 checks over two runs in one invocation)
A the linked item: the property equals the resolution, the envelope, the sheet's structure names in
sheet order, the fields per section, both remediation tasks in number order with their own values,
the entry's sub category id read through the extended class, the configuration item as a display
value, the not-found message. B an item with nothing linked: an empty task list and `""` everywhere.
C the rule on a real update and a real insert. D rendering by dictionary type, including a date, and a
reference whose record is gone. E every refusal of the processor and the producer with its exact log
line (only the lines of that script are read): each malformed property line, an envelope off its
constants refused by the validation inside `buildPayload`, three tampered payloads naming every
validation branch, the topic property empty, padded (trimmed, sent) and malformed, the payloads the
producer refuses, no record and a record never saved; a journal field configured on the finding, sent as
its latest entry without its header. E2 the rule on a real update with the property empty: the processor
logs once and the producer is never called. **F how many remediation tasks the item has**: two, one,
none, a link whose task is gone, both links on one task (taken once), the two links swapped, and the
older task (smaller sys_id, larger number) renumbered below the other, to prove the order comes from the
task number; the other three sections do not change with the count. G the same finding whether the
processor is called directly or from inside a function of a global script.

## Fixtures (`fixtures_1804.py`)
Adds the sheet's custom fields to the vulnerability tables as stand-ins for the client's
(`u_vuln_sub_cat_id` on `sn_vul_app_vul_entry` — deliberately on the extended table only —
`u_avul_record_url` and `u_primary_ait` on the remediation task, `u_verification_status` and
`u_avit_record_url` on the item, `u_assessment_id` on the pen test request), under the global Default
set, never delivered. Then the linked item with an entry of the extended class, a release with a
Primary AIT, a CI, a pen test request, an exception approval, a consequence and **two** remediation
tasks (each with its own Primary AIT), two comments a minute apart and a VAMP source id (`AVT-448812`)
with its record link, and the bare item.

## Drivers
`build_1804.py` (set `SNOWUSEMTP-1804_MS_VAMP AVIT Outbound Payload_V2.3` in the mirror application,
its Default set created when missing, the earlier sys_ids captured as deletions (each created under its
old sys_id and deleted again; a current property of the same name steps aside for the moment), records
captured explicitly, scope audit), `resolve_1804.py`, `test_1804.py` (run 1 writes the sample),
`export_1804.py` (topic property emptied, native export, deletions recorded before the current records,
upload with the platform's preview, archive), `package_1804.py` (`VAMP AVIT Outbound Payload -
Records.xml`: the deletions first, then the five records, topic property empty, stamps removed, scripts
asserted equal to the repository files), `check_1804.py` (workbook against mapping, sections,
field-check rows, resolution, the property, record XML, sample structure and keys, and the processor's
own wiring: every section must be the item table or carry a path, and only the remediation tasks a
list).

## Delivery
The update set XML imports on the client instance as it is (the PDI holds a mirror of the client
integration application `x_boar_bofa_usem_1`, same scope name and application sys_id); the record XML
is the alternative. After import the client sets `x_boar_bofa_usem_1.usem.vamp.kafka.topic_sys_id` to the
sys_id of its Kafka topic record: `export_1804.py` empties that property and captures it before
exporting, so both files deliver it empty and nothing points at a topic of the development instance.
Every import of a later version empties it again, so it is set after each import.

Open points for the client:
- The acceptance criteria say the trigger is the verification status changing to *Pending Validation*.
  The rule still has no condition and sends on every insert and update, as in V1.x. Adding the
  condition needs the field and the exact choice value on the client instance, and changes when
  messages are sent, so it is not in this build.
- `sn_vul_app_vul_entry.number` has no field on the developer instance and is sent as `""` there; the
  field check on the client instance resolves it (their payload shows the CVE number).
- The three rows added to the sheet (`tpe.u_vuln_sub_cat_id`, `remediation_task.u_avul_record_url`,
  `finding.u_avit_record_url`) were transcribed from the screenshot of the updated workbook; the real
  file regenerates everything through `extract_mapping.py` when it arrives.

The PDI has no Stream Connect: the producer's send fails there and is caught (`message not sent for
<key> - ...`), which is what the rule tests look for after the processor message.
