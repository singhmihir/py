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
- Values: references as the display value, dates and date/times `MM-dd-yyyy[ HH:mm:ss]`, everything
  else as stored; a field the instance does not have, an empty field or a section without a record
  is `""`.

## Versions
V1.0 to V1.6 keyed the sections by ServiceNow table name and sent one remediation task.
**V2.0** (current): sections named by the sheet's JSON structure and carried in the one field
property, as for the CDP payloads; the remediation tasks sent as a list; the vulnerability entry read
in its own class; error handling, payload validation and comments on every function; built in a PDI
mirror of the client integration application, so the update set carries the client names and imports
as it is.

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
  `gs.addInfoMessage` on the item; a second message names any configured field the instance does not
  have. `_payloadMap()` reads the one property and yields the sections with their table, their shape
  and their fields. The paths from the item to the other sections live in `initialize()`:
  `vulnerability` for the entry, `assessment_request` for the pen test request and the group item
  table for the remediation tasks; a path with `list` makes its section a list and a task linked more
  than once is taken once.
- `BOFASIKafkaProducerVamp.js` — `sendPayload(payload, record)`: topic sys_id from
  `usem.vamp.kafka.topic_sys_id`, key `<table>.<sys_id>`, `sn_ih_kafka.ProducerV2().send(...)`
  asynchronous, no headers, no schema; the response shown with `gs.addInfoMessage`.
- `VAMP Field Check - Background Script.js` — generated from the workbook by `extract_mapping.py`.
  Read only, global scope. For every sheet row it looks for the field behind the JSON field name:
  same name, then the sheet's label, then the `u_` variant; checks the type and prints the two
  property values to use. `resolve_1804.py` runs it and writes `field_resolution.json`,
  `field_check_output.txt` and `properties.json`.

## Error handling, validation and comments (V2.0)
Every function carries a JSDoc header. The rule and the two public methods are the only try/catch
blocks; the private methods throw and the entry point logs one `gs.error` in the form
`<class>: <what failed> for <table> <sys_id> - <reason>` (`no record` as the key when no record was
given). The processor refuses a record that was never fetched or does not exist, a property that is
not configured or holds nothing, a line with more than one "=", without a field name, without a
payload name or with a payload name that is not `<structure>.<field>`, a section that would take
fields from two tables, the same payload name twice in a section, and a section with no path from the
item.
`_validatePayload` then checks the finished message before it is returned: the envelope constants, a
UUID event id, a UTC timestamp, an activity of INSERT / UPDATE / DELETE, `element_count` equal to the
number of findings, every configured section present (a list where the sheet is one to many), every
configured field present as a string, and nothing else in the message; all problems are named in one
error. A refused build returns `''`, so the rule never calls the producer. The producer refuses an
empty topic property or one that is not a sys_id, and a payload that is empty, not JSON, without
envelope or findings, or whose `element_count` does not match.

## Tests (`test_1804.py`, 87 checks per run, run twice in one invocation)
A the linked item: the property equals the resolution, the envelope, the sheet's structure names in
sheet order, the fields per section, both remediation tasks in number order with their own values,
the entry's sub category id read through the extended class, the configuration item as a display
value, the not-found message. B an item with nothing linked: an empty task list and `""` everywhere.
C the rule on a real update and a real insert. D rendering by dictionary type, including a date, and a
reference whose record is gone. E the error paths and the validation, including every refusal above,
the sections the property alone yields and the producer's refusals. **F how many remediation tasks the
item has**: two, one, none, a link whose task is gone, the two links swapped to prove the order comes
from the task number, and the proof that the other three sections do not change with the count.

## Fixtures (`fixtures_1804.py`)
Adds the sheet's custom fields to the vulnerability tables as stand-ins for the client's
(`u_vuln_sub_cat_id` on `sn_vul_app_vul_entry` — deliberately on the extended table only —
`u_avul_record_url` and `u_primary_ait` on the remediation task, `u_verification_status` and
`u_avit_record_url` on the item, `u_assessment_id` on the pen test request), under the global Default
set, never delivered. Then the linked item with an entry of the extended class, a release with a
Primary AIT, a CI, a pen test request, an exception approval, a consequence and **two** remediation
tasks, and the bare item.

## Drivers
`build_1804.py` (set `SNOWUSEMTP-1804_MS_VAMP AVIT Outbound Payload_V2.0` in the mirror application,
its Default set created when missing, records captured explicitly, scope audit), `resolve_1804.py`,
`test_1804.py` (run 1 writes the sample), `export_1804.py` (native export, upload proof, archive),
`package_1804.py` (`VAMP AVIT Outbound Payload - Records.xml`, topic property empty, stamps removed,
scripts asserted equal to the repository files), `check_1804.py` (workbook against mapping, sections,
field-check rows, resolution, the property, record XML, sample structure and keys, and the processor's
own wiring: every section must be the item table or carry a path, and only the remediation tasks a
list).

## Delivery
The update set XML imports on the client instance as it is (the PDI holds a mirror of the client
integration application `x_boar_bofa_usem_1`, same scope name and application sys_id); the record XML
is the alternative. After import the client sets `usem.vamp.kafka.topic_sys_id` to the sys_id of its
Kafka topic record: `export_1804.py` empties that property and captures it before exporting, so both
files deliver it empty and nothing points at a topic of the development instance.

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
