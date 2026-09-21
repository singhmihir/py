# SNOWUSEMTP-1624 — Consequence outbound payload to CDP

Same build as SNOWUSEMTP-1804 (VAMP), applied to the consequence table: one rule, two script
includes and two properties, the CDP architecture (topic property, one field property on the
consequence table, envelope and rendering in code). The payload names are exactly the JSON field
names of the tab "Outbound to CDP (consequence)" of `Terminology per Source Consolidation.xlsx`
(kept here; the two `sys_mod_count` rows carry no "CDP Required = Yes" and are left out, as for the
CDP remediation task payload); the ServiceNow field behind each name is resolved on the instance by
the field-check script, never assumed.

Versions: V1.0 placed the scripts and properties in the integration application `x_boar_bofa_usem_1`
(the rule would have run across scopes); V1.1 moved the five records into the consequence application
`x_boar_bofa_usem_0` (BOFA USEM Consequence, sys_id 488be1cd2b1247102b30f8e14391bf0c) after the
captures from the client forms, still built in the PDI's stand-in scope and re-pointed in the record
XML; **V1.2** (current) is built in a PDI mirror of the client application itself (same scope name,
same sys_id, tables `x_boar_bofa_usem_0_consequence` and `x_boar_bofa_usem_0_consequence_rule`), so the
native update set export and the record XML both carry the client names and import on the client
instance as they are, and adds error handling, payload validation and function comments.

## Records
- `BOFA_BR_Consequence_CdpOutbound.js` — after insert/update rule on `x_boar_bofa_usem_0_consequence`,
  order 100, no condition: processor → producer, one try/catch with one `gs.error`; an empty payload
  (a build the processor refused) stops the rule before the producer.
- `BOFASIConsequenceOutboundProcessor.js` — `buildPayload(record)` returns the JSON text
  `{envelope, consequences: [{x_boar_bofa_usem_0_consequence, x_boar_bofa_usem_0_consequence_rule}]}`
  (sections keyed by table name, the array key `consequences` as in the client sample) and shows it
  with `gs.addInfoMessage` on the record; a second message names any configured field the instance
  does not have. Envelope as CDP (topic `sn_usem_consequence_outbound`, namespace `com.bofa.usem`,
  versions 1.0.0, UUID event id, UTC timestamp, element_count 1, element_activity from
  `record.operation()`). The rule section is the consequence's `u_rule` reference record. Every
  field comes from the one property `x_boar_bofa_usem_0.usem.consequence.fields.x_boar_bofa_usem_0_consequence`
  in the CDP line format and parser (`servicenow_field=payload_field,`): the consequence's own fields
  plain, the rule's as `x_boar_bofa_usem_0_consequence_rule.<field>`. Values: references as the display
  value; a document id (the client's Configuration item, whose table is its Class field) as the
  display value of the record it points at through `getRefRecord()`, so `Trade Processing Portal`
  rather than the platform's `Business Application: Trade Processing Portal`, and `""` when the
  value or its class is missing; choices, integers, booleans, table names, conditions and strings as
  stored; date/times `MM-dd-yyyy HH:mm:ss`; a field missing on the table, an empty field or a
  consequence without a rule is sent as `""`.
- `BOFASIKafkaProducerConsequence.js` — `sendPayload(payload, record)`: topic sys_id from
  `x_boar_bofa_usem_0.usem.consequence.kafka.topic_sys_id`, key `<table>.<sys_id>`,
  `sn_ih_kafka.ProducerV2().send(...)` asynchronous, no headers, no schema; the response shown with
  `gs.addInfoMessage`; one try/catch with one `gs.error`.
- `Consequence Field Check - Background Script.js` — generated from the workbook by
  `extract_mapping.py` (with `consequence_mapping.json`). Read only, global scope. For every sheet row
  it looks for the field behind the payload name: the sheet's field name, then the payload name, then
  the sheet's label, then the `u_` variant, then the name without its `u_` or `x_` prefix (the sheet
  names the rule fields `x_applies_to`, `x_name` and so on); prints one line per row, the property
  value to use and the rows to raise. `resolve_1624.py` runs it on the PDI (the stand-in AIT table
  renamed to the client's in the report) and writes `field_resolution.json`, `field_check_output.txt`
  and `properties.json`. On the PDI every row resolves: the sheet's `u_state` resolves to `state` by
  the payload name, the rule's `x_` names to the plain names, the rest by name.

## Error handling and payload validation (V1.2)
Every function in the rule and the two script includes carries a JSDoc header (purpose, parameters,
return, what it throws). The rule and the two public methods are the only try/catch blocks; the
private methods throw and the entry point logs one `gs.error` in the form
`<class>: <what failed> for <table> <sys_id> - <reason>` (`no record` as the key when no record was
given). Processor, `buildPayload`: `_requireRecord` refuses a missing record and a record that was
never fetched or does not exist; `_fieldMapping` refuses a property that is not configured, holds no
field, or holds a line without a field name (the line is quoted); `_sectionRecord` refuses a table
outside the property; `_validatePayload` checks the finished payload before it is returned (envelope
keys and constants, UUID event id, UTC timestamp, activity in INSERT / UPDATE / DELETE, element count 1,
one consequence element, every configured section and payload name present as a string, no extra
sections or keys, the consequence section not empty) and lists every problem in one error
(`payload invalid: ...; ...`). A refused build returns `''`, so the rule never calls the producer.
Producer, `sendPayload`: `_topicSysId` refuses an empty topic property and a value that is not a
sys_id; `_requirePayload` refuses an empty payload, text that is not JSON and JSON without `envelope`
or `consequences`; the Kafka API's own failure is caught by the same block (`message not sent for
<key> - <reason>`). The info messages (payload, fields not found, Kafka response) stay as in VAMP.

## Captured from the client forms (21 Sep)
The consequence form shows Number, AIT (reference), Configuration item with a Class field (a document
id and its table-name field), State, Consequence Level (`level_1`, a string), Enforcement Status
(choice), Rule (reference to `x_boar_bofa_usem_0_consequence_rule`), the two effective dates,
Accountable Party and Comments; the rule form shows Number, Valid from, Valid to, Global Exception
(checkbox), Conditions (condition builder), Name, Comments, State, Applies to and Table (a table name,
shown as `Consequence [x_boar_bofa_usem_0_consequence]`); the application record is `BOFA USEM
Consequence`, scope `x_boar_bofa_usem_0`, JavaScript mode ECMAScript 2021, application administration
off. The rule section's field names stay as the PDI resolved them (`name`, `state`, `applies_to`, ...);
the field-check script on the client instance confirms them.

## Mirror of the client application on the PDI
The PDI's company code (`glide.appcreator.company.code`, 2055194) gives every application created
there the vendor prefix `x_196061_`, which a scoped property or API name must carry; that prefix was
never in a client file, but it showed in the PDI builds and in the update set exports. A `sys_app`
record can be inserted directly with the client's scope name and sys_id (`setNewGuidValue`), and
tables, properties and scripts in it work: `fixtures_1624.py` ensures the record (name `BOFA USEM
Consequence`, scope and `source` `x_boar_bofa_usem_0`, vendor prefix `boar`, sys_id
488be1cd2b1247102b30f8e14391bf0c) and creates the two client tables in it with the sheet's fields
under the global Default update set. `source` must equal the scope name: the exporter stamps it on
every `sys_scope` reference in the captured payloads, and a payload captured before the correction
keeps the old value until the record is captured again (`GlideUpdateManager2().saveRecord`). The V1.1
copies in the stand-in scope (rule, two script includes, two properties) were removed under the
stand-in's own set; the VAMP records there are untouched.

## Fixtures (`fixtures_1624.py`)
Consequence table: `number`, `state` (1 Open, 2 Deferred, 3 Closed, 4 Cancelled), `u_consequence_level`,
`u_accountable_party`, `u_comments`, `u_change_freeze_effective_date`, `u_enforcement_status` (choice),
`u_network_isolation_effective_date`, `u_rule` (reference), `u_class` (table name) with `cmdb_ci` as a
document id depending on it, `u_bofa_ait` (reference to the stand-in AIT table), `u_rejection_reason`;
rule table: `number`, `name`, `applies_to`, `comments`, `conditions`, `global_exception`, `state`,
`table`, `valid_from`, `valid_to`. Then one rule record, one consequence linked to the rule, a business
application CI and an AIT with every field filled, and one bare consequence (`fixtures.json`).
`getRefRecord()` on a document id returns the record its class field names, and null when the value or
the class is empty; a column type change on a scoped table runs inside the scope (`ui.js(..., scope=...)`),
a cross-scope `deleteRecord()` on a dictionary row returns false.

## Drivers
`build_1624.py` (set `SNOWUSEMTP-1624_MS_Consequence CDP Outbound Payload_V1.2` in the mirror
application, its Default set created when missing, stale properties removed, records captured
explicitly, scope audit), `test_1624.py` (55 checks per run, run twice in one invocation: A the linked
fixture — property equals the resolution, envelope, sections, every value, references and the document
id as display values, the rule section through `u_rule`; B the bare consequence; C the rule on a real
update and a real insert with the processor and producer messages; D rendering by dictionary type; E
the error paths — unfetched and missing record, empty property, line without a field name, a tampered
payload named problem by problem, the intact payload accepted, empty and non-sys_id topic, empty,
non-JSON and envelope-less payload, producer without a record, one error per refusal and nothing else;
run 1 writes the sample), `export_1624.py` (native export, upload proof, archive; importable on the
client as is), `package_1624.py` (`Consequence CDP Outbound Payload - Records.xml`: the five records,
topic property empty, stamps removed, scripts asserted equal to the repository files),
`check_1624.py` (workbook against mapping, field-check rows, resolution, property, record XML, sample
payload keys, client sample keys and processor sections), `attach_1624.py` (files and a comment to the
drop-box incident). `samples/` holds the client's sample from the story and a payload built from the
linked fixture.

## Delivery
Attached to the drop-box incident: the update set XML (`Consequence CDP Outbound Payload - Update
Set.xml`), the record XML, the sample payload and the field-check script. After import the client sets
`x_boar_bofa_usem_0.usem.consequence.kafka.topic_sys_id` to the sys_id of the Kafka topic record for
`sn_usem_consequence_outbound`: the update set carries the PDI's placeholder id (as VAMP's did), the
record XML leaves it empty.

Open point for the client: the acceptance criteria also mention a scheduled job every 15 minutes,
which this build does not add (the rule sends on every insert and update, as VAMP does).

The PDI has no Stream Connect: the producer's send fails there and is caught (`message not sent for
<key> - ...`), which is what the rule tests look for after the processor message.
