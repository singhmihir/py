# SNOWUSEMTP-1624 — Consequence outbound payload to CDP

Same build as SNOWUSEMTP-1804 (VAMP), applied to the consequence table: one rule, the payload processor
and two properties, the CDP architecture (topic property, one field property on the
consequence table, envelope and rendering in code). The payload names are exactly the JSON field
names of the tab "Outbound to CDP (consequence)" of `Terminology per Source Consolidation.xlsx`
(kept here; the two `sys_mod_count` rows carry no "CDP Required = Yes" and are left out, as for the
CDP remediation task payload); the ServiceNow field behind each name is resolved on the instance by
the field-check script, never assumed.

Versions: V1.0 placed the scripts and properties in the integration application `x_boar_bofa_usem_1`
(the rule would have run across scopes); V1.1 moved the five records into the consequence application
`x_boar_bofa_usem_0` (BOFA USEM Consequence, sys_id 488be1cd2b1247102b30f8e14391bf0c) after the
captures from the client forms, still built in the PDI's stand-in scope and re-pointed in the record
XML; V1.2 is built in a PDI mirror of the client application itself (same scope name,
same sys_id, tables `x_boar_bofa_usem_0_consequence` and `x_boar_bofa_usem_0_consequence_rule`), so the
native update set export and the record XML both carry the client names and import on the client
instance as they are, and adds error handling, payload validation and function comments. **V1.3**
names the sections as the sheet and the client sample do (`consequence`, `rule`), sends choices as labels and a
reference whose record is gone as `""`, reads the field types in a way a scoped application may use whoever
calls it, refuses every malformed line of the field property, and deletes the records V1.0/V1.1 delivered under
other sys_ids (see *Earlier sys_ids*). **V1.4** accepts only the INSERT and UPDATE the rule fires on. **V1.5**
(current) sends through the one Kafka producer shared with the remediation tasks, `BOFA_SI_KafkaProducerV2` of the
integration application (see `stories/kafka-producer-v2`), which reads the consequence topic property; the
consequence's own producer is deleted. The processor again names the configured fields the instance lacks in a
second info message, after the payload.

## Records
- `BOFA_BR_Consequence_CdpOutbound.js` — after insert/update rule on `x_boar_bofa_usem_0_consequence`,
  order 100, no condition: processor → `x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2` (the producer shared with
  the remediation tasks), one try/catch with one `gs.error`; an empty payload (a build the processor refused)
  stops the rule before the producer.
- `BOFASIConsequenceOutboundProcessor.js` — `buildPayload(record)` returns the JSON text
  `{envelope, consequences: [{consequence: {...}, rule: {...}}]}` (the section names of the sheet and of the
  client sample, set in `SECTIONS` of `initialize()` with the reference field `u_rule` that leads to the rule;
  the array key `consequences` as in the client sample) and shows it with `gs.addInfoMessage` on the record.
  Envelope as CDP (topic
  `sn_usem_consequence_outbound`, namespace `com.bofa.usem`, versions 1.0.0, UUID event id, UTC timestamp,
  element_count 1, element_activity from `record.operation()`). Every field comes from the one property
  `x_boar_bofa_usem_0.usem.consequence.fields.x_boar_bofa_usem_0_consequence` in the CDP line format
  (`servicenow_field=payload_field,`): the consequence's own fields plain, the rule's as
  `x_boar_bofa_usem_0_consequence_rule.<field>`. Values by dictionary type: a reference as its display value
  and `""` when its record is gone (never the sys_id); the configuration item (a document id whose table is the
  Class field) as the display value of its record (`Trade Processing Portal`, not the platform's
  `Business Application: Trade Processing Portal`), looked up in `cmdb_ci` by sys_id when the Class field is
  empty or names another class than the CI's, `""` when no CI is found; an integer with choices as its label
  and a plain count as stored (a display value carries the user's thousands separator); strings, choices,
  booleans (`true`/`false`) and lists as displayed, so choice fields give their labels as in the client sample
  (`Change Frozen`); table names and conditions as stored; a journal field as its latest entry without the
  date and author line the platform puts above it; date/times `MM-dd-yyyy HH:mm:ss`; display markup
  `[code]...[/code]` as its visible text; a field missing on the table, an empty field or a consequence without
  a rule gives `""`. Field types are read from a record of the table the processor opens itself: a scoped
  application may not read the dictionary descriptor of a record handed over from inside a function of a
  global script (measured on the PDI: `StatefulElementDescriptor ... not allowed in scope`).
- The producer is the shared `BOFA_SI_KafkaProducerV2` (x_boar_bofa_usem_1, delivered with its own record XML):
  its table map gives `x_boar_bofa_usem_0_consequence` the topic property
  `x_boar_bofa_usem_0.usem.consequence.kafka.topic_sys_id`, which stays in this application; key
  `<table>.<sys_id>`, asynchronous send, payload validated before it goes, one `gs.error` per failure
  (`BOFA_SI_KafkaProducerV2: message not sent for <table> <sys_id> - <reason>`). The consequence's own producer
  of V1.2-V1.4 (`BOFASIKafkaProducerConsequence`) is deleted by this version.
- `Consequence Field Check - Background Script.js` — generated from the workbook by
  `extract_mapping.py` (with `consequence_mapping.json`). Read only, global scope. For every sheet row
  it looks for the field behind the payload name: the sheet's field name, then the payload name, then
  the sheet's label, then the `u_` variant, then the name without its `u_` or `x_` prefix (the sheet
  names the rule fields `x_applies_to`, `x_name` and so on); prints one line per row, the property
  value to use and the rows to raise. `resolve_1624.py` runs it on the PDI (the stand-in AIT table
  renamed to the client's in the report) and writes `field_resolution.json`, `field_check_output.txt`
  and `properties.json`. On the PDI every row resolves: the sheet's `u_state` resolves to `state` by
  the payload name, the rule's `x_` names to the plain names, the rest by name.

## Error handling and payload validation
Every function in the rule and the processor carries a JSDoc header (purpose, parameters, return, what it
throws). The rule and `buildPayload` are the only try/catch blocks; the private methods throw and the entry point logs one `gs.error`
in the form `<class>: <what failed> for <table> <sys_id> - <reason>` (`no record` as the key when no record
was given). Processor, `buildPayload`: `_requireRecord` refuses a missing record and a record that was never
fetched or does not exist; `_fieldMapping` refuses a table without a section, a property that is not
configured or holds no field, and a line with more than one `=`, without a field name, without a payload
name, with a field that is neither `<field>` nor `<table>.<field>` (`a.b.c`, `.name`), of a table that is no
section of the payload (a dot-walk such as `u_rule.name` included), or naming a payload field of its section
twice (the line is quoted); `_validatePayload` checks the finished payload
before it is returned (envelope keys and constants, UUID event id, UTC timestamp, activity INSERT or
UPDATE, element count 1, one consequence element, every configured section and payload name
present as a string, no extra sections or keys, the consequence section not empty) and lists every
problem in one error (`payload invalid: ...; ...`). A refused build returns `''`, so the rule never calls
the producer. The shared producer then refuses no record or one that does not exist, an empty topic property or
one that is not a sys_id, and a payload that is empty, not JSON, without its envelope fields, or whose element
count differs from the consequences carried (see `stories/kafka-producer-v2`). Info messages on the record: the
payload, and the configured fields the instance lacks (sent as `""`).

## Earlier sys_ids
V1.0/V1.1 were built in the PDI's stand-in scope and delivered as record XML under the stand-in's sys_ids;
V1.2 was built in the mirror application under new ones. An instance that loaded V1.1 and then V1.2 holds
two rules and two copies of each script include (same API names), and the V1.2 properties were refused
there (property names are unique), leaving the V1.1 values in place. V1.3 keeps the V1.2 sys_ids and
deletes the five earlier ones (`prior_records.json`): the update set carries a DELETE for each, recorded
before the current records so that on commit the earlier property goes before the current one of the same
name is written; the record XML lists them first as `action="DELETE"` elements (Import XML deletes such a
record and ignores a sys_id it does not hold, measured on the PDI). On an instance without the earlier
records the deletions do nothing. Where an earlier property was edited after its import (the topic, for
instance), the platform's preview flags its deletion as *Found a local update that is newer than this one*:
accept the remote update so that the earlier property goes.

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
`table`, `valid_from`, `valid_to`; the consequence table also has a journal (`u_work_notes`) to show that the
latest entry is sent. Then two rules (CQR0001001 with every field filled and the checkbox on, CQR0001002 a draft
with the checkbox off and no end date, each with its own author and times), a business application CI and an AIT,
and five consequences (`fixtures.json`): CON0001001 linked to the first rule with every field filled and two
work notes a minute apart, CON0001002 bare, CON0001003 whose rule and AIT are gone and whose Class field is
empty, CON0001004 linked to the second rule with a Class field naming another class than its CI's, CON0001005
whose CI is gone.
`getRefRecord()` on a document id returns the record its class field names, and null when the value or
the class is empty; a column type change on a scoped table runs inside the scope (`ui.js(..., scope=...)`),
a cross-scope `deleteRecord()` on a dictionary row returns false.

## Drivers
`build_1624.py` (set `SNOWUSEMTP-1624_MS_Consequence CDP Outbound Payload_V1.4` in the mirror application,
its Default set created when missing, stale properties removed, the earlier sys_ids captured as deletions
(each created under its old sys_id and deleted again; a current property of the same name steps aside for
the moment), records captured explicitly, scope audit), `fixtures_1624.py` (two rules with their own
authors and times, the checkbox on and off; a linked, a bare, a dangling (rule and AIT gone, CI without
class), a misclassed (class field naming another class) and a ghost (CI gone) consequence), `test_1624.py`
(100 checks over two runs in one invocation, 24 exact refusal lines among them, every log check reading only the lines of its own script: A every
fixture from inside a function of a global script and directly, every value against the value worked out
through REST plus literals; B the rule on a real update and a real insert; C every refusal of the processor
and the producer with its exact line; D properties, deployed scripts equal to the repository, hygiene; run 1
writes the sample), `export_1624.py` (topic property emptied, native export, deletions recorded before the
current records, upload with the platform's preview, archive; importable on the client as is),
`package_1624.py` (`Consequence CDP Outbound Payload - Records.xml`: the deletions, then the five records,
topic property empty, stamps removed, scripts asserted equal to the repository files), `check_1624.py`
(workbook against mapping, field-check rows, resolution, property, record XML, sample payload keys and
sections, client sample sections, processor sections), `attach_1624.py` (files and a comment to the
drop-box incident). `samples/` holds the client's sample from the story and a payload built from the
linked fixture.

## Delivery
Attached to the drop-box incident: the update set XML (`Consequence CDP Outbound Payload - Update
Set.xml`), the record XML, the sample payload and the field-check script. After import the client sets
`x_boar_bofa_usem_0.usem.consequence.kafka.topic_sys_id` to the sys_id of the Kafka topic record for
`sn_usem_consequence_outbound`: the update set and the record XML both carry it empty (V1.2's update set
carried the PDI's placeholder id). Every import of a later version empties it again, so it is set after each
import.

Open point for the client: the acceptance criteria also mention a scheduled job every 15 minutes,
which this build does not add (the rule sends on every insert and update, as VAMP does).

The PDI has no Stream Connect: the producer's send fails there and is caught (`message not sent for
<key> - ...`), which is what the rule tests look for after the processor message.
