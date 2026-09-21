# SNOWUSEMTP-1624 — Consequence outbound payload to CDP

Same build as SNOWUSEMTP-1804 (VAMP), applied to the consequence table: one rule, two script
includes and two properties, the CDP architecture (topic property, one field property on the
consequence table, envelope and rendering in code). The payload names are exactly the JSON field
names of the tab "Outbound to CDP (consequence)" of `Terminology per Source Consolidation.xlsx`
(kept here; the two `sys_mod_count` rows carry no "CDP Required = Yes" and are left out, as for the
CDP remediation task payload); the ServiceNow field behind each name is resolved on the instance by
the field-check script, never assumed. Built and tested in the stand-in scope on the PDI, delivered
as import-ready record XML for the client consequence application `x_boar_bofa_usem_0` (BOFA USEM
Consequence, sys_id 488be1cd2b1247102b30f8e14391bf0c), which holds the tables
`x_boar_bofa_usem_0_consequence` and `x_boar_bofa_usem_0_consequence_rule`, the rule, the script
includes and the properties (V1.1; V1.0 had placed the scripts and properties in the integration
application `x_boar_bofa_usem_1`, which would have left the rule running across scopes).

- `BOFA_BR_Consequence_CdpOutbound.js` — after insert/update rule on `x_boar_bofa_usem_0_consequence`,
  order 100, no condition: processor → producer, one try/catch.
- `BOFASIConsequenceOutboundProcessor.js` — `buildPayload(record)` returns the JSON text
  `{envelope, consequences: [{x_boar_bofa_usem_0_consequence, x_boar_bofa_usem_0_consequence_rule}]}`
  (sections keyed by table name, the array key `consequences` as in the client sample) and shows it
  with `gs.addInfoMessage` on the record; a second message names any configured field the instance
  does not have. Envelope as CDP (topic `sn_usem_consequence_outbound`, namespace `com.bofa.usem`,
  versions 1.0.0, UUID event id, UTC timestamp, element_count 1, element_activity from
  `current.operation()`). The rule section is the consequence's `u_rule` reference record. Every
  field comes from the one property `usem.consequence.fields.x_boar_bofa_usem_0_consequence` in the
  CDP line format and parser (`servicenow_field=payload_field,`): the consequence's own fields plain,
  the rule's as `x_boar_bofa_usem_0_consequence_rule.<field>`. Values: references as the display
  value; a document id (the client's Configuration item, whose table is its Class field) as the
  display value of the record it points at through `getRefRecord()`, so `Trade Processing Portal`
  rather than the platform's `Business Application: Trade Processing Portal`, and `""` when the
  value or its class is missing; choices, integers, booleans, table names, conditions and strings as
  stored; date/times `MM-dd-yyyy HH:mm:ss`; a field missing on the table, an empty field or a
  consequence without a rule is sent as `""`.
- `BOFASIKafkaProducerConsequence.js` — `sendPayload(payload, record)`: topic sys_id from
  `usem.consequence.kafka.topic_sys_id`, key `<table>.<sys_id>`, `sn_ih_kafka.ProducerV2().send(...)`
  asynchronous, no headers, no schema; the response shown with `gs.addInfoMessage`; one try/catch
  with one `gs.error`.
- `Consequence Field Check - Background Script.js` — generated from the workbook by
  `extract_mapping.py` (with `consequence_mapping.json`). Read only, global scope. For every sheet row
  it looks for the field behind the payload name: the sheet's field name, then the payload name, then
  the sheet's label, then the `u_` variant, then the name without its `u_` or `x_` prefix (the sheet
  names the rule fields `x_applies_to`, `x_name` and so on); prints one line per row, the property
  value to use and the rows to raise. `resolve_1624.py` runs it on the PDI (client table names swapped
  for the stand-in tables while it runs) and writes `field_resolution.json`, `field_check_output.txt`
  and `properties.json`. On the PDI every row resolves: the sheet's `u_state` resolves to `state` by
  the payload name, the rule's `x_` names to the plain names, the rest by name.
- No payload validation and no comments, as for VAMP.

Captured from the client forms on 21 Sep (screenshots): the consequence form shows Number, AIT
(reference), Configuration item with a Class field (a document id and its table-name field), State,
Consequence Level (`level_1`, a string), Enforcement Status (choice), Rule (reference to
`x_boar_bofa_usem_0_consequence_rule`), the two effective dates, Accountable Party and Comments; the
rule form shows Number, Valid from, Valid to, Global Exception (checkbox), Conditions (condition
builder), Name, Comments, State, Applies to and Table (a table name, shown as `Consequence
[x_boar_bofa_usem_0_consequence]`); the application record is `BOFA USEM Consequence`, scope
`x_boar_bofa_usem_0`, JavaScript mode ECMAScript 2021, application administration off. The rule
section's field names stay as the PDI resolved them (`name`, `state`, `applies_to`, ...); the
field-check script on the client instance confirms them.

Fixtures (`fixtures_1624.py`): the stand-in consequence table on the PDI carried only `number`,
`state` and `u_consequence_level`; the driver adds the sheet's other fields to it (strings, two
date/times, the `u_enforcement_status` choice, `cmdb_ci` as a document id with the table-name field
`u_class` as its Class, as on the client form, references to the stand-in AIT table and a new stand-in
rule table `x_196061_bofasim_consequence_rule` with the sheet's rule fields) under the global Default
update set, never delivered; a column type change on a scoped table has to run inside the scope
(`ui.js(..., scope=...)`), a cross-scope `deleteRecord()` on the dictionary row returns false; then
one rule record, one consequence linked to the rule, a business application CI and an AIT with every
field filled, and one bare consequence. `getRefRecord()` on a document id returns the record its
class field names, and null when the value or the class is empty.

Drivers: `build_1624.py` (set `SNOWUSEMTP-1624_MS_Consequence CDP Outbound Payload_V1.1`, fresh set,
records captured explicitly, scope audit; the client prefix `x_boar_bofa_usem_0` swapped for the
stand-in), `test_1624.py` (44 checks per run, run twice in one invocation: the property equals the
resolution, the payload carries exactly the sheet payload names per table and every value, references
and the document id as display values, the rule section through `u_rule`, the bare consequence, the
rule on a real update and a real insert with the processor and producer messages, rendering by type;
run 1 writes the sample), `export_1624.py` (native export, upload proof, archive — stand-in scope,
internal record only), `package_1624.py` (`Consequence CDP Outbound Payload - Records.xml`: the five
records re-pointed to the client consequence application, topic property empty, stamps removed),
`check_1624.py` (workbook against mapping, field-check rows, resolution, property, record XML, sample
payload keys, client sample keys and processor sections). `samples/` holds the client's sample from the
story and a payload built from the linked fixture.

Open point for the client: the acceptance criteria also mention a scheduled job every 15 minutes,
which this build does not add (the rule sends on every insert and update, as VAMP does).

The PDI has no Stream Connect: the producer's send fails there and is caught (`message not sent for
<key> - ...`), which is what the rule tests look for after the processor message.
