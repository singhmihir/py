# SNOWUSEMTP-1804 — VAMP outbound payload for application vulnerable items

First iteration (payload still under discussion with the client): one rule, two script includes and
two properties, the CDP architecture (topic property, one field property on the application
vulnerable item table, envelope and rendering in code). The payload names are exactly column B of
the sheet "SN to VAMP" (`SN to VAMP Mapping.xlsx`, kept here); the ServiceNow field behind each name
is resolved on the instance by the field-check script, never assumed. Built and tested in the
stand-in scope on the PDI, delivered as import-ready record XML for the client application
`x_boar_bofa_usem_1`.

- `BOFA_BR_AVIT_VampOutbound.js` — after insert/update rule on `sn_vul_app_vulnerable_item`, order
  100, no condition yet: processor → producer, one try/catch.
- `BOFASIVampOutboundProcessor.js` — `buildPayload(record)` returns the JSON text
  `{envelope, findings: [{sn_vul_app_vulnerable_item, sn_vul_app_vul_entry, sn_vul_app_vulnerability,
  sn_vul_pen_test_assessment_request}]}` (sections keyed by table name) and shows it with
  `gs.addInfoMessage` on the item (lines without semicolon, on purpose, to spot them later); a second
  message names any configured field the instance does not have. Envelope as CDP (topic
  `sn_usem_verification_outbound`, namespace `com.bofa.usem`, versions 1.0.0, UUID event id, UTC
  timestamp, element_count 1, element_activity from `current.operation()`). The four sections are
  the four sheet tables: the item itself, its `vulnerability` (sn_vul_app_vul_entry), the task reached
  through `sn_vul_app_m2m_vul_group_item` (sn_vul_app_vulnerability, carries `primary_ait`) and its
  `assessment_request` (sn_vul_pen_test_assessment_request). Every field comes from the one property
  `usem.vamp.fields.sn_vul_app_vulnerable_item` in the CDP line format and parser
  (`servicenow_field=payload_field,`): the ServiceNow field on the left, the sheet's payload name on
  the right, the item's own fields plain, the other tables' fields as `<table>.<field>`, which the
  code places in that table's section. Values as the sheet types them: references as the sys_id,
  integers and strings as stored, date/times `MM-dd-yyyy HH:mm:ss`; a field missing on the table, an
  empty field or a section without a record is sent as `""`.
- `BOFASIKafkaProducerVamp.js` — `sendPayload(payload, record)`: topic sys_id from
  `usem.vamp.kafka.topic_sys_id`, key `<table>.<sys_id>`, `sn_ih_kafka.ProducerV2().send(...)`
  asynchronous, no headers, no schema; the response object (`delivery`, and `partition`/`offset`
  when synchronous) shown with `gs.addInfoMessage`; one try/catch with one `gs.error`.
- `VAMP Field Check - Background Script.js` — generated from the workbook by `extract_mapping.py`
  (with `vamp_mapping.json`). Read only, global scope. For every sheet row it looks for the field
  behind the payload name: same name, then the sheet's label, then the `u_` variant; checks the type;
  prints one line per row, the property value to use and the rows to raise. `resolve_1804.py` runs it
  on the PDI and writes `field_resolution.json`, `field_check_output.txt` and `properties.json`. On
  the PDI: `configuration_item` resolves to `cmdb_ci` by label (reference to cmdb_ci); four rows have
  no field here and keep the sheet name on the left until the client names the field:
  `sn_vul_app_vul_entry.number`, `sn_vul_app_vulnerability.primary_ait`,
  `sn_vul_app_vulnerable_item.u_verification_status`, `sn_vul_pen_test_assessment_request.u_assessment_id`
  (similar label there: `risk_assessment_id`).
- No payload validation and no comments, as asked for the first iteration.

Drivers: `build_1804.py` (set `SNOWUSEMTP-1804_MS_VAMP AVIT Outbound Payload_V1.5`, fresh set,
properties of earlier versions removed under the scope's Default set, records captured explicitly,
scope audit), `fixtures_1804.py` (two fixture items, rules off: one linked to every source, one
bare), `test_1804.py` (50 checks per run, run twice: the property equals the resolution, the payload
carries exactly the sheet payload names per table and every value, the configuration item as the
sys_id of its CI, the not-found message, the bare item, the rule on a real update and a real insert
with the processor and producer messages, rendering by type), `export_1804.py` (native export,
upload proof, archive — stand-in scope, internal record only), `package_1804.py` (`VAMP AVIT
Outbound Payload - Records.xml`: the five records re-pointed to the client application, topic
property empty, stamps removed), `check_1804.py` (workbook against mapping, field-check rows,
resolution, property, record XML, sample payload keys and processor sections). `samples/` holds a
payload built from the linked fixture.

Earlier versions the same day: V1.0 (sections property plus one field property per section), V1.1
(one property with dotted paths, related sections beyond the sheet), V1.2 (one field property per
sheet table), V1.3 (one property, column B used as the field name, so `configuration_item` never
resolved). V1.4 verifies the field behind every payload name; V1.5 keys the sections by table name.

The PDI has no Stream Connect: the producer's send fails there and is caught (`message not sent for
<key> - ...`), which is what the rule tests look for after the processor message.
