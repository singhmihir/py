# SNOWUSEMTP-1804 — VAMP outbound payload for application vulnerable items

First iteration (payload still under discussion with the client): one rule, two script includes and
two properties, the CDP architecture (topic property, one field property on the application
vulnerable item table, envelope and rendering in code), the payload fields exactly the rows of the
sheet "SN to VAMP" (`SN to VAMP Mapping.xlsx`, kept here). Built and tested in the stand-in scope on the PDI, delivered as
import-ready record XML for the client application `x_boar_bofa_usem_1`.

- `BOFA_BR_AVIT_VampOutbound.js` — after insert/update rule on `sn_vul_app_vulnerable_item`, order
  100, no condition yet: processor → producer, one try/catch.
- `BOFASIVampOutboundProcessor.js` — `buildPayload(record)` returns the JSON text
  `{envelope, findings: [{finding, tpe, remediation_task, ptreq}]}` and shows it with
  `gs.addInfoMessage` on the item (line without semicolon, on purpose, to spot it later). Envelope as
  CDP (topic `sn_usem_verification_outbound`, namespace `com.bofa.usem`, versions 1.0.0, UUID event
  id, UTC timestamp, element_count 1, element_activity from `current.operation()`). The four
  sections are the four sheet tables: `finding` the item itself, `tpe` the item's `vulnerability`
  (sn_vul_app_vul_entry), `remediation_task` the task reached through
  `sn_vul_app_m2m_vul_group_item` (sn_vul_app_vulnerability, carries `primary_ait`), `ptreq` the
  item's `assessment_request`. Every field comes from the one property
  `usem.vamp.fields.sn_vul_app_vulnerable_item` in the CDP line format and parser
  (`servicenow_field=json_field,`): the item's own fields plain, the other tables' fields as
  `<table>.<field>`, which the code places in that table's section; values rendered as the sheet
  types them: references as the sys_id, integers and strings as stored, date/times `MM-dd-yyyy HH:mm:ss`;
  a field missing on the table, an empty field or a section without a record is sent as `""`.
- `BOFASIKafkaProducerVamp.js` — `sendPayload(payload, record)`: topic sys_id from
  `usem.vamp.kafka.topic_sys_id`, key `<table>.<sys_id>`, `sn_ih_kafka.ProducerV2().send(...)`
  asynchronous, no headers, no schema; the response object (`delivery`, and `partition`/`offset`
  when synchronous) shown with `gs.addInfoMessage`; one try/catch with one `gs.error`.
- `extract_mapping.py` reads the workbook and generates `vamp_mapping.json` (the 13 rows),
  `properties.json` (topic plus the one field property, names exactly as the sheet) and
  `VAMP Field Check - Background Script.js`, a read-only background script that checks every sheet
  row against the dictionary of the instance it runs on (table exists, field exists, type as the
  sheet says, reference target and label) and lists what to raise. On the PDI it flags five sheet
  fields that do not exist here: `sn_vul_app_vul_entry.number`, `sn_vul_app_vulnerability.primary_ait`,
  `sn_vul_app_vulnerable_item.configuration_item`, `sn_vul_app_vulnerable_item.u_verification_status`,
  `sn_vul_pen_test_assessment_request.u_assessment_id`; the client instance decides what stands.
- No payload validation and no comments, as asked for the first iteration.

Drivers: `build_1804.py` (set `SNOWUSEMTP-1804_MS_VAMP AVIT Outbound Payload_V1.3`, fresh set,
properties of earlier versions removed under the scope's Default set, records captured explicitly,
scope audit), `fixtures_1804.py` (two fixture items, rules off: one linked to every source, one bare),
`test_1804.py` (47 checks per run, run twice: the field property equals the sheet rows, the payload
carries exactly the sheet fields per table and every value, the bare item, the rule on a real update
and a real insert with the processor and producer messages, rendering by type), `export_1804.py`
(native export, upload proof, archive — stand-in scope, internal record only), `package_1804.py`
(`VAMP AVIT Outbound Payload - Records.xml`: the five records re-pointed to the client application,
topic property empty, stamps removed), `check_1804.py` (workbook rows against properties.json, the
record XML, the field-check script and the sample payload). `samples/` holds a payload built from
the linked fixture.

V1.0 (sections property plus one field property per section), V1.1 (one property with dotted paths,
related sections added beyond the sheet) and V1.2 (one field property per sheet table) were replaced
the same day: the payload must hold exactly the sheet fields, references as sys_ids, the AIT from
the task's `primary_ait`, and one property on the item table referring to the other tables.

The PDI has no Stream Connect: the producer's send fails there and is caught (`message not sent for
<key> - ...`), which is what the rule tests look for after the processor message.
