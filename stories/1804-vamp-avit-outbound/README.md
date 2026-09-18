# SNOWUSEMTP-1804 — VAMP outbound payload for application vulnerable items

First iteration (payload still under discussion with the client): one rule, two script includes and
ten properties, built and tested in the stand-in scope on the PDI and delivered as import-ready
record XML for the client application `x_boar_bofa_usem_1`.

- `BOFA_BR_AVIT_VampOutbound.js` — after insert/update rule on `sn_vul_app_vulnerable_item`, order
  100, no condition yet: processor → producer, one try/catch.
- `BOFASIVampOutboundProcessor.js` — `buildPayload(record)` returns the JSON text
  `{envelope, findings: [{finding, tpe, remediation_task, ait, ci, exception, consequence, ptreq}]}`
  and shows it with `gs.addInfoMessage` on the item (line without semicolon, on purpose, to spot it
  later). Envelope as CDP (topic `sn_usem_verification_outbound`, namespace `com.bofa.usem`, versions
  1.0.0, UUID event id, UTC timestamp, element_count 1, element_activity from `current.operation()`).
  Sections come from `usem.vamp.avit.sections` (`json_key=path`, dot-walked from the item; empty
  path = the item, `remediation_task` = the task reached through `sn_vul_app_m2m_vul_group_item`);
  each section's fields from `usem.vamp.avit.fields.<json_key>` in the CDP line format
  (`servicenow_field=json_field,`), rendered by dictionary type, dates `MM-dd-yyyy HH:mm:ss`, a
  field missing on the table, an empty field or a section without a record sent as `""`.
- `BOFASIKafkaProducerVamp.js` — `sendPayload(payload, record)`: topic sys_id from
  `usem.vamp.kafka.topic_sys_id`, key `<table>.<sys_id>`, `sn_ih_kafka.ProducerV2().send(...)`
  asynchronous, no headers, no schema; the response object (`delivery`, and `partition`/`offset`
  when synchronous) shown with `gs.addInfoMessage`; one try/catch with one `gs.error`.
- `properties.json` — the ten property values and descriptions (client prefix). The sheet
  "SN to VAMP" gives the finding, tpe, remediation task and ptreq fields; ait, ci, exception and
  consequence carry starter lists until the client names their fields.
- No payload validation and no comments, as asked for the first iteration.

Drivers: `build_1804.py` (set `SNOWUSEMTP-1804_MS_VAMP AVIT Outbound Payload_V1.0`, scope audit),
`fixtures_1804.py` (two fixture items, rules off: one linked to every section source, one bare),
`test_1804.py` (53 checks per run, run twice: payload shape and every section value, the bare item,
the rule on a real update and a real insert with the processor and producer messages),
`export_1804.py` (native export, upload proof, archive — stand-in scope, internal record only),
`package_1804.py` (`VAMP AVIT Outbound Payload - Records.xml`: the 13 records re-pointed to the
client application, topic property empty, stamps removed). `samples/` holds a payload built from
the linked fixture.

The PDI has no Stream Connect: the producer's send fails there and is caught (`message not sent for
<key> - ...`), which is what the rule tests look for after the processor message.
