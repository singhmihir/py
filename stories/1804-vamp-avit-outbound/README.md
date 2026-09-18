# SNOWUSEMTP-1804 — VAMP outbound payload for application vulnerable items

First iteration (payload still under discussion with the client): one rule, two script includes and
two properties, the CDP architecture (topic property, one field-mapping property per table, envelope
and rendering in code), built and tested in the stand-in scope on the PDI and delivered as
import-ready record XML for the client application `x_boar_bofa_usem_1`.

- `BOFA_BR_AVIT_VampOutbound.js` — after insert/update rule on `sn_vul_app_vulnerable_item`, order
  100, no condition yet: processor → producer, one try/catch.
- `BOFASIVampOutboundProcessor.js` — `buildPayload(record)` returns the JSON text
  `{envelope, findings: [finding]}` and shows it with `gs.addInfoMessage` on the item (line without
  semicolon, on purpose, to spot it later). Envelope as CDP (topic `sn_usem_verification_outbound`,
  namespace `com.bofa.usem`, versions 1.0.0, UUID event id, UTC timestamp, element_count 1,
  element_activity from `current.operation()`). The finding comes from the property
  `usem.vamp.finding.fields.sn_vul_app_vulnerable_item` in the CDP line format
  (`servicenow_field=json_field,`, CDP parser): the ServiceNow field may dot-walk from the item
  (`cmdb_ci.name`; `remediation_task.<field>` reaches the task through
  `sn_vul_app_m2m_vul_group_item`), a dot in the json field nests it (`ci.name` → `{ci: {name}}`),
  so the delivered value produces the objects finding, tpe, remediation_task, ait, ci, exception,
  consequence, ptreq. Rendering by dictionary type as CDP, dates `MM-dd-yyyy HH:mm:ss`, a field
  missing on the table, an empty field or an empty reference on the path sent as `""`.
- `BOFASIKafkaProducerVamp.js` — `sendPayload(payload, record)`: topic sys_id from
  `usem.vamp.kafka.topic_sys_id`, key `<table>.<sys_id>`, `sn_ih_kafka.ProducerV2().send(...)`
  asynchronous, no headers, no schema; the response object (`delivery`, and `partition`/`offset`
  when synchronous) shown with `gs.addInfoMessage`; one try/catch with one `gs.error`.
- `properties.json` — the two property values and descriptions (client prefix). The sheet
  "SN to VAMP" gives the finding, tpe, remediation task and ptreq lines; ait, ci, exception and
  consequence carry starter lines until the client names their fields.
- No payload validation and no comments, as asked for the first iteration.

Drivers: `build_1804.py` (set `SNOWUSEMTP-1804_MS_VAMP AVIT Outbound Payload_V1.1`, fresh set, the
nine section properties of V1.0 removed under the scope's Default set, records captured explicitly,
scope audit), `fixtures_1804.py` (two fixture items, rules off: one linked to every source, one
bare), `test_1804.py` (55 checks per run, run twice: the two properties, payload shape with the
nested sections and every value, the bare item, the rule on a real update and a real insert with the
processor and producer messages), `export_1804.py` (native export, upload proof, archive — stand-in
scope, internal record only), `package_1804.py` (`VAMP AVIT Outbound Payload - Records.xml`: the
five records re-pointed to the client application, topic property empty, stamps removed).
`samples/` holds a payload built from the linked fixture.

V1.0 (same day) had a sections property plus one field property per section; replaced by V1.1 on
Mihir's request to keep the CDP architecture.

The PDI has no Stream Connect: the producer's send fails there and is caught (`message not sent for
<key> - ...`), which is what the rule tests look for after the processor message.
