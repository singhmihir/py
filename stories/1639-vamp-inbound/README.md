# SNOWUSEMTP-1639 — Kafka consumer for VAMP findings (`sn_usem_vamp_inbound`)

Status (23 Sep): analysis only. The payload is not given yet; nothing built.

## The story
As an Application Vulnerability Administrator, connect to `sn_usem_vamp_inbound` and consume the messages VAMP
sends. Acceptance criteria: create message replicators in Stream Connect, create a Kafka consumer for the inbound
topic, create an import set table for the inbound data, and map the messages to the import set tables "so that
replicated messages in Kafka can be imported". The AC stops at the staging tables; it does not name the target
records. Related: SNOWUSEMTP-1550 (Increase number of Scheduled Import Templates). Assignee Mihir, reporter Ravali.

On bofadev the topic exists: `sys_kafka_topic` `sn_usem_vamp_inbound`, namespace USEM, 16 partitions, cluster name
`snc.bofasecopsdev.usem.sn_streamconnect.sn_usem_vamp_inbound`, created 15 Sep.

## What Mohammad built (SNOWUSEMTP-1615, CDP IVR detections inbound, received on INC0010013)
Update set `SNOWUSEMTP-1615_Import Detections from CDP to ServiceNow_MK_v1`, application BOFA USEM CDP integration
(`x_boar_bofa_usem_1`), 70 updates. The live chain:

1. Topic alias `sn_usem_ivr_inbound [BOFA USEM CDP integration]` (`sys_sc_topic_alias`).
2. Kafka stream `CDP IVR Inbound` (`sys_kafka_stream`, not in the set, exported separately): topic alias + consumer,
   initial offset latest, message handling dynamic, concurrency 1, run as Mohammad's own user.
3. Kafka script consumer `CDP IVR Inbound` (`sys_kafka_script_consumer`): parses `messages[0]` and calls
   `BofaCDPUtils.processPayload(payload)`.
4. `BofaCDPUtils.processPayload`: inserts a `sys_import_set` (state loading), one row per `payload.findings[i]` in the
   import set table `x_boar_bofa_usem_1_usem_cdp_ivr_inbound_import` (36 columns: envelope fields plus the `dis`,
   `detections`, `vits`, `tpes` sections, each field set by hand), sets the set to loaded and runs
   `GlideImportSetTransformer().transformAllMaps()`.
5. Transform map to `sn_vul_vulnerable_item`: onStart inserts an integration run and starts the VR Detection API
   (`sn_vul.Detection`) with the integration and implementation sys_ids from two properties; onBefore matches the
   host with `sn_vul.ImportHost().hostImport()` (CI lookup rules) and calls `createDetection`, then `ignore = true`;
   onComplete calls `finalizeDetections()`.
6. VR integration records that give the Detection API its integration/implementation/run: third party integration
   `CDP Integration`, integration instance `CDP`, REST integration `USEM Inbound Integration CDP - IVR` (on demand)
   with `IVRCDPIntegrationUtil` (REST polling scaffolding, unused by the Kafka path), two properties holding their
   sys_ids, 11 cross-scope privileges, a module and a form layout, a data source built from a sample Excel.
7. Not in the live path: flow `USEM CDP IVR Inbound` (status draft, copied from "CDP Inbound POC with Transform") and
   action `Trigger Import Set for CDP IVR Inbound` (logs "action started"); business rule `Check CDP state` deleted.

Points to do differently: only `messages[0]` of a batch is processed (the rest are lost); `JSON.parse` unguarded and
the only error handling is a `gs.info`; `processPayload` is called without the data source it expects; field-by-field
mapping hard-coded in the script; the raw message is not kept; no duplicate handling for an at-least-once topic;
the integration run is created COMPLETE before anything runs; the stream runs as a named person; draft flow and action
shipped in the set.

## What the platform offers (PDI, measured 23 Sep)
- Stream Connect consumer types (`sys_kafka_etl_consumer` subclasses): Script Consumer, ETL Consumer (Robust
  Transform Engine) and **Transform Map Consumer** (`sys_kafka_transform_map_consumer`: `transform_map`,
  `column_mapping` = message JSON keys to import set columns by name or label, `synchronize_inserts` = one record per
  coalesce value). The transform map consumer loads the import set and runs the transform itself: no flow, no loader
  script. Messages that fail land in `sys_kafka_unprocessed_messages` (key, message, partition, offset, headers).
  The PDI has the tables but no Kafka runtime (ProducerV2 absent), so the consumption itself is tested on bofadev;
  the import set and transform are tested on the PDI by loading rows the way the consumer does.
- For application findings the VR equivalent of the Detection API is the **AVR import API**
  (`new sn_vul.AVRImportAPIFactory().getAPI('v1', {process_gr: ...})`): `createOrUpdateAVIT`, `createOrUpdateApp`,
  `createOrUpdateAppVulEntry`, `createOrUpdateCWE`, ... It finds an AVIT by `source_avit_id` + application release +
  scan type + integration instance, creates the application release and vulnerability entry when missing, maps the
  source status to AVIT state and counts inserted/updated on the run. Required per AVIT: `source_app_id`,
  `source_scan_id`, `source_avit_id`, `source_severity`, `source_entry_id`, `scan_type` (plus `app_name` for a new
  release). The pen test manual ingestion (`sn_vul_manual_ingestion_avit_pentest_import` +
  `ManualIngestionAVRPentestProcessor`) inserts pen test requests and AVITs but never updates, so it does not fit a
  stream of updates.

## Proposed design (to confirm with the payload)
- Same application (`x_boar_bofa_usem_1`), same naming as the outbound work; no flow.
- Topic alias `sn_usem_vamp_inbound`, Kafka stream running as an integration account.
- If VAMP sends **one finding per message**: Stream Connect Transform Map Consumer on an import set table
  `x_boar_bofa_usem_1_usem_vamp_inbound_import` (one column per payload field, plus the raw message); no loader code.
  If VAMP sends **an envelope with a list of findings**: a script consumer that loops over every message and every
  finding, writes one staging row each (field list in one system property, `json_path=column`), keeps the raw message,
  refuses a malformed message with one `gs.error` and never stops the batch, then runs the transform.
- Transform map (only if the target is in this story): onStart creates the integration run and the AVR import API,
  onBefore builds the AVIT object and calls `createOrUpdateAVIT` (`ignore = true`), onComplete closes the run with the
  counts. Integration records as Mohammad's (integration, instance, properties), without the REST polling class.
- Duplicates: coalesce on the VAMP finding id (the AVR API does), and skip a replayed `event_id`.

## Questions (23 Sep, second round, posted with explanations on INC0010013)
Blockers: 1, 2, 5, 6. Blockers when the story includes creating or updating AVITs: 7, 8, 9 (the AVR import API refuses a
new AVIT without application, assessment/scan id, severity, vulnerability/CWE and scan type; updates need a stable finding
id, and a retest result must carry our AVIT number or the source id sent in 1804). 12 blocks testing on dev only.
The rest can be answered while building.

1. Can you share a sample message for sn_usem_vamp_inbound, with the list of fields and which ones are mandatory? Is it plain JSON or Avro?
2. Will one message carry one finding, or can one message carry several findings?
3. Will the message have the same envelope block as our outbound messages (topic name, event id, timestamp, element count, activity)?
4. What will you use as the message key? We'd like it to be the finding id.
5. What does a message mean for us: a new finding raised in VAMP, the result of a retest on a finding we sent you (SNOWUSEMTP-1804), or both? If both, how do we tell them apart?
6. What should ServiceNow create or update from these messages, and is that part of this story? The acceptance criteria only cover loading the data into the import set table.
7. Which field identifies a finding and stays the same on every update? For a retest result, will you send back our AVIT number or source id from 1804? How do we find the application and the pen test request on our side (AIT number, assessment id)?
8. For a new finding we need at least the application id, the assessment or test id, the severity, the vulnerability or CWE id and the type of test. Will all of these be in the message?
9. Can you share the list of VAMP statuses and what each one should become in ServiceNow? What should happen when a message says DELETE?
10. Will findings carry evidence such as screenshots or request/response captures? If so, how should that reach us?
11. Will there be a mapping sheet for the inbound fields, like the SN to VAMP mapping we got for the outbound story?
12. Is the replication from VAMP's Kafka into sn_usem_vamp_inbound already set up on dev, and can you send us a few test messages? When we turn the consumer on, should it read only new messages or also the ones already in the topic?
13. Roughly how many messages a day should we expect, and will there be a one-time load of existing findings at go-live?
14. Kafka can deliver the same message twice. Does each message carry an id that stays the same on a resend, so we can skip duplicates?
15. If a message can't be processed (bad data, application not found), who should know about it and how?
16. Which account should the consumer run as? We'd rather not use a personal account.
