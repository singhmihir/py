# SNOWUSEMTP-2125 — VAMP findings into Application Vulnerability Response (POC)

Story (25 Sep): Kafka consumer for VAMP findings (the story text says Confluent Kafka; **Mihir 25 Sep: the bus is Hermes,
ServiceNow's own Stream Connect Kafka, at all places; Mohammad's document has Confluent wrong**), import set / transform map into
`sn_vul_pen_test_assessment_request`, `sn_vul_app_vulnerable_item`, `sn_vul_app_vul_entry`, using the OOB script
includes of the integration framework; no flows. Drop-box incident **INC0010038** (`d759c5ad93670fd0e3aef0aefaba1096`),
which also holds Mohammad's design document *Vulnerability Stream Bridge* (27 Aug, CDP IVR over Kafka into the import
set; he chose transform maps over ETL). Design diagram reference on the story: SNOWUSEMTP-1585 (not readable from here).

## Decisions (Mihir, 25 Sep)
- Diagram covers 2125 and the three tables; drawn in the document the way Mohammad's figures are (card-and-band style).
- Scripted consumer like the CDP IVR build (a VAMP message may carry several findings), not the OOB transform map consumer.
- Pen test request: lookup-or-create in the transform map's onBefore (by `u_assessment_id`), since no OOB API covers the table.

## Facts behind the diagram (read from the OOB code on the PDI)
- AVR import API: `new sn_vul.AVRImportAPIFactory().getAPI('v1', { process_gr })`; `createOrUpdateApp`,
  `createOrUpdateAppVulEntry` (+ `cwe_list` → `sn_vul_m2m_entry_cwe`), `createOrUpdateAVIT`. Required fields per table in
  `AVRImportAPIBase.REQUIRED_FIELDS`; any dictionary column of the table is accepted (so `assessment_request` passes).
  AVIT identity: `source_avit_id` + `application_release` + `scan_type` + integration instance. State from
  `sn_vul_app_state_map` via `VulnerabilityStateMapper.mapState(sec_integration, source_remediation_status)`. Application via
  `AppVulUtils.productModelOrScannedApp` (CI lookup rules; else Scanned Application / product model). The API accepts a
  classic `sn_vul_integration_process` or a framework `sn_vul_int_fw_integration_process` (`isUsingIntegrationFramework`),
  and stamps `integration_run` or `integration_fw_run` accordingly.
- OOB scanner integrations call the API from processor script includes (`ApplicationVulnerabilityImportProcessorBase`,
  `ApplicationVulnerabilityIntegrationBase`); no OOB transform script calls it. `completeProcess()` writes the counts.
- `ManualIngestionAVRPentestProcessor` is the only OOB writer of `sn_vul_pen_test_assessment_request`: insert-only,
  bound to manual (spreadsheet) ingestion, application by name; it sets `assessment_request`, `scan_type=manual`,
  `source=Penetration Test` on the AVIT. Not callable from a transform map.

## Files
- `build_figure.js` → `figure-architecture.png` (HTML in Mohammad's figure style, screenshotted at 2x with the bundled
  Chromium: `NODE_MODULES=<dir> CHROME=<chrome> node build_figure.js`).
- `build_doc.js` → *VAMP Inbound - Architecture Diagram.docx* (figure + caption + OOB used / not usable table).
- `attach_2125.py` — attaches to INC0010038 with a comment.
