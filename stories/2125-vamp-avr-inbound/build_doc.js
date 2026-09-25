// Builds "VAMP Inbound - Architecture Diagram.docx": the architecture figure of SNOWUSEMTP-2125 with its
// caption and the table of out-of-box code used, not usable, and what the story builds instead.
// Usage: NODE_MODULES=<dir with docx> node build_doc.js   (run build_figure.js first)
const fs = require('fs');
const path = require('path');
const H = require('../1639-vamp-inbound/doc_helpers.js');
const { Document, Packer, Paragraph, ImageRun, AlignmentType, PageBreak } = H.D;
const { NAVY, RED, t, p, body, h1, table } = H;

const png = fs.readFileSync(path.join(__dirname, 'figure-architecture.png'));
const sizeOf = (buf) => ({ w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) });
const px = sizeOf(png);
const width = 600;  // px at 96 dpi: the figure fills one page on its own
const height = Math.round(width * px.h / px.w);

const children = [];
children.push(new Paragraph({ children: [t('SNOWUSEMTP-2125', { size: 18, bold: true, color: RED })], spacing: { after: 40 } }));
children.push(new Paragraph({ children: [t('VAMP findings into Application Vulnerability Response', { size: 34, bold: true, color: NAVY })], spacing: { after: 60 } }));
children.push(new Paragraph({ children: [t('Architecture diagram: Kafka consumer, import set and transform map, out-of-box AVR import API', { size: 22, color: RED })], spacing: { after: 100 } }));
children.push(body('Prepared 25 September 2026. Architecture only; the build plan and the field mapping follow once the VAMP payload is available. The table below says which out-of-box code the design uses and which it cannot; the figure on the next page shows the whole path. The pattern is the one used for the CDP IVR inbound build (Kafka stream, script consumer, import set, transform map), with the application-vulnerability API of the integration framework in place of the infrastructure one.', { size: 18 }));

children.push(h1('Out-of-box code: what is used, what is not, and why'));
children.push(table(['Component', 'Out of the box', 'In this story'], [
  ['Stream Connect', 'Kafka topic, subscription, topic alias, stream, script consumer (sys_kafka_* and sys_sc_topic_alias)', 'Configured. Topic sn_usem_vamp_inbound exists on dev; alias, stream and consumer are created in the application scope.'],
  ['Import sets', 'sys_import_set, staging table, GlideImportSetTransformer, transform map engine with onStart / onBefore / onComplete', 'Used as the front door, exactly as in the CDP IVR build: one import set per message, one row per finding, transformAllMaps().'],
  ['AVR import API', 'sn_vul.AVRImportAPIFactory, AVRImportAPI_v1Base, AVRImportAPIBase: createOrUpdateApp, createOrUpdateAppVulEntry (+ CWE links), createOrUpdateAVIT', 'Called from the transform map scripts. Required fields: app_name + source_app_id (application); source_entry_id + source_severity (entry); source_app_id, source_scan_id, source_avit_id, source_severity, source_entry_id, scan_type (AVIT).'],
  ['Application matching', 'sn_vul.AppVulUtils.productModelOrScannedApp with the CI lookup rules (sn_sec_cmn.CIIdentify)', 'Inherited through the API: business application when a rule matches, otherwise a Scanned Application record.'],
  ['State mapping', 'sn_vul_app_state_map rows per integration, read by sn_vul.VulnerabilityStateMapper', 'Configured: one row per VAMP status, giving state and substate. No status logic in script.'],
  ['Integration framework records', 'sn_sec_int_integration, sn_sec_int_impl, sn_vul_int_fw_integration_run and _process (or the classic sn_vul_integration_run / _process; the API accepts both)', 'Created once (integration, instance); run and process written per message by onStart, counts by onComplete, so the import is auditable like a scheduled one.'],
  ['sn_vul.Detection, sn_vul.ImportHost', 'The infrastructure (IVR) detection API used by the CDP IVR build', 'Not used: they create host-based vulnerable items (sn_vul_vulnerable_item), not application findings.'],
  ['Kafka transform map consumer', 'sys_kafka_transform_map_consumer: JSON keys mapped to import set columns without code', 'Not used: it takes one message as one row, and a VAMP message can carry several findings. The scripted consumer keeps the same front door.'],
  ['ManualIngestionAVRPentestProcessor', 'The only OOB code that creates sn_vul_pen_test_assessment_request', 'Not usable: insert-only, bound to spreadsheet ingestion, application looked up by name. The AVR import API has no method for the table.'],
  ['Pen test assessment request', 'None', 'Built: onBefore finds the request by u_assessment_id (VAMP assessment id) or inserts it with the fields the OOB processor sets, and passes it as assessment_request to createOrUpdateAVIT.'],
  ['Flow Designer', 'Flows and actions', 'Not used, as the story asks.'],
], [22, 38, 40]));

children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(new Paragraph({ children: [new ImageRun({ type: 'png', data: png, transformation: { width: width, height: height } })], alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 } }));
children.push(new Paragraph({ children: [t('Figure 1. ', { size: 17, bold: true, color: NAVY }), t('VAMP findings into Application Vulnerability Response. Bands 1 and 3 are platform code, configured or reused; band 2 and the right half of band 4 are what the story builds; the left card of band 4 is the out-of-box code that does not fit.', { size: 17, italics: true })], alignment: AlignmentType.CENTER, spacing: { after: 200 } }));


const doc = new Document({
  creator: 'Mihir Singh',
  styles: { default: { document: { run: { font: H.FONT, size: 20, color: H.INK } } } },
  sections: [{ properties: { page: { margin: { top: 720, bottom: 720, left: 1000, right: 1000 } } }, children: children }],
});
const out = path.join(__dirname, 'VAMP Inbound - Architecture Diagram.docx');
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(out, b); console.log('written:', out, b.length, 'bytes'); });
