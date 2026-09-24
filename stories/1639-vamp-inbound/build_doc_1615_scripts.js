// Builds "CDP IVR Inbound Integration - Transform Scripts Explained.docx": how the three transform map
// scripts of the SNOWUSEMTP-1615 build take a CDP finding from the staging row to the vulnerable item,
// with the platform calls (ImportHost, Detection API) opened up step by step.
const fs = require('fs');
const path = require('path');
const H = require('./doc_helpers.js');
const { Document, Packer, Paragraph } = H.D;
const { INST, NAVY, RED, t, p, body, h1, h2, code, bullet, numbered, link, rec, list, table, L } = H;

const ID = {
  map: '792d2e543b9b4b10974548c643e45a55', onStart: 'a5dd66943b9b4b10974548c643e45ae0', onBefore: 'c7fd2a943b9b4b10974548c643e45a46',
  onComplete: 'd71e6a943b9b4b10974548c643e45ab8', utils: '802d454a2b5f03102b30f8e14391bff3', importTable: 'd81d6a543b9b4b10974548c643e45ad8',
  rest: '6712aa143bd74b10974548c643e45a6b', instance: '11731b9c3bdb4b10974548c643e45a09',
  propInt: '4d221dc93b97cb10974548c643e45a0a', propImpl: '6fc2110d3b97cb10974548c643e45ac4',
};
const STAGING = 'x_boar_bofa_usem_1_usem_cdp_ivr_inbound_import';
const m = (s) => t(s, { mono: true });
const numbered2 = (runs) => new Paragraph({ children: runs, numbering: { reference: 'steps2', level: 0 }, spacing: { after: 100, line: 260 } });

const children = [];
children.push(new Paragraph({ children: [t('CDP IVR Inbound Integration', { size: 40, bold: true, color: NAVY })], spacing: { after: 60 } }));
children.push(new Paragraph({ children: [t('The transform map scripts explained: from the CDP finding to the vulnerable item', { size: 24, color: RED })], spacing: { after: 60 } }));
children.push(body('Prepared 24 September 2026. Companion to the architecture overview of the SNOWUSEMTP-1615 build. It follows one CDP finding through the three scripts of the transform map and opens up the two platform calls they rely on, the host matcher (sn_vul.ImportHost) and the Detection API (sn_vul.Detection), so that every record the finding leaves behind can be explained.', { size: 18 }));
children.push(p([t('Records on the development instance: ', { size: 18 }), rec('sys_transform_map', ID.map, 'transform map'), t(' · ', { size: 18 }), rec('sys_transform_script', ID.onStart, 'onStart'), t(' · ', { size: 18 }), rec('sys_transform_script', ID.onBefore, 'onBefore'), t(' · ', { size: 18 }), rec('sys_transform_script', ID.onComplete, 'onComplete'), t(' · ', { size: 18 }), rec('sys_script_include', ID.utils, 'BofaCDPUtils'), t(' · ', { size: 18 }), rec('sys_db_object', ID.importTable, 'staging table')]));

children.push(h1('1. What arrives at the transform map'));
children.push(body('Before the map runs, BofaCDPUtils.processPayload has already flattened the CDP message: one message becomes one import set (sys_import_set) and each element of findings[] becomes one row of the staging table. The row carries the envelope fields and the four finding sections as flat columns, 36 in all, for example:'));
children.push(table(['Message field', 'Staging column', 'Used later as'], [
  ['detections.ip_address', 'u_ip_address', 'host matching, detection ip_address'],
  ['detections.dns', 'u_dns', 'host matching, detection dns and netbios'],
  ['detections.vulnerability', 'u_vulnerability', 'the CDP vulnerability id (src_vuln_id)'],
  ['detections.port', 'u_port', 'detection port'],
  ['detections.first_found / last_found', 'u_first_found / u_last_found', 'detection and vulnerable item dates'],
  ['vits.state', 'u_state', 'detection status (0 open, 1 closed, 2 stale)'],
  ['vits.source', 'u_source', 'detection source (defaults to "CDP")'],
  ['dis.app_id, dis.os_name, dis.sn_cmdb_sys_id, cloud fields', 'u_app_id, u_os_name, u_sn_cmdb_sys_id, ...', 'host object handed to the CI lookup rules'],
], [34, 30, 36]));
children.push(body('processPayload then calls GlideImportSetTransformer().transformAllMaps() on the import set, which starts the transform engine.', { before: 120 }));

children.push(h1('2. Order of execution'));
children.push(bullet([t('The engine runs '), m('onStart'), t(' once, then '), m('onBefore'), t(' once per staging row, then '), m('onComplete'), t(' once after the last row.')]));
children.push(bullet([t('The transform map has '), t('no field mappings', { bold: true }), t('. Everything is done by the scripts, and the map engine never writes the target table (Vulnerable Item): onBefore ends with '), m('ignore = true'), t(' for every row.')]));
children.push(bullet([t('The three scripts share one JavaScript object, '), m('import_set'), t('. onStart stores the integration run sys_id, the implementation sys_id and the open Detection API on it; onBefore and onComplete read them back.')]));

children.push(h1('3. onStart: runs once per message'));
children.push(...code([
  "var integrationId = gs.getProperty('x_boar_bofa_usem_1.CDP_IVR_Integration');",
  "var implId        = gs.getProperty('x_boar_bofa_usem_1.CDP IVR Integration Implement');",
]));
children.push(p([t('Two system properties hold the sys_ids of the Vulnerability Response records that represent CDP as a scanner: the REST integration "USEM Inbound Integration CDP - IVR" (the '), t('integration', { italics: true }), t(') and the integration instance "CDP" (the '), t('implementation', { italics: true }), t('). The Detection API needs both because every vulnerable item, detection and discovered item it creates is stamped with them; that is how the platform knows which scanner a finding came from. '), rec('sys_properties', ID.propInt, 'Integration property'), t(' · '), rec('sys_properties', ID.propImpl, 'Implementation property'), t(' · '), rec('sn_vul_rest_integration', ID.rest, 'REST integration'), t(' · '), rec('sn_sec_int_impl', ID.instance, 'Integration instance')]));
children.push(...code([
  "var runGR = new GlideRecord('sn_vul_integration_run');",
  "runGR.initialize();",
  "runGR.setValue('integration', integrationId);   runGR.setValue('implementation', implId);",
  "runGR.setValue('state', 'COMPLETE');            runGR.setValue('substate', 'SUCCESS');",
  "runGR.setValue('source', 'CDP IVR');",
  "var runSysId = runGR.insert();",
]));
children.push(p([t('Inserts an integration run. In a scanner import the platform creates this record itself and it tracks the import’s progress; here one is created by hand per message, already marked complete. Every record created below points to this run, so opening the run shows everything one message produced. '), list('sn_vul_integration_run', 'source=CDP IVR', 'Integration runs')]));
children.push(...code([
  "import_set.runSysId = runSysId;",
  "import_set.implId   = implId;",
  "import_set.detectionSI = new sn_vul.Detection(integrationId, implId, runSysId, 'Kafka_TransformMap');",
]));
children.push(body('Opens the Detection API (sn_vul.Detection, the class the Qualys and Tenable integrations use) and parks it on import_set so every onBefore uses the same instance. Opening it prepares the in-memory caches: detections grouped by vulnerable item, and the key configuration that decides which fields identify a detection and which identify a vulnerable item (section 4.3).'));

children.push(h1('4. onBefore: runs once per staging row (one CDP finding)'));
children.push(h2('4.1 Build the host object'));
children.push(...code([
  'var hostInfo = {',
  '    "ip_address": source.u_ip_address + "",   "dns": source.u_dns + "",',
  '    "os_name":    source.u_os_name + "",      "app_id": source.u_app_id + "",',
  '    "sn_cmdb_sys_id": source.u_sn_cmdb_sys_id + "",',
  '    "vulnerability": source.u_vulnerability + "",  "port": source.u_port + "",',
  '    "state": source.u_state + "",  "first_found": ...,  "last_found": ...,',
  '    ... every other staging column ...',
  '    "id": source.sys_id + ""',
  '};',
]));
children.push(p([t('Every staging column is copied into one plain object; '), m('source'), t(' is the staging row. The last key, '), m('id'), t(', is the staging row’s own sys_id and becomes the source id of the discovered item (4.2).')]));

children.push(h2('4.2 Match the host to a CI'));
children.push(...code(['var matchResult = new sn_vul.ImportHost().hostImport(import_set.implId, hostInfo, "id", import_set.runSysId);', 'var disc_item_id = matchResult.disc_item_id;']));
children.push(body('hostImport is the platform’s host matcher, the call a scanner import makes for each scanned host. With these arguments it does the following:'));
children.push(numbered([t('Looks for an existing discovered item ('), m('sn_sec_cmn_src_ci'), t(') of this integration instance whose source id equals '), m('hostInfo.id'), t('. Because that id is the staging row’s sys_id and every row is new, nothing is ever found: every finding produces a fresh discovered item and a fresh CI lookup, even for a host seen a minute earlier.')]));
children.push(numbered([t('Runs the CI lookup rules ('), m('CIIdentify.identify'), t(') against '), m('hostInfo'), t('. The rules read the payload by key ('), m('ip_address'), t(', '), m('dns'), t(', '), m('os_name'), t(', ...), the names the BOFA rule chain looks for, so the same rules that resolve Qualys hosts resolve CDP findings.')]));
children.push(numbered([t('When a rule returns a CI: creates the discovered item with '), m('cmdb_ci'), t(' = that CI, '), m('source_data'), t(' = the whole hostInfo as JSON, state matched, the rule that matched and the integration run. When no rule matches: creates it unmatched (and, depending on the IRE settings, a placeholder CI).')]));
children.push(numbered([t('Returns '), m('{ sys_id: <CI sys_id or null>, disc_item_id: <discovered item sys_id>, insert / update / ignore }'), t('.')]));
children.push(p([t('The script only continues when '), m('matchResult.sys_id'), t(' is set: '), t('a finding whose host cannot be matched to a CI stops here', { bold: true }), t(', leaving its discovered item behind as the trace. '), list('sn_sec_cmn_src_ci', 'source=' + ID.instance, 'Discovered items of the CDP instance')]));

children.push(h2('4.3 Build the detection'));
children.push(...code([
  'var detection = import_set.detectionSI.newDetection();',
  'detection.cmdb_ci     = matchResult.sys_id;        detection.src_ci   = disc_item_id;',
  'detection.src_vuln_id = hostInfo.vulnerability;    // the CDP vulnerability id',
  'detection.status      = hostInfo.state ? hostInfo.state : 0;',
  'detection.port        = hostInfo.port ? hostInfo.port : \'0\';',
  'detection.source      = hostInfo.source || "CDP";  detection.proof = "";',
  'detection.ip_address, dns, netbios (= dns), asset_id, first_found, last_found  from hostInfo',
]));
children.push(body('newDetection() returns a template object with every field the Detection API understands (about thirty); the script fills thirteen. Two of them matter most:'));
children.push(bullet([m('status'), t(' decides the vulnerable item’s state later. The Detection API expects '), t('0 = Open, 1 = Closed, 2 = Stale', { bold: true }), t('. The script passes vits.state straight through, so CDP must send those numbers; a word such as "Open" is not recognised as open (section 5).')]));
children.push(bullet([m('proof'), t(' is empty, so two findings of the same vulnerability on the same host and port are the same detection (the detection key is built from vulnerability, port, protocol, asset, proof and nic).')]));
children.push(...code([
  "var vulGr = new GlideRecord('sn_vul_nvd_entry');",
  'if (vulGr.get("id", hostInfo.vulnerability + ""))',
  '    detection.vulnerability = vulGr.getUniqueValue();',
]));
children.push(body('Tries to link the finding to an NVD entry (the CVE library) by id. When the CDP vulnerability id is a CVE present in the library, the vulnerable item points at that CVE; otherwise detection.vulnerability stays empty and the Detection API handles it (step 1 below).'));
children.push(...code([
  "import_set.detectionSI.insertFixed = 'true';",
  'import_set.detectionSI.createDetection(detection);',
]));
children.push(p([m('insertFixed = true'), t(' tells the API to create a vulnerable item even when the detection arrives already closed (normally a closed detection with no existing item is skipped). Then '), m('createDetection'), t(' does the real work, in this order:')]));
children.push(numbered2([t('Vulnerability entry.', { bold: true }), t(' When detection.vulnerability is empty, looks up '), m('sn_vul_third_party_entry'), t(' by id = src_vuln_id; when none exists, inserts a blank third-party vulnerability with that id, source "CDP" and this integration instance. An unknown CDP id still gets a vulnerability record, an empty one.')]));
children.push(numbered2([t('Detection key.', { bold: true }), t(' MD5 of vulnerability + port + protocol + asset + proof + nic. Looks for an existing detection ('), m('sn_vul_detection'), t(') with that key for this instance; when one exists with a later last_found, the incoming detection is ignored as older.')]));
children.push(numbered2([t('Vulnerable item key.', { bold: true }), t(' MD5 of cmdb_ci + vulnerability (the default key). Looks for an existing vulnerable item whose '), m('external_id'), t(' equals that key for this instance. This is the de-duplication that matters: the same vulnerability on the same CI always maps to the same vulnerable item, however many messages arrive.')]));
children.push(numbered2([t('Placeholder.', { bold: true }), t(' When no vulnerable item exists yet, creates an in-memory placeholder (a newRecord() on sn_vul_vulnerable_item, not inserted yet) and files the detection under it in the cache.')]));
children.push(numbered2([t('Detection row.', { bold: true }), t(' Inserts or updates the row in '), m('sn_vul_detection'), t(' at once: cmdb_ci, src_ci, vulnerability, status, port, ip_address, dns, netbios, first_found, last_found, source, detection_key, integration run, integration instance, and vulnerable_item = the placeholder’s or the existing item’s sys_id.')]));
children.push(numbered2([t('Roll-up.', { bold: true }), t(' Records in the cache the earliest first_found and latest last_found per vulnerable item, and keeps the first detection’s ip, port, dns, cmdb_ci, src_ci and source as the values the item will carry.')]));

children.push(h2('4.4 Stop the map engine'));
children.push(...code(['ignore = true;']));
children.push(body('The transform-map switch that says "do not insert or update the target for this row". The engine writes nothing to sn_vul_vulnerable_item and marks the staging row Ignored in the import set, which is expected here. All writing of vulnerable items is left to onComplete.'));

children.push(h1('5. onComplete: runs once, after the last row'));
children.push(...code([
  'if (import_set.detectionSI) {',
  '    var summary = import_set.detectionSI.finalizeDetections();',
  '    gs.info("Kafka Transform Map finished processing. Created VIs: " + summary.inserted.vis);',
  '}',
]));
children.push(body('finalizeDetections walks the cache built in 4.3, one vulnerable item at a time:'));
children.push(bullet([t('Existing vulnerable item: ', { bold: true }), t('updates first_found and last_found from the detections, re-reads the states of all its detections and decides the state. At least one open detection on an item that is Closed - Fixed, Closed - Stale or Resolved reopens it. No open detection and at least one closed one moves it to Closed - Fixed with the close note "following an update from the scanner import". Otherwise the item is left as it is.')]));
children.push(bullet([t('New vulnerable item (placeholder): ', { bold: true }), t('inserts it with vulnerability, cmdb_ci, src_ci (the discovered item), ip_address, port, dns, netbios, first_found, last_found, source, external_id (the key), integration, integration instance and integration run, in state Open when any detection is open, Closed - Fixed when none is open, Closed - Stale when only stale ones exist. The out-of-box business rules then fill risk score, assignment and the rest as for any scanner-created item.')]));
children.push(bullet([t('Returns the counters (inserted, updated and ignored items and detections); the script logs only inserted.vis.')]));

children.push(h1('6. The records one CDP finding leaves behind'));
children.push(table(['Table', 'Record', 'Written by'], [
  ['sys_import_set', 'one per message', 'processPayload'],
  [STAGING, 'one row per finding, state Ignored after the transform', 'processPayload, then the engine'],
  ['sn_vul_integration_run', 'one per message, source "CDP IVR"', 'onStart'],
  ['sn_sec_cmn_src_ci (discovered item)', 'one per finding, source_data = the flattened finding, cmdb_ci from the lookup rules', 'hostImport (onBefore)'],
  ['sn_vul_third_party_entry', 'one per new CDP vulnerability id not found in the NVD library', 'createDetection (onBefore)'],
  ['sn_vul_detection', 'one per finding; updated when the same key already exists', 'createDetection (onBefore)'],
  ['sn_vul_vulnerable_item', 'one per CI + vulnerability, created or updated', 'finalizeDetections (onComplete)'],
], [30, 42, 28]));

children.push(h1('7. Likely questions, with the answers from the code'));
children.push(table(['Question', 'Answer'], [
  ['Where is the field mapping?', 'Not on the map. The mapping is the hostInfo object in onBefore plus the thirteen detection.* lines. A new CDP field needs a staging column, a line in processPayload and a line in onBefore.'],
  ['How are duplicates avoided?', 'At the vulnerable item level by the key cmdb_ci + vulnerability (external_id); at the detection level by the detection key. Not at the discovered item level: each finding creates a new discovered item because the source id is the staging row’s sys_id.'],
  ['How does it know which CI?', 'The CI lookup rules, run by hostImport on the hostInfo fields. sn_cmdb_sys_id travels in the payload but nothing in the chain reads it; a rule would have to.'],
  ['What closes an item?', 'A finding whose vits.state arrives as 1 (Closed) with no other open detection on the same CI + vulnerability, at the end of that message’s transform.'],
  ['What if the host does not match?', 'The finding stops at 4.2: a discovered item is created unmatched, no detection and no vulnerable item.'],
  ['What if CDP sends state as a word?', 'detection.status would not be 0, 1 or 2, so no item would count as open: new items would be created Closed - Fixed. The state values have to be agreed with CDP or converted in onBefore.'],
  ['What links the finding to a CVE?', 'A lookup of sn_vul_nvd_entry by the CDP vulnerability id. When it is not a known CVE, a third-party vulnerability entry with that id is created instead.'],
  ['Where can I see one message end to end?', 'Open the integration run (source "CDP IVR") of that message: the discovered items, detections and vulnerable items created for it all reference it.'],
], [30, 70]));

const doc = new Document({
  creator: 'Mihir Singh',
  styles: { default: { document: { run: { font: H.FONT, size: 20, color: H.INK } } } },
  numbering: { config: ['steps', 'steps2'].map((ref) => ({ reference: ref, levels: [{ level: 0, format: 'decimal', text: '%1.', alignment: 'left',
    style: { paragraph: { indent: { left: 540, hanging: 360 } } } }] })) },
  sections: [{ properties: { page: { margin: { top: 1080, bottom: 1080, left: 1150, right: 1150 } } }, children: children }],
});
const out = path.join(__dirname, 'CDP IVR Inbound Integration - Transform Scripts Explained.docx');
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(out, b); console.log('written:', out, b.length, 'bytes'); });
