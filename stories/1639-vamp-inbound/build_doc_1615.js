// Builds "CDP IVR Inbound Integration - Architecture Overview.docx": how the SNOWUSEMTP-1615 build
// (Kafka topic -> import set -> transform map -> Vulnerability Response detections) is put together,
// with a link to every record on the client dev instance.
const fs = require('fs');
const path = require('path');
let D; try { D = require('docx'); } catch (e) { D = require(path.join(process.env.NODE_MODULES || 'node_modules', 'docx')); }
const { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType,
        BorderStyle, ExternalHyperlink, ShadingType, TableLayoutType, PageBreak } = D;

const INST = 'https://bofasecopsdev.service-now.com/';
const FONT = 'Arial', MONO = 'Courier New';
const INK = '4D4F53', NAVY = '012169', RED = 'E31837', HEAD = 'E8EAEC', ZEBRA = 'F5F6F7';
const HAIR = { style: BorderStyle.SINGLE, size: 4, color: 'C9CDD1' };

function t(text, o) {
  o = o || {};
  return new TextRun({ text: text, font: o.mono ? MONO : FONT, size: o.size || 20, bold: !!o.bold,
    italics: !!o.italics, color: o.color || INK });
}
function p(runs, o) {
  o = o || {};
  return new Paragraph({ children: Array.isArray(runs) ? runs : [runs],
    spacing: { before: o.before || 0, after: o.after === undefined ? 120 : o.after, line: o.line || 260 },
    keepNext: !!o.keepNext });
}
function body(text, o) { return p(t(text, o), o); }
function h1(text) {
  return new Paragraph({ children: [t(text, { size: 30, bold: true, color: NAVY })], heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 140 }, keepNext: true });
}
function h2(text) {
  return new Paragraph({ children: [t(text, { size: 23, bold: true, color: NAVY })], heading: HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 100 }, keepNext: true });
}
function code(lines) {
  return lines.map((l, i) => new Paragraph({
    children: [t(l === '' ? ' ' : l, { mono: true, size: 17 })],
    spacing: { before: i === 0 ? 60 : 0, after: i === lines.length - 1 ? 140 : 0, line: 220 },
    shading: { type: ShadingType.CLEAR, fill: 'F2F3F4' }, indent: { left: 180, right: 180 },
  }));
}
function bullet(runs, level) {
  return new Paragraph({ children: Array.isArray(runs) ? runs : [t(runs)], bullet: { level: level || 0 },
    spacing: { after: 80, line: 260 } });
}
function numbered(runs) {
  return new Paragraph({ children: Array.isArray(runs) ? runs : [t(runs)], numbering: { reference: 'steps', level: 0 },
    spacing: { after: 100, line: 260 } });
}
function link(url, label) {
  return new ExternalHyperlink({ children: [new TextRun({ text: label || url, font: FONT, size: 18, color: '1155CC', underline: {} })], link: url });
}
function rec(table, id, label) { return link(INST + table + '.do?sys_id=' + id, label); }
function list(table, query, label) { return link(INST + table + '_list.do?sysparm_query=' + encodeURIComponent(query), label); }
function cell(children, o) {
  o = o || {};
  return new TableCell({ children: children, width: { size: o.w, type: WidthType.PERCENTAGE },
    shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill } : undefined,
    margins: { top: 70, bottom: 70, left: 110, right: 110 }, verticalAlign: 'top' });
}
function table(headers, rows, widths) {
  const head = new TableRow({ tableHeader: true, cantSplit: true,
    children: headers.map((hd, i) => cell([p(t(hd, { bold: true, size: 17 }), { after: 0, line: 220 })], { w: widths[i], fill: HEAD })) });
  const trs = rows.map((r, ri) => new TableRow({ cantSplit: true,
    children: r.map((c, i) => cell(Array.isArray(c) ? c : [p(t(String(c), { size: 17 }), { after: 0, line: 220 })],
      { w: widths[i], fill: ri % 2 ? ZEBRA : undefined })) }));
  return new Table({ rows: [head].concat(trs), width: { size: 100, type: WidthType.PERCENTAGE }, layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR } });
}
const L = (children) => [p(children, { after: 0, line: 220 })];
const S = (text) => [p(t(text, { size: 17 }), { after: 0, line: 220 })];

// Records of the build on the client dev instance
const ID = {
  set: '05675dc0975fc3d0f1f1bdf0f053afa0', scope: '4ba447d22b43cb10cb55fbcc6e91bf0f',
  topic: '23702ab12b324310cb55fbcc6e91bffe', alias: 'b8137a583b9b4b10974548c643e45ac1', subscription: '5490e994fb67c3102045fbd37eefdc62',
  stream: 'bcfe498a2b5f03102b30f8e14391bf5d', consumer: '0f8cc90a2b5f03102b30f8e14391bf3f', utils: '802d454a2b5f03102b30f8e14391bff3',
  importTable: 'd81d6a543b9b4b10974548c643e45ad8', map: '792d2e543b9b4b10974548c643e45a55',
  onStart: 'a5dd66943b9b4b10974548c643e45ae0', onBefore: 'c7fd2a943b9b4b10974548c643e45a46', onComplete: 'd71e6a943b9b4b10974548c643e45ab8',
  integration: '13ff61c497dfc3d0f1f1bdf0f053afd8', instance: '11731b9c3bdb4b10974548c643e45a09', rest: '6712aa143bd74b10974548c643e45a6b',
  restUtil: '6b94ca04975307d0f1f1bdf0f053afe9', propInt: '4d221dc93b97cb10974548c643e45a0a', propImpl: '6fc2110d3b97cb10974548c643e45ac4',
  dataSource: 'ef0d6a543b9b4b10974548c643e45aa6', module: 'f51dea543b9b4b10974548c643e45a36', flow: '66113a183b9b4b10974548c643e45a66',
  action: 'ac917e183b9b4b10974548c643e45aef', rule: 'e03b0d453b97cb10974548c643e45a7e',
};
const STAGING = 'x_boar_bofa_usem_1_usem_cdp_ivr_inbound_import';

const children = [];
children.push(new Paragraph({ children: [t('CDP IVR Inbound Integration', { size: 40, bold: true, color: NAVY })], spacing: { after: 60 } }));
children.push(new Paragraph({ children: [t('Architecture overview of the SNOWUSEMTP-1615 build (Kafka to Vulnerability Response)', { size: 24, color: RED })], spacing: { after: 60 } }));
children.push(body('Prepared 24 September 2026 from the update set SNOWUSEMTP-1615_Import Detections from CDP to ServiceNow_MK_v1 and the Stream Connect records on the development instance. Every record named below is linked to the development instance so the build can be read alongside this document.', { size: 18 }));

children.push(h1('1. What the integration does'));
children.push(body('CDP publishes infrastructure vulnerability detections (IVR) to a Kafka topic. ServiceNow consumes the topic, stages each finding as a row in an import set table, and hands the rows to the Vulnerability Response Detection API through a transform map. The Detection API matches the host against the CMDB, creates or updates the vulnerable item and records an integration run, exactly as it does for a scanner import.'));
children.push(body('The design keeps all parsing in one script include, all Vulnerability Response work in the transform map scripts, and uses the platform’s own import set and detection machinery in between. No Flow Designer flow is on the live path.'));

children.push(h1('2. End-to-end flow'));
const steps = [
  [t('Kafka topic '), t('sn_usem_ivr_inbound', { mono: true }), t(' (16 partitions, USEM namespace) receives the messages from CDP. '), rec('sys_kafka_topic', ID.topic, 'Topic record')],
  [t('The topic alias '), t('sn_usem_ivr_inbound [BOFA USEM CDP integration]', { mono: true }), t(' makes the topic usable from the application scope. '), rec('sys_sc_topic_alias', ID.alias, 'Topic alias')],
  [t('The Kafka stream '), t('CDP IVR Inbound', { mono: true }), t(' subscribes to the alias and routes each message to the consumer (initial offset latest, dynamic message handling, concurrency 1). '), rec('sys_kafka_stream', ID.stream, 'Stream'), t(' · '), rec('sys_kafka_subscription', ID.subscription, 'Subscription SUBS00001015')],
  [t('The Kafka script consumer '), t('CDP IVR Inbound', { mono: true }), t(' parses the first message of the batch as JSON and calls '), t('BofaCDPUtils.processPayload(payload)', { mono: true }), t('. '), rec('sys_kafka_script_consumer', ID.consumer, 'Script consumer')],
  [t('Script include '), t('BofaCDPUtils', { mono: true }), t(' creates an import set, writes one staging row per element of '), t('payload.findings', { mono: true }), t(' (envelope fields plus the dis, detections, vits and tpes sections), marks the set loaded and runs '), t('GlideImportSetTransformer().transformAllMaps()', { mono: true }), t('. '), rec('sys_script_include', ID.utils, 'Script include'), t(' · '), rec('sys_db_object', ID.importTable, 'Staging table'), t(' · '), link(INST + STAGING + '_list.do', 'Staging rows')],
  [t('The transform map '), t('USEM CDP IVR Inbound Transform map', { mono: true }), t(' (source: staging table, target: Vulnerable Item) runs its three scripts: onStart opens the Detection API, onBefore matches the host and creates the detection, onComplete finalises. The map itself writes no target row: onBefore sets '), t('ignore = true', { mono: true }), t(' so the Detection API owns the vulnerable item. '), rec('sys_transform_map', ID.map, 'Transform map')],
  [t('The Detection API ('), t('sn_vul.Detection', { mono: true }), t(') creates or updates the vulnerable items and their detections under the integration run created in onStart. '), list('sn_vul_integration_run', 'source=CDP IVR', 'Integration runs of this integration')],
];
steps.forEach(s => children.push(numbered(s)));

children.push(h1('3. Components and where to find them'));
children.push(table(['Component', 'Record', 'Role', 'Link'], [
  ['Update set', 'SNOWUSEMTP-1615_Import Detections from CDP to ServiceNow_MK_v1 (70 updates, scope BOFA USEM CDP integration)', 'Carries everything below except the stream, the subscription and the topic, which are instance configuration.', L([rec('sys_update_set', ID.set, 'Update set'), t(' · '), rec('sys_app', ID.scope, 'Application')])],
  ['Kafka topic', 'sn_usem_ivr_inbound', 'Inbound topic created by the Stream Connect administrator.', L([rec('sys_kafka_topic', ID.topic, 'Topic')])],
  ['Topic alias', 'sn_usem_ivr_inbound [BOFA USEM CDP integration]', 'Scope-level handle on the topic.', L([rec('sys_sc_topic_alias', ID.alias, 'Alias')])],
  ['Kafka stream', 'CDP IVR Inbound', 'Binds the alias to the consumer; holds offset, concurrency and run-as settings.', L([rec('sys_kafka_stream', ID.stream, 'Stream')])],
  ['Kafka script consumer', 'CDP IVR Inbound', 'Entry point: parses the message and calls the script include.', L([rec('sys_kafka_script_consumer', ID.consumer, 'Consumer')])],
  ['Script include', 'BofaCDPUtils', 'processPayload: import set + staging rows + transform.', L([rec('sys_script_include', ID.utils, 'Script include')])],
  ['Import set table', STAGING, 'Staging table, 36 columns (envelope + finding sections).', L([rec('sys_db_object', ID.importTable, 'Table'), t(' · '), link(INST + STAGING + '_list.do', 'Rows')])],
  ['Transform map', 'USEM CDP IVR Inbound Transform map', 'Staging table to Vulnerable Item, order 100, business rules on.', L([rec('sys_transform_map', ID.map, 'Map')])],
  ['Transform scripts', 'onStart / onBefore / onComplete', 'Detection API lifecycle (open, create detection per row, finalise).', L([rec('sys_transform_script', ID.onStart, 'onStart'), t(' · '), rec('sys_transform_script', ID.onBefore, 'onBefore'), t(' · '), rec('sys_transform_script', ID.onComplete, 'onComplete')])],
  ['Third-party integration', 'CDP Integration', 'Vulnerability Response integration header the runs are filed under.', L([rec('sn_sec_int_integration', ID.integration, 'Integration')])],
  ['Integration instance', 'CDP', 'Implementation record the Detection API and host import need.', L([rec('sn_sec_int_impl', ID.instance, 'Instance')])],
  ['REST integration', 'USEM Inbound Integration CDP - IVR (on demand)', 'Integration definition whose sys_id the onStart script reads; its polling script is not used by the Kafka path.', L([rec('sn_vul_rest_integration', ID.rest, 'REST integration'), t(' · '), rec('sys_script_include', ID.restUtil, 'IVRCDPIntegrationUtil')])],
  ['System properties', 'x_boar_bofa_usem_1.CDP_IVR_Integration, x_boar_bofa_usem_1.CDP IVR Integration Implement', 'Hold the sys_ids of the REST integration and the integration instance.', L([rec('sys_properties', ID.propInt, 'Integration property'), t(' · '), rec('sys_properties', ID.propImpl, 'Implementation property')])],
  ['Data source', 'cdp ivr sample data.xlsx (Uploaded)', 'Built from a sample spreadsheet to generate the staging table; processPayload is called without it.', L([rec('sys_data_source', ID.dataSource, 'Data source')])],
  ['Module', 'USEM CDP IVR Inbound Import', 'Navigator entry for the staging table.', L([rec('sys_app_module', ID.module, 'Module')])],
], [16, 27, 33, 24]));

children.push(h1('4. The message the consumer expects'));
children.push(body('processPayload reads the following shape. Every field is copied into a staging column of the same name with the u_ prefix (for example detections.ip_address becomes u_ip_address). Missing sections are skipped; missing fields are stored empty.'));
children.push(...code([
  '{',
  '  "envelope": {',
  '    "type", "topic_name", "namespace", "core_version", "ivr_version",',
  '    "event_id", "event_timestamp", "element_count", "element_activity"',
  '  },',
  '  "findings": [',
  '    {',
  '      "dis": {',
  '        "app_id", "app_full_name", "os_name", "sn_cmdb_sys_id", "cloud_account",',
  '        "resource_id", "cloud_resource_type", "runtime", "consequence_in_scope_flag"',
  '      },',
  '      "detections": {',
  '        "vulnerability", "dns", "port", "ip_address", "first_found", "last_found",',
  '        "solution_summary"',
  '      },',
  '      "vits": {',
  '        "source", "state", "cdp_finding_id", "sor_finding_id", "scorecard_source",',
  '        "description", "tcrs_special_exceptions"',
  '      },',
  '      "tpes": { "summary", "observation_category", "observation_subcategory" }',
  '    }',
  '  ]',
  '}',
]));

children.push(h1('5. How a staging row becomes a vulnerable item'));
children.push(h2('onStart (once per import set)'));
children.push(bullet('Reads the two system properties for the integration and the implementation sys_ids.'));
children.push(bullet([t('Inserts an integration run ('), t('sn_vul_integration_run', { mono: true }), t(', source "CDP IVR") and stores its sys_id on the import_set object shared by the three scripts.')]));
children.push(bullet([t('Opens the Detection API: '), t('new sn_vul.Detection(integrationId, implId, runSysId, \'Kafka_TransformMap\')', { mono: true }), t('.')]));
children.push(h2('onBefore (once per staging row)'));
children.push(bullet([t('Builds a host object from the row (ip_address, dns, app_id, sn_cmdb_sys_id, cloud fields, ...) and calls '), t('new sn_vul.ImportHost().hostImport(implId, host, "id", runSysId)', { mono: true }), t(', which creates the discovered item and resolves the CI through the CI lookup rules.')]));
children.push(bullet([t('When a CI is returned, creates a detection: cmdb_ci, src_vuln_id (the CDP vulnerability id), status from vits.state, port, source, ip_address, dns, src_ci, first_found and last_found; links the vulnerability when '), t('sn_vul_nvd_entry', { mono: true }), t(' holds an entry with that id; '), t('insertFixed = true', { mono: true }), t(' so fixed detections are also written.')]));
children.push(bullet([t('Sets '), t('ignore = true', { mono: true }), t(': the transform map never inserts a vulnerable item itself.')]));
children.push(h2('onComplete (once per import set)'));
children.push(bullet([t('Calls '), t('finalizeDetections()', { mono: true }), t(', which creates and updates the vulnerable items from the detections collected during the run, and logs the number created.')]));

children.push(h1('6. Stream Connect settings'));
children.push(table(['Setting', 'Value', 'Meaning'], [
  ['Topic', 'sn_usem_ivr_inbound, 16 partitions, namespace USEM', 'Cluster name snc.usem.sn_streamconnect.sn_usem_ivr_inbound.'],
  ['Subscription', 'SUBS00001015, delivery at least once, serialization text', 'A message can be delivered more than once after a failure; the consumer does not check for repeats.'],
  ['Initial offset', 'latest', 'On first start the stream reads only messages published after it started.'],
  ['Message handling', 'dynamic', 'The platform decides the batch size; the consumer receives a messages array.'],
  ['Max concurrency', '1', 'One consumer thread; messages are processed in order.'],
  ['Run as', 'a named user account', 'The consumer script runs with that user’s rights; a shared integration user is the usual choice.'],
], [20, 35, 45]));

children.push(h1('7. Records in the update set that are not on the live path'));
children.push(bullet([t('Flow '), t('USEM CDP IVR Inbound', { mono: true }), t(' (status draft, copied from the "CDP Inbound POC with Transform" flow) and the action '), t('Trigger Import Set for CDP IVR Inbound', { mono: true }), t(', an earlier approach that was replaced by the script consumer. '), rec('sys_hub_flow', ID.flow, 'Flow'), t(' · '), rec('sys_hub_action_type_definition', ID.action, 'Action')]));
children.push(bullet([t('Business rule '), t('Check CDP state', { mono: true }), t(' (deleted in the set). '), rec('sys_script', ID.rule, 'Business rule')]));
children.push(bullet([t('Script include '), t('IVRCDPIntegrationUtil', { mono: true }), t(' and the REST integration’s polling setup: kept so the Vulnerability Response integration records exist, not called by the Kafka path.')]));

children.push(h1('8. Points to keep in mind when reusing the pattern'));
[
  'The consumer reads messages[0] only. With dynamic message handling a batch can hold several messages; the others in the batch are not processed.',
  'JSON.parse runs without a guard and the only error handling is a gs.info in processPayload. A malformed message is logged at info level and dropped rather than parked in the unprocessed messages table.',
  'processPayload expects a data source sys_id but the consumer calls it without one, so the import sets carry no data source.',
  'The field-by-field mapping from the message to the staging columns is written into the script include; a new field needs a code change as well as a column.',
  'The raw message is not stored, so a row cannot be traced back to the exact message once staged.',
  'With at-least-once delivery, a message delivered twice produces two staging rows and two detection calls; there is no check on event_id.',
  'The integration run is inserted with state COMPLETE / SUCCESS before any row is processed.',
  'The stream runs as a personal user account.',
].forEach(x => children.push(bullet(x)));

children.push(h1('9. Where to look while it runs'));
children.push(bullet([rec('sys_kafka_stream', ID.stream, 'Stream'), t(' and '), rec('sys_kafka_subscription', ID.subscription, 'subscription'), t(': state, lag and messages per second.')]));
children.push(bullet([link(INST + 'sys_kafka_unprocessed_messages_list.do', 'Unprocessed messages'), t(': messages the platform could not hand to the consumer.')]));
children.push(bullet([list('sys_import_set', 'table_name=' + STAGING, 'Import sets'), t(' and '), link(INST + STAGING + '_list.do', 'staging rows'), t(': what arrived and how each row transformed.')]));
children.push(bullet([list('sn_vul_integration_run', 'source=CDP IVR', 'Integration runs'), t(' and '), list('sn_sec_cmn_src_ci', 'source=' + ID.instance, 'discovered items'), t(': host matching results.')]));
children.push(bullet([list('sn_vul_vulnerable_item', 'source=CDP', 'Vulnerable items'), t(' created by the Detection API (source "CDP" unless the message names another).')]));

const doc = new Document({
  creator: 'Mihir Singh',
  styles: { default: { document: { run: { font: FONT, size: 20, color: INK } } } },
  numbering: { config: [{ reference: 'steps', levels: [{ level: 0, format: 'decimal', text: '%1.', alignment: 'left',
    style: { paragraph: { indent: { left: 540, hanging: 360 } } } }] }] },
  sections: [{ properties: { page: { margin: { top: 1080, bottom: 1080, left: 1150, right: 1150 } } }, children: children }],
});
const out = path.join(__dirname, 'CDP IVR Inbound Integration - Architecture Overview.docx');
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(out, b); console.log('written:', out, b.length, 'bytes'); });
