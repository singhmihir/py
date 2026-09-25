// Renders the architecture figure of SNOWUSEMTP-2125 (VAMP findings into Application Vulnerability
// Response over Kafka) as figure-architecture.png, drawn in the card-and-band style of the
// "Vulnerability Stream Bridge" design document: HTML laid out here, screenshotted with the bundled
// Chromium at 2x (2088 px wide, the width of that document's figures).
// Usage: NODE_MODULES=<dir with puppeteer-core> CHROME=<chrome binary> node build_figure.js
const path = require('path');
const puppeteer = require(path.join(process.env.NODE_MODULES || 'node_modules', 'puppeteer-core'));

const chip = (t) => `<span class="chip">${t}</span>`;
const card = (o) => `<div class="card${o.cls ? ' ' + o.cls : ''}"${o.style ? ` style="${o.style}"` : ''}>
  ${o.kicker ? `<div class="kicker${o.kcls ? ' ' + o.kcls : ''}">${o.kicker}</div>` : ''}
  <div class="title">${o.title}</div>
  ${o.desc ? `<div class="desc">${o.desc}</div>` : ''}
  ${o.chips ? `<div class="chips">${o.chips.map(chip).join(' ')}</div>` : ''}
</div>`;
const harrow = (label) => `<div class="harrow"><div class="lbl">${label || ''}</div><div class="line"></div></div>`;
const varrow = (label, cls) => `<div class="varrow${cls ? ' ' + cls : ''}"><div class="stem"></div><div class="lbl">${label}</div></div>`;
const band = (o) => `<div class="band${o.cls ? ' ' + o.cls : ''}">
  <div class="bhead"><span class="bl${o.lcls ? ' ' + o.lcls : ''}">${o.label}</span><span class="bd">${o.desc}</span></div>
  <div class="row"${o.rowStyle ? ` style="${o.rowStyle}"` : ''}>${o.body}</div>
</div>`;

const html = `<!doctype html><html><head><meta charset="utf-8"><style>
  * { box-sizing: border-box; }
  body { margin: 0; background: #ffffff; font-family: "Liberation Sans", Arial, Helvetica, sans-serif; color: #1c1e21; }
  .fig { width: 1044px; padding: 30px 34px 26px; background: #f8f9f9; }
  h1 { font-size: 25px; margin: 0 0 6px; letter-spacing: -0.2px; }
  .sub { font-size: 12.5px; color: #555b60; line-height: 1.45; margin-bottom: 18px; max-width: 900px; }
  .band { border: 1px solid #d5d9dc; border-radius: 10px; background: #f0f2f3; padding: 12px 14px 14px; margin: 0; }
  .band.fw { background: #eaf3f3; border-color: #b6d0d0; }
  .band.gap { background: #f4f0f0; border-color: #d6c2c2; }
  .bhead { margin-bottom: 10px; }
  .bl { font-size: 10px; font-weight: bold; letter-spacing: 1.2px; color: #1f5f5f; text-transform: uppercase; margin-right: 8px; }
  .bl.built { color: #a5581a; }
  .bl.gapl { color: #9b2c2c; }
  .bd { font-size: 11.5px; color: #555b60; }
  .row { display: flex; align-items: stretch; gap: 0; }
  .card { background: #fff; border: 1px solid #d3d7da; border-radius: 8px; padding: 10px 12px 11px; flex: 1 1 0; min-width: 0; }
  .card.hi { border: 2px solid #2a6f6f; }
  .card.built { border: 2px solid #d98a3a; }
  .card.bad { border: 2px solid #c25454; background: #fff7f7; }
  .card.out { background: #fbfefe; }
  .kicker { font-size: 9px; letter-spacing: 1.1px; text-transform: uppercase; color: #6a7075; font-weight: bold; margin-bottom: 3px; }
  .kicker.teal { color: #1f5f5f; } .kicker.orange { color: #a5581a; } .kicker.red { color: #9b2c2c; }
  .title { font-size: 13.5px; font-weight: bold; line-height: 1.25; overflow-wrap: anywhere; }
  .desc { font-size: 10.8px; color: #555b60; line-height: 1.4; margin-top: 3px; overflow-wrap: anywhere; }
  .desc b { color: #1c1e21; }
  .chips { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px; }
  .chip { font-family: "Liberation Mono", "Courier New", monospace; font-size: 9px; background: #e3eeee; color: #1f5f5f; border-radius: 3px; padding: 2px 5px; white-space: nowrap; }
  .card.built .chip { background: #f7e9da; color: #8a4a12; }
  .card.bad .chip { background: #f5dede; color: #8a2b2b; }
  .harrow { width: 84px; flex: 0 0 84px; padding: 0 6px; position: relative; display: flex; flex-direction: column; justify-content: center; align-items: center; }
  .harrow .line { width: 100%; height: 0; border-top: 1.5px solid #9aa2a8; position: relative; }
  .harrow .line::after { content: ""; position: absolute; right: -1px; top: -5px; border-left: 8px solid #9aa2a8; border-top: 4.5px solid transparent; border-bottom: 4.5px solid transparent; }
  .harrow .lbl { font-size: 9.8px; color: #555b60; text-align: center; line-height: 1.2; margin-bottom: 5px; width: 76px; }
  .varrow { display: flex; align-items: center; gap: 8px; height: 40px; padding-left: 50%; }
  .varrow .stem { width: 0; height: 100%; border-left: 1.5px solid #9aa2a8; position: relative; margin-left: -1px; }
  .varrow .stem::after { content: ""; position: absolute; bottom: -1px; left: -5px; border-top: 8px solid #9aa2a8; border-left: 4.5px solid transparent; border-right: 4.5px solid transparent; }
  .varrow .lbl { font-size: 10.5px; color: #555b60; }
  .varrow.teal .lbl { color: #1f5f5f; font-weight: bold; }
  .varrow.teal .stem { border-color: #2a6f6f; } .varrow.teal .stem::after { border-top-color: #2a6f6f; }
  .col { display: flex; flex-direction: column; gap: 8px; flex: 1 1 0; min-width: 0; }
  .hooks { margin-top: 8px; display: flex; flex-direction: column; gap: 5px; }
  .hook { display: flex; gap: 8px; align-items: flex-start; font-size: 10.6px; line-height: 1.38; color: #555b60; }
  .hook .tag { font-family: "Liberation Mono", monospace; font-size: 9px; background: #e3eeee; color: #1f5f5f; border-radius: 3px; padding: 2px 5px; white-space: nowrap; margin-top: 1px; }
  .hook b { color: #1c1e21; }
  .list { margin: 6px 0 0; padding: 0 0 0 14px; font-size: 10.6px; color: #555b60; line-height: 1.4; }
  .list li { margin-bottom: 3px; }
  .list b { color: #1c1e21; }
  .legend { display: flex; gap: 18px; align-items: center; font-size: 10.5px; color: #555b60; margin: 14px 2px 10px; }
  .sw { display: inline-block; width: 22px; height: 12px; border-radius: 3px; background: #fff; vertical-align: middle; margin-right: 5px; border: 2px solid #2a6f6f; }
  .sw.grey { border-color: #d3d7da; border-width: 1.5px; } .sw.orange { border-color: #d98a3a; } .sw.red { border-color: #c25454; background: #fff7f7; }
  .callout { background: #fdf1e2; border: 1px solid #f0d3ac; border-radius: 6px; padding: 10px 14px; font-size: 11px; color: #4a4d50; line-height: 1.45; }
  .callout .cl { font-size: 9.5px; letter-spacing: 1.1px; text-transform: uppercase; color: #a5581a; font-weight: bold; margin-right: 8px; }
  .src { display: flex; justify-content: center; }
  .src .card { flex: 0 0 380px; }
</style></head><body><div class="fig">
<h1>VAMP findings reach Application Vulnerability Response over Kafka</h1>
<div class="sub">VAMP has no integration into ServiceNow today. The consumer stages one row per finding; the Transform Map's own scripts hand each row to the <b>AVR import API</b>, the code every application-scanner integration already uses, so application matching, vulnerability entries, state mapping and the AVIT lifecycle are inherited. One table the API does not cover, the pen test request, is filled by a small lookup-or-create in the same script.</div>

<div class="src">${card({ kicker: 'Source', title: 'VAMP', desc: 'source of the pen test findings and their retest results', style: 'flex:0 0 380px' })}</div>
${varrow('publishes each finding or retest result as a JSON message to Hermes')}

${band({ label: '1 · Kafka transport', desc: 'licensed platform infrastructure, configured, not built', body: [
  card({ kicker: 'ServiceNow · Hermes', title: 'Hermes Kafka', desc: 'ServiceNow’s own Kafka cluster behind Stream Connect (hermes-internal); VAMP’s producer publishes straight to it over the Stream Connect endpoint' }),
  harrow('carries'),
  card({ kicker: 'ServiceNow · Stream Connect', title: 'Topic sn_usem_vamp_inbound', desc: 'already created on dev: cluster name snc.usem.sn_streamconnect.sn_usem_vamp_inbound, 16 partitions, USEM namespace, JSON, at-least-once delivery', chips: ['sys_kafka_topic', 'sys_kafka_subscription'] }),
  harrow('aliased into the scope'),
  card({ kicker: 'ServiceNow · Stream Connect', title: 'Topic alias + Kafka stream', desc: 'scope x_boar_bofa_usem_1; the stream binds alias and consumer: initial offset, concurrency, run-as integration user', chips: ['sys_sc_topic_alias', 'sys_kafka_stream'] }),
].join('') })}
${varrow('one message per finding, delivered at least once')}

${band({ label: '2 · The consumer', lcls: 'built', desc: 'the only code this story writes before the framework: the same shape as the CDP IVR build', body: [
  card({ cls: 'built', kicker: 'Entry point', kcls: 'orange', title: 'Kafka script consumer', desc: 'receives the batch and hands <b>every</b> message to the loader, parsing guarded', chips: ['sys_kafka_script_consumer'] }),
  harrow('calls'),
  card({ cls: 'built', kicker: 'Script include', kcls: 'orange', title: 'VAMP inbound loader', desc: 'one Import Set per message, one staging row per finding (envelope + finding fields, raw message kept), then <b>transformAllMaps()</b>', chips: ['sys_script_include'] }),
  harrow('inserts into'),
  card({ cls: 'built', kicker: 'Front door', kcls: 'orange', title: 'Staging table', desc: 'x_boar_bofa_usem_1_vamp_inbound_import: one row per finding; import sets and their rows are the platform’s own', chips: ['sys_import_set', 'x_boar_bofa_usem_1_vamp_inbound_import'] }),
].join('') })}
${varrow('one row, into the Transform Map', 'teal')}

${band({ cls: 'fw', label: '3 · VR integration framework', desc: 'out-of-box code, reused unchanged; the Transform Map scripts are the only place it is called from', body: `
  <div class="col" style="flex:1.25">${card({ cls: 'hi', kicker: 'Where the work happens', kcls: 'teal', title: 'Transform Map', desc: 'source: staging table · target: Application Vulnerable Item · no field maps, three script hooks:', chips: ['sys_transform_map'] }).replace('</div>\n</div>', `</div>
    <div class="hooks">
      <div class="hook"><span class="tag">onStart</span><span>creates the <b>Integration Run</b> and <b>Process</b>, then opens the API: <b>new sn_vul.AVRImportAPIFactory().getAPI('v1', { process_gr })</b></span></div>
      <div class="hook"><span class="tag">onBefore</span><span>per row: <b>createOrUpdateApp()</b> → <b>createOrUpdateAppVulEntry()</b> (with cwe_list) → pen test lookup-or-create (band 4) → <b>createOrUpdateAVIT()</b>; then <b>ignore = true</b></span></div>
      <div class="hook"><span class="tag">onComplete</span><span><b>completeProcess()</b> writes the created / updated / unchanged counts on the Process and closes the Run</span></div>
    </div>
  </div>`)}
  </div>
  ${harrow('the API does the rest')}
  <div class="col">${`<div class="card"><div class="kicker teal">Inside the API · inherited</div><div class="title">sn_vul.AVRImportAPI (v1)</div><ul class="list">
      <li><b>Application</b> matched by the app lookup rules (sn_sec_cmn.CIIdentify) to a business application, else a Scanned Application is created</li>
      <li><b>Vulnerability</b>: NVD entry for a CVE id, otherwise an app vulnerability entry with its CWE links</li>
      <li><b>State</b> from the state map rows of the VAMP integration (VAMP status → state / substate)</li>
      <li><b>AVIT identity</b> = source_avit_id + application release + scan type + instance: a replay updates, never duplicates</li>
      <li>Run, Process and instance stamped on every record</li>
    </ul><div class="chips">${['sn_vul.AVRImportAPIFactory', 'sn_vul.AVRImportAPIBase', 'sn_vul.AppVulUtils', 'sn_vul.VulnerabilityStateMapper'].map(chip).join(' ')}</div></div>`}
  </div>
  ${harrow('creates or updates')}
  <div class="col" style="flex:0.9">
    ${card({ cls: 'out', kicker: 'Outcome', kcls: 'teal', title: 'Application release', desc: 'the application the finding belongs to', chips: ['sn_vul_app_release'] })}
    ${card({ cls: 'out', kicker: 'Outcome', kcls: 'teal', title: 'App vulnerability entry', desc: 'the weakness, with CWE links', chips: ['sn_vul_app_vul_entry', 'sn_vul_m2m_entry_cwe'] })}
    ${card({ cls: 'out hi', kicker: 'Outcome', kcls: 'teal', title: 'Application vulnerable item', desc: 'what the analyst works; same lifecycle as a scanner-imported AVIT', chips: ['sn_vul_app_vulnerable_item'] })}
  </div>` })}
${varrow('the one table the API does not write', 'teal')}

${band({ cls: 'gap', label: '4 · The gap: pen test assessment request', lcls: 'gapl', desc: 'no out-of-box path fits, so the Transform Map’s onBefore fills it with a lookup-or-create', body: [
  card({ cls: 'bad', kicker: 'Out of box · does not fit', kcls: 'red', title: 'ManualIngestionAVRPentestProcessor', desc: 'the only OOB code that creates a pen test request: insert-only (never updates), bound to spreadsheet ingestion, finds the application by name. The AVR import API has no method for this table at all.', chips: ['sn_vul.ManualIngestionAVRPentestProcessor'] }),
  harrow('replaced by'),
  card({ cls: 'built', kicker: 'Built · in onBefore', kcls: 'orange', title: 'Lookup-or-create', desc: 'find the request whose <b>u_assessment_id</b> equals VAMP’s assessment id; when missing, insert it with the fields the OOB processor sets (state Open, application, assessment type, requested by, application team); pass its sys_id as <b>assessment_request</b> to createOrUpdateAVIT()', chips: ['sys_transform_script · onBefore'] }),
  harrow('creates or reuses'),
  card({ cls: 'out', kicker: 'Outcome', kcls: 'teal', title: 'Pen test assessment request', desc: 'one per VAMP assessment; every AVIT of that assessment links to it', chips: ['sn_vul_pen_test_assessment_request'] }),
].join('') })}

<div class="legend"><span><span class="sw"></span>out-of-box code, reused unchanged</span><span><span class="sw grey"></span>platform, configured</span><span><span class="sw orange"></span>built in this story</span><span><span class="sw red"></span>out-of-box code that does not fit</span></div>
<div class="callout"><span class="cl">What this story writes</span>one loader script include, three Transform Map scripts and the pen test lookup-or-create. Everything else, Stream Connect, import sets, the AVR import API, the app lookup rules and the state map, is platform code. The OOB scanner integrations call the same API from processor script includes; calling it from the Transform Map scripts is what the story asks for, and the API does not care who calls it.</div>
</div></body></html>`;

(async () => {
  const b = await puppeteer.launch({ executablePath: process.env.CHROME, args: ['--no-sandbox', '--disable-gpu'] });
  const p = await b.newPage();
  await p.setViewport({ width: 1044, height: 800, deviceScaleFactor: 2 });
  await p.setContent(html, { waitUntil: 'load' });
  const el = await p.$('.fig');
  const out = path.join(__dirname, 'figure-architecture.png');
  await el.screenshot({ path: out });
  const box = await el.boundingBox();
  await b.close();
  console.log('written:', out, Math.round(box.width) + 'x' + Math.round(box.height), 'css px');
})().catch((e) => { console.error(e); process.exit(1); });
