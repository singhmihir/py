// Builds "VR Field Guide - New Joiner Training.pptx": Vulnerability Response on ServiceNow for new joiners, from the
// BofA and Citi programmes. Deloitte colours, Arial, 16:9 wide. Usage: NODE_PATH=<dir with pptxgenjs> node build_deck.js
const path = require('path');
const pptxgen = require('pptxgenjs');

const PDI = 'https://dev390397.service-now.com/';
const C = { black: '000000', green: '86BC25', dkgreen: '26890D', teal: '0D8390', blue: '007CB0', ink: '222222', grey: '53565A',
  mid: '75787B', light: 'BBBCBC', panel: 'F2F2F2', line: 'D0D0CE', white: 'FFFFFF' };
const F = 'Arial';
const W = 13.333, H = 7.5, M = 0.6;

const pres = new pptxgen();
pres.layout = 'LAYOUT_WIDE';
pres.title = 'Vulnerability Response on ServiceNow - Field Guide';
let page = 0;

function text(slide, t, x, y, w, h, o) {
  o = o || {};
  slide.addText(t, Object.assign({ x, y, w, h, fontFace: F, fontSize: 14, color: C.ink, margin: 0, valign: 'top', isTextBox: true }, o));
}
function titled(section, title, lead) {
  const s = pres.addSlide();
  page++;
  s.background = { color: C.white };
  text(s, section.toUpperCase(), M, 0.35, 8, 0.3, { fontSize: 10, bold: true, color: C.dkgreen, charSpacing: 1.5 });
  text(s, [{ text: title, options: { color: C.black } }, { text: '.', options: { color: C.green } }], M, 0.62, W - 2 * M, 0.7,
    { fontSize: 30, bold: true, valign: 'middle' });
  if (lead) text(s, lead, M, 1.36, W - 2 * M, 0.45, { fontSize: 14, color: C.grey });
  text(s, String(page), W - M - 0.5, H - 0.42, 0.5, 0.25, { fontSize: 9, color: C.mid, align: 'right' });
  text(s, 'VR field guide', M, H - 0.42, 3, 0.25, { fontSize: 9, color: C.mid });
  return s;
}
function card(slide, x, y, w, h, fill) {
  slide.addShape(pres.shapes.RECTANGLE, { x, y, w, h, fill: { color: fill || C.panel }, line: { color: fill || C.panel, width: 0 } });
}
function dot(slide, x, y, d, label, o) {
  o = o || {};
  slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: o.fill || C.green }, line: { color: o.fill || C.green, width: 0 } });
  if (label !== undefined) text(slide, String(label), x, y, d, d, { fontSize: o.size || 14, bold: true, color: o.color || C.white, align: 'center', valign: 'middle' });
}
function arrow(slide, x, y, w) {
  slide.addShape(pres.shapes.LINE, { x, y, w, h: 0, line: { color: C.light, width: 1.5, endArrowType: 'triangle' } });
}
function darrow(slide, x, y, h) {
  slide.addShape(pres.shapes.LINE, { x, y, w: 0, h, line: { color: C.light, width: 1.5, endArrowType: 'triangle' } });
}
function mono(t, o) { return { text: t, options: Object.assign({ fontFace: 'Courier New', color: C.dkgreen }, o || {}) }; }
function link(label, rel) { return { text: label, options: { hyperlink: { url: PDI + rel }, color: C.blue } }; }

// 1 ------------------------------------------------------------------ title
{
  const s = pres.addSlide(); page++;
  s.background = { color: C.black };
  text(s, 'TRAINING  ·  NEW JOINERS', M, 0.6, 8, 0.3, { fontSize: 11, bold: true, color: C.green, charSpacing: 2 });
  text(s, [{ text: 'Vulnerability Response on ServiceNow', options: { color: C.white } }, { text: '.', options: { color: C.green } }],
    M, 2.2, 9.6, 1.6, { fontSize: 44, bold: true, valign: 'bottom' });
  text(s, 'A field guide for your first live project', M, 3.95, 9, 0.5, { fontSize: 22, color: C.light });
  text(s, 'Lessons from the BofA and Citi programmes  ·  September 2026', M, 6.4, 9, 0.35, { fontSize: 13, color: C.mid });
  dot(s, 10.55, 2.35, 1.9); dot(s, 11.25, 4.55, 0.9, undefined, { fill: C.dkgreen }); dot(s, 10.2, 4.75, 0.45, undefined, { fill: C.teal });
  s.addNotes('Welcome. This session is the map you need before touching a live VR project: where findings come from, how each one finds its CI, the vocabulary (CVE, CWE, CVSS, SBOM), how to run an integration safely, and what is new in USEM. Demo links for the PDI are on slide 19.');
}

// 2 ------------------------------------------------------------------ agenda
{
  const s = titled('Agenda', 'What we will cover', 'Seven blocks, each ending with something you can do on the PDI.');
  const items = [
    ['The landscape', 'How a finding travels; why BofA runs about fifteen feeds'],
    ['From scan to CI', 'One host seen by two scanners; lookup rules and IRE'],
    ['Core concepts', 'DNS, FQDN, load balancers, network adapters; the rules that matter'],
    ['Running an integration', 'Before you start, common questions, two years of history, switching scanners'],
    ['Vulnerability basics', 'CVE vs CWE, CVSS v2 vs v3, SBOM, why CWE drives application findings'],
    ['Best practices', 'Credentials, error handling, fallback lookup rules'],
    ['USEM today', 'What is new, and the demo links'],
  ];
  items.forEach((it, i) => {
    const col = i < 4 ? 0 : 1, row = i < 4 ? i : i - 4;
    const x = M + col * 6.2, y = 2.15 + row * 1.12;
    dot(s, x, y, 0.62, i + 1, { size: 16 });
    text(s, it[0], x + 0.85, y - 0.02, 5.1, 0.38, { fontSize: 17, bold: true, color: C.black });
    text(s, it[1], x + 0.85, y + 0.36, 5.1, 0.6, { fontSize: 12.5, color: C.grey });
  });
  s.addNotes('Keep the pace brisk: the landscape and the scan-to-CI path are the foundation; everything after builds on them.');
}

// 3 ------------------------------------------------------------------ flow
{
  const s = titled('1 · The landscape', 'How a finding travels', 'Whatever the scanner, every finding follows the same path into ServiceNow.');
  const steps = [
    ['Scanner or feed', 'Qualys, VAMP, CDP, container and compliance scanners', 'source system'],
    ['Import', 'A scheduled integration run pulls what changed since the last run', 'sn_vul_integration_run'],
    ['Discovered item', 'One record per host per source, holding the scanned payload', 'sn_sec_cmn_src_ci'],
    ['CI lookup', 'Lookup rules find the CI; if none does, IRE decides', 'cmdb_ci'],
    ['Vulnerable item', 'The finding on that CI: VIT, AVIT, CVIT or test result', 'sn_vul_vulnerable_item'],
    ['Remediation task', 'Findings grouped, assigned to an owner, tracked to closure', 'sn_vul_vulnerability'],
  ];
  const bw = 1.78, gap = (W - 2 * M - 6 * bw) / 5;
  steps.forEach((st, i) => {
    const x = M + i * (bw + gap), y = 2.35;
    card(s, x, y, bw, 2.9, i === 3 ? 'E8F2D5' : C.panel);
    dot(s, x + 0.18, y + 0.2, 0.46, i + 1, { size: 13 });
    text(s, st[0], x + 0.18, y + 0.82, bw - 0.3, 0.6, { fontSize: 15, bold: true, color: C.black });
    text(s, st[1], x + 0.18, y + 1.45, bw - 0.3, 1.1, { fontSize: 11.5, color: C.grey });
    text(s, st[2], x + 0.12, y + 2.5, bw - 0.18, 0.3, { fontSize: 8, fontFace: 'Courier New', color: C.dkgreen });
    if (i < 5) arrow(s, x + bw + 0.04, y + 1.45, gap - 0.08);
  });
  card(s, M, 5.65, W - 2 * M, 1.0, C.white);
  text(s, [{ text: 'Then: ', options: { bold: true, color: C.black } },
    { text: 'the owner fixes and the next scan stops reporting the finding (closed), or raises a change, or requests an exception. Step 4, finding the right CI, is where most project effort goes.' }],
    M, 5.75, W - 2 * M, 0.8, { fontSize: 13, color: C.grey });
  s.addNotes('Walk left to right. Stress step 3: the discovered item keeps the raw payload per source, which is what we debug from. Step 4 is the subject of the next four slides.');
}

// 4 ------------------------------------------------------------------ 15 integrations
{
  const s = titled('1 · The landscape', 'Why BofA runs about fifteen integrations', 'No single tool sees everything, and every finding needs context before anyone can act on it.');
  text(s, '~15', M, 2.05, 3.2, 1.3, { fontSize: 80, bold: true, color: C.green });
  text(s, 'feeds in and out of VR at BofA', M, 3.35, 3.4, 0.4, { fontSize: 14, bold: true, color: C.black });
  const why = [
    'Each scanner sees a different surface: hosts, code, containers, cloud, configuration.',
    'Findings need context: who owns the asset, how critical it is.',
    'Bank data moves over a shared bus, both ways.',
    'Prioritising needs intelligence the scanners do not have.',
  ];
  text(s, why.map((w, i) => ({ text: w, options: { bullet: true, breakLine: i < why.length - 1 } })), M, 3.9, 3.5, 2.8,
    { fontSize: 12.5, color: C.grey, paraSpaceAfter: 8 });
  const groups = [
    ['Hosts and network', 'Qualys: host detections and the knowledge base (QIDs)'],
    ['Applications', 'VAMP: AppSec findings in (SAST, DAST, SCA, pen tests), status back out'],
    ['Containers and cloud', 'Container image scans; Wiz for cloud workloads'],
    ['Configuration', 'Compliance scans become test results and remediation groups'],
    ['Enterprise bus', 'CDP on Hermes (Kafka): findings in; remediation tasks and consequences out'],
    ['Context', 'CMDB and Discovery (IP enrichment); AIT inventory gives the owner; consequence records'],
    ['Intelligence', 'NVD (CVE), CWE, vendor advisories (CSAF, Microsoft, Red Hat)'],
  ];
  const gx = 4.45, gw = (W - M - gx - 0.25) / 2;
  groups.forEach((g, i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = gx + col * (gw + 0.25), y = 2.05 + row * 1.13;
    card(s, x, y, gw, 0.98);
    text(s, g[0], x + 0.2, y + 0.12, gw - 0.4, 0.3, { fontSize: 13, bold: true, color: C.black });
    text(s, g[1], x + 0.2, y + 0.43, gw - 0.4, 0.5, { fontSize: 11, color: C.grey });
  });
  text(s, 'Grouped from the BofA work we have delivered; the client integration register holds the full list.', gx, 6.62, W - M - gx, 0.3,
    { fontSize: 9.5, italic: true, color: C.mid });
  s.addNotes('Explain by category, not by product: a new scanner or feed almost always lands in one of these boxes. The counts vary by client; the categories do not.');
}

// 5 ------------------------------------------------------------------ same CI two scanners
{
  const s = titled('2 · From scan to CI', 'One host, two scanners', 'Two sources report the same server. Whether you get one CI or two depends on the lookup rules.');
  const src = [
    ['Qualys scan', 'DNS  app01.corp.example.com\nIP   10.20.30.40\nOS   Red Hat Enterprise Linux 8\nID   QG_HOSTID 48213'],
    ['Second source (Tenable, CDP)', 'FQDN app01.corp.example.com\nIP   10.20.30.40\nMAC  00:50:56:9a:1c:07\nID   agent 7f3c-…'],
  ];
  src.forEach((sr, i) => {
    const y = 2.1 + i * 2.05;
    card(s, M, y, 3.1, 1.75);
    text(s, sr[0], M + 0.2, y + 0.12, 2.8, 0.3, { fontSize: 13, bold: true, color: C.black });
    text(s, sr[1], M + 0.2, y + 0.5, 2.8, 1.15, { fontSize: 10, fontFace: 'Courier New', color: C.grey });
    arrow(s, M + 3.15, y + 0.87, 0.4);
    card(s, M + 3.6, y + 0.3, 2.1, 1.15, 'E8F2D5');
    text(s, 'Discovered item\n+ that source\'s lookup rules', M + 3.75, y + 0.42, 1.85, 0.9, { fontSize: 11, bold: true, color: C.black, valign: 'middle' });
    s.addShape(pres.shapes.LINE, { x: M + 5.75, y: y + 0.87, w: 0.55, h: i === 0 ? 1.03 : -1.02, line: { color: C.light, width: 1.5, endArrowType: 'triangle' } });
  });
  dot(s, M + 6.3, 3.35, 1.35);
  text(s, 'One CI\napp01', M + 6.3, 3.35, 1.35, 1.35, { fontSize: 13, bold: true, color: C.white, align: 'center', valign: 'middle' });
  text(s, 'Two vulnerable items on it (one per source), both pointing to the same CVE', M + 5.9, 4.85, 2.2, 1.0, { fontSize: 10.5, color: C.grey, align: 'center' });
  const px = 9.35, pw = W - M - px;
  text(s, 'Remember', px, 2.05, pw, 0.35, { fontSize: 15, bold: true, color: C.black });
  const pts = [
    'Each source keeps its own discovered item and its own rule chain.',
    'They meet on one CI only if both chains find the same record: shared identifiers (FQDN, serial) make that happen.',
    'Same CVE from two scanners = two vulnerable items. Report by CVE + CI to avoid double counting.',
    'If one chain misses, IRE can create a second, placeholder CI. Fix the rule or the CMDB data, never relink by hand.',
  ];
  pts.forEach((p, i) => {
    dot(s, px, 2.6 + i * 1.02, 0.34, i + 1, { size: 10 });
    text(s, p, px + 0.5, 2.55 + i * 1.02, pw - 0.5, 0.95, { fontSize: 11.5, color: C.grey });
  });
  s.addNotes('Use the BofA case: Qualys plus the CDP feed report the same servers. Payload values here are illustrative. Demo: open a matched discovered item and its CI.');
}

// 6 ------------------------------------------------------------------ lookup + IRE
{
  const s = titled('2 · From scan to CI', 'Lookup rules first, then IRE', 'What happens between the discovered item and the CI, and where IRE comes in.');
  const steps = [
    ['Import writes the discovered item', 'The host\'s payload: name, FQDN, IP, OS, scanner id.'],
    ['The source\'s lookup rules run in order', 'The first rule that returns exactly one CI wins.'],
    ['Retired CIs and ignored classes drop out', [mono('sn_sec_cmn.filterOutDecommissionedCI'), { text: ',  ' }, mono('sn_sec_cmn.ignoreCIClass')]],
    ['No rule matched: IRE decides', [{ text: 'On when ' }, mono('sn_sec_cmn.ci_creation_through_IRE'), { text: ' is true.' }]],
    ['The finding lands on the CI', 'Discovered item shows matched or unmatched; Reapply re-runs unmatched items later.'],
  ];
  steps.forEach((st, i) => {
    const y = 2.1 + i * 0.93;
    dot(s, M, y, 0.46, i + 1, { size: 13 });
    text(s, st[0], M + 0.7, y - 0.03, 6.2, 0.32, { fontSize: 14, bold: true, color: C.black });
    text(s, st[1], M + 0.7, y + 0.3, 6.2, 0.55, { fontSize: 11.5, color: C.grey });
    if (i < 4) darrow(s, M + 0.23, y + 0.5, 0.4);
  });
  const px = 7.75, pw = W - M - px;
  card(s, px, 2.05, pw, 4.65, C.black);
  text(s, [{ text: 'IRE  ', options: { color: C.green, fontSize: 20 } }, { text: 'Identification and Reconciliation Engine', options: { color: C.white } }], px + 0.3, 2.22, pw - 0.6, 0.42,
    { fontSize: 13.5, bold: true, valign: 'middle' });
  text(s, 'The CMDB\'s gatekeeper for every source that writes CIs.', px + 0.3, 2.7, pw - 0.6, 0.35, { fontSize: 12, color: C.light });
  const ire = [
    ['Identify', 'Identification rules (serial number, name, MAC + IP) decide: existing CI, or a new one.'],
    ['Reconcile', 'Reconciliation rules and data source precedence decide which source may update which field.'],
    ['De-duplicate', 'Duplicates are flagged for clean-up instead of silently multiplying.'],
    ['In VR', 'An unmatched host becomes a placeholder CI (Unclassed Hardware), kept out of reporting by the ignore list. Matching it properly is the lookup rules\' job.'],
  ];
  ire.forEach((r, i) => {
    const y = 3.2 + i * 0.84;
    text(s, r[0], px + 0.3, y, 1.4, 0.3, { fontSize: 12, bold: true, color: C.green });
    text(s, r[1], px + 1.7, y, pw - 2.0, 0.8, { fontSize: 11, color: C.white });
  });
  s.addNotes('Key message: lookup rules are VR\'s own matching, per source; IRE is the CMDB-wide engine used when they fail. A placeholder CI is a symptom, not a fix. Demo: sys_properties sn_sec_cmn.*, then the unmatched discovered items list.');
}

// 7 ------------------------------------------------------------------ core concepts
{
  const s = titled('3 · Core concepts', 'The words behind every lookup rule', 'What each identifier is, and how to reach the real CI behind a load balancer or an adapter.');
  const terms = [
    ['DNS', 'The network\'s phone book: turns a name into an IP address, and back.'],
    ['FQDN', 'Full name with domain: app01.corp.example.com. Unique, so the best name to match on.'],
    ['Hostname', 'The short name: app01. Often repeated across domains.'],
    ['NetBIOS', 'Windows short name (15 characters at most), from Windows scans.'],
    ['IP address', 'Where a host sits now. It moves (DHCP) and can be shared (virtual IPs).'],
    ['MAC address', 'Hardware id of a network card; stable for that card.'],
    ['Serial number', 'Vendor hardware id; the strongest identifier when it is not a dummy value.'],
    ['Network adapter', 'CI for a network card: holds IP and MAC, points to its host CI.'],
    ['Load balancer, VIP', 'A device spreading traffic across servers; the VIP is the one address users call.'],
  ];
  terms.forEach((t, i) => {
    const y = 2.02 + i * 0.5;
    if (i % 2 === 0) card(s, M, y - 0.04, 7.05, 0.5);
    text(s, t[0], M + 0.15, y + 0.06, 1.8, 0.3, { fontSize: 12, bold: true, color: C.black });
    text(s, t[1], M + 2.0, y + 0.06, 5.0, 0.4, { fontSize: 11, color: C.grey });
  });
  const cx = 8.15, cw = W - M - cx;
  function chain(y, title, nodes, note) {
    text(s, title, cx, y, cw, 0.3, { fontSize: 13, bold: true, color: C.black });
    const nw = (cw - 0.3 * (nodes.length - 1)) / nodes.length;
    nodes.forEach((n, i) => {
      const x = cx + i * (nw + 0.3);
      card(s, x, y + 0.42, nw, 0.72, i === nodes.length - 1 ? 'E8F2D5' : C.panel);
      text(s, n, x + 0.06, y + 0.42, nw - 0.12, 0.72, { fontSize: 9.5, bold: true, color: C.black, align: 'center', valign: 'middle' });
      if (i < nodes.length - 1) arrow(s, x + nw + 0.02, y + 0.78, 0.26);
    });
    text(s, note, cx, y + 1.22, cw, 0.62, { fontSize: 10.5, color: C.grey });
  }
  chain(2.02, 'Behind a load balancer', ['VIP\n(LB service)', 'Pool', 'Pool member', 'Server'],
    'Exactly one server behind the VIP: the finding goes to that server. Several: it stays on the VIP record.');
  chain(4.05, 'Behind an address', ['IP address record', 'Network adapter', 'Host CI'],
    'The address alone is weak: accept the host only if its class agrees with the scanned OS and its name with the scan.');
  s.addNotes('One slide on purpose: these nine words explain almost every lookup rule. Demo: cmdb_ci_lb_service, then a pool member, then cmdb_ci_network_adapter with its CI.');
}

// 8 ------------------------------------------------------------------ important rules
{
  const s = titled('3 · Core concepts', 'The lookup rules that matter', 'Our Qualys chain: 22 custom rules in front of 5 out-of-box ones, strongest identifier first.');
  const stages = [
    ['175–180', 'Hard identifiers', 'Serial number inside the class the OS implies, then across hardware.'],
    ['200–415', 'Names', 'Cisco phone MAC; FQDN; hostname + domain; DNS record → adapter → CI; short hostname; device name.'],
    ['420–460', 'Special devices', 'Management controllers (iLO, iDRAC) to their server; network interfaces; load balancer member, then service.'],
    ['700–750', 'Addresses, last', 'IP within the OS class; IP in hardware; adapter; IP record → adapter; vCenter, cluster VIP, phones.'],
    ['850–940', 'Fallbacks', 'Broad FQDN name; then out-of-box Qualys Host ID, FQDN, NetBIOS, DNS.'],
  ];
  const fills = [C.dkgreen, '4E9A1E', C.green, 'A9D16A', C.light];
  stages.forEach((st, i) => {
    const y = 2.05 + i * 0.93, inset = i * 0.18;
    card(s, M + inset, y, 7.6 - 2 * inset, 0.8, fills[i]);
    text(s, st[0], M + inset + 0.2, y + 0.1, 1.2, 0.3, { fontSize: 11, bold: true, color: i < 3 ? C.white : C.black });
    text(s, st[1], M + inset + 0.2, y + 0.4, 1.9, 0.32, { fontSize: 13, bold: true, color: i < 3 ? C.white : C.black });
    text(s, st[2], M + inset + 2.2, y + 0.1, 5.25 - 2 * inset, 0.65, { fontSize: 10.5, color: i < 3 ? C.white : C.black, valign: 'middle' });
  });
  const px = 8.75, pw = W - M - px;
  text(s, 'Three rules of thumb', px, 2.05, pw, 0.35, { fontSize: 15, bold: true, color: C.black });
  const rules = [
    ['Exactly one, or decline', 'Never guess. An unmatched host is honest; a wrong match hides a risk.'],
    ['Strongest first, IP last', 'Addresses move and are shared; names and serials do not.'],
    ['Class must agree', 'A Windows scan must not land on a network switch.'],
  ];
  rules.forEach((r, i) => {
    const y = 2.6 + i * 1.3;
    dot(s, px, y, 0.42, i + 1, { size: 12 });
    text(s, r[0], px + 0.6, y - 0.02, pw - 0.6, 0.32, { fontSize: 13, bold: true, color: C.black });
    text(s, r[1], px + 0.6, y + 0.33, pw - 0.6, 0.8, { fontSize: 11.5, color: C.grey });
  });
  s.addNotes('Order numbers are the rule order field: lower runs first. The same principles apply to any scanner; rules are defined per source. Demo: the Qualys rule list ordered by order.');
}

// 9 ------------------------------------------------------------------ before you start
{
  const s = titled('4 · Running an integration', 'Before you start any integration', 'Six things to settle in week one. Missing any of them is what delays go-live.');
  const cards = [
    ['Access', 'Service account with least privilege. API keys in ServiceNow credential records. Who renews them, and when.'],
    ['Connectivity', 'Cloud or on-premises source; MID Server, proxy and firewall allow-lists; the source\'s API rate limits.'],
    ['Data', 'Sample payloads, the field mapping sheet, daily volumes, run schedule, and how much history is needed.'],
    ['CMDB readiness', 'Do the hosts exist with FQDN, serial and IP? In which classes? Which lookup rules will find them?'],
    ['Process', 'Who owns each finding, how findings are grouped, remediation targets, and the exception route.'],
    ['Sign-off', 'A test instance with realistic data; success criteria (match rate, counts vs the source); a way back.'],
  ];
  const cw = (W - 2 * M - 0.5) / 3, ch = 2.1;
  cards.forEach((c, i) => {
    const x = M + (i % 3) * (cw + 0.25), y = 2.05 + Math.floor(i / 3) * (ch + 0.25);
    card(s, x, y, cw, ch);
    dot(s, x + 0.25, y + 0.25, 0.5, i + 1, { size: 14 });
    text(s, c[0], x + 0.95, y + 0.3, cw - 1.2, 0.4, { fontSize: 16, bold: true, color: C.black });
    text(s, c[1], x + 0.25, y + 0.95, cw - 0.5, 1.1, { fontSize: 12, color: C.grey });
  });
  s.addNotes('Turn this into the kick-off checklist. CMDB readiness is the item most often skipped and the root of most unmatched findings later.');
}

// 10 ----------------------------------------------------------------- FAQ
{
  const s = titled('4 · Running an integration', 'Questions you will be asked', 'The same eight come up on every project. Short answers, and where to look.');
  const qa = [
    ['Why are so many hosts unmatched?', 'Usually the host is not in the CMDB, or its name or IP differ there. Measure before changing rules.'],
    ['Why is a finding on the wrong CI?', 'A loose rule matched a shared or reused IP. Tighten the rule; never hand-edit the item.'],
    ['Why do we have duplicate CIs?', 'A lookup miss sent the host to IRE, which created a placeholder. Fix the rule or the data, then reapply.'],
    ['Why are fixed findings still open?', 'The source still reports them, or closure depends on the next scan. Check last found and close settings.'],
    ['Why don\'t counts match the scanner?', 'Different filters: states, sources, ignored classes, retired CIs, and time zones.'],
    ['The integration run failed. Now?', 'Expired credentials, rate limits, time-outs. Read the integration run and its log first.'],
    ['Why do times look different?', 'The instance shows your time zone; exports and APIs use UTC. Never compare the two raw.'],
    ['My update set missed records.', 'Lookup rules and scheduled jobs are not tracked; capture them explicitly. One scope per set.'],
  ];
  const cw = (W - 2 * M - 0.4) / 2;
  qa.forEach((q, i) => {
    const col = Math.floor(i / 4), row = i % 4, x = M + col * (cw + 0.4), y = 2.05 + row * 1.15;
    card(s, x, y, cw, 1.02);
    text(s, q[0], x + 0.22, y + 0.12, cw - 0.44, 0.3, { fontSize: 13, bold: true, color: C.black });
    text(s, q[1], x + 0.22, y + 0.46, cw - 0.44, 0.52, { fontSize: 11.5, color: C.grey });
  });
  s.addNotes('Each answer comes from a real BofA or Citi ticket. The first one matters most: on the demo instance nearly all imported hosts are unmatched because the CMDB behind them is not loaded; show that list.');
}

// 11 ----------------------------------------------------------------- history
{
  const s = titled('4 · Running an integration', 'Loading two years of history', 'Integrations are incremental: each run asks for what changed since the last one. History is a planned, one-off load.');
  const steps = [
    ['Agree scope', 'Which findings (open only, or fixed too), which sources, how many months.'],
    ['Check the source', 'How far back its API returns data; limits and paging.'],
    ['Prepare', 'Pause notifications, assignment and outbound feeds for backfilled items. Book an off-peak window.'],
    ['Load in slices', 'Set the integration\'s start date (delta start time) back and run month by month.'],
    ['Reconcile', 'Compare counts per slice with the source, then return to normal incremental runs.'],
  ];
  const bw = (W - 2 * M - 4 * 0.3) / 5;
  steps.forEach((st, i) => {
    const x = M + i * (bw + 0.3), y = 2.25;
    dot(s, x, y, 0.55, i + 1, { size: 15 });
    if (i < 4) s.addShape(pres.shapes.LINE, { x: x + 0.62, y: y + 0.275, w: bw - 0.32, h: 0, line: { color: C.light, width: 1.5 } });
    text(s, st[0], x, y + 0.75, bw - 0.1, 0.35, { fontSize: 14, bold: true, color: C.black });
    text(s, st[1], x, y + 1.13, bw - 0.1, 1.2, { fontSize: 11.5, color: C.grey });
  });
  card(s, M, 4.75, W - 2 * M, 1.9);
  text(s, 'Watch out for', M + 0.25, 4.88, 4, 0.35, { fontSize: 14, bold: true, color: C.black });
  const wo = [
    [{ text: 'Fixed findings may only update existing items, not create closed ones (Qualys: ' }, mono('sn_vul_qualys.update_fixed'), { text: ').' }],
    [{ text: 'Remediation targets count from first found: old items can arrive already overdue.' }],
    [{ text: 'Volume: storage, import queue and run time grow fast; test one month first.' }],
    [{ text: 'Downstream: do not send backfilled items to CDP / Kafka consumers unless agreed.' }],
  ];
  wo.forEach((w, i) => {
    const col = i % 2, row = Math.floor(i / 2), x = M + 0.25 + col * 6.05, y = 5.32 + row * 0.62;
    dot(s, x, y + 0.07, 0.16);
    text(s, w, x + 0.3, y, 5.6, 0.58, { fontSize: 11.5, color: C.grey });
  });
  s.addNotes('Two years is a lot of data for most scanners; many keep fixed detections for a limited time only, so confirm what the source can actually return before promising anything.');
}

// 12 ----------------------------------------------------------------- switching scanners
{
  const s = titled('4 · Running an integration', 'Switching scanners: Qualys to Tenable', 'Treat it as a new integration plus a controlled retirement. Seven steps.');
  const steps = [
    ['Inventory', 'Everything that depends on Qualys: integrations, lookup rules, assignment, grouping and target rules, exceptions, reports, outbound feeds.'],
    ['Build Tenable in test', 'Credentials; MID Server for Tenable.sc (on-premises); schedule and volumes.'],
    ['Rebuild lookup rules', 'Rules are per source. Same logic, on Tenable fields: FQDN, hostname, NetBIOS, IP, MAC, agent id.'],
    ['Map findings', 'A QID and a Tenable plugin meet at the CVE. Move exceptions and deferrals by CVE + CI.'],
    ['Run both', 'Compare match rates and counts per CI. Report by source to avoid double counting.'],
    ['Cut over', 'Stop Qualys runs. Close the remaining Qualys items with a clear reason; keep history.'],
    ['Decommission', 'Deactivate the Qualys integration, rules and jobs; update dashboards and runbooks.'],
  ];
  const cw = (W - 2 * M - 0.75) / 4, ch = 1.95;
  steps.forEach((st, i) => {
    const row = i < 4 ? 0 : 1, col = i < 4 ? i : i - 4, x = M + col * (cw + 0.25), y = 2.0 + row * (ch + 0.25);
    card(s, x, y, cw, ch);
    dot(s, x + 0.2, y + 0.2, 0.44, i + 1, { size: 13 });
    text(s, st[0], x + 0.8, y + 0.24, cw - 0.95, 0.35, { fontSize: 13.5, bold: true, color: C.black });
    text(s, st[1], x + 0.2, y + 0.78, cw - 0.4, 1.12, { fontSize: 11, color: C.grey });
  });
  const x = M + 3 * (cw + 0.25), y = 2.0 + ch + 0.25;
  card(s, x, y, cw, ch, C.black);
  text(s, 'Watch out', x + 0.2, y + 0.2, cw - 0.4, 0.3, { fontSize: 13.5, bold: true, color: C.green });
  text(s, 'New items restart remediation clocks. Owners see "new" findings that are old. Exceptions do not carry over by themselves.', x + 0.2, y + 0.6, cw - 0.4, 1.3,
    { fontSize: 11, color: C.white });
  s.addNotes('The parallel run is the step people skip. Without it you cannot show the client that Tenable finds the same hosts on the same CIs.');
}

// 13 ----------------------------------------------------------------- CVE vs CWE
{
  const s = titled('5 · Vulnerability basics', 'CVE vs CWE', 'A CVE is one flaw in one product. A CWE is the kind of mistake behind it.');
  const cols = [
    ['CVE', 'Common Vulnerabilities and Exposures', [
      'A specific, publicly disclosed flaw in a specific product and version.',
      'Format CVE-YEAR-NUMBER, e.g. CVE-2021-44228 (Log4Shell, Apache Log4j 2).',
      'Assigned by CVE numbering authorities, published in the NVD.',
    ], [mono('sn_vul_nvd_entry')]],
    ['CWE', 'Common Weakness Enumeration', [
      'A category of software weakness: the type of mistake.',
      'e.g. CWE-79 cross-site scripting, CWE-502 deserialization of untrusted data.',
      'Maintained by MITRE; basis of the CWE Top 25, mapped to the OWASP Top 10.',
    ], [mono('sn_vul_cwe')]],
  ];
  const cw = (W - 2 * M - 0.4) / 2;
  cols.forEach((c, i) => {
    const x = M + i * (cw + 0.4), y = 2.05;
    card(s, x, y, cw, 3.3, i === 0 ? C.black : C.panel);
    text(s, c[0], x + 0.35, y + 0.25, 2, 0.6, { fontSize: 34, bold: true, color: C.green });
    text(s, c[1], x + 0.35, y + 0.9, cw - 0.7, 0.35, { fontSize: 13, bold: true, color: i === 0 ? C.white : C.black });
    text(s, c[2].map((b, j) => ({ text: b, options: { bullet: true, breakLine: j < c[2].length - 1 } })), x + 0.35, y + 1.35, cw - 0.7, 1.45,
      { fontSize: 12, color: i === 0 ? 'E0E0E0' : C.grey, paraSpaceAfter: 5 });
    text(s, [{ text: 'In ServiceNow: ', options: { color: i === 0 ? C.light : C.mid } }].concat(c[3]), x + 0.35, y + 2.88, cw - 0.7, 0.3, { fontSize: 11 });
  });
  card(s, M, 5.6, W - 2 * M, 1.05, 'E8F2D5');
  text(s, [{ text: 'Many CVEs, one CWE. ', options: { bold: true, color: C.black } },
    { text: 'Log4Shell (CVE-2021-44228) is classified under CWE-917 and CWE-502. Scanner ids (Qualys QID, Tenable plugin, Veracode flaw) sit in ' },
    mono('sn_vul_third_party_entry'), { text: ' and link to their CVEs.' }], M + 0.3, 5.72, W - 2 * M - 0.6, 0.85, { fontSize: 12.5, color: C.grey, valign: 'middle' });
  s.addNotes('Demo: open the Log4Shell entry in sn_vul_nvd_entry, then CWE-79 and CWE-502 in sn_vul_cwe.');
}

// 14 ----------------------------------------------------------------- CVSS
{
  const s = titled('5 · Vulnerability basics', 'CVSS v2 vs CVSS v3', 'Both score severity from 0 to 10, but they measure it differently. The same flaw can land in a different band.');
  const rows = [
    ['', 'CVSS v2', 'CVSS v3.x'],
    ['Published', '2007', '3.0 in 2015, 3.1 in 2019'],
    ['How the attack works', 'Access Vector, Access Complexity, Authentication', 'Attack Vector (adds Physical), Attack Complexity, Privileges Required, User Interaction'],
    ['Reach beyond the target', 'Not measured', 'Scope: can the attack affect other components?'],
    ['Severity bands', 'Low 0–3.9 · Medium 4–6.9 · High 7–10', 'None 0 · Low 0.1–3.9 · Medium 4–6.9 · High 7–8.9 · Critical 9–10'],
    ['Status', 'NVD stopped scoring new CVEs with v2 in July 2022', 'Current standard; v4.0 published November 2023'],
  ];
  const tw = 8.3;
  s.addTable(rows.map((r, i) => r.map((c, j) => ({ text: c, options: {
    bold: i === 0 || j === 0, color: i === 0 ? C.white : (j === 0 ? C.black : C.grey),
    fill: { color: i === 0 ? C.black : (i % 2 ? C.white : C.panel) }, fontSize: i === 0 ? 13 : 11.5, fontFace: F, valign: 'middle',
    margin: [0.06, 0.12, 0.06, 0.12] } }))),
  { x: M, y: 2.05, w: tw, colW: [2.1, 2.9, 3.3], rowH: [0.45, 0.5, 0.85, 0.6, 0.75, 0.75], border: { type: 'solid', pt: 0.5, color: C.line } });
  const px = M + tw + 0.4, pw = W - M - px;
  card(s, px, 2.05, pw, 2.55, C.black);
  text(s, 'Log4Shell, scored twice', px + 0.3, 2.2, pw - 0.6, 0.35, { fontSize: 13, bold: true, color: C.green });
  text(s, [{ text: 'v2    9.3  ', options: { color: C.white, bold: true } }, { text: 'High', options: { color: C.light, breakLine: true } },
    { text: 'v3.1 10.0  ', options: { color: C.white, bold: true } }, { text: 'Critical', options: { color: C.green, bold: true } }], px + 0.3, 2.7, pw - 0.6, 1.0,
    { fontSize: 16, fontFace: 'Courier New', paraSpaceAfter: 4 });
  text(s, 'v2 has no Critical band.', px + 0.3, 3.95, pw - 0.6, 0.4, { fontSize: 11.5, color: C.light });
  card(s, px, 4.8, pw, 1.6);
  text(s, [{ text: 'Severity is not risk. ', options: { bold: true, color: C.black } },
    { text: 'Prioritise with exploitability, exposure and how critical the asset is: that is what the VR risk score adds.' }],
  px + 0.3, 4.95, pw - 0.6, 1.6, { fontSize: 12, color: C.grey });
  s.addNotes('Many clients still carry v2 scores on older CVEs and v3 on newer ones: check which one a risk rule or report reads. v4.0 adds attack requirements and supplemental metrics; expect it in newer feeds.');
}

// 15 ----------------------------------------------------------------- SBOM
{
  const s = titled('5 · Vulnerability basics', 'SBOM: the software bill of materials', 'An ingredients list for software: every component inside an application, with its version.');
  card(s, M, 2.05, 5.2, 4.6, C.black);
  text(s, 'payments-api 4.2.0', M + 0.3, 2.25, 4.6, 0.4, { fontSize: 15, bold: true, color: C.white });
  const comps = [['log4j-core', '2.14.1', true], ['spring-core', '5.3.18', false], ['jackson-databind', '2.13.2', false], ['openssl', '1.1.1k', false], ['commons-text', '1.9', false]];
  comps.forEach((c, i) => {
    const y = 2.85 + i * 0.66;
    card(s, M + 0.3, y, 4.6, 0.52, c[2] ? '3A5A12' : '1F1F1F');
    text(s, c[0], M + 0.5, y + 0.1, 2.0, 0.32, { fontSize: 12.5, fontFace: 'Courier New', color: C.white });
    text(s, c[1], M + 2.45, y + 0.1, 0.9, 0.32, { fontSize: 12.5, fontFace: 'Courier New', color: c[2] ? C.green : C.light });
    if (c[2]) text(s, 'CVE-2021-44228', M + 3.35, y + 0.12, 1.4, 0.3, { fontSize: 9.5, bold: true, color: C.green, align: 'right' });
  });
  const px = 6.3, pw = W - M - px;
  const pts = [
    ['What it lists', 'Components (libraries, packages), versions, suppliers, licences and hashes, for one build of one application.'],
    ['Formats', 'SPDX and CycloneDX, produced by build pipelines and SCA tools, or supplied by vendors.'],
    ['Why it matters', 'When the next Log4Shell lands, it answers "which of our applications ship log4j-core 2.14?" in minutes instead of weeks.'],
    ['Why now', 'US Executive Order 14028 (2021) made SBOMs expected for software sold to the US government; banks followed.'],
  ];
  pts.forEach((p, i) => {
    const y = 2.05 + i * 1.18;
    dot(s, px, y + 0.02, 0.4, i + 1, { size: 12 });
    text(s, p[0], px + 0.6, y, pw - 0.6, 0.32, { fontSize: 14, bold: true, color: C.black });
    text(s, p[1], px + 0.6, y + 0.36, pw - 0.6, 0.75, { fontSize: 12, color: C.grey });
  });
  s.addNotes('The component list is illustrative. Link to the next slide: SBOM covers the third-party part of an application; the bank\'s own code is covered by SAST and DAST, which speak CWE.');
}

// 16 ----------------------------------------------------------------- CWE for AVIT
{
  const s = titled('5 · Vulnerability basics', 'Why CWE matters more than CVE for AVITs', 'Application findings are mostly flaws in the bank\'s own code, and own code never gets a CVE.');
  const lanes = [
    ['Own code', 'SAST, DAST, pen tests', ['No CVE exists: CVEs are for published flaws in distributed products.', 'The finding carries a CWE, e.g. a real AVIT: Veracode-10 CWE-522 (insufficiently protected credentials).', 'Fix guidance, grouping, developer training and OWASP reporting all work by CWE.'], 'CWE', true],
    ['Third-party components', 'SCA tools, SBOM', ['A CVE applies to the library version the application ships.', 'The fix is to upgrade or replace the component.', 'The SBOM tells you where else that component lives.'], 'CVE', false],
  ];
  lanes.forEach((l, i) => {
    const y = 2.05 + i * 2.2;
    card(s, M, y, W - 2 * M, 2.0, l[4] ? 'E8F2D5' : C.panel);
    text(s, l[0], M + 0.3, y + 0.25, 2.9, 0.4, { fontSize: 17, bold: true, color: C.black });
    text(s, l[1], M + 0.3, y + 0.7, 2.9, 0.35, { fontSize: 12, color: C.grey });
    text(s, l[2].map((b, j) => ({ text: b, options: { bullet: true, breakLine: j < l[2].length - 1 } })), M + 3.4, y + 0.25, 6.9, 1.6,
      { fontSize: 12, color: C.grey, paraSpaceAfter: 6 });
    dot(s, W - M - 1.55, y + 0.35, 1.3, l[3], { size: 20, fill: l[4] ? C.dkgreen : C.mid });
  });
  text(s, [{ text: 'In short: ', options: { bold: true, color: C.black } },
    { text: 'for application findings the CWE tells the developer what to fix and the programme where its weak spots are. A CVE only appears when the flaw sits in someone else\'s component.' }],
  M, 6.45, W - 2 * M, 0.5, { fontSize: 12.5, color: C.grey });
  s.addNotes('The Veracode example is a real AVIT on the PDI (demo link on slide 19). BofA application findings reach us through VAMP with the CWE in the vulnerability reference.');
}

// 17 ----------------------------------------------------------------- best practices
{
  const s = titled('6 · Best practices', 'How we build VR integrations', 'Three habits that separate a clean go-live from months of clean-up.');
  const cols = [
    ['Credentials', [
      'Keep secrets in credential records (or the client\'s vault), never in scripts or properties.',
      'A service account with the least privilege the API needs.',
      'An owner for rotation and an alert before expiry.',
      'Separate credentials per environment.',
    ]],
    ['Error handling', [
      'One try/catch at the entry point; one clear error: what failed, for which record, why.',
      'Validate a payload before it leaves the instance.',
      'Make every run safe to repeat.',
      'Show failures where people look: the integration run, the record.',
    ]],
    ['Fallback lookup rules', [
      'Strongest identifier first, IP last.',
      'Exactly one match or decline; never guess.',
      'Keep the out-of-box rules as the final fallback.',
      'Measure the match rate before and after every change; reapply after.',
    ]],
  ];
  const cw = (W - 2 * M - 0.5) / 3;
  cols.forEach((c, i) => {
    const x = M + i * (cw + 0.25), y = 2.05;
    card(s, x, y, cw, 3.4);
    dot(s, x + 0.25, y + 0.25, 0.5, i + 1, { size: 14 });
    text(s, c[0], x + 0.95, y + 0.3, cw - 1.2, 0.4, { fontSize: 16, bold: true, color: C.black });
    text(s, c[1].map((b, j) => ({ text: b, options: { bullet: true, breakLine: j < c[1].length - 1 } })), x + 0.25, y + 0.95, cw - 0.5, 2.35,
      { fontSize: 12.5, color: C.grey, paraSpaceAfter: 9 });
  });
  card(s, M, 5.75, W - 2 * M, 0.72, C.black);
  text(s, [{ text: 'Delivery  ', options: { bold: true, color: C.green } },
    { text: 'One scope per update set  ·  capture untracked records explicitly  ·  test positive and negative paths twice  ·  no client rule change without sign-off', options: { color: C.white } }],
  M + 0.3, 5.75, W - 2 * M - 0.6, 0.72, { fontSize: 12, valign: 'middle' });
  s.addNotes('These are the review points we apply on BofA deliveries. The Delivery line is where most first-time mistakes happen.');
}

// 18 ----------------------------------------------------------------- USEM
{
  const s = titled('7 · USEM today', 'What is new in USEM', 'Unified Security Exposure Management brings the separate exposure types under one roof.');
  const cards = [
    ['Common layer', 'Unified Security Exposure Management: one foundation for infrastructure, application, container and configuration findings.', 'sn_vul_usem_common'],
    ['One workspace', 'Security Exposure Management workspace: analyse exposures across all types in one place.', '/now/vr-analysis'],
    ['Risk scoring', 'Risk Scoring for Security Exposure Management: one way to score risk across exposure types.', 'sn_sec_calculator'],
    ['Exceptions', 'Exception Management for USEM: one route for exceptions and deferrals, whatever the finding type.', 'sn_sec_exception'],
    ['Remediation', 'Remediation for Security Exposure Management: shared remediation handling across types.', 'sn_sec_rem'],
    ['One catalogue', 'Central Vulnerability Database: one place for vulnerability entries (CVE, CWE, scanner ids).', 'sn_sec_cvd'],
  ];
  const cw = (W - 2 * M - 0.5) / 3, ch = 2.05;
  cards.forEach((c, i) => {
    const x = M + (i % 3) * (cw + 0.25), y = 2.05 + Math.floor(i / 3) * (ch + 0.22);
    card(s, x, y, cw, ch);
    text(s, c[0], x + 0.25, y + 0.2, cw - 0.5, 0.38, { fontSize: 16, bold: true, color: C.black });
    text(s, c[1], x + 0.25, y + 0.65, cw - 0.5, 1.0, { fontSize: 11.5, color: C.grey });
    text(s, c[2], x + 0.25, y + 1.68, cw - 0.5, 0.28, { fontSize: 9.5, fontFace: 'Courier New', color: C.dkgreen });
  });
  text(s, 'Also new as sources: Wiz for cloud and containers, and CSAF vendor advisories. Installed on the demo PDI; check the release notes of the client\'s version.',
    M, 6.62, W - 2 * M, 0.3, { fontSize: 10, italic: true, color: C.mid });
  s.addNotes('All six applications are installed on the PDI (Australia release). Show the Security Exposure Management workspace next to the IT Remediation Workspace: same findings, one lens across types.');
}

// 19 ----------------------------------------------------------------- demo links
{
  const s = titled('7 · USEM today', 'Demo on the PDI', 'Every link opens the record or list on the demo instance. Log in first.');
  const groups = [
    ['Workspaces', [['IT Remediation Workspace', 'now/vr'], ['Security Exposure Management', 'now/vr-analysis'], ['CMDB Workspace', 'now/cmdb'],
      ['Integrations (sources)', 'sn_sec_int_integration_list.do'], ['Qualys host detection integration', 'sn_vul_integration.do?sys_id=2ff9d3701b7034102586a710604bcb0c']]],
    ['From scan to CI', [['Qualys lookup rules, in order', 'sn_sec_cmn_ci_lookup_rule_list.do?sysparm_query=source%3Ded44bdc453220300e8f9f745911c0801%5Eactive%3Dtrue%5EORDERBYorder'],
      ['Unmatched discovered items', 'sn_sec_cmn_src_ci_list.do?sysparm_query=state%3Dunmatched'], ['A matched item (virtual IP)', 'sn_sec_cmn_src_ci.do?sys_id=000574ba3bdacb502fcecefe23e45af0'],
      ['VR properties (ignore list, IRE)', 'sys_properties_list.do?sysparm_query=nameSTARTSWITHsn_sec_cmn'], ['IRE identification rules', 'cmdb_identifier_list.do'],
      ['Load balancer services', 'cmdb_ci_lb_service_list.do'], ['Pool members', 'cmdb_ci_lb_pool_member_list.do'], ['Network adapters', 'cmdb_ci_network_adapter_list.do']]],
    ['Findings and intelligence', [['Log4Shell (CVE-2021-44228)', 'sn_vul_nvd_entry.do?sys_id=50c9ac0b97558110e1349734a253af9a'],
      ['CWE-79 cross-site scripting', 'sn_vul_cwe.do?sys_id=fc49d490c71c10107393ec22c7c260b3'], ['CWE-502 deserialization', 'sn_vul_cwe.do?sys_id=6c5c0b76c72410107393ec22c7c26060'],
      ['AVIT with a CWE (Veracode)', 'sn_vul_app_vulnerable_item.do?sys_id=1168a83477596010ae567c51681061d8'], ['Open vulnerable items', 'sn_vul_vulnerable_item_list.do?sysparm_query=active%3Dtrue'],
      ['Remediation tasks', 'sn_vul_vulnerability_list.do?sysparm_query=active%3Dtrue'], ['Compliance remediation groups', 'sn_vulc_result_group_list.do']]],
  ];
  const cw = (W - 2 * M - 0.5) / 3;
  groups.forEach((g, i) => {
    const x = M + i * (cw + 0.25);
    card(s, x, 2.05, cw, 4.45);
    text(s, g[0], x + 0.25, 2.22, cw - 0.5, 0.38, { fontSize: 15, bold: true, color: C.black });
    text(s, g[1].map((l, j) => Object.assign(link(l[0], l[1]), { options: Object.assign(link(l[0], l[1]).options, { breakLine: j < g[1].length - 1, bullet: { code: '25CF' } }) })),
      x + 0.25, 2.78, cw - 0.5, 3.65, { fontSize: 13, paraSpaceAfter: 11 });
  });
  text(s, PDI.replace(/\/$/, ''), M, 6.72, 6, 0.25, { fontSize: 9.5, color: C.mid });
  s.addNotes('Suggested order: IT Remediation Workspace, a matched discovered item and its CI, the Qualys rule list, the unmatched list with the IRE property, a load balancer service and its pool, Log4Shell and CWE-79, the Veracode AVIT, then the Security Exposure Management workspace.');
}

// 20 ----------------------------------------------------------------- close
{
  const s = pres.addSlide(); page++;
  s.background = { color: C.black };
  text(s, [{ text: 'Five things to remember', options: { color: C.white } }, { text: '.', options: { color: C.green } }], M, 0.8, 11, 0.8, { fontSize: 34, bold: true });
  const pts = [
    'Every finding follows one path: import, discovered item, CI, vulnerable item, remediation task.',
    'Match on the strongest identifier. Exactly one CI, or none.',
    'IRE guards the CMDB. A lookup miss becomes a placeholder, not a fix.',
    'CVE is the flaw in a product; CWE is the kind of mistake. For the bank\'s own code, CWE is what you have.',
    'Measure before you change: counts, match rates, and a test on the PDI.',
  ];
  pts.forEach((p, i) => {
    const y = 2.0 + i * 0.95;
    dot(s, M, y, 0.55, i + 1, { size: 15 });
    text(s, p, M + 0.85, y + 0.03, 11, 0.5, { fontSize: 17, color: C.white, valign: 'middle' });
  });
  text(s, 'Questions?', M, 6.7, 6, 0.4, { fontSize: 14, bold: true, color: C.green });
  s.addNotes('Close by pointing people to the PDI demo links and to the project README of the story they are joining.');
}

pres.writeFile({ fileName: path.join(__dirname, 'VR Field Guide - New Joiner Training.pptx') }).then((f) => console.log('written:', f));
