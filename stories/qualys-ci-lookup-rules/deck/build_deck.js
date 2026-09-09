// Builds "Qualys CI Lookup Rules - Technical Walkthrough.pptx" from deck_data.json.
const fs = require('fs');
const path = require('path');
const PptxGenJS = require(path.join('/tmp/claude-0/-home-user-py/92674a7d-a733-5fc3-a7aa-42bdf76f593b/scratchpad', 'node_modules', 'pptxgenjs'));

const D = JSON.parse(fs.readFileSync(path.join(__dirname, 'deck_data.json'), 'utf8'));

const INK = '24272A', RED = 'E31837', NAVY = '012169', LIGHT = 'F4F5F6', WHITE = 'FFFFFF';
const MUTED = '6B7177', LINE = 'DDE0E3', CODEBG = '1E2124', CODEFG = 'E9EBED', CODEDIM = '9AA1A8';
const W = 13.33, H = 7.5, M = 0.5;
const SANS = 'Arial', MONO = 'Courier New';

const pres = new PptxGenJS();
pres.layout = 'LAYOUT_WIDE';
pres.author = 'Mihir Kumar Singh';
pres.title = 'Qualys CI Lookup Rules - Technical Walkthrough';

const shadow = () => ({ type: 'outer', color: '9AA1A8', blur: 6, offset: 1, angle: 90, opacity: 0.28 });

function light(s) { s.background = { color: LIGHT }; }

function slideTitle(s, text, kicker) {
  if (kicker) s.addText(kicker.toUpperCase(), { x: M, y: 0.34, w: 12.3, h: 0.24, fontFace: SANS, fontSize: 10.5,
    bold: true, color: RED, charSpacing: 1.6, isTextBox: true, margin: 0 });
  s.addText(text, { x: M, y: kicker ? 0.60 : 0.42, w: 12.3, h: 0.62, fontFace: SANS, fontSize: 30, bold: true,
    color: INK, isTextBox: true, margin: 0, valign: 'top' });
}

function card(s, x, y, w, h, fill) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.05, fill: { color: fill || WHITE },
    line: { color: LINE, width: 0.75 }, shadow: shadow() });
}

function codeBlock(s, x, y, w, h, lines, size) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.04, fill: { color: CODEBG }, line: { color: CODEBG, width: 0 } });
  const runs = lines.map((l, i) => {
    const cut = l.indexOf('//');
    const parts = [];
    if (cut > 0) {
      parts.push({ text: l.slice(0, cut), options: { color: CODEFG } });
      parts.push({ text: l.slice(cut), options: { color: CODEDIM, italic: true } });
    } else if (cut === 0) {
      parts.push({ text: l, options: { color: CODEDIM, italic: true } });
    } else {
      parts.push({ text: l || ' ', options: { color: CODEFG } });
    }
    parts[parts.length - 1].options.breakLine = i < lines.length - 1;
    return parts;
  }).flat();
  s.addText(runs, { x: x + 0.12, y: y + 0.08, w: w - 0.24, h: h - 0.16, fontFace: MONO, fontSize: size || 8,
    lineSpacingMultiple: 0.94, isTextBox: true, margin: 0, valign: 'top' });
}

function badge(s, x, y, text, w, h, fill) {
  const bw = w || 0.92, bh = h || 0.56;
  s.addShape(pres.ShapeType.roundRect, { x, y, w: bw, h: bh, rectRadius: 0.16, fill: { color: fill || RED }, line: { width: 0 } });
  s.addText(text, { x, y, w: bw, h: bh, fontFace: SANS, fontSize: bh > 0.5 ? 19 : 13, bold: true, color: WHITE,
    align: 'center', valign: 'middle', isTextBox: true, margin: 0 });
}

function divider(kicker, title, blurb, contents) {
  const s = pres.addSlide();
  s.background = { color: INK };
  s.addShape(pres.ShapeType.roundRect, { x: M, y: 2.55, w: 0.62, h: 0.62, rectRadius: 0.16, fill: { color: RED }, line: { width: 0 } });
  s.addText(kicker, { x: M, y: 2.55, w: 0.62, h: 0.62, fontFace: SANS, fontSize: 22, bold: true, color: WHITE,
    align: 'center', valign: 'middle', isTextBox: true, margin: 0 });
  s.addText(title, { x: 1.32, y: 2.52, w: 11.4, h: 0.72, fontFace: SANS, fontSize: 34, bold: true, color: WHITE,
    isTextBox: true, margin: 0, valign: 'middle' });
  s.addText(blurb, { x: 1.32, y: 3.34, w: 7.2, h: 0.9, fontFace: SANS, fontSize: 13.5, color: 'B9BEC3',
    isTextBox: true, margin: 0, valign: 'top' });
  (contents || []).forEach((c, i) => {
    const y = 2.56 + i * 0.44;
    s.addShape(pres.ShapeType.roundRect, { x: 9.05, y: y + 0.09, w: 0.16, h: 0.16, rectRadius: 0.05, fill: { color: RED }, line: { width: 0 } });
    s.addText(c, { x: 9.38, y, w: 3.45, h: 0.38, fontFace: SANS, fontSize: 11.5, color: 'D3D7DA', isTextBox: true, margin: 0, valign: 'middle' });
  });
  return s;
}

function footer(s, text) {
  s.addText(text, { x: M, y: 7.06, w: 12.3, h: 0.24, fontFace: SANS, fontSize: 8.5, color: MUTED,
    isTextBox: true, margin: 0 });
}

// ------------------------------------------------------------------ 1. title
{
  const s = pres.addSlide();
  s.background = { color: INK };
  s.addText('SNOWUSEMTP-895', { x: M, y: 1.78, w: 6, h: 0.26, fontFace: SANS, fontSize: 11, bold: true, color: RED,
    charSpacing: 1.8, isTextBox: true, margin: 0 });
  s.addText('Qualys CI Lookup Rules', { x: M, y: 2.52, w: 11.6, h: 0.92, fontFace: SANS, fontSize: 44, bold: true,
    color: WHITE, isTextBox: true, margin: 0, valign: 'middle' });
  s.addText('How a scanned host becomes a configuration item, rule by rule', { x: M, y: 3.48, w: 11.2, h: 0.44,
    fontFace: SANS, fontSize: 17, color: 'B9BEC3', isTextBox: true, margin: 0 });
  const facts = [['19', 'rules in the USEM chain'], ['3', 'added for the unmatched backlog'], ['6', 'property lists, no code to change']];
  facts.forEach(([n, l], i) => {
    const x = M + i * 4.15;
    s.addText(n, { x, y: 4.55, w: 1.05, h: 0.66, fontFace: SANS, fontSize: 42, bold: true, color: RED, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(l, { x: x + 1.1, y: 4.55, w: 2.9, h: 0.66, fontFace: SANS, fontSize: 12, color: 'B9BEC3', isTextBox: true, margin: 0, valign: 'middle' });
  });
  s.addText('SNOWUSEMTP-895   |   Unified Security Exposure Management   |   Vulnerability Response, Qualys Cloud Platform source',
    { x: M, y: 6.62, w: 12.3, h: 0.3, fontFace: SANS, fontSize: 11, color: '8A9198', isTextBox: true, margin: 0 });
  s.addNotes('Walkthrough of the custom CI lookup rules built for the Qualys source: what each rule matches, why it sits where it does, and how the chain behaves as a whole.');
}

// ------------------------------------------------------------------ 2. agenda
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'What this deck covers', 'Agenda');
  const items = [
    ['1', 'The framework', 'Where CI lookup sits in Vulnerability Response, what a rule is handed and what it must return.'],
    ['2', 'Five principles', 'The design decisions every rule in the chain shares, and why they are the same in all nineteen.'],
    ['3', 'The rules, in order', 'One page per rule: purpose, evidence, matching stages and place in the chain.'],
    ['4', 'The unmatched backlog', 'What the unresolved population is made of, and the three rules added to reach it.'],
    ['5', 'Testing and delivery', 'How the chain was exercised, what shipped, and how it is tuned in production.'],
  ];
  items.forEach(([n, t, d], i) => {
    const y = 1.52 + i * 1.06;
    card(s, M, y, 12.33, 0.92);
    badge(s, M + 0.22, y + 0.19, n, 0.54, 0.54);
    s.addText(t, { x: M + 0.95, y: y + 0.14, w: 3.3, h: 0.32, fontFace: SANS, fontSize: 15, bold: true, color: INK, isTextBox: true, margin: 0 });
    s.addText(d, { x: M + 0.95, y: y + 0.47, w: 11.0, h: 0.34, fontFace: SANS, fontSize: 11.5, color: MUTED, isTextBox: true, margin: 0 });
  });
  s.addNotes('Five sections. The middle one is the bulk of the deck: nineteen rule pages in chain order.');
}

// ------------------------------------------------------------------ section 1
divider('1', 'The framework', 'What the platform hands a lookup rule, what the rule owes back, and where the answer ends up.',
  ['From a scan to an accountable owner', 'What the platform hands a rule', 'What a rule owes back', 'The chain at a glance']);

// 3. from scan to owner
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'From a scan to an accountable owner', 'Why CI lookup matters');
  const steps = [
    ['Qualys scan', 'A host is scanned. Qualys reports its name, address, operating system and, sometimes, a serial.'],
    ['Discovered Item', 'The integration writes one row per scanned host, carrying the raw payload as source data.'],
    ['CI lookup chain', 'Rules run in order against that payload. The first rule to return a CI wins.'],
    ['Configuration item', 'The Discovered Item turns from unmatched to matched and points at a real CMDB record.'],
    ['Owner and remediation', 'Findings inherit the CI, its primary application, and with it the accountable owner.'],
  ];
  const cw = 2.34, gap = 0.15;
  steps.forEach(([t, d], i) => {
    const x = M + i * (cw + gap);
    card(s, x, 1.62, cw, 2.24);
    badge(s, x + 0.18, 1.80, String(i + 1), 0.44, 0.44);
    s.addText(t, { x: x + 0.18, y: 2.34, w: cw - 0.36, h: 0.52, fontFace: SANS, fontSize: 13.5, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'top' });
    s.addText(d, { x: x + 0.18, y: 2.88, w: cw - 0.36, h: 1.2, fontFace: SANS, fontSize: 10.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
    if (i < 4) s.addText('>', { x: x + cw + 0.01, y: 2.56, w: 0.14, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: RED, align: 'center', isTextBox: true, margin: 0 });
  });
  card(s, M, 4.14, 12.33, 1.5, WHITE);
  s.addText('Everything downstream depends on this one decision', { x: M + 0.3, y: 4.32, w: 11.7, h: 0.32, fontFace: SANS, fontSize: 15, bold: true, color: INK, isTextBox: true, margin: 0 });
  s.addText([
    { text: 'A wrong CI is worse than no CI. ', options: { bold: true, color: INK } },
    { text: 'An unmatched host stays visible on the exception report and gets chased. A host matched to the wrong CI silently sends its findings to the wrong application owner, who has no way to tell the difference. Every rule in the chain is therefore written to decline rather than guess: it returns a CI only when exactly one candidate survives its evidence, and hands the host on otherwise.', options: { color: MUTED } },
  ], { x: M + 0.3, y: 4.70, w: 11.7, h: 0.86, fontFace: SANS, fontSize: 11.5, isTextBox: true, margin: 0, valign: 'top' });
  footer(s, 'Discovered Items live on sn_sec_cmn_src_ci; vulnerable items reach them through the src_ci reference.');
  s.addNotes('The cost of a wrong match is the whole argument for the exactly-one design that follows.');
}

// 4. what a rule receives
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'What the platform hands a rule', 'The input');
  card(s, M, 1.58, 6.05, 2.35);
  s.addText('The entry point', { x: M + 0.25, y: 1.72, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  codeBlock(s, M + 0.25, 2.10, 5.55, 1.62, [
    '(function process(rule, sourceValue, sourcePayload) {',
    '',
    '    // rule          the lookup rule record itself',
    '    // sourceValue   the field named in Source field',
    '    // sourcePayload the whole scanned host record',
    '',
    '})(rule, sourceValue, sourcePayload);',
  ], 9);
  card(s, 6.78, 1.58, 6.05, 2.35);
  s.addText('The payload of one scanned host', { x: 7.03, y: 1.72, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  codeBlock(s, 7.03, 2.10, 5.55, 1.62, [
    '{ "ID": "35832680",',
    '  "IP": "171.128.225.96",',
    '  "DNS": "ah-1047132-001.corp.example.com",',
    '  "NETBIOS": "AH-1047132-001",',
    '  "OS": "Red Hat Enterprise Linux 9.8",',
    '  "TRACKING_METHOD": "AGENT",',
    '  "SERIAL_NUMBER": "VMware-42 1a 9c ..." }',
  ], 9);
  const fields = [
    ['SERIAL_NUMBER', 'Serial rules', 'Strongest identifier, but only 0.3% of the backlog carries one.'],
    ['DNS', 'Name rules and the three new rules', 'Present on 85.9% of hosts. Carries the hostname, the domain, and often the device role.'],
    ['IP', 'Address rules and the VIP rule', 'Always present. Weakest evidence: addresses move and are shared.'],
    ['OS', 'Every rule, as class evidence', 'Turned into a CMDB class. Empty on 32.6% and a multi-guess string on a further 5.0%.'],
  ];
  s.addText('What each field is used for', { x: M, y: 4.14, w: 6, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  fields.forEach(([f, r, d], i) => {
    const y = 4.52 + i * 0.62;
    card(s, M, y, 12.33, 0.54);
    s.addText(f, { x: M + 0.2, y: y + 0.06, w: 2.1, h: 0.42, fontFace: MONO, fontSize: 10.5, bold: true, color: RED, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(r, { x: M + 2.35, y: y + 0.06, w: 3.1, h: 0.42, fontFace: SANS, fontSize: 10.5, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(d, { x: M + 5.55, y: y + 0.06, w: 6.6, h: 0.42, fontFace: SANS, fontSize: 10.5, color: MUTED, isTextBox: true, margin: 0, valign: 'middle' });
  });
  footer(s, 'Source field on the rule record decides which payload field arrives as sourceValue; the rule reads the rest from sourcePayload.');
  s.addNotes('NetBIOS and the Qualys host id are used by the out-of-box rules at the end of the chain, not by the USEM rules.');
}

// 5. the contract
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'What a rule owes back', 'The contract');
  const cols = [
    ['Return a sys_id', RED, 'The host is matched. The framework links the Discovered Item and every finding on it to that CI and stops: no later rule is consulted.'],
    ['Return null', NAVY, 'The rule declines. The host moves to the next rule with its payload untouched. Declining is normal and cheap.'],
    ['Never guess', INK, 'A rule that cannot narrow its evidence to one CI must decline. Returning the first of several is the one outcome the chain forbids.'],
  ];
  cols.forEach(([t, c, d], i) => {
    const x = M + i * 4.15;
    card(s, x, 1.6, 3.9, 1.72);
    s.addShape(pres.ShapeType.roundRect, { x: x + 0.25, y: 1.82, w: 0.4, h: 0.4, rectRadius: 0.12, fill: { color: c }, line: { width: 0 } });
    s.addText(t, { x: x + 0.78, y: 1.82, w: 2.9, h: 0.4, fontFace: SANS, fontSize: 14.5, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(d, { x: x + 0.25, y: 2.34, w: 3.4, h: 1.0, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  });
  card(s, M, 3.55, 6.05, 2.85);
  s.addText('How the chain is ordered', { x: M + 0.25, y: 3.71, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  s.addText([
    { text: 'Rules run from the lowest order to the highest, and the first non-null answer wins. The order is therefore a statement about evidence: whatever runs earlier is trusted more.', options: { breakLine: true, paraSpaceAfter: 8 } },
    { text: 'The custom USEM rules occupy 175 to 850. The out-of-box Qualys rules run after them, from 860, so nothing shipped by the platform is replaced or bypassed.', options: {} },
  ], { x: M + 0.25, y: 4.09, w: 5.55, h: 2.1, fontFace: SANS, fontSize: 11.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  card(s, 6.78, 3.55, 6.05, 2.85);
  s.addText('Fields on the rule record', { x: 7.03, y: 3.71, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  const rec = [
    ['Source', 'Qualys Cloud Platform'],
    ['Table', 'sn_vul_qualys_host_attrb'],
    ['Source field', 'DNS, IP or SERIAL_NUMBER'],
    ['Method / Type', 'Script / Custom'],
    ['Order', '175 to 850'],
    ['Reapply', 'true, so changed items are re-evaluated'],
  ];
  rec.forEach(([k, v], i) => {
    const y = 4.13 + i * 0.38;
    s.addText(k, { x: 7.03, y, w: 1.9, h: 0.3, fontFace: SANS, fontSize: 10.5, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(v, { x: 8.95, y, w: 3.7, h: 0.3, fontFace: MONO, fontSize: 9.5, color: MUTED, isTextBox: true, margin: 0, valign: 'middle' });
  });
  footer(s, 'The framework entry point is sn_sec_cmn.CIIdentify.identify(source, payload); the reconcile job re-runs it for changed Discovered Items.');
  s.addNotes('Reapply true is what lets the on-demand job re-evaluate items after the rules change.');
}

// 6. the chain at a glance
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'The chain at a glance', 'Nineteen rules, strongest evidence first');
  const cells = [
    ['Serial number', ['175  Serial Number Class Match', '180  Serial Number Hardware Match'],
     'One machine for life, so it is tried first. Only 0.3% of scanned hosts report one.', M, 1.52, 1.86],
    ['Device label', ['200  Cisco IP Phone MAC'],
     'A phone label is a MAC address in disguise, resolved before it can look like a server name.', M, 3.50, 1.86],
    ['Name', ['250  FQDN Class Match', '260  FQDN Hardware Match', '300  Hostname Domain Class Match',
              '310  Hostname Domain Hardware Match', '350  Layered DNS Match', '400  Hostname Class Match',
              '410  Hostname Hardware Match', '450  FQDN Name Hardware Match'],
     'Eight rules, from the most precise name evidence, an exact FQDN written on the CI, down to a bare short name with only the CI class to vouch for it.', 4.72, 1.52, 3.84],
    ['Added for the backlog', ['420  Management Interface Match', '430  Network Interface Name Match', '460  Load Balancer Service Match'],
     'Labels that describe a part of a device, a controller, a port or a virtual address, rather than the device itself.', 8.94, 1.52, 1.86],
    ['Address', ['700  IP Class Match', '705  IP Hardware Match', '730  IP Adapter Match', '740  IP Layered Match'],
     'Last, and hedged with class and balancer checks, because addresses move between machines.', 8.94, 3.50, 1.86],
  ];
  cells.forEach(([t2, rules, note, x, y, h]) => {
    const w = 3.9;
    card(s, x, y, w, h);
    s.addText(t2, { x: x + 0.2, y: y + 0.12, w: w - 0.4, h: 0.28, fontFace: SANS, fontSize: 13, bold: true, color: RED, isTextBox: true, margin: 0 });
    s.addText(rules.map((rr, j) => ({ text: rr, options: { breakLine: j < rules.length - 1 } })),
      { x: x + 0.2, y: y + 0.44, w: w - 0.4, h: rules.length * 0.215 + 0.06, fontFace: MONO, fontSize: 9.5, color: INK,
        isTextBox: true, margin: 0, valign: 'top', lineSpacingMultiple: 1.06 });
    s.addText(note, { x: x + 0.2, y: y + 0.5 + rules.length * 0.215, w: w - 0.4, h: h - 0.58 - rules.length * 0.215,
      fontFace: SANS, fontSize: 9.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  });
  card(s, M, 5.52, 12.33, 1.16, WHITE);
  s.addText('Last in the chain', { x: M + 0.3, y: 5.64, w: 4, h: 0.28, fontFace: SANS, fontSize: 13, bold: true, color: RED, isTextBox: true, margin: 0 });
  s.addText([
    { text: '850  FQDN Name Broad Match', options: { fontFace: MONO, fontSize: 10, bold: true, color: INK } },
    { text: '   the only rule allowed outside the hardware tree, which is why it runs after everything else. Then the out-of-box Qualys rules: 860 Host ID, 880 Cloud Resource Id, 900 FQDN, 920 NetBIOS, 940 DNS, and the two IP rules that ship inactive. A host the custom chain declines still gets every platform rule; nothing shipped by ServiceNow is replaced, disabled or reordered.', options: { fontFace: SANS, fontSize: 10.5, color: MUTED } },
  ], { x: M + 0.3, y: 5.94, w: 11.7, h: 0.62, isTextBox: true, margin: 0, valign: 'top' });
  footer(s, 'Orders are spaced so a future rule can be inserted between two existing ones without renumbering the chain.');
  s.addNotes('The eight name rules are the heart of the chain because 85.9% of scanned hosts carry a DNS name and nothing stronger.');
}

// ------------------------------------------------------------------ section 2
divider('2', 'Five principles', 'The same five decisions run through all nineteen rules. Once they are clear, every rule page reads quickly.',
  ['Exactly one candidate, or decline', 'The class must agree with the scan', 'Placeholders are never a match', 'The IP breaks a name tie', 'A balancer is never the host']);

// 7. principle 1
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'One: exactly one candidate, or decline', 'Principle');
  card(s, M, 1.52, 6.05, 2.32);
  s.addText('Before: a capped result set', { x: M + 0.25, y: 1.66, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: MUTED, isTextBox: true, margin: 0 });
  codeBlock(s, M + 0.25, 2.02, 5.55, 0.74, [
    "gr.addQuery('name', host);",
    'gr.setLimit(2);        // ask the database for two',
    'gr.query();',
    'if (gr.getRowCount() == 1) { ... }',
  ], 9);
  s.addText('setLimit caps what comes back, so "one row" means one row inside the cap. It reads like a uniqueness test and is not one: a name shared by five CIs looks exactly like a name shared by two.',
    { x: M + 0.25, y: 2.88, w: 5.55, h: 0.86, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  card(s, 6.78, 1.52, 6.05, 2.32);
  s.addText('Now: first row, then look for a second', { x: 7.03, y: 1.66, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: RED, isTextBox: true, margin: 0 });
  codeBlock(s, 7.03, 2.02, 5.55, 0.98, [
    "gr.addQuery('name', host);",
    'gr.query();',
    'if (!gr.next()) return null;',
    'var match = gr.getUniqueValue();',
    'if (gr.hasNext()) return null;  // a second CI exists',
    'return match;',
  ], 9);
  s.addText('hasNext() asks the whole result set, so two CIs anywhere in the CMDB carrying that value end the rule. The uniqueness test now means what it says.',
    { x: 7.03, y: 3.12, w: 5.55, h: 0.62, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  const notes = [
    ['Where a tie can still be broken', 'The FQDN and hostname rules collect every candidate and take one when the scanned IP confirms exactly one of them. That is a second, independent piece of evidence, not a cap on the result.'],
    ['Where it cannot', 'Serial, address and the three new rules have nothing further to weigh. Two candidates always end the rule, and the host moves to whichever rule can read different evidence.'],
    ['What it costs', 'A rule that used to answer on a shared value now declines, so a few hosts fall further down the chain. That is the intended trade: a later, weaker match, or an honest unmatched, instead of a confident wrong one.'],
  ];
  notes.forEach(([t2, d], i) => {
    const x = M + i * 4.15;
    card(s, x, 4.04, 3.9, 2.4);
    s.addText(t2, { x: x + 0.25, y: 4.2, w: 3.4, h: 0.56, fontFace: SANS, fontSize: 13, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'top' });
    s.addText(d, { x: x + 0.25, y: 4.8, w: 3.4, h: 1.5, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  });
  footer(s, 'No rule in the chain calls setLimit; every one of them ends on next() followed by hasNext(), or on a counted set of owners.');
  s.addNotes('This is the single biggest correctness change in the rewrite.');
}

// 8. principle 2 - class
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'Two: the CI class must agree with the scan', 'Principle');
  s.addText('Qualys reports an operating system as free text. classFor() turns that text into the CMDB class the CI should be in, and the chain uses the answer in two different ways.',
    { x: M, y: 1.42, w: 12.3, h: 0.34, fontFace: SANS, fontSize: 12, color: MUTED, isTextBox: true, margin: 0 });
  card(s, M, 1.90, 6.05, 2.5);
  s.addText('As a filter, in the class rules', { x: M + 0.25, y: 2.04, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  codeBlock(s, M + 0.25, 2.42, 5.55, 0.86, [
    'var pref = classFor(sourcePayload.OS);',
    'if (!pref) return null;',
    'var gr = new GlideRecord(pref);   // and its sub-classes',
  ], 9);
  s.addText('The search never leaves the class, so a Red Hat host cannot be matched to a Windows Server that happens to carry the same name. No class means the rule declines and its hardware-wide twin takes over.',
    { x: M + 0.25, y: 3.36, w: 5.55, h: 0.9, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  card(s, 6.78, 1.90, 6.05, 2.5);
  s.addText('As a veto, in the hardware rules', { x: 7.03, y: 2.04, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  codeBlock(s, 7.03, 2.42, 5.55, 0.86, [
    'if (pref) {',
    '    var chk = new GlideRecord(pref);',
    '    if (!chk.get(id) && !generic[cls]) return null;',
    '}',
  ], 9);
  s.addText('The search covers the whole hardware tree, and the class is checked afterwards. Generic classes, Hardware, Computer, Server and UNIX Server, say nothing about the OS and never veto.',
    { x: 7.03, y: 3.36, w: 5.55, h: 0.9, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  card(s, M, 4.62, 12.33, 1.9);
  s.addText('What the OS text maps to', { x: M + 0.25, y: 4.76, w: 6, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  const map = [
    ['Red Hat, Ubuntu, SUSE, CentOS, EulerOS, Amazon', 'Linux Server'],
    ['Windows Server 2016 Standard', 'Windows Server'],
    ['Windows 10 Enterprise', 'Computer, a workstation'],
    ['VMware ESXi 7.0.3', 'ESX Server'],
    ['AIX, Solaris, SunOS, HP-UX', 'the matching UNIX class'],
    ['Cisco NX-OS, CatOS, Cisco', 'Network Gear'],
    ['NetApp, ONTAP', 'Storage Server'],
    ['Seven products separated by slashes', 'no class: the scan could not identify it'],
  ];
  map.forEach(([a, b], i) => {
    const x = M + (i % 2) * 6.15, y = 5.16 + Math.floor(i / 2) * 0.33;
    s.addText(a, { x: x + 0.25, y, w: 3.4, h: 0.3, fontFace: SANS, fontSize: 10, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText('>', { x: x + 3.68, y, w: 0.2, h: 0.3, fontFace: SANS, fontSize: 10, bold: true, color: RED, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(b, { x: x + 3.92, y, w: 2.0, h: 0.3, fontFace: SANS, fontSize: 10, bold: true, color: MUTED, isTextBox: true, margin: 0, valign: 'middle' });
  });
  footer(s, 'A third or more of the backlog carries no OS text at all, which is why every class rule has a hardware-wide twin behind it.');
  s.addNotes('Multi-guess fingerprints come from unauthenticated scans and are deliberately treated as no evidence.');
}

// 9. principle 3 - ignore list
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'Three: placeholder classes are never a match', 'Principle');
  card(s, M, 1.58, 6.05, 2.3);
  s.addText('Read once, applied in every search', { x: M + 0.25, y: 1.72, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  codeBlock(s, M + 0.25, 2.10, 5.55, 1.1, [
    "var ignore = (typeof _ignoreClass != 'undefined' &&",
    "    _ignoreClass) ? ('' + _ignoreClass) :",
    "    gs.getProperty('sn_sec_cmn.ignoreCIClass', '');",
    '',
    "gr.addQuery('sys_class_name', 'NOT IN', ignore);",
  ], 9);
  s.addText('The framework passes the list in when it has one; otherwise the rule reads the platform property itself. Either way the same exclusion is on every query.',
    { x: M + 0.25, y: 3.26, w: 5.55, h: 0.5, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  card(s, 6.78, 1.58, 6.05, 2.3);
  s.addText('What is on the list', { x: 7.03, y: 1.72, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  const ign = [
    ['sn_sec_cmn_unmatched_ci', 'the placeholder written when nothing matched'],
    ['sn_vul_qualys_ci', 'the scanner’s own shadow record'],
    ['cmdb_ci_unclassed_hardware', 'a device discovery could not classify'],
    ['cmdb_ci_incomplete_ip', 'an address with no device behind it'],
    ['cmdb_ci_dns_name', 'a name record, not a machine'],
  ];
  ign.forEach(([a, b], i) => {
    const y = 2.12 + i * 0.34;
    s.addText(a, { x: 7.03, y, w: 2.85, h: 0.3, fontFace: MONO, fontSize: 9, color: RED, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(b, { x: 9.92, y, w: 2.7, h: 0.3, fontFace: SANS, fontSize: 9.5, color: MUTED, isTextBox: true, margin: 0, valign: 'middle' });
  });
  card(s, M, 4.10, 12.33, 1.62);
  s.addText('Why a placeholder must never win', { x: M + 0.3, y: 4.28, w: 6, h: 0.32, fontFace: SANS, fontSize: 15, bold: true, color: INK, isTextBox: true, margin: 0 });
  s.addText('These classes exist to record that something was seen, not what it is. Matching a host to one of them would turn an honest "unmatched" into a false "matched": the Discovered Item would look resolved, the exception report would stop showing it, and the findings would hang off a record no application team owns. Excluding them keeps an unresolved host visible and chaseable, which is the outcome the design prefers over a comfortable but empty answer.',
    { x: M + 0.3, y: 4.66, w: 11.7, h: 1.2, fontFace: SANS, fontSize: 11.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  footer(s, 'Administrators change the list in sn_sec_cmn.ignoreCIClass; no rule holds a copy of it.');
  s.addNotes('This is also why the rules never write a placeholder themselves.');
}

// 10. principle 4 and 5
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'Four and five: the tie-break, and the balancer', 'Principles');
  card(s, M, 1.55, 6.05, 2.55);
  badge(s, M + 0.25, 1.72, '4', 0.44, 0.44);
  s.addText('The scanned IP breaks a name tie', { x: M + 0.82, y: 1.72, w: 5.0, h: 0.44, fontFace: SANS, fontSize: 15, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
  s.addText('CMDBs carry duplicate names honestly: a retired server and its rebuilt replacement, a cluster alias on two nodes. Where a second, independent piece of evidence exists, the rule uses it rather than declining.',
    { x: M + 0.25, y: 2.26, w: 5.55, h: 0.72, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  codeBlock(s, M + 0.25, 3.02, 5.55, 0.92, [
    'if (ids.length == 1)',
    '    return ids[0];                 // no tie at all',
    'if (ids.length > 1 && ipHits.length == 1)',
    '    return ipHits[0];              // the IP decides',
  ], 9);
  card(s, 6.78, 1.55, 6.05, 2.55);
  badge(s, 7.03, 1.72, '5', 0.44, 0.44);
  s.addText('A load balancer is never the host', { x: 7.60, y: 1.72, w: 5.0, h: 0.44, fontFace: SANS, fontSize: 15, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
  s.addText('A balancer answers on virtual addresses for the servers behind it. Matching a scanned VIP to the balancer device would put every pool member’s findings on the network team.',
    { x: 7.03, y: 2.26, w: 5.55, h: 0.72, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  codeBlock(s, 7.03, 3.02, 5.55, 0.92, [
    'function isLoadBalancer(id) {',
    "    var lb = new GlideRecord('cmdb_ci_lb');",
    '    return lb.isValid() && lb.get(id);',
    '}',
  ], 9);
  card(s, M, 4.32, 12.33, 1.75);
  s.addText('The consequence, and the rule that answers it', { x: M + 0.3, y: 4.50, w: 8, h: 0.32, fontFace: SANS, fontSize: 15, bold: true, color: INK, isTextBox: true, margin: 0 });
  s.addText([
    { text: 'Refusing the balancer left those hosts unmatched, and virtual IPs are the single largest group in the backlog. The answer is not to relax the refusal but to give the host its proper record: the Load Balancer Service CI that models the VIP itself. ', options: { color: MUTED } },
    { text: 'Rule 460 does exactly that, and the hardware rules go on refusing the device.', options: { color: INK, bold: true } },
  ], { x: M + 0.3, y: 4.88, w: 11.7, h: 1.0, fontFace: SANS, fontSize: 11.5, isTextBox: true, margin: 0, valign: 'top' });
  footer(s, 'Load Balancer devices sit under Server in the CMDB hierarchy, not under Network Gear; the interface rule searches both branches for that reason.');
  s.addNotes('Principles four and five are the two places where the chain deliberately does something more than an exact match.');
}

// 11. queryMatch decision
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'A platform helper we chose not to call', 'Design decision');
  s.addText('The out-of-box CIIdentify script include carries a _queryMatch helper that looks, at first glance, like exactly what these rules do. It was reviewed and left alone. Four reasons:',
    { x: M, y: 1.44, w: 12.3, h: 0.36, fontFace: SANS, fontSize: 12, color: MUTED, isTextBox: true, margin: 0 });
  const reasons = [
    ['It is private', 'The leading underscore marks it as internal. It is undocumented and free to change or vanish in any upgrade, which makes it an unsafe dependency for rules the bank runs in production.'],
    ['It resolves ties by picking one', 'On several matches it logs the duplication and returns the first. That is the precise behaviour the chain is built to avoid: a silent wrong answer instead of an honest decline.'],
    ['It mutates the framework result', 'It writes into the caller’s own result object and caps the collection it fills at ten entries, so its behaviour depends on state the rule does not control.'],
    ['It saves two lines', 'What it replaces is a query and a uniqueness check. Writing those out keeps each rule readable on its own and keeps the chain independent of internals.'],
  ];
  reasons.forEach(([t, d], i) => {
    const x = M + (i % 2) * 6.28, y = 1.92 + Math.floor(i / 2) * 1.72;
    card(s, x, y, 6.05, 1.55);
    badge(s, x + 0.25, y + 0.2, String(i + 1), 0.42, 0.42);
    s.addText(t, { x: x + 0.8, y: y + 0.2, w: 5.0, h: 0.42, fontFace: SANS, fontSize: 13.5, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(d, { x: x + 0.25, y: y + 0.72, w: 5.55, h: 0.72, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  });
  card(s, M, 5.42, 12.33, 0.98, WHITE);
  s.addText([
    { text: 'What the rules need instead.  ', options: { bold: true, color: INK } },
    { text: '"Exactly one match, or decline" is not on offer anywhere in the platform API, and it is the whole contract of this chain. Each rule states it in two lines of its own code, where a reviewer can see it.', options: { color: MUTED } },
  ], { x: M + 0.3, y: 5.60, w: 11.7, h: 0.7, fontFace: SANS, fontSize: 11.5, isTextBox: true, margin: 0, valign: 'top' });
  footer(s, 'The platform rules that ship with the Qualys integration continue to use it; only the custom USEM rules avoid it.');
  s.addNotes('Worth stating explicitly in review, since a reader who knows the script include will ask.');
}

// ------------------------------------------------------------------ section 3: rules
divider('3', 'The rules, in order', 'One page per rule: what it matches, the stages that do the work, and where it sits in the chain.',
  ['Serial number, 175 and 180', 'Device label, 200', 'Name, 250 to 450', 'Backlog additions, 420 to 460', 'Address, 700 to 740', 'Broad fallback, 850']);

const GROUPCOLOR = { Serial: RED, Phone: NAVY, Name: NAVY, Backlog: RED, Address: NAVY, Fallback: INK };
const GROUPLABEL = { Serial: 'Serial number evidence', Phone: 'Device label evidence', Name: 'Name evidence',
  Backlog: 'Added for the unmatched backlog', Address: 'Address evidence', Fallback: 'Broad fallback' };

const CODE_LINE = 0.128, CODE_PAD = 0.18, NOTE_LINE = 0.156;

function wrapCount(text, chars) { // rough line count for a fixed-width column
  let lines = 0;
  text.split(' ').reduce((cur, w) => {
    if ((cur + ' ' + w).trim().length > chars) { lines++; return w; }
    return (cur + ' ' + w).trim();
  }, '');
  return lines + 1;
}

D.rules.forEach((r) => {
  const s = pres.addSlide(); light(s);
  badge(s, M, 0.36, r.order, 0.92, 0.58, GROUPCOLOR[r.group]);
  s.addText(r.name, { x: M + 1.08, y: 0.34, w: 11.2, h: 0.36, fontFace: SANS, fontSize: 22, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
  s.addText(GROUPLABEL[r.group].toUpperCase(), { x: M + 1.08, y: 0.70, w: 11.2, h: 0.22, fontFace: SANS, fontSize: 9,
    bold: true, color: MUTED, charSpacing: 1.4, isTextBox: true, margin: 0 });
  s.addText(r.purpose, { x: M, y: 1.04, w: 12.33, h: 0.56, fontFace: SANS, fontSize: 11.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });

  [['Reads', r.reads], ['Returns', r.returns]].forEach(([k, v], i) => {
    const x = M + i * 6.28;
    card(s, x, 1.68, 6.05, 0.5);
    s.addText(k, { x: x + 0.2, y: 1.72, w: 0.86, h: 0.42, fontFace: SANS, fontSize: 10, bold: true, color: RED, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(v, { x: x + 1.08, y: 1.72, w: 4.8, h: 0.42, fontFace: SANS, fontSize: 10.5, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
  });

  // rows sized to their own content, then the slack shared out and the stack centred
  const rows = r.rows, n = rows.length, top = 2.32, avail = 4.04, gap = 0.10;
  const need = rows.map((row) => {
    const codeH = row[2].length * CODE_LINE + CODE_PAD;
    const textH = 0.34 + wrapCount(row[1], 52) * NOTE_LINE;
    return Math.max(codeH + 0.26, textH + 0.24, 0.86);
  });
  const sum = need.reduce((a, b) => a + b, 0) + gap * (n - 1);
  const slack = Math.max(0, avail - sum);
  const add = Math.min(slack / n, 0.6);
  const heights = need.map((h) => h + add);
  const total = heights.reduce((a, b) => a + b, 0) + gap * (n - 1);
  if (sum > avail) console.warn('OVERFLOW RISK on rule ' + r.order + ': needs ' + sum.toFixed(2) + '" of ' + avail + '"');
  let y = top + Math.max(0, (avail - total) / 2);

  rows.forEach((row, i) => {
    const rh = heights[i];
    card(s, M, y, 12.33, rh);
    s.addShape(pres.ShapeType.roundRect, { x: M + 0.22, y: y + rh / 2 - 0.14, w: 0.28, h: 0.28, rectRadius: 0.09, fill: { color: GROUPCOLOR[r.group] }, line: { width: 0 } });
    s.addText(String(i + 1), { x: M + 0.22, y: y + rh / 2 - 0.14, w: 0.28, h: 0.28, fontFace: SANS, fontSize: 10, bold: true, color: WHITE, align: 'center', valign: 'middle', isTextBox: true, margin: 0 });
    s.addText([
      { text: row[0], options: { fontSize: 12, bold: true, color: INK, breakLine: true, paraSpaceAfter: 4 } },
      { text: row[1], options: { fontSize: 9.5, color: MUTED } },
    ], { x: M + 0.6, y: y + 0.1, w: 3.55, h: rh - 0.2, fontFace: SANS, isTextBox: true, margin: 0, valign: 'middle' });
    const codeH = row[2].length * CODE_LINE + CODE_PAD;
    codeBlock(s, 5.05, y + (rh - codeH) / 2, 7.6, codeH, row[2], 8);
    y += rh + gap;
  });

  const chain = [['Before', r.before], ['Reaches', r.reaches], ['After', r.after]];
  chain.forEach(([k, v], i) => {
    const x = M + i * 4.15;
    s.addText(k.toUpperCase(), { x, y: 6.50, w: 3.9, h: 0.2, fontFace: SANS, fontSize: 8.5, bold: true, color: RED, charSpacing: 1.2, isTextBox: true, margin: 0 });
    s.addText(v, { x, y: 6.72, w: 3.9, h: 0.6, fontFace: SANS, fontSize: 9.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  });
  s.addNotes(r.name + '. ' + r.purpose);
});

// ------------------------------------------------------------------ section 4: backlog
divider('4', 'The unmatched backlog', 'What the unresolved population is actually made of, and the three rules built to reach it.',
  ['What 281,700 hosts are made of', 'What evidence they carry', 'Six properties that tune the rules']);

// population chart
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'What 281,700 unmatched hosts are made of', 'Analysis');
  s.addText('A spread sample of the unresolved Discovered Items was profiled by the evidence each host carries, then projected across the whole population. Three groups stood out as reachable by rules that did not yet exist.',
    { x: M, y: 1.42, w: 12.3, h: 0.36, fontFace: SANS, fontSize: 12, color: MUTED, isTextBox: true, margin: 0 });
  const labels = D.population.map((p) => p[0]);
  const values = D.population.map((p) => p[1]);
  s.addChart(pres.ChartType.bar, [{ name: 'Estimated hosts', labels, values }], {
    x: M, y: 1.92, w: 7.5, h: 4.55, barDir: 'bar', barGapWidthPct: 45,
    chartColors: [RED], showTitle: false, showLegend: false,
    showValue: true, dataLabelPosition: 'outEnd', dataLabelColor: INK, dataLabelFontFace: SANS, dataLabelFontSize: 9,
    dataLabelFormatCode: '#,##0',
    catAxisLabelColor: INK, catAxisLabelFontFace: SANS, catAxisLabelFontSize: 9.5, catAxisLineShow: false,
    valAxisLabelColor: MUTED, valAxisLabelFontFace: SANS, valAxisLabelFontSize: 8.5, valAxisMinVal: 0, valAxisMaxVal: 90000, valAxisMajorUnit: 15000,
    valGridLine: { color: 'E4E6E8', size: 0.75 }, catGridLine: { style: 'none' }, valAxisLineShow: false,
  });
  const gaps = [
    ['460', 'Virtual IPs', '71,892', 'Refused by every hardware rule on purpose, because the address belongs to a balancer.'],
    ['430', 'Interface and VLAN addresses', '47,420', 'The label names a port on a device, so the whole label never matches a CI name.'],
    ['420', 'Management controllers', '4,402', 'The label is the server name plus a suffix, so the server is never found under it.'],
  ];
  s.addText('The three gaps, and the rules that close them', { x: 8.32, y: 1.92, w: 4.5, h: 0.3, fontFace: SANS, fontSize: 13.5, bold: true, color: INK, isTextBox: true, margin: 0 });
  gaps.forEach(([o, t, n, d], i) => {
    const y = 2.34 + i * 1.42;
    card(s, 8.32, y, 4.51, 1.28);
    badge(s, 8.52, y + 0.16, o, 0.62, 0.34);
    s.addText(t, { x: 9.24, y: y + 0.16, w: 3.4, h: 0.34, fontFace: SANS, fontSize: 12, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(n + ' hosts', { x: 8.52, y: y + 0.54, w: 2.0, h: 0.24, fontFace: SANS, fontSize: 10.5, bold: true, color: RED, isTextBox: true, margin: 0 });
    s.addText(d, { x: 8.52, y: y + 0.78, w: 4.1, h: 0.42, fontFace: SANS, fontSize: 9.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  });
  footer(s, 'Counts are projections from the profiled sample onto 281,700 unmatched Discovered Items, so treat them as proportions rather than exact totals.');
  s.addNotes('The largest group, plain-named hosts, is already served by the existing name rules; it stays unmatched because those CIs are absent, not because a rule is missing.');
}

// evidence carried
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'What evidence those hosts actually carry', 'Analysis');
  const big = [['85.9%', 'carry a DNS name', 'so name rules do most of the work'], ['0.3%', 'carry a serial number', 'so the strongest rule reaches almost nobody'], ['32.6%', 'report no OS text', 'so a third of hosts get no class evidence']];
  big.forEach(([n, t, d], i) => {
    const x = M + i * 4.15;
    card(s, x, 1.52, 3.9, 1.5);
    s.addText(n, { x: x + 0.25, y: 1.66, w: 3.4, h: 0.6, fontFace: SANS, fontSize: 36, bold: true, color: RED, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(t, { x: x + 0.25, y: 2.24, w: 3.4, h: 0.28, fontFace: SANS, fontSize: 12.5, bold: true, color: INK, isTextBox: true, margin: 0 });
    s.addText(d, { x: x + 0.25, y: 2.52, w: 3.4, h: 0.4, fontFace: SANS, fontSize: 10.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  });
  card(s, M, 3.24, 6.05, 3.0);
  s.addText('The full picture', { x: M + 0.25, y: 3.38, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  D.evidence.forEach(([label, pct, count], i) => {
    const y = 3.76 + i * 0.3;
    s.addText(label, { x: M + 0.25, y, w: 3.5, h: 0.26, fontFace: SANS, fontSize: 10, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(pct, { x: M + 3.8, y, w: 0.85, h: 0.26, fontFace: SANS, fontSize: 10, bold: true, color: RED, align: 'right', isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(count, { x: M + 4.75, y, w: 1.05, h: 0.26, fontFace: SANS, fontSize: 10, color: MUTED, align: 'right', isTextBox: true, margin: 0, valign: 'middle' });
  });
  card(s, 6.78, 3.24, 6.05, 3.0);
  s.addText('What the numbers decided', { x: 7.03, y: 3.38, w: 5.5, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  const reads = [
    ['Names carry the load', 'With serials on 0.3% of hosts and cloud ids on none, the name rules are where matching is won or lost. Eight of the nineteen rules work on the DNS field.'],
    ['Class evidence is thin', 'A third of hosts report no OS and a further twentieth report a list of guesses. Every class-scoped rule therefore has a hardware-wide twin behind it.'],
    ['The label describes the part', 'In the three new groups the DNS name is present and accurate; it just names a controller, a port or a VIP rather than the machine. That is a parsing problem, not a data gap.'],
  ];
  reads.forEach(([t, d], i) => {
    const y = 3.78 + i * 0.82;
    s.addText(t, { x: 7.03, y, w: 5.55, h: 0.26, fontFace: SANS, fontSize: 11.5, bold: true, color: INK, isTextBox: true, margin: 0 });
    s.addText(d, { x: 7.03, y: y + 0.26, w: 5.55, h: 0.52, fontFace: SANS, fontSize: 10, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  });
  footer(s, 'Percentages are of the profiled sample; host counts are projected onto the 281,700 unmatched Discovered Items.');
  s.addNotes('The last point is the argument for the three new rules: the evidence was already there, unread.');
}

// properties
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'Six properties, so the lists are not in the code', 'Tuning');
  s.addText('The three new rules each depend on a vocabulary: which suffixes mark a controller, which segments mark an interface, which words name a load balancer. Naming habits differ by site and change over time, so every list is a system property the rule reads at run time.',
    { x: M, y: 1.44, w: 12.3, h: 0.4, fontFace: SANS, fontSize: 12, color: MUTED, isTextBox: true, margin: 0 });
  D.props.forEach(([name, rule, value, desc], i) => {
    const y = 1.96 + i * 0.78;
    card(s, M, y, 12.33, 0.7);
    s.addText(name, { x: M + 0.22, y: y + 0.08, w: 3.5, h: 0.28, fontFace: MONO, fontSize: 10, bold: true, color: RED, isTextBox: true, margin: 0, valign: 'middle' });
    badge(s, M + 3.78, y + 0.09, rule, 0.5, 0.26);
    s.addText(desc, { x: M + 4.42, y: y + 0.08, w: 7.6, h: 0.28, fontFace: SANS, fontSize: 10, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(value, { x: M + 0.22, y: y + 0.38, w: 11.8, h: 0.26, fontFace: MONO, fontSize: 9, color: MUTED, isTextBox: true, margin: 0, valign: 'middle' });
  });
  card(s, M, 6.62, 12.33, 0.62, WHITE);
  s.addText([
    { text: 'Adding a site’s naming habit is a property edit, not a code change.  ', options: { bold: true, color: INK } },
    { text: 'A new controller suffix or VLAN marker is typed into the list; the rule picks it up on the next evaluation, with no update set and no release.', options: { color: MUTED } },
  ], { x: M + 0.3, y: 6.74, w: 11.7, h: 0.4, fontFace: SANS, fontSize: 11, isTextBox: true, margin: 0, valign: 'middle' });
  s.addNotes('The values shown are the defaults shipped with the rules; each rule falls back to them if its property is missing.');
}

// ------------------------------------------------------------------ section 5
divider('5', 'Testing and delivery', 'How the chain was exercised end to end, what shipped, and what to watch once it runs.',
  ['Three layers of testing', 'What ships and how it is operated', 'Rule reference']);

// testing
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'Three layers of testing', 'Assurance');
  const layers = [
    ['Direct', 'Rule behaviour', 'Purpose-built CMDB fixtures, then the platform’s own identify() call for the Qualys source with one payload per case: the positive match, the negative, the ambiguity, and a regression on a neighbouring rule. Eighteen cases, run twice.', '36 of 36 as expected'],
    ['Pipeline', 'End to end', 'Real unresolved Discovered Items re-run through the platform’s own reconcile utility, the same call the scheduled job makes, so the whole framework path is exercised and not just the script.', '9 of 9 turned matched'],
    ['Sweep', 'No regression', 'One representative host per rule pushed through the chain before and after every redeploy, comparing which rule answered and which CI came back.', 'identical, 19 of 19 rules answering'],
  ];
  layers.forEach(([k, t2, d, r], i) => {
    const x = M + i * 4.15;
    card(s, x, 1.55, 3.9, 2.92);
    badge(s, x + 0.25, 1.74, String(i + 1), 0.42, 0.42);
    s.addText(k, { x: x + 0.8, y: 1.74, w: 2.8, h: 0.42, fontFace: SANS, fontSize: 15, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(t2.toUpperCase(), { x: x + 0.25, y: 2.24, w: 3.4, h: 0.22, fontFace: SANS, fontSize: 8.5, bold: true, color: MUTED, charSpacing: 1.2, isTextBox: true, margin: 0 });
    s.addText(d, { x: x + 0.25, y: 2.5, w: 3.4, h: 1.36, fontFace: SANS, fontSize: 10.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
    s.addText(r, { x: x + 0.25, y: 3.9, w: 3.4, h: 0.4, fontFace: SANS, fontSize: 12, bold: true, color: RED, isTextBox: true, margin: 0, valign: 'middle' });
  });
  card(s, M, 4.72, 12.33, 1.6);
  s.addText('What the negative cases prove', { x: M + 0.3, y: 4.88, w: 6, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: INK, isTextBox: true, margin: 0 });
  s.addText('Half the suite asserts that a rule stays out of the way: a hyphenated server name is not treated as an interface, a server sharing an address with a VIP is not turned into a load balancer service, a controller label with two candidate servers declines rather than picks, and an ordinary Windows workstation passes every new rule untouched. A rule that matches too much is the failure mode that matters here, so it is the one tested hardest.',
    { x: M + 0.3, y: 5.24, w: 11.7, h: 0.9, fontFace: SANS, fontSize: 11.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  s.addNotes('The sweep is what makes a comments-only redeploy safe to sign off.');
}

// delivery
{
  const s = pres.addSlide(); light(s);
  slideTitle(s, 'What ships, and how it is operated', 'Delivery');
  const sets = [
    ['Rule scripts', '16 updates', 'The rewritten scripts for the existing custom chain. Names, orders, source fields and descriptions are untouched; only the script field changes.'],
    ['Backlog rules', '9 updates', 'Three new rules and their six properties. Applies on top of the first set.'],
  ];
  sets.forEach(([t2, n, d], i) => {
    const x = M + i * 6.28;
    card(s, x, 1.55, 6.05, 1.2);
    s.addText(t2, { x: x + 0.25, y: 1.68, w: 4.2, h: 0.32, fontFace: SANS, fontSize: 15, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(n, { x: x + 4.4, y: 1.68, w: 1.4, h: 0.32, fontFace: SANS, fontSize: 13, bold: true, color: RED, align: 'right', isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(d, { x: x + 0.25, y: 2.04, w: 5.55, h: 0.6, fontFace: SANS, fontSize: 11, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  });
  const ops = [
    ['Turning a rule off', 'Every rule is independent. Clearing Active on one takes it out of the chain; the hosts it served fall through to the next rule that can read their evidence.'],
    ['Adding a naming habit', 'A new controller suffix, VLAN marker or balancer product goes into the matching property. No script edit, no update set.'],
    ['Applying it to existing data', 'The rules run on new scans automatically. To reach the existing backlog, re-run the reconcile job for the changed Discovered Items.'],
    ['What to watch first', 'The matched share of Discovered Items by rule. A rule that suddenly matches far more than its group size is the early sign that a property list has been widened too far.'],
  ];
  ops.forEach(([t2, d], i) => {
    const x = M + (i % 2) * 6.28, y = 3.06 + Math.floor(i / 2) * 1.72;
    card(s, x, y, 6.05, 1.5);
    s.addText([
      { text: t2, options: { fontSize: 13.5, bold: true, color: INK, breakLine: true, paraSpaceAfter: 6 } },
      { text: d, options: { fontSize: 11, color: MUTED } },
    ], { x: x + 0.25, y: y + 0.1, w: 5.55, h: 1.3, fontFace: SANS, isTextBox: true, margin: 0, valign: 'middle' });
  });
  footer(s, 'Both sets are Global scope. The rule table is not update-set tracked by default, so each rule is captured explicitly on save.');
  s.addNotes('The last point is the operational guardrail: watch the matched share per rule after any property change.');
}

// appendix tables
[0, 1].forEach((half) => {
  const s = pres.addSlide(); light(s);
  slideTitle(s, half === 0 ? 'Rule reference' : 'Rule reference, continued', 'Appendix');
  const items = D.rules.slice(half * 10, half * 10 + 10);
  const heads = ['Order', 'Rule', 'Reads', 'Returns'];
  const xs = [M, M + 0.95, M + 4.55, M + 7.05];
  const ws = [0.85, 3.5, 2.4, 5.7];
  heads.forEach((h, i) => s.addText(h.toUpperCase(), { x: xs[i], y: 1.5, w: ws[i], h: 0.24, fontFace: SANS, fontSize: 8.5, bold: true, color: RED, charSpacing: 1.2, isTextBox: true, margin: 0 }));
  items.forEach((r, i) => {
    const y = 1.82 + i * 0.52;
    card(s, M, y, 12.33, 0.46);
    s.addText(r.order, { x: M + 0.14, y, w: 0.7, h: 0.46, fontFace: MONO, fontSize: 10, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(r.name.replace('USEM ', ''), { x: xs[1], y, w: ws[1], h: 0.46, fontFace: SANS, fontSize: 10, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(r.reads, { x: xs[2], y, w: ws[2], h: 0.46, fontFace: SANS, fontSize: 9.5, color: MUTED, isTextBox: true, margin: 0, valign: 'middle' });
    s.addText(r.returns, { x: xs[3], y, w: ws[3] - 0.14, h: 0.46, fontFace: SANS, fontSize: 9.5, color: MUTED, isTextBox: true, margin: 0, valign: 'middle' });
  });
  if (half === 1) footer(s, 'Every rule returns null when its evidence is missing, when nothing matches, or when more than one candidate survives.');
  s.addNotes('Reference table for the chain.');
});

// closing
{
  const s = pres.addSlide();
  s.background = { color: INK };
  s.addText('What to take away', { x: M, y: 2.4, w: 11.6, h: 0.7, fontFace: SANS, fontSize: 34, bold: true, color: WHITE, isTextBox: true, margin: 0, valign: 'middle' });
  const points = [
    'The chain reads evidence in order of how much a machine can be trusted to keep it: serial, then name, then address.',
    'Every rule ends the same way, on exactly one candidate or a decline, so a wrong owner is never the cheap outcome.',
    'The three new rules read evidence that was already in the feed but described a part of a device rather than the device.',
    'The vocabularies those rules depend on live in properties, so a naming habit can be added without touching a script.',
  ];
  points.forEach((p, i) => {
    const y = 3.36 + i * 0.72;
    s.addShape(pres.ShapeType.roundRect, { x: M, y: y + 0.06, w: 0.22, h: 0.22, rectRadius: 0.07, fill: { color: RED }, line: { width: 0 } });
    s.addText(p, { x: M + 0.46, y, w: 11.6, h: 0.6, fontFace: SANS, fontSize: 13, color: 'D3D7DA', isTextBox: true, margin: 0, valign: 'top' });
  });
  s.addText('SNOWUSEMTP-895   |   Qualys CI Lookup Rules', { x: M, y: 6.7, w: 12.3, h: 0.3, fontFace: SANS, fontSize: 11, color: '8A9198', isTextBox: true, margin: 0 });
}

const out = path.join(__dirname, '..', 'Qualys CI Lookup Rules - Technical Walkthrough.pptx');
pres.writeFile({ fileName: out }).then(() => console.log('written:', out));
