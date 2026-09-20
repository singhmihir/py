// Builds "Qualys CI Lookup Rules - CMDB Team Demo.pptx" from demo_data.json (python3 build_demo_data.py first).
const fs = require('fs');
const path = require('path');
const PptxGenJS = require('pptxgenjs');   // NODE_PATH points at the node_modules holding pptxgenjs

const D = JSON.parse(fs.readFileSync(path.join(__dirname, 'demo_data.json'), 'utf8'));
const OUT = path.join(__dirname, '..', 'Qualys CI Lookup Rules - CMDB Team Demo.pptx');

const INK = '24272A', RED = 'E31837', NAVY = '012169', LIGHT = 'F4F5F6', WHITE = 'FFFFFF';
const MUTED = '6B7177', LINE = 'DDE0E3', SOFT = 'EAF0F8';
const W = 13.33, H = 7.5, M = 0.5, SANS = 'Arial';

const pres = new PptxGenJS();
pres.layout = 'LAYOUT_WIDE';
pres.author = 'Mihir Kumar Singh';
pres.title = D.title + ' - CMDB Team Demo';

const shadow = () => ({ type: 'outer', color: '9AA1A8', blur: 6, offset: 1, angle: 90, opacity: 0.25 });
const light = s => { s.background = { color: LIGHT }; };

function kickerTitle(s, kicker, title, size) {
  s.addText(kicker.toUpperCase(), { x: M, y: 0.34, w: 12.3, h: 0.24, fontFace: SANS, fontSize: 10.5, bold: true, color: RED, charSpacing: 1.6, isTextBox: true, margin: 0 });
  s.addText(title, { x: M, y: 0.60, w: 12.3, h: 0.66, fontFace: SANS, fontSize: size || 28, bold: true, color: INK, isTextBox: true, margin: 0, valign: 'top', fit: 'shrink' });
}
function card(s, x, y, w, h, fill) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.05, fill: { color: fill || WHITE }, line: { color: LINE, width: 0.75 }, shadow: shadow() });
}
function heading(s, x, y, w, text) {
  s.addText(text.toUpperCase(), { x, y, w, h: 0.26, fontFace: SANS, fontSize: 9.5, bold: true, color: NAVY, charSpacing: 1.2, isTextBox: true, margin: 0 });
}
function bullets(s, x, y, w, h, items, size, para) {
  const runs = [];
  items.forEach((t, i) => {
    const last = i === items.length - 1, sp = para == null ? 6 : para;
    if (typeof t === 'string') {
      runs.push({ text: t, options: { bullet: { indent: 14 }, breakLine: !last, paraSpaceAfter: sp } });
    } else {
      runs.push({ text: t.title + '  ', options: { bullet: { indent: 14 }, bold: true, color: NAVY } });
      runs.push({ text: t.detail, options: { breakLine: !last, paraSpaceAfter: sp } });
    }
  });
  s.addText(runs, { x, y, w, h, fontFace: SANS, fontSize: size || 14, color: INK, isTextBox: true, margin: 0, valign: 'top', fit: 'shrink' });
}
function facts(s, x, y, w, h, rows, size) {
  const runs = [];
  rows.forEach((r, i) => {
    runs.push({ text: r[0] + '  ', options: { color: MUTED, bold: true } });
    runs.push({ text: r[1], options: { color: INK, breakLine: i < rows.length - 1, paraSpaceAfter: 3 } });
  });
  s.addText(runs, { x, y, w, h, fontFace: SANS, fontSize: size || 10.5, isTextBox: true, margin: 0, valign: 'top', fit: 'shrink' });
}
function link(s, x, y, w, text, url) {
  s.addText(text, { x, y, w, h: 0.24, fontFace: SANS, fontSize: 9.5, color: NAVY, underline: { style: 'sng' }, hyperlink: { url, tooltip: url }, isTextBox: true, margin: 0 });
}
function footer(s, text) {
  s.addText(text, { x: M, y: H - 0.42, w: 12.3, h: 0.2, fontFace: SANS, fontSize: 8, color: MUTED, isTextBox: true, margin: 0 });
}

// ---------------------------------------------------------------- title
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  s.addShape(pres.ShapeType.rect, { x: 0, y: 0, w: 0.28, h: H, fill: { color: RED }, line: { width: 0 } });
  s.addText('USEM  ·  VULNERABILITY RESPONSE', { x: 1.0, y: 2.2, w: 11, h: 0.3, fontFace: SANS, fontSize: 12, bold: true, color: 'C9D1E3', charSpacing: 2, isTextBox: true, margin: 0 });
  s.addText(D.title, { x: 1.0, y: 2.6, w: 11, h: 1.0, fontFace: SANS, fontSize: 40, bold: true, color: WHITE, isTextBox: true, margin: 0 });
  s.addText(D.subtitle, { x: 1.0, y: 3.6, w: 11, h: 0.5, fontFace: SANS, fontSize: 20, color: 'E4E8F0', isTextBox: true, margin: 0 });
  s.addText('Demo for the CMDB team  ·  22 September 2026  ·  Mihir Kumar Singh', { x: 1.0, y: 5.6, w: 11, h: 0.3, fontFace: SANS, fontSize: 12, color: 'C9D1E3', isTextBox: true, margin: 0 });
}

// ---------------------------------------------------------------- concepts
D.concepts.forEach(c => {
  const s = pres.addSlide(); light(s);
  kickerTitle(s, c.kicker, c.title);
  if (c.columns) {
    const cw = (12.33 - 0.3) / 2;
    c.columns.forEach((col, i) => {
      const x = M + i * (cw + 0.3);
      card(s, x, 1.45, cw, 5.55);
      heading(s, x + 0.3, 1.62, cw - 0.6, col.heading);
      bullets(s, x + 0.3, 1.92, cw - 0.6, 4.95, col.bullets, c.size || 11.5, 5);
    });
  } else {
    card(s, M, 1.45, 12.33, 5.55);
    bullets(s, M + 0.4, 1.8, 11.5, 5.0, c.bullets, c.size || 16, 10);
  }
  if (c.footer) footer(s, c.footer);
});

// ---------------------------------------------------------------- chain at a glance
{
  const s = pres.addSlide(); light(s);
  kickerTitle(s, 'Key concepts', 'The chain at a glance: first rule to answer wins');
  const head = ['Order', 'Rule', 'Reads', 'Returns'].map(t => ({ text: t, options: { bold: true, color: WHITE, fill: { color: NAVY }, fontSize: 9 } }));
  const rows = [head].concat(D.chain.map((r, i) => r.map((v, j) => ({ text: v, options: { fontSize: 8, bold: j < 2, color: j === 0 ? RED : INK, fill: { color: i % 2 ? SOFT : WHITE } } }))));
  s.addTable(rows, { x: M, y: 1.4, w: 12.33, colW: [0.7, 3.0, 2.9, 5.73], fontFace: SANS, border: { type: 'solid', pt: 0.5, color: LINE }, rowH: 0.235, margin: 0.03, valign: 'middle' });
  footer(s, 'After the USEM rules the platform\'s own rules run (FQDN, NetBIOS, DNS). Rules that return nothing hand the host to the next one.');
}

// ---------------------------------------------------------------- rules
D.rules.forEach(r => {
  const s = pres.addSlide(); light(s);
  kickerTitle(s, 'Rule ' + r.order + '  ·  ' + r.group, r.name.replace('USEM ', ''));
  const strip = [
    { text: 'READS  ', options: { bold: true, color: NAVY } }, { text: r.reads + '   ', options: { color: INK } },
    { text: 'RETURNS  ', options: { bold: true, color: NAVY } }, { text: r.returns, options: { color: INK, breakLine: true } },
    { text: 'RUNS AFTER  ', options: { bold: true, color: NAVY } }, { text: (r.before_names || r.before) + '   ', options: { color: INK } },
    { text: 'HANDS OVER TO  ', options: { bold: true, color: NAVY } }, { text: r.after_names || r.after, options: { color: INK } },
  ];
  if (r.matched != null) strip.push({ text: '   ITEMS MATCHED  ', options: { bold: true, color: NAVY } }, { text: String(r.matched), options: { color: INK } });
  s.addText(strip, { x: M, y: 1.28, w: 12.33, h: 0.62, fontFace: SANS, fontSize: 9.5, isTextBox: true, margin: 0, valign: 'top', fit: 'shrink' });
  card(s, M, 1.98, 12.33, 3.6);
  heading(s, M + 0.3, 2.12, 12, 'What it looks for');
  s.addText(r.purpose, { x: M + 0.3, y: 2.38, w: 11.75, h: 0.62, fontFace: SANS, fontSize: 11.5, color: INK, isTextBox: true, margin: 0, valign: 'top', fit: 'shrink' });
  heading(s, M + 0.3, 3.05, 12, 'How the script works');
  const half = Math.ceil(r.mechanics.length / 2), colW = (12.33 - 0.6 - 0.35) / 2;
  bullets(s, M + 0.3, 3.32, colW, 2.18, r.mechanics.slice(0, half), 10, 3);
  bullets(s, M + 0.3 + colW + 0.35, 3.32, colW, 2.18, r.mechanics.slice(half), 10, 3);
  card(s, M, 5.7, 12.33, 1.5, SOFT);
  heading(s, M + 0.3, 5.82, 12, 'Declines when');
  const dh = Math.ceil(r.declines.length / 2);
  bullets(s, M + 0.3, 6.06, colW, 1.08, r.declines.slice(0, dh), 9, 1);
  bullets(s, M + 0.3 + colW + 0.35, 6.06, colW, 1.08, r.declines.slice(dh), 9, 1);
  if (!r.examples.length) {
    const e = pres.addSlide(); light(e);
    kickerTitle(e, 'Rule ' + r.order + '  ·  Examples', 'Three matched discovered items');
    card(e, M, 1.45, 12.33, 2.2);
    e.addText('Three discovered items matched by this rule on the development instance will be shown here, one per page, each with the scanned values, the steps the rule took and the CI it returned.',
      { x: M + 0.35, y: 1.8, w: 11.6, h: 1.6, fontFace: SANS, fontSize: 16, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
    return;
  }
  r.examples.forEach((x, k) => {
    const e = pres.addSlide(); light(e);
    kickerTitle(e, 'Rule ' + r.order + '  ·  Example ' + (k + 1) + ' of ' + r.examples.length, x.host, 24);
    const cw = 3.95, gap = 0.24, y0 = 1.45, ch = 4.7;
    // discovered item
    card(e, M, y0, cw, ch);
    heading(e, M + 0.25, y0 + 0.18, cw - 0.5, 'Discovered item');
    e.addText(x.number, { x: M + 0.25, y: y0 + 0.48, w: cw - 0.5, h: 0.45, fontFace: SANS, fontSize: 19, bold: true, color: INK, isTextBox: true, margin: 0 });
    facts(e, M + 0.25, y0 + 1.05, cw - 0.5, 3.0, x.item_facts, 12.5);
    link(e, M + 0.25, y0 + ch - 0.42, cw - 0.5, 'Open the discovered item', x.item_link);
    // walk
    const x2 = M + cw + gap;
    card(e, x2, y0, cw + 0.5, ch, WHITE);
    heading(e, x2 + 0.25, y0 + 0.18, cw, 'What the rule did');
    const steps = x.walk.map((t, i) => ({ text: t, options: { bullet: { type: 'number' }, breakLine: i < x.walk.length - 1, paraSpaceAfter: 8 } }));
    e.addText(steps, { x: x2 + 0.25, y: y0 + 0.52, w: cw, h: ch - 0.75, fontFace: SANS, fontSize: 13.5, color: INK, isTextBox: true, margin: 0, valign: 'top', fit: 'shrink' });
    // ci
    const x3 = x2 + cw + 0.5 + gap;
    card(e, x3, y0, W - M - x3, ch, WHITE);
    e.addShape(pres.ShapeType.rect, { x: x3, y: y0, w: 0.09, h: ch, fill: { color: RED }, line: { width: 0 } });
    heading(e, x3 + 0.3, y0 + 0.18, W - M - x3 - 0.5, 'CI matched');
    e.addText(x.ci_name, { x: x3 + 0.3, y: y0 + 0.48, w: W - M - x3 - 0.55, h: 0.75, fontFace: SANS, fontSize: 17, bold: true, color: NAVY, isTextBox: true, margin: 0, valign: 'top', fit: 'shrink' });
    e.addText(x.ci_class, { x: x3 + 0.3, y: y0 + 1.25, w: W - M - x3 - 0.55, h: 0.32, fontFace: SANS, fontSize: 13, color: RED, bold: true, isTextBox: true, margin: 0 });
    facts(e, x3 + 0.3, y0 + 1.7, W - M - x3 - 0.55, 2.5, x.ci_facts, 12.5);
    link(e, x3 + 0.3, y0 + ch - 0.42, W - M - x3 - 0.55, 'Open the CI', x.ci_link);
  });
});

pres.writeFile({ fileName: OUT }).then(() => {
  const n = 1 + D.concepts.length + 1 + D.rules.reduce((a, r) => a + 1 + Math.max(1, r.examples.length), 0);
  console.log('written: ' + OUT + ' | slides: ' + n);
});
