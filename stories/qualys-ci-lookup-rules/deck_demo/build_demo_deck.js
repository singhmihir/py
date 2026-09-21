// Builds "Qualys CI Lookup Rules - CMDB Team Demo.pptx" from demo_data.json (python3 build_demo_data.py first).
// Layout pass of 21 Sep: each rule spreads over three pages (what it looks for, how the script works on one or two
// pages, when it declines), every text box is sized by measuring its text (PowerPoint does not shrink text on its own),
// Bank of America colours (red E31837, blue 012169, dark grey 4D4F53, dark red 96172E).
const fs = require('fs');
const path = require('path');
const PptxGenJS = require('pptxgenjs');   // NODE_PATH points at the node_modules holding pptxgenjs

const D = JSON.parse(fs.readFileSync(process.argv[2] || path.join(__dirname, 'demo_data.json'), 'utf8'));
const OUT = process.argv[3] || path.join(__dirname, '..', 'Qualys CI Lookup Rules - CMDB Team Demo.pptx');

// ---------------------------------------------------------------- palette and page geometry
const RED = 'E31837', NAVY = '012169', INK = '4D4F53', DARK_RED = '96172E', WHITE = 'FFFFFF';
const TITLE = '1F2A44', MUTED = '6E7279', LINE = 'D8DDE6', PAGE = 'F3F5F8', TINT = 'EAF0F8', TINT2 = 'F7F9FC';
const W = 13.33, H = 7.5, M = 0.55, SANS = 'Arial';
const CONTENT_W = W - 2 * M;

const pres = new PptxGenJS();
pres.layout = 'LAYOUT_WIDE';
pres.author = 'Mihir Kumar Singh';
pres.title = D.title + ' - CMDB Team Demo';

// ---------------------------------------------------------------- text measurement (Arial; 0.50 em per glyph keeps the estimate about a sixth above the rendered height)
const EM = 0.50;
function lines(text, widthIn, size, indentPt) {
  const cpl = Math.max(8, Math.floor((widthIn * 72 - (indentPt || 0)) / (size * EM)));
  return Math.max(1, Math.ceil(String(text).length / cpl));
}
function itemText(it) { return typeof it === 'string' ? it : (it.title ? it.title + '  ' : '') + (it.detail || ''); }
function heightOf(items, widthIn, size, paraPt, indentPt) {
  let n = 0;
  items.forEach(it => { n += lines(itemText(it), widthIn, size, indentPt); });
  return (n * size * 1.2 + items.length * (paraPt || 0)) / 72;
}
function pick(items, widthIn, heightIn, sizes, paraPt, indentPt) {
  for (const s of sizes) if (heightOf(items, widthIn, s, paraPt, indentPt) <= heightIn) return s;
  return null;
}
// split items into two columns of roughly equal height
function twoColumns(items, widthIn, size, paraPt, indentPt) {
  const hs = items.map(it => heightOf([it], widthIn, size, paraPt, indentPt));
  const total = hs.reduce((a, b) => a + b, 0);
  let acc = 0, cut = items.length;
  for (let i = 0; i < items.length; i++) { acc += hs[i]; if (acc >= total / 2) { cut = i + 1; break; } }
  if (cut < 1) cut = 1;
  const left = items.slice(0, cut), right = items.slice(cut);
  return { left, right, height: Math.max(heightOf(left, widthIn, size, paraPt, indentPt), right.length ? heightOf(right, widthIn, size, paraPt, indentPt) : 0) };
}
function pickTwoColumns(items, widthIn, heightIn, sizes, paraPt, indentPt) {
  for (const s of sizes) if (twoColumns(items, widthIn, s, paraPt, indentPt).height <= heightIn) return s;
  return null;
}
const sentences = text => String(text).split(/(?<=[.!?])\s+(?=[A-Z])/).map(s => s.trim()).filter(Boolean);
const cap = s => s ? s[0].toUpperCase() + s.slice(1) : s;

// ---------------------------------------------------------------- drawing helpers
const shadow = () => ({ type: 'outer', color: 'A7ADB8', blur: 5, offset: 1, angle: 90, opacity: 0.22 });
function page(kicker, title, subtitle) {
  const s = pres.addSlide();
  s.background = { color: PAGE };
  s.addShape(pres.ShapeType.rect, { x: 0, y: 0, w: W, h: 0.12, fill: { color: NAVY }, line: { width: 0 } });
  s.addShape(pres.ShapeType.rect, { x: 0, y: 0.12, w: 1.6, h: 0.05, fill: { color: RED }, line: { width: 0 } });
  s.addText(kicker.toUpperCase(), { x: M, y: 0.32, w: CONTENT_W, h: 0.26, fontFace: SANS, fontSize: 10.5, bold: true, color: RED, charSpacing: 1.8, isTextBox: true, margin: 0 });
  const tsize = title.length > 58 ? 20 : title.length > 46 ? 23 : 27;
  s.addText(title, { x: M, y: 0.56, w: CONTENT_W, h: 0.58, fontFace: SANS, fontSize: tsize, bold: true, color: TITLE, isTextBox: true, margin: 0, valign: 'top' });
  if (subtitle) s.addText(subtitle, { x: M, y: 1.12, w: CONTENT_W, h: 0.3, fontFace: SANS, fontSize: 12.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
  s.addText(D.title + '  ·  CMDB team demo', { x: M, y: H - 0.38, w: 8, h: 0.22, fontFace: SANS, fontSize: 8.5, color: MUTED, isTextBox: true, margin: 0 });
  s.slideNumber = { x: W - M - 1.0, y: H - 0.38, w: 1.0, h: 0.22, fontFace: SANS, fontSize: 8.5, color: MUTED, align: 'right' };
  return s;
}
function card(s, x, y, w, h, fill, accent) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.06, fill: { color: fill || WHITE }, line: { color: LINE, width: 0.75 }, shadow: shadow() });
  if (accent) s.addShape(pres.ShapeType.rect, { x: x, y: y + 0.18, w: 0.07, h: h - 0.36, fill: { color: accent }, line: { width: 0 } });
}
function heading(s, x, y, w, text, color) {
  s.addText(text.toUpperCase(), { x, y, w, h: 0.26, fontFace: SANS, fontSize: 9.5, bold: true, color: color || NAVY, charSpacing: 1.4, isTextBox: true, margin: 0 });
  s.addShape(pres.ShapeType.line, { x, y: y + 0.3, w: 0.5, h: 0, line: { color: RED, width: 1.5 } });
}
// bullet list: items are strings or {title, detail}; bullets true = round bullets; numbered from `start`
function list(s, x, y, w, h, items, size, paraPt, opts) {
  opts = opts || {};
  const runs = [];
  items.forEach((it, i) => {
    const last = i === items.length - 1;
    const bullet = opts.numbered ? false : (opts.bullets === false ? false : { indent: 14 });
    if (typeof it === 'string') {
      runs.push({ text: it, options: { bullet, breakLine: !last, paraSpaceAfter: paraPt } });
    } else {
      const lead = (opts.numbered ? (opts.start + i) + '   ' : '') + it.title + '  ';
      runs.push({ text: lead, options: { bullet, bold: true, color: NAVY } });
      runs.push({ text: it.detail, options: { breakLine: !last, paraSpaceAfter: paraPt } });
    }
  });
  s.addText(runs, { x, y, w, h, fontFace: SANS, fontSize: size, color: INK, isTextBox: true, margin: 0, valign: 'top', lineSpacingMultiple: 1.0 });
}
function facts(s, x, y, w, h, rows, size) {
  const runs = [];
  rows.forEach((r, i) => {
    runs.push({ text: r[0] + '  ', options: { color: MUTED, bold: true } });
    runs.push({ text: r[1], options: { color: INK, breakLine: i < rows.length - 1, paraSpaceAfter: 3 } });
  });
  s.addText(runs, { x, y, w, h, fontFace: SANS, fontSize: size, isTextBox: true, margin: 0, valign: 'top' });
}
function link(s, x, y, w, text, url) {
  s.addText(text, { x, y, w, h: 0.24, fontFace: SANS, fontSize: 9.5, color: NAVY, underline: { style: 'sng' }, hyperlink: { url, tooltip: url }, isTextBox: true, margin: 0 });
}
const warnings = [];
const WP = require('./walk_pages.js');

// ---------------------------------------------------------------- step-by-step pages with record links (one example, one or more pages)
function walkPages(r, x, k, name) {
  const tr = WP.T.items[x.number];
  if (!tr) { warnings.push('example ' + x.number + ' has no trace'); return; }
  const kind = tr.kind;
  const rows = tr.steps.map((st, i) => ({ no: String(i + 1), what: WP.explain(kind, st.title, tr), title: st.title, runs: WP.itemRuns(st, NAVY, INK, MUTED) }));
  const SZ = 9, COLW = [0.45, 4.15, CONTENT_W - 0.45 - 4.15], topY = 1.62, avail = H - 0.55 - topY;
  const cpl = (w) => Math.max(20, Math.floor(w * 72 / (SZ * EM)) - 2);
  const rowH = (row) => {
    const whatLines = Math.ceil((row.title.length + 2 + row.what.length) / cpl(COLW[1] - 0.16));
    const itemChars = row.runs.reduce((a, u) => a + u.text.length, 0), breaks = row.runs.filter(u => u.options && u.options.breakLine).length;
    const itemLines = Math.ceil(itemChars / cpl(COLW[2] - 0.16)) + breaks;
    return Math.max(whatLines, itemLines, 1) * SZ * 1.22 / 72 + 0.14;
  };
  const headH = 0.3;
  const pages = []; let cur = [], used = headH;
  rows.forEach(row => { const h = Math.min(rowH(row), avail - headH); if (used + h > avail && cur.length) { pages.push(cur); cur = []; used = headH; } cur.push(row); used += h; });
  if (cur.length) pages.push(cur);
  const itemUrl = WP.rec('sn_sec_cmn_src_ci', tr.item.sys_id), ruleUrl = WP.RULE_ID[r.order] ? WP.rec('sn_sec_cmn_ci_lookup_rule', WP.RULE_ID[r.order]) : x.item_link;
  pages.forEach((pg, pi) => {
    const s = page('Rule ' + r.order + '  ·  ' + name + '  ·  example ' + (k + 1) + ' step by step' + (pages.length > 1 ? '  ·  page ' + (pi + 1) + ' of ' + pages.length : ''), x.host, '');
    // header line: item, rule record, property, CI
    const hdr = [{ text: 'Discovered item ', options: { color: MUTED } }, { text: tr.item.number, options: { color: NAVY, underline: { style: 'sng' }, hyperlink: { url: itemUrl, tooltip: itemUrl } } },
      { text: '   ·   rule record ', options: { color: MUTED } }, { text: tr.rule_name, options: { color: NAVY, underline: { style: 'sng' }, hyperlink: { url: ruleUrl, tooltip: ruleUrl } } },
      { text: '   ·   ignored classes ', options: { color: MUTED } }, { text: 'sn_sec_cmn.ignoreCIClass', options: { color: NAVY, underline: { style: 'sng' }, hyperlink: { url: WP.PROP_URL, tooltip: WP.PROP_URL } } },
      { text: '   ·   CI returned ', options: { color: MUTED } }, { text: x.ci_name, options: { color: NAVY, underline: { style: 'sng' }, hyperlink: { url: x.ci_link, tooltip: x.ci_link } } }];
    s.addText(hdr, { x: M, y: 1.14, w: CONTENT_W, h: 0.3, fontFace: SANS, fontSize: 10, isTextBox: true, margin: 0, valign: 'top' });
    const head = [{ text: 'No.', options: { bold: true, color: NAVY, fill: { color: TINT } } }, { text: 'What the script does', options: { bold: true, color: NAVY, fill: { color: TINT } } }, { text: 'For this item (every record and filter is a link)', options: { bold: true, color: NAVY, fill: { color: TINT } } }];
    const body = pg.map(row => [{ text: row.no, options: { color: MUTED, bold: true } },
      { text: [{ text: row.title, options: { bold: true, color: TITLE, breakLine: true } }, { text: row.what, options: { color: INK } }] },
      { text: row.runs }]);
    s.addTable([head].concat(body), { x: M, y: topY, w: CONTENT_W, colW: COLW, fontFace: SANS, fontSize: SZ, color: INK, border: { type: 'solid', pt: 0.5, color: LINE }, fill: { color: WHITE }, valign: 'top', margin: 0.06, autoPage: false });
  });
}

// ---------------------------------------------------------------- title
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  s.addShape(pres.ShapeType.rect, { x: 0, y: 0, w: 0.3, h: H, fill: { color: RED }, line: { width: 0 } });
  s.addShape(pres.ShapeType.rect, { x: 1.05, y: 2.05, w: 1.2, h: 0.06, fill: { color: RED }, line: { width: 0 } });
  s.addText('USEM  ·  VULNERABILITY RESPONSE', { x: 1.05, y: 2.25, w: 11, h: 0.3, fontFace: SANS, fontSize: 12, bold: true, color: 'C9D1E3', charSpacing: 2.2, isTextBox: true, margin: 0 });
  s.addText(D.title, { x: 1.05, y: 2.65, w: 11, h: 1.0, fontFace: SANS, fontSize: 42, bold: true, color: WHITE, isTextBox: true, margin: 0 });
  s.addText(D.subtitle, { x: 1.05, y: 3.65, w: 11, h: 0.5, fontFace: SANS, fontSize: 20, color: 'E4E8F0', isTextBox: true, margin: 0 });
  s.addText('Demo for the CMDB team  ·  21 September 2026  ·  Mihir Kumar Singh', { x: 1.05, y: 5.7, w: 11, h: 0.3, fontFace: SANS, fontSize: 12, color: 'C9D1E3', isTextBox: true, margin: 0 });
}

// ---------------------------------------------------------------- concepts: one page per column of the source
D.concepts.forEach(c => {
  c.columns.forEach((col, ci) => {
    const s = page(c.kicker + '  ·  ' + c.title, col.heading, (ci + 1) + ' of ' + c.columns.length + '  ·  ' + c.title);
    const y0 = 1.58, avail = H - 0.5 - y0, colW = (CONTENT_W - 0.7 - 0.4) / 2;
    const items = col.bullets.map(b => ({ title: b.title, detail: b.detail }));
    const size = pickTwoColumns(items, colW, avail - 0.7, [15, 14.5, 14, 13.5, 13, 12.5, 12, 11.5, 11], 10, 14) || 10.5;
    if (size < 11) warnings.push('concept page ' + col.heading + ' at ' + size + 'pt');
    const cols = twoColumns(items, colW, size, 10, 14);
    const ch = Math.min(avail, cols.height + 0.75);
    card(s, M, y0, CONTENT_W, ch);
    list(s, M + 0.35, y0 + 0.35, colW, ch - 0.6, cols.left, size, 10);
    list(s, M + 0.35 + colW + 0.4, y0 + 0.35, colW, ch - 0.6, cols.right, size, 10);
  });
});

// ---------------------------------------------------------------- chain at a glance
{
  const s = page('Key concepts', 'The chain at a glance: first rule to answer wins');
  const head = ['Order', 'Rule', 'Reads', 'Returns'].map(t => ({ text: t, options: { bold: true, color: WHITE, fill: { color: NAVY }, fontSize: 10 } }));
  const rows = [head].concat(D.chain.map((r, i) => r.map((v, j) => ({ text: v, options: { fontSize: 9, bold: j < 2, color: j === 0 ? RED : j === 1 ? TITLE : INK, fill: { color: i % 2 ? TINT : WHITE } } }))));
  s.addTable(rows, { x: M, y: 1.35, w: CONTENT_W, colW: [0.7, 3.0, 2.3, CONTENT_W - 6.0], fontFace: SANS, border: { type: 'solid', pt: 0.5, color: LINE }, rowH: 0.245, margin: 0.03, valign: 'middle' });
  s.addText("After the USEM rules the platform's own rules run (FQDN, NetBIOS, DNS). A rule that returns nothing hands the host to the next one.", { x: M, y: 6.8, w: CONTENT_W, h: 0.24, fontFace: SANS, fontSize: 9.5, color: MUTED, isTextBox: true, margin: 0 });
}

// ---------------------------------------------------------------- rules
D.rules.forEach(r => {
  const name = r.name.replace('USEM ', '');
  const kicker = 'Rule ' + r.order + '  ·  ' + r.group;
  const steps = r.mechanics.map(m => ({ title: m.title, detail: m.detail }));
  // how many step pages are needed (two columns, 12pt down to 11pt, else split)
  const y0 = 1.58, avail = H - 0.5 - y0, colW = (CONTENT_W - 0.7 - 0.4) / 2, inner = avail - 0.62;
  let stepPages;
  const one = pickTwoColumns(steps, colW, inner, [15, 14.5, 14, 13.5, 13, 12.5], 8, 0);
  if (one) stepPages = [{ items: steps, size: one }];
  else {
    const pages = [];
    let cur = [];
    steps.forEach(st => {
      if (cur.length && twoColumns(cur.concat([st]), colW, 12, 8, 0).height > inner) { pages.push(cur); cur = [st]; } else cur.push(st);
    });
    if (cur.length) pages.push(cur);
    // rebalance: equal counts across the pages
    const per = Math.ceil(steps.length / pages.length);
    stepPages = [];
    for (let i = 0; i < steps.length; i += per) stepPages.push({ items: steps.slice(i, i + per), size: 0 });
    stepPages.forEach(p => { p.size = pickTwoColumns(p.items, colW, inner, [15, 14.5, 14, 13.5, 13, 12.5, 12, 11.5, 11, 10.5], 8, 0) || 10; if (p.size < 11) warnings.push('rule ' + r.order + ' steps page at ' + p.size + 'pt'); });
  }
  const total = 2 + stepPages.length;

  // page 1: what it looks for, the contract, the place in the chain
  {
    const s = page(kicker + '  ·  1 of ' + total, name, 'What it looks for');
    const purpose = sentences(r.purpose);
    const pw = CONTENT_W - 0.7;
    const psize = pick(purpose, pw, 1.9, [15, 14.5, 14, 13.5, 13, 12.5, 12, 11.5], 6, 14) || 11;
    const ph = heightOf(purpose, pw, psize, 6, 14) + 0.7;
    card(s, M, y0, CONTENT_W, ph, WHITE, RED);
    heading(s, M + 0.35, y0 + 0.2, pw, 'What it looks for');
    list(s, M + 0.35, y0 + 0.58, pw, ph - 0.7, purpose, psize, 6);
    const y1 = y0 + ph + 0.25, hmax = H - 0.5 - y1;
    const lw = CONTENT_W * 0.62, rw = CONTENT_W - lw - 0.25;
    const contract = [{ title: 'Reads', detail: r.reads }, { title: 'Returns', detail: r.returns }];
    const csize = pick(contract, lw - 0.7, hmax - 0.85, [14, 13.5, 13, 12.5, 12, 11.5, 11, 10.5, 10], 8, 0) || 9.5;
    const h1 = Math.min(hmax, Math.max(2.5, heightOf(contract, lw - 0.7, csize, 8, 0) + 0.95));
    card(s, M, y1, lw, h1);
    heading(s, M + 0.35, y1 + 0.2, lw - 0.7, 'The contract of the script');
    if (csize < 10.5) warnings.push('rule ' + r.order + ' contract at ' + csize + 'pt');
    list(s, M + 0.35, y1 + 0.6, lw - 0.7, h1 - 0.8, contract, csize, 8, { bullets: false });
    const x2 = M + lw + 0.25;
    card(s, x2, y1, rw, h1, TINT2);
    heading(s, x2 + 0.35, y1 + 0.2, rw - 0.7, 'Place in the chain');
    const chain = [{ title: 'Runs after', detail: r.before_names }, { title: 'Hands over to', detail: r.after_names }];
    const chsize = pick(chain, rw - 0.7, h1 - 1.9, [13, 12.5, 12, 11.5, 11, 10.5], 8, 0) || 10;
    list(s, x2 + 0.35, y1 + 0.6, rw - 0.7, h1 - 1.9, chain, chsize, 8, { bullets: false });
    if (r.matched != null) {
      const n = String(r.matched).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
      s.addText(n, { x: x2 + 0.35, y: y1 + h1 - 1.2, w: rw - 0.7, h: 0.6, fontFace: SANS, fontSize: 28, bold: true, color: RED, isTextBox: true, margin: 0, valign: 'bottom' });
      s.addText('discovered items matched by this rule on the development instance', { x: x2 + 0.35, y: y1 + h1 - 0.58, w: rw - 0.7, h: 0.4, fontFace: SANS, fontSize: 9.5, color: MUTED, isTextBox: true, margin: 0, valign: 'top' });
    }
  }
  // step pages
  let start = 1;
  stepPages.forEach((p, pi) => {
    const sub = 'How the script works' + (stepPages.length > 1 ? '  ·  steps ' + start + ' to ' + (start + p.items.length - 1) : '');
    const s = page(kicker + '  ·  ' + (2 + pi) + ' of ' + total, name, sub);
    const cols = twoColumns(p.items, colW, p.size, 8, 0);
    const sh = Math.min(avail, cols.height + 0.7);
    card(s, M, y0, CONTENT_W, sh);
    list(s, M + 0.35, y0 + 0.33, colW, sh - 0.6, cols.left, p.size, 8, { numbered: true, start });
    list(s, M + 0.35 + colW + 0.4, y0 + 0.33, colW, sh - 0.6, cols.right, p.size, 8, { numbered: true, start: start + cols.left.length });
    start += p.items.length;
  });
  // last page: declines when
  {
    const s = page(kicker + '  ·  ' + total + ' of ' + total, name, 'When it declines');
    const items = r.declines.map(cap);
    const dsize = pickTwoColumns(items, colW, avail - 1.5, [15, 14.5, 14, 13.5, 13, 12.5, 12, 11.5, 11], 9, 14) || 10.5;
    if (dsize < 11) warnings.push('rule ' + r.order + ' declines at ' + dsize + 'pt');
    const dh = Math.min(avail - 0.95, twoColumns(items, colW, dsize, 9, 14).height + 0.85);
    card(s, M, y0, CONTENT_W, dh, WHITE, RED);
    heading(s, M + 0.35, y0 + 0.2, CONTENT_W - 0.7, 'The rule returns nothing when');
    const cols = twoColumns(items, colW, dsize, 9, 14);
    list(s, M + 0.35, y0 + 0.58, colW, dh - 0.7, cols.left, dsize, 9);
    list(s, M + 0.35 + colW + 0.4, y0 + 0.58, colW, dh - 0.7, cols.right, dsize, 9);
    const y2 = y0 + dh + 0.25, h2 = Math.min(0.72, H - 0.5 - y2);
    if (h2 >= 0.6) {
      card(s, M, y2, CONTENT_W, h2, TINT);
      const next = r.after_names.startsWith('the platform') ? r.after_names : 'USEM ' + r.after_names;
      s.addText([{ text: 'Every decline hands the host to  ', options: { color: INK } }, { text: next, options: { bold: true, color: NAVY } }, { text: r.after_names.startsWith('the platform') ? '.' : ', the next rule in the chain.', options: { color: INK } }],
        { x: M + 0.35, y: y2, w: CONTENT_W - 0.7, h: h2, fontFace: SANS, fontSize: 12.5, isTextBox: true, margin: 0, valign: 'middle' });
    }
  }
  // example pages: a band of the earlier rules' findings on top, then the item, the walk and the CI side by side
  r.examples.forEach((x, k) => {
    const s = page('Rule ' + r.order + '  ·  ' + name + '  ·  example ' + (k + 1) + ' of ' + r.examples.length, x.host, x.path ? 'Path through the rule  ·  ' + x.path : '');
    const ey = 1.52, bottom = H - 0.5, gap = 0.22;
    // why band: the families are grouped by what happened (sign absent, nothing found, no single acceptable record)
    const why = [];
    {
      const groups = { skip: [], none: [], other: [] };
      const single = [];
      const FAMILIES = ['Serial rules', 'Phone MAC rule', 'FQDN rules', 'Name + domain rules', 'Layered DNS rule', 'Host name rules', 'Device name rule', 'Controller rule', 'Interface rule', 'Whole-fqdn name rule', 'Member rule', 'Service rule', 'Address rules', 'Adapter rule', 'IP Address record rule'];
      (x.why_lines || []).forEach(l => {
        const k2 = l.indexOf(': ');
        if (!(k2 > 0 && k2 < 30) || FAMILIES.indexOf(l.slice(0, k2)) === -1) { single.push(l); return; }
        const fam = l.slice(0, k2), detail = l.slice(k2 + 2), last = detail.split(' / ').pop();
        const kind = /is not sep \+ 12 hex|no dot in the name|no domain in the name|gives no class$|OS gives the class|no controller suffix|no interface domain|no VIP sign|no serial reported|is a placeholder/.test(last) ? 'skip'
          : /^no record|^no DNS Name record|^none named|^no adapter|^no IP Address record|^no service record|^nothing/.test(last) ? 'none' : 'other';
        const short = fam.replace(/ rules?$/, '').replace(/^(\w)/, c => c.toLowerCase()).replace(/^fQDN/, 'FQDN').replace(/^iP/, 'IP');
        groups[kind].push(short + ' (' + detail + ')');
      });
      single.forEach(l => { const k2 = l.indexOf(': '); why.push(k2 > 0 && k2 < 40 ? { title: l.slice(0, k2) + ':', detail: l.slice(k2 + 2) } : { title: '', detail: l }); });
      if (groups.skip.length) why.push({ title: 'Skipped, their sign is absent:', detail: groups.skip.join('  ·  ') });
      if (groups.none.length) why.push({ title: 'Searched, nothing found:', detail: groups.none.join('  ·  ') });
      if (groups.other.length) why.push({ title: 'Searched, no single acceptable record:', detail: groups.other.join('  ·  ') });
    }
    let by = ey, bh = 0, wsize = 10;
    if (why.length) {
      const rows = why.map(it => it.title ? it : it.detail);
      wsize = pick(rows, CONTENT_W - 0.56, 1.5, [11, 10.5, 10, 9.5, 9], 4, 0) || 8.5;
      if (wsize < 9) warnings.push('example ' + x.number + ' why at ' + wsize + 'pt');
      bh = heightOf(rows, CONTENT_W - 0.56, wsize, 4, 0) + 0.66;
      card(s, M, by, CONTENT_W, bh, TINT2);
      heading(s, M + 0.28, by + 0.15, CONTENT_W - 0.56, 'Why this rule and not an earlier one');
      list(s, M + 0.28, by + 0.5, CONTENT_W - 0.56, bh - 0.56, rows, wsize, 4, { bullets: false });
    }
    const ry = by + bh + (bh ? gap : 0), rh = bottom - ry;
    const walkChars = x.walk.reduce((a, w) => a + (typeof w === 'string' ? w.length : w.title.length + w.detail.length), 0);
    const iw = walkChars > 700 ? 2.85 : 3.05, cw = walkChars > 700 ? 3.15 : 3.55, kx = M + iw + gap, kw = CONTENT_W - iw - cw - 2 * gap, cx = kx + kw + gap;
    // discovered item
    card(s, M, ry, iw, rh);
    heading(s, M + 0.26, ry + 0.17, iw - 0.52, 'Discovered item');
    s.addText(x.number, { x: M + 0.26, y: ry + 0.52, w: iw - 0.52, h: 0.34, fontFace: SANS, fontSize: 15, bold: true, color: TITLE, isTextBox: true, margin: 0 });
    const ifacts = x.item_facts.map(f => f[0] + '  ' + f[1]);
    const ifh = rh - 0.92 - 0.78;
    const isize = pick(ifacts, iw - 0.52, ifh, [12, 11.5, 11, 10.5, 10, 9.5, 9], 3, 0) || 8.5;
    if (isize < 9.5) warnings.push('example ' + x.number + ' item facts at ' + isize + 'pt (card ' + rh.toFixed(2) + ')');
    facts(s, M + 0.26, ry + 0.92, iw - 0.52, ifh, x.item_facts, isize);
    link(s, M + 0.26, ry + rh - 0.4, iw - 0.52, 'Open the discovered item', x.item_link);
    // what the rule did
    card(s, kx, ry, kw, rh);
    heading(s, kx + 0.28, ry + 0.17, kw - 0.56, 'What the rule did');
    const walk = x.walk.map(w => typeof w === 'string' ? w : { title: w.title, detail: w.detail });
    const ksize = pick(walk, kw - 0.56, rh - 0.72, [13, 12.5, 12, 11.5, 11, 10.5, 10, 9.5, 9], 7, 0) || 8.5;
    if (ksize < 9.5) warnings.push('example ' + x.number + ' walk at ' + ksize + 'pt (card ' + rh.toFixed(2) + ' x ' + kw.toFixed(2) + ')');
    list(s, kx + 0.28, ry + 0.55, kw - 0.56, rh - 0.72, walk, ksize, 7, { numbered: true, start: 1 });
    // CI matched
    card(s, cx, ry, cw, rh, WHITE, RED);
    heading(s, cx + 0.3, ry + 0.17, cw - 0.56, 'CI matched');
    const nsize = x.ci_name.length > 44 ? 11 : x.ci_name.length > 30 ? 12 : x.ci_name.length > 22 ? 13.5 : 15;
    const nh = Math.max(0.32, lines(x.ci_name, cw - 0.58, nsize, 0) * nsize * 1.2 / 72 + 0.04);
    s.addText(x.ci_name, { x: cx + 0.3, y: ry + 0.52, w: cw - 0.58, h: nh, fontFace: SANS, fontSize: nsize, bold: true, color: NAVY, isTextBox: true, margin: 0, valign: 'top' });
    s.addText(x.ci_class, { x: cx + 0.3, y: ry + 0.55 + nh, w: cw - 0.58, h: 0.26, fontFace: SANS, fontSize: 11, bold: true, color: RED, isTextBox: true, margin: 0 });
    const cfy = ry + 0.9 + nh, cfh = ry + rh - 0.78 - cfy;
    const cfacts = x.ci_facts.map(f => f[0] + '  ' + f[1]);
    const csize = pick(cfacts, cw - 0.58, cfh, [12, 11.5, 11, 10.5, 10, 9.5, 9], 3, 0) || 8.5;
    if (csize < 9.5) warnings.push('example ' + x.number + ' CI facts at ' + csize + 'pt (h ' + cfh.toFixed(2) + ')');
    facts(s, cx + 0.3, cfy, cw - 0.58, cfh, x.ci_facts, csize);
    link(s, cx + 0.3, ry + rh - 0.4, cw - 0.58, 'Open the CI', x.ci_link);
    walkPages(r, x, k, name);
  });
});

pres.writeFile({ fileName: OUT }).then(() => {
  const n = 1 + D.concepts.reduce((a, c) => a + c.columns.length, 0) + 1 + D.rules.reduce((a, r) => a + 3 + r.examples.length, 0);
  console.log('written: ' + OUT + ' | slides at least: ' + n + (warnings.length ? '\nwarnings:\n  ' + warnings.join('\n  ') : '\nno size warnings'));
});
