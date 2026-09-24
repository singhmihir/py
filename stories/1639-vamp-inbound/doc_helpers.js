// Shared docx helpers for the 1639 documents (house style: Arial, navy headings, hairline tables).
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
module.exports = { D, INST, FONT, MONO, INK, NAVY, RED, HEAD, ZEBRA, t, p, body, h1, h2, code, bullet, numbered, link, rec, list, cell, table, L, S };
