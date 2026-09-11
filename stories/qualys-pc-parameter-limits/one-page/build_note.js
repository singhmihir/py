// One-page note for the story comment: setStringParameter and the Qualys ids parameter.
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
        AlignmentType, LevelFormat, ExternalHyperlink, TableLayoutType } = require('docx');
const FONT = 'Arial', SZ = 18, MUTED = '555555', HEAD = 'E8EAED', ZEBRA = 'F6F7F8';
const HAIR = { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0' };
const t = (text, o) => { o = o || {}; return new TextRun({ text, font: o.mono ? 'Consolas' : FONT, size: o.size || SZ, bold: o.bold, italics: o.italics, color: o.color }); };
const link = (url, label) => new ExternalHyperlink({ children: [new TextRun({ text: label, font: FONT, size: SZ, color: '1155CC', underline: {} })], link: url });
const p = (runs, o) => { o = o || {}; return new Paragraph({ children: Array.isArray(runs) ? runs : [runs], spacing: { before: o.before || 0, after: o.after == null ? 40 : o.after, line: o.line || 228 }, alignment: o.align }); };
const h = (text) => new Paragraph({ children: [t(text, { bold: true, size: 20 })], spacing: { before: 100, after: 30, line: 240 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0', space: 2 } } });
const b = (runs, level) => new Paragraph({ children: Array.isArray(runs) ? runs : [runs], numbering: { reference: 'bullets', level: level || 0 }, spacing: { after: 24, line: 228 } });
const cell = (children, w, fill) => new TableCell({ children, width: { size: w, type: WidthType.DXA }, shading: fill ? { type: ShadingType.CLEAR, fill } : undefined,
  margins: { top: 40, bottom: 40, left: 80, right: 80 } });
function table(headers, rows, widths) {
  const mk = (r, fill, bold) => new TableRow({ cantSplit: true, children: r.map((c, i) => cell([p(t(String(c), { bold, size: 17, mono: i === 3 && !bold }), { after: 0, line: 220 })], widths[i], fill)) });
  return new Table({ rows: [mk(headers, HEAD, true)].concat(rows.map((r, i) => mk(r, i % 2 ? ZEBRA : undefined, false))),
    width: { size: widths.reduce((a, c) => a + c, 0), type: WidthType.DXA }, columnWidths: widths, layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR } });
}
const K = [];
K.push(p(t('setStringParameter and the Qualys ids parameter', { bold: true, size: 26 }), { after: 20 }));
K.push(p(t('Points for the story comment: how the value is handled, what limits apply and where each figure is documented or stored.', { color: MUTED }), { after: 40 }));

K.push(h('1. How the parameter handles the value'));
K.push(b([t('RESTMessageV2.setStringParameter(name, value)', { mono: true }), t(' replaces the '), t('${ids}', { mono: true }), t(' placeholder when the request is executed. Placeholders are allowed in the endpoint URL, HTTP query parameter values, HTTP headers and POST/PUT content. XML reserved characters in the value are escaped; '), t('setStringParameterNoEscape', { mono: true }), t(' is identical without the escaping.')]));
K.push(b([t('The value is held for that request only and is not written to any table, so no field length applies to it; a 3,000-character value passed this way left the stored endpoint unchanged, with the '), t('${ids}', { mono: true }), t(' placeholder still in the field. The only bound is the length of the request the platform builds.')]));
K.push(b([t('The shipped Qualys Policy Compliance integration uses this route: '), t('setStringParameter("policyId", ...)', { mono: true }), t(' and '), t('setStringParameter("truncation_limit_pc_result", ...)', { mono: true }), t(' in '), t('QualysPCResultsIntegration', { mono: true }), t(', one policy per request (Qualys Integration for Security Operations 30.6.0).')]));

K.push(h('2. Character limits'));
K.push(b([t('ServiceNow documents no length limit for a value passed through setStringParameter.')]));
K.push(b([t('Declared lengths of the fields a stored value would sit in (Max length on the dictionary entry): HTTP Query Parameter '), t('Value', { bold: true }), t(' 1,000; Variable Substitutions '), t('Test value', { bold: true }), t(' 1,000 (a test value only, not the live value); HTTP Method '), t('Endpoint', { bold: true }), t(' 200; Integration Instance Parameter '), t('Value', { bold: true }), t(' 512 (the route the shipped integration configures); System property '), t('Value', { bold: true }), t(' 4,000.')]));
K.push(b([t('Max length is not enforced on save by the platform: writes of 1,200 and 2,000 characters into the 1,000-character query parameter field were kept in full, and the database may map a declared length to a wider column type. Treat the declared figure as the supported ceiling; the form applies it and a later column change can enforce it.')]));
K.push(b([t('Request URL: RFC 9110 recommends support for URIs of at least 8,000 octets; Apache limits the request line to 8,190 bytes by default; IIS request filtering defaults to 2,048 bytes of query string and 4,096 bytes of URL. Plan for about 2,000 characters of query string against an unknown server; use POST for a longer list (Qualys states GET limits are toolkit dependent and POST has none).')]));
K.push(b([t('Qualys '), t('ids', { mono: true }), t(' on the Policy List call ('), t('/api/2.0/fo/compliance/policy/?action=list', { mono: true }), t('): comma-separated policy IDs and ranges such as 160-165; no maximum count is documented; 1,000 policy records are processed per request and the rest are paged through the WARNING element. On the Posture Info call, '), t('policy_id', { mono: true }), t(' takes one policy and '), t('policy_ids', { mono: true }), t(' takes up to 10 and disables truncation_limit.')]));

K.push(h('3. Where it is documented'));
const D = [
  ['RESTMessageV2 API reference, setStringParameter', 'https://www.servicenow.com/docs/r/api-reference/server-api-reference/c_RESTMessageV2API.html'],
  ['Variable substitution in outbound REST messages', 'https://www.servicenow.com/docs/r/api-reference/web-services/c_VariableSubstitutionREST.html'],
  ['Field types reference, String Max length', 'https://www.servicenow.com/docs/r/platform-administration/r_FieldTypes.html'],
  ['Modify string field length', 'https://www.servicenow.com/docs/r/platform-administration/t_ModifyingStringFieldLength.html'],
  ['Max length not enforced on save (ServiceNow Community)', 'https://www.servicenow.com/community/developer-forum/max-length-value-of-string-field-is-not-honoured/td-p/3307639'],
  ['Qualys PC API, List Policies (ids parameter, 1,000 per request)', 'https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-pc/policies/list_policies.htm'],
  ['Qualys PC API, List Compliance Posture Info (policy_id, policy_ids, truncation_limit)', 'https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-pc/posture/list_posture_info.htm'],
  ['Qualys API Quick Reference, API notes on GET and POST', 'https://cdn2.qualys.com/docs/qualys-api-quick-reference.pdf'],
  ['RFC 9110, section 4.1 URI references', 'https://www.rfc-editor.org/rfc/rfc9110.html#name-uri-references'],
  ['Apache HTTP Server, LimitRequestLine', 'https://httpd.apache.org/docs/2.4/mod/core.html#limitrequestline'],
  ['IIS request filtering, requestLimits', 'https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/requestlimits/'],
];
D.forEach((d) => K.push(b([link(d[1], d[0]), t('  ' + d[1].replace(/^https?:\/\/(www\.)?/, '').split('/')[0], { color: MUTED, size: 16 })])));

K.push(h('4. Where the lengths are stored on the instance'));
K.push(p(t('Dictionary entries, table sys_dictionary. Open /sys_dictionary.do?sys_id=<id> on the instance to read the Max length figure.', { color: MUTED }), { after: 40 }));
K.push(table(['Related list', 'Field', 'Max length', 'Dictionary record id'], [
  ['HTTP Query Parameters (sys_rest_message_fn_param_defs)', 'value', '1,000', '4d84182cf50003100a22c0b3dfa15142'],
  ['Variable Substitutions (sys_rest_message_fn_parameters)', 'value "Test value"', '1,000', 'dd84182cf50003100a22c0b3dfa1519a'],
  ['HTTP Method (sys_rest_message_fn)', 'rest_endpoint', '200', '7084d42cf50003100a22c0b3dfa1518f'],
  ['Integration Instance Parameter (sn_sec_int_impl_config)', 'value', '512', '1b9d2390934e4710e3aef0aefaba1029'],
  ['System Property (sys_properties)', 'value', '4,000', '31931420f50003100a22c0b3dfa151f8'],
], [3100, 1500, 900, 4500]));

K.push(h('5. Suggested wording for the comment'));
K.push(p(t('The ids value is supplied at run time with RESTMessageV2.setStringParameter, which substitutes it into the ${ids} placeholder when the request is executed and escapes XML reserved characters. The value is not stored, so no field length applies to it. The HTTP Query Parameter Value field it substitutes into is declared at 1,000 characters (sys_rest_message_fn_param_defs.value) and a system property at 4,000 (sys_properties.value); neither length is enforced on save, so the declared figure is the supported ceiling. The practical limit is the request URL: plan for about 2,000 characters of query string (IIS default 2,048 bytes; Apache 8,190; RFC 9110 recommends 8,000 octets) and use POST for anything longer. Qualys accepts comma-separated IDs and ranges in ids, processes 1,000 policy records per request and pages the rest.', { italics: true }), { after: 0 }));

const doc = new Document({
  creator: 'Mihir Kumar Singh', lastModifiedBy: 'Mihir Kumar Singh', title: 'setStringParameter and the Qualys ids parameter',
  styles: { default: { document: { run: { font: FONT, size: SZ } } } },
  numbering: { config: [{ reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT,
    style: { paragraph: { indent: { left: 300, hanging: 200 } } } }] }] },
  sections: [{ properties: { page: { margin: { top: 600, bottom: 560, left: 680, right: 680 } } }, children: K }],
});
Packer.toBuffer(doc).then((buf) => { const out = __dirname + '/../../setStringParameter and the Qualys ids parameter.docx'; fs.writeFileSync(out, buf); console.log('written', out, buf.length, 'bytes'); });
