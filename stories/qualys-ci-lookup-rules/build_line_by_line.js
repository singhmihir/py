// One-hour read: rules 455 and 460 line by line, from line_by_line_455_460.json (drafted, reviewed and repaired
// against the delivered scripts), with the sample world, a second walk with another payload, and rule 450 as an appendix.
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
        AlignmentType, LevelFormat, TableLayoutType, PageNumber, Footer, PageBreak } = require('docx');
const DATA = JSON.parse(fs.readFileSync(__dirname + '/line_by_line_455_460.json', 'utf8'));
const FONT = 'Arial', SZ = 18, MUTED = '555555', HEAD = 'E8EAED', ZEBRA = 'F6F7F8', NOTE = 'FFF6DC', CODE = 'EEF1F5';
const HAIR = { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0' };
const t = (text, o) => { o = o || {}; return new TextRun({ text, font: o.mono ? 'Consolas' : FONT, size: o.size || SZ, bold: o.bold, italics: o.italics, color: o.color }); };
const p = (runs, o) => { o = o || {}; return new Paragraph({ children: Array.isArray(runs) ? runs : [runs], spacing: { before: o.before || 0, after: o.after == null ? 70 : o.after, line: o.line || 250 }, alignment: o.align, shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill } : undefined, keepNext: o.keepNext, indent: o.indent ? { left: o.indent } : undefined }); };
const h1 = (text) => new Paragraph({ children: [t(text, { bold: true, size: 28 })], spacing: { before: 280, after: 80, line: 250 }, border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: '9AA0A6', space: 2 } }, keepNext: true });
const h2 = (text) => new Paragraph({ children: [t(text, { bold: true, size: 23 })], spacing: { before: 200, after: 60, line: 250 }, border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0', space: 2 } }, keepNext: true });
const h3 = (text) => new Paragraph({ children: [t(text, { bold: true, size: 19 })], spacing: { before: 160, after: 40, line: 250 }, keepNext: true });
const b = (runs) => new Paragraph({ children: Array.isArray(runs) ? runs : [runs], numbering: { reference: 'bullets', level: 0 }, spacing: { after: 40, line: 250 } });
const codeLine = (text) => new Paragraph({ children: [t(text || ' ', { mono: true, size: 16 })], spacing: { before: 90, after: 30, line: 225 }, shading: { type: ShadingType.CLEAR, fill: CODE }, keepNext: true });
const cell = (children, w, fill) => new TableCell({ children, width: { size: w, type: WidthType.DXA }, shading: fill ? { type: ShadingType.CLEAR, fill } : undefined, margins: { top: 34, bottom: 34, left: 80, right: 80 } });
function table(headers, rows, widths, monoCols) {
  monoCols = monoCols || [];
  const mk = (r, fill, bold) => new TableRow({ cantSplit: true, children: r.map((c, i) => cell([p(t(String(c), { bold, size: 16, mono: !bold && monoCols.indexOf(i) > -1 }), { after: 0, line: 225 })], widths[i], fill)) });
  return new Table({ rows: [mk(headers, HEAD, true)].concat(rows.map((r, i) => mk(r, i % 2 ? ZEBRA : undefined, false))),
    width: { size: widths.reduce((a, c) => a + c, 0), type: WidthType.DXA }, columnWidths: widths, layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR } });
}
const K = [];
K.push(p(t('Rules 455 and 460, Line by Line', { bold: true, size: 34 }), { after: 20 }));
K.push(p(t('A one-hour read: every line of USEM Load Balancer Service Match and USEM Load Balancer Member Match in plain English, with the values each line produces for one sample host', { color: MUTED, size: 20 }), { after: 140 }));
K.push(p(t('How to read this', { bold: true })));
K.push(p(t('Section 1 sets up the sample world: one Qualys host record and the handful of CMDB records the two rules will meet, plus the few keywords the code uses. Sections 2 and 3 walk the two scripts one line at a time: the line itself, what it does, and the values in memory after it for the sample host. Section 4 puts the two rules side by side and follows a second, different host through both. The appendix covers rule 450 in a page. Read 460 before 455: 455 begins with the same forty lines and only then walks further.')));
K.push(table(['Section', 'Minutes'], [['1  The sample world and the keywords', '10'], ['2  Rule 460 line by line', '15'], ['3  Rule 455 line by line', '25'], ['4  Side by side and a second host', '8'], ['Appendix  Rule 450', '2']], [6000, 1500]));

// ---------------------------------------------------------------- Section 1
K.push(h1('1  The sample world and the keywords'));
K.push(h2('1.1  The host record the rules receive'));
K.push(p(t('The platform hands each rule three things: rule (the rule record itself, not read by these scripts), sourceValue (the value of the rule’s Source field taken from the host record; both rules have Source field IP, so it is the scanned address) and sourcePayload (the whole host record). For the sample host:')));
K.push(codeLine('{"ID": "1202267231", "IP": "171.203.142.26", "TRACKING_METHOD": "IP", "OS": "F5 Big IP", "DNS": "crisp-tx.bankofamerica.com"}'));
K.push(table(['Variable the platform passes', 'Value for the sample'], [['sourceValue', '"171.203.142.26"'], ['sourcePayload.IP', '"171.203.142.26"'], ['sourcePayload.DNS', '"crisp-tx.bankofamerica.com"'], ['sourcePayload.OS', '"F5 Big IP"'], ['rule', 'the lookup rule record; unused']], [3500, 5500], [0, 1]));
K.push(h2('1.2  The CMDB records the rules will meet'));
K.push(table(['Record', 'Class (table)', 'Fields that matter'], [
  ['crisp-tx (the virtual server)', 'Load Balancer Service (cmdb_ci_lb_service)', 'fqdn crisp-tx.bankofamerica.com; ip_address 171.203.142.26; port 443; pool -> crisp-tx-pool; load_balancer -> rvcpcz1atmlb01s'],
  ['crisp-tx-pool', 'Load Balancer Pool (cmdb_ci_lb_pool)', 'service -> crisp-tx; load_balancer -> rvcpcz1atmlb01s'],
  ['crisp-tx-pool_10.10.20.31_443 (the one member)', 'Load Balancer Pool Member (cmdb_ci_lb_pool_member)', 'pool -> crisp-tx-pool; ip_address 10.10.20.31; service_port 443'],
  ['usvacrispweb01 (the real server)', 'Linux Server (cmdb_ci_linux_server, in the Hardware tree)', 'ip_address 10.10.20.31; no adapter records, no IP Address records'],
  ['rvcpcz1atmlb01s (the balancer device)', 'F5 BIG-IP (cmdb_ci_lb_bigip, under Load Balancer, under Server, under Hardware)', 'ip_address 171.203.142.26'],
], [3100, 3300, 3600]));
K.push(p(t('No relationship rows (cmdb_rel_ci) involve these records. The platform property sn_sec_cmn.ignoreCIClass holds "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name". In the text below, <crisp-tx>, <crisp-tx-pool>, <member-31>, <usvacrispweb01> and <bigip> stand for the sys_ids (the 32-character record identifiers) of those records.'), { before: 60 }));
K.push(h2('1.3  The keywords, once'));
K.push(table(['Written in the code', 'Meaning'], [
  ['var x = ...;', 'create a named box called x and put the value on the right in it'],
  ['if (condition) ... ', 'do the next line only when the condition holds; "!" in front means "not"'],
  ['return value;', 'the rule stops here and answers with this value; return null means "no CI, next rule"'],
  ['function name(a, b) { ... }', 'a named helper that can be called later with two inputs; the lines between the braces run when it is called'],
  ['for (var i = 0; i < list.length; i++) { ... }', 'repeat the lines between the braces once for each item of the list, i counting from 0'],
  ['while (gr.next()) { ... }', 'repeat the lines between the braces for each row the query returned'],
  ['a == b, a != b', 'a equals b; a differs from b (values compared after converting types)'],
  ['a === null', 'a is exactly the special value null (no type conversion)'],
  ['a && b, a || b', 'both hold; at least one holds. "x || \'\'" also means: x, or an empty text when x is empty'],
  ['null, undefined', 'null: an empty answer given on purpose; undefined: a box that was never filled'],
  ['\'\' + x', 'turn x into text (an empty text glued to x); an empty field becomes the text "null", which is why some lines add "|| \'\'" first'],
  ['s.trim(), s.toLowerCase()', 'remove spaces at both ends; make every letter lower case'],
  ['s.split(\'.\')[0], s.split(\'-\')', 'cut the text at each dot and keep the first piece; cut at each hyphen and keep all pieces as a list'],
  ['s.indexOf(w) != -1', 'the text contains w (indexOf gives the position of w, or -1 when absent); == 0 means "starts with w"'],
  ['new GlideRecord(\'table\')', 'open a query on that table (its sub-classes included)'],
  ['gr.addQuery(f, v), gr.addNotNullQuery(f)', 'add a condition "field f equals v"; add "field f is not empty"'],
  ['gr.query(); gr.next(); gr.hasNext()', 'run the query; step to the next row (false when none is left); is there another row after this one'],
  ['gr.get(id)', 'load the record with that sys_id from this table or its sub-classes; true when found'],
  ['gr.getValue(f), gr.getUniqueValue()', 'the value of field f (null when empty); the sys_id of the current row'],
  ['gr.isValid()', 'true when the table exists on this instance'],
  ['obj[key] = true; Object.keys(obj)', 'remember key in a set; the list of remembered keys'],
], [3600, 6400], [0]));

// ---------------------------------------------------------------- Sections 2 and 3 from the reviewed data
function ruleSection(num, order, title, lead) {
  const R = DATA.rules.find(r => r.rule == order);
  K.push(new Paragraph({ children: [new PageBreak()] }));
  K.push(h1(num + '  ' + title));
  K.push(p(t(lead)));
  R.stages.forEach((st, si) => {
    K.push(h2(num + '.' + (si + 1) + '  ' + st.title));
    K.push(p(t(st.summary), { fill: NOTE }));
    st.lines.forEach(l => {
      K.push(codeLine(l.code));
      K.push(p(t(l.explanation), { indent: 200, after: 20, keepNext: !!(l.state || l.note) }));
      if (l.state) K.push(p([t('Values now: ', { bold: true, color: MUTED }), t(l.state)], { indent: 200, after: l.note ? 20 : 60 }));
      if (l.note) K.push(p([t('Note: ', { bold: true, color: MUTED }), t(l.note)], { indent: 200, after: 60 }));
    });
  });
}
ruleSection('2', '460', 'Rule 460, USEM Load Balancer Service Match, line by line',
  'This rule finds the Load Balancer Service record of a virtual server. It runs on the scanned address, goes on only for a host that looks like a virtual IP, and searches the service table by fqdn, name, label and address, accepting exactly one record at each step. For the sample host it returns the sys_id of "crisp-tx".');
ruleSection('3', '455', 'Rule 455, USEM Load Balancer Member Match, line by line',
  'This rule runs just before 460 and starts with the same lines: the same VIP sign and the same service search. It then walks Service to Pool to Pool Member to server and returns the real server only when exactly one sits behind the virtual server. For the sample host it returns the sys_id of "usvacrispweb01".');

// ---------------------------------------------------------------- Section 4
K.push(new Paragraph({ children: [new PageBreak()] }));
K.push(h1('4  Side by side, and a second host'));
K.push(h2('4.1  What the two rules share and where they part'));
K.push(table(['Part of the script', '460 Service Match', '455 Member Match'], [
  ['Source field, the value in sourceValue', 'IP', 'IP'],
  ['Preparation (address, DNS name, label, OS text, ignore list)', 'identical', 'identical'],
  ['isMarker() helper', 'identical', 'identical'],
  ['VIP sign (osMarkers, labelMarkers)', 'identical lists; the flag is called evidence in the code', 'identical lists; the flag is called sign'],
  ['one() helper and the four search steps', 'a step that finds one service returns it as the rule’s answer', 'a step that finds one service keeps it in the variable service and the rule goes on'],
  ['After the service is found', 'the rule is finished', 'isRealServer(), related(), the pool stage, the member stage, the server stage'],
  ['Answer for the sample', '<crisp-tx>, the virtual server record', '<usvacrispweb01>, the real server'],
  ['Answer when there is no pool data', '<crisp-tx>', 'null, so 460 answers instead'],
], [3300, 3300, 3400]));
K.push(p(t('Why 455 runs first: the chain takes the first rule that answers. A single real server behind the virtual server is the more precise CI, so that rule must have its turn before the service rule attaches the virtual server record. When 455 finds nothing it costs a few reads and hands over.'), { before: 60 }));

K.push(h2('4.2  A second host through both rules'));
K.push(p(t('The host: IP 164.91.236.18, OS "Linux 2.6", DNS rbps-dev3-sve-vip.ecommnp.rpg. The CMDB holds a Load Balancer Service named "rbps-dev3-sve-vip" with ip_address 164.91.236.18, an empty fqdn and no pool; no pool or member records refer to it; no relationships.')));
K.push(table(['Stage', 'Rule 455', 'Rule 460'], [
  ['Preparation', 'ip = "164.91.236.18"; dns = "rbps-dev3-sve-vip.ecommnp.rpg"; label = "rbps-dev3-sve-vip"; os = "linux 2.6"', 'the same values'],
  ['VIP sign', 'no OS marker ("linux 2.6" contains none of f5, big-ip, big ip, netscaler); the label splits into ["rbps", "dev3", "sve", "vip"]; the segment "vip" equals the marker "vip", so the sign is true', 'the same: evidence becomes true through the segment "vip"'],
  ['Step fqdn = dns', 'no service has fqdn "rbps-dev3-sve-vip.ecommnp.rpg": one() returns undefined, next step', 'the same'],
  ['Step name = dns', 'no service is named with the whole FQDN: undefined, next step', 'the same'],
  ['Step name = label', 'the service "rbps-dev3-sve-vip" is found, no second row: one() returns its sys_id; service holds it', 'the same sys_id is returned at once: the rule answers with the virtual server record'],
  ['Pool stage', 'the service has an empty pool field; no pool points at the service; no pool is related to it; poolIds is an empty list; the rule returns null', 'not reached'],
  ['Answer', 'null', '<rbps-dev3-sve-vip>'],
], [1700, 4600, 3700]));
K.push(p(t('The finding of this host stays on the virtual server record, because the CMDB holds nothing behind it. The moment a pool with exactly one member on a real server is loaded for it, 455 will answer with that server on the next import.'), { before: 60 }));

// ---------------------------------------------------------------- Appendix 450
K.push(h1('Appendix  Rule 450, USEM FQDN Name Hardware Match'));
K.push(p(t('The rule for CIs whose name field holds the whole FQDN instead of the short host name. Source field DNS. Sample host: DNS lva40bneehcs01.ecomm.devicenp.rpg; the CMDB holds a Linux Server named exactly "lva40bneehcs01.ecomm.devicenp.rpg".')));
[
 ["(function process(rule, sourceValue, sourcePayload) {", 'The whole script is one function that the platform calls with the rule record, the DNS value and the host record.', 'sourceValue = "lva40bneehcs01.ecomm.devicenp.rpg"'],
 ["    if (!sourceValue)                             // nothing to look up", 'When the DNS field is empty there is nothing to search: stop with null.', 'the sample has a DNS value, so the rule goes on'],
 ["        return null;", 'The answer "no CI" for the empty case.', ''],
 ["    var fqdn = ('' + sourceValue).trim().toLowerCase();   // \"lva40bneehcs01.ecomm.devicenp.rpg\"", 'Make the value text, remove spaces at both ends, lower-case it, and keep it as fqdn.', 'fqdn = "lva40bneehcs01.ecomm.devicenp.rpg"'],
 ["    if (fqdn.indexOf('.') == -1)                  // a bare label is left to the hostname rules", 'A value with no dot is a bare host name, which the host name rules handle; stop.', 'the sample has dots, so it goes on'],
 ["        return null;", 'The answer for the bare-label case.', ''],
 ["    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?", 'Read the list of classes that must never be matched: the value the platform passes in when it does, otherwise the property.', 'ignore = the property value (the five class names)'],
 ["        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');", 'The second half of the same statement.', ''],
 ["    var gr = new GlideRecord('cmdb_ci_hardware');// Hardware and every class beneath it", 'Open a query on the Hardware table; servers, computers, network gear, storage and printers are all beneath it.', ''],
 ["    gr.addQuery('name', fqdn);", 'Condition: the name field equals the whole FQDN.', ''],
 ["    if (ignore)", 'Only when the ignore list is not empty:', ''],
 ["        gr.addQuery('sys_class_name', 'NOT IN', ignore);", 'Condition: the record’s class is not one of the ignored ones.', ''],
 ["    gr.query();", 'Run the query.', 'one row: the Linux Server'],
 ["    if (!gr.next())", 'No row at all: stop with null.', 'a row exists, so it goes on'],
 ["        return null;", 'The answer for "nothing carries this name".', ''],
 ["    var match = gr.getUniqueValue();", 'Keep the sys_id of the first row.', 'match = <the Linux Server>'],
 ["    if (gr.hasNext())                             // a second CI carries the same value, never guess", 'Is there a second row? Then the name is shared and the rule must not guess.', 'no second row'],
 ["        return null;", 'The answer for a shared name.', ''],
 ["    return match;", 'The answer: the one CI named with the FQDN.', 'the rule returns <the Linux Server>'],
 ["})(rule, sourceValue, sourcePayload);", 'The call of the function with the three values the platform provides.', ''],
].forEach(l => { K.push(codeLine(l[0])); K.push(p(t(l[1]), { indent: 200, after: l[2] ? 20 : 60 })); if (l[2]) K.push(p([t('Values now: ', { bold: true, color: MUTED }), t(l[2])], { indent: 200, after: 60 })); });

const doc = new Document({
  styles: { default: { document: { run: { font: FONT, size: SZ } } } },
  numbering: { config: [{ reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360, hanging: 240 } } } }] }] },
  sections: [{ properties: { page: { margin: { top: 1000, bottom: 900, left: 1000, right: 1000 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [t('Rules 455 and 460, line by line   ', { size: 14, color: MUTED }), new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 14, color: MUTED })] })] }) },
    children: K }]
});
Packer.toBuffer(doc).then(buf => { fs.writeFileSync(__dirname + '/Rules 455 and 460 - Line by Line.docx', buf); console.log('written', buf.length, 'bytes'); });
