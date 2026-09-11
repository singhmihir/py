// Builds "Qualys PC Integration - Parameter Length and Paging Limits.docx" from
// instance_readings.json (readings taken on the instance) and citations.json (published sources).
const fs = require('fs');
const path = require('path');
const NM = process.env.NODE_MODULES || 'node_modules';   // where docx is installed
const D = require(path.join(NM, 'docx'));
const { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType,
        BorderStyle, ExternalHyperlink, AlignmentType, ShadingType, TableLayoutType } = D;

const R = JSON.parse(fs.readFileSync(path.join(__dirname, 'instance_readings.json'), 'utf8'));
const CITES = fs.existsSync(path.join(__dirname, 'citations.json'))
  ? JSON.parse(fs.readFileSync(path.join(__dirname, 'citations.json'), 'utf8')) : { groups: [] };

const FONT = 'Arial', MONO = 'Courier New';
const INK = '1F1F1F', MUTED = '5A5F63', ACCENT = 'A5122A', HEAD = 'E8EAEC', ZEBRA = 'F5F6F7';
const NONE = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
const HAIR = { style: BorderStyle.SINGLE, size: 4, color: 'C9CDD1' };

function t(text, o) {
  o = o || {};
  return new TextRun({ text: text, font: o.mono ? MONO : FONT, size: o.size || 20, bold: !!o.bold,
    italics: !!o.italics, color: o.color || INK });
}
function p(runs, o) {
  o = o || {};
  return new Paragraph({ children: Array.isArray(runs) ? runs : [runs], alignment: o.align,
    spacing: { before: o.before === undefined ? 0 : o.before, after: o.after === undefined ? 120 : o.after,
      line: o.line || 260 }, keepNext: !!o.keepNext, indent: o.indent });
}
function body(text, o) { return p(t(text, o), o); }
function h1(text) {
  return new Paragraph({ children: [t(text, { size: 30, bold: true })], heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 140 }, keepNext: true });
}
function h2(text) {
  return new Paragraph({ children: [t(text, { size: 23, bold: true })], heading: HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 100 }, keepNext: true });
}
function code(lines) {
  return lines.map((l, i) => new Paragraph({
    children: [t(l === '' ? ' ' : l, { mono: true, size: 17 })],
    spacing: { before: i === 0 ? 60 : 0, after: i === lines.length - 1 ? 140 : 0, line: 220 },
    shading: { type: ShadingType.CLEAR, fill: 'F2F3F4' },
    indent: { left: 180, right: 180 },
  }));
}
function bullet(text, o) {
  o = o || {};
  return new Paragraph({ children: [t(text, o)], bullet: { level: o.level || 0 },
    spacing: { after: 80, line: 260 } });
}
function link(url, label) {
  return new ExternalHyperlink({ children: [new TextRun({ text: label || url, font: FONT, size: 18,
    color: '1155CC', underline: {} })], link: url });
}
function cell(children, o) {
  o = o || {};
  return new TableCell({
    children: children,
    width: { size: o.w || 20, type: WidthType.PERCENTAGE },
    shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill } : undefined,
    margins: { top: 70, bottom: 70, left: 110, right: 110 },
    columnSpan: o.span,
    verticalAlign: 'top',
  });
}
function table(headers, rows, widths, opts) {
  opts = opts || {};
  const head = new TableRow({
    tableHeader: true,
    cantSplit: true,
    children: headers.map((hd, i) => cell([p(t(hd, { bold: true, size: 17 }), { after: 0, line: 220 })],
      { w: widths[i], fill: HEAD })),
  });
  const trs = rows.map((r, ri) => new TableRow({
    cantSplit: true,
    children: r.map((c, i) => cell(
      Array.isArray(c) ? c : [p(t(String(c), { size: 17, mono: opts.mono && opts.mono.indexOf(i) !== -1 }), { after: 0, line: 220 })],
      { w: widths[i], fill: ri % 2 ? ZEBRA : undefined })),
  }));
  return new Table({
    rows: [head].concat(trs),
    width: { size: 100, type: WidthType.PERCENTAGE },
    layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR },
  });
}
function spacer(h) { return new Paragraph({ children: [t('')], spacing: { after: h || 120 } }); }
function rec(table_, sysId) { return '/' + table_ + '.do?sys_id=' + sysId; }
function wj(v) { return String(v).replace(/\$\{/g, '$\u2060{'); }

const kids = [];

// ---------------------------------------------------------------- title block
kids.push(new Paragraph({
  children: [t('Qualys Policy Compliance integration', { size: 34, bold: true })],
  spacing: { after: 60 },
}));
kids.push(new Paragraph({
  children: [t('How long a parameter value can be, what the page size actually is, and why one policy goes per request', { size: 22, color: MUTED })],
  spacing: { after: 200 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: ACCENT, space: 8 } },
}));
kids.push(body('Supporting material for a story comment. Every figure below is either a reading taken from a ServiceNow ' +
  'instance running the application versions listed at the end, with the record named so it can be opened and checked, ' +
  'or a published statement from ServiceNow, Qualys, the IETF or a web server vendor, with a link and the sentence it ' +
  'comes from. Section 8 lists the four points where an earlier informal answer of mine was wrong or incomplete.',
  { color: MUTED, size: 19 }));

kids.push(h1('1. The short answer'));
kids.push(body('The question was how many characters are safe in an outbound REST parameter, specifically an id list for ' +
  'the Qualys Policy Compliance calls. There is no single number, because a value can sit in four different places on ' +
  'its way into the request, and the limit depends on which one is used.'));
kids.push(table(
  ['Where the value sits', 'Limit', 'When this is the one that applies'],
  [
    ['Value column of an HTTP Query Parameter', '1,000 characters declared', 'A fixed list is stored on the method itself. The form applies this figure; the platform does not enforce it on save.'],
    ['Integration Instance Parameter', '512 characters declared', 'The value is configuration that an administrator edits. This is the route the shipped Qualys integration uses.'],
    ['System property', '4,000 characters declared', 'A list is kept as configuration outside the integration framework. Widest of the three stores.'],
    ['Passed at run time by setStringParameter()', 'No column limit applies', 'A script supplies the value. It is never written to a field, so the ceiling moves to the length of the request URL.'],
    ['The request URL that results', 'Plan for about 2,000 characters of query string', 'Always, once the value is substituted. The standard recommends supporting 8,000 octets; common servers cut lower.'],
  ], [30, 20, 50]));
kids.push(spacer(60));
kids.push(body('So the earlier figure of roughly a thousand characters, four thousand in a property, is right for two of the ' +
  'stored cases and misleading for the case that matters: the shipped integration passes its values at run time, and the ' +
  'configuration field behind them stops at 512, not 1,000.', { bold: true }));

kids.push(h1('2. How a value reaches the Qualys request'));
kids.push(body('Nothing is hard coded into the URL. The two values that change per call arrive as variable substitutions, ' +
  'in four steps.'));
kids.push(bullet('An administrator sets the page size on the Qualys integration instance. That value lives in an Integration Instance Parameter record.'));
kids.push(bullet('The script include reads every parameter for that instance into a configuration object, through the Security Integration Framework.'));
kids.push(bullet('It calls setStringParameter() once per variable, supplying the policy id and the page size for this request.'));
kids.push(bullet('The method holds the query parameters, two of them written as $\u2060{policyId} and $\u2060{truncation_limit_pc_result}. The platform substitutes them when the message is sent.'));
kids.push(spacer(40));
kids.push(body('The relevant lines of the shipped script include:', { size: 19, color: MUTED }));
kids.push(...code(R.codeLines.map((c) => 'line ' + c[0] + '   ' + c[1])));
kids.push(body('The configuration object is built by the Security Integration Framework, which reads the Integration ' +
  'Instance Parameter records belonging to the running instance:', { size: 19, color: MUTED }));
kids.push(...code([
  'this.config = (new sn_sec_int.Implementation()).getConfiguration(this.integrationRunGr.implementation + "");',
  '',
  'getConfiguration: function(implementationID, getEncryptedValue, fullConfig) {',
  '    var implConfigGR = new GlideRecord("sn_sec_int_impl_config");',
  '    implConfigGR.addQuery("implementation", implementationID);',
  '    implConfigGR.query();',
  '    while (implConfigGR.next()) { ... config[implConfigGR.configuration.name + ""] = value; }',
]));
kids.push(body('That is the point that matters for length. Anything an administrator configures has already passed ' +
  'through the Integration Instance Parameter field, so that field, at 512 characters, is the binding limit for the ' +
  'configured route. A value a script builds for itself and hands straight to setStringParameter() never touches it.'));

kids.push(h1('3. The limits in that chain'));
kids.push(body('Each row is a dictionary entry read from the instance. To open one, go to /sys_dictionary.do?sys_id= ' +
  'followed by the id in the last column, on your own instance address.'));
kids.push(table(
  ['Related list and table', 'Field', 'Type, length', 'Dictionary record id'],
  R.columns.map((c) => [
    [p([t(c[1], { size: 17, bold: true }), t('\n' + c[0], { size: 14, mono: true, color: MUTED })], { after: 0, line: 210 })],
    c[2] + '  "' + c[3] + '"',
    c[4] + ', ' + c[5],
    [p(t(c[6], { size: 15, mono: true, color: MUTED }), { after: 0, line: 210 })],
  ]), [30, 22, 16, 32]));
kids.push(spacer(60));
kids.push(body('Three of these need a note.'));
kids.push(bullet('The Value column on Variable Substitutions is labelled "Test value", and ServiceNow documents it as being used when testing an HTTP method from the form. It is not the live value, so a long string there never reaches Qualys.'));
kids.push(bullet('The method Endpoint field stops at 200 characters, so writing an id list straight into the URL is the tightest option of all, not the loosest.'));
kids.push(bullet('The declared lengths are not a hard cut. ServiceNow states that the database may widen a column to the nearest matching type, and a write above the declared length was kept in full when made by script, as section 6 records.'));

kids.push(h1('4. The page size: what is set, and what Qualys would do anyway'));
kids.push(body('The page size for the Posture Info calls is not left to chance. ServiceNow ships a parameter for it, gives ' +
  'it a default, and that default is set on the instance. The last two columns are record ids: the shipped definition on ' +
  'sn_sec_int_config, and the value held for this integration instance on sn_sec_int_impl_config.'));
kids.push(table(
  ['Parameter', 'Shipped default', 'Set on the instance', 'Definition id', 'Value id'],
  R.config.map((c) => [
    [p([t(c[1], { size: 16, bold: true }), t('\n' + c[0], { size: 13, mono: true, color: MUTED })], { after: 0, line: 200 })],
    c[2], c[3],
    [p(t(c[4], { size: 15, mono: true, color: MUTED }), { after: 0, line: 210 })],
    [p(t(c[5], { size: 15, mono: true, color: MUTED }), { after: 0, line: 210 })],
  ]), [26, 12, 13, 24, 25]));
kids.push(spacer(60));
kids.push(body('The 5,000 is worth dwelling on, because it is the same on both sides. Qualys documents the default page ' +
  'size for a single policy Posture Info request as 5,000 records, and ServiceNow ships truncation_limit_pc_result set ' +
  'to 5,000. The platform is reproducing the Qualys default rather than overriding it, and the second Posture Info ' +
  'method carries the same figure as a literal instead of a variable.', { bold: true }));
kids.push(spacer(40));
kids.push(body('The 300 in the first row is also confirmed from the other direction: the release notes for this ' +
  'application record the host truncation limit being reduced from 500 to 300, which is the figure the instance holds.',
  { size: 19, color: MUTED }));
kids.push(spacer(40));
kids.push(body('Query parameters on the two shipped Posture Info methods, each row an HTTP Query Parameter record on ' +
  'sys_rest_message_fn_param_defs:', { size: 19, color: MUTED }));
kids.push(table(
  ['Method', 'Parameter', 'Value', 'Order', 'Record id'],
  R.rest.paramsList.map((q) => ['List', q[0], wj(q[1]), q[2], q[3]])
    .concat(R.rest.paramsComprehensive.map((q) => ['List Comprehensive', q[0], wj(q[1]), q[2], q[3]])),
  [18, 21, 22, 8, 31], { mono: [4] }));

kids.push(h1('5. What the Qualys API itself allows'));
kids.push(body('The ServiceNow side is only half the picture. The endpoint has its own rules, and they close off the idea ' +
  'of a long id list on this particular call.'));
kids.push(table(
  ['Parameter or behaviour', 'What Qualys documents'],
  [
    ['policy_id', 'One policy per request. A valid policy ID is required, and policy_id and policy_ids cannot appear in the same request.'],
    ['policy_ids', 'Up to 10 policies, comma separated. When it is used, all posture data is downloaded and truncation_limit becomes invalid.'],
    ['truncation_limit', 'Valid only for a single policy request with policy_id. Default 5,000 records; you may set 1 to 4,999 or 5,001 to 1,000,000.'],
    ['Paging', 'When more records exist than the limit, the response carries a WARNING element holding the URL for the next batch.'],
    ['ids, on the Policy List call', 'One or more policy IDs or ranges, comma separated, a range written with a hyphen such as 160-165. A maximum of 1,000 policy records is processed per request.'],
    ['GET against POST', 'Qualys states there are known, toolkit dependent limits on how much data GET can carry, and no fundamental limit on POST.'],
  ], [26, 74]));
kids.push(spacer(60));
kids.push(body('Two practical consequences. A long id list has no route into the Posture Info call at all, because the ' +
  'parameter that accepts several policies caps at ten and switches paging off. And the place an id list does belong, ' +
  'the Policy List call, is where the character budget question actually applies.'));

kids.push(h1('6. Readings taken on the instance'));
kids.push(body('Four checks were run to see how the limits behave in practice rather than on paper.'));
kids.push(table(['Check', 'Result', 'What it means'],
  R.readings.map((r) => [r[0], r[1], r[2]]), [30, 26, 44]));
kids.push(spacer(60));
kids.push(body('The third row matches what ServiceNow says elsewhere: the platform does not enforce max length on save, ' +
  'and the database may map a declared length to a wider column type. Treat the declared figure as the supported ' +
  'ceiling anyway, because the form applies it and a future column change could bring it back into force.'));

kids.push(h1('7. One request per policy'));
kids.push(body('The script builds the list of policies to pull, takes the first, and puts the rest back on the queue. A ' +
  'run therefore makes one request per policy and pages through that policy before moving on.'));
kids.push(...code(R.policyLoop));
kids.push(body('The number of requests in a run is the count of active, non-deprecated Qualys policies carrying a numeric ' +
  'source id. Reducing that set is the lever that lowers call volume; lengthening any single request is not, since the ' +
  'endpoint takes one policy at a time by construction.'));

kids.push(h1('8. Where my earlier answer needs correcting'));
kids.push(body('Four points from an earlier informal answer changed once the records and the vendor documentation were ' +
  'opened. They are listed here so the story comment carries the corrected version rather than the first one.'));
kids.push(table(['Said earlier', 'What the records and the documentation show'],
  [
    ['The 1,000 character limit sits on sys_rest_message_fn_parameters.',
     'That table is Variable Substitutions and holds a test value. HTTP Query Parameters is sys_rest_message_fn_param_defs. Both fields are 1,000, so the number was right and the table name was not.'],
    ['The page size in force is 1,000, the Qualys default.',
     'Wrong on both halves. Qualys documents 5,000 as the Posture Info default, and ServiceNow sets truncation_limit_pc_result to 5,000. The 1,000 figure belongs to the Host List call, a different endpoint.'],
    ['A value longer than the field is truncated on save.',
     'Writes of 1,200 and 2,000 characters were kept in full when made by script, and ServiceNow states that max length is not enforced by the client or the server.'],
    ['Ten policy ids per request, from recollection, to be confirmed.',
     'Now confirmed in two Qualys sources. Worth adding that using policy_ids turns truncation_limit off and downloads all posture data.'],
  ], [33, 67]));

kids.push(h1('9. If a longer list is ever needed'));
kids.push(bullet('Keep it out of the stored fields. A value passed at run time with setStringParameter() is held in no column, so only the request URL bounds it.'));
kids.push(bullet('Budget against the query string, not the ServiceNow field. The tightest common default is 2,048 bytes of query string on IIS; Apache allows 8,190 for the whole request line; the standard recommends supporting at least 8,000 octets. Around 2,000 characters is the conservative planning figure against an unknown server.'));
kids.push(bullet('Use POST if the list has to be long. Qualys states GET has toolkit dependent limits and POST does not.'));
kids.push(bullet('Prefer trimming the policy set. The integration already loops one policy at a time, so a shorter active policy list reduces the work more reliably than any single longer request.'));
kids.push(bullet('If the list must be configuration, a system property gives 4,000 characters against 512 for an integration parameter, at the cost of a script change to read it.'));

// ---------------------------------------------------------------- references
kids.push(h1('10. References'));
if (CITES.groups && CITES.groups.length) {
  CITES.groups.forEach((g) => {
    kids.push(h2(g.title));
    g.items.forEach((it) => {
      kids.push(new Paragraph({
        children: [t(it.claim, { size: 19, bold: true })],
        spacing: { before: 120, after: 40, line: 250 }, keepNext: true,
      }));
      if (it.quote) {
        kids.push(new Paragraph({
          children: [t('“' + it.quote + '”', { size: 18, italics: true, color: MUTED })],
          spacing: { after: 40, line: 240 }, indent: { left: 240 },
        }));
      }
      kids.push(new Paragraph({
        children: [t(it.title + ' — ', { size: 18, color: MUTED }), link(it.url)],
        spacing: { after: 100, line: 240 }, indent: { left: 240 },
      }));
    });
  });
} else {
  kids.push(body('No published sources attached.'));
}

kids.push(h2('Readings taken on the instance'));
kids.push(body('Paths are relative so they open on whichever instance you are signed in to. Versions in place when the ' +
  'readings were taken:', { size: 19, color: MUTED }));
kids.push(table(['Application', 'Scope', 'Version'],
  R.versions.map((v) => [v[0], v[1], v[2]]), [50, 28, 22], { mono: [1] }));
kids.push(spacer(80));
kids.push(table(['Record', 'What it shows', 'Path'],
  [
    ['REST message ' + R.rest.message[0], 'Endpoint ' + R.rest.message[2], rec('sys_rest_message', R.rest.message[1])],
    ['Method List', 'The query parameters that carry the substitutions', rec('sys_rest_message_fn', R.rest.methods[0][1])],
    ['Method List Comprehensive', 'The same call with a literal page size', rec('sys_rest_message_fn', R.rest.methods[1][1])],
    ['Script include QualysPCResultsIntegration', 'The setStringParameter calls and the policy loop', rec('sys_script_include', R.scripts[0][1])],
    ['Script include Implementation (sn_sec_int)', 'getConfiguration, which builds the config object', rec('sys_script_include', R.scripts[1][1])],
    ['Integration instance Qualys', 'The instance whose parameters are read at run time', rec('sn_sec_int_impl', 'cd94a86493660754e3aef0aefaba10db')],
  ], [30, 40, 30], { mono: [2] }));

kids.push(h2('Reproducing the readings'));
kids.push(body('Run as a background script to reproduce the length figures in section 3 and section 4.', { size: 19, color: MUTED }));
kids.push(...code([
  "var want = [['sys_rest_message_fn_param_defs','value'], ['sn_sec_int_impl_config','value'],",
  "            ['sys_rest_message_fn','rest_endpoint'], ['sys_properties','value']];",
  'for (var i = 0; i < want.length; i++) {',
  "    var d = new GlideRecord('sys_dictionary');",
  "    d.addQuery('name', want[i][0]); d.addQuery('element', want[i][1]); d.query();",
  '    if (d.next())',
  "        gs.info(want[i][0] + '.' + want[i][1] + ' max_length ' + d.getValue('max_length'));",
  '}',
  '',
  "var c = new GlideRecord('sn_sec_int_impl_config');",
  "c.addQuery('configuration.name', 'truncation_limit_pc_result');",
  'c.query();',
  "while (c.next()) gs.info('page size in force: ' + c.getValue('value'));",
]));

const doc = new Document({
  creator: 'Mihir Kumar Singh',
  lastModifiedBy: 'Mihir Kumar Singh',
  title: 'Qualys Policy Compliance integration - parameter length and paging limits',
  description: 'Supporting note on outbound REST parameter length limits and the Posture Info page size.',
  styles: { default: { document: { run: { font: FONT, size: 20, color: INK } } } },
  sections: [{
    properties: { page: { margin: { top: 1000, bottom: 1000, left: 1000, right: 1000 } } },
    children: kids,
  }],
});

const out = path.join(__dirname, '..', 'Qualys PC Integration - Parameter Limits.docx');
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(out, b); console.log('written:', out, b.length, 'bytes'); });
