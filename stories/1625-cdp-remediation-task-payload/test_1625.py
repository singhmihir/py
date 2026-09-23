"""Checks the remediation task payload builder (global reference) on the PDI. Every expected value is
worked out apart from the builder, through the REST API: the dictionary type of each mapped field, its
stored and display values, the latest journal entry, the change request links and the exception
approvals; the fixture tasks are also checked against literal values.
1. Payload per record: the twelve fixture tasks (no change, one change, several changes, on each of
   the four tables), the four sample records and the five latest tasks per table.
2. Property handling: the accepted layouts and every refusal, each with its one error line.
3. Business rule context: the operation, a save adding a comment, a save adding none, an insert.
4. Configuration: the properties equal the sheet rows, one script include, script hygiene; timing.
Run twice."""
import os, sys, json, re, html
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
ui = SNUI(); ui.app('global')
H = {'X-UserToken': ui.ck(), 'Accept': 'application/json'}
P = json.load(open(os.path.join(HERE, 'properties.json')))['properties']
ST = json.load(open(os.path.join(HERE, 'state.json'))); FX = json.load(open(os.path.join(HERE, 'fixtures.json')))
GLOBAL_DEFAULT = '7dba58ecf54403100a22c0b3dfa151af'
CLS = 'RemediationTaskPayloadBuilder'
TABLES = ['sn_vul_vulnerability', 'sn_vul_app_vulnerability', 'sn_vul_container_vulnerability', 'sn_vulc_result_group']
LINKS = {'sn_vul_vulnerability': ('sn_vul_m2m_vg_change_request', 'sn_vul_vulnerability'),
         'sn_vul_app_vulnerability': ('sn_vul_app_m2m_vg_change_request', 'sn_vul_app_vulnerability'),
         'sn_vul_container_vulnerability': ('sn_vul_container_m2m_remediation_task_change_request', 'sn_vul_container_vulnerability'),
         'sn_vulc_result_group': ('sn_vulc_m2m_trg_change_request', 'result_group')}
# sample records by sys_id: record numbers collide with the fixtures on this instance
RECS = {'sn_vul_vulnerability': 'ad21d45d13bc3300a23a7f176144b055', 'sn_vul_app_vulnerability': 'ff39e68bf9442110f877708ae9db0207',
        'sn_vul_container_vulnerability': '5f39668bf9442110f877708ae9db02ae', 'sn_vulc_result_group': '29be63ce93470310e3aef0aefaba109b'}
KINDS = ['bare', 'single', 'plural']
LABELS = {'sn_vul_vulnerability': 'Remediation Task', 'sn_vul_app_vulnerability': 'Application Remediation Task',
          'sn_vul_container_vulnerability': 'Container Remediation Task', 'sn_vulc_result_group': 'Remediation Task'}
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
DT = re.compile(r'^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}$')
MARKUP = re.compile(r'^\[code\]([\s\S]*)\[/code\]$')
FAILS = []; TOTAL = [0]
def check(label, cond, detail=''):
    TOTAL[0] += 1
    print(('PASS ' if cond else 'FAIL ') + label + (' | ' + str(detail)[:900] if detail and not cond else ''))
    if not cond: FAILS.append(label)

# ---------- the oracle: REST reads, Python rendering ----------
def rest(table, query, fields=None, display='false', limit=5000):
    params = {'sysparm_query': query, 'sysparm_display_value': display, 'sysparm_exclude_reference_link': 'true', 'sysparm_limit': limit}
    if fields: params['sysparm_fields'] = ','.join(fields)
    r = ui.s.get(INST + '/api/now/table/' + table, params=params, headers=H); r.raise_for_status()
    return r.json()['result']
DICT = {}
def dictionary(table):
    if table not in DICT:
        rows = rest('sys_dictionary', 'nameINtask,%s^elementISNOTEMPTY' % table, ['name', 'element', 'internal_type', 'choice'])
        out = {}
        for r in sorted(rows, key=lambda r: r['name'] == table):   # the table's own definition wins
            out[r['element']] = (r['internal_type'], r['choice'])
        DICT[table] = out
    return DICT[table]
def mapping(value):
    out = []
    for line in re.split(r'\r?\n|,', value):
        line = line.strip()
        if not line: continue
        parts = [x.strip() for x in line.split('=')]
        out.append((parts[0], parts[1] if len(parts) > 1 else parts[0]))
    return out
def plain(v):
    m = MARKUP.match(v)
    return html.unescape(re.sub(r'<[^>]*>', '', m.group(1)).replace('&nbsp;', ' ')).strip() if m else v
def latest_entry(sys_id, field):
    rows = rest('sys_journal_field', 'element_id=%s^element=%s^ORDERBYDESCsys_created_on' % (sys_id, field), ['value', 'sys_created_on'], limit=2)
    if not rows: return '', False
    return rows[0]['value'].strip(), len(rows) > 1 and rows[0]['sys_created_on'] == rows[1]['sys_created_on']
def expect(table, field, cells, sys_id):
    dic = dictionary(table)
    if field not in dic or field not in cells: return ''   # a dictionary row alone does not put a field on the table
    kind, choice = dic[field]
    if kind in ('journal_input', 'journal', 'journal_list'): return latest_entry(sys_id, field)[0]
    value, shown = cells[field]['value'] or '', cells[field]['display_value'] or ''
    if value == '': return ''
    if kind in ('glide_date_time', 'due_date'): return '%s-%s-%s %s' % (value[5:7], value[8:10], value[0:4], value[11:19])
    if kind == 'glide_date': return '%s-%s-%s' % (value[5:7], value[8:10], value[0:4])
    if kind in ('reference', 'document_id'): return '' if shown == value else shown
    if kind == 'integer': return shown if choice in ('1', '3') else value
    if kind in ('string', 'glide_list', 'boolean', 'glide_duration', 'timer', 'domain_id', 'sys_class_name', 'choice'): return plain(shown)
    return plain(value)
def expected_changes(table, sys_id):
    assoc, field = LINKS[table]
    ids = []
    for r in rest(assoc, '%s=%s' % (field, sys_id), ['change_request']):
        if r['change_request'] and r['change_request'] not in ids: ids.append(r['change_request'])
    if not ids: return ''
    return ','.join(sorted(c['number'] for c in rest('change_request', 'sys_idIN' + ','.join(ids), ['number', 'state']) if c['state'] != '4'))
def expected_exceptions(table, sys_id):
    return ','.join(sorted(x['number'] for x in rest('sn_sec_exception_change_approval', 'table=%s^record=%s^approval_stateIN1,4' % (table, sys_id), ['number'])))

# ---------- 1. one payload per record ----------
targets = []
for t in TABLES:
    for k in KINDS: targets.append((t, FX['ids'][t + '.' + k], k))
    targets.append((t, RECS[t], 'sample'))
d = ui.js(r'''
(function() {
var o = {rows: []}, targets = %s, have = {};
var b = new RemediationTaskPayloadBuilder();
for (var i = 0; i < targets.length; i++) {
    var g = new GlideRecord(targets[i][0]); g.get(targets[i][1]); have[targets[i][1]] = true;
    o.rows.push({table: targets[i][0], id: targets[i][1], kind: targets[i][2], payload: b.buildPayload(g), again: b.buildPayload(g)});
}
var tables = %s;
for (var t = 0; t < tables.length; t++) {
    var r = new GlideRecord(tables[t]); r.addQuery('short_description', 'NOT LIKE', 'VSO-PAYLOAD%%').addOrCondition('short_description', 'ISEMPTY'); r.addQuery('short_description', 'NOT LIKE', 'Payload fixture%%').addOrCondition('short_description', 'ISEMPTY'); r.orderByDesc('sys_updated_on'); r.setLimit(12); r.query(); var n = 0;
    while (r.next() && n < 5) {
        if (have[r.getUniqueValue()]) continue;
        n++; o.rows.push({table: tables[t], id: r.getUniqueValue(), kind: 'latest', payload: b.buildPayload(r), again: b.buildPayload(r)});
    }
}
gs.print('X::' + JSON.stringify(o));
})();''' % (json.dumps(targets), json.dumps(TABLES)))
LIVE = {r['name']: r['value'] for r in rest('sys_properties', 'nameSTARTSWITHusem.cdp.remtask.fields.', ['name', 'value'])}
PAYLOADS = {}
values_checked = 0
for row in d['rows']:
    t, sid, kind = row['table'], row['id'], row['kind']; tag = '%s %s %s' % (t, kind, sid[:8])
    check('1a %s: payload built' % tag, bool(row['payload']))
    if not row['payload']: continue
    p = json.loads(row['payload']); PAYLOADS[sid] = p
    env, task = p['envelope'], p['rem_tasks'][0]['remediation_task']
    cells = rest(t, 'sys_id=' + sid, display='all')[0]
    mapped = mapping(LIVE['usem.cdp.remtask.fields.' + t])
    check('1b %s: envelope' % tag, list(p.keys()) == ['envelope', 'rem_tasks'] and len(p['rem_tasks']) == 1 and list(p['rem_tasks'][0].keys()) == ['remediation_task']
          and env['type'] == 'record' and env['topic_name'] == 'sn_usem_remtask_outbound' and env['namespace'] == 'com.bofa.usem' and env['core_version'] == '1.0.0'
          and env['outbound_version'] == '1.0.0' and env['element_count'] == 1 and UUID.match(env['event_id']) and TS.match(env['event_timestamp'])
          and env['element_activity'] == ('UPDATE' if int(cells['sys_mod_count']['value']) > 0 else 'INSERT'), env)
    check('1c %s: exactly the property keys in property order, then the two derived keys' % tag, list(task.keys()) == [j for _, j in mapped] + ['change_requests', 'exception_requests'])
    bad = []
    for field, key in mapped:
        want = expect(t, field, cells, sid); values_checked += 1
        if not isinstance(task[key], str) or task[key] != want: bad.append('%s(%s): %r, expected %r' % (key, dictionary(t).get(field, ('missing',))[0], task[key], want))
    check('1d %s: every mapped value (%d) equal to the value worked out through REST' % (tag, len(mapped)), not bad, '; '.join(bad[:6]))
    stamps = [(key, cells[field]['value'], task[key]) for field, key in mapped if field in cells and re.match(r'^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$', cells[field]['value'] or '')]
    wrong_dates = [(k, v, got) for k, v, got in stamps if got != ('%s-%s-%s' % (v[5:7], v[8:10], v[0:4]) + (' ' + v[11:19] if len(v) > 10 else ''))]
    check('1d2 %s: every stored date or date/time (%d) sent as MM-dd-yyyy[ HH:mm:ss] in UTC, whatever its dictionary type' % (tag, len(stamps)), not wrong_dates and all(DT.match(g) or re.match(r'^\d{2}-\d{2}-\d{4}$', g) for _, _, g in stamps), wrong_dates[:4])
    check('1e %s: change_requests: each change once, cancelled and gone ones left out, number order' % tag, task['change_requests'] == expected_changes(t, sid), '%r vs %r' % (task['change_requests'], expected_changes(t, sid)))
    check('1f %s: exception_requests: approved and expired approvals of this record only' % tag, task['exception_requests'] == expected_exceptions(t, sid), '%r vs %r' % (task['exception_requests'], expected_exceptions(t, sid)))
    again = json.loads(row['again'])
    check('1g %s: a second build gives the same task and a new event id' % tag, again['rem_tasks'] == p['rem_tasks'] and again['envelope']['event_id'] != env['event_id'])
    if kind in KINDS:
        check('1h %s: change_requests literal %r' % (tag, FX['expected_change_requests'][t][kind]), task['change_requests'] == FX['expected_change_requests'][t][kind], task['change_requests'])
        check('1i %s: exception_requests literal %r' % (tag, FX['expected_exception_requests'][t][kind]), task['exception_requests'] == FX['expected_exception_requests'][t][kind], task['exception_requests'])
    if kind == 'plural':
        m = dict(mapped); inv = {v: k for k, v in m.items()}
        lit = {'state': 'Open', 'short_description': 'Payload fixture %s (several changes)' % t}
        if 'reassignment_count' in m: lit[m['reassignment_count']] = '1250'
        if 'comments' in m: lit[m['comments']] = 'Payload fixture comment two'
        if 'total_vis' in m and 'total_vis' in cells: lit[m['total_vis']] = '1250'
        if 'cr_count' in m and 'cr_count' in cells: lit[m['cr_count']] = '3'
        if 'sys_class_name' in m: lit[m['sys_class_name']] = LABELS[t]
        wrong = {k: task.get(k) for k, v in lit.items() if task.get(k) != v}
        check('1j %s: literals: latest comment on a record loaded afresh, counts as stored numbers, change count without markup, state label (%s)' % (tag, ', '.join(sorted(lit))), not wrong, wrong)
        tie = latest_entry(sid, 'comments')[1]
        check('1k %s: the fixture comments are a minute apart (no tie for the latest entry)' % tag, not tie)
check('1l %d records built, %d mapped values compared' % (len(PAYLOADS), values_checked), len(PAYLOADS) == len(d['rows']) and len(d['rows']) >= 16 + 4 * 3)
ivr = PAYLOADS[RECS['sn_vul_vulnerability']]['rem_tasks'][0]['remediation_task']
check('1m sample record: the change count held as markup on the instance is sent as its number', ivr['cr_count'] == '1', ivr['cr_count'])
cols = {t: set(rest(t, 'sys_id=' + RECS[t], display='all')[0]) for t in TABLES}
missing = {t: [j for f, j in mapping(LIVE['usem.cdp.remtask.fields.' + t]) if f not in cols[t]] for t in TABLES}
check('1n fields absent on this instance are sent as "" on every record (%s)' % '; '.join('%s: %s' % (t, ','.join(v)) for t, v in missing.items() if v),
      all(PAYLOADS[r['id']]['rem_tasks'][0]['remediation_task'][j] == '' for r in d['rows'] for j in missing[r['table']]))

# ---------- 2. property handling ----------
REC = RECS['sn_vul_vulnerability']; PROP = 'usem.cdp.remtask.fields.sn_vul_vulnerability'
CASES = {
    'layout': ' number = task_number ,\n short_description,\n\n bogus_field=bogus , assigned_to.name=owner_name ,\r\n sys_mod_count = updates ,\n state=status,',
    'two_equals': 'number=task_number,\nstate=a=b,',
    'no_field': 'number=task_number,\n=nothing,',
    'no_payload_name': 'number=task_number,\nrisk_score=,',
    'duplicate': 'state=status,\nsubstate=status,',
    'bare_duplicate': 'state,\nnumber,\nstate,',
    'derived': 'number=change_requests,',
    'derived_bare': 'exception_requests,',
    'separators': ' ,\n , \r\n,',
    'spaces': '   ',
    'blank': '',
}
REASONS = {
    'two_equals': 'property %s holds a line with more than one "=": "state=a=b"' % PROP,
    'no_field': 'property %s holds a line without a field name: "=nothing"' % PROP,
    'no_payload_name': 'property %s holds a line without a payload name: "risk_score="' % PROP,
    'duplicate': 'property %s names status twice' % PROP,
    'bare_duplicate': 'property %s names state twice' % PROP,
    'derived': 'property %s names change_requests, which the payload derives itself' % PROP,
    'derived_bare': 'property %s names exception_requests, which the payload derives itself' % PROP,
    'separators': 'property %s holds no field' % PROP,
    'spaces': 'property %s holds no field' % PROP,
    'blank': 'table sn_vul_vulnerability is not configured in property %s' % PROP,
}
d2 = ui.js(r'''
(function() {
var o = {cases: {}};
new GlideUpdateSet().set(%s);
var t0 = new GlideDateTime().getValue();
var name = %s, cases = %s;
var original = '' + gs.getProperty(name);
var g = new GlideRecord('sn_vul_vulnerability'); g.get(%s);
try {
    for (var k in cases) { gs.setProperty(name, cases[k]); o.cases[k] = new RemediationTaskPayloadBuilder().buildPayload(g); }
} finally {
    gs.setProperty(name, original);
}
o.restored = '' + gs.getProperty(name) === original;
o.mod = '' + g.getValue('sys_mod_count');
var b = new RemediationTaskPayloadBuilder();
var inc = new GlideRecord('incident'); inc.setLimit(1); inc.query(); inc.next(); o.inc_id = inc.getUniqueValue();
o.unsupported = b.buildPayload(inc);
var base = new GlideRecord('task'); base.get(%s); o.base = b.buildPayload(base);
o.neg = [b.buildPayload(null), b.buildPayload({}), b.buildPayload('VUL0004576'), b.buildPayload(new GlideRecord('sn_vul_vulnerability')), b.buildPayload()];
// a document id: the record field of an exception approval, mapped for the test only; its table field set, then empty
var dp = new GlideRecord('sys_properties'); dp.initialize(); dp.setValue('name', %s); dp.setValue('type', 'string'); dp.setValue('value', 'number=number,\ntable=table,\nrecord=record,'); var dpId = dp.insert();
var other = new GlideRecord('sn_sec_exception_change_approval'); other.get(%s); var keepTable = '' + other.getValue('table');
try {
    var linked = new GlideRecord('sn_sec_exception_change_approval'); linked.get(%s); o.doc_linked = new RemediationTaskPayloadBuilder().buildPayload(linked);
    other.setWorkflow(false); other.setValue('table', ''); other.update();
    var empty = new GlideRecord('sn_sec_exception_change_approval'); empty.get(%s); o.doc_empty = new RemediationTaskPayloadBuilder().buildPayload(empty);
} finally {
    var back = new GlideRecord('sn_sec_exception_change_approval'); back.get(%s); back.setWorkflow(false); back.setValue('table', keepTable); back.update();
    var gone = new GlideRecord('sys_properties'); if (gone.get(dpId)) gone.deleteRecord();
}
o.doc_restored = (function() { var c = new GlideRecord('sn_sec_exception_change_approval'); c.get(%s); return '' + c.getValue('table') == keepTable; })();
o.msgs = [];
var l = new GlideRecord('syslog'); l.addQuery('sys_created_on', '>=', t0); l.addQuery('message', 'STARTSWITH', 'RemediationTaskPayloadBuilder'); l.query();
while (l.next()) o.msgs.push('' + l.getValue('message'));
var ux = new GlideAggregate('sys_update_xml'); ux.addQuery('update_set', %s); ux.addAggregate('COUNT'); ux.query(); ux.next(); o.delivered_rows = parseInt(ux.getAggregate('COUNT'));
gs.print('X::' + JSON.stringify(o));
})();''' % (json.dumps(GLOBAL_DEFAULT), json.dumps(PROP), json.dumps(CASES), json.dumps(REC), json.dumps(REC), json.dumps('usem.cdp.remtask.fields.sn_sec_exception_change_approval'),
             json.dumps(FX['ids']['sn_vul_vulnerability.exc.other']), json.dumps(FX['ids']['sn_vul_vulnerability.exc.approved']), json.dumps(FX['ids']['sn_vul_vulnerability.exc.other']),
             json.dumps(FX['ids']['sn_vul_vulnerability.exc.other']), json.dumps(FX['ids']['sn_vul_vulnerability.exc.other']), json.dumps(ST['set'])))
layout = json.loads(d2['cases']['layout'])['rem_tasks'][0]['remediation_task']
check('2a accepted layout: spaces round names, bare name, blank line, CRLF, several pairs on one line, rename',
      list(layout.keys()) == ['task_number', 'short_description', 'bogus', 'owner_name', 'updates', 'status', 'change_requests', 'exception_requests']
      and layout['task_number'] == 'VUL0004576' and layout['updates'] == d2['mod'] and layout['status'] == ivr['state'] and layout['short_description'] == ivr['short_description'], layout)
check('2b a field the table does not have, and a dot-walk, are sent as ""', layout['bogus'] == '' and layout['owner_name'] == '')
check('2c every refused layout gives "" (%d cases)' % len(REASONS), all(d2['cases'][k] == '' for k in REASONS), {k: d2['cases'][k][:60] for k in REASONS if d2['cases'][k] != ''})
want = ['%s: payload not built for sn_vul_vulnerability %s - %s' % (CLS, REC, REASONS[k]) for k in REASONS]
want += ['%s: payload not built for incident %s - table incident is not configured in property usem.cdp.remtask.fields.incident' % (CLS, d2['inc_id']),
         '%s: payload not built for task %s - table task is not configured in property usem.cdp.remtask.fields.task' % (CLS, REC)]
want += ['%s: payload not built - record is not a valid GlideRecord' % CLS] * 4 + ['%s: payload not built for sn_vul_vulnerability - record is not a valid GlideRecord' % CLS]
check('2d exactly one error line per refusal, each naming the reason, nothing else logged (%d lines)' % len(want), sorted(d2['msgs']) == sorted(want),
      'extra: %s | missing: %s' % ([m for m in d2['msgs'] if m not in want], [m for m in want if m not in d2['msgs']]))
check('2e unsupported table, base task record and invalid inputs give ""', d2['unsupported'] == '' and d2['base'] == '' and d2['neg'] == [''] * 5)
check('2f property restored, delivered update set untouched (12 rows)', d2['restored'] and d2['delivered_rows'] == 12, d2['delivered_rows'])
dl, de = json.loads(d2['doc_linked'])['rem_tasks'][0]['remediation_task'], json.loads(d2['doc_empty'])['rem_tasks'][0]['remediation_task']
check('2g a document id renders the display value of its record, and "" when its table field is empty (the approval record restored)',
      dl['record'] == FX['tables']['sn_vul_vulnerability']['numbers']['plural'] and dl['table'] == 'sn_vul_vulnerability' and de['record'] == '' and de['table'] == '' and de['number'] == FX['tables']['sn_vul_vulnerability']['exceptions']['other']['number'] and d2['doc_restored'], (dl, de))

# ---------- 3. business rule context ----------
plural = FX['ids']['sn_vul_vulnerability.plural']
before = rest('sn_vul_vulnerability', 'sys_id=' + plural, ['reassignment_count', 'total_vis', 'cr_count', 'description'])[0]
latest_before = latest_entry(plural, 'comments')[0]
d3 = ui.js(r'''
(function() {
var o = {};
new GlideUpdateSet().set(%s);
var stamp = '' + new GlideDateTime().getNumericValue();
var br = new GlideRecord('sys_script'); br.initialize();
br.setValue('name', 'ZZ payload probe'); br.setValue('collection', 'sn_vul_vulnerability'); br.setValue('when', 'after'); br.setValue('order', 10000);
br.setValue('action_insert', true); br.setValue('action_update', true); br.setValue('active', true); br.setValue('advanced', true);
br.setValue('script', "(function executeRule(current, previous) { var p = new RemediationTaskPayloadBuilder().buildPayload(current); var t = p ? JSON.parse(p) : null; gs.info('PAYLOADPROBE ' + JSON.stringify({id: current.getUniqueValue(), step: '' + current.getValue('description'), op: current.operation(), activity: t ? t.envelope.element_activity : 'EMPTY', comments: t ? t.rem_tasks[0].remediation_task.comments : 'EMPTY', changes: t ? t.rem_tasks[0].remediation_task.change_requests : 'EMPTY'})); })(current, previous);");
br.insert();
var t0 = new GlideDateTime().getValue();
try {
    var g = new GlideRecord('sn_vul_vulnerability'); g.get(%s);
    g.setValue('description', 'Payload probe step a ' + stamp); g.update();
    g = new GlideRecord('sn_vul_vulnerability'); g.get(%s);
    o.comment = 'Payload probe comment ' + stamp; g.setValue('description', 'Payload probe step b ' + stamp); g.comments = o.comment; g.update();
    var n = new GlideRecord('sn_vul_vulnerability'); n.initialize(); n.setValue('short_description', 'VSO-PAYLOAD probe insert'); o.inserted = '' + n.insert();
    var c = new GlideRecord('sn_vul_vulnerability'); c.initialize(); c.setValue('short_description', 'VSO-PAYLOAD probe insert with comment'); o.insert_comment = 'Payload probe insert comment ' + stamp; c.comments = o.insert_comment; o.inserted_commented = '' + c.insert();
} finally {
    var del = new GlideRecord('sys_script'); del.addQuery('name', 'ZZ payload probe'); del.query(); while (del.next()) del.deleteRecord();
}
o.lines = [];
var l = new GlideRecord('syslog'); l.addQuery('message', 'STARTSWITH', 'PAYLOADPROBE'); l.addQuery('sys_created_on', '>=', t0); l.orderBy('sys_created_on'); l.query();
while (l.next()) o.lines.push(JSON.parse(('' + l.getValue('message')).substring(13)));
o.errors = [];
var e = new GlideRecord('syslog'); e.addQuery('message', 'STARTSWITH', 'RemediationTaskPayloadBuilder'); e.addQuery('sys_created_on', '>=', t0); e.query();
while (e.next()) o.errors.push('' + e.getValue('message'));
// tidy: probe comments and inserts out, the fixture counts back as the fixtures set them
var j = new GlideRecord('sys_journal_field'); j.addQuery('value', 'STARTSWITH', 'Payload probe'); j.query(); while (j.next()) j.deleteRecord();
var tidy = new GlideRecord('sn_vul_vulnerability'); tidy.addQuery('short_description', 'STARTSWITH', 'VSO-PAYLOAD'); tidy.query();
while (tidy.next()) { tidy.setValue('active', false); tidy.setValue('state', 3); tidy.setWorkflow(false); tidy.update(); }
var back = new GlideRecord('sn_vul_vulnerability'); back.get(%s); back.setWorkflow(false); var keep = %s;
for (var f in keep) back.setValue(f, keep[f]);
back.update();
gs.print('X::' + JSON.stringify(o));
})();''' % (json.dumps(GLOBAL_DEFAULT), json.dumps(plural), json.dumps(plural), json.dumps(plural), json.dumps(before)))
by = {}
for line in d3['lines']: by.setdefault(line['id'], []).append(line)
upd = sorted(by.get(plural, []), key=lambda line: line['step'])   # step a, then step b (one second may hold both lines)
check('3a a save that adds no comment: UPDATE, comments = the latest entry %r, all change requests' % latest_before,
      len(upd) == 2 and upd[0]['step'].startswith('Payload probe step a') and upd[0]['op'] == 'update' and upd[0]['activity'] == 'UPDATE' and upd[0]['comments'] == latest_before and upd[0]['changes'] == FX['expected_change_requests']['sn_vul_vulnerability']['plural'], upd[:1])
check('3b a save that adds a comment: comments = that comment', len(upd) == 2 and upd[1]['step'].startswith('Payload probe step b') and upd[1]['activity'] == 'UPDATE' and upd[1]['comments'] == d3['comment'], upd[1:2])
ins = by.get(d3['inserted'], [])
check('3c an insert: INSERT from the operation, comments ""', len(ins) == 1 and ins[0]['op'] == 'insert' and ins[0]['activity'] == 'INSERT' and ins[0]['comments'] == '' and ins[0]['changes'] == '', ins)
insc = by.get(d3['inserted_commented'], [])
check('3d an insert carrying a comment: comments = that comment', len(insc) == 1 and insc[0]['activity'] == 'INSERT' and insc[0]['comments'] == d3['insert_comment'], insc)
check('3e no builder error during the rule runs', not d3['errors'], d3['errors'])
after = rest('sn_vul_vulnerability', 'sys_id=' + plural, ['reassignment_count', 'total_vis', 'cr_count', 'description'])[0]
check('3f fixture counts and description restored after the rule runs', after == before, after)

# ---------- 4. configuration, hygiene, timing ----------
sheet = json.load(open(os.path.join(HERE, 'remtask_mapping.json')))
groups = {'sn_vul_app_vulnerability (App. VR)': 'sn_vul_app_vulnerability', 'sn_vul_container_vulnerability (CVR)': 'sn_vul_container_vulnerability', 'sn_vul_vulnerability (IVR)': 'sn_vul_vulnerability', 'sn_vulc_result_group(CC)': 'sn_vulc_result_group'}
common, seen = [], set(); specific = {v: [] for v in groups.values()}
for m in sheet:
    if m['required'].strip().lower() != 'yes' or not m['sn_field']: continue
    pair = (m['sn_field'], m['json'].strip().replace(' ', '_'))
    if m['table'].startswith('Common'):
        if pair not in seen: seen.add(pair); common.append(pair)
    elif m['table'] in groups: specific[groups[m['table']]].append(pair)
check('4a live properties equal the sheet rows with CDP Required = Yes, per table, and the delivered values', all(mapping(LIVE['usem.cdp.remtask.fields.' + t]) == common + specific[t] and LIVE['usem.cdp.remtask.fields.' + t] == P['usem.cdp.remtask.fields.' + t] for t in TABLES) and len(LIVE) == 4, sorted(LIVE))
check('4b every property line is field=json ending with a comma', all(all(line.endswith(',') and line.count('=') == 1 for line in v.split('\n')) for v in LIVE.values()))
d4 = ui.js(r'''
(function() {
var o = {};
var s = new GlideRecord('sys_script_include'); s.addQuery('name', 'IN', 'RemediationTaskPayloadBuilder,CdpRemediationTaskPayloadBuilder'); s.query(); o.builders = [];
while (s.next()) { o.builders.push('' + s.getValue('name')); o.script = '' + s.getValue('script'); }
var b = new RemediationTaskPayloadBuilder(); var t0 = new Date().getTime(); var n = 0;
var many = new GlideRecord('sn_vul_vulnerability'); many.setLimit(50); many.query(); while (many.next()) { if (b.buildPayload(many)) n++; }
o.perf = {built: n, ms: new Date().getTime() - t0};
gs.print('X::' + JSON.stringify(o));
})();''')
src = open(os.path.join(HERE, 'RemediationTaskPayloadBuilder.js')).read()
sc = d4['script']
check('4c one payload script include on the instance, its script equal to the repository copy', d4['builders'] == [CLS] and sc.rstrip('\n') == src.rstrip('\n'))
check('4d script hygiene: one try/catch, one gs.error, no gs.info/gs.warn, no field list in code, only scoped-safe descriptor calls',
      sc.count('try {') == 1 and sc.count('catch (') == 1 and sc.count('gs.error(') == 1 and 'gs.info' not in sc and 'gs.warn' not in sc and 'assigned_to' not in sc and 'getChoice(' not in sc and sc.count('getED()') == 1 and 'dictionary.getElement(field).getED()' in sc)
check('4e 50 payloads built', d4['perf']['built'] == 50, d4['perf'])
print('   timing: %d payloads in %d ms' % (d4['perf']['built'], d4['perf']['ms']))

print('\n%s: %d checks, %d failed%s' % ('ALL PASS' if not FAILS else 'FAILED', TOTAL[0], len(FAILS), '' if not FAILS else ' -> ' + '; '.join(FAILS)))
os.makedirs(os.path.join(HERE, 'samples'), exist_ok=True)
user = os.environ.get('SN_USER', '')
for t in (TABLES if not FAILS else []):   # samples only from a run where every check passed
    txt = json.dumps(PAYLOADS[RECS[t]], indent=2).replace(INST.split('//')[1], 'instance.example.com')
    if user: txt = txt.replace(user, 'admin')
    txt = txt.replace('Mihir Kumar Singh', 'System Administrator')
    assert not re.search(r'probe|fixture|VSO-', txt, re.I), 'test text in the sample of %s' % t
    open(os.path.join(HERE, 'samples', 'Sample payload - %s.json' % t), 'w').write(txt + '\n')
sys.exit(1 if FAILS else 0)
