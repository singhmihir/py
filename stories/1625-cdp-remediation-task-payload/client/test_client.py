"""Checks the client copy of the builder (stand-in scope, so the scoped script API applies as on the client
instance) against the global reference builder, whose values test_1625.py works out independently:
1. every record of the reference test - the twelve fixture tasks, the four sample records and the five
   latest tasks per table - gives the same task as the reference; the payload is an object; the
   activity follows the parameter and, without one, the record; literals on the plural fixtures;
2. property handling: the accepted layout and every refusal with its one error line, invalid inputs;
3. the deployed script equals the repository copy and keeps to scoped-safe calls.
A global script calling a scoped application from inside one of its functions hands over a record
whose dictionary descriptors the scope may not read; section 1 calls the builder that way.
Run twice, never together with test_1625.py (both change properties while they run)."""
import os, sys, json, re
HERE = os.path.dirname(os.path.abspath(__file__)); STORY = os.path.dirname(HERE); BASE = os.path.dirname(os.path.dirname(STORY))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ST = json.load(open(os.path.join(HERE, 'state.json'))); FX = json.load(open(os.path.join(STORY, 'fixtures.json')))
REF = json.load(open(os.path.join(STORY, 'properties.json')))['properties']
CLS = 'BOA_SI_USEM_RemediationTaskPayloadBuilder'; PREFIX = 'x_boar_bofa_usem_1.usem.cdp.remtask.fields.'
TABLES = ['sn_vul_vulnerability', 'sn_vul_app_vulnerability', 'sn_vul_container_vulnerability', 'sn_vulc_result_group']
RECS = {'sn_vul_vulnerability': 'ad21d45d13bc3300a23a7f176144b055', 'sn_vul_app_vulnerability': 'ff39e68bf9442110f877708ae9db0207',
        'sn_vul_container_vulnerability': '5f39668bf9442110f877708ae9db02ae', 'sn_vulc_result_group': '29be63ce93470310e3aef0aefaba109b'}
KINDS = ['bare', 'single', 'plural']
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'); TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
ui = SNUI(); ui.app('global'); FAILS = []; TOTAL = [0]
def check(label, cond, detail=''):
    TOTAL[0] += 1; print(('PASS ' if cond else 'FAIL ') + label + (' | ' + str(detail)[:900] if detail and not cond else ''))
    if not cond: FAILS.append(label)

# ---------- 1. the client copy against the reference ----------
targets = []
for t in TABLES:
    for k in KINDS: targets.append((t, FX['ids'][t + '.' + k], k))
    targets.append((t, RECS[t], 'sample'))
d = ui.js(r'''
(function() {
var o = {rows: [], props: {}}, targets = %s, have = {}, tables = %s;
var C = x_196061_bofasim.BOA_SI_USEM_RemediationTaskPayloadBuilder;
function one(table, g, kind) {
    var client = new C().buildPayload(g, 'UPDATE');
    o.rows.push({table: table, id: g.getUniqueValue(), kind: kind, mod: parseInt(g.getValue('sys_mod_count')), client_type: typeof client, client: JSON.stringify(client),
        insert: JSON.stringify(new C().buildPayload(g, 'insert')), none: JSON.stringify(new C().buildPayload(g)), reference: new RemediationTaskPayloadBuilder().buildPayload(g)});
}
for (var i = 0; i < targets.length; i++) { var g = new GlideRecord(targets[i][0]); g.get(targets[i][1]); have[targets[i][1]] = true; one(targets[i][0], g, targets[i][2]); }
for (var t = 0; t < tables.length; t++) {
    var r = new GlideRecord(tables[t]); r.orderByDesc('sys_updated_on'); r.setLimit(12); r.query(); var n = 0;
    while (r.next() && n < 5) { if (have[r.getUniqueValue()]) continue; n++; one(tables[t], r, 'latest'); }
}
// the same record handed over directly rather than from inside a function of this global script
var direct = new GlideRecord('sn_vul_vulnerability'); direct.get(targets[2][1]); o.direct = JSON.stringify(new C().buildPayload(direct, 'UPDATE'));
var p = new GlideRecord('sys_properties'); p.addQuery('name', 'STARTSWITH', 'x_boar_bofa_usem_1.usem.cdp.remtask.fields.'); p.query();
while (p.next()) o.props['' + p.getValue('name')] = '' + p.getValue('value');
gs.print('X::' + JSON.stringify(o));
})();''' % (json.dumps(targets), json.dumps(TABLES)))
files = {PREFIX + t: open(os.path.join(HERE, PREFIX + t + '.txt')).read().rstrip('\n') for t in TABLES}
check('1a the four client-named properties hold the reference values and equal the delivered files', sorted(d['props']) == sorted(files)
      and all(d['props'][PREFIX + t] == REF['usem.cdp.remtask.fields.' + t] == files[PREFIX + t] for t in TABLES))
for row in d['rows']:
    t, kind = row['table'], row['kind']; tag = '%s %s %s' % (t, kind, row['id'][:8])
    if row['client_type'] != 'object' or not row['reference']:
        check('1b %s: client payload is an object and the reference built' % tag, False, row['client'][:200]); continue
    c, ref, ins, none = json.loads(row['client']), json.loads(row['reference']), json.loads(row['insert']), json.loads(row['none'])
    ct, rt = c['rem_tasks'][0]['remediation_task'], ref['rem_tasks'][0]['remediation_task']
    diff = [k for k in list(ct) + list(rt) if ct.get(k) != rt.get(k)]
    check('1b %s: same keys in the same order and every value equal to the reference (%d keys)' % (tag, len(rt)), list(ct) == list(rt) and not diff,
          ', '.join('%s: %r vs %r' % (k, ct.get(k), rt.get(k)) for k in diff[:4]))
    e = c['envelope']
    check('1c %s: envelope, activity from the parameter, upper-cased' % tag, list(e) == list(ref['envelope']) and e['type'] == 'record' and e['topic_name'] == 'sn_usem_remtask_outbound'
          and e['namespace'] == 'com.bofa.usem' and e['core_version'] == '1.0.0' and e['outbound_version'] == '1.0.0' and e['element_count'] == 1
          and UUID.match(e['event_id']) and TS.match(e['event_timestamp']) and e['element_activity'] == 'UPDATE' and ins['envelope']['element_activity'] == 'INSERT' and ins['rem_tasks'] == c['rem_tasks'])
    check('1d %s: no parameter and no rule: activity from the record (%s)' % (tag, 'UPDATE' if row['mod'] > 0 else 'INSERT'), none['envelope']['element_activity'] == ('UPDATE' if row['mod'] > 0 else 'INSERT'))
    if kind == 'plural':
        want = {'change_requests': FX['expected_change_requests'][t]['plural'], 'exception_requests': FX['expected_exception_requests'][t]['plural'],
                'comments': 'Payload fixture comment two', 'reassignment_count': '1250', 'state': 'Open'}
        if 'cr_count' in ct and t != 'sn_vulc_result_group': want['cr_count'] = '3'
        wrong = {k: ct.get(k) for k, v in want.items() if ct.get(k) != v}
        check('1e %s: literals: change and exception numbers, latest comment, count as stored, change count without markup, state label' % tag, not wrong, wrong)
check('1f %d records compared, each handed over from inside a function of a global script' % len(d['rows']), len(d['rows']) == 36)
nested = [r for r in d['rows'] if r['id'] == targets[2][1]][0]
check('1g the same record handed over directly gives the same task (both call paths of a global caller)', json.loads(d['direct'])['rem_tasks'] == json.loads(nested['client'])['rem_tasks'])

# ---------- 2. property handling ----------
PROP = PREFIX + 'sn_vul_vulnerability'; REC = RECS['sn_vul_vulnerability']
CASES = {
    'layout': ' number = task_number ,\n short_description,\n\n bogus_field=bogus , assigned_to.name=owner_name ,\r\n sys_mod_count = updates ,\n state=status,',
    'two_equals': 'number=task_number,\nstate=a=b,',
    'no_field': 'number=task_number,\n=nothing,',
    'no_payload_name': 'number=task_number,\nrisk_score=,',
    'duplicate': 'state=status,\nsubstate=status,',
    'derived': 'number=change_requests,',
    'separators': ' ,\n , \r\n,',
    'blank': '',
}
REASONS = {
    'two_equals': 'property %s holds a line with more than one "=": "state=a=b"' % PROP,
    'no_field': 'property %s holds a line without a field name: "=nothing"' % PROP,
    'no_payload_name': 'property %s holds a line without a payload name: "risk_score="' % PROP,
    'duplicate': 'property %s names status twice' % PROP,
    'derived': 'property %s names change_requests, which the payload derives itself' % PROP,
    'separators': 'property %s holds no field' % PROP,
    'blank': 'table sn_vul_vulnerability is not configured in property %s' % PROP,
}
n = ui.js(r'''
(function() {
var o = {cases: {}};
new GlideUpdateSet().set(%s);
var t0 = new GlideDateTime().getValue();
var C = x_196061_bofasim.BOA_SI_USEM_RemediationTaskPayloadBuilder, cases = %s;
var p = new GlideRecord('sys_properties'); p.get(%s); var keep = '' + p.getValue('value');
var g = new GlideRecord('sn_vul_vulnerability'); g.get(%s);
try {
    for (var k in cases) { p.setValue('value', cases[k]); p.update(); var r = new C().buildPayload(g, 'UPDATE'); o.cases[k] = typeof r === 'string' ? r : JSON.stringify(r); }
} finally {
    p.setValue('value', keep); p.update();
}
o.restored = '' + gs.getProperty(%s) === keep;
o.mod = '' + g.getValue('sys_mod_count');
var b = new C();
var inc = new GlideRecord('incident'); inc.setLimit(1); inc.query(); inc.next(); o.inc_id = inc.getUniqueValue();
o.unsupported = b.buildPayload(inc, 'UPDATE');
o.neg = [b.buildPayload(null, 'UPDATE'), b.buildPayload({}, 'UPDATE'), b.buildPayload('VUL0004576', 'UPDATE'), b.buildPayload(new GlideRecord('sn_vul_vulnerability'), 'UPDATE')];
o.msgs = [];
var l = new GlideRecord('syslog'); l.addQuery('sys_created_on', '>=', t0); l.addQuery('message', 'STARTSWITH', 'BOA_SI_USEM_RemediationTaskPayloadBuilder'); l.query();
while (l.next()) o.msgs.push('' + l.getValue('message'));
var s = new GlideRecord('sys_script_include'); s.get(%s); o.script = '' + s.getValue('script'); o.api = '' + s.getValue('api_name');
gs.print('X::' + JSON.stringify(o));
})();''' % (json.dumps(ST['global_default']), json.dumps(CASES), json.dumps(ST['props'][PROP]), json.dumps(REC), json.dumps(PROP), json.dumps(ST['si'])))
layout = json.loads(n['cases']['layout'])['rem_tasks'][0]['remediation_task']
sample = [r for r in d['rows'] if r['id'] == REC][0]; sample_task = json.loads(sample['client'])['rem_tasks'][0]['remediation_task']
check('2a accepted layout: spaces round names, bare name, blank line, CRLF, several pairs on one line, rename, unknown and dot-walked fields as ""',
      list(layout) == ['task_number', 'short_description', 'bogus', 'owner_name', 'updates', 'status', 'change_requests', 'exception_requests']
      and layout['task_number'] == 'VUL0004576' and layout['updates'] == n['mod'] and layout['status'] == sample_task['state'] and layout['bogus'] == '' and layout['owner_name'] == '', layout)
check('2b every refused layout gives "" (%d cases)' % len(REASONS), all(n['cases'][k] == '' for k in REASONS), {k: n['cases'][k][:60] for k in REASONS if n['cases'][k] != ''})
want = ['%s: payload not built for sn_vul_vulnerability %s - %s' % (CLS, REC, REASONS[k]) for k in REASONS]
want += ['%s: payload not built for incident %s - table incident is not configured in property %sincident' % (CLS, n['inc_id'], PREFIX)]
want += ['%s: payload not built - record is not a valid GlideRecord' % CLS] * 4
check('2c exactly one error line per refusal, naming the client property, nothing else logged (%d lines)' % len(want), sorted(n['msgs']) == sorted(want),
      'extra: %s | missing: %s' % ([m for m in n['msgs'] if m not in want], [m for m in want if m not in n['msgs']]))
check('2d unsupported table and invalid inputs give "", property restored', n['unsupported'] == '' and n['neg'] == [''] * 4 and n['restored'])

# ---------- 3. the deployed script ----------
src = open(os.path.join(HERE, CLS + '.js')).read()
sc = n['script']
check('3a the deployed script equals the repository copy', sc.rstrip('\n') == src.rstrip('\n'))
check('3b one try/catch, one gs.error, no gs.info/gs.warn, the client property prefix, only scoped-safe descriptor calls, object returned',
      sc.count('try {') == 1 and sc.count('catch (') == 1 and sc.count('gs.error(') == 1 and 'gs.info' not in sc and 'gs.warn' not in sc
      and "this.FIELDS_PROPERTY_PREFIX = 'x_boar_bofa_usem_1.usem.cdp.remtask.fields.';" in sc and 'getChoice(' not in sc and sc.count('getED()') == 1 and 'dictionary.getElement(field).getED()' in sc and 'return payload;' in sc and 'JSON.stringify' not in sc)
ref_src = open(os.path.join(STORY, 'RemediationTaskPayloadBuilder.js')).read()
body = lambda s, a, b: s[s.index(a):s.index(b)]
check('3c the rendering, the mapping and the derived lists are the same code as the reference',
      all(body(sc, a, b) == body(ref_src, a, b) for a, b in [('    _buildRemediationTask:', '    type:')]))
print('\n%s: %d checks, %d failed%s' % ('ALL PASS' if not FAILS else 'FAILED', TOTAL[0], len(FAILS), '' if not FAILS else ' -> ' + '; '.join(FAILS)))
sys.exit(1 if FAILS else 0)
