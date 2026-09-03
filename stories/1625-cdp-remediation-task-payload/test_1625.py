import os, sys, json, re
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
ui = SNUI()
ui.app('global')
FAILS = []
def check(label, cond, detail=''):
    print(('PASS ' if cond else 'FAIL ') + label + (' | ' + detail if detail else ''))
    if not cond: FAILS.append(label)
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
DT = re.compile(r'^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}$')
D = re.compile(r'^\d{2}-\d{2}-\d{4}$')
ERR = re.compile(r'^(RemediationTaskPayloadBuilder|CdpRemediationTaskPayloadBuilder): payload not built( for [a-z_]+ [0-9a-f]{32})? - .+$')
def errors_since(marker_count):
    return ui.js('''
var o = {msgs: []};
var l = new GlideRecord('syslog'); l.addQuery('message', 'STARTSWITH', 'RemediationTaskPayloadBuilder: payload not built').addOrCondition('message', 'STARTSWITH', 'CdpRemediationTaskPayloadBuilder: payload not built'); l.orderByDesc('sys_created_on'); l.setLimit(%d); l.query();
while (l.next()) o.msgs.push('' + l.getValue('message'));
gs.print('X::' + JSON.stringify(o));''' % marker_count)['msgs']

# ---------- script include 1 ----------
d = ui.js(r'''
var o = {};
function rec(table, number) { var g = new GlideRecord(table); g.addQuery('number', number); g.query(); g.next(); return g; }
var b = new RemediationTaskPayloadBuilder();
var vul = rec('sn_vul_vulnerability', 'VUL0004576');
o.vul_payload = b.buildPayload(vul);
o.vul_facts = {opened_at: '' + vul.getValue('opened_at'), state: '' + vul.getDisplayValue('state'), opened_by: '' + vul.getDisplayValue('opened_by'),
    ttr_status: '' + vul.getDisplayValue('ttr_status'), ttr_raw: '' + vul.getValue('ttr_status'), sys_id: vul.getUniqueValue(),
    resolution_date: '' + vul.getValue('resolution_date'), risk_score: '' + vul.getValue('risk_score'), mod_count: '' + vul.getValue('sys_mod_count')};
var fresh = new GlideRecord('sn_vul_vulnerability'); fresh.initialize(); fresh.setValue('short_description', 'VSO-PAYLOAD fresh record'); fresh.setWorkflow(false); var freshId = fresh.insert();
var fresh2 = new GlideRecord('sn_vul_vulnerability'); fresh2.get(freshId);
o.fresh_payload = b.buildPayload(fresh2); o.fresh_mod = '' + fresh2.getValue('sys_mod_count'); o.fresh_id = '' + freshId;
var avul = rec('sn_vul_app_vulnerability', 'AVUL0010008');
o.avul_payload = b.buildPayload(avul); o.avul_id = avul.getUniqueValue();
o.base_url = '' + gs.getProperty('glide.servlet.uri');
var unqueried = new GlideRecord('sn_vul_vulnerability');
o.neg = [b.buildPayload(null), b.buildPayload({}), b.buildPayload('VUL0004576'), b.buildPayload(unqueried)];
gs.print('X::' + JSON.stringify(o));''')
p = json.loads(d['vul_payload']); f = d['vul_facts']; env, task = p['envelope'], p['rem_tasks'][0]['remediation_task']
check('S1-1 payload parses with envelope + rem_tasks', set(p.keys()) == {'envelope', 'rem_tasks'} and len(p['rem_tasks']) == 1)
check('S1-2 envelope constants', env['type'] == 'record' and env['topic_name'] == 'sn_usem_remtask_outbound' and env['namespace'] == 'com.bofa.usem' and env['core_version'] == '1.0.0' and env['outbound_version'] == '1.0.0' and env['element_count'] == 1)
check('S1-3 event_id is a UUID, timestamp ISO-8601 UTC', bool(UUID.match(env['event_id'])) and bool(TS.match(env['event_timestamp'])))
check('S1-4 activity derived: updated record -> UPDATE, never-updated record -> INSERT', env['element_activity'] == 'UPDATE' and int(f['mod_count']) > 0 and json.loads(d['fresh_payload'])['envelope']['element_activity'] == 'INSERT' and d['fresh_mod'] == '0', 'mod_count=%s fresh_mod=%s' % (f['mod_count'], d['fresh_mod']))
order = ['assigned_to','assignment_type','closed_at','closed_by','defer_extend_count','number','opened_at','opened_by','reassignment_count','resolution_date','resolved_by','risk_score','short_description','state','status_updated_on','sys_created_by','sys_created_on','sys_updated_by','sys_updated_on','total_cis','ttr_status','ttr_target_date','defer_count','total_vis','u_verification_status','u_avul_record_url']
keys = list(task.keys())
check('S1-5 keys are a subset of the agreed list, in order, url last', all(k in order for k in keys) and keys == [k for k in order if k in keys] and keys[-1] == 'u_avul_record_url', str(keys))
check('S1-6 all values are strings', all(isinstance(v, str) for v in task.values()))
y, m, dd = f['opened_at'][:10].split('-'); manual = '%s-%s-%s %s' % (m, dd, y, f['opened_at'][11:])
check('S1-7 date-times formatted MM-dd-yyyy HH:mm:ss from the UTC value', task['opened_at'] == manual and all(DT.match(task[k]) for k in ['opened_at','sys_created_on','sys_updated_on'] if k in task), task.get('opened_at') + ' vs ' + manual)
check('S1-8 date-only field formatted MM-dd-yyyy or absent', ('resolution_date' not in task) or bool(D.match(task['resolution_date'])))
check('S1-9 type-driven rendering: choice integer, reference and choice string as display values', task['state'] == f['state'] and task.get('opened_by', f['opened_by']) == f['opened_by'] and task.get('ttr_status', f['ttr_status']) == f['ttr_status'], 'ttr_status %s (raw %s)' % (task.get('ttr_status'), f['ttr_raw']))
check('S1-10 record url built from instance property', task['u_avul_record_url'] == d['base_url'].rstrip('/') + '/now/vr-analysis/record/sn_vul_vulnerability/' + f['sys_id'])
check('S1-11 empty and missing fields omitted', 'u_verification_status' not in task and ('resolution_date' in task) == bool(f['resolution_date']))
check('S1-12 number and risk score raw', task['number'] == 'VUL0004576' and task['risk_score'] == f['risk_score'])
pa = json.loads(d['avul_payload'])['rem_tasks'][0]['remediation_task']
check('S1-13 application remediation task works the same way', pa['number'] == 'AVUL0010008' and 'sn_vul_app_vulnerability/' + d['avul_id'] in pa['u_avul_record_url'])
msgs = errors_since(4)
check('S1-14 invalid inputs return empty string with one error each in the single format', d['neg'] == ['', '', '', ''] and len(msgs) == 4 and all(ERR.match(x) for x in msgs) and all(x == 'RemediationTaskPayloadBuilder: payload not built - record is not a valid GlideRecord' for x in msgs), msgs[0] if msgs else '')

# ---------- script include 2 ----------
d2 = ui.js(r'''
var o = {payloads: {}, facts: {}};
function rec(table, number) { var g = new GlideRecord(table); g.addQuery('number', number); g.query(); g.next(); return g; }
var b = new CdpRemediationTaskPayloadBuilder();
var recs = {sn_vul_vulnerability: 'VUL0004576', sn_vul_app_vulnerability: 'AVUL0010008', sn_vul_container_vulnerability: 'CVUL0010001', sn_vulc_result_group: 'CRG0001133'};
for (var t in recs) {
    var g = rec(t, recs[t]);
    o.payloads[t] = b.buildPayload(g);
    o.facts[t] = {state: '' + g.getDisplayValue('state'), cls: '' + g.getDisplayValue('sys_class_name'), group: '' + g.getDisplayValue('assignment_group'), sys_id: g.getUniqueValue(), mod: '' + g.getValue('sys_mod_count'), knowledge: '' + g.getValue('knowledge'), ttr: '' + g.getDisplayValue('ttr_status')};
}
o.common_count = b.COMMON_FIELDS.length; o.specific = {}; for (var k in b.TABLES) o.specific[k] = b.TABLES[k].fields.length;
var exc = rec('sn_vul_vulnerability', 'VUL0010547'); o.exc_payload = b.buildPayload(exc);
var inc = new GlideRecord('incident'); inc.setLimit(1); inc.query(); inc.next(); o.inc_id = inc.getUniqueValue();
o.unsupported = b.buildPayload(inc);
o.neg = [b.buildPayload(null), b.buildPayload(new GlideRecord('sn_vul_vulnerability'))];
var t0 = new Date().getTime(); var n = 0;
var many = new GlideRecord('sn_vul_vulnerability'); many.setLimit(50); many.query();
while (many.next()) { if (b.buildPayload(many)) n++; }
o.perf = {built: n, ms: new Date().getTime() - t0};
gs.print('X::' + JSON.stringify(o));''')
common = 78; spec = {'sn_vul_vulnerability': 27, 'sn_vul_app_vulnerability': 25, 'sn_vul_container_vulnerability': 19, 'sn_vulc_result_group': 16}
check('S2-0 mapping loaded from the sheet (78 common + table specific)', d2['common_count'] == common and d2['specific'] == spec)
for t, n in spec.items():
    p = json.loads(d2['payloads'][t]); task = p['rem_tasks'][0]['remediation_task']; f = d2['facts'][t]
    check('S2-1 %s: every mapped key present (%d), all strings' % (t, common + n + 2), len(task) == common + n + 2 and all(isinstance(v, str) for v in task.values()))
    check('S2-2 %s: state/class/ttr labels, activity from mod count' % t, task['state'] == f['state'] and task['class_name'] == f['cls'] and task['ttr_status'] == f['ttr'] and p['envelope']['element_activity'] == ('UPDATE' if int(f['mod']) > 0 else 'INSERT'), task['state'] + ' / ' + task['class_name'] + ' / ' + p['envelope']['element_activity'])
    check('S2-3 %s: created_on formatted, sys_id raw, group display, boolean text' % t, bool(DT.match(task['created_on'])) and task['sys_id'] == f['sys_id'] and task['assignment_group'] == f['group'] and task['knowledge'] in ('true', 'false'))
cc = json.loads(d2['payloads']['sn_vulc_result_group'])['rem_tasks'][0]['remediation_task']
check('S2-4 fields missing on a table yield empty strings', cc['risk_score'] == '' and cc['total_cis'] == '' and cc['u_confidential'] == '')
vul = json.loads(d2['payloads']['sn_vul_vulnerability'])['rem_tasks'][0]['remediation_task']
check('S2-5 change_requests from the association table', vul['change_requests'] == 'CHG0003510', vul['change_requests'])
exc = json.loads(d2['exc_payload'])['rem_tasks'][0]['remediation_task']
check('S2-6 exception_requests lists approved/expired exception approvals', 'VCA0010007' in exc['exception_requests'].split(','), exc['exception_requests'])
msgs = errors_since(3)
expected_unsupported = 'CdpRemediationTaskPayloadBuilder: payload not built for incident %s - table incident is not a supported remediation task table' % d2['inc_id']
check('S2-7 unsupported table and invalid inputs: empty string, single error format', d2['unsupported'] == '' and d2['neg'] == ['', ''] and len(msgs) == 3 and all(ERR.match(x) for x in msgs) and expected_unsupported in msgs, ' || '.join(msgs))
check('S2-8 50 payloads built', d2['perf']['built'] == 50, '%d ms for 50 records' % d2['perf']['ms'])

# ---------- business rule context: activity from current.operation() ----------
d3 = ui.js(r'''
var probeResult = {};
new GlideUpdateSet().set('7dba58ecf54403100a22c0b3dfa151af');
var br = new GlideRecord('sys_script'); br.initialize();
br.setValue('name', 'ZZ payload probe'); br.setValue('collection', 'sn_vul_vulnerability'); br.setValue('when', 'after'); br.setValue('order', 5000);
br.setValue('action_insert', true); br.setValue('action_update', true); br.setValue('active', true); br.setValue('advanced', true);
br.setValue('script', "(function executeRule(current, previous) { var p1 = new RemediationTaskPayloadBuilder().buildPayload(current); var p2 = new CdpRemediationTaskPayloadBuilder().buildPayload(current); var a = p1 ? JSON.parse(p1).envelope.element_activity : 'EMPTY'; var b = p2 ? JSON.parse(p2).envelope.element_activity : 'EMPTY'; gs.info('PAYLOADPROBE ' + current.getUniqueValue() + ' ' + current.operation() + ' ' + a + ' ' + b); })(current, previous);");
probeResult.probe = '' + br.insert();
var g = new GlideRecord('sn_vul_vulnerability'); g.addQuery('number', 'VUL0004576'); g.query(); g.next();
g.setValue('description', 'payload probe ' + new GlideDateTime().getNumericValue()); g.update(); probeResult.updated = '' + g.getUniqueValue();
var n = new GlideRecord('sn_vul_vulnerability'); n.initialize(); n.setValue('short_description', 'VSO-PAYLOAD probe insert'); probeResult.inserted = '' + n.insert();
var lines = [];
var l = new GlideRecord('syslog'); l.addQuery('message', 'STARTSWITH', 'PAYLOADPROBE'); l.addQuery('sys_created_on', '>', gs.minutesAgoStart(2)); l.query();
while (l.next()) lines.push('' + l.getValue('message'));
probeResult.lines = lines;
var del = new GlideRecord('sys_script'); del.addQuery('name', 'ZZ payload probe'); del.query(); while (del.next()) del.deleteRecord();
var tidy = new GlideRecord('sn_vul_vulnerability'); tidy.addQuery('short_description', 'STARTSWITH', 'VSO-PAYLOAD'); tidy.query();
while (tidy.next()) { tidy.setValue('active', false); tidy.setValue('state', 3); tidy.setWorkflow(false); tidy.update(); }
gs.print('X::' + JSON.stringify(probeResult));''')
upd = [x for x in d3['lines'] if d3['updated'] in x]; ins = [x for x in d3['lines'] if d3['inserted'] in x]
check('S3-1 business rule on update: activity UPDATE from current.operation()', bool(upd) and upd[0].endswith(' update UPDATE UPDATE'), upd[0] if upd else 'no line')
check('S3-2 business rule on insert: activity INSERT from current.operation()', bool(ins) and ins[0].endswith(' insert INSERT INSERT'), ins[0] if ins else 'no line')
print('---'); print('RESULT:', 'ALL PASS' if not FAILS else 'FAILURES: ' + ', '.join(FAILS))
os.makedirs(os.path.join(BASE, 'stories', '1625-cdp-remediation-task-payload', 'samples'), exist_ok=True)
for name, payload in [('RemediationTaskPayloadBuilder', d['vul_payload']), ('CdpRemediationTaskPayloadBuilder', d2['payloads']['sn_vul_vulnerability'])]:
    txt = json.dumps(json.loads(payload), indent=2).replace(INST.split('//')[1], 'instance.example.com')
    open(os.path.join(BASE, 'stories', '1625-cdp-remediation-task-payload', 'samples', 'Sample payload - %s.json' % name), 'w').write(txt)
