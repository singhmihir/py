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
# ---------- script include 1 ----------
d = ui.js(r'''
var o = {};
function rec(table, number) { var g = new GlideRecord(table); g.addQuery('number', number); g.query(); g.next(); return g; }
var b = new RemediationTaskPayloadBuilder();
var vul = rec('sn_vul_vulnerability', 'VUL0004576');
o.vul_payload = b.buildPayload(vul);
o.vul_update = b.buildPayload(vul, 'update');
o.vul_facts = {opened_at: '' + vul.getValue('opened_at'), state: '' + vul.getDisplayValue('state'), opened_by: '' + vul.getDisplayValue('opened_by'), sys_id: vul.getUniqueValue(), resolution_date: '' + vul.getValue('resolution_date'), risk_score: '' + vul.getValue('risk_score')};
var avul = rec('sn_vul_app_vulnerability', 'AVUL0010008');
o.avul_payload = b.buildPayload(avul);
o.avul_facts = {sys_id: avul.getUniqueValue(), number: '' + avul.number};
o.base_url = '' + gs.getProperty('glide.servlet.uri');
var before = new GlideAggregate('syslog'); before.addQuery('message', 'STARTSWITH', 'RemediationTaskPayloadBuilder: payload not built'); before.addAggregate('COUNT'); before.query(); before.next();
var errs_before = parseInt(before.getAggregate('COUNT'));
var unqueried = new GlideRecord('sn_vul_vulnerability');
o.neg = [b.buildPayload(null), b.buildPayload({}), b.buildPayload('VUL0004576'), b.buildPayload(unqueried)];
var after = new GlideAggregate('syslog'); after.addQuery('message', 'STARTSWITH', 'RemediationTaskPayloadBuilder: payload not built'); after.addAggregate('COUNT'); after.query(); after.next();
o.neg_errors = parseInt(after.getAggregate('COUNT')) - errs_before;
gs.print('X::' + JSON.stringify(o));''')
p = json.loads(d['vul_payload']); f = d['vul_facts']
env, task = p['envelope'], p['rem_tasks'][0]['remediation_task']
check('S1-1 payload parses with envelope + rem_tasks', set(p.keys()) == {'envelope', 'rem_tasks'} and len(p['rem_tasks']) == 1)
check('S1-2 envelope constants', env['type'] == 'record' and env['topic_name'] == 'sn_usem_remtask_outbound' and env['namespace'] == 'com.bofa.usem' and env['core_version'] == '1.0.0' and env['outbound_version'] == '1.0.0' and env['element_count'] == 1 and env['element_activity'] == 'INSERT')
check('S1-3 event_id is a UUID, timestamp ISO-8601 UTC', bool(UUID.match(env['event_id'])) and bool(TS.match(env['event_timestamp'])), env['event_id'] + ' ' + env['event_timestamp'])
check('S1-4 activity argument normalised', json.loads(d['vul_update'])['envelope']['element_activity'] == 'UPDATE')
order = ['assigned_to','assignment_type','closed_at','closed_by','defer_extend_count','number','opened_at','opened_by','reassignment_count','resolution_date','resolved_by','risk_score','short_description','state','status_updated_on','sys_created_by','sys_created_on','sys_updated_by','sys_updated_on','total_cis','ttr_status','ttr_target_date','defer_count','total_vis','u_avul_record_url','u_verification_status']
keys = list(task.keys())
check('S1-5 keys are a subset of the agreed list, in order', all(k in order for k in keys) and keys == [k for k in order if k in keys], str(keys))
check('S1-6 all values are strings', all(isinstance(v, str) for v in task.values()))
y, m, dd = f['opened_at'][:10].split('-'); manual = '%s-%s-%s %s' % (m, dd, y, f['opened_at'][11:])
check('S1-7 date-times formatted MM-dd-yyyy HH:mm:ss from the UTC value', task['opened_at'] == manual and all(DT.match(task[k]) for k in ['opened_at','sys_created_on','sys_updated_on'] if k in task), task.get('opened_at') + ' vs ' + manual)
check('S1-8 date-only field formatted MM-dd-yyyy or absent', ('resolution_date' not in task) or bool(D.match(task['resolution_date'])), task.get('resolution_date', '(absent)'))
check('S1-9 choice/reference fields carry display values', task['state'] == f['state'] and task.get('opened_by', f['opened_by']) == f['opened_by'], task['state'])
check('S1-10 record url built from instance property', task['u_avul_record_url'] == d['base_url'].rstrip('/') + '/now/vr-analysis/record/sn_vul_vulnerability/' + f['sys_id'])
check('S1-11 empty and missing fields omitted', 'u_verification_status' not in task and ('resolution_date' in task) == bool(f['resolution_date']))
check('S1-12 number kept as raw value', task['number'] == 'VUL0004576' and task['risk_score'] == f['risk_score'])
pa = json.loads(d['avul_payload'])['rem_tasks'][0]['remediation_task']
check('S1-13 application remediation task works the same way', pa['number'] == 'AVUL0010008' and 'sn_vul_app_vulnerability/' + d['avul_facts']['sys_id'] in pa['u_avul_record_url'])
check('S1-14 invalid inputs return empty string, one error each', d['neg'] == ['', '', '', ''] and d['neg_errors'] == 4, str(d['neg']) + ' errors=' + str(d['neg_errors']))
# ---------- script include 2 ----------
d2 = ui.js(r'''
var o = {payloads: {}, facts: {}};
function rec(table, number) { var g = new GlideRecord(table); g.addQuery('number', number); g.query(); g.next(); return g; }
var b = new CdpRemediationTaskPayloadBuilder();
var recs = {sn_vul_vulnerability: 'VUL0004576', sn_vul_app_vulnerability: 'AVUL0010008', sn_vul_container_vulnerability: 'CVUL0010001', sn_vulc_result_group: 'CRG0001133'};
for (var t in recs) {
    var g = rec(t, recs[t]);
    o.payloads[t] = b.buildPayload(g, 'UPDATE');
    o.facts[t] = {state: '' + g.getDisplayValue('state'), cls: '' + g.getDisplayValue('sys_class_name'), group: '' + g.getDisplayValue('assignment_group'), active: '' + g.getValue('active'), sys_id: g.getUniqueValue(), created_on: '' + g.getValue('sys_created_on'), knowledge: '' + g.getValue('knowledge')};
}
o.common_count = b.COMMON_FIELDS.length; o.specific = {}; for (var k in b.TABLES) o.specific[k] = b.TABLES[k].fields.length;
var exc = rec('sn_vul_vulnerability', 'VUL0010547'); o.exc_payload = b.buildPayload(exc);
var before = new GlideAggregate('syslog'); before.addQuery('message', 'STARTSWITH', 'RemediationTaskPayloadBuilder: payload not built'); before.addAggregate('COUNT'); before.query(); before.next();
var e0 = parseInt(before.getAggregate('COUNT'));
var inc = new GlideRecord('incident'); inc.setLimit(1); inc.query(); inc.next();
o.unsupported = b.buildPayload(inc);
o.neg = [b.buildPayload(null), b.buildPayload(new GlideRecord('sn_vul_vulnerability'))];
var after = new GlideAggregate('syslog'); after.addQuery('message', 'STARTSWITH', 'RemediationTaskPayloadBuilder: payload not built'); after.addAggregate('COUNT'); after.query(); after.next();
o.neg_errors = parseInt(after.getAggregate('COUNT')) - e0;
var t0 = new Date().getTime(); var n = 0;
var many = new GlideRecord('sn_vul_vulnerability'); many.setLimit(50); many.query();
while (many.next()) { if (b.buildPayload(many)) n++; }
o.perf = {built: n, ms: new Date().getTime() - t0};
gs.print('X::' + JSON.stringify(o));''')
common = 78; spec = {'sn_vul_vulnerability': 27, 'sn_vul_app_vulnerability': 25, 'sn_vul_container_vulnerability': 19, 'sn_vulc_result_group': 16}
check('S2-0 mapping loaded from the sheet (78 common + table specific)', d2['common_count'] == common and d2['specific'] == spec, str(d2['specific']))
for t, n in spec.items():
    p = json.loads(d2['payloads'][t]); task = p['rem_tasks'][0]['remediation_task']; f = d2['facts'][t]
    check('S2-1 %s: every mapped key present (%d)' % (t, common + n + 2), len(task) == common + n + 2 and 'change_requests' in task and 'exception_requests' in task, str(len(task)))
    check('S2-2 %s: all values strings' % t, all(isinstance(v, str) for v in task.values()))
    check('S2-3 %s: state label, class label, activity UPDATE' % t, task['state'] == f['state'] and task['class_name'] == f['cls'] and p['envelope']['element_activity'] == 'UPDATE', task['state'] + ' / ' + task['class_name'])
    check('S2-4 %s: created_on formatted, sys_id raw, assignment_group display' % t, bool(DT.match(task['created_on'])) and task['sys_id'] == f['sys_id'] and task['assignment_group'] == f['group'], task['created_on'])
    check('S2-5 %s: boolean rendered true/false' % t, task['knowledge'] in ('true', 'false'), task['knowledge'])
missing_cc = json.loads(d2['payloads']['sn_vulc_result_group'])['rem_tasks'][0]['remediation_task']
check('S2-6 fields missing on a table yield empty strings (CC has no risk_score/total_cis)', missing_cc['risk_score'] == '' and missing_cc['total_cis'] == '' and missing_cc['u_confidential'] == '')
vul = json.loads(d2['payloads']['sn_vul_vulnerability'])['rem_tasks'][0]['remediation_task']
check('S2-7 change_requests from the association table', vul['change_requests'] == 'CHG0003510', vul['change_requests'])
exc = json.loads(d2['exc_payload'])['rem_tasks'][0]['remediation_task']
check('S2-8 exception_requests lists approved/expired exception approvals', 'VCA0010007' in exc['exception_requests'].split(','), exc['exception_requests'])
check('S2-9 unsupported table and invalid inputs return empty, one error each', d2['unsupported'] == '' and d2['neg'] == ['', ''] and d2['neg_errors'] == 3, 'errors=' + str(d2['neg_errors']))
check('S2-10 50 payloads built', d2['perf']['built'] == 50, '%d ms for 50 records' % d2['perf']['ms'])
print('---'); print('RESULT:', 'ALL PASS' if not FAILS else 'FAILURES: ' + ', '.join(FAILS))
open(BASE + '/stories/1625-cdp-remediation-task-payload/sample_out_vul.json', 'w').write(json.dumps(json.loads(d2['payloads']['sn_vul_vulnerability']), indent=2))
open(BASE + '/stories/1625-cdp-remediation-task-payload/sample_out_si1.json', 'w').write(json.dumps(json.loads(d['vul_payload']), indent=2))
