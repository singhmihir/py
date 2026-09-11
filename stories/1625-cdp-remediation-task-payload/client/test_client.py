import os, sys, json, re
HERE = os.path.dirname(os.path.abspath(__file__)); STORY = os.path.dirname(HERE); BASE = os.path.dirname(os.path.dirname(STORY))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ST = json.load(open(os.path.join(HERE, 'state.json')))
TABLES = ['sn_vul_vulnerability', 'sn_vul_app_vulnerability', 'sn_vul_container_vulnerability', 'sn_vulc_result_group']
RECS = {'sn_vul_vulnerability': 'VUL0004576', 'sn_vul_app_vulnerability': 'AVUL0010008', 'sn_vul_container_vulnerability': 'CVUL0010001', 'sn_vulc_result_group': 'CRG0001133'}
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'); TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
ui = SNUI(); ui.app('global'); FAILS = []; TOTAL = [0]
def check(label, cond, detail=''):
    TOTAL[0] += 1; print(('PASS ' if cond else 'FAIL ') + label + (' | ' + detail if detail else ''))
    if not cond: FAILS.append(label)
ui.js('new GlideUpdateSet().set(%s); gs.print("X::{}");' % json.dumps(ST['global_default']))
d = ui.js(r'''
var __t = {tables: {}};
var C = x_196061_bofasim.BOA_SI_USEM_RemediationTaskPayloadBuilder;
var recs = %s;
for (var t in recs) {
    var g = new GlideRecord(t); g.addQuery('number', recs[t]); g.query(); g.next();
    var client = new C().buildPayload(g, 'UPDATE');
    var reference = new RemediationTaskPayloadBuilder().buildPayload(g);
    __t.tables[t] = {client_type: typeof client, client: JSON.stringify(client), again: JSON.stringify(new C().buildPayload(g, 'INSERT')), reference: reference, mapping_len: new C()._fieldMapping(t).length};
}
gs.print('X::' + JSON.stringify(__t));''' % json.dumps(RECS))
for t, r in d['tables'].items():
    c, ref, again = json.loads(r['client']), json.loads(r['reference']), json.loads(r['again'])
    ct, rt = c['rem_tasks'][0]['remediation_task'], ref['rem_tasks'][0]['remediation_task']
    check('1 %s: client copy returns the payload object' % t, r['client_type'] == 'object')
    check('1 %s: same keys in the same order as the reference builder (%d fields)' % (t, r['mapping_len']), list(ct.keys()) == list(rt.keys()), '%d vs %d' % (len(ct), len(rt)))
    diff = [k for k in ct if ct[k] != rt.get(k)]
    check('1 %s: every value equal to the reference builder' % t, not diff, ', '.join('%s: %r vs %r' % (k, ct[k], rt.get(k)) for k in diff[:4]))
    e = c['envelope']
    check('1 %s: envelope with the given activity' % t, e['type'] == 'record' and e['topic_name'] == 'sn_usem_remtask_outbound' and e['namespace'] == 'com.bofa.usem' and e['element_count'] == 1 and e['element_activity'] == 'UPDATE' and UUID.match(e['event_id']) and TS.match(e['event_timestamp']))
    check('1 %s: activity follows the parameter (INSERT on the second call)' % t, again['envelope']['element_activity'] == 'INSERT' and again['rem_tasks'] == c['rem_tasks'])
n = ui.js(r'''
var __n = {}; var name = 'x_boar_bofa_usem_1.usem.cdp.remtask.fields.sn_vul_vulnerability';
var p = new GlideRecord('sys_properties'); p.get(%s); var keep = '' + p.getValue('value');
var C = x_196061_bofasim.BOA_SI_USEM_RemediationTaskPayloadBuilder;
var g = new GlideRecord('sn_vul_vulnerability'); g.addQuery('number', 'VUL0004576'); g.query(); g.next();
function set(v) { p.setValue('value', v); p.update(); return '' + gs.getProperty(name, ''); }
set('{"number": "task_number", '); __n.bad_json = new C().buildPayload(g, 'UPDATE');
set('["number"]'); __n.array = new C().buildPayload(g, 'UPDATE');
set('{}'); __n.empty = new C().buildPayload(g, 'UPDATE');
set('{"number": 5}'); __n.non_string = new C().buildPayload(g, 'UPDATE');
set(JSON.stringify({"number": "task_number", "short_description": "", "state": "status"})); var small = new C().buildPayload(g, 'UPDATE'); __n.small = JSON.stringify(small);
__n.restored = set(keep) === keep; __n.after = JSON.stringify(new C().buildPayload(g, 'UPDATE'));
var l = new GlideRecord('syslog'); l.addQuery('message', 'STARTSWITH', 'BOA_SI_USEM_RemediationTaskPayloadBuilder: payload not built'); l.addQuery('sys_created_on', '>', gs.minutesAgoStart(2)); l.orderByDesc('sys_created_on'); l.query();
__n.msgs = []; while (l.next()) __n.msgs.push('' + l.getValue('message'));
gs.print('X::' + JSON.stringify(__n));''' % json.dumps(ST['props']['x_boar_bofa_usem_1.usem.cdp.remtask.fields.sn_vul_vulnerability']))
PFX = 'BOA_SI_USEM_RemediationTaskPayloadBuilder: payload not built for sn_vul_vulnerability '
M = n['msgs']
check('2 invalid JSON -> "" and the property named with the parser reason', n['bad_json'] == '' and any(re.search(PFX + r'[0-9a-f]{32} - property x_boar_bofa_usem_1\.usem\.cdp\.remtask\.fields\.sn_vul_vulnerability is not valid JSON - .+$', m) for m in M), next((m for m in M if 'not valid JSON' in m), 'no log'))
check('2 JSON array -> ""', n['array'] == '' and any(m.endswith('must be a JSON object of "servicenow_field": "json_field" pairs') for m in M))
check('2 empty object -> ""', n['empty'] == '' and any(m.endswith('holds no fields') for m in M))
check('2 non-string json_field -> ""', n['non_string'] == '' and any(m.endswith('the json_field for number must be a string') for m in M))
small = json.loads(n['small'])['rem_tasks'][0]['remediation_task']
check('2 small mapping: rename, empty json_field keeps the field, order kept', list(small.keys()) == ['task_number', 'short_description', 'status', 'change_requests', 'exception_requests'] and small['task_number'] == 'VUL0004576', str(list(small.keys())))
check('2 property restored and the full mapping back', n['restored'] and len(json.loads(n['after'])['rem_tasks'][0]['remediation_task']) == d['tables']['sn_vul_vulnerability']['mapping_len'] + 2)
print('\n%s: %d checks, %d failed%s' % ('ALL PASS' if not FAILS else 'FAILED', TOTAL[0], len(FAILS), '' if not FAILS else ' -> ' + '; '.join(FAILS)))
sys.exit(1 if FAILS else 0)
