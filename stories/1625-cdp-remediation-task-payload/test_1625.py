import os, sys, json, re
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
ui = SNUI(); ui.app('global')
HERE = os.path.join(BASE, 'stories', '1625-cdp-remediation-task-payload')
P = json.load(open(os.path.join(HERE, 'properties.json')))['properties']
FAILS = []
def check(label, cond, detail=''):
    print(('PASS ' if cond else 'FAIL ') + label + (' | ' + detail if detail else ''))
    if not cond: FAILS.append(label)
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
DT = re.compile(r'^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}$')
D = re.compile(r'^\d{2}-\d{2}-\d{4}$')
ERR = re.compile(r'^RemediationTaskPayloadBuilder: payload not built( for [a-z_]+ [0-9a-f]{32})? - .+$')
def errors(n):
    return ui.js('''
var o = {msgs: []};
var l = new GlideRecord('syslog'); l.addQuery('message', 'STARTSWITH', 'RemediationTaskPayloadBuilder: payload not built'); l.orderByDesc('sys_created_on'); l.setLimit(%d); l.query();
while (l.next()) o.msgs.push('' + l.getValue('message'));
gs.print('X::' + JSON.stringify(o));''' % n)['msgs']
def expected_keys(table):
    keys = []
    for entry in P['usem.cdp.remtask.fields.' + table].split(','):
        f, j = entry.split('=')
        keys.append(j)
    return keys + ['change_requests', 'exception_requests']
RECS = {'sn_vul_vulnerability': 'VUL0004576', 'sn_vul_app_vulnerability': 'AVUL0010008', 'sn_vul_container_vulnerability': 'CVUL0010001', 'sn_vulc_result_group': 'CRG0001133'}

# ---------- 1. one payload per table, checked field by field ----------
d = ui.js(r'''
var o = {tables: {}, base_url: '' + gs.getProperty('glide.servlet.uri')};
var b = new RemediationTaskPayloadBuilder();
var recs = %s;
for (var t in recs) {
    var g = new GlideRecord(t); g.addQuery('number', recs[t]); g.query(); g.next();
    var facts = {sys_id: g.getUniqueValue(), mod: '' + g.getValue('sys_mod_count'), fields: {}};
    var mapping = b._fieldMapping(t);
    for (var i = 0; i < mapping.length; i++) {
        var f = mapping[i].field; var info = {exists: g.isValidField(f)};
        if (info.exists) { var el = g.getElement(f); info.empty = el.nil(); info.type = '' + el.getED().getInternalType(); info.display = '' + el.getDisplayValue(); info.value = '' + el.getValue(); }
        facts.fields[mapping[i].json] = info;
    }
    o.tables[t] = {payload: b.buildPayload(g), facts: facts};
}
gs.print('X::' + JSON.stringify(o));''' % json.dumps(RECS))
for t, blob in d['tables'].items():
    p = json.loads(blob['payload']); env, task, facts = p['envelope'], p['rem_tasks'][0]['remediation_task'], blob['facts']
    check('1a %s: envelope' % t, env['type'] == 'record' and env['topic_name'] == 'sn_usem_remtask_outbound' and env['namespace'] == 'com.bofa.usem' and env['core_version'] == '1.0.0' and env['outbound_version'] == '1.0.0' and env['element_count'] == 1 and UUID.match(env['event_id']) and TS.match(env['event_timestamp']) and env['element_activity'] == ('UPDATE' if int(facts['mod']) > 0 else 'INSERT'))
    check('1b %s: exactly the property keys, in order, plus the two derived keys' % t, list(task.keys()) == expected_keys(t), '%d keys' % len(task))
    check('1c %s: every value is a string' % t, all(isinstance(v, str) for v in task.values()))
    missing = [k for k, i in facts['fields'].items() if not i['exists']]; empty = [k for k, i in facts['fields'].items() if i['exists'] and i['empty']]
    check('1d %s: fields missing on the table -> "" (%s)' % (t, ','.join(missing) or 'none missing'), all(task[k] == '' for k in missing))
    check('1e %s: empty fields -> "" (%d empty)' % (t, len(empty)), all(task[k] == '' for k in empty))
    bad = []
    for k, i in facts['fields'].items():
        if not i['exists'] or i['empty']: continue
        ty, v = i['type'], task[k]
        if ty == 'glide_date_time': ok = bool(DT.match(v)) and v[6:10] == i['value'][:4] and v[11:] == i['value'][11:]
        elif ty == 'glide_date': ok = bool(D.match(v)) and v[6:10] == i['value'][:4]
        elif ty == 'journal_input': ok = v != '' 
        elif ty in ('reference', 'glide_list', 'boolean', 'glide_duration', 'timer', 'domain_id', 'sys_class_name', 'integer', 'string'): ok = v == i['display']
        else: ok = v == i['value']
        if not ok: bad.append('%s(%s)=%s' % (k, ty, v))
    check('1f %s: populated fields rendered by type (%d checked)' % (t, len([1 for i in facts['fields'].values() if i['exists'] and not i['empty']])), not bad, ', '.join(bad))
    check('1g %s: sys_id raw, number raw, state label' % t, task['sys_id'] == facts['sys_id'] and task['number'] == RECS[t] and task['state'] == facts['fields']['state']['display'])
vul = json.loads(d['tables']['sn_vul_vulnerability']['payload'])['rem_tasks'][0]['remediation_task']
check('1h derived change_requests from the association table', vul['change_requests'] == 'CHG0003510', vul['change_requests'])
ivr_missing = ['patch_miss_target', 'patch_not_sch', 'patch_sch']; avr = json.loads(d['tables']['sn_vul_app_vulnerability']['payload'])['rem_tasks'][0]['remediation_task']
check('1i table-specific fields absent on this instance are blank, never an error', all(vul[k] == '' for k in ivr_missing) and avr['u_avul_record_url'] == '' and avr['u_verification_status'] == '')
cc = json.loads(d['tables']['sn_vulc_result_group']['payload'])['rem_tasks'][0]['remediation_task']
check('1j common fields the CC table does not have are blank', cc['risk_score'] == '' and cc['total_cis'] == '' and cc['until'] == '')

# ---------- 2. property handling, existence checks, errors ----------
d2 = ui.js(r'''
var probe = {};
var b = new RemediationTaskPayloadBuilder();
var g = new GlideRecord('sn_vul_vulnerability'); g.addQuery('number', 'VUL0004576'); g.query(); g.next();
var name = 'usem.cdp.remtask.fields.sn_vul_vulnerability'; var original = gs.getProperty(name);
gs.setProperty(name, ' number = task_number , short_description,, bogus_field=bogus , assigned_to.name=owner_name , sys_mod_count = updates ');
probe.custom = new RemediationTaskPayloadBuilder().buildPayload(g);
probe.mod = '' + g.getValue('sys_mod_count');
gs.setProperty(name, '');
probe.blank = new RemediationTaskPayloadBuilder().buildPayload(g);
gs.setProperty(name, original);
probe.restored = new RemediationTaskPayloadBuilder().buildPayload(g);
var inc = new GlideRecord('incident'); inc.setLimit(1); inc.query(); inc.next(); probe.inc_id = inc.getUniqueValue();
probe.unsupported = new RemediationTaskPayloadBuilder().buildPayload(inc);
probe.neg = [b.buildPayload(null), b.buildPayload({}), b.buildPayload('VUL0004576'), b.buildPayload(new GlideRecord('sn_vul_vulnerability'))];
var exc = new GlideRecord('sn_vul_vulnerability'); exc.addQuery('number', 'VUL0010547'); exc.query(); exc.next(); probe.exc = b.buildPayload(exc);
var fresh = new GlideRecord('sn_vul_vulnerability'); fresh.initialize(); fresh.setValue('short_description', 'VSO-PAYLOAD fresh record'); fresh.setWorkflow(false); var fid = fresh.insert();
var fresh2 = new GlideRecord('sn_vul_vulnerability'); fresh2.get(fid); probe.fresh = b.buildPayload(fresh2);
var t0 = new Date().getTime(); var n = 0; var many = new GlideRecord('sn_vul_vulnerability'); many.setLimit(50); many.query(); while (many.next()) { if (b.buildPayload(many)) n++; }
probe.perf = {built: n, ms: new Date().getTime() - t0};
var left = new GlideRecord('sys_script_include'); left.addQuery('name', 'IN', 'RemediationTaskPayloadBuilder,CdpRemediationTaskPayloadBuilder'); left.query(); probe.builders = []; while (left.next()) probe.builders.push('' + left.name);
var props = new GlideRecord('sys_properties'); props.addQuery('name', 'STARTSWITH', 'usem.cdp.remtask.').addOrCondition('name', 'usem.remtask.payload.fields'); props.query(); probe.props = []; while (props.next()) probe.props.push('' + props.name);
gs.print('X::' + JSON.stringify(probe));''')
custom = json.loads(d2['custom'])['rem_tasks'][0]['remediation_task']
check('2a property parsing: rename, bare name, blanks, whitespace', list(custom.keys()) == ['task_number', 'short_description', 'bogus', 'owner_name', 'updates', 'change_requests', 'exception_requests'] and custom['task_number'] == 'VUL0004576' and custom['updates'] == d2['mod'], str(list(custom.keys())))
check('2b unknown field and dot-walk entries yield "" without error', custom['bogus'] == '' and custom['owner_name'] == '')
msgs = errors(6)
check('2c blank table property -> "" with the single error format', d2['blank'] == '' and any(m.endswith('- table sn_vul_vulnerability is not configured in property usem.cdp.remtask.fields.sn_vul_vulnerability') for m in msgs))
check('2d property restored -> sheet layout back', list(json.loads(d2['restored'])['rem_tasks'][0]['remediation_task'].keys()) == expected_keys('sn_vul_vulnerability'))
check('2e unsupported table -> "" with the single error format', d2['unsupported'] == '' and ('RemediationTaskPayloadBuilder: payload not built for incident %s - table incident is not configured in property usem.cdp.remtask.fields.incident' % d2['inc_id']) in msgs)
check('2f invalid inputs -> "" with one error each', d2['neg'] == ['', '', '', ''] and sum(1 for m in msgs if m == 'RemediationTaskPayloadBuilder: payload not built - record is not a valid GlideRecord') >= 4 and all(ERR.match(m) for m in msgs))
check('2g derived exception_requests (approved/expired)', 'VCA0010007' in json.loads(d2['exc'])['rem_tasks'][0]['remediation_task']['exception_requests'].split(','))
check('2h never-updated record -> INSERT outside a business rule', json.loads(d2['fresh'])['envelope']['element_activity'] == 'INSERT')
check('2i 50 payloads built', d2['perf']['built'] == 50, '%d ms' % d2['perf']['ms'])
check('2j exactly one payload script include and four table properties remain', d2['builders'] == ['RemediationTaskPayloadBuilder'] and sorted(d2['props']) == sorted(P.keys()), str(d2['builders']) + ' ' + str(sorted(d2['props'])))

# ---------- 3. business rule context ----------
d3 = ui.js(r'''
var probeResult = {};
new GlideUpdateSet().set('7dba58ecf54403100a22c0b3dfa151af');
var br = new GlideRecord('sys_script'); br.initialize();
br.setValue('name', 'ZZ payload probe'); br.setValue('collection', 'sn_vul_vulnerability'); br.setValue('when', 'after'); br.setValue('order', 5000);
br.setValue('action_insert', true); br.setValue('action_update', true); br.setValue('active', true); br.setValue('advanced', true);
br.setValue('script', "(function executeRule(current, previous) { var p = new RemediationTaskPayloadBuilder().buildPayload(current); gs.info('PAYLOADPROBE ' + current.getUniqueValue() + ' ' + current.operation() + ' ' + (p ? JSON.parse(p).envelope.element_activity : 'EMPTY')); })(current, previous);");
probeResult.probe = '' + br.insert();
var g = new GlideRecord('sn_vul_vulnerability'); g.addQuery('number', 'VUL0004576'); g.query(); g.next();
g.setValue('description', 'payload probe ' + new GlideDateTime().getNumericValue()); g.update(); probeResult.updated = '' + g.getUniqueValue();
var n = new GlideRecord('sn_vul_vulnerability'); n.initialize(); n.setValue('short_description', 'VSO-PAYLOAD probe insert'); probeResult.inserted = '' + n.insert();
var lines = []; var l = new GlideRecord('syslog'); l.addQuery('message', 'STARTSWITH', 'PAYLOADPROBE'); l.addQuery('sys_created_on', '>', gs.minutesAgoStart(2)); l.query();
while (l.next()) lines.push('' + l.getValue('message'));
probeResult.lines = lines;
var del = new GlideRecord('sys_script'); del.addQuery('name', 'ZZ payload probe'); del.query(); while (del.next()) del.deleteRecord();
var tidy = new GlideRecord('sn_vul_vulnerability'); tidy.addQuery('short_description', 'STARTSWITH', 'VSO-PAYLOAD'); tidy.query();
while (tidy.next()) { tidy.setValue('active', false); tidy.setValue('state', 3); tidy.setWorkflow(false); tidy.update(); }
gs.print('X::' + JSON.stringify(probeResult));''')
upd = [x for x in d3['lines'] if d3['updated'] in x]; ins = [x for x in d3['lines'] if d3['inserted'] in x]
check('3a business rule on update -> UPDATE from current.operation()', bool(upd) and upd[0].endswith(' update UPDATE'), upd[0] if upd else 'no line')
check('3b business rule on insert -> INSERT from current.operation()', bool(ins) and ins[0].endswith(' insert INSERT'), ins[0] if ins else 'no line')
print('---'); print('RESULT:', 'ALL PASS' if not FAILS else 'FAILURES: ' + ', '.join(FAILS))
os.makedirs(os.path.join(HERE, 'samples'), exist_ok=True)
for t, blob in d['tables'].items():
    txt = json.dumps(json.loads(blob['payload']), indent=2).replace(INST.split('//')[1], 'instance.example.com')
    open(os.path.join(HERE, 'samples', 'Sample payload - %s.json' % t), 'w').write(txt)
