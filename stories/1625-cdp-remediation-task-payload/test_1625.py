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
def pairs(table):
    return [(f, j or f) for f, j in json.loads(P['usem.cdp.remtask.fields.' + table]).items()]
def expected_keys(table):
    return [j for _, j in pairs(table)] + ['change_requests', 'exception_requests']
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
gs.setProperty(name, JSON.stringify({"number": "task_number", "short_description": "", "bogus_field": "bogus", "assigned_to.name": "owner_name", "sys_mod_count": "updates", "state": "state", "risk_score": ""}, null, 2));
probe.custom = new RemediationTaskPayloadBuilder().buildPayload(g);
probe.mod = '' + g.getValue('sys_mod_count');
gs.setProperty(name, '{"number": "task_number", ');
probe.bad_json = new RemediationTaskPayloadBuilder().buildPayload(g);
gs.setProperty(name, '["number"]');
probe.array = new RemediationTaskPayloadBuilder().buildPayload(g);
gs.setProperty(name, '{}');
probe.empty_obj = new RemediationTaskPayloadBuilder().buildPayload(g);
gs.setProperty(name, '{"number": 5}');
probe.non_string = new RemediationTaskPayloadBuilder().buildPayload(g);
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
check('2a property parsing: JSON object in payload order, rename, empty json_field keeps the field name, unknown field, dot-walk', list(custom.keys()) == ['task_number', 'short_description', 'bogus', 'owner_name', 'updates', 'state', 'risk_score', 'change_requests', 'exception_requests'] and custom['task_number'] == 'VUL0004576' and custom['updates'] == d2['mod'], str(list(custom.keys())))
check('2b unknown field and dot-walk entries yield "" without error', custom['bogus'] == '' and custom['owner_name'] == '')
msgs = errors(12)
check('2c blank table property -> "" with the single error format', d2['blank'] == '' and any(m.endswith('- table sn_vul_vulnerability is not configured in property usem.cdp.remtask.fields.sn_vul_vulnerability') for m in msgs))
check('2k property not valid JSON -> "" naming the property and the parser reason', d2['bad_json'] == '' and any(re.search(r'- property usem\.cdp\.remtask\.fields\.sn_vul_vulnerability is not valid JSON - .+$', m) for m in msgs), next((m for m in msgs if 'not valid JSON' in m), 'no log'))
check('2l property is a JSON array -> "" with the format named', d2['array'] == '' and any(m.endswith('- property usem.cdp.remtask.fields.sn_vul_vulnerability must be a JSON object of "servicenow_field": "json_field" pairs') for m in msgs))
check('2m empty JSON object -> ""', d2['empty_obj'] == '' and any(m.endswith('- property usem.cdp.remtask.fields.sn_vul_vulnerability holds no fields') for m in msgs))
check('2n json_field that is not a string -> "" naming the field', d2['non_string'] == '' and any(m.endswith('- property usem.cdp.remtask.fields.sn_vul_vulnerability: the json_field for number must be a string') for m in msgs))
check('2d property restored -> sheet layout back', list(json.loads(d2['restored'])['rem_tasks'][0]['remediation_task'].keys()) == expected_keys('sn_vul_vulnerability'))
check('2e unsupported table -> "" with the single error format', d2['unsupported'] == '' and ('RemediationTaskPayloadBuilder: payload not built for incident %s - table incident is not configured in property usem.cdp.remtask.fields.incident' % d2['inc_id']) in msgs)
check('2f invalid inputs -> "" with one error each', d2['neg'] == ['', '', '', ''] and sum(1 for m in msgs if m == 'RemediationTaskPayloadBuilder: payload not built - record is not a valid GlideRecord') >= 4 and all(ERR.match(m) for m in msgs))
check('2g derived exception_requests (approved/expired)', 'VCA0010007' in json.loads(d2['exc'])['rem_tasks'][0]['remediation_task']['exception_requests'].split(','))
check('2h never-updated record -> INSERT outside a business rule', json.loads(d2['fresh'])['envelope']['element_activity'] == 'INSERT')
check('2i 50 payloads built', d2['perf']['built'] == 50, '%d ms' % d2['perf']['ms'])
check('2j exactly one payload script include and four table properties remain', d2['builders'] == ['RemediationTaskPayloadBuilder'] and sorted(d2['props']) == sorted(P.keys()), str(d2['builders']) + ' ' + str(sorted(d2['props'])))

# ---------- verification layer: 5 records per table recomputed independently ----------
d5 = ui.js(r'''
var o = {tables: {}};
var b = new RemediationTaskPayloadBuilder();
var tabs = ['sn_vul_vulnerability', 'sn_vul_app_vulnerability', 'sn_vul_container_vulnerability', 'sn_vulc_result_group'];
for (var ti = 0; ti < tabs.length; ti++) {
    var t = tabs[ti]; o.tables[t] = [];
    var mapping = b._fieldMapping(t);
    var g = new GlideRecord(t); g.orderByDesc('sys_updated_on'); g.setLimit(5); g.query();
    while (g.next()) {
        var facts = {};
        for (var i = 0; i < mapping.length; i++) {
            var f = mapping[i].field; var info = {exists: g.isValidField(f)};
            if (info.exists) { var el = g.getElement(f); info.empty = el.nil(); info.type = '' + el.getED().getInternalType(); info.display = '' + el.getDisplayValue(); info.value = '' + el.getValue(); if (info.type == 'journal_input' && !info.empty) info.journal = ('' + el.getJournalEntry(1)).trim(); }
            facts[mapping[i].json] = info;
        }
        var p1 = b.buildPayload(g); var p2 = b.buildPayload(g);
        o.tables[t].push({id: g.getUniqueValue(), payload: p1, again: p2, facts: facts});
    }
}
gs.print('X::' + JSON.stringify(o));''')
def expect(info):
    if not info['exists'] or info['empty']: return ''
    ty, v = info['type'], info['value']
    if ty == 'glide_date_time': return '%s-%s-%s %s' % (v[5:7], v[8:10], v[0:4], v[11:19])
    if ty == 'glide_date': return '%s-%s-%s' % (v[5:7], v[8:10], v[0:4])
    if ty == 'journal_input': return info['journal']
    if ty in ('reference', 'glide_list', 'boolean', 'glide_duration', 'timer', 'domain_id', 'sys_class_name', 'integer', 'string'): return info['display']
    return v
total = 0; mismatches = []
for t, rows in d5['tables'].items():
    for row in rows:
        task = json.loads(row['payload'])['rem_tasks'][0]['remediation_task']
        if list(task.keys()) != expected_keys(t): mismatches.append(t + ' keys ' + row['id'])
        for k, info in row['facts'].items():
            total += 1
            if task[k] != expect(info): mismatches.append('%s %s %s: %r != %r' % (t, row['id'][:8], k, task[k], expect(info)))
        a, b2 = json.loads(row['payload']), json.loads(row['again'])
        if a['rem_tasks'] != b2['rem_tasks']: mismatches.append(t + ' not repeatable ' + row['id'])
check('V2 20 records x every mapped field recomputed independently (%d values), keys and repeatability' % total, not mismatches, '; '.join(mismatches[:5]))
# ---------- verification layer: properties equal the sheet's required rows; script hygiene ----------
mapping = json.load(open(os.path.join(HERE, 'remtask_mapping.json')))
groups = {'sn_vul_app_vulnerability (App. VR)': 'sn_vul_app_vulnerability', 'sn_vul_container_vulnerability (CVR)': 'sn_vul_container_vulnerability', 'sn_vul_vulnerability (IVR)': 'sn_vul_vulnerability', 'sn_vulc_result_group(CC)': 'sn_vulc_result_group'}
required_common, seen = [], set(); required_specific = {v: [] for v in groups.values()}
for m in mapping:
    if m['required'].strip().lower() != 'yes' or not m['sn_field']: continue
    pair = (m['sn_field'], m['json'].strip().replace(' ', '_'))
    if m['table'].startswith('Common'):
        if pair not in seen: seen.add(pair); required_common.append(pair)
    elif m['table'] in groups: required_specific[groups[m['table']]].append(pair)
live = ui.js(r'''
var o = {props: {}, script: ''};
var p = new GlideRecord('sys_properties'); p.addQuery('name', 'STARTSWITH', 'usem.cdp.remtask.fields.'); p.query();
while (p.next()) o.props['' + p.name] = '' + p.getValue('value');
var s = new GlideRecord('sys_script_include'); s.addQuery('name', 'RemediationTaskPayloadBuilder'); s.query(); s.next(); o.script = '' + s.script;
gs.print('X::' + JSON.stringify(o));''')
def live_pairs(v): return [(f, j or f) for f, j in json.loads(v).items()]
check('V3a live properties equal the sheet rows with CDP Required = Yes, per table', all(live_pairs(live['props']['usem.cdp.remtask.fields.' + t]) == required_common + required_specific[t] for t in groups.values()) and len(live['props']) == 4)
check('V3b every property is a JSON object, one "servicenow_field": "json_field" pair per line, every json_field a string', all(isinstance(json.loads(v), dict) and v.count('\n') == len(json.loads(v)) + 1 and all(isinstance(j, str) for j in json.loads(v).values()) for v in live['props'].values()))
sc = live['script']
check('V3c script hygiene: entry-point try/catch plus the JSON parse translation, one gs.error, no info/warn, no field lists in code', sc.count('try {') == 2 and sc.count('catch (') == 2 and sc.count('gs.error(') == 1 and 'gs.info' not in sc and 'gs.warn' not in sc and 'assigned_to' not in sc)
not_required = [m['sn_field'] for m in mapping if m['required'].strip().lower() != 'yes' and m['sn_field'] and m['sn_field'] not in ('table',)]
leak = [f for f in set(not_required) if any(f == a for a, _ in live_pairs(live['props']['usem.cdp.remtask.fields.sn_vul_vulnerability']))]
check('V3d no non-required sheet field leaks into the IVR property', not leak, str(leak))

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
