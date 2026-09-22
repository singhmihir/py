"""Checks the VAMP outbound build on the PDI against the sheet "SN to VAMP" and the fixture items:
the properties hold the sections and the resolved ServiceNow fields, the payload carries the sheet's
JSON structure names with the sheet's field names per section and every value, the remediation tasks
of an item are a list with one entry per linked task, and the fields the instance does not have are
named in a second message (A); an item with nothing linked (B); the rule on a real update and a real
insert with the processor and producer messages (C); rendering by dictionary type (D); the error
paths and the payload validation of the processor and the producer (E); and the number of remediation
tasks behind one item: two, one, none, and a link whose task is gone (F). Run twice."""
import os, sys, json, re, html
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ST = json.load(open(os.path.join(HERE, 'state.json'))); FX = json.load(open(os.path.join(HERE, 'fixtures.json')))
SHEET = json.load(open(os.path.join(HERE, 'vamp_mapping.json'))); SECTIONS = json.load(open(os.path.join(HERE, 'vamp_sections.json')))
PROPS = json.load(open(os.path.join(HERE, 'properties.json'))); RESOLUTION = json.load(open(os.path.join(HERE, 'field_resolution.json')))
P = 'x_boar_bofa_usem_1'
ITEM = 'sn_vul_app_vulnerable_item'
MANY = 'sn_vul_app_vulnerability'          # the section reached through the group item table: a list
NAMES = [s['json'] for s in SECTIONS]
TABLE_OF = {s['json']: s['table'] for s in SECTIONS}
FIELDS = {s['json']: [r['json'] for r in SHEET if r['table'] == s['table']] for s in SECTIONS}
NOT_FOUND = ['%s.%s' % (e['table'], e['json']) for e in RESOLUTION if not e['field']]
ENVELOPE = ['type', 'topic_name', 'namespace', 'core_version', 'outbound_version', 'event_id', 'event_timestamp', 'element_count', 'element_activity']
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
STAMP = re.compile(r'^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}$')
ui = SNUI(); ui.app('global')
passed = failed = 0
def js(script):
    raw = ui.run(script)
    m = re.search(r'X::(\{.*\})', raw, re.S)
    if not m:
        raise RuntimeError('NO MARKER; tail: ' + raw[-1500:])
    text = html.unescape(re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', raw)))
    messages = []
    for s in re.findall(r'Background message, type:info, message: (.*?)(?=Background message, type:|\*\*\* Script|$)', text):
        s = s.strip()
        if s.startswith('VAMP payload for '):
            start = s.index(': {') + 2
            s = s[:json.JSONDecoder().raw_decode(s, start)[1]]
        s = re.split(r'Time: \d:\d\d:\d\d|' + re.escape(P + ' ('), s)[0].strip()
        messages.append(s)
    return json.loads(m.group(1)), messages
def check(name, ok, detail=''):
    global passed, failed
    ok = bool(ok)
    passed += ok; failed += (not ok)
    print(('  ok   ' if ok else '  FAIL ') + name + ('' if ok else '  -> ' + str(detail)[:700]))

def build(sys_id):
    r, messages = js('''
var o = {};
var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(%s);
var before = new GlideAggregate('syslog_app_scope'); before.addAggregate('COUNT'); before.addQuery('message', 'CONTAINS', 'BOFASIVampOutboundProcessor'); before.query(); before.next(); o.errors_before = parseInt(before.getAggregate('COUNT'));
o.text = new x_boar_bofa_usem_1.BOFASIVampOutboundProcessor().buildPayload(a);
var after = new GlideAggregate('syslog_app_scope'); after.addAggregate('COUNT'); after.addQuery('message', 'CONTAINS', 'BOFASIVampOutboundProcessor'); after.query(); after.next(); o.errors_after = parseInt(after.getAggregate('COUNT'));
function stamp(v) { if (!v) return ''; var g = new GlideDateTime(v); return g.getDate().getByFormat('MM-dd-yyyy') + ' ' + g.getTime().getByFormat('HH:mm:ss'); }
o.expect = {number: '' + a.getValue('number'), created: stamp(a.getValue('sys_created_on')), updated: stamp(a.getValue('sys_updated_on')), state: '' + a.getValue('state'), mod: parseInt(a.getValue('sys_mod_count')),
    src: '' + (a.getValue('source_avit_id') || ''), status: '' + (a.getValue('u_verification_status') || ''), url: '' + (a.getValue('u_avit_record_url') || ''),
    ci: '' + (a.getValue('cmdb_ci') || ''), ci_display: '' + a.getDisplayValue('cmdb_ci'), has_ci_field: a.isValidField('configuration_item'),
    ptreq: '' + a.getDisplayValue('assessment_request'), ptreq_created: stamp(a.assessment_request.sys_created_on.getValue()), ptreq_assessment: '' + (a.assessment_request.u_assessment_id ? a.assessment_request.u_assessment_id.getValue() || '' : ''),
    entry_display: '' + a.getDisplayValue('vulnerability'), entry_class: '', entry_sub_cat: '', entry_has_number_on_class: false, entry_sub_cat_on_base: new GlideRecord('sn_vul_entry').isValidField('u_vuln_sub_cat_id')};
if (!a.vulnerability.nil()) {
    var ref = a.vulnerability.getRefRecord();
    o.expect.entry_class = '' + ref.getValue('sys_class_name');
    var cls = new GlideRecord(o.expect.entry_class); cls.get(ref.getUniqueValue());
    o.expect.entry_sub_cat = '' + (cls.getValue('u_vuln_sub_cat_id') || '');
    o.expect.entry_has_number_on_class = cls.isValidField('number');
}
o.expect.tasks = [];
var m = new GlideRecord('sn_vul_app_m2m_vul_group_item'); m.addQuery('sn_vul_app_vulnerable_item', a.getUniqueValue()); m.addNotNullQuery('sn_vul_app_vulnerability'); m.orderBy('sn_vul_app_vulnerability.number'); m.query();
while (m.next()) { var t = m.sn_vul_app_vulnerability.getRefRecord(); if (t && t.isValidRecord()) o.expect.tasks.push({number: '' + t.getValue('number'), ait: '' + t.getDisplayValue('u_primary_ait'), url: '' + (t.getValue('u_avul_record_url') || '')}); }
o.props = {}; var p = new GlideRecord('sys_properties'); p.addQuery('name', 'STARTSWITH', 'x_boar_bofa_usem_1.usem.vamp.'); p.orderBy('name'); p.query(); while (p.next()) o.props['' + p.getValue('name')] = '' + p.getValue('value');
gs.print('X::' + JSON.stringify(o));''' % json.dumps(sys_id))
    r['messages'] = messages
    return r

def shape(tag, r):
    p = json.loads(r['text']); e = p['envelope']
    expected_props = {P + '.' + k: v['value'] for k, v in PROPS.items() if k != 'usem.vamp.kafka.topic_sys_id'}
    check(tag + ' the sections and fields properties hold exactly the sheet, the topic property the only other one', {k: v for k, v in r['props'].items() if not k.endswith('topic_sys_id')} == expected_props and len(r['props']) == 3, r['props'])
    check(tag + ' payload is JSON with envelope and findings only', sorted(p.keys()) == ['envelope', 'findings'], list(p.keys()))
    check(tag + ' envelope keys in order', list(e.keys()) == ENVELOPE, list(e.keys()))
    check(tag + ' envelope constants', (e['type'], e['topic_name'], e['namespace'], e['core_version'], e['outbound_version']) == ('record', 'sn_usem_verification_outbound', 'com.bofa.usem', '1.0.0', '1.0.0'), e)
    check(tag + ' element_count is the number of findings', e['element_count'] == len(p['findings']) == 1, (e['element_count'], len(p['findings'])))
    check(tag + ' event_id is a UUID and timestamp is UTC ISO', UUID.match(e['event_id']) and re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', e['event_timestamp']), e)
    el = p['findings'][0]
    check(tag + ' the finding carries the sheet JSON structure names in sheet order', list(el.keys()) == NAMES, (list(el.keys()), NAMES))
    check(tag + ' the remediation tasks are a list, every other section an object', isinstance(el['remediation_task'], list) and all(isinstance(el[n], dict) for n in NAMES if n != 'remediation_task'), {n: type(el[n]).__name__ for n in NAMES})
    for name in NAMES:
        entries = el[name] if name == 'remediation_task' else [el[name]]
        check(tag + ' %s carries exactly the sheet fields of %s in sheet order' % (name, TABLE_OF[name]), all(list(x.keys()) == FIELDS[name] for x in entries), ([list(x.keys()) for x in entries], FIELDS[name]))
    check(tag + ' every value is a string', all(isinstance(v, str) for n in NAMES for x in (el[n] if n == 'remediation_task' else [el[n]]) for v in x.values()), el)
    check(tag + ' no processor error logged', r['errors_after'] == r['errors_before'], (r['errors_before'], r['errors_after']))
    check(tag + ' first info message holds exactly the payload', r['messages'][:1] == ['VAMP payload for ' + el['finding']['number'] + ': ' + r['text']], r['messages'])
    check(tag + ' second info message names the fields this instance does not have, nothing else', r['messages'][1:] == ['VAMP fields not found on this instance, sent as "": ' + ', '.join(NOT_FOUND)] and NOT_FOUND == ['sn_vul_app_vul_entry.number'], (r['messages'][1:], NOT_FOUND))
    return p, el, e

for run in (1, 2):
    print('== run', run)
    print('A. linked fixture', FX['linked_number'], 'with two remediation tasks')
    r = build(FX['linked']); x = r['expect']
    p, el, e = shape('A', r)
    check('A element_activity from sys_mod_count', e['element_activity'] == ('UPDATE' if x['mod'] > 0 else 'INSERT'), (e['element_activity'], x['mod']))
    f = el['finding']
    check('A finding number, state as the stored integer, source_avit_id', (f['number'], f['state'], f['source_avit_id']) == (x['number'], x['state'], 'VAMP-FIXTURE-001') and x['state'] == '1', (f, x))
    check('A finding dates MM-dd-yyyy HH:mm:ss', f['sys_created_on'] == x['created'] and f['sys_updated_on'] == x['updated'] and STAMP.match(f['sys_created_on']), (f, x['created'], x['updated']))
    check('A configuration_item resolves through cmdb_ci to the display value Trade Processing Portal', f['configuration_item'] == x['ci_display'] == 'Trade Processing Portal' and len(x['ci']) == 32 and not x['has_ci_field'], (f['configuration_item'], x))
    check('A the two custom finding fields carry their values', (f['u_verification_status'], f['u_avit_record_url']) == (x['status'], x['url']) and x['status'] == 'Pending Validation' and x['url'].endswith('VAMP-FIXTURE-001'), (f, x))
    check('A tpe read from the entry class: the sub category id of sn_vul_app_vul_entry, never on sn_vul_entry', el['tpe']['u_vuln_sub_cat_id'] == x['entry_sub_cat'] == FX['entry_sub_cat'] and x['entry_class'] == 'sn_vul_app_vul_entry' and not x['entry_sub_cat_on_base'], (el['tpe'], x))
    check('A tpe number "" (no number field on the entry table here) and the entry is the linked one', el['tpe']['number'] == '' and not x['entry_has_number_on_class'] and x['entry_display'] == FX['entry_display'], (el['tpe'], x))
    check('A remediation_task holds both tasks, in task number order', [t['number'] for t in el['remediation_task']] == [t['number'] for t in x['tasks']] == FX['task_numbers'] and len(el['remediation_task']) == 2, (el['remediation_task'], x['tasks']))
    check('A every task carries its own record url and the Primary AIT as a display value', [t['u_avul_record_url'] for t in el['remediation_task']] == FX['task_urls'] and all(t['primary_ait'] == FX['task_ait'] for t in el['remediation_task']), el['remediation_task'])
    if run == 1:
        open(os.path.join(HERE, 'samples', 'Sample payload - application vulnerable item.json'), 'w').write(json.dumps(p, indent=2) + '\n')
    check('A ptreq number, created, assessment id', el['ptreq'] == {'number': x['ptreq'], 'sys_created_on': x['ptreq_created'], 'u_assessment_id': x['ptreq_assessment']} and x['ptreq'] == 'PTREQ0012001' and x['ptreq_assessment'] == FX['ptreq_assessment'] and STAMP.match(x['ptreq_created']), (el['ptreq'], x))

    print('B. bare fixture', FX['bare_number'])
    r = build(FX['bare']); x = r['expect']
    p, el, e = shape('B', r)
    check('B remediation_task is an empty list', el['remediation_task'] == [] and x['tasks'] == [], (el['remediation_task'], x['tasks']))
    check('B the not-found message is the same as for an item with tasks: it names the table, not the records', r['messages'][1:] == ['VAMP fields not found on this instance, sent as "": ' + ', '.join(NOT_FOUND)], r['messages'][1:])
    check('B tpe and ptreq render "" for every field', all(v == '' for k in ['tpe', 'ptreq'] for v in el[k].values()), el)
    check('B finding still carries its own values, configuration_item "" with no CI', el['finding']['number'] == x['number'] and el['finding']['state'] == '1' and el['finding']['source_avit_id'] == '' and el['finding']['configuration_item'] == '' and x['ci'] == '', el['finding'])

    print('C. rule on a real update and a real insert')
    r, messages = js('''
var o = {};
function count(text) { var c = new GlideAggregate('syslog_app_scope'); c.addAggregate('COUNT'); c.addQuery('message', 'CONTAINS', text); c.query(); c.next(); return parseInt(c.getAggregate('COUNT')); }
var linked = %(linked)s;
o.before = {producer: count('BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item.' + linked), processor: count('BOFASIVampOutboundProcessor: payload not built'), rule: count('BOFA_BR_AVIT_VampOutbound')};
var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(linked); a.setValue('short_description', 'VAMP outbound fixture (linked) run %(run)s at ' + new GlideDateTime().getNumericValue()); a.update();
o.after_update = {producer: count('BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item.' + linked), processor: count('BOFASIVampOutboundProcessor: payload not built'), rule: count('BOFA_BR_AVIT_VampOutbound')};
var log = new GlideRecord('syslog_app_scope'); log.addQuery('message', 'CONTAINS', 'BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item.' + linked); log.orderByDesc('sys_created_on'); log.setLimit(1); log.query(); log.next();
o.producer_log = {level: '' + log.getValue('level'), message: '' + log.getValue('message'), age_s: (new GlideDateTime().getNumericValue() - new GlideDateTime(log.getValue('sys_created_on')).getNumericValue()) / 1000};
var n = new GlideRecord('sn_vul_app_vulnerable_item'); n.initialize(); n.setValue('short_description', 'VAMP outbound fixture (inserted, run %(run)s)'); n.setValue('source', 'VAMP fixture'); n.setValue('source_avit_id', 'VAMP-FIXTURE-INSERT'); var nid = n.insert();
o.inserted = {sys_id: '' + nid, number: '' + n.getValue('number')};
o.after_insert = {producer: count('BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item.' + nid), processor: count('BOFASIVampOutboundProcessor: payload not built'), rule: count('BOFA_BR_AVIT_VampOutbound')};
var c = new GlideRecord('sn_vul_app_vulnerable_item'); c.get(nid); c.setWorkflow(false); c.setValue('active', false); c.setValue('short_description', 'VAMP outbound fixture (inserted, retired)'); c.update(); o.retired = '' + c.getValue('active');
gs.print('X::' + JSON.stringify(o));''' % dict(linked=json.dumps(FX['linked']), run=run))
    check('C update: producer logged one send failure for the item (rule -> processor -> producer ran)', r['after_update']['producer'] == r['before']['producer'] + 1, (r['before'], r['after_update']))
    check('C update: no processor or rule error', r['after_update']['processor'] == r['before']['processor'] and r['after_update']['rule'] == r['before']['rule'], (r['before'], r['after_update']))
    check('C update: producer error carries the key and the missing Kafka API reason, logged just now', 'sn_vul_app_vulnerable_item.' + FX['linked'] + ' - ' in r['producer_log']['message'] and ('sn_ih_kafka' in r['producer_log']['message'] or 'undefined is not a function' in r['producer_log']['message']) and r['producer_log']['age_s'] < 180, r['producer_log'])
    payloads = {}
    for msg in messages:
        mm = re.match(r'VAMP payload for (\S+): (\{.*\})$', msg)
        if mm:
            payloads[mm.group(1)] = json.loads(mm.group(2))
    not_found = [m for m in messages if m.startswith('VAMP fields not found')]
    check('C info messages on the page: one payload per item plus the not-found list, nothing else', sorted(payloads) == sorted([FX['linked_number'], r['inserted']['number']]) and 1 <= len(not_found) <= 2 and all(m == 'VAMP fields not found on this instance, sent as "": ' + ', '.join(NOT_FOUND) for m in not_found) and len(messages) == len(payloads) + len(not_found), (len(messages), len(payloads), len(not_found), messages))
    upd = payloads.get(FX['linked_number']); ins = payloads.get(r['inserted']['number'])
    check('C update: the rule sends the same shape, element_activity UPDATE, both tasks, the CI display value', bool(upd) and upd['envelope']['element_activity'] == 'UPDATE' and list(upd['findings'][0].keys()) == NAMES and [t['number'] for t in upd['findings'][0]['remediation_task']] == FX['task_numbers'] and upd['findings'][0]['finding']['configuration_item'] == 'Trade Processing Portal', upd)
    check('C insert: producer logged one send failure for the new item', r['after_insert']['producer'] == 1 and r['after_insert']['processor'] == r['before']['processor'] and r['after_insert']['rule'] == r['before']['rule'], (r['before'], r['after_insert']))
    check('C insert: element_activity INSERT, the new number and an empty remediation_task list', bool(ins) and ins['envelope']['element_activity'] == 'INSERT' and ins['findings'][0]['finding']['number'] == r['inserted']['number'] and ins['findings'][0]['finding']['source_avit_id'] == 'VAMP-FIXTURE-INSERT' and ins['findings'][0]['remediation_task'] == [], ins)
    check('C insert: fixture retired afterwards', r['retired'] == '0', r['retired'])

    print('D. rendering by dictionary type')
    r, _ = js('''
var o = {};
var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(%s);
var fields = ['cmdb_ci', 'assessment_request', 'state', 'sys_created_on', 'first_found', 'short_description', 'closed_at', 'no_such_field'];
var processor = new x_boar_bofa_usem_1.BOFASIVampOutboundProcessor(); o.rendered = {};
o.types = {first_found: '' + a.first_found.getED().getInternalType(), cmdb_ci: '' + a.cmdb_ci.getED().getInternalType()};
var savedFound = '' + (a.getValue('first_found') || '');
a.setWorkflow(false); a.setValue('first_found', '2026-03-31'); a.update();
var withDate = new GlideRecord('sn_vul_app_vulnerable_item'); withDate.get(a.getUniqueValue());
for (var i = 0; i < fields.length; i++) o.rendered[fields[i]] = processor._fieldValue(withDate, fields[i]);
o.no_record = processor._fieldValue(null, 'number');
var savedCi = '' + withDate.getValue('cmdb_ci');
var gone = new GlideRecord('sn_vul_app_vulnerable_item'); gone.get(a.getUniqueValue());
gone.setWorkflow(false); gone.setValue('cmdb_ci', '00000000000000000000000000000000'); gone.update();
var broken = new GlideRecord('sn_vul_app_vulnerable_item'); broken.get(a.getUniqueValue());
o.dangling_reference = processor._fieldValue(broken, 'cmdb_ci');
o.dangling_display = '' + broken.getDisplayValue('cmdb_ci');
var back = new GlideRecord('sn_vul_app_vulnerable_item'); back.get(a.getUniqueValue());
back.setWorkflow(false); back.setValue('cmdb_ci', savedCi); back.setValue('first_found', savedFound); back.update();
var restored = new GlideRecord('sn_vul_app_vulnerable_item'); restored.get(a.getUniqueValue());
o.restored = {ci: '' + restored.getValue('cmdb_ci'), first_found: '' + (restored.getValue('first_found') || '')};
function stamp(v) { var g = new GlideDateTime(v); return g.getDate().getByFormat('MM-dd-yyyy') + ' ' + g.getTime().getByFormat('HH:mm:ss'); }
var fd = new GlideDate(); fd.setValue(a.getValue('first_found'));
o.expect = {ci: '' + a.getValue('cmdb_ci'), ci_display: '' + a.getDisplayValue('cmdb_ci'), ptreq: '' + a.getValue('assessment_request'), ptreq_display: '' + a.getDisplayValue('assessment_request'), state: '' + a.getValue('state'), state_display: '' + a.getDisplayValue('state'), created: stamp(a.getValue('sys_created_on')), first_found: a.getValue('first_found') ? fd.getByFormat('MM-dd-yyyy') : '', sd: '' + a.getValue('short_description'), closed_empty: a.closed_at.nil()};
gs.print('X::' + JSON.stringify(o));''' % json.dumps(FX['linked']))
    d = r['rendered']; x = r['expect']
    check('D reference fields render the display value, not the sys_id', d['cmdb_ci'] == x['ci_display'] == 'Trade Processing Portal' and d['cmdb_ci'] != x['ci'] and d['assessment_request'] == x['ptreq_display'] == 'PTREQ0012001' and len(x['ptreq']) == 32, (d, x))
    check('D integer renders the stored value, not the label', d['state'] == x['state'] == '1' and x['state_display'] == 'Open', (d['state'], x))
    check('D date/time MM-dd-yyyy HH:mm:ss, and a date field of type glide_date as MM-dd-yyyy', d['sys_created_on'] == x['created'] and d['first_found'] == '03-31-2026' and r['types']['first_found'] == 'glide_date', (d, r['types'], x))
    check('D string raw, empty field "", missing field "", no record ""', d['short_description'] == x['sd'] and d['closed_at'] == '' and x['closed_empty'] and d['no_such_field'] == '' and r['no_record'] == '', (d, r['no_record'], x))
    check('D a reference whose record is gone renders "", never the stored sys_id (the platform display value here: %r)' % r['dangling_display'], r['dangling_reference'] == '' and r['types']['cmdb_ci'] == 'reference' and r['dangling_display'] in ('', '00000000000000000000000000000000'), (r['dangling_reference'], r['dangling_display']))
    check('D the fixture is restored afterwards', r['restored']['ci'] == x['ci'] and len(x['ci']) == 32 and r['restored']['first_found'] == '', (r['restored'], x['ci']))

    print('E. error handling and payload validation')
    r, _ = js('''
var o = {};
function count(text) { var c = new GlideAggregate('syslog_app_scope'); c.addAggregate('COUNT'); c.addQuery('message', 'CONTAINS', text); c.query(); c.next(); return parseInt(c.getAggregate('COUNT')); }
function lastError(text) { var l = new GlideRecord('syslog_app_scope'); l.addQuery('message', 'CONTAINS', text); l.orderByDesc('sys_created_on'); l.setLimit(1); l.query(); return l.next() ? '' + l.getValue('message') : ''; }
var T = 'sn_vul_app_vulnerable_item', P = 'x_boar_bofa_usem_1';
var FIELDS = P + '.usem.vamp.fields.' + T, SECTIONS = P + '.usem.vamp.sections.' + T, TOPIC = P + '.usem.vamp.kafka.topic_sys_id';
new GlideUpdateSet().set(%(default_set)s);
var processor = new x_boar_bofa_usem_1.BOFASIVampOutboundProcessor(), producer = new x_boar_bofa_usem_1.BOFASIKafkaProducerVamp();
var a = new GlideRecord(T); a.get(%(linked)s);
var good = processor.buildPayload(a);
o.before = {built: count('BOFASIVampOutboundProcessor: payload not built'), sent: count('BOFASIKafkaProducerVamp: message not sent')};
o.unfetched = processor.buildPayload(new GlideRecord(T)); o.unfetched_error = lastError('payload not built');
o.nothing = processor.buildPayload(null); o.nothing_error = lastError('payload not built');
function withProperty(name, value, run) {
    var p = new GlideRecord('sys_properties'); p.addQuery('name', name); p.query(); p.next();
    var saved = '' + p.getValue('value');
    p.setValue('value', value); p.update();
    var out = run();
    var back = new GlideRecord('sys_properties'); back.get(p.getUniqueValue()); back.setValue('value', saved); back.update();
    return {out: out, restored: gs.getProperty(name, '') == saved};
}
var fieldsValue = '' + gs.getProperty(FIELDS, ''), sectionsValue = '' + gs.getProperty(SECTIONS, '');
var r1 = withProperty(FIELDS, '', function() { return processor.buildPayload(a); });
o.no_fields = r1.out; o.no_fields_error = lastError('payload not built'); o.no_fields_restored = r1.restored;
var r2 = withProperty(FIELDS, '=number,\\n' + fieldsValue, function() { return processor.buildPayload(a); });
o.bad_field_line = r2.out; o.bad_field_line_error = lastError('payload not built'); o.bad_field_line_restored = r2.restored;
var r3 = withProperty(SECTIONS, '', function() { return processor.buildPayload(a); });
o.no_sections = r3.out; o.no_sections_error = lastError('payload not built'); o.no_sections_restored = r3.restored;
var r4 = withProperty(SECTIONS, 'sn_vul_app_vul_entry,\\n' + sectionsValue, function() { return processor.buildPayload(a); });
o.bad_section_line = r4.out; o.bad_section_line_error = lastError('payload not built'); o.bad_section_line_restored = r4.restored;
var r5 = withProperty(SECTIONS, 'sn_vul_app_vulnerable_item=finding,', function() { return processor.buildPayload(a); });
o.orphan_field = r5.out; o.orphan_field_error = lastError('payload not built'); o.orphan_field_restored = r5.restored;
var r6 = withProperty(FIELDS, 'number=number,', function() { return processor.buildPayload(a); });
o.empty_section = r6.out; o.empty_section_error = lastError('payload not built'); o.empty_section_restored = r6.restored;
var sp = new GlideRecord('sys_properties'); sp.addQuery('name', SECTIONS); sp.query(); sp.next();
var fp = new GlideRecord('sys_properties'); fp.addQuery('name', FIELDS); fp.query(); fp.next();
sp.setValue('value', sectionsValue.replace('sn_vul_app_vul_entry=', 'sn_vul_app_vul_scan=')); sp.update();
fp.setValue('value', fieldsValue.replace(/sn_vul_app_vul_entry\./g, 'sn_vul_app_vul_scan.')); fp.update();
o.no_path = processor.buildPayload(a); o.no_path_error = lastError('payload not built');
sp.setValue('value', sectionsValue); sp.update(); fp.setValue('value', fieldsValue); fp.update();
o.no_path_restored = gs.getProperty(SECTIONS, '') == sectionsValue && gs.getProperty(FIELDS, '') == fieldsValue;
var sections = processor._sections(T), mapping = processor._fieldMapping(T);
var tampered = JSON.parse(good);
tampered.envelope.element_count = 2; tampered.envelope.event_id = 'not-a-uuid'; tampered.envelope.element_activity = 'CHANGED';
delete tampered.findings[0].finding.number; tampered.findings[0].finding.state = 1; tampered.findings[0].finding.stranger = 'x';
tampered.findings[0].remediation_task = {}; tampered.findings[0].extra = {};
try { processor._validatePayload(tampered, sections, mapping, a); o.tampered = 'accepted'; } catch (e) { o.tampered = '' + (e.message || e); }
try { processor._validatePayload(JSON.parse(good), sections, mapping, a); o.intact = 'accepted'; } catch (e) { o.intact = '' + (e.message || e); }
o.after_build = {built: count('BOFASIVampOutboundProcessor: payload not built')};
var t1 = withProperty(TOPIC, '', function() { producer.sendPayload(good, a); return lastError('message not sent'); });
o.no_topic_error = t1.out;
var t2 = withProperty(TOPIC, 'not-a-sys-id', function() { producer.sendPayload(good, a); return lastError('message not sent'); });
o.bad_topic_error = t2.out; o.topic_restored = t1.restored && t2.restored;
producer.sendPayload('', a); o.empty_payload_error = lastError('message not sent');
producer.sendPayload('not json', a); o.not_json_error = lastError('message not sent');
producer.sendPayload('{"a": 1}', a); o.no_envelope_error = lastError('message not sent');
var miscount = JSON.parse(good); miscount.envelope.element_count = 5; producer.sendPayload(JSON.stringify(miscount), a); o.count_error = lastError('message not sent');
producer.sendPayload(good, null); o.no_record_error = lastError('message not sent');
o.after_send = {sent: count('BOFASIKafkaProducerVamp: message not sent')};
gs.print('X::' + JSON.stringify(o));''' % dict(default_set=json.dumps(ST['default_set']), linked=json.dumps(FX['linked'])))
    check('E a record that does not exist: empty payload, one error naming it', r['unfetched'] == '' and 'the record does not exist' in r['unfetched_error'], r['unfetched_error'])
    check('E no record at all: empty payload, one error keyed "no record"', r['nothing'] == '' and 'no record was given' in r['nothing_error'] and 'for no record' in r['nothing_error'], r['nothing_error'])
    check('E fields property empty: empty payload, error names the property, property restored', r['no_fields'] == '' and 'is not configured in property' in r['no_fields_error'] and r['no_fields_restored'], (r['no_fields_error'], r['no_fields_restored']))
    check('E fields line without a field name: error quotes the line, property restored', r['bad_field_line'] == '' and 'line without a field name' in r['bad_field_line_error'] and r['bad_field_line_restored'], (r['bad_field_line_error'], r['bad_field_line_restored']))
    check('E sections property empty: error names the property, property restored', r['no_sections'] == '' and 'is not configured in property' in r['no_sections_error'] and r['no_sections_restored'], (r['no_sections_error'], r['no_sections_restored']))
    check('E sections line without a payload name: error quotes the line, property restored', r['bad_section_line'] == '' and 'line without a payload name' in r['bad_section_line_error'] and r['bad_section_line_restored'], (r['bad_section_line_error'], r['bad_section_line_restored']))
    check('E a configured field of a table that is no section is refused', r['orphan_field'] == '' and 'belongs to no section' in r['orphan_field_error'] and r['orphan_field_restored'], (r['orphan_field_error'], r['orphan_field_restored']))
    check('E a section without a single field is refused', r['empty_section'] == '' and 'has no field in property' in r['empty_section_error'] and r['empty_section_restored'], (r['empty_section_error'], r['empty_section_restored']))
    check('E a section with no path from the item is refused', r['no_path'] == '' and 'has no path from' in r['no_path_error'] and r['no_path_restored'], (r['no_path_error'], r['no_path_restored']))
    check('E validation names every problem of a tampered payload', all(s in r['tampered'] for s in ['payload invalid', 'event_id is not a UUID', 'element_activity "CHANGED"', 'element_count 2', 'finding.number is missing', 'finding.state is not a string', 'carries "stranger"', 'section remediation_task is not a list', 'carries "extra"']), r['tampered'])
    check('E validation accepts the intact payload', r['intact'] == 'accepted', r['intact'])
    check('E nine refused builds logged nine errors, nothing else', r['after_build']['built'] == r['before']['built'] + 9, (r['before'], r['after_build']))
    check('E producer refuses an empty topic property and a value that is not a sys_id, property restored', 'holds no topic' in r['no_topic_error'] and 'is not a sys_id' in r['bad_topic_error'] and r['topic_restored'], (r['no_topic_error'], r['bad_topic_error'], r['topic_restored']))
    check('E producer refuses an empty payload, text that is not JSON and JSON without envelope', 'the payload is empty' in r['empty_payload_error'] and 'the payload is not JSON' in r['not_json_error'] and 'no envelope or no findings' in r['no_envelope_error'], (r['empty_payload_error'], r['not_json_error'], r['no_envelope_error']))
    check('E producer refuses a payload whose element count is not the number of findings', 'counts 5 element(s) and carries 1' in r['count_error'], r['count_error'])
    check('E producer without a record still logs, keyed "no record"', 'message not sent for no record' in r['no_record_error'], r['no_record_error'])
    check('E seven refused sends logged seven errors, nothing else', r['after_send']['sent'] == r['before']['sent'] + 7, (r['before'], r['after_send']))

    print('F. how many remediation tasks the item has')
    r, _ = js('''
var o = {};
var processor = new x_boar_bofa_usem_1.BOFASIVampOutboundProcessor();
var linked = %(linked)s, first = %(first)s, second = %(second)s, firstTask = %(first_task)s, secondTask = %(second_task)s;
function set(m2m, value) { var g = new GlideRecord('sn_vul_app_m2m_vul_group_item'); g.get(m2m); g.setWorkflow(false); g.setValue('sn_vul_app_vulnerability', value); g.update(); }
function payload() { var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(linked); return JSON.parse(processor.buildPayload(a)).findings[0]; }
o.two = payload();
set(second, ''); o.one = payload();
set(first, ''); o.none = payload();
set(second, secondTask); set(first, firstTask); o.restored = payload();
set(second, '00000000000000000000000000000000'); o.dangling = payload();
set(second, secondTask); o.after = payload();
gs.print('X::' + JSON.stringify(o));''' % dict(linked=json.dumps(FX['linked']), first=json.dumps(FX['m2m']['first']), second=json.dumps(FX['m2m']['second']),
                                               first_task=json.dumps(FX['tasks']['first']), second_task=json.dumps(FX['tasks']['second'])))
    tasks = lambda k: [t['number'] for t in r[k]['remediation_task']]
    check('F two links: both tasks, in task number order', tasks('two') == FX['task_numbers'], tasks('two'))
    check('F one link: only the task still linked, the other gone from the list', tasks('one') == [FX['avul']], (tasks('one'), FX['avul']))
    check('F no link: an empty list, never a missing section', r['none']['remediation_task'] == [] and 'remediation_task' in r['none'], r['none'].get('remediation_task'))
    check('F links restored: both tasks again', tasks('restored') == FX['task_numbers'], tasks('restored'))
    check('F a link whose task is gone is skipped, the other task still sent', len(tasks('dangling')) == 1 and tasks('dangling')[0] in FX['task_numbers'], tasks('dangling'))
    check('F after the restore the list is back to both tasks', tasks('after') == FX['task_numbers'], tasks('after'))
    check('F the other three sections do not change with the number of tasks', all(r[k]['finding'] == r['two']['finding'] and r[k]['tpe'] == r['two']['tpe'] and r[k]['ptreq'] == r['two']['ptreq'] for k in ['one', 'none', 'restored', 'dangling', 'after']), {k: r[k]['finding']['number'] for k in r})
print('RESULT: %d passed, %d failed' % (passed, failed))
ui.app('global')
sys.exit(1 if failed else 0)
