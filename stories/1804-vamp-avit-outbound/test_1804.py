"""Checks the VAMP outbound build on the PDI against the sheet "SN to VAMP" and the fixture items:
the one field property holds the sheet rows with the resolved ServiceNow fields, the payload carries
the sheet's JSON structure names with the sheet's field names per section and every value, the remediation tasks
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
    check(tag + ' one field property holding exactly the sheet rows, the topic property the only other one', {k: v for k, v in r['props'].items() if not k.endswith('topic_sys_id')} == expected_props and len(r['props']) == 2 and list(expected_props) == [P + '.usem.vamp.fields.' + ITEM], r['props'])
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
    check(tag + ' the payload is the only info message', r['messages'][1:] == [], r['messages'][1:])
    return p, el, e

for run in (1, 2):
    print('== run', run)
    print('A. linked fixture', FX['linked_number'], 'with two remediation tasks')
    r = build(FX['linked']); x = r['expect']
    p, el, e = shape('A', r)
    check('A element_activity from sys_mod_count', e['element_activity'] == ('UPDATE' if x['mod'] > 0 else 'INSERT'), (e['element_activity'], x['mod']))
    f = el['finding']
    check('A finding number, state as the stored integer, source_avit_id', (f['number'], f['state'], f['source_avit_id']) == (x['number'], x['state'], FX['source_avit_id']) and x['state'] == '1', (f, x))
    check('A finding dates MM-dd-yyyy HH:mm:ss', f['sys_created_on'] == x['created'] and f['sys_updated_on'] == x['updated'] and STAMP.match(f['sys_created_on']), (f, x['created'], x['updated']))
    check('A configuration_item resolves through cmdb_ci to the display value Trade Processing Portal', f['configuration_item'] == x['ci_display'] == 'Trade Processing Portal' and len(x['ci']) == 32 and not x['has_ci_field'], (f['configuration_item'], x))
    check('A the two custom finding fields carry their values', (f['u_verification_status'], f['u_avit_record_url']) == (x['status'], x['url']) and x['status'] == 'Pending Validation' and x['url'].endswith(FX['source_avit_id']), (f, x))
    check('A tpe read from the entry class: the sub category id of sn_vul_app_vul_entry, never on sn_vul_entry', el['tpe']['u_vuln_sub_cat_id'] == x['entry_sub_cat'] == FX['entry_sub_cat'] and x['entry_class'] == 'sn_vul_app_vul_entry' and not x['entry_sub_cat_on_base'], (el['tpe'], x))
    check('A tpe number "" (no number field on the entry table here) and the entry is the linked one', el['tpe']['number'] == '' and not x['entry_has_number_on_class'] and x['entry_display'] == FX['entry_display'], (el['tpe'], x))
    check('A remediation_task holds both tasks, in task number order', [t['number'] for t in el['remediation_task']] == [t['number'] for t in x['tasks']] == FX['task_numbers'] and len(el['remediation_task']) == 2, (el['remediation_task'], x['tasks']))
    check('A every task carries its own record url and its own Primary AIT as a display value', [t['u_avul_record_url'] for t in el['remediation_task']] == FX['task_urls'] and [t['primary_ait'] for t in el['remediation_task']] == FX['task_aits'] and len(set(FX['task_aits'])) == 2, el['remediation_task'])
    if run == 1:
        SAMPLE = p
    check('A ptreq number, created, assessment id', el['ptreq'] == {'number': x['ptreq'], 'sys_created_on': x['ptreq_created'], 'u_assessment_id': x['ptreq_assessment']} and x['ptreq'] == 'PTREQ0012001' and x['ptreq_assessment'] == FX['ptreq_assessment'] and STAMP.match(x['ptreq_created']), (el['ptreq'], x))

    print('B. bare fixture', FX['bare_number'])
    r = build(FX['bare']); x = r['expect']
    p, el, e = shape('B', r)
    check('B remediation_task is an empty list', el['remediation_task'] == [] and x['tasks'] == [], (el['remediation_task'], x['tasks']))
    check('B the payload is the only info message', r['messages'][1:] == [], r['messages'][1:])
    check('B tpe and ptreq render "" for every field', all(v == '' for k in ['tpe', 'ptreq'] for v in el[k].values()), el)
    check('B finding still carries its own values, configuration_item "" with no CI', el['finding']['number'] == x['number'] and el['finding']['state'] == '1' and el['finding']['source_avit_id'] == '' and el['finding']['configuration_item'] == '' and x['ci'] == '', el['finding'])

    print('C. rule on a real update and a real insert')
    r, messages = js('''
var o = {};
function count(text) { var c = new GlideAggregate('syslog_app_scope'); c.addAggregate('COUNT'); c.addQuery('message', 'CONTAINS', text); c.query(); c.next(); return parseInt(c.getAggregate('COUNT')); }
var linked = %(linked)s;
o.before = {producer: count('BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item ' + linked), processor: count('BOFASIVampOutboundProcessor: payload not built'), rule: count('BOFA_BR_AVIT_VampOutbound')};
var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(linked); a.setValue('short_description', 'VAMP outbound fixture (linked) run %(run)s at ' + new GlideDateTime().getNumericValue()); a.update();
o.after_update = {producer: count('BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item ' + linked), processor: count('BOFASIVampOutboundProcessor: payload not built'), rule: count('BOFA_BR_AVIT_VampOutbound')};
var log = new GlideRecord('syslog_app_scope'); log.addQuery('message', 'CONTAINS', 'BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item ' + linked); log.orderByDesc('sys_created_on'); log.setLimit(1); log.query(); log.next();
o.producer_log = {level: '' + log.getValue('level'), message: '' + log.getValue('message'), age_s: (new GlideDateTime().getNumericValue() - new GlideDateTime(log.getValue('sys_created_on')).getNumericValue()) / 1000};
var n = new GlideRecord('sn_vul_app_vulnerable_item'); n.initialize(); n.setValue('short_description', 'VAMP outbound fixture (inserted, run %(run)s)'); n.setValue('source', 'VAMP fixture'); n.setValue('source_avit_id', 'VAMP-FIXTURE-INSERT'); var nid = n.insert();
o.inserted = {sys_id: '' + nid, number: '' + n.getValue('number')};
o.after_insert = {producer: count('BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item ' + nid), processor: count('BOFASIVampOutboundProcessor: payload not built'), rule: count('BOFA_BR_AVIT_VampOutbound')};
var c = new GlideRecord('sn_vul_app_vulnerable_item'); c.get(nid); c.setWorkflow(false); c.setValue('active', false); c.setValue('short_description', 'VAMP outbound fixture (inserted, retired)'); c.update(); o.retired = '' + c.getValue('active');
gs.print('X::' + JSON.stringify(o));''' % dict(linked=json.dumps(FX['linked']), run=run))
    check('C update: producer logged one send failure for the item (rule -> processor -> producer ran)', r['after_update']['producer'] == r['before']['producer'] + 1, (r['before'], r['after_update']))
    check('C update: no processor or rule error', r['after_update']['processor'] == r['before']['processor'] and r['after_update']['rule'] == r['before']['rule'], (r['before'], r['after_update']))
    check('C update: producer error names the item and the missing Kafka API reason, logged just now', 'sn_vul_app_vulnerable_item ' + FX['linked'] + ' - ' in r['producer_log']['message'] and ('sn_ih_kafka' in r['producer_log']['message'] or 'undefined is not a function' in r['producer_log']['message']) and r['producer_log']['age_s'] < 180, r['producer_log'])
    payloads = {}
    for msg in messages:
        mm = re.match(r'VAMP payload for (\S+): (\{.*\})$', msg)
        if mm:
            payloads[mm.group(1)] = json.loads(mm.group(2))
    check('C info messages on the page: one payload per item, nothing else', sorted(payloads) == sorted([FX['linked_number'], r['inserted']['number']]) and len(messages) == len(payloads), (len(messages), len(payloads), messages))
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
var dictionary = new GlideRecord('sn_vul_app_vulnerable_item');
for (var i = 0; i < fields.length; i++) o.rendered[fields[i]] = processor._fieldValue(withDate, dictionary, fields[i]);
o.no_record = processor._fieldValue(null, null, 'number');
var savedCi = '' + withDate.getValue('cmdb_ci');
var gone = new GlideRecord('sn_vul_app_vulnerable_item'); gone.get(a.getUniqueValue());
gone.setWorkflow(false); gone.setValue('cmdb_ci', '00000000000000000000000000000000'); gone.update();
var broken = new GlideRecord('sn_vul_app_vulnerable_item'); broken.get(a.getUniqueValue());
o.dangling_reference = processor._fieldValue(broken, dictionary, 'cmdb_ci');
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
    FIELD_PROP = P + '.usem.vamp.fields.' + ITEM; TOPIC_PROP = P + '.usem.vamp.kafka.topic_sys_id'
    base = PROPS['usem.vamp.fields.' + ITEM]['value']
    CASES = {
        'no_property': '', 'separators': ' ,\n , \r\n,',
        'no_field': '=finding.number,\n' + base, 'no_payload_name': 'number,\n' + base, 'flat_name': 'number=finding,\n' + base,
        'empty_structure': 'number=.number,\n' + base, 'empty_field': 'number=finding.,\n' + base, 'three_parts': 'number=finding.a.b,\n' + base,
        'two_tables': base + '\nsn_vul_pen_test_assessment_request.number=finding.number_again,', 'twice': base + '\nsys_created_by=finding.number,',
        'no_path': base.replace('sn_vul_app_vul_entry.', 'sn_vul_app_vul_scan.'), 'dot_walk': 'cmdb_ci.name=finding.ci_name,\n' + base,
        'left_empty_field': 'sn_vul_app_vul_entry.=tpe.extra,\n' + base, 'two_equals': 'number=finding.number=again,\n' + base,
        'spaced': base.replace('number=finding.number,', ' number = finding . number ,'),
        'journal': base + '\n' + FX['journal_field'] + '=finding.' + FX['journal_field'] + ',',
    }
    line = lambda k: CASES[k].split('\n')[0]
    REASONS = {
        'no_property': 'table %s is not configured in property %s' % (ITEM, FIELD_PROP), 'separators': 'property %s holds no field' % FIELD_PROP,
        'no_field': 'property %s holds a line without a field name: "=finding.number"' % FIELD_PROP,
        'no_payload_name': 'property %s holds a line without a payload name: "number"' % FIELD_PROP,
        'flat_name': 'property %s holds the payload name "finding", which is not <structure>.<field>: "number=finding"' % FIELD_PROP,
        'empty_structure': 'property %s holds the payload name ".number", which is not <structure>.<field>: "number=.number"' % FIELD_PROP,
        'empty_field': 'property %s holds the payload name "finding.", which is not <structure>.<field>: "number=finding."' % FIELD_PROP,
        'three_parts': 'property %s holds the payload name "finding.a.b", which is not <structure>.<field>: "number=finding.a.b"' % FIELD_PROP,
        'two_tables': 'section finding of property %s takes fields from %s and from sn_vul_pen_test_assessment_request' % (FIELD_PROP, ITEM),
        'twice': 'section finding of property %s names number twice' % FIELD_PROP,
        'no_path': 'property %s names table sn_vul_app_vul_scan, which has no path from %s: "sn_vul_app_vul_scan.number=tpe.number"' % (FIELD_PROP, ITEM),
        'dot_walk': 'property %s names table cmdb_ci, which has no path from %s: "cmdb_ci.name=finding.ci_name"' % (FIELD_PROP, ITEM),
        'left_empty_field': 'property %s holds the field "sn_vul_app_vul_entry.", which is not <field> or <table>.<field>: "sn_vul_app_vul_entry.=tpe.extra"' % FIELD_PROP,
        'two_equals': 'property %s holds a line with more than one "=": "number=finding.number=again"' % FIELD_PROP,
    }
    r, _ = js(r"""
(function() {
var o = {cases: {}};
gs.sleep(1100); var t0 = new GlideDateTime().getValue();
new GlideUpdateSet().set(%(default_set)s);
try { new sn_ih_kafka.ProducerV2(); o.api_missing = ''; } catch (e) { o.api_missing = '' + (e.message || e); }
var T = %(item)s, FIELDS = %(fields)s, TOPIC = %(topic)s, cases = %(cases)s;
var C = x_boar_bofa_usem_1.BOFASIVampOutboundProcessor, K = x_boar_bofa_usem_1.BOFASIKafkaProducerVamp;
var a = new GlideRecord(T); a.get(%(linked)s);
var good = new C().buildPayload(a);
o.unfetched = new C().buildPayload(new GlideRecord(T));
o.nothing = new C().buildPayload(null);
var fp = new GlideRecord('sys_properties'); fp.addQuery('name', FIELDS); fp.query(); fp.next(); var saved = '' + (fp.getValue('value') || '');
try {
    for (var k in cases) { fp.setValue('value', cases[k]); fp.update(); o.cases[k] = new C().buildPayload(a); }
} finally {
    fp.setValue('value', saved); fp.update();
}
o.fields_restored = gs.getProperty(FIELDS, '') == saved;
// the validation runs inside buildPayload: an envelope built off its constants is refused there
var off = new C(); var build = off._buildEnvelope; off._buildEnvelope = function(activity, count) { var e = build.call(this, activity, count); e.namespace = 'com.other'; return e; };
o.off_constants = off.buildPayload(a);
var proc = new C(), sections = proc._payloadMap(T);
function refusal(p) { try { proc._validatePayload(p, sections, a); return 'accepted'; } catch (e) { return '' + (e.message || e); } }
var t1 = JSON.parse(good);
t1.envelope.element_count = 2; t1.envelope.event_id = 'not-a-uuid'; t1.envelope.element_activity = 'CHANGED';
delete t1.findings[0].finding.number; t1.findings[0].finding.state = 1; t1.findings[0].finding.stranger = 'x';
t1.findings[0].remediation_task = {}; t1.findings[0].extra = {};
o.tampered = refusal(t1);
var t2 = JSON.parse(good); t2.envelope.core_version = '9.9.9'; t2.envelope.event_timestamp = '2026-09-22 10:00:00'; delete t2.findings[0].tpe; t2.findings[0].ptreq = 'x'; t2.findings[0].remediation_task.push('x');
o.tampered2 = refusal(t2);
var t3 = JSON.parse(good); t3.findings = []; o.tampered3 = refusal(t3);
o.intact = refusal(JSON.parse(good));
var tp = new GlideRecord('sys_properties'); tp.addQuery('name', TOPIC); tp.query(); tp.next(); var topic = '' + (tp.getValue('value') || '');
try {
    tp.setValue('value', ''); tp.update(); new K().sendPayload(good, a);
    tp.setValue('value', 'not-a-sys-id'); tp.update(); new K().sendPayload(good, a);
    tp.setValue('value', '  ' + topic + ' \n'); tp.update(); new K().sendPayload(good, a);
} finally {
    tp.setValue('value', topic); tp.update();
}
o.topic_restored = gs.getProperty(TOPIC, '') == topic;
new K().sendPayload('', a);
new K().sendPayload('not json', a);
new K().sendPayload('{"a": 1}', a);
new K().sendPayload('{"envelope": {"element_count": 0}, "findings": []}', a);
var miscount = JSON.parse(good); miscount.envelope.element_count = 5; new K().sendPayload(JSON.stringify(miscount), a);
new K().sendPayload(good, null);
var unsaved = new GlideRecord(T); unsaved.newRecord(); o.unsaved = unsaved.getUniqueValue(); new K().sendPayload(good, unsaved);
o.id = a.getUniqueValue();
o.lines = [];
var l = new GlideRecord('syslog'); l.addQuery('sys_created_on', '>=', t0); l.addQuery('message', 'STARTSWITH', 'BOFASIVampOutboundProcessor').addOrCondition('message', 'STARTSWITH', 'BOFASIKafkaProducerVamp').addOrCondition('message', 'STARTSWITH', 'BOFA_BR_AVIT_VampOutbound'); l.addQuery('sys_created_by', gs.getUserName()); l.query();
while (l.next()) o.lines.push('' + l.getValue('message'));
gs.print('X::' + JSON.stringify(o));
})();""" % dict(default_set=json.dumps(ST['default_set']), item=json.dumps(ITEM), fields=json.dumps(FIELD_PROP), topic=json.dumps(TOPIC_PROP), cases=json.dumps(CASES), linked=json.dumps(FX['linked'])))
    spaced = json.loads(r['cases']['spaced']) if r['cases']['spaced'] else {}
    journal = json.loads(r['cases']['journal'])['findings'][0]['finding'] if r['cases']['journal'] else {}
    check('E a journal field is sent as its latest entry, without its header, on a record loaded afresh', journal.get(FX['journal_field']) == FX['latest_comment'], journal.get(FX['journal_field']))
    check('E spaces round the "=" and round the dot of a payload name are ignored: the same finding as the property as delivered', bool(spaced) and spaced['findings'][0]['finding'] == json.loads(build(FX['linked'])['text'])['findings'][0]['finding'], r['cases']['spaced'][:200])
    check('E every refused property gives "", as do an unfetched record, no record and an envelope off its constants', all(r['cases'][k] == '' for k in REASONS) and r['unfetched'] == '' and r['nothing'] == '' and r['off_constants'] == '',
          {k: r['cases'][k][:40] for k in REASONS if r['cases'][k]})
    V = 'BOFASIKafkaProducerVamp: message not sent for %s %s - ' % (ITEM, r['id']); B = 'BOFASIVampOutboundProcessor: payload not built for %s %s - ' % (ITEM, r['id'])
    want = [B + REASONS[k] for k in REASONS] + ['BOFASIVampOutboundProcessor: payload not built for no record - no record was given',
            B + 'payload invalid for %s: the envelope does not carry the configured constants' % FX['linked_number'],
            V + 'property %s holds no topic' % TOPIC_PROP, V + 'property %s holds "not-a-sys-id", which is not a sys_id' % TOPIC_PROP, V + r['api_missing'],
            V + 'the payload is empty', V + 'the payload is not JSON', V + 'the payload has no envelope or no findings', V + 'the payload carries no finding',
            V + 'the payload counts 5 element(s) and carries 1', 'BOFASIKafkaProducerVamp: message not sent for no record - no record was given',
            'BOFASIKafkaProducerVamp: message not sent for %s %s - no record was given' % (ITEM, r['unsaved'])]
    unfetched = [m for m in r['lines'] if m.startswith('BOFASIVampOutboundProcessor: payload not built for %s ' % ITEM) and m.endswith(' - the record does not exist')]
    others = [m for m in r['lines'] if m not in unfetched]
    check('E one exact line per refusal (%d): every parser refusal, the validation inside buildPayload, the producer refusals, the padded topic trimmed (the send reached), nothing else' % (len(want) + 1),
          len(unfetched) == 1 and sorted(others) == sorted(want) and r['api_missing'] != '', 'extra: %s | missing: %s' % ([m for m in others if m not in want], [m for m in want if m not in others]))
    check('E validation names every problem of a tampered payload', all(x in r['tampered'] for x in ['payload invalid', 'event_id is not a UUID', 'element_activity "CHANGED"', 'element_count 2', 'finding.number is missing', 'finding.state is not a string', 'carries "stranger"', 'section remediation_task is not a list', 'carries "extra"']), r['tampered'])
    check('E validation also names constants, timestamp, a missing section, a section that is not an object and a task entry that is not an object', all(x in r['tampered2'] for x in ['the envelope does not carry the configured constants', 'event_timestamp is not a UTC timestamp', 'section tpe is missing', 'section ptreq is not an object', 'section remediation_task is not an object']), r['tampered2'])
    check('E validation refuses a message without a finding; accepts the intact payload; both properties restored', 'the message carries no finding' in r['tampered3'] and r['intact'] == 'accepted' and r['fields_restored'] and r['topic_restored'], (r['tampered3'], r['intact']))

    print('E2. the rule stops when the processor refuses')
    r, messages = js(r"""
(function() {
var o = {};
gs.sleep(1100); var t0 = new GlideDateTime().getValue();
new GlideUpdateSet().set(%(default_set)s);
var fp = new GlideRecord('sys_properties'); fp.addQuery('name', %(fields)s); fp.query(); fp.next(); var saved = '' + (fp.getValue('value') || '');
var a = new GlideRecord(%(item)s); a.get(%(linked)s); var keep = '' + a.getValue('short_description');
try {
    fp.setValue('value', ''); fp.update();
    a.setValue('short_description', 'VAMP outbound fixture (linked) refused run ' + new GlideDateTime().getNumericValue()); a.update();
} finally {
    fp.setValue('value', saved); fp.update();
    var back = new GlideRecord(%(item)s); back.get(%(linked)s); back.setWorkflow(false); back.setValue('short_description', keep); back.update();
}
o.restored = gs.getProperty(%(fields)s, '') == saved;
o.lines = [];
var l = new GlideRecord('syslog'); l.addQuery('sys_created_on', '>=', t0); l.addQuery('message', 'STARTSWITH', 'BOFASIVampOutboundProcessor').addOrCondition('message', 'STARTSWITH', 'BOFASIKafkaProducerVamp').addOrCondition('message', 'STARTSWITH', 'BOFA_BR_AVIT_VampOutbound'); l.addQuery('sys_created_by', gs.getUserName()); l.query();
while (l.next()) o.lines.push('' + l.getValue('message'));
gs.print('X::' + JSON.stringify(o));
})();""" % dict(default_set=json.dumps(ST['default_set']), item=json.dumps(ITEM), fields=json.dumps(FIELD_PROP), linked=json.dumps(FX['linked'])))
    check('E2 a real update with the property empty: the processor logs its reason once, the producer is never called, nothing is shown on the page',
          r['lines'] == ['BOFASIVampOutboundProcessor: payload not built for %s %s - %s' % (ITEM, FX['linked'], REASONS['no_property'])] and not [m for m in messages if m.startswith('VAMP payload for')] and r['restored'], (r['lines'], messages))

    print('F. how many remediation tasks the item has')
    r, _ = js('''
var o = {};
var processor = new x_boar_bofa_usem_1.BOFASIVampOutboundProcessor();
var linked = %(linked)s, first = %(first)s, second = %(second)s, firstTask = %(first_task)s, secondTask = %(second_task)s;
function set(m2m, value) { var g = new GlideRecord('sn_vul_app_m2m_vul_group_item'); g.get(m2m); g.setWorkflow(false); g.setValue('sn_vul_app_vulnerability', value); g.update(); }
function payload() { var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(linked); return JSON.parse(processor.buildPayload(a)).findings[0]; }
try {
    o.two = payload();
    set(first, secondTask); set(second, firstTask); o.swapped = payload();
    set(first, firstTask); set(second, secondTask);
    set(second, ''); o.one = payload();
    set(first, ''); o.none = payload();
    set(second, secondTask); set(first, firstTask); o.restored = payload();
    set(second, '00000000000000000000000000000000'); o.dangling = payload();
    set(second, firstTask); o.duplicate = payload();
} finally {
    set(first, firstTask); set(second, secondTask);
}
var renumber = new GlideRecord('sn_vul_app_vulnerability'); renumber.get(firstTask); var number = '' + renumber.getValue('number');
try {
    renumber.setWorkflow(false); renumber.setValue('number', 'AVUL0000001'); renumber.update(); o.renumbered = payload();
} finally {
    var undo = new GlideRecord('sn_vul_app_vulnerability'); undo.get(firstTask); undo.setWorkflow(false); undo.setValue('number', number); undo.update();
}
o.after = payload();
o.first_older = firstTask < secondTask;
gs.print('X::' + JSON.stringify(o));''' % dict(linked=json.dumps(FX['linked']), first=json.dumps(FX['m2m']['first']), second=json.dumps(FX['m2m']['second']),
                                               first_task=json.dumps(FX['tasks']['first']), second_task=json.dumps(FX['tasks']['second'])))
    tasks = lambda k: [t['number'] for t in r[k]['remediation_task']]
    check('F two links: both tasks, in task number order', tasks('two') == FX['task_numbers'], tasks('two'))
    check('F the order is the task number, not the order of the links: swapping the two links changes nothing', tasks('swapped') == FX['task_numbers'] and r['swapped']['remediation_task'] == r['two']['remediation_task'], tasks('swapped'))
    check('F one link: only the task still linked, the other gone from the list', tasks('one') == [FX['avul']], (tasks('one'), FX['avul']))
    check('F no link: an empty list, never a missing section', r['none']['remediation_task'] == [] and 'remediation_task' in r['none'], r['none'].get('remediation_task'))
    check('F links restored: both tasks again', tasks('restored') == FX['task_numbers'], tasks('restored'))
    check('F a link whose task is gone is skipped, the other task still sent', len(tasks('dangling')) == 1 and tasks('dangling')[0] in FX['task_numbers'], tasks('dangling'))
    newer = [n for n in FX['task_numbers'] if n != FX['avul']][0]
    check('F both links pointing at one task: that task once', tasks('duplicate') == [FX['avul']], tasks('duplicate'))
    check('F the order follows the task number, not the sys_id or the creation order: the older task (smaller sys_id) carries the larger number and comes last; renumbered below the other, it comes first',
          r['first_older'] and tasks('two') == [newer, FX['avul']] and tasks('renumbered') == ['AVUL0000001', newer], (tasks('two'), tasks('renumbered')))
    check('F after the restore the list is back to both tasks', tasks('after') == FX['task_numbers'], tasks('after'))
    check('F the other three sections do not change with the number of tasks', all(r[k]['finding'] == r['two']['finding'] and r[k]['tpe'] == r['two']['tpe'] and r[k]['ptreq'] == r['two']['ptreq'] for k in ['one', 'none', 'restored', 'dangling', 'duplicate', 'renumbered', 'after']), {k: v['finding']['number'] for k, v in r.items() if isinstance(v, dict)})
    print('G. called from inside a function of a global script and directly')
    r, _ = js('''
(function() {
var o = {};
var C = x_boar_bofa_usem_1.BOFASIVampOutboundProcessor;
function viaFunction(g) { return new C().buildPayload(g); }
var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(%s);
o.nested = viaFunction(a); o.direct = new C().buildPayload(a);
gs.print('X::' + JSON.stringify(o));
})();''' % json.dumps(FX['linked']))
    check('G the same finding on both call paths', bool(r['nested']) and bool(r['direct']) and json.loads(r['nested'])['findings'] == json.loads(r['direct'])['findings'], (r['nested'][:100], r['direct'][:100]))
print('RESULT: %d passed, %d failed' % (passed, failed))
if not failed:   # the sample is written from run 1 only when every check passed
    text = json.dumps(SAMPLE, indent=2)
    assert not re.search(r'probe|fixture|VSO-|' + re.escape(os.environ['SN_USER']), text, re.I), 'test text in the sample'
    open(os.path.join(HERE, 'samples', 'Sample payload - application vulnerable item.json'), 'w').write(text + '\n')
ui.app('global')
sys.exit(1 if failed else 0)
