"""Checks the VAMP outbound build on the PDI against the sheet "SN to VAMP" and the two fixture items:
the field property holds the resolved ServiceNow field on the left and the sheet's payload name on
the right, the topic property is the only other one, the payload carries exactly the sheet payload
names per table and every value, the configuration item resolves through cmdb_ci to its sys_id, and
the fields the instance does not have are named in a second message (A), an item with nothing linked (B), the rule on a real update and a real
insert with the processor and producer messages (C), and rendering by type: references as sys_id,
integers raw, dates formatted, missing or empty as "" (D). Run twice."""
import os, sys, json, re, html
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ST = json.load(open(os.path.join(HERE, 'state.json'))); FX = json.load(open(os.path.join(HERE, 'fixtures.json')))
SHEET = json.load(open(os.path.join(HERE, 'vamp_mapping.json'))); PROPS = json.load(open(os.path.join(HERE, 'properties.json'))); RESOLUTION = json.load(open(os.path.join(HERE, 'field_resolution.json')))
P = 'x_196061_bofasim'
SECTIONS = [(t, t) for t in ['sn_vul_app_vulnerable_item', 'sn_vul_app_vul_entry', 'sn_vul_app_vulnerability', 'sn_vul_pen_test_assessment_request']]
FIELDS = {key: [r['payload'] for r in SHEET if r['table'] == table] for key, table in SECTIONS}
NOT_FOUND = ['%s.%s' % (e['table'], e['payload']) for p in (0, 1) for e in RESOLUTION if not e['field'] and (p == 0) == (e['table'] == 'sn_vul_app_vulnerable_item')]
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
o.text = new x_196061_bofasim.BOFASIVampOutboundProcessor().buildPayload(a);
var after = new GlideAggregate('syslog_app_scope'); after.addAggregate('COUNT'); after.addQuery('message', 'CONTAINS', 'BOFASIVampOutboundProcessor'); after.query(); after.next(); o.errors_after = parseInt(after.getAggregate('COUNT'));
function stamp(v) { if (!v) return ''; var g = new GlideDateTime(v); return g.getDate().getByFormat('MM-dd-yyyy') + ' ' + g.getTime().getByFormat('HH:mm:ss'); }
o.expect = {number: '' + a.getValue('number'), created: stamp(a.getValue('sys_created_on')), updated: stamp(a.getValue('sys_updated_on')), state: '' + a.getValue('state'), mod: parseInt(a.getValue('sys_mod_count')),
    src: '' + (a.getValue('source_avit_id') || ''), has_ci_field: a.isValidField('configuration_item'), has_status_field: a.isValidField('u_verification_status'), ci: '' + (a.getValue('cmdb_ci') || ''), ci_display: '' + a.getDisplayValue('cmdb_ci'),
    ptreq: '' + a.getDisplayValue('assessment_request'), ptreq_created: stamp(a.assessment_request.sys_created_on.getValue()), entry: '' + a.getDisplayValue('vulnerability')};
var m = new GlideRecord('sn_vul_app_m2m_vul_group_item'); m.addQuery('sn_vul_app_vulnerable_item', a.getUniqueValue()); m.orderByDesc('sys_created_on'); m.query(); o.expect.avul = m.next() ? '' + m.getDisplayValue('sn_vul_app_vulnerability') : '';
o.expect.avul_has_ait_field = new GlideRecord('sn_vul_app_vulnerability').isValidField('primary_ait');
o.props = {}; var p = new GlideRecord('sys_properties'); p.addQuery('name', 'STARTSWITH', 'x_196061_bofasim.usem.vamp.'); p.orderBy('name'); p.query(); while (p.next()) o.props['' + p.getValue('name')] = '' + p.getValue('value');
gs.print('X::' + JSON.stringify(o));''' % json.dumps(sys_id))
    r['messages'] = messages
    return r

def shape(tag, r):
    p = json.loads(r['text']); e = p['envelope']
    expected_props = {P + '.' + k: v['value'] for k, v in PROPS.items() if k != 'usem.vamp.kafka.topic_sys_id'}
    check(tag + ' one field property holding exactly the sheet rows, the topic property the only other one', {k: v for k, v in r['props'].items() if not k.endswith('topic_sys_id')} == expected_props and len(r['props']) == 2 and list(expected_props) == [P + '.usem.vamp.fields.sn_vul_app_vulnerable_item'], r['props'])
    check(tag + ' payload is JSON with envelope and findings only', sorted(p.keys()) == ['envelope', 'findings'], list(p.keys()))
    check(tag + ' envelope keys in order', list(e.keys()) == ENVELOPE, list(e.keys()))
    check(tag + ' envelope constants', (e['type'], e['topic_name'], e['namespace'], e['core_version'], e['outbound_version'], e['element_count']) == ('record', 'sn_usem_verification_outbound', 'com.bofa.usem', '1.0.0', '1.0.0', 1), e)
    check(tag + ' event_id is a UUID and timestamp is UTC ISO', UUID.match(e['event_id']) and re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', e['event_timestamp']), e)
    check(tag + ' one element keyed by the four sheet table names in property order', len(p['findings']) == 1 and list(p['findings'][0].keys()) == [k for k, t in SECTIONS], list(p['findings'][0].keys()) if p['findings'] else p)
    el = p['findings'][0]
    for key, table in SECTIONS:
        check(tag + ' %s carries exactly the sheet fields of %s in sheet order' % (key, table), list(el[key].keys()) == FIELDS[key], (list(el[key].keys()), FIELDS[key]))
    check(tag + ' every value is a string', all(isinstance(v, str) for k, t in SECTIONS for v in el[k].values()), el)
    check(tag + ' no processor error logged', r['errors_after'] == r['errors_before'], (r['errors_before'], r['errors_after']))
    check(tag + ' first info message holds exactly the payload', r['messages'][:1] == ['VAMP payload for ' + el['sn_vul_app_vulnerable_item']['number'] + ': ' + r['text']], r['messages'])
    check(tag + ' second info message names the fields this instance does not have, nothing else', r['messages'][1:] == ['VAMP fields not found on this instance, sent as "": ' + ', '.join(NOT_FOUND)] and len(NOT_FOUND) == 4, (r['messages'][1:], NOT_FOUND))
    return p, el, e

for run in (1, 2):
    print('== run', run)
    print('A. linked fixture', FX['linked_number'])
    r = build(FX['linked']); x = r['expect']
    p, el, e = shape('A', r)
    check('A element_activity from sys_mod_count', e['element_activity'] == ('UPDATE' if x['mod'] > 0 else 'INSERT'), (e['element_activity'], x['mod']))
    f = el['sn_vul_app_vulnerable_item']
    check('A finding number, state as the stored integer, source_avit_id', (f['number'], f['state'], f['source_avit_id']) == (x['number'], x['state'], 'VAMP-FIXTURE-001') and x['state'] == '1', (f, x))
    check('A finding dates MM-dd-yyyy HH:mm:ss', f['sys_created_on'] == x['created'] and f['sys_updated_on'] == x['updated'] and STAMP.match(f['sys_created_on']), (f, x['created'], x['updated']))
    check('A configuration_item resolves through cmdb_ci to the sys_id of Trade Processing Portal', f['configuration_item'] == x['ci'] and len(x['ci']) == 32 and x['ci_display'] == 'Trade Processing Portal' and not x['has_ci_field'], (f['configuration_item'], x))
    check('A u_verification_status absent from this instance renders ""', f['u_verification_status'] == '' and not x['has_status_field'], (f, x))
    check('A tpe reached through vulnerability, number "" (no number field on the entry table here)', el['sn_vul_app_vul_entry'] == {'number': ''} and x['entry'] == 'VULNENT123451', (el['sn_vul_app_vul_entry'], x['entry']))
    check('A remediation task through the group item table, primary_ait "" (field absent here)', el['sn_vul_app_vulnerability'] == {'number': x['avul'], 'primary_ait': ''} and x['avul'] == FX['avul'] and not x['avul_has_ait_field'], (el['sn_vul_app_vulnerability'], x))
    check('A ptreq number, created, u_assessment_id ""', el['sn_vul_pen_test_assessment_request'] == {'number': x['ptreq'], 'sys_created_on': x['ptreq_created'], 'u_assessment_id': ''} and x['ptreq'] == 'PTREQ0012001' and STAMP.match(x['ptreq_created']), (el['sn_vul_pen_test_assessment_request'], x))

    print('B. bare fixture', FX['bare_number'])
    r = build(FX['bare']); x = r['expect']
    p, el, e = shape('B', r)
    check('B tpe, remediation_task and ptreq render "" for every field', all(v == '' for k in ['sn_vul_app_vul_entry', 'sn_vul_app_vulnerability', 'sn_vul_pen_test_assessment_request'] for v in el[k].values()), el)
    check('B finding still carries its own values, configuration_item "" with no CI', el['sn_vul_app_vulnerable_item']['number'] == x['number'] and el['sn_vul_app_vulnerable_item']['state'] == '1' and el['sn_vul_app_vulnerable_item']['source_avit_id'] == '' and el['sn_vul_app_vulnerable_item']['configuration_item'] == '' and x['ci'] == '', el['sn_vul_app_vulnerable_item'])

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
    check('C update: producer error carries the key and the missing Kafka API reason, logged just now', 'sn_vul_app_vulnerable_item.' + FX['linked'] + ' - ' in r['producer_log']['message'] and ('sn_ih_kafka' in r['producer_log']['message'] or 'undefined is not a function' in r['producer_log']['message']) and r['producer_log']['age_s'] < 120, r['producer_log'])
    payloads = {}
    for msg in messages:
        mm = re.match(r'VAMP payload for (\S+): (\{.*\})$', msg)
        if mm:
            payloads[mm.group(1)] = json.loads(mm.group(2))
    not_found = [m for m in messages if m.startswith('VAMP fields not found')]
    check('C info messages on the page: one payload per item plus the not-found list (the page shows an identical message once), nothing else', sorted(payloads) == sorted([FX['linked_number'], r['inserted']['number']]) and 1 <= len(not_found) <= 2 and all(m == 'VAMP fields not found on this instance, sent as "": ' + ', '.join(NOT_FOUND) for m in not_found) and len(messages) == len(payloads) + len(not_found), (len(messages), len(payloads), len(not_found), messages))
    upd = payloads.get(FX['linked_number']); ins = payloads.get(r['inserted']['number'])
    check('C update: info message shows the payload with element_activity UPDATE, the sheet sections and the CI sys_id', bool(upd) and upd['envelope']['element_activity'] == 'UPDATE' and upd['findings'][0]['sn_vul_app_vulnerable_item']['number'] == FX['linked_number'] and list(upd['findings'][0].keys()) == [k for k, t in SECTIONS] and len(upd['findings'][0]['sn_vul_app_vulnerable_item']['configuration_item']) == 32, upd)
    check('C insert: producer logged one send failure for the new item', r['after_insert']['producer'] == 1 and r['after_insert']['processor'] == r['before']['processor'] and r['after_insert']['rule'] == r['before']['rule'], (r['before'], r['after_insert']))
    check('C insert: info message shows the payload with element_activity INSERT and the new number', bool(ins) and ins['envelope']['element_activity'] == 'INSERT' and ins['findings'][0]['sn_vul_app_vulnerable_item']['number'] == r['inserted']['number'] and ins['findings'][0]['sn_vul_app_vulnerable_item']['source_avit_id'] == 'VAMP-FIXTURE-INSERT', ins)
    check('C insert: fixture retired afterwards', r['retired'] == '0', r['retired'])

    print('D. rendering by dictionary type')
    r, _ = js('''
var o = {};
var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(%s);
var fields = ['cmdb_ci', 'assessment_request', 'state', 'sys_created_on', 'first_found', 'short_description', 'closed_at', 'no_such_field'];
var processor = new x_196061_bofasim.BOFASIVampOutboundProcessor(); o.rendered = {};
for (var i = 0; i < fields.length; i++) o.rendered[fields[i]] = processor._fieldValue(a, fields[i]);
function stamp(v) { var g = new GlideDateTime(v); return g.getDate().getByFormat('MM-dd-yyyy') + ' ' + g.getTime().getByFormat('HH:mm:ss'); }
var fd = new GlideDate(); fd.setValue(a.getValue('first_found'));
o.expect = {ci: '' + a.getValue('cmdb_ci'), ci_display: '' + a.getDisplayValue('cmdb_ci'), ptreq: '' + a.getValue('assessment_request'), state: '' + a.getValue('state'), state_display: '' + a.getDisplayValue('state'), created: stamp(a.getValue('sys_created_on')), first_found: a.getValue('first_found') ? fd.getByFormat('MM-dd-yyyy') : '', sd: '' + a.getValue('short_description'), closed_empty: a.closed_at.nil()};
gs.print('X::' + JSON.stringify(o));''' % json.dumps(FX['linked']))
    d = r['rendered']; x = r['expect']
    check('D reference fields render the sys_id, not the display value', d['cmdb_ci'] == x['ci'] and len(x['ci']) == 32 and d['cmdb_ci'] != x['ci_display'] and d['assessment_request'] == x['ptreq'] and len(x['ptreq']) == 32, (d, x))
    check('D integer renders the stored value, not the label', d['state'] == x['state'] == '1' and x['state_display'] == 'Open', (d['state'], x))
    check('D date/time MM-dd-yyyy HH:mm:ss and date MM-dd-yyyy', d['sys_created_on'] == x['created'] and d['first_found'] == x['first_found'], (d, x))
    check('D string raw, empty field "", missing field ""', d['short_description'] == x['sd'] and d['closed_at'] == '' and x['closed_empty'] and d['no_such_field'] == '', (d, x))
print('RESULT: %d passed, %d failed' % (passed, failed))
ui.app('global')
sys.exit(1 if failed else 0)
