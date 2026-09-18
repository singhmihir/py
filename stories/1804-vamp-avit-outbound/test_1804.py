"""Checks the VAMP outbound build on the PDI against the two fixture items: the two properties, payload
shape with the sections nested from the dotted json names and every value (A), an item with nothing
linked (B), and the rule firing on a real update and a real insert with the processor and producer
messages (C). Run twice."""
import os, sys, json, re, html
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ST = json.load(open(os.path.join(HERE, 'state.json'))); FX = json.load(open(os.path.join(HERE, 'fixtures.json')))
P = 'x_196061_bofasim'
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
            end = json.JSONDecoder().raw_decode(s, start)[1]
            s = s[:end]
        messages.append(s)
    return json.loads(m.group(1)), messages
def check(name, ok, detail=''):
    global passed, failed
    ok = bool(ok)
    passed += ok; failed += (not ok)
    print(('  ok   ' if ok else '  FAIL ') + name + ('' if ok else '  -> ' + str(detail)[:600]))
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
STAMP = re.compile(r'^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}$')
ENVELOPE = ['type', 'topic_name', 'namespace', 'core_version', 'outbound_version', 'event_id', 'event_timestamp', 'element_count', 'element_activity']
SECTIONS = ['finding', 'tpe', 'remediation_task', 'ait', 'ci', 'exception', 'consequence', 'ptreq']
FIELDS = {'finding': ['number', 'sys_created_on', 'sys_updated_on', 'state', 'configuration_item', 'u_verification_status', 'source_avit_id'], 'tpe': ['number'],
          'remediation_task': ['number', 'primary_ait'], 'ait': ['number'], 'ci': ['name', 'class_name'], 'exception': ['number', 'approval_state', 'desired_validity_date'],
          'consequence': ['number', 'state', 'u_consequence_level'], 'ptreq': ['number', 'sys_created_on', 'u_assessment_id']}

def build(sys_id):
    r, messages = js('''
var o = {};
var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(%s);
var before = new GlideAggregate('syslog_app_scope'); before.addAggregate('COUNT'); before.addQuery('message', 'CONTAINS', 'BOFASIVampOutboundProcessor'); before.query(); before.next(); o.errors_before = parseInt(before.getAggregate('COUNT'));
o.text = new x_196061_bofasim.BOFASIVampOutboundProcessor().buildPayload(a);
var after = new GlideAggregate('syslog_app_scope'); after.addAggregate('COUNT'); after.addQuery('message', 'CONTAINS', 'BOFASIVampOutboundProcessor'); after.query(); after.next(); o.errors_after = parseInt(after.getAggregate('COUNT'));
function stamp(v) { if (!v) return ''; var g = new GlideDateTime(v); return g.getDate().getByFormat('MM-dd-yyyy') + ' ' + g.getTime().getByFormat('HH:mm:ss'); }
o.expect = {number: '' + a.getValue('number'), created: stamp(a.getValue('sys_created_on')), updated: stamp(a.getValue('sys_updated_on')), state: '' + a.getDisplayValue('state'), ci: '' + a.getDisplayValue('cmdb_ci'),
    src: '' + (a.getValue('source_avit_id') || ''), mod: parseInt(a.getValue('sys_mod_count')), ait: '' + a.application_release.u_primary_ait.getDisplayValue(), ci_name: '' + a.cmdb_ci.name, ci_class: '' + a.cmdb_ci.sys_class_name.getDisplayValue(),
    exc: '' + a.getDisplayValue('change_approval'), exc_state: '' + a.change_approval.approval_state.getDisplayValue(), exc_until: stamp(a.change_approval.desired_validity_date.getValue()),
    cons: '' + a.getDisplayValue('u_consequence'), cons_state: '' + a.u_consequence.state.getDisplayValue(), cons_level: '' + a.u_consequence.u_consequence_level.getDisplayValue(),
    ptreq: '' + a.getDisplayValue('assessment_request'), ptreq_created: stamp(a.assessment_request.sys_created_on.getValue())};
var m = new GlideRecord('sn_vul_app_m2m_vul_group_item'); m.addQuery('sn_vul_app_vulnerable_item', a.getUniqueValue()); m.orderByDesc('sys_created_on'); m.query(); o.expect.avul = m.next() ? '' + m.getDisplayValue('sn_vul_app_vulnerability') : '';
o.vamp_props = []; var p = new GlideRecord('sys_properties'); p.addQuery('name', 'STARTSWITH', 'x_196061_bofasim.usem.vamp.'); p.orderBy('name'); p.query(); while (p.next()) o.vamp_props.push('' + p.getValue('name'));
gs.print('X::' + JSON.stringify(o));''' % json.dumps(sys_id))
    r['messages'] = messages
    return r

def shape(tag, r):
    p = json.loads(r['text']); e = p['envelope']
    check(tag + ' exactly two properties: topic and the AVIT field mapping', r['vamp_props'] == [P + '.usem.vamp.finding.fields.sn_vul_app_vulnerable_item', P + '.usem.vamp.kafka.topic_sys_id'], r['vamp_props'])
    check(tag + ' payload is JSON with envelope and findings only', sorted(p.keys()) == ['envelope', 'findings'], list(p.keys()))
    check(tag + ' envelope keys in order', list(e.keys()) == ENVELOPE, list(e.keys()))
    check(tag + ' envelope constants', (e['type'], e['topic_name'], e['namespace'], e['core_version'], e['outbound_version'], e['element_count']) == ('record', 'sn_usem_verification_outbound', 'com.bofa.usem', '1.0.0', '1.0.0', 1), e)
    check(tag + ' event_id is a UUID and timestamp is UTC ISO', bool(UUID.match(e['event_id'])) and bool(re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', e['event_timestamp'])), e)
    check(tag + ' one element with the eight sections nested from the dotted json names, in property order', len(p['findings']) == 1 and list(p['findings'][0].keys()) == SECTIONS and all(isinstance(p['findings'][0][s], dict) for s in SECTIONS), list(p['findings'][0].keys()) if p['findings'] else p)
    el = p['findings'][0]
    for s in SECTIONS:
        check(tag + ' section %s carries its mapped json fields in order' % s, list(el[s].keys()) == FIELDS[s], list(el[s].keys()))
    check(tag + ' every value is a string', all(isinstance(v, str) for s in SECTIONS for v in el[s].values()), el)
    check(tag + ' no processor error logged', r['errors_after'] == r['errors_before'], (r['errors_before'], r['errors_after']))
    expected = 'VAMP payload for ' + json.loads(r['text'])['findings'][0]['finding']['number'] + ': ' + r['text']
    diff = next((i for i in range(min(len(expected), len(r['messages'][0]))) if expected[i] != r['messages'][0][i]), None) if r['messages'] else None
    check(tag + ' one info message holds exactly the payload', r['messages'] == [expected], (len(r['messages']), diff, [len(x) for x in r['messages']], len(expected), [x[-60:] for x in r['messages']], expected[-60:]))
    return p, el, e

for run in (1, 2):
    print('== run', run)
    print('A. linked fixture', FX['linked_number'])
    r = build(FX['linked']); x = r['expect']
    p, el, e = shape('A', r)
    check('A element_activity from sys_mod_count', e['element_activity'] == ('UPDATE' if x['mod'] > 0 else 'INSERT'), (e['element_activity'], x['mod']))
    f = el['finding']
    check('A finding number/state/ci/source', (f['number'], f['state'], f['configuration_item'], f['source_avit_id']) == (x['number'], x['state'], x['ci'], 'VAMP-FIXTURE-001'), f)
    check('A finding dates MM-dd-yyyy HH:mm:ss', f['sys_created_on'] == x['created'] and f['sys_updated_on'] == x['updated'] and STAMP.match(f['sys_created_on']), (f, x['created'], x['updated']))
    check('A finding field missing on the table is ""', f['u_verification_status'] == '', f)
    check('A tpe number "" (sn_vul_entry has no number field)', el['tpe'] == {'number': ''}, el['tpe'])
    check('A remediation task through the group item table', el['remediation_task'] == {'number': x['avul'], 'primary_ait': ''} and x['avul'] == FX['avul'], (el['remediation_task'], x['avul']))
    check('A ait via application_release.u_primary_ait', el['ait'] == {'number': x['ait']} and x['ait'] == 'AIT57152', (el['ait'], x['ait']))
    check('A ci name and class display', el['ci'] == {'name': x['ci_name'], 'class_name': x['ci_class']} and x['ci_name'] == 'Trade Processing Portal', (el['ci'], x['ci_name'], x['ci_class']))
    check('A exception number/state/validity', el['exception'] == {'number': x['exc'], 'approval_state': x['exc_state'], 'desired_validity_date': x['exc_until']} and x['exc'] == FX['exception_number'] and x['exc_state'] == 'Approved' and x['exc_until'] == '03-31-2027 00:00:00', (el['exception'], x))
    check('A consequence number/state/level', el['consequence'] == {'number': x['cons'], 'state': x['cons_state'], 'u_consequence_level': x['cons_level']} and x['cons'] == 'CONSEQ-L2-OPEN', (el['consequence'], x))
    check('A ptreq number/created/assessment id', el['ptreq'] == {'number': x['ptreq'], 'sys_created_on': x['ptreq_created'], 'u_assessment_id': ''} and x['ptreq'] == 'PTREQ0012001' and STAMP.match(x['ptreq_created']), (el['ptreq'], x))

    print('B. bare fixture', FX['bare_number'])
    r = build(FX['bare']); x = r['expect']
    p, el, e = shape('B', r)
    blanks = {s: all(v == '' for v in el[s].values()) for s in SECTIONS if s != 'finding'}
    check('B every linked section renders "" for every field', all(blanks.values()), blanks)
    check('B finding still carries its own values', el['finding']['number'] == x['number'] and el['finding']['state'] == x['state'] and el['finding']['configuration_item'] == '' and el['finding']['source_avit_id'] == '', el['finding'])

    print('C. rule on a real update and a real insert')
    r, messages = js('''
var o = {};
function count(text) { var c = new GlideAggregate('syslog_app_scope'); c.addAggregate('COUNT'); c.addQuery('message', 'CONTAINS', text); c.query(); c.next(); return parseInt(c.getAggregate('COUNT')); }
var linked = %(linked)s;
o.before = {producer: count('BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item.' + linked), processor: count('BOFASIVampOutboundProcessor: payload not built'), rule: count('BOFA_BR_AVIT_VampOutbound')};
var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(linked); a.setValue('short_description', 'VAMP outbound fixture (linked) run %(run)s'); a.update();
o.after_update = {producer: count('BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item.' + linked), processor: count('BOFASIVampOutboundProcessor: payload not built'), rule: count('BOFA_BR_AVIT_VampOutbound')};
var log = new GlideRecord('syslog_app_scope'); log.addQuery('message', 'CONTAINS', 'BOFASIKafkaProducerVamp: message not sent for sn_vul_app_vulnerable_item.' + linked); log.orderByDesc('sys_created_on'); log.setLimit(1); log.query(); log.next();
o.producer_log = {level: '' + log.getValue('level'), message: '' + log.getValue('message'), source: '' + log.getValue('source'), age_s: (new GlideDateTime().getNumericValue() - new GlideDateTime(log.getValue('sys_created_on')).getNumericValue()) / 1000};
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
    check('C two info messages on the page, one per item, nothing else', len(messages) == 2 and sorted(payloads) == sorted([FX['linked_number'], r['inserted']['number']]), messages)
    upd = payloads.get(FX['linked_number']); ins = payloads.get(r['inserted']['number'])
    check('C update: info message shows the payload with element_activity UPDATE', bool(upd) and upd['envelope']['element_activity'] == 'UPDATE' and upd['findings'][0]['finding']['number'] == FX['linked_number'] and upd['findings'][0]['ait'] == {'number': 'AIT57152'}, upd)
    check('C insert: producer logged one send failure for the new item', r['after_insert']['producer'] == 1 and r['after_insert']['processor'] == r['before']['processor'] and r['after_insert']['rule'] == r['before']['rule'], (r['before'], r['after_insert']))
    check('C insert: info message shows the payload with element_activity INSERT and the new number', bool(ins) and ins['envelope']['element_activity'] == 'INSERT' and ins['findings'][0]['finding']['number'] == r['inserted']['number'] and ins['findings'][0]['finding']['source_avit_id'] == 'VAMP-FIXTURE-INSERT', ins)
    check('C insert: fixture retired afterwards', r['retired'] == '0', r['retired'])
    print('  inserted item', r['inserted']['number'], '| update payload:', json.dumps(upd)[:900] if upd else None)
print('RESULT: %d passed, %d failed' % (passed, failed))
ui.app('global')
sys.exit(1 if failed else 0)
