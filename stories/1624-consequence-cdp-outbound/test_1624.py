"""Checks the consequence outbound build on the PDI against the tab "Outbound to CDP (consequence)"
and the fixture records: the field property holds the resolved ServiceNow field on the left and the
sheet's payload name on the right, the topic property is the only other one, the payload carries
exactly the sheet payload names per table and every value, the references resolve to display
values and the rule section comes through u_rule (A), a consequence with nothing linked (B), the
rule on a real update and a real insert with the processor and producer messages (C), and rendering
by type: references as display value, integers and choices raw, dates formatted, booleans and
strings as stored, missing or empty as "" (D). Run twice. Run 1 writes the sample payload."""
import os, sys, json, re, html
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ST = json.load(open(os.path.join(HERE, 'state.json'))); FX = json.load(open(os.path.join(HERE, 'fixtures.json')))
SHEET = json.load(open(os.path.join(HERE, 'consequence_mapping.json'))); PROPS = json.load(open(os.path.join(HERE, 'properties.json'))); RESOLUTION = json.load(open(os.path.join(HERE, 'field_resolution.json')))
P = 'x_196061_bofasim'
CLIENT_TABLE_PREFIX, PDI_TABLE_PREFIX = 'x_boar_bofa_usem_0_', 'x_196061_bofasim_'
pdi = lambda s: s.replace('x_boar_bofa_usem_0', P)
CONSEQUENCE, RULE = PDI_TABLE_PREFIX + 'consequence', PDI_TABLE_PREFIX + 'consequence_rule'
SECTIONS = [CONSEQUENCE, RULE]
FIELDS = {pdi(t): [r['payload'] for r in SHEET if r['table'] == t] for t in ['x_boar_bofa_usem_0_consequence', 'x_boar_bofa_usem_0_consequence_rule']}
NOT_FOUND = ['%s.%s' % (pdi(e['table']), e['sheet_field']) for p in (0, 1) for e in RESOLUTION if not e['field'] and (p == 0) == (e['table'] == 'x_boar_bofa_usem_0_consequence')]
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
        if s.startswith('Consequence payload for '):
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
var a = new GlideRecord(%(cons)s); a.get(%(id)s);
var before = new GlideAggregate('syslog_app_scope'); before.addAggregate('COUNT'); before.addQuery('message', 'CONTAINS', 'BOFASIConsequenceOutboundProcessor'); before.query(); before.next(); o.errors_before = parseInt(before.getAggregate('COUNT'));
o.text = new x_196061_bofasim.BOFASIConsequenceOutboundProcessor().buildPayload(a);
var after = new GlideAggregate('syslog_app_scope'); after.addAggregate('COUNT'); after.addQuery('message', 'CONTAINS', 'BOFASIConsequenceOutboundProcessor'); after.query(); after.next(); o.errors_after = parseInt(after.getAggregate('COUNT'));
function stamp(v) { if (!v) return ''; var g = new GlideDateTime(v); return g.getDate().getByFormat('MM-dd-yyyy') + ' ' + g.getTime().getByFormat('HH:mm:ss'); }
function raw(g, f) { return '' + (g.getValue(f) || ''); }
o.expect = {sys_id: a.getUniqueValue(), number: raw(a, 'number'), state: raw(a, 'state'), state_display: '' + a.getDisplayValue('state'), level: raw(a, 'u_consequence_level'), party: raw(a, 'u_accountable_party'), comments: raw(a, 'u_comments'),
    freeze: stamp(a.getValue('u_change_freeze_effective_date')), created_by: raw(a, 'sys_created_by'), updated_by: raw(a, 'sys_updated_by'), created: stamp(a.getValue('sys_created_on')), updated: stamp(a.getValue('sys_updated_on')),
    enforcement: raw(a, 'u_enforcement_status'), enforcement_display: '' + a.getDisplayValue('u_enforcement_status'), isolation: stamp(a.getValue('u_network_isolation_effective_date')), rule: '' + a.getDisplayValue('u_rule'), rule_id: raw(a, 'u_rule'),
    ci: a.cmdb_ci.nil() ? '' : '' + a.cmdb_ci.getRefRecord().getDisplayValue(), ci_label: '' + a.getDisplayValue('cmdb_ci'), ci_id: raw(a, 'cmdb_ci'), ci_class: raw(a, 'u_class'), ait: '' + a.getDisplayValue('u_bofa_ait'), ait_id: raw(a, 'u_bofa_ait'), rejection: raw(a, 'u_rejection_reason'), mod: parseInt(a.getValue('sys_mod_count'))};
var r = a.u_rule.getRefRecord(); o.expect.rule_valid = r.isValidRecord();
if (r.isValidRecord()) o.expect.rule_fields = {applies_to: raw(r, 'applies_to'), comments: raw(r, 'comments'), conditions: raw(r, 'conditions'), created_on: stamp(r.getValue('sys_created_on')), screated_by: raw(r, 'sys_created_by'), global_exception: raw(r, 'global_exception'), name: raw(r, 'name'), number: raw(r, 'number'), state: raw(r, 'state'), sys_id: r.getUniqueValue(), table: raw(r, 'table'), updated_on: stamp(r.getValue('sys_updated_on')), updated_by: raw(r, 'sys_updated_by'), valid_from: stamp(r.getValue('valid_from')), valid_to: stamp(r.getValue('valid_to'))};
o.props = {}; var p = new GlideRecord('sys_properties'); p.addQuery('name', 'STARTSWITH', 'x_196061_bofasim.usem.consequence.'); p.orderBy('name'); p.query(); while (p.next()) o.props['' + p.getValue('name')] = '' + p.getValue('value');
gs.print('X::' + JSON.stringify(o));''' % dict(cons=json.dumps(CONSEQUENCE), id=json.dumps(sys_id)))
    r['messages'] = messages
    return r

def shape(tag, r):
    p = json.loads(r['text']); e = p['envelope']
    expected_props = {P + '.' + pdi(k): pdi(v['value']) for k, v in PROPS.items() if k != 'usem.consequence.kafka.topic_sys_id'}
    check(tag + ' one field property holding exactly the sheet rows, the topic property the only other one', {k: v for k, v in r['props'].items() if not k.endswith('topic_sys_id')} == expected_props and len(r['props']) == 2 and list(expected_props) == [P + '.usem.consequence.fields.' + CONSEQUENCE], r['props'])
    check(tag + ' payload is JSON with envelope and consequences only', sorted(p.keys()) == ['consequences', 'envelope'], list(p.keys()))
    check(tag + ' envelope keys in order', list(e.keys()) == ENVELOPE, list(e.keys()))
    check(tag + ' envelope constants', (e['type'], e['topic_name'], e['namespace'], e['core_version'], e['outbound_version'], e['element_count']) == ('record', 'sn_usem_consequence_outbound', 'com.bofa.usem', '1.0.0', '1.0.0', 1), e)
    check(tag + ' event_id is a UUID and timestamp is UTC ISO', UUID.match(e['event_id']) and re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', e['event_timestamp']), e)
    check(tag + ' one element keyed by the two sheet table names in property order', len(p['consequences']) == 1 and list(p['consequences'][0].keys()) == SECTIONS, list(p['consequences'][0].keys()) if p['consequences'] else p)
    el = p['consequences'][0]
    for table in SECTIONS:
        check(tag + ' %s carries exactly the sheet fields in sheet order' % table, list(el[table].keys()) == FIELDS[table], (list(el[table].keys()), FIELDS[table]))
    check(tag + ' every value is a string', all(isinstance(v, str) for t in SECTIONS for v in el[t].values()), el)
    check(tag + ' no processor error logged', r['errors_after'] == r['errors_before'], (r['errors_before'], r['errors_after']))
    check(tag + ' first info message holds exactly the payload', r['messages'][:1] == ['Consequence payload for ' + el[CONSEQUENCE]['number'] + ': ' + r['text']], r['messages'])
    check(tag + ' every sheet field exists on this instance: no not-found message', r['messages'][1:] == [] and NOT_FOUND == [], (r['messages'][1:], NOT_FOUND))
    return p, el, e

for run in (1, 2):
    print('== run', run)
    print('A. linked fixture', FX['linked_number'])
    r = build(FX['linked']); x = r['expect']
    p, el, e = shape('A', r)
    check('A element_activity from sys_mod_count', e['element_activity'] == ('UPDATE' if x['mod'] > 0 else 'INSERT'), (e['element_activity'], x['mod']))
    f = el[CONSEQUENCE]
    check('A number, state and enforcement status as the stored choice values, level and strings as stored', (f['number'], f['state'], f['enforcement_status'], f['consequence_level'], f['accountable_party'], f['comments'], f['rejection_reason']) == (x['number'], x['state'], x['enforcement'], x['level'], x['party'], x['comments'], x['rejection']) and x['state'] == '1' and x['state_display'] == 'Open' and x['enforcement'] == '1' and x['enforcement_display'] == 'Change Frozen' and x['party'] == 'Digest Owner One', (f, x))
    check('A dates MM-dd-yyyy HH:mm:ss, the empty network isolation date ""', f['created_on'] == x['created'] and f['updated_on'] == x['updated'] and f['change_freeze_effective_date'] == x['freeze'] == '09-15-2026 12:40:01' and f['network_isolation_effective_date'] == '' and x['isolation'] == '' and STAMP.match(f['created_on']), (f, x))
    check('A sys_id, created_by and updated_by as stored', f['sys_id'] == x['sys_id'] == FX['linked'] and f['created_by'] == x['created_by'] and f['updated_by'] == x['updated_by'] and len(f['sys_id']) == 32, (f, x))
    check('A references rule and bofa_ait as display values, the document id cmdb_ci as the display value of the record its Class names, not sys_ids', f['rule'] == x['rule'] == 'CQR-FIXTURE-001' and f['cmdb_ci'] == x['ci'] == 'Trade Processing Portal' and x['ci_label'] == 'Business Application: Trade Processing Portal' and x['ci_class'] == 'cmdb_ci_business_app' and f['bofa_ait'] == x['ait'] == 'AIT57152' and len(x['rule_id']) == len(x['ci_id']) == len(x['ait_id']) == 32, (f, x))
    check('A rule section reached through u_rule carries every rule field as stored', el[RULE] == x['rule_fields'] and x['rule_valid'] and x['rule_fields']['sys_id'] == FX['rule'] and x['rule_fields']['table'] == 'x_boar_bofa_usem_0_consequence' and x['rule_fields']['state'] == 'Approved' and x['rule_fields']['valid_from'] == '09-01-2026 00:00:00', (el[RULE], x.get('rule_fields')))
    if run == 1:
        sample = json.loads(r['text'].replace(PDI_TABLE_PREFIX, CLIENT_TABLE_PREFIX).replace(os.environ['SN_USER'], 'admin'))
        json.dump(sample, open(os.path.join(HERE, 'samples', 'Sample payload - consequence.json'), 'w'), indent=2)

    print('B. bare fixture', FX['bare_number'])
    r = build(FX['bare']); x = r['expect']
    p, el, e = shape('B', r)
    check('B rule section renders "" for every field', all(v == '' for v in el[RULE].values()) and not x['rule_valid'], el[RULE])
    check('B consequence carries its own values, references and empty fields ""', el[CONSEQUENCE]['number'] == x['number'] and el[CONSEQUENCE]['state'] == '1' and el[CONSEQUENCE]['sys_id'] == FX['bare'] and all(el[CONSEQUENCE][k] == '' for k in ['rule', 'cmdb_ci', 'bofa_ait', 'consequence_level', 'accountable_party', 'comments', 'change_freeze_effective_date', 'enforcement_status', 'network_isolation_effective_date', 'rejection_reason']), el[CONSEQUENCE])

    print('C. rule on a real update and a real insert')
    r, messages = js('''
var o = {};
function count(text) { var c = new GlideAggregate('syslog_app_scope'); c.addAggregate('COUNT'); c.addQuery('message', 'CONTAINS', text); c.query(); c.next(); return parseInt(c.getAggregate('COUNT')); }
var linked = %(linked)s, T = %(cons)s;
o.before = {producer: count('BOFASIKafkaProducerConsequence: message not sent for ' + T + '.' + linked), processor: count('BOFASIConsequenceOutboundProcessor: payload not built'), rule: count('BOFA_BR_Consequence_CdpOutbound')};
var a = new GlideRecord(T); a.get(linked); a.setValue('u_comments', 'Consequence outbound fixture (linked) run %(run)s at ' + new GlideDateTime().getNumericValue()); a.update();
o.after_update = {producer: count('BOFASIKafkaProducerConsequence: message not sent for ' + T + '.' + linked), processor: count('BOFASIConsequenceOutboundProcessor: payload not built'), rule: count('BOFA_BR_Consequence_CdpOutbound')};
var log = new GlideRecord('syslog_app_scope'); log.addQuery('message', 'CONTAINS', 'BOFASIKafkaProducerConsequence: message not sent for ' + T + '.' + linked); log.orderByDesc('sys_created_on'); log.setLimit(1); log.query(); log.next();
o.producer_log = {level: '' + log.getValue('level'), message: '' + log.getValue('message'), age_s: (new GlideDateTime().getNumericValue() - new GlideDateTime(log.getValue('sys_created_on')).getNumericValue()) / 1000};
var n = new GlideRecord(T); n.initialize(); n.setValue('number', 'CONSEQ-CDP-INSERT-%(run)s'); n.setValue('state', 2); n.setValue('u_consequence_level', '2'); n.setValue('u_comments', 'Consequence outbound fixture (inserted, run %(run)s)'); var nid = n.insert();
o.inserted = {sys_id: '' + nid, number: '' + n.getValue('number')};
o.after_insert = {producer: count('BOFASIKafkaProducerConsequence: message not sent for ' + T + '.' + nid), processor: count('BOFASIConsequenceOutboundProcessor: payload not built'), rule: count('BOFA_BR_Consequence_CdpOutbound')};
var c = new GlideRecord(T); c.get(nid); c.setWorkflow(false); c.deleteRecord(); o.gone = !new GlideRecord(T).get(nid);
gs.print('X::' + JSON.stringify(o));''' % dict(linked=json.dumps(FX['linked']), cons=json.dumps(CONSEQUENCE), run=run))
    check('C update: producer logged one send failure for the consequence (rule -> processor -> producer ran)', r['after_update']['producer'] == r['before']['producer'] + 1, (r['before'], r['after_update']))
    check('C update: no processor or rule error', r['after_update']['processor'] == r['before']['processor'] and r['after_update']['rule'] == r['before']['rule'], (r['before'], r['after_update']))
    check('C update: producer error carries the key and the missing Kafka API reason, logged just now', CONSEQUENCE + '.' + FX['linked'] + ' - ' in r['producer_log']['message'] and ('sn_ih_kafka' in r['producer_log']['message'] or 'undefined is not a function' in r['producer_log']['message']) and r['producer_log']['age_s'] < 120, r['producer_log'])
    payloads = {}
    for msg in messages:
        mm = re.match(r'Consequence payload for (\S+): (\{.*\})$', msg)
        if mm:
            payloads[mm.group(1)] = json.loads(mm.group(2))
    check('C info messages on the page: one payload per record, nothing else', sorted(payloads) == sorted([FX['linked_number'], r['inserted']['number']]) and len(messages) == len(payloads), (len(messages), len(payloads), messages))
    upd = payloads.get(FX['linked_number']); ins = payloads.get(r['inserted']['number'])
    check('C update: info message shows the payload with element_activity UPDATE, the two sections and the display values', bool(upd) and upd['envelope']['element_activity'] == 'UPDATE' and upd['consequences'][0][CONSEQUENCE]['number'] == FX['linked_number'] and list(upd['consequences'][0].keys()) == SECTIONS and upd['consequences'][0][CONSEQUENCE]['cmdb_ci'] == 'Trade Processing Portal' and upd['consequences'][0][RULE]['number'] == 'CQR-FIXTURE-001' and upd['consequences'][0][CONSEQUENCE]['comments'].startswith('Consequence outbound fixture (linked) run %d' % run), upd)
    check('C insert: producer logged one send failure for the new record', r['after_insert']['producer'] == 1 and r['after_insert']['processor'] == r['before']['processor'] and r['after_insert']['rule'] == r['before']['rule'], (r['before'], r['after_insert']))
    check('C insert: info message shows the payload with element_activity INSERT, the new number and state 2, the rule section ""', bool(ins) and ins['envelope']['element_activity'] == 'INSERT' and ins['consequences'][0][CONSEQUENCE]['number'] == r['inserted']['number'] and ins['consequences'][0][CONSEQUENCE]['state'] == '2' and ins['consequences'][0][CONSEQUENCE]['consequence_level'] == '2' and all(v == '' for v in ins['consequences'][0][RULE].values()), ins)
    check('C insert: fixture removed afterwards', r['gone'], r['gone'])

    print('D. rendering by dictionary type')
    r, _ = js('''
var o = {};
var a = new GlideRecord(%(cons)s); a.get(%(id)s);
var rule = a.u_rule.getRefRecord();
var fields = ['cmdb_ci', 'u_rule', 'state', 'u_enforcement_status', 'sys_created_on', 'u_change_freeze_effective_date', 'u_comments', 'u_network_isolation_effective_date', 'no_such_field', 'sys_id'];
var processor = new x_196061_bofasim.BOFASIConsequenceOutboundProcessor(); o.rendered = {};
for (var i = 0; i < fields.length; i++) o.rendered[fields[i]] = processor._fieldValue(a, fields[i]);
o.rendered.rule_global_exception = processor._fieldValue(rule, 'global_exception'); o.rendered.rule_valid_to = processor._fieldValue(rule, 'valid_to');
function stamp(v) { var g = new GlideDateTime(v); return g.getDate().getByFormat('MM-dd-yyyy') + ' ' + g.getTime().getByFormat('HH:mm:ss'); }
o.expect = {ci: '' + a.getValue('cmdb_ci'), ci_display: '' + a.cmdb_ci.getRefRecord().getDisplayValue(), ci_type: '' + a.cmdb_ci.getED().getInternalType(), rule: '' + a.getValue('u_rule'), rule_display: '' + a.getDisplayValue('u_rule'), state: '' + a.getValue('state'), state_display: '' + a.getDisplayValue('state'), enf: '' + a.getValue('u_enforcement_status'), enf_display: '' + a.getDisplayValue('u_enforcement_status'),
    created: stamp(a.getValue('sys_created_on')), freeze: stamp(a.getValue('u_change_freeze_effective_date')), comments: '' + a.getValue('u_comments'), isolation_empty: a.u_network_isolation_effective_date.nil(), sys_id: a.getUniqueValue(), ge: '' + rule.getValue('global_exception'), valid_to: stamp(rule.getValue('valid_to'))};
gs.print('X::' + JSON.stringify(o));''' % dict(cons=json.dumps(CONSEQUENCE), id=json.dumps(FX['linked'])))
    d = r['rendered']; x = r['expect']
    check('D reference and document_id fields render the display value, not the sys_id', d['cmdb_ci'] == x['ci_display'] == 'Trade Processing Portal' and d['cmdb_ci'] != x['ci'] and x['ci_type'] == 'document_id' and d['u_rule'] == x['rule_display'] == 'CQR-FIXTURE-001' and len(x['rule']) == 32, (d, x))
    check('D integer choices render the stored value, not the label', d['state'] == x['state'] == '1' and x['state_display'] == 'Open' and d['u_enforcement_status'] == x['enf'] == '1' and x['enf_display'] == 'Change Frozen', (d, x))
    check('D date/time MM-dd-yyyy HH:mm:ss', d['sys_created_on'] == x['created'] and d['u_change_freeze_effective_date'] == x['freeze'] == '09-15-2026 12:40:01' and d['rule_valid_to'] == x['valid_to'] == '12-31-2026 23:59:59', (d, x))
    check('D string raw, boolean as stored, sys_id, empty field "", missing field ""', d['u_comments'] == x['comments'] and d['rule_global_exception'] == x['ge'] and d['sys_id'] == x['sys_id'] and d['u_network_isolation_effective_date'] == '' and x['isolation_empty'] and d['no_such_field'] == '', (d, x))
print('RESULT: %d passed, %d failed' % (passed, failed))
ui.app('global')
sys.exit(1 if failed else 0)
