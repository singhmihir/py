"""Checks the Kafka producer V2 in the stand-in scope on the PDI:
A. the payload validation, one case per refusal reason and the payloads it accepts;
A2. the script layout, the ProducerV2.send call and its argument order;
B. the producer with the send captured: topic, key and message per table, every refusal logged once
   and never sent, the real send on this instance (no Stream Connect) logged in the same format;
C. the topic property: empty, padded with spaces, holding a topic name;
D. the client's chain in a business rule of the Vulnerability Response scope: the rule as written on
   the client instance (builder object serialised by the rule), the same rule when the builder cannot
   build, and the suggested rule body in both cases.
Every log check reads only the lines written by the script that produced them. Run twice."""
import os, sys, json, re, html
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
ST = json.load(open(os.path.join(HERE, 'state.json')))
FX = json.load(open(os.path.join(BASE, 'stories', '1625-cdp-remediation-task-payload', 'fixtures.json')))
CLIENT_ST = json.load(open(os.path.join(BASE, 'stories', '1625-cdp-remediation-task-payload', 'client', 'state.json')))
PROPERTY = 'x_boar_bofa_usem_1.x_boar_bofa.usem.kafka.topic_sys_id'
CLIENT_PROPERTY = 'x_boar_bofa_usem_1.usem.cdp.remtask.fields.sn_vul_vulnerability'
VR_SCOPE = '054cdcc2ff200200158bffffffffff94'   # Vulnerability Response, the scope of the client's rule
SAMPLE = 'ad21d45d13bc3300a23a7f176144b055'     # VUL0004576
PLURAL = FX['ids']['sn_vul_vulnerability.plural']
SINGLE = FX['ids']['sn_vul_vulnerability.single']
TABLES = ['sn_vul_vulnerable_item', 'sn_vul_app_vulnerable_item', 'sn_vul_container_image_vulnerable_item', 'sn_vulc_result',
          'sn_vul_vulnerability', 'sn_vul_app_vulnerability', 'sn_vul_container_vulnerability', 'sn_vulc_result_group']
ENVELOPE = ['type', 'topic_name', 'namespace', 'core_version', 'outbound_version', 'event_id', 'event_timestamp', 'element_count', 'element_activity']
SENT = 'BOFA_SI_KafkaProducerV2: message not sent for '
BUILT = 'BOA_SI_USEM_RemediationTaskPayloadBuilder: payload not built for '
VALIDATION = ['payload is', 'envelope', 'rem_tasks', 'no Kafka topic', 'property ']
ui = SNUI(); ui.app('global')
FAILS = []; TOTAL = [0]
def check(label, cond, detail=''):
    TOTAL[0] += 1
    print(('PASS ' if cond else 'FAIL ') + label + (' | ' + str(detail)[:900] if detail and not cond else ''))
    if not cond: FAILS.append(label)
def lines_since(var='t0'):
    """JavaScript that collects the producer and builder error lines written since <var>."""
    return '''o.lines = [];
var l = new GlideRecord('syslog'); l.addQuery('sys_created_on', '>=', %s); l.addQuery('message', 'STARTSWITH', 'BOFA_SI_KafkaProducerV2').addOrCondition('message', 'STARTSWITH', 'BOA_SI_USEM_RemediationTaskPayloadBuilder').addOrCondition('message', 'STARTSWITH', '[TEST BR]').addOrCondition('message', 'STARTSWITH', 'BOA_BR_VUL_KafkaOutbound'); l.query();
while (l.next()) o.lines.push('' + l.getValue('message'));''' % var
ui.js('new GlideUpdateSet().set(%s); gs.print("X::{}");' % json.dumps(ST['global_default']))

# ---------- A. validation: every reason it can refuse, and what it accepts ----------
a = ui.js(r'''
(function() {
var o = {cases: {}};
var V = x_196061_bofasim.BOFA_SI_KafkaProducerV2;
function attempt(x) { try { return {ok: true, out: '' + new V()._validate(x)}; } catch (e) { return {ok: false, err: '' + e.message}; } }
var g = new GlideRecord('sn_vul_vulnerability'); g.get(%s);
var good = new RemediationTaskPayloadBuilder().buildPayload(g);
var obj = JSON.parse(good);
o.good = good; o.canonical = JSON.stringify(obj);
o.cases.good_string = attempt(good);
o.cases.good_object = attempt(JSON.parse(good));
o.cases.pretty_printed = attempt(JSON.stringify(obj, null, 4));
o.cases.client_object = attempt(new x_196061_bofasim.BOA_SI_USEM_RemediationTaskPayloadBuilder().buildPayload(g, 'UPDATE'));
o.cases.empty_string = attempt(''); o.cases.blank_string = attempt('  \n '); o.cases.null_payload = attempt(null); o.cases.undefined_payload = attempt(undefined);
o.cases.stringified_empty = attempt(JSON.stringify('')); o.cases.json_null = attempt('null'); o.cases.stringified_failed_object = attempt(JSON.stringify(''));
o.cases.truncated_json = attempt(good.substring(0, 40)); o.cases.trailing_garbage = attempt(good + 'x'); o.cases.single_quotes = attempt("{'envelope': {}}");
o.cases.json_string_literal = attempt('"text"'); o.cases.json_array = attempt('[]'); o.cases.json_number = attempt('42'); o.cases.json_false = attempt('false');
o.cases.number_payload = attempt(42); o.cases.array_payload = attempt([obj]); o.cases.boolean_payload = attempt(true);
o.cases.empty_object = attempt('{}'); o.cases.envelope_string = attempt({envelope: 'x', rem_tasks: obj.rem_tasks}); o.cases.envelope_array = attempt({envelope: [], rem_tasks: obj.rem_tasks});
var fields = %s;
for (var i = 0; i < fields.length; i++) {
    var c = JSON.parse(good); delete c.envelope[fields[i]]; o.cases['missing_' + fields[i]] = attempt(c);
    c = JSON.parse(good); c.envelope[fields[i]] = ''; o.cases['empty_' + fields[i]] = attempt(JSON.stringify(c));
    c = JSON.parse(good); c.envelope[fields[i]] = null; o.cases['null_' + fields[i]] = attempt(c);
}
var c = JSON.parse(good); delete c.rem_tasks; o.cases.no_list = attempt(c);
c = JSON.parse(good); c.findings = [{finding: {a: 1}}]; o.cases.two_lists = attempt(c);
c = JSON.parse(good); c.extra = 'x'; o.cases.extra_key = attempt(c);
c = JSON.parse(good); c.rem_tasks = {}; o.cases.list_is_object = attempt(c);
c = JSON.parse(good); c.rem_tasks = []; o.cases.list_empty = attempt(c);
c = JSON.parse(good); c.rem_tasks = 'x'; o.cases.list_string = attempt(c);
c = JSON.parse(good); c.envelope.element_count = 2; o.cases.count_too_high = attempt(c);
c = JSON.parse(good); c.envelope.element_count = 0; o.cases.count_zero = attempt(c);
c = JSON.parse(good); c.envelope.element_count = 'x'; o.cases.count_text = attempt(c);
c = JSON.parse(good); c.envelope.element_count = true; o.cases.count_true = attempt(c);
c = JSON.parse(good); c.envelope.element_count = 1.5; o.cases.count_decimal = attempt(c);
c = JSON.parse(good); c.envelope.element_count = '1.0'; o.cases.count_decimal_text = attempt(c);
c = JSON.parse(good); c.envelope.element_count = ' 1'; o.cases.count_padded = attempt(c);
c = JSON.parse(good); c.envelope.element_count = -1; o.cases.count_negative = attempt(c);
c = JSON.parse(good); c.envelope.element_count = [1]; o.cases.count_array = attempt(c);
c = JSON.parse(good); c.rem_tasks = ['x']; o.cases.element_string = attempt(c);
c = JSON.parse(good); c.rem_tasks = [{}]; o.cases.element_empty_object = attempt(c);
c = JSON.parse(good); c.rem_tasks = [null]; o.cases.element_null = attempt(c);
c = JSON.parse(good); c.rem_tasks = [[]]; o.cases.element_array = attempt(c);
c = JSON.parse(good); c.rem_tasks.push('x'); c.envelope.element_count = 2; o.cases.second_element_bad = attempt(c);
c = JSON.parse(good); c.envelope.element_count = '1'; o.cases.count_as_string = attempt(c);
c = JSON.parse(good); c.rem_tasks.push(JSON.parse(good).rem_tasks[0]); c.envelope.element_count = 2; o.cases.two_elements = attempt(c);
c = JSON.parse(good); c.rem_tasks.push(JSON.parse(good).rem_tasks[0]); o.cases.two_elements_count_one = attempt(c);
c = JSON.parse(good); delete c.envelope; c.findings = [{finding: {a: 1}}]; o.cases.no_envelope_other_list = attempt(c);
c = JSON.parse(good); c.findings = c.rem_tasks; delete c.rem_tasks; o.cases.other_list_name = attempt(c);
c = JSON.parse(good); c.envelope.element_activity = 'DELETE'; o.cases.other_activity = attempt(c);
gs.print('X::' + JSON.stringify(o));
})();''' % (json.dumps(SAMPLE), json.dumps(ENVELOPE)))
C = a['cases']
def refused(name, reason):
    c = C[name]; check('A refuses %s: %s' % (name, reason), (not c['ok']) and c['err'] == reason, c.get('err', 'ACCEPTED'))
check('A good payload text comes back as its canonical JSON text', C['good_string']['ok'] and C['good_string']['out'] == a['canonical'] and json.loads(C['good_string']['out']) == json.loads(a['good']))
check('A the same payload as an object comes back as the same text', C['good_object']['ok'] and C['good_object']['out'] == a['canonical'])
check('A pretty-printed JSON text comes back compact', C['pretty_printed']['ok'] and C['pretty_printed']['out'] == a['canonical'] and '\n' not in C['pretty_printed']['out'])
check('A the client builder\'s payload object is accepted', C['client_object']['ok'] and json.loads(C['client_object']['out'])['rem_tasks'] == json.loads(a['good'])['rem_tasks'], C['client_object'])
for n in ['empty_string', 'blank_string', 'null_payload', 'undefined_payload', 'stringified_empty', 'json_null', 'stringified_failed_object']: refused(n, 'payload is empty')
for n in ['truncated_json', 'trailing_garbage', 'single_quotes']:
    c = C[n]; check('A refuses %s with the parser reason' % n, (not c['ok']) and c['err'].startswith('payload is not valid JSON - ') and len(c['err']) > len('payload is not valid JSON - '), c.get('err', 'ACCEPTED'))
for n in ['json_string_literal', 'json_array', 'json_number', 'json_false', 'number_payload', 'array_payload', 'boolean_payload']: refused(n, 'payload is not a JSON object')
for n in ['empty_object', 'envelope_string', 'envelope_array']: refused(n, 'envelope is missing')
for f in ENVELOPE:
    for kind in ['missing', 'empty', 'null']: refused(kind + '_' + f, 'envelope.' + f + ' is missing or empty')
refused('no_list', 'payload must hold the envelope and one list of elements, found envelope')
refused('two_lists', 'payload must hold the envelope and one list of elements, found envelope, rem_tasks, findings')
refused('extra_key', 'payload must hold the envelope and one list of elements, found envelope, rem_tasks, extra')
for n in ['list_is_object', 'list_empty', 'list_string']: refused(n, 'rem_tasks is not a list of elements')
refused('count_too_high', 'envelope.element_count is 2 but rem_tasks holds 1')
refused('count_zero', 'envelope.element_count is 0 but rem_tasks holds 1')
refused('count_text', 'envelope.element_count is not a whole number: "x"')
refused('count_true', 'envelope.element_count is not a whole number: true')
refused('count_decimal', 'envelope.element_count is not a whole number: 1.5')
refused('count_decimal_text', 'envelope.element_count is not a whole number: "1.0"')
refused('count_padded', 'envelope.element_count is not a whole number: " 1"')
refused('count_negative', 'envelope.element_count is not a whole number: -1')
refused('count_array', 'envelope.element_count is not a whole number: [1]')
for n in ['element_string', 'element_empty_object', 'element_null', 'element_array']: refused(n, 'rem_tasks[0] is not an element')
refused('second_element_bad', 'rem_tasks[1] is not an element')
check('A accepts element_count given as the digits "1"', C['count_as_string']['ok'] and json.loads(C['count_as_string']['out'])['envelope']['element_count'] == '1')
check('A accepts two elements with element_count 2', C['two_elements']['ok'] and len(json.loads(C['two_elements']['out'])['rem_tasks']) == 2)
refused('two_elements_count_one', 'envelope.element_count is 1 but rem_tasks holds 2')
refused('no_envelope_other_list', 'envelope is missing')
check('A accepts a list of another name (the finding tables share the producer)', C['other_list_name']['ok'] and list(json.loads(C['other_list_name']['out'])) == ['envelope', 'findings'])
check('A accepts any element_activity text', C['other_activity']['ok'])

# ---------- A2. layout, the send call ----------
sc = ui.js(r'''
(function() {
var o = {names: []};
var si = new GlideRecord('sys_script_include'); si.addQuery('sys_scope', %s); si.addQuery('name', 'STARTSWITH', 'BOFA_SI_Kafka'); si.query();
while (si.next()) o.names.push('' + si.getValue('name'));
var p = new GlideRecord('sys_script_include'); p.get(%s); o.script = '' + p.getValue('script');
gs.print('X::' + JSON.stringify(o));
})();''' % (json.dumps(ST['scope']), json.dumps(ST['si']['BOFA_SI_KafkaProducerV2'])))
body = sc['script']; line = body.find('// ______')
before = ['sendPayload: function', '_topicSysId: function', '_send: function']; after = ['_validate: function', '_parse: function', '_checkEnvelope: function', '_checkElements: function', '_isObject: function', '_isWholeNumber: function', '_isEmpty: function']
check('A2 only the producer remains in the scope (no separate validator)', sc['names'] == ['BOFA_SI_KafkaProducerV2'], sc['names'])
check('A2 the deployed script equals the repository copy', body.rstrip('\n') == open(os.path.join(HERE, 'BOFA_SI_KafkaProducerV2.js')).read().rstrip('\n'))
check('A2 separator line present with the payload validation comment', line > 0 and 'Payload validation' in body[line:line + 400])
check('A2 send methods before the line, every validation function after it', all(0 < body.find(m) < line for m in before) and all(body.find(m) > line for m in after) and body.find("type: 'BOFA_SI_KafkaProducerV2'") > max(body.find(m) for m in after))
check('A2 ProducerV2.send called once, arguments in the documented order: topic, key, message, isSync, headers, schemaID',
      body.count('.send(') == 1 and 'new sn_ih_kafka.ProducerV2().send(topicSysId, key, message, this.IS_SYNC, this.HEADERS, this.SCHEMA_ID);' in body
      and "this._send(topicSysId, table + '.' + sysId, message);" in body)
check('A2 one gs.error, one entry-point try/catch plus the JSON parse translation, no info/warn', body.count('gs.error(') == 1 and body.count('try {') == 2 and 'gs.info' not in body and 'gs.warn' not in body)

# ---------- B. producer: topic per table, key, message, and every refusal ----------
b = ui.js(r'''
(function() {
var o = {sent: [], subjects: {}, topic: '' + gs.getProperty(%s, '')};
gs.sleep(1100); var t0 = new GlideDateTime().getValue();
var P = x_196061_bofasim.BOFA_SI_KafkaProducerV2;
var g = new GlideRecord('sn_vul_vulnerability'); g.get(%s);
var good = new RemediationTaskPayloadBuilder().buildPayload(g);
o.canonical = JSON.stringify(JSON.parse(good));
var tables = %s;
for (var i = 0; i < tables.length; i++) {
    var r = new GlideRecord(tables[i]); r.orderByDesc('sys_created_on'); r.setLimit(1); r.query();
    if (!r.next()) { r.newRecord(); o.subjects[tables[i]] = 'unsaved'; } else o.subjects[tables[i]] = 'existing';
    var p = new P(); p._send = function(t, k, m) { o.sent.push({table: r.getTableName(), topic: '' + t, key: '' + k, message: '' + m, args: arguments.length, expected_key: r.getTableName() + '.' + r.getUniqueValue()}); };
    p.sendPayload(good, r);
    var p2 = new P(); p2._send = function(t, k, m) { o.sent.push({table: r.getTableName(), topic: '' + t, key: '' + k, message: '' + m, args: arguments.length, expected_key: r.getTableName() + '.' + r.getUniqueValue(), object_payload: true}); };
    p2.sendPayload(JSON.parse(good), r);
}
var inc = new GlideRecord('incident'); inc.orderByDesc('sys_created_on'); inc.setLimit(1); inc.query(); inc.next(); o.incident = inc.getUniqueValue();
var hits = 0;
function stub() { var p = new P(); p._send = function() { hits++; }; return p; }
stub().sendPayload(good, inc);
stub().sendPayload('{bad json', g);
stub().sendPayload(JSON.stringify(''), g);
stub().sendPayload('', g);
var bad = JSON.parse(good); delete bad.envelope.element_activity; stub().sendPayload(JSON.stringify(bad), g);
o.stub_hits_on_refusals = hits;
try { stub().sendPayload(good, null); o.null_record = 'no throw'; } catch (e) { o.null_record = 'THREW ' + e.message; }
try { new sn_ih_kafka.ProducerV2(); o.api_missing = ''; } catch (e) { o.api_missing = '' + (e.message || e); }
var real = new GlideRecord('sn_vul_vulnerability'); real.get(%s);
try { new P().sendPayload(good, real); o.real_send = 'no throw'; } catch (e) { o.real_send = 'THREW ' + e.message; }
o.vul = g.getUniqueValue(); o.real = real.getUniqueValue();
o.defaults = {is_sync: new P().IS_SYNC, headers: new P().HEADERS, schema: new P().SCHEMA_ID, tables: Object.keys(new P().TOPIC_PROPERTIES)};
%s
gs.print('X::' + JSON.stringify(o));
})();''' % (json.dumps(PROPERTY), json.dumps(SAMPLE), json.dumps(TABLES), json.dumps(SINGLE), lines_since()))
check('B property fixture holds the topic the build recorded', b['topic'] == ST['topic'], b['topic'])
sent = b['sent']
check('B one send per table per payload form: %d tables x 2 = %d sends' % (len(TABLES), len(sent)), len(sent) == 2 * len(TABLES))
check('B every send used the topic from the property, three arguments to _send', all(s['topic'] == ST['topic'] and s['args'] == 3 for s in sent))
check('B every key is <table>.<sys_id>', all(s['key'] == s['expected_key'] and re.match(r'^[a-z_]+\.[0-9a-f]{32}$', s['key']) for s in sent))
check('B every message is the canonical JSON text, whether given as string or object', all(s['message'] == b['canonical'] for s in sent))
check('B all eight tables covered (%s)' % ', '.join('%s:%s' % (t, b['subjects'][t]) for t in TABLES), sorted(set(s['table'] for s in sent)) == sorted(TABLES))
check('B refusals never reach send (5 refusals, %d stub hits)' % b['stub_hits_on_refusals'], b['stub_hits_on_refusals'] == 0)
check('B null record and the real send do not throw', b['null_record'] == 'no throw' and b['real_send'] == 'no throw', (b['null_record'], b['real_send']))
check('B defaults: async send, no headers, no schema, 8 tables', b['defaults']['is_sync'] is False and b['defaults']['headers'] is None and b['defaults']['schema'] is None and sorted(b['defaults']['tables']) == sorted(TABLES))
V = SENT + 'sn_vul_vulnerability %s - ' % b['vul']
exact = [SENT + 'incident %s - no Kafka topic is associated with table incident' % b['incident'], V + 'payload is empty', V + 'payload is empty', V + 'envelope.element_activity is missing or empty']
L = b['lines']
check('B exactly seven lines logged by this script', len(L) == 7, L)
check('B unmapped table, stringified empty string, empty string, envelope breach: one exact line each', all(L.count(m) == exact.count(m) for m in exact), [m for m in exact if m not in L])
parser = [m for m in L if m.startswith(V + 'payload is not valid JSON - ')]
check('B malformed JSON: one line with the parser reason', len(parser) == 1 and len(parser[0]) > len(V + 'payload is not valid JSON - '), parser)
nul = [m for m in L if m.startswith(SENT + 'record - ')]
check('B null record: one line, subject "record"', len(nul) == 1, nul)
real = [m for m in L if m.startswith(SENT + 'sn_vul_vulnerability %s - ' % b['real'])]
reason = real[0][len(SENT + 'sn_vul_vulnerability %s - ' % b['real']):] if len(real) == 1 else ''
check('B real send (no Stream Connect here): one line in the same format, its reason the platform\'s own error for the missing Kafka API (%r)' % b['api_missing'],
      len(real) == 1 and b['api_missing'] != '' and reason == b['api_missing'] and not any(reason.startswith(v) for v in VALIDATION), real)
print('   real send reason on this instance: %s' % reason)
REAL_REASON = reason

# ---------- C. the topic property: empty, padded, a topic name ----------
c = ui.js(r'''
(function() {
var o = {sent: []};
gs.sleep(1100); var t0 = new GlideDateTime().getValue();
var P = x_196061_bofasim.BOFA_SI_KafkaProducerV2;
var g = new GlideRecord('sn_vul_vulnerability'); g.get(%s);
var good = new RemediationTaskPayloadBuilder().buildPayload(g);
var p = new GlideRecord('sys_properties'); p.get(%s); var keep = '' + p.getValue('value');
function run(value) { p.setValue('value', value); p.update(); var pr = new P(); pr._send = function(t) { o.sent.push('' + t); }; pr.sendPayload(good, g); }
try {
    run(''); run('  ' + keep + '  \n'); run('sn_usem_remtask_outbound'); run(keep.toUpperCase());
} finally {
    p.setValue('value', keep); p.update();
}
o.restored = '' + gs.getProperty(%s, '');
o.vul = g.getUniqueValue();
%s
gs.print('X::' + JSON.stringify(o));
})();''' % (json.dumps(SAMPLE), json.dumps(ST['property']), json.dumps(PROPERTY), lines_since()))
V = SENT + 'sn_vul_vulnerability %s - ' % c['vul']
check('C property padded with spaces: the trimmed sys_id is sent; the same sys_id in capitals is accepted', c['sent'] == [ST['topic'], ST['topic'].upper()], c['sent'])
check('C empty property and a topic name refused before send, naming the property and the value',
      sorted(c['lines']) == sorted([V + 'property %s holds no topic sys_id' % PROPERTY, V + 'property %s holds "sn_usem_remtask_outbound", which is not a topic sys_id' % PROPERTY]), c['lines'])
check('C property restored', c['restored'] == ST['topic'], c['restored'])

# ---------- D. the client's chain in a rule of the Vulnerability Response scope ----------
original = open(os.path.join(HERE, 'original', 'BOA_BR_VUL_KafkaOutbound.xml')).read()
body_original = re.search(r'<script><!\[CDATA\[(.*?)\]\]></script>', original, re.S).group(1)
CLIENT_RULE = body_original.replace('[Mihir USEM Outbound][VUL]', '[TEST BR]')
check('D the rule under test is the client\'s rule as exported, only its log tag changed', CLIENT_RULE.count('[TEST BR]') == 1 and 'JSON.stringify(new x_boar_bofa_usem_1.BOA_SI_USEM_RemediationTaskPayloadBuilder().buildPayload(current, operation))' in CLIENT_RULE)
readme = open(os.path.join(HERE, 'README.md')).read()
SUGGESTED = re.search(r'```javascript\n(.*?)```', readme, re.S).group(1).strip()
def rule_run(script, break_builder):
    code = r'''
(function() {
var o = {};
gs.sleep(1100); var t0 = new GlideDateTime().getValue();
var br = new GlideRecord('sys_script'); br.initialize();
br.setValue('name', 'TEST BOA_BR_VUL_KafkaOutbound'); br.setValue('collection', 'sn_vul_vulnerability'); br.setValue('when', 'after');
br.setValue('order', 10000); br.setValue('action_update', true); br.setValue('action_insert', true); br.setValue('active', true); br.setValue('advanced', true);
br.setValue('sys_scope', %s); br.setValue('script', %s);
o.br = '' + br.insert(); var check = new GlideRecord('sys_script'); check.get(o.br); o.rule_scope = '' + check.getValue('sys_scope');
var prop = new GlideRecord('sys_properties'); prop.get(%s); var keepProp = '' + prop.getValue('value');
var g = new GlideRecord('sn_vul_vulnerability'); g.get(%s); var keep = '' + g.getValue('description');
try {
    if (%s) { prop.setValue('value', ''); prop.update(); }
    g.setValue('description', 'Kafka rule probe ' + new GlideDateTime().getNumericValue()); g.update();
    var n = new GlideRecord('sn_vul_vulnerability'); n.initialize(); n.setValue('short_description', 'VSO-PAYLOAD kafka rule insert'); o.inserted = '' + n.insert();
} finally {
    prop.setValue('value', keepProp); prop.update();
    var del = new GlideRecord('sys_script'); del.addQuery('name', 'TEST BOA_BR_VUL_KafkaOutbound'); del.query(); o.deleted = 0; while (del.next()) { del.deleteRecord(); o.deleted++; }
    var ux = new GlideRecord('sys_update_xml'); ux.addQuery('name', 'sys_script_' + o.br); ux.query(); o.capture_rows = ux.getRowCount(); while (ux.next()) ux.deleteRecord();
    var g2 = new GlideRecord('sn_vul_vulnerability'); g2.get(%s); g2.setWorkflow(false); g2.setValue('description', keep); g2.update();
    var tidy = new GlideRecord('sn_vul_vulnerability'); tidy.addQuery('short_description', 'STARTSWITH', 'VSO-PAYLOAD'); tidy.addQuery('active', true); tidy.query();
    while (tidy.next()) { tidy.setValue('active', false); tidy.setValue('state', 3); tidy.setWorkflow(false); tidy.update(); }
}
o.vul = g.getUniqueValue(); o.prop_restored = '' + gs.getProperty(%s, '') === keepProp;
o.direct = JSON.stringify(new x_196061_bofasim.BOA_SI_USEM_RemediationTaskPayloadBuilder().buildPayload(g, 'UPDATE'));
%s
gs.print('X::' + JSON.stringify(o));
})();''' % (json.dumps(VR_SCOPE), json.dumps(script.replace('x_boar_bofa_usem_1.', 'x_196061_bofasim.')), json.dumps(CLIENT_ST['props'][CLIENT_PROPERTY]), json.dumps(PLURAL),
            'true' if break_builder else 'false', json.dumps(PLURAL), json.dumps(CLIENT_PROPERTY), lines_since())
    raw = ui.run(code, scope=VR_SCOPE)
    m = re.search(r'X::(\{.*\})', raw, re.S)
    if not m: raise RuntimeError('NO MARKER; tail: ' + raw[-1500:])
    text = html.unescape(re.sub(r'<[^>]+>', ' ', raw))
    infos = [s.strip() for s in re.findall(r'Background message, type:info, message: (\{.*?\}\]\})', text, re.S)]
    return json.loads(m.group(1)), infos
def subjects(r):
    return {'upd': SENT + 'sn_vul_vulnerability %s - ' % r['vul'], 'ins': SENT + 'sn_vul_vulnerability %s - ' % r['inserted'],
            'bupd': BUILT + 'sn_vul_vulnerability %s - ' % r['vul'], 'bins': BUILT + 'sn_vul_vulnerability %s - ' % r['inserted']}
for tag, script in [('client rule', CLIENT_RULE), ('suggested rule', SUGGESTED)]:
    r, infos = rule_run(script, False)
    s = subjects(r); L = r['lines']
    check('D %s: created in the Vulnerability Response scope, removed afterwards with its capture row' % tag, r['rule_scope'] == VR_SCOPE and r['deleted'] == 1 and r['capture_rows'] >= 1, (r['rule_scope'], r['deleted'], r['capture_rows']))
    check('D %s: on an update and an insert the chain reached the send each time, nothing else logged (2 lines)' % tag,
          sorted(L) == sorted([s['upd'] + REAL_REASON, s['ins'] + REAL_REASON]), L)
    if tag == 'client rule':
        got = [json.loads(i) for i in infos]
        direct = json.loads(r['direct'])
        check('D client rule: the payload the rule serialised is the builder\'s payload for the record (update, then insert)',
              len(got) == 2 and got[0]['rem_tasks'] == direct['rem_tasks'] and got[0]['envelope']['element_activity'] == 'UPDATE' and got[1]['envelope']['element_activity'] == 'INSERT', [i[:120] for i in infos])
    r, infos = rule_run(script, True)
    s = subjects(r); L = r['lines']
    reason = 'table sn_vul_vulnerability is not configured in property %s' % CLIENT_PROPERTY
    if tag == 'client rule':
        want = [s['bupd'] + reason, s['upd'] + 'payload is empty', s['bins'] + reason, s['ins'] + 'payload is empty']
        check('D client rule, builder cannot build: the builder\'s reason, then "payload is empty" from the producer (the rule serialises ""); never sent', sorted(L) == sorted(want), L)
    else:
        want = [s['bupd'] + reason, s['bins'] + reason]
        check('D suggested rule, builder cannot build: one line, the builder\'s reason; the producer is not called', sorted(L) == sorted(want), L)
    check('D %s: property restored after the failure run' % tag, r['prop_restored'])

print('\n%s: %d checks, %d failed%s' % ('ALL PASS' if not FAILS else 'FAILED', TOTAL[0], len(FAILS), '' if not FAILS else ' -> ' + '; '.join(FAILS)))
sys.exit(1 if FAILS else 0)
