import os, sys, json, re
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
ST = json.load(open(os.path.join(HERE, 'state.json')))
PROPERTY = 'x_boar_bofa_usem_1.x_boar_bofa.usem.kafka.topic_sys_id'
TABLES = ['sn_vul_vulnerable_item', 'sn_vul_app_vulnerable_item', 'sn_vul_container_image_vulnerable_item', 'sn_vulc_result',
          'sn_vul_vulnerability', 'sn_vul_app_vulnerability', 'sn_vul_container_vulnerability', 'sn_vulc_result_group']
ENVELOPE = ['type', 'topic_name', 'namespace', 'core_version', 'outbound_version', 'event_id', 'event_timestamp', 'element_count', 'element_activity']
ui = SNUI(); ui.app('global')
FAILS = []; TOTAL = [0]
def check(label, cond, detail=''):
    TOTAL[0] += 1
    print(('PASS ' if cond else 'FAIL ') + label + (' | ' + detail if detail else ''))
    if not cond: FAILS.append(label)
def now():
    return ui.js("gs.print('X::' + JSON.stringify({t: '' + new GlideDateTime()}));")['t']
def errors(since_minutes=3, since=None):
    return ui.js('''
var o = {msgs: []};
var l = new GlideRecord('syslog'); l.addQuery('message', 'STARTSWITH', 'BOFA_SI_KafkaProducerV2: message not sent'); l.addQuery('sys_created_on', '>=', %s); l.orderByDesc('sys_created_on'); l.query();
while (l.next()) o.msgs.push('' + l.getValue('message'));
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(since) if since else 'gs.minutesAgoStart(%d)' % since_minutes))['msgs']
ui.js('new GlideUpdateSet().set(%s); gs.print("X::{}");' % json.dumps(ST['global_default']))

# ---------- A. validator: every reason it can refuse, and what it accepts ----------
a = ui.js(r'''
var o = {cases: {}};
var V = x_196061_bofasim.BOFA_SI_KafkaPayloadValidator;
function attempt(x) { try { return {ok: true, out: '' + new V().validate(x)}; } catch (e) { return {ok: false, err: '' + e.message}; } }
var g = new GlideRecord('sn_vul_vulnerability'); g.addQuery('number', 'VUL0004576'); g.query(); g.next();
var good = new RemediationTaskPayloadBuilder().buildPayload(g);
var obj = JSON.parse(good);
o.good = good; o.canonical = JSON.stringify(obj);
o.cases.good_string = attempt(good);
o.cases.good_object = attempt(JSON.parse(good));
o.cases.empty_string = attempt(''); o.cases.blank_string = attempt('   '); o.cases.null_payload = attempt(null); o.cases.undefined_payload = attempt(undefined);
o.cases.truncated_json = attempt(good.substring(0, 40)); o.cases.trailing_garbage = attempt(good + 'x'); o.cases.single_quotes = attempt("{'envelope': {}}");
o.cases.json_string_literal = attempt('"text"'); o.cases.stringified_empty = attempt(JSON.stringify('')); o.cases.json_array = attempt('[]'); o.cases.json_number = attempt('42');
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
c = JSON.parse(good); c.rem_tasks = ['x']; o.cases.element_string = attempt(c);
c = JSON.parse(good); c.rem_tasks = [{}]; o.cases.element_empty_object = attempt(c);
c = JSON.parse(good); c.rem_tasks = [null]; o.cases.element_null = attempt(c);
c = JSON.parse(good); c.rem_tasks = [[]]; o.cases.element_array = attempt(c);
c = JSON.parse(good); c.envelope.element_count = '1'; o.cases.count_as_string = attempt(c);
c = JSON.parse(good); c.rem_tasks.push(JSON.parse(good).rem_tasks[0]); c.envelope.element_count = 2; o.cases.two_elements = attempt(c);
c = JSON.parse(good); c.rem_tasks.push(JSON.parse(good).rem_tasks[0]); o.cases.two_elements_count_one = attempt(c);
c = JSON.parse(good); delete c.envelope; c.findings = [{finding: {a: 1}}]; o.cases.no_envelope_other_list = attempt(c);
c = JSON.parse(good); c.envelope.element_activity = 'DELETE'; o.cases.other_activity = attempt(c);
gs.print('X::' + JSON.stringify(o));''' % json.dumps(ENVELOPE))
C = a['cases']
def refused(name, reason):
    c = C[name]; check('A refuses %s' % name, (not c['ok']) and c['err'] == reason, c.get('err', 'ACCEPTED'))
def accepted(name):
    c = C[name]; check('A accepts %s' % name, c['ok'] and c['out'] == C['good_string']['out'] if name in ('good_string', 'good_object') else c['ok'], c.get('err', ''))
check('A good payload comes back as its canonical JSON text', C['good_string']['ok'] and C['good_string']['out'] == a['canonical'] and json.loads(C['good_string']['out']) == json.loads(a['good']))
accepted('good_object')
for n in ['empty_string', 'blank_string', 'null_payload', 'undefined_payload']: refused(n, 'payload is empty')
for n in ['truncated_json', 'trailing_garbage', 'single_quotes']:
    c = C[n]; check('A refuses %s' % n, (not c['ok']) and c['err'].startswith('payload is not valid JSON - ') and len(c['err']) > len('payload is not valid JSON - '), c.get('err', 'ACCEPTED'))
for n in ['json_string_literal', 'stringified_empty', 'json_array', 'json_number', 'number_payload', 'array_payload', 'boolean_payload']: refused(n, 'payload is not a JSON object')
for n in ['empty_object', 'envelope_string', 'envelope_array']: refused(n, 'envelope is missing')
for f in ENVELOPE:
    for kind in ['missing', 'empty', 'null']: refused(kind + '_' + f, 'envelope.' + f + ' is missing or empty')
refused('no_list', 'payload must hold the envelope and one list of elements, found envelope')
refused('two_lists', 'payload must hold the envelope and one list of elements, found envelope, rem_tasks, findings')
refused('extra_key', 'payload must hold the envelope and one list of elements, found envelope, rem_tasks, extra')
for n in ['list_is_object', 'list_empty', 'list_string']: refused(n, 'rem_tasks is not a list of elements')
refused('count_too_high', 'envelope.element_count is 2 but rem_tasks holds 1')
refused('count_zero', 'envelope.element_count is 0 but rem_tasks holds 1')
refused('count_text', 'envelope.element_count is NaN but rem_tasks holds 1')
for n in ['element_string', 'element_empty_object', 'element_null', 'element_array']: refused(n, 'rem_tasks[0] is not an element')
check('A accepts element_count given as text "1"', C['count_as_string']['ok'] and json.loads(C['count_as_string']['out'])['envelope']['element_count'] == '1')
check('A accepts two elements with element_count 2', C['two_elements']['ok'] and len(json.loads(C['two_elements']['out'])['rem_tasks']) == 2)
refused('two_elements_count_one', 'envelope.element_count is 1 but rem_tasks holds 2')
refused('no_envelope_other_list', 'envelope is missing')
check('A accepts any element_activity text', C['other_activity']['ok'])

# ---------- B. producer: topic per table, key, message, and every refusal ----------
b = ui.js(r'''
var o = {sent: [], subjects: {}, topic: '' + gs.getProperty(%s, '')};
var P = x_196061_bofasim.BOFA_SI_KafkaProducerV2;
var g = new GlideRecord('sn_vul_vulnerability'); g.addQuery('number', 'VUL0004576'); g.query(); g.next();
var good = new RemediationTaskPayloadBuilder().buildPayload(g);
o.canonical = JSON.stringify(JSON.parse(good));
var tables = %s;
for (var i = 0; i < tables.length; i++) {
    var r = new GlideRecord(tables[i]); r.orderByDesc('sys_created_on'); r.setLimit(1); r.query();
    if (!r.next()) { r.newRecord(); o.subjects[tables[i]] = 'unsaved'; } else o.subjects[tables[i]] = 'existing';
    var p = new P(); p._send = function(t, k, m) { o.sent.push({table: r.getTableName(), topic: '' + t, key: '' + k, message: '' + m, expected_key: r.getTableName() + '.' + r.getUniqueValue()}); };
    p.sendPayload(good, r);
    var p2 = new P(); p2._send = function(t, k, m) { o.sent.push({table: r.getTableName(), topic: '' + t, key: '' + k, message: '' + m, expected_key: r.getTableName() + '.' + r.getUniqueValue(), object_payload: true}); };
    p2.sendPayload(JSON.parse(good), r);
}
var inc = new GlideRecord('incident'); inc.orderByDesc('sys_created_on'); inc.setLimit(1); inc.query(); inc.next(); o.incident = inc.getUniqueValue();
var stub_hits = 0;
var p3 = new P(); p3._send = function() { stub_hits++; }; p3.sendPayload(good, inc);
var p4 = new P(); p4._send = function() { stub_hits++; }; p4.sendPayload('{bad json', g);
var p5 = new P(); p5._send = function() { stub_hits++; }; p5.sendPayload(JSON.stringify(''), g);
var p6 = new P(); p6._send = function() { stub_hits++; }; p6.sendPayload('', g);
var bad = JSON.parse(good); delete bad.envelope.element_activity;
var p7 = new P(); p7._send = function() { stub_hits++; }; p7.sendPayload(JSON.stringify(bad), g);
o.stub_hits_on_refusals = stub_hits;
var p8 = new P(); try { p8.sendPayload(good, null); o.null_record = 'no throw'; } catch (e) { o.null_record = 'THREW ' + e.message; }
var p9 = new P(); try { p9.sendPayload(good, g); o.real_send = 'no throw'; } catch (e) { o.real_send = 'THREW ' + e.message; }
o.vul = g.getUniqueValue();
o.defaults = {is_sync: new P().IS_SYNC, headers: new P().HEADERS, schema: new P().SCHEMA_ID, tables: Object.keys(new P().TOPIC_PROPERTIES)};
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(PROPERTY), json.dumps(TABLES)))
check('B property fixture holds the topic the build recorded', b['topic'] == ST['topic'], b['topic'])
sent = b['sent']
check('B one send per table per payload form: %d tables x 2 = %d sends' % (len(TABLES), len(sent)), len(sent) == 2 * len(TABLES))
check('B every send used the topic from the property', all(s['topic'] == ST['topic'] for s in sent))
check('B every key is <table>.<sys_id>', all(s['key'] == s['expected_key'] and re.match(r'^[a-z_]+\.[0-9a-f]{32}$', s['key']) for s in sent), '; '.join(sorted(set(s['key'][:s['key'].index('.')] for s in sent))))
check('B every message is the canonical JSON text, whether given as string or object', all(s['message'] == b['canonical'] for s in sent))
check('B all eight tables covered (%s)' % ', '.join('%s:%s' % (t, b['subjects'][t]) for t in TABLES), sorted(set(s['table'] for s in sent)) == sorted(TABLES))
check('B refusals never reach send (5 refusals, %d stub hits)' % b['stub_hits_on_refusals'], b['stub_hits_on_refusals'] == 0)
check('B null record does not throw', b['null_record'] == 'no throw', b['null_record'])
check('B real send on an instance without Stream Connect does not throw', b['real_send'] == 'no throw', b['real_send'])
check('B defaults: async send, no headers, no schema, 8 tables', b['defaults']['is_sync'] is False and b['defaults']['headers'] is None and b['defaults']['schema'] is None and sorted(b['defaults']['tables']) == sorted(TABLES))
msgs = errors()
def logged(prefix, reason_check, label):
    hits = [m for m in msgs if m.startswith(prefix)]
    ok = bool(hits) and reason_check(hits[0][len(prefix):])
    check(label, ok, hits[0] if hits else 'NO LOG for ' + prefix)
V = 'BOFA_SI_KafkaProducerV2: message not sent for sn_vul_vulnerability %s - ' % b['vul']
logged('BOFA_SI_KafkaProducerV2: message not sent for incident %s - ' % b['incident'], lambda r: r == 'no Kafka topic is associated with table incident', 'B logs the unmapped table')
logged(V + 'payload is not valid JSON - ', lambda r: len(r) > 0, 'B logs malformed JSON with the parser reason')
logged(V + 'payload is not a JSON object', lambda r: r == '', 'B logs the stringified empty string the rule would pass when the builder fails')
logged(V + 'payload is empty', lambda r: r == '', 'B logs the empty payload')
logged(V + 'envelope.element_activity is missing or empty', lambda r: r == '', 'B logs the envelope contract breach')
logged('BOFA_SI_KafkaProducerV2: message not sent for record - ', lambda r: len(r) > 0, 'B logs the null record without crashing')
real = [m for m in msgs if m.startswith(V) and 'ProducerV2' in m or (m.startswith(V) and 'not a function' in m)]
check('B real send failure is logged in the same format (Stream Connect absent here)', bool(real), real[0] if real else 'NO LOG')

# ---------- C. property empty: refused with the property named ----------
c = ui.js(r'''
var o = {};
var p = new GlideRecord('sys_properties'); p.get(%s); var keep = '' + p.getValue('value'); p.setValue('value', ''); p.update();
o.read_back = '' + gs.getProperty(%s, 'DEFAULT');
var hits = 0; var P = x_196061_bofasim.BOFA_SI_KafkaProducerV2;
var g = new GlideRecord('sn_vul_vulnerability'); g.addQuery('number', 'VUL0004576'); g.query(); g.next();
var pr = new P(); pr._send = function() { hits++; }; pr.sendPayload(new RemediationTaskPayloadBuilder().buildPayload(g), g);
o.hits = hits;
p.setValue('value', keep); p.update(); o.restored = '' + gs.getProperty(%s, '');
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(ST['property']), json.dumps(PROPERTY), json.dumps(PROPERTY)))
check('C property blanked for the check and restored after', c['read_back'] in ('', 'DEFAULT') and c['restored'] == ST['topic'], json.dumps(c))
msgs = errors(2)
hit = [m for m in msgs if m.endswith('property ' + PROPERTY + ' holds no topic sys_id')]
check('C empty topic property is refused before send, naming the property', bool(hit) and c['hits'] == 0, hit[0] if hit else 'NO LOG')

# ---------- D. business rule context: the rule as written, builder -> producer, on a real update ----------
# the rule's own transaction clobbers a plain `o` (an out-of-box rule assigns to it), hence the unusual variable name
t0 = now()
d = ui.js(r"""
var __kafkaTest = {};
var br = new GlideRecord('sys_script'); br.initialize();
br.setValue('name', 'TEST BOA_BR_VUL_KafkaOutbound'); br.setValue('collection', 'sn_vul_vulnerability'); br.setValue('when', 'after');
br.setValue('order', 10000); br.setValue('action_update', true); br.setValue('action_insert', true); br.setValue('active', true); br.setValue('advanced', true);
br.setValue('script', "(function executeRule(current, previous) {\n    try {\n        var payload = new RemediationTaskPayloadBuilder().buildPayload(current);\n        new x_196061_bofasim.BOFA_SI_KafkaProducerV2().sendPayload(payload, current);\n    } catch (ex) {\n        gs.error('[TEST BR] Failed for {0}:{1}. Error: {2}', [current.getTableName(), current.getUniqueValue(), ex.message || ex]);\n    }\n})(current, previous);");
__kafkaTest.br = br.insert();
var g = new GlideRecord('sn_vul_vulnerability'); g.addQuery('number', 'VUL0004576'); g.query(); g.next();
var keep = '' + g.getValue('description'); g.setValue('description', keep + ' '); g.update();
__kafkaTest.vul = g.getUniqueValue();
var g2 = new GlideRecord('sn_vul_vulnerability'); g2.get(__kafkaTest.vul); g2.setValue('description', keep); g2.update();
__kafkaTest.desc_restored = ('' + g2.getValue('description')) === keep;
var del = new GlideRecord('sys_script'); del.addQuery('name', 'TEST BOA_BR_VUL_KafkaOutbound'); del.query(); __kafkaTest.deleted = 0;
while (del.next()) { del.deleteRecord(); __kafkaTest.deleted++; }
var left = new GlideRecord('sys_script'); left.addQuery('name', 'TEST BOA_BR_VUL_KafkaOutbound'); left.query(); __kafkaTest.left = left.getRowCount();
gs.print('X::' + JSON.stringify(__kafkaTest));""")
msgs = errors(since=t0)
V = 'BOFA_SI_KafkaProducerV2: message not sent for sn_vul_vulnerability %s - ' % d['vul']
from_br = [m for m in msgs if m.startswith(V)]
br_catch = ui.js("""var __c = {}; var l = new GlideRecord('syslog'); l.addQuery('message', 'STARTSWITH', '[TEST BR]'); l.addQuery('sys_created_on', '>', gs.minutesAgoStart(2)); l.query(); __c.n = l.getRowCount(); gs.print('X::' + JSON.stringify(__c));""")['n']
check('D rule fired on both updates and the producer logged the send failure each time; the rule catch was never needed', len(from_br) == 2 and br_catch == 0, '%d producer logs, %d rule-catch logs' % (len(from_br), br_catch))
check('D failure reason is the missing ProducerV2 API, nothing earlier in the chain', bool(from_br) and all(('ProducerV2' in m or 'not a function' in m) and 'payload' not in m for m in from_br), from_br[0] if from_br else '')
check('D temporary rule removed and the record description restored', d['deleted'] == 1 and d['left'] == 0 and d['desc_restored'], json.dumps(d))

print('\n%s: %d checks, %d failed%s' % ('ALL PASS' if not FAILS else 'FAILED', TOTAL[0], len(FAILS), '' if not FAILS else ' -> ' + '; '.join(FAILS)))
sys.exit(1 if FAILS else 0)
