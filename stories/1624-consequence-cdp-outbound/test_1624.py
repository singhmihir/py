"""Checks the consequence outbound build on the PDI (mirror of the client application). Every expected value
is worked out apart from the processor, through the REST API (dictionary type, stored and display value of
each field of the consequence and of its rule), and the fixtures are also checked against literal values.
A. Payload per fixture - linked, bare, a rule and an AIT that are gone with a CI whose class field is
   empty, a class field naming another class than the CI's, a CI that is gone: envelope, the sections
   consequence and rule of the sheet, every field, choices as labels, the checkbox as true/false; each
   built from inside a function of a global script and directly, with the same result.
B. The rule on a real update and a real insert: payload on the page, the send reached (the PDI has no
   Stream Connect: the producer logs the platform's own error), nothing else logged.
C. Error handling: unusable records, every refusal of the field property, a tampered payload, the topic
   property empty, padded and malformed, unusable payloads and no record at the producer; one exact line
   each, nothing sent.
D. Configuration: the properties, the deployed scripts equal to the repository, script hygiene.
Every log check reads only the lines written by the script under test. Run twice; run 1 writes the sample."""
import os, sys, json, re, html
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
ST = json.load(open(os.path.join(HERE, 'state.json'))); FX = json.load(open(os.path.join(HERE, 'fixtures.json')))
SHEET = json.load(open(os.path.join(HERE, 'consequence_mapping.json'))); PROPS = json.load(open(os.path.join(HERE, 'properties.json')))
P = 'x_boar_bofa_usem_0'
CONSEQUENCE, RULE = P + '_consequence', P + '_consequence_rule'
FIELD_PROP = P + '.usem.consequence.fields.' + CONSEQUENCE
TOPIC_PROP = P + '.usem.consequence.kafka.topic_sys_id'
SECTION_OF = {CONSEQUENCE: 'consequence', RULE: 'rule'}
FIELDS = {SECTION_OF[t]: [r['payload'] for r in SHEET if r['table'] == t] for t in (CONSEQUENCE, RULE)}
ENVELOPE = ['type', 'topic_name', 'namespace', 'core_version', 'outbound_version', 'event_id', 'event_timestamp', 'element_count', 'element_activity']
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
MARKUP = re.compile(r'^\[code\]([\s\S]*)\[/code\]$')
BUILT = 'BOFASIConsequenceOutboundProcessor: payload not built for '
SENT = 'BOFA_SI_KafkaProducerV2: message not sent for '   # the shared producer of the integration application
KINDS = ['linked', 'bare', 'dangling', 'misclassed', 'ghost']
ui = SNUI(); ui.app('global')
H = {'X-UserToken': ui.ck(), 'Accept': 'application/json'}
passed = failed = 0
def check(name, ok, detail=''):
    global passed, failed
    ok = bool(ok); passed += ok; failed += (not ok)
    print(('  ok   ' if ok else '  FAIL ') + name + ('' if ok else '  -> ' + str(detail)[:900]))
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
LINES = '''o.lines = [];
var l = new GlideRecord('syslog'); l.addQuery('sys_created_on', '>=', t0); l.addQuery('message', 'STARTSWITH', 'BOFASIConsequenceOutboundProcessor').addOrCondition('message', 'STARTSWITH', 'BOFA_SI_KafkaProducerV2').addOrCondition('message', 'STARTSWITH', 'BOFA_BR_Consequence_CdpOutbound'); l.addQuery('sys_created_by', gs.getUserName()); l.query();
while (l.next()) o.lines.push('' + l.getValue('message'));'''
START = "gs.sleep(1100); var t0 = new GlideDateTime().getValue();"

# ---------- the oracle ----------
def rest(table, query, fields=None, display='false'):
    params = {'sysparm_query': query, 'sysparm_display_value': display, 'sysparm_exclude_reference_link': 'true', 'sysparm_limit': 1000}
    if fields: params['sysparm_fields'] = ','.join(fields)
    r = ui.s.get(INST + '/api/now/table/' + table, params=params, headers=H); r.raise_for_status()
    return r.json()['result']
DICT = {t: {r['element']: (r['internal_type'], r['choice']) for r in rest('sys_dictionary', 'name=%s^elementISNOTEMPTY' % t, ['element', 'internal_type', 'choice'])} for t in (CONSEQUENCE, RULE)}
def mapping(value):
    out = []
    for line in re.split(r'\r?\n|,', value):
        if line.strip():
            left, json_name = [x.strip() for x in line.split('=')]
            table, field = (left.split('.', 1) if '.' in left else (CONSEQUENCE, left))
            out.append((table, field, SECTION_OF[table], json_name))
    return out
def plain(v):
    m = MARKUP.match(v)
    return html.unescape(re.sub(r'<[^>]*>', '', m.group(1)).replace('&nbsp;', ' ')).strip() if m else v
def expect(table, field, cells):
    if cells is None or field not in DICT[table] or field not in cells: return ''
    kind, choice = DICT[table][field]
    value, shown = cells[field]['value'] or '', cells[field]['display_value'] or ''
    if value == '': return ''
    if kind in ('glide_date_time', 'due_date'): return '%s-%s-%s %s' % (value[5:7], value[8:10], value[0:4], value[11:19])
    if kind == 'glide_date': return '%s-%s-%s' % (value[5:7], value[8:10], value[0:4])
    if kind == 'reference': return '' if shown == value else shown
    if kind == 'document_id': return None   # checked against literals
    if kind == 'integer': return shown if choice in ('1', '3') else value
    if kind in ('string', 'glide_list', 'boolean', 'glide_duration', 'timer', 'domain_id', 'sys_class_name', 'choice'): return plain(shown)
    return plain(value)
LIVE_FIELDS = rest('sys_properties', 'name=' + FIELD_PROP, ['value'])[0]['value']
MAP = mapping(LIVE_FIELDS)
CI_LITERAL = {'linked': 'Trade Processing Portal', 'bare': '', 'dangling': 'Trade Processing Portal', 'misclassed': 'Trade Processing Portal', 'ghost': ''}

for run in (1, 2):
    print('== run', run)
    # ---------- A. payload per fixture, two call paths ----------
    r, messages = js('''
(function() {
var o = {rows: {}};
%s
var C = x_boar_bofa_usem_0.BOFASIConsequenceOutboundProcessor, fx = %s, kinds = %s;
function viaFunction(g) { return new C().buildPayload(g); }
for (var i = 0; i < kinds.length; i++) {
    var g = new GlideRecord(%s); g.get(fx[kinds[i]]);
    var nested = viaFunction(g);
    var direct = new C().buildPayload(g);
    o.rows[kinds[i]] = {nested: nested, direct: direct, mod: parseInt(g.getValue('sys_mod_count'))};
}
%s
gs.print('X::' + JSON.stringify(o));
})();''' % (START, json.dumps(FX), json.dumps(KINDS), json.dumps(CONSEQUENCE), LINES))
    check('A no error logged while building the five payloads twice', r['lines'] == [], r['lines'])
    shown = [m for m in messages if m.startswith('Consequence payload for ')]
    check('A one payload message per build, ten, and no fields-not-found message', len(shown) == 10 and len(messages) == 10, messages[:3])
    for kind in KINDS:
        row = r['rows'][kind]; tag = 'A %s:' % kind
        if not row['nested'] or not row['direct']:
            check(tag + ' payload built on both call paths', False, row); continue
        p, q = json.loads(row['nested']), json.loads(row['direct'])
        check(tag + ' the same payload from inside a function of a global script and directly', p['consequences'] == q['consequences'] and p['envelope']['element_activity'] == q['envelope']['element_activity'])
        e = p['envelope']; el = p['consequences'][0] if p.get('consequences') else {}
        check(tag + ' envelope: keys, constants, UUID, UTC time, one element, activity from the update count',
              list(p) == ['envelope', 'consequences'] and list(e) == ENVELOPE and (e['type'], e['topic_name'], e['namespace'], e['core_version'], e['outbound_version'], e['element_count']) == ('record', 'sn_usem_consequence_outbound', 'com.bofa.usem', '1.0.0', '1.0.0', 1)
              and UUID.match(e['event_id']) and re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', e['event_timestamp']) and len(p['consequences']) == 1
              and e['element_activity'] == ('UPDATE' if row['mod'] > 0 else 'INSERT'), e)
        check(tag + ' sections named as the sheet: consequence, then rule', list(el) == ['consequence', 'rule'], list(el))
        check(tag + ' each section carries exactly the sheet fields in sheet order', all(list(el.get(s, {})) == FIELDS[s] for s in FIELDS), {s: list(el.get(s, {})) for s in el})
        cons = rest(CONSEQUENCE, 'sys_id=' + FX[kind], display='all')[0]
        rule_id = cons['u_rule']['value']
        rules = rest(RULE, 'sys_id=' + rule_id, display='all') if rule_id else []
        cells = {CONSEQUENCE: cons, RULE: rules[0] if rules else None}
        bad = []
        for table, field, section, name in MAP:
            want = expect(table, field, cells[table])
            if want is None: continue
            got = el.get(section, {}).get(name)
            if got != want: bad.append('%s.%s(%s): %r, expected %r' % (section, name, DICT[table].get(field, ('missing',))[0], got, want))
        check(tag + ' every value equal to the value worked out through REST (%d fields)' % len(MAP), not bad, '; '.join(bad[:5]))
        check(tag + ' configuration item: %r' % CI_LITERAL[kind], el['consequence']['cmdb_ci'] == CI_LITERAL[kind], el['consequence']['cmdb_ci'])
        if kind == 'linked':
            c, ru = el['consequence'], el['rule']
            lit = {'state': 'Open', 'enforcement_status': 'Change Frozen', 'rule': FX['rule_number'], 'bofa_ait': 'AIT57152', 'consequence_level': '1', 'accountable_party': 'Application Manager', 'comments': FX['linked_comment'],
                   'change_freeze_effective_date': '09-15-2026 12:40:01', 'network_isolation_effective_date': '', 'rejection_reason': 'Not applicable', 'sys_id': FX['linked']}
            rlit = {'number': FX['rule_number'], 'global_exception': 'true', 'state': 'Approved', 'screated_by': 'rule.author', 'updated_by': 'rule.editor', 'created_on': '08-20-2026 10:15:00',
                    'updated_on': '09-02-2026 08:30:45', 'valid_from': '09-01-2026 00:00:00', 'valid_to': '12-31-2026 23:59:59', 'conditions': 'u_state=1^EQ', 'table': CONSEQUENCE, 'sys_id': FX['rule']}
            wrong = {k: c.get(k) for k, v in lit.items() if c.get(k) != v}; wrong.update({'rule.' + k: ru.get(k) for k, v in rlit.items() if ru.get(k) != v})
            check(tag + ' literals: choices as labels, references and the CI as display values, the rule section from the rule record (its own authors and times), checkbox "true"', not wrong, wrong)
            if run == 1:
                SAMPLE = json.loads(row['nested'].replace(os.environ['SN_USER'], 'admin'))
        if kind == 'bare':
            check(tag + ' rule section all "", the consequence carries its own values', all(v == '' for v in el['rule'].values()) and el['consequence']['number'] == FX['bare_number'] and el['consequence']['state'] == 'Open' and el['consequence']['rule'] == '', el)
        if kind == 'dangling':
            c = el['consequence']
            check(tag + ' a rule and an AIT that are gone give "", never their sys_ids; the rule section all ""; state and enforcement labels',
                  c['rule'] == '' and c['bofa_ait'] == '' and all(v == '' for v in el['rule'].values()) and c['state'] == 'Deferred' and c['enforcement_status'] == 'Pending Network Isolation Decision'
                  and c['network_isolation_effective_date'] == '10-05-2026 07:05:09', c)
        if kind == 'misclassed':
            check(tag + ' the second rule: checkbox "false", empty valid_to "", state label Closed', el['rule']['global_exception'] == 'false' and el['rule']['valid_to'] == '' and el['rule']['number'] == FX['rule_off_number']
                  and el['consequence']['state'] == 'Closed' and el['consequence']['enforcement_status'] == 'Network Isolated', el)
        if kind == 'ghost':
            check(tag + ' a CI that is gone gives ""; state Cancelled', el['consequence']['cmdb_ci'] == '' and el['consequence']['state'] == 'Cancelled', el['consequence'])

    # ---------- B. the rule on a real update and a real insert ----------
    r, messages = js('''
(function() {
var o = {};
%s
try { new sn_ih_kafka.ProducerV2(); o.api_missing = ''; } catch (e) { o.api_missing = '' + (e.message || e); }
var T = %s;
var a = new GlideRecord(T); a.get(%s); a.setValue('u_comments', 'Consequence outbound fixture (linked) run %d at ' + new GlideDateTime().getNumericValue()); a.update();
var n = new GlideRecord(T); n.initialize(); n.setValue('number', 'CONSEQ-CDP-INSERT-%d'); n.setValue('state', 2); n.setValue('u_consequence_level', '2'); n.setValue('u_comments', 'Consequence outbound fixture (inserted, run %d)'); o.inserted = '' + n.insert();
o.inserted_number = '' + n.getValue('number');
%s
var c = new GlideRecord(T); c.get(o.inserted); c.setWorkflow(false); c.deleteRecord(); o.gone = !new GlideRecord(T).get(o.inserted);
var back = new GlideRecord(T); back.get(%s); back.setWorkflow(false); back.setValue('u_comments', %s); back.update();
gs.print('X::' + JSON.stringify(o));
})();''' % (START, json.dumps(CONSEQUENCE), json.dumps(FX['linked']), run, run, run, LINES, json.dumps(FX['linked']), json.dumps(FX['linked_comment'])))
    check('B the send was reached on the update and on the insert: one line each, the platform\'s own error for the missing Kafka API (%r), nothing else' % r['api_missing'],
          r['api_missing'] != '' and sorted(r['lines']) == sorted([SENT + CONSEQUENCE + ' ' + FX['linked'] + ' - ' + r['api_missing'], SENT + CONSEQUENCE + ' ' + r['inserted'] + ' - ' + r['api_missing']]), r['lines'])
    payloads = {}
    for msg in messages:
        mm = re.match(r'Consequence payload for (\S+): (\{.*\})$', msg)
        if mm: payloads[mm.group(1)] = json.loads(mm.group(2))
    check('B one payload message per record on the page, nothing else', sorted(payloads) == sorted([FX['linked_number'], r['inserted_number']]) and len(messages) == 2, messages)
    upd, ins = payloads.get(FX['linked_number']), payloads.get(r['inserted_number'])
    check('B update: UPDATE, the two sections, the new comment', bool(upd) and upd['envelope']['element_activity'] == 'UPDATE' and list(upd['consequences'][0]) == ['consequence', 'rule']
          and upd['consequences'][0]['consequence']['comments'].startswith('Consequence outbound fixture (linked) run %d' % run) and upd['consequences'][0]['rule']['number'] == FX['rule_number'], upd)
    check('B insert: INSERT, state label Deferred, the rule section all ""', bool(ins) and ins['envelope']['element_activity'] == 'INSERT' and ins['consequences'][0]['consequence']['state'] == 'Deferred'
          and all(v == '' for v in ins['consequences'][0]['rule'].values()), ins)
    check('B inserted record removed afterwards', r['gone'])

    # ---------- C. error handling ----------
    CASES = {
        'layout': ' number = number ,\r\n state=state,\n\n x_boar_bofa_usem_0_consequence_rule.number = number ,x_boar_bofa_usem_0_consequence_rule.state=state,\nu_work_notes=work_notes,',
        'empty_field': 'number=number,\nx_boar_bofa_usem_0_consequence_rule.=valid_to,',
        'dot_walk_after_table': 'number=number,\nx_boar_bofa_usem_0_consequence_rule.u_owner.name=owner,',
        'two_equals': 'number=number,\nstate=a=b,',
        'no_field': 'number=number,\n=state,',
        'no_payload_name': 'number=number,\nstate=,',
        'bare_field': 'number=number,\nstate,',
        'other_table': 'number=number,\nx_boar_bofa_usem_0_other.name=name,',
        'dot_walk': 'number=number,\nu_rule.name=rule_name,',
        'duplicate': 'number=number,\nstate=number,',
        'missing': 'number=number,\nu_no_such_field=extra,\nx_boar_bofa_usem_0_consequence_rule.number=number,\nx_boar_bofa_usem_0_consequence_rule.u_no_such_rule_field=extra,',
        'separators': ' ,\n , \r\n,',
        'blank': '',
    }
    REASONS = {
        'two_equals': 'property %s holds a line with more than one "=": "state=a=b"' % FIELD_PROP,
        'no_field': 'property %s holds a line without a field name: "=state"' % FIELD_PROP,
        'no_payload_name': 'property %s holds a line without a payload name: "state="' % FIELD_PROP,
        'bare_field': 'property %s holds a line without a payload name: "state"' % FIELD_PROP,
        'other_table': 'property %s names table x_boar_bofa_usem_0_other, which is not a section of the payload: "x_boar_bofa_usem_0_other.name=name"' % FIELD_PROP,
        'dot_walk': 'property %s names table u_rule, which is not a section of the payload: "u_rule.name=rule_name"' % FIELD_PROP,
        'duplicate': 'property %s names number twice in section consequence' % FIELD_PROP,
        'empty_field': 'property %s holds the field "x_boar_bofa_usem_0_consequence_rule.", which is not <field> or <table>.<field>: "x_boar_bofa_usem_0_consequence_rule.=valid_to"' % FIELD_PROP,
        'dot_walk_after_table': 'property %s holds the field "x_boar_bofa_usem_0_consequence_rule.u_owner.name", which is not <field> or <table>.<field>: "x_boar_bofa_usem_0_consequence_rule.u_owner.name=owner"' % FIELD_PROP,
        'separators': 'property %s holds no field' % FIELD_PROP,
        'blank': 'table %s is not configured in property %s' % (CONSEQUENCE, FIELD_PROP),
    }
    r, messages = js('''
(function() {
var o = {cases: {}};
%s
new GlideUpdateSet().set(%s);
try { new sn_ih_kafka.ProducerV2(); o.api_missing = ''; } catch (e) { o.api_missing = '' + (e.message || e); }
var T = %s, FIELDS = %s, TOPIC = %s, cases = %s;
var C = x_boar_bofa_usem_0.BOFASIConsequenceOutboundProcessor, K = x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2;
var a = new GlideRecord(T); a.get(%s);
var good = new C().buildPayload(a);
o.unfetched = new C().buildPayload(new GlideRecord(T));
o.nothing = new C().buildPayload(null);
var inc = new GlideRecord('incident'); inc.setLimit(1); inc.query(); inc.next(); o.inc = inc.getUniqueValue(); o.other_record = new C().buildPayload(inc);
var fp = new GlideRecord('sys_properties'); fp.addQuery('name', FIELDS); fp.query(); fp.next(); var saved = '' + (fp.getValue('value') || '');
try {
    for (var k in cases) { fp.setValue('value', cases[k]); fp.update(); o.cases[k] = new C().buildPayload(a); }
} finally {
    fp.setValue('value', saved); fp.update();
}
o.fields_restored = gs.getProperty(FIELDS, '') == saved;
var tampered = JSON.parse(good); tampered.envelope.element_count = 2; tampered.envelope.event_id = 'not-a-uuid'; delete tampered.consequences[0].consequence.number; tampered.consequences[0].extra = {}; tampered.consequences[0].consequence.stranger = 'x'; tampered.consequences[0].consequence.state = 1;
var proc = new C();
try { proc._validatePayload(tampered, a, proc._fieldMapping(T)); o.tampered = 'accepted'; } catch (e) { o.tampered = '' + (e.message || e); }
try { proc._validatePayload(JSON.parse(good), a, proc._fieldMapping(T)); o.intact = 'accepted'; } catch (e) { o.intact = '' + (e.message || e); }
var tp = new GlideRecord('sys_properties'); tp.addQuery('name', TOPIC); tp.query(); tp.next(); var topic = '' + (tp.getValue('value') || '');
try {
    tp.setValue('value', ''); tp.update(); new K().sendPayload(good, a);
    tp.setValue('value', 'not-a-sys-id'); tp.update(); new K().sendPayload(good, a);
    tp.setValue('value', '  ' + topic + ' \\n'); tp.update(); new K().sendPayload(good, a);
} finally {
    tp.setValue('value', topic); tp.update();
}
o.topic_restored = gs.getProperty(TOPIC, '') == topic;
new K().sendPayload('', a);
new K().sendPayload('not json', a);
new K().sendPayload('{"a": 1}', a);
new K().sendPayload('{"envelope": {"element_count": 0}, "consequences": []}', a);
var two = JSON.parse(good); two.envelope.element_count = 2; new K().sendPayload(JSON.stringify(two), a);
new K().sendPayload(JSON.stringify(''), a);
new K().sendPayload(good, null);
var unsaved = new GlideRecord(T); unsaved.newRecord(); o.unsaved = unsaved.getUniqueValue(); new K().sendPayload(good, unsaved);
o.id = a.getUniqueValue();
%s
gs.print('X::' + JSON.stringify(o));
})();''' % (START, json.dumps(ST['default_set']), json.dumps(CONSEQUENCE), json.dumps(FIELD_PROP), json.dumps(TOPIC_PROP), json.dumps(CASES), json.dumps(FX['linked']), LINES))
    lay = json.loads(r['cases']['layout'])['consequences'][0]
    check('C accepted layout: spaces round names, CRLF, blank line, two pairs on one line, the same payload name in both sections',
          lay == {'consequence': {'number': FX['linked_number'], 'state': 'Open', 'work_notes': FX['latest_work_note']}, 'rule': {'number': FX['rule_number'], 'state': 'Approved'}}, lay)
    miss = json.loads(r['cases']['missing'])['consequences'][0]
    check('C fields the instance lacks are sent as "" and the section keeps the others', miss == {'consequence': {'number': FX['linked_number'], 'extra': ''}, 'rule': {'number': FX['rule_number'], 'extra': ''}}, miss)
    not_found = [m for m in messages if m.startswith('Consequence fields not found')]
    check('C one info message names the fields the instance lacks, table by table', not_found == ['Consequence fields not found on this instance, sent as "": %s.u_no_such_field, %s.u_no_such_rule_field' % (CONSEQUENCE, RULE)], not_found)
    check('C every other info message is a payload, one per build', all(m.startswith('Consequence payload for ') for m in messages if m not in not_found) and len(messages) - len(not_found) == 3, [m[:60] for m in messages])
    check('C every refused layout, an unfetched record, no record and a record of another table give ""', all(r['cases'][k] == '' for k in REASONS) and r['unfetched'] == '' and r['nothing'] == '' and r['other_record'] == '', {k: r['cases'][k][:40] for k in REASONS if r['cases'][k]})
    V = SENT + CONSEQUENCE + ' ' + r['id'] + ' - '
    want = [BUILT + CONSEQUENCE + ' ' + r['id'] + ' - ' + REASONS[k] for k in REASONS]
    want += [BUILT + 'no record - no record was given', BUILT + 'incident ' + r['inc'] + ' - table incident has no section in the payload']
    want += [V + 'property %s holds no topic sys_id' % TOPIC_PROP, V + 'property %s holds "not-a-sys-id", which is not a topic sys_id' % TOPIC_PROP, V + r['api_missing'],
             V + 'payload is empty', V + 'envelope is missing', V + 'envelope.type is missing or empty',
             V + 'envelope.element_count is 2 but consequences holds 1', V + 'payload is empty', SENT + 'no record - no record was given', SENT + CONSEQUENCE + ' ' + r['unsaved'] + ' - the record does not exist']
    unfetched = [m for m in r['lines'] if m.startswith(BUILT + CONSEQUENCE + ' ') and m.endswith(' - the record does not exist')]
    parser = [m for m in r['lines'] if m.startswith(V + 'payload is not valid JSON - ')]
    rest_lines = [m for m in r['lines'] if m not in unfetched and m not in parser]
    check('C one exact line per refusal (%d), the unfetched record named, text that is not JSON with the parser\'s reason, the padded topic accepted and trimmed (the send reached), nothing else' % (len(want) + 2),
          len(unfetched) == 1 and len(parser) == 1 and sorted(rest_lines) == sorted(want), 'extra: %s | missing: %s' % ([m for m in rest_lines if m not in want], [m for m in want if m not in rest_lines]))
    check('C validation names every problem of a tampered payload', all(s in r['tampered'] for s in ['payload invalid', 'element_count is "2"', 'not-a-uuid', 'section consequence lacks number', 'section extra is not in the field property', 'carries stranger', 'consequence.state is not a string']), r['tampered'])
    check('C validation accepts the intact payload; both properties restored', r['intact'] == 'accepted' and r['fields_restored'] and r['topic_restored'], (r['intact'], r['fields_restored'], r['topic_restored']))

    # ---------- D. configuration ----------
    r, _ = js('''
(function() {
var o = {props: {}, scripts: {}};
var p = new GlideRecord('sys_properties'); p.addQuery('name', 'STARTSWITH', 'x_boar_bofa_usem_0.usem.consequence.'); p.query(); while (p.next()) o.props['' + p.getValue('name')] = '' + p.getValue('value');
var s = new GlideRecord('sys_script_include'); s.addQuery('sys_scope', %s); s.query(); while (s.next()) o.scripts['' + s.getValue('name')] = '' + s.getValue('script');
var k = new GlideRecord('sys_script_include'); k.addQuery('api_name', 'x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2'); k.query(); o.producers = []; while (k.next()) o.producers.push('' + k.getValue('script'));
var b = new GlideRecord('sys_script'); b.addQuery('name', 'BOFA_BR_Consequence_CdpOutbound'); b.query(); o.rules = []; while (b.next()) o.rules.push({script: '' + b.getValue('script'), scope: '' + b.getValue('sys_scope'), order: '' + b.getValue('order')});
gs.print('X::' + JSON.stringify(o));
})();''' % json.dumps(ST['scope']))
    check('D two properties: the field property as delivered, the topic a sys_id', sorted(r['props']) == sorted([FIELD_PROP, TOPIC_PROP]) and r['props'][FIELD_PROP] == PROPS['usem.consequence.fields.' + CONSEQUENCE]['value'] and re.match(r'^[0-9a-f]{32}$', r['props'][TOPIC_PROP]), sorted(r['props']))
    src = {n: open(os.path.join(HERE, n + '.js')).read().rstrip('\n') for n in ['BOFASIConsequenceOutboundProcessor', 'BOFA_BR_Consequence_CdpOutbound']}
    src['BOFA_SI_KafkaProducerV2'] = open(os.path.join(BASE, 'stories', 'kafka-producer-v2', 'BOFA_SI_KafkaProducerV2.js')).read().rstrip('\n')
    check('D the shared producer is the one copy of the repository file in the integration application', len(r['producers']) == 1 and r['producers'][0].rstrip('\n') == src['BOFA_SI_KafkaProducerV2'])
    check('D the one script include of the application and the one rule equal the repository copies; the rule calls the shared producer', sorted(r['scripts']) == ['BOFASIConsequenceOutboundProcessor']
          and 'new x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2().sendPayload(payload, current);' in src['BOFA_BR_Consequence_CdpOutbound']
          and all(r['scripts'][n].rstrip('\n') == src[n] for n in r['scripts']) and len(r['rules']) == 1 and r['rules'][0]['script'].rstrip('\n') == src['BOFA_BR_Consequence_CdpOutbound'] and r['rules'][0]['scope'] == ST['scope'])
    proc, prod = src['BOFASIConsequenceOutboundProcessor'], src['BOFA_SI_KafkaProducerV2']
    check('D hygiene: one gs.error per script, no gs.info/warn, field types from records the processor opens itself',
          proc.count('gs.error(') == 1 and prod.count('gs.error(') == 1 and 'gs.info' not in proc + prod and 'gs.warn' not in proc + prod and proc.count('getED()') == 1 and 'dictionary.getElement(field).getED()' in proc)
print('RESULT: %d passed, %d failed' % (passed, failed))
if not failed:   # the sample is written from run 1 only when every check passed
    assert not re.search(r'probe|fixture|VSO-|' + re.escape(os.environ['SN_USER']) + '|' + re.escape(INST.split('//')[1].split('.')[0]), json.dumps(SAMPLE), re.I), 'test text in the sample'
    json.dump(SAMPLE, open(os.path.join(HERE, 'samples', 'Sample payload - consequence.json'), 'w'), indent=2)
ui.app('global')
sys.exit(1 if failed else 0)
