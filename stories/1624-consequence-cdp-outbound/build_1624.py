"""Deploys the consequence outbound build into the stand-in scope on the PDI under a pinned update set:
the two script includes, the two properties (topic and the one field property of the consequence
table) and the after insert/update rule on that table. The repository files carry the client
application prefix x_boar_bofa_usem_0 (the consequence application: its tables, the rule, the scripts
and the properties); the deployment swaps it for the stand-in scope. Each version is a fresh
set: properties of earlier versions that are not deployed any more are removed under the scope's
Default set first. Re-runnable: reopens the set recorded in state.json when its name matches."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
SCOPE = '9d1e03de930b8310e3aef0aefaba10d5'          # stand-in scoped app on the PDI
CLIENT_PREFIX, PDI_PREFIX = 'x_boar_bofa_usem_0', 'x_196061_bofasim'   # the consequence application, which holds the tables, the rule and the scripts
NAME = 'SNOWUSEMTP-1624_MS_Consequence CDP Outbound Payload_V1.1'
DEFAULT_SET = 'a91e03de930b8310e3aef0aefaba10de'      # Default update set of the stand-in scope
BR_NAME = 'BOFA_BR_Consequence_CdpOutbound'
SI_NAMES = ['BOFASIConsequenceOutboundProcessor', 'BOFASIKafkaProducerConsequence']
TABLE = PDI_PREFIX + '_consequence'
DESC = {
    'BOFASIConsequenceOutboundProcessor': 'Builds the outbound CDP payload (envelope plus one consequence element) for a consequence record. The fields come from the property usem.consequence.fields.<consequence table>, the rule section through the u_rule reference.',
    'BOFASIKafkaProducerConsequence': 'Sends a consequence payload to the Kafka topic held in usem.consequence.kafka.topic_sys_id with sn_ih_kafka.ProducerV2 (key <table>.<sys_id>).\nDocumentation of API used - https://www.servicenow.com/docs/r/api-reference/server-api-reference/ProducerV2ScopedAPI.html',
}
def pdi(text): return text.replace(CLIENT_PREFIX, PDI_PREFIX)
scripts = {n: pdi(open(os.path.join(HERE, n + '.js')).read()) for n in SI_NAMES}
br_script = pdi(open(os.path.join(HERE, BR_NAME + '.js')).read())
props = {pdi(k): {'value': pdi(v['value']), 'description': v['description']} for k, v in json.load(open(os.path.join(HERE, 'properties.json'))).items()}
TOPIC_PROP = 'usem.consequence.kafka.topic_sys_id'
ui = SNUI(); ui.app('global')
st_path = os.path.join(HERE, 'state.json'); ST = json.load(open(st_path)) if os.path.exists(st_path) else {}
reuse = ST.get('set_name') == NAME
c = ui.js('''
var o = {removed: []};
new GlideUpdateSet().set(%s);
var p = new GlideRecord('sys_properties'); p.addQuery('name', 'STARTSWITH', %s); p.addQuery('name', 'NOT IN', %s); p.query();
while (p.next()) { o.removed.push('' + p.getValue('name')); p.deleteRecord(); }
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(DEFAULT_SET), json.dumps(PDI_PREFIX + '.usem.consequence.'), json.dumps(','.join(PDI_PREFIX + '.' + s for s in props))), scope=SCOPE)
print('properties of earlier versions removed under the Default set:', c['removed'])
d = ui.js('''
var o = {rows: [], si: {}, props: {}};
var us = new GlideRecord('sys_update_set');
if (%(has)s && us.get(%(set)s)) { us.setValue('state', 'in progress'); us.setValue('name', %(name)s); us.update(); }
else { us.initialize(); us.setValue('name', %(name)s); us.setValue('application', %(scope)s);
  us.setValue('description', 'Consequence outbound integration to CDP: payload processor, Kafka producer, properties and the after insert/update rule on the consequence table.'); us.insert(); }
o.set = us.getUniqueValue(); o.set_scope = '' + us.application.getDisplayValue();
new GlideUpdateSet().set(o.set);
var scripts = %(scripts)s, desc = %(desc)s;
for (var name in scripts) {
    var si = new GlideRecord('sys_script_include'); si.addQuery('name', name); si.addQuery('sys_scope', %(scope)s); si.query();
    if (!si.next()) { si.initialize(); si.setValue('name', name); }
    si.setValue('script', scripts[name]); si.setValue('description', desc[name]); si.setValue('access', 'public'); si.setValue('active', true); si.setValue('client_callable', false);
    si.update() || si.insert();
    o.si[name] = {sys_id: si.getUniqueValue(), api_name: '' + si.getValue('api_name'), scope: '' + si.sys_scope.getDisplayValue(), access: '' + si.getValue('access')};
}
var props = %(props)s, prefix = %(prefix)s;
for (var suffix in props) {
    var pname = prefix + '.' + suffix;
    var p = new GlideRecord('sys_properties'); p.addQuery('name', pname); p.query();
    if (!p.next()) { p.initialize(); p.setValue('name', pname); p.setValue('type', 'string'); }
    var value = props[suffix].value;
    if (suffix == %(topic)s) value = ('' + p.getValue('value')).length == 32 ? '' + p.getValue('value') : gs.generateGUID();
    p.setValue('value', value); p.setValue('description', props[suffix].description);
    p.update() || p.insert();
    o.props[suffix] = {sys_id: p.getUniqueValue(), name: pname, scope: '' + p.sys_scope.getDisplayValue(), read_back: '' + gs.getProperty(pname, '')};
}
var br = new GlideRecord('sys_script'); br.addQuery('name', %(br)s); br.addQuery('collection', %(table)s); br.query();
if (!br.next()) { br.initialize(); br.setValue('name', %(br)s); br.setValue('collection', %(table)s); }
br.setValue('when', 'after'); br.setValue('order', 100); br.setValue('action_insert', true); br.setValue('action_update', true); br.setValue('action_delete', false); br.setValue('action_query', false);
br.setValue('active', true); br.setValue('abort_action', false); br.setValue('filter_condition', ''); br.setValue('condition', ''); br.setValue('script', %(br_script)s);
br.setValue('description', 'Builds the CDP payload for the consequence with BOFASIConsequenceOutboundProcessor and sends it with BOFASIKafkaProducerConsequence on every insert and update.');
br.update() || br.insert();
o.br = {sys_id: br.getUniqueValue(), scope: '' + br.sys_scope.getDisplayValue(), when: '' + br.getValue('when'), order: '' + br.getValue('order'), insert: '' + br.getValue('action_insert'), update: '' + br.getValue('action_update'), active: '' + br.getValue('active'), collection: '' + br.getValue('collection')};
gs.print('X::' + JSON.stringify(o));''' % dict(has=json.dumps(reuse), set=json.dumps(ST.get('set', '')), name=json.dumps(NAME), scope=json.dumps(SCOPE),
                                            scripts=json.dumps(scripts), desc=json.dumps(DESC), props=json.dumps(props), prefix=json.dumps(PDI_PREFIX), topic=json.dumps(TOPIC_PROP),
                                            br=json.dumps(BR_NAME), table=json.dumps(TABLE), br_script=json.dumps(br_script)), scope=SCOPE)
a = ui.js('''
var o = {rows: [], captured: 0};
new GlideUpdateSet().set(%s);
var ids = %s;
for (var i = 0; i < ids.length; i++) { var gr = new GlideRecord(ids[i][0]); if (gr.get(ids[i][1])) { new GlideUpdateManager2().saveRecord(gr); o.captured++; } }
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', %s); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(d['set']), json.dumps([['sys_script_include', i['sys_id']] for i in d['si'].values()] + [['sys_properties', i['sys_id']] for i in d['props'].values()] + [['sys_script', d['br']['sys_id']]]), json.dumps(d['set'])))
d['rows'] = a['rows']
print('update set:', d['set'], '|', d['set_scope'], '|', NAME, '| records captured explicitly:', a['captured'])
for n, i in d['si'].items(): print('  script include:', i['api_name'], i['sys_id'], '|', i['scope'], '| access', i['access'])
for s, i in d['props'].items():
    expect = props[s]['value'] if s != TOPIC_PROP else i['read_back']
    print('  property:', i['name'], i['sys_id'], '|', i['scope'], '| read back', len(i['read_back']), 'chars')
    assert i['read_back'] == expect and i['scope'] == 'BofA Sim' and (s != TOPIC_PROP or len(i['read_back']) == 32), (s, i)
print('  rule:', BR_NAME, d['br']['sys_id'], '|', d['br'])
print('\n'.join('  captured: ' + r for r in d['rows']))
assert d['set_scope'] == 'BofA Sim' and all(r.endswith('| BofA Sim') for r in d['rows']) and len(d['rows']) == 2 + len(props) + 1, d['rows']
assert all(i['scope'] == 'BofA Sim' and i['access'] == 'public' and i['api_name'] == PDI_PREFIX + '.' + n for n, i in d['si'].items())
assert d['br'] == dict(sys_id=d['br']['sys_id'], scope='BofA Sim', when='after', order='100', insert='1', update='1', active='1', collection=TABLE)
json.dump({'set': d['set'], 'set_name': NAME, 'previous_set': ST.get('set') if not reuse else ST.get('previous_set'), 'scope': SCOPE, 'si': {n: i['sys_id'] for n, i in d['si'].items()}, 'props': {s: i['sys_id'] for s, i in d['props'].items()},
           'topic': d['props'][TOPIC_PROP]['read_back'], 'br': d['br']['sys_id'], 'rows': len(d['rows'])}, open(st_path, 'w'), indent=1)
ui.app('global')
print('deployed: 2 script includes, %d properties, 1 rule; update set scope matches every captured row' % len(props))
