import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
SCOPE = '9d1e03de930b8310e3aef0aefaba10d5'  # stand-in scoped app on the PDI
PROPERTY = 'x_boar_bofa_usem_1.x_boar_bofa.usem.kafka.topic_sys_id'  # read by the producer, test fixture on the PDI
NAME = 'INC0010003_MS_Kafka Producer V2 and Payload Validator_V1.0'
SCRIPTS = {n: open(os.path.join(HERE, n + '.js')).read() for n in ['BOFA_SI_KafkaProducerV2', 'BOFA_SI_KafkaPayloadValidator']}
DESC = {
    'BOFA_SI_KafkaProducerV2': 'Utilizes KafkaProducer V2 to send messages to Hermes kafka.\nDocumentation of API used - https://www.servicenow.com/docs/r/api-reference/server-api-reference/ProducerV2ScopedAPI.html',
    'BOFA_SI_KafkaPayloadValidator': 'Checks an outbound Kafka payload before it is sent: well-formed JSON, the envelope with every mandatory field, and one list of elements matching element_count. Throws an Error naming the first problem found; BOFA_SI_KafkaProducerV2 logs it and does not send.',
}
ui = SNUI(); ui.app('global')
st_path = os.path.join(HERE, 'state.json')
ST = json.load(open(st_path)) if os.path.exists(st_path) else {}

# 1. global: pin the global Default set, then create the topic property fixture the producer reads
g = ui.js('''
var o = {};
var d = new GlideRecord('sys_update_set'); d.addQuery('name', 'Default'); d.addQuery('application', 'global'); d.query(); d.next();
new GlideUpdateSet().set(d.getUniqueValue()); o.global_default = d.getUniqueValue();
var p = new GlideRecord('sys_properties'); p.addQuery('name', %s); p.query();
if (!p.next()) { p.initialize(); p.setValue('name', %s); p.setValue('type', 'string'); p.setValue('value', gs.generateGUID());
  p.setValue('description', 'Test fixture: sys_id of the Kafka topic used by BOFA_SI_KafkaProducerV2.'); p.insert(); }
o.property = p.getUniqueValue(); o.topic = '' + p.getValue('value'); o.property_scope = '' + p.sys_scope.getDisplayValue();
o.read_back = '' + gs.getProperty(%s, '');
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(PROPERTY), json.dumps(PROPERTY), json.dumps(PROPERTY)))
assert g['read_back'] == g['topic'] and len(g['topic']) == 32, g
print('property fixture:', PROPERTY, '=', g['topic'], '|', g['property_scope'])

# 2. scoped: update set in the stand-in scope, pinned, then the two script includes
d = ui.js('''
var o = {rows: []};
var us = new GlideRecord('sys_update_set');
if (%s && us.get(%s)) { us.setValue('state', 'in progress'); us.update(); }
else { us.initialize(); us.setValue('name', %s); us.setValue('application', %s);
  us.setValue('description', 'Kafka producer (sn_ih_kafka.ProducerV2) and outbound payload validator for the CDP integration, built here in the stand-in scope.'); us.insert(); }
o.set = us.getUniqueValue(); o.set_scope = '' + us.application.getDisplayValue();
new GlideUpdateSet().set(o.set);
var scripts = %s; var desc = %s; o.si = {};
for (var name in scripts) {
    var si = new GlideRecord('sys_script_include'); si.addQuery('name', name); si.addQuery('sys_scope', %s); si.query();
    if (!si.next()) { si.initialize(); si.setValue('name', name); }
    si.setValue('script', scripts[name]); si.setValue('description', desc[name]); si.setValue('access', 'public');
    si.setValue('active', true); si.setValue('client_callable', false);
    si.update() || si.insert();
    o.si[name] = {sys_id: si.getUniqueValue(), api_name: '' + si.getValue('api_name'), scope: '' + si.sys_scope.getDisplayValue(), access: '' + si.getValue('access')};
}
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', o.set); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(bool(ST.get('set'))), json.dumps(ST.get('set', '')), json.dumps(NAME), json.dumps(SCOPE),
                                         json.dumps(SCRIPTS), json.dumps(DESC), json.dumps(SCOPE)), scope=SCOPE)
print('update set:', d['set'], '|', d['set_scope'])
for n, i in d['si'].items(): print(' ', i['api_name'], i['sys_id'], '|', i['scope'], '| access', i['access'])
print('\n'.join(' captured: ' + r for r in d['rows']))
assert d['set_scope'] == 'BofA Sim' and all(r.endswith('| BofA Sim') for r in d['rows']) and len(d['rows']) == 2
assert all(i['scope'] == 'BofA Sim' and i['access'] == 'public' for i in d['si'].values())
json.dump({'set': d['set'], 'set_name': NAME, 'scope': SCOPE, 'si': {n: i['sys_id'] for n, i in d['si'].items()},
           'property': g['property'], 'topic': g['topic'], 'global_default': g['global_default']}, open(st_path, 'w'), indent=1)
ui.app('global')
print('deployed: 2 script includes in the stand-in scope, update set scope matches every captured row')
