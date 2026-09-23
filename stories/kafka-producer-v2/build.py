import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
SCOPE = '4ba447d22b43cb10cb55fbcc6e91bf0f'  # mirror of the client application BOFA USEM CDP integration (x_boar_bofa_usem_1), same sys_id
STANDIN = '9d1e03de930b8310e3aef0aefaba10d5'  # stand-in scoped app that held the producer until V1.4
CLIENT_SYS_ID = '075d9ba02b9fc7102b30f8e14391bfdb'  # the producer's sys_id on the client instance
APP_NAME = 'BOFA USEM CDP integration'
STALE_PROPERTY = 'x_boar_bofa_usem_1.usem.cdp.remtask.kafka.topic_sys_id'   # created for a separate remediation task topic, which is not finalised: removed
PROPERTY = 'x_boar_bofa_usem_1.x_boar_bofa.usem.kafka.topic_sys_id'  # the finding topic, the client's own property; a test fixture on the PDI
NAME = 'INC0010003_MS_Kafka Producer V2 with Payload Validation_V1.5'
SCRIPTS = {n: open(os.path.join(HERE, n + '.js')).read() for n in ['BOFA_SI_KafkaProducerV2']}
DESC = {
    'BOFA_SI_KafkaProducerV2': 'Utilizes KafkaProducer V2 to send messages to Hermes kafka. The payload is validated before it is sent (payload validation section of the script).\nDocumentation of API used - https://www.servicenow.com/docs/r/api-reference/server-api-reference/ProducerV2ScopedAPI.html',
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

# 2. the stand-in copy goes (under the stand-in's Default set): the producer lives in the mirror of the client application,
#    where the consequence rule of x_boar_bofa_usem_0 calls it by its client name x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2
r = ui.js('''
var o = {removed: []};
var d = new GlideRecord('sys_update_set'); d.addQuery('application', %s); d.addQuery('is_default', true); d.query(); d.next(); new GlideUpdateSet().set(d.getUniqueValue());
var gone = new GlideRecord('sys_script_include'); gone.addQuery('sys_scope', %s); gone.addQuery('name', 'IN', 'BOFA_SI_KafkaProducerV2,BOFA_SI_KafkaPayloadValidator'); gone.query();
while (gone.next()) { o.removed.push('' + gone.getValue('api_name')); gone.deleteRecord(); }
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(STANDIN), json.dumps(STANDIN)), scope=STANDIN)
print('stand-in copies removed:', r['removed'])

# 3. mirror application: update set, pinned, then the producer under the client's sys_id, captured explicitly
reuse = ST.get('set_name') == NAME
d = ui.js('''
var o = {rows: []};
var us = new GlideRecord('sys_update_set');
if (%s && us.get(%s)) { us.setValue('state', 'in progress'); us.update(); }
else { us.initialize(); us.setValue('name', %s); us.setValue('application', %s);
  us.setValue('description', 'Kafka producer (sn_ih_kafka.ProducerV2) with payload validation, shared by the finding, remediation task and consequence tables.'); us.insert(); }
o.set = us.getUniqueValue(); o.set_scope = '' + us.application.getDisplayValue();
new GlideUpdateSet().set(o.set);
var scripts = %s; var desc = %s; o.si = {};
for (var name in scripts) {
    var si = new GlideRecord('sys_script_include');
    if (!si.get(%s)) { si.initialize(); si.setNewGuidValue(%s); si.setValue('name', name); }
    si.setValue('script', scripts[name]); si.setValue('description', desc[name]); si.setValue('access', 'public');
    si.setValue('active', true); si.setValue('client_callable', false);
    si.update() || si.insert();
    var back = new GlideRecord('sys_script_include'); back.get(si.getUniqueValue()); new GlideUpdateManager2().saveRecord(back);
    o.si[name] = {sys_id: back.getUniqueValue(), api_name: '' + back.getValue('api_name'), scope: '' + back.sys_scope.getDisplayValue(), access: '' + back.getValue('access')};
}
var rp = new GlideRecord('sys_properties'); rp.addQuery('name', %s); rp.query(); o.stale_removed = 0;
while (rp.next()) {
    var rid = rp.getUniqueValue(); rp.deleteRecord(); o.stale_removed++;
    var ur = new GlideRecord('sys_update_xml'); ur.addQuery('update_set', o.set); ur.addQuery('name', 'sys_properties_' + rid); ur.query(); while (ur.next()) ur.deleteRecord();
}
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', o.set); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(reuse), json.dumps(ST.get('set', '')), json.dumps(NAME), json.dumps(SCOPE),
                                         json.dumps(SCRIPTS), json.dumps(DESC), json.dumps(CLIENT_SYS_ID), json.dumps(CLIENT_SYS_ID),
                                         json.dumps(STALE_PROPERTY)), scope=SCOPE)
print('update set:', d['set'], '|', d['set_scope'])
for n, i in d['si'].items(): print(' ', i['api_name'], i['sys_id'], '|', i['scope'], '| access', i['access'])
print('\n'.join(' captured: ' + r for r in d['rows']))
print(' stale property removed:', STALE_PROPERTY, d['stale_removed'])
assert d['set_scope'] == APP_NAME and d['rows'] == ['BOFA_SI_KafkaProducerV2 | INSERT_OR_UPDATE | ' + APP_NAME], d['rows']
assert all(i['scope'] == APP_NAME and i['access'] == 'public' and i['sys_id'] == CLIENT_SYS_ID and i['api_name'] == 'x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2' for i in d['si'].values())
json.dump({'set': d['set'], 'set_name': NAME, 'scope': SCOPE, 'si': {n: i['sys_id'] for n, i in d['si'].items()},
           'property': g['property'], 'topic': g['topic'], 'global_default': g['global_default']}, open(st_path, 'w'), indent=1)
ui.app('global')
print('deployed: producer in the integration application under its client sys_id, stand-in copy removed, update set scope matches every captured row')
