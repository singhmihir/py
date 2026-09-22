"""Deploys the VAMP outbound build on the PDI into the mirror of the client integration application
(scope x_boar_bofa_usem_1, the client's application sys_id) under a pinned update set: the two script
includes, the three properties (topic, sections and fields of the application vulnerable item table)
and the after insert/update rule on that table. Nothing is renamed: the repository files carry the
client names and the PDI holds the same application, so the export imports on the client instance as
is. Each version is a fresh set: properties of earlier versions that are not deployed any more are
removed under the application's Default set first. Re-runnable: reopens the set recorded in state.json
when its name matches."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
SCOPE = '4ba447d22b43cb10cb55fbcc6e91bf0f'          # mirror of the client application BOFA USEM CDP integration on the PDI, same sys_id and scope name
PREFIX = 'x_boar_bofa_usem_1'
APP_NAME = 'BOFA USEM CDP integration'
NAME = 'SNOWUSEMTP-1804_MS_VAMP AVIT Outbound Payload_V2.0'
TOPIC_PROP = 'usem.vamp.kafka.topic_sys_id'
BR_NAME = 'BOFA_BR_AVIT_VampOutbound'
SI_NAMES = ['BOFASIVampOutboundProcessor', 'BOFASIKafkaProducerVamp']
DESC = {
    'BOFASIVampOutboundProcessor': 'Builds the outbound VAMP payload (envelope plus one finding element) for an application vulnerable item. The sections come from the property usem.vamp.sections.<item table> and their fields from usem.vamp.fields.<item table>; the remediation tasks of the item are a list, one entry per linked task.',
    'BOFASIKafkaProducerVamp': 'Sends a VAMP payload to the Kafka topic held in usem.vamp.kafka.topic_sys_id with sn_ih_kafka.ProducerV2 (key <table>.<sys_id>).\nDocumentation of API used - https://www.servicenow.com/docs/r/api-reference/server-api-reference/ProducerV2ScopedAPI.html',
}
scripts = {n: open(os.path.join(HERE, n + '.js')).read() for n in SI_NAMES}
br_script = open(os.path.join(HERE, BR_NAME + '.js')).read()
props = json.load(open(os.path.join(HERE, 'properties.json')))
ui = SNUI(); ui.app('global')
st_path = os.path.join(HERE, 'state.json'); ST = json.load(open(st_path)) if os.path.exists(st_path) else {}
reuse = ST.get('set_name') == NAME
app = ui.js('''
var o = {};
var a = new GlideRecord('sys_app');
if (!a.get(%s)) {
    a.initialize(); a.setNewGuidValue(%s); a.setValue('name', %s); a.setValue('scope', %s);
    a.setValue('source', %s); a.setValue('vendor_prefix', 'boar'); a.setValue('version', '1.0.0'); a.insert();
    o.created = true;
} else if (a.getValue('source') != %s) { a.setValue('source', %s); a.setWorkflow(false); a.update(); o.corrected = true; }
var b = new GlideRecord('sys_app'); b.get(%s);
o.app = {sys_id: '' + b.getUniqueValue(), name: '' + b.getValue('name'), scope: '' + b.getValue('scope'), source: '' + b.getValue('source')};
var d = new GlideRecord('sys_update_set'); d.addQuery('application', %s); d.addQuery('is_default', true); d.query();
if (!d.next()) { d.initialize(); d.setValue('name', 'Default'); d.setValue('application', %s); d.setValue('is_default', true); d.setValue('state', 'in progress'); d.insert(); }
o.default_set = d.getUniqueValue();
gs.print('X::' + JSON.stringify(o));''' % ((json.dumps(SCOPE), json.dumps(SCOPE), json.dumps(APP_NAME), json.dumps(PREFIX)) + (json.dumps(PREFIX),) * 3 + (json.dumps(SCOPE),) * 3))
assert app['app'] == {'sys_id': SCOPE, 'name': APP_NAME, 'scope': PREFIX, 'source': PREFIX}, app
print('application:', app['app'], '| default set', app['default_set'])
DEFAULT_SET = app['default_set']
c = ui.js('''
var o = {removed: []};
new GlideUpdateSet().set(%s);
var p = new GlideRecord('sys_properties'); p.addQuery('name', 'STARTSWITH', %s); p.addQuery('name', 'NOT IN', %s); p.query();
while (p.next()) { o.removed.push('' + p.getValue('name')); p.deleteRecord(); }
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(DEFAULT_SET), json.dumps(PREFIX + '.usem.vamp.'), json.dumps(','.join(PREFIX + '.' + s for s in props))), scope=SCOPE)
print('properties of earlier versions removed under the Default set:', c['removed'])
d = ui.js('''
var o = {rows: [], si: {}, props: {}};
var us = new GlideRecord('sys_update_set');
if (%(has)s && us.get(%(set)s)) { us.setValue('state', 'in progress'); us.setValue('name', %(name)s); us.update(); }
else { us.initialize(); us.setValue('name', %(name)s); us.setValue('application', %(scope)s);
  us.setValue('description', 'VAMP outbound integration for application vulnerable items: payload processor, Kafka producer, properties and the after insert/update rule.'); us.insert(); }
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
var br = new GlideRecord('sys_script'); br.addQuery('name', %(br)s); br.addQuery('collection', 'sn_vul_app_vulnerable_item'); br.addQuery('sys_scope', %(scope)s); br.query();
if (!br.next()) { br.initialize(); br.setValue('name', %(br)s); br.setValue('collection', 'sn_vul_app_vulnerable_item'); }
br.setValue('when', 'after'); br.setValue('order', 100); br.setValue('action_insert', true); br.setValue('action_update', true); br.setValue('action_delete', false); br.setValue('action_query', false);
br.setValue('active', true); br.setValue('abort_action', false); br.setValue('filter_condition', ''); br.setValue('condition', ''); br.setValue('script', %(br_script)s);
br.setValue('description', 'Builds the VAMP payload for the application vulnerable item with BOFASIVampOutboundProcessor and sends it with BOFASIKafkaProducerVamp on every insert and update.');
br.update() || br.insert();
o.br = {sys_id: br.getUniqueValue(), scope: '' + br.sys_scope.getDisplayValue(), when: '' + br.getValue('when'), order: '' + br.getValue('order'), insert: '' + br.getValue('action_insert'), update: '' + br.getValue('action_update'), active: '' + br.getValue('active')};
gs.print('X::' + JSON.stringify(o));''' % dict(has=json.dumps(reuse), set=json.dumps(ST.get('set', '')), name=json.dumps(NAME), scope=json.dumps(SCOPE),
                                            scripts=json.dumps(scripts), desc=json.dumps(DESC), props=json.dumps(props), prefix=json.dumps(PREFIX),
                                            br=json.dumps(BR_NAME), br_script=json.dumps(br_script), topic=json.dumps(TOPIC_PROP)), scope=SCOPE)
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
    assert i['read_back'] == expect and i['scope'] == APP_NAME and (s != TOPIC_PROP or len(i['read_back']) == 32), (s, i)
print('  rule:', BR_NAME, d['br']['sys_id'], '|', d['br'])
print('\n'.join('  captured: ' + r for r in d['rows']))
assert d['set_scope'] == APP_NAME and all(r.endswith('| ' + APP_NAME) for r in d['rows']) and len(d['rows']) == 2 + len(props) + 1, d['rows']
assert all(i['scope'] == APP_NAME and i['access'] == 'public' and i['api_name'] == PREFIX + '.' + n for n, i in d['si'].items())
assert d['br'] == dict(sys_id=d['br']['sys_id'], scope=APP_NAME, when='after', order='100', insert='1', update='1', active='1')
json.dump({'set': d['set'], 'set_name': NAME, 'previous_set': ST.get('set') if not reuse else ST.get('previous_set'), 'scope': SCOPE, 'si': {n: i['sys_id'] for n, i in d['si'].items()}, 'props': {s: i['sys_id'] for s, i in d['props'].items()},
           'app_name': APP_NAME, 'default_set': DEFAULT_SET, 'topic': d['props'][TOPIC_PROP]['read_back'], 'br': d['br']['sys_id'], 'rows': len(d['rows'])}, open(st_path, 'w'), indent=1)
ui.app('global')
print('deployed: 2 script includes, %d properties, 1 rule; update set scope matches every captured row' % len(props))
