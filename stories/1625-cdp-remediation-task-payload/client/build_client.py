"""Deploys the client copy of the builder into the stand-in scope on the PDI, with the four
client-named properties as global test fixtures, so the JSON parsing is exercised exactly as the
client instance will run it."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); STORY = os.path.dirname(HERE); BASE = os.path.dirname(os.path.dirname(STORY))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
SCOPE = '9d1e03de930b8310e3aef0aefaba10d5'
NAME = 'INC0010003_MS_Remediation Task Payload Builder_V1.1'
script = open(os.path.join(HERE, 'BOA_SI_USEM_RemediationTaskPayloadBuilder.js')).read()
props = {n: open(os.path.join(HERE, n + '.txt')).read().rstrip('\n') for n in json.load(open(os.path.join(HERE, 'property_descriptions.json')))}
ui = SNUI(); ui.app('global')
st_path = os.path.join(HERE, 'state.json'); ST = json.load(open(st_path)) if os.path.exists(st_path) else {}
g = ui.js('''
var __g = {props: {}};
var d = new GlideRecord('sys_update_set'); d.addQuery('name', 'Default'); d.addQuery('application', 'global'); d.query(); d.next(); new GlideUpdateSet().set(d.getUniqueValue()); __g.global_default = d.getUniqueValue();
var props = %s;
for (var name in props) {
    var p = new GlideRecord('sys_properties'); p.addQuery('name', name); p.query();
    if (!p.next()) { p.initialize(); p.setValue('name', name); p.setValue('type', 'string'); p.setValue('description', 'Test fixture: client-named copy of the CDP field mapping.'); }
    p.setValue('value', props[name]); p.update() || p.insert(); __g.props[name] = {sys_id: p.getUniqueValue(), read_back: ('' + gs.getProperty(name, '')).length};
}
gs.print('X::' + JSON.stringify(__g));''' % json.dumps(props))
for n, i in g['props'].items(): assert i['read_back'] == len(props[n]), (n, i)
print('fixture properties:', len(g['props']), 'created/updated, all read back at full length')
d = ui.js('''
var __d = {rows: []};
var us = new GlideRecord('sys_update_set');
if (%s && us.get(%s)) { us.setValue('state', 'in progress'); us.setValue('name', %s); us.update(); }
else { us.initialize(); us.setValue('name', %s); us.setValue('application', %s); us.setValue('description', 'Client copy of the remediation task payload builder, built here in the stand-in scope.'); us.insert(); }
__d.set = us.getUniqueValue(); __d.set_scope = '' + us.application.getDisplayValue();
new GlideUpdateSet().set(__d.set);
var si = new GlideRecord('sys_script_include'); si.addQuery('name', 'BOA_SI_USEM_RemediationTaskPayloadBuilder'); si.addQuery('sys_scope', %s); si.query();
if (!si.next()) { si.initialize(); si.setValue('name', 'BOA_SI_USEM_RemediationTaskPayloadBuilder'); }
si.setValue('script', %s); si.setValue('access', 'public'); si.setValue('active', true); si.setValue('client_callable', false);
si.setValue('description', 'Builds the outbound Kafka payload for one remediation task; fields per table from the property usem.cdp.remtask.fields.<table>.');
si.update() || si.insert(); __d.si = si.getUniqueValue(); __d.api_name = '' + si.getValue('api_name');
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', __d.set); ux.query();
while (ux.next()) __d.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
gs.print('X::' + JSON.stringify(__d));''' % (json.dumps(bool(ST.get('set'))), json.dumps(ST.get('set', '')), json.dumps(NAME), json.dumps(NAME), json.dumps(SCOPE), json.dumps(SCOPE), json.dumps(script)), scope=SCOPE)
print('update set:', d['set'], '|', d['set_scope'], '|', d['api_name'], d['si']); print('\n'.join(' captured: ' + r for r in d['rows']))
assert d['set_scope'] == 'BofA Sim' and d['rows'] == ['BOA_SI_USEM_RemediationTaskPayloadBuilder | INSERT_OR_UPDATE | BofA Sim']
json.dump({'set': d['set'], 'set_name': NAME, 'si': d['si'], 'props': {n: i['sys_id'] for n, i in g['props'].items()}, 'global_default': g['global_default']}, open(st_path, 'w'), indent=1)
ui.app('global'); print('deployed')
