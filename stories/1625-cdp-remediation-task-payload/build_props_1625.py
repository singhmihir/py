import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ui = SNUI(); ui.app('global')
HERE = os.path.join(BASE, 'stories', '1625-cdp-remediation-task-payload')
ST = json.load(open(os.path.join(HERE, 'state.json')))
P = json.load(open(os.path.join(HERE, 'properties.json')))
si1 = open(os.path.join(HERE, 'RemediationTaskPayloadBuilder.js')).read()
si2 = open(os.path.join(HERE, 'CdpRemediationTaskPayloadBuilder.js')).read()
d = ui.js('''
var o = {props: [], rows: []};
var us = new GlideRecord('sys_update_set'); us.get(%s); us.setValue('state', 'in progress'); us.setValue('name', 'SNOWUSEMTP-1625_MS_Remediation Task CDP Payload_V1.2'); us.update();
new GlideUpdateSet().set(%s);
var props = %s; var desc = %s;
for (var name in props) {
    var p = new GlideRecord('sys_properties'); p.addQuery('name', name); p.query();
    if (!p.next()) { p.initialize(); p.setValue('name', name); p.setValue('type', 'string'); }
    p.setValue('value', props[name]); p.setValue('description', desc[name]); p.setValue('ignore_cache', false);
    var pid = p.update() || p.insert(); new GlideUpdateManager2().saveRecord(p); o.props.push(name);
}
var a = new GlideRecord('sys_script_include'); a.get(%s); a.setValue('script', %s); a.update();
var b = new GlideRecord('sys_script_include'); b.get(%s); b.setValue('script', %s); b.update();
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', %s); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.application.getDisplayValue());
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(ST['set']), json.dumps(ST['set']), json.dumps(P['properties']), json.dumps(P['descriptions']),
                                            json.dumps(ST['si1']), json.dumps(si1), json.dumps(ST['si2']), json.dumps(si2), json.dumps(ST['set'])))
print('\n'.join(d['rows']))
assert len(d['rows']) == 12 and all(r.endswith('| Global') for r in d['rows'])
print('deployed: 10 properties + 2 script includes captured in Global set')
