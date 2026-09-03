import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ui = SNUI(); ui.app('global')
HERE = os.path.join(BASE, 'stories', '1625-cdp-remediation-task-payload')
ST = json.load(open(os.path.join(HERE, 'state.json')))
P = json.load(open(os.path.join(HERE, 'properties.json')))
script = open(os.path.join(HERE, 'RemediationTaskPayloadBuilder.js')).read()
NAME = 'SNOWUSEMTP-1625_MS_Remediation Task CDP Payload_V2.0'
d = ui.js('''
var o = {rows: [], deleted: []};
var us = new GlideRecord('sys_update_set'); us.get(%s); us.setValue('state', 'in progress'); us.setValue('name', %s);
us.setValue('description', 'Kafka payload builder for remediation tasks sent to the sn_usem_remtask_outbound topic. One script include, RemediationTaskPayloadBuilder, builds envelope + rem_tasks for one record; the CDP required fields per table come from the system properties usem.cdp.remtask.fields.<table> (servicenow_field=json_field pairs) so field changes need no code change. change_requests and exception_requests are derived. The earlier CdpRemediationTaskPayloadBuilder and the superseded properties are removed.');
us.update();
new GlideUpdateSet().set(%s);
var um = new GlideUpdateManager2();
var gone = new GlideRecord('sys_script_include'); gone.addQuery('name', 'CdpRemediationTaskPayloadBuilder'); gone.query();
while (gone.next()) { o.deleted.push('' + gone.name); gone.deleteRecord(); }
var oldProps = ['usem.cdp.remtask.fields.common', 'usem.remtask.payload.fields', 'usem.cdp.remtask.changes.sn_vul_vulnerability', 'usem.cdp.remtask.changes.sn_vul_app_vulnerability', 'usem.cdp.remtask.changes.sn_vul_container_vulnerability', 'usem.cdp.remtask.changes.sn_vulc_result_group'];
for (var i = 0; i < oldProps.length; i++) { var op = new GlideRecord('sys_properties'); op.addQuery('name', oldProps[i]); op.query(); while (op.next()) { o.deleted.push('' + op.name); op.deleteRecord(); } }
var props = %s; var desc = %s;
for (var name in props) {
    var p = new GlideRecord('sys_properties'); p.addQuery('name', name); p.query();
    if (!p.next()) { p.initialize(); p.setValue('name', name); p.setValue('type', 'string'); }
    p.setValue('value', props[name]); p.setValue('description', desc[name]); p.setValue('ignore_cache', false);
    p.update() || p.insert(); um.saveRecord(p);
}
var si = new GlideRecord('sys_script_include'); si.get(%s); si.setValue('script', %s);
si.setValue('description', 'SNOWUSEMTP-1625 - builds the outbound Kafka payload (topic sn_usem_remtask_outbound) for one remediation task record. Fields per table come from usem.cdp.remtask.fields.<table>; a field missing on the table or empty is sent as an empty string; change_requests and exception_requests are derived; the activity comes from the record operation.');
si.update(); um.saveRecord(si);
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', %s); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
var left = new GlideRecord('sys_script_include'); left.addQuery('name', 'IN', 'RemediationTaskPayloadBuilder,CdpRemediationTaskPayloadBuilder'); left.query(); o.builders_left = []; while (left.next()) o.builders_left.push('' + left.name);
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(ST['set']), json.dumps(NAME), json.dumps(ST['set']), json.dumps(P['properties']), json.dumps(P['descriptions']), json.dumps(ST['si1']), json.dumps(script), json.dumps(ST['set'])))
print('\n'.join(d['rows'])); print('deleted:', d['deleted']); print('script includes left:', d['builders_left'])
assert len(d['rows']) == 12 and all(r.endswith('| Global') for r in d['rows']) and d['builders_left'] == ['RemediationTaskPayloadBuilder']
print('deployed: 1 script include + 4 properties, 1 script include + 6 properties deleted, all Global')
