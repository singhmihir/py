import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ui = SNUI()
ui.app('global')
si1 = open(BASE + '/stories/1625-cdp-remediation-task-payload/RemediationTaskPayloadBuilder.js').read()
si2 = open(BASE + '/stories/1625-cdp-remediation-task-payload/CdpRemediationTaskPayloadBuilder.js').read()
d = ui.js('''
var o = {rows: []};
var us = new GlideRecord('sys_update_set'); us.initialize();
us.setValue('name', 'SNOWUSEMTP-1625_MS_Remediation Task CDP Payload_V1.0');
us.setValue('description', 'Kafka payload builders for remediation tasks sent to the sn_usem_remtask_outbound topic. RemediationTaskPayloadBuilder builds the agreed payload (envelope + rem_tasks) for one remediation task record. CdpRemediationTaskPayloadBuilder extends it and builds the full mapping-driven payload from the sheet Outbound to CDP (RemTask) for sn_vul_vulnerability, sn_vul_app_vulnerability, sn_vul_container_vulnerability and sn_vulc_result_group, including change_requests and exception_requests.');
var id = us.insert(); o.set = '' + id; o.app = '' + us.application.getDisplayValue();
new GlideUpdateSet().set(id);
function si(name, script, desc) {
    var s = new GlideRecord('sys_script_include'); s.addQuery('name', name); s.query();
    if (!s.next()) { s.initialize(); s.setValue('name', name); s.setValue('api_name', 'global.' + name); }
    s.setValue('script', script); s.setValue('description', desc); s.setValue('access', 'public'); s.setValue('client_callable', false); s.setValue('active', true);
    var sid = s.update() || s.insert(); new GlideUpdateManager2().saveRecord(s); return '' + sid;
}
o.si1 = si('RemediationTaskPayloadBuilder', %s, 'SNOWUSEMTP-1625 - builds the outbound Kafka payload (topic sn_usem_remtask_outbound) for one remediation task record: envelope plus rem_tasks with the agreed remediation task fields.');
o.si2 = si('CdpRemediationTaskPayloadBuilder', %s, 'SNOWUSEMTP-1625 - extends RemediationTaskPayloadBuilder with the full CDP mapping (sheet Outbound to CDP (RemTask)) for every remediation task table, rendered by field type, plus change_requests and exception_requests.');
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', id); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.application.getDisplayValue());
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(si1), json.dumps(si2)))
print(json.dumps(d, indent=1))
assert d['app'] == 'Global' and len(d['rows']) == 2 and all(r.endswith('| Global') for r in d['rows'])
json.dump(d, open(BASE + '/stories/1625-cdp-remediation-task-payload/state.json', 'w'))
print('deployed: 2 script includes captured in Global set')
