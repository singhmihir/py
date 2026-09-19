"""SNOWUSEMTP-1825: extend the Security Support Common property sn_sec_cmn.ignoreCIClass (the CI classes
the CI lookup rules never match against) with the classes listed on the story, captured in an update set
of the property's own scope. Re-running reopens the same set. Writes state.json."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
NAME = 'SNOWUSEMTP-1825_MS_Ignore CI Classes for Lookup Rules_V1.0'
DESC = ('Security Support Common property sn_sec_cmn.ignoreCIClass extended with the CI classes that discovered items must never be '
        'matched against: IP address, network adapter and NIC records, storage volumes, disk partitions, file systems and storage pools, '
        'load balancer devices and pool members, DNS names, virtual machine instances and templates, router interfaces, switch forwarding '
        'rules, TCP endpoints, print queues and certificates. The five classes already on the property are kept.')
SCOPE = 'f38c97005301120034c69816a11c081d'            # Security Support Common (sn_sec_cmn)
PROPERTY = 'sn_sec_cmn.ignoreCIClass'
ADD = ['cmdb_ci_ip_address', 'cmdb_ci_network_adapter', 'cmdb_ci_nic', 'cmdb_ci_vmware_nic', 'cmdb_ci_storage_volume',
       'cmdb_ci_disk_partition', 'cmdb_ci_lb', 'cmdb_ci_dns_name', 'cmdb_ci_file_system', 'cmdb_ci_vm_instance',
       'cmdb_ci_vm_template', 'cmdb_ci_vmware_instance', 'cmdb_ci_storage_pool', 'cmdb_ci_lb_pool_member',
       'dscy_router_interface', 'dscy_swtch_fwd_rule', 'cmdb_ci_endpoint_tcp', 'cmdb_ci_print_queue', 'cmdb_ci_certificate']
STATE = os.path.join(HERE, 'state.json')
PRIOR = json.load(open(STATE))['set'] if os.path.exists(STATE) else ''
ui = SNUI()
d = ui.js('''
var o = {rows: []};
var us = new GlideRecord('sys_update_set'); var prior = %s;
if (prior && us.get(prior)) { o.set = us.getUniqueValue(); us.setValue('state', 'in progress'); us.update(); }
else { us.initialize(); us.setValue('name', %s); us.setValue('application', %s); us.setValue('state', 'in progress'); us.setValue('description', %s); o.set = '' + us.insert(); }
new GlideUpdateSet().set(o.set);
var p = new GlideRecord('sys_properties'); p.addQuery('name', %s); p.query(); p.next();
o.before = '' + p.getValue('value');
var have = o.before.split(','); var add = %s; var missing = [];
for (var i = 0; i < add.length; i++) if (have.indexOf(add[i]) == -1) have.push(add[i]);
for (var j = 0; j < have.length; j++) { var t = new GlideRecord('sys_db_object'); t.addQuery('name', have[j]); t.query(); if (!t.next()) missing.push(have[j]); }
o.after = have.join(',');
if (o.after != o.before) { p.setValue('value', o.after); p.update(); }
o.stored = '' + gs.getProperty(%s);
o.not_on_this_instance = missing;
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', o.set); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue() + ' | ' + ux.getValue('name'));
var s2 = new GlideRecord('sys_update_set'); s2.get(o.set); o.set_app = '' + s2.application.getDisplayValue(); o.set_name = '' + s2.getValue('name');
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(PRIOR), json.dumps(NAME), json.dumps(SCOPE), json.dumps(DESC), json.dumps(PROPERTY), json.dumps(ADD), json.dumps(PROPERTY)), scope=SCOPE)
print('set:', d['set'], '|', d['set_name'], '|', d['set_app'])
print('before:', d['before']); print('after: ', d['after']); print('stored value matches:', d['stored'] == d['after'])
print('classes not present on this instance (kept on the property):', d['not_on_this_instance'] or 'none')
print('captured:'); print('\n'.join(d['rows']))
assert d['stored'] == d['after'] and len(d['rows']) == 1 and all('| Security Support Common |' in r for r in d['rows']) and d['set_app'] == 'Security Support Common'
json.dump({'set': d['set'], 'name': NAME, 'rows': 1, 'file': 'Ignore CI Classes for Lookup Rules - Update Set.xml', 'value': d['after']}, open(STATE, 'w'), indent=1)
print('DEPLOYED: property captured (1 row), Security Support Common')
