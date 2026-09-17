"""Deploys the load balancer refinements of 17 Sep into one Global update set: rule 350 refuses a
load balancer device at the end of the discovery chain; rules 455 and 460 treat several Load Balancer
Service records of one name (an HA pair, a test copy) as one virtual server; rule 455 treats several
server records of one name as one machine and returns its fittest record. Captured explicitly with
GlideUpdateManager2.saveRecord. No other rule is touched. V1.1 (same day): a member the CMDB cannot place makes 455
decline, and 460 walks the same pool and attaches the virtual server record only when the CMDB does not show several
servers behind it."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
NAME = 'SNOWUSEMTP-895_MS_Qualys CI Lookup Rules Load Balancer Refinements_V1.1'
DESC = ('Three USEM Qualys CI lookup rules re-issued. 350 Layered DNS Match refuses a load balancer device at the end of the DNS Name -> IP '
        'Address -> adapter -> CI chain, because the name then belongs to a virtual address the balancer answers on; the host goes on to the '
        'load balancer rules. 455 Load Balancer Member Match and 460 Load Balancer Service Match treat several Load Balancer Service records '
        'carrying one name (an HA pair keeps the same virtual server on both devices; a test leaves a copy) as the same virtual server recorded '
        'more than once: the records answering on the scanned address are kept, then the live ones; the member rule walks the pools of every '
        'record kept, the service rule returns the one record left and declines when two live records still compete; two different names on '
        'one value still decline. 455 also treats several server records of one name as one machine: a retired record is set aside for the '
        'live one, two live records decline, two differently named machines decline; a member that leads to no server in the CMDB makes 455 '
        'decline, because the pool is then partly unknown. 460 walks the same pool and attaches the virtual server record only when the pool '
        'is unknown, empty, or fronts one server; several member addresses or several machines leave the host unmatched. No guess is made '
        'anywhere: an ambiguity the CMDB cannot settle leaves the item unmatched. No system property is read or shipped.')
QUALYS = 'ed44bdc453220300e8f9f745911c0801'
RULES = [
    ('350', 'USEM Layered DNS Match', 'DNS', 'DNS Name record -> IP Address record -> Network Adapter -> CI, for hosts whose name is not on the CI record; a CI whose class contradicts the scanned OS is left out (a Linux fingerprint agrees with Network Gear, Load Balancer and Storage Server records); several CIs resolved by the scanned IP or declined; a load balancer device at the end of the chain is refused, the name then belongs to a virtual address.'),
    ('455', 'USEM Load Balancer Member Match', 'IP', 'Virtual server found as the service rule does (records of one name on the scanned address are one virtual server, retired copies set aside), then Load Balancer Service -> Pool -> Pool Member -> server; the one machine every member leads to, its live record when a retired duplicate exists, or null (a member the CMDB cannot place, no machine, two machines, two live records of one machine) so that the service rule decides.'),
    ('460', 'USEM Load Balancer Service Match', 'IP', 'Virtual IP matched to its Load Balancer Service CI when the CMDB does not show several servers behind it: load balancer OS word or VIP label marker required, service found by fqdn, then name, then address (records of one name are one virtual server; two live records or two different names decline), then the pool walked as in the member rule; the record is attached when the pool is unknown, empty, or fronts one server, and the host stays unmatched when several member addresses or several machines sit behind it. The product and marker lists are declared in the script.'),
]
rules = [{'order': o, 'name': n, 'field': f, 'description': d, 'script': open(os.path.join(HERE, 'rules', '%s_%s.js' % (o, n.replace(' ', '_')))).read()} for o, n, f, d in RULES]
STATE = os.path.join(HERE, 'state_v9.json')
PRIOR = json.load(open(STATE))['set'] if os.path.exists(STATE) else ''
assert all('gs.getProperty(' not in r['script'].replace("gs.getProperty('sn_sec_cmn.ignoreCIClass'", '') for r in rules), 'a rule still reads a property'
ui = SNUI(); ui.app('global')
d = ui.js('''
var o = {rows: [], rules: []};
var us = new GlideRecord('sys_update_set'); var prior = %s;
if (prior && us.get(prior)) { o.set = us.getUniqueValue(); us.setValue('state', 'in progress'); us.update();
    var us1 = new GlideRecord('sys_update_set'); us1.get(o.set); us1.setValue('name', %s); us1.setValue('description', %s); us1.update(); }
else { us.initialize(); us.setValue('name', %s); us.setValue('application', 'global'); us.setValue('state', 'in progress'); us.setValue('description', %s); o.set = '' + us.insert(); }
new GlideUpdateSet().set(o.set);
var um = new GlideUpdateManager2();
var rules = %s;
for (var i = 0; i < rules.length; i++) {
    var r = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); r.addQuery('name', rules[i].name); r.addQuery('source', %s); r.query();
    if (!r.next()) { r.initialize(); r.setValue('name', rules[i].name); r.setValue('source', %s); r.setValue('type', 'custom'); r.setValue('lookup_target', 'ci'); r.setValue('table', 'sn_vul_qualys_host_attrb');
        r.setValue('method', 'script'); r.setValue('active', true); r.setValue('reapply', true); r.setValue('reapply_version', 1); r.setValue('target_table_product_model', 'cmdb_application_product_model'); }
    r.setValue('order', rules[i].order); r.setValue('source_field', rules[i].field); r.setValue('description', rules[i].description); r.setValue('script', rules[i].script);
    var rid = r.update() || r.insert(); var rg = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rg.get(rid); um.saveRecord(rg);
    o.rules.push(rg.getValue('order') + ' ' + rg.getValue('name') + ' | ' + rg.getUniqueValue() + ' | field ' + rg.getValue('source_field') + ' | active ' + rg.getValue('active') + ' | ' + ((('' + rg.getValue('script')) == rules[i].script) ? 'stored' : 'STORED TEXT DIFFERS'));
}
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', o.set); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue() + ' | ' + ux.getValue('name'));
var chain = []; var c = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); c.addQuery('source', %s); c.addActiveQuery(); c.orderBy('order'); c.query(); while (c.next()) chain.push(c.getValue('order') + ' ' + c.getValue('name')); o.chain = chain;
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(PRIOR), json.dumps(NAME), json.dumps(DESC), json.dumps(NAME), json.dumps(DESC), json.dumps(rules), json.dumps(QUALYS), json.dumps(QUALYS), json.dumps(QUALYS)))
print('set:', d['set']); print('\n'.join(d['rules'])); print('captured:'); print('\n'.join(d['rows'])); print('active chain:', ' > '.join(d['chain']))
assert len(d['rows']) == len(RULES) and all('| Global |' in r for r in d['rows']) and all(r.endswith('stored') for r in d['rules'])
json.dump({'set': d['set'], 'name': NAME, 'rows': len(RULES), 'file': 'Qualys CI Lookup Rules Load Balancer Refinements - Update Set.xml'}, open(STATE, 'w'), indent=1)
print('DEPLOYED: rules 350, 455 and 460 captured (%d rows), Global' % len(RULES))
