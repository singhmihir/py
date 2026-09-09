"""Deploys the three rules added for the unmatched backlog (420, 430, 460) into a Global
update set. The rules carry their own lists; no system property is created or read.
Rules are created when missing (same source, table and flags as the existing USEM rules)
and captured explicitly with GlideUpdateManager2.saveRecord (the rule table is not tracked)."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
NAME = 'SNOWUSEMTP-895_MS_Qualys CI Lookup Rules_V3.4'
DESC = ('Three CI lookup rules added to the USEM Qualys chain for hosts the existing chain cannot resolve: 420 Management '
        'Interface Match (iLO, ILOM, iDRAC, IMM, CIMC, BMC controllers matched to their server), 430 Network Interface Name '
        'Match (interface and VLAN addresses of switches, routers, firewalls and load balancer devices matched to the device), '
        '460 Load Balancer Service Match (virtual IPs matched to the Load Balancer Service CI). The suffix, marker and product '
        'lists each rule relies on are declared in the script itself; no system property is read or shipped, and this set '
        'also removes the six usem.ci_lookup.* properties an earlier cut shipped. Each script opens with the sample host '
        'record its notes refer to. Each rule accepts a CI only when exactly one candidate remains. Applies on top of V2.4.')
QUALYS = 'ed44bdc453220300e8f9f745911c0801'
RULES = [('420', 'USEM Management Interface Match', 'DNS', 'Management controller of a server (iLO, ILOM, iDRAC, IMM, CIMC, BMC) matched to the server: controller suffix on the label or controller OS, server name unique in the hardware tree, load balancers refused. The suffix and OS word lists are declared in the script.'),
         ('430', 'USEM Network Interface Name Match', 'DNS', 'Interface or VLAN address of a network device matched to the device: interface domain or marker segment required, label walked from the longest prefix to the shortest against Network Gear and Load Balancer devices, unique owner required. The domain and marker lists are declared in the script.'),
         ('460', 'USEM Load Balancer Service Match', 'IP', 'Virtual IP matched to its Load Balancer Service CI: load balancer OS word or VIP label marker required, service found by fqdn, then name, then address, exactly one at each step. The product and marker lists are declared in the script.')]
rules = [{'order': o, 'name': n, 'field': f, 'description': d, 'script': open(os.path.join(HERE, 'rules', '%s_%s.js' % (o, n.replace(' ', '_')))).read()} for o, n, f, d in RULES]
STATE = os.path.join(HERE, 'state_v3.json')
PRIOR = json.load(open(STATE))['set'] if os.path.exists(STATE) else ''
PRIOR_ROWS = json.load(open(STATE)).get('rows', 3) if os.path.exists(STATE) else 3
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
assert len(d['rows']) == PRIOR_ROWS and all('| Global |' in r for r in d['rows']) and sum('sn_sec_cmn_ci_lookup_rule' in r for r in d['rows']) == 3 and all(r.endswith('stored') for r in d['rules'])
json.dump({'set': d['set'], 'name': NAME, 'rows': PRIOR_ROWS, 'file': 'Qualys CI Lookup Rules V3 - Update Set.xml'}, open(STATE, 'w'), indent=1)
print('DEPLOYED: 3 rules re-captured into the reopened set (%d rows), all Global' % PRIOR_ROWS)
