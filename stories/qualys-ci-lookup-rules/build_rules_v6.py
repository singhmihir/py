"""Deploys the six rules refined after the measurement runs into a Global update set, captured
explicitly with GlideUpdateManager2.saveRecord (the rule table is not tracked). Rules 350 and 410
accept a Linux fingerprint against appliance classes; rules 700, 705, 730 and 740 require the CI
reached through the address to carry the scanned host name. Applies on top of V2.4, V3.4 and the
Class Agreement set."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
NAME = 'SNOWUSEMTP-895_MS_Qualys CI Lookup Rules Appliances and Address Names_V1.0'
DESC = ('Six USEM Qualys CI lookup rules refined after reviewing how the chain resolves the discovered items. (1) Rules 350 Layered DNS '
        'Match and 410 Hostname Hardware Match accept a Linux fingerprint against Network Gear, Load Balancer and Storage Server records: '
        'switches, balancers and storage nodes run Linux underneath and Qualys reports that kernel, so a switch named with the scanned host '
        'name is no longer treated as a class contradiction. (2) Rules 700 IP Class Match, 705 IP Hardware Match, 730 IP Adapter Match and '
        '740 IP Layered Match require the CI reached through the scanned address to carry the scanned host name when the scan has one (the '
        'same first label, or that label plus or minus an interface tail); a record named after another machine sits on a reused address '
        'and is declined. Applies on top of V2.4, V3.4 and the Class Agreement set; no system property is read or shipped.')
QUALYS = 'ed44bdc453220300e8f9f745911c0801'
RULES = [('350', 'USEM Layered DNS Match', 'DNS', 'DNS Name record -> IP Address record -> Network Adapter -> CI, for hosts whose name is not on the CI record; a CI whose class contradicts the scanned OS is left out (a Linux fingerprint agrees with Network Gear, Load Balancer and Storage Server records); several CIs resolved by the scanned IP or declined.'),
         ('410', 'USEM Hostname Hardware Match', 'DNS', 'Short hostname across the hardware tree, exactly one CI, accepted when its class is the one the OS implies, a sub-class or a parent of it, or an appliance class (Network Gear, Load Balancer, Storage Server) for a Linux fingerprint.'),
         ('700', 'USEM IP Class Match', 'IP', 'Last-resort IP matching, stage 1: address must belong to exactly one CI of the OS-implied class, named with the scanned host name when the scan carries one.'),
         ('705', 'USEM IP Hardware Match', 'IP', 'Scanned address across the hardware tree, exactly one CI, not a load balancer, named with the scanned host name when the scan carries one, its class the one the OS implies, a sub-class or a parent of it.'),
         ('730', 'USEM IP Adapter Match', 'IP', 'Network Adapter carrying the scanned address -> its owning CI; owners whose class contradicts the scanned OS are skipped; one owner, not a load balancer, named with the scanned host name when the scan carries one.'),
         ('740', 'USEM IP Layered Match', 'IP', 'IP Address record -> Network Adapter -> CI; owners whose class contradicts the scanned OS are skipped; one owner, not a load balancer, named with the scanned host name when the scan carries one.')]
rules = [{'order': o, 'name': n, 'field': f, 'description': d, 'script': open(os.path.join(HERE, 'rules', '%s_%s.js' % (o, n.replace(' ', '_')))).read()} for o, n, f, d in RULES]
STATE = os.path.join(HERE, 'state_v6.json')
PRIOR = json.load(open(STATE))['set'] if os.path.exists(STATE) else ''
PRIOR_ROWS = json.load(open(STATE)).get('rows', 6) if os.path.exists(STATE) else 6
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
assert len(d['rows']) == PRIOR_ROWS and all('| Global |' in r for r in d['rows']) and sum('sn_sec_cmn_ci_lookup_rule' in r for r in d['rows']) == 6 and all(r.endswith('stored') for r in d['rules'])
json.dump({'set': d['set'], 'name': NAME, 'rows': PRIOR_ROWS, 'file': 'Qualys CI Lookup Rules Appliances and Address Names - Update Set.xml'}, open(STATE, 'w'), indent=1)
print('DEPLOYED: 6 rules captured (%d rows), all Global' % PRIOR_ROWS)
