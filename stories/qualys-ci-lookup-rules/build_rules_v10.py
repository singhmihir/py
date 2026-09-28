"""Deploys the new rule 750 USEM IP Outside Hardware Match (the scanned address looked up in the classes the CMDB
keeps outside the Hardware tree: vCenter, cluster virtual IP standing for its cluster, IP Phone, Imaging Hardware;
the gaps the Shazzam "IP in CMDB" enrichment covers and the chain did not) into its own Global update set, captured
explicitly with GlideUpdateManager2.saveRecord. Applies on top of the earlier sets; no existing rule is touched."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
NAME = 'SNOWUSEMTP-895_MS_Qualys CI Lookup Rules IP Outside Hardware Match_V1.0'
DESC = ('One new USEM Qualys CI lookup rule, 750 IP Outside Hardware Match, placed after the address rules: the scanned address '
        'is looked up in the four classes the CMDB keeps outside the Hardware tree that the Discovery status enrichment (Shazzam) '
        'uses for its "IP in CMDB" column: vCenter, cluster virtual IP (standing for its cluster), IP Phone and Imaging Hardware. '
        'Exactly one CI on the address is the match; two different CIs, a virtual IP without a cluster, or a server or desktop OS '
        'on a phone or imaging address make it decline. Address alone, no name check. No existing rule changes; no system '
        'property is read or shipped.')
QUALYS = 'ed44bdc453220300e8f9f745911c0801'
RULES = [('750', 'USEM IP Outside Hardware Match', 'IP', 'Scanned address searched in the classes outside the Hardware tree (vCenter, cluster virtual IP standing for its cluster, IP Phone, Imaging Hardware); exactly one CI on the address; declined for two different CIs, a virtual IP without a cluster, or a server or desktop OS on a phone or imaging address.')]
rules = [{'order': o, 'name': n, 'field': f, 'description': d, 'script': open(os.path.join(HERE, 'rules', '%s_%s.js' % (o, n.replace(' ', '_')))).read()} for o, n, f, d in RULES]
STATE = os.path.join(HERE, 'state_v10.json')
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
var chain = []; var c = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); c.addQuery('source', %s); c.addActiveQuery(); c.orderBy('order'); c.query(); while (c.next()) chain.push(c.getValue('order')); o.chain = chain;
var dflt = new GlideRecord('sys_update_set'); dflt.addQuery('is_default', true); dflt.addQuery('application', 'global'); dflt.query(); if (dflt.next()) new GlideUpdateSet().set(dflt.getUniqueValue());
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(PRIOR), json.dumps(NAME), json.dumps(DESC), json.dumps(NAME), json.dumps(DESC), json.dumps(rules), json.dumps(QUALYS), json.dumps(QUALYS), json.dumps(QUALYS)))
print('set:', d['set']); print('\n'.join(d['rules'])); print('captured:'); print('\n'.join(d['rows'])); print('active chain:', ' > '.join(d['chain']))
assert len(d['rows']) == 1 and all('| Global |' in r for r in d['rows']) and all(r.endswith('stored') for r in d['rules'])
json.dump({'set': d['set'], 'name': NAME, 'rows': 1, 'file': 'Qualys CI Lookup Rules IP Outside Hardware Match - Update Set.xml'}, open(STATE, 'w'), indent=1)
print('DEPLOYED: rule 750 captured (1 row), Global')
