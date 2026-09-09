"""Deploy the rewritten Qualys CI lookup rule scripts into a new Global update set.

Reads rules/<order>_<name>.js, updates the script field of the matching
sn_sec_cmn_ci_lookup_rule record (matched by sys_id, name and order) and
audits that every captured update landed in the Global application.

sn_sec_cmn_ci_lookup_rule is not update-set tracked (no update_synch attribute
on its collection), so every rule is captured explicitly with
GlideUpdateManager2.saveRecord after the update.
"""
import os, sys, json, glob
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.join(BASE, 'stories', 'qualys-ci-lookup-rules')
NAME = 'SNOWUSEMTP-895_MS_Qualys CI Lookup Rules_V2.4'
DESC = ('Qualys CI lookup rules (USEM custom chain, orders 175 to 850) rewritten so that any reader can follow them. '
        'Each rule script opens with its purpose, the sample Qualys host record every note refers to, what the rule reads '
        'and returns, what it returns for the sample, and its place in the chain. Each stage that does the matching (class '
        'from the scanned OS, the search and the exactly-one decision, the IP tie-break, the load balancer and '
        'class-contradiction checks) carries a note that ends with what happens to the sample; the remaining lines carry '
        'a short comment. Result sets are not capped with setLimit: a rule accepts a CI only when exactly one candidate '
        'remains, or, for the tie-break rules, when the scanned IP confirms one of several. Matching behaviour is unchanged.')
live = json.load(open(os.path.join(HERE, 'live_rules.json')))['rules']
STATE = os.path.join(HERE, 'state.json')
PRIOR = json.load(open(STATE))['set'] if os.path.exists(STATE) else ''
rules = []
for fn in sorted(glob.glob(os.path.join(HERE, 'rules', '*.js'))):
    order, rest = os.path.basename(fn)[:-3].split('_', 1)
    if order in ('420', '430', '460'):            # delivered in the V3 set (build_rules_v3.py)
        continue
    name = rest.replace('_', ' ')
    match = [r for r in live if r['name'] == name and r['order'] == order and r['source'].startswith('Qualys')]
    assert len(match) == 1, (name, order, len(match))
    rules.append({'id': match[0]['id'], 'name': name, 'order': order, 'script': open(fn).read()})
assert len(rules) == 16
ui = SNUI(); ui.app('global')
d = ui.js('''
var o = {rows: [], updated: [], mismatch: []};
var rules = %s;
var us = new GlideRecord('sys_update_set'); var prior = %s;
if (prior && us.get(prior)) { o.set = us.getUniqueValue(); o.existing = true; us.setValue('state', 'in progress'); us.update();
    var us1 = new GlideRecord('sys_update_set'); us1.get(o.set); us1.setValue('name', %s); us1.setValue('description', %s); us1.update(); }
else {
    us.initialize(); us.setValue('name', %s); us.setValue('application', 'global'); us.setValue('state', 'in progress');
    us.setValue('description', %s); o.set = '' + us.insert(); o.existing = false;
}
new GlideUpdateSet().set(o.set);
var um = new GlideUpdateManager2();
var pinned = new GlideRecord('sys_update_set'); pinned.get('' + new GlideUpdateSet().get());
o.pinned = '' + pinned.getValue('name') + ' | ' + pinned.application.getDisplayValue();
for (var i = 0; i < rules.length; i++) {
    var r = new GlideRecord('sn_sec_cmn_ci_lookup_rule');
    if (!r.get(rules[i].id) || ('' + r.getValue('name')) != rules[i].name || ('' + r.getValue('order')) != rules[i].order) { o.mismatch.push(rules[i].name); continue; }
    r.setValue('script', rules[i].script); r.update(); um.saveRecord(r);
    var chk = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); chk.get(rules[i].id);
    o.updated.push(rules[i].order + ' ' + rules[i].name + (('' + chk.getValue('script')) == rules[i].script ? ' | stored' : ' | STORED TEXT DIFFERS'));
}
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', o.set); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue() + ' | ' + ux.getValue('name'));
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(rules), json.dumps(PRIOR), json.dumps(NAME), json.dumps(DESC), json.dumps(NAME), json.dumps(DESC)))
print('set:', d['set'], '(existing)' if d['existing'] else '(new)', '| pinned:', d['pinned'])
print('\n'.join(d['updated'])); print('mismatch:', d['mismatch'])
print('\n'.join(d['rows']))
json.dump({'set': d['set'], 'name': NAME, 'rules': {r['order']: r['id'] for r in rules}}, open(STATE, 'w'), indent=1)
assert not d['mismatch'] and len(d['updated']) == 16 and all(u.endswith('| stored') for u in d['updated'])
assert len(d['rows']) == 16 and all(' | Global | sn_sec_cmn_ci_lookup_rule_' in r for r in d['rows'])
print('DEPLOYED: 16 rule scripts captured, all Global')
