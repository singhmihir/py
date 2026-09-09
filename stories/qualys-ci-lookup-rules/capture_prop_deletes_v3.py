"""Records the removal of the six usem.ci_lookup.* properties in the delivered set.

The set that holds the three backlog rules is reopened and renamed to the next version. Each
property is re-inserted under the sys_id it had in V3.0 / V3.1 and deleted again while the set is
pinned, so the platform turns the capture into a DELETE that removes the record on any instance
where an earlier version was applied. Instances that never had them skip the delete."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
NAME = 'SNOWUSEMTP-895_MS_Qualys CI Lookup Rules_V3.3'
DESC = ('Three CI lookup rules added to the USEM Qualys chain for hosts the existing chain cannot resolve: 420 Management '
        'Interface Match, 430 Network Interface Name Match, 460 Load Balancer Service Match. The suffix, marker and product '
        'lists each rule relies on are declared in the script itself. This set also removes the six usem.ci_lookup.* system '
        'properties that V3.0 and V3.1 shipped; instances that never had them skip those deletes. Applies on top of V2.3.')
state = json.load(open(os.path.join(HERE, 'state_v3.json')))
props = json.load(open(os.path.join(HERE, 'props_v31_ids.json')))
ui = SNUI(); ui.app('global')
d = ui.js('''
var o = {rows: [], steps: [], left: 0};
var us = new GlideRecord('sys_update_set'); if (!us.get(%s)) { gs.print('X::' + JSON.stringify({error: 'set not found'})); }
us.setValue('state', 'in progress'); us.update();
var us1 = new GlideRecord('sys_update_set'); us1.get(us.getUniqueValue()); us1.setValue('name', %s); us1.setValue('description', %s); us1.update();
new GlideUpdateSet().set(us.getUniqueValue());
var pinned = new GlideRecord('sys_update_set'); pinned.get('' + new GlideUpdateSet().get());
o.pinned = '' + pinned.getValue('name') + ' | ' + pinned.application.getDisplayValue() + ' | ' + pinned.getValue('state');
var props = %s;
for (var name in props) {
    var chk = new GlideRecord('sys_properties'); chk.addQuery('name', name); chk.query();
    if (chk.next()) { o.steps.push(name + ': still present, deleting'); chk.deleteRecord(); continue; }
    var p = new GlideRecord('sys_properties'); p.initialize(); p.setNewGuidValue(props[name].sys_id);
    p.setValue('name', name); p.setValue('type', 'string'); p.setValue('value', props[name].value); p.setValue('description', props[name].description); p.setValue('ignore_cache', false);
    var id = '' + p.insert();
    var del = new GlideRecord('sys_properties'); if (del.get(id)) { del.deleteRecord(); o.steps.push(name + ': recreated as ' + id + (id == props[name].sys_id ? ' (original id)' : ' (ID DIFFERS)') + ', deleted'); }
    else o.steps.push(name + ': INSERT FAILED');
}
var q = new GlideRecord('sys_properties'); q.addQuery('name', 'STARTSWITH', 'usem.ci_lookup'); q.query(); while (q.next()) o.left++;
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', us.getUniqueValue()); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue() + ' | ' + ux.getValue('name'));
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(state['set']), json.dumps(NAME), json.dumps(DESC), json.dumps(props)))
print('pinned:', d['pinned']); print('\n'.join(d['steps'])); print('captured rows:'); print('\n'.join(d['rows'])); print('usem.ci_lookup.* properties left on the instance:', d['left'])
rules = [r for r in d['rows'] if 'sn_sec_cmn_ci_lookup_rule_' in r and '| INSERT_OR_UPDATE |' in r]
dels = [r for r in d['rows'] if r.startswith('usem.ci_lookup') and '| DELETE |' in r]
assert d['left'] == 0 and len(rules) == 3 and len(dels) == 6 and len(d['rows']) == 9 and all('| Global |' in r for r in d['rows']), 'unexpected capture'
assert all('(original id)' in s for s in d['steps'] if 'recreated' in s), 'a property came back under a different sys_id'
state.update({'name': NAME, 'rows': 9}); json.dump(state, open(os.path.join(HERE, 'state_v3.json'), 'w'), indent=1)
print('CAPTURED: 3 rule updates + 6 property deletes, all Global; state_v3.json -> V3.3, 9 rows')
