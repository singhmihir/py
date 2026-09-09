"""Deletes the six usem.ci_lookup.* properties that V3.0 / V3.1 shipped, now that no rule reads
them. The Global Default update set is pinned first so the deletes stay out of the delivered set."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
NAMES = ['usem.ci_lookup.mgmt_suffixes', 'usem.ci_lookup.mgmt_os_markers', 'usem.ci_lookup.interface_domains',
         'usem.ci_lookup.interface_markers', 'usem.ci_lookup.vip_os_markers', 'usem.ci_lookup.vip_markers']
ui = SNUI(); ui.app('global')
d = ui.js('''
var o = {pinned: '', deleted: [], missing: [], readers: []};
var def = new GlideRecord('sys_update_set'); def.addQuery('is_default', true); def.addQuery('application', 'global'); def.query();
if (def.next()) { new GlideUpdateSet().set(def.getUniqueValue()); o.pinned = '' + def.getValue('name') + ' (' + def.application.getDisplayValue() + ')'; }
var names = %s;
var r = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); r.addQuery('script', 'CONTAINS', 'usem.ci_lookup'); r.query(); while (r.next()) o.readers.push('' + r.getValue('name'));
if (o.readers.length == 0) for (var i = 0; i < names.length; i++) {
    var p = new GlideRecord('sys_properties'); p.addQuery('name', names[i]); p.query();
    if (p.next()) { p.deleteRecord(); o.deleted.push(names[i]); } else o.missing.push(names[i]);
}
var left = 0; var q = new GlideRecord('sys_properties'); q.addQuery('name', 'STARTSWITH', 'usem.ci_lookup'); q.query(); while (q.next()) left++;
o.left = left;
gs.print('X::' + JSON.stringify(o));''' % json.dumps(NAMES))
print('pinned:', d['pinned']); print('rules still reading the properties:', d['readers'] or 'none')
print('deleted:', d['deleted']); print('already absent:', d['missing']); print('usem.ci_lookup.* properties left on the instance:', d['left'])
assert not d['readers'] and d['left'] == 0
