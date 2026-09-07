"""End-to-end proof through the platform pipeline: re-runs the CI lookup for
nine real unmatched Discovered Items (the platform's CILookupUtil.reRunCILookupRules,
the same call the on-demand reconcile job makes) and reports each item's state,
CI and rule before and after. CIs for these hosts exist as marked fixtures."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ITEMS = [('437ec0fe3bd60b502fcecefe23e45a04', 'tx6dd630001-ilo (iLO suffix)', '420', 'tx6dd630001'),
         ('d1dbd0323b5e83100e435c8a04e45afb', 'xtp24cel03-ilom (ILOM suffix)', '420', 'xtp24cel03'),
         ('352e4cf63bd60b502fcecefe23e45aa1', 'uspaltwrr01drm0119-cz04-hsrp-vlan705.network (VLAN interface)', '430', 'uspaltwrr01drm0119'),
         ('0421a0fe3b5e83100e435c8a04e45a29', 'rvcpcz1atmlb01s-vs1.network (load balancer device interface)', '430', 'rvcpcz1atmlb01s'),
         ('ac31d936931a0310cfcebc5a7bba107e', 'crisp-tx (F5 VIP with fqdn)', '460', 'crisp-tx'),
         ('bfb17cba2b960710a277fab2f291bf52', 'rbps-dev3-sve-vip (VIP label, Linux OS)', '460', 'rbps-dev3-sve-vip'),
         ('a2112cf63b128b502fcecefe23e45ac6', 'sep6c5e3b2925ac (SEP phone)', '200', 'SEP6C5E3B2925AC'),
         ('f35ec872eb52c310017ff4d7cad0cd21', 'bofascanner75 (plain name, no OS)', '410', 'bofascanner75'),
         ('251ec4b63bd60b502fcecefe23e45afb', 'AH-1015198-001 (asset tag name, Windows)', '400', 'AH-1015198-001')]
ui = SNUI(); ui.app('global')
d = ui.js('''
var o = {before: [], after: []}; var ids = %s;
function snap(list) { var out = []; for (var i = 0; i < ids.length; i++) { var g = new GlideRecord('sn_sec_cmn_src_ci'); g.get(ids[i]);
  out.push({number: '' + g.getValue('number'), state: '' + g.getValue('state'), ci: '' + g.cmdb_ci.name, ci_class: '' + g.cmdb_ci.sys_class_name, ci_class_field: '' + g.getValue('cmdb_ci_class'), rule: '' + g.ci_lookup_rule.order + ' ' + g.ci_lookup_rule.name, mt: '' + g.getValue('matching_type'), updated: '' + g.getValue('sys_updated_on')}); } return out; }
o.before = snap();
var util = new sn_sec_cmn.CILookupUtil();
util.reRunCILookupRules(ids.join(','));
o.stats = '' + util.getStats();
o.after = snap();
gs.print('X::' + JSON.stringify(o));''' % json.dumps([i[0] for i in ITEMS]))
print('platform stats:\n' + d['stats'] + '\n')
passed = 0
for it, b, a in zip(ITEMS, d['before'], d['after']):
    ok = a['state'] == 'matched' and a['ci'] == it[3] and a['rule'].startswith(it[2] + ' ')
    passed += ok
    print('%s %-16s %-62s before: %s / %s [%s]   after: %s / %s [%s] via %s / %s' % ('PASS' if ok else 'FAIL', b['number'], it[1], b['state'], b['ci'] or '(placeholder)', b['ci_class_field'], a['state'], a['ci'], a['ci_class'], a['rule'], a['mt']))
print('passed', passed, 'of', len(ITEMS))
