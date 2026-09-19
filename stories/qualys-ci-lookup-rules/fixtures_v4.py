"""Four marked CMDB fixtures so the sweep exercises the address rules and the broad name rule."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
MARK = 'USEM lookup rule fixture (V4)'
ui = SNUI(); ui.app('global')
r = ui.js('''
var o = []; var M = %s;
function one(table, name, fields) { var g = new GlideRecord(table); g.addQuery('name', name); g.addQuery('short_description', M); g.query();
  if (g.next()) { o.push(table + ' ' + name + ' exists ' + g.getUniqueValue()); return g.getUniqueValue(); }
  g.initialize(); g.setValue('name', name); g.setValue('short_description', M); for (var k in fields) g.setValue(k, fields[k]); var id = g.insert(); o.push(table + ' ' + name + ' created ' + id); return id; }
one('cmdb_ci_server', 'fixv4-srv705', {ip_address: '30.162.178.24'});
var s730 = one('cmdb_ci_server', 'fixv4-srv730', {});
var a = new GlideRecord('cmdb_ci_network_adapter'); a.addQuery('cmdb_ci', s730); a.addQuery('ip_address', '30.162.178.22'); a.query();
if (a.next()) o.push('adapter 730 exists'); else { a.initialize(); a.setValue('name', 'eth0'); a.setValue('cmdb_ci', s730); a.setValue('ip_address', '30.162.178.22'); a.setValue('short_description', M); o.push('adapter 730 created ' + a.insert()); }
var s740 = one('cmdb_ci_server', 'fixv4-srv740', {});
var b = new GlideRecord('cmdb_ci_network_adapter'); b.addQuery('cmdb_ci', s740); b.addQuery('name', 'eth0'); b.query(); var nic;
if (b.next()) { nic = b.getUniqueValue(); o.push('adapter 740 exists'); } else { b.initialize(); b.setValue('name', 'eth0'); b.setValue('cmdb_ci', s740); b.setValue('short_description', M); nic = '' + b.insert(); o.push('adapter 740 created ' + nic); }
var ipr = new GlideRecord('cmdb_ci_ip_address'); ipr.addQuery('nic', nic); ipr.addQuery('ip_address', '30.162.178.23'); ipr.query();
if (ipr.next()) o.push('ip address 740 exists'); else { ipr.initialize(); ipr.setValue('name', '30.162.178.23'); ipr.setValue('ip_address', '30.162.178.23'); ipr.setValue('nic', nic); ipr.setValue('short_description', M); o.push('ip address 740 created ' + ipr.insert()); }
one('cmdb_ci_vm_instance', 'lva40bneehcs02.ecomm.devicenp.rpg', {});
gs.print('X::' + JSON.stringify({out: o}));''' % json.dumps(MARK))
print('\n'.join(r['out']))
