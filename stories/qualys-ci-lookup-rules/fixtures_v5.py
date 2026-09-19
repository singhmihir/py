"""Fixtures reproducing the case William raised: an IP Router named usmabghwt01atr0001 with no fqdn and no
dns_domain, a Computer whose adapter owns two IP Address records, and the DNS Name record of the router's
scanned name linked to both of those addresses. Marked in short_description; `python3 fixtures_v5.py remove`
takes them away again."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
MARK = 'USEM lookup rule fixture (V5)'
ui = SNUI(); ui.app('global')
if len(sys.argv) > 1 and sys.argv[1] == 'remove':
    r = ui.js('''
var __o = {removed: []}; var M = %s;
var tables = ['cmdb_ip_address_dns_name', 'cmdb_ci_ip_address', 'cmdb_ci_dns_name', 'cmdb_ci_network_adapter', 'cmdb_ci_ip_router', 'cmdb_ci_ip_switch', 'cmdb_ci_computer', 'cmdb_ci_server', 'cmdb_ci_netgear'];
for (var i = 0; i < tables.length; i++) { var g = new GlideRecord(tables[i]); if (!g.isValid()) continue; if (tables[i] == 'cmdb_ip_address_dns_name') g.addQuery('dns_name.short_description', M); else g.addQuery('short_description', M); g.query();
  while (g.next()) { __o.removed.push(tables[i] + ' ' + g.getValue('name')); g.deleteRecord(); } }
gs.print('X::' + JSON.stringify(__o));''' % json.dumps(MARK))
    print('\n'.join(r['removed']) or 'nothing to remove'); sys.exit(0)
r = ui.js('''
var __o = {out: []}; var M = %s;
function one(table, name, fields) { var g = new GlideRecord(table); g.addQuery('name', name); g.addQuery('short_description', M); for (var k in fields || {}) if (k == 'ip_address' || k == 'nic' || k == 'cmdb_ci') g.addQuery(k, fields[k]); g.query();
  if (g.next()) { __o.out.push(table + ' ' + name + ' exists'); return g.getUniqueValue(); }
  g.initialize(); g.setValue('name', name); g.setValue('short_description', M); for (var k2 in fields || {}) g.setValue(k2, fields[k2]); var id = '' + g.insert(); __o.out.push(table + ' ' + name + ' created'); return id; }
// the router exactly as exported: name only, address on the record, no fqdn, no dns_domain
__o.router = one('cmdb_ci_ip_router', 'usmabghwt01atr0001', {ip_address: '10.223.38.115', serial_number: 'FJC2127L0AR'});
// the Computer that the discovery chain ends on
__o.computer = one('cmdb_ci_computer', 'KBC091B0ACE13', {});
var nic = one('cmdb_ci_network_adapter', 'eth0', {cmdb_ci: __o.computer});
var ip1 = one('cmdb_ci_ip_address', '10.223.38.115', {ip_address: '10.223.38.115', nic: nic});
var ip2 = one('cmdb_ci_ip_address', '10.223.38.116', {ip_address: '10.223.38.116', nic: nic});
var dns = one('cmdb_ci_dns_name', 'usmabghwt01atr0001.network.bankofamerica.com', {fqdn: 'usmabghwt01atr0001.network.bankofamerica.com', ip_address: '10.223.38.115'});
var ips = [ip1, ip2];
for (var i = 0; i < ips.length; i++) { var m = new GlideRecord('cmdb_ip_address_dns_name'); m.addQuery('dns_name', dns); m.addQuery('ip_address', ips[i]); m.query();
  if (m.next()) __o.out.push('link ' + i + ' exists'); else { m.initialize(); m.setValue('dns_name', dns); m.setValue('ip_address', ips[i]); m.insert(); __o.out.push('link ' + i + ' created'); } }
// a second router of a sibling class for the class-agreement variations
__o.sw = one('cmdb_ci_ip_switch', 'fixv5-switch', {});
gs.print('X::' + JSON.stringify(__o));''' % json.dumps(MARK))
print('\n'.join(r['out'])); print('router', r['router'], '| computer', r['computer'])
json.dump({'router': r['router'], 'computer': r['computer'], 'switch': r['sw']}, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures_v5.json'), 'w'), indent=1)
