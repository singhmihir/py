"""The BlueCat appliance case from INC0010003 (SDI000003711605): recreates the client's CI records for
SGSG02PPZ1IPTDR02 as marked fixtures, runs the Qualys payload through the platform chain and through every
USEM rule individually, and prints what each rule answered. `python3 sg_case.py remove` deletes the fixtures."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
from william_case import run
MARK = 'USEM lookup fixture SG'
PAYLOAD = {"ID": "1260928581", "IP": "171.147.168.234", "TRACKING_METHOD": "IP", "OS": "x86_64 Linux/5.10.0-36-amd64", "DNS": "sgsg02ppz1iptdr02-mgmt.network.asia.bankofamerica.com",
           "DNS_DATA": "\n          sgsg02ppz1iptdr02-mgmt\n          network.asia.bankofamerica.com\n          sgsg02ppz1iptdr02-mgmt.network.asia.bankofamerica.com\n        ", "TAGS": ""}
ui = SNUI(); ui.app('global')
if len(sys.argv) > 1 and sys.argv[1] == 'remove':
    r = ui.js('''var o = {n: 0}; var g = new GlideRecord('cmdb_ci'); g.addQuery('comments', %s); g.query(); while (g.next()) { g.setWorkflow(false); g.deleteRecord(); o.n++; } gs.print('X::' + JSON.stringify(o));''' % json.dumps(MARK))
    print('removed', r['n']); sys.exit(0)
f = ui.js('''var o = {made: {}}; var M = %s;
function one(table, fields) { var g = new GlideRecord(table); g.addQuery('comments', M); g.addQuery('sys_class_name', table); g.query(); if (g.next()) { o.made[table] = 'exists ' + g.getUniqueValue(); return; }
  g.initialize(); g.setValue('comments', M); for (var k in fields) g.setValue(k, fields[k]); o.made[table] = '' + g.insert(); }
var man = new GlideRecord('core_company'); man.addQuery('name', 'BlueCat Networks'); man.query(); if (!man.next()) { man.initialize(); man.setValue('name', 'BlueCat Networks'); man.setValue('manufacturer', true); man.insert(); }
one('cmdb_ci_netgear', {name: 'SGSG02PPZ1IPTDR02', short_description: 'SGSG02PPZ1IPTDR02', ip_address: '171.147.168.234', serial_number: '159RQ53', install_status: 7, operational_status: 6, hardware_status: 'retired', hardware_substatus: 'scrapped', manufacturer: man.getUniqueValue(), model_number: '6500', discovery_source: 'BOFA Nlyte', internet_facing: true});
one('cmdb_ci_ip_switch', {name: 'SGSG02PPZ1IPTDR02', short_description: 'SGSG02PPZ1IPTDR02', ip_address: '171.147.117.140', serial_number: '3ZWTT64', install_status: 1, operational_status: 1, hardware_status: 'installed', hardware_substatus: 'in_use', manufacturer: man.getUniqueValue(), model_number: 'BDDS6500-HW-F', discovery_source: 'BOFA Nlyte', internet_facing: true});
one('cmdb_ci_unclassed_hardware', {name: 'sgsg02ppz1iptdr02.network.asia.bankofamerica.com', fqdn: 'sgsg02ppz1iptdr02.network.asia.bankofamerica.com', ip_address: '171.147.117.140', install_status: 1, operational_status: 1, discovery_source: 'VR-Qualys'});
o.ignore = gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
o.same_name = []; var s = new GlideRecord('cmdb_ci'); s.addQuery('name', 'SGSG02PPZ1IPTDR02'); s.query(); while (s.next()) o.same_name.push(s.getValue('sys_class_name') + ' ' + s.getValue('ip_address') + ' status ' + s.getValue('install_status') + ' ' + (s.getValue('comments') == M ? '(fixture)' : '(OTHER RECORD)'));
o.same_ip = []; var i = new GlideRecord('cmdb_ci'); i.addQuery('ip_address', '171.147.168.234'); i.query(); while (i.next()) o.same_ip.push(i.getValue('name') + ' [' + i.getValue('sys_class_name') + '] ' + (i.getValue('comments') == M ? '(fixture)' : '(OTHER RECORD)'));
gs.print('X::' + JSON.stringify(o));''' % json.dumps(MARK))
print('fixtures:', json.dumps(f['made'])); print('ignore classes:', f['ignore']); print('CIs named SGSG02PPZ1IPTDR02:', f['same_name']); print('CIs with 171.147.168.234:', f['same_ip'])
run(ui, PAYLOAD, 'SG mgmt host')
