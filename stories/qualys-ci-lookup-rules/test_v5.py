"""Class-agreement cases for rules 350, 410, 705, 730 and 740, on top of the fixtures from fixtures_v5.py.
Runs the platform's CIIdentify.identify() and, where useful, one rule on its own. Run twice."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
from william_case import PAYLOAD
QUALYS = 'ed44bdc453220300e8f9f745911c0801'; MARK = 'USEM lookup rule fixture (V5)'
CISCO = 'Cisco IOS 15.9(3)M7, RELEASE SOFTWARE (fc2)'; MULTI = 'Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software'
def P(**k): d = dict(PAYLOAD); d.update(k); return d
CASES = [  # label, payload, expected chain rule order ('' = no match), expected CI, (optional) rule to run alone and its expected CI
    ('William host: Cisco IOS router, DNS chain ends on a Computer -> the router by name', PAYLOAD, '400', 'usmabghwt01atr0001', '350', ''),
    ('740 alone on the same host: the Computer is skipped', PAYLOAD, '400', 'usmabghwt01atr0001', '740', ''),
    ('same host, OS empty: no class, the chain is trusted (known limit)', P(OS=''), '350', 'KBC091B0ACE13', '350', 'KBC091B0ACE13'),
    ('same host, multi-guess OS: no class, the chain is trusted (known limit)', P(OS=MULTI), '350', 'KBC091B0ACE13', '350', 'KBC091B0ACE13'),
    ('350: alias of a plain Network Gear device, Cisco OS -> accepted (same class)', {'IP': '10.223.39.10', 'TRACKING_METHOD': 'IP', 'OS': CISCO, 'DNS': 'alias-ng.network.bankofamerica.com'}, '350', 'fixv5-netgear', '350', 'fixv5-netgear'),
    ('350: alias of an IP Switch, Cisco OS -> accepted (sub-class of Network Gear)', {'IP': '10.223.39.11', 'TRACKING_METHOD': 'IP', 'OS': CISCO, 'DNS': 'alias-sw.network.bankofamerica.com'}, '350', 'fixv5-switch', '350', 'fixv5-switch'),
    ('350: alias of an IP Switch, Windows OS -> skipped by 350 (the platform DNS rule at 940 then takes it)', {'IP': '10.223.39.11', 'TRACKING_METHOD': 'IP', 'OS': 'Windows Server 2019 Standard', 'DNS': 'alias-sw.network.bankofamerica.com'}, '940', 'fixv5-switch', '350', ''),
    ('350: alias of a Linux Server, Red Hat OS -> accepted (regression)', {'IP': '167.202.60.26', 'TRACKING_METHOD': 'IP', 'OS': 'Red Hat Enterprise Linux Server 7.9', 'DNS': 'hklvteqoradbp3.hk.baml.com'}, '350', 'hklvteqoradbp3', '350', 'hklvteqoradbp3'),
    ('410: plain Server named like the host, Cisco OS -> refused (Server is not a parent of Network Gear)', {'IP': '10.223.41.1', 'TRACKING_METHOD': 'IP', 'OS': CISCO, 'DNS': 'fixv5-srvname.corp.bankofamerica.com'}, '', '', '410', ''),
    ('410: same Server, AIX OS -> accepted (Server is a parent of AIX Server)', {'IP': '10.223.41.1', 'TRACKING_METHOD': 'IP', 'OS': 'AIX 7.3 TL3', 'DNS': 'fixv5-srvname.corp.bankofamerica.com'}, '410', 'fixv5-srvname', '410', 'fixv5-srvname'),
    ('410: same Server, OS empty -> accepted (nothing to contradict)', {'IP': '10.223.41.1', 'TRACKING_METHOD': 'IP', 'OS': '', 'DNS': 'fixv5-srvname.corp.bankofamerica.com'}, '410', 'fixv5-srvname', '410', 'fixv5-srvname'),
    ('705: Computer on the address, Cisco OS -> refused', {'IP': '10.223.40.5', 'TRACKING_METHOD': 'IP', 'OS': CISCO}, '', '', '705', ''),
    ('705: Computer on the address, Windows 10 -> the class rule takes it first', {'IP': '10.223.40.5', 'TRACKING_METHOD': 'IP', 'OS': 'Windows 10 Enterprise 64 bit Edition Version 22H2'}, '700', 'fixv5-comp705', '705', 'fixv5-comp705'),
    ('705: Computer on the address, OS empty -> accepted', {'IP': '10.223.40.5', 'TRACKING_METHOD': 'IP', 'OS': ''}, '705', 'fixv5-comp705', '705', 'fixv5-comp705'),
    ('730: Computer owns the adapter, Cisco OS -> refused', {'IP': '10.223.40.6', 'TRACKING_METHOD': 'IP', 'OS': CISCO}, '', '', '730', ''),
    ('730: Computer owns the adapter, multi-guess OS -> accepted', {'IP': '10.223.40.6', 'TRACKING_METHOD': 'IP', 'OS': MULTI}, '730', 'fixv5-comp730', '730', 'fixv5-comp730'),
    ('740: IP Address record of the Computer, Cisco OS -> refused', {'IP': '10.223.38.116', 'TRACKING_METHOD': 'IP', 'OS': CISCO}, '', '', '740', ''),
    ('740: IP Address record of the Computer, Windows 10 -> accepted (same class)', {'IP': '10.223.38.116', 'TRACKING_METHOD': 'IP', 'OS': 'Windows 10 Enterprise 64 bit Edition Version 22H2'}, '740', 'KBC091B0ACE13', '740', 'KBC091B0ACE13'),
]
ui = SNUI(); ui.app('global')
f = ui.js('''
var __f = {out: []}; var M = %s;
function one(table, name, fields) { var g = new GlideRecord(table); g.addQuery('name', name); g.addQuery('short_description', M); g.query();
  if (g.next()) { __f.out.push(name + ' exists'); return g.getUniqueValue(); }
  g.initialize(); g.setValue('name', name); g.setValue('short_description', M); for (var k in fields || {}) g.setValue(k, fields[k]); var id = '' + g.insert(); __f.out.push(name + ' created'); return id; }
function chain(ciId, adapterName, ip, dnsName) {
  var a = new GlideRecord('cmdb_ci_network_adapter'); a.addQuery('cmdb_ci', ciId); a.addQuery('name', adapterName); a.query(); var nic;
  if (a.next()) nic = a.getUniqueValue(); else { a.initialize(); a.setValue('name', adapterName); a.setValue('cmdb_ci', ciId); a.setValue('short_description', M); nic = '' + a.insert(); }
  var r = new GlideRecord('cmdb_ci_ip_address'); r.addQuery('nic', nic); r.addQuery('ip_address', ip); r.query(); var ipId;
  if (r.next()) ipId = r.getUniqueValue(); else { r.initialize(); r.setValue('name', ip); r.setValue('ip_address', ip); r.setValue('nic', nic); r.setValue('short_description', M); ipId = '' + r.insert(); }
  if (!dnsName) return;
  var d = one('cmdb_ci_dns_name', dnsName, {fqdn: dnsName, ip_address: ip});
  var m = new GlideRecord('cmdb_ip_address_dns_name'); m.addQuery('dns_name', d); m.addQuery('ip_address', ipId); m.query();
  if (!m.next()) { m.initialize(); m.setValue('dns_name', d); m.setValue('ip_address', ipId); m.insert(); } }
var ng = one('cmdb_ci_netgear', 'fixv5-netgear', {}); chain(ng, 'mgmt0', '10.223.39.10', 'alias-ng.network.bankofamerica.com');
var sw = one('cmdb_ci_ip_switch', 'fixv5-switch', {}); chain(sw, 'mgmt0', '10.223.39.11', 'alias-sw.network.bankofamerica.com');
one('cmdb_ci_server', 'fixv5-srvname', {});
one('cmdb_ci_computer', 'fixv5-comp705', {ip_address: '10.223.40.5'});
var c730 = one('cmdb_ci_computer', 'fixv5-comp730', {});
var a2 = new GlideRecord('cmdb_ci_network_adapter'); a2.addQuery('cmdb_ci', c730); a2.addQuery('ip_address', '10.223.40.6'); a2.query();
if (!a2.next()) { a2.initialize(); a2.setValue('name', 'eth0'); a2.setValue('cmdb_ci', c730); a2.setValue('ip_address', '10.223.40.6'); a2.setValue('short_description', M); a2.insert(); __f.out.push('adapter 730 created'); }
gs.print('X::' + JSON.stringify(__f));''' % json.dumps(MARK))
print('fixtures:', ', '.join(f['out']))
passed = failed = 0
for run in (1, 2):
    r = ui.js('''
var __o = {results: []}; var cases = %s; var ci = new sn_sec_cmn.CIIdentify();
for (var i = 0; i < cases.length; i++) {
    var p = cases[i][1]; var res = null, err = '';
    try { res = ci.identify(%s, p, true); } catch (ex) { err = '' + ex; }
    var out = {rule: '', ci: '', error: err, alone: ''};
    if (res && res.lookupRule) { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); out.rule = '' + rr.getValue('order'); }
    if (res && res.ci && res.ci.mainCi) { var c = new GlideRecord('cmdb_ci'); c.get(res.ci.mainCi); out.ci = '' + c.getValue('name'); }
    if (cases[i][4]) { var l = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); l.addQuery('source', %s); l.addQuery('order', cases[i][4]); l.addQuery('name', 'STARTSWITH', 'USEM'); l.query();
        if (l.next()) { var ev = new GlideScopedEvaluator(); ev.putVariable('rule', l); ev.putVariable('sourceValue', p[l.getValue('source_field')] || ''); ev.putVariable('sourcePayload', p);
            var one = null; try { one = ev.evaluateScript(l, 'script', null); } catch (e2) { out.error += ' alone: ' + e2; }
            if (one) { var g = new GlideRecord('cmdb_ci'); out.alone = g.get('' + one) ? '' + g.getValue('name') : '' + one; } } }
    __o.results.push(out);
}
gs.print('X::' + JSON.stringify(__o));''' % (json.dumps(CASES), json.dumps(QUALYS), json.dumps(QUALYS)))
    for c, x in zip(CASES, r['results']):
        ok = x['rule'] == c[2] and x['ci'] == c[3] and (not c[4] or x['alone'] == c[5]) and not x['error']
        passed += ok; failed += (not ok)
        print('%s run%d %s | chain %s %s%s%s' % ('PASS' if ok else 'FAIL', run, c[0], x['rule'] or '(no match)', x['ci'], (' | %s alone -> %s' % (c[4], x['alone'] or '-')) if c[4] else '', (' ERROR ' + x['error']) if x['error'] else ''))
print('\n%s: %d passed, %d failed' % ('ALL PASS' if not failed else 'FAILED', passed, failed))
sys.exit(1 if failed else 0)
