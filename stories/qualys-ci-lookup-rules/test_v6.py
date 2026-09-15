"""Cases for the appliance acceptance in rules 350 and 410 and the name agreement in rules 700, 705,
730 and 740, on self-contained fixtures marked in short_description. Runs the platform's
CIIdentify.identify() and, where useful, one rule on its own; a chain expectation of '*' is not
checked. Runs twice. `python3 test_v6.py remove` deletes the fixtures."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
QUALYS = 'ed44bdc453220300e8f9f745911c0801'; MARK = 'USEM lookup rule fixture (V6)'
LINUX = 'Ubuntu/Linux'; WIN = 'Windows Server 2019 Standard'; RHEL = 'Red Hat Enterprise Linux 9.8'; W10 = 'Windows 10 Enterprise 64 bit Edition Version 22H2'
MULTI = 'Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software'
def P(ip, os_, dns=None):
    d = {'IP': ip, 'TRACKING_METHOD': 'IP', 'OS': os_}
    if dns: d['DNS'] = dns
    return d
CASES = [  # label, payload, expected chain rule ('' = no match, '*' = not checked), expected CI, (optional) rule to run alone and its expected CI
    # appliances reporting the Linux they run on (350, 410)
    ('410: IP Switch named with the host, Linux fingerprint -> accepted', P('10.226.1.1', LINUX, 'fixv6switch.network.bankofamerica.com'), '410', 'fixv6switch', '410', 'fixv6switch'),
    ('410: BIG-IP device named with the host, Linux fingerprint -> accepted', P('10.226.1.4', LINUX, 'fixv6bigip.network.bankofamerica.com'), '410', 'fixv6bigip', '410', 'fixv6bigip'),
    ('410: Storage Server named with the host, Linux fingerprint -> accepted', P('10.226.1.5', LINUX, 'fixv6storage.corp.bankofamerica.com'), '410', 'fixv6storage', '410', 'fixv6storage'),
    ('410: the same IP Switch, Windows OS -> still refused', P('10.226.1.1', WIN, 'fixv6switch.network.bankofamerica.com'), '', '', '410', ''),
    ('410: Windows Server named with the host, Linux fingerprint -> still refused (a namesake)', P('10.226.1.6', LINUX, 'fixv6winname.corp.bankofamerica.com'), '', '', '410', ''),
    ('350: alias of the IP Switch, Linux fingerprint -> accepted', P('10.226.1.2', LINUX, 'alias-v6sw.network.bankofamerica.com'), '350', 'fixv6switch', '350', 'fixv6switch'),
    ('350: alias of the IP Switch, Windows OS -> skipped by 350 (the platform DNS rule at 940 then takes it)', P('10.226.1.2', WIN, 'alias-v6sw.network.bankofamerica.com'), '940', 'fixv6switch', '350', ''),
    ('705: IP Switch carrying the address on its record, Linux fingerprint, no name -> still refused (address alone)', P('10.226.1.3', LINUX), '', '', '705', ''),
    # the CI reached through the address must carry the scanned name (700, 705, 730, 740)
    ('700: Linux Server on the address, scanned with its name -> the name rule takes it; 700 alone accepts', P('10.226.2.1', RHEL, 'fixv6lx700.corp.bankofamerica.com'), '400', 'fixv6lx700', '700', 'fixv6lx700'),
    ('700: the same server, no DNS -> accepted', P('10.226.2.1', RHEL), '700', 'fixv6lx700', '700', 'fixv6lx700'),
    ('700: the same server, scanned as its name plus an unknown tail -> accepted', P('10.226.2.1', RHEL, 'fixv6lx700-zz9.corp.bankofamerica.com'), '700', 'fixv6lx700', '700', 'fixv6lx700'),
    ('700: the same server, scanned under another name -> declined (reused address)', P('10.226.2.1', RHEL, 'fixv6scanned.corp.bankofamerica.com'), '', '', '700', ''),
    ('700: CI named with its fqdn, scanned with that fqdn -> accepted', P('10.226.2.2', RHEL, 'fixv6lxfq.corp.bankofamerica.com'), '*', '', '700', 'fixv6lxfq.corp.bankofamerica.com'),
    ('700: CI named with the host plus a tail, scanned with the bare host -> accepted', P('10.226.2.4', RHEL, 'fixv6lxtail.corp.bankofamerica.com'), '700', 'fixv6lxtail-a', '700', 'fixv6lxtail-a'),
    ('705: Server on the address, scanned with its name, no class -> the name rule takes it; 705 alone accepts', P('10.226.2.5', MULTI, 'fixv6srv705.corp.bankofamerica.com'), '410', 'fixv6srv705', '705', 'fixv6srv705'),
    ('705: the same Server, scanned under another name -> declined', P('10.226.2.5', MULTI, 'fixv6other.corp.bankofamerica.com'), '', '', '705', ''),
    ('705: the same Server, no DNS -> accepted', P('10.226.2.5', MULTI), '705', 'fixv6srv705', '705', 'fixv6srv705'),
    ('730: Computer owning the adapter, scanned with its name -> the name rule takes it; 730 alone accepts', P('10.226.2.6', W10, 'fixv6comp730.corp.bankofamerica.com'), '400', 'fixv6comp730', '730', 'fixv6comp730'),
    ('730: the same Computer, scanned under another name -> declined', P('10.226.2.6', W10, 'fixv6nomatch.corp.bankofamerica.com'), '', '', '730', ''),
    ('730: the same Computer, no DNS -> accepted', P('10.226.2.6', W10), '730', 'fixv6comp730', '730', 'fixv6comp730'),
    ('740: Computer behind an IP Address record, scanned with its name -> the name rule takes it; 740 alone accepts', P('10.226.2.7', W10, 'fixv6comp740.corp.bankofamerica.com'), '400', 'fixv6comp740', '740', 'fixv6comp740'),
    ('740: the same Computer, scanned under another name -> declined', P('10.226.2.7', W10, 'fixv6nomatch.corp.bankofamerica.com'), '', '', '740', ''),
    ('740: the same Computer, no DNS -> accepted', P('10.226.2.7', W10), '740', 'fixv6comp740', '740', 'fixv6comp740'),
    ('740: the same Computer, scanned as its name plus an unknown tail -> accepted', P('10.226.2.7', W10, 'fixv6comp740-zz9.corp.bankofamerica.com'), '740', 'fixv6comp740', '740', 'fixv6comp740'),
    ('the reused-address case: retired Computer named after another machine owns the adapter -> declined', P('10.226.2.8', 'Windows 11 Enterprise 64 bit Edition Version 24H2', 'fixv6vk1660790.corp.bankofamerica.com'), '', '', '730', ''),
]
TABLES = ['cmdb_ip_address_dns_name', 'cmdb_ci_ip_address', 'cmdb_ci_dns_name', 'cmdb_ci_network_adapter', 'cmdb_ci_ip_switch', 'cmdb_ci_lb_bigip', 'cmdb_ci_storage_server', 'cmdb_ci_win_server', 'cmdb_ci_linux_server', 'cmdb_ci_server', 'cmdb_ci_computer']
ui = SNUI(); ui.app('global')
if len(sys.argv) > 1 and sys.argv[1] == 'remove':
    r = ui.js('''
var __r = {removed: []}; var M = %s; var tables = %s;
for (var i = 0; i < tables.length; i++) { var g = new GlideRecord(tables[i]); if (tables[i] == 'cmdb_ip_address_dns_name') g.addQuery('dns_name.short_description', M); else g.addQuery('short_description', M); g.query();
  while (g.next()) { __r.removed.push(tables[i] + ' ' + g.getValue('name')); g.deleteRecord(); } }
gs.print('X::' + JSON.stringify(__r));''' % (json.dumps(MARK), json.dumps(TABLES)))
    print('\n'.join(r['removed']) or 'nothing to remove'); sys.exit(0)
f = ui.js('''
var __f = {out: []}; var M = %s;
function one(table, name, fields) { var g = new GlideRecord(table); g.addQuery('name', name); g.addQuery('short_description', M); g.query();
  if (g.next()) { __f.out.push(name + ' exists'); return g.getUniqueValue(); }
  g.initialize(); g.setValue('name', name); g.setValue('short_description', M); for (var k in fields || {}) g.setValue(k, fields[k]); var id = '' + g.insert(); __f.out.push(name + ' created'); return id; }
function adapter(ciId, name, ip) { var a = new GlideRecord('cmdb_ci_network_adapter'); a.addQuery('cmdb_ci', ciId); a.addQuery('name', name); a.query();
  if (a.next()) return a.getUniqueValue(); a.initialize(); a.setValue('name', name); a.setValue('cmdb_ci', ciId); a.setValue('short_description', M); if (ip) a.setValue('ip_address', ip); return '' + a.insert(); }
function ipRecord(nic, ip) { var r = new GlideRecord('cmdb_ci_ip_address'); r.addQuery('nic', nic); r.addQuery('ip_address', ip); r.query();
  if (r.next()) return r.getUniqueValue(); r.initialize(); r.setValue('name', ip); r.setValue('ip_address', ip); r.setValue('nic', nic); r.setValue('short_description', M); return '' + r.insert(); }
function dnsLink(ipId, ip, dnsName) { var d = one('cmdb_ci_dns_name', dnsName, {fqdn: dnsName, ip_address: ip});
  var m = new GlideRecord('cmdb_ip_address_dns_name'); m.addQuery('dns_name', d); m.addQuery('ip_address', ipId); m.query();
  if (!m.next()) { m.initialize(); m.setValue('dns_name', d); m.setValue('ip_address', ipId); m.insert(); } }
var sw = one('cmdb_ci_ip_switch', 'fixv6switch', {}); dnsLink(ipRecord(adapter(sw, 'mgmt0'), '10.226.1.2'), '10.226.1.2', 'alias-v6sw.network.bankofamerica.com');
one('cmdb_ci_ip_switch', 'fixv6switchip', {ip_address: '10.226.1.3'});
one('cmdb_ci_lb_bigip', 'fixv6bigip', {});
one('cmdb_ci_storage_server', 'fixv6storage', {});
one('cmdb_ci_win_server', 'fixv6winname', {});
one('cmdb_ci_linux_server', 'fixv6lx700', {ip_address: '10.226.2.1'});
one('cmdb_ci_linux_server', 'fixv6lxfq.corp.bankofamerica.com', {ip_address: '10.226.2.2'});
one('cmdb_ci_linux_server', 'fixv6lxtail-a', {ip_address: '10.226.2.4'});
one('cmdb_ci_server', 'fixv6srv705', {ip_address: '10.226.2.5'});
adapter(one('cmdb_ci_computer', 'fixv6comp730', {}), 'eth0', '10.226.2.6');
ipRecord(adapter(one('cmdb_ci_computer', 'fixv6comp740', {}), 'eth0'), '10.226.2.7');
adapter(one('cmdb_ci_computer', 'fixv6vk1448212', {install_status: 7}), 'eth0', '10.226.2.8');
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
        ok = (c[2] == '*' or (x['rule'] == c[2] and x['ci'] == c[3])) and (not c[4] or x['alone'] == c[5]) and not x['error']
        passed += ok; failed += (not ok)
        print('%s run%d %s | chain %s %s%s%s' % ('PASS' if ok else 'FAIL', run, c[0], x['rule'] or '(no match)', x['ci'], (' | %s alone -> %s' % (c[4], x['alone'] or '-')) if c[4] else '', (' ERROR ' + x['error']) if x['error'] else ''))
print('\n%s: %d passed, %d failed' % ('ALL PASS' if not failed else 'FAILED', passed, failed))
sys.exit(1 if failed else 0)
