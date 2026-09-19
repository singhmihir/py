"""Fixtures and tests for rules 420, 430 and 460 on the PDI.

Creates CMDB fixtures (marked in short_description) when missing, then runs the
platform's own CIIdentify.identify() for the Qualys source with one payload per
case and compares the rule and CI returned with the expectation. The whole suite
runs twice."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
QUALYS = 'ed44bdc453220300e8f9f745911c0801'
MARK = 'USEM lookup rule fixture (V3)'
FIX = [  # table, name, extra fields
    ('cmdb_ci_linux_server', 'tx6dd630001', {}), ('cmdb_ci_linux_server', 'xtp24cel03', {}),
    ('cmdb_ci_linux_server', 'crpchictx103', {'serial_number': 'FIXV3-DUP-A'}), ('cmdb_ci_linux_server', 'crpchictx103', {'serial_number': 'FIXV3-DUP-B'}),
    ('cmdb_ci_ip_switch', 'uspaltwrr01drm0119', {}), ('cmdb_ci_ip_switch', 'ustxrdnwl01rsm004z', {'serial_number': 'FIXV3-SW-A'}), ('cmdb_ci_ip_switch', 'ustxrdnwl01rsm004z', {'serial_number': 'FIXV3-SW-B'}),
    ('cmdb_ci_linux_server', 'gtcmmrlpa05a', {}), ('cmdb_ci_lb_bigip', 'rvcpcz1atmlb01s', {}),
    ('cmdb_ci_lb_service', 'crisp-tx', {'fqdn': 'crisp-tx.bankofamerica.com', 'ip_address': '171.203.142.26', 'port': 443}),
    ('cmdb_ci_lb_service', 'rbps-dev3-sve-vip', {'ip_address': '164.91.236.18', 'port': 443}),
    ('cmdb_ci_lb_service', 'vs_171.145.73.51_443', {'ip_address': '171.145.73.51', 'port': 443}),
    ('cmdb_ci_lb_service', 'dup-vip-a', {'ip_address': '164.91.176.197', 'port': 443}), ('cmdb_ci_lb_service', 'dup-vip-b', {'ip_address': '164.91.176.197', 'port': 8443}),
]
CASES = [  # label, payload, expected rule order ('' for no match), expected CI name
    ('420 iLO suffix -> server', {'IP': '159.185.200.11', 'TRACKING_METHOD': 'IP', 'OS': 'HP iLO', 'DNS': 'tx6dd630001-ilo.bankofamerica.com'}, '420', 'tx6dd630001'),
    ('420 ilom suffix, ordinary OS -> server', {'IP': '30.123.8.235', 'TRACKING_METHOD': 'IP', 'OS': 'Ubuntu / Linux 3.x', 'DNS': 'xtp24cel03-ilom.sdi.corp.bankofamerica.com'}, '420', 'xtp24cel03'),
    ('420 controller OS, unlisted tail -> declines on two servers', {'IP': '158.171.31.179', 'TRACKING_METHOD': 'IP', 'OS': 'HP iLO', 'DNS': 'crpchictx103-r.bankofamerica.com'}, '', ''),
    ('420 no controller evidence -> no match', {'IP': '10.1.1.1', 'TRACKING_METHOD': 'IP', 'OS': 'Windows 10 Enterprise 64 bit Edition Version 22H2', 'DNS': 'usposwks0042-x.bankofamerica.com'}, '', ''),
    ('430 interface domain -> switch', {'IP': '171.149.3.49', 'TRACKING_METHOD': 'IP', 'OS': 'Linux 2.6', 'DNS': 'uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com'}, '430', 'uspaltwrr01drm0119'),
    ('430 two switches with the prefix -> declines', {'IP': '30.204.117.3', 'TRACKING_METHOD': 'IP', 'OS': 'Cisco Nexus Switch', 'DNS': 'ustxrdnwl01rsm004z-atm1-v201.network.bankofamerica.com'}, '', ''),
    ('430 marker segment but the CI is a server, not network gear -> no match', {'IP': '171.151.4.232', 'TRACKING_METHOD': 'IP', 'OS': 'Linux 2.6', 'DNS': 'gtcmmrlpa05a-vlan10.corp.bankofamerica.com'}, '', ''),
    ('430 load balancer device interface (aom) -> the device', {'IP': '30.204.120.4', 'TRACKING_METHOD': 'IP', 'OS': '', 'DNS': 'rvcpcz1atmlb01s-vs1.network.bankofamerica.com'}, '430', 'rvcpcz1atmlb01s'),
    ('430 hyphenated server name without evidence stays with the name rules', {'IP': '30.143.70.11', 'TRACKING_METHOD': 'IP', 'OS': 'Windows Server 2016 Standard 64 bit Edition Version 1607', 'DNS': 'wsaoi01zeapd1.sdi.corp.bankofamerica.com'}, '400', 'WSAOI01ZEAPD1'),
    ('460 F5 OS, fqdn -> service', {'IP': '171.203.142.26', 'TRACKING_METHOD': 'IP', 'OS': 'F5 Big IP', 'DNS': 'crisp-tx.bankofamerica.com'}, '460', 'crisp-tx'),
    ('460 vip label, ordinary OS, name -> service', {'IP': '164.91.236.18', 'TRACKING_METHOD': 'IP', 'OS': 'Linux 2.6', 'DNS': 'rbps-dev3-sve-vip.ecommnp.rpg'}, '460', 'rbps-dev3-sve-vip'),
    ('460 no DNS, F5 OS, address -> service', {'IP': '171.145.73.51', 'TRACKING_METHOD': 'IP', 'OS': 'F5 Networks Big-IP'}, '460', 'vs_171.145.73.51_443'),
    ('460 two services on the address -> declines', {'IP': '164.91.176.197', 'TRACKING_METHOD': 'IP', 'OS': 'F5 Networks Big-IP'}, '', ''),
    ('460 F5 device only, no service -> no match (device still refused)', {'IP': '30.199.99.99', 'TRACKING_METHOD': 'IP', 'OS': 'F5 Big IP'}, '', ''),
    ('460 vip label but no service -> no match', {'IP': '164.91.186.189', 'TRACKING_METHOD': 'IP', 'OS': 'Windows 10 / Windows 11', 'DNS': 'misp-ds-tx-vip.bankofamerica.com'}, '', ''),
    ('460 server sharing a VIP address, no VIP evidence -> not a service', {'IP': '171.203.142.26', 'TRACKING_METHOD': 'IP', 'OS': 'Red Hat Enterprise Linux 9.8', 'DNS': 'somehost.corp.bankofamerica.com'}, '', ''),
    ('regression 350 layered DNS', {'IP': '167.202.60.26', 'TRACKING_METHOD': 'IP', 'OS': 'Red Hat Enterprise Linux Server 7.9', 'DNS': 'hklvteqoradbp3.hk.baml.com'}, '350', 'hklvteqoradbp3'),
    ('regression 200 phone', {'IP': '30.144.62.108', 'TRACKING_METHOD': 'IP', 'OS': 'Cisco IP Phone', 'DNS': 'sep64f69dd5c9b0.voip.bankofamerica.com'}, '200', 'SEP64F69DD5C9B0'),
]
ui = SNUI(); ui.app('global')
f = ui.js('''
var o = {fixtures: []}; var fix = %s;
for (var i = 0; i < fix.length; i++) {
    var g = new GlideRecord(fix[i][0]); g.addQuery('name', fix[i][1]); g.addQuery('short_description', %s); for (var k in fix[i][2]) g.addQuery(k, fix[i][2][k]); g.query();
    if (g.next()) { o.fixtures.push(fix[i][1] + ' exists'); continue; }
    g.initialize(); g.setValue('name', fix[i][1]); g.setValue('short_description', %s); for (var k2 in fix[i][2]) g.setValue(k2, fix[i][2][k2]);
    var id = g.insert(); o.fixtures.push(fix[i][1] + ' created ' + id);
}
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(FIX), json.dumps(MARK), json.dumps(MARK)))
print('\n'.join(f['fixtures']))
passed = failed = 0
for run in (1, 2):
    r = ui.js('''
var o = {results: []}; var cases = %s; var ci = new sn_sec_cmn.CIIdentify();
for (var i = 0; i < cases.length; i++) {
    var res = null, err = '';
    try { res = ci.identify(%s, cases[i][1], true); } catch (ex) { err = '' + ex; }
    var out = {label: cases[i][0], rule: '', ci: '', error: err};
    if (res && res.lookupRule) { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); out.rule = '' + rr.getValue('order'); }
    if (res && res.ci && res.ci.mainCi) { var c = new GlideRecord('cmdb_ci'); c.get(res.ci.mainCi); out.ci = '' + c.getValue('name'); out.cls = '' + c.getValue('sys_class_name'); }
    o.results.push(out);
}
gs.print('X::' + JSON.stringify(o));''' % (json.dumps([[c[0], c[1]] for c in CASES]), json.dumps(QUALYS)))
    print('--- run', run)
    for case, got in zip(CASES, r['results']):
        ok = got['rule'] == case[2] and got['ci'] == case[3] and not got['error']
        passed += ok; failed += (not ok)
        print('%s %-72s -> rule %-4s ci %s%s' % ('PASS' if ok else 'FAIL', case[0], got['rule'] or '-', got['ci'] or '(none)', (' [' + got.get('cls', '') + ']' if got['ci'] else '') + (' ERROR ' + got['error'] if got['error'] else '') + ('' if ok else '   expected rule %s ci %s' % (case[2] or '-', case[3] or '(none)'))))
print('passed', passed, 'failed', failed)
sys.exit(1 if failed else 0)
