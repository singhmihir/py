"""Tests for rule 750 USEM IP Outside Hardware Match (the Shazzam "IP in CMDB" gaps): marked fixtures for clusters,
cluster nodes, cluster virtual IPs, vCenters, IP phones, an imaging device and a server, then 18 payloads run through
the whole chain (CIIdentify.identify) and through rule 750 alone. Runs twice; `python3 test_750.py remove` deletes the
fixtures."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
QUALYS = 'ed44bdc453220300e8f9f745911c0801'; MARK = 'USEM lookup rule fixture (750)'

# table, name, ip, references (field -> fixture name)
CIS = [
    ('cmdb_ci_cluster', 'FIX750-SQLCLU01', '', {}),
    ('cmdb_ci_cluster', 'FIX750-SQLCLU02', '', {}),
    ('cmdb_ci_win_server', 'FIX750-SQLN01', '10.75.0.11', {}),
    ('cmdb_ci_cluster_node', 'FIX750-SQLCLU01-N1', '', {'cluster': 'FIX750-SQLCLU01', 'server': 'FIX750-SQLN01'}),
    ('cmdb_ci_cluster_vip', 'FIX750-SQLCLU01-VIP', '10.75.0.10', {'cluster': 'FIX750-SQLCLU01', 'node': 'FIX750-SQLCLU01-N1'}),
    ('cmdb_ci_cluster_vip', 'FIX750-ORPHAN-VIP', '10.75.0.12', {}),
    ('cmdb_ci_cluster_vip', 'FIX750-SQLCLU02-VIPA', '10.75.0.13', {'cluster': 'FIX750-SQLCLU02'}),
    ('cmdb_ci_cluster_vip', 'FIX750-SQLCLU02-VIPB', '10.75.0.13', {'cluster': 'FIX750-SQLCLU02'}),
    ('cmdb_ci_cluster_vip', 'FIX750-MIX-VIP1', '10.75.0.14', {'cluster': 'FIX750-SQLCLU01'}),
    ('cmdb_ci_cluster_vip', 'FIX750-MIX-VIP2', '10.75.0.14', {'cluster': 'FIX750-SQLCLU02'}),
    ('cmdb_ci_vcenter', 'FIX750-VC01', '10.75.0.20', {}),
    ('cmdb_ci_ip_phone', 'FIX750-PHONE01', '10.75.0.30', {}),
    ('cmdb_ci_ip_phone', 'FIX750-PHONE02', '10.75.0.31', {}),
    ('cmdb_ci_ip_phone', 'FIX750-PHONE03', '10.75.0.31', {}),
    ('cmdb_ci_imaging_hardware', 'FIX750-SCAN01', '10.75.0.40', {}),
    ('cmdb_ci_ip_phone', 'FIX750-PHONE04', '10.75.0.50', {}),
    ('cmdb_ci_vcenter', 'FIX750-VC02', '10.75.0.50', {}),
    ('cmdb_ci_linux_server', 'FIX750-SRV60', '10.75.0.60', {}),
    ('cmdb_ci_vcenter', 'FIX750-VC60', '10.75.0.60', {}),
]
def P(ip, dns='', os_=''):
    d = {'IP': ip, 'TRACKING_METHOD': 'IP'}
    if dns: d['DNS'] = dns
    if os_: d['OS'] = os_
    return d
WIN = 'Windows Server 2019 Standard 64 bit Edition Version 1809'
CASES = [  # label, payload, expected chain rule ('' = no match), expected CI, expected CI from rule 750 alone
    ('cluster VIP, scanned as the Windows node answering -> the cluster, not the node\'s server', P('10.75.0.10', 'fix750-sqlclu01.bankofamerica.com', WIN), '750', 'FIX750-SQLCLU01', 'FIX750-SQLCLU01'),
    ('the same VIP with no DNS and no OS -> the cluster (address alone)', P('10.75.0.10'), '750', 'FIX750-SQLCLU01', 'FIX750-SQLCLU01'),
    ('a VIP that names no cluster -> declined', P('10.75.0.12', '', WIN), '', '', ''),
    ('two VIP records of one cluster on the address -> that cluster', P('10.75.0.13', 'fix750-sqlclu02.bankofamerica.com'), '750', 'FIX750-SQLCLU02', 'FIX750-SQLCLU02'),
    ('VIPs of two different clusters on one address -> declined', P('10.75.0.14', '', WIN), '', '', ''),
    ('vCenter on the address, scanned as VMware Photon OS -> the vCenter', P('10.75.0.20', 'fix750-vc01.bankofamerica.com', 'VMware Photon OS 3.0'), '750', 'FIX750-VC01', 'FIX750-VC01'),
    ('the vCenter scanned under another DNS name -> still the vCenter (address alone, no name check)', P('10.75.0.20', 'vcsa-mgmt17.bankofamerica.com', 'Linux 4.19'), '750', 'FIX750-VC01', 'FIX750-VC01'),
    ('the vCenter scanned as Windows Server -> still the vCenter (the OS rules nothing out for it)', P('10.75.0.20', '', 'Windows Server 2016 Standard'), '750', 'FIX750-VC01', 'FIX750-VC01'),
    ('IP phone on the address, no DNS, no OS -> the phone', P('10.75.0.30'), '750', 'FIX750-PHONE01', 'FIX750-PHONE01'),
    ('the phone scanned under a DNS name no phone carries -> the phone (address alone)', P('10.75.0.30', 'avx0a1b2c.cc.bofa.com'), '750', 'FIX750-PHONE01', 'FIX750-PHONE01'),
    ('the phone scanned as "Linux 2.x" (embedded Linux) -> the phone', P('10.75.0.30', '', 'Linux 2.x'), '750', 'FIX750-PHONE01', 'FIX750-PHONE01'),
    ('a Windows 10 host on the phone\'s address -> declined (the address now belongs to another machine)', P('10.75.0.30', '', 'Windows 10 Enterprise 64 bit Edition Version 22H2'), '', '', ''),
    ('two phones on one address -> declined', P('10.75.0.31'), '', '', ''),
    ('imaging device on the address -> the device', P('10.75.0.40', '', 'Unknown OS'), '750', 'FIX750-SCAN01', 'FIX750-SCAN01'),
    ('a phone and a vCenter on one address -> declined', P('10.75.0.50'), '', '', ''),
    ('a Linux server and a vCenter on one address, Red Hat scanned -> the address rule for the server wins first', P('10.75.0.60', '', 'Red Hat Enterprise Linux 9.4'), '700', 'FIX750-SRV60', 'FIX750-VC60'),
    ('nothing outside the Hardware tree on the address -> declined', P('10.75.0.99', '', WIN), '', '', ''),
    ('loopback address -> declined', P('127.0.0.1'), '', '', ''),
]

ui = SNUI(); ui.app('global')
TABLES = sorted({c[0] for c in CIS})
if len(sys.argv) > 1 and sys.argv[1] == 'remove':
    r = ui.js('''var __r = {removed: 0}; var tables = %s;
for (var i = 0; i < tables.length; i++) { var g = new GlideRecord(tables[i]); if (!g.isValid()) continue; g.addQuery('short_description', %s); g.query(); while (g.next()) { g.deleteRecord(); __r.removed++; } }
gs.print('X::' + JSON.stringify(__r));''' % (json.dumps(TABLES), json.dumps(MARK)))
    print('removed', r['removed']); sys.exit(0)

f = ui.js('''var __f = {created: 0, present: 0, failed: []}; var cis = %s; var M = %s; var ids = {};
for (var i = 0; i < cis.length; i++) {
    var c = cis[i]; var g = new GlideRecord(c[0]);
    if (!g.isValid()) { __f.failed.push(c[0] + ' not installed'); continue; }
    g.addQuery('name', c[1]); g.addQuery('short_description', M); g.query();
    if (!g.next()) { g.initialize(); g.setValue('name', c[1]); g.setValue('short_description', M); }
    else __f.present++;
    if (c[2]) g.setValue('ip_address', c[2]);
    for (var k in c[3]) g.setValue(k, ids[c[3][k]]);
    var id = g.isNewRecord() ? g.insert() : (g.update(), g.getUniqueValue());
    if (!id) __f.failed.push(c[0] + ' ' + c[1] + ': ' + g.getLastErrorMessage()); else { ids[c[1]] = '' + id; if (__f.present + __f.created < i + 1) __f.created++; }
}
gs.print('X::' + JSON.stringify(__f));''' % (json.dumps(CIS), json.dumps(MARK)))
print('fixtures: %d records, %d created, %d already present%s' % (len(CIS), f['created'], f['present'], (', FAILED: ' + '; '.join(f['failed'])) if f['failed'] else ''))
assert not f['failed']

passed = failed = 0
for run in (1, 2):
    r = ui.js('''var __o = {results: []}; var cases = %s; var ci = new sn_sec_cmn.CIIdentify();
function label(id) { var c = new GlideRecord('cmdb_ci'); if (!c.get('' + id)) return '' + id; return c.getValue('name') + ' [' + c.getValue('sys_class_name') + ']'; }
var l = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); l.addQuery('source', %s); l.addQuery('order', 750); l.query(); l.next();
for (var i = 0; i < cases.length; i++) {
    var p = cases[i][1]; var res = null, out = {rule: '', ci: '', alone: '', error: ''};
    try { res = ci.identify(%s, p, true); } catch (ex) { out.error = '' + ex; }
    if (res && res.lookupRule) { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); out.rule = '' + rr.getValue('order'); }
    if (res && res.ci && res.ci.mainCi) out.ci = label(res.ci.mainCi);
    var ev = new GlideScopedEvaluator(); ev.putVariable('rule', l); ev.putVariable('sourceValue', p.IP); ev.putVariable('sourcePayload', p);
    var one = null; try { one = ev.evaluateScript(l, 'script', null); } catch (e2) { out.error += ' alone: ' + e2; }
    if (one) out.alone = label(one);
    __o.results.push(out);
}
gs.print('X::' + JSON.stringify(__o));''' % (json.dumps(CASES), json.dumps(QUALYS), json.dumps(QUALYS)))
    for c, x in zip(CASES, r['results']):
        name = lambda s: s.split(' [')[0] if s else ''
        ok = x['rule'] == c[2] and name(x['ci']) == c[3] and name(x['alone']) == c[4] and not x['error']
        passed += ok; failed += (not ok)
        print('%s run%d %s | chain %s %s | 750 alone -> %s%s%s' % ('ok  ' if ok else 'FAIL', run, c[0], x['rule'] or '(no match)', x['ci'], x['alone'] or '-',
              (' ERROR ' + x['error']) if x['error'] else '', '' if ok else '   expected chain %s %s, alone %s' % (c[2] or '(no match)', c[3], c[4] or '-')))
print('\n%s: %d of %d as expected' % ('ALL AS EXPECTED' if not failed else 'FAILURES', passed, passed + failed))
sys.exit(1 if failed else 0)
