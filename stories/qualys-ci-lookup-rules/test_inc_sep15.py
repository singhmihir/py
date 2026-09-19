"""The cases Mihir attached to INC0010003 on 15 Sep: four discovered items with the CI records that
carry their names or addresses (exported from the client instance, rebuilt here as marked fixtures in
the same classes, placeholders included), plus variations on the contact-centre phone case. Expected
outcomes are the ones judged correct: the Avaya phone and the scanner match by name through USEM
Device Name Match; the Cisco Meeting Server stays unmatched because the CMDB holds it twice; the F5
virtual servers stay unmatched because only their IRE placeholders carry the name. Runs twice;
`python3 test_inc_sep15.py remove` deletes the fixtures."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
QUALYS = 'ed44bdc453220300e8f9f745911c0801'; MARK = 'USEM lookup rule fixture (INC 15 Sep)'
SPEC = json.load(open(os.path.join(HERE, 'inc_cases_sep15.json')))
def P(ip, dns, os_=None):
    d = {'IP': ip, 'TRACKING_METHOD': 'IP', 'DNS': dns}
    if os_ is not None: d['OS'] = os_
    return d
CASES = [  # label, payload, expected chain rule ('' = no match), expected CI (name, or name@ip when the name is shared), (optional) rule alone and its expected CI
    ('SDI000003720429 avxdd008a.cc.bofa.com, no OS: Avaya phone named AVXDD008A on the same address -> Device Name Match', P('10.190.29.132', 'avxdd008a.cc.bofa.com'), '415', 'AVXDD008A', '415', 'AVXDD008A'),
    ('the same phone scanned as "Foundry Networks" -> still the phone', P('10.190.29.132', 'avxdd008a.cc.bofa.com', 'Foundry Networks'), '415', 'AVXDD008A', '415', 'AVXDD008A'),
    ('the same phone scanned as "Linux 2.x" (embedded Linux) -> still the phone', P('10.190.29.132', 'avxdd008a.cc.bofa.com', 'Linux 2.x'), '415', 'AVXDD008A', '415', 'AVXDD008A'),
    ('the same phone scanned as "Unknown OS" -> still the phone', P('10.190.29.132', 'avxdd008a.cc.bofa.com', 'Unknown OS'), '415', 'AVXDD008A', '415', 'AVXDD008A'),
    ('the same phone scanned as "Cisco IP Phone" -> still the phone', P('10.190.29.132', 'avxdd008a.cc.bofa.com', 'Cisco IP Phone'), '415', 'AVXDD008A', '415', 'AVXDD008A'),
    ('the same phone scanned as Windows 10 -> refused (a desktop OS is not a phone)', P('10.190.29.132', 'avxdd008a.cc.bofa.com', 'Windows 10 Enterprise 64 bit Edition Version 22H2'), '', '', '415', ''),
    ('the same phone on a new DHCP address -> still the phone (the name identifies it)', P('10.190.29.200', 'avxdd008a.cc.bofa.com'), '415', 'AVXDD008A', '415', 'AVXDD008A'),
    ('a phone label with no phone record -> no match', P('10.190.29.201', 'avx000000.cc.bofa.com'), '', '', '415', ''),
    ('two phones sharing a name, scanned on the address of the second -> that one', P('10.190.29.212', 'avxdup001.cc.bofa.com'), '415', 'AVXDUP001@10.190.29.212', '415', 'AVXDUP001@10.190.29.212'),
    ('two phones sharing a name, scanned on an address neither carries -> declined', P('10.190.29.250', 'avxdup001.cc.bofa.com'), '', '', '415', ''),
    ('SDI000003655772 scr02tx25540101.scanners, no OS, address moved: Scanner named SCR02TX25540101 (certificates of that name are not devices) -> Device Name Match', P('30.223.92.54', 'scr02tx25540101.scanners.bankofamerica.com'), '415', 'SCR02TX25540101', '415', 'SCR02TX25540101'),
    ('SDI000003719884 usvasdnvetpuatcms1k03, Ubuntu/Linux: the CMS held twice (Communication Distribution Panel and Server, same serial and address) -> stays unmatched', P('171.205.112.70', 'usvasdnvetpuatcms1k03.bankofamerica.com', 'Ubuntu/Linux'), '', '', '410', ''),
    ('the same CMS through the address rule alone -> declined too (two hardware CIs on the address)', P('171.205.112.70', 'usvasdnvetpuatcms1k03.bankofamerica.com', 'Ubuntu/Linux'), '', '', '705', ''),
    ('SDI000002541496 pts-zelle-transfer-va2, F5: only the IRE placeholder carries the name and address -> stays unmatched', P('171.176.104.95', 'pts-zelle-transfer-va2.bankofamerica.com', 'F5 Networks Big-IP'), '', '', '460', ''),
    ('horizon-vip.dif.gwimnp.rpg, F5: placeholder only -> stays unmatched', P('167.202.145.99', 'horizon-vip.dif.gwimnp.rpg', 'F5 Networks Big-IP'), '', '', '460', ''),
    ('pts-zelle-transfer-tt1, F5: placeholder plus DNS Name records of other names on its address -> stays unmatched', P('164.91.177.142', 'pts-zelle-transfer-tt1.ecnp.bankofamerica.com', 'F5 Networks Big-IP'), '', ''),
]
EXTRA = [{'table': 'cmdb_ci_ip_phone', 'name': 'AVXDUP001', 'ip_address': '10.190.29.211'}, {'table': 'cmdb_ci_ip_phone', 'name': 'AVXDUP001', 'ip_address': '10.190.29.212'}]
CIS = SPEC['cis'] + EXTRA
TABLES = sorted({c['table'] for c in CIS})
ui = SNUI(); ui.app('global')
if len(sys.argv) > 1 and sys.argv[1] == 'remove':
    r = ui.js('''
var __r = {removed: 0}; var M = %s; var tables = %s;
for (var i = 0; i < tables.length; i++) { var g = new GlideRecord(tables[i]); if (!g.isValid()) continue; g.addQuery('short_description', M); g.query(); while (g.next()) { g.deleteRecord(); __r.removed++; } }
gs.print('X::' + JSON.stringify(__r));''' % (json.dumps(MARK), json.dumps(TABLES)))
    print('removed', r['removed']); sys.exit(0)
f = ui.js('''
var __f = {created: 0, present: 0, invalid: {}, failed: []}; var M = %s; var cis = %s; var seen = {};
for (var i = 0; i < cis.length; i++) {
    var c = cis[i]; var g = new GlideRecord(c.table); if (!g.isValid()) { __f.invalid[c.table] = (__f.invalid[c.table] || 0) + 1; continue; }
    var key = c.table + '|' + c.name + '|' + (c.ip_address || '') + '|' + (c.serial_number || ''); seen[key] = (seen[key] || 0) + 1;
    g.addQuery('name', c.name); g.addQuery('sys_class_name', c.table); if (c.ip_address && g.isValidField('ip_address')) g.addQuery('ip_address', c.ip_address); if (c.serial_number && g.isValidField('serial_number')) g.addQuery('serial_number', c.serial_number); g.query();
    if (g.getRowCount() >= seen[key]) { __f.present++; continue; }
    g.initialize(); g.setValue('name', c.name); g.setValue('short_description', M);
    var fields = ['ip_address', 'fqdn', 'install_status', 'operational_status', 'serial_number', 'mac_address', 'model_number'];
    for (var k = 0; k < fields.length; k++) if (c[fields[k]] && g.isValidField(fields[k])) g.setValue(fields[k], c[fields[k]]);
    if (g.isValidField('subject_alternative_name')) g.setValue('subject_alternative_name', c.name);   // mandatory on certificates here
    if (g.insert()) __f.created++; else __f.failed.push(c.table + ' ' + c.name + ': ' + g.getLastErrorMessage());
}
gs.print('X::' + JSON.stringify(__f));''' % (json.dumps(MARK), json.dumps(CIS)))
print('fixtures: %d records, %d created, %d already present%s%s' % (len(CIS), f['created'], f['present'], (', tables missing here: ' + json.dumps(f['invalid'])) if f['invalid'] else '', (', NOT INSERTED: ' + '; '.join(f['failed'])) if f['failed'] else ''))
passed = failed = 0
for run in (1, 2):
    r = ui.js('''
var __o = {results: []}; var cases = %s; var ci = new sn_sec_cmn.CIIdentify();
function label(id) { var c = new GlideRecord('cmdb_ci'); if (!c.get('' + id)) return '' + id; return c.getValue('name') + '@' + (c.getValue('ip_address') || '') + ' [' + c.getValue('sys_class_name') + ']'; }
for (var i = 0; i < cases.length; i++) {
    var p = cases[i][1]; var res = null, err = '';
    try { res = ci.identify(%s, p, true); } catch (ex) { err = '' + ex; }
    var out = {rule: '', ci: '', error: err, alone: ''};
    if (res && res.lookupRule) { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); out.rule = '' + rr.getValue('order'); }
    if (res && res.ci && res.ci.mainCi) out.ci = label(res.ci.mainCi);
    if (cases[i][4]) { var l = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); l.addQuery('source', %s); l.addQuery('order', cases[i][4]); l.addQuery('name', 'STARTSWITH', 'USEM'); l.query();
        if (l.next()) { var ev = new GlideScopedEvaluator(); ev.putVariable('rule', l); ev.putVariable('sourceValue', p[l.getValue('source_field')] || ''); ev.putVariable('sourcePayload', p);
            var one = null; try { one = ev.evaluateScript(l, 'script', null); } catch (e2) { out.error += ' alone: ' + e2; }
            if (one) out.alone = label(one); } else out.alone = '(rule ' + cases[i][4] + ' not deployed)'; }
    __o.results.push(out);
}
gs.print('X::' + JSON.stringify(__o));''' % (json.dumps(CASES), json.dumps(QUALYS), json.dumps(QUALYS)))
    def same(got, exp):
        if not exp: return not got
        name, ip = got.split(' [')[0].split('@'); return got.split(' [')[0] == exp if '@' in exp else name == exp
    for c, x in zip(CASES, r['results']):
        ok = x['rule'] == c[2] and same(x['ci'], c[3]) and (len(c) < 5 or same(x['alone'], c[5])) and not x['error']
        passed += ok; failed += (not ok)
        print('%s run%d %s | chain %s %s%s%s%s' % ('PASS' if ok else 'FAIL', run, c[0], x['rule'] or '(no match)', x['ci'], (' | %s alone -> %s' % (c[4], x['alone'] or '-')) if len(c) > 4 else '', (' ERROR ' + x['error']) if x['error'] else '', '' if ok else '   expected chain %s %s' % (c[2] or '(no match)', c[3])))
print('\n%s: %d passed, %d failed' % ('ALL PASS' if not failed else 'FAILED', passed, failed))
sys.exit(1 if failed else 0)
