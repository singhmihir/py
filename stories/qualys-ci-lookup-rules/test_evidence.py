"""Replays the discovered items listed in the measurement runs from the client instance (bofadev_runs/)
against the chain on the PDI, with the CMDB evidence each line reports rebuilt as marked fixtures: the
CIs carrying the name, the base name, the fqdn or the address, in the classes listed, retired where
the run says so. The expected outcome follows from the design: an appliance named with the scanned
host and reporting Linux is matched by name; everything else in the lists stays declined (duplicates,
retired-only records, storage node labels, reused addresses, hosts absent from the CMDB). The one
wrong match of the runs (a Windows host landing on the retired record of another machine through the
address) is rebuilt by hand with two controls; there the rule is also run on its own, because the
platform's CIIdentify drops a retired CI after the rule returns it (property
sn_sec_cmn.filterOutDecommissionedCI, default true). Runs twice; `python3 test_evidence.py remove`
deletes the fixtures."""
import os, sys, re, json, glob
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
QUALYS = 'ed44bdc453220300e8f9f745911c0801'; MARK = 'USEM lookup rule fixture (EV)'
APPLIANCE = {'netgear', 'ip_switch', 'ip_router', 'lb', 'lb_bigip', 'lb_f5', 'lb_f5_ltm', 'storage_server'}
CONTRADICTS = 'name on one record whose class contradicts the scanned OS'
EV = re.compile(r'(name|base|fqdn|ip) (\d+)(?:\((\d+) retired\))?(?:\[([^\]]*)\])?')
def classes(text):
    out = []
    for part in (text or '').split(','):
        if not part: continue
        m = re.match(r'(.+?)x(\d+)$', part); out += [m.group(1)] * int(m.group(2)) if m else [part]
    return out
lines = {}
for f in sorted(glob.glob(os.path.join(HERE, 'bofadev_runs', 'run[23]_*.txt'))):
    section = ''
    for l in open(f):
        if l.startswith('--- '): section = l.strip(); continue
        if not l.startswith('  SDI') or 'different CI' in section: continue
        p = [x.strip() for x in l.strip().split(' | ')]
        if len(p) < 6 or p[0] in lines: continue
        if p[4].startswith('today:'): p.pop(4)
        sdi, dns, ip, os_, cause, ev = p[0], p[1], p[2], p[3].rstrip('~'), p[4], p[5]
        e = {k: {'n': int(n), 'retired': int(r or 0), 'classes': classes(c)} for k, n, r, c in EV.findall(ev)}
        osm = re.search(r' os (\S+)', ' ' + ev); lines[sdi] = (sdi, dns, ip, os_, cause, e, osm.group(1) if osm else '-')
cases = []   # label, payload, expected chain rule, expected chain CI, (optional) rule to run alone and its expected CI
specs = []   # table, name, ip, fqdn, retired
for sdi, dns, ip, os_, cause, e, osc in lines.values():
    label = dns.lower().split('.')[0]; base = label[:label.rfind('-')] if '-' in label else ''
    payload = {'IP': ip, 'TRACKING_METHOD': 'IP', 'OS': os_}
    if dns: payload['DNS'] = dns
    name, addr = e.get('name', {'n': 0, 'retired': 0, 'classes': []}), e.get('ip', {'n': 0, 'retired': 0, 'classes': []})
    merged = name['n'] and name['n'] == addr['n'] and sorted(name['classes']) == sorted(addr['classes']) and name['retired'] == addr['retired']
    for i, cls in enumerate(name['classes']): specs.append(('cmdb_ci_' + cls, label, ip if merged else '', '', i < name['retired']))
    if not merged:
        for i, cls in enumerate(addr['classes']): specs.append(('cmdb_ci_' + cls, 'ev-addr-' + ip.replace('.', '-') + '-' + str(i), ip, '', i < addr['retired']))
    for i, cls in enumerate(e.get('base', {'classes': [], 'retired': 0})['classes']): specs.append(('cmdb_ci_' + cls, base, '', '', i < e['base']['retired']))
    for i, cls in enumerate(e.get('fqdn', {'classes': [], 'retired': 0})['classes']): specs.append(('cmdb_ci_' + cls, 'ev-fqdn-' + label + '-' + str(i), '', dns.lower(), i < e['fqdn']['retired']))
    exp = ('410', label) if cause == CONTRADICTS and osc == 'cmdb_ci_linux_server' and name['classes'] and name['classes'][0] in APPLIANCE else ('', '')
    cases.append(('%s %s %s | %s | %s' % (sdi, dns or '(no DNS)', ip, os_[:32], cause), payload, exp[0], exp[1]))
W11 = 'Windows 11 Enterprise 64 bit Edition Version 24H2'
cases.append(('SDI000003713027 vk1660790 on the reused address of the retired vk1448212 (adapter and IP Address record) -> declined', {'IP': '165.40.47.119', 'TRACKING_METHOD': 'IP', 'OS': W11, 'DNS': 'vk1660790.corp.bankofamerica.com'}, '', ''))
cases.append(('control: the retired vk1448212 scanned under its own name -> rule 400 returns it, the platform then drops the retired CI', {'IP': '165.40.47.119', 'TRACKING_METHOD': 'IP', 'OS': W11, 'DNS': 'vk1448212.corp.bankofamerica.com'}, '', '', '400', 'vk1448212'))
cases.append(('control: the retired vk1448212 scanned by address only -> rule 740 returns it (no name to contradict), the platform then drops the retired CI', {'IP': '165.40.47.119', 'TRACKING_METHOD': 'IP', 'OS': W11}, '', '', '740', 'vk1448212'))
TABLES = sorted({s[0] for s in specs} | {'cmdb_ci_vmware_instance', 'cmdb_ci_computer', 'cmdb_ci_network_adapter', 'cmdb_ci_ip_address'})
ui = SNUI(); ui.app('global')
if len(sys.argv) > 1 and sys.argv[1] == 'remove':
    r = ui.js('''
var __r = {removed: 0}; var M = %s; var tables = %s;
for (var i = 0; i < tables.length; i++) { var g = new GlideRecord(tables[i]); if (!g.isValid()) continue; g.addQuery('short_description', M); g.query(); while (g.next()) { g.deleteRecord(); __r.removed++; } }
gs.print('X::' + JSON.stringify(__r));''' % (json.dumps(MARK), json.dumps(TABLES)))
    print('removed', r['removed']); sys.exit(0)
f = ui.js('''
var __f = {created: 0, present: 0, invalid: []}; var M = %s; var specs = %s; var seen = {};
for (var i = 0; i < specs.length; i++) {
    var t = specs[i][0], name = specs[i][1], ip = specs[i][2], fqdn = specs[i][3], retired = specs[i][4];
    var key = t + '|' + name + '|' + ip + '|' + fqdn; seen[key] = (seen[key] || 0) + 1;
    var g = new GlideRecord(t); if (!g.isValid()) { __f.invalid.push(t); continue; }
    g.addQuery('name', name); g.addQuery('sys_class_name', t); if (ip) g.addQuery('ip_address', ip); if (fqdn) g.addQuery('fqdn', fqdn); g.query();
    if (g.getRowCount() >= seen[key]) { __f.present++; continue; }
    g.initialize(); g.setValue('name', name); g.setValue('short_description', M); if (ip) g.setValue('ip_address', ip); if (fqdn) g.setValue('fqdn', fqdn); if (retired) g.setValue('install_status', 7); g.insert(); __f.created++;
}
function one(t, name, fields) { var g = new GlideRecord(t); g.addQuery('name', name); g.addQuery('short_description', M); g.query(); if (g.next()) return g.getUniqueValue();
  g.initialize(); g.setValue('name', name); g.setValue('short_description', M); for (var k in fields) g.setValue(k, fields[k]); __f.created++; return '' + g.insert(); }
var vm = one('cmdb_ci_vmware_instance', 'vk1448212', {install_status: 7}); one('cmdb_ci_network_adapter', 'eth0-vm', {cmdb_ci: vm, ip_address: '165.40.47.119'});
var pc = one('cmdb_ci_computer', 'vk1448212', {install_status: 7}); var nic = one('cmdb_ci_network_adapter', 'eth0-pc', {cmdb_ci: pc}); one('cmdb_ci_ip_address', '165.40.47.119', {ip_address: '165.40.47.119', nic: nic});
gs.print('X::' + JSON.stringify(__f));''' % (json.dumps(MARK), json.dumps(specs)))
print('fixtures: %d specs, %d created, %d already present%s' % (len(specs), f['created'], f['present'], (', INVALID TABLES ' + ','.join(f['invalid'])) if f['invalid'] else ''))
passed = failed = 0
for run in (1, 2):
    for start in range(0, len(cases), 60):
        chunk = cases[start:start + 60]
        r = ui.js('''
var __o = {results: []}; var cases = %s; var ci = new sn_sec_cmn.CIIdentify();
for (var i = 0; i < cases.length; i++) {
    var res = null, err = '';
    try { res = ci.identify(%s, cases[i][1], true); } catch (ex) { err = '' + ex; }
    var out = {rule: '', ci: '', cls: '', error: err, alone: ''};
    if (res && res.lookupRule) { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); out.rule = '' + rr.getValue('order'); }
    if (res && res.ci && res.ci.mainCi) { var c = new GlideRecord('cmdb_ci'); c.get(res.ci.mainCi); out.ci = '' + c.getValue('name'); out.cls = '' + c.getValue('sys_class_name'); }
    if (cases[i][4]) { var l = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); l.addQuery('source', %s); l.addQuery('order', cases[i][4]); l.addQuery('name', 'STARTSWITH', 'USEM'); l.query();
        if (l.next()) { var ev = new GlideScopedEvaluator(); ev.putVariable('rule', l); ev.putVariable('sourceValue', cases[i][1][l.getValue('source_field')] || ''); ev.putVariable('sourcePayload', cases[i][1]);
            var one = null; try { one = ev.evaluateScript(l, 'script', null); } catch (e2) { out.error += ' alone: ' + e2; }
            if (one) { var g = new GlideRecord('cmdb_ci'); out.alone = g.get('' + one) ? '' + g.getValue('name') : '' + one; } } }
    __o.results.push(out);
}
gs.print('X::' + JSON.stringify(__o));''' % (json.dumps(chunk), json.dumps(QUALYS), json.dumps(QUALYS)))
        for c, x in zip(chunk, r['results']):
            ok = x['rule'] == c[2] and x['ci'] == c[3] and (len(c) < 5 or x['alone'] == c[5]) and not x['error']
            passed += ok; failed += (not ok)
            print('%s run%d %s -> %s%s%s%s' % ('PASS' if ok else 'FAIL', run, c[0], (x['rule'] + ' ' + x['ci'] + ' [' + x['cls'] + ']') if x['rule'] else 'no match', (' | %s alone -> %s' % (c[4], x['alone'] or '-')) if len(c) > 4 else '', (' ERROR ' + x['error']) if x['error'] else '', '' if ok else '   expected %s %s' % (c[2] or 'no match', c[3])))
print('\n%s: %d passed, %d failed (%d items, run twice)' % ('ALL PASS' if not failed else 'FAILED', passed, failed, len(cases)))
sys.exit(1 if failed else 0)
