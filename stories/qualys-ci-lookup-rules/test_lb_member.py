"""Cases for rule 455 USEM Load Balancer Member Match on a marked fixture model of virtual servers, pools,
members and real servers (reference fields and relationships, addresses on device records, adapters and
IP Address records). Runs the platform chain and the rule on its own, twice. `python3 test_lb_member.py
remove` deletes the fixtures."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
QUALYS = 'ed44bdc453220300e8f9f745911c0801'; MARK = 'USEM lookup rule fixture (LB)'
F5 = 'F5 Networks Big-IP'
def P(ip, os_, dns=None):
    d = {'IP': ip, 'TRACKING_METHOD': 'IP', 'OS': os_}
    if dns: d['DNS'] = dns
    return d
CASES = [  # label, payload, expected chain rule ('' = no match), expected CI, (optional) rule alone and its expected CI
    ('one member behind the virtual server, address on the server record -> the server', P('10.230.1.10', F5, 'vip-one.bankofamerica.com'), '455', 'lbsrv-one', '455', 'lbsrv-one'),
    ('the same virtual server scanned by address only -> the server', P('10.230.1.10', F5), '455', 'lbsrv-one', '455', 'lbsrv-one'),
    ('the same virtual server with a Linux fingerprint and a -vip label -> the server', P('10.230.1.10', 'Linux 2.6', 'vip-one.bankofamerica.com'), '455', 'lbsrv-one', '455', 'lbsrv-one'),
    ('three members behind the virtual server -> declined, the service rule attaches the virtual server', P('10.230.1.20', F5, 'vip-many.bankofamerica.com'), '460', 'vip-many', '455', ''),
    ('virtual server without a pool -> declined, the virtual server record', P('10.230.1.30', F5, 'vip-nopool.bankofamerica.com'), '460', 'vip-nopool', '455', ''),
    ('pool and member linked by relationships only, member address on an adapter -> the server', P('10.230.1.40', F5, 'vip-rel.bankofamerica.com'), '455', 'lbsrv-rel', '455', 'lbsrv-rel'),
    ('member address on an IP Address record of the server -> the server', P('10.230.1.50', F5, 'vip-ipr.bankofamerica.com'), '455', 'lbsrv-ipr', '455', 'lbsrv-ipr'),
    ('member without an address, related to the server -> the server', P('10.230.1.55', F5, 'vip-relsrv.bankofamerica.com'), '455', 'lbsrv-relsrv', '455', 'lbsrv-relsrv'),
    ('member address carried by two device records -> declined, the virtual server record', P('10.230.1.60', F5, 'vip-dup.bankofamerica.com'), '460', 'vip-dup', '455', ''),
    ('the only member is the load balancer itself -> declined, the virtual server record', P('10.230.1.70', F5, 'vip-lbonly.bankofamerica.com'), '460', 'vip-lbonly', '455', ''),
    ('a virtual address with no service record -> no match', P('10.230.1.99', F5, 'vip-none.bankofamerica.com'), '', '', '455', ''),
    ('no VIP sign: a Red Hat host on the virtual address -> the rule does not run', P('10.230.1.10', 'Red Hat Enterprise Linux 9.8', 'somehost.corp.bankofamerica.com'), '', '', '455', ''),
    ('the real server scanned on its own address and name -> the name rule, untouched', P('10.230.2.11', 'Red Hat Enterprise Linux 9.8', 'lbsrv-one.corp.bankofamerica.com'), '400', 'lbsrv-one'),
]
TABLES = ['cmdb_ci_ip_address', 'cmdb_ci_network_adapter', 'cmdb_ci_lb_pool_member', 'cmdb_ci_lb_pool', 'cmdb_ci_lb_service', 'cmdb_ci_lb_bigip', 'cmdb_ci_linux_server', 'cmdb_ci_win_server', 'cmdb_ci_server']
ui = SNUI(); ui.app('global')
if len(sys.argv) > 1 and sys.argv[1] == 'remove':
    r = ui.js('''
var __r = {removed: 0, rels: 0}; var M = %s; var tables = %s;
var rel = new GlideRecord('cmdb_rel_ci'); rel.addQuery('parent.short_description', M).addOrCondition('child.short_description', M); rel.query(); while (rel.next()) { rel.deleteRecord(); __r.rels++; }
for (var i = 0; i < tables.length; i++) { var g = new GlideRecord(tables[i]); if (!g.isValid()) continue; g.addQuery('short_description', M); g.query(); while (g.next()) { g.deleteRecord(); __r.removed++; } }
gs.print('X::' + JSON.stringify(__r));''' % (json.dumps(MARK), json.dumps(TABLES)))
    print('removed', r['removed'], 'records and', r['rels'], 'relationships'); sys.exit(0)
f = ui.js('''
var __f = {out: []}; var M = %s;
function one(table, name, fields) { var g = new GlideRecord(table); g.addQuery('name', name); g.addQuery('short_description', M); g.query();
  if (g.next()) return g.getUniqueValue();
  g.initialize(); g.setValue('name', name); g.setValue('short_description', M); for (var k in fields || {}) g.setValue(k, fields[k]); var id = '' + g.insert(); __f.out.push(name); return id; }
function rel(parent, child) { var t = new GlideRecord('cmdb_rel_type'); t.addQuery('name', 'Depends on::Used by'); t.query(); t.next();
  var r = new GlideRecord('cmdb_rel_ci'); r.addQuery('parent', parent); r.addQuery('child', child); r.query(); if (r.next()) return;
  r.initialize(); r.setValue('parent', parent); r.setValue('child', child); r.setValue('type', t.getUniqueValue()); r.insert(); __f.out.push('rel'); }
function adapter(ci, name, ip) { var a = new GlideRecord('cmdb_ci_network_adapter'); a.addQuery('cmdb_ci', ci); a.addQuery('name', name); a.query(); if (a.next()) return a.getUniqueValue();
  a.initialize(); a.setValue('name', name); a.setValue('cmdb_ci', ci); a.setValue('short_description', M); if (ip) a.setValue('ip_address', ip); return '' + a.insert(); }
function ipRecord(nic, ip) { var r = new GlideRecord('cmdb_ci_ip_address'); r.addQuery('nic', nic); r.addQuery('ip_address', ip); r.query(); if (r.next()) return;
  r.initialize(); r.setValue('name', ip); r.setValue('ip_address', ip); r.setValue('nic', nic); r.setValue('short_description', M); r.insert(); }
var lb = one('cmdb_ci_lb_bigip', 'fixlb-bigip', {ip_address: '10.230.0.1'});
function vip(name, ip, withPool) { var s = one('cmdb_ci_lb_service', name, {ip_address: ip, port: 443, fqdn: name + '.bankofamerica.com', load_balancer: lb});
  if (!withPool) return {service: s};
  var p = one('cmdb_ci_lb_pool', name + '-pool', {service: s, load_balancer: lb}); var sg = new GlideRecord('cmdb_ci_lb_service'); sg.get(s); if (!sg.getValue('pool')) { sg.setValue('pool', p); sg.update(); }
  return {service: s, pool: p}; }
function member(pool, name, ip) { var fields = {load_balancer: lb}; if (pool) fields.pool = pool; if (ip) fields.ip_address = ip; fields.service_port = 443; return one('cmdb_ci_lb_pool_member', name, fields); }
var v1 = vip('vip-one', '10.230.1.10', true); member(v1.pool, 'vip-one-pool_10.230.2.11_443', '10.230.2.11'); one('cmdb_ci_linux_server', 'lbsrv-one', {ip_address: '10.230.2.11'});
var v2 = vip('vip-many', '10.230.1.20', true); var abc = ['a', 'b', 'c'];
for (var i = 0; i < 3; i++) { member(v2.pool, 'vip-many-pool_10.230.2.2' + (i + 1) + '_443', '10.230.2.2' + (i + 1)); one('cmdb_ci_linux_server', 'lbsrv-' + abc[i], {ip_address: '10.230.2.2' + (i + 1)}); }
vip('vip-nopool', '10.230.1.30', false);
var v4 = vip('vip-rel', '10.230.1.40', false); var p4 = one('cmdb_ci_lb_pool', 'vip-rel-pool', {load_balancer: lb}); rel(v4.service, p4);
var m4 = member(null, 'vip-rel-pool_10.230.2.41_443', '10.230.2.41'); rel(p4, m4); var s4 = one('cmdb_ci_linux_server', 'lbsrv-rel', {}); adapter(s4, 'eth0', '10.230.2.41');
var v5 = vip('vip-ipr', '10.230.1.50', true); member(v5.pool, 'vip-ipr-pool_10.230.2.51_443', '10.230.2.51'); var s5 = one('cmdb_ci_linux_server', 'lbsrv-ipr', {}); ipRecord(adapter(s5, 'eth0'), '10.230.2.51');
var v6 = vip('vip-relsrv', '10.230.1.55', true); var m6 = member(v6.pool, 'vip-relsrv-pool_member', ''); var s6 = one('cmdb_ci_linux_server', 'lbsrv-relsrv', {}); rel(m6, s6);
var v7 = vip('vip-dup', '10.230.1.60', true); member(v7.pool, 'vip-dup-pool_10.230.2.61_443', '10.230.2.61'); one('cmdb_ci_linux_server', 'lbsrv-dup1', {ip_address: '10.230.2.61'}); one('cmdb_ci_win_server', 'lbsrv-dup2', {ip_address: '10.230.2.61'});
var v8 = vip('vip-lbonly', '10.230.1.70', true); member(v8.pool, 'vip-lbonly-pool_10.230.0.1_443', '10.230.0.1');
gs.print('X::' + JSON.stringify(__f));''' % json.dumps(MARK))
print('fixtures created:', ', '.join(f['out']) or 'none (all present)')
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
            if (one) { var g = new GlideRecord('cmdb_ci'); out.alone = g.get('' + one) ? '' + g.getValue('name') : '' + one; } } else out.alone = '(rule not deployed)'; }
    __o.results.push(out);
}
gs.print('X::' + JSON.stringify(__o));''' % (json.dumps(CASES), json.dumps(QUALYS), json.dumps(QUALYS)))
    for c, x in zip(CASES, r['results']):
        ok = x['rule'] == c[2] and x['ci'] == c[3] and (len(c) < 5 or x['alone'] == c[5]) and not x['error']
        passed += ok; failed += (not ok)
        print('%s run%d %s | chain %s %s%s%s%s' % ('PASS' if ok else 'FAIL', run, c[0], x['rule'] or '(no match)', x['ci'], (' | %s alone -> %s' % (c[4], x['alone'] or '-')) if len(c) > 4 else '', (' ERROR ' + x['error']) if x['error'] else '', '' if ok else '   expected chain %s %s' % (c[2] or '(no match)', c[3])))
print('\n%s: %d passed, %d failed' % ('ALL PASS' if not failed else 'FAILED', passed, failed))
sys.exit(1 if failed else 0)
