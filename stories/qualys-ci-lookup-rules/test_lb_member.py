"""Cases for the load balancer rules on a marked fixture model of virtual servers, pools, members and real
servers (reference fields and relationships, addresses on device records, adapters and IP Address records),
including twin service records of one name (an HA pair, a copy on another address, a retired twin), twin
server records of one name (retired beside live, two live), a virtual address held on the balancer itself
through the discovery records, and pools the CMDB cannot place in full (the service rule attaches the
virtual server record only when the CMDB does not show several servers behind it). Runs the platform chain and one rule on its own, twice; a Load
Balancer Service result is shown as name@address, "+pool" when the record carries a pool.
`python3 test_lb_member.py remove` deletes the fixtures."""
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
    ('three members on three servers behind the virtual server (service record without fqdn, as on the client) -> no match: the service rule declines too, several servers behind the VIP', P('10.230.1.20', F5, 'vip-many.bankofamerica.com'), '', '', '460', ''),
    ('virtual server without a pool -> declined, the virtual server record', P('10.230.1.30', F5, 'vip-nopool.bankofamerica.com'), '460', 'vip-nopool@10.230.1.30', '455', ''),
    ('pool and member linked by relationships only, member address on an adapter -> the server', P('10.230.1.40', F5, 'vip-rel.bankofamerica.com'), '455', 'lbsrv-rel', '455', 'lbsrv-rel'),
    ('member address on an IP Address record of the server -> the server', P('10.230.1.50', F5, 'vip-ipr.bankofamerica.com'), '455', 'lbsrv-ipr', '455', 'lbsrv-ipr'),
    ('member without an address, related to the server -> the server', P('10.230.1.55', F5, 'vip-relsrv.bankofamerica.com'), '455', 'lbsrv-relsrv', '455', 'lbsrv-relsrv'),
    ('member address carried by two differently named device records -> no match: two machines behind one member address', P('10.230.1.60', F5, 'vip-dup.bankofamerica.com'), '', '', '460', ''),
    ('the only member is the load balancer itself -> the member rule declines; one identity the CMDB cannot place, the virtual server record', P('10.230.1.70', F5, 'vip-lbonly.bankofamerica.com'), '460', 'vip-lbonly@10.230.1.70+pool', '455', ''),
    ('a virtual address with no service record -> no match', P('10.230.1.99', F5, 'vip-none.bankofamerica.com'), '', '', '455', ''),
    ('no VIP sign: a Red Hat host on the virtual address -> the rule does not run', P('10.230.1.10', 'Red Hat Enterprise Linux 9.8', 'somehost.corp.bankofamerica.com'), '', '', '455', ''),
    ('the real server scanned on its own address and name -> the name rule, untouched', P('10.230.2.11', 'Red Hat Enterprise Linux 9.8', 'lbsrv-one.corp.bankofamerica.com'), '400', 'lbsrv-one'),
    ('three members of which only one address is a server in the CMDB -> no match: two members unplaced, three identities', P('10.230.1.80', F5, 'vip-partial.bankofamerica.com'), '', '', '455', ''),
    ('an HA pair: two records of one virtual server on one address, the pool on one of them -> the server', P('10.230.1.90', F5), '455', 'lbsrv-pair', '455', 'lbsrv-pair'),
    ('the same HA pair, the service rule alone -> declined, two live records of one virtual server compete', P('10.230.1.90', F5), '455', 'lbsrv-pair', '460', ''),
    ('twins of one name where only the retired twin carries the pool -> the live twin is kept, it has no pool, the member rule declines; the service rule attaches the live twin', P('10.230.1.92', F5, 'vip-rtwin.bankofamerica.com'), '460', 'vip-rtwin@10.230.1.92', '455', ''),
    ('one name on two addresses (a copy on another site) -> the server behind the record on the scanned address', P('10.230.1.93', F5, 'vip-far.bankofamerica.com'), '455', 'lbsrv-far', '455', 'lbsrv-far'),
    ('the same name scanned on the other address -> the server behind that record; the service rule alone picks the record on the address', P('10.230.1.94', F5, 'vip-far.bankofamerica.com'), '455', 'lbsrv-far2', '460', 'vip-far@10.230.1.94+pool'),
    ('two differently named services on one address -> no match', P('10.230.1.95', F5), '', '', '460', ''),
    ('member address on a retired Server and a live Linux Server of one name -> the live record', P('10.230.1.96', F5, 'vip-twin.bankofamerica.com'), '455', 'lbsrv-twin', '455', 'lbsrv-twin'),
    ('member address on a live Server and a live Linux Server of one name -> declined, two live records compete; the virtual server record', P('10.230.1.97', F5, 'vip-depth.bankofamerica.com'), '460', 'vip-depth@10.230.1.97+pool', '455', ''),
    ('member address on two live Linux Servers of one name -> declined, two live records compete; the virtual server record', P('10.230.1.98', F5, 'vip-time.bankofamerica.com'), '460', 'vip-time@10.230.1.98+pool', '455', ''),
    ('member address on a retired Linux Server and a live plain Server of one name -> the live record, even though less specific', P('10.230.1.100', F5, 'vip-twin2.bankofamerica.com'), '455', 'LBSRV-TWIN2', '455', 'LBSRV-TWIN2'),
    ('a virtual address held on the balancer itself through the discovery records, Linux fingerprint -> the layered rule refuses the balancer, the member rule finds the server', P('10.230.1.101', 'Linux 2.6', 'vip-layer.bankofamerica.com'), '455', 'lbsrv-layer', '350', ''),
    ('two member records of one address, ports 80 and 443, on one server -> the server', P('10.230.1.102', F5, 'vip-ports.bankofamerica.com'), '455', 'lbsrv-ports', '455', 'lbsrv-ports'),
    ('one member whose address no CI carries -> the member rule declines; one identity the CMDB cannot place, the virtual server record', P('10.230.1.103', F5, 'vip-unknown.bankofamerica.com'), '460', 'vip-unknown@10.230.1.103+pool', '455', ''),
    ('two members whose addresses no CI carries -> no match: two identities, several servers behind the VIP', P('10.230.1.104', F5, 'vip-unknown2.bankofamerica.com'), '', '', '460', ''),
    ('two members, one on a server and one that no CI carries -> no match: an unplaced member, two identities', P('10.230.1.105', F5, 'vip-half.bankofamerica.com'), '', '', '460', ''),
]
TABLES = ['cmdb_ip_address_dns_name', 'cmdb_ci_dns_name', 'cmdb_ci_ip_address', 'cmdb_ci_network_adapter', 'cmdb_ci_lb_pool_member', 'cmdb_ci_lb_pool', 'cmdb_ci_lb_service', 'cmdb_ci_lb_bigip', 'cmdb_ci_linux_server', 'cmdb_ci_win_server', 'cmdb_ci_server']
ui = SNUI(); ui.app('global')
if len(sys.argv) > 1 and sys.argv[1] == 'remove':
    r = ui.js('''
var __r = {removed: 0, rels: 0}; var M = %s; var tables = %s;
var rel = new GlideRecord('cmdb_rel_ci'); rel.addQuery('parent.short_description', M).addOrCondition('child.short_description', M); rel.query(); while (rel.next()) { rel.deleteRecord(); __r.rels++; }
for (var i = 0; i < tables.length; i++) { var g = new GlideRecord(tables[i]); if (!g.isValid()) continue; if (tables[i] == 'cmdb_ip_address_dns_name') g.addQuery('dns_name.short_description', M); else g.addQuery('short_description', M); g.query(); while (g.next()) { g.deleteRecord(); __r.removed++; } }
gs.print('X::' + JSON.stringify(__r));''' % (json.dumps(MARK), json.dumps(TABLES)))
    print('removed', r['removed'], 'records and', r['rels'], 'relationships'); sys.exit(0)
f = ui.js('''
var __f = {out: []}; var M = %s;
function one(table, name, fields, extra) { var g = new GlideRecord(table); g.addQuery('name', name); g.addQuery('short_description', M); for (var x in extra || {}) g.addQuery(x, extra[x]); g.query();
  if (g.next()) return g.getUniqueValue();
  g.initialize(); g.setValue('name', name); g.setValue('short_description', M); for (var k in fields || {}) g.setValue(k, fields[k]); var id = '' + g.insert(); __f.out.push(name); return id; }
function rel(parent, child) { var t = new GlideRecord('cmdb_rel_type'); t.addQuery('name', 'Depends on::Used by'); t.query(); t.next();
  var r = new GlideRecord('cmdb_rel_ci'); r.addQuery('parent', parent); r.addQuery('child', child); r.query(); if (r.next()) return;
  r.initialize(); r.setValue('parent', parent); r.setValue('child', child); r.setValue('type', t.getUniqueValue()); r.insert(); __f.out.push('rel'); }
function adapter(ci, name, ip) { var a = new GlideRecord('cmdb_ci_network_adapter'); a.addQuery('cmdb_ci', ci); a.addQuery('name', name); a.query(); if (a.next()) return a.getUniqueValue();
  a.initialize(); a.setValue('name', name); a.setValue('cmdb_ci', ci); a.setValue('short_description', M); if (ip) a.setValue('ip_address', ip); return '' + a.insert(); }
function ipRecord(nic, ip) { var r = new GlideRecord('cmdb_ci_ip_address'); r.addQuery('nic', nic); r.addQuery('ip_address', ip); r.query(); if (r.next()) return r.getUniqueValue();
  r.initialize(); r.setValue('name', ip); r.setValue('ip_address', ip); r.setValue('nic', nic); r.setValue('short_description', M); return '' + r.insert(); }
function dnsLink(ipId, ip, dnsName) { var d = one('cmdb_ci_dns_name', dnsName, {fqdn: dnsName, ip_address: ip});
  var m = new GlideRecord('cmdb_ip_address_dns_name'); m.addQuery('dns_name', d); m.addQuery('ip_address', ipId); m.query();
  if (!m.next()) { m.initialize(); m.setValue('dns_name', d); m.setValue('ip_address', ipId); m.insert(); __f.out.push('dnslink'); } }
var lb = one('cmdb_ci_lb_bigip', 'fixlb-bigip', {ip_address: '10.230.0.1'}); var lb2 = one('cmdb_ci_lb_bigip', 'fixlb-bigip-b', {ip_address: '10.230.0.2'});
function vip(name, ip, withPool, balancer, more) { balancer = balancer || lb; var fields = {ip_address: ip, port: 443, fqdn: name + '.bankofamerica.com', load_balancer: balancer}; for (var k in more || {}) fields[k] = more[k];
  var s = one('cmdb_ci_lb_service', name, fields, {ip_address: ip, load_balancer: balancer});
  if (more && more.fqdn === '') { var fg = new GlideRecord('cmdb_ci_lb_service'); fg.get(s); if (fg.getValue('fqdn')) { fg.setValue('fqdn', ''); fg.update(); __f.out.push(name + ' fqdn cleared'); } }
  if (!withPool) return {service: s};
  var p = one('cmdb_ci_lb_pool', name + '-pool', {service: s, load_balancer: balancer}, {load_balancer: balancer}); var sg = new GlideRecord('cmdb_ci_lb_service'); sg.get(s); if (!sg.getValue('pool')) { sg.setValue('pool', p); sg.update(); }
  return {service: s, pool: p}; }
function member(pool, name, ip) { var fields = {load_balancer: lb}; if (pool) fields.pool = pool; if (ip) fields.ip_address = ip; fields.service_port = 443; return one('cmdb_ci_lb_pool_member', name, fields); }
var v1 = vip('vip-one', '10.230.1.10', true); member(v1.pool, 'vip-one-pool_10.230.2.11_443', '10.230.2.11'); one('cmdb_ci_linux_server', 'lbsrv-one', {ip_address: '10.230.2.11'});
var v2 = vip('vip-many', '10.230.1.20', true, lb, {fqdn: ''}); var abc = ['a', 'b', 'c'];
for (var i = 0; i < 3; i++) { member(v2.pool, 'vip-many-pool_10.230.2.2' + (i + 1) + '_443', '10.230.2.2' + (i + 1)); one('cmdb_ci_linux_server', 'lbsrv-' + abc[i], {ip_address: '10.230.2.2' + (i + 1)}); }
vip('vip-nopool', '10.230.1.30', false);
var v4 = vip('vip-rel', '10.230.1.40', false); var p4 = one('cmdb_ci_lb_pool', 'vip-rel-pool', {load_balancer: lb}); rel(v4.service, p4);
var m4 = member(null, 'vip-rel-pool_10.230.2.41_443', '10.230.2.41'); rel(p4, m4); var s4 = one('cmdb_ci_linux_server', 'lbsrv-rel', {}); adapter(s4, 'eth0', '10.230.2.41');
var v5 = vip('vip-ipr', '10.230.1.50', true); member(v5.pool, 'vip-ipr-pool_10.230.2.51_443', '10.230.2.51'); var s5 = one('cmdb_ci_linux_server', 'lbsrv-ipr', {}); ipRecord(adapter(s5, 'eth0'), '10.230.2.51');
var v6 = vip('vip-relsrv', '10.230.1.55', true); var m6 = member(v6.pool, 'vip-relsrv-pool_member', ''); var s6 = one('cmdb_ci_linux_server', 'lbsrv-relsrv', {}); rel(m6, s6);
var v7 = vip('vip-dup', '10.230.1.60', true, lb, {fqdn: ''}); member(v7.pool, 'vip-dup-pool_10.230.2.61_443', '10.230.2.61'); one('cmdb_ci_linux_server', 'lbsrv-dup1', {ip_address: '10.230.2.61'}); one('cmdb_ci_win_server', 'lbsrv-dup2', {ip_address: '10.230.2.61'});
var v8 = vip('vip-lbonly', '10.230.1.70', true); member(v8.pool, 'vip-lbonly-pool_10.230.0.1_443', '10.230.0.1');
var v9 = vip('vip-partial', '10.230.1.80', true, lb, {fqdn: ''}); member(v9.pool, 'vip-partial-pool_10.230.2.81_443', '10.230.2.81'); member(v9.pool, 'vip-partial-pool_10.230.2.82_443', '10.230.2.82'); member(v9.pool, 'vip-partial-pool_10.230.2.83_443', '10.230.2.83'); one('cmdb_ci_linux_server', 'lbsrv-partial-only', {ip_address: '10.230.2.81'});
// twin service records of one name: an HA pair (no fqdn, scanned by address), a retired twin holding the pool, a copy of the name on another address, two different names on one address
var pa = one('cmdb_ci_lb_service', '/Common/vip-pair-443', {ip_address: '10.230.1.90', port: 443, load_balancer: lb}, {ip_address: '10.230.1.90', load_balancer: lb}); one('cmdb_ci_lb_service', '/Common/vip-pair-443', {ip_address: '10.230.1.90', port: 443, load_balancer: lb2}, {ip_address: '10.230.1.90', load_balancer: lb2});
var pap = one('cmdb_ci_lb_pool', '/Common/vip-pair-443-pool', {service: pa, load_balancer: lb}); var pag = new GlideRecord('cmdb_ci_lb_service'); pag.get(pa); if (!pag.getValue('pool')) { pag.setValue('pool', pap); pag.update(); }
member(pap, '/Common/vip-pair-443-pool_10.230.2.91_443', '10.230.2.91'); one('cmdb_ci_linux_server', 'lbsrv-pair', {ip_address: '10.230.2.91'});
var rt = vip('vip-rtwin', '10.230.1.92', true, lb, {install_status: 7}); vip('vip-rtwin', '10.230.1.92', false, lb2); member(rt.pool, 'vip-rtwin-pool_10.230.2.93_443', '10.230.2.93'); one('cmdb_ci_linux_server', 'lbsrv-rtwin', {ip_address: '10.230.2.93'});
var fa = vip('vip-far', '10.230.1.93', true, lb); member(fa.pool, 'vip-far-pool_10.230.2.94_443', '10.230.2.94'); one('cmdb_ci_linux_server', 'lbsrv-far', {ip_address: '10.230.2.94'});
var fb = vip('vip-far', '10.230.1.94', true, lb2); member(fb.pool, 'vip-far-pool_10.230.2.95_443', '10.230.2.95'); one('cmdb_ci_linux_server', 'lbsrv-far2', {ip_address: '10.230.2.95'});
vip('vip-x1', '10.230.1.95', false, lb); vip('vip-x2', '10.230.1.95', false, lb2);
// twin server records of one name behind one member address: retired vs live, plain Server vs Linux Server, older vs newer
var tw = vip('vip-twin', '10.230.1.96', true); member(tw.pool, 'vip-twin-pool_10.230.2.96_443', '10.230.2.96');
one('cmdb_ci_server', 'LBSRV-TWIN', {ip_address: '10.230.2.96', install_status: 7, serial_number: 'FIXLB-TWIN-1'}, {serial_number: 'FIXLB-TWIN-1'}); one('cmdb_ci_linux_server', 'lbsrv-twin', {ip_address: '10.230.2.96', serial_number: 'FIXLB-TWIN-2'}, {serial_number: 'FIXLB-TWIN-2'});
var dp = vip('vip-depth', '10.230.1.97', true); member(dp.pool, 'vip-depth-pool_10.230.2.97_443', '10.230.2.97');
one('cmdb_ci_server', 'LBSRV-DEPTH', {ip_address: '10.230.2.97', serial_number: 'FIXLB-DEPTH-1'}, {serial_number: 'FIXLB-DEPTH-1'}); one('cmdb_ci_linux_server', 'lbsrv-depth', {ip_address: '10.230.2.97', serial_number: 'FIXLB-DEPTH-2'}, {serial_number: 'FIXLB-DEPTH-2'});
var tm = vip('vip-time', '10.230.1.98', true); member(tm.pool, 'vip-time-pool_10.230.2.98_443', '10.230.2.98');
var t1 = one('cmdb_ci_linux_server', 'lbsrv-time', {ip_address: '10.230.2.98', serial_number: 'FIXLB-TIME-1'}, {serial_number: 'FIXLB-TIME-1'});
var t2q = new GlideRecord('cmdb_ci_linux_server'); t2q.addQuery('serial_number', 'FIXLB-TIME-2'); t2q.query(); if (!t2q.next()) { gs.sleep(1500); one('cmdb_ci_linux_server', 'LBSRV-TIME', {ip_address: '10.230.2.98', serial_number: 'FIXLB-TIME-2'}, {serial_number: 'FIXLB-TIME-2'}); }
var t2 = vip('vip-twin2', '10.230.1.100', true); member(t2.pool, 'vip-twin2-pool_10.230.2.100_443', '10.230.2.100');
one('cmdb_ci_linux_server', 'lbsrv-twin2', {ip_address: '10.230.2.100', install_status: 7, serial_number: 'FIXLB-TWIN2-1'}, {serial_number: 'FIXLB-TWIN2-1'}); one('cmdb_ci_server', 'LBSRV-TWIN2', {ip_address: '10.230.2.100', serial_number: 'FIXLB-TWIN2-2'}, {serial_number: 'FIXLB-TWIN2-2'});
// a virtual address held on the balancer itself through the discovery records (DNS Name -> IP Address -> adapter -> balancer), plus the service and its one member
dnsLink(ipRecord(adapter(lb, 'vip-if'), '10.230.1.101'), '10.230.1.101', 'vip-layer.bankofamerica.com');
var ly = vip('vip-layer', '10.230.1.101', true); member(ly.pool, 'vip-layer-pool_10.230.2.101_443', '10.230.2.101'); one('cmdb_ci_linux_server', 'lbsrv-layer', {ip_address: '10.230.2.101'});
// pools that are not one known machine: two ports of one server (fine), one unplaced member, two unplaced members, one placed and one unplaced
var po = vip('vip-ports', '10.230.1.102', true); member(po.pool, 'vip-ports-pool_10.230.2.102_80', '10.230.2.102'); member(po.pool, 'vip-ports-pool_10.230.2.102_443', '10.230.2.102'); one('cmdb_ci_linux_server', 'lbsrv-ports', {ip_address: '10.230.2.102'});
var un = vip('vip-unknown', '10.230.1.103', true); member(un.pool, 'vip-unknown-pool_10.230.2.103_443', '10.230.2.103');
var un2 = vip('vip-unknown2', '10.230.1.104', true, lb, {fqdn: ''}); member(un2.pool, 'vip-unknown2-pool_10.230.2.104_443', '10.230.2.104'); member(un2.pool, 'vip-unknown2-pool_10.230.2.105_443', '10.230.2.105');
var hf = vip('vip-half', '10.230.1.105', true, lb, {fqdn: ''}); member(hf.pool, 'vip-half-pool_10.230.2.106_443', '10.230.2.106'); member(hf.pool, 'vip-half-pool_10.230.2.107_443', '10.230.2.107'); one('cmdb_ci_linux_server', 'lbsrv-half', {ip_address: '10.230.2.106'});
gs.print('X::' + JSON.stringify(__f));''' % json.dumps(MARK))
print('fixtures created:', ', '.join(f['out']) or 'none (all present)')
passed = failed = 0
for run in (1, 2):
    r = ui.js('''
var __o = {results: []}; var cases = %s; var ci = new sn_sec_cmn.CIIdentify();
function show(id) { var c = new GlideRecord('cmdb_ci'); if (!id || !c.get('' + id)) return '' + (id || ''); var n = '' + c.getValue('name');
    if (c.getValue('sys_class_name') == 'cmdb_ci_lb_service') { var s = new GlideRecord('cmdb_ci_lb_service'); s.get('' + id); n += '@' + s.getValue('ip_address') + (s.getValue('pool') ? '+pool' : ''); } return n; }
for (var i = 0; i < cases.length; i++) {
    var p = cases[i][1]; var res = null, err = '';
    try { res = ci.identify(%s, p, true); } catch (ex) { err = '' + ex; }
    var out = {rule: '', ci: '', error: err, alone: ''};
    if (res && res.lookupRule) { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); out.rule = '' + rr.getValue('order'); }
    if (res && res.ci && res.ci.mainCi) out.ci = show(res.ci.mainCi);
    if (cases[i][4]) { var l = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); l.addQuery('source', %s); l.addQuery('order', cases[i][4]); l.addQuery('name', 'STARTSWITH', 'USEM'); l.query();
        if (l.next()) { var ev = new GlideScopedEvaluator(); ev.putVariable('rule', l); ev.putVariable('sourceValue', p[l.getValue('source_field')] || ''); ev.putVariable('sourcePayload', p);
            var one = null; try { one = ev.evaluateScript(l, 'script', null); } catch (e2) { out.error += ' alone: ' + e2; }
            if (one) out.alone = show(one); } else out.alone = '(rule not deployed)'; }
    __o.results.push(out);
}
gs.print('X::' + JSON.stringify(__o));''' % (json.dumps(CASES), json.dumps(QUALYS), json.dumps(QUALYS)))
    for c, x in zip(CASES, r['results']):
        ok = x['rule'] == c[2] and x['ci'] == c[3] and (len(c) < 5 or x['alone'] == c[5]) and not x['error']
        passed += ok; failed += (not ok)
        print('%s run%d %s | chain %s %s%s%s%s' % ('PASS' if ok else 'FAIL', run, c[0], x['rule'] or '(no match)', x['ci'], (' | %s alone -> %s' % (c[4], x['alone'] or '-')) if len(c) > 4 else '', (' ERROR ' + x['error']) if x['error'] else '', '' if ok else '   expected chain %s %s' % (c[2] or '(no match)', c[3])))
print('\n%s: %d passed, %d failed' % ('ALL PASS' if not failed else 'FAILED', passed, failed))
sys.exit(1 if failed else 0)
