"""Prototypes of two possible tightenings of the load balancer rules, evaluated beside the delivered scripts on the
fixture model without touching any rule record: variant A makes 455 require one distinct member address, variant B
makes both rules treat several services that share one name on one address (an HA pair) as one record."""
import sys, json, re, html
sys.path.insert(0, '/home/user/py/tools')
from snui import SNUI
ui = SNUI(); ui.app('global')
H = '/home/user/py/stories/qualys-ci-lookup-rules/rules/'
r455 = open(H + '455_USEM_Load_Balancer_Member_Match.js').read(); r460 = open(H + '460_USEM_Load_Balancer_Service_Match.js').read()
# variant A: 455 requires exactly one distinct member address (all members on one server)
A = r455.replace("    var memberIds = Object.keys(members);\n    if (!memberIds.length)\n        return null;",
                 "    var memberIds = Object.keys(members);\n    if (!memberIds.length)\n        return null;\n    var addresses = {};\n    for (var a = 0; a < memberIds.length; a++)\n        if (members[memberIds[a]])\n            addresses[members[memberIds[a]]] = true;\n    if (Object.keys(addresses).length > 1)           // several real addresses behind the virtual server: shared pool\n        return null;")
assert A != r455
# variant B: one() treats several services that share one name as one record (an HA pair): takes the first
B_one = """        var id = gr.getUniqueValue();
        var sameName = true;
        var firstName = '' + gr.getValue('name');
        while (gr.hasNext()) {
            gr.next();
            if (('' + gr.getValue('name')) != firstName)
                sameName = false;
        }
        if (!sameName)
            return null;                          // two different services, never guess
        return id;"""
B460 = r460.replace("        var id = gr.getUniqueValue();\n        if (gr.hasNext())\n            return null;                          // two services, never guess\n        return id;", B_one)
B455 = r455.replace("        var id = gr.getUniqueValue();\n        if (gr.hasNext())\n            return null;                          // two services, never guess\n        return id;", B_one)
assert B460 != r460 and B455 != r455
# fixtures for the HA pair: two services named the same on one address, one pool with one member
f = ui.js('''var __f = {made: []}; var M = 'USEM lookup rule fixture (LB)';
function one(t, name, fields, extra) { var g = new GlideRecord(t); g.addQuery('name', name); g.addQuery('short_description', M); for (var k in extra || {}) g.addQuery(k, extra[k]); g.query(); if (g.next()) return g.getUniqueValue();
  g.initialize(); g.setValue('name', name); g.setValue('short_description', M); for (var k2 in fields) g.setValue(k2, fields[k2]); __f.made.push(name + (extra ? ' ' + JSON.stringify(extra) : '')); return '' + g.insert(); }
var lb1 = one('cmdb_ci_lb_bigip', 'fixlb-bigip', {ip_address: '10.230.0.1'}); var lb2 = one('cmdb_ci_lb_bigip', 'fixlb-bigip-b', {ip_address: '10.230.0.2'});
var s1 = one('cmdb_ci_lb_service', '/Common/vip-pair-443', {ip_address: '10.230.1.90', port: 443, load_balancer: lb1}, {load_balancer: lb1});
var s2 = one('cmdb_ci_lb_service', '/Common/vip-pair-443', {ip_address: '10.230.1.90', port: 443, load_balancer: lb2}, {load_balancer: lb2});
var p = one('cmdb_ci_lb_pool', '/Common/vip-pair-443-pool', {service: s1, load_balancer: lb1}); var sg = new GlideRecord('cmdb_ci_lb_service'); sg.get(s1); if (!sg.getValue('pool')) { sg.setValue('pool', p); sg.update(); }
one('cmdb_ci_lb_pool_member', '/Common/vip-pair-443-pool_10.230.2.91_443', {pool: p, ip_address: '10.230.2.91', service_port: 443, load_balancer: lb1});
one('cmdb_ci_linux_server', 'lbsrv-pair', {ip_address: '10.230.2.91'});
gs.print('X::' + JSON.stringify(__f));''')
print('HA-pair fixtures made:', f['made'] or 'all present')
F5 = 'F5 Networks Big-IP'
PAYLOADS = [('vip-one, one member', {'IP': '10.230.1.10', 'TRACKING_METHOD': 'IP', 'OS': F5, 'DNS': 'vip-one.bankofamerica.com'}),
            ('vip-many, three members on three servers', {'IP': '10.230.1.20', 'TRACKING_METHOD': 'IP', 'OS': F5, 'DNS': 'vip-many.bankofamerica.com'}),
            ('vip-partial, three members, one server known', {'IP': '10.230.1.80', 'TRACKING_METHOD': 'IP', 'OS': F5, 'DNS': 'vip-partial.bankofamerica.com'}),
            ('vip-rel, relationships only', {'IP': '10.230.1.40', 'TRACKING_METHOD': 'IP', 'OS': F5, 'DNS': 'vip-rel.bankofamerica.com'}),
            ('vip-dup, one member address on two servers', {'IP': '10.230.1.60', 'TRACKING_METHOD': 'IP', 'OS': F5, 'DNS': 'vip-dup.bankofamerica.com'}),
            ('vip-pair, two services of one name on one address (HA pair), one member', {'IP': '10.230.1.90', 'TRACKING_METHOD': 'IP', 'OS': F5}),
            ('vip-nopool', {'IP': '10.230.1.30', 'TRACKING_METHOD': 'IP', 'OS': F5, 'DNS': 'vip-nopool.bankofamerica.com'}),
            ('two different services on one address (from the V3 fixtures)', {'IP': '164.91.176.197', 'TRACKING_METHOD': 'IP', 'OS': F5})]
def run(label, script, payloads):
    r = ui.js('''var __o = {rows: []}; var scripts = %s; var payloads = %s;
for (var i = 0; i < payloads.length; i++) { var row = {label: payloads[i][0]};
  for (var name in scripts) { var rule = null, sourceValue = payloads[i][1].IP, sourcePayload = payloads[i][1]; var res = null, err = '';
    try { res = eval(scripts[name]); } catch (ex) { err = '' + ex; }
    var c = new GlideRecord('cmdb_ci'); row[name] = err ? 'ERROR ' + err : (res && c.get('' + res) ? c.getValue('name') + ' [' + ('' + c.getValue('sys_class_name')).replace('cmdb_ci_', '') + ']' : 'null'); }
  __o.rows.push(row); }
gs.print('X::' + JSON.stringify(__o));''' % (json.dumps(script), json.dumps(payloads)))
    print('\n--', label)
    for row in r['rows']: print('  %-70s ' % row['label'] + ' | '.join('%s: %s' % (k, v) for k, v in row.items() if k != 'label'))
run('current 455 and 460, then variant A (455 needs one distinct member address) and variant B (same-named services count as one)', {'455 now': r455, '460 now': r460, '455 A': A, '455 B': B455, '460 B': B460}, PAYLOADS)
