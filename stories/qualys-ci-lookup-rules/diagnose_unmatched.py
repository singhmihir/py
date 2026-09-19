"""Diagnosis for the Discovered Items (sn_sec_cmn_src_ci) in state "unmatched".

For every unmatched item: the identifying attributes from its source payload,
the CIs the CMDB holds for those attributes (short name, full name, fqdn, IP on
the CI, on an adapter, on an IP Address record, NetBIOS, serial, DNS Name
record) and the outcome of the platform's own CIIdentify.identify() for the
Qualys source. Read-only; runs in batches of ten items per request.
"""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.join(BASE, 'stories', 'qualys-ci-lookup-rules')
QUALYS = 'ed44bdc453220300e8f9f745911c0801'
BATCH = 10
ui = SNUI()
SAMPLE = int(sys.argv[1]) if len(sys.argv) > 1 else 60
ids = ui.js('''
var o = {ids: []};
var g = new GlideRecord('sn_sec_cmn_src_ci'); g.addQuery('state', 'unmatched'); g.orderByDesc('sys_created_on'); g.setLimit(%d); g.query();
while (g.next()) o.ids.push(g.getUniqueValue());
for (var w = 1; w <= %d; w++) { var s = new GlideRecord('sn_sec_cmn_src_ci'); s.addQuery('state', 'unmatched'); s.orderBy('sys_created_on'); s.chooseWindow(w * 9000, w * 9000 + 1); s.query(); if (s.next()) o.ids.push(s.getUniqueValue()); }
gs.print('X::' + JSON.stringify(o));''' % (SAMPLE // 2, SAMPLE // 2))['ids']
print('sampled unmatched items:', len(ids), '(newest half plus a spread across the table)')
items = []
for i in range(0, len(ids), BATCH):
    chunk = ids[i:i + BATCH]
    d = ui.js('''
var o = {items: []};
function cis(table, field, value, extraNull) {
    var out = []; if (!value) return out; var g = new GlideRecord(table); if (!g.isValid()) return out;
    g.addQuery(field, value); if (extraNull) g.addNotNullQuery(extraNull); g.setLimit(6); g.query();
    while (g.next()) { var rec = extraNull ? g.getElement(extraNull).getRefRecord() : g; var owner = '' + rec.getValue('name') + ' [' + rec.getValue('sys_class_name') + ']';
        out.push(owner + (g.isValidField('fqdn') && g.getValue('fqdn') ? ' fqdn=' + g.getValue('fqdn') : '') + (g.isValidField('ip_address') && g.getValue('ip_address') ? ' ip=' + g.getValue('ip_address') : '') + (rec.isValidField('install_status') ? ' st=' + rec.getValue('install_status') : '')); }
    return out;
}
var ci = new sn_sec_cmn.CIIdentify();
var g = new GlideRecord('sn_sec_cmn_src_ci'); g.addQuery('sys_id', 'IN', %s); g.orderByDesc('sys_created_on'); g.query();
while (g.next()) {
    var p = {}; try { p = JSON.parse('' + g.getValue('source_data')); } catch (e) { p = {}; } if (!p || typeof p != 'object') p = {};
    var dns = ('' + (p.DNS || '')).toLowerCase(); var host = dns.split('.')[0]; var ip = '' + (p.IP || '');
    var it = {sys_id: g.getUniqueValue(), number: '' + g.getValue('number'), created: '' + g.getValue('sys_created_on'), name: '' + g.getValue('cmdb_ci_name'), cls: '' + g.getValue('cmdb_ci_class'),
        ip: ip, dns: dns, netbios: '' + (p.NETBIOS || ''), os: '' + (p.OS || ''), track: '' + (p.TRACKING_METHOD || ''), serial: '' + (p.SERIAL_NUMBER || ''), qg: '' + (p.QG_HOSTID || ''), cloud: '' + (p.CLOUD_RESOURCE_ID || ''), payload_keys: Object.keys(p),
        ci_by_short_name: cis('cmdb_ci', 'name', host), ci_by_full_name: dns && dns != host ? cis('cmdb_ci', 'name', dns) : [], ci_by_fqdn: cis('cmdb_ci', 'fqdn', dns), ci_by_ip: cis('cmdb_ci', 'ip_address', ip),
        nic_by_ip: cis('cmdb_ci_network_adapter', 'ip_address', ip, 'cmdb_ci'), ipaddr_by_ip: cis('cmdb_ci_ip_address', 'ip_address', ip, 'nic'), ci_by_netbios: p.NETBIOS ? cis('cmdb_ci', 'name', '' + p.NETBIOS) : [],
        ci_by_serial: p.SERIAL_NUMBER ? cis('cmdb_ci', 'serial_number', '' + p.SERIAL_NUMBER) : [], dns_name_rec: cis('cmdb_ci_dns_name', 'name', dns)};
    var payload = {}; for (var k in p) if (typeof p[k] == 'string' || typeof p[k] == 'number') payload[k] = '' + p[k];
    try { var res = ci.identify(QUALYS_SOURCE, payload, true); it.identify = res ? {rule: res.lookupRule ? (function () { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); return rr.getValue('order') + ' ' + rr.getValue('name'); })() : '', ci: res.ci && res.ci.mainCi ? (function () { var c = new GlideRecord('cmdb_ci'); c.get(res.ci.mainCi); return c.getValue('name') + ' [' + c.getValue('sys_class_name') + ']'; })() : ''} : null; }
    catch (ex) { it.identify = {error: '' + ex}; }
    o.items.push(it);
}
gs.print('X::' + JSON.stringify(o));'''.replace('QUALYS_SOURCE', "'" + QUALYS + "'") % json.dumps(','.join(chunk)))
    items += d['items']
    print('batch', i // BATCH + 1, 'done:', len(items), 'items', flush=True)
json.dump({'sampled': len(ids), 'items': items}, open(os.path.join(HERE, 'diagnosis.json'), 'w'), indent=1)
for it in items:
    cands = {k: v for k, v in it.items() if k.startswith(('ci_', 'nic_', 'ipaddr_', 'dns_name')) and v}
    print('%s | %s | %s | ip %s | track %s | os %s' % (it['number'], it['created'][:10], it['name'][:55], it['ip'], it['track'], it['os'][:45]))
    print('     identify:', json.dumps(it['identify']), '| candidates:', json.dumps(cands) if cands else 'NONE')
