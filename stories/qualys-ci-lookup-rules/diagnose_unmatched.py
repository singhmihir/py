"""Diagnosis for hosts the Qualys CI lookup rules do not match.

Dumps the recently created unmatched CIs, Qualys host records, vulnerable
items and CIs, then runs the platform's own CIIdentify.identify() with the
Qualys source for every recent host record and reports which rule matched.
Read-only: nothing is written on the instance.
"""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
DAYS = int(sys.argv[1]) if len(sys.argv) > 1 else 30
QUALYS = 'ed44bdc453220300e8f9f745911c0801'
ui = SNUI()
d = ui.js('''
var o = {days: %d};
var SYS = {sys_id: 1, sys_created_on: 1, sys_created_by: 1, sys_updated_on: 1, sys_updated_by: 1, sys_mod_count: 1, sys_domain: 1, sys_domain_path: 1, sys_tags: 1, sys_class_path: 1};
function dump(table, limit, extraOrder) {
    var out = []; var gr = new GlideRecord(table); if (!gr.isValid()) return 'no table ' + table;
    gr.addQuery('sys_created_on', '>', gs.daysAgoStart(%d)); gr.orderByDesc('sys_created_on'); gr.setLimit(limit); gr.query();
    while (gr.next()) {
        var row = {sys_id: gr.getUniqueValue(), created: '' + gr.getValue('sys_created_on'), by: '' + gr.getValue('sys_created_by'), sys_class_name: '' + gr.getValue('sys_class_name')};
        var els = gr.getElements ? gr.getElements() : null;
        if (els) for (var i = 0; i < els.size(); i++) { var el = els.get(i); var n = '' + el.getName(); if (SYS[n]) continue; var v = '' + el; if (v) row[n] = (el.getED().getInternalType() == 'reference') ? v + ' [' + el.getDisplayValue() + ']' : v; }
        out.push(row);
    }
    return out;
}
o.unmatched = dump('sn_sec_cmn_unmatched_ci', 60);
o.qualys_hosts = dump('sn_vul_qualys_host_attrb', 60);
o.vits = dump('sn_vul_vulnerable_item', 60);
o.cis = dump('cmdb_ci', 80);
// evaluate the rules for every recent Qualys host record
o.identify = [];
var ci = new sn_sec_cmn.CIIdentify();
var h = new GlideRecord('sn_vul_qualys_host_attrb'); h.addQuery('sys_created_on', '>', gs.daysAgoStart(%d)); h.orderByDesc('sys_created_on'); h.setLimit(60); h.query();
while (h.next()) {
    var payload = {}; var els2 = h.getElements();
    for (var j = 0; j < els2.size(); j++) { var e2 = els2.get(j); var n2 = '' + e2.getName(); if (SYS[n2]) continue; var v2 = '' + e2; if (!v2) continue; payload[n2] = v2; payload[n2.toUpperCase()] = v2; }
    var res = null, err = '';
    try { res = ci.identify(QUALYS_SOURCE, payload, true); } catch (ex) { err = '' + ex; }
    var out = {host: h.getUniqueValue(), payload: payload, error: err};
    if (res) { out.rule = res.lookupRule ? ('' + new GlideRecord('sn_sec_cmn_ci_lookup_rule').get(res.lookupRule) && (function () { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); return rr.getValue('order') + ' ' + rr.getValue('name'); })()) : '';
        var mc = res.ci && res.ci.mainCi ? res.ci.mainCi : (res.ci || ''); out.ci = '' + mc;
        if (mc) { var cg = new GlideRecord('cmdb_ci'); if (cg.get(mc)) out.ci_name = '' + cg.getValue('name') + ' [' + cg.getValue('sys_class_name') + ']'; } }
    o.identify.push(out);
}
gs.print('X::' + JSON.stringify(o));'''.replace('QUALYS_SOURCE', "'" + QUALYS + "'") % (DAYS, DAYS, DAYS))
for k in ('unmatched', 'qualys_hosts', 'vits', 'cis', 'identify'):
    v = d[k]
    print('=====', k, (len(v) if isinstance(v, list) else v))
    if isinstance(v, list):
        for row in v: print('  ', json.dumps(row, ensure_ascii=False))
json.dump(d, open(os.path.join(BASE, 'stories', 'qualys-ci-lookup-rules', 'diagnosis.json'), 'w'), indent=1)
