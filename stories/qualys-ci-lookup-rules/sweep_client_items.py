"""Runs the chain and every USEM rule on its own over a spread sample of the client's Qualys discovered
items held on the PDI (the payloads Mihir loaded), plus every item matched there today. Reports script
errors, timing per rule, the payload shapes seen, every CI any rule returned (the PDI holds no client
CMDB, so each match is looked at by hand) and every disagreement between rules. Results in
sweep_client_items.json. `python3 sweep_client_items.py [items] [batch]`."""
import os, sys, json, time
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
QUALYS = 'ed44bdc453220300e8f9f745911c0801'
TOTAL = int(sys.argv[1]) if len(sys.argv) > 1 else 6000; BATCH = int(sys.argv[2]) if len(sys.argv) > 2 else 500
JS = '''
var __o = {n: 0, chain_ms: 0, alone_ms: 0, matched: [], alone: [], disagree: [], errors: {}, per_rule_ms: {}, per_rule_max: {}, shapes: {dns_empty: 0, dns_ip: 0, dns_upper: 0, dns_nodot: 0, ip_empty: 0, os_empty: 0, os_multi: 0, tracking: {}, keys: {}}, today: []};
var Q = %s; var ci = new sn_sec_cmn.CIIdentify();
var rules = []; var l = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); l.addQuery('source', Q); l.addQuery('name', 'STARTSWITH', 'USEM'); l.addActiveQuery(); l.orderBy('order'); l.query();
while (l.next()) rules.push({id: l.getUniqueValue(), order: l.getValue('order'), field: l.getValue('source_field')});
function ciLabel(id) { var c = new GlideRecord('cmdb_ci'); if (!c.get(id)) return '' + id + ' (no such CI)'; return c.getValue('name') + ' [' + c.getValue('sys_class_name') + (c.getValue('install_status') == '7' ? ', retired' : '') + '] ' + ('' + c.getValue('short_description')).substring(0, 40); }
var di = new GlideRecord('sn_sec_cmn_src_ci'); di.addQuery('source.name', 'CONTAINS', 'Qualys'); %s di.orderBy('sys_id'); %s di.query();
while (di.next()) {
    var p; try { p = JSON.parse('' + di.getValue('source_data')); } catch (e) { __o.errors['payload parse'] = (__o.errors['payload parse'] || 0) + 1; continue; }
    __o.n++; var dns = '' + (p.DNS || ''), ip = '' + (p.IP || ''), os = '' + (p.OS || '');
    if (!dns) __o.shapes.dns_empty++; else { if (/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(dns)) __o.shapes.dns_ip++; if (dns != dns.toLowerCase()) __o.shapes.dns_upper++; if (dns.indexOf('.') == -1) __o.shapes.dns_nodot++; }
    if (!ip) __o.shapes.ip_empty++; if (!os) __o.shapes.os_empty++; else if (os.split('/').length > 2) __o.shapes.os_multi++;
    var tm = '' + (p.TRACKING_METHOD || '(none)'); __o.shapes.tracking[tm] = (__o.shapes.tracking[tm] || 0) + 1;
    for (var k in p) __o.shapes.keys[k] = (__o.shapes.keys[k] || 0) + 1;
    var item = di.getValue('number') + ' | ' + dns + ' | ' + ip + ' | ' + os.substring(0, 40);
    var t = new Date().getTime(); var res = null;
    try { res = ci.identify(Q, p, true); } catch (ex) { __o.errors['chain: ' + ex] = (__o.errors['chain: ' + ex] || 0) + 1; }
    __o.chain_ms += new Date().getTime() - t;
    var chainCi = (res && res.ci && res.ci.mainCi) ? '' + res.ci.mainCi : '';
    if (chainCi) { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); __o.matched.push(item + ' -> ' + rr.getValue('order') + ' ' + ciLabel(chainCi)); }
    if (di.getValue('state') == 'matched') __o.today.push(item + ' | today ' + ciLabel(di.getValue('cmdb_ci')) + ' | chain ' + (chainCi ? ciLabel(chainCi) : 'no match'));
    var found = {};
    for (var r = 0; r < rules.length; r++) {
        var lr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); lr.get(rules[r].id);
        var ev = new GlideScopedEvaluator(); ev.putVariable('rule', lr); ev.putVariable('sourceValue', p[rules[r].field] || ''); ev.putVariable('sourcePayload', p);
        var t1 = new Date().getTime(); var out = null;
        try { out = ev.evaluateScript(lr, 'script', null); } catch (e2) { var key = rules[r].order + ': ' + e2; __o.errors[key] = (__o.errors[key] || 0) + 1; }
        var d = new Date().getTime() - t1; __o.per_rule_ms[rules[r].order] = (__o.per_rule_ms[rules[r].order] || 0) + d; if (d > (__o.per_rule_max[rules[r].order] || 0)) __o.per_rule_max[rules[r].order] = d; __o.alone_ms += d;
        if (out) { found[rules[r].order] = '' + out; __o.alone.push(item + ' -> ' + rules[r].order + ' ' + ciLabel('' + out)); }
    }
    var ids = {}; for (var o in found) ids[found[o]] = true; if (Object.keys(ids).length > 1) __o.disagree.push(item + ' -> ' + JSON.stringify(found));
}
gs.print('X::' + JSON.stringify(__o));'''
ui = SNUI(); ui.app('global')
count = ui.js('''var __c = {}; var ga = new GlideAggregate('sn_sec_cmn_src_ci'); ga.addQuery('source.name', 'CONTAINS', 'Qualys'); ga.addAggregate('COUNT'); ga.query(); ga.next(); __c.n = parseInt(ga.getAggregate('COUNT')); gs.print('X::' + JSON.stringify(__c));''')['n']
batches = [(int(i * count / (TOTAL / BATCH)), BATCH) for i in range(TOTAL // BATCH)]
agg = {'n': 0, 'chain_ms': 0, 'alone_ms': 0, 'matched': [], 'alone': [], 'disagree': [], 'errors': {}, 'per_rule_ms': {}, 'per_rule_max': {}, 'shapes': None, 'today': [], 'population': count}
def merge(r):
    agg['n'] += r['n']; agg['chain_ms'] += r['chain_ms']; agg['alone_ms'] += r['alone_ms']
    for k in ('matched', 'alone', 'disagree', 'today'): agg[k] += r[k]
    for k, v in r['errors'].items(): agg['errors'][k] = agg['errors'].get(k, 0) + v
    for k, v in r['per_rule_ms'].items(): agg['per_rule_ms'][k] = agg['per_rule_ms'].get(k, 0) + v
    for k, v in r['per_rule_max'].items(): agg['per_rule_max'][k] = max(agg['per_rule_max'].get(k, 0), v)
    if agg['shapes'] is None: agg['shapes'] = r['shapes']
    else:
        for k, v in r['shapes'].items():
            if isinstance(v, dict):
                for k2, v2 in v.items(): agg['shapes'][k][k2] = agg['shapes'][k].get(k2, 0) + v2
            else: agg['shapes'][k] += v
t0 = time.time()
r = ui.js(JS % (json.dumps(QUALYS), "di.addQuery('state', 'matched');", ''))
merge(r); print('matched today: %d items, %d chain matches, %.0fs' % (r['n'], len(r['matched']), time.time() - t0), flush=True)
for i, (offset, size) in enumerate(batches):
    t1 = time.time()
    r = ui.js(JS % (json.dumps(QUALYS), '', 'di.chooseWindow(%d, %d);' % (offset, offset + size)))
    merge(r); print('batch %d/%d offset %d: %d items, chain matches %d, rule hits %d, errors %d, %.0fs' % (i + 1, len(batches), offset, r['n'], len(r['matched']), len(r['alone']), sum(r['errors'].values()), time.time() - t1), flush=True)
json.dump(agg, open(os.path.join(HERE, 'sweep_client_items.json'), 'w'), indent=1)
print('\nitems %d of %d | chain %.0f ms/item | all rules alone %.0f ms/item' % (agg['n'], count, agg['chain_ms'] / max(agg['n'], 1), agg['alone_ms'] / max(agg['n'], 1)))
print('payload shapes:', json.dumps(agg['shapes']))
print('errors:', json.dumps(agg['errors']) if agg['errors'] else 'none')
print('per rule ms total / max:', ', '.join('%s: %d / %d' % (k, agg['per_rule_ms'][k], agg['per_rule_max'][k]) for k in sorted(agg['per_rule_ms'], key=int)))
print('\nchain matches (%d):' % len(agg['matched'])); print('\n'.join('  ' + x for x in agg['matched']))
print('\nrules returning a CI on their own (%d):' % len(agg['alone'])); print('\n'.join('  ' + x for x in agg['alone']))
print('\nrules disagreeing on an item (%d):' % len(agg['disagree'])); print('\n'.join('  ' + x for x in agg['disagree']))
print('\nitems matched today on the PDI (%d):' % len(agg['today'])); print('\n'.join('  ' + x for x in agg['today']))
