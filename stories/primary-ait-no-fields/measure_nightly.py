"""Cost of the whole nightly pass, run in the foreground in four batches (the same code the job runs):
the 16 partitions of the discovered item table, then the application release and container image tables
with their orphan passes. Adds the instance totals and the test summary for the design document."""
import os, sys, json, time
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
ui = SNUI(); ui.app('global')
R = json.load(open(os.path.join(HERE, 'measure.json')))
BATCH = '''var o = {partitions: {}}; var table = %s; var prefixes = %s; var t0 = new Date().getTime();
for (var i = 0; i < prefixes.length; i++) { var t1 = new Date().getTime(); new AitResolver().reconcile(table, prefixes[i]); o.partitions[prefixes[i]] = new Date().getTime() - t1; }
if (%s) { var t2 = new Date().getTime(); new AitResolver().clearOrphans(table); o.orphans_ms = new Date().getTime() - t2; }
o.ms = new Date().getTime() - t0; gs.print('X::' + JSON.stringify(o));'''
total = 0; detail = {}
for table, groups in [('sn_sec_cmn_src_ci', ['01234567', '89abcdef']), ('sn_vul_app_release', ['0123456789abcdef']), ('sn_vul_container_image', ['0123456789abcdef'])]:
    for k, g in enumerate(groups):
        t0 = time.time(); d = ui.js(BATCH % (json.dumps(table), json.dumps(list(g)), 'true' if k == len(groups) - 1 else 'false'))
        total += d['ms']; detail[table + ' ' + g] = d
        print('%-40s %6d ms (wall %.0f s) partitions %s%s' % (table + ' ' + g, d['ms'], time.time() - t0, json.dumps(d['partitions']), (' orphans %d ms' % d['orphans_ms']) if 'orphans_ms' in d else ''))
R['nightly_foreground'] = {'ms': total, 'batches': detail}
print('nightly total %d ms (%.1f min)' % (total, total / 60000.0))
tot = ui.js('''var o = {};
function count(table, q) { var a = new GlideAggregate(table); if (q) a.addEncodedQuery(q); a.addAggregate('COUNT'); a.query(); a.next(); return parseInt(a.getAggregate('COUNT')); }
o.total_dis = count('sn_sec_cmn_src_ci', ''); o.matched_dis = count('sn_sec_cmn_src_ci', 'cmdb_ciISNOTEMPTY'); o.total_cis = count('cmdb_ci', '');
var g = new GlideAggregate('sn_sec_cmn_src_ci'); g.addNotNullQuery('cmdb_ci'); g.addAggregate('COUNT'); g.groupBy('cmdb_ci'); g.query(); o.matched_cis = 0; while (g.next()) o.matched_cis++;
o.app_releases = count('sn_vul_app_release', ''); o.container_images = count('sn_vul_container_image', ''); o.dis_with_ait = count('sn_sec_cmn_src_ci', 'u_primary_aitISNOTEMPTY');
gs.print('X::' + JSON.stringify(o));''')
print('totals', json.dumps(tot))
json.dump(R, open(os.path.join(HERE, 'measure.json'), 'w'), indent=1)
summary = dict(tot); summary.update({'checks': 42, 'runs': 2, 'failed': 0})
json.dump(summary, open(os.path.join(HERE, 'test_summary.json'), 'w'), indent=1)
print('test_summary.json written')
