"""Profiles the unmatched Discovered Items (sn_sec_cmn_src_ci, state=unmatched):
one group-by on the stored OS text, two counts, then a spread sample of rows
whose payloads are analysed locally. Read-only."""
import os, sys, json, re
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.join(BASE, 'stories', 'qualys-ci-lookup-rules')
ui = SNUI()
Q = 'state=unmatched'
P = {}
P['by_os'] = ui.js('''
var o = {rows: []}; var a = new GlideAggregate('sn_sec_cmn_src_ci'); a.addEncodedQuery(%s); a.addAggregate('COUNT'); a.groupBy('os'); a.orderByAggregate('COUNT'); a.query(); var n = 0;
while (a.next() && n++ < 80) o.rows.push(['' + a.getValue('os'), parseInt(a.getAggregate('COUNT'))]);
gs.print('X::' + JSON.stringify(o));''' % json.dumps(Q))['rows']
print('by_os top 80:', flush=True); [print('   %7d  %s' % (n, v), flush=True) for v, n in P['by_os']]
P['netbios_filled'] = ui.js('''var o = {}; var a = new GlideAggregate('sn_sec_cmn_src_ci'); a.addEncodedQuery('state=unmatched^netbiosISNOTEMPTY'); a.addAggregate('COUNT'); a.query(); a.next(); o.n = parseInt(a.getAggregate('COUNT')); gs.print('X::' + JSON.stringify(o));''')['n']
P['resource_id_filled'] = ui.js('''var o = {}; var a = new GlideAggregate('sn_sec_cmn_src_ci'); a.addEncodedQuery('state=unmatched^resource_idISNOTEMPTY'); a.addAggregate('COUNT'); a.query(); a.next(); o.n = parseInt(a.getAggregate('COUNT')); gs.print('X::' + JSON.stringify(o));''')['n']
print('netbios filled', P['netbios_filled'], '| resource_id filled', P['resource_id_filled'], flush=True)
sample = []
for w in range(0, 12):
    off = w * 23000
    rows = ui.js('''
var o = {rows: []}; var g = new GlideRecord('sn_sec_cmn_src_ci'); g.addEncodedQuery(%s); g.orderBy('sys_created_on'); g.chooseWindow(%d, %d); g.query();
while (g.next()) { var p = {}; try { p = JSON.parse('' + g.getValue('source_data')); } catch (e) {} if (!p || typeof p != 'object') p = {};
  o.rows.push({n: '' + g.getValue('cmdb_ci_name'), c: '' + g.getValue('cmdb_ci_class'), t: '' + (p.TRACKING_METHOD || ''), dns: '' + (p.DNS || ''), nb: '' + (p.NETBIOS || ''), qg: !!p.QG_HOSTID, sn: '' + (p.SERIAL_NUMBER || ''), cloud: '' + (p.CLOUD_RESOURCE_ID || ''), os: '' + (p.OS || ''), ip: '' + (p.IP || ''), keys: Object.keys(p).length, created: '' + g.getValue('sys_created_on')}); }
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(Q), off, off + 400))['rows']
    sample += rows; print('sample window', w, 'rows', len(rows), 'total', len(sample), flush=True)
P['sample'] = sample
json.dump(P, open(os.path.join(HERE, 'unmatched_profile.json'), 'w'), indent=1)
print('PROFILE DONE', len(sample), flush=True)
