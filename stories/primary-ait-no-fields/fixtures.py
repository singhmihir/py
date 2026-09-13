"""Fixture graph for the Primary AIT resolution, marked 'USEM AIT fixture' in short_description
(the discovered items in source_id). `python3 fixtures.py remove` takes everything away."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__)); MARK = 'USEM AIT fixture'; BOFASIM = '9d1e03de930b8310e3aef0aefaba10d5'
ui = SNUI(); ui.app('global')
ST = json.load(open(os.path.join(HERE, 'state.json')))
def rest_delete(ui, table, condition):
    """Deletes rows of a store application table through the table API: scripts from another scope
    are refused by the application access setting, the API applies the ordinary ACLs."""
    from snui import INST
    head = {'X-UserToken': ui.ck(), 'Accept': 'application/json'}
    rows = ui.s.get(INST + '/api/now/table/' + table, params={'sysparm_query': condition, 'sysparm_fields': 'sys_id', 'sysparm_limit': 1000}, headers=head).json().get('result', [])
    deleted = sum(1 for r in rows if ui.s.delete(INST + '/api/now/table/' + table + '/' + r['sys_id'], headers=head).status_code == 204)
    left = len(ui.s.get(INST + '/api/now/table/' + table, params={'sysparm_query': condition, 'sysparm_fields': 'sys_id', 'sysparm_limit': 1000}, headers=head).json().get('result', []))
    return {'deleted': deleted, 'left': left}
def remove(table, condition, scope='global'):
    code = '''var o = {}; var g = new GlideRecord(%s); g.addEncodedQuery(%s); g.query(); o.n = 0; while (g.next()) { g.setWorkflow(false); g.deleteRecord(); o.n++; }
var left = new GlideRecord(%s); left.addEncodedQuery(%s); left.query(); o.left = left.getRowCount(); gs.print('X::' + JSON.stringify(o));''' % (json.dumps(table), json.dumps(condition), json.dumps(table), json.dumps(condition))
    r = ui.js(code, scope=scope) if scope != 'global' else ui.js(code)
    print('%-28s removed %d, left %d' % (table, r['n'], r['left']))
if len(sys.argv) > 1 and sys.argv[1] == 'remove':
    remove('sn_sec_cmn_src_ci', 'source_idSTARTSWITHUSEMAIT')
    print('sn_vul_app_release', json.dumps(rest_delete(ui, 'sn_vul_app_release', 'source_release_idSTARTSWITHUSEMAIT')))
    print('sn_vul_container_image', json.dumps(rest_delete(ui, 'sn_vul_container_image', 'image_idSTARTSWITHUSEMAIT')))
    print('sn_vul_m2m_ci_services', json.dumps(rest_delete(ui, 'sn_vul_m2m_ci_services', 'service.short_description=' + MARK)))
    remove('svc_ci_assoc', 'service_id.short_description=' + MARK)
    remove('cmdb_rel_ci', 'parent.short_description=' + MARK + '^ORchild.short_description=' + MARK)
    remove('cmdb_ci_linux_server', 'short_description=' + MARK)
    remove('cmdb_ci_service', 'short_description=' + MARK)
    remove('cmdb_ci_business_app', 'short_description=' + MARK)
    sys.exit(0)
# 1. the stand-in tier column, in the stand-in scope, and tiers on the four AITs
t = ui.js('''var o = {};
var d = new GlideRecord('sys_dictionary'); d.addQuery('name', 'x_196061_bofasim_ait'); d.addQuery('element', 'rto_tier'); d.query();
if (!d.next()) { d.initialize(); d.setValue('name', 'x_196061_bofasim_ait'); d.setValue('element', 'rto_tier'); d.setValue('column_label', 'RTO tier'); d.setValue('internal_type', 'integer'); d.setValue('max_length', 40); d.setValue('active', true); o.column = '' + d.insert(); } else o.column = 'exists';
var tiers = {AIT57151: 1, AIT57152: 2, AIT57153: 3, AIT57154: 2}; o.aits = {};
var a = new GlideRecord('x_196061_bofasim_ait'); a.query(); while (a.next()) { var n = '' + a.getValue('number'); if (tiers[n] !== undefined) { a.setWorkflow(false); a.setValue('rto_tier', tiers[n]); a.update(); } o.aits[n] = a.getUniqueValue(); }
gs.print('X::' + JSON.stringify(o));''', scope=BOFASIM)
print('tier column:', t['column'], '| AITs:', t['aits'])
A = t['aits']
# 2. applications, services, relationships, CIs, associations, related services, discovered items
f = ui.js('''var o = {out: []}; var M = %s; var A = %s;
function one(table, name, fields) { var g = new GlideRecord(table); g.addQuery('name', name); g.addQuery('short_description', M); g.query();
  if (g.next()) { return g.getUniqueValue(); }
  g.initialize(); g.setValue('name', name); g.setValue('short_description', M); for (var k in fields || {}) g.setValue(k, fields[k]); var id = '' + g.insert(); o.out.push(table + ' ' + name); return id; }
var apps = {App1: one('cmdb_ci_business_app', 'USEMAIT App1', {u_primary_ait: A.AIT57151}), App2: one('cmdb_ci_business_app', 'USEMAIT App2', {u_primary_ait: A.AIT57152}),
            App3: one('cmdb_ci_business_app', 'USEMAIT App3', {u_primary_ait: A.AIT57153}), App4: one('cmdb_ci_business_app', 'USEMAIT App4 (no AIT)', {}), App5: one('cmdb_ci_business_app', 'USEMAIT App5', {u_primary_ait: A.AIT57154})};
var svcs = {}; ['S1', 'S2', 'S3', 'S4', 'S5', 'S6'].forEach(function(s) { svcs[s] = one('cmdb_ci_service', 'USEMAIT ' + s, {}); });
var rt = new GlideRecord('cmdb_rel_type'); rt.addQuery('name', 'Depends on::Used by'); rt.query(); rt.next(); var TYPE = rt.getUniqueValue();
function rel(parent, child) { var r = new GlideRecord('cmdb_rel_ci'); r.addQuery('parent', parent); r.addQuery('child', child); r.query(); if (r.next()) return; r.initialize(); r.setValue('parent', parent); r.setValue('child', child); r.setValue('type', TYPE); r.insert(); }
rel(apps.App1, svcs.S1); rel(apps.App2, svcs.S2); rel(apps.App3, svcs.S2); rel(svcs.S3, apps.App3); rel(apps.App4, svcs.S4); rel(svcs.S5, apps.App5); rel(apps.App2, svcs.S6); rel(svcs.S6, apps.App5);
var cis = {}; ['C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C9', 'C10'].forEach(function(c) { cis[c] = one('cmdb_ci_linux_server', 'usemait-' + c.toLowerCase(), {}); });
function assoc(ci, svc) { var g = new GlideRecord('svc_ci_assoc'); g.addQuery('ci_id', ci); g.addQuery('service_id', svc); g.query(); if (g.next()) return; g.initialize(); g.setValue('ci_id', ci); g.setValue('service_id', svc); g.insert(); }
assoc(cis.C1, svcs.S1); assoc(cis.C2, svcs.S2); assoc(cis.C3, svcs.S3); assoc(cis.C4, svcs.S4); assoc(cis.C5, svcs.S2); assoc(cis.C5, svcs.S3); assoc(cis.C9, svcs.S5); assoc(cis.C10, svcs.S6);
var m = new GlideRecord('sn_vul_m2m_ci_services'); m.addQuery('item', cis.C6); m.addQuery('service', svcs.S1); m.query(); if (m.next()) o.related = 'exists'; else { m.initialize(); m.setValue('item', cis.C6); m.setValue('service', svcs.S1); o.related = m.insert() ? 'inserted' : 'REFUSED'; }
rel(svcs.S3, cis.C7);
var expected = {C1: A.AIT57151, C2: A.AIT57152, C3: A.AIT57153, C4: '', C5: A.AIT57152, C6: A.AIT57151, C7: A.AIT57153, C8: '', C9: A.AIT57154, C10: A.AIT57152};
function di(table, keyField, name, ci, extra) { var g = new GlideRecord(table); g.addQuery(keyField, name); g.query(); if (g.next()) return g.getUniqueValue(); g.initialize(); g.setValue(keyField, name); g.setValue('cmdb_ci', ci); for (var k in extra || {}) g.setValue(k, extra[k]); var id = '' + g.insert(); o.out.push(table + ' ' + name); return id; }
o.dis = {};
for (var c in cis) { for (var k = 1; k <= 3; k++) o.dis['src_' + c + '_' + k] = di('sn_sec_cmn_src_ci', 'source_id', 'USEMAIT-' + c + '-' + k, cis[c], {name: 'USEMAIT-' + c + '-' + k}); }
o.dis['rel_C2'] = di('sn_vul_app_release', 'source_release_id', 'USEMAIT-REL-C2', cis.C2, {app_name: 'USEMAIT-REL-C2', active: true}); o.dis['rel_C8'] = di('sn_vul_app_release', 'source_release_id', 'USEMAIT-REL-C8', cis.C8, {app_name: 'USEMAIT-REL-C8', active: true});
var impl = new GlideRecord('sn_sec_int_impl'); impl.setLimit(1); impl.query(); impl.next();
o.dis['img_C3'] = di('sn_vul_container_image', 'image_id', 'USEMAIT-IMG-C3', cis.C3, {image_name: 'USEMAIT-IMG-C3', host_list: 'usemait-c3', source: impl.getUniqueValue()}); o.dis['img_C4'] = di('sn_vul_container_image', 'image_id', 'USEMAIT-IMG-C4', cis.C4, {image_name: 'USEMAIT-IMG-C4', host_list: 'usemait-c4', source: impl.getUniqueValue()});
o.checks = {}; for (var d in o.dis) { var tbl = d.indexOf('src_') == 0 ? 'sn_sec_cmn_src_ci' : d.indexOf('rel_') == 0 ? 'sn_vul_app_release' : 'sn_vul_container_image'; var chk = new GlideRecord(tbl); if (!chk.get(o.dis[d]) || chk.getValue('cmdb_ci') != cis[d.split('_')[1]]) o.checks[d] = 'WRONG ROW'; }
o.apps = apps; o.svcs = svcs; o.cis = cis; o.expected = expected;
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(MARK), json.dumps(A)))
print('created:', ', '.join(f['out']) or 'nothing new'); print('discovered items:', len(f['dis']), '| related service link C6-S1:', f['related'], '| row checks:', json.dumps(f['checks']))
assert f['related'] != 'REFUSED' and not f['checks']
# stray Related Services rows on the fixture services (only C6-S1 belongs to the graph) are removed in the owning scope
stray = rest_delete(ui, 'sn_vul_m2m_ci_services', 'service.short_description=' + MARK + '^item!=' + f['cis']['C6']); print('stray related service rows:', json.dumps(stray)); assert stray['left'] == 0
json.dump({'aits': A, 'apps': f['apps'], 'svcs': f['svcs'], 'cis': f['cis'], 'dis': f['dis'], 'expected': f['expected']}, open(os.path.join(HERE, 'fixtures.json'), 'w'), indent=1)
