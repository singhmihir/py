"""Cost of the Primary AIT resolution on the instance, measured on the server (run after build.py
and fixtures.py, never while test.py is running):
1. the import path: discovered item inserts with the before rule on and off, for a CI with services,
   a CI that resolves through a related CI and a CI without any link
2. one keyed refresh with a wide fan-out: a service gaining 2,000 CIs at once
3. one partition of the nightly reconcile over the whole discovered item table, and the full job
Fixture rows created here are removed at the end; the timing rows are written to measure.json."""
import os, sys, json, time
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
F = json.load(open(os.path.join(HERE, 'fixtures.json'))); ST = json.load(open(os.path.join(HERE, 'state.json')))
C = F['cis']; S = F['svcs']
ui = SNUI(); ui.app('global')
R = {}
def step(label, code):
    t0 = time.time(); d = ui.js(code); d['wall_s'] = round(time.time() - t0, 1); print('%-78s %s' % (label, json.dumps(d))); return d
# 1. import path: 100 inserts per case, rule on; then the same with the rule off (Default set pinned while the flag is flipped)
INSERT = '''var o = {}; var N = 100; function batch(ci, tag) { var t0 = new Date().getTime(); for (var i = 0; i < N; i++) { var g = new GlideRecord('sn_sec_cmn_src_ci'); g.initialize(); g.setValue('name', 'USEMAIT-M-' + tag + '-' + i); g.setValue('source_id', 'USEMAIT-M-' + tag + '-' + i); g.setValue('cmdb_ci', ci); g.insert(); } return Math.round((new Date().getTime() - t0) / N * 100) / 100; }
o.ms_per_insert_ci_with_service = batch(%s, 'svc'); o.ms_per_insert_ci_related_only = batch(%s, 'rel'); o.ms_per_insert_ci_without_links = batch(%s, 'none');
var c = new GlideAggregate('sn_sec_cmn_src_ci'); c.addQuery('source_id', 'STARTSWITH', 'USEMAIT-M-'); c.addNotNullQuery('u_primary_ait'); c.addAggregate('COUNT'); c.query(); c.next(); o.rows_stamped = parseInt(c.getAggregate('COUNT'));
var d = new GlideRecord('sn_sec_cmn_src_ci'); d.addQuery('source_id', 'STARTSWITH', 'USEMAIT-M-'); d.query(); o.rows_removed = 0; while (d.next()) { d.setWorkflow(false); d.deleteRecord(); o.rows_removed++; }
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(C['C5']), json.dumps(C['C7']), json.dumps(C['C8']))
R['import_rule_on'] = step('1a. 100 discovered item inserts per case, before rule active (ms per insert)', INSERT)
FLIP = '''var dflt = new GlideRecord('sys_update_set'); dflt.addQuery('is_default', true); dflt.addQuery('application', 'global'); dflt.query(); dflt.next(); new GlideUpdateSet().set(dflt.getUniqueValue());
var br = new GlideRecord('sys_script'); br.get(%s); br.setValue('active', %s); br.update(); new GlideUpdateSet().set(%s); gs.print('X::{}');'''
ui.js(FLIP % (json.dumps(ST['made']['di_rules']['sn_sec_cmn_src_ci']), 'false', json.dumps(ST['set'])))
try:
    R['import_rule_off'] = step('1b. the same inserts with the before rule inactive (ms per insert)', INSERT)
finally:
    ui.js(FLIP % (json.dumps(ST['made']['di_rules']['sn_sec_cmn_src_ci']), 'true', json.dumps(ST['set'])))
    print('   rule re-activated, captured in the Default set only')
# 2. wide fan-out: 2,000 placeholder CIs join S1 at once (associations written with rules off, so no events), then one keyed refresh of S1
R['fanout'] = step('2a. service S1 gains 2,000 CIs: one refresh(service) resolves and stamps them', '''var o = {}; var S1 = %s; var ids = [];
var ph = new GlideAggregate('sn_sec_cmn_src_ci'); ph.addQuery('cmdb_ci.sys_class_name', 'cmdb_ci_unclassed_hardware'); ph.addAggregate('COUNT'); ph.groupBy('cmdb_ci'); ph.setLimit(2000); ph.query(); while (ph.next()) ids.push(ph.getValue('cmdb_ci'));
o.cis = ids.length; var t0 = new Date().getTime();
for (var i = 0; i < ids.length; i++) { var a = new GlideRecord('svc_ci_assoc'); a.initialize(); a.setWorkflow(false); a.setValue('ci_id', ids[i]); a.setValue('service_id', S1); a.insert(); }
o.assoc_insert_ms = new Date().getTime() - t0;
var dc = new GlideAggregate('sn_sec_cmn_src_ci'); dc.addQuery('cmdb_ci', 'IN', ids.join(',')); dc.addAggregate('COUNT'); dc.query(); dc.next(); o.dis_of_those_cis = parseInt(dc.getAggregate('COUNT'));
t0 = new Date().getTime(); new AitResolver().refresh('service', S1); o.refresh_ms = new Date().getTime() - t0;
var sc = new GlideAggregate('sn_sec_cmn_src_ci'); sc.addQuery('cmdb_ci', 'IN', ids.join(',')); sc.addQuery('u_primary_ait', %s); sc.addAggregate('COUNT'); sc.query(); sc.next(); o.dis_stamped = parseInt(sc.getAggregate('COUNT'));
t0 = new Date().getTime(); new AitResolver().refresh('service', S1); o.refresh_again_ms = new Date().getTime() - t0;
o.ids = ids; gs.print('X::' + JSON.stringify(o));''' % (json.dumps(S['S1']), json.dumps(F['aits']['AIT57151'])))
ids = R['fanout'].pop('ids')
R['fanout_clear'] = step('2b. the associations are removed with rules off; refreshCis over the 2,000 CIs clears the items', '''var o = {}; var ids = %s; var S1 = %s;
var a = new GlideRecord('svc_ci_assoc'); a.addQuery('service_id', S1); a.addQuery('ci_id', 'IN', ids.join(',')); a.query(); o.assoc_removed = 0; while (a.next()) { a.setWorkflow(false); a.deleteRecord(); o.assoc_removed++; }
var t0 = new Date().getTime(); new AitResolver().refreshCis(ids); o.clear_ms = new Date().getTime() - t0;
var sc = new GlideAggregate('sn_sec_cmn_src_ci'); sc.addQuery('cmdb_ci', 'IN', ids.join(',')); sc.addNotNullQuery('u_primary_ait'); sc.addAggregate('COUNT'); sc.query(); sc.next(); o.dis_still_stamped = parseInt(sc.getAggregate('COUNT'));
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(ids), json.dumps(S['S1'])))
# 3. the nightly reconcile: one partition timed in the foreground, then the whole job as a scheduled job
R['reconcile_partition'] = step('3a. reconcile of partition 0 of sn_sec_cmn_src_ci (CIs whose sys_id starts with 0)', '''var o = {};
var ga = new GlideAggregate('sn_sec_cmn_src_ci'); ga.addNotNullQuery('cmdb_ci'); ga.addQuery('cmdb_ci.sys_id', 'STARTSWITH', '0'); ga.addAggregate('COUNT'); ga.groupBy('cmdb_ci'); ga.query(); o.cis = 0; o.dis = 0; while (ga.next()) { o.cis++; o.dis += parseInt(ga.getAggregate('COUNT')); }
var t0 = new Date().getTime(); new AitResolver().reconcile('sn_sec_cmn_src_ci', '0'); o.ms = new Date().getTime() - t0; o.ms_per_ci = Math.round(o.ms / o.cis * 100) / 100;
gs.print('X::' + JSON.stringify(o));''')
before = ui.js('''var o = {}; var c = new GlideAggregate('sn_sec_cmn_src_ci'); c.addNotNullQuery('u_primary_ait'); c.addAggregate('COUNT'); c.query(); c.next(); o.dis_with_ait = parseInt(c.getAggregate('COUNT'));
var t = new GlideRecord('sys_trigger'); t.addQuery('document', %s); t.query(); o.trigger = t.next() ? t.getUniqueValue() : ''; gs.print('X::' + JSON.stringify(o));''' % json.dumps(ST['made']['reconcile_job']))
ui.js('''var j = new GlideRecord('sysauto_script'); j.get(%s); SncTriggerSynchronizer.executeNow(j); gs.print('X::{}');''' % json.dumps(ST['made']['reconcile_job']))
t0 = time.time(); state = None
time.sleep(5)
while time.time() - t0 < 3600:
    st = ui.js('''var o = {}; var t = new GlideRecord('sys_trigger'); t.addQuery('document', %s); t.query(); o.running = 0; while (t.next()) if (t.getValue('state') == '1') o.running++;
var w = new GlideRecord('sys_trigger'); w.addQuery('name', 'STARTSWITH', 'USEM Primary AIT reconcile'); w.addQuery('state', '1'); w.query(); o.running += w.getRowCount();
var l = new GlideRecord('syslog'); l.addQuery('sys_created_on', '>', new GlideDateTime(new GlideDateTime().getNumericValue() - 3600000)); l.addQuery('message', 'STARTSWITH', 'AitResolver'); l.query(); o.errors = l.getRowCount();
gs.print('X::' + JSON.stringify(o));''' % json.dumps(ST['made']['reconcile_job']))
    if st['running'] == 0 and time.time() - t0 > 20:
        state = st; break
    time.sleep(10)
after = ui.js('''var o = {}; var c = new GlideAggregate('sn_sec_cmn_src_ci'); c.addNotNullQuery('u_primary_ait'); c.addAggregate('COUNT'); c.query(); c.next(); o.dis_with_ait = parseInt(c.getAggregate('COUNT'));
var f = new GlideAggregate('sn_sec_cmn_src_ci'); f.addQuery('source_id', 'STARTSWITH', 'USEMAIT-'); f.addNotNullQuery('u_primary_ait'); f.addAggregate('COUNT'); f.query(); f.next(); o.fixture_dis_with_ait = parseInt(f.getAggregate('COUNT')); gs.print('X::' + JSON.stringify(o));''')
R['reconcile_job'] = {'wall_s': round(time.time() - t0, 1), 'dis_with_ait_before': before['dis_with_ait'], 'dis_with_ait_after': after['dis_with_ait'], 'fixture_dis_with_ait': after['fixture_dis_with_ait'], 'errors': (state or {}).get('errors')}
print('%-78s %s' % ('3b. the whole nightly job (3 tables x 16 partitions + orphans) as a scheduled job', json.dumps(R['reconcile_job'])))
json.dump(R, open(os.path.join(HERE, 'measure.json'), 'w'), indent=1)
