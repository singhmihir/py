"""Scenario tests for the Primary AIT resolution on the fixture graph (run after build.py and
fixtures.py; re-runnable). Every scenario changes one source record through the normal write path,
waits for the keyed event to be processed and compares every fixture discovered item with the
expected value; the reconcile, orphan and catch-up paths are exercised with rules bypassed."""
import os, sys, json, time
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
F = json.load(open(os.path.join(HERE, 'fixtures.json'))); ST = json.load(open(os.path.join(HERE, 'state.json')))
A = F['aits']; NUM = dict((v, k) for k, v in A.items()); C = F['cis']; S = F['svcs']; P = F['apps']; D = F['dis']
ui = SNUI(); ui.app('global')
def rest_delete(ui, table, condition):
    """Deletes rows of a store application table through the table API: scripts from another scope
    are refused by the application access setting, the API applies the ordinary ACLs."""
    from snui import INST
    head = {'X-UserToken': ui.ck(), 'Accept': 'application/json'}
    rows = ui.s.get(INST + '/api/now/table/' + table, params={'sysparm_query': condition, 'sysparm_fields': 'sys_id', 'sysparm_limit': 1000}, headers=head).json().get('result', [])
    deleted = sum(1 for r in rows if ui.s.delete(INST + '/api/now/table/' + table + '/' + r['sys_id'], headers=head).status_code == 204)
    left = len(ui.s.get(INST + '/api/now/table/' + table, params={'sysparm_query': condition, 'sysparm_fields': 'sys_id', 'sysparm_limit': 1000}, headers=head).json().get('result', []))
    return {'deleted': deleted, 'left': left}
RESULTS = []; T0 = None
def check(label, ok, detail=''):
    RESULTS.append((label, bool(ok))); print('%s  %s%s' % ('PASS' if ok else 'FAIL', label, ('  [' + detail + ']') if detail else ''))
def js(code, scope='global'):
    return ui.js(code, scope=scope) if scope != 'global' else ui.js(code)
def values():
    d = js('''var o = {}; var D = %s; var tables = {src: 'sn_sec_cmn_src_ci', rel: 'sn_vul_app_release', img: 'sn_vul_container_image'}; var fields = {src: 'u_primary_ait', rel: 'u_primary_ait', img: 'u_bofa_primary_ait'};
for (var k in D) { var kind = k.split('_')[0]; var g = new GlideRecord(tables[kind]); g.get(D[k]); o[k] = '' + (g.getValue(fields[kind]) || ''); }
gs.print('X::' + JSON.stringify(o));''' % json.dumps(D))
    return dict((k, NUM.get(v, v)) for k, v in d.items())
def expected(overrides=None):
    exp = {}
    for k in D:
        ci = k.split('_')[1]
        exp[k] = NUM.get(F['expected'][ci], '')
    for ci, ait in (overrides or {}).items():
        for k in D:
            if k.split('_')[1] == ci:
                exp[k] = ait
    return exp
def compare(label, overrides=None):
    exp = expected(overrides); act = values(); diff = dict((k, (exp[k], act[k])) for k in exp if exp[k] != act[k])
    check(label, not diff, '' if not diff else 'expected/actual ' + json.dumps(diff))
def wait_events(timeout=150):
    t0 = time.time()
    while time.time() - t0 < timeout:
        d = js('''var o = {pending: 0, error: 0}; var e = new GlideAggregate('sysevent'); e.addQuery('name', 'usem.ait.refresh'); e.addQuery('state', 'IN', 'ready,queued'); e.addAggregate('COUNT'); e.query(); e.next(); o.pending = parseInt(e.getAggregate('COUNT'));
var f = new GlideAggregate('sysevent'); f.addQuery('name', 'usem.ait.refresh'); f.addQuery('state', 'error'); f.addAggregate('COUNT'); f.query(); f.next(); o.error = parseInt(f.getAggregate('COUNT')); gs.print('X::' + JSON.stringify(o));''')
        if d['pending'] == 0:
            return round(time.time() - t0, 1), d['error']
        time.sleep(2)
    return None, d['error']
def settle(label, overrides=None):
    waited, errors = wait_events(); compare(label + ' (events settled in %ss, %s in error)' % (waited, errors), overrides); check(label + ': queue drained without errors', waited is not None and errors == 0)
def sysid_prefix(ci):
    return C[ci][0]
T0 = js('''gs.print('X::' + JSON.stringify({now: new GlideDateTime().getValue()}));''')['now']
# 1. state after fixtures: before rules stamped every discovered item at insert
compare('T1 discovered items hold the expected Primary AIT after insert')
q = js('''var o = {}; var t = new GlideRecord('sys_trigger'); t.addQuery('name', 'events process usem_ait'); t.query(); o.trigger = t.getRowCount();
var q = new GlideRecord('sysevent_queue'); q.get('queue', 'usem_ait'); o.queue = {order: q.getValue('processing_order'), job_config: q.getValue('job_config') + '=' + q.getValue('job_config_value'), poll: q.getValue('poll_interval'), auto: q.getValue('automatic_processing')};
var st = new GlideAggregate('sysevent'); st.addQuery('name', 'usem.ait.refresh'); st.addAggregate('COUNT'); st.groupBy('state'); st.query(); o.states = {}; while (st.next()) o.states[st.getValue('state')] = parseInt(st.getAggregate('COUNT'));
gs.print('X::' + JSON.stringify(o));''')
check('T2 queue registry provisioned its processing job, sequential, one job', q['trigger'] == 1 and q['queue']['order'] == 'sequential' and q['queue']['job_config'] == 'job_count=1', json.dumps(q['queue']))
settle('T2 fixture events processed')
print('   event states:', json.dumps(q['states']))
# 3. discovered item re-pointed to another CI: value written in the same transaction
r = js('''var o = {}; var g = new GlideRecord('sn_sec_cmn_src_ci'); g.get(%s); g.setValue('cmdb_ci', %s); g.update(); var h = new GlideRecord('sn_sec_cmn_src_ci'); h.get(%s); o.after = '' + (h.getValue('u_primary_ait') || '');
h.setValue('cmdb_ci', %s); h.update(); var i = new GlideRecord('sn_sec_cmn_src_ci'); i.get(%s); o.back = '' + (i.getValue('u_primary_ait') || '');
var n = new GlideRecord('sn_sec_cmn_src_ci'); n.initialize(); n.setValue('name', 'USEMAIT-C1-tmp'); n.setValue('source_id', 'USEMAIT-C1-tmp'); n.setValue('cmdb_ci', %s); var id = n.insert(); var m = new GlideRecord('sn_sec_cmn_src_ci'); m.get(id); o.inserted = '' + (m.getValue('u_primary_ait') || ''); m.setWorkflow(false); o.deleted = '' + m.deleteRecord();
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(D['src_C8_1']), json.dumps(C['C1']), json.dumps(D['src_C8_1']), json.dumps(C['C8']), json.dumps(D['src_C8_1']), json.dumps(C['C1'])))
check('T3 re-pointed discovered item takes the new CI value in the same write', NUM.get(r['after']) == 'AIT57151', r['after'])
check('T3 pointed back to a CI without services, cleared in the same write', r['back'] == '', repr(r['back']))
check('T3 new discovered item stamped at insert', NUM.get(r['inserted']) == 'AIT57151', 'delete of the temporary row: ' + r['deleted'])
# 4. service association inserted and deleted (C8 joins S3)
js('''var g = new GlideRecord('svc_ci_assoc'); g.initialize(); g.setValue('ci_id', %s); g.setValue('service_id', %s); g.insert(); gs.print('X::{}');''' % (json.dumps(C['C8']), json.dumps(S['S3'])))
settle('T4 association insert: C8 takes the AIT of S3 on every table', {'C8': 'AIT57153'})
js('''var g = new GlideRecord('svc_ci_assoc'); g.addQuery('ci_id', %s); g.addQuery('service_id', %s); g.query(); while (g.next()) g.deleteRecord(); gs.print('X::{}');''' % (json.dumps(C['C8']), json.dumps(S['S3'])))
settle('T4 association delete: C8 cleared')
# 5. relationship application to service inserted and deleted (App1 supports S4)
js('''var rt = new GlideRecord('cmdb_rel_type'); rt.get('name', 'Depends on::Used by'); var r = new GlideRecord('cmdb_rel_ci'); r.initialize(); r.setValue('parent', %s); r.setValue('child', %s); r.setValue('type', rt.getUniqueValue()); r.insert(); gs.print('X::{}');''' % (json.dumps(P['App1']), json.dumps(S['S4'])))
settle('T5 relationship App1 to S4 insert: C4 takes AIT57151 (S4 had only an application without AIT)', {'C4': 'AIT57151'})
js('''var r = new GlideRecord('cmdb_rel_ci'); r.addQuery('parent', %s); r.addQuery('child', %s); r.query(); while (r.next()) r.deleteRecord(); gs.print('X::{}');''' % (json.dumps(P['App1']), json.dumps(S['S4'])))
settle('T5 relationship delete: C4 cleared')
# 6. application moves to another AIT (App3: AIT57153 tier 3 -> AIT57151 tier 1)
js('''var a = new GlideRecord('cmdb_ci_business_app'); a.get(%s); a.setValue('u_primary_ait', %s); a.update(); gs.print('X::{}');''' % (json.dumps(P['App3']), json.dumps(A['AIT57151'])))
settle('T6 application AIT change: S2 and S3 now resolve to AIT57151 (C2, C3, C5, C7), C10 unchanged', {'C2': 'AIT57151', 'C3': 'AIT57151', 'C5': 'AIT57151', 'C7': 'AIT57151'})
js('''var a = new GlideRecord('cmdb_ci_business_app'); a.get(%s); a.setValue('u_primary_ait', %s); a.update(); gs.print('X::{}');''' % (json.dumps(P['App3']), json.dumps(A['AIT57153'])))
settle('T6 application AIT reverted: values back')
# 7. AIT tier change (AIT57154 tier 2 -> 1: S6 tie broken by tier, C10 -> AIT57154; C9 unchanged)
js('''var a = new GlideRecord('x_196061_bofasim_ait'); a.get(%s); a.setValue('rto_tier', 1); a.update(); gs.print('X::{}');''' % json.dumps(A['AIT57154']))
settle('T7 AIT tier change: C10 moves to AIT57154', {'C10': 'AIT57154'})
js('''var a = new GlideRecord('x_196061_bofasim_ait'); a.get(%s); a.setValue('rto_tier', 2); a.update(); gs.print('X::{}');''' % json.dumps(A['AIT57154']))
settle('T7 AIT tier reverted: C10 back to AIT57152 (tie by number)')
# 8. relationship service to CI (the fallback: C8 related to S1, no association of its own)
js('''var rt = new GlideRecord('cmdb_rel_type'); rt.get('name', 'Depends on::Used by'); var r = new GlideRecord('cmdb_rel_ci'); r.initialize(); r.setValue('parent', %s); r.setValue('child', %s); r.setValue('type', rt.getUniqueValue()); r.insert(); gs.print('X::{}');''' % (json.dumps(S['S1']), json.dumps(C['C8'])))
settle('T8 relationship S1 to C8 insert: C8 takes AIT57151 through the related service', {'C8': 'AIT57151'})
js('''var r = new GlideRecord('cmdb_rel_ci'); r.addQuery('parent', %s); r.addQuery('child', %s); r.query(); while (r.next()) r.deleteRecord(); gs.print('X::{}');''' % (json.dumps(S['S1']), json.dumps(C['C8'])))
settle('T8 relationship delete: C8 cleared')
# 9. Related Services link inserted and deleted (C8 -> S2)
m = js('''var o = {}; var m = new GlideRecord('sn_vul_m2m_ci_services'); m.initialize(); m.setValue('item', %s); m.setValue('service', %s); o.id = '' + m.insert(); gs.print('X::' + JSON.stringify(o));''' % (json.dumps(C['C8']), json.dumps(S['S2'])))
settle('T9 Related Services insert: C8 takes AIT57152', {'C8': 'AIT57152'})
gone = rest_delete(ui, 'sn_vul_m2m_ci_services', 'item=' + C['C8'] + '^service=' + S['S2'])
check('T9 Related Services row deleted through the table API', gone['deleted'] == 1 and gone['left'] == 0, json.dumps(gone))
settle('T9 Related Services delete: C8 cleared')
# 10. idempotence: a refresh over every fixture CI finds nothing stale and changes nothing
idem = js('''var o = {}; var C = %s; var E = %s; var ids = []; for (var k in C) ids.push(C[k]);
function stale() { var n = 0; for (var k in C) { var g = new GlideRecord('sn_sec_cmn_src_ci'); g.addQuery('cmdb_ci', C[k]); if (E[k]) g.addEncodedQuery('u_primary_ait!=' + E[k] + '^ORu_primary_aitISEMPTY'); else g.addNotNullQuery('u_primary_ait'); g.query(); n += g.getRowCount(); } return n; }
o.stale_before = stale(); var t0 = new Date().getTime(); new AitResolver().refreshCis(ids); o.ms = new Date().getTime() - t0; o.stale_after = stale();
var mods = {}; for (var k in C) { var g = new GlideRecord('sn_sec_cmn_src_ci'); g.addQuery('cmdb_ci', C[k]); g.query(); while (g.next()) mods[g.getUniqueValue()] = g.getValue('sys_mod_count') + '|' + g.getValue('sys_updated_on'); }
var t1 = new Date().getTime(); new AitResolver().refreshCis(ids); o.ms_second = new Date().getTime() - t1; var changed = 0; for (var id in mods) { var h = new GlideRecord('sn_sec_cmn_src_ci'); h.get(id); if (mods[id] != h.getValue('sys_mod_count') + '|' + h.getValue('sys_updated_on')) changed++; } o.rows_touched_second_run = changed;
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(C), json.dumps(F['expected'])))
check('T10 nothing stale before and after a full refresh of the fixture CIs', idem['stale_before'] == 0 and idem['stale_after'] == 0, json.dumps(idem))
compare('T10 values unchanged by two refresh runs')
# 11. reconcile repairs drift written past the rules; orphans are cleared
drift = js('''var o = {}; function force(id, field, value) { var g = new GlideRecord('sn_sec_cmn_src_ci'); g.get(id); g.setWorkflow(false); g.autoSysFields(false); g.setValue(field, value); g.update(); }
force(%s, 'u_primary_ait', %s); force(%s, 'u_primary_ait', 'NULL'); force(%s, 'cmdb_ci', 'NULL'); force(%s, 'u_primary_ait', %s);
var r = new AitResolver(); var t0 = new Date().getTime(); r.reconcile('sn_sec_cmn_src_ci', %s); r.reconcile('sn_sec_cmn_src_ci', %s); o.reconcile_ms = new Date().getTime() - t0; r.clearOrphans('sn_sec_cmn_src_ci');
var g = new GlideRecord('sn_sec_cmn_src_ci'); g.get(%s); o.orphan_after = '' + (g.getValue('u_primary_ait') || ''); force(%s, 'cmdb_ci', %s);
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(D['src_C1_1']), json.dumps(A['AIT57153']), json.dumps(D['src_C2_2']), json.dumps(D['src_C8_2']), json.dumps(D['src_C8_2']), json.dumps(A['AIT57151']),
                                            json.dumps(sysid_prefix('C1')), json.dumps(sysid_prefix('C2')), json.dumps(D['src_C8_2']), json.dumps(D['src_C8_2']), json.dumps(C['C8'])))
check('T11 orphan (no CI) cleared by clearOrphans', drift['orphan_after'] == '', json.dumps(drift))
compare('T11 reconcile of the two partitions repaired the wrong and the missing value')
# 12. the resolution is deterministic and its cost per CI (a fresh instance per call, as the before rule does)
cost = js('''var o = {}; var C = %s; var E = %s; var ids = []; for (var k in C) ids.push(C[k]);
function run() { var out = {}; var t0 = new Date().getTime(); for (var i = 0; i < 30; i++) for (var j = 0; j < ids.length; j++) out[ids[j]] = new AitResolver().ciAit(ids[j]); return {values: out, ms: new Date().getTime() - t0}; }
var first = run(); var second = run(); o.same = JSON.stringify(first.values) == JSON.stringify(second.values); o.expected = true; for (var k in C) if (first.values[C[k]] != E[k]) o.expected = false;
o.ms_per_ci = Math.round((first.ms + second.ms) / 600 * 100) / 100;
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(C), json.dumps(F['expected'])))
check('T12 600 fresh resolutions deterministic and equal to the expected graph values', cost['same'] and cost['expected'], 'ms per CI resolution: %s' % cost['ms_per_ci'])
# 13. an association written past the rules (no event) is picked up by the catch-up job in the job context
js('''var g = new GlideRecord('svc_ci_assoc'); g.initialize(); g.setWorkflow(false); g.setValue('ci_id', %s); g.setValue('service_id', %s); g.insert(); gs.print('X::{}');''' % (json.dumps(C['C8']), json.dumps(S['S3'])))
compare('T13 association written with rules off: nothing changed yet (no event)')
js('''var j = new GlideRecord('sysauto_script'); j.get(%s); SncTriggerSynchronizer.executeNow(j); gs.print('X::{}');''' % json.dumps(ST['made']['catchup_job']))
t0 = time.time(); got = None
while time.time() - t0 < 120:
    v = values()
    if v['src_C8_1'] == 'AIT57153' and v['rel_C8'] == 'AIT57153':
        got = round(time.time() - t0, 1); break
    time.sleep(3)
compare('T13 catch-up job (executed as a scheduled job) stamped C8 after %s s' % got, {'C8': 'AIT57153'})
js('''var g = new GlideRecord('svc_ci_assoc'); g.addQuery('ci_id', %s); g.addQuery('service_id', %s); g.query(); while (g.next()) { g.setWorkflow(false); g.deleteRecord(); } new AitResolver().reconcile('sn_sec_cmn_src_ci', %s); new AitResolver().reconcile('sn_vul_app_release', %s); gs.print('X::{}');''' % (json.dumps(C['C8']), json.dumps(S['S3']), json.dumps(sysid_prefix('C8')), json.dumps(sysid_prefix('C8'))))
compare('T13 association deleted with rules off, reconcile cleared C8')
# 14. no resolver errors were logged during the run
log = js('''var o = {}; var l = new GlideRecord('syslog'); l.addQuery('sys_created_on', '>=', %s); l.addQuery('message', 'STARTSWITH', 'AitResolver:'); l.query(); o.count = l.getRowCount(); o.first = ''; if (l.next()) o.first = l.getValue('message'); gs.print('X::' + JSON.stringify(o));''' % json.dumps(T0))
check('T14 no AitResolver errors in the system log during the run', log['count'] == 0, log['first'])
compare('T15 final state equals the expected state')
failed = [l for l, ok in RESULTS if not ok]
print('\n%d checks, %d failed' % (len(RESULTS), len(failed)))
for l in failed: print('  FAILED:', l)
sys.exit(1 if failed else 0)
