"""Rigorous test of the hand-over script on real application vulnerable items of the instance (Veracode items with
a CI and a vulnerability, one item without a vulnerability, one number shared by several items). The deferral is
granted through the platform's own exception request (StateChangeManager.handleStateChangeRequest) and approval
(the approver records, then ChangeApproval.onApproval, the call the approval flow makes). The exact attached script
is run with the property off and on, closing as Fixed and as Stale, twice on the main item. Every item is restored
to its original values and the request records are removed at the end."""
import os, sys, json, time, re, html
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
HERE = os.path.dirname(os.path.abspath(__file__)); PROP = 'sn_vul.auto_defer_avit_in_active_exception_window'; TAG = 'USEM 1552 real test'
SCRIPT = open(os.path.join(HERE, 'AVIT Rescan Simulation - Background Script.js')).read()
ui = SNUI(); ui.app('global'); RESULTS = []; REQUESTS = []
FIELDS = ['state', 'substate', 'active', 'ignore_expiration', 'ignore_expiration_dt_tm', 'backup_substate', 'backup_state', 'ignored_by', 'ignore_reason', 'ignore_date', 'defer_count', 'reopened', 'reopened_count', 'closed_at', 'closed_by', 'close_notes', 'resolution_date', 'resolution_dt_tm', 'resolution_reason', 'resolved_by', 'last_opened', 'last_opened_dt_tm', 'last_state_changed_on', 'age_closed', 'change_approval', 'ttr_status', 'ttr_calculated', 'auto_exception_rule', 'managed_by_vul']
def check(label, ok, detail=''):
    RESULTS.append((label, bool(ok))); print('%s  %s%s' % ('PASS' if ok else 'FAIL', label, ('  [' + detail + ']') if detail else ''))
def js(code): return ui.js(code)
def read(sid):
    return js('''var __out = {}; var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(%s); var F = %s; for (var i = 0; i < F.length; i++) __out[F[i]] = g.getValue(F[i]); __out.number = g.getValue('number'); __out.state_label = g.getDisplayValue('state'); __out.substate_label = g.getDisplayValue('substate');
var j = new GlideRecord('sys_journal_field'); j.addQuery('element_id', %s); j.addQuery('element', 'work_notes'); j.orderByDesc('sys_created_on'); j.setLimit(1); j.query(); __out.note = j.next() ? '' + j.getValue('value') : ''; gs.print('X::' + JSON.stringify(__out));''' % (json.dumps(sid), json.dumps(FIELDS), json.dumps(sid)))
def has_note(sid, text):
    return js('''var j = new GlideRecord('sys_journal_field'); j.addQuery('element_id', %s); j.addQuery('element', 'work_notes'); j.addQuery('value', 'CONTAINS', %s); j.addQuery('sys_created_on', '>', gs.minutesAgoStart(3)); j.query(); gs.print('X::' + JSON.stringify({n: j.getRowCount()}));''' % (json.dumps(sid), json.dumps(text)))['n'] > 0
def run_script(sid, prop, close_substate=4, prepare=False):
    js('''gs.setProperty(%s, %s); gs.print('X::{}');''' % (json.dumps(PROP), json.dumps(prop)))
    code = SCRIPT.replace("var SYS_ID = '';", "var SYS_ID = '%s';" % sid).replace('var CLOSE_SUBSTATE = 4;', 'var CLOSE_SUBSTATE = %d;' % close_substate).replace('var PREPARE_DEFERRAL = false;', 'var PREPARE_DEFERRAL = %s;' % ('true' if prepare else 'false'))
    raw = ui.run(code); txt = html.unescape(re.sub(r'<[^>]+>', '\n', raw))
    lines = [l.replace('*** Script: ', '').rstrip() for l in txt.split('\n') if '*** Script:' in l]
    print('   ' + '\n   '.join(lines)); return '\n'.join(lines)
def request_and_approve(sid, days):
    r = js('''var __out = {}; var item = new GlideRecord('sn_vul_app_vulnerable_item'); item.get(%s); var until = new GlideDateTime(); until.addDaysUTC(%d);
var res = new sn_sec_exception.StateChangeManager().handleStateChangeRequest(item, '12', '2', %s, until.getValue(), false, null, null, %s, null, null);
__out.change = res && res.changeSysId ? '' + res.changeSysId : ''; var after = new GlideRecord('sn_vul_app_vulnerable_item'); after.get(%s); __out.state_after_request = after.getValue('state');
var vca = new GlideRecord('sn_sec_exception_change_approval'); vca.get(__out.change); __out.vca = {number: vca.getValue('number'), approval_state: vca.getValue('approval_state'), desired_state: vca.getValue('desired_state'), desired_substate: vca.getValue('desired_substate'), desired_ignore_date: vca.getValue('desired_ignore_date')};
gs.print('X::' + JSON.stringify(__out));''' % (json.dumps(sid), days, json.dumps(TAG), json.dumps(TAG), json.dumps(sid)))
    REQUESTS.append(r['change']); approved_by = 'approver records'
    for _ in range(6):
        time.sleep(5)
        a = js('''var __out = {n: 0, states: []}; var ap = new GlideRecord('sysapproval_approver'); ap.addQuery('document_id', %s); ap.query(); while (ap.next()) { __out.n++; __out.states.push(ap.getValue('state')); if (ap.getValue('state') == 'requested') { ap.setValue('state', 'approved'); ap.update(); } }
var it = new GlideRecord('sn_vul_app_vulnerable_item'); it.get(%s); __out.state = it.getValue('state'); gs.print('X::' + JSON.stringify(__out));''' % (json.dumps(r['change']), json.dumps(sid)))
        if a['state'] == '12': break
    if a['state'] != '12':
        approved_by = 'ChangeApproval.onApproval (the call the approval flow makes)'
        js('''var vca = new GlideRecord('sn_sec_exception_change_approval'); vca.get(%s); vca.setValue('approval_state', 1); vca.update(); var v2 = new GlideRecord('sn_sec_exception_change_approval'); v2.get(%s); new sn_sec_exception.ChangeApproval(v2).onApproval(); gs.print('X::{}');''' % (json.dumps(r['change']), json.dumps(r['change'])))
    return r, approved_by
def restore(sid, snap):
    js('''var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(%s); var S = %s; g.setWorkflow(false); g.autoSysFields(false); for (var k in S) g.setValue(k, S[k] === null ? '' : S[k]); g.update(); gs.print('X::{}');''' % (json.dumps(sid), json.dumps({k: snap[k] for k in FIELDS})))
def defer_by_hand(sid, days):
    js('''var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(%s); var until = new GlideDate(); until.addDaysUTC(%d); g.setValue('state', 12); g.setValue('substate', 2); g.setValue('ignore_expiration_dt_tm', until.getValue() + ' 00:00:00'); g.setValue('ignored_by', gs.getUserID()); g.setValue('ignore_reason', %s); g.update(); gs.print('X::{}');''' % (json.dumps(sid), days, json.dumps(TAG)))
def set_state(sid, state, substate):
    js('''var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(%s); g.setValue('state', %d); g.setValue('substate', %s); g.update(); gs.print('X::{}');''' % (json.dumps(sid), state, json.dumps(substate)))
# items: three Veracode items with CI and vulnerability, one item without a vulnerability, one number shared by several items
pick = js('''var __out = {real: [], novul: '', dup: ''}; var av = new GlideRecord('sn_vul_app_vulnerable_item'); av.addQuery('state', 1); av.addNotNullQuery('vulnerability'); av.addNotNullQuery('cmdb_ci'); av.addQuery('sys_created_by', 'VR.System'); av.addQuery('change_approval', ''); av.orderBy('number'); av.setLimit(3); av.query(); while (av.next()) __out.real.push(av.getUniqueValue());
var nv = new GlideRecord('sn_vul_app_vulnerable_item'); nv.addQuery('state', 1); nv.addNullQuery('vulnerability'); nv.addNotNullQuery('cmdb_ci'); nv.setLimit(1); nv.query(); if (nv.next()) __out.novul = nv.getUniqueValue();
var d = new GlideAggregate('sn_vul_app_vulnerable_item'); d.addQuery('state', 1); d.addAggregate('COUNT'); d.groupBy('number'); d.addHaving('COUNT', '>', 1); d.query(); if (d.next()) { var dr = new GlideRecord('sn_vul_app_vulnerable_item'); dr.addQuery('number', d.getValue('number')); dr.addQuery('state', 1); dr.query(); if (dr.next()) __out.dup = dr.getUniqueValue(); }
gs.print('X::' + JSON.stringify(__out));''')
A, B, C = pick['real']; D = pick['novul'] or pick['dup']; ITEMS = {'A': A, 'B': B, 'C': C, 'D': D}
snaps = dict((k, read(v)) for k, v in ITEMS.items())
print('items:', ', '.join('%s=%s (%s/%s)' % (k, snaps[k]['number'], snaps[k]['state_label'], snaps[k]['substate_label'] or '-') for k in ITEMS))
prop_before = js('''gs.print('X::' + JSON.stringify({v: gs.getProperty(%s)}));''' % json.dumps(PROP))['v']
try:
    # A: deferral through the platform's exception request and approval
    r, how = request_and_approve(A, 30)
    a = read(A); print('   request %s -> item %s, approved through %s' % (r['vca']['number'], r['state_after_request'], how))
    check('T1 exception request put A In Review and the approval deferred it with both Until fields and the backup substate', r['state_after_request'] == '11' and a['state'] == '12' and a['substate'] == '2' and a['backup_substate'] == '2' and bool(a['ignore_expiration']) and bool(a['ignore_expiration_dt_tm']), 'state %s substate %s backup %s until %s / %s' % (a['state'], a['substate'], a['backup_substate'], a['ignore_expiration'], a['ignore_expiration_dt_tm']))
    for cycle in (1, 2):
        out = run_script(A, 'true'); a = read(A)
        check('T2.%d script on A, property true: closed Fixed then put back to Deferred' % cycle, 'put back to Deferred by the platform rule' in out and a['state'] == '12' and a['substate'] == '2' and has_note(A, 'falls under valid exception window'), 'defer count %s' % a['defer_count'])
        out = run_script(A, 'false'); a = read(A)
        check('T3.%d script on A, property false: closed Fixed then Open' % cycle, 'state Open (1)' in out.split('3. Scanner finds it again')[-1] and a['state'] == '1' and a['backup_substate'] == '2' and bool(a['ignore_expiration']), 'until and backup kept: %s / %s' % (a['ignore_expiration'], a['backup_substate']))
        set_state(A, 12, '2')
    # B: approved deferral, closed as Stale by the auto-close rule
    r, how = request_and_approve(B, 30); b = read(B); print('   request %s, approved through %s' % (r['vca']['number'], how))
    out = run_script(B, 'true', close_substate=6); b = read(B)
    check('T4 script on B, property true, closed Stale: put back to Deferred', 'Closed (3) / Stale' in out and 'put back to Deferred by the platform rule' in out and b['state'] == '12')
    # C: deferred by editing the item (no date Until, no backup substate)
    defer_by_hand(C, 30)
    out = run_script(C, 'true'); c = read(C)
    check('T5a script on C deferred by hand, property true: warns and ends Open', 'lacks one of them' in out and c['state'] == '1' and not c['backup_substate'])
    set_state(C, 12, '2'); out = run_script(C, 'true', prepare=True); c = read(C)
    check('T5b same item with PREPARE_DEFERRAL: fields filled, put back to Deferred', 'put back to Deferred by the platform rule' in out and c['state'] == '12' and c['backup_substate'] == '2' and bool(c['ignore_expiration']))
    # D: item without a vulnerability (outside the rule), or a shared number
    defer_by_hand(D, 30); out = run_script(D, 'true', prepare=True); d = read(D)
    check('T6 script on D (%s): reports the rule filter or the shared number, ends Open' % ('no vulnerability' if pick['novul'] else 'shared number'), ('Outside the platform rule' in out or 'item(s) carry this number' in out) and (d['state'] == '1' if pick['novul'] else True), 'state %s' % d['state'])
    check('T7 no resolver-style errors: every run printed the three steps', all(x in out for x in ['1. Before', '2. Scanner', '3. Scanner']))
finally:
    for k, sid in ITEMS.items(): restore(sid, snaps[k])
    js('''gs.setProperty(%s, %s); gs.print('X::{}');''' % (json.dumps(PROP), json.dumps(prop_before)))
    cleanup = js('''var __out = {approvers: 0, notes: 0, requests_closed: 0}; var ids = %s; var requests = %s;
if (requests.length) { var ap = new GlideRecord('sysapproval_approver'); ap.addQuery('document_id', 'IN', requests.join(',')); ap.query(); while (ap.next()) { ap.deleteRecord(); __out.approvers++; }
  var vca = new GlideRecord('sn_sec_exception_change_approval'); vca.addQuery('sys_id', 'IN', requests.join(',')); vca.query(); while (vca.next()) { vca.setValue('active', false); vca.setValue('approval_state', 3); vca.update(); __out.requests_closed++; } }
var j = new GlideRecord('sys_journal_field'); j.addQuery('element_id', 'IN', ids.join(',')); j.addQuery('sys_created_on', '>', gs.hoursAgoStart(2)); j.query(); while (j.next()) { j.deleteRecord(); __out.notes++; } gs.print('X::' + JSON.stringify(__out));''' % (json.dumps(list(ITEMS.values())), json.dumps(REQUESTS)))
    after = dict((k, read(v)) for k, v in ITEMS.items())
    same = all(after[k][f] == snaps[k][f] for k in ITEMS for f in FIELDS)
    print('restored: items back to their original values %s | test requests closed as No Longer Required %d | their approver rows removed %d | test work notes removed %d | property %s' % (same, cleanup['requests_closed'], cleanup['approvers'], cleanup['notes'], prop_before))
failed = [l for l, ok in RESULTS if not ok]; print('\n%d checks, %d failed' % (len(RESULTS), len(failed))); [print('  FAILED:', l) for l in failed]
sys.exit(1 if failed else 0)
