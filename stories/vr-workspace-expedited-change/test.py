"""Tests the Expedited change from the VR workspace on the PDI for every remediation task type (application tasks share
the dialog and code of IT tasks; containers; Configuration Compliance), twice. Per type and run: the Create Change dialog
offers Standard, Normal, Emergency and Expedited; Expedited submitted from the dialog creates a change of type expedited
on the Expedited model, linked to the task; Normal submitted still creates a Normal change; Standard still shows the
template picker and switching on to Expedited hides it; the classic form's path gives the same Expedited change; with no
Expedited model the action fails with one error line and creates or links nothing. The three types run side by side in
the browser. Changes created are removed and the tasks restored after each run. Needs `fixtures.py apply`.
Usage: python3 test.py"""
import os, sys, json, subprocess
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST

SHOTS = os.path.join(HERE, 'shots'); os.makedirs(SHOTS, exist_ok=True)
MARK = 'PDI stand-in for the client Expedited change model'
TYPES = {  # table, staging table, its task field, link table, its task field, script include, tasks for run 1 (run 2 rotates them)
    'avul': dict(table='sn_vul_app_vulnerability', staging='sn_vul_action_create_cr', parent='vg_sys_id', link='sn_vul_app_m2m_vg_change_request',
                 link_task='sn_vul_app_vulnerability', include='sn_vul.ChangeMgmt',
                 tasks=['0059e2cbf9442110f877708ae9db024a', 'c949aa8bf9442110f877708ae9db0267', 'ff39e68bf9442110f877708ae9db0207', '30496a8bf9442110f877708ae9db02dc']),
    'cvul': dict(table='sn_vul_container_vulnerability', staging='sn_vul_container_action_create_cr', parent='cvg_sys_id',
                 link='sn_vul_container_m2m_remediation_task_change_request', link_task='sn_vul_container_vulnerability', include='sn_vul_container.ChangeMgmt',
                 tasks=['02496e8bf9442110f877708ae9db023e', '03baa68ff9442110f877708ae9db0202', '03baa68ff9442110f877708ae9db0210', '07ba668ff9442110f877708ae9db02de']),
    'crg': dict(table='sn_vulc_result_group', staging='sn_vulc_action_create_cr', parent='result_group', link='sn_vulc_m2m_trg_change_request',
                link_task='result_group', include='sn_vulc.ChangeMgmt',
                tasks=['4a7bfbb993fe4f50e3aef0aefaba107e', '5748dbb093b6c350e3aef0aefaba10ad', '150fa828938a0b10e3aef0aefaba1075', '1ff727ca93070310e3aef0aefaba103b']),
}
ROLES = ['expedited', 'normal', 'classic', 'nomodel']
ALL_OPTIONS = ['Standard', 'Normal', 'Emergency', 'Expedited']
for attempt in range(5):  # the proxy resets a handshake now and then while the browser runs
    try:
        ui = SNUI(); break
    except Exception:
        if attempt == 4: raise
ui.s.mount('https://', HTTPAdapter(max_retries=Retry(total=5, connect=5, read=2, backoff_factor=2, allowed_methods=None)))
ui.app('global')
NODE_ENV = dict(os.environ, NODE_PATH=subprocess.run(['npm', 'root', '-g'], capture_output=True, text=True).stdout.strip())


def browser(table, task, labels, submit, shot):
    r = subprocess.run(['node', os.path.join(HERE, 'test_browser.js'), table, task, labels, submit, os.path.join(SHOTS, shot)],
                       capture_output=True, text=True, env=NODE_ENV, timeout=900)
    line = [l for l in r.stdout.splitlines() if l.startswith('R::')]
    return json.loads(line[-1][3:]) if line else {'error': (r.stderr or r.stdout)[-300:]}


def api(method, path, **kw):
    """Table API as the classic form uses it (a global script may not write sn_vul* rows: cross-scope policy)."""
    return ui.s.request(method, INST + '/api/now/table/' + path, headers={'X-UserToken': ui.ck(), 'Accept': 'application/json'}, **kw)


def snapshot(t, tasks):
    return ui.js('''var o = {}; var g = new GlideRecord(%s); g.addQuery('sys_id', 'IN', %s); g.query();
while (g.next()) o[g.getUniqueValue()] = {state: g.getValue('state'), assigned_to: g.getValue('assigned_to') || '', number: g.getValue('number')};
gs.print('OUT::' + JSON.stringify(o));''' % (json.dumps(t['table']), json.dumps(','.join(tasks))), marker='OUT')


def results(t, tasks, start):
    return ui.js('''var o = {}; var t = %(t)s, tasks = %(tasks)s;
for (var i = 0; i < tasks.length; i++) {
    var r = {staging: [], changes: []};
    var a = new GlideRecord(t.staging); a.addQuery(t.parent, tasks[i]); a.addQuery('sys_created_on', '>=', %(start)s); a.query();
    while (a.next()) r.staging.push({type: a.getValue('change_request_type'), status: a.getValue('status')});
    var c = new GlideRecord('change_request'); c.addQuery('parent', tasks[i]); c.addQuery('sys_created_on', '>=', %(start)s); c.query();
    while (c.next()) { var l = new GlideRecord(t.link); l.addQuery(t.link_task, tasks[i]); l.addQuery('change_request', c.getUniqueValue()); l.query();
        r.changes.push({number: c.getValue('number'), type: c.getValue('type'), model: c.chg_model.getDisplayValue(), linked: l.hasNext()}); }
    var el = new GlideAggregate(t.link); el.addQuery(t.link_task, tasks[i]); el.addQuery('sys_created_on', '>=', %(start)s); el.addAggregate('COUNT'); el.query(); el.next();
    r.links = parseInt(el.getAggregate('COUNT')); var tk = new GlideRecord(t.table); tk.get(tasks[i]); r.state = tk.getValue('state');
    o[tasks[i]] = r;
}
gs.print('OUT::' + JSON.stringify(o));''' % dict(t=json.dumps(t), tasks=json.dumps(tasks), start=json.dumps(start)), marker='OUT')


def classic(t, task):
    """The classic form's path: the staging record saved as the form saves it, then the Create Change action's server call."""
    rec = api('POST', t['staging'], json={t['parent']: task, 'change_request_type': 'expedited', 'short_description': 'Expedited change test'}).json()['result']
    return ui.js('''var current = new GlideRecord(%s); current.get(%s);
gs.sleep(1100); var since = new GlideDateTime().getValue();
current.status = 'in_progress';
var sysIds = new %s().actionCreateChange(current);
var id = !sysIds ? '' : (sysIds.changeSysId || (typeof sysIds.getUniqueValue == 'function' ? sysIds.getUniqueValue() : ''));
var c = new GlideRecord('change_request'); var found = id ? c.get(id) : false;
var log = new GlideRecord('syslog'); log.addQuery('sys_created_on', '>=', since); log.addQuery('level', 2); log.addQuery('message', 'CONTAINS', current.getUniqueValue()); log.query();
var errors = []; while (log.next()) errors.push(log.getValue('message'));
gs.print('OUT::' + JSON.stringify({status: current.getValue('status'), change: found ? c.getValue('number') : '', type: found ? c.getValue('type') : '',
    model: found ? c.chg_model.getDisplayValue() : '', errors: errors}));''' % (json.dumps(t['staging']), json.dumps(rec['sys_id']), t['include']), marker='OUT')


def model(on):
    """Switches the stand-in Expedited model off (renamed, no preset) and back on."""
    return ui.js('''var m = new GlideRecord('chg_model'); m.addQuery('description', %s); m.query(); m.next();
m.setValue('name', %s ? 'Expedited' : 'Stand-in switched off'); m.setValue('record_preset', %s ? 'type=expedited^EQ' : ''); m.update();
gs.print('OUT::' + JSON.stringify({name: m.getValue('name')}));''' % (json.dumps(MARK), 'true' if on else 'false', 'true' if on else 'false'), marker='OUT')


def cleanup(t, snap, start):
    """Deleting a change runs rules that assign a global 'o', so the result object has its own name."""
    tasks = list(snap)
    r = ui.js('''var __cl = {changes: 0, links: 0, ids: []}; var t = %(t)s, snap = %(snap)s, tasks = %(tasks)s;
var c = new GlideRecord('change_request'); c.addQuery('parent', 'IN', tasks.join(',')); c.addQuery('sys_created_on', '>=', %(start)s); c.query();
while (c.next()) { var id = c.getUniqueValue();
    var l = new GlideRecord(t.link); l.addQuery('change_request', id); l.query(); while (l.next()) { l.deleteRecord(); __cl.links++; }
    var tc = new GlideRecord('task_ci'); tc.addQuery('task', id); tc.query(); while (tc.next()) tc.deleteRecord();
    c.deleteRecord(); __cl.changes++; }
var el = new GlideRecord(t.link); el.addQuery(t.link_task, 'IN', tasks.join(',')); el.addQuery('change_request', ''); el.query(); while (el.next()) { el.deleteRecord(); __cl.links++; }
for (var i = 0; i < tasks.length; i++) { var g = new GlideRecord(t.table); g.get(tasks[i]); g.setWorkflow(false);
    g.setValue('state', snap[tasks[i]].state); g.setValue('assigned_to', snap[tasks[i]].assigned_to); g.update(); }
var a = new GlideRecord(t.staging); a.addQuery(t.parent, 'IN', tasks.join(',')); a.addQuery('sys_created_on', '>=', %(start)s); a.query(); while (a.next()) __cl.ids.push(a.getUniqueValue());
gs.print('OUT::' + JSON.stringify(__cl));''' % dict(t=json.dumps(t), snap=json.dumps(snap), tasks=json.dumps(tasks), start=json.dumps(start)), marker='OUT')
    r['staging'] = sum(api('DELETE', t['staging'] + '/' + x).status_code == 204 for x in r.pop('ids'))
    return r


checks = []
def check(label, ok, detail=''):
    checks.append(bool(ok)); print('%s %s%s' % ('ok  ' if ok else 'FAIL', label, (' | ' + detail) if detail else ''))

for n in (1, 2):
    runs = {k: dict(zip(ROLES, t['tasks'][n - 1:] + t['tasks'][:n - 1])) for k, t in TYPES.items()}
    snaps = {k: snapshot(TYPES[k], list(run.values())) for k, run in runs.items()}
    start = ui.js('''gs.sleep(1100); gs.print('OUT::' + JSON.stringify({s: new GlideDateTime().getValue()}));''', marker='OUT')['s']
    try:
        jobs = [(k, role, labels, submit) for k in TYPES for role, labels, submit in (('expedited', 'Expedited', 'yes'), ('normal', 'Normal', 'yes'), ('normal', 'Standard,Expedited', 'no'))]
        with ThreadPoolExecutor(max_workers=3) as pool:
            got = list(pool.map(lambda j: browser(TYPES[j[0]]['table'], runs[j[0]][j[1]], j[2], j[3], 'run%d_%s_%s' % (n, j[0], j[2].replace(',', '-'))), jobs))
        web = {(j[0], j[2]): g for j, g in zip(jobs, got)}
        cl = {k: classic(TYPES[k], runs[k]['classic']) for k in TYPES}
        model(False)
        try:
            nm = {k: classic(TYPES[k], runs[k]['nomodel']) for k in TYPES}
        finally:
            model(True)
        for k, t in TYPES.items():
            run, snap = runs[k], snaps[k]; num = {role: snap[run[role]]['number'] for role in ROLES}
            res = results(t, list(run.values()), start)
            e, m, s = web[(k, 'Expedited')], web[(k, 'Normal')], web[(k, 'Standard,Expedited')]
            ex, no, c, x = res[run['expedited']], res[run['normal']], cl[k], nm[k]
            ec = e.get('checks', {}).get('Expedited', {})
            check('run%d %s dialog offers %s; Expedited selected, template picker hidden, implementation plan shown, create enabled' % (n, k, ', '.join(ALL_OPTIONS)),
                  e.get('options') == ALL_OPTIONS and ec == {'selected': 'Expedited', 'templateShown': False, 'implementationShown': True, 'createEnabled': True},
                  json.dumps({'options': e.get('options'), 'Expedited': ec, 'error': e.get('error')}))
            sc, se = s.get('checks', {}).get('Standard', {}), s.get('checks', {}).get('Expedited', {})
            check('run%d %s Standard shows the template picker; switching to Expedited hides it and shows the implementation plan' % (n, k),
                  sc.get('selected') == 'Standard' and sc.get('templateShown') is True and se.get('selected') == 'Expedited'
                  and se.get('templateShown') is False and se.get('implementationShown') is True, json.dumps({'checks': s.get('checks'), 'error': s.get('error')}))
            check('run%d %s %s: dialog Expedited -> staging "expedited" finished, one change of type expedited on the Expedited model, linked' % (n, k, num['expedited']),
                  e.get('submitted') and ex['staging'] == [{'type': 'expedited', 'status': 'finished'}] and len(ex['changes']) == 1
                  and ex['changes'][0]['type'] == 'expedited' and ex['changes'][0]['model'] == 'Expedited' and ex['changes'][0]['linked'], json.dumps(ex))
            check('run%d %s %s: dialog Normal -> one Normal change on the Normal model, linked' % (n, k, num['normal']),
                  m.get('submitted') and len(no['changes']) == 1 and no['changes'][0]['type'] == 'normal' and no['changes'][0]['model'] == 'Normal' and no['changes'][0]['linked'], json.dumps(no))
            check('run%d %s %s: classic form path -> the same Expedited change' % (n, k, num['classic']),
                  c['type'] == 'expedited' and c['model'] == 'Expedited' and c['status'] != 'error' and not c['errors'] and len(res[run['classic']]['changes']) == 1
                  and res[run['classic']]['changes'][0]['linked'], json.dumps(c))
            check('run%d %s %s: no Expedited model -> nothing created or linked, task untouched, status error, one error line' % (n, k, num['nomodel']),
                  not x['change'] and x['status'] == 'error' and not res[run['nomodel']]['changes'] and not res[run['nomodel']]['links']
                  and res[run['nomodel']]['state'] == snap[run['nomodel']]['state'] and len(x['errors']) == 1
                  and x['errors'][0].startswith('ChangeMgmt: change creation failed for %s ' % t['staging']) and x['errors'][0].endswith(' - no active change model presets type expedited'), json.dumps(x))
    finally:
        for k in TYPES:
            print('   cleanup %s:' % k, json.dumps(cleanup(TYPES[k], snaps[k], start)))

print('\n%s: %d of %d as expected' % ('ALL AS EXPECTED' if all(checks) else 'FAILURES', sum(checks), len(checks)))
json.dump({'checks': len(checks), 'passed': sum(checks)}, open(os.path.join(HERE, 'test_results.json'), 'w'), indent=1)
sys.exit(0 if all(checks) else 1)
