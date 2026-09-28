"""Tests the Expedited change from the VR workspace on the PDI, twice, on application remediation tasks: the Create Change
dialog offers Standard, Normal, Emergency and Expedited; Expedited submitted from the dialog creates a change of type
expedited on the Expedited model, linked to the task; Normal still creates a Normal change; Standard still shows the
template picker; the classic form's path gives the same Expedited change; with no Expedited model the action fails with
one error line and creates nothing. Changes created are removed and the tasks restored after each run. Needs
`fixtures.py apply`. Usage: python3 test.py"""
import os, sys, json, subprocess
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST

SHOTS = os.path.join(HERE, 'shots'); os.makedirs(SHOTS, exist_ok=True)
MARK = 'PDI stand-in for the client Expedited change model'
RUNS = [  # workspace Expedited, workspace Normal (and Standard shown), classic-form path, no Expedited model
    {'expedited': '0059e2cbf9442110f877708ae9db024a', 'normal': 'c949aa8bf9442110f877708ae9db0267', 'classic': 'ff39e68bf9442110f877708ae9db0207', 'nomodel': '30496a8bf9442110f877708ae9db02dc'},
    {'expedited': 'c949aa8bf9442110f877708ae9db0267', 'normal': '0059e2cbf9442110f877708ae9db024a', 'classic': '30496a8bf9442110f877708ae9db02dc', 'nomodel': 'ff39e68bf9442110f877708ae9db0207'},
]
ALL_OPTIONS = ['Standard', 'Normal', 'Emergency', 'Expedited']
for attempt in range(5):  # the proxy resets a handshake now and then while the browser runs
    try:
        ui = SNUI(); break
    except Exception:
        if attempt == 4: raise
ui.s.mount('https://', HTTPAdapter(max_retries=Retry(total=5, connect=5, read=2, backoff_factor=2, allowed_methods=None)))
ui.app('global')
NODE_ENV = dict(os.environ, NODE_PATH=subprocess.run(['npm', 'root', '-g'], capture_output=True, text=True).stdout.strip())


def browser(task, label, submit, shot):
    r = subprocess.run(['node', os.path.join(HERE, 'test_browser.js'), task, label, submit, os.path.join(SHOTS, shot)],
                       capture_output=True, text=True, env=NODE_ENV, timeout=900)
    line = [l for l in r.stdout.splitlines() if l.startswith('R::')]
    return json.loads(line[-1][3:]) if line else {'error': (r.stderr or r.stdout)[-300:]}


def api(method, path, **kw):
    """Table API as the classic form uses it (a global script may not write sn_vul tables: cross-scope policy)."""
    return ui.s.request(method, INST + '/api/now/table/' + path, headers={'X-UserToken': ui.ck(), 'Accept': 'application/json'}, **kw)


def snapshot(tasks):
    return ui.js('''var o = {}; var t = new GlideRecord('sn_vul_app_vulnerability'); t.addQuery('sys_id', 'IN', %s); t.query();
while (t.next()) o[t.getUniqueValue()] = {state: t.getValue('state'), assigned_to: t.getValue('assigned_to') || '', number: t.getValue('number')};
gs.sleep(1100); o.__start = new GlideDateTime().getValue();
gs.print('OUT::' + JSON.stringify(o));''' % json.dumps(','.join(tasks)), marker='OUT')


def results(tasks, start):
    return ui.js('''var o = {}; var tasks = %s;
for (var i = 0; i < tasks.length; i++) {
    var a = new GlideRecord('sn_vul_action_create_cr'); a.addQuery('vg_sys_id', tasks[i]); a.addQuery('sys_created_on', '>=', %s); a.query();
    var r = {staging: [], changes: []};
    while (a.next()) r.staging.push({type: a.getValue('change_request_type'), status: a.getValue('status')});
    var c = new GlideRecord('change_request'); c.addQuery('parent', tasks[i]); c.addQuery('sys_created_on', '>=', %s); c.query();
    while (c.next()) { var l = new GlideRecord('sn_vul_app_m2m_vg_change_request'); l.addQuery('sn_vul_app_vulnerability', tasks[i]); l.addQuery('change_request', c.getUniqueValue()); l.query();
        r.changes.push({number: c.getValue('number'), type: c.getValue('type'), model: c.chg_model.getDisplayValue(), state: c.state.getDisplayValue(), linked: l.hasNext()}); }
    var el = new GlideAggregate('sn_vul_app_m2m_vg_change_request'); el.addQuery('sn_vul_app_vulnerability', tasks[i]); el.addQuery('sys_created_on', '>=', %s); el.addAggregate('COUNT'); el.query(); el.next();
    r.links = parseInt(el.getAggregate('COUNT')); var tk = new GlideRecord('sn_vul_app_vulnerability'); tk.get(tasks[i]); r.state = tk.getValue('state');
    o[tasks[i]] = r;
}
gs.print('OUT::' + JSON.stringify(o));''' % (json.dumps(tasks), json.dumps(start), json.dumps(start), json.dumps(start)), marker='OUT')


def classic(task):
    """The classic form's path: the staging record saved as the form saves it, then the Create Change action's server call."""
    t = api('GET', 'sn_vul_app_vulnerability/' + task, params={'sysparm_fields': 'short_description,description'}).json()['result']
    rec = api('POST', 'sn_vul_action_create_cr', json={'vg_sys_id': task, 'change_request_type': 'expedited', 'add_cis_to_cr': 'true',
              'short_description': t['short_description'], 'description': t['description']}).json()['result']
    return ui.js('''var current = new GlideRecord('sn_vul_action_create_cr'); current.get(%s);
gs.sleep(1100); var since = new GlideDateTime().getValue();
current.status = 'in_progress';
var sysIds = new sn_vul.ChangeMgmt().actionCreateChange(current);
var c = new GlideRecord('change_request'); var found = sysIds ? c.get(sysIds.changeSysId) : false;
var log = new GlideRecord('syslog'); log.addQuery('sys_created_on', '>=', since); log.addQuery('level', 2); log.addQuery('message', 'CONTAINS', current.getUniqueValue()); log.query();
var errors = []; while (log.next()) errors.push(log.getValue('message'));
gs.print('OUT::' + JSON.stringify({staging_type: current.getValue('change_request_type'), status: current.getValue('status'), change: found ? c.getValue('number') : '',
    type: found ? c.getValue('type') : '', model: found ? c.chg_model.getDisplayValue() : '', errors: errors}));''' % json.dumps(rec['sys_id']), marker='OUT')


def model(on):
    """Switches the stand-in Expedited model off (renamed, no preset) and back on."""
    return ui.js('''var m = new GlideRecord('chg_model'); m.addQuery('description', %s); m.query(); m.next();
m.setValue('name', %s ? 'Expedited' : 'Stand-in switched off'); m.setValue('record_preset', %s ? 'type=expedited^EQ' : ''); m.update();
gs.print('OUT::' + JSON.stringify({name: m.getValue('name')}));''' % (json.dumps(MARK), 'true' if on else 'false', 'true' if on else 'false'), marker='OUT')


def cleanup(snap, start):
    """Deleting a change runs rules that assign a global 'o', so the result object has its own name."""
    tasks = [k for k in snap if not k.startswith('__')]
    r = ui.js('''var __cl = {changes: 0, links: 0, ids: []}; var snap = %s; var tasks = %s;
var c = new GlideRecord('change_request'); c.addQuery('parent', 'IN', tasks.join(',')); c.addQuery('sys_created_on', '>=', %s); c.query();
while (c.next()) { var id = c.getUniqueValue();
    var l = new GlideRecord('sn_vul_app_m2m_vg_change_request'); l.addQuery('change_request', id); l.query(); while (l.next()) { l.deleteRecord(); __cl.links++; }
    var tc = new GlideRecord('task_ci'); tc.addQuery('task', id); tc.query(); while (tc.next()) tc.deleteRecord();
    c.deleteRecord(); __cl.changes++; }
var el = new GlideRecord('sn_vul_app_m2m_vg_change_request'); el.addQuery('sn_vul_app_vulnerability', 'IN', tasks.join(',')); el.addQuery('change_request', ''); el.query(); while (el.next()) { el.deleteRecord(); __cl.links++; }
for (var i = 0; i < tasks.length; i++) { var t = new GlideRecord('sn_vul_app_vulnerability'); t.get(tasks[i]); t.setWorkflow(false);
    t.setValue('state', snap[tasks[i]].state); t.setValue('assigned_to', snap[tasks[i]].assigned_to); t.update(); }
var a = new GlideRecord('sn_vul_action_create_cr'); a.addQuery('vg_sys_id', 'IN', tasks.join(',')); a.addQuery('sys_created_on', '>=', %s); a.query(); while (a.next()) __cl.ids.push(a.getUniqueValue());
gs.print('OUT::' + JSON.stringify(__cl));''' % (json.dumps(snap), json.dumps(tasks), json.dumps(start), json.dumps(start)), marker='OUT')
    r['staging'] = sum(api('DELETE', 'sn_vul_action_create_cr/' + x).status_code == 204 for x in r.pop('ids'))
    return r


checks = []
def check(label, ok, detail=''):
    checks.append(bool(ok)); print('%s %s%s' % ('ok  ' if ok else 'FAIL', label, (' | ' + detail) if detail else ''))

for n, run in enumerate(RUNS, 1):
    tasks = list(run.values()); snap = snapshot(tasks); start = snap['__start']
    nums = {k: snap[v]['number'] for k, v in run.items()}
    try:
        e = browser(run['expedited'], 'Expedited', 'yes', 'run%d_expedited' % n)
        check('run%d dialog offers %s' % (n, ', '.join(ALL_OPTIONS)), e.get('options') == ALL_OPTIONS, json.dumps(e.get('options')))
        check('run%d Expedited selected: template picker hidden, implementation plan shown, create enabled' % n,
              e.get('selected') == 'Expedited' and e.get('templateShown') is False and e.get('implementationShown') is True and e.get('createEnabled') is True,
              json.dumps({k: e.get(k) for k in ('selected', 'templateShown', 'implementationShown', 'createEnabled', 'error')}))
        m = browser(run['normal'], 'Normal', 'yes', 'run%d_normal' % n)
        s = browser(run['normal'], 'Standard', 'no', 'run%d_standard' % n)
        check('run%d Standard still shows the template picker and hides the implementation plan' % n,
              s.get('templateShown') is True and s.get('implementationShown') is False, json.dumps({k: s.get(k) for k in ('templateShown', 'implementationShown', 'error')}))
        c = classic(run['classic'])
        model(False)
        try:
            x = classic(run['nomodel'])
        finally:
            model(True)
        r = results(tasks, start)
        ex, no, cl, nm = r[run['expedited']], r[run['normal']], r[run['classic']], r[run['nomodel']]
        check('run%d %s: dialog Expedited -> staging "expedited" finished, one change of type expedited on the Expedited model, linked' % (n, nums['expedited']),
              e.get('submitted') and ex['staging'] == [{'type': 'expedited', 'status': 'finished'}] and len(ex['changes']) == 1
              and ex['changes'][0]['type'] == 'expedited' and ex['changes'][0]['model'] == 'Expedited' and ex['changes'][0]['linked'], json.dumps(ex))
        check('run%d %s: dialog Normal -> one Normal change on the Normal model, linked' % (n, nums['normal']),
              m.get('submitted') and len(no['changes']) == 1 and no['changes'][0]['type'] == 'normal' and no['changes'][0]['model'] == 'Normal' and no['changes'][0]['linked'], json.dumps(no))
        check('run%d %s: classic form path -> the same Expedited change' % (n, nums['classic']),
              c['type'] == 'expedited' and c['model'] == 'Expedited' and len(cl['changes']) == 1 and cl['changes'][0]['linked'] and not c['errors'], json.dumps(c))
        check('run%d %s: no Expedited model -> nothing created or linked, task untouched, status error, one error line' % (n, nums['nomodel']),
              not x['change'] and x['status'] == 'error' and not nm['changes'] and len(x['errors']) == 1
              and x['errors'][0].startswith('ChangeMgmt: change creation failed for sn_vul_action_create_cr ') and x['errors'][0].endswith(' - no active change model presets type expedited')
              and not nm['links'] and nm['state'] == snap[run['nomodel']]['state'], json.dumps(dict(x, task=nm)))
    finally:
        print('   cleanup:', json.dumps(cleanup(snap, start)))

print('\n%s: %d of %d as expected' % ('ALL AS EXPECTED' if all(checks) else 'FAILURES', sum(checks), len(checks)))
json.dump({'checks': len(checks), 'passed': sum(checks)}, open(os.path.join(HERE, 'test_results.json'), 'w'), indent=1)
sys.exit(0 if all(checks) else 1)
