"""Same rescan as simulate.py, but the deferral sits on the application remediation task (the usual client path:
the exception is requested on the task and the items inherit its state). Checks whether the task pulls a re-opened
item back to Deferred on its own, with the property off and on. Fixtures removed at the end; property restored."""
import os, sys, json, time
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
PROP = 'sn_vul.auto_defer_avit_in_active_exception_window'
ui = SNUI(); ui.app('global')
LIB = '''var PROP = %s;
function fixture() { var ci = new GlideRecord('cmdb_ci'); ci.addQuery('short_description', 'USEM AIT fixture'); ci.setLimit(1); ci.query(); ci.next();
  var ve = new GlideRecord('sn_vul_app_vul_entry'); ve.setLimit(1); ve.query(); ve.next(); var ar = new GlideRecord('sn_vul_app_release'); ar.setLimit(1); ar.query(); ar.next();
  var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.initialize(); g.setValue('cmdb_ci', ci.getUniqueValue()); g.setValue('vulnerability', ve.getUniqueValue()); g.setValue('application_release', ar.getUniqueValue()); g.setValue('state', 1); g.setValue('ignore_reason', 'USEM 1552 task test'); return '' + g.insert(); }
function taskOf(id) { var m = new GlideRecord('sn_vul_app_m2m_vul_group_item'); m.addQuery('sn_vul_app_vulnerable_item', id); m.query(); return m.next() ? '' + m.getValue('sn_vul_app_vulnerability') : ''; }
function linkToTask(id) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); var t = new GlideRecord('sn_vul_app_vulnerability'); t.initialize(); t.setValue('short_description', 'USEM 1552 task test'); t.setValue('ignore_reason', 'USEM 1552 task test'); t.setValue('vulnerability', g.getValue('vulnerability')); t.setValue('state', 1); var taskId = '' + t.insert();
  var m = new GlideRecord('sn_vul_app_m2m_vul_group_item'); m.initialize(); m.setValue('sn_vul_app_vulnerable_item', id); m.setValue('sn_vul_app_vulnerability', taskId); m.insert(); return taskId; }
function deferTask(taskId, until) { var t = new GlideRecord('sn_vul_app_vulnerability'); t.get(taskId); t.setValue('state', 12); t.setValue('substate', 2); t.setValue('ignore_expiration', until); t.setValue('ignore_expiration_dt_tm', until + ' 00:00:00'); t.setValue('ignored_by', gs.getUserID()); t.setValue('ignore_reason', 'USEM 1552 task test'); t.update(); }
function scannerClose(id) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); g.setValue('state', 3); g.setValue('substate', 4); var ok = g.update(); return ok ? 'saved' : 'REFUSED ' + gs.getErrorMessages(); }
function scannerReopen(id) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); g.setValue('state', 1); var ok = g.update(); return ok ? 'saved' : 'REFUSED ' + gs.getErrorMessages(); }
function read(id) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); var t = new GlideRecord('sn_vul_app_vulnerability'); var task = taskOf(id); var ts = t.get(task) ? t.getValue('number') + ' ' + t.getDisplayValue('state') + '/' + (t.getDisplayValue('substate') || '-') : '(no task)';
  return {item: g.getValue('number'), state: g.getDisplayValue('state') + ' (' + g.getValue('state') + ')', substate: g.getDisplayValue('substate') || '-', active: g.getValue('active'), backup: g.getValue('backup_substate') || '-', until: g.getValue('ignore_expiration') || '-', defer_count: g.getValue('defer_count') || '0', inherit: g.getValue('state_inheritance_count') || '0', task: ts}; }
function day(n) { var d = new GlideDate(); d.addDaysUTC(n); return d.getValue(); }
''' % json.dumps(PROP)
def js(code): return ui.js(LIB + code)
def show(label, r): print('  %-40s %-16s %-14s active %s backup %s until %s defer_count %s inherit %s | task %s' % (label, r['state'], r['substate'], r['active'], r['backup'], r['until'], r['defer_count'], r['inherit'], r['task']))
orig = js('''gs.print('X::' + JSON.stringify({value: gs.getProperty(PROP)}));''')['value']
for prop in ['false', 'true']:
    print('\n== task-level deferral, property %s' % prop)
    r = js('''var __out = {}; gs.setProperty(PROP, %s); var id = fixture(); __out.id = id; __out.created = read(id); var task = taskOf(id) || linkToTask(id); __out.task = task; if (task) deferTask(task, day(1)); gs.print('X::' + JSON.stringify(__out));''' % json.dumps(prop))
    show('created', r['created'])
    if not r['task']:
        print('  no remediation task was linked to the item; stopping this case'); continue
    time.sleep(8)
    r2 = js('''var __out = {}; var id = %s; __out.after_task_defer = read(id); __out.close = scannerClose(id); __out.closed = read(id); gs.print('X::' + JSON.stringify(__out));''' % json.dumps(r['id']))
    show('task deferred until tomorrow (8 s later)', r2['after_task_defer']); show('scanner closed Fixed: ' + r2['close'], r2['closed'])
    time.sleep(8)
    r3 = js('''var __out = {}; var id = %s; __out.closed_later = read(id); __out.reopen = scannerReopen(id); __out.reopened = read(id); gs.print('X::' + JSON.stringify(__out));''' % json.dumps(r['id']))
    show('closed, 8 s later', r3['closed_later']); show('scanner re-opened: ' + r3['reopen'], r3['reopened'])
    time.sleep(8)
    r4 = js('''var __out = {}; var id = %s; __out.later = read(id); gs.print('X::' + JSON.stringify(__out));''' % json.dumps(r['id']))
    show('re-opened, 8 s later', r4['later'])
js('''gs.setProperty(PROP, %s); gs.print('X::{}');''' % json.dumps(orig)); print('\nproperty restored to', orig)
head = {'X-UserToken': ui.ck(), 'Accept': 'application/json'}
def wipe(table, query):
    rows = ui.s.get(INST + '/api/now/table/' + table, params={'sysparm_query': query, 'sysparm_fields': 'sys_id', 'sysparm_limit': 200}, headers=head).json().get('result', [])
    return sum(1 for r in rows if ui.s.delete(INST + '/api/now/table/' + table + '/' + r['sys_id'], headers=head).status_code == 204), len(rows)
print('links removed %d of %d' % wipe('sn_vul_app_m2m_vul_group_item', 'sn_vul_app_vulnerability.ignore_reason=USEM 1552 task test'))
print('items removed %d of %d' % wipe('sn_vul_app_vulnerable_item', 'ignore_reason=USEM 1552 task test'))
print('tasks removed %d of %d' % wipe('sn_vul_app_vulnerability', 'ignore_reason=USEM 1552 task test'))
print('orphan links removed %d of %d' % wipe('sn_vul_app_m2m_vul_group_item', 'sn_vul_app_vulnerable_item.sys_idISEMPTY^sys_created_onONToday@javascript:gs.beginningOfToday()@javascript:gs.endOfToday()'))
