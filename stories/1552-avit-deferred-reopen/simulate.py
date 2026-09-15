"""SNOWUSEMTP-1552: what happens to a deferred application vulnerable item that the scanner closes and
re-opens while its deferral is still valid, with the property sn_vul.auto_defer_avit_in_active_exception_window
off and on. The scanner is simulated with the two writes the AVR import API makes on the item record (state
Closed with the scanner's substate, then state Open); the deferral with the writes the exception approval makes.
Fixture items are marked 'USEM 1552 fixture' and removed at the end; the property is put back to its value."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
PROP = 'sn_vul.auto_defer_avit_in_active_exception_window'; MARK = 'USEM 1552 fixture'
ui = SNUI(); ui.app('global')
LIB = '''var PROP = %s; var MARK = %s;
function fixture(label) { var ci = new GlideRecord('cmdb_ci'); ci.addQuery('short_description', 'USEM AIT fixture'); ci.setLimit(1); ci.query(); ci.next();
  var ve = new GlideRecord('sn_vul_app_vul_entry'); ve.setLimit(1); ve.query(); ve.next(); var ar = new GlideRecord('sn_vul_app_release'); ar.setLimit(1); ar.query(); ar.next();
  var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.initialize(); g.setValue('cmdb_ci', ci.getUniqueValue()); g.setValue('vulnerability', ve.getUniqueValue()); g.setValue('application_release', ar.getUniqueValue()); g.setValue('short_description', MARK + ' ' + label); g.setValue('state', 1); return '' + g.insert(); }
function defer(id, until) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); g.setValue('state', 12); g.setValue('substate', 2); g.setValue('backup_substate', 2); g.setValue('ignore_expiration', until); g.setValue('ignore_expiration_dt_tm', until + ' 00:00:00'); g.setValue('ignored_by', gs.getUserID()); g.setValue('ignore_reason', 'USEM 1552 test deferral'); g.update(); }
function scannerClose(id, substate) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); g.setValue('state', 3); g.setValue('substate', substate); g.update(); }
function scannerReopen(id) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); g.setValue('state', 1); g.update(); }
function manualReopen(id) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); new sn_vul.VulnerabilityUtils().reopenVulnerableItem(g, false, true); }
function read(id) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); var note = ''; var j = new GlideRecord('sys_journal_field'); j.addQuery('element_id', id); j.addQuery('element', 'work_notes'); j.orderByDesc('sys_created_on'); j.setLimit(1); j.query(); if (j.next()) note = '' + j.getValue('value');
  return {number: g.getValue('number'), state: g.getDisplayValue('state') + ' (' + g.getValue('state') + ')', substate: g.getDisplayValue('substate') || '-', active: g.getValue('active'), backup_substate: g.getValue('backup_substate') || '-', until: g.getValue('ignore_expiration') || '-', defer_count: g.getValue('defer_count') || '0', reopened: g.getValue('reopened'), reopened_count: g.getValue('reopened_count') || '0', ignore_date: g.getValue('ignore_date') || '-', note: note.substring(0, 120)}; }
function day(offset) { var d = new GlideDate(); d.addDaysUTC(offset); return d.getValue(); }
''' % (json.dumps(PROP), json.dumps(MARK))
def js(code): return ui.js(LIB + code)
def show(label, r): print('  %-44s state %-16s substate %-14s active %s backup %s until %s defer_count %s reopened %s/%s note: %s' % (label, r['state'], r['substate'], r['active'], r['backup_substate'], r['until'], r['defer_count'], r['reopened'], r['reopened_count'], r['note']))
orig = js('''gs.print('X::' + JSON.stringify({value: gs.getProperty(PROP), tz: gs.getSession().getTimeZoneName() + '', systz: gs.getProperty('glide.sys.default.tz')}));''')
print('property before:', orig['value'], '| session tz', orig['tz'], '| system tz', orig['systz'])
def scenario(title, prop, until_offset, close_substate=4, reopen='scanner', tz=None):
    print('\n== ' + title)
    r = js('''var __out = {}; gs.setProperty(PROP, %s); %s var id = fixture(%s); __out.created = read(id); defer(id, day(%d)); __out.deferred = read(id); scannerClose(id, %d); __out.closed = read(id); %s; __out.reopened = read(id); __out.id = id; gs.print('X::' + JSON.stringify(__out));'''
           % (json.dumps(prop), ("gs.getSession().setTimeZoneName(%s);" % json.dumps(tz)) if tz else '', json.dumps(title), until_offset, close_substate, 'manualReopen(id)' if reopen == 'manual' else 'scannerReopen(id)'))
    show('created', r['created']); show('deferred until day%+d' % until_offset, r['deferred']); show('scanner closed (substate %d)' % close_substate, r['closed']); show('%s re-opened, property %s' % (reopen, prop), r['reopened'])
    return r
results = {}
results['off'] = scenario('A. property false, until tomorrow, scanner close Fixed then re-open', 'false', 1)
results['on'] = scenario('B. property true, until tomorrow, scanner close Fixed then re-open', 'true', 1)
results['on_stale'] = scenario('C. property true, until tomorrow, closed as Stale by auto-close then re-open', 'true', 1, close_substate=6)
results['on_expired'] = scenario('D. property true, until yesterday (deferral expired) then re-open', 'true', -1)
results['on_today_ist'] = scenario('E. property true, until today, session in IST', 'true', 0)
results['on_today_utc'] = scenario('F. property true, until today, session in UTC', 'true', 0, tz='UTC')
results['on_manual'] = scenario('G. property true, until tomorrow, manual re-open (Reopen action) instead of scanner', 'true', 1, reopen='manual')
results['on_twice'] = js('''var __out = {}; gs.setProperty(PROP, 'true'); var id = fixture('H. two cycles'); defer(id, day(1)); scannerClose(id, 4); scannerReopen(id); __out.first = read(id); scannerClose(id, 4); scannerReopen(id); __out.second = read(id); gs.print('X::' + JSON.stringify(__out));''')
print('\n== H. property true, two close/re-open cycles on one item'); show('after cycle 1', results['on_twice']['first']); show('after cycle 2', results['on_twice']['second'])
end = js('''var __out = {}; gs.setProperty(PROP, %s); __out.value = gs.getProperty(PROP); gs.print('X::' + JSON.stringify(__out));''' % json.dumps(orig['value']))
print('\nproperty restored to', end['value'])
head = {'X-UserToken': ui.ck(), 'Accept': 'application/json'}
# the item's short description is rewritten from the vulnerability on insert, so the fixtures are found by the deferral reason
rows = ui.s.get(INST + '/api/now/table/sn_vul_app_vulnerable_item', params={'sysparm_query': 'ignore_reason=USEM 1552 test deferral', 'sysparm_fields': 'sys_id,number', 'sysparm_limit': 100}, headers=head).json().get('result', [])
links = ui.s.get(INST + '/api/now/table/sn_vul_app_m2m_vul_group_item', params={'sysparm_query': 'vulnerable_item.ignore_reason=USEM 1552 test deferral', 'sysparm_fields': 'sys_id', 'sysparm_limit': 200}, headers=head).json().get('result', [])
gone_links = sum(1 for r in links if ui.s.delete(INST + '/api/now/table/sn_vul_app_m2m_vul_group_item/' + r['sys_id'], headers=head).status_code == 204)
gone = sum(1 for r in rows if ui.s.delete(INST + '/api/now/table/sn_vul_app_vulnerable_item/' + r['sys_id'], headers=head).status_code == 204)
print('fixture items removed through the table API: %d of %d (%s); task links removed: %d of %d' % (gone, len(rows), ', '.join(r['number'] for r in rows), gone_links, len(links)))
json.dump(results, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'simulate_results.json'), 'w'), indent=1)
