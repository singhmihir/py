"""Keeps the PDI responsive. Background jobs that do nothing useful on a developer instance run all day
(measured 23 Sep: the Now Assist troubleshooting notifications every 5 minutes started 1,174 flows in 48 hours,
two CMDB health collectors run every minute, the ATF test generator and two Virtual Agent processors poll every
5-10 seconds, each Virtual Agent trigger twice), and syslog keeps 90 days of lines.

Usage: python3 tools/pdi_keep_fast.py [--restore]
  - switches the jobs off (sysauto records inactive, triggers without a job record parked in 2099),
  - sets the table cleaner to keep 7 days of syslog and transaction logs,
  - installs the scheduled job "PDI Keep Fast" (hourly) that re-applies all of this, so the instance stays fast
    after a wake-up or a plugin re-enables something, and writes a health line to the property pdi.keep_fast.last_run,
  - prints the instance health (jobs overdue within the last day, table sizes, response time); older entries
    (startup and one-off jobs dated 2013 or at the instance build) never run and are not counted.
The original settings are saved to tools/pdi_keep_fast_original.json on the first run; --restore puts them back and
removes the scheduled job. PDI only: nothing here is ever delivered."""
import os, sys, json, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from snui import SNUI

JOBS_OFF = ['Generate Now Assist Troubleshooting Notifications', 'CMDB Get Well Metric Collection',
            'CMDB Get Well CIs Processed Via IRE Metric Batch Collection', 'CMDB Get Well CIs Not Updated Metric Batch Collection',
            'CMDB Sys Object Source Cleanup']
TRIGGERS_PARKED = ['@dotwalk/atf-commons-server/SNBOQProcess', 'VA Event Processor 0', 'VA Notification Batch Event Handler']
CLEANER_DAYS = {'syslog': 7, 'syslog_transaction': 7}
PARK_UNTIL = '2099-01-01 00:00:00'
JOB_NAME = 'PDI Keep Fast'
ORIGINAL = os.path.join(HERE, 'pdi_keep_fast_original.json')

# The same function runs now and every hour in the scheduled job.
KEEP_FAST = r'''
function pdiKeepFast(jobsOff, triggersParked, cleanerDays, parkUntil) {
    var done = {jobs_off: 0, triggers_parked: 0, cleaner: 0};
    var job = new GlideRecord('sysauto'); job.addQuery('name', 'IN', jobsOff.join(',')); job.addActiveQuery(); job.query();
    while (job.next()) { job.setValue('active', false); job.update(); done.jobs_off++; }
    var trg = new GlideRecord('sys_trigger'); trg.addQuery('name', 'IN', triggersParked.join(',')); trg.addQuery('next_action', '<', parkUntil); trg.query();
    while (trg.next()) { trg.setValue('next_action', parkUntil); trg.update(); done.triggers_parked++; }
    for (var table in cleanerDays) {
        var rule = new GlideRecord('sys_auto_flush'); rule.addQuery('tablename', table); rule.addQuery('matchfield', 'sys_created_on'); rule.query();
        while (rule.next()) if (parseInt(rule.getValue('age')) != cleanerDays[table] * 86400) { rule.setValue('age', cleanerDays[table] * 86400); rule.setValue('active', true); rule.update(); done.cleaner++; }
    }
    var overdue = new GlideAggregate('sys_trigger'); overdue.addQuery('state', 0); overdue.addQuery('next_action', '<', gs.minutesAgoStart(5)); overdue.addQuery('next_action', '>', gs.daysAgoStart(1)); overdue.addAggregate('COUNT'); overdue.query(); overdue.next();
    done.overdue_jobs = parseInt(overdue.getAggregate('COUNT'));
    done.at = new GlideDateTime().getValue();
    gs.setProperty('pdi.keep_fast.last_run', JSON.stringify(done), 'Last run of the PDI Keep Fast job (PDI only)');
    return done;
}
'''

def config_args():
    return '%s, %s, %s, %s' % (json.dumps(JOBS_OFF), json.dumps(TRIGGERS_PARKED), json.dumps(CLEANER_DAYS), json.dumps(PARK_UNTIL))

def health(ui):
    t0 = time.time()
    h = ui.js('''var o = {tables: {}};
var names = ['syslog', 'syslog_transaction', 'sys_flow_context', 'sysevent', 'sys_audit'];
for (var i = 0; i < names.length; i++) { var a = new GlideAggregate(names[i]); a.addAggregate('COUNT'); a.query(); a.next(); o.tables[names[i]] = parseInt(a.getAggregate('COUNT')); }
var t = new GlideAggregate('sys_trigger'); t.addQuery('state', 0); t.addQuery('next_action', '<', gs.minutesAgoStart(5)); t.addQuery('next_action', '>', gs.daysAgoStart(1)); t.addAggregate('COUNT'); t.query(); t.next(); o.overdue_jobs = parseInt(t.getAggregate('COUNT'));
gs.print('X::' + JSON.stringify(o));''')
    h['script_seconds'] = round(time.time() - t0, 1)
    return h

def main():
    ui = SNUI(); ui.app('global')
    d = ui.js('''var o = {jobs: [], triggers: [], cleaner: []};
var d = new GlideRecord('sys_update_set'); d.addQuery('name', 'Default'); d.addQuery('application', 'global'); d.query(); d.next(); new GlideUpdateSet().set(d.getUniqueValue());
var j = new GlideRecord('sysauto'); j.addQuery('name', 'IN', %s); j.query(); while (j.next()) o.jobs.push({sys_id: j.getUniqueValue(), cls: j.getValue('sys_class_name'), name: j.getValue('name'), active: j.getValue('active') == '1'});
var t = new GlideRecord('sys_trigger'); t.addQuery('name', 'IN', %s); t.query(); while (t.next()) o.triggers.push({sys_id: t.getUniqueValue(), name: t.getValue('name'), next_action: t.getValue('next_action')});
var c = new GlideRecord('sys_auto_flush'); c.addQuery('tablename', 'IN', %s); c.addQuery('matchfield', 'sys_created_on'); c.query(); while (c.next()) o.cleaner.push({sys_id: c.getUniqueValue(), table: c.getValue('tablename'), age: c.getValue('age'), active: c.getValue('active') == '1'});
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(','.join(JOBS_OFF)), json.dumps(','.join(TRIGGERS_PARKED)), json.dumps(','.join(CLEANER_DAYS))))
    if '--restore' in sys.argv:
        orig = json.load(open(ORIGINAL))
        r = ui.js('''var o = orig = %s; var n = 0;
for (var i = 0; i < orig.jobs.length; i++) { var j = new GlideRecord('sysauto'); if (j.get(orig.jobs[i].sys_id)) { j.setValue('active', orig.jobs[i].active); j.update(); n++; } }
for (var k = 0; k < orig.triggers.length; k++) { var t = new GlideRecord('sys_trigger'); if (t.get(orig.triggers[k].sys_id)) { t.setValue('next_action', new GlideDateTime().getValue()); t.update(); n++; } }
for (var c = 0; c < orig.cleaner.length; c++) { var f = new GlideRecord('sys_auto_flush'); if (f.get(orig.cleaner[c].sys_id)) { f.setValue('age', orig.cleaner[c].age); f.setValue('active', orig.cleaner[c].active); f.update(); n++; } }
var s = new GlideRecord('sysauto_script'); s.addQuery('name', %s); s.query(); while (s.next()) { s.deleteRecord(); n++; }
gs.print('X::' + JSON.stringify({restored: n}));''' % (json.dumps(orig), json.dumps(JOB_NAME)))
        print('restored:', r); return
    if not os.path.exists(ORIGINAL):
        json.dump(d, open(ORIGINAL, 'w'), indent=1)
        print('original settings saved to', ORIGINAL)
    before = health(ui)
    job_script = KEEP_FAST + '\npdiKeepFast(%s);\n' % config_args()
    r = ui.js('''%s
var done = pdiKeepFast(%s);
var s = new GlideRecord('sysauto_script'); s.addQuery('name', %s); s.query();
if (!s.next()) { s.initialize(); s.setValue('name', %s); }
s.setValue('script', %s); s.setValue('run_type', 'periodically'); s.setValue('run_period', '1970-01-01 01:00:00'); s.setValue('active', true);
s.update() || s.insert();
done.job = s.getUniqueValue();
gs.print('X::' + JSON.stringify(done));''' % (KEEP_FAST, config_args(), json.dumps(JOB_NAME), json.dumps(JOB_NAME), json.dumps(job_script)))
    print('applied:', r)
    print('health before:', before)
    print('health after: ', health(ui))
    print('jobs switched off:', [j['name'] for j in d['jobs']])
    print('triggers parked until %s:' % PARK_UNTIL, sorted(set(t['name'] for t in d['triggers'])))

if __name__ == '__main__':
    main()
