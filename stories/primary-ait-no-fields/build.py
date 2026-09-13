"""Deploys the Primary AIT resolution without new fields or tables into a Global update set on the
PDI: properties, the AitResolver script include, the event and its parallel queue, the script action,
the before rules on the discovered item tables, the keyed after rules on the source tables, and the
two jobs (captured with saveRecord, the job table is not tracked)."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
NAME = 'SNOWUSEMTP-AIT_MS_Primary AIT Resolution_V1.0'
DESC = ('Primary AIT resolution for discovered items without new fields or tables. AitResolver derives the Primary AIT of a CI from the '
        'service association, Related Services and relationship index tables (lowest RTO tier over the business applications related to the '
        'services the CI belongs to, tie broken by AIT number). Discovered items receive the value in a before rule when their CI changes; '
        'changes on svc_ci_assoc, sn_vul_m2m_ci_services, cmdb_rel_ci, the business application AIT reference and the AIT tier queue one keyed '
        'event on the sequential queue usem_ait, where the processor resolves only the CIs the key can affect and stamps the discovered item '
        'tables in sets grouped by the value written. A nightly partitioned reconcile job re-derives everything from source; a catch-up job replays the last 30 '
        'minutes of association and relationship inserts. Table and field names, the discovered item tables in scope, the chunk size and '
        'the queue name are system properties usem.ait.*.')
BOFASIM = '9d1e03de930b8310e3aef0aefaba10d5'
PROPS = {
    'usem.ait.ait_table': ('x_196061_bofasim_ait', 'Table holding the AITs (client: x_boar_bofa_techad_ait).'),
    'usem.ait.tier_field': ('rto_tier', 'Numeric RTO tier field on the AIT table; the lowest tier wins.'),
    'usem.ait.app_table': ('cmdb_ci_business_app', 'Business application table.'),
    'usem.ait.app_ait_field': ('u_primary_ait', 'Reference on the business application to its AIT.'),
    'usem.ait.di_tables': ('sn_sec_cmn_src_ci=cmdb_ci=u_primary_ait\nsn_vul_app_release=cmdb_ci=u_primary_ait\nsn_vul_container_image=cmdb_ci=u_bofa_primary_ait',
                           'Discovered item tables kept current, one table=ci_field=ait_field per line.'),
    'usem.ait.sources': ('assoc,self,related', 'Where a CI finds its services: assoc = service associations in both directions, self = a service counts for itself, related = the Related Services links.'),
    'usem.ait.fallback': ('neighbours', 'When the sources find nothing: neighbours = the sources applied to the CIs related to it, walk = the platform impact walk, none.'),
    'usem.ait.stamp_chunk': ('200', 'CIs per set-based statement when stamping discovered items.'),
    'usem.ait.event_queue': ('usem_ait', 'Event queue that carries the keyed refresh events (Queue Registry).'),
}
RETIRED_PROPS = ['usem.ait.session_cache', 'usem.ait.cache_seconds']
DI_RULES = {'sn_sec_cmn_src_ci': 'USEM Primary AIT - discovered item', 'sn_vul_app_release': 'USEM Primary AIT - application release', 'sn_vul_container_image': 'USEM Primary AIT - container image'}
RULE_NAMES = {'assoc': 'USEM Primary AIT - service association', 'related': 'USEM Primary AIT - related service', 'rel': 'USEM Primary AIT - relationship',
              'app': 'USEM Primary AIT - application AIT', 'ait': 'USEM Primary AIT - AIT tier'}
assert all(len(n) <= 40 for n in list(DI_RULES.values()) + list(RULE_NAMES.values())), 'sys_script.name holds 40 characters'
SCRIPT = open(os.path.join(HERE, 'AitResolver.js')).read()
DI_RULE = """(function executeRule(current, previous) {
    new AitResolver().resolveRecord(current);
})(current, previous);"""
ASSOC_RULE = """(function executeRule(current, previous) {
    var ids = [current.getValue('ci_id'), current.getValue('service_id')];
    if (current.operation() == 'update')
        ids.push(previous.getValue('ci_id'), previous.getValue('service_id'));
    new AitResolver().enqueue('ci', ids.join(','));
})(current, previous);"""
RELATED_RULE = """(function executeRule(current, previous) {
    var ids = [current.getValue('item')];
    if (current.operation() == 'update')
        ids.push(previous.getValue('item'));
    new AitResolver().enqueue('ci', ids.join(','));
})(current, previous);"""
REL_RULE = """(function executeRule(current, previous) {
    var resolver = new AitResolver();
    resolver.enqueueRelationship(current.getValue('parent'), current.getValue('child'));
    if (current.operation() == 'update')
        resolver.enqueueRelationship(previous.getValue('parent'), previous.getValue('child'));
})(current, previous);"""
APP_RULE = """(function executeRule(current, previous) {
    new AitResolver().enqueue('app', current.getUniqueValue());
})(current, previous);"""
AIT_RULE = """(function executeRule(current, previous) {
    new global.AitResolver().enqueue('ait', current.getUniqueValue());
})(current, previous);"""
ACTION = """new AitResolver().refresh('' + event.parm1, '' + event.parm2);"""
RECONCILE_JOB = """var resolver = new AitResolver();
var prefixes = '0123456789abcdef'.split('');
for (var table in resolver.DI_TABLES) {
    for (var i = 0; i < prefixes.length; i++)
        new AitResolver().reconcile(table, prefixes[i]);
    resolver.clearOrphans(table);
}"""
CATCHUP_JOB = """var resolver = new AitResolver();
var since = new GlideDateTime();
since.addSeconds(-30 * 60);
var cis = [];
var assoc = new GlideRecord('svc_ci_assoc');
assoc.addQuery('sys_created_on', '>', since);
assoc.query();
while (assoc.next())
    cis.push(assoc.getValue('ci_id'), assoc.getValue('service_id'));
if (resolver.SOURCES.related) {
    var related = new GlideRecord('sn_vul_m2m_ci_services');
    related.addQuery('sys_created_on', '>', since);
    related.query();
    while (related.next())
        cis.push(related.getValue('item'));
}
if (cis.length)
    resolver.refresh('ci', cis.join(','));
var ends = [];
var rel = new GlideRecord('cmdb_rel_ci');
rel.addQuery('sys_created_on', '>', since);
rel.query();
while (rel.next())
    ends.push(rel.getValue('parent'), rel.getValue('child'));
if (ends.length)
    resolver.refresh('rel', ends.join(','));"""
ui = SNUI(); ui.app('global')
st_path = os.path.join(HERE, 'state.json'); ST = json.load(open(st_path)) if os.path.exists(st_path) else {}
d = ui.js('''
var o = {rows: [], made: {}};
var us = new GlideRecord('sys_update_set');
if (%s && us.get(%s)) { us.setValue('state', 'in progress'); us.setValue('name', %s); us.setValue('description', %s); us.update(); }
else { us.initialize(); us.setValue('name', %s); us.setValue('application', 'global'); us.setValue('description', %s); us.insert(); }
o.set = us.getUniqueValue(); new GlideUpdateSet().set(o.set);
var um = new GlideUpdateManager2();
var retired = %s;
for (var r = 0; r < retired.length; r++) {
    var old = new GlideRecord('sys_properties'); old.addQuery('name', retired[r]); old.query(); while (old.next()) old.deleteRecord();
    var oldx = new GlideRecord('sys_update_xml'); oldx.addQuery('update_set', o.set); oldx.addQuery('target_name', retired[r]); oldx.query(); while (oldx.next()) oldx.deleteRecord();
}
var keep = %s;
var stale = new GlideRecord('sys_script'); stale.addQuery('name', 'STARTSWITH', 'USEM Primary AIT'); stale.addQuery('name', 'NOT IN', keep.join(',')); stale.query();
while (stale.next()) { var sx = new GlideRecord('sys_update_xml'); sx.addQuery('update_set', o.set); sx.addQuery('name', 'sys_script_' + stale.getUniqueValue()); sx.query(); while (sx.next()) sx.deleteRecord(); stale.deleteRecord(); }
var dx = new GlideRecord('sys_update_xml'); dx.addQuery('update_set', o.set); dx.addQuery('type', 'Business Rule'); dx.addQuery('action', 'DELETE'); dx.query(); while (dx.next()) dx.deleteRecord();
var props = %s;
for (var name in props) {
    var p = new GlideRecord('sys_properties'); p.addQuery('name', name); p.query();
    if (!p.next()) { p.initialize(); p.setValue('name', name); p.setValue('type', 'string'); }
    p.setValue('value', props[name][0]); p.setValue('description', props[name][1]); p.setValue('ignore_cache', false);
    p.update() || p.insert(); um.saveRecord(p);
}
var si = new GlideRecord('sys_script_include'); si.addQuery('name', 'AitResolver'); si.query();
if (!si.next()) { si.initialize(); si.setValue('name', 'AitResolver'); }
si.setValue('script', %s); si.setValue('access', 'public'); si.setValue('active', true); si.setValue('client_callable', false);
si.setValue('description', 'Derives the Primary AIT of a CI from the service association, Related Services and relationship index tables, writes it on discovered items, and propagates keyed changes (CI, service, application, AIT) by stamping discovered items in sets. No intermediate value is stored anywhere; configuration in the usem.ait.* properties.');
si.update() || si.insert(); o.made.script_include = si.getUniqueValue();
var er = new GlideRecord('sysevent_register'); er.addQuery('event_name', 'usem.ait.refresh'); er.query();
if (!er.next()) { er.initialize(); er.setValue('event_name', 'usem.ait.refresh'); }
er.setValue('queue', 'usem_ait'); er.setValue('description', 'Keyed Primary AIT refresh: parm1 = ait | app | service | ci | rel, parm2 = comma-separated sys_ids. Processed by the script action USEM Primary AIT refresh on the usem_ait queue.');
er.update() || er.insert(); o.made.event = er.getUniqueValue();
var q = new GlideRecord('sysevent_queue'); q.addQuery('queue', 'usem_ait'); q.query();
if (!q.next()) { q.initialize(); q.setValue('queue', 'usem_ait'); }
q.setValue('processing_order', 'sequential'); q.setValue('job_config', 'job_count'); q.setValue('job_config_value', 1); q.setValue('poll_interval', '1970-01-01 00:00:10'); q.setValue('automatic_processing', true);
q.setValue('description', 'Primary AIT keyed refresh events, processed one at a time in the order they were queued so that a later change always writes after an earlier one.');
q.update() || q.insert(); o.made.queue = q.getUniqueValue(); um.saveRecord(q);
var sa = new GlideRecord('sysevent_script_action'); sa.addQuery('name', 'USEM Primary AIT refresh'); sa.query();
if (!sa.next()) { sa.initialize(); sa.setValue('name', 'USEM Primary AIT refresh'); }
sa.setValue('event_name', 'usem.ait.refresh'); sa.setValue('active', true); sa.setValue('order', 100); sa.setValue('script', %s);
sa.setValue('description', 'Resolves the CIs a keyed change can affect and stamps the discovered item tables.');
sa.update() || sa.insert(); o.made.script_action = sa.getUniqueValue();
function rule(name, table, when, ins, upd, del, filter, script, order) {
    var br = new GlideRecord('sys_script'); br.addQuery('name', name); br.query();
    if (!br.next()) { br.initialize(); br.setValue('name', name); }
    br.setValue('collection', table); br.setValue('when', when); br.setValue('action_insert', ins); br.setValue('action_update', upd); br.setValue('action_delete', del);
    br.setValue('active', true); br.setValue('advanced', true); br.setValue('filter_condition', filter); br.setValue('order', order); br.setValue('script', script);
    br.update() || br.insert(); return br.getUniqueValue();
}
var diRules = %s; var names = %s; o.made.di_rules = {};
for (var t in diRules) o.made.di_rules[t] = rule(diRules[t], t, 'before', true, true, false, 'cmdb_ciVALCHANGES^EQ', %s, 100);
o.made.assoc_rule = rule(names.assoc, 'svc_ci_assoc', 'after', true, true, true, '', %s, 100);
o.made.related_rule = rule(names.related, 'sn_vul_m2m_ci_services', 'after', true, true, true, '', %s, 100);
o.made.rel_rule = rule(names.rel, 'cmdb_rel_ci', 'after', true, true, true, '', %s, 100);
o.made.app_rule = rule(names.app, 'cmdb_ci_business_app', 'after', false, true, false, 'u_primary_aitVALCHANGES^EQ', %s, 100);
var aitRule = new GlideRecord('sys_script'); aitRule.addQuery('name', names.ait); aitRule.query();
if (!aitRule.next()) { aitRule.initialize(); aitRule.setValue('name', names.ait); }
aitRule.setValue('collection', 'x_196061_bofasim_ait'); aitRule.setValue('when', 'after'); aitRule.setValue('action_update', true); aitRule.setValue('active', true); aitRule.setValue('advanced', true);
aitRule.setValue('filter_condition', 'rto_tierVALCHANGES^EQ'); aitRule.setValue('order', 100); aitRule.setValue('script', %s);
var aitRuleId = aitRule.update() || aitRule.insert(); o.made.ait_rule = aitRuleId ? aitRuleId : 'REFUSED';
function job(name, script, runType, extra) {
    var j = new GlideRecord('sysauto_script'); j.addQuery('name', name); j.query();
    if (!j.next()) { j.initialize(); j.setValue('name', name); }
    j.setValue('script', script); j.setValue('active', true); j.setValue('run_type', runType); j.setValue('conditional', false);
    for (var k in extra) j.setValue(k, extra[k]);
    j.update() || j.insert(); var jg = new GlideRecord('sysauto_script'); jg.get(j.getUniqueValue()); um.saveRecord(jg); return j.getUniqueValue();
}
o.made.reconcile_job = job('USEM Primary AIT reconcile', %s, 'daily', {run_time: '1970-01-01 02:00:00'});
o.made.catchup_job = job('USEM Primary AIT catch-up', %s, 'periodically', {run_period: '1970-01-01 00:15:00'});
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', o.set); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('type') + ' | ' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(bool(ST.get('set'))), json.dumps(ST.get('set', '')), json.dumps(NAME), json.dumps(DESC), json.dumps(NAME), json.dumps(DESC),
                                            json.dumps(list(DI_RULES.values()) + list(RULE_NAMES.values())), json.dumps(RETIRED_PROPS), json.dumps(PROPS), json.dumps(SCRIPT), json.dumps(ACTION),
                                            json.dumps(DI_RULES), json.dumps(RULE_NAMES), json.dumps(DI_RULE),
                                            json.dumps(ASSOC_RULE), json.dumps(RELATED_RULE), json.dumps(REL_RULE), json.dumps(APP_RULE), json.dumps(AIT_RULE), json.dumps(RECONCILE_JOB), json.dumps(CATCHUP_JOB)))
print('set:', d['set']); print(json.dumps(d['made'], indent=1)); print('captured:'); print('\n'.join(' ' + r for r in d['rows']))
assert all(r.endswith('| Global') for r in d['rows']) and d['made']['ait_rule'] != 'REFUSED' and d['made']['queue'], 'scope mismatch, refused rule or queue not created'
json.dump({'set': d['set'], 'name': NAME, 'made': d['made'], 'rows': len(d['rows'])}, open(st_path, 'w'), indent=1)
print('DEPLOYED: %d updates, all Global' % len(d['rows']))
