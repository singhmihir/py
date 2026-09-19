"""Timing evidence for the primary AIT design, measured on the instance:
1. cost of the platform's own CI -> services walk (CIUtils.servicesAffectedByCI)
2. set-based stamping of a CI-level field across 100k CIs (updateMultiple)
3. set-based stamping of discovered items by their CI's AIT in one statement per AIT
4. the per-record alternative on a 2,000-row slice, for extrapolation
5. drift detection by aggregate count per AIT
Every step is timed on the server. Only fixture placeholder CIs and the discovered
items that point at them are touched; the field values are cleared at the end."""
import os, sys, json, time
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ui = SNUI(); ui.app('global')
def step(label, js):
    t0 = time.time(); d = ui.js(js); d['_wall_s'] = round(time.time() - t0, 1); print('%-70s %s' % (label, json.dumps(d))); return d
R = {}
R['field'] = step('0. ensure cmdb_ci.u_primary_ait exists (reference to the AIT stand-in)', '''
var o = {}; var dd = new GlideRecord('sys_dictionary'); dd.addQuery('name', 'cmdb_ci'); dd.addQuery('element', 'u_primary_ait'); dd.query();
if (dd.next()) o.existing = true; else { dd.initialize(); dd.setValue('name', 'cmdb_ci'); dd.setValue('element', 'u_primary_ait'); dd.setValue('column_label', 'Primary AIT'); dd.setValue('internal_type', 'reference'); dd.setValue('reference', 'x_196061_bofasim_ait'); dd.setValue('max_length', 32); dd.setValue('active', true); o.created = '' + dd.insert(); }
var chk = new GlideRecord('cmdb_ci'); o.valid = chk.isValidField('u_primary_ait');
var ait = new GlideRecord('x_196061_bofasim_ait'); ait.orderBy('number'); ait.query(); o.aits = []; while (ait.next()) o.aits.push(ait.getUniqueValue());
gs.print('X::' + JSON.stringify(o));''')
A, B = R['field']['aits'][0], R['field']['aits'][1]
R['walk'] = step('1. platform walk CI -> services, 100 CIs that have associations', '''
var o = {}; var ids = []; var a = new GlideAggregate('svc_ci_assoc'); a.addAggregate('COUNT'); a.groupBy('ci_id'); a.setLimit(100); a.query(); while (a.next()) ids.push('' + a.getValue('ci_id'));
var util = new global.CIUtils(); var t0 = new Date().getTime(); var found = 0;
for (var i = 0; i < ids.length; i++) found += util.servicesAffectedByCI(ids[i], {maxDepth: 10, maxSize: 1000}).length;
o.cis = ids.length; o.services_found = found; o.total_ms = new Date().getTime() - t0; o.ms_per_ci = Math.round(o.total_ms / Math.max(1, ids.length) * 10) / 10;
gs.print('X::' + JSON.stringify(o));''')
R['ci_stamp'] = step('2. stamp cmdb_ci.u_primary_ait on 100k placeholder CIs (two statements)', '''
var o = {}; var t0 = new Date().getTime();
var g = new GlideRecord('cmdb_ci_unclassed_hardware'); g.addEncodedQuery('sys_idSTARTSWITH0^ORsys_idSTARTSWITH1^ORsys_idSTARTSWITH2^ORsys_idSTARTSWITH3^ORsys_idSTARTSWITH4^ORsys_idSTARTSWITH5^ORsys_idSTARTSWITH6^ORsys_idSTARTSWITH7'); g.setWorkflow(false); g.autoSysFields(false); g.setValue('u_primary_ait', %s); g.updateMultiple();
o.first_half_ms = new Date().getTime() - t0; t0 = new Date().getTime();
var h = new GlideRecord('cmdb_ci_unclassed_hardware'); h.addEncodedQuery('u_primary_aitISEMPTY'); h.setWorkflow(false); h.autoSysFields(false); h.setValue('u_primary_ait', %s); h.updateMultiple();
o.second_half_ms = new Date().getTime() - t0;
var c1 = new GlideAggregate('cmdb_ci'); c1.addQuery('u_primary_ait', %s); c1.addAggregate('COUNT'); c1.query(); c1.next(); o.cis_with_A = parseInt(c1.getAggregate('COUNT'));
var c2 = new GlideAggregate('cmdb_ci'); c2.addQuery('u_primary_ait', %s); c2.addAggregate('COUNT'); c2.query(); c2.next(); o.cis_with_B = parseInt(c2.getAggregate('COUNT'));
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(A), json.dumps(B), json.dumps(A), json.dumps(B)))
R['di_count'] = step('3a. discovered items whose CI is a placeholder (joinable rows)', '''
var o = {}; var t0 = new Date().getTime(); var c = new GlideAggregate('sn_sec_cmn_src_ci'); c.addQuery('cmdb_ci.sys_class_name', 'cmdb_ci_unclassed_hardware'); c.addAggregate('COUNT'); c.query(); c.next(); o.joinable = parseInt(c.getAggregate('COUNT')); o.count_ms = new Date().getTime() - t0;
gs.print('X::' + JSON.stringify(o));''')
R['di_stamp'] = step('3b. stamp DI.u_primary_ait from the CI (one statement per AIT value)', '''
var o = {}; var t0 = new Date().getTime();
var d1 = new GlideRecord('sn_sec_cmn_src_ci'); d1.addQuery('cmdb_ci.u_primary_ait', %s); d1.addQuery('u_primary_ait', '!=', %s); d1.setWorkflow(false); d1.autoSysFields(false); d1.setValue('u_primary_ait', %s); d1.updateMultiple();
o.ait_A_ms = new Date().getTime() - t0; t0 = new Date().getTime();
var d2 = new GlideRecord('sn_sec_cmn_src_ci'); d2.addQuery('cmdb_ci.u_primary_ait', %s); d2.addQuery('u_primary_ait', '!=', %s); d2.setWorkflow(false); d2.autoSysFields(false); d2.setValue('u_primary_ait', %s); d2.updateMultiple();
o.ait_B_ms = new Date().getTime() - t0; t0 = new Date().getTime();
var c1 = new GlideAggregate('sn_sec_cmn_src_ci'); c1.addQuery('u_primary_ait', %s); c1.addAggregate('COUNT'); c1.query(); c1.next(); o.dis_with_A = parseInt(c1.getAggregate('COUNT'));
var c2 = new GlideAggregate('sn_sec_cmn_src_ci'); c2.addQuery('u_primary_ait', %s); c2.addAggregate('COUNT'); c2.query(); c2.next(); o.dis_with_B = parseInt(c2.getAggregate('COUNT')); o.count_ms = new Date().getTime() - t0;
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(A), json.dumps(A), json.dumps(A), json.dumps(B), json.dumps(B), json.dumps(B), json.dumps(A), json.dumps(B)))
R['di_stamp_repeat'] = step('3c. same statements again (nothing stale: cost of an idempotent re-run)', '''
var o = {}; var t0 = new Date().getTime();
var d1 = new GlideRecord('sn_sec_cmn_src_ci'); d1.addQuery('cmdb_ci.u_primary_ait', %s); d1.addQuery('u_primary_ait', '!=', %s); d1.setWorkflow(false); d1.autoSysFields(false); d1.setValue('u_primary_ait', %s); d1.updateMultiple();
o.ait_A_ms = new Date().getTime() - t0;
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(A), json.dumps(A), json.dumps(A)))
R['drift'] = step('4. drift check: DIs whose stored AIT differs from their CI (per AIT count)', '''
var o = {}; var t0 = new Date().getTime();
var c = new GlideAggregate('sn_sec_cmn_src_ci'); c.addQuery('cmdb_ci.u_primary_ait', %s); c.addQuery('u_primary_ait', '!=', %s); c.addAggregate('COUNT'); c.query(); c.next(); o.drift_A = parseInt(c.getAggregate('COUNT')); o.ms = new Date().getTime() - t0;
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(A), json.dumps(A)))
R['per_record'] = step('5. per-record alternative: 2,000 DIs updated one by one (rules off)', '''
var o = {}; var t0 = new Date().getTime(); var n = 0;
var g = new GlideRecord('sn_sec_cmn_src_ci'); g.addQuery('u_primary_ait', %s); g.setLimit(2000); g.query();
while (g.next()) { g.setWorkflow(false); g.autoSysFields(false); g.setValue('u_primary_ait', %s); g.update(); n++; }
o.rows = n; o.ms = new Date().getTime() - t0; o.ms_per_row = Math.round(o.ms / Math.max(1, n) * 100) / 100;
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(A), json.dumps(B)))
R['per_record_rules_on'] = step('6. per-record with business rules running: 300 DIs', '''
var o = {}; var t0 = new Date().getTime(); var n = 0;
var g = new GlideRecord('sn_sec_cmn_src_ci'); g.addQuery('cmdb_ci.u_primary_ait', %s); g.addQuery('u_primary_ait', %s); g.setLimit(300); g.query();
while (g.next()) { g.setValue('u_primary_ait', %s); g.update(); n++; }
o.rows = n; o.ms = new Date().getTime() - t0; o.ms_per_row = Math.round(o.ms / Math.max(1, n) * 100) / 100;
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(A), json.dumps(B), json.dumps(A)))
R['cleanup'] = step('7. clear the benchmark values (DIs of placeholder CIs, then the CIs)', '''
var o = {}; var t0 = new Date().getTime();
var d = new GlideRecord('sn_sec_cmn_src_ci'); d.addQuery('cmdb_ci.sys_class_name', 'cmdb_ci_unclassed_hardware'); d.addNotNullQuery('u_primary_ait'); d.setWorkflow(false); d.autoSysFields(false); d.setValue('u_primary_ait', ''); d.updateMultiple();
o.di_clear_ms = new Date().getTime() - t0; t0 = new Date().getTime();
var c = new GlideRecord('cmdb_ci_unclassed_hardware'); c.addNotNullQuery('u_primary_ait'); c.setWorkflow(false); c.autoSysFields(false); c.setValue('u_primary_ait', ''); c.updateMultiple();
o.ci_clear_ms = new Date().getTime() - t0;
var left = new GlideAggregate('sn_sec_cmn_src_ci'); left.addQuery('cmdb_ci.sys_class_name', 'cmdb_ci_unclassed_hardware'); left.addNotNullQuery('u_primary_ait'); left.addAggregate('COUNT'); left.query(); left.next(); o.dis_left = parseInt(left.getAggregate('COUNT'));
gs.print('X::' + JSON.stringify(o));''')
json.dump(R, open(os.path.join(BASE, 'stories', 'primary-ait-performance', 'benchmark_results.json'), 'w'), indent=1)
