"""Prepares the PDI for the VAMP outbound build with business rules switched off. Adds the sheet's
custom fields to the vulnerability tables as stand-ins for the client's (global Default update set,
PDI only, never delivered), then the fixture records used by test_1804.py: one application vulnerable
item linked to every section source (an entry of the extended class sn_vul_app_vul_entry, a release
with a Primary AIT, a CI, a pen test request, an exception approval, a consequence and TWO remediation
tasks through the group item table) and one with nothing linked. Re-runnable: reuses the records in
fixtures.json."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ui = SNUI(); ui.app('global')
fx_path = os.path.join(HERE, 'fixtures.json'); FX = json.load(open(fx_path)) if os.path.exists(fx_path) else {}
GLOBAL_DEFAULT_SET = '7dba58ecf54403100a22c0b3dfa151af'   # global Default set: where the stand-in columns were created
LINKS = {'release': '78922071935b0750e3aef0aefaba10cf', 'ptreq': '11873fd45316301031f7ddeeff7b127c',
         'consequence': 'ccf527da930f8310e3aef0aefaba105e', 'avul': '0059e2cbf9442110f877708ae9db024a'}
d = ui.js('''
var o = {steps: [], errors: []}, fx = %(fx)s, L = %(links)s;
new GlideUpdateSet().set(%(set)s);
// the sheet's custom fields, as they are expected on the client instance
function col(table, element, type, label, reference) {
    var ex = new GlideRecord('sys_dictionary'); ex.addQuery('name', table); ex.addQuery('element', element); ex.query();
    if (ex.hasNext()) return;
    var c = new GlideRecord('sys_dictionary'); c.initialize();
    c.setValue('name', table); c.setValue('element', element); c.setValue('internal_type', type); c.setValue('column_label', label);
    if (type == 'string') c.setValue('max_length', 255);
    if (reference) c.setValue('reference', reference);
    var id = c.insert();
    if (!id) { o.errors.push(table + '.' + element + ': ' + c.getLastErrorMessage()); return; }
    o.steps.push('column ' + table + '.' + element);
}
col('sn_vul_app_vul_entry', 'u_vuln_sub_cat_id', 'string', 'Vulnerability sub category ID');
col('sn_vul_app_vulnerability', 'u_avul_record_url', 'string', 'AVUL record URL');
col('sn_vul_app_vulnerability', 'u_primary_ait', 'reference', 'Primary AIT', 'x_196061_bofasim_ait');
col('sn_vul_app_vulnerable_item', 'u_verification_status', 'string', 'Verification status');
col('sn_vul_app_vulnerable_item', 'u_avit_record_url', 'string', 'AVIT record URL');
col('sn_vul_pen_test_assessment_request', 'u_assessment_id', 'string', 'Assessment ID');

var ci = new GlideRecord('cmdb_ci_business_app'); ci.addQuery('name', 'Trade Processing Portal'); ci.query(); ci.next(); L.ci = ci.getUniqueValue();
var ait = new GlideRecord('x_196061_bofasim_ait'); ait.addQuery('number', 'AIT57152'); ait.query(); ait.next(); L.ait = ait.getUniqueValue();
// the entry of the extended class: its sub category id is a field of sn_vul_app_vul_entry only, never of sn_vul_entry
var entry = new GlideRecord('sn_vul_app_vul_entry');
if (!(fx.links && fx.links.entry && entry.get(fx.links.entry) && entry.getValue('sys_class_name') == 'sn_vul_app_vul_entry')) {
    entry = new GlideRecord('sn_vul_app_vul_entry'); entry.orderBy('sys_created_on'); entry.setLimit(1); entry.query(); entry.next();
}
entry.setWorkflow(false); entry.setValue('u_vuln_sub_cat_id', 'VSC-4471'); entry.update();
L.entry = entry.getUniqueValue();
o.entry = {sys_id: '' + L.entry, cls: '' + entry.getValue('sys_class_name'), display: '' + entry.getDisplayValue(),
    sub_cat: '' + entry.getValue('u_vuln_sub_cat_id'), on_base: new GlideRecord('sn_vul_entry').isValidField('u_vuln_sub_cat_id'),
    on_class: new GlideRecord('sn_vul_app_vul_entry').isValidField('u_vuln_sub_cat_id')};

var p = new GlideRecord('sn_vul_pen_test_assessment_request'); p.get(L.ptreq); p.setWorkflow(false); p.setValue('u_assessment_id', 'ASMT-90210'); p.update();
o.ptreq = {number: '' + p.getValue('number'), assessment: '' + p.getValue('u_assessment_id')};

function item(key, values) {
    var a = new GlideRecord('sn_vul_app_vulnerable_item');
    if (!(fx[key] && a.get(fx[key]))) { a.initialize(); }
    a.setWorkflow(false);
    for (var f in values) a.setValue(f, values[f]);
    a.setValue('active', true); a.setValue('state', 1); a.setValue('source', 'VAMP fixture');
    var id = a.isNewRecord() ? a.insert() : (a.update(), a.getUniqueValue());
    var b = new GlideRecord('sn_vul_app_vulnerable_item'); b.get(id);
    return {sys_id: '' + id, number: '' + b.getValue('number'), release: '' + b.getDisplayValue('application_release'), ait: '' + b.application_release.u_primary_ait.getDisplayValue(),
            ci: '' + b.getDisplayValue('cmdb_ci'), entry: '' + b.getDisplayValue('vulnerability'), ptreq: '' + b.getDisplayValue('assessment_request'), cons: '' + b.getDisplayValue('u_consequence'),
            exc: '' + b.getDisplayValue('change_approval'), state: '' + b.getDisplayValue('state'), active: '' + b.getValue('active'),
            status: '' + (b.getValue('u_verification_status') || ''), url: '' + (b.getValue('u_avit_record_url') || '')};
}
o.linked = item('linked', {short_description: 'VAMP outbound fixture (linked)', vulnerability: L.entry, application_release: L.release, cmdb_ci: L.ci,
    assessment_request: L.ptreq, u_consequence: L.consequence, source_avit_id: 'VAMP-FIXTURE-001',
    u_verification_status: 'Pending Validation', u_avit_record_url: 'https://example.invalid/avit/VAMP-FIXTURE-001'});

var e = new GlideRecord('sn_sec_exception_change_approval');
if (!(fx.exception && e.get(fx.exception))) { e.initialize(); }
e.setWorkflow(false); e.setValue('table', 'sn_vul_app_vulnerable_item'); e.setValue('record', o.linked.sys_id); e.setValue('approval_state', 1); e.setValue('desired_validity_date', '2027-03-31 00:00:00'); e.setValue('description', 'VAMP outbound fixture exception');
var eid = e.isNewRecord() ? e.insert() : (e.update(), e.getUniqueValue());
var e2 = new GlideRecord('sn_sec_exception_change_approval'); e2.get(eid); o.exception = {sys_id: '' + eid, number: '' + e2.getValue('number'), state: '' + e2.getDisplayValue('approval_state')};
var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(o.linked.sys_id); a.setWorkflow(false); a.setValue('change_approval', eid); a.update(); o.linked.exc = '' + a.getDisplayValue('change_approval');

// two remediation tasks on the linked item: the payload must carry both
function task(key, values) {
    var t = new GlideRecord('sn_vul_app_vulnerability');
    if (!(fx.tasks && fx.tasks[key] && t.get(fx.tasks[key]))) { t.initialize(); }
    t.setWorkflow(false);
    for (var f in values) t.setValue(f, values[f]);
    var id = t.isNewRecord() ? t.insert() : (t.update(), t.getUniqueValue());
    var g = new GlideRecord('sn_vul_app_vulnerability'); g.get(id);
    return {sys_id: '' + id, number: '' + g.getValue('number'), ait: '' + g.getDisplayValue('u_primary_ait'), url: '' + g.getValue('u_avul_record_url')};
}
var first = new GlideRecord('sn_vul_app_vulnerability'); first.get(L.avul);
first.setWorkflow(false); first.setValue('u_primary_ait', L.ait); first.setValue('u_avul_record_url', 'https://example.invalid/avul/' + first.getValue('number')); first.update();
o.tasks = {first: {sys_id: '' + L.avul, number: '' + first.getValue('number'), ait: '' + first.getDisplayValue('u_primary_ait'), url: '' + first.getValue('u_avul_record_url')}};
o.tasks.second = task('second', {short_description: 'VAMP outbound fixture (second remediation task)', u_primary_ait: L.ait,
    u_avul_record_url: 'https://example.invalid/avul/second', state: 1});
var second = new GlideRecord('sn_vul_app_vulnerability'); second.get(o.tasks.second.sys_id);
second.setWorkflow(false); second.setValue('u_avul_record_url', 'https://example.invalid/avul/' + second.getValue('number')); second.update();
o.tasks.second.url = '' + second.getValue('u_avul_record_url');
function link(taskId) {
    var m = new GlideRecord('sn_vul_app_m2m_vul_group_item');
    m.addQuery('sn_vul_app_vulnerable_item', o.linked.sys_id); m.addQuery('sn_vul_app_vulnerability', taskId); m.query();
    if (!m.next()) { m.initialize(); m.setWorkflow(false); m.setValue('sn_vul_app_vulnerable_item', o.linked.sys_id); m.setValue('sn_vul_app_vulnerability', taskId); m.insert(); }
    return '' + m.getUniqueValue();
}
o.m2m = {first: link(L.avul), second: link(o.tasks.second.sys_id)};
var count = new GlideAggregate('sn_vul_app_m2m_vul_group_item'); count.addQuery('sn_vul_app_vulnerable_item', o.linked.sys_id); count.addAggregate('COUNT'); count.query(); count.next();
o.linked_tasks = parseInt(count.getAggregate('COUNT'));

o.bare = item('bare', {short_description: 'VAMP outbound fixture (bare)', u_verification_status: '', u_avit_record_url: ''});
var bareCount = new GlideAggregate('sn_vul_app_m2m_vul_group_item'); bareCount.addQuery('sn_vul_app_vulnerable_item', o.bare.sys_id); bareCount.addAggregate('COUNT'); bareCount.query(); bareCount.next();
o.bare_tasks = parseInt(bareCount.getAggregate('COUNT'));
o.links = L;
gs.print('X::' + JSON.stringify(o));''' % dict(fx=json.dumps(FX), links=json.dumps(LINKS), set=json.dumps(GLOBAL_DEFAULT_SET)))
print(json.dumps(d, indent=1))
assert not d['errors'], d['errors']
assert d['entry']['cls'] == 'sn_vul_app_vul_entry' and d['entry']['sub_cat'] == 'VSC-4471' and d['entry']['on_class'] and not d['entry']['on_base'], d['entry']
assert d['linked']['ait'] == 'AIT57152' and d['linked']['ci'] == 'Trade Processing Portal' and d['linked']['ptreq'] == 'PTREQ0012001' and d['linked']['cons'] == 'CONSEQ-L2-OPEN'
assert d['linked']['exc'] == d['exception']['number'] and d['exception']['state'] == 'Approved' and d['linked']['entry']
assert d['linked']['status'] == 'Pending Validation' and d['linked']['url'].endswith('VAMP-FIXTURE-001')
assert d['linked_tasks'] == 2 and d['tasks']['first']['number'] != d['tasks']['second']['number'], (d['linked_tasks'], d['tasks'])
assert d['tasks']['first']['ait'] == d['tasks']['second']['ait'] == 'AIT57152' and d['tasks']['first']['url'] and d['tasks']['second']['url']
assert d['bare']['release'] == '' and d['bare']['ci'] == '' and d['bare']['entry'] == '' and d['bare']['exc'] == '' and d['bare_tasks'] == 0
tasks = {k: v['sys_id'] for k, v in d['tasks'].items()}
order = sorted([d['tasks']['first'], d['tasks']['second']], key=lambda t: t['number'])
json.dump({'linked': d['linked']['sys_id'], 'linked_number': d['linked']['number'], 'bare': d['bare']['sys_id'], 'bare_number': d['bare']['number'],
           'exception': d['exception']['sys_id'], 'exception_number': d['exception']['number'], 'm2m': d['m2m'], 'tasks': tasks,
           'task_numbers': [t['number'] for t in order], 'task_urls': [t['url'] for t in order], 'task_ait': 'AIT57152',
           'entry_sub_cat': d['entry']['sub_cat'], 'entry_display': d['entry']['display'], 'ptreq_assessment': d['ptreq']['assessment'],
           'avul': d['tasks']['first']['number'], 'links': d['links']}, open(fx_path, 'w'), indent=1)
print('FIXTURES OK')
