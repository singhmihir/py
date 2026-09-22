"""Plural fixtures for the remediation task payload, with business rules switched off: on each of the
four remediation task tables, one task with no link, one with a single change request, and one with
several change requests linked out of number order, the same change linked twice, a cancelled change,
a change of the child class change_request_imac and a link whose change is gone; exception approvals
on the plural task in the approved, expired and one other state, and one approval for another record;
two additional comments a minute apart, a four-digit total and a change count held as display markup
on the plural task, to measure how journals, counts and markup render on a record loaded afresh.
Global Default update set, never delivered. Re-runnable: reuses the records in fixtures.json."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ui = SNUI(); ui.app('global')
fx_path = os.path.join(HERE, 'fixtures.json'); FX = json.load(open(fx_path)) if os.path.exists(fx_path) else {}
GLOBAL_DEFAULT_SET = '7dba58ecf54403100a22c0b3dfa151af'
LINKS = {'sn_vul_vulnerability': ['sn_vul_m2m_vg_change_request', 'sn_vul_vulnerability'],
         'sn_vul_app_vulnerability': ['sn_vul_app_m2m_vg_change_request', 'sn_vul_app_vulnerability'],
         'sn_vul_container_vulnerability': ['sn_vul_container_m2m_remediation_task_change_request', 'sn_vul_container_vulnerability'],
         'sn_vulc_result_group': ['sn_vulc_m2m_trg_change_request', 'result_group']}
d = ui.js(r'''
(function() {
var o = {tables: {}, changes: {}, errors: []}, fx = %(fx)s, LINKS = %(links)s;
new GlideUpdateSet().set(%(set)s);
function keep(table, key, values) {
    var g = new GlideRecord(table);
    var found = fx.ids && fx.ids[key] && g.get(fx.ids[key]);
    if (!found && values.short_description) {
        g = new GlideRecord(table); g.addQuery('short_description', values.short_description); g.orderBy('sys_created_on'); g.query(); found = g.next();
    }
    if (!found && values.description && table == 'sn_sec_exception_change_approval') {
        g = new GlideRecord(table); g.addQuery('description', values.description); g.addQuery('record', values.record); g.query(); found = g.next();
    }
    if (!found) { g = new GlideRecord(table); g.initialize(); }
    g.setWorkflow(false);
    for (var f in values) g.setValue(f, values[f]);
    var id = g.isNewRecord() ? g.insert() : (g.update(), g.getUniqueValue());
    if (!id) o.errors.push(key + ': ' + g.getLastErrorMessage());
    return '' + id;
}
o.ids = {};
// four change requests, created in this order so that their numbers rise: open, closed, cancelled, imac
o.ids.chg_open = keep('change_request', 'chg_open', {short_description: 'Payload fixture change (open)', state: -5});
o.ids.chg_closed = keep('change_request', 'chg_closed', {short_description: 'Payload fixture change (closed)', state: 3});
o.ids.chg_cancelled = keep('change_request', 'chg_cancelled', {short_description: 'Payload fixture change (cancelled)', state: 4});
o.ids.chg_imac = keep('change_request_imac', 'chg_imac', {short_description: 'Payload fixture change (IMAC class)', state: -5});
for (var k in {chg_open: 1, chg_closed: 1, chg_cancelled: 1, chg_imac: 1}) {
    var c = new GlideRecord('change_request'); c.get(o.ids[k]);
    o.changes[k] = {number: '' + c.getValue('number'), state: '' + c.getValue('state'), cls: '' + c.getValue('sys_class_name')};
}
function link(assoc, field, task, change, key) {
    var m = new GlideRecord(assoc);
    var found = fx.ids && fx.ids[key] && m.get(fx.ids[key]);
    if (!found && !/_again$/.test(key)) { m = new GlideRecord(assoc); m.addQuery(field, task); m.addQuery('change_request', change); m.orderBy('sys_created_on'); m.query(); found = m.next(); }
    if (!found && /_again$/.test(key)) { m = new GlideRecord(assoc); m.addQuery(field, task); m.addQuery('change_request', change); m.orderBy('sys_created_on'); m.query(); m.next(); found = m.next(); }
    if (!found) { m = new GlideRecord(assoc); m.initialize(); }
    m.setWorkflow(false); m.setValue(field, task); m.setValue('change_request', change);
    var id = m.isNewRecord() ? m.insert() : (m.update(), m.getUniqueValue());
    if (!id) o.errors.push(key + ': ' + m.getLastErrorMessage());
    o.ids[key] = '' + id;
}
for (var t in LINKS) {
    var assoc = LINKS[t][0], field = LINKS[t][1];
    var bare = keep(t, t + '.bare', {short_description: 'Payload fixture ' + t + ' (no change)'});
    var single = keep(t, t + '.single', {short_description: 'Payload fixture ' + t + ' (one change)'});
    var plural = keep(t, t + '.plural', {short_description: 'Payload fixture ' + t + ' (several changes)'});
    o.ids[t + '.bare'] = bare; o.ids[t + '.single'] = single; o.ids[t + '.plural'] = plural;
    link(assoc, field, single, o.ids.chg_open, t + '.single.open');
    // out of number order, the open change twice, a cancelled one, the IMAC class, and one gone
    link(assoc, field, plural, o.ids.chg_imac, t + '.plural.imac');
    link(assoc, field, plural, o.ids.chg_closed, t + '.plural.closed');
    link(assoc, field, plural, o.ids.chg_open, t + '.plural.open');
    link(assoc, field, plural, o.ids.chg_open, t + '.plural.open_again');
    link(assoc, field, plural, o.ids.chg_cancelled, t + '.plural.cancelled');
    link(assoc, field, plural, '00000000000000000000000000000000', t + '.plural.gone');
    // exception approvals raised for the plural task: approved, expired, requested; one for the bare task
    var states = {approved: 1, expired: 4, requested: 2};
    for (var s in states)
        o.ids[t + '.exc.' + s] = keep('sn_sec_exception_change_approval', t + '.exc.' + s,
            {table: t, record: plural, approval_state: states[s], description: 'Payload fixture exception (' + s + ')', desired_validity_date: '2027-03-31 00:00:00'});
    o.ids[t + '.exc.other'] = keep('sn_sec_exception_change_approval', t + '.exc.other',
        {table: t, record: bare, approval_state: 1, description: 'Payload fixture exception (other record)', desired_validity_date: '2027-03-31 00:00:00'});
    // two comments, the second the latest, and a count above 999 (rules off, so nothing recalculates it)
    var pl = new GlideRecord(t); pl.get(plural);
    var jc = new GlideAggregate('sys_journal_field'); jc.addQuery('element_id', plural); jc.addQuery('element', 'comments'); jc.addAggregate('COUNT'); jc.query(); jc.next();
    if (parseInt(jc.getAggregate('COUNT')) < 2) {
        pl.comments = 'Payload fixture comment one'; pl.update();
        pl = new GlideRecord(t); pl.get(plural); pl.comments = 'Payload fixture comment two'; pl.update();
    }
    // the second comment one minute after the first, so that the latest entry is never a tie
    var two = new GlideRecord('sys_journal_field'); two.addQuery('element_id', plural); two.addQuery('element', 'comments'); two.addQuery('value', 'Payload fixture comment two'); two.query();
    var one = new GlideRecord('sys_journal_field'); one.addQuery('element_id', plural); one.addQuery('element', 'comments'); one.addQuery('value', 'Payload fixture comment one'); one.query();
    if (two.next() && one.next()) {
        var earlier = new GlideDateTime(two.getValue('sys_created_on')); earlier.addSeconds(-60);
        one.autoSysFields(false); one.setWorkflow(false); one.setValue('sys_created_on', earlier.getValue()); one.update();
    }
    o.ids[t + '.commented'] = plural;
    var cnt1 = new GlideRecord(t); cnt1.get(plural); cnt1.setWorkflow(false);
    if (cnt1.isValidField('total_vis')) cnt1.setValue('total_vis', 1250);
    if (cnt1.isValidField('reassignment_count')) cnt1.setValue('reassignment_count', 1250);
    // the change count as the platform stores it: display markup around a link
    if (cnt1.isValidField('cr_count')) cnt1.setValue('cr_count', '[code]<a href="/nav_to.do?uri=%%2Fchange_request_list.do%%3Fsysparm_query%%3Dsys_idIN' + o.ids.chg_open + '%%2C' + o.ids.chg_closed + '%%2C' + o.ids.chg_imac + '" target="_parent">3</a>[/code]');
    cnt1.update();
    var fresh = new GlideRecord(t); fresh.get(plural);
    o.measure = o.measure || {};
    o.measure[t] = {comments_nil: fresh.comments.nil(), comments_value: '' + (fresh.getValue('comments') || ''), entry1: '' + fresh.comments.getJournalEntry(1),
        journal_rows: (function() { var j = new GlideAggregate('sys_journal_field'); j.addQuery('element_id', plural); j.addQuery('element', 'comments'); j.addAggregate('COUNT'); j.query(); j.next(); return parseInt(j.getAggregate('COUNT')); })(),
        reassign_value: '' + fresh.getValue('reassignment_count'), reassign_display: '' + fresh.getDisplayValue('reassignment_count'),
        cr_count_value: fresh.isValidField('cr_count') ? '' + fresh.getValue('cr_count') : 'no field'};
    var nums = {};
    for (var n in {bare: 1, single: 1, plural: 1}) { var g = new GlideRecord(t); g.get(o.ids[t + '.' + n]); nums[n] = '' + g.getValue('number'); }
    var ex = {};
    for (var e in {approved: 1, expired: 1, requested: 1, other: 1}) { var x = new GlideRecord('sn_sec_exception_change_approval'); x.get(o.ids[t + '.exc.' + e]); ex[e] = {number: '' + x.getValue('number'), state: '' + x.getValue('approval_state')}; }
    var cnt = new GlideAggregate(assoc); cnt.addQuery(field, plural); cnt.addAggregate('COUNT'); cnt.query(); cnt.next();
    o.tables[t] = {numbers: nums, exceptions: ex, plural_links: parseInt(cnt.getAggregate('COUNT'))};
}
gs.print('X::' + JSON.stringify(o));
})();''' % dict(fx=json.dumps(FX), links=json.dumps(LINKS), set=json.dumps(GLOBAL_DEFAULT_SET)))
print(json.dumps(d, indent=1))
assert not d['errors'], d['errors']
ch = d['changes']
assert ch['chg_cancelled']['state'] == '4' and ch['chg_imac']['cls'] == 'change_request_imac'
nums = sorted([ch['chg_open']['number'], ch['chg_closed']['number'], ch['chg_imac']['number']])
for t, v in d['tables'].items():
    assert v['plural_links'] == 6, (t, v)
exp = {t: {'bare': '', 'single': ch['chg_open']['number'], 'plural': ','.join(nums)} for t in LINKS}
exc = {t: {'bare': '', 'single': '', 'plural': ','.join(sorted([v['exceptions']['approved']['number'], v['exceptions']['expired']['number']]))} for t, v in d['tables'].items()}
for t in LINKS:
    other = d['tables'][t]['exceptions']['other']['number']
    exc[t]['bare'] = other
json.dump({'ids': d['ids'], 'changes': ch, 'tables': d['tables'], 'expected_change_requests': exp, 'expected_exception_requests': exc, 'measure': d.get('measure', {})}, open(fx_path, 'w'), indent=1)
print('FIXTURES OK')
