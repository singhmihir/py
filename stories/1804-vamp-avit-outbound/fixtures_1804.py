"""Creates the two fixture application vulnerable items used by test_1804.py with business rules
switched off: one linked to every section source (entry, release with Primary AIT, CI, pen test
request, exception approval, consequence, remediation task through the group item table) and one
with nothing linked. Re-runnable: reuses the records in fixtures.json."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ui = SNUI(); ui.app('global')
fx_path = os.path.join(HERE, 'fixtures.json'); FX = json.load(open(fx_path)) if os.path.exists(fx_path) else {}
LINKS = {'entry': 'db89fb585316301031f7ddeeff7b12ac', 'release': '78922071935b0750e3aef0aefaba10cf', 'ptreq': '11873fd45316301031f7ddeeff7b127c',
         'consequence': 'ccf527da930f8310e3aef0aefaba105e', 'avul': '0059e2cbf9442110f877708ae9db024a'}
d = ui.js('''
var o = {}, fx = %(fx)s, L = %(links)s;
var ci = new GlideRecord('cmdb_ci_business_app'); ci.addQuery('name', 'Trade Processing Portal'); ci.query(); ci.next(); L.ci = ci.getUniqueValue();
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
            exc: '' + b.getDisplayValue('change_approval'), state: '' + b.getDisplayValue('state'), active: '' + b.getValue('active')};
}
o.linked = item('linked', {short_description: 'VAMP outbound fixture (linked)', vulnerability: L.entry, application_release: L.release, cmdb_ci: L.ci, assessment_request: L.ptreq, u_consequence: L.consequence, source_avit_id: 'VAMP-FIXTURE-001'});
var e = new GlideRecord('sn_sec_exception_change_approval');
if (!(fx.exception && e.get(fx.exception))) { e.initialize(); }
e.setWorkflow(false); e.setValue('table', 'sn_vul_app_vulnerable_item'); e.setValue('record', o.linked.sys_id); e.setValue('approval_state', 1); e.setValue('desired_validity_date', '2027-03-31 00:00:00'); e.setValue('description', 'VAMP outbound fixture exception');
var eid = e.isNewRecord() ? e.insert() : (e.update(), e.getUniqueValue());
var e2 = new GlideRecord('sn_sec_exception_change_approval'); e2.get(eid); o.exception = {sys_id: '' + eid, number: '' + e2.getValue('number'), state: '' + e2.getDisplayValue('approval_state'), until: '' + e2.getValue('desired_validity_date')};
var a = new GlideRecord('sn_vul_app_vulnerable_item'); a.get(o.linked.sys_id); a.setWorkflow(false); a.setValue('change_approval', eid); a.update(); o.linked.exc = '' + a.getDisplayValue('change_approval');
var m = new GlideRecord('sn_vul_app_m2m_vul_group_item'); m.addQuery('sn_vul_app_vulnerable_item', o.linked.sys_id); m.addQuery('sn_vul_app_vulnerability', L.avul); m.query();
if (!m.next()) { m.initialize(); m.setWorkflow(false); m.setValue('sn_vul_app_vulnerable_item', o.linked.sys_id); m.setValue('sn_vul_app_vulnerability', L.avul); m.insert(); }
o.m2m = {sys_id: m.getUniqueValue(), avul: '' + m.getDisplayValue('sn_vul_app_vulnerability')};
o.bare = item('bare', {short_description: 'VAMP outbound fixture (bare)'});
o.entry_fields = []; var dd = new GlideRecord('sys_dictionary'); dd.addQuery('name', 'IN', 'sn_vul_entry,sn_vul_app_vul_entry'); dd.addQuery('element', 'IN', 'number,id,name,u_number'); dd.query(); while (dd.next()) o.entry_fields.push('' + dd.getValue('name') + '.' + dd.getValue('element') + ':' + dd.getValue('internal_type'));
var v = new GlideRecord('sn_vul_entry'); v.get(L.entry); o.entry = {id: '' + v.getValue('id'), name: '' + v.getValue('name'), cls: '' + v.getValue('sys_class_name')};
gs.print('X::' + JSON.stringify(o));''' % dict(fx=json.dumps(FX), links=json.dumps(LINKS)))
print(json.dumps(d, indent=1))
assert d['linked']['ait'] == 'AIT57152' and d['linked']['ci'] == 'Trade Processing Portal' and d['linked']['ptreq'] == 'PTREQ0012001' and d['linked']['cons'] == 'CONSEQ-L2-OPEN'
assert d['linked']['exc'] == d['exception']['number'] and d['exception']['state'] == 'Approved' and d['m2m']['avul'] == 'AVUL0010093' and d['linked']['entry']
assert d['bare']['release'] == '' and d['bare']['ci'] == '' and d['bare']['entry'] == '' and d['bare']['exc'] == ''
json.dump({'linked': d['linked']['sys_id'], 'linked_number': d['linked']['number'], 'bare': d['bare']['sys_id'], 'bare_number': d['bare']['number'], 'exception': d['exception']['sys_id'], 'exception_number': d['exception']['number'],
           'm2m': d['m2m']['sys_id'], 'avul': 'AVUL0010093', 'links': LINKS}, open(fx_path, 'w'), indent=1)
print('FIXTURES OK')
