"""Prepares the PDI for the consequence outbound build with business rules switched off. Ensures the mirror of
the client application (BOFA USEM Consequence, scope x_boar_bofa_usem_0, the client's sys_id, source and vendor
prefix) exists, creates the client's consequence and consequence rule tables in it with the sheet's fields (the
configuration item as a document id with a Class table-name field, as on the client) under the global Default
update set (PDI-only records, never delivered); then the fixture records used by test_1624.py: two rules with
their own authors and times (the checkbox on and off), a consequence linked to the first rule with a CI and an
AIT and every field filled, a bare consequence, one whose rule and AIT are gone and whose CI has no class, one
whose class field names another class than its CI's, linked to the second rule, and one whose CI is gone.
Re-runnable: reuses the records in fixtures.json."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
CONSEQUENCE, RULE, AIT = 'x_boar_bofa_usem_0_consequence', 'x_boar_bofa_usem_0_consequence_rule', 'x_196061_bofasim_ait'   # the client's table names in the mirror application; the AIT stand-in stays where it is
APP = '488be1cd2b1247102b30f8e14391bf0c'   # mirror of the client application BOFA USEM Consequence (x_boar_bofa_usem_0), same sys_id
GLOBAL_DEFAULT_SET = '7dba58ecf54403100a22c0b3dfa151af'   # global Default set: where the stand-in tables were created
ui = SNUI(); ui.app('global')
fx_path = os.path.join(HERE, 'fixtures.json'); FX = json.load(open(fx_path)) if os.path.exists(fx_path) else {}
d = ui.js('''
var o = {steps: [], errors: []}, fx = %(fx)s;
new GlideUpdateSet().set(%(set)s);
var appId = %(app)s;
var app = new GlideRecord('sys_app');
if (!app.get(appId)) {
    app.initialize(); app.setNewGuidValue(appId); app.setValue('name', 'BOFA USEM Consequence'); app.setValue('scope', 'x_boar_bofa_usem_0');
    app.setValue('source', 'x_boar_bofa_usem_0'); app.setValue('vendor_prefix', 'boar'); app.setValue('version', '1.0.0'); app.insert();
    o.steps.push('application x_boar_bofa_usem_0');
} else if (app.getValue('source') != 'x_boar_bofa_usem_0') {
    app.setValue('source', 'x_boar_bofa_usem_0'); app.setWorkflow(false); app.update();   // the exporter stamps this on every sys_scope reference
    o.steps.push('application source set to x_boar_bofa_usem_0');
}
function table(name, label) {
    if (new GlideRecord(name).isValid()) return;
    var t = new GlideRecord('sys_db_object'); t.initialize(); t.setValue('name', name); t.setValue('label', label); t.setValue('sys_scope', appId);
    t.setValue('create_access', true); t.setValue('read_access', true); t.setValue('update_access', true); t.setValue('delete_access', true); t.insert();
    o.steps.push('table ' + name);
}
function col(tableName, element, type, label, extra) {
    var ex = new GlideRecord('sys_dictionary'); ex.addQuery('name', tableName); ex.addQuery('element', element); ex.query();
    if (ex.hasNext()) return;
    var c = new GlideRecord('sys_dictionary'); c.initialize(); c.setValue('name', tableName); c.setValue('element', element); c.setValue('internal_type', type); c.setValue('column_label', label); c.setValue('sys_scope', appId);
    if (type == 'string') c.setValue('max_length', extra && extra.max_length ? extra.max_length : 100);
    if (extra) for (var k in extra) if (k != 'max_length') c.setValue(k, extra[k]);
    c.insert(); o.steps.push('column ' + tableName + '.' + element);
}
function choice(tableName, element, values) {
    for (var v in values) {
        var ch = new GlideRecord('sys_choice'); ch.addQuery('name', tableName); ch.addQuery('element', element); ch.addQuery('value', v); ch.query();
        if (ch.hasNext()) continue;
        ch.initialize(); ch.setValue('name', tableName); ch.setValue('element', element); ch.setValue('value', v); ch.setValue('label', values[v]); ch.setValue('sequence', parseInt(v) * 100); ch.setValue('language', 'en'); ch.setValue('sys_scope', appId); ch.insert();
        o.steps.push('choice ' + tableName + '.' + element + '=' + v);
    }
}
try {
    table(%(cons)s, 'Consequence');
    col(%(cons)s, 'number', 'string', 'Number', {display: true});
    col(%(cons)s, 'state', 'integer', 'State', {choice: 1});
    choice(%(cons)s, 'state', {1: 'Open', 2: 'Deferred', 3: 'Closed', 4: 'Cancelled'});
    col(%(cons)s, 'u_consequence_level', 'string', 'Consequence Level');
    table(%(rule)s, 'Consequence Rule');
    col(%(rule)s, 'number', 'string', 'Number', {display: true});
    col(%(rule)s, 'name', 'string', 'Name');
    col(%(rule)s, 'applies_to', 'string', 'Applies to');
    col(%(rule)s, 'comments', 'string', 'Comments', {max_length: 4000});
    col(%(rule)s, 'conditions', 'string', 'Conditions', {max_length: 4000});
    col(%(rule)s, 'global_exception', 'boolean', 'Global Exception');
    col(%(rule)s, 'state', 'string', 'State');
    col(%(rule)s, 'table', 'string', 'Table');
    col(%(rule)s, 'valid_from', 'glide_date_time', 'Valid from');
    col(%(rule)s, 'valid_to', 'glide_date_time', 'Valid to');
    col(%(cons)s, 'u_accountable_party', 'string', 'Accountable Party');
    col(%(cons)s, 'u_comments', 'string', 'Comments', {max_length: 4000});
    col(%(cons)s, 'u_change_freeze_effective_date', 'glide_date_time', 'Change Freeze Effective Date');
    col(%(cons)s, 'u_enforcement_status', 'integer', 'Enforcement Status', {choice: 1});
    choice(%(cons)s, 'u_enforcement_status', {1: 'Change Frozen', 2: 'Paused', 3: 'Pending Network Isolation Decision', 4: 'Network Isolated'});
    col(%(cons)s, 'u_network_isolation_effective_date', 'glide_date_time', 'Network Isolation Effective Date');
    col(%(cons)s, 'u_rule', 'reference', 'Rule', {reference: %(rule)s});
    col(%(cons)s, 'u_class', 'table_name', 'Class');
    col(%(cons)s, 'cmdb_ci', 'document_id', 'Configuration item', {dependent: 'u_class'});   // as on the client: a document id whose table is the Class field
    col(%(cons)s, 'u_bofa_ait', 'reference', 'AIT', {reference: %(ait)s});
    col(%(cons)s, 'u_rejection_reason', 'string', 'Rejection Reason', {max_length: 1000});
} catch (e) { o.errors.push('schema: ' + e); }
gs.print('X::' + JSON.stringify(o));''' % dict(fx=json.dumps(FX), set=json.dumps(GLOBAL_DEFAULT_SET), rule=json.dumps(RULE), cons=json.dumps(CONSEQUENCE), ait=json.dumps(AIT), app=json.dumps(APP)))
print('schema:', json.dumps(d))
assert not d['errors'], d['errors']
c = ui.js('''
var o = {};
new GlideUpdateSet().set(%(set)s);
var d = new GlideRecord('sys_dictionary'); d.addQuery('name', %(cons)s); d.addQuery('element', 'cmdb_ci'); d.query(); d.next();
if (d.getValue('internal_type') != 'document_id') { d.setValue('internal_type', 'document_id'); d.setValue('reference', ''); d.setValue('dependent', 'u_class'); d.update(); o.changed = true; }
var d2 = new GlideRecord('sys_dictionary'); d2.addQuery('name', %(cons)s); d2.addQuery('element', 'cmdb_ci'); d2.query(); d2.next();
o.cmdb_ci = {type: '' + d2.getValue('internal_type'), dependent: '' + d2.getValue('dependent')};
gs.print('X::' + JSON.stringify(o));''' % dict(set=json.dumps(GLOBAL_DEFAULT_SET), cons=json.dumps(CONSEQUENCE)), scope=APP)
print('configuration item column:', json.dumps(c))
assert c['cmdb_ci'] == {'type': 'document_id', 'dependent': 'u_class'}, c
f = ui.js('''
var o = {}, fx = %(fx)s;
new GlideUpdateSet().set(%(set)s);
var ci = new GlideRecord('cmdb_ci_business_app'); ci.addQuery('name', 'Trade Processing Portal'); ci.query(); ci.next(); var ciId = ci.getUniqueValue();
var ait = new GlideRecord(%(ait)s); ait.addQuery('number', 'AIT57152'); ait.query(); ait.next(); var aitId = ait.getUniqueValue();
var GONE = '00000000000000000000000000000000', GHOST = '11111111111111111111111111111111';
function upsert(tableName, key, values, stamps) {
    var g = new GlideRecord(tableName);
    if (!(fx[key] && g.get(fx[key]))) { g.initialize(); }
    g.setWorkflow(false);
    if (stamps) g.autoSysFields(false);
    for (var f in values) g.setValue(f, values[f]);
    for (var s in stamps || {}) g.setValue(s, stamps[s]);
    var id = g.isNewRecord() ? g.insert() : (g.update(), g.getUniqueValue());
    var b = new GlideRecord(tableName); b.get(id); return b;
}
// the rules carry their own authors and times, so that a value read from the wrong section shows
var r = upsert(%(rule)s, 'rule', {number: 'CQR-FIXTURE-001', name: 'Consequence outbound fixture rule', applies_to: 'New and Existing', comments: 'Consequence outbound fixture rule', conditions: 'u_state=1^EQ', global_exception: true, state: 'Approved', table: 'x_boar_bofa_usem_0_consequence', valid_from: '2026-09-01 00:00:00', valid_to: '2026-12-31 23:59:59'},
    {sys_created_on: '2026-08-20 10:15:00', sys_created_by: 'rule.author', sys_updated_on: '2026-09-02 08:30:45', sys_updated_by: 'rule.editor', sys_mod_count: 3});
var r2 = upsert(%(rule)s, 'rule_off', {number: 'CQR-FIXTURE-002', name: 'Consequence outbound fixture rule without exception', applies_to: 'New', comments: 'Second fixture rule', conditions: 'u_state=2^EQ', global_exception: false, state: 'Draft', table: 'x_boar_bofa_usem_0_consequence', valid_from: '2026-10-01 06:00:00', valid_to: ''},
    {sys_created_on: '2026-08-21 11:00:00', sys_created_by: 'rule.author2', sys_updated_on: '2026-08-21 11:00:00', sys_updated_by: 'rule.author2', sys_mod_count: 0});
o.rule = {sys_id: r.getUniqueValue(), number: '' + r.getValue('number'), display: '' + r.getDisplayValue(), global_exception: '' + r.getValue('global_exception'), created_by: '' + r.getValue('sys_created_by')};
o.rule_off = {sys_id: r2.getUniqueValue(), global_exception: '' + r2.getValue('global_exception')};
var l = upsert(%(cons)s, 'linked', {number: 'CONSEQ-CDP-LINKED', state: 1, u_consequence_level: '1', u_accountable_party: 'Digest Owner One', u_comments: 'Consequence outbound fixture (linked)', u_change_freeze_effective_date: '2026-09-15 12:40:01', u_enforcement_status: 1, u_rule: r.getUniqueValue(), u_class: 'cmdb_ci_business_app', cmdb_ci: ciId, u_bofa_ait: aitId, u_rejection_reason: 'Not rejected'});
o.linked = {sys_id: l.getUniqueValue(), number: '' + l.getValue('number'), rule: '' + l.getDisplayValue('u_rule'), ci: '' + l.cmdb_ci.getRefRecord().getDisplayValue(), ci_type: '' + l.cmdb_ci.getED().getInternalType(), ci_raw: '' + l.getValue('cmdb_ci'), ci_class: '' + l.getValue('u_class'), ait: '' + l.getDisplayValue('u_bofa_ait'), state: '' + l.getDisplayValue('state'), enforcement: '' + l.getDisplayValue('u_enforcement_status'), isolation: '' + l.getValue('u_network_isolation_effective_date')};
var b = upsert(%(cons)s, 'bare', {number: 'CONSEQ-CDP-BARE', state: 1});
o.bare = {sys_id: b.getUniqueValue(), number: '' + b.getValue('number'), rule: '' + b.getDisplayValue('u_rule'), ci: '' + (b.getValue('cmdb_ci') || ''), ait: '' + b.getDisplayValue('u_bofa_ait'), level: '' + (b.getValue('u_consequence_level') || '')};
// a rule and an AIT that are gone, and a configuration item whose class field is empty
var g1 = upsert(%(cons)s, 'dangling', {number: 'CONSEQ-CDP-DANGLING', state: 2, u_consequence_level: '2', u_enforcement_status: 3, u_rule: GONE, u_bofa_ait: GONE, u_class: '', cmdb_ci: ciId, u_network_isolation_effective_date: '2026-10-05 07:05:09'});
o.dangling = {sys_id: g1.getUniqueValue(), number: '' + g1.getValue('number'), rule_raw: '' + g1.getValue('u_rule'), cls: '' + (g1.getValue('u_class') || ''), ci_raw: '' + g1.getValue('cmdb_ci'), ref: '' + (g1.cmdb_ci.getRefRecord() ? g1.cmdb_ci.getRefRecord().isValidRecord() : null)};
// a configuration item whose class field names another class than the record's, linked to the second rule
var g2 = upsert(%(cons)s, 'misclassed', {number: 'CONSEQ-CDP-MISCLASSED', state: 3, u_enforcement_status: 4, u_rule: r2.getUniqueValue(), u_class: 'cmdb_ci_server', cmdb_ci: ciId, u_bofa_ait: aitId});
o.misclassed = {sys_id: g2.getUniqueValue(), number: '' + g2.getValue('number'), ref: '' + (g2.cmdb_ci.getRefRecord() ? g2.cmdb_ci.getRefRecord().isValidRecord() : null)};
// a configuration item that is gone
var g3 = upsert(%(cons)s, 'ghost', {number: 'CONSEQ-CDP-GHOST', state: 4, u_class: 'cmdb_ci_business_app', cmdb_ci: GHOST});
o.ghost = {sys_id: g3.getUniqueValue(), number: '' + g3.getValue('number')};
gs.print('X::' + JSON.stringify(o));''' % dict(fx=json.dumps(FX), set=json.dumps(GLOBAL_DEFAULT_SET), rule=json.dumps(RULE), cons=json.dumps(CONSEQUENCE), ait=json.dumps(AIT)))
print('fixtures:', json.dumps(f, indent=1))
assert f['linked']['rule'] == 'CQR-FIXTURE-001' == f['rule']['display'] and f['linked']['ci'] == 'Trade Processing Portal' and f['linked']['ci_type'] == 'document_id' and len(f['linked']['ci_raw']) == 32 and f['linked']['ci_class'] == 'cmdb_ci_business_app' and f['linked']['ait'] == 'AIT57152' and f['linked']['state'] == 'Open' and f['linked']['enforcement'] == 'Change Frozen' and f['linked']['isolation'] == ''
assert f['bare']['rule'] == '' and f['bare']['ci'] == '' and f['bare']['ait'] == '' and f['bare']['level'] == ''
assert f['rule']['global_exception'] == '1' and f['rule_off']['global_exception'] == '0' and f['rule']['created_by'] == 'rule.author'
assert f['dangling']['rule_raw'] == '0' * 32 and f['dangling']['cls'] == '' and f['dangling']['ci_raw'] == f['linked']['ci_raw'] and f['misclassed']['ref'] != 'true'
json.dump({'rule': f['rule']['sys_id'], 'rule_off': f['rule_off']['sys_id'], 'linked': f['linked']['sys_id'], 'linked_number': f['linked']['number'], 'bare': f['bare']['sys_id'], 'bare_number': f['bare']['number'],
           'dangling': f['dangling']['sys_id'], 'misclassed': f['misclassed']['sys_id'], 'ghost': f['ghost']['sys_id'], 'ci': f['linked']['ci_raw']}, open(fx_path, 'w'), indent=1)
print('FIXTURES OK')
