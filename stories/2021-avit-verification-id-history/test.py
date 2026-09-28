"""SNOWUSEMTP-2021 tests on the PDI. Borrows three application vulnerable items, gives them test Source AVIT IDs (workflow
off), drives the script include and the before rule the way the inbound integration and a user would, checks the field
after each step and the error log lines, then restores the items. Usage: python3 test.py [runs]"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI

TEST = r'''
var SI = new BOFA_SI_VerificationIdHistory();
var out = {checks: [], today: new GlideDate().getByFormat('MM-dd-yyyy')};
var D = ' (' + out.today + ')';
function check(name, got, want) { out.checks.push({name: name, ok: got === want, got: got, want: want}); }
function field(id) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); return g.getValue('u_verification_id') || ''; }
function force(id, values) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); for (var k in values) g.setValue(k, values[k]); g.setWorkflow(false); g.update(); }
function write(id, value) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(id); g.setValue('u_verification_id', value); g.update(); }

// borrow three items, keep what they held
var ids = [], orig = {};
var p = new GlideRecord('sn_vul_app_vulnerable_item'); p.addQuery('u_verification_id', ''); p.orderBy('number'); p.setLimit(3); p.query();
while (p.next()) { ids.push(p.getUniqueValue()); orig[p.getUniqueValue()] = {source_avit_id: p.getValue('source_avit_id') || '', number: p.getValue('number')}; }
out.items = ids.map(function(i) { return orig[i].number + ' ' + i; });
var A = ids[0], B1 = ids[1], B2 = ids[2];
force(A, {source_avit_id: 'VMP-T2021-A', u_verification_id: ''});
force(B1, {source_avit_id: 'VMP-T2021-B', u_verification_id: ''});
force(B2, {source_avit_id: 'VMP-T2021-B', u_verification_id: ''});
gs.sleep(1100); var logStart = new GlideDateTime();

try {
    // the inbound path: find by Source AVIT ID, add the ID
    check('1 first ID on an empty field: 1 item updated', SI.recordVerification('VMP-T2021-A', 'VER-501'), 1);
    check('1 first ID stored with the date', field(A), 'VER-501' + D);
    SI.recordVerification('VMP-T2021-A', 'VER-622');
    check('2 second ID below the first', field(A), 'VER-501' + D + '\nVER-622' + D);
    SI.recordVerification('VMP-T2021-A', 'VER-622');
    check('3 same ID delivered again: not added twice', field(A), 'VER-501' + D + '\nVER-622' + D);
    SI.recordVerification('VMP-T2021-A', '  VER-790  ');
    check('4 third ID, spaces trimmed, oldest stays on top', field(A), 'VER-501' + D + '\nVER-622' + D + '\nVER-790' + D);
    SI.recordVerification('VMP-T2021-A', 'VER-501');
    check('5 an earlier ID again: history unchanged', field(A), 'VER-501' + D + '\nVER-622' + D + '\nVER-790' + D);
    check('6 two items share a Source AVIT ID: both updated', SI.recordVerification('VMP-T2021-B', 'VER-900'), 2);
    check('6 first item of the pair', field(B1), 'VER-900' + D);
    check('6 second item of the pair', field(B2), 'VER-900' + D);
    check('7 unknown Source AVIT ID: nothing updated', SI.recordVerification('VMP-T2021-NONE', 'VER-1'), 0);
    check('8 empty verification ID: nothing updated', SI.recordVerification('VMP-T2021-A', ''), 0);
    check('8 empty verification ID: field unchanged', field(A), 'VER-501' + D + '\nVER-622' + D + '\nVER-790' + D);
    check('9 empty Source AVIT ID: nothing updated', SI.recordVerification('', 'VER-2'), 0);

    // any other writer of the field gets the same history (form, REST, transform map field map)
    force(B1, {u_verification_id: 'VER-100'});
    write(B1, 'VER-200');
    check('10 value from before the change (no date) kept on top', field(B1), 'VER-100\nVER-200' + D);
    write(B1, 'VER-100\nVER-200' + D + '\nVER-300 (09-01-2026)');
    check('11 a user edits the history (several lines): left as written', field(B1), 'VER-100\nVER-200' + D + '\nVER-300 (09-01-2026)');
    write(B2, 'VER-555 (09-15-2026)');
    check('12 a user types one stamped entry: left as written', field(B2), 'VER-555 (09-15-2026)');
    write(B2, '');
    check('13 a user clears the field: stays empty', field(B2), '');
    write(B2, 'VER-600');
    check('14 new ID after the field was cleared', field(B2), 'VER-600' + D);

    // insert: no previous record
    var n = new GlideRecord('sn_vul_app_vulnerable_item'); n.initialize(); n.setValue('u_verification_id', 'VER-700');
    SI.appendToHistory(n, null);
    check('15 insert with an ID (no previous record)', n.getValue('u_verification_id'), 'VER-700' + D);

    // the rule honours an aborted save
    var br = new GlideRecord('sys_script'); br.addQuery('name', 'BOFA_BR_AVIT_VerificationIdHistory'); br.query(); br.next();
    check('16 rule: before, order 1000, insert and update, only when the field changes',
          [br.getValue('when'), br.getValue('order'), br.getValue('action_insert'), br.getValue('action_update'), br.getValue('filter_condition')].join(' '),
          'before 1000 1 1 u_verification_idVALCHANGES^EQ');
    var dic = new GlideRecord('sys_dictionary'); dic.addQuery('name', 'sn_vul_app_vulnerable_item'); dic.addQuery('element', 'u_verification_id'); dic.query(); dic.next();
    check('17 field: string, 4000 characters (multi-line on the form)', dic.getValue('internal_type') + ' ' + dic.getValue('max_length'), 'string 4000');

    // error log lines, one per refused call
    var logs = []; var l = new GlideRecord('syslog'); l.addQuery('sys_created_on', '>=', logStart); l.addQuery('message', 'STARTSWITH', 'BOFA_SI_VerificationIdHistory'); l.orderBy('sys_created_on'); l.query();
    while (l.next()) logs.push(l.getValue('level') + ' ' + l.getValue('message'));
    out.logs = logs;
    check('18 three refused calls, three error lines', logs.length, 3);
    var want = ['2 BOFA_SI_VerificationIdHistory: verification ID VER-1 not recorded for sn_vul_app_vulnerable_item source_avit_id VMP-T2021-NONE - no application vulnerable item has this Source AVIT ID',
                '2 BOFA_SI_VerificationIdHistory: verification ID  not recorded for sn_vul_app_vulnerable_item source_avit_id VMP-T2021-A - no verification ID was given',
                '2 BOFA_SI_VerificationIdHistory: verification ID VER-2 not recorded for sn_vul_app_vulnerable_item source_avit_id  - no Source AVIT ID was given'];
    // lines written within one second come back in either order
    check('18 the three error lines, one per refusal', logs.slice().sort().join('\n'), want.slice().sort().join('\n'));
    out.sample = field(A);
} finally {
    for (var i = 0; i < ids.length; i++) force(ids[i], {source_avit_id: orig[ids[i]].source_avit_id, u_verification_id: ''});
    out.restored = ids.map(function(i) { var g = new GlideRecord('sn_vul_app_vulnerable_item'); g.get(i); return g.getValue('number') + ' ' + (g.getValue('source_avit_id') || '') + ' [' + (g.getValue('u_verification_id') || '') + ']'; });
}
gs.print('X::' + JSON.stringify(out));
'''

runs = int(sys.argv[1]) if len(sys.argv) > 1 else 2
ui = SNUI(); ui.app('global')
results = []
for run in range(1, runs + 1):
    r = ui.js(TEST)
    ok = sum(c['ok'] for c in r['checks'])
    print('run %d: %d/%d checks | items %s | restored %s' % (run, ok, len(r['checks']), r['items'], r['restored']))
    for c in r['checks']:
        if not c['ok']:
            print('  FAIL', c['name'], '| got', repr(c['got']), '| want', repr(c['want']))
    results.append({'run': run, 'passed': ok, 'total': len(r['checks']), 'checks': r['checks'], 'logs': r.get('logs'), 'sample': r.get('sample')})
print('field after step 4:\n' + results[-1]['sample'])
json.dump(results, open(os.path.join(HERE, 'test_results.json'), 'w'), indent=1)
sys.exit(0 if all(x['passed'] == x['total'] for x in results) else 1)
