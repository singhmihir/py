"""Runs William's payload through the platform chain and through every USEM rule individually, printing
what each rule answered. `python3 william_case.py label` keeps the label in the printout."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
QUALYS = 'ed44bdc453220300e8f9f745911c0801'
PAYLOAD = {"ID": "294861802", "IP": "10.223.38.115", "TRACKING_METHOD": "IP", "OS": "Cisco IOS 15.9(3)M7, RELEASE SOFTWARE (fc2)", "OS_CPE": "cpe:/o:cisco:ios:15.9%283%29m7%2C_release_software_%28fc2%29:::", "DNS": "usmabghwt01atr0001.network.bankofamerica.com", "DNS_DATA": "\n          usmabghwt01atr0001\n          network.bankofamerica.com\n          usmabghwt01atr0001.network.bankofamerica.com\n        ", "TAGS": ""}
def run(ui, payload, label=''):
    r = ui.js('''
var __o = {rules: [], chain: {}}; var p = %s;
var ci = new sn_sec_cmn.CIIdentify(); var res = null, err = '';
try { res = ci.identify(%s, p, true); } catch (ex) { err = '' + ex; }
__o.chain.error = err;
if (res && res.lookupRule) { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); __o.chain.rule = rr.getValue('order') + ' ' + rr.getValue('name'); }
if (res && res.ci && res.ci.mainCi) { var c = new GlideRecord('cmdb_ci'); c.get(res.ci.mainCi); __o.chain.ci = c.getValue('name') + ' [' + c.getValue('sys_class_name') + ']'; }
var l = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); l.addQuery('source', %s); l.addQuery('name', 'STARTSWITH', 'USEM'); l.addActiveQuery(); l.orderBy('order'); l.query();
while (l.next()) {
    var v = p[l.getValue('source_field')] || '';
    var ev = new GlideScopedEvaluator(); ev.putVariable('rule', l); ev.putVariable('sourceValue', v); ev.putVariable('sourcePayload', p);
    var out = null, e2 = '';
    try { out = ev.evaluateScript(l, 'script', null); } catch (ex2) { e2 = '' + ex2; }
    var name = '';
    if (out) { var g = new GlideRecord('cmdb_ci'); if (g.get('' + out)) name = g.getValue('name') + ' [' + g.getValue('sys_class_name') + ']'; else name = '' + out; }
    __o.rules.push({order: l.getValue('order'), name: l.getValue('name'), field: l.getValue('source_field'), result: name, error: e2});
}
gs.print('X::' + JSON.stringify(__o));''' % (json.dumps(payload), json.dumps(QUALYS), json.dumps(QUALYS)))
    print('%s chain -> %s %s %s' % (label, r['chain'].get('rule', '(no match)'), r['chain'].get('ci', ''), r['chain'].get('error', '')))
    for x in r['rules']: print('   %-4s %-38s %-4s -> %s%s' % (x['order'], x['name'], x['field'], x['result'] or '-', (' ERROR ' + x['error']) if x['error'] else ''))
    return r
if __name__ == '__main__':
    ui = SNUI(); ui.app('global')
    run(ui, PAYLOAD, sys.argv[1] if len(sys.argv) > 1 else 'William host')
