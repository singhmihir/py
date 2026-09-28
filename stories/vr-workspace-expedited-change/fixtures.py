"""PDI stand-ins for what the client instance has, never delivered (captured in the default sets only).
`apply`: (1) the Create Change button needs plugin sn_sow_chg (installed on the client, not here): ChangeMgmt gets an
isITSMAdvancedPluginActive that returns true on top of the delivered script; (2) the client's change model "Expedited"
presetting type expedited, copied from Normal with the platform's Copy Model (states, transitions, conditions).
`remove` puts the delivered ChangeMgmt back and deletes the model copy. Usage: python3 fixtures.py apply|remove"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI

MARK = 'PDI stand-in for the client Expedited change model'
DELIVERED = open(os.path.join(HERE, 'ChangeMgmt.js')).read()
PLUGIN = "    isITSMAdvancedPluginActive: function() {\n        return true;\n    },\n\n"
STAND_IN = DELIVERED.replace("    EXPEDITED: 'expedited',\n", PLUGIN + "    EXPEDITED: 'expedited',\n")
mode = sys.argv[1] if len(sys.argv) > 1 else ''
assert mode in ('apply', 'remove') and STAND_IN != DELIVERED, __doc__
ST = json.load(open(os.path.join(HERE, 'state.json')))
ui = SNUI(); ui.app('global')
r = ui.js('''var __fx = {}; var apply = %(apply)s;
new GlideUpdateSet().set(%(dflt)s);
var si = new GlideRecord('sys_script_include'); si.get('api_name', 'sn_vul.ChangeMgmt'); si.setValue('script', apply ? %(stand_in)s : %(delivered)s); si.update();
__fx.script = si.getValue('script').indexOf('isITSMAdvancedPluginActive') >= 0 ? 'stand-in' : 'delivered';
var m = new GlideRecord('chg_model'); m.addQuery('description', %(mark)s); m.query();
if (apply && !m.next()) {
    var normal = new GlideRecord('chg_model'); normal.get('007c4001c343101035ae3f52c1d3aeb2');
    m = new GlideRecord('chg_model'); m.get(new global.STTRMModel(normal).copy());
    m.setValue('name', 'Expedited'); m.setValue('description', %(mark)s); m.setValue('record_preset', 'type=expedited^EQ'); m.setValue('default_change_model', false);
}
if (apply) { m.setValue('active', true); m.update(); }  // Copy Model leaves the copy inactive
else if (!apply) { while (m.next()) { var st = new GlideRecord('sttrm_state'); st.addQuery('sttrm_model', m.getUniqueValue()); st.deleteMultiple(); m.deleteRecord(); } }
var left = new GlideRecord('chg_model'); left.addQuery('description', %(mark)s); left.query(); __fx.model = left.next() ? left.getValue('name') + ' | active ' + left.getValue('active') + ' | ' + left.getValue('record_preset') + ' | ' + left.getUniqueValue() : 'none';
var sts = new GlideAggregate('sttrm_state'); sts.addQuery('sttrm_model', left.getUniqueValue() || 'none'); sts.addAggregate('COUNT'); sts.query(); sts.next(); __fx.states = sts.getAggregate('COUNT');
gs.print('X::' + JSON.stringify(__fx));''' % dict(apply='true' if mode == 'apply' else 'false', dflt=json.dumps(ST['default_set']), stand_in=json.dumps(STAND_IN),
                                                delivered=json.dumps(DELIVERED), mark=json.dumps(MARK)), scope=ST['scope'])
print(mode, json.dumps(r))
