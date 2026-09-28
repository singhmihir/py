"""Expedited change from the VR workspace, as one update set batch:
- parent (Global) `SNOWUSEMTP_MS_VR Workspace Expedited Change_V1.0`: the change_request Type choice list with Expedited;
- child (Vulnerability Response): the workspace page "Modal - Create Change Request" with the item Expedited (value
  expedited) in its Change type picker, and sn_vul ChangeMgmt overriding createNewChangeRequest so an Expedited change is
  created through the change API from the client's Expedited change model (ChangeMgmt.js).
Idempotent. Usage: python3 build.py"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI

NAME = 'SNOWUSEMTP_MS_VR Workspace Expedited Change_V1.0'
CHILD = 'SNOWUSEMTP_MS_VR Workspace Expedited Change - Vulnerability Response_V1.0'
DESC = ('Expedited change from the Vulnerability Response workspace. This set carries the change_request Type choice list with '
        'Expedited (value expedited); its child set carries the Create Change dialog item and the ChangeMgmt override.')
CHILD_DESC = ('The Create Change dialog of the workspace (page Modal - Create Change Request) offers Expedited next to Standard, '
              'Normal and Emergency, and ChangeMgmt.createNewChangeRequest creates an Expedited change through the change API '
              'from the change model that presets the Expedited type, for the workspace dialog and the classic Create Change form alike.')
PAGE = '59061b92b7072010aed5b064ce11a92c'
ITEM = {'id': 'expedited', 'label': 'Expedited', 'sublabel': 'Create an expedited Change Request.'}
SCRIPT = open(os.path.join(HERE, 'ChangeMgmt.js')).read()
ST_PATH = os.path.join(HERE, 'state.json')
ST = json.load(open(ST_PATH)) if os.path.exists(ST_PATH) else {}

ui = SNUI(); ui.app('global')
g = ui.js('''var o = {};
var s = new GlideRecord('sys_scope'); s.get('scope', 'sn_vul'); o.scope = s.getUniqueValue();
var d = new GlideRecord('sys_update_set'); d.addQuery('application', o.scope); d.addQuery('is_default', true); d.query(); d.next(); o.dflt = d.getUniqueValue();
var gd = new GlideRecord('sys_update_set'); gd.addQuery('application', 'global'); gd.addQuery('is_default', true); gd.query(); gd.next(); o.global_dflt = gd.getUniqueValue();
var p = new GlideRecord('sys_update_set');
if (%(parent)s && p.get(%(parent)s)) { p.setValue('state', 'in progress'); p.update(); }
else { p.initialize(); p.setValue('name', %(name)s); p.setValue('application', 'global'); p.setValue('description', %(desc)s); p.insert(); p.setValue('base_update_set', p.getUniqueValue()); p.update(); }
o.parent = p.getUniqueValue();
var c = new GlideRecord('sys_update_set');
if (%(child)s && c.get(%(child)s)) c.setValue('state', 'in progress');
else { c.initialize(); c.setValue('application', o.scope); }
c.setValue('name', %(child_name)s); c.setValue('description', %(child_desc)s); c.setValue('parent', o.parent); c.setValue('base_update_set', o.parent);
o.child = c.isNewRecord() ? '' + c.insert() : (c.update(), c.getUniqueValue());

new GlideUpdateSet().set(o.parent);
var ch = new GlideRecord('sys_choice'); ch.addQuery('name', 'change_request'); ch.addQuery('element', 'type'); ch.addQuery('value', 'expedited'); ch.addQuery('language', 'en'); ch.query();
if (!ch.next()) { ch.initialize(); ch.setValue('name', 'change_request'); ch.setValue('element', 'type'); ch.setValue('value', 'expedited'); ch.setValue('label', 'Expedited'); ch.setValue('language', 'en'); ch.setValue('sequence', 4); ch.insert(); }
new GlideUpdateManager2().saveRecord(ch);
new GlideUpdateSet().set(o.global_dflt);
gs.print('X::' + JSON.stringify(o));''' % dict(parent=json.dumps(ST.get('parent', '')), name=json.dumps(NAME), desc=json.dumps(DESC),
                                               child=json.dumps(ST.get('set', '')), child_name=json.dumps(CHILD), child_desc=json.dumps(CHILD_DESC)))

d = ui.js('''var o = {rows: []}; var item = %(item)s;
new GlideUpdateSet().set(%(child)s);
var um = new GlideUpdateManager2();
var m = new GlideRecord('sys_ux_macroponent'); m.get(%(page)s);
var comp = JSON.parse(m.getValue('composition'));
function find(list) {
    for (var i = 0; i < list.length; i++) {
        if (list[i].elementId == 'change_type') return list[i];
        var sub = list[i].overrides && list[i].overrides.composition ? find(list[i].overrides.composition) : null;
        if (sub) return sub;
    }
    return null;
}
var items = find(comp).propertyValues.items.container;
function text(v) { return {type: 'TRANSLATION_LITERAL', value: {code: null, comment: '', message: v}}; }
if (!items.some(function (x) { return x.container.id.value == item.id; })) {
    items.push({container: {id: {type: 'JSON_LITERAL', value: item.id}, label: text(item.label), sublabel: text(item.sublabel)}, type: 'MAP_CONTAINER'});
    var tr = JSON.parse(m.getValue('required_translations') || '[]');
    [item.label, item.sublabel].forEach(function (msg) { if (!tr.some(function (t) { return t.message == msg; })) tr.push({message: msg, code: '', comment: ''}); });
    tr.sort(function (a, b) { return a.message < b.message ? -1 : a.message > b.message ? 1 : 0; });
    m.setValue('composition', JSON.stringify(comp)); m.setValue('required_translations', JSON.stringify(tr)); m.update();
}
um.saveRecord(m);
o.items = items.map(function (x) { return x.container.id.value; });
var si = new GlideRecord('sys_script_include'); si.get('api_name', 'sn_vul.ChangeMgmt');
if (si.getValue('script') != %(script)s) { si.setValue('script', %(script)s); si.update(); }
um.saveRecord(si);
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', 'IN', %(sets)s); ux.orderBy('name'); ux.query();
while (ux.next()) o.rows.push(ux.update_set.getDisplayValue() + ' | ' + ux.getValue('name') + ' | ' + ux.getValue('target_name') + ' | ' + ux.application.getDisplayValue());
new GlideUpdateSet().set(%(dflt)s);
gs.print('X::' + JSON.stringify(o));''' % dict(item=json.dumps(ITEM), child=json.dumps(g['child']), page=json.dumps(PAGE), script=json.dumps(SCRIPT),
                                               sets=json.dumps(g['parent'] + ',' + g['child']), dflt=json.dumps(g['dflt'])), scope=g['scope'])
print('parent', g['parent'], '| child', g['child'], '| change type items:', ', '.join(d['items'])); print('\n'.join('  ' + r for r in d['rows']))
expected = {('sys_choice_change_request_type', 'Global', NAME), ('sys_script_include_8d44bcd1b726330004aae3fdde11a95c', 'Vulnerability Response', CHILD),
            ('sys_ux_macroponent_59061b92b7072010aed5b064ce11a92c', 'Vulnerability Response', CHILD)}
got = {(r.split(' | ')[1], r.split(' | ')[3], r.split(' | ')[0]) for r in d['rows']}
assert got == expected and len(d['rows']) == 3, 'unexpected rows: %s' % (got ^ expected)
json.dump({'parent': g['parent'], 'set': g['child'], 'name': NAME, 'child_name': CHILD, 'scope': g['scope'], 'default_set': g['dflt'],
           'global_default_set': g['global_dflt']}, open(ST_PATH, 'w'), indent=1)
