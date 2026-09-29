"""Expedited change from the VR workspace for every remediation task type, as one update set batch:
- parent (Global) `SNOWUSEMTP_MS_VR Workspace Expedited Change_V1.0`: the change_request Type choice list with Expedited;
- child Vulnerability Response (IT and application remediation tasks): the Create Change dialog page with the item
  Expedited, and sn_vul ChangeMgmt (ChangeMgmt.js: override of createNewChangeRequest / actionCreateChange, and the
  shared getExpeditedChangeModel);
- child Containers (CVUL): its dialog page, and sn_vul_container ChangeMgmt ("ChangeMgmt (Containers).js");
- child Configuration Compliance (CRG): its dialog page, and the two edits of sn_vulc ChangeMgmt (cc_edits.json).
Each dialog is changed with the delivered script "Add Expedited to Create Change Dialog.js", run in its application.
Idempotent. Usage: python3 build.py"""
import os, sys, json, re
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI

NAME = 'SNOWUSEMTP_MS_VR Workspace Expedited Change_V1.0'
DESC = ('Expedited change from the Vulnerability Response workspace. This set carries the change_request Type choice list with '
        'Expedited (value expedited); its child sets carry the Create Change dialogs and the change creation code of Vulnerability '
        'Response, Containers and Configuration Compliance.')
CHILDREN = [  # key, scope, set name, description, script include api name, how the script include changes
    ('vr', 'sn_vul', 'SNOWUSEMTP_MS_VR Workspace Expedited Change - Vulnerability Response_V1.0',
     'IT and application remediation tasks: Create Change dialog (page Modal - Create Change Request) offers Expedited; ChangeMgmt '
     'creates an Expedited change from the change model that presets the Expedited type and offers that model to the other apps.',
     'sn_vul.ChangeMgmt', ('script', 'ChangeMgmt.js')),
    ('cvul', 'sn_vul_container', 'SNOWUSEMTP_MS_VR Workspace Expedited Change - Containers_V1.0',
     'Container remediation tasks: Create Change dialog (page Modal - Container Create Change Request default) offers Expedited; '
     'ChangeMgmt creates an Expedited change from the Expedited change model.',
     'sn_vul_container.ChangeMgmt', ('script', 'ChangeMgmt (Containers).js')),
    ('crg', 'sn_vulc', 'SNOWUSEMTP_MS_VR Workspace Expedited Change - Configuration Compliance_V1.0',
     'Configuration Compliance remediation tasks: Create Change dialog (page Modal - CC Create Change Request) offers Expedited; '
     'ChangeMgmt creates an Expedited change from the Expedited change model.',
     'sn_vulc.ChangeMgmt', ('edits', 'cc_edits.json')),
]
DIALOG = open(os.path.join(HERE, 'Add Expedited to Create Change Dialog.js')).read()
ST_PATH = os.path.join(HERE, 'state.json')
ST = json.load(open(ST_PATH)) if os.path.exists(ST_PATH) else {}
ST.setdefault('children', {})
if ST.get('set') and 'vr' not in ST['children']:
    ST['children']['vr'] = ST['set']

ui = SNUI(); ui.app('global')
g = ui.js('''var o = {scopes: {}, defaults: {}};
%(scopes)s.forEach(function (s) { var sc = new GlideRecord('sys_scope'); sc.get('scope', s); o.scopes[s] = sc.getUniqueValue();
    var d = new GlideRecord('sys_update_set'); d.addQuery('application', sc.getUniqueValue()); d.addQuery('is_default', true); d.query(); d.next(); o.defaults[s] = d.getUniqueValue(); });
var gd = new GlideRecord('sys_update_set'); gd.addQuery('application', 'global'); gd.addQuery('is_default', true); gd.query(); gd.next(); o.global_dflt = gd.getUniqueValue();
var p = new GlideRecord('sys_update_set');
if (%(parent)s && p.get(%(parent)s)) { p.setValue('state', 'in progress'); p.update(); }
else { p.initialize(); p.setValue('name', %(name)s); p.setValue('application', 'global'); p.setValue('description', %(desc)s); p.insert(); p.setValue('base_update_set', p.getUniqueValue()); p.update(); }
o.parent = p.getUniqueValue(); o.children = {};
var children = %(children)s, known = %(known)s;
children.forEach(function (c) {
    var u = new GlideRecord('sys_update_set');
    if (known[c.key] && u.get(known[c.key])) u.setValue('state', 'in progress');
    else { u.initialize(); u.setValue('application', o.scopes[c.scope]); }
    u.setValue('name', c.name); u.setValue('description', c.desc); u.setValue('parent', o.parent); u.setValue('base_update_set', o.parent);
    o.children[c.key] = u.isNewRecord() ? '' + u.insert() : (u.update(), u.getUniqueValue());
});
new GlideUpdateSet().set(o.parent);
var ch = new GlideRecord('sys_choice'); ch.addQuery('name', 'change_request'); ch.addQuery('element', 'type'); ch.addQuery('value', 'expedited'); ch.addQuery('language', 'en'); ch.query();
if (!ch.next()) { ch.initialize(); ch.setValue('name', 'change_request'); ch.setValue('element', 'type'); ch.setValue('value', 'expedited'); ch.setValue('label', 'Expedited'); ch.setValue('language', 'en'); ch.setValue('sequence', 4); ch.insert(); }
new GlideUpdateManager2().saveRecord(ch);
new GlideUpdateSet().set(o.global_dflt);
gs.print('X::' + JSON.stringify(o));''' % dict(scopes=json.dumps([c[1] for c in CHILDREN]), parent=json.dumps(ST.get('parent', '')), name=json.dumps(NAME),
                                               desc=json.dumps(DESC), children=json.dumps([{'key': c[0], 'scope': c[1], 'name': c[2], 'desc': c[3]} for c in CHILDREN]),
                                               known=json.dumps(ST['children'])))

for key, scope, name, desc, api, (how, src) in CHILDREN:
    child, scope_id, dflt = g['children'][key], g['scopes'][scope], g['defaults'][scope]
    out = ui.run('new GlideUpdateSet().set(%s);\n%s\nnew GlideUpdateSet().set(%s);' % (json.dumps(child), DIALOG, json.dumps(dflt)), scope=scope_id)
    print(key, '|', (re.findall(r'\*\*\* Script: ([^\n<]*)', out) or [out[-300:]])[0])
    if how == 'script':
        script, edits = open(os.path.join(HERE, src)).read(), []
    else:
        script, edits = None, json.load(open(os.path.join(HERE, src)))
    d = ui.js('''var o = {}; new GlideUpdateSet().set(%(child)s);
var si = new GlideRecord('sys_script_include'); si.get('api_name', %(api)s); var s = si.getValue('script'); var script = %(script)s, edits = %(edits)s;
if (script === null) { o.edits = []; if (s.indexOf('getExpeditedChangeModel') < 0) edits.forEach(function (e) { var n = s.split(e.find).length - 1; o.edits.push(e.where + ' ' + n); if (n == 1) s = s.replace(e.find, e.replace); }); script = s; }
if (si.getValue('script') != script) { si.setValue('script', script); si.update(); }
new GlideUpdateManager2().saveRecord(si);
var pg = new GlideRecord('sys_ux_macroponent'); pg.addQuery('sys_id', 'IN', '59061b92b7072010aed5b064ce11a92c,fd9d6e2953021110501fddeeff7b1296,996c1f486db42110f877388cdecc4b6f'); pg.addQuery('sys_scope', %(scope)s); pg.query(); pg.next();
new GlideUpdateManager2().saveRecord(pg);
o.rows = []; var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', %(child)s); ux.orderBy('name'); ux.query();
while (ux.next()) o.rows.push(ux.getValue('name') + ' | ' + ux.getValue('target_name') + ' | ' + ux.application.getDisplayValue());
new GlideUpdateSet().set(%(dflt)s);
gs.print('X::' + JSON.stringify(o));''' % dict(child=json.dumps(child), api=json.dumps(api), script=json.dumps(script), edits=json.dumps(edits),
                                                scope=json.dumps(scope_id), dflt=json.dumps(dflt)), scope=scope_id)
    print('  ' + ('edits: %s' % d['edits'] if 'edits' in d else 'script replaced'))
    print('\n'.join('  ' + r for r in d['rows']))
    assert len(d['rows']) == 2 and all(r.startswith(('sys_script_include_', 'sys_ux_macroponent_')) for r in d['rows']), 'unexpected rows in ' + name
    assert d.get('edits', ['x 1']) == [] or all(e.endswith(' 1') for e in d.get('edits', [])), 'an edit anchor was not found once'

json.dump({'parent': g['parent'], 'name': NAME, 'children': g['children'], 'child_names': {c[0]: c[2] for c in CHILDREN},
           'scopes': {c[0]: g['scopes'][c[1]] for c in CHILDREN}, 'defaults': {c[0]: g['defaults'][c[1]] for c in CHILDREN},
           'global_default_set': g['global_dflt'], 'set': g['children']['vr'], 'scope': g['scopes']['sn_vul'], 'default_set': g['defaults']['sn_vul']},
          open(ST_PATH, 'w'), indent=1)
print('parent', g['parent'], '| children', json.dumps(g['children']))
