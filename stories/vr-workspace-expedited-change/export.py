"""VR workspace Expedited change: checks the live ChangeMgmt is the delivered script (run `fixtures.py remove` first),
captures the records again so each set holds their latest update, audits the batch (parent Global: the Type choice list;
child Vulnerability Response: page and ChangeMgmt), completes both sets, exports the batch with the platform's batch
exporter (Export Update Set Batch to XML), scrubs and parses the file, proves it through the XML upload path with the
platform preview on each retrieved set, and archives a copy under stories/_update_sets. Usage: python3 export.py"""
import os, sys, json, shutil, time
import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST

ST = json.load(open(os.path.join(HERE, 'state.json')))
OUT = os.path.join(HERE, 'VR Workspace Expedited Change - Update Set.xml')
SCRIPT = open(os.path.join(HERE, 'ChangeMgmt.js')).read()
EXPECTED = {ST['name']: {'sys_choice_change_request_type': 'Global'},
            ST['child_name']: {'sys_script_include_8d44bcd1b726330004aae3fdde11a95c': 'Vulnerability Response',
                               'sys_ux_macroponent_59061b92b7072010aed5b064ce11a92c': 'Vulnerability Response'}}

ui = SNUI(); ui.app('global')
c = ui.js('''var o = {};
var si = new GlideRecord('sys_script_include'); si.get('api_name', 'sn_vul.ChangeMgmt'); o.delivered = si.getValue('script') == %(script)s;
if (o.delivered) {
    var us = new GlideRecord('sys_update_set'); us.get(%(child)s); us.setValue('state', 'in progress'); us.update();
    new GlideUpdateSet().set(%(child)s);
    var m = new GlideRecord('sys_ux_macroponent'); m.get('59061b92b7072010aed5b064ce11a92c');
    var um = new GlideUpdateManager2(); um.saveRecord(si); um.saveRecord(m);
    new GlideUpdateSet().set(%(dflt)s);
}
gs.print('X::' + JSON.stringify(o));''' % dict(script=json.dumps(SCRIPT), child=json.dumps(ST['set']), dflt=json.dumps(ST['default_set'])), scope=ST['scope'])
assert c['delivered'], 'the live ChangeMgmt is not the delivered script: run fixtures.py remove first'
a = ui.js('''var o = {sets: {}};
var p = new GlideRecord('sys_update_set'); p.get(%(parent)s); p.setValue('state', 'in progress'); p.update();
new GlideUpdateSet().set(%(parent)s);
var ch = new GlideRecord('sys_choice'); ch.addQuery('name', 'change_request'); ch.addQuery('element', 'type'); ch.addQuery('value', 'expedited'); ch.query(); ch.next();
new GlideUpdateManager2().saveRecord(ch);
new GlideUpdateSet().set(%(gdflt)s);
[%(parent)s, %(child)s].forEach(function (id) {
    var us = new GlideRecord('sys_update_set'); us.get(id);
    var s = {app: '' + us.application.getDisplayValue(), parent: us.parent.getDisplayValue(), base: us.getValue('base_update_set'), rows: {}, standIn: false, override: false, item: false, choices: ''};
    var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', id); ux.query();
    while (ux.next()) { var pl = ux.getValue('payload'); s.rows[ux.getValue('name')] = '' + ux.application.getDisplayValue();
        s.standIn = s.standIn || pl.indexOf('isITSMAdvancedPluginActive') >= 0; s.override = s.override || pl.indexOf('_expeditedModelOrType') >= 0;
        s.item = s.item || pl.indexOf('Create an expedited Change Request.') >= 0; if (ux.getValue('name') == 'sys_choice_change_request_type') s.choices = (pl.match(/<value>[^<]*<\\/value>/g) || []).join(' '); }
    o.sets[us.getValue('name')] = s;
});
[%(child)s, %(parent)s].forEach(function (id) { var us = new GlideRecord('sys_update_set'); us.get(id); us.setValue('state', 'complete'); us.update(); });
gs.print('X::' + JSON.stringify(o));''' % dict(parent=json.dumps(ST['parent']), child=json.dumps(ST['set']), gdflt=json.dumps(ST['global_default_set'])))
for name, s in a['sets'].items():
    print('%s | %s | parent %s | rows %s | stand-in %s | override %s | item %s | choices %s' % (name, s['app'], s['parent'] or '-', json.dumps(s['rows']), s['standIn'], s['override'], s['item'], s['choices']))
assert {k: v['rows'] for k, v in a['sets'].items()} == EXPECTED, 'audit failed'
child, parent = a['sets'][ST['child_name']], a['sets'][ST['name']]
assert child['app'] == 'Vulnerability Response' and parent['app'] == 'Global' and child['parent'] == ST['name'] and parent['base'] == ST['parent'] and child['base'] == ST['parent']
assert child['override'] and child['item'] and not child['standIn'] and 'expedited' in parent['choices']

# the platform's batch export (UI action "Export Update Set Batch to XML")
rid = ui.js('''var p = new GlideRecord('sys_update_set'); p.get(%s); gs.print('X::' + JSON.stringify({rid: '' + new UpdateSetExport().exportHierarchy(p)}));''' % json.dumps(ST['parent']))['rid']
resp = ui.s.get(INST + '/export_base_update_set.do', params={'sysparm_sys_id': rid, 'sysparm_delete_when_done': 'true', 'sysparm_is_remote': 'false', 'sysparm_ck': ui.ck()})
content = resp.text.replace(os.environ['SN_USER'], 'admin'); open(OUT, 'w').write(content); low = content.lower()
hits = [w for w in ['dev390397', 'zk5lg9v', 'service-now.com', 'x_196061', 'bofasim', os.environ['SN_PASSWORD'].lower(), 'claude', 'anthropic', 'isitsmadvancedpluginactive'] if w in low]
root = ET.fromstring(content.encode())
sets = [(x.findtext('name'), x.findtext('sys_id')) for x in root.findall('sys_remote_update_set')]
rows = root.findall('sys_update_xml')
print('export: %d sets %s, %d updates, %d bytes, scrub %s' % (len(sets), [s[0] for s in sets], len(rows), len(content), hits or 'CLEAN'))
assert sorted(s[0] for s in sets) == sorted(EXPECTED) and len(rows) == 3 and not hits

# upload proof: wait until the exporter's temporary copies are gone, upload, then preview each retrieved set
ids = [s[1] for s in sets]
count = '''var o = {sets: 0, rows: 0}; var ids = %s;
var rs = new GlideRecord('sys_remote_update_set'); rs.addQuery('sys_id', 'IN', ids.join(',')); rs.query(); o.sets = rs.getRowCount();
var cu = new GlideAggregate('sys_update_xml'); cu.addQuery('remote_update_set', 'IN', ids.join(',')); cu.addAggregate('COUNT'); cu.query(); if (cu.next()) o.rows = parseInt(cu.getAggregate('COUNT'));
gs.print('X::' + JSON.stringify(o));''' % json.dumps(ids)
for _ in range(40):
    left = ui.js(count)
    if not left['sets'] and not left['rows']: break
    time.sleep(3)
else:
    raise RuntimeError('the exporter copies are still on the instance: %s' % left)
ui.s.post(INST + '/sys_upload.do', data={'sysparm_ck': ui.ck(), 'sysparm_target': 'sys_remote_update_set', 'sysparm_referring_url': 'sys_remote_update_set_list.do',
          'sysparm_encryption_context': ''}, files={'attachFile': (os.path.basename(OUT), content.encode(), 'text/xml')}, allow_redirects=True)
for _ in range(20):
    time.sleep(3)
    got = ui.js(count)
    if got['sets'] == 2 and got['rows'] >= 3: break
p = ui.js('''var o = {sets: []}; var ids = %s;
for (var i = 0; i < ids.length; i++) {
    var id = ids[i], e = {names: [], problems: [], preview: ''};
    try { new UpdateSetPreviewer().generatePreviewRecordsWithUpdate(id); e.preview = 'ran'; } catch (ex) { e.preview = 'failed: ' + (ex.message || ex); }
    var rs = new GlideRecord('sys_remote_update_set'); rs.get(id); e.name = rs.getValue('name'); e.app = '' + rs.application.getDisplayValue(); e.parent = rs.parent.getDisplayValue(); e.state = rs.getValue('state');
    var ux = new GlideRecord('sys_update_xml'); ux.addQuery('remote_update_set', id); ux.query(); while (ux.next()) e.names.push(ux.getValue('name'));
    var pb = new GlideRecord('sys_update_preview_problem'); pb.addQuery('remote_update_set', id); pb.query();
    while (pb.next()) e.problems.push(pb.getValue('type') + ': ' + pb.remote_update.name + ' - ' + pb.getValue('description'));
    o.sets.push(e);
}
for (var j = 0; j < ids.length; j++) {
    var pp = new GlideRecord('sys_update_preview_problem'); pp.addQuery('remote_update_set', ids[j]); pp.deleteMultiple();
    var dd = new GlideRecord('sys_update_xml'); dd.addQuery('remote_update_set', ids[j]); dd.deleteMultiple();
    var r2 = new GlideRecord('sys_remote_update_set'); if (r2.get(ids[j])) r2.deleteRecord();
}
gs.print('X::' + JSON.stringify(o));''' % json.dumps(ids))
for e in p['sets']:
    print('retrieved %(name)s | %(app)s | parent %(parent)s | %(state)s | preview %(preview)s | updates %(names)s | problems %(problems)s' % e)
assert len(p['sets']) == 2 and all(e['preview'] == 'ran' and not e['problems'] for e in p['sets'])
assert sorted(n for e in p['sets'] for n in e['names']) == sorted(n for v in EXPECTED.values() for n in v)

arch = os.path.join(BASE, 'stories', '_update_sets'); fname = ST['name'].replace(' ', '_') + '.xml'
shutil.copy(OUT, os.path.join(arch, fname))
idx_path = os.path.join(arch, 'index.json'); idx = [x for x in json.load(open(idx_path)) if x['name'] != ST['name']]
idx.append({'name': ST['name'], 'app': 'global + sn_vul (batch)', 'rows': 3, 'exported': len(rows), 'file': fname,
            'created': root.findtext('sys_remote_update_set/sys_created_on') or '', 'scrub': []})
json.dump(idx, open(idx_path, 'w'), indent=1)
print('archived as', fname, '| EXPORT OK')
