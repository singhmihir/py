"""Export of the Primary AIT resolution update set: the two records that name the stand-in AIT table
(the usem.ait.ait_table property and the tier rule's table) are pointed at the client table for the
export and restored afterwards under the Default set; then the platform exporter, scrub, parse, the
XML upload proof (retrieved copy deleted) and a copy under stories/_update_sets."""
import os, sys, json, time, shutil
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__))
ST = json.load(open(os.path.join(HERE, 'state.json'))); SET = ST['set']; NAME = ST['name']; EXPECT = ST['rows']
OUT = os.path.join(HERE, 'Primary AIT Resolution - Update Set.xml')
PDI_TABLE = 'x_196061_bofasim_ait'; CLIENT_TABLE = 'x_boar_bofa_techad_ait'
ui = SNUI(); ui.app('global')
ui.js('''var us = new GlideRecord('sys_update_set'); us.get(%s); us.setValue('state', 'in progress'); us.update(); gs.print('X::{}');''' % json.dumps(SET))
SWAP = '''var o = {}; var pin = %s; var table = %s;
if (pin == 'default') { var dflt = new GlideRecord('sys_update_set'); dflt.addQuery('is_default', true); dflt.addQuery('application', 'global'); dflt.query(); dflt.next(); pin = dflt.getUniqueValue(); }
new GlideUpdateSet().set(pin);
var p = new GlideRecord('sys_properties'); p.get('name', 'usem.ait.ait_table'); p.setValue('value', table); p.update(); var p2 = new GlideRecord('sys_properties'); p2.get('name', 'usem.ait.ait_table'); o.property = '' + p2.getValue('value');
var r = new GlideRecord('sys_script'); r.get(%s); r.setValue('collection', table); r.update(); var r2 = new GlideRecord('sys_script'); r2.get(%s); o.rule_table = '' + r2.getValue('collection');
gs.print('X::' + JSON.stringify(o));'''
sw = ui.js(SWAP % (json.dumps(SET), json.dumps(CLIENT_TABLE), json.dumps(ST['made']['ait_rule']), json.dumps(ST['made']['ait_rule'])))
print('client names applied:', json.dumps(sw))
assert sw['property'] == CLIENT_TABLE and sw['rule_table'] == CLIENT_TABLE, 'the table name swap did not stick'
try:
    d = ui.js('''
var o = {rows: []};
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', %s); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('type') + ' | ' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue() + (('' + ux.getValue('payload')).indexOf(%s) > -1 ? ' | PDI NAME' : ''));
var us = new GlideRecord('sys_update_set'); us.get(%s); o.name = '' + us.name; o.app = '' + us.application.getDisplayValue(); us.setValue('state', 'complete'); us.update();
var us2 = new GlideRecord('sys_update_set'); us2.get(%s); o.remote_id = '' + new UpdateSetExport().exportUpdateSet(us2);
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(SET), json.dumps(PDI_TABLE), json.dumps(SET), json.dumps(SET)))
    print('\n'.join(d['rows'])); print('set:', d['name'], '|', d['app'], '|', len(d['rows']), 'rows')
    assert d['name'] == NAME and d['app'] == 'Global' and len(d['rows']) == EXPECT and all(r.endswith('| Global') for r in d['rows'])
    r = ui.s.get(INST + '/export_update_set.do', params={'sysparm_sys_id': d['remote_id'], 'sysparm_delete_when_done': 'true', 'sysparm_is_remote': 'false', 'sysparm_ck': ui.ck()})
    content = r.text.replace(os.environ['SN_USER'], 'admin')
    open(OUT, 'w').write(content)
finally:
    back = ui.js(SWAP % (json.dumps('default'), json.dumps(PDI_TABLE), json.dumps(ST['made']['ait_rule']), json.dumps(ST['made']['ait_rule'])))
    print('instance names restored under the Default set:', json.dumps(back))
low = content.lower(); hits = [t for t in ['dev390397', 'zk5lg9v', 'service-now.com', 'x_196061', 'bofasim', os.environ['SN_PASSWORD'].lower()] if t in low]
root = ET.parse(OUT).getroot()
print('export:', r.status_code, len(content), 'bytes | nodes', len(root.findall('sys_update_xml')), '| set in file:', root.find('sys_remote_update_set/name').text, '| scrub', 'CLEAN' if not hits else hits, '| client table occurrences', content.count(CLIENT_TABLE))
assert not hits and len(root.findall('sys_update_xml')) == EXPECT and content.count(CLIENT_TABLE) >= 2
ui.s.post(INST + '/sys_upload.do', data={'sysparm_ck': ui.ck(), 'sysparm_target': 'sys_remote_update_set', 'sysparm_referring_url': 'sys_remote_update_set_list.do', 'sysparm_encryption_context': ''},
          files={'attachFile': (os.path.basename(OUT), content.encode(), 'text/xml')}, allow_redirects=True)
time.sleep(3)
d3 = ui.js('''
var o = {sets: []};
var rs = new GlideRecord('sys_remote_update_set'); rs.addQuery('name', %s); rs.addQuery('sys_created_on', '>', gs.minutesAgoStart(3)); rs.query();
while (rs.next()) {
    var names = []; var ux = new GlideRecord('sys_update_xml'); ux.addQuery('remote_update_set', rs.getUniqueValue()); ux.orderBy('target_name'); ux.query();
    while (ux.next()) names.push('' + ux.getValue('target_name') + ':' + ux.getValue('action'));
    o.sets.push({state: '' + rs.state, app: '' + rs.application.getDisplayValue(), names: names});
    var dd = new GlideRecord('sys_update_xml'); dd.addQuery('remote_update_set', rs.getUniqueValue()); dd.query(); while (dd.next()) dd.deleteRecord();
    rs.deleteRecord();
}
var local = new GlideAggregate('sys_update_xml'); local.addQuery('update_set', %s); local.addAggregate('COUNT'); local.query(); local.next(); o.local_rows_intact = parseInt(local.getAggregate('COUNT'));
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(NAME), json.dumps(SET)))
print('UI import test:', json.dumps(d3, indent=1))
assert len(d3['sets']) == 1 and len(d3['sets'][0]['names']) == EXPECT and d3['sets'][0]['app'] == 'Global' and d3['local_rows_intact'] == EXPECT
arch = os.path.join(BASE, 'stories', '_update_sets'); fname = NAME.replace(' ', '_') + '.xml'
shutil.copy(OUT, os.path.join(arch, fname))
idx_path = os.path.join(arch, 'index.json'); idx = json.load(open(idx_path))
idx = [e for e in idx if e['name'] != NAME]
idx.append({'name': NAME, 'app': 'global', 'rows': EXPECT, 'exported': EXPECT, 'file': fname, 'created': root.find('sys_remote_update_set/sys_created_on').text if root.find('sys_remote_update_set/sys_created_on') is not None else '', 'scrub': []})
json.dump(idx, open(idx_path, 'w'), indent=1)
print('archived as', fname); print('EXPORT OK')
