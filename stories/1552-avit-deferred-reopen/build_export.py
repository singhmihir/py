"""SNOWUSEMTP-1552: captures sn_vul.auto_defer_avit_in_active_exception_window = true in an update set of the
Vulnerability Response scope (the property's own scope), exports it with the platform exporter, scrubs, parses,
proves it through the XML upload path and archives a copy under stories/_update_sets."""
import os, sys, json, time, shutil
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__))
NAME = 'SNOWUSEMTP-1552_MS_AVIT Deferral Kept On Scanner Reopen_V1.0'
PROP = 'sn_vul.auto_defer_avit_in_active_exception_window'; SN_VUL = '054cdcc2ff200200158bffffffffff94'
OUT = os.path.join(HERE, 'AVIT Deferral Kept On Scanner Reopen - Update Set.xml')
DESC = ('Enables the platform behaviour that keeps an application vulnerable item in the Deferred state when the scanner closes it and '
        'finds it again while its approved deferral (Until date) is still valid: property ' + PROP + ' set to true. The out-of-box before '
        'rule "Run exception rules" on the application vulnerable item then restores state Deferred with the original reason on the '
        'scanner re-open, increments the defer count and writes a work note; a manual re-open is not affected.')
ui = SNUI(); ui.app('global')
st_path = os.path.join(HERE, 'state.json'); ST = json.load(open(st_path)) if os.path.exists(st_path) else {}
d = ui.js('''var o = {rows: []};
var us = new GlideRecord('sys_update_set');
if (%s && us.get(%s)) { us.setValue('state', 'in progress'); us.update(); }
else { us.initialize(); us.setValue('name', %s); us.setValue('application', %s); us.setValue('description', %s); us.insert(); }
o.set = us.getUniqueValue(); new GlideUpdateSet().set(o.set);
var p = new GlideRecord('sys_properties'); p.get('name', %s); p.setValue('value', 'true'); p.update(); o.value = gs.getProperty(%s); o.prop_scope = p.sys_scope.getDisplayValue();
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', o.set); ux.query(); while (ux.next()) o.rows.push(ux.getValue('type') + ' | ' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
var s2 = new GlideRecord('sys_update_set'); s2.get(o.set); o.set_app = s2.application.getDisplayValue();
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(bool(ST.get('set'))), json.dumps(ST.get('set', '')), json.dumps(NAME), json.dumps(SN_VUL), json.dumps(DESC), json.dumps(PROP), json.dumps(PROP)))
print('set:', d['set'], '|', d['set_app'], '| property now', d['value'], '| property scope', d['prop_scope']); print('\n'.join(' ' + r for r in d['rows']))
assert d['value'] == 'true' and len(d['rows']) == 1 and d['rows'][0].endswith('| Vulnerability Response') and d['set_app'] == 'Vulnerability Response'
json.dump({'set': d['set'], 'name': NAME, 'rows': 1}, open(st_path, 'w'), indent=1)
e = ui.js('''var o = {}; var us = new GlideRecord('sys_update_set'); us.get(%s); us.setValue('state', 'complete'); us.update();
var us2 = new GlideRecord('sys_update_set'); us2.get(%s); o.remote_id = '' + new UpdateSetExport().exportUpdateSet(us2);
var dflt = new GlideRecord('sys_update_set'); dflt.addQuery('is_default', true); dflt.addQuery('application', 'global'); dflt.query(); dflt.next(); new GlideUpdateSet().set(dflt.getUniqueValue());
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(d['set']), json.dumps(d['set'])))
r = ui.s.get(INST + '/export_update_set.do', params={'sysparm_sys_id': e['remote_id'], 'sysparm_delete_when_done': 'true', 'sysparm_is_remote': 'false', 'sysparm_ck': ui.ck()})
content = r.text.replace(os.environ['SN_USER'], 'admin'); open(OUT, 'w').write(content)
low = content.lower(); hits = [t for t in ['dev390397', 'zk5lg9v', 'service-now.com', 'x_196061', 'bofasim', os.environ['SN_PASSWORD'].lower()] if t in low]
root = ET.parse(OUT).getroot()
print('export:', r.status_code, len(content), 'bytes | nodes', len(root.findall('sys_update_xml')), '| set in file:', root.find('sys_remote_update_set/name').text, '| scrub', 'CLEAN' if not hits else hits)
assert not hits and len(root.findall('sys_update_xml')) == 1
ui.s.post(INST + '/sys_upload.do', data={'sysparm_ck': ui.ck(), 'sysparm_target': 'sys_remote_update_set', 'sysparm_referring_url': 'sys_remote_update_set_list.do', 'sysparm_encryption_context': ''},
          files={'attachFile': (os.path.basename(OUT), content.encode(), 'text/xml')}, allow_redirects=True)
time.sleep(3)
d3 = ui.js('''var o = {sets: []}; var rs = new GlideRecord('sys_remote_update_set'); rs.addQuery('name', %s); rs.addQuery('sys_created_on', '>', gs.minutesAgoStart(3)); rs.query();
while (rs.next()) { var names = []; var ux = new GlideRecord('sys_update_xml'); ux.addQuery('remote_update_set', rs.getUniqueValue()); ux.query(); while (ux.next()) names.push('' + ux.getValue('target_name') + ':' + ux.getValue('action'));
  o.sets.push({state: '' + rs.state, app: '' + rs.application.getDisplayValue(), names: names}); var dd = new GlideRecord('sys_update_xml'); dd.addQuery('remote_update_set', rs.getUniqueValue()); dd.query(); while (dd.next()) dd.deleteRecord(); rs.deleteRecord(); }
var local = new GlideAggregate('sys_update_xml'); local.addQuery('update_set', %s); local.addAggregate('COUNT'); local.query(); local.next(); o.local_rows_intact = parseInt(local.getAggregate('COUNT'));
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(NAME), json.dumps(d['set'])))
print('UI import test:', json.dumps(d3))
assert len(d3['sets']) == 1 and d3['sets'][0]['names'] == [PROP + ':INSERT_OR_UPDATE'] and d3['sets'][0]['app'] == 'Vulnerability Response' and d3['local_rows_intact'] == 1
arch = os.path.join(BASE, 'stories', '_update_sets'); fname = NAME.replace(' ', '_') + '.xml'; shutil.copy(OUT, os.path.join(arch, fname))
idx_path = os.path.join(arch, 'index.json'); idx = [x for x in json.load(open(idx_path)) if x['name'] != NAME]
idx.append({'name': NAME, 'app': 'sn_vul', 'rows': 1, 'exported': 1, 'file': fname, 'created': root.find('sys_remote_update_set/sys_created_on').text if root.find('sys_remote_update_set/sys_created_on') is not None else '', 'scrub': []})
json.dump(idx, open(idx_path, 'w'), indent=1); print('archived as', fname); print('EXPORT OK')
