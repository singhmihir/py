import os, sys, json, time
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
ui = SNUI(); ui.app('global')
ST = json.load(open(BASE + '/stories/1625-cdp-remediation-task-payload/state.json')); SET = ST['set']
NAME = 'SNOWUSEMTP-1625_MS_Remediation Task CDP Payload_V1.3'
OUT = BASE + '/stories/1625-cdp-remediation-task-payload/Remediation Task CDP Payload - Update Set.xml'
d = ui.js('''
var o = {};
var us = new GlideRecord('sys_update_set'); us.get(%s); us.setValue('name', 'SNOWUSEMTP-1625_MS_Remediation Task CDP Payload_V1.3'); us.setValue('state', 'complete'); us.update();
var us2 = new GlideRecord('sys_update_set'); us2.get(%s); o.remote_id = '' + new UpdateSetExport().exportUpdateSet(us2);
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(SET), json.dumps(SET)))
r = ui.s.get(INST + '/export_update_set.do', params={'sysparm_sys_id': d['remote_id'], 'sysparm_delete_when_done': 'true', 'sysparm_is_remote': 'false', 'sysparm_ck': ui.ck()})
content = r.text.replace('ZK5LG9V', 'admin')
open(OUT, 'w').write(content)
low = content.lower(); hits = [t for t in ['dev390397', 'zk5lg9v', 'service-now.com', 'x_196061', 'bofasim'] if t in low]
root = ET.parse(OUT).getroot()
print('export:', r.status_code, len(content), 'bytes | nodes', len(root.findall('sys_update_xml')), '| scrub', 'CLEAN' if not hits else hits)
r = ui.s.post(INST + '/sys_upload.do', data={'sysparm_ck': ui.ck(), 'sysparm_target': 'sys_remote_update_set', 'sysparm_referring_url': 'sys_remote_update_set_list.do', 'sysparm_encryption_context': ''},
              files={'attachFile': ('Remediation Task CDP Payload - Update Set.xml', content.encode(), 'text/xml')}, allow_redirects=True)
time.sleep(3)
d3 = ui.js('''
var o = {sets: []};
var rs = new GlideRecord('sys_remote_update_set'); rs.addQuery('name', %s); rs.addQuery('sys_created_on', '>', gs.minutesAgoStart(3)); rs.query();
while (rs.next()) { var names = []; var ux = new GlideRecord('sys_update_xml'); ux.addQuery('remote_update_set', rs.getUniqueValue()); ux.query(); while (ux.next()) names.push('' + ux.getValue('target_name'));
  o.sets.push({state: '' + rs.state, app: '' + rs.application.getDisplayValue(), names: names});
  var dd = new GlideRecord('sys_update_xml'); dd.addQuery('remote_update_set', rs.getUniqueValue()); dd.query(); while (dd.next()) dd.deleteRecord(); rs.deleteRecord(); }
var local = new GlideAggregate('sys_update_xml'); local.addQuery('update_set', %s); local.addAggregate('COUNT'); local.query(); local.next(); o.local_rows_intact = parseInt(local.getAggregate('COUNT'));
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(NAME), json.dumps(SET)))
print('UI import test:', json.dumps(d3))
assert len(d3['sets']) == 1 and len(d3['sets'][0]['names']) == 12 and d3['local_rows_intact'] == 12
print('EXPORT OK')
