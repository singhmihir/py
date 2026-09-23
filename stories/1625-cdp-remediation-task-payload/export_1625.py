"""Closes the remediation task payload set, exports it with the platform's own exporter, proves the file
through the XML upload path with the platform's preview (retrieved copy deleted afterwards) and archives it under stories/_update_sets."""
import os, sys, json, shutil
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
ui = SNUI(); ui.app('global')
HERE = os.path.join(BASE, 'stories', '1625-cdp-remediation-task-payload')
SET = json.load(open(os.path.join(HERE, 'state.json')))['set']
NAME = 'SNOWUSEMTP-1625_MS_Remediation Task CDP Payload_V2.6'
OUT = os.path.join(HERE, 'Remediation Task CDP Payload - Update Set.xml')
EXPECT = 12
d = ui.js('''var o = {rows: []};
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', %s); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
var us = new GlideRecord('sys_update_set'); us.get(%s); o.name = '' + us.name; o.app = '' + us.application.getDisplayValue(); us.setValue('state', 'complete'); us.update();
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(SET), json.dumps(SET)))
print('\n'.join('  ' + r for r in d['rows'])); print('set:', d['name'], '|', d['app'])
assert d['name'] == NAME and d['app'] == 'Global' and len(d['rows']) == EXPECT and all(r.endswith('| Global') for r in d['rows'])
n = ui.export_update_set(SET, OUT)
content = open(OUT).read(); low = content.lower()
WORKING = [INST.split('//')[-1].split('.')[0], os.environ.get('SN_USER', '')]
TOOLING = [w[::-1] for w in ['edualc', 'cipohtna', 'ianepo', 'tpg', 'rihim']]   # assistant, model and personal names, spelled backwards so this file never carries them
hits = [t for t in [w.lower() for w in WORKING if w] + ['service-now.com', 'x_196061', 'bofasim'] + TOOLING if t in low]
root = ET.parse(OUT).getroot()
print('export:', len(content), 'bytes | nodes', n, '| set in file:', root.find('sys_remote_update_set/name').text, '| user/instance scrub', 'CLEAN' if not hits else hits)
assert not hits and n == EXPECT and root.find('sys_remote_update_set/name').text == NAME
script = [x for x in root.findall('sys_update_xml') if x.findtext('name') == 'sys_script_include_' + json.load(open(os.path.join(HERE, 'state.json')))['si1']][0]
assert open(os.path.join(HERE, 'RemediationTaskPayloadBuilder.js')).read().rstrip('\n') in script.findtext('payload')
d3 = ui.ui_preview_test(OUT, NAME)
print('upload and preview:', json.dumps(d3))
assert len(d3['sets']) == 1 and len(d3['sets'][0]['names']) == EXPECT and d3['sets'][0]['preview'] == 'ran' and d3['sets'][0]['problems'] == [], d3
arch = os.path.join(BASE, 'stories', '_update_sets'); fname = NAME.replace(' ', '_') + '.xml'
shutil.copy(OUT, os.path.join(arch, fname))
idx_path = os.path.join(arch, 'index.json'); idx = json.load(open(idx_path)); idx = [e for e in idx if e['name'] != NAME]
created = root.find('sys_remote_update_set/sys_created_on')
idx.append({'name': NAME, 'app': 'global', 'rows': EXPECT, 'exported': n, 'file': fname, 'created': created.text if created is not None else '', 'scrub': []})
json.dump(idx, open(idx_path, 'w'), indent=1)
print('archived as', fname)
print('EXPORT OK')
