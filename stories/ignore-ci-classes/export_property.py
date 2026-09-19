"""Complete the property update set, export it with the platform exporter, scrub, parse, prove it through
the XML upload path (retrieved copy deleted afterwards) and archive a copy under stories/_update_sets."""
import os, sys, json, shutil
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__))
ST = json.load(open(os.path.join(HERE, 'state.json'))); SET = ST['set']; NAME = ST['name']; EXPECT = ST['rows']
OUT = os.path.join(HERE, ST['file'])
ui = SNUI(); ui.app('global')
d = ui.js('''var o = {rows: []};
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', %s); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.application.getDisplayValue() + ' | ' + ((('' + ux.getValue('payload')).indexOf(%s) > -1) ? 'new value' : 'OLD VALUE'));
var us = new GlideRecord('sys_update_set'); us.get(%s); o.name = '' + us.name; o.app = '' + us.application.getDisplayValue(); us.setValue('state', 'complete'); us.update();
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(SET), json.dumps(ST['value']), json.dumps(SET)))
print('\n'.join(d['rows'])); print('set:', d['name'], '|', d['app'])
assert d['name'] == NAME and d['app'] == 'Security Support Common' and len(d['rows']) == EXPECT and all(r.endswith('| new value') for r in d['rows'])
n = ui.export_update_set(SET, OUT)
content = open(OUT).read(); low = content.lower()
hits = [t for t in ['dev390397', 'zk5lg9v', 'service-now.com', 'x_196061', 'bofasim'] if t in low]
root = ET.parse(OUT).getroot()
print('export:', len(content), 'bytes | nodes', n, '| set in file:', root.find('sys_remote_update_set/name').text, '| scrub', 'CLEAN' if not hits else hits)
assert not hits and n == EXPECT and root.find('sys_remote_update_set/name').text == NAME
d3 = ui.ui_import_test(OUT, NAME)
print('UI import test:', json.dumps(d3))
assert len(d3['sets']) == 1 and len(d3['sets'][0]['names']) == EXPECT and d3['sets'][0]['app'] == 'Security Support Common'
arch = os.path.join(BASE, 'stories', '_update_sets'); fname = NAME.replace(' ', '_') + '.xml'
shutil.copy(OUT, os.path.join(arch, fname))
idx_path = os.path.join(arch, 'index.json'); idx = json.load(open(idx_path)); idx = [e for e in idx if e['name'] != NAME]
idx.append({'name': NAME, 'app': 'sn_sec_cmn', 'rows': EXPECT, 'exported': n, 'file': fname, 'created': root.find('sys_remote_update_set/sys_created_on').text if root.find('sys_remote_update_set/sys_created_on') is not None else '', 'scrub': []})
json.dump(idx, open(idx_path, 'w'), indent=1)
print('archived as', fname); print('EXPORT OK')
