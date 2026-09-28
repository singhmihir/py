"""SNOWUSEMTP-2021: audits the captured rows (all Global), completes the set, exports it with the platform exporter,
scrubs and parses the file, proves it through the XML upload path with the platform preview, and archives a copy under
stories/_update_sets. Usage: python3 export.py"""
import os, sys, json, shutil
import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI

ST = json.load(open(os.path.join(HERE, 'state.json')))
NAME = ST['name']
OUT = os.path.join(HERE, 'AVIT Verification ID History - Update Set.xml')
EXPECTED = ['sys_documentation_sn_vul_app_vulnerable_item_u_verification_id_en', 'sys_dictionary_sn_vul_app_vulnerable_item_u_verification_id',
            'sys_script_include_' + ST['si'], 'sys_script_' + ST['br']]

ui = SNUI(); ui.app('global')
a = ui.js('''var o = {rows: []};
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', %s); ux.query();
while (ux.next()) o.rows.push({name: ux.getValue('name'), app: '' + ux.application.getDisplayValue()});
var us = new GlideRecord('sys_update_set'); us.get(%s); o.set_app = '' + us.application.getDisplayValue();
us.setValue('state', 'complete'); us.update();
var dflt = new GlideRecord('sys_update_set'); dflt.addQuery('is_default', true); dflt.addQuery('application', 'global'); dflt.query(); dflt.next(); new GlideUpdateSet().set(dflt.getUniqueValue());
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(ST['set']), json.dumps(ST['set'])))
names = sorted(r['name'] for r in a['rows'])
print('set application', a['set_app'], '| rows', len(names)); print('\n'.join('  %s | %s' % (r['name'], r['app']) for r in a['rows']))
assert a['set_app'] == 'Global' and all(r['app'] == 'Global' for r in a['rows']) and names == sorted(EXPECTED), 'audit failed'

n = ui.export_update_set(ST['set'], OUT)
content = open(OUT).read(); low = content.lower()
hits = [w for w in ['dev390397', 'zk5lg9v', 'service-now.com', 'x_196061', 'bofasim', os.environ['SN_PASSWORD'].lower(), 'claude', 'anthropic'] if w in low]
root = ET.parse(OUT).getroot()
print('export: %d updates, %d bytes, set in file: %s, scrub %s' % (n, len(content), root.findtext('sys_remote_update_set/name'), hits or 'CLEAN'))
assert n == 4 and not hits and root.findtext('sys_remote_update_set/name') == NAME

p = ui.ui_preview_test(OUT, NAME)
print('import + preview:', json.dumps(p))
s = p['sets'][0]
assert len(p['sets']) == 1 and len(s['names']) == 4 and s['app'] == 'Global' and s['preview'] == 'ran' and not s['problems']

arch = os.path.join(BASE, 'stories', '_update_sets'); fname = NAME.replace(' ', '_') + '.xml'
shutil.copy(OUT, os.path.join(arch, fname))
idx_path = os.path.join(arch, 'index.json'); idx = [x for x in json.load(open(idx_path)) if x['name'] != NAME]
idx.append({'name': NAME, 'app': 'global', 'rows': 4, 'exported': n, 'file': fname,
            'created': root.findtext('sys_remote_update_set/sys_created_on') or '', 'scrub': []})
json.dump(idx, open(idx_path, 'w'), indent=1)
print('archived as', fname, '| EXPORT OK')
