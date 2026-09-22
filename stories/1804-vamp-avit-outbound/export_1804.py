"""Empties the Kafka topic property and captures it so that the client fills it in, then completes the
update set, exports it with the platform exporter, parses it, proves it through the
XML upload path (retrieved copy deleted afterwards) and archives it under stories/_update_sets. The
export carries the client application (the PDI holds a mirror of it), so it imports on the client
instance as it is; package_1804.py builds the record XML as the alternative."""
import os, sys, json, re, shutil
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
ST = json.load(open(os.path.join(HERE, 'state.json'))); SET = ST['set']; NAME = ST['set_name']; EXPECT = ST['rows']; APP_NAME = ST['app_name']
OUT = os.path.join(HERE, 'VAMP AVIT Outbound Payload - Update Set.xml')
ui = SNUI(); ui.app('global')
TOPIC = 'x_boar_bofa_usem_1.usem.vamp.kafka.topic_sys_id'
blank = ui.js('''
var o = {};
new GlideUpdateSet().set(%s);
var p = new GlideRecord('sys_properties'); p.addQuery('name', %s); p.query(); p.next();
o.was = '' + (p.getValue('value') || '');
p.setValue('value', ''); p.update();
new GlideUpdateManager2().saveRecord(p);
var back = new GlideRecord('sys_properties'); back.get(p.getUniqueValue());
o.now = '' + (back.getValue('value') || '');
o.scope = '' + back.sys_scope.getDisplayValue();
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(SET), json.dumps(TOPIC)), scope=ST['scope'])
assert blank['now'] == '' and blank['scope'] == ST['app_name'], blank
print('topic property emptied for the export (was %d characters)' % len(blank['was']))
d = ui.js('''var o = {rows: []};
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', %s); ux.orderBy('target_name'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
var us = new GlideRecord('sys_update_set'); us.get(%s); o.name = '' + us.name; o.app = '' + us.application.getDisplayValue(); us.setValue('state', 'complete'); us.update();
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(SET), json.dumps(SET)))
print('\n'.join('  ' + r for r in d['rows'])); print('set:', d['name'], '|', d['app'])
assert d['name'] == NAME and d['app'] == APP_NAME and len(d['rows']) == EXPECT and all(r.endswith('| ' + APP_NAME) for r in d['rows'])
n = ui.export_update_set(SET, OUT)
content = open(OUT).read(); low = content.lower()
WORKING = [INST.split('//')[-1].split('.')[0], os.environ.get('SN_USER', '')]
hits = [t for t in [w.lower() for w in WORKING if w] + ['service-now.com', 'x_196061', 'bofasim'] if t in low]
root = ET.parse(OUT).getroot()
print('export:', len(content), 'bytes | nodes', n, '| set in file:', root.find('sys_remote_update_set/name').text, '| user/instance scrub', 'CLEAN' if not hits else hits)
assert not hits and n == EXPECT and root.find('sys_remote_update_set/name').text == NAME
d3 = ui.ui_import_test(OUT, NAME)
print('UI import test:', json.dumps(d3))
assert len(d3['sets']) == 1 and len(d3['sets'][0]['names']) == EXPECT and d3['sets'][0]['app'] == APP_NAME
arch = os.path.join(BASE, 'stories', '_update_sets'); fname = NAME.replace(' ', '_') + '.xml'
shutil.copy(OUT, os.path.join(arch, fname))
idx_path = os.path.join(arch, 'index.json'); idx = json.load(open(idx_path)); idx = [e for e in idx if e['name'] != NAME]
created = root.find('sys_remote_update_set/sys_created_on')
idx.append({'name': NAME, 'app': 'x_boar_bofa_usem_1 (mirror of the client application, same scope name and sys_id)', 'rows': EXPECT, 'exported': n, 'file': fname, 'created': created.text if created is not None else '', 'scrub': ['client scope and application sys_id: importable on the client instance as is; the client receives the record XML too']})
json.dump(idx, open(idx_path, 'w'), indent=1)
print('archived as', fname)
restored = ui.js('''
var o = {};
new GlideUpdateSet().set(%s);
var p = new GlideRecord('sys_properties'); p.addQuery('name', %s); p.query(); p.next();
p.setValue('value', gs.generateGUID()); p.update();
var back = new GlideRecord('sys_properties'); back.get(p.getUniqueValue());
o.value = '' + (back.getValue('value') || '');
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(ST['default_set']), json.dumps(TOPIC)), scope=ST['scope'])
assert len(restored['value']) == 32, restored
print('topic property given a fresh id on the development instance again, under its Default set')
topic_payload = [ET.fromstring(node.findtext('payload')) for node in root.findall('sys_update_xml') if node.findtext('target_name') == TOPIC]
assert len(topic_payload) == 1, 'the exported set does not carry the topic property once: %d' % len(topic_payload)
assert (topic_payload[0].findtext('sys_properties/value') or '') == '', 'the exported topic property is not empty: %r' % topic_payload[0].findtext('sys_properties/value')
print('the exported topic property is empty, for the client to fill')
print('EXPORT OK')
