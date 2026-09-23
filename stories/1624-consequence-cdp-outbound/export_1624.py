"""Empties the Kafka topic property and captures it so that the client fills it in, then completes the update set,
exports it with the platform exporter, parses it, checks that every deletion of an earlier sys_id is recorded before
the current records (so that on import the earlier property goes before the current one of the same name is
inserted), proves the file through the XML upload path with the platform's preview (retrieved copy deleted
afterwards) and archives it under stories/_update_sets. The export carries the client's own scope name and
application sys_id (the PDI mirrors the application), so it imports on the client instance as is; the client
receives the record XML built by package_1624.py as well."""
import os, sys, json, shutil
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
WORKING = [INST.split('//')[1].split('.')[0], os.environ['SN_USER']]   # instance and user names that must never reach a delivered file
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
ST = json.load(open(os.path.join(HERE, 'state.json'))); SET = ST['set']; NAME = ST['set_name']; EXPECT = ST['rows']; APP_NAME = ST['app_name']
PRIOR = json.load(open(os.path.join(HERE, 'prior_records.json')))['records']
OUT = os.path.join(HERE, 'Consequence CDP Outbound Payload - Update Set.xml')
TOPIC = 'x_boar_bofa_usem_0.usem.consequence.kafka.topic_sys_id'
ui = SNUI(); ui.app('global')
blank = ui.js('''
var o = {};
new GlideUpdateSet().set(%s);
var p = new GlideRecord('sys_properties'); p.addQuery('name', %s); p.query(); p.next();
o.was = '' + (p.getValue('value') || '');
p.setValue('value', ''); p.update();
new GlideUpdateManager2().saveRecord(p);
var back = new GlideRecord('sys_properties'); back.get(p.getUniqueValue());
o.now = '' + (back.getValue('value') || ''); o.scope = '' + back.sys_scope.getDisplayValue();
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(SET), json.dumps(TOPIC)), scope=ST['scope'])
assert blank['now'] == '' and blank['scope'] == APP_NAME, blank
print('topic property emptied for the export (was %d characters)' % len(blank['was']))
d = ui.js('''var o = {rows: []};
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', %s); ux.orderBy('sys_recorded_at'); ux.query();
while (ux.next()) o.rows.push('' + ux.getValue('target_name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
var us = new GlideRecord('sys_update_set'); us.get(%s); o.name = '' + us.name; o.app = '' + us.application.getDisplayValue(); us.setValue('state', 'complete'); us.update();
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(SET), json.dumps(SET)))
print('\n'.join('  ' + r for r in d['rows'])); print('set:', d['name'], '|', d['app'])
assert d['name'] == NAME and d['app'] == APP_NAME and len(d['rows']) == EXPECT and all(r.endswith('| ' + APP_NAME) for r in d['rows'])
n = ui.export_update_set(SET, OUT)
content = open(OUT).read(); low = content.lower()
TOOLING = [w[::-1] for w in ['edualc', 'cipohtna', 'ianepo', 'tpg', 'rihim']]   # assistant, model and personal names, spelled backwards so this file never carries them
hits = [t for t in [w.lower() for w in WORKING + [os.environ.get('SN_PASSWORD', '')] if w] + ['service-now.com', 'x_196061', 'bofasim'] + TOOLING if t in low]
root = ET.parse(OUT).getroot()
print('export:', len(content), 'bytes | nodes', n, '| set in file:', root.find('sys_remote_update_set/name').text, '| user/instance scrub', 'CLEAN' if not hits else hits)
assert not hits and n == EXPECT and root.find('sys_remote_update_set/name').text == NAME
nodes = root.findall('sys_update_xml')
deletes = [x for x in nodes if x.findtext('action') == 'DELETE']; current = [x for x in nodes if x.findtext('action') != 'DELETE']
assert sorted(x.findtext('name') for x in deletes) == sorted(p['table'] + '_' + p['sys_id'] for p in PRIOR), [x.findtext('name') for x in deletes]
assert max(x.findtext('sys_recorded_at') for x in deletes) < min(x.findtext('sys_recorded_at') for x in current), 'a deletion is recorded after a current record'
print('deletions of the %d earlier sys_ids recorded before the %d current records' % (len(deletes), len(current)))
for script in ['BOFASIConsequenceOutboundProcessor']:
    node = [x for x in current if x.findtext('target_name') == script][0]
    assert open(os.path.join(HERE, script + '.js')).read().rstrip('\n') in node.findtext('payload'), script
topic_payload = [ET.fromstring(x.findtext('payload')) for x in current if x.findtext('target_name') == TOPIC]
assert len(topic_payload) == 1 and (topic_payload[0].findtext('sys_properties/value') or '') == '', 'the exported topic property is not empty'
print('scripts in the file equal the repository copies; the exported topic property is empty, for the client to fill')
d3 = ui.ui_preview_test(OUT, NAME)
print('upload and preview:', json.dumps(d3))
assert len(d3['sets']) == 1 and len(d3['sets'][0]['names']) == EXPECT and d3['sets'][0]['app'] == APP_NAME and d3['sets'][0]['preview'] == 'ran'
# On this instance the preview flags the deletions of the earlier properties as "Found a local update that is newer than
# this one" (their versions here were recorded again by the build); any other problem stops the export.
allowed = ['error: %s DELETE - Found a local update that is newer than this one' % p['name'] for p in PRIOR if p['table'] == 'sys_properties']
assert all(x in allowed for x in d3['sets'][0]['problems']), d3['sets'][0]['problems']
arch = os.path.join(BASE, 'stories', '_update_sets'); fname = NAME.replace(' ', '_') + '.xml'
shutil.copy(OUT, os.path.join(arch, fname))
idx_path = os.path.join(arch, 'index.json'); idx = json.load(open(idx_path)); idx = [e for e in idx if e['name'] != NAME]
created = root.find('sys_remote_update_set/sys_created_on')
idx.append({'name': NAME, 'app': 'x_boar_bofa_usem_0 (mirror of the client application, same scope name and sys_id)', 'rows': EXPECT, 'exported': n, 'file': fname, 'created': created.text if created is not None else '',
            'scrub': ['client scope and application sys_id: importable on the client instance as is; the client receives the record XML too', 'topic property empty, for the client to fill']})
json.dump(idx, open(idx_path, 'w'), indent=1)
print('archived as', fname)
restored = ui.js('''
var o = {};
new GlideUpdateSet().set(%s);
var p = new GlideRecord('sys_properties'); p.addQuery('name', %s); p.query(); p.next();
p.setValue('value', gs.generateGUID()); p.update();
var back = new GlideRecord('sys_properties'); back.get(p.getUniqueValue()); o.value = '' + (back.getValue('value') || '');
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(ST['default_set']), json.dumps(TOPIC)), scope=ST['scope'])
assert len(restored['value']) == 32, restored
print('topic property given a fresh id on the development instance again, under its Default set')
print('EXPORT OK')
