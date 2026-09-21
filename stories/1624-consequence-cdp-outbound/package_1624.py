"""Builds the import-ready record XML for the client instance from the records deployed on the PDI:
the two script includes, the two properties and the rule, already in the client consequence application
x_boar_bofa_usem_0 (BOFA USEM Consequence), which the PDI mirrors with the same scope name and sys_id. User, timestamp and mod-count fields are left out so the import stamps
them; the topic property is delivered empty for the client to fill with the sys_id of its Kafka topic."""
import os, sys, json, re
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
WORKING = [INST.split('//')[1].split('.')[0], os.environ['SN_USER']]   # instance and user names that must never reach a delivered file
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
ST = json.load(open(os.path.join(HERE, 'state.json')))
OUT = os.path.join(HERE, 'Consequence CDP Outbound Payload - Records.xml')
CLIENT_SCOPE = '488be1cd2b1247102b30f8e14391bf0c'   # BOFA USEM Consequence, the same sys_id on the PDI mirror and on the client
CLIENT_PREFIX = 'x_boar_bofa_usem_0'
CONSEQUENCE = CLIENT_PREFIX + '_consequence'
STAMP = re.compile(r'<(sys_created_by|sys_created_on|sys_updated_by|sys_updated_on|sys_mod_count)>[^<]*</\1>\n?')
ui = SNUI(); ui.app('global')
def unload(table, ids):
    recs = []
    for sys_id in ids:
        r = ui.s.get(INST + '/%s.do' % table, params={'XML': '', 'sys_id': sys_id}); r.raise_for_status()
        m = re.search(r'<%s>(.*?)</%s>' % (table, table), r.text, re.S)
        assert m and '<sys_id>%s</sys_id>' % sys_id in m.group(1), (table, sys_id)
        recs.append('<%s action="INSERT_OR_UPDATE">%s</%s>' % (table, m.group(1), table))
    return recs
records = unload('sys_script_include', list(ST['si'].values())) + unload('sys_properties', list(ST['props'].values())) + unload('sys_script', [ST['br']])
def repoint(rec):
    rec = STAMP.sub('', rec)
    if '<name>%s.usem.consequence.kafka.topic_sys_id</name>' % CLIENT_PREFIX in rec:
        rec = re.sub(r'<value>[^<]*</value>', '<value/>', rec)
    return rec
records = [repoint(r) for r in records]
content = '<?xml version="1.0" encoding="UTF-8"?>\n<unload>\n' + '\n'.join(records) + '\n</unload>\n'
open(OUT, 'w').write(content)
root = ET.parse(OUT).getroot()
sis = root.findall('sys_script_include'); props = root.findall('sys_properties'); brs = root.findall('sys_script')
for r in sis:
    script = open(os.path.join(HERE, r.findtext('name') + '.js')).read().rstrip('\n')
    assert r.findtext('script').rstrip('\n') == script and r.findtext('api_name') == CLIENT_PREFIX + '.' + r.findtext('name') and r.findtext('sys_scope') == CLIENT_SCOPE and r.findtext('access') == 'public', r.findtext('name')
    print('  script include', r.findtext('api_name'), r.findtext('sys_id'), '| script matches repository file')
expected_props = json.load(open(os.path.join(HERE, 'properties.json')))
for r in props:
    suffix = r.findtext('name')[len(CLIENT_PREFIX) + 1:]
    assert (r.findtext('value') or '') == expected_props[suffix]['value'] and r.findtext('sys_scope') == CLIENT_SCOPE, (r.findtext('name'), r.findtext('value'))
    print('  property', r.findtext('name'), '| value', repr((r.findtext('value') or '')[:40]))
for r in brs:
    script = open(os.path.join(HERE, r.findtext('name') + '.js')).read().rstrip('\n')
    assert r.findtext('script').rstrip('\n') == script and r.findtext('collection') == CONSEQUENCE and r.findtext('when') == 'after' and r.findtext('action_insert') == 'true' and r.findtext('action_update') == 'true' and r.findtext('sys_scope') == CLIENT_SCOPE
    print('  rule', r.findtext('name'), r.findtext('sys_id'), '| after insert/update on', r.findtext('collection'), '| order', r.findtext('order'))
low = content.lower()
TOOLING = [w[::-1] for w in ['edualc', 'cipohtna', 'ianepo', 'tpg']]   # assistant and model names, spelled backwards so this file never carries them
hits = [t for t in [w.lower() for w in WORKING] + ['service-now.com', 'x_196061', 'bofasim'] + TOOLING if t in low]
assert len(sis) == 2 and len(props) == 2 and len(brs) == 1 and not hits and '<sys_updated_by>' not in content, hits
print('written:', OUT, len(content), 'bytes | records', len(sis) + len(props) + len(brs), '| scrub', 'CLEAN' if not hits else hits)
