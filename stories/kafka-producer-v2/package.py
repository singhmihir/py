"""Builds the import-ready record XML for the client instance from the export received on INC0010003:
the producer under its existing sys_id and metadata, preceded by a deletion of the separate validator
V1.0 delivered (prior_records.json; Import XML deletes a record of an action="DELETE" element and ignores
a sys_id it does not hold). User, timestamp and mod-count fields are left out so the import stamps them."""
import os, sys, re, html, json
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), 'tools'))
from snui import INST
OUT = os.path.join(HERE, 'Kafka Producer V2 - Script Include.xml')
STAMP = re.compile(r'<(sys_created_by|sys_created_on|sys_updated_by|sys_updated_on|sys_mod_count)>[^<]*</\1>\n?')
def record(template, name, sys_id, script, description):
    t = STAMP.sub('', template)
    t = re.sub(r'<script><!\[CDATA\[.*?\]\]></script>', lambda m: '<script><![CDATA[' + script + ']]></script>', t, flags=re.S)
    t = re.sub(r'<description>.*?</description>|<description/>', '<description>' + html.escape(description, quote=False) + '</description>', t, flags=re.S)
    t = t.replace('BOFA_SI_KafkaProducerV2', name).replace('075d9ba02b9fc7102b30f8e14391bfdb', sys_id)
    return t
src = open(os.path.join(HERE, 'original', 'BOFA_SI_KafkaProducerV2.xml')).read()
template = re.search(r'<sys_script_include action="INSERT_OR_UPDATE">.*?</sys_script_include>', src, re.S).group(0)
producer = open(os.path.join(HERE, 'BOFA_SI_KafkaProducerV2.js')).read().rstrip('\n')
records = [
    record(template, 'BOFA_SI_KafkaProducerV2', '075d9ba02b9fc7102b30f8e14391bfdb', producer,
           'Utilizes KafkaProducer V2 to send messages to Hermes kafka. The payload is validated before it is sent (payload validation section of the script).\n'
           'Documentation of API used - https://www.servicenow.com/docs/r/api-reference/server-api-reference/ProducerV2ScopedAPI.html'),
]
PRIOR = json.load(open(os.path.join(HERE, 'prior_records.json')))['records']
deletions = ['<%s action="DELETE"><sys_id>%s</sys_id><name>%s</name></%s>' % (p['table'], p['sys_id'], p['name'], p['table']) for p in PRIOR]
content = '<?xml version="1.0" encoding="UTF-8"?>\n<unload>\n' + '\n'.join(deletions + records) + '\n</unload>\n'
open(OUT, 'w').write(content)
root = ET.parse(OUT).getroot()
dels = [r for r in root if r.get('action') == 'DELETE']
assert [(r.tag, r.findtext('sys_id')) for r in dels] == [(p['table'], p['sys_id']) for p in PRIOR] and list(root)[:len(dels)] == dels
print('  %d deletion of an earlier record first in the file' % len(dels))
names = [(r.findtext('name'), r.findtext('api_name'), r.findtext('sys_id'), r.findtext('sys_scope'), r.findtext('access')) for r in root.findall('sys_script_include') if r.get('action') != 'DELETE']
for n in names: print(' ', n)
for r in [r for r in root.findall('sys_script_include') if r.get('action') != 'DELETE']:
    assert r.findtext('script').rstrip('\n') == producer and r.findtext('sys_scope') == '4ba447d22b43cb10cb55fbcc6e91bf0f'
    assert r.findtext('api_name') == 'x_boar_bofa_usem_1.' + r.findtext('name') and r.findtext('sys_name') == r.findtext('name')
    assert r.findtext('sys_update_name') == 'sys_script_include_' + r.findtext('sys_id') and r.findtext('sys_updated_by') is None
assert [r.tag for r in root] == ['sys_script_include', 'sys_script_include'], [r.tag for r in root]
low = content.lower()
hits = [t for t in [w.lower() for w in [INST.split('//')[1].split('.')[0], os.environ.get('SN_USER', ''), os.environ.get('SN_PASSWORD', '')] if w] + ['dev390397', 'zk5lg9v', 'service-now.com', 'x_196061', 'bofasim'] + [w[::-1] for w in ['edualc', 'cipohtna', 'ianepo', 'tpg', 'rihim']] if t in low]   # assistant, model and personal names spelled backwards
assert not hits, hits
print('written:', OUT, len(content), 'bytes | records', len(names), '| scrub', 'CLEAN' if not hits else hits)
