"""Builds the import-ready record XML for the client instance from the exports received on
INC0010003: the producer keeps its sys_id and metadata, the validator is a new record in the
same scope. User, timestamp and mod-count fields are left out so the import stamps them."""
import os, re, uuid, html
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'Kafka Producer V2 - Script Includes.xml')
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
validator = open(os.path.join(HERE, 'BOFA_SI_KafkaPayloadValidator.js')).read().rstrip('\n')
assert 'BOFA_SI_KafkaPayloadValidator' not in template
records = [
    record(template, 'BOFA_SI_KafkaProducerV2', '075d9ba02b9fc7102b30f8e14391bfdb', producer,
           'Utilizes KafkaProducer V2 to send messages to Hermes kafka. The payload is checked by BOFA_SI_KafkaPayloadValidator before it is sent.\n'
           'Documentation of API used - https://www.servicenow.com/docs/r/api-reference/server-api-reference/ProducerV2ScopedAPI.html'),
    record(template, 'BOFA_SI_KafkaPayloadValidator', uuid.uuid4().hex, validator,
           'Checks an outbound Kafka payload before BOFA_SI_KafkaProducerV2 sends it: well-formed JSON, the envelope with every mandatory field, '
           'and one list of elements matching element_count. Throws an Error naming the first problem found, which the producer logs instead of sending.'),
]
content = '<?xml version="1.0" encoding="UTF-8"?>\n<unload>\n' + '\n'.join(records) + '\n</unload>\n'
open(OUT, 'w').write(content)
root = ET.parse(OUT).getroot()
names = [(r.findtext('name'), r.findtext('api_name'), r.findtext('sys_id'), r.findtext('sys_scope'), r.findtext('access')) for r in root.findall('sys_script_include')]
for n in names: print(' ', n)
for r in root.findall('sys_script_include'):
    assert r.findtext('script').rstrip('\n') in (producer, validator) and r.findtext('sys_scope') == '4ba447d22b43cb10cb55fbcc6e91bf0f'
    assert r.findtext('api_name') == 'x_boar_bofa_usem_1.' + r.findtext('name') and r.findtext('sys_name') == r.findtext('name')
    assert r.findtext('sys_update_name') == 'sys_script_include_' + r.findtext('sys_id') and r.findtext('sys_updated_by') is None
low = content.lower()
hits = [t for t in ['dev390397', 'zk5lg9v', 'service-now.com', 'x_196061', 'bofasim', 'claude', 'anthropic', 'openai', 'gpt'] if t in low]
print('written:', OUT, len(content), 'bytes | records', len(names), '| scrub', 'CLEAN' if not hits else hits)
