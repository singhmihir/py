"""Runs the field-check background script on the PDI, keeps its report (field_resolution.json and the
printed output in field_check_output.txt) and writes properties.json: the topic property, the sections
property (the ServiceNow table on the left, the JSON structure of the sheet on the right, in sheet
order) and the fields property of the application vulnerable item table (the ServiceNow field the
check resolved on the left, the sheet's JSON field name on the right, a row not found keeping the
sheet name on the left until the field is known)."""
import os, sys, json, re, html
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
ITEM = 'sn_vul_app_vulnerable_item'
script = open(os.path.join(HERE, 'VAMP Field Check - Background Script.js')).read()
ui = SNUI(); ui.app('global')
raw = ui.run(script + "\ngs.print('X::' + JSON.stringify({report: report, fields: fieldLines, sections: sectionLines}));")
m = re.search(r'X::(\{.*\})', raw, re.S)
if not m:
    raise RuntimeError('NO MARKER; tail: ' + raw[-1500:])
result = json.loads(m.group(1))
text = html.unescape(re.sub(r'<[^>]+>', '\n', raw))
start = text.find('SN to VAMP field check'); end = text.find('*** Script: X::')
output = re.sub(r'\n\s*\n+', '\n', text[start:end]).replace('*** Script: ', '\n').strip()
host = INST.split('//')[-1].split('.')[0]
open(os.path.join(HERE, 'field_check_output.txt'), 'w').write(output.replace(host, 'the instance') + '\n')
json.dump(result['report'], open(os.path.join(HERE, 'field_resolution.json'), 'w'), indent=1)
sheet = json.load(open(os.path.join(HERE, 'vamp_mapping.json')))
sections = json.load(open(os.path.join(HERE, 'vamp_sections.json')))
assert [(e['table'], e['json']) for e in result['report']] == [(r['table'], r['json']) for r in sheet]
assert result['sections'] == ['%s=%s,' % (s['table'], s['json']) for s in sections], result['sections']
expected_lines = ['%s%s=%s,' % ('' if e['table'] == ITEM else e['table'] + '.', e['field'] or e['json'], e['json']) for e in result['report']]
assert result['fields'] == expected_lines, (result['fields'], expected_lines)
props = {'usem.vamp.kafka.topic_sys_id': {
    'value': '',
    'description': 'sys_id of the Kafka Topic record [sys_kafka_topic] for sn_usem_verification_outbound, read by BOFASIKafkaProducerVamp.'},
    'usem.vamp.sections.' + ITEM: {
    'value': '\n'.join(result['sections']),
    'description': 'VAMP payload sections, one servicenow_table=json_structure pair per line in payload order: the ServiceNow table on the left, the JSON structure of the sheet "SN to VAMP" on the right. The section of a table reached through a many to many (the remediation tasks of the item) is a list, one entry per linked record.'},
    'usem.vamp.fields.' + ITEM: {
    'value': '\n'.join(result['fields']),
    'description': 'VAMP payload fields, one servicenow_field=json_field pair per line in payload order: the ServiceNow field on the left (verified with the field check script), the JSON field name of the sheet "SN to VAMP" on the right; the fields of the application vulnerable item plain, the fields of another section as <table>.<field>. A field missing on the table or empty is sent as "".'}}
json.dump(props, open(os.path.join(HERE, 'properties.json'), 'w'), indent=1)
print(output)
print('\nresolved %d of %d rows; properties.json written' % (sum(1 for e in result['report'] if e['field']), len(result['report'])))
