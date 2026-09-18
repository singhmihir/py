"""Runs the field-check background script on the PDI, keeps its report (field_resolution.json and
the printed output in field_check_output.txt) and writes properties.json: the topic property and
the one field property of the application vulnerable item table, the ServiceNow field the check
resolved on the left, the sheet's payload name on the right, a row not found keeping the sheet name
on the left until the field is known."""
import os, sys, json, re, html
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
ITEM = 'sn_vul_app_vulnerable_item'
script = open(os.path.join(HERE, 'VAMP Field Check - Background Script.js')).read()
ui = SNUI(); ui.app('global')
raw = ui.run(script + "\ngs.print('X::' + JSON.stringify({report: report, property: propertyLines}));")
m = re.search(r'X::(\{.*\})', raw, re.S)
if not m:
    raise RuntimeError('NO MARKER; tail: ' + raw[-1500:])
result = json.loads(m.group(1))
text = html.unescape(re.sub(r'<[^>]+>', '\n', raw))
start = text.find('SN to VAMP field check'); end = text.find('*** Script: X::')
output = re.sub(r'\n\s*\n+', '\n', text[start:end]).replace('*** Script: ', '\n').strip()
open(os.path.join(HERE, 'field_check_output.txt'), 'w').write(output + '\n')
json.dump(result['report'], open(os.path.join(HERE, 'field_resolution.json'), 'w'), indent=1)
sheet = json.load(open(os.path.join(HERE, 'vamp_mapping.json')))
assert [(e['table'], e['payload']) for e in result['report']] == [(r['table'], r['payload']) for r in sheet]
expected_lines = ['%s%s=%s,' % ('' if e['table'] == ITEM else e['table'] + '.', e['field'] or e['payload'], e['payload']) for p in (0, 1) for e in result['report'] if (p == 0) == (e['table'] == ITEM)]
assert result['property'] == expected_lines, (result['property'], expected_lines)
props = {'usem.vamp.kafka.topic_sys_id': {
    'value': '',
    'description': 'sys_id of the Kafka Topic record [sys_kafka_topic] for sn_usem_verification_outbound, read by BOFASIKafkaProducerVamp.'},
    'usem.vamp.fields.' + ITEM: {
    'value': '\n'.join(result['property']),
    'description': 'VAMP payload fields, one servicenow_field=payload_field pair per line in payload order: the ServiceNow field on the left (verified with the field check script), the payload name of the sheet "SN to VAMP" on the right; the fields of the application vulnerable item first, then the fields of the related tables as <table>.<field> (sn_vul_app_vul_entry, sn_vul_app_vulnerability, sn_vul_pen_test_assessment_request). A field missing on the table or empty is sent as "".'}}
json.dump(props, open(os.path.join(HERE, 'properties.json'), 'w'), indent=1)
print(output)
print('\nresolved %d of %d rows; properties.json written' % (sum(1 for e in result['report'] if e['field']), len(result['report'])))
