"""Runs the field-check background script on the PDI (client table names swapped for the stand-in
tables while it runs), keeps its report (field_resolution.json and the printed output in
field_check_output.txt, both with the client table names) and writes properties.json: the topic
property and the one field property of the consequence table, the ServiceNow field the check resolved
on the left, the sheet's payload name on the right, a row not found keeping the sheet name on the left
until the field is known."""
import os, sys, json, re, html
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
CONSEQUENCE = 'x_boar_bofa_usem_0_consequence'
CLIENT_TABLE_PREFIX, PDI_TABLE_PREFIX = 'x_boar_bofa_usem_0', 'x_196061_bofasim'
AIT_PDI, AIT_CLIENT = 'x_196061_bofasim_ait', 'x_boar_bofa_techad_ait'   # the stand-in AIT table and the client's
script = open(os.path.join(HERE, 'Consequence Field Check - Background Script.js')).read().replace(CLIENT_TABLE_PREFIX, PDI_TABLE_PREFIX)
ui = SNUI(); ui.app('global')
raw = ui.run(script + "\ngs.print('X::' + JSON.stringify({report: report, property: propertyLines}));")
m = re.search(r'X::(\{.*\})', raw, re.S)
if not m:
    raise RuntimeError('NO MARKER; tail: ' + raw[-1500:])
client = lambda s: s.replace(AIT_PDI, AIT_CLIENT).replace(PDI_TABLE_PREFIX, CLIENT_TABLE_PREFIX)
result = json.loads(client(m.group(1)))
text = client(html.unescape(re.sub(r'<[^>]+>', '\n', raw)))
start = text.find('Outbound to CDP (consequence) field check'); end = text.find('*** Script: X::')
output = re.sub(r'\n\s*\n+', '\n', text[start:end]).replace('*** Script: ', '\n').strip()
open(os.path.join(HERE, 'field_check_output.txt'), 'w').write(output.replace(INST.split('//')[1].split('.')[0], 'the instance') + '\n')
json.dump(result['report'], open(os.path.join(HERE, 'field_resolution.json'), 'w'), indent=1)
sheet = json.load(open(os.path.join(HERE, 'consequence_mapping.json')))
assert [(e['table'], e['payload']) for e in result['report']] == [(r['table'], r['payload']) for r in sheet]
expected_lines = ['%s%s=%s,' % ('' if e['table'] == CONSEQUENCE else e['table'] + '.', e['field'] or e['sheet_field'], e['payload']) for p in (0, 1) for e in result['report'] if (p == 0) == (e['table'] == CONSEQUENCE)]
assert result['property'] == expected_lines, (result['property'], expected_lines)
props = {'usem.consequence.kafka.topic_sys_id': {
    'value': '',
    'description': 'sys_id of the Kafka Topic record [sys_kafka_topic] for sn_usem_consequence_outbound, read by BOFASIKafkaProducerConsequence.'},
    'usem.consequence.fields.' + CONSEQUENCE: {
    'value': '\n'.join(result['property']),
    'description': 'Consequence payload fields, one servicenow_field=payload_field pair per line in payload order: the ServiceNow field on the left (verified with the field check script), the payload name of the tab "Outbound to CDP (consequence)" on the right; the fields of the consequence first, then the fields of its rule as x_boar_bofa_usem_0_consequence_rule.<field>. A field missing on the table or empty is sent as "".'}}
json.dump(props, open(os.path.join(HERE, 'properties.json'), 'w'), indent=1)
print(output)
print('\nresolved %d of %d rows; properties.json written' % (sum(1 for e in result['report'] if e['field']), len(result['report'])))
