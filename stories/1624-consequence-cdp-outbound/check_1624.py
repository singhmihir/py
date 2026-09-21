"""Cross-checks the workbook against every delivered artifact, offline: the required sheet rows against
consequence_mapping.json, the rows embedded in the field-check script, the field resolution the check
produced, properties.json (ServiceNow field on the left as resolved, payload name on the right in
sheet order), the property values inside the record XML, the keys of the sample payload and the
processor's section sources. Any difference is a transcription error."""
import os, json, re
import openpyxl
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__))
CONSEQUENCE, RULE = 'x_boar_bofa_usem_0_consequence', 'x_boar_bofa_usem_0_consequence_rule'
ws = openpyxl.load_workbook(os.path.join(HERE, 'Terminology per Source Consolidation.xlsx'), data_only=True)['Outbound to CDP (consequence)']
sheet = [(str(r[10]).strip(), str(r[8]).strip(), str(r[0]).strip(), str(r[1]).strip()) for r in ws.iter_rows(min_row=2, values_only=True) if r[8] and str(r[4] or '').strip().lower() == 'yes']
by_table = {}
for table, payload, label, field in sheet:
    by_table.setdefault(table, []).append(payload)
problems = []
mapping = json.load(open(os.path.join(HERE, 'consequence_mapping.json')))
if [(r['table'], r['payload'], r['label'], r['field']) for r in mapping] != sheet:
    problems.append('consequence_mapping.json differs from the sheet')
script = open(os.path.join(HERE, 'Consequence Field Check - Background Script.js')).read()
rows = json.loads(re.search(r'var SHEET = (\[.*?\]);\n', script, re.S).group(1))
if [(r['table'], r['payload'], r['label'], r['field']) for r in rows] != sheet:
    problems.append('field-check script rows differ from the sheet')
resolution = json.load(open(os.path.join(HERE, 'field_resolution.json')))
if [(e['table'], e['payload'], e['label'], e['sheet_field']) for e in resolution] != sheet:
    problems.append('field_resolution.json rows differ from the sheet')
ordered = [e for p in (0, 1) for e in resolution if (p == 0) == (e['table'] == CONSEQUENCE)]
expected_value = '\n'.join('%s%s=%s,' % ('' if e['table'] == CONSEQUENCE else e['table'] + '.', e['field'] or e['sheet_field'], e['payload']) for e in ordered)
props = json.load(open(os.path.join(HERE, 'properties.json')))
if props.get('usem.consequence.fields.' + CONSEQUENCE, {}).get('value') != expected_value:
    problems.append('properties.json field property differs from the resolution')
if sorted(props) != ['usem.consequence.fields.' + CONSEQUENCE, 'usem.consequence.kafka.topic_sys_id']:
    problems.append('properties.json holds other properties: ' + ', '.join(sorted(props)))
right_sides = [line.split('=')[1].rstrip(',') for line in expected_value.split('\n')]
if right_sides != [e['payload'] for e in ordered] or sorted(right_sides) != sorted(p for t, p, l, f in sheet):
    problems.append('payload names on the right of the property are not exactly the sheet JSON field names')
root = ET.parse(os.path.join(HERE, 'Consequence CDP Outbound Payload - Records.xml')).getroot()
xml_props = {r.findtext('name'): (r.findtext('value') or '') for r in root.findall('sys_properties')}
if xml_props.get('x_boar_bofa_usem_1.usem.consequence.fields.' + CONSEQUENCE) != expected_value:
    problems.append('record XML field property differs from the resolution')
if sorted(xml_props) != sorted('x_boar_bofa_usem_1.' + n for n in props):
    problems.append('record XML property names differ from properties.json')
sample = json.load(open(os.path.join(HERE, 'samples', 'Sample payload - consequence.json')))
element = sample['consequences'][0]
if list(element) != [CONSEQUENCE, RULE]:
    problems.append('sample payload sections: ' + ', '.join(element))
for table in (CONSEQUENCE, RULE):
    if list(element.get(table, {})) != by_table[table]:
        problems.append('sample payload %s keys %s differ from the sheet payload names' % (table, list(element.get(table, {}))))
if sample['envelope']['topic_name'] != 'sn_usem_consequence_outbound' or sorted(sample) != ['consequences', 'envelope']:
    problems.append('sample envelope or root keys')
client = json.load(open(os.path.join(HERE, 'samples', 'Client sample - sn_usem_consequence_outbound.json')))
client_keys = set(k for it in client['consequences'] for k in it['consequence']) | set('rule.' + k for it in client['consequences'] for k in it.get('rule', {}))
sheet_keys = set(by_table[CONSEQUENCE]) | set('rule.' + p for p in by_table[RULE])
if client_keys - sheet_keys:
    problems.append('client sample carries keys the sheet does not: ' + ', '.join(sorted(client_keys - sheet_keys)))
processor = open(os.path.join(HERE, 'BOFASIConsequenceOutboundProcessor.js')).read()
if RULE not in processor or "'u_rule'" not in processor or 'consequences:' not in processor:
    problems.append('processor does not reach the rule section through u_rule under the consequences key')
print('sheet rows required:', len(sheet), '| resolved on the PDI:', sum(1 for e in resolution if e['field']), '| not found:', ', '.join('%s.%s' % (e['table'], e['payload']) for e in resolution if not e['field']) or 'none',
      '| client sample keys not on the sheet:', ', '.join(sorted(client_keys - sheet_keys)) or 'none', '| sheet keys absent from the client sample:', ', '.join(sorted(sheet_keys - client_keys)) or 'none')
print('CHECK OK: sheet = mapping = field-check rows = resolution -> property (resolved field = sheet payload name) = record XML = sample keys = processor sections' if not problems else 'PROBLEMS:\n- ' + '\n- '.join(problems))
raise SystemExit(1 if problems else 0)
