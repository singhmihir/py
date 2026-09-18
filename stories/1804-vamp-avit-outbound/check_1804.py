"""Cross-checks the workbook against every delivered artifact, offline: the sheet rows against
vamp_mapping.json, the rows embedded in the field-check script, the field resolution the check
produced, properties.json (ServiceNow field on the left as resolved, payload name on the right in
sheet order), the property values inside the record XML, the keys of the sample payload and the
processor's section list. Any difference is a transcription error."""
import os, json, re
import openpyxl
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__))
ITEM = 'sn_vul_app_vulnerable_item'
ws = openpyxl.load_workbook(os.path.join(HERE, 'SN to VAMP Mapping.xlsx'), data_only=True)['SN to VAMP']
sheet = [(str(r[4]).strip(), str(r[1]).strip(), str(r[0]).strip(), str(r[3]).strip()) for r in ws.iter_rows(min_row=2, values_only=True) if r[1]]
by_table = {}
for table, payload, label, dtype in sheet:
    by_table.setdefault(table, []).append(payload)
problems = []
mapping = json.load(open(os.path.join(HERE, 'vamp_mapping.json')))
if [(r['table'], r['payload'], r['label'], r['type']) for r in mapping] != sheet:
    problems.append('vamp_mapping.json differs from the sheet')
script = open(os.path.join(HERE, 'VAMP Field Check - Background Script.js')).read()
rows = json.loads(re.search(r'var SHEET = (\[.*?\]);\n', script, re.S).group(1))
if [(r['table'], r['payload'], r['label'], r['type']) for r in rows] != sheet:
    problems.append('field-check script rows differ from the sheet')
resolution = json.load(open(os.path.join(HERE, 'field_resolution.json')))
if [(e['table'], e['payload'], e['label'], e['type']) for e in resolution] != sheet:
    problems.append('field_resolution.json rows differ from the sheet')
for e in resolution:
    if e['field'] and not e['type_ok']:
        problems.append('resolved field %s.%s has a type other than the sheet says' % (e['table'], e['field']))
ordered = [e for p in (0, 1) for e in resolution if (p == 0) == (e['table'] == ITEM)]
expected_value = '\n'.join('%s%s=%s,' % ('' if e['table'] == ITEM else e['table'] + '.', e['field'] or e['payload'], e['payload']) for e in ordered)
props = json.load(open(os.path.join(HERE, 'properties.json')))
if props.get('usem.vamp.fields.' + ITEM, {}).get('value') != expected_value:
    problems.append('properties.json field property differs from the resolution')
if sorted(props) != ['usem.vamp.fields.' + ITEM, 'usem.vamp.kafka.topic_sys_id']:
    problems.append('properties.json holds other properties: ' + ', '.join(sorted(props)))
right_sides = [line.split('=')[1].rstrip(',') for line in expected_value.split('\n')]
if right_sides != [e['payload'] for e in ordered] or sorted(right_sides) != sorted(p for t, p, l, d in sheet):
    problems.append('payload names on the right of the property are not exactly the sheet column B')
root = ET.parse(os.path.join(HERE, 'VAMP AVIT Outbound Payload - Records.xml')).getroot()
xml_props = {r.findtext('name'): (r.findtext('value') or '') for r in root.findall('sys_properties')}
if xml_props.get('x_boar_bofa_usem_1.usem.vamp.fields.' + ITEM) != expected_value:
    problems.append('record XML field property differs from the resolution')
if sorted(xml_props) != sorted('x_boar_bofa_usem_1.' + n for n in props):
    problems.append('record XML property names differ from properties.json')
sample = json.load(open(os.path.join(HERE, 'samples', 'Sample payload - application vulnerable item.json')))
sections = {'finding': ITEM, 'tpe': 'sn_vul_app_vul_entry', 'remediation_task': 'sn_vul_app_vulnerability', 'ptreq': 'sn_vul_pen_test_assessment_request'}
element = sample['findings'][0]
if list(element) != list(sections):
    problems.append('sample payload sections: ' + ', '.join(element))
for key, table in sections.items():
    if list(element.get(key, {})) != by_table[table]:
        problems.append('sample payload %s keys %s differ from the sheet payload names of %s' % (key, list(element.get(key, {})), table))
ci = next(e for e in resolution if e['payload'] == 'configuration_item')
if ci['field'] != 'cmdb_ci' or len(element['finding']['configuration_item']) != 32:
    problems.append('configuration_item does not resolve to cmdb_ci with a sys_id in the sample')
processor = open(os.path.join(HERE, 'BOFASIVampOutboundProcessor.js')).read()
for table in by_table:
    if not re.search(r'^\s+%s:\s+\{ key:' % re.escape(table), processor, re.M):
        problems.append('processor has no section for ' + table)
print('sheet rows:', len(sheet), '| resolved on the PDI:', sum(1 for e in resolution if e['field']), '| not found:', ', '.join('%s.%s' % (e['table'], e['payload']) for e in resolution if not e['field']))
print('CHECK OK: sheet = mapping = field-check rows = resolution -> property (resolved field = sheet payload name) = record XML = sample keys = processor sections' if not problems else 'PROBLEMS:\n- ' + '\n- '.join(problems))
raise SystemExit(1 if problems else 0)
