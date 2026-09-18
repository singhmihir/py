"""Cross-checks the workbook against every delivered artifact, offline: the sheet rows against
vamp_mapping.json, properties.json, the property values inside the record XML, the rows embedded in
the field-check script and the keys of the sample payload. Any difference is a transcription error."""
import os, json, re
import openpyxl
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__))
ws = openpyxl.load_workbook(os.path.join(HERE, 'SN to VAMP Mapping.xlsx'), data_only=True)['SN to VAMP']
sheet = [(str(r[4]).strip(), str(r[1]).strip(), str(r[0]).strip(), str(r[3]).strip()) for r in ws.iter_rows(min_row=2, values_only=True) if r[1]]
by_table = {}
for table, field, label, dtype in sheet:
    by_table.setdefault(table, []).append(field)
problems = []
mapping = json.load(open(os.path.join(HERE, 'vamp_mapping.json')))
if [(r['table'], r['field'], r['label'], r['type']) for r in mapping] != sheet:
    problems.append('vamp_mapping.json differs from the sheet')
props = json.load(open(os.path.join(HERE, 'properties.json')))
AVIT = 'sn_vul_app_vulnerable_item'
expected_props = {'usem.vamp.fields.' + AVIT: '\n'.join(['%s=%s,' % (f, f) for f in by_table[AVIT]] + ['%s.%s=%s,' % (t, f, f) for t, fields in by_table.items() if t != AVIT for f in fields])}
for name, value in expected_props.items():
    if props.get(name, {}).get('value') != value:
        problems.append('properties.json: ' + name + ' differs from the sheet')
extra = sorted(set(props) - set(expected_props) - {'usem.vamp.kafka.topic_sys_id'})
if extra:
    problems.append('properties.json holds properties outside the sheet: ' + ', '.join(extra))
root = ET.parse(os.path.join(HERE, 'VAMP AVIT Outbound Payload - Records.xml')).getroot()
xml_props = {r.findtext('name'): (r.findtext('value') or '') for r in root.findall('sys_properties')}
for name, value in expected_props.items():
    if xml_props.get('x_boar_bofa_usem_1.' + name) != value:
        problems.append('record XML: ' + name + ' differs from the sheet')
if sorted(xml_props) != sorted('x_boar_bofa_usem_1.' + n for n in props):
    problems.append('record XML property names differ from properties.json')
script = open(os.path.join(HERE, 'VAMP Field Check - Background Script.js')).read()
rows = json.loads(re.search(r'var SHEET = (\[.*?\]);\n', script, re.S).group(1))
if [(r['table'], r['field'], r['label'], r['type']) for r in rows] != sheet:
    problems.append('field-check script rows differ from the sheet')
sample = json.load(open(os.path.join(HERE, 'samples', 'Sample payload - application vulnerable item.json')))
sections = {'finding': 'sn_vul_app_vulnerable_item', 'tpe': 'sn_vul_app_vul_entry', 'remediation_task': 'sn_vul_app_vulnerability', 'ptreq': 'sn_vul_pen_test_assessment_request'}
element = sample['findings'][0]
if list(element) != list(sections):
    problems.append('sample payload sections: ' + ', '.join(element))
for key, table in sections.items():
    if list(element.get(key, {})) != by_table[table]:
        problems.append('sample payload %s keys %s differ from the sheet fields of %s' % (key, list(element.get(key, {})), table))
processor = open(os.path.join(HERE, 'BOFASIVampOutboundProcessor.js')).read()
for table in by_table:
    if not re.search(r'^\s+%s:\s+\{ key:' % re.escape(table), processor, re.M):
        problems.append('processor has no section for ' + table)
print('sheet rows:', len(sheet), '| tables:', ', '.join('%s (%d)' % (t, len(f)) for t, f in by_table.items()))
print('CHECK OK: sheet = mapping = properties.json (one field property) = record XML = field-check script = sample payload keys = processor sections' if not problems else 'PROBLEMS:\n- ' + '\n- '.join(problems))
raise SystemExit(1 if problems else 0)
