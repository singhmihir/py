"""Cross-checks the workbook against every delivered artifact, offline: the sheet rows against
vamp_mapping.json and vamp_sections.json, the rows embedded in the field-check script, the field
resolution the check produced, properties.json (one property, the ServiceNow field as resolved on the
left and <column H>.<column I> on the right, in sheet order), the property value inside the record XML, the structure and keys of the sample payload and the tables the
processor names. Any difference is a transcription error."""
import os, json, re
import openpyxl
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__))
ITEM = 'sn_vul_app_vulnerable_item'
MANY = 'sn_vul_app_vulnerability'
PREFIX = 'x_boar_bofa_usem_1'
ws = openpyxl.load_workbook(os.path.join(HERE, 'SN to VAMP Mapping.xlsx'), data_only=True)['SN to VAMP']
sheet = [(str(r[4]).strip(), str(r[7]).strip(), str(r[8]).strip(), str(r[0] or '').strip(), str(r[3]).strip())
         for r in ws.iter_rows(min_row=2, values_only=True) if r[8]]
structure_of, fields_of, order = {}, {}, []
for table, structure, json_name, label, dtype in sheet:
    name = structure.lower().replace(' ', '_')
    structure_of[table] = name
    fields_of.setdefault(name, []).append(json_name)
    if name not in order:
        order.append(name)
problems = []
mapping = json.load(open(os.path.join(HERE, 'vamp_mapping.json')))
if [(r['table'], r['structure'], r['json'], r['label'], r['type']) for r in mapping] != sheet:
    problems.append('vamp_mapping.json differs from the sheet')
sections = json.load(open(os.path.join(HERE, 'vamp_sections.json')))
if [(s['table'], s['json']) for s in sections] != [(t, structure_of[t]) for t in dict.fromkeys(r[0] for r in sheet)]:
    problems.append('vamp_sections.json differs from the sheet')
script = open(os.path.join(HERE, 'VAMP Field Check - Background Script.js')).read()
rows = json.loads(re.search(r'var SHEET = (\[.*?\]);\n', script, re.S).group(1))
if [(r['table'], r['structure'], r['json'], r['label'], r['type']) for r in rows] != sheet:
    problems.append('field-check script rows differ from the sheet')
if json.loads(re.search(r'var SECTIONS = (\[.*?\]);\n', script, re.S).group(1)) != sections:
    problems.append('field-check script sections differ from vamp_sections.json')
resolution = json.load(open(os.path.join(HERE, 'field_resolution.json')))
if [(e['table'], e['structure'], e['json'], e['label'], e['type']) for e in resolution] != sheet:
    problems.append('field_resolution.json rows differ from the sheet')
for e in resolution:
    if e['field'] and not e['type_ok']:
        problems.append('resolved field %s.%s has a type other than the sheet says' % (e['table'], e['field']))
expected_fields = '\n'.join('%s%s=%s.%s,' % ('' if e['table'] == ITEM else e['table'] + '.', e['field'] or e['json'], structure_of[e['table']], e['json']) for e in resolution)
props = json.load(open(os.path.join(HERE, 'properties.json')))
if props.get('usem.vamp.fields.' + ITEM, {}).get('value') != expected_fields:
    problems.append('properties.json field property differs from the resolution')
if sorted(props) != sorted(['usem.vamp.fields.' + ITEM, 'usem.vamp.kafka.topic_sys_id']):
    problems.append('properties.json holds other properties: ' + ', '.join(sorted(props)))
right_sides = [line.split('=')[1].rstrip(',') for line in expected_fields.split('\n')]
if right_sides != ['%s.%s' % (structure_of[e['table']], e['json']) for e in resolution] or sorted(right_sides) != sorted('%s.%s' % (structure_of[r[0]], r[2]) for r in sheet):
    problems.append('payload names on the right of the property are not exactly <column H>.<column I>')
if list(dict.fromkeys(n.split('.')[0] for n in right_sides)) != order:
    problems.append('the sections the property introduces are not the sheet structures in sheet order')
root = ET.parse(os.path.join(HERE, 'VAMP AVIT Outbound Payload - Records.xml')).getroot()
xml_props = {r.findtext('name'): (r.findtext('value') or '') for r in root.findall('sys_properties')}
if xml_props.get('%s.usem.vamp.fields.%s' % (PREFIX, ITEM)) != expected_fields:
    problems.append('record XML property differs from the resolution')
if sorted(xml_props) != sorted(PREFIX + '.' + n for n in props):
    problems.append('record XML property names differ from properties.json')
sample = json.load(open(os.path.join(HERE, 'samples', 'Sample payload - application vulnerable item.json')))
element = sample['findings'][0]
if list(element) != order:
    problems.append('sample payload structures: %s, the sheet says %s' % (list(element), order))
for name in order:
    entries = element.get(name) if isinstance(element.get(name), list) else [element.get(name, {})]
    for entry in entries:
        if list(entry) != fields_of[name]:
            problems.append('sample payload %s keys %s differ from the sheet field names' % (name, list(entry)))
if not isinstance(element.get(structure_of[MANY]), list):
    problems.append('the remediation task section of the sample is not a list')
if sample['envelope']['element_count'] != len(sample['findings']):
    problems.append('the sample element_count is not the number of findings')
ci = next(e for e in resolution if e['json'] == 'configuration_item')
if ci['field'] != 'cmdb_ci' or element['finding']['configuration_item'] != 'Trade Processing Portal':
    problems.append('configuration_item does not resolve to cmdb_ci with the display value in the sample')
# the processor's own wiring: every section of the sheet must be the item table or carry a path in
# RELATED, and the many to many section must be the one declared as a list
processor = open(os.path.join(HERE, 'BOFASIVampOutboundProcessor.js')).read()
related_block = re.search(r'this\.RELATED = \{([\s\S]*?)\n        \};', processor)
if not related_block:
    problems.append('the processor has no RELATED block')
else:
    paths = dict(re.findall(r'(\w+):\s*\{([^}]*)\}', related_block.group(1)))
    for table in structure_of:
        if table == ITEM:
            continue
        if table not in paths:
            problems.append('the processor has no path for section ' + table)
        elif table == MANY and 'list:' not in paths[table]:
            problems.append('the remediation task section is not declared as a list in the processor')
        elif table != MANY and 'reference:' not in paths[table]:
            problems.append('section %s is not declared as a reference in the processor' % table)
    for table in paths:
        if table not in structure_of:
            problems.append('the processor carries a path for %s, which is not a section of the sheet' % table)
    if 'sn_vul_app_m2m_vul_group_item' not in paths.get(MANY, ''):
        problems.append('the remediation tasks are not read through the group item table')
print('sheet rows:', len(sheet), '| sections:', ', '.join('%s -> %s' % (t, n) for t, n in structure_of.items()),
      '| resolved on the PDI:', sum(1 for e in resolution if e['field']),
      '| not found:', ', '.join('%s.%s' % (e['table'], e['json']) for e in resolution if not e['field']) or 'none')
print('CHECK OK: sheet = mapping = sections = field-check rows = resolution -> one property = record XML = sample structure and keys = processor wiring' if not problems else 'PROBLEMS:\n- ' + '\n- '.join(problems))
raise SystemExit(1 if problems else 0)
