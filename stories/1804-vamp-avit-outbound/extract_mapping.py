"""Reads the sheet "SN to VAMP" of the client workbook and generates, without hand transcription:
vamp_mapping.json (the rows in sheet order), properties.json (the topic property and the one field
property of the application vulnerable item table: its own fields first, then the fields of the other
sheet tables as <table>.<field>, one servicenow_field=json_field pair per line, names exactly as the
sheet) and
the read-only background script that checks every sheet field against the dictionary of the
instance it runs on."""
import os, json
import openpyxl
HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT_PREFIX = 'x_boar_bofa_usem_1'
wb = openpyxl.load_workbook(os.path.join(HERE, 'SN to VAMP Mapping.xlsx'), data_only=True)
ws = wb['SN to VAMP']
header = [c for c in next(ws.iter_rows(min_row=1, max_row=1, values_only=True))]
assert header[:5] == ['SN Fields', 'SN Payload ID', 'VAMPRequired?', 'SN Data Type', 'Table'], header
rows = []
for r in ws.iter_rows(min_row=2, values_only=True):
    if not any(c is not None for c in r):
        continue
    label, field, required, dtype, table = (str(c).strip() if c is not None else '' for c in r[:5])
    notes = str(r[5]).strip() if len(r) > 5 and r[5] is not None else ''
    rows.append({'table': table, 'field': field, 'label': label, 'type': dtype, 'required': required, 'notes': notes})
tables = []
for r in rows:
    if r['table'] not in tables:
        tables.append(r['table'])
json.dump(rows, open(os.path.join(HERE, 'vamp_mapping.json'), 'w'), indent=1)
props = {'usem.vamp.kafka.topic_sys_id': {
    'value': '',
    'description': 'sys_id of the Kafka Topic record [sys_kafka_topic] for sn_usem_verification_outbound, read by BOFASIKafkaProducerVamp.'}}
AVIT = 'sn_vul_app_vulnerable_item'
required = [r for r in rows if r['required'].lower() == 'yes']
lines = ['%s=%s,' % (r['field'], r['field']) for r in required if r['table'] == AVIT]
lines += ['%s.%s=%s,' % (r['table'], r['field'], r['field']) for r in required if r['table'] != AVIT]
props['usem.vamp.fields.' + AVIT] = {
    'value': '\n'.join(lines),
    'description': 'VAMP payload fields, one servicenow_field=json_field pair per line in payload order, exactly the rows of the sheet "SN to VAMP": the fields of the application vulnerable item, then the fields of the related tables as <table>.<field> (sn_vul_app_vul_entry, sn_vul_app_vulnerability, sn_vul_pen_test_assessment_request); a field missing on the table or empty is sent as "".'}
json.dump(props, open(os.path.join(HERE, 'properties.json'), 'w'), indent=1)
check = '''// Checks every field of the sheet "SN to VAMP" against the dictionary of this instance.
// Read only. Run as a background script in global scope; the output lists one line per sheet
// row and a summary of what to raise.
var SHEET = %s;
var TYPES = { 'String': ['string'], 'Reference': ['reference'], 'Date/Time': ['glide_date_time'], 'Integer': ['integer'] };
var lines = [], issues = [];
for (var i = 0; i < SHEET.length; i++) {
    var row = SHEET[i];
    var gr = new GlideRecord(row.table);
    var line = row.table + '.' + row.field + ' (' + row.label + ', sheet type ' + row.type + '): ';
    if (!gr.isValid()) {
        line += 'TABLE MISSING';
        issues.push(row.table + ' does not exist');
    } else if (!gr.isValidField(row.field)) {
        line += 'FIELD MISSING';
        issues.push(row.table + '.' + row.field + ' (' + row.label + ') does not exist');
    } else {
        var ed = gr.getElement(row.field).getED();
        var type = '' + ed.getInternalType();
        var reference = '' + (ed.getReference() || '');
        line += 'found, type ' + type + (reference ? ' -> ' + reference : '') + ', label "' + ed.getLabel() + '"';
        if ((TYPES[row.type] || []).indexOf(type) < 0) {
            line += ', TYPE DIFFERS';
            issues.push(row.table + '.' + row.field + ' is ' + type + ' on this instance, the sheet says ' + row.type);
        }
    }
    lines.push(line);
}
gs.print('SN to VAMP field check on ' + gs.getProperty('instance_name') + ' - ' + SHEET.length + ' sheet rows\\n' + lines.join('\\n'));
gs.print(issues.length ? 'To raise (' + issues.length + '):\\n- ' + issues.join('\\n- ') : 'Every sheet field exists with the sheet type.');
''' % json.dumps([{'table': r['table'], 'field': r['field'], 'label': r['label'], 'type': r['type']} for r in rows], indent=4)
open(os.path.join(HERE, 'VAMP Field Check - Background Script.js'), 'w').write(check)
print('sheet rows:', len(rows), '| tables:', tables)
print('  usem.vamp.fields.' + AVIT + ' =\n    ' + props['usem.vamp.fields.' + AVIT]['value'].replace('\n', '\n    '))
print('required flags:', sorted(set(r['required'] for r in rows)), '| types:', sorted(set(r['type'] for r in rows)))
