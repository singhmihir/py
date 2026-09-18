// Checks every field of the sheet "SN to VAMP" against the dictionary of this instance.
// Read only. Run as a background script in global scope; the output lists one line per sheet
// row and a summary of what to raise.
var SHEET = [
    {
        "table": "sn_vul_app_vul_entry",
        "field": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerability",
        "field": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerability",
        "field": "primary_ait",
        "label": "Primary AIT",
        "type": "Reference"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "field": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "field": "sys_created_on",
        "label": "Created",
        "type": "Date/Time"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "field": "sys_updated_on",
        "label": "Updated",
        "type": "Date/Time"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "field": "state",
        "label": "State",
        "type": "Integer"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "field": "configuration_item",
        "label": "Configuration Item",
        "type": "Reference"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "field": "u_verification_status",
        "label": "Verification Status",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "field": "source_avit_id",
        "label": "Source AVIT ID",
        "type": "String"
    },
    {
        "table": "sn_vul_pen_test_assessment_request",
        "field": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_pen_test_assessment_request",
        "field": "sys_created_on",
        "label": "Created",
        "type": "Date/Time"
    },
    {
        "table": "sn_vul_pen_test_assessment_request",
        "field": "u_assessment_id",
        "label": "Assessment ID",
        "type": "String"
    }
];
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
gs.print('SN to VAMP field check on ' + gs.getProperty('instance_name') + ' - ' + SHEET.length + ' sheet rows\n' + lines.join('\n'));
gs.print(issues.length ? 'To raise (' + issues.length + '):\n- ' + issues.join('\n- ') : 'Every sheet field exists with the sheet type.');
