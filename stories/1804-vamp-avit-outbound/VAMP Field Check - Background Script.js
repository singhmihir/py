// Checks the sheet "SN to VAMP" against this instance. For every sheet row it looks for the
// ServiceNow field behind the JSON field name: a field of that name, then a field with the sheet's
// label, then the u_ variant of the name. It checks the type against the sheet, prints one line per
// row, the two property values to use (the sections of the payload, and the ServiceNow field on the
// left with the JSON field name on the right) and the rows to raise. Read only; run as a background
// script in global scope.
var SHEET = [
    {
        "table": "sn_vul_app_vul_entry",
        "structure": "tpe",
        "json": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vul_entry",
        "structure": "tpe",
        "json": "u_vuln_sub_cat_id",
        "label": "",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerability",
        "structure": "remediation task",
        "json": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerability",
        "structure": "remediation task",
        "json": "primary_ait",
        "label": "Primary AIT",
        "type": "Reference"
    },
    {
        "table": "sn_vul_app_vulnerability",
        "structure": "remediation task",
        "json": "u_avul_record_url",
        "label": "",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "structure": "finding",
        "json": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "structure": "finding",
        "json": "sys_created_on",
        "label": "Created",
        "type": "Date/Time"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "structure": "finding",
        "json": "sys_updated_on",
        "label": "Updated",
        "type": "Date/Time"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "structure": "finding",
        "json": "state",
        "label": "State",
        "type": "Integer"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "structure": "finding",
        "json": "configuration_item",
        "label": "Configuration Item",
        "type": "Reference"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "structure": "finding",
        "json": "u_verification_status",
        "label": "Verification Status",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "structure": "finding",
        "json": "source_avit_id",
        "label": "Source AVIT ID",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "structure": "finding",
        "json": "u_avit_record_url",
        "label": "",
        "type": "String"
    },
    {
        "table": "sn_vul_pen_test_assessment_request",
        "structure": "ptreq",
        "json": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_pen_test_assessment_request",
        "structure": "ptreq",
        "json": "sys_created_on",
        "label": "Created",
        "type": "Date/Time"
    },
    {
        "table": "sn_vul_pen_test_assessment_request",
        "structure": "ptreq",
        "json": "u_assessment_id",
        "label": "Assessment ID",
        "type": "String"
    }
];
var SECTIONS = [
    {
        "table": "sn_vul_app_vul_entry",
        "json": "tpe"
    },
    {
        "table": "sn_vul_app_vulnerability",
        "json": "remediation_task"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "json": "finding"
    },
    {
        "table": "sn_vul_pen_test_assessment_request",
        "json": "ptreq"
    }
];
var TYPES = { 'String': ['string'], 'Reference': ['reference'], 'Date/Time': ['glide_date_time'], 'Integer': ['integer'] };
var ITEM_TABLE = 'sn_vul_app_vulnerable_item';
var report = [], lines = [], raise = [], fieldLines = [], sectionLines = [], cache = {};

function fieldsOf(table) {
    if (!cache[table]) {
        var list = [], gr = new GlideRecord(table);
        if (gr.isValid()) {
            gr.initialize();
            var all = gr.getFields();
            for (var i = 0; i < all.size(); i++) {
                var ed = all.get(i).getED();
                list.push({ name: '' + ed.getName(), label: '' + ed.getLabel(), type: '' + ed.getInternalType(), reference: '' + (ed.getReference() || '') });
            }
        }
        cache[table] = list;
    }
    return cache[table];
}

function first(list, test) {
    for (var i = 0; i < list.length; i++)
        if (test(list[i]))
            return list[i];
    return null;
}

function resolve(row) {
    var fields = fieldsOf(row.table);
    var label = row.label.toLowerCase().replace('record number', 'number');
    var alt = row.json.indexOf('u_') == 0 ? row.json.substring(2) : 'u_' + row.json;
    var found = first(fields, function(f) { return f.name == row.json; });
    if (found)
        return { field: found, how: 'same name' };
    if (label)
        found = first(fields, function(f) { return f.label.toLowerCase() == label || f.label.toLowerCase() == row.label.toLowerCase(); });
    if (found)
        return { field: found, how: 'label "' + found.label + '"' };
    found = first(fields, function(f) { return f.name == alt; });
    if (found)
        return { field: found, how: 'name ' + alt };
    return null;
}

function candidates(row) {
    var words = row.label.toLowerCase().replace('record number', 'number').split(/\s+/);
    var names = [];
    if (!row.label)
        return names;
    var fields = fieldsOf(row.table);
    for (var i = 0; i < fields.length; i++) {
        var l = fields[i].label.toLowerCase(), all = true;
        for (var w = 0; w < words.length; w++)
            if (l.indexOf(words[w]) < 0)
                all = false;
        if (all)
            names.push(fields[i].name + ' ("' + fields[i].label + '")');
    }
    return names;
}

for (var i = 0; i < SHEET.length; i++) {
    var row = SHEET[i], head = row.structure + '.' + row.json + ' (' + row.table + (row.label ? ', ' + row.label : '') + ', ' + row.type + '): ';
    var entry = { table: row.table, structure: row.structure, json: row.json, label: row.label, type: row.type, field: '', how: '', found_type: '', reference: '', type_ok: false, candidates: [] };
    if (!new GlideRecord(row.table).isValid()) {
        lines.push(head + 'TABLE MISSING');
        raise.push(row.table + ' does not exist');
    } else {
        var hit = resolve(row);
        if (!hit) {
            entry.candidates = candidates(row);
            lines.push(head + 'NOT FOUND - no field named ' + row.json + (row.label ? ', none labelled "' + row.label + '"' : '') + (entry.candidates.length ? '; similar labels: ' + entry.candidates.join(', ') : ''));
            raise.push(row.table + '.' + row.json + (row.label ? ' (' + row.label + ')' : '') + ' has no field on this instance');
        } else {
            entry.field = hit.field.name; entry.how = hit.how; entry.found_type = hit.field.type; entry.reference = hit.field.reference;
            entry.type_ok = (TYPES[row.type] || []).indexOf(hit.field.type) > -1;
            lines.push(head + hit.field.name + ' by ' + hit.how + ', type ' + hit.field.type + (hit.field.reference ? ' -> ' + hit.field.reference : '') + (entry.type_ok ? '' : ', TYPE DIFFERS FROM THE SHEET'));
            if (!entry.type_ok)
                raise.push(row.table + '.' + hit.field.name + ' is ' + hit.field.type + ' on this instance, the sheet says ' + row.type);
        }
    }
    report.push(entry);
}
for (var s = 0; s < SECTIONS.length; s++)
    sectionLines.push(SECTIONS[s].table + '=' + SECTIONS[s].json + ',');
for (var r = 0; r < report.length; r++) {
    var e = report[r];
    fieldLines.push((e.table == ITEM_TABLE ? '' : e.table + '.') + (e.field || e.json) + '=' + e.json + ',');
}
gs.print('SN to VAMP field check on ' + gs.getProperty('instance_name') + ' - ' + SHEET.length + ' sheet rows\n' + lines.join('\n'));
gs.print('Property value to use for usem.vamp.sections.' + ITEM_TABLE + ' (the JSON structure of the sheet, in sheet order):\n' + sectionLines.join('\n'));
gs.print('Property value to use for usem.vamp.fields.' + ITEM_TABLE + ' (a row not found keeps the sheet name until the field is known):\n' + fieldLines.join('\n'));
gs.print(raise.length ? 'To raise (' + raise.length + '):\n- ' + raise.join('\n- ') : 'Every sheet row resolves to a field of the sheet type.');
