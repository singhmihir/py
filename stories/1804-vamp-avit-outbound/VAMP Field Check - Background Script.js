// Checks the sheet "SN to VAMP" against this instance. For every sheet row it looks for the
// ServiceNow field behind the payload name: a field of that name, then a field with the sheet's
// label, then the u_ variant of the name. It checks the type against the sheet, prints one line per
// row, the property value to use (ServiceNow field on the left, payload name on the right) and the
// rows to raise. Read only; run as a background script in global scope.
var SHEET = [
    {
        "table": "sn_vul_app_vul_entry",
        "payload": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerability",
        "payload": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerability",
        "payload": "primary_ait",
        "label": "Primary AIT",
        "type": "Reference"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "payload": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "payload": "sys_created_on",
        "label": "Created",
        "type": "Date/Time"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "payload": "sys_updated_on",
        "label": "Updated",
        "type": "Date/Time"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "payload": "state",
        "label": "State",
        "type": "Integer"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "payload": "configuration_item",
        "label": "Configuration Item",
        "type": "Reference"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "payload": "u_verification_status",
        "label": "Verification Status",
        "type": "String"
    },
    {
        "table": "sn_vul_app_vulnerable_item",
        "payload": "source_avit_id",
        "label": "Source AVIT ID",
        "type": "String"
    },
    {
        "table": "sn_vul_pen_test_assessment_request",
        "payload": "number",
        "label": "Record Number",
        "type": "String"
    },
    {
        "table": "sn_vul_pen_test_assessment_request",
        "payload": "sys_created_on",
        "label": "Created",
        "type": "Date/Time"
    },
    {
        "table": "sn_vul_pen_test_assessment_request",
        "payload": "u_assessment_id",
        "label": "Assessment ID",
        "type": "String"
    }
];
var TYPES = { 'String': ['string'], 'Reference': ['reference'], 'Date/Time': ['glide_date_time'], 'Integer': ['integer'] };
var ITEM_TABLE = 'sn_vul_app_vulnerable_item';
var report = [], lines = [], raise = [], propertyLines = [], cache = {};

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
    var alt = row.payload.indexOf('u_') == 0 ? row.payload.substring(2) : 'u_' + row.payload;
    var found = first(fields, function(f) { return f.name == row.payload; });
    if (found)
        return { field: found, how: 'same name' };
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
    var row = SHEET[i], head = row.table + '.' + row.payload + ' (' + row.label + ', ' + row.type + '): ';
    var entry = { table: row.table, payload: row.payload, label: row.label, type: row.type, field: '', how: '', found_type: '', reference: '', type_ok: false, candidates: [] };
    if (!new GlideRecord(row.table).isValid()) {
        lines.push(head + 'TABLE MISSING');
        raise.push(row.table + ' does not exist');
    } else {
        var hit = resolve(row);
        if (!hit) {
            entry.candidates = candidates(row);
            lines.push(head + 'NOT FOUND - no field named ' + row.payload + ', none labelled "' + row.label + '"' + (entry.candidates.length ? '; similar labels: ' + entry.candidates.join(', ') : ''));
            raise.push(row.table + '.' + row.payload + ' (' + row.label + ') has no field on this instance');
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
for (var p = 0; p < 2; p++)
    for (var r = 0; r < report.length; r++) {
        var e = report[r];
        if ((p == 0) != (e.table == ITEM_TABLE))
            continue;
        propertyLines.push((e.table == ITEM_TABLE ? '' : e.table + '.') + (e.field || e.payload) + '=' + e.payload + ',');
    }
gs.print('SN to VAMP field check on ' + gs.getProperty('instance_name') + ' - ' + SHEET.length + ' sheet rows\n' + lines.join('\n'));
gs.print('Property value to use for usem.vamp.fields.' + ITEM_TABLE + ' (a row not found keeps the sheet name until the field is known):\n' + propertyLines.join('\n'));
gs.print(raise.length ? 'To raise (' + raise.length + '):\n- ' + raise.join('\n- ') : 'Every sheet row resolves to a field of the sheet type.');
