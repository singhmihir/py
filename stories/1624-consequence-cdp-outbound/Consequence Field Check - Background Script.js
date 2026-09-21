// Checks the tab "Outbound to CDP (consequence)" against this instance. For every sheet row it looks
// for the ServiceNow field behind the payload name: the sheet's field name, then the payload name,
// then a field with the sheet's label, then the u_ variant, then the name without its u_ or x_
// prefix. It prints one line per row, the property value to use (ServiceNow field on the left,
// payload name on the right) and the rows to raise. Read only; run as a background script in global scope.
var SHEET = [
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "state",
        "label": "State",
        "field": "u_state"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "accountable_party",
        "label": "Accountable Party",
        "field": "u_accountable_party"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "updated_on",
        "label": "Updated",
        "field": "sys_updated_on"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "comments",
        "label": "Comments",
        "field": "u_comments"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "change_freeze_effective_date",
        "label": "Change Freeze Effective Date",
        "field": "u_change_freeze_effective_date"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "consequence_level",
        "label": "Consequence Level",
        "field": "u_consequence_level"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "sys_id",
        "label": "Sys ID",
        "field": "sys_id"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "created_by",
        "label": "Created by",
        "field": "sys_created_by"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "enforcement_status",
        "label": "Enforcement Status",
        "field": "u_enforcement_status"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "network_isolation_effective_date",
        "label": "Network Isolation Effective Date",
        "field": "u_network_isolation_effective_date"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "rule",
        "label": "Rule",
        "field": "u_rule"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "cmdb_ci",
        "label": "Configuration item",
        "field": "cmdb_ci"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "created_on",
        "label": "Created",
        "field": "sys_created_on"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "bofa_ait",
        "label": "AIT",
        "field": "u_bofa_ait"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "number",
        "label": "Number",
        "field": "number"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "updated_by",
        "label": "Updated by",
        "field": "sys_updated_by"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence",
        "payload": "rejection_reason",
        "label": "Rejection Reason",
        "field": "u_rejection_reason"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "applies_to",
        "label": "Applies to",
        "field": "x_applies_to"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "comments",
        "label": "Comments",
        "field": "x_comments"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "conditions",
        "label": "Conditions",
        "field": "x_conditions"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "created_on",
        "label": "Created",
        "field": "sys_created_on"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "screated_by",
        "label": "Created by",
        "field": "sys_created_by"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "global_exception",
        "label": "Global Exception",
        "field": "x_global_exception"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "name",
        "label": "Name",
        "field": "x_name"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "number",
        "label": "Number",
        "field": "number"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "state",
        "label": "State",
        "field": "x_state"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "sys_id",
        "label": "Sys ID",
        "field": "sys_id"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "table",
        "label": "Table",
        "field": "x_table"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "updated_on",
        "label": "Updated",
        "field": "sys_updated_on"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "updated_by",
        "label": "Updated by",
        "field": "sys_updated_by"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "valid_from",
        "label": "Valid from",
        "field": "x_valid_from"
    },
    {
        "table": "x_boar_bofa_usem_0_consequence_rule",
        "payload": "valid_to",
        "label": "Valid to",
        "field": "x_valid_to"
    }
];
var CONSEQUENCE_TABLE = 'x_boar_bofa_usem_0_consequence';
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
            if (!first(list, function(f) { return f.name == 'sys_id'; }))
                list.push({ name: 'sys_id', label: 'Sys ID', type: 'GUID', reference: '' });
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
    var label = row.label.toLowerCase();
    var bare = row.field.replace(/^(u_|x_)/, '');
    var attempts = [
        ['same name', function(f) { return f.name == row.field; }],
        ['payload name', function(f) { return f.name == row.payload; }],
        ['label "' + row.label + '"', function(f) { return f.label.toLowerCase() == label; }],
        ['name u_' + bare, function(f) { return f.name == 'u_' + bare; }],
        ['name ' + bare, function(f) { return f.name == bare; }]
    ];
    for (var i = 0; i < attempts.length; i++) {
        var found = first(fields, attempts[i][1]);
        if (found)
            return { field: found, how: attempts[i][0] };
    }
    return null;
}

function candidates(row) {
    var words = row.label.toLowerCase().split(/\s+/);
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
    var row = SHEET[i], head = row.table + '.' + row.field + ' -> ' + row.payload + ' (' + row.label + '): ';
    var entry = { table: row.table, payload: row.payload, label: row.label, sheet_field: row.field, field: '', how: '', found_type: '', reference: '', candidates: [] };
    if (!new GlideRecord(row.table).isValid()) {
        lines.push(head + 'TABLE MISSING');
        raise.push(row.table + ' does not exist');
    } else {
        var hit = resolve(row);
        if (!hit) {
            entry.candidates = candidates(row);
            lines.push(head + 'NOT FOUND - no field named ' + row.field + ' or ' + row.payload + ', none labelled "' + row.label + '"' + (entry.candidates.length ? '; similar labels: ' + entry.candidates.join(', ') : ''));
            raise.push(row.table + '.' + row.field + ' (' + row.label + ') has no field on this instance');
        } else {
            entry.field = hit.field.name; entry.how = hit.how; entry.found_type = hit.field.type; entry.reference = hit.field.reference;
            lines.push(head + hit.field.name + ' by ' + hit.how + ', type ' + hit.field.type + (hit.field.reference ? ' -> ' + hit.field.reference : ''));
        }
    }
    report.push(entry);
}
for (var p = 0; p < 2; p++)
    for (var r = 0; r < report.length; r++) {
        var e = report[r];
        if ((p == 0) != (e.table == CONSEQUENCE_TABLE))
            continue;
        propertyLines.push((e.table == CONSEQUENCE_TABLE ? '' : e.table + '.') + (e.field || e.sheet_field) + '=' + e.payload + ',');
    }
gs.print('Outbound to CDP (consequence) field check on ' + gs.getProperty('instance_name') + ' - ' + SHEET.length + ' sheet rows\n' + lines.join('\n'));
gs.print('Property value to use for usem.consequence.fields.' + CONSEQUENCE_TABLE + ' (a row not found keeps the sheet name until the field is known):\n' + propertyLines.join('\n'));
gs.print(raise.length ? 'To raise (' + raise.length + '):\n- ' + raise.join('\n- ') : 'Every sheet row resolves to a field on this instance.');
