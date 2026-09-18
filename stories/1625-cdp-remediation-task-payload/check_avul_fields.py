"""Compares the CDP-required fields of the remediation task sheet against the delivered AVUL property.

Reads the sheet "Outbound to CDP (RemTask)" of a copy of the mapping workbook, keeps the rows marked
CDP Required? = Yes for the application remediation task (the common rows plus the
sn_vul_app_vulnerability rows) and reports what the workbook now asks for against
usem.cdp.remtask.fields.sn_vul_app_vulnerability as delivered, and against the copy of the sheet the
property was built from (remtask_mapping.json). Reporting only; nothing is changed.

    python3 check_avul_fields.py <workbook.xlsx>
"""
import json, os, sys
import openpyxl

HERE = os.path.dirname(os.path.abspath(__file__))
SHEET = 'Outbound to CDP (RemTask)'
TABLES = ('Common (AVR, IVR, CC, CVR)', 'sn_vul_app_vulnerability (App. VR)')
DERIVED = ('change_requests', 'exception requests', 'exception_requests')


def sheet_rows(path):
    ws = openpyxl.load_workbook(path, data_only=True, read_only=True)[SHEET]
    rows = list(ws.iter_rows(values_only=True))
    head = [str(c).strip() if c is not None else '' for c in rows[0]]
    col = {name: head.index(name) for name in ('CDP Required?', 'JSON structure', 'JSON field name', 'Table', 'SN Field Label', 'SN Field Name', 'Expected field type in CDP')}
    out = []
    for r in rows[1:]:
        def cell(name):
            v = r[col[name]]
            return str(v).strip() if v is not None else ''
        if not cell('JSON field name'):
            continue
        out.append({'json': cell('JSON field name'), 'sn_field': cell('SN Field Name'), 'sn_label': cell('SN Field Label'),
                    'table': cell('Table'), 'required': cell('CDP Required?'), 'structure': cell('JSON structure'), 'type': cell('Expected field type in CDP')})
    return out


def avul(rows):
    return [r for r in rows if r['required'].lower() == 'yes' and r['table'] in TABLES]


def pairs(rows):
    """json field -> ServiceNow field, leaving out the rows the builder derives."""
    return {r['json']: r['sn_field'] for r in rows if r['json'] not in DERIVED}


def property_pairs():
    text = open(os.path.join(HERE, 'client', 'x_boar_bofa_usem_1.usem.cdp.remtask.fields.sn_vul_app_vulnerability.txt')).read()
    out = {}
    for entry in text.replace('\r', '').replace(',', '\n').split('\n'):
        entry = entry.strip()
        if not entry:
            continue
        field, _, json_name = entry.partition('=')
        out[(json_name or field).strip()] = field.strip()
    return out


def report(title, now, before, now_label, before_label):
    added = [k for k in now if k not in before]
    removed = [k for k in before if k not in now]
    changed = [(k, before[k], now[k]) for k in now if k in before and now[k] != before[k]]
    print('== %s' % title)
    print('   %s: %d fields | %s: %d fields' % (now_label, len(now), before_label, len(before)))
    print('   added in %s: %s' % (now_label, ', '.join('%s (%s)' % (k, now[k] or 'no ServiceNow field') for k in added) if added else 'none'))
    print('   missing from %s: %s' % (now_label, ', '.join('%s (%s)' % (k, before[k]) for k in removed) if removed else 'none'))
    print('   ServiceNow field changed: %s' % (', '.join('%s: %s -> %s' % c for c in changed) if changed else 'none'))
    return added, removed, changed


path = sys.argv[1] if len(sys.argv) > 1 else None
if not path:
    sys.exit(__doc__)
new_rows = avul(sheet_rows(path))
old_rows = avul(json.load(open(os.path.join(HERE, 'remtask_mapping.json'))))
new, old, prop = pairs(new_rows), pairs(old_rows), property_pairs()
print('workbook: %s' % os.path.basename(path))
print('sheet "%s": %d CDP-required rows for the application remediation task (%d common, %d application)' % (
    SHEET, len(new_rows), sum(1 for r in new_rows if r['table'] == TABLES[0]), sum(1 for r in new_rows if r['table'] == TABLES[1])))
print('derived rows carried by the builder, not by the property: %s' % ', '.join(r['json'] for r in new_rows if r['json'] in DERIVED))
print()
a1, r1, c1 = report('New workbook against the delivered property', new, prop, 'workbook', 'property')
print()
a2, r2, c2 = report('New workbook against the copy the property was built from', new, old, 'new workbook', 'previous workbook')
print()
print('VERDICT: no change to the AVUL field list' if not (a1 or r1 or c1) else 'VERDICT: the AVUL field list differs, see above')
