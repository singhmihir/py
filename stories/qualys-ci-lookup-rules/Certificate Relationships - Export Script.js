/* Certificate relationships of the discovered items (read-only)
   -------------------------------------------------------------------------------------------------
   For every discovered item whose CI is a Unique Certificate, lists the CIs the certificate is related
   to (cmdb_rel_ci, either direction) with the class, install status, operational status, address and
   fqdn of each related record, and the verdict a lookup rule would reach if it followed the
   certificate to a device: one live device, several, or none. A device counts when it sits in the
   Hardware tree, is not a load balancer, is not of an ignored class and is not retired. One row per
   item and related record; an item whose certificate has no relationship gets one row with the
   related columns empty. The file is a CSV (opens directly in Excel) attached to the record named in
   TARGET_TABLE / TARGET_SYS_ID; leave TARGET_SYS_ID empty to print the CSV in the output instead.
   Nothing else is written.
   ------------------------------------------------------------------------------------------------- */
var SOURCE_NAME = 'Qualys';                       // the discovery source, matched with CONTAINS
var TARGET_TABLE = 'incident';                    // record that receives the CSV attachment
var TARGET_SYS_ID = '';                           // empty = print the CSV instead of attaching it
var FILE_NAME = 'Certificate Relationships.csv';
var BATCH = 200;                                  // certificates per relationship query

function csvCell(v) { v = '' + (v == null ? '' : v); return '"' + v.replace(/"/g, '""') + '"'; }
var ignore = ',' + gs.getProperty('sn_sec_cmn.ignoreCIClass', '') + ',';

// 1. the discovered items on certificates, with the scanned values from the source data
var items = [], certIds = {};
var di = new GlideRecord('sn_sec_cmn_src_ci');
di.addQuery('source.name', 'CONTAINS', SOURCE_NAME);
di.addQuery('cmdb_ci.sys_class_name', 'cmdb_ci_certificate');
di.query();
while (di.next()) {
    var payload = {};
    try { payload = JSON.parse('' + di.getValue('source_data')); } catch (e) { }
    var cert = '' + di.getValue('cmdb_ci');
    certIds[cert] = true;
    items.push({ number: '' + di.getValue('number'), ip: payload.IP || '', dns: payload.DNS || '', os: payload.OS || '', cert: cert, certName: '' + di.cmdb_ci.name, updated: '' + di.getValue('sys_updated_on') });
}

// 2. the relationships of those certificates, both directions, in batches
var related = {};                                 // certificate sys_id -> [{other, type, direction}]
var ids = Object.keys(certIds);
for (var b = 0; b < ids.length; b += BATCH) {
    var slice = ids.slice(b, b + BATCH).join(',');
    var rel = new GlideRecord('cmdb_rel_ci');
    rel.addQuery('parent', 'IN', slice).addOrCondition('child', 'IN', slice);
    rel.query();
    while (rel.next()) {
        var parent = '' + rel.getValue('parent'), child = '' + rel.getValue('child'), type = rel.type.getDisplayValue();
        if (certIds[parent])
            (related[parent] = related[parent] || []).push({ other: child, type: type, direction: 'certificate is parent' });
        if (certIds[child] && child != parent)
            (related[child] = related[child] || []).push({ other: parent, type: type, direction: 'certificate is child' });
    }
}

// 3. the related records, read once each
var records = {};
function describe(id) {
    if (records[id]) return records[id];
    var ci = new GlideRecord('cmdb_ci');
    if (!ci.get(id)) return (records[id] = { name: '(record not found)', cls: '', install: '', operational: '', ip: '', fqdn: '', hardware: false, lb: false, ignored: false, retired: false, live: false });
    var cls = '' + ci.getValue('sys_class_name');
    var hardware = new GlideRecord('cmdb_ci_hardware').get(id);
    var lbTable = new GlideRecord('cmdb_ci_lb');
    var lb = lbTable.isValid() && lbTable.get(id);
    var ignored = ignore.indexOf(',' + cls + ',') != -1;
    var retired = ci.getValue('install_status') == '7' || ci.getValue('operational_status') == '6' || ci.life_cycle_stage_status.getDisplayValue() == 'Retired';
    return (records[id] = { name: '' + ci.getValue('name'), cls: cls, install: ci.install_status.getDisplayValue(), operational: ci.operational_status.getDisplayValue(),
        ip: '' + (ci.getValue('ip_address') || ''), fqdn: '' + (ci.getValue('fqdn') || ''), hardware: hardware, lb: lb, ignored: ignored, retired: retired, live: hardware && !lb && !ignored && !retired });
}

// 4. the verdict per certificate: distinct live devices behind it
var verdict = {};
for (var c in related) {
    var live = {}, devices = {};
    for (var r = 0; r < related[c].length; r++) {
        var d = describe(related[c][r].other);
        if (d.hardware) devices[related[c][r].other] = true;
        if (d.live) live[related[c][r].other] = true;
    }
    var n = Object.keys(live).length;
    verdict[c] = { live: n, devices: Object.keys(devices).length, text: n == 1 ? 'one live device' : n == 0 ? 'none' : 'several' };
}

// 5. the CSV, one row per item and related record
var header = ['Item', 'Scanned IP', 'Scanned DNS', 'Scanned OS', 'Item updated', 'Certificate', 'Certificate sys_id', 'Direction', 'Relationship type',
              'Related record', 'Related sys_id', 'Related class', 'Install status', 'Operational status', 'Related IP address', 'Related fqdn',
              'In hardware tree', 'Load balancer', 'Ignored class', 'Retired', 'Counts as live device', 'Devices behind the certificate', 'Live devices behind the certificate', 'Verdict'];
var csv = [header.map(csvCell).join(',')];
var summary = { items: items.length, certificates: ids.length, withRelationship: 0, one: 0, several: 0, none: 0, noRelationship: 0 };
for (var i = 0; i < items.length; i++) {
    var it = items[i], rels = related[it.cert] || [], v = verdict[it.cert];
    var base = [it.number, it.ip, it.dns, it.os, it.updated, it.certName, it.cert];
    if (!rels.length) {
        summary.noRelationship++;
        csv.push(base.concat(['none', '', '', '', '', '', '', '', '', '', '', '', '', '', 0, 0, 'no relationship']).map(csvCell).join(','));
        continue;
    }
    summary.withRelationship++;
    summary[v.live == 1 ? 'one' : v.live == 0 ? 'none' : 'several']++;
    for (var k = 0; k < rels.length; k++) {
        var rec = describe(rels[k].other);
        csv.push(base.concat([rels[k].direction, rels[k].type, rec.name, rels[k].other, rec.cls, rec.install, rec.operational, rec.ip, rec.fqdn,
            rec.hardware ? 'yes' : 'no', rec.lb ? 'yes' : 'no', rec.ignored ? 'yes' : 'no', rec.retired ? 'yes' : 'no', rec.live ? 'yes' : 'no', v.devices, v.live, v.text]).map(csvCell).join(','));
    }
}
var text = csv.join('\n');
gs.print('items on certificates: ' + summary.items + ' | certificates: ' + summary.certificates + ' | items whose certificate has a relationship: ' + summary.withRelationship +
    ' (one live device: ' + summary.one + ', several: ' + summary.several + ', none live: ' + summary.none + ') | no relationship: ' + summary.noRelationship + ' | rows: ' + (csv.length - 1));
if (TARGET_SYS_ID) {
    var target = new GlideRecord(TARGET_TABLE);
    if (!target.get(TARGET_SYS_ID)) {
        gs.print('target record not found; CSV follows');
        gs.print(text);
    } else {
        var att = new GlideSysAttachment();
        var attId = att.write(target, FILE_NAME, 'text/csv', text);
        gs.print('attached ' + FILE_NAME + ' to ' + TARGET_TABLE + ' ' + target.getDisplayValue() + ' (' + attId + ')');
    }
} else
    gs.print(text);
