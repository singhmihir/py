/* Discovered item classes (read-only)
   -------------------------------------------------------------------------------------------------
   Builds a spreadsheet of the CI classes the Qualys discovered items were matched into: one row per
   class, lookup rule and state, with the item count and the share, plus a total row. The file is a
   CSV (opens directly in Excel) attached to the record named in TARGET_TABLE / TARGET_SYS_ID; leave
   TARGET_SYS_ID empty to print the CSV in the output instead. DAYS = 0 takes every item of the source.
   ------------------------------------------------------------------------------------------------- */
var SOURCE_NAME = 'Qualys';                       // the discovery source, matched with CONTAINS
var DAYS = 0;                                     // 0 = all items; otherwise items updated in the last DAYS days
var TARGET_TABLE = 'incident';                    // record that receives the CSV attachment
var TARGET_SYS_ID = '';                           // empty = print the CSV instead of attaching it
var FILE_NAME = 'Discovered Item Classes.csv';

function csvCell(v) { v = '' + (v == null ? '' : v); return '"' + v.replace(/"/g, '""') + '"'; }
var rows = [];
var total = 0;
var ga = new GlideAggregate('sn_sec_cmn_src_ci');
ga.addQuery('source.name', 'CONTAINS', SOURCE_NAME);
if (DAYS > 0)
    ga.addQuery('sys_updated_on', '>=', gs.daysAgoStart(DAYS));
ga.addAggregate('COUNT');
ga.groupBy('cmdb_ci.sys_class_name');
ga.groupBy('ci_lookup_rule');
ga.groupBy('state');
ga.groupBy('matching_type');
ga.query();
while (ga.next()) {
    var cls = ga.getValue('cmdb_ci.sys_class_name');
    var clsLabel = cls ? new GlideRecord(cls).getLabel() : '(no CI)';
    var ruleId = ga.getValue('ci_lookup_rule');
    var ruleName = '';
    if (ruleId) { var rl = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); if (rl.get(ruleId)) ruleName = rl.getValue('order') + ' ' + rl.getValue('name'); }
    var n = parseInt(ga.getAggregate('COUNT'));
    total += n;
    rows.push({ cls: cls || '', clsLabel: clsLabel, rule: ruleName, state: ga.getValue('state'), matching: ga.getValue('matching_type'), n: n });
}
rows.sort(function (a, b) { return b.n - a.n; });
var csv = ['Class label,Class name,Lookup rule,State,Matching type,Items,Share'.split(',').map(csvCell).join(',')];
for (var i = 0; i < rows.length; i++)
    csv.push([rows[i].clsLabel, rows[i].cls, rows[i].rule, rows[i].state, rows[i].matching, rows[i].n, total ? (100 * rows[i].n / total).toFixed(2) + '%' : ''].map(csvCell).join(','));
csv.push(['Total', '', '', '', '', total, '100%'].map(csvCell).join(','));
var text = csv.join('\r\n');
if (TARGET_SYS_ID) {
    var target = new GlideRecord(TARGET_TABLE);
    if (!target.get(TARGET_SYS_ID)) {
        gs.print('target record not found; CSV follows');
        gs.print(text);
    } else {
        var att = new GlideSysAttachment();
        var id = att.write(target, FILE_NAME, 'text/csv', text);
        gs.print('attached ' + FILE_NAME + ' (' + rows.length + ' rows, ' + total + ' items) to ' + TARGET_TABLE + ' ' + target.getDisplayValue() + ' as ' + id);
    }
} else {
    gs.print(rows.length + ' rows, ' + total + ' items');
    gs.print(text);
}
