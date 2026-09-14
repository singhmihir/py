/* Qualys lookup rule measurement (read-only)
   -------------------------------------------------------------------------------------------------
   Runs a sample of Discovered Items through the scripted Qualys lookup rules exactly as the framework
   does (one rule after the other, the first CI returned wins) without creating or updating anything,
   and compares the answer with what the item holds today. For every item the rules decline it
   records the evidence the CMDB offers for the scanned name and address, so the declines can be
   read by cause. Paste into Scripts - Background (global scope) and run; adjust the four settings.
   ------------------------------------------------------------------------------------------------- */
var MATCHED_LIMIT = 300;      // items in state matched to sample (newest first)
var UNMATCHED_LIMIT = 300;    // items in state unmatched to sample (newest first)
var DAYS = 30;                // only items created in the last DAYS days; 0 = any age
var LIST_CAP = 150;           // lines printed per detail list
var SKIP_ABSENT = true;       // leave hosts that exist nowhere in the CMDB out of the detail lists (they are still counted)

var started = new Date().getTime();
// every active scripted rule of the Qualys source, whatever its name, in chain order
var rules = [];
var rl = new GlideRecord('sn_sec_cmn_ci_lookup_rule');
rl.addQuery('source.name', 'CONTAINS', 'Qualys');
rl.addQuery('method', 'script');
rl.addActiveQuery();
rl.orderBy('order');
rl.query();
while (rl.next()) {
    var text = '' + rl.getValue('script');
    var marks = [];
    if (text.indexOf('agrees(') != -1) marks.push('class agreement');
    if (text.indexOf('hasNext()') != -1) marks.push('exactly one');
    if (text.indexOf('setLimit(') != -1) marks.push('setLimit');
    if (text.indexOf('usem.ci_lookup') != -1) marks.push('properties');
    rules.push({ id: rl.getUniqueValue(), order: '' + rl.getValue('order'), name: '' + rl.getValue('name'), field: '' + rl.getValue('source_field'),
        info: 'updated ' + rl.getValue('sys_updated_on') + ', ' + text.length + ' chars' + (marks.length ? ', ' + marks.join(', ') : '') });
}
var ruleRecords = {};
for (var r = 0; r < rules.length; r++) {
    var g = new GlideRecord('sn_sec_cmn_ci_lookup_rule');
    g.get(rules[r].id);
    ruleRecords[rules[r].id] = g;
}
var ignore = gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
var suffixes = ['ilo', 'ilom', 'idrac', 'drac', 'ipmi', 'bmc', 'oob', 'mgmt', 'imm', 'cimc', 'rmm', 'con'];

function classFor(os) {
    if (!os) return '';
    var s = ('' + os).toLowerCase();
    if (s.split('/').length > 2) return '';
    if (s.indexOf('esx') != -1) return 'cmdb_ci_esx_server';
    if (s.indexOf('windows') != -1) return s.indexOf('server') != -1 ? 'cmdb_ci_win_server' : 'cmdb_ci_computer';
    if (s.indexOf('aix') != -1) return 'cmdb_ci_aix_server';
    if (s.indexOf('solaris') != -1 || s.indexOf('sunos') != -1) return 'cmdb_ci_solaris_server';
    if (s.indexOf('hp-ux') != -1) return 'cmdb_ci_hpux_server';
    if (s.indexOf('netapp') != -1 || s.indexOf('ontap') != -1) return 'cmdb_ci_storage_server';
    if (s.indexOf('printer') != -1 || s.indexOf('laserjet') != -1 || s.indexOf('jetdirect') != -1) return 'cmdb_ci_printer';
    if (s.indexOf('red hat') != -1 || s.indexOf('linux') != -1 || s.indexOf('centos') != -1 || s.indexOf('ubuntu') != -1 || s.indexOf('suse') != -1 ||
        s.indexOf('debian') != -1 || s.indexOf('fedora') != -1 || s.indexOf('euleros') != -1 || s.indexOf('oracle enterprise') != -1 || s.indexOf('amazon') != -1)
        return 'cmdb_ci_linux_server';
    if (s.indexOf('nx-os') != -1 || s.indexOf('catos') != -1 || s.indexOf('cisco') != -1) return 'cmdb_ci_netgear';
    return '';
}
function kernelOnly(os) {
    var s = ('' + os).toLowerCase();
    return s.indexOf('linux') != -1 && !/red hat|centos|ubuntu|suse|debian|fedora|euleros|oracle|amazon|rhel/.test(s);
}
var parentCache = {};
function parentsOf(table) {
    if (parentCache[table]) return parentCache[table];
    var out = [table];
    var db = new GlideRecord('sys_db_object');
    db.addQuery('name', table);
    db.query();
    while (db.next() && db.getValue('super_class')) {
        var parent = '' + db.super_class.name;
        out.push(parent);
        db = new GlideRecord('sys_db_object');
        db.addQuery('name', parent);
        db.query();
    }
    return (parentCache[table] = out);
}
function agrees(cls, pref) {
    if (!pref || !cls || cls == pref) return true;
    return parentsOf(cls).indexOf(pref) != -1 || parentsOf(pref).indexOf(cls) != -1;
}
// how many hardware CIs carry a value in a field, how many of them are retired, and their classes
function found(table, field, value) {
    var out = { n: 0, retired: 0, classes: {}, one: '', oneClass: '' };
    if (!value) return out;
    var ga = new GlideRecord(table);
    ga.addQuery(field, value);
    if (ignore) ga.addQuery('sys_class_name', 'NOT IN', ignore);
    ga.query();
    while (ga.next()) {
        out.n++;
        var cls = '' + ga.getValue('sys_class_name');
        out.classes[cls] = (out.classes[cls] || 0) + 1;
        if (ga.getValue('install_status') == '7' || ga.getValue('operational_status') == '6') out.retired++;
        else { out.one = ga.getUniqueValue(); out.oneClass = cls; }
    }
    return out;
}
function fmt(f) {
    var cl = []; for (var c in f.classes) cl.push(c.replace('cmdb_ci_', '') + (f.classes[c] > 1 ? 'x' + f.classes[c] : ''));
    return f.n + (f.retired ? '(' + f.retired + ' retired)' : '') + (cl.length ? '[' + cl.join(',') + ']' : '');
}
function ciLabel(id) {
    if (!id) return '';
    var c = new GlideRecord('cmdb_ci');
    if (!c.get(id)) return id;
    return c.getValue('name') + ' [' + ('' + c.getValue('sys_class_name')).replace('cmdb_ci_', '') + (c.getValue('install_status') == '7' ? ', retired' : '') + ']';
}
function runChain(p) {
    for (var i = 0; i < rules.length; i++) {
        var v = p[rules[i].field];
        if (!v) continue;
        var ev = new GlideScopedEvaluator();
        ev.putVariable('rule', ruleRecords[rules[i].id]);
        ev.putVariable('sourceValue', '' + v);
        ev.putVariable('sourcePayload', p);
        var out = null;
        try { out = ev.evaluateScript(ruleRecords[rules[i].id], 'script', null); } catch (e) { return { rule: rules[i], error: '' + e }; }
        if (out) return { rule: rules[i], ci: '' + out };
    }
    return null;
}
// evidence the CMDB offers for a declined item, and the most likely cause of the decline
function evidence(p) {
    var dns = ('' + (p.DNS || '')).toLowerCase();
    var label = dns.split('.')[0];
    var dash = label.lastIndexOf('-');
    var base = dash > 0 ? label.substring(0, dash) : '';
    var tail = dash > 0 ? label.substring(dash + 1) : '';
    var e = { osClass: classFor(p.OS), kernel: kernelOnly(p.OS), network: dns.indexOf('.network.') != -1, controller: suffixes.indexOf(tail) != -1 };
    e.name = found('cmdb_ci_hardware', 'name', label);
    e.base = found('cmdb_ci_hardware', 'name', base);
    e.fqdn = found('cmdb_ci', 'fqdn', dns);
    e.ip = found('cmdb_ci_hardware', 'ip_address', p.IP);
    var live = { n: e.name.n - e.name.retired, base: e.base.n - e.base.retired, ip: e.ip.n - e.ip.retired };
    function conflict(f) { return f.n == 1 && f.retired == 0 && e.osClass && !agrees(f.oneClass, e.osClass); }
    if (!dns && !p.IP) e.reason = 'no name and no address in the payload';
    else if (e.name.n + e.base.n + e.fqdn.n + e.ip.n == 0) e.reason = 'nothing in the CMDB carries the name, the base name, the fqdn or the address';
    else if (e.name.n == 1 && e.name.retired == 0 && !conflict(e.name)) e.reason = 'name on one live record';
    else if (e.name.n == 1 && e.name.retired == 1) e.reason = 'name only on a retired record';
    else if (e.name.n > 1 && live.n == 1) e.reason = 'name shared with a retired record';
    else if (e.name.n > 1) e.reason = 'name on two or more live records';
    else if (conflict(e.name)) e.reason = e.kernel ? 'name on one record whose class contradicts a Linux kernel fingerprint' : 'name on one record whose class contradicts the scanned OS';
    else if (e.fqdn.n == 1) e.reason = 'fqdn on one record';
    else if (e.fqdn.n > 1) e.reason = 'fqdn on two or more records';
    else if (e.base.n == 1 && e.base.retired == 0 && (e.controller || e.network) && !conflict(e.base)) e.reason = 'interface label, base name on one live record';
    else if (e.base.n == 1 && e.base.retired == 0) e.reason = 'base name on one live record, tail not recognised as an interface';
    else if (e.base.n > 1 && live.base == 1) e.reason = 'base name shared with a retired record';
    else if (e.base.n > 1) e.reason = 'base name on two or more live records';
    else if (e.base.n == 1 && e.base.retired == 1) e.reason = 'base name only on a retired record';
    else if (e.ip.n == 1 && e.ip.retired == 1) e.reason = 'address only on a retired record';
    else if (e.ip.n > 1 && live.ip == 1) e.reason = 'address shared with retired records';
    else if (e.ip.n > 1) e.reason = 'address on two or more live records';
    else if (conflict(e.ip)) e.reason = e.kernel ? 'address on one record whose class contradicts a Linux kernel fingerprint' : 'address on one record whose class contradicts the scanned OS';
    else if (e.ip.n == 1) e.reason = 'address on one live record, name not in the CMDB';
    else e.reason = 'other';
    return e;
}
function clip(s, n) { s = '' + (s || ''); return s.length > n ? s.substring(0, n - 1) + '~' : s; }

var byRule = {}, agree = { same: 0, different: 0, usemOnly: 0, prodOnly: 0, none: 0 }, reasons = {}, pairs = {}, errors = 0;
var ABSENT = 'nothing in the CMDB carries the name, the base name, the fqdn or the address';
function notePair(e) {
    if (e.reason.indexOf('contradicts') == -1) return;
    var f = e.name.n == 1 ? e.name : e.base.n == 1 ? e.base : e.ip;
    var key = (e.osClass || '-').replace('cmdb_ci_', '') + ' (scan) vs ' + f.oneClass.replace('cmdb_ci_', '') + ' (CI)';
    pairs[key] = (pairs[key] || 0) + 1;
}
var lists = { different: [], usemOnly: [], prodOnly: [], declined: [] };
var hasRuleField = new GlideRecord('sn_sec_cmn_src_ci').isValidField('ci_lookup_rule');
var items = 0, parseFailures = 0, today = {};
var states = [['matched', MATCHED_LIMIT], ['unmatched', UNMATCHED_LIMIT]];
for (var s = 0; s < states.length; s++) {
    var di = new GlideRecord('sn_sec_cmn_src_ci');
    di.addQuery('state', states[s][0]);
    di.addQuery('source.name', 'CONTAINS', 'Qualys');
    if (DAYS > 0) di.addQuery('sys_created_on', '>', gs.daysAgoStart(DAYS));
    di.orderByDesc('sys_created_on');
    di.setLimit(states[s][1]);
    di.query();
    while (di.next()) {
        var p;
        try { p = JSON.parse('' + di.getValue('source_data')); } catch (e) { parseFailures++; continue; }
        items++;
        var prodCi = '' + (di.getValue('cmdb_ci') || '');
        var prodType = '' + (di.getValue('matching_type') || '');
        today[states[s][0] + ' / ' + (prodType || 'no matching type')] = (today[states[s][0] + ' / ' + (prodType || 'no matching type')] || 0) + 1;
        var prodRule = hasRuleField && di.ci_lookup_rule ? '' + di.ci_lookup_rule.getDisplayValue() : '';
        var res = runChain(p);
        if (res && res.error) { errors++; res = null; }
        var line = di.getValue('number') + ' | ' + clip(p.DNS, 60) + ' | ' + (p.IP || '') + ' | ' + clip(p.OS, 40);
        if (res) byRule[res.rule.order + ' ' + res.rule.name] = (byRule[res.rule.order + ' ' + res.rule.name] || 0) + 1;
        if (res && prodCi && states[s][0] == 'matched') {
            if (res.ci == prodCi) agree.same++;
            else { agree.different++; lists.different.push(line + ' | today: ' + ciLabel(prodCi) + ' via ' + (prodRule || prodType) + ' | usem: ' + res.rule.order + ' -> ' + ciLabel(res.ci)); }
        } else if (res) {
            agree.usemOnly++; lists.usemOnly.push(line + ' | today: ' + prodType + ' | usem: ' + res.rule.order + ' -> ' + ciLabel(res.ci));
        } else if (prodCi && states[s][0] == 'matched') {
            agree.prodOnly++; var ev1 = evidence(p); reasons[ev1.reason] = (reasons[ev1.reason] || 0) + 1; notePair(ev1);
            if (!SKIP_ABSENT || ev1.reason != ABSENT) lists.prodOnly.push(line + ' | today: ' + ciLabel(prodCi) + ' via ' + (prodRule || prodType) + ' | ' + ev1.reason + ' | name ' + fmt(ev1.name) + ' base ' + fmt(ev1.base) + ' fqdn ' + fmt(ev1.fqdn) + ' ip ' + fmt(ev1.ip) + ' os ' + (ev1.osClass || '-'));
        } else {
            agree.none++; var ev2 = evidence(p); reasons[ev2.reason] = (reasons[ev2.reason] || 0) + 1; notePair(ev2);
            if (!SKIP_ABSENT || ev2.reason != ABSENT) lists.declined.push(line + ' | ' + ev2.reason + ' | name ' + fmt(ev2.name) + ' base ' + fmt(ev2.base) + ' fqdn ' + fmt(ev2.fqdn) + ' ip ' + fmt(ev2.ip) + ' os ' + (ev2.osClass || '-') + (ev2.kernel ? ' (kernel only)' : ''));
        }
    }
}
var out = [];
out.push('=== Qualys lookup rule measurement, read-only ===');
out.push('items: ' + items + ' (payloads not parsed: ' + parseFailures + ', rule errors: ' + errors + ') | window: last ' + DAYS + ' days | elapsed: ' + Math.round((new Date().getTime() - started) / 1000) + ' s');
out.push('');
out.push('--- active scripted rules of the Qualys source, in chain order ---');
for (var ri = 0; ri < rules.length; ri++) out.push('  ' + rules[ri].order + ' ' + rules[ri].name + ' (' + rules[ri].field + '): ' + rules[ri].info);
out.push('');
out.push('--- items sampled, state / matching type today ---');
for (var tk in today) out.push('  ' + today[tk] + '  ' + tk);
out.push('');
out.push('--- matches per rule ---');
for (var k in byRule) out.push('  ' + k + ': ' + byRule[k]);
out.push('');
out.push('--- against what the items hold today ---');
out.push('  same CI: ' + agree.same + ' | different CI: ' + agree.different + ' | rules match an item that is unmatched today: ' + agree.usemOnly + ' | rules decline an item matched today: ' + agree.prodOnly + ' | both unmatched: ' + agree.none);
out.push('');
out.push('--- evidence behind the declines (both lists below) ---');
for (var rk in reasons) out.push('  ' + reasons[rk] + '  ' + rk);
out.push('');
out.push('--- class contradictions, scanned OS class against the class of the one CI carrying the name or address ---');
for (var pk in pairs) out.push('  ' + pairs[pk] + '  ' + pk);
function list(title, arr) {
    out.push(''); out.push('--- ' + title + ' (' + arr.length + (arr.length > LIST_CAP ? ', first ' + LIST_CAP : '') + ') ---');
    for (var i = 0; i < arr.length && i < LIST_CAP; i++) out.push('  ' + arr[i]);
}
list('different CI than today', lists.different);
list('rules decline an item matched today', lists.prodOnly);
list('rules match an item unmatched today', lists.usemOnly);
list('unmatched today and declined, with the evidence in the CMDB' + (SKIP_ABSENT ? ', hosts absent from the CMDB left out' : ''), lists.declined);
gs.print(out.join('\n'));
